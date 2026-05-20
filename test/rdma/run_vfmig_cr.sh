#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# End-to-end CRIU dump+restore of an mlx5_sriov_vfmig holder process,
# exercising the full plugin pipeline:
#
#   Dump path:
#     1. uverbs_ctx_holder opens an ibv_context against the VF ibdev,
#        allocates a PD, and waits.
#     2. criu dump triggers the mlx5_sriov_vfmig plugin:
#          - DUMP_UVERBS_CONTEXT snapshots the ucontext via the
#            new dyn-UAR verbs (libmlx5 default lib_uar_dyn=true) and
#            queues a per-VF SAVE.
#          - HANDLE_DEVICE_VMA persists the UAR mappings.
#          - fini(DUMP) drains the queue: SAVE_VHCA_STATE per VF +
#            mlx5_vfmig.img with one entry per ucontext.
#
#   Restore path:
#     3. Orchestrator tears down the source VF (sriov_numvfs=0) and
#        reprovisions a fresh "destination" VF with set_tracked=1,
#        but does NOT bind mlx5_core -- the plugin's init(RESTORE)
#        does LOAD_VHCA_STATE, driver_override+bind, then opens the
#        destination uverbs cdev with VFMIG_RESTORE | DYN_UAR and
#        replays the dyn-UAR records.
#     4. UPDATE_VMA_MAP hands the workload a dup of the dest cdev fd
#        with the source's pgoff verbatim.
#     5. uverbsfd_open() drives rdma_restore_uobj_dag_for_ufile()
#        which issues UVERBS_METHOD_RESTORE_PD per PD entry in
#        rdma-uobj.img. For mlx5 the verb carries a UHW payload
#        (struct mlx5_ib_restore_pd_req) with the source FW pdn
#        captured from RDMA_NLDEV_ATTR_RES_PDN; mlx5_ib_restore_pd
#        adopts that pdn into a fresh kernel-side mlx5_ib_pd via
#        Model A (no destination FW round-trip; the source pdn is
#        already reserved in firmware after LOAD_VHCA_STATE). See
#        linux/tools/testing/mlx5_vfmig/design/uobject_restore.md
#        §9.1 S3b.
#     6. RESTORE_MR is deferred to the pie restorer because it
#        depends on user VMAs (the MR's backing pages) being live
#        in the destination task's mm. After open_vmas() lays
#        them out, criu/pie/restorer.c::restore_rdma_mr issues
#        UVERBS_METHOD_RESTORE_MR on each queued MR. For mlx5 the
#        wire carries struct mlx5_ib_restore_mr_req in the UHW
#        attribute (mkey_index = lkey_hint >> 8); the kernel
#        handler adopts the source's FW mkey via mlx5_ib_restore
#        _mr (Model A) and the Stage-3 D4 wrapper binds the dest
#        process's pinned user pages onto the (KIND_MR, mkey_
#        index) placeholder iova that LOAD_VHCA_STATE replayed.
#        Linux 7c496744b43b + 7c6fb51f43f6 + 10fd8abeaaf0 +
#        5b6f13a52c20. See linux design/uobject_restore.md §9.6
#        and design/user_mr_dma.md §A.C.
#     7. SIGUSR1 to the restored holder runs the §S3b/§S4b
#        incremental-coverage acid test: confirm the restored MR's
#        lkey/rkey survived round-trip (libibverbs cache vs the
#        kernel-installed identity), then build a fresh CQ + QP
#        on the *adopted* PD (exercises FW CREATE_QP/CREATE_MKEY
#        accepting the adopted pdn under the destination
#        ucontext's uid -- the libibverbs version of pd_adopt's
#        FW gate validation), then tear them down in dependency
#        order ending in ibv_dereg_mr + ibv_dealloc_pd of the
#        pre-dump objects.
#
# Usage:
#   sudo PF=0000:08:00.0 ./run_vfmig_cr.sh
#
# Exits 0 on PASS, non-zero on FAIL with a tail of dump/restore logs.

set -euo pipefail

PF="${PF:-0000:08:00.0}"
CRIU="${CRIU:-/usr/local/sbin/criu}"
VFMIG_TOOL="${VFMIG_TOOL:-/opt/builds/linux/tools/testing/mlx5_vfmig/tools/mlx5_vfmig}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PROG="$HERE/uverbs_ctx_holder"
WORKDIR="$(mktemp -d /tmp/vfmig-cr-XXXXXX)"
PIDFILE="$WORKDIR/holder.pid"
RESTORED_PIDFILE="$WORKDIR/restored.pid"
STATUS="$WORKDIR/status"
LOG="$WORKDIR/holder.log"
DUMPDIR="$WORKDIR/img"

SRIOV_NUMVFS="/sys/bus/pci/devices/$PF/sriov_numvfs"

# dmesg slice the harness will start ignoring everything before, so
# the post-test capture only contains kernel events from this run.
# `dmesg --since` is not portable across distros so we record a
# kernel-uptime mark and slice on it via timestamps in the saved
# file. Set at script start (after WORKDIR exists) and used by the
# cleanup trap.
DMESG_SINCE_KTIME=
record_dmesg_mark() {
    DMESG_SINCE_KTIME="$(awk '{print $1}' /proc/uptime)"
}

cleanup() {
    local pid
    for pid in "$PIDFILE" "$RESTORED_PIDFILE"; do
        [[ -f "$pid" ]] || continue
        local p
        p="$(cat "$pid" 2>/dev/null || true)"
        [[ -n "$p" ]] || continue
        kill -KILL "$p" 2>/dev/null || true
    done
    # Snapshot the kernel ring buffer slice from this run into the
    # preserved workdir. Without this, the FW-error dmesg lines
    # (e.g. CREATE_QP bad_parameter, DEALLOC_PD bad_resource) get
    # rolled out of the kernel ring buffer by any subsequent RDMA
    # activity, leaving you racing the ring to triage. -T prints
    # human-readable timestamps; we filter to lines emitted at or
    # after the ktime mark recorded in record_dmesg_mark().
    if [[ -n "$DMESG_SINCE_KTIME" ]]; then
        dmesg -T --time-format=ctime > "$WORKDIR/dmesg.full" 2>/dev/null || true
        # Slice on the [seconds-since-boot] form (dmesg without -T)
        # because that's what the kernel actually stamps lines with;
        # awk-numeric compare against the recorded mark.
        dmesg | awk -v mark="$DMESG_SINCE_KTIME" '
            match($0, /^\[[ ]*([0-9]+\.[0-9]+)\]/, m) {
                if (m[1]+0 >= mark+0) print
            }' > "$WORKDIR/dmesg.run" 2>/dev/null || true
        # Targeted slice: just the FW-error and infiniband lines
        # most likely to be useful for PD-restore triage.
        grep -E '^\[' "$WORKDIR/dmesg.run" 2>/dev/null \
            | grep -E 'mlx5_core|infiniband mlx5|CREATE_|DEALLOC_|RESTORE_|create_qp|create_cq|create_mkey|alloc_pd|restore_pd|bad parameter|bad resource' \
            > "$WORKDIR/dmesg.fw" 2>/dev/null || true
    fi
    echo "(workdir preserved at $WORKDIR for triage)"
    if [[ -s "$WORKDIR/dmesg.fw" ]]; then
        echo "(FW-relevant dmesg lines: $WORKDIR/dmesg.fw -- $(wc -l < "$WORKDIR/dmesg.fw") lines)"
    fi
}
trap cleanup EXIT
record_dmesg_mark

[[ "$EUID" -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
[[ -x "$PROG" ]]    || { echo "missing $PROG -- 'make -C $HERE'" >&2; exit 1; }
[[ -x "$CRIU" ]]    || { echo "missing $CRIU" >&2; exit 1; }
[[ -x "$VFMIG_TOOL" ]] || { echo "missing $VFMIG_TOOL" >&2; exit 1; }

# CRIU has no --disable-plugin CLI; the closest knob is -L/--libdir
# which overrides the entire plugin search dir. amdgpu_plugin
# unconditionally hooks CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA and
# returns an error (rather than declining) when /dev/kfd is absent
# on hosts without an AMD GPU, which fires for any unrecognised
# /dev/* mapping including the libmlx5 UAR write-only-shared
# mapping at /dev/infiniband/uverbsN. Build a sandbox plugin dir
# with only the RDMA plugins (the ones this test cares about) and
# point criu at it via -L. cuda_plugin doesn't HANDLE_DEVICE_VMA
# so it'd be harmless either way; we omit it for cleanliness.
PLUGIN_SRC="${PLUGIN_SRC:-/usr/local/lib/criu}"
PLUGIN_SANDBOX="$WORKDIR/plugins"
mkdir -p "$PLUGIN_SANDBOX"
for p in rdma_rxe_plugin.so rdma_mlx5_vfmig_plugin.so; do
    [[ -f "$PLUGIN_SRC/$p" ]] || {
        echo "missing plugin $PLUGIN_SRC/$p -- 'make install' first" >&2
        exit 1
    }
    ln -s "$PLUGIN_SRC/$p" "$PLUGIN_SANDBOX/$p"
done
CRIU_LIB_FLAG="-L $PLUGIN_SANDBOX"

vf_path() { echo "/sys/bus/pci/devices/$1"; }

resolve_vf_ibdev() {
    local pf=$1 vf_id=$2 vf_bdf
    vf_bdf="$(readlink "$pf/virtfn$vf_id" | xargs basename)"
    for ib in /sys/class/infiniband/*; do
        local target
        target="$(readlink "$ib/device" | xargs basename)"
        [[ "$target" == "$vf_bdf" ]] && { basename "$ib"; return; }
    done
    return 1
}

provision_vf() {
    local label=$1
    echo "=== $label: provision VF ==="
    echo 0 >"$SRIOV_NUMVFS"
    echo 0 | tee "/sys/bus/pci/devices/$PF/sriov_drivers_autoprobe" >/dev/null
    echo 1 >"$SRIOV_NUMVFS"
    "$VFMIG_TOOL" "$PF" set_tracked 0 1
    "$VFMIG_TOOL" "$PF" enable_migratable 0
    local vf_bdf
    vf_bdf="$(readlink "/sys/bus/pci/devices/$PF/virtfn0" | xargs basename)"
    echo mlx5_core >"/sys/bus/pci/devices/$vf_bdf/driver_override"
    echo "$vf_bdf" >/sys/bus/pci/drivers/mlx5_core/bind
    # Wait for ibdev to appear.
    local ib
    for _ in $(seq 1 60); do
        ib="$(resolve_vf_ibdev "$(vf_path "$PF")" 0 || true)"
        [[ -n "$ib" ]] && break
        sleep 0.5
    done
    [[ -n "$ib" ]] || { echo "FAIL: VF ibdev did not appear" >&2; exit 1; }
    echo "VF ibdev: $ib (vf_bdf=$vf_bdf)"
    "$VFMIG_TOOL" "$PF" query_vf 0
    VF_IBDEV="$ib"
    VF_BDF="$vf_bdf"
}

reprovision_vf_for_restore() {
    echo "=== Phase D: tear down source VF ==="
    echo 0 >"$SRIOV_NUMVFS"
    sleep 0.5
    echo "=== Phase E: provision destination VF (no bind -- plugin handles it) ==="
    echo 1 >"$SRIOV_NUMVFS"
    "$VFMIG_TOOL" "$PF" set_tracked 0 1
    # Plugin's init(RESTORE) does enable_migratable + driver_override + bind.
    local vf_bdf
    vf_bdf="$(readlink "/sys/bus/pci/devices/$PF/virtfn0" | xargs basename)"
    VF_BDF_DEST="$vf_bdf"
    "$VFMIG_TOOL" "$PF" query_vf 0
    echo "destination VF prepared: $vf_bdf (no driver bound)"
}

# ---- Phase A: source VF provisioning ----------------------------------
provision_vf "Phase A"

# ---- Phase B: launch holder -------------------------------------------
echo "=== Phase B: launch uverbs_ctx_holder against $VF_IBDEV ==="
# systemd-run --scope to avoid inheriting the agent's unix sockets/fds.
systemd-run --scope --quiet --unit="vfmig-holder-$$" \
    bash -c "exec </dev/null >'$LOG' 2>&1; '$PROG' '$VF_IBDEV' '$STATUS' pd_mr" &
SCOPE_PID=$!
# Find the actual holder pid (child of the scope).
HOLDER_PID=
for _ in $(seq 1 50); do
    HOLDER_PID="$(pgrep -fx "$PROG $VF_IBDEV $STATUS pd_mr" || true)"
    [[ -n "$HOLDER_PID" ]] && break
    sleep 0.1
done
[[ -n "$HOLDER_PID" ]] || { echo "FAIL: holder did not start" >&2; cat "$LOG" >&2; exit 1; }
echo "$HOLDER_PID" >"$PIDFILE"
for _ in $(seq 1 50); do
    [[ -s "$STATUS" ]] && break
    sleep 0.1
done
[[ "$(cat "$STATUS")" == "READY" ]] || {
    echo "FAIL: holder status=$(cat "$STATUS"):" >&2
    cat "$LOG" >&2
    exit 1
}
echo "holder ready (pid=$HOLDER_PID)"
grep -E '^READY ' "$LOG" || true

# ---- Phase C: criu dump -----------------------------------------------
mkdir -p "$DUMPDIR"
echo "=== Phase C: criu dump ==="
echo "criu dump -t $HOLDER_PID -D $DUMPDIR -v4"
"$CRIU" dump -t "$HOLDER_PID" -D "$DUMPDIR" -v4 -o dump.log --shell-job $CRIU_LIB_FLAG || {
    echo "FAIL: criu dump returned $?"
    echo "--- dump log tail ---"
    tail -120 "$DUMPDIR/dump.log" || true
    exit 1
}
if kill -0 "$HOLDER_PID" 2>/dev/null; then
    echo "BUG: holder still alive after dump" >&2
    exit 1
fi
echo "dump OK; image dir contents:"
ls -la "$DUMPDIR" | sed 's/^/  /'

# ---- Phase D + E: teardown + reprovision ------------------------------
reprovision_vf_for_restore

# ---- Phase F: criu restore --------------------------------------------
echo "=== Phase F: criu restore ==="
"$CRIU" restore -D "$DUMPDIR" -v4 -o restore.log -d \
    --pidfile "$RESTORED_PIDFILE" --shell-job $CRIU_LIB_FLAG || {
    echo "FAIL: criu restore returned $?"
    echo "--- restore log tail ---"
    tail -120 "$DUMPDIR/restore.log" || true
    exit 1
}
RESTORED_PID="$(cat "$RESTORED_PIDFILE")"
echo "restored pid=$RESTORED_PID"

# Positive RESTORE_{PD,MR} dispatch assertions. Three log shapes
# correspond to the three stages the post-VMA pie-restorer split
# (criu/rdma.c::rdma_prepare_rdma_mrs + criu/pie/restorer.c::
# restore_rdma_mr) introduced for rxe S4a and that mlx5 S4b reuses
# verbatim:
#
#   Phase A           (criu master, in uverbsfd_open() during the
#                      uverbs-cdev open hook): VA-independent verbs.
#                      RESTORE_PD here; MR(s) get deferred.
#   Phase B-prep      (criu master, in restore_one_alive_task right
#                      after open_vmas): walks the deferred MRs,
#                      dups the cdev fd at high min, and serialises
#                      struct rst_rdma_mr into RM_PRIVATE for the
#                      pie blob to consume.
#   Phase B (pie)     (criu/pie/restorer.c, post-VMA-placement):
#                      iterates args->rdma_mrs and issues UVERBS_
#                      METHOD_RESTORE_MR. For mlx5 the wire carries
#                      struct mlx5_ib_restore_mr_req in the UHW
#                      attribute (mkey_index = lkey_hint >> 8); the
#                      kernel handler adopts the source's FW mkey
#                      via mlx5_ib_restore_mr (Model A) and the
#                      Stage-3 D4 wrapper binds dest user pages to
#                      the placeholder iova.
#
# Per-ufile summary lines (all printed by criu/rdma.c):
#   Phase A           "ufile_id=... Phase A: restored 1 PD(s) [...]; 1 MR(s) deferred to post-VMA Phase B"
#   Phase B-prep      "ufile_id=... Phase B-prep: serialised 1 MR(s) [skipped 0] for pie restorer"
#   Phase B (pie)     "pie: PID: RDMA: ufile_id=... RESTORE_MR(target_handle=..., lkey=..., rkey=..., mkey_index=...) ok"
#
# pd_mr mode: the mlx5_vfmig holder allocates exactly one PD + one
# MR pre-dump. Phase A asserts >=1 PD restored + >=1 MR deferred,
# Phase B-prep asserts >=1 MR serialised, and the pie blob asserts
# >=1 RESTORE_MR ok with the mkey_index field present (the mlx5-
# specific suffix). If the kernel-side identity check fails the pie
# blob aborts before printing the "ok" line, so absence of this line
# typically means the wire-format-vs-kernel mismatch (most often:
# UHW not being shipped, lkey_hint != rkey_hint, or
# (lkey_hint >> 8) != mkey_index).
if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\]; [1-9][0-9]* MR\(s\) deferred' \
    "$DUMPDIR/restore.log"; then
    echo "FAIL: restore.log shows no Phase-A RESTORE_PD dispatch by" \
         "rdma_restore_uobj_dag_for_ufile() with deferred MRs --" \
         "the per-ufile restore pass either didn't run, found no" \
         "PD/MR entries, or skipped them for missing ufile_handle /" \
         "QUERY_MR fields." >&2
    grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
        echo "(no uobj DAG lines at all)" >&2
    exit 1
fi
if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase B-prep: serialised [1-9][0-9]* MR\(s\) \[skipped 0\] for pie restorer' \
    "$DUMPDIR/restore.log"; then
    echo "FAIL: restore.log shows no RESTORE_MR Phase-B-prep" \
         "serialisation in restore_one_alive_task -- the post-" \
         "VMA hand-off to the pie restorer didn't run or every" \
         "MR was skipped." >&2
    grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
        echo "(no uobj DAG lines at all)" >&2
    exit 1
fi
if ! grep -qE 'pie: [0-9]+: RDMA: ufile_id=[^ ]+ RESTORE_MR\(target_handle=[0-9]+, lkey=[0-9a-fx]+, rkey=[0-9a-fx]+, mkey_index=[0-9a-fx]+\) ok' \
    "$DUMPDIR/restore.log"; then
    echo "FAIL: restore.log shows no mlx5 RESTORE_MR pie-restorer" \
         "dispatch -- either the pie blob never reached the queued" \
         "MR(s) (rdma_mrs_n=0 / RST_MEM_FIXUP_PPTR misorder), or" \
         "the ioctl returned an error (kernel handler -EINVAL on" \
         "missing UHW / mkey_index mismatch / non-restore-mode" \
         "ucontext, or stage-3 D4 -EFAULT / -ENOENT on placeholder" \
         "miss). Without Phase B firing the libibverbs MR cache in" \
         "the restored process points at slots that don't exist in" \
         "the kernel ucontext." >&2
    echo "--- restore log pie RDMA lines ---" >&2
    grep -E 'pie:.* RDMA:' "$DUMPDIR/restore.log" >&2 || \
        echo "(no pie RDMA lines at all)" >&2
    exit 1
fi
echo "RESTORE_PD (Phase A) + RESTORE_MR (mlx5 UHW pie Phase B) dispatched ok"

# ---- Phase G: verify --------------------------------------------------
echo "=== Phase G: post-restore checks ==="
echo "WAITING" >"$STATUS"
kill -USR1 "$RESTORED_PID"
for _ in $(seq 1 50); do
    cur="$(cat "$STATUS" 2>/dev/null || true)"
    [[ "$cur" != "WAITING" ]] && break
    sleep 0.1
done
RESULT="$(cat "$STATUS" 2>/dev/null || true)"
echo "post-restore status: $RESULT"

if [[ "$RESULT" == "OK" ]]; then
    kill -TERM "$RESTORED_PID" 2>/dev/null || true
    echo "PASS"
    exit 0
fi

echo "FAIL ($RESULT)"
# Specific failure modes the holder distinguishes (see
# uverbs_ctx_holder.c::run_post_restore_checks):
#   - "ibv_query_device after restore": ucontext / cdev reattach
#     broken (RDMA_OPEN_UVERBS_CDEV path).
#   - "ibv_create_cq on restored ucontext": fresh-resource creation
#     against the restore-mode ucontext broken.
#   - "ibv_create_qp on pre-dump PD": Model A pdn adoption broken
#     for QP -- FW CREATE_QP rejected the adopted pdn under the
#     destination ucontext's uid (the live-fire half of the
#     pd_adopt FW-gate test).
#   - "ibv_reg_mr on pre-dump PD": same for FW CREATE_MKEY -- the
#     specific verb pd_adopt validates empirically.
#   - "ibv_dealloc_pd of pre-dump PD (after draining dependents)":
#     dependency-ordered teardown reached PD with all dependents
#     already gone, so DEALLOC_PD should be unconditional. A
#     failure here means kernel-side ib_uobject leaked a
#     dependent or the adopted mpd->pdn is stale.
echo "--- dump log tail ---" >&2
tail -120 "$DUMPDIR/dump.log" >&2 || true
echo "--- restore log tail ---" >&2
tail -120 "$DUMPDIR/restore.log" >&2 || true
# Print the FW-relevant dmesg slice now (the cleanup trap also
# saves it to $WORKDIR/dmesg.fw, but printing inline avoids the
# user having to chase a temp dir to see the FW status code that
# explains the failure -- e.g. "CREATE_QP bad parameter (0x3)
# syndrome 0xec06a5" or "DEALLOC_PD bad resource (0x5) syndrome
# 0x593117" tell the actual story behind a generic EINVAL).
if [[ -n "$DMESG_SINCE_KTIME" ]]; then
    echo "--- kernel dmesg (FW + infiniband, this run only) ---" >&2
    dmesg | awk -v mark="$DMESG_SINCE_KTIME" '
        match($0, /^\[[ ]*([0-9]+\.[0-9]+)\]/, m) {
            if (m[1]+0 >= mark+0) print
        }' \
        | grep -E 'mlx5_core|infiniband mlx5|CREATE_|DEALLOC_|RESTORE_|create_qp|create_cq|create_mkey|alloc_pd|restore_pd|bad parameter|bad resource' \
        | tail -60 >&2 || true
fi
exit 1
