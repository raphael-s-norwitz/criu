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
#        rdma-uobj.img.
#     6. RESTORE_MR is deferred to the pie restorer because it
#        depends on user VMAs (the MR's backing pages) being live
#        in the destination task's mm. After open_vmas() lays
#        them out, criu/pie/restorer.c::restore_rdma_mr issues
#        UVERBS_METHOD_RESTORE_MR on each queued MR.
#     7. SIGUSR1 to the restored holder runs the §S3b/§S4b
#        incremental-coverage acid test.
#     8. Phase J -- data-path acid test (RDMA WRITE through the
#        restored MR's lkey + rkey).
#
# Two passes per run:
#
#   pass 1 (aligned)    legacy Phase J baseline. 4 KiB MR registered
#                       at the base of a 4 KiB page-aligned buffer;
#                       umem fits in one page so the source-side
#                       vfmig_dma_ops.map_sg installs exactly one
#                       external registry entry per MR. The kernel's
#                       single-sibling secondary-index path is what
#                       the original Phase J validation exercised
#                       end-to-end.
#
#   pass 2 (unaligned)  multi-page regression coverage for the kernel
#                       commit "mlx5_vfmig: support multi-page user
#                       objects in the secondary index" (composite
#                       (instance_key, iova) ordering, sibling-chain
#                       walk in vfmig_iova_bind_user_object). 4 KiB
#                       MR registered at offset 0x800 inside an 8 KiB
#                       allocation, so the umem covers second half of
#                       page 0 + first half of page 1. ib_umem_get
#                       pins both pages; sg_alloc_append_table_from
#                       _pages produces >= 2 sg entries on a typical
#                       anonymous-page layout, and vfmig_dma_ops.
#                       map_sg installs N external registry entries
#                       all sharing one (KIND_MR, mkey_index)
#                       instance_key. Pre-fix this tripped -EEXIST
#                       in vfmig_iova_user_index_insert_locked on
#                       the second sibling, rolled the entries back
#                       to KIND_NONE, vfmig_save_hup_emit_cb dropped
#                       them, and RESTORE_MR returned -ENOENT against
#                       the missing placeholder. Post-fix the second
#                       sibling tie-breaks on iova and the bind-side
#                       walk maps every sibling. This pass is the
#                       in-CRIU regression that mirrors the
#                       rdma_test_agent_vfmig_criu_swap_after_mr
#                       E2E failure.
#
# Usage:
#   sudo PF=0000:08:00.0 ./run_vfmig_cr.sh
#
# Exits 0 on PASS (both passes green), non-zero on FAIL with a tail
# of dump/restore logs and the FW-relevant dmesg slice for the
# failing pass.

set -euo pipefail

PF="${PF:-0000:08:00.0}"
CRIU="${CRIU:-/usr/local/sbin/criu}"
VFMIG_TOOL="${VFMIG_TOOL:-/opt/builds/linux/tools/testing/mlx5_vfmig/tools/mlx5_vfmig}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PROG="$HERE/uverbs_ctx_holder"
WORKDIR="$(mktemp -d /tmp/vfmig-cr-XXXXXX)"

SRIOV_NUMVFS="/sys/bus/pci/devices/$PF/sriov_numvfs"

# Per-pass state (set by run_pass before any code that needs them).
PASS_NAME=
PASS_DIR=
PIDFILE=
RESTORED_PIDFILE=
STATUS=
LOG=
DUMPDIR=
HOLDER_PID=
RESTORED_PID=
VF_IBDEV=
VF_BDF=
VF_BDF_DEST=
DMESG_SINCE_KTIME=

record_dmesg_mark() {
    DMESG_SINCE_KTIME="$(awk '{print $1}' /proc/uptime)"
}

cleanup() {
    local pidfile p
    # Kill any holder/restored process we tracked across all passes.
    for pidfile in "$WORKDIR"/*/holder.pid "$WORKDIR"/*/restored.pid; do
        [[ -f "$pidfile" ]] || continue
        p="$(cat "$pidfile" 2>/dev/null || true)"
        [[ -n "$p" ]] || continue
        kill -KILL "$p" 2>/dev/null || true
    done
    # Snapshot the kernel ring buffer slice from this run into the
    # preserved workdir. Without this, the FW-error dmesg lines
    # (e.g. CREATE_QP bad_parameter, DEALLOC_PD bad_resource) get
    # rolled out of the kernel ring buffer by any subsequent RDMA
    # activity, leaving you racing the ring to triage.
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
        # most likely to be useful for PD/MR-restore triage.
        grep -E '^\[' "$WORKDIR/dmesg.run" 2>/dev/null \
            | grep -E 'mlx5_core|infiniband mlx5|CREATE_|DEALLOC_|RESTORE_|create_qp|create_cq|create_mkey|alloc_pd|restore_pd|vfmig|bad parameter|bad resource' \
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
# point criu at it via -L.
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

#
# pass_fail <reason> -- print FAIL with logs + dmesg slice for the
# current pass, then exit 1.
#
pass_fail() {
    local reason="$1"
    echo "FAIL ($PASS_NAME: $reason)"
    echo "--- dump log tail ---" >&2
    tail -120 "$DUMPDIR/dump.log" >&2 || true
    echo "--- restore log tail ---" >&2
    tail -120 "$DUMPDIR/restore.log" >&2 || true
    if [[ -n "$DMESG_SINCE_KTIME" ]]; then
        echo "--- kernel dmesg (FW + infiniband, this run only) ---" >&2
        dmesg | awk -v mark="$DMESG_SINCE_KTIME" '
            match($0, /^\[[ ]*([0-9]+\.[0-9]+)\]/, m) {
                if (m[1]+0 >= mark+0) print
            }' \
            | grep -E 'mlx5_core|infiniband mlx5|CREATE_|DEALLOC_|RESTORE_|create_qp|create_cq|create_mkey|alloc_pd|restore_pd|vfmig|bad parameter|bad resource' \
            | tail -80 >&2 || true
    fi
    exit 1
}

#
# run_pass <pass_name> <unaligned: 0|1>
#
# One full Phase A..G dump+restore+post-restore-checks cycle scoped
# to $WORKDIR/<pass_name>/. Provisions its own source VF, runs its
# own holder process, dumps, reprovisions destination, restores, and
# fires Phase J. Returns 0 on success, exits with pass_fail() on any
# failure.
#
# The two MR-geometry passes share their assertion set verbatim;
# only the holder's UVERBS_HOLDER_UNALIGNED_MR env var changes. The
# READY-line "mr_unaligned=N" field is asserted before dump so a
# silent env-var dropout (e.g. systemd-run scope env-stripping) is
# caught up-front instead of producing a false PASS.
#
run_pass() {
    PASS_NAME="$1"
    local unaligned="$2"

    PASS_DIR="$WORKDIR/$PASS_NAME"
    PIDFILE="$PASS_DIR/holder.pid"
    RESTORED_PIDFILE="$PASS_DIR/restored.pid"
    STATUS="$PASS_DIR/status"
    LOG="$PASS_DIR/holder.log"
    DUMPDIR="$PASS_DIR/img"

    mkdir -p "$DUMPDIR"

    echo
    echo "==============================================="
    echo " pass=$PASS_NAME unaligned=$unaligned"
    echo "==============================================="

    # ---- Phase A: source VF provisioning ------------------------------
    provision_vf "Phase A ($PASS_NAME)"

    # ---- Phase B: launch holder ---------------------------------------
    echo "=== Phase B ($PASS_NAME): launch uverbs_ctx_holder against $VF_IBDEV ==="
    # systemd-run --scope to avoid inheriting the agent's unix sockets/fds.
    # Per-pass unit name (vfmig-holder-$$-$pass) avoids "unit already
    # exists" if the second pass tries to reuse the script-PID-only name.
    # Env var is set inline inside the bash -c body since --setenv
    # plumbing varies across systemd versions and we want the holder to
    # see exactly UVERBS_HOLDER_UNALIGNED_MR=$unaligned at startup.
    systemd-run --scope --quiet --unit="vfmig-holder-$$-$PASS_NAME" \
        bash -c "exec </dev/null >'$LOG' 2>&1; UVERBS_HOLDER_UNALIGNED_MR='$unaligned' '$PROG' '$VF_IBDEV' '$STATUS' pd_mr" &
    # Find the actual holder pid (child of the scope).
    HOLDER_PID=
    local _ cur
    for _ in $(seq 1 50); do
        HOLDER_PID="$(pgrep -fx "$PROG $VF_IBDEV $STATUS pd_mr" || true)"
        [[ -n "$HOLDER_PID" ]] && break
        sleep 0.1
    done
    [[ -n "$HOLDER_PID" ]] || {
        echo "FAIL ($PASS_NAME): holder did not start" >&2
        cat "$LOG" >&2 || true
        exit 1
    }
    echo "$HOLDER_PID" >"$PIDFILE"
    for _ in $(seq 1 50); do
        [[ -s "$STATUS" ]] && break
        sleep 0.1
    done
    [[ "$(cat "$STATUS")" == "READY" ]] || {
        echo "FAIL ($PASS_NAME): holder status=$(cat "$STATUS"):" >&2
        cat "$LOG" >&2
        exit 1
    }
    echo "holder ready (pid=$HOLDER_PID)"
    grep -E '^READY ' "$LOG" || true

    # Cross-check that the holder picked up the requested geometry.
    # A regression where UVERBS_HOLDER_UNALIGNED_MR is read wrong
    # (env-var stripping by the systemd-run scope, parser flipped,
    # dropped from the holder, etc.) would silently turn
    # pass=unaligned into a duplicate of pass=aligned. Catch it
    # before we burn dump/restore time on a pass that wasn't
    # actually exercising the multi-page path.
    if ! grep -qE "^READY .* mr_unaligned=$unaligned " "$LOG"; then
        echo "FAIL ($PASS_NAME): holder READY line does not advertise" \
             "mr_unaligned=$unaligned -- env-var plumbing broken or" \
             "holder didn't honour UVERBS_HOLDER_UNALIGNED_MR" >&2
        grep -E '^READY ' "$LOG" >&2 || true
        exit 1
    fi

    # ---- Phase C: criu dump -------------------------------------------
    echo "=== Phase C ($PASS_NAME): criu dump ==="
    echo "criu dump -t $HOLDER_PID -D $DUMPDIR -v4"
    "$CRIU" dump -t "$HOLDER_PID" -D "$DUMPDIR" -v4 -o dump.log --shell-job $CRIU_LIB_FLAG || {
        echo "criu dump returned $?"
        pass_fail "criu dump failed"
    }
    if kill -0 "$HOLDER_PID" 2>/dev/null; then
        echo "BUG: holder still alive after dump" >&2
        pass_fail "holder alive after dump"
    fi
    echo "dump OK; image dir contents:"
    ls -la "$DUMPDIR" | sed 's/^/  /'

    # ---- Phase D + E: teardown + reprovision --------------------------
    reprovision_vf_for_restore

    # ---- Phase F: criu restore ----------------------------------------
    echo "=== Phase F ($PASS_NAME): criu restore ==="
    "$CRIU" restore -D "$DUMPDIR" -v4 -o restore.log -d \
        --pidfile "$RESTORED_PIDFILE" --shell-job $CRIU_LIB_FLAG || {
        echo "criu restore returned $?"
        pass_fail "criu restore failed"
    }
    RESTORED_PID="$(cat "$RESTORED_PIDFILE")"
    echo "restored pid=$RESTORED_PID"

    # Positive RESTORE_{PD,MR} dispatch assertions (per-ufile DAG
    # summary lines printed by criu/rdma.c). pd_mr mode: the holder
    # allocates exactly one PD + one MR pre-dump. Phase A asserts
    # >=1 PD restored + >=1 MR deferred, Phase B-prep asserts >=1
    # MR serialised, the pie blob asserts >=1 RESTORE_MR ok with
    # the mkey_index field present (mlx5-specific suffix).
    if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\]; [1-9][0-9]* MR\(s\) deferred' \
        "$DUMPDIR/restore.log"; then
        echo "missing Phase-A RESTORE_PD dispatch line" >&2
        grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
            echo "(no uobj DAG lines at all)" >&2
        pass_fail "no RESTORE_PD dispatch"
    fi
    if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase B-prep: serialised [1-9][0-9]* MR\(s\) \[skipped 0\] for pie restorer' \
        "$DUMPDIR/restore.log"; then
        echo "missing Phase B-prep MR serialisation" >&2
        grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
            echo "(no uobj DAG lines at all)" >&2
        pass_fail "no Phase B-prep MR serialisation"
    fi
    if ! grep -qE 'pie: [0-9]+: RDMA: ufile_id=[^ ]+ RESTORE_MR\(target_handle=[0-9]+, lkey=[0-9a-fx]+, rkey=[0-9a-fx]+, mkey_index=[0-9a-fx]+\) ok' \
        "$DUMPDIR/restore.log"; then
        echo "missing pie-restorer RESTORE_MR ok line. The pie blob" \
             "either didn't see the queued MR(s) (rdma_mrs_n=0 /" \
             "RST_MEM_FIXUP_PPTR misorder), or the ioctl returned" \
             "an error (kernel handler -EINVAL on missing UHW /" \
             "mkey_index mismatch / non-restore-mode ucontext, or" \
             "stage-3 D4 -EFAULT / -ENOENT on placeholder miss)." >&2
        echo "--- restore log pie RDMA lines ---" >&2
        grep -E 'pie:.* RDMA:' "$DUMPDIR/restore.log" >&2 || \
            echo "(no pie RDMA lines at all)" >&2
        pass_fail "no RESTORE_MR pie-restorer dispatch"
    fi
    echo "RESTORE_PD (Phase A) + RESTORE_MR (mlx5 UHW pie Phase B) dispatched ok"

    # ---- Phase G: verify ----------------------------------------------
    echo "=== Phase G ($PASS_NAME): post-restore checks ==="
    echo "WAITING" >"$STATUS"
    kill -USR1 "$RESTORED_PID"
    for _ in $(seq 1 50); do
        cur="$(cat "$STATUS" 2>/dev/null || true)"
        [[ "$cur" != "WAITING" ]] && break
        sleep 0.1
    done
    local RESULT="$(cat "$STATUS" 2>/dev/null || true)"
    echo "post-restore status: $RESULT"

    if [[ "$RESULT" != "OK" ]]; then
        pass_fail "post-restore status: $RESULT"
    fi

    # Phase J -- data-path acid test through the restored MR.
    if ! grep -qE 'PHASE_J: ok qp_a=0x[0-9a-f]+ qp_b=0x[0-9a-f]+ len=[1-9][0-9]* restored_lkey=0x[0-9a-f]+ restored_rkey=0x[0-9a-f]+ peer_lkey=0x[0-9a-f]+ peer_rkey=0x[0-9a-f]+' \
        "$LOG"; then
        echo "FAIL ($PASS_NAME): holder reported OK but holder.log has no" \
             "PHASE_J: ok line. The status-vs-log invariant is" \
             "broken; either the holder dropped the print or" \
             "run_phase_j was bypassed." >&2
        echo "--- holder log tail ---" >&2
        tail -40 "$LOG" >&2 || true
        exit 1
    fi
    echo "Phase J data path:" \
         "$(grep -E '^PHASE_J: ' "$LOG" | head -1)"

    # Drain the restored holder so the destination uverbs cdev is
    # released before the next pass tries to take it.
    kill -TERM "$RESTORED_PID" 2>/dev/null || true
    for _ in $(seq 1 30); do
        kill -0 "$RESTORED_PID" 2>/dev/null || break
        sleep 0.1
    done
    echo "pass=$PASS_NAME: PASS"
}

# ---- driver: aligned baseline, then unaligned multi-page regression ---
run_pass aligned 0
run_pass unaligned 1

echo
echo "ALL PASSES OK"
echo "PASS"
exit 0
