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
# Multiple passes per run, gated by env-var (defaults below):
#
#   pass pd_mr_aligned     legacy Phase J baseline. 4 KiB MR
#   (UVERBS_CR_RUN_       registered at the base of a 4 KiB
#    PD_MR=1, default)    page-aligned buffer; umem fits in one
#                          page so the source-side
#                          vfmig_dma_ops.map_sg installs exactly
#                          one external registry entry per MR. The
#                          kernel's single-sibling secondary-index
#                          path is what the original Phase J
#                          validation exercised end-to-end.
#
#   pass pd_mr_unaligned   multi-page regression coverage for the
#   (UVERBS_CR_RUN_       kernel commit "mlx5_vfmig: support
#    PD_MR=1, default)    multi-page user objects in the
#                          secondary index" (composite
#                          (instance_key, iova) ordering,
#                          sibling-chain walk in
#                          vfmig_iova_bind_user_object). 4 KiB MR
#                          registered at offset 0x800 inside an
#                          8 KiB allocation, so the umem covers
#                          second half of page 0 + first half of
#                          page 1. ib_umem_get pins both pages;
#                          sg_alloc_append_table_from_pages
#                          produces >= 2 sg entries on a typical
#                          anonymous-page layout, and
#                          vfmig_dma_ops.map_sg installs N external
#                          registry entries all sharing one
#                          (KIND_MR, mkey_index) instance_key.
#                          Pre-fix this tripped -EEXIST in
#                          vfmig_iova_user_index_insert_locked on
#                          the second sibling, rolled the entries
#                          back to KIND_NONE,
#                          vfmig_save_hup_emit_cb dropped them, and
#                          RESTORE_MR returned -ENOENT against the
#                          missing placeholder. Post-fix the second
#                          sibling tie-breaks on iova and the
#                          bind-side walk maps every sibling. This
#                          pass is the in-CRIU regression that
#                          mirrors the
#                          rdma_test_agent_vfmig_criu_swap_after_mr
#                          E2E failure.
#
#   pass pd_cq             S5a RESTORE_CQ coverage. PD + 1 CQ
#   (UVERBS_CR_RUN_       (comp_channel=NULL, comp_vector=0).
#    PD_CQ=1, default)    Hits the new pipeline:
#                            dump-side: mlx5_sriov_vfmig plugin's
#                              CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ
#                              calls MLX5_IB_METHOD_VFMIG_QUERY_CQ
#                              and packs the kernel's 32B
#                              mlx5_ib_restore_cq_req into the
#                              per-CQ RdmaUobjEntry.plugin_blob.
#                            restore-side: rdma_send_restore_cq
#                              (driver-agnostic) builds the kernel-
#                              UAPI core attrs from RdmaCqAttrs,
#                              the plugin's
#                              RDMA_RESTORE_UOBJ_CQ_UHW_PACK hook
#                              copies the 32B blob into UHW_IN, the
#                              kernel's mlx5_ib_restore_cq adopts
#                              the source's FW cqn via
#                              mlx5_core_adopt_cq, and the
#                              destination CQE-ring umem +
#                              DBR-page umem are pinned on the
#                              destination task's mm.
#                          Post-restore (SIGUSR1 -> holder's
#                          run_post_restore_checks_pd_cq) asserts
#                          ibv_destroy_cq + ibv_dealloc_pd both
#                          succeed -- the smoking gun that the
#                          source's CQ ufile_handle survived in
#                          the destination ucontext IDR and that
#                          the FW cqn adoption didn't desync uverbs
#                          from FW state.
#
#   pass pd_2cq            multi-CQ + multi-comp_vector coverage
#   (UVERBS_CR_RUN_       on top of pd_cq. Two CQs created with
#    PD_2CQ=1, opt-in)    comp_vector=0 and comp_vector=1 (mlx5
#                          hosts typically report
#                          num_comp_vectors >= #cores so the
#                          comp_vector=1 selection is the common
#                          case). Validates per-CQ dispatcher key
#                          uniqueness (one VFMIG_QUERY_CQ per CQ,
#                          plugin_blob bytes never crossed between
#                          CQs) and FW comp_vector round-trip
#                          (cqc.c_eqn_or_apu_element adopted
#                          unchanged so the destination CQ binds
#                          to the same EQ slot). Reverse-creation-
#                          order teardown surfaces a one-CQ
#                          regression as ibv_destroy_cq -EINVAL on
#                          the second teardown rather than letting
#                          a single missing CQ hide.
#
# Usage:
#   sudo PF=0000:08:00.0 ./run_vfmig_cr.sh
#   sudo PF=... UVERBS_CR_RUN_PD_2CQ=1 ./run_vfmig_cr.sh
#   sudo PF=... UVERBS_CR_RUN_PD_MR=0 UVERBS_CR_RUN_PD_CQ=1 \
#       ./run_vfmig_cr.sh    # CQ-only triage on a Phase-J-broken host
#
# Exits 0 on PASS (every enabled pass green), non-zero on FAIL with
# a tail of dump/restore logs and the FW-relevant dmesg slice for
# the failing pass.

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
# run_pass <pass_name> <holder_mode> <unaligned: 0|1>
#
# One full Phase A..G dump+restore+post-restore-checks cycle scoped
# to $WORKDIR/<pass_name>/. Provisions its own source VF, runs its
# own holder process, dumps, reprovisions destination, restores, and
# (for pd_mr) fires Phase J. Returns 0 on success, exits with
# pass_fail() on any failure.
#
# @holder_mode controls the pre-dump resource graph the
# uverbs_ctx_holder builds:
#
#   pd_mr   -- baseline: PD + MR. Exercises the full S3b/S4b mlx5
#              vfmig pipeline including SAVE_VHCA_STATE,
#              LOAD_VHCA_STATE, RESTORE_PD adoption, mlx5 UHW pie
#              RESTORE_MR, and the Phase J data-path acid test
#              through the restored MR's lkey/rkey. The
#              UVERBS_HOLDER_UNALIGNED_MR env var picks between
#              aligned (single-page) and unaligned (multi-page)
#              umem geometry; both passes share assertions verbatim.
#
#   pd_cq   -- S5a regression coverage: PD + 1 CQ. Exercises the
#              MLX5_IB_METHOD_VFMIG_QUERY_CQ -> RdmaUobjEntry.
#              plugin_blob -> RESTORE_CQ pipeline. Post-restore
#              acid test asserts CQ ufile_handle survival via
#              ibv_destroy_cq -EINVAL (kernel IDR slot must exist
#              at the source's handle, kernel-side cqn adoption
#              must not have desynced uverbs IDR from FW state).
#              No MR -> no Phase B-prep, no pie restorer, no Phase
#              J. The unaligned arg is ignored (no MR geometry to
#              vary); we still pass it for argument-shape symmetry
#              across modes.
#
#   pd_2cq  -- multi-CQ-per-ufile + multi-comp_vector coverage on
#              top of pd_cq. Two CQs created with comp_vector=0 and
#              comp_vector=1 (mlx5 hosts typically report
#              num_comp_vectors >= #cores so the clamp is a no-op).
#              Validates per-CQ dispatcher key uniqueness (CRIU
#              must dispatch exactly one VFMIG_QUERY_CQ per CQ,
#              keyed off the per-CQ ufile_handle, no
#              cross-contamination of the 32B mlx5_ib_restore_cq_req
#              blob between CQs) and comp_vector round-trip (FW
#              cqc.c_eqn_or_apu_element must adopt unchanged from
#              source so the destination CQ binds to the same EQ
#              slot). Post-restore tears down in reverse-creation
#              order so a regression that drops one CQ surfaces as
#              ibv_destroy_cq -EINVAL on the second teardown.
#
# pd_mr's READY-line "mr_unaligned=N" field is asserted before
# dump so a silent env-var dropout (e.g. systemd-run scope
# env-stripping) is caught up-front instead of producing a false
# PASS. pd_cq/pd_2cq don't carry that axis so the assertion is
# skipped for those modes.
#
run_pass() {
    PASS_NAME="$1"
    local holder_mode="$2"
    local unaligned="$3"

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
    echo "=== Phase B ($PASS_NAME): launch uverbs_ctx_holder against $VF_IBDEV (mode=$holder_mode) ==="
    # systemd-run --scope to avoid inheriting the agent's unix sockets/fds.
    # Per-pass unit name (vfmig-holder-$$-$pass) avoids "unit already
    # exists" if the second pass tries to reuse the script-PID-only name.
    # Env var is set inline inside the bash -c body since --setenv
    # plumbing varies across systemd versions and we want the holder to
    # see exactly UVERBS_HOLDER_UNALIGNED_MR=$unaligned at startup.
    # @holder_mode is appended to the holder argv as argv[3] (the
    # holder's mode selector documented in uverbs_ctx_holder.c).
    systemd-run --scope --quiet --unit="vfmig-holder-$$-$PASS_NAME" \
        bash -c "exec </dev/null >'$LOG' 2>&1; UVERBS_HOLDER_UNALIGNED_MR='$unaligned' '$PROG' '$VF_IBDEV' '$STATUS' '$holder_mode'" &
    # Find the actual holder pid (child of the scope).
    HOLDER_PID=
    local _ cur
    for _ in $(seq 1 50); do
        HOLDER_PID="$(pgrep -fx "$PROG $VF_IBDEV $STATUS $holder_mode" || true)"
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

    # Cross-check the holder picked up the requested geometry. A
    # regression where UVERBS_HOLDER_UNALIGNED_MR is read wrong
    # (env-var stripping by the systemd-run scope, parser flipped,
    # dropped from the holder, etc.) would silently turn
    # pass=unaligned into a duplicate of pass=aligned. Catch it
    # before we burn dump/restore time on a pass that wasn't
    # actually exercising the multi-page path. pd_cq/pd_2cq have
    # no MR geometry axis -- the holder doesn't print
    # mr_unaligned= on the READY line in those modes -- so we
    # skip the cross-check there.
    if [[ "$holder_mode" == "pd_mr" ]]; then
        if ! grep -qE "^READY .* mr_unaligned=$unaligned " "$LOG"; then
            echo "FAIL ($PASS_NAME): holder READY line does not advertise" \
                 "mr_unaligned=$unaligned -- env-var plumbing broken or" \
                 "holder didn't honour UVERBS_HOLDER_UNALIGNED_MR" >&2
            grep -E '^READY ' "$LOG" >&2 || true
            exit 1
        fi
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

    # Positive RESTORE_{PD,CQ,MR} dispatch assertions (per-ufile DAG
    # summary lines printed by criu/rdma/uobj_restore.c). The
    # mode-agnostic Phase A line shape is:
    #   "Phase A: restored N PD(s) [skipped M], P CQ(s) [skipped Q]; R MR(s) deferred ..."
    # Mode-specific minima:
    #   pd_mr   P=0  R>=1 : 1 PD,        0 CQ,           >=1 MR deferred + B-prep + pie ok + Phase J
    #   pd_cq   P=1  R=0  : 1 PD,        1 CQ restored,  0 MR deferred
    #   pd_2cq  P=2  R=0  : 1 PD,        2 CQs restored, 0 MR deferred
    #
    # Mode-agnostic gate first: at least one PD must have been
    # restored. Catches the regression where rdma_restore_uobj_dag_
    # for_ufile() didn't run at all (R3 walker missing, plugin
    # mismatch, ufile_handle dropout etc.).
    if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\], [0-9]+ CQ\(s\) \[skipped [0-9]+\]; [0-9]+ MR\(s\) deferred' \
        "$DUMPDIR/restore.log"; then
        echo "missing Phase-A RESTORE_PD dispatch line" >&2
        grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
            echo "(no uobj DAG lines at all)" >&2
        pass_fail "no RESTORE_PD dispatch"
    fi

    if [[ "$holder_mode" == "pd_mr" ]]; then
        # pd_mr: P=0 (no CQs in this mode), R>=1 (the MR gets
        # deferred to Phase B-prep + pie restorer).
        if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\], 0 CQ\(s\) \[skipped 0\]; [1-9][0-9]* MR\(s\) deferred' \
            "$DUMPDIR/restore.log"; then
            echo "missing Phase-A pd_mr summary (1+ MR deferred, 0 CQ)" >&2
            grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
                echo "(no uobj DAG lines at all)" >&2
            pass_fail "wrong pd_mr Phase-A counts"
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
    elif [[ "$holder_mode" == "pd_cq" || "$holder_mode" == "pd_2cq" ]]; then
        # pd_cq:  exactly 1 CQ restored.
        # pd_2cq: exactly 2 CQs restored (multi-CQ-per-ufile dispatch
        #         coverage; comp_vector axis is the holder's
        #         responsibility -- mlx5 hosts typically have
        #         num_comp_vectors >= 2 so the clamp is a no-op).
        # Both modes defer 0 MRs.
        local min_cq=1
        [[ "$holder_mode" == "pd_2cq" ]] && min_cq=2
        if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\], '"$min_cq"' CQ\(s\) \[skipped 0\]; 0 MR\(s\) deferred' \
            "$DUMPDIR/restore.log"; then
            echo "missing Phase-A pd_cq/pd_2cq summary ($min_cq CQ" \
                 "restored, 0 MR deferred). Either RESTORE_CQ" \
                 "didn't run (kernel under test pre-dates" \
                 "mlx5_ib_restore_cq registration in" \
                 "ib_dev_ops, or the dispatcher hit -EOPNOTSUPP /" \
                 "-EPERM / -EINVAL on the mlx5_ib_restore_cq_req" \
                 "32B blob), or the per-CQ dispatcher mis-keyed" \
                 "the plugin_blob between CQs (pd_2cq only), or" \
                 "the dump-side VFMIG_QUERY_CQ failed silently" \
                 "and emitted N-1 CQs to rdma-uobj.img." >&2
            echo "--- restore log uobj DAG lines ---" >&2
            grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
                echo "(no uobj DAG lines at all)" >&2
            pass_fail "wrong pd_cq/pd_2cq Phase-A counts"
        fi
        echo "RESTORE_PD + RESTORE_CQ x$min_cq (Phase A) dispatched ok"
    fi

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
    # Only fires in pd_mr mode (pd_cq / pd_2cq have no MR or QP and
    # the holder's run_post_restore_checks_pd_cq() does the
    # CQ-survival assertion entirely via the SIGUSR1 status file
    # round-trip checked above).
    if [[ "$holder_mode" == "pd_mr" ]]; then
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
    fi

    # Drain the restored holder so the destination uverbs cdev is
    # released before the next pass tries to take it.
    kill -TERM "$RESTORED_PID" 2>/dev/null || true
    for _ in $(seq 1 30); do
        kill -0 "$RESTORED_PID" 2>/dev/null || break
        sleep 0.1
    done
    echo "pass=$PASS_NAME: PASS"
}

# ---- driver -----------------------------------------------------------
#
# Pass list, in dependency-of-failure order (cheaper / more
# fundamental passes first so a regression surfaces with the
# narrowest possible diagnosis):
#
#   pd_mr_aligned     : baseline. PD + 1 MR (single-page umem). Hits
#                       SAVE_VHCA_STATE -> LOAD_VHCA_STATE ->
#                       RESTORE_PD -> pie RESTORE_MR -> Phase J.
#   pd_mr_unaligned   : multi-page MR regression coverage for the
#                       (instance_key, iova) secondary-index path.
#   pd_cq             : S5a CQ-restore coverage. PD + 1 CQ. Hits
#                       MLX5_IB_METHOD_VFMIG_QUERY_CQ ->
#                       RdmaUobjEntry.plugin_blob -> RESTORE_CQ ->
#                       mlx5_core_adopt_cq. Cheap (no MR / no QP /
#                       no Phase J data path) so a regression in
#                       the per-CQ dispatcher or the 32B
#                       mlx5_ib_restore_cq_req plumbing surfaces
#                       fast and in isolation.
#   pd_2cq            : multi-CQ + multi-comp_vector coverage on top
#                       of pd_cq. Opt-in (UVERBS_CR_RUN_PD_2CQ=1)
#                       since num_comp_vectors >= 2 isn't strictly
#                       guaranteed (but is the common mlx5 case);
#                       gating opt-in keeps the default pass set
#                       portable across hosts.
#
# Each pass is independently gateable via env-var so an operator
# triaging a CQ-only regression on a host where pd_mr Phase J fails
# environmentally (peer not reachable / no usable netdev / etc.)
# can still validate the CQ pipeline in isolation:
#
#   UVERBS_CR_RUN_PD_MR=0  PF=... ./run_vfmig_cr.sh   # CQ only
#   UVERBS_CR_RUN_PD_CQ=0  PF=... ./run_vfmig_cr.sh   # MR only
#   UVERBS_CR_RUN_PD_2CQ=1 PF=... ./run_vfmig_cr.sh   # incl. multi-CQ
#
if [[ "${UVERBS_CR_RUN_PD_MR:-1}" == "1" ]]; then
    run_pass pd_mr_aligned   pd_mr 0
    run_pass pd_mr_unaligned pd_mr 1
else
    echo
    echo "[skip] pd_mr passes disabled by UVERBS_CR_RUN_PD_MR=0."
    echo "       Default is to run; this switch exists for hosts"
    echo "       where Phase J's RDMA-WRITE data-path test can't"
    echo "       run end-to-end (no usable netdev / peer / etc.),"
    echo "       letting the CQ regression coverage land in"
    echo "       isolation."
fi
if [[ "${UVERBS_CR_RUN_PD_CQ:-1}" == "1" ]]; then
    run_pass pd_cq           pd_cq 0
else
    echo
    echo "[skip] pd_cq pass disabled by UVERBS_CR_RUN_PD_CQ=0."
    echo "       Default is to run; this switch exists for kernels"
    echo "       that pre-date the S5 B-series mlx5_ib_restore_cq"
    echo "       registration in mlx5_ib_dev_ops, where a pd_cq"
    echo "       pass would only ever fail with -EOPNOTSUPP."
fi
if [[ "${UVERBS_CR_RUN_PD_2CQ:-0}" == "1" ]]; then
    run_pass pd_2cq          pd_2cq 0
else
    echo
    echo "[skip] pd_2cq pass not enabled (UVERBS_CR_RUN_PD_2CQ=0)."
    echo "       Set UVERBS_CR_RUN_PD_2CQ=1 to add multi-CQ +"
    echo "       multi-comp_vector coverage on a host with"
    echo "       num_comp_vectors >= 2 (the default mlx5 case)."
fi

echo
echo "ALL PASSES OK"
echo "PASS"
exit 0
