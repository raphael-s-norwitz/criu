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
# Orchestrator-stamped per-VF UUID (KS7.3). Generated once per pass
# in run_pass and stamped by both provision_vf (source) and
# reprovision_vf_for_restore (destination) via
# `mlx5_vfmig <PF> set_vf_uuid 0 <PASS_VF_UUID>`. The CRIU plugin's
# dump path hard-refuses any VF whose QUERY_VF.vf_uuid is all-zeros,
# and the restore path matches dumped images to destination VFs by
# this UUID -- so the harness has to play the orchestrator role and
# stamp the same UUID on both sides of the cycle. See KS7.3 in
# tools/testing/mlx5_vfmig/design/vf_prerestore_split.md §3.5 for
# the full contract.
PASS_VF_UUID=
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
    # KS7.3: stamp the orchestrator-owned UUID before workload bind.
    # CRIU dump's vfmig_capture_one_vf() reads QUERY_VF.vf_uuid and
    # hard-refuses on all-zeros, so the harness has to play
    # orchestrator and stamp a stable identity here. The same
    # PASS_VF_UUID is re-stamped on the destination VF in
    # reprovision_vf_for_restore() so the restore-side identity
    # match (Phase 2, future work) succeeds.
    [[ -n "$PASS_VF_UUID" ]] || {
        echo "BUG: provision_vf called with empty PASS_VF_UUID" >&2
        exit 1
    }
    "$VFMIG_TOOL" "$PF" set_vf_uuid 0 "$PASS_VF_UUID"
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

#
# reprovision_vf_for_restore -- tear down the source-side VF and
# (re)provision the destination side per the orchestrator-stamp
# knobs:
#
#   PASS_DEST_NUM_VFS    : sriov_numvfs to write on the destination
#                          PF. >=1. Default 1 (degenerate case --
#                          source's vf_id=0 is also the only dest
#                          slot, which is what every pre-Phase-3
#                          smoke pass tested). Set to >=2 to expose
#                          extra empty slots so the cross-slot
#                          positive case can stamp the dest UUID
#                          onto a vf_id != 0 and prove the
#                          restore-side resolver actually keys off
#                          vf_uuid rather than coincidentally
#                          matching by vf_id.
#
#   PASS_DEST_VF_ID      : the vf_id slot to stamp the destination
#                          UUID onto. Default 0. Must be in
#                          [0, PASS_DEST_NUM_VFS).
#
#   PASS_DEST_STAMP_MODE : controls what gets stamped on
#                          PASS_DEST_VF_ID:
#                            match -- stamp PASS_VF_UUID (the same
#                                     UUID the source side stamped
#                                     and the dump captured). The
#                                     restore-side resolver should
#                                     succeed.
#                            none  -- skip set_vf_uuid entirely.
#                                     Models an orchestrator that
#                                     forgot to stamp the
#                                     destination at all. Restore
#                                     must hard-refuse with the
#                                     KS7.3 "no VF on this host has
#                                     vf_uuid=..." error.
#                            wrong -- stamp a freshly-generated
#                                     UUID different from
#                                     PASS_VF_UUID. Models an
#                                     orchestrator that provisioned
#                                     the dest VF for some other
#                                     workload's CRIU image (a
#                                     near-miss). Restore must
#                                     refuse the same way as 'none'
#                                     -- the resolver does first-
#                                     match-wins on exact 16-byte
#                                     UUID compare and tolerates
#                                     no near-misses.
#                          Default match.
#
# All other VFs in [0, PASS_DEST_NUM_VFS) get set_tracked=1 with
# no UUID stamp, so they show up in the resolver's QUERY_VF scan
# as known-but-unowned slots (vf_uuid=all-zeros) -- exactly the
# state a real orchestrator would leave the unrelated slots in.
#
reprovision_vf_for_restore() {
    local num_vfs="${PASS_DEST_NUM_VFS:-1}"
    local dest_vf_id="${PASS_DEST_VF_ID:-0}"
    local stamp_mode="${PASS_DEST_STAMP_MODE:-match}"
    local v stamp_uuid vf_bdf

    [[ -n "$PASS_VF_UUID" ]] || {
        echo "BUG: reprovision_vf_for_restore called with empty PASS_VF_UUID" >&2
        exit 1
    }
    (( num_vfs >= 1 )) || {
        echo "BUG: PASS_DEST_NUM_VFS=$num_vfs must be >= 1" >&2
        exit 1
    }
    (( dest_vf_id >= 0 && dest_vf_id < num_vfs )) || {
        echo "BUG: PASS_DEST_VF_ID=$dest_vf_id must be in" \
             "[0, PASS_DEST_NUM_VFS=$num_vfs)" >&2
        exit 1
    }

    echo "=== Phase D: tear down source VF ==="
    echo 0 >"$SRIOV_NUMVFS"
    sleep 0.5
    echo "=== Phase E: provision destination" \
         "(num_vfs=$num_vfs dest_vf_id=$dest_vf_id" \
         "stamp_mode=$stamp_mode; no bind -- plugin handles it) ==="
    echo "$num_vfs" >"$SRIOV_NUMVFS"

    # set_tracked on every dest slot, not just the one we'll
    # stamp the dest UUID onto. The resolver scans all VFs the
    # cdev exposes and queries each one; tracked=1 is what
    # mlx5_vfmig requires for QUERY_VF to surface the per-VF
    # state at all (including vf_uuid). Leaving the non-target
    # slots tracked=1 + uuid=all-zeros lets us validate the
    # resolver actually skips empty slots and lands on the
    # tagged one rather than first-match-wins'ing the lowest
    # vf_id with tracked=1.
    for ((v = 0; v < num_vfs; v++)); do
        "$VFMIG_TOOL" "$PF" set_tracked "$v" 1
    done

    case "$stamp_mode" in
        match)
            # Standard positive path: stamp the same UUID the
            # source side stamped and the dump captured onto
            # dest_vf_id. The resolver should match this slot.
            "$VFMIG_TOOL" "$PF" set_vf_uuid "$dest_vf_id" "$PASS_VF_UUID"
            ;;
        none)
            # Negative: orchestrator forgot to stamp. Restore
            # must refuse with the KS7.3 "no VF on this host
            # has vf_uuid=..." error. Every dest slot is left
            # vf_uuid=all-zeros from sriov_numvfs reprovision.
            echo "(negative-test: skipping set_vf_uuid on dest;" \
                 "all slots remain vf_uuid=all-zeros)"
            ;;
        wrong)
            # Negative: orchestrator stamped a different UUID
            # (e.g. provisioned the dest VF for a different
            # workload's CRIU image and never released it).
            # Restore must refuse same as 'none' -- the
            # resolver does exact 16-byte UUID compare with no
            # near-miss tolerance. We re-roll a fresh UUID
            # each pass so the restore-log error message
            # carries an obviously-not-the-source UUID; the
            # tail of the test inspects the log to confirm the
            # refuse path fired for the right reason.
            stamp_uuid="$(cat /proc/sys/kernel/random/uuid)"
            "$VFMIG_TOOL" "$PF" set_vf_uuid "$dest_vf_id" "$stamp_uuid"
            echo "(negative-test: dest vf_id=$dest_vf_id stamped" \
                 "with WRONG uuid=$stamp_uuid;" \
                 "expected source uuid=$PASS_VF_UUID)"
            ;;
        *)
            echo "BUG: unknown PASS_DEST_STAMP_MODE=$stamp_mode" \
                 "(want match | none | wrong)" >&2
            exit 1
            ;;
    esac

    # VF_BDF_DEST tracks the BDF behind virtfn$dest_vf_id for
    # diagnostic logging only. The plugin's init(RESTORE) walks
    # the resolver-discovered (pf_bdf, vf_id) tuple itself and
    # owns enable_migratable + driver_override + bind on it; we
    # never touch /sys/bus/pci/.../bind from the harness on the
    # destination side.
    vf_bdf="$(readlink "/sys/bus/pci/devices/$PF/virtfn$dest_vf_id" | xargs basename)"
    VF_BDF_DEST="$vf_bdf"
    for ((v = 0; v < num_vfs; v++)); do
        "$VFMIG_TOOL" "$PF" query_vf "$v"
    done
    echo "destination VFs prepared (focus dest_vf_id=$dest_vf_id" \
         "-> $vf_bdf, no driver bound)"
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
#   pd_cq_qp -- S6b regression coverage: PD + 1 CQ + 1 RC QP
#              advanced through INIT -> RTR -> RTS via self-
#              loopback (peer = own qpn, port 1, GID 0). Exercises:
#                dump-side: MLX5_IB_METHOD_VFMIG_QUERY_QP packs the
#                  64B mlx5_ib_restore_qp_req into the per-QP
#                  RdmaUobjEntry.plugin_blob; CRIU's R3 walker
#                  consumes RDMA_NLDEV_ATTR_RES_{SEND,RECV}_CQN to
#                  emit R3XR_SEND_CQ / R3XR_RECV_CQ xrefs that
#                  resolve to the parent CQ's ufile_handle on the
#                  destination side via the Phase B-prep handle map.
#                restore-side: rdma_prepare_rdma_qps() resolves the
#                  xrefs, calls the plugin's
#                  RDMA_RESTORE_UOBJ_QP_UHW_PACK hook, serialises
#                  into ta->rdma_qps[]. Pie restorer issues
#                  UVERBS_METHOD_RESTORE_QP with the inlined
#                  ibv_qp_cap; the resp_qpn == qpn_hint hard-assert
#                  fires inside restore_rdma_qp().
#              Post-restore acid test asserts qp_num continuity
#              (libibverbs ibv_qp->qp_num cache must match the
#              pre-dump value) and QP/CQ/PD destroyability in
#              dependency order. A regression where RESTORE_QP
#              didn't link the QP into the parent CQ's
#              list_send_qp / list_recv_qp surfaces as
#              ibv_destroy_cq -EBUSY (FW reports CQ has outstanding
#              QPs) after the QP destroy succeeds. The unaligned
#              arg is ignored (no MR geometry).
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

    # KS7.3: one freshly-generated UUID per pass, stamped on both
    # the source VF (provision_vf) and the destination VF
    # (reprovision_vf_for_restore). Reusing one UUID across both
    # roles in a single pass is the correct cross-host orchestrator
    # contract -- the source and destination represent the same
    # logical workload identity even though the underlying PCI VF
    # slot was torn down and recreated between source-bind and
    # destination-bind.
    PASS_VF_UUID="$(cat /proc/sys/kernel/random/uuid)"

    echo
    echo "==============================================="
    echo " pass=$PASS_NAME unaligned=$unaligned vf_uuid=$PASS_VF_UUID"
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
        local rc=$?
        echo "criu dump returned $rc"
        # Historical EXPECTED-FAIL on pd_cq_qp + libmlx5 auto-DEVX
        # was removed (2026-06-04) once the kernel-side gate in
        # mlx5_ib_dealloc_pd (vfmig_restored + 0xef0c8a syndrome
        # tolerance) and the RESTORE_UCONTEXT devx_uid relax
        # landed, plus the empirical confirmation that
        # DESTROY_QP/CQ/MKEY honor cross-uid (kernel
        # tools/testing/mlx5_vfmig/uobject_restore/{qp,cq,mr}_
        # destroy_matrix harnesses). The CRIU plugin's per-QP
        # dump hook no longer refuses on meta.devx_uid != 0 or
        # on lib_uar_dyn=true; the v0 critical path (default
        # libmlx5 auto-DEVX source) round-trips cleanly. See
        # tools/testing/mlx5_vfmig/design/pd_registration_wipe.md
        # for the full architectural argument.
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
    local restore_rc=0
    "$CRIU" restore -D "$DUMPDIR" -v4 -o restore.log -d \
        --pidfile "$RESTORED_PIDFILE" --shell-job $CRIU_LIB_FLAG || restore_rc=$?

    # Negative-test branch (KS7.3 orchestrator-misconfiguration
    # coverage): EXPECT_RESTORE_FAIL=1 means the harness
    # deliberately misconfigured the destination orchestrator
    # stamp and the plugin was supposed to refuse at
    # vfmig_restore_init_all_vfs() with one of two distinct
    # error patterns, selected by EXPECT_RESTORE_FAIL_REASON:
    #
    #   uuid_mismatch  -- "no VF on this host has vf_uuid=..."
    #                     Orchestrator forgot SET_VF_UUID
    #                     entirely, or stamped a different
    #                     UUID on every dest slot
    #                     (PASS_DEST_STAMP_MODE=none|wrong).
    #
    #   slot_misalign  -- "found vf_uuid=... on (pf=...,
    #                     vf_id=Z) but image was dumped from
    #                     vf_id=Y". Orchestrator stamped the
    #                     right UUID but on the wrong slot
    #                     (PASS_DEST_STAMP_MODE=match with
    #                     PASS_DEST_VF_ID != source's vf_id,
    #                     which is always 0 in this harness).
    #                     KS7.3 §3.5.3.1 contract: cross-slot
    #                     LOAD is not supported (kernel's per-
    #                     VF IOVA window + FW E-Switch
    #                     vport_num are both vf_id-keyed) so
    #                     CRIU refuses BEFORE the kernel LOAD
    #                     wire to give the operator a clear
    #                     orchestrator-side error message
    #                     instead of a kernel-side -EINVAL.
    #
    # Two things have to be true regardless of reason: (a)
    # criu restore exited non-zero, and (b) the refuse fired
    # for the *expected* reason -- a restore that failed for
    # an unrelated error (kernel ABI mismatch, plugin .so
    # missing, etc.) shouldn't be interpreted as a passing
    # negative test. The reason-specific grep catches a
    # regression where one refuse path silently degrades into
    # the other (e.g. slot-misalign degrades to UUID-mismatch
    # because the resolver started returning -ENOENT for
    # paired-match instead of plain UUID match).
    if [[ "${EXPECT_RESTORE_FAIL:-0}" == "1" ]]; then
        local reason="${EXPECT_RESTORE_FAIL_REASON:-uuid_mismatch}"
        local expected_re reason_label
        case "$reason" in
            uuid_mismatch)
                # vfmig_restore.c emits this when
                # vfmig_resolve_uuid_to_pf_vf returns -ENOENT.
                expected_re='no VF on this host has vf_uuid='
                reason_label="KS7.3 UUID-mismatch path"
                ;;
            slot_misalign)
                # vfmig_restore.c emits this when the resolver
                # matched a UUID but the matched vf_id != image
                # vf_id (KS7.3 §3.5.3.1 paired-match contract).
                # The match is on the literal "found vf_uuid="
                # token plus "but image was dumped from vf_id=";
                # both phrases come from the
                # vfmig_restore_init_all_vfs() error path and
                # are stable across log-format changes.
                expected_re='found vf_uuid=.* but image was dumped from vf_id='
                reason_label="KS7.3 slot-misalignment path (§3.5.3.1)"
                ;;
            *)
                echo "BUG: unknown EXPECT_RESTORE_FAIL_REASON=$reason" \
                     "(want uuid_mismatch | slot_misalign)" >&2
                pass_fail "harness misconfigured"
                ;;
        esac
        if [[ "$restore_rc" == "0" ]]; then
            echo "FAIL ($PASS_NAME): expected criu restore to refuse" \
                 "via the $reason_label" \
                 "(EXPECT_RESTORE_FAIL=1, EXPECT_RESTORE_FAIL_REASON=$reason)" \
                 "but it succeeded; the harness deliberately" \
                 "misconfigured" \
                 "PASS_DEST_STAMP_MODE=${PASS_DEST_STAMP_MODE:-match}" \
                 "PASS_DEST_VF_ID=${PASS_DEST_VF_ID:-0}" \
                 "so the plugin should have refused inside" \
                 "vfmig_restore_init_all_vfs()." >&2
            # Reap the wrongly-restored process so it doesn't
            # leak into the next pass (or into systemd-run's
            # scope, which we don't own anymore).
            if [[ -s "$RESTORED_PIDFILE" ]]; then
                local rpid
                rpid="$(cat "$RESTORED_PIDFILE")"
                [[ -n "$rpid" ]] && kill -KILL "$rpid" 2>/dev/null || true
            fi
            pass_fail "negative-test refuse path didn't fire"
        fi
        if ! grep -qE "$expected_re" "$DUMPDIR/restore.log"; then
            echo "FAIL ($PASS_NAME): criu restore failed (rc=$restore_rc)" \
                 "but not via the expected $reason_label." \
                 "EXPECT_RESTORE_FAIL=1 +" \
                 "EXPECT_RESTORE_FAIL_REASON=$reason only counts as a" \
                 "passing negative if vfmig_restore_init_all_vfs()" \
                 "emitted the matching orchestrator-misconfigured" \
                 "error (regex: $expected_re) -- otherwise the" \
                 "restore probably broke for an unrelated reason or" \
                 "one refuse path silently degraded into another and" \
                 "the negative coverage is bogus." >&2
            echo "--- restore log resolver / error lines ---" >&2
            grep -E 'vfmig: (matched|no VF on this host|found vf_uuid=)|Error \(vfmig_' \
                "$DUMPDIR/restore.log" >&2 \
                || echo "(no resolver / error lines at all)" >&2
            pass_fail "restore refused but for wrong reason"
        fi
        echo "pass=$PASS_NAME: PASS (negative; restore refused via" \
             "$reason_label, rc=$restore_rc)"
        return 0
    fi

    # Positive path: criu restore must have succeeded.
    [[ "$restore_rc" == "0" ]] || {
        echo "criu restore returned $restore_rc"
        pass_fail "criu restore failed"
    }
    RESTORED_PID="$(cat "$RESTORED_PIDFILE")"
    echo "restored pid=$RESTORED_PID"

    # Multi-VF positive assertion (KS7.3 §3.5.3): when the
    # harness provisioned more than one slot on the
    # destination, the resolver had to iterate past at least
    # one tracked-but-unstamped slot before landing on the
    # one carrying the matching UUID. Confirm the resolver
    # match line names the source's vf_id (always 0 in this
    # harness) on both sides of the arrow -- under the
    # paired-match contract, dest vf_id MUST equal source
    # vf_id, so anything other than "vf_id=0 -> ... vf_id=0"
    # in this assertion line is a regression. Skip in the
    # degenerate PASS_DEST_NUM_VFS=1 case where there's no
    # iteration to validate.
    if (( ${PASS_DEST_NUM_VFS:-1} > 1 )); then
        if ! grep -qE \
            "vfmig: matched ctxn=[0-9]+ source\(pf=[^ ]+ vf_id=0\) -> dest\(pf=[^ ]+ vf_id=0\) by vf_uuid=" \
            "$DUMPDIR/restore.log"; then
            echo "FAIL ($PASS_NAME): multi-VF resolver did not bind" \
                 "to vf_id=0 on the destination; restore.log is" \
                 "missing the expected paired-match line. Either" \
                 "the resolver iterated past vf_id=0 by mistake" \
                 "(possibly returning vf_id=1's all-zeros UUID as" \
                 "a match) or the harness stamped the UUID on the" \
                 "wrong slot." >&2
            echo "--- restore log resolver lines ---" >&2
            grep -E 'vfmig: (matched|no VF on this host|found vf_uuid=)' \
                "$DUMPDIR/restore.log" >&2 \
                || echo "(no resolver lines at all)" >&2
            pass_fail "multi-VF resolver did not pick vf_id=0"
        fi
        echo "multi-VF resolver: source vf_id=0 -> dest vf_id=0" \
             "confirmed (skipped past ${PASS_DEST_NUM_VFS}-1=$((${PASS_DEST_NUM_VFS}-1)) other tracked slot(s))"
    fi

    # Positive RESTORE_{PD,CQ,QP,MR} dispatch assertions (per-ufile
    # DAG summary lines printed by criu/rdma/uobj_restore.c). The
    # mode-agnostic Phase A line shape now has separate columns for
    # master-restored CQs (rxe path) vs. pie-deferred CQs (mlx5
    # path) vs. pie-deferred QPs (mlx5 vfmig only, v0 always pie-
    # deferred via NEEDS_PIE=1), driven by the plugin's per-class
    # NEEDS_PIE opt-in hooks:
    #   "Phase A: restored N PD(s) [skipped M], R CQ(s) [skipped Q]; D CQ(s) + P QP(s) [skipped V] + S MR(s) deferred ..."
    # On mlx5 (NEEDS_PIE registered) R=0 always; D = number of CQs;
    #                                P = number of QPs.
    # On rxe   (no hook)             D=0; R = number of CQs;
    #                                P=0 (no rxe QP coverage yet).
    # MRs are always pie-deferred (S>=1 in pd_mr; S=0 in pd_cq{,_qp}).
    #
    # Mode-specific minima for mlx5:
    #   pd_mr     D=0 P=0 S>=1 : 1 PD, 0 CQ master, 0 deferred, >=1 MR deferred + pie MR ok + Phase J
    #   pd_cq     D=1 P=0 S=0  : 1 PD, 0 CQ master, 1 CQ deferred + pie CQ ok
    #   pd_2cq    D=2 P=0 S=0  : 1 PD, 0 CQ master, 2 CQs deferred + pie CQ x2 ok
    #   pd_cq_qp  D=1 P=1 S=0  : 1 PD, 0 CQ master, 1 CQ + 1 QP deferred + pie CQ + QP ok
    #
    # Mode-agnostic gate first: at least one PD must have been
    # restored. Catches the regression where rdma_restore_uobj_dag_
    # for_ufile() didn't run at all (R3 walker missing, plugin
    # mismatch, ufile_handle dropout etc.).
    if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\], [0-9]+ CQ\(s\) \[skipped [0-9]+\]; [0-9]+ CQ\(s\) \+ [0-9]+ QP\(s\) \[skipped [0-9]+\] \+ [0-9]+ MR\(s\) deferred' \
        "$DUMPDIR/restore.log"; then
        echo "missing Phase-A RESTORE_PD dispatch line" >&2
        grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
            echo "(no uobj DAG lines at all)" >&2
        pass_fail "no RESTORE_PD dispatch"
    fi

    if [[ "$holder_mode" == "pd_mr" ]]; then
        # pd_mr (mlx5): no CQs / QPs at all; >=1 MR deferred to pie.
        if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\], 0 CQ\(s\) \[skipped 0\]; 0 CQ\(s\) \+ 0 QP\(s\) \[skipped 0\] \+ [1-9][0-9]* MR\(s\) deferred' \
            "$DUMPDIR/restore.log"; then
            echo "missing Phase-A pd_mr summary (1+ MR deferred, 0 CQ, 0 QP)" >&2
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
        # Post-MR-refactor log shape (commit "criu/rdma: plugin-shape
        # UHW for RESTORE_MR via PACK/VERIFY hooks"): the pie restorer
        # no longer hard-codes mlx5 mkey_index in its OK line. The
        # driver-private UHW_IN is now plugin-shaped and shipped through
        # rst_rdma_mr.uhw_in_buf, so the OK line carries the generic
        # (driver_id, uhw_in_len) tuple instead. For mlx5 we expect
        # uhw_in=16 (size of struct mlx5_ib_restore_mr_req); for rxe
        # uhw_in=0.
        if ! grep -qE 'pie: [0-9]+: RDMA: ufile_id=[^ ]+ RESTORE_MR\(target_handle=[0-9]+, lkey=[0-9a-fx]+, rkey=[0-9a-fx]+, driver_id=[0-9]+, uhw_in=[0-9]+\) ok' \
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
        echo "RESTORE_PD (Phase A) + RESTORE_MR (plugin UHW pie Phase B) dispatched ok"
    elif [[ "$holder_mode" == "pd_cq" || "$holder_mode" == "pd_2cq" || "$holder_mode" == "pd_cq_qp" ]]; then
        # pd_cq:    exactly 1 CQ deferred.
        # pd_2cq:   exactly 2 CQs deferred (multi-CQ-per-ufile
        #           dispatch coverage; comp_vector axis is the
        #           holder's responsibility -- mlx5 hosts typically
        #           have num_comp_vectors >= 2 so the clamp is a
        #           no-op).
        # pd_cq_qp: 1 CQ + 1 QP deferred. Same pie-deferred shape as
        #           pd_cq with the addition of the QP column. v0
        #           RESTORE_QP requires SEND_CQ + RECV_CQ resolution
        #           through the per-ufile handle map populated when
        #           the CQ row is walked, so the CQ column must
        #           also be present.
        # All modes defer 0 MRs and dispatch the pie-deferred verbs
        # from the pie restorer (mlx5_ib_restore_cq / _qp pin
        # umem against current->mm; only valid in the restored
        # task's mm at sigreturn_restore time).
        local min_cq=1
        local min_qp=0
        case "$holder_mode" in
            pd_2cq)   min_cq=2 ;;
            pd_cq_qp) min_qp=1 ;;
        esac
        if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\], 0 CQ\(s\) \[skipped 0\]; '"$min_cq"' CQ\(s\) \+ '"$min_qp"' QP\(s\) \[skipped 0\] \+ 0 MR\(s\) deferred' \
            "$DUMPDIR/restore.log"; then
            echo "missing Phase-A $holder_mode summary ($min_cq CQ" \
                 "+ $min_qp QP deferred, 0 MR deferred). Either" \
                 "Phase A failed before the CQ/QP count loops, or" \
                 "the dump-side VFMIG_QUERY_{CQ,QP} failed silently" \
                 "and emitted fewer entries than expected to" \
                 "rdma-uobj.img." >&2
            echo "--- restore log uobj DAG lines ---" >&2
            grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
                echo "(no uobj DAG lines at all)" >&2
            pass_fail "wrong $holder_mode Phase-A counts"
        fi
        if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase B-prep: serialised '"$min_cq"' CQ\(s\) \[skipped 0\] for pie restorer' \
            "$DUMPDIR/restore.log"; then
            echo "missing Phase B-prep CQ serialisation ($min_cq CQ)" >&2
            grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
                echo "(no uobj DAG lines at all)" >&2
            pass_fail "no Phase B-prep CQ serialisation"
        fi
        if [[ "$min_qp" -gt 0 ]]; then
            if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase B-prep: serialised '"$min_qp"' QP\(s\) \[skipped 0\] for pie restorer' \
                "$DUMPDIR/restore.log"; then
                echo "missing Phase B-prep QP serialisation ($min_qp QP)" >&2
                grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
                    echo "(no uobj DAG lines at all)" >&2
                pass_fail "no Phase B-prep QP serialisation"
            fi
        fi
        # Pie-side OK line: one per CQ. Catches the regression where
        # the pie blob enters the dispatch loop but the kernel's
        # RESTORE_CQ ioctl returns -EINVAL / -EFAULT / -EOPNOTSUPP
        # (the wire-shape error class we'd want to catch loudly --
        # mlx5_ib_restore_cq registration regression, mlx5_ib_
        # restore_cq_req size mismatch from the plugin's UHW_PACK,
        # or pin_user_pages_fast EFAULT against a non-restoree mm).
        local cq_ok_lines
        cq_ok_lines=$(grep -cE 'pie: [0-9]+: RDMA: ufile_id=[^ ]+ RESTORE_CQ\(target_handle=[0-9]+, cqe=[0-9]+, resp_cqe=[0-9]+, .*driver_id=[0-9]+, uhw_in=[0-9]+, uhw_out=[0-9]+\) ok' \
            "$DUMPDIR/restore.log" || true)
        if [[ "$cq_ok_lines" -lt "$min_cq" ]]; then
            echo "missing pie-restorer RESTORE_CQ ok line(s); saw" \
                 "$cq_ok_lines but expected $min_cq" >&2
            grep -E 'pie:.* RDMA:' "$DUMPDIR/restore.log" >&2 || \
                echo "(no pie RDMA lines at all)" >&2
            pass_fail "no RESTORE_CQ pie-restorer dispatch"
        fi
        if [[ "$min_qp" -gt 0 ]]; then
            local qp_ok_lines
            qp_ok_lines=$(grep -cE 'pie: [0-9]+: RDMA: ufile_id=[^ ]+ RESTORE_QP\(target_handle=[0-9]+, resp_qpn=[0-9]+, type=[0-9]+, state=[0-9]+, driver_id=[0-9]+, uhw_in=[0-9]+, uhw_out=[0-9]+\) ok' \
                "$DUMPDIR/restore.log" || true)
            if [[ "$qp_ok_lines" -lt "$min_qp" ]]; then
                echo "missing pie-restorer RESTORE_QP ok line(s);" \
                     "saw $qp_ok_lines but expected $min_qp" >&2
                grep -E 'pie:.* RDMA:' "$DUMPDIR/restore.log" >&2 || \
                    echo "(no pie RDMA lines at all)" >&2
                pass_fail "no RESTORE_QP pie-restorer dispatch"
            fi
        fi
        if [[ "$min_qp" -gt 0 ]]; then
            echo "RESTORE_PD (Phase A) + RESTORE_CQ x$min_cq + RESTORE_QP x$min_qp (plugin UHW pie Phase B) dispatched ok"
        else
            echo "RESTORE_PD (Phase A) + RESTORE_CQ x$min_cq (plugin UHW pie Phase B) dispatched ok"
        fi
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
#   pd_cq_qp          : S6b QP-restore coverage. PD + 1 CQ + 1 RC QP
#                       advanced through INIT -> RTR -> RTS via
#                       self-loopback. Hits the new MLX5_IB_METHOD_
#                       VFMIG_QUERY_QP -> plugin_blob -> RESTORE_QP
#                       pipeline + send_cqn/recv_cqn NLDEV resolution.
#                       Default-on so a kernel without the S6b
#                       commits surfaces as -EOPNOTSUPP on the very
#                       first run; gate to 0 for kernels that
#                       pre-date S6b.
#   pd_cq_multivf_pos : KS7.3 multi-VF positive coverage. Same
#                       holder geometry as pd_cq, but the harness
#                       provisions sriov_numvfs=2 on the
#                       destination, both slots tracked, with the
#                       matching UUID stamped on vf_id=0 (the
#                       source's slot per the KS7.3 §3.5.3.1
#                       paired-match contract) and vf_id=1 left
#                       tracked-but-unstamped (vf_uuid=all-zeros).
#                       The resolver must iterate, find the
#                       matching UUID on vf_id=0, and bind there.
#                       End-to-end positive: the trivial pd_cq
#                       case (sriov_numvfs=1) doesn't exercise the
#                       resolver's iteration loop at all
#                       (single-slot ⇒ no choice to make), so this
#                       pass is the only place where iteration
#                       coverage in the success direction lives.
#                       Iteration coverage in the failure
#                       direction lives in pd_cq_neg_slot_misalign
#                       below.
#   pd_cq_neg_no_stamp : KS7.3 negative coverage: orchestrator
#                       forgot to stamp the destination at all
#                       (PASS_DEST_STAMP_MODE=none). Restore must
#                       hard-refuse with the "no VF on this host
#                       has vf_uuid=..." error
#                       (EXPECT_RESTORE_FAIL_REASON=uuid_mismatch).
#                       Asserts (a) criu restore exits non-zero,
#                       (b) restore.log carries the matching
#                       refuse error. A passing-positive restore
#                       (or a failing-but-for-wrong-reason
#                       restore) both fail the pass.
#   pd_cq_neg_wrong_stamp : KS7.3 negative coverage: orchestrator
#                       stamped a different UUID on the destination
#                       (PASS_DEST_STAMP_MODE=wrong, near-miss
#                       case). Same expected refuse path as
#                       pd_cq_neg_no_stamp -- the resolver does
#                       exact 16-byte UUID compare with no near-
#                       miss tolerance.
#   pd_cq_neg_slot_misalign : KS7.3 §3.5.3.1 negative coverage:
#                       orchestrator stamped the right UUID but
#                       on the *wrong* slot
#                       (PASS_DEST_NUM_VFS=2, PASS_DEST_VF_ID=1,
#                       PASS_DEST_STAMP_MODE=match). Source ran
#                       on vf_id=0; the resolver finds the UUID
#                       on vf_id=1, then enforces the paired-
#                       match contract (dest vf_id MUST == source
#                       vf_id) and refuses with the *distinct*
#                       slot_misalign error ("found vf_uuid=...
#                       but image was dumped from vf_id=0",
#                       EXPECT_RESTORE_FAIL_REASON=slot_misalign).
#                       The reason-specific assertion catches a
#                       regression where slot-misalign silently
#                       degrades to UUID-mismatch (or vice-versa)
#                       and surfaces the wrong refuse path to the
#                       operator. CRIU emits this BEFORE hitting
#                       the kernel LOAD wire, so the operator
#                       gets a clear orchestrator-side error
#                       instead of a kernel-side -EINVAL with a
#                       vfmig_iova slot-grid warn buried in
#                       dmesg.
#
# Each pass is independently gateable via env-var so an operator
# triaging a CQ-only regression on a host where pd_mr Phase J fails
# environmentally (peer not reachable / no usable netdev / etc.)
# can still validate the CQ pipeline in isolation:
#
#   UVERBS_CR_RUN_PD_MR=0    PF=... ./run_vfmig_cr.sh   # CQ + QP only
#   UVERBS_CR_RUN_PD_CQ=0    PF=... ./run_vfmig_cr.sh   # MR only
#   UVERBS_CR_RUN_PD_CQ_QP=0 PF=... ./run_vfmig_cr.sh   # no QP coverage
#   UVERBS_CR_RUN_PD_2CQ=1   PF=... ./run_vfmig_cr.sh   # incl. multi-CQ
#   UVERBS_CR_RUN_KS7_3=0    PF=... ./run_vfmig_cr.sh   # no KS7.3 coverage
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
if [[ "${UVERBS_CR_RUN_PD_CQ_QP:-1}" == "1" ]]; then
    # S6b QP-restore coverage. PD + 1 CQ + 1 RC QP advanced through
    # INIT -> RTR -> RTS via self-loopback before dump. Hits:
    #   dump-side:   MLX5_IB_METHOD_VFMIG_QUERY_QP packs the 64B
    #                mlx5_ib_restore_qp_req into RdmaUobjEntry.
    #                plugin_blob; NLDEV emits send_cqn / recv_cqn so
    #                the per-ufile handle map resolves to the CQ
    #                ufile_handle on the destination side.
    #   restore-side: rdma_prepare_rdma_qps() walks the per-ufile
    #                pending list, resolves PARENT_PD / SEND_CQ /
    #                RECV_CQ xrefs, calls the plugin's
    #                RDMA_RESTORE_UOBJ_QP_UHW_PACK hook, and
    #                serialises into ta->rdma_qps[]. Pie restorer
    #                issues UVERBS_METHOD_RESTORE_QP from the
    #                restored task's mm at sigreturn_restore time;
    #                the resp_qpn == qpn_hint hard-assert (Step 6
    #                seam) is enforced inside restore_rdma_qp().
    # Post-restore acid test asserts qp_num continuity (libibverbs
    # ibv_qp->qp_num cache must match the pre-dump value), QP/CQ/PD
    # are destroyable in dependency order. A regression where
    # RESTORE_QP didn't register the QP into list_send_qp /
    # list_recv_qp on the parent CQ surfaces as ibv_destroy_cq
    # -EBUSY after the QP destroy succeeds (FW still sees the
    # adopted QP from the CQ side).
    run_pass pd_cq_qp        pd_cq_qp 0
else
    echo
    echo "[skip] pd_cq_qp pass disabled by UVERBS_CR_RUN_PD_CQ_QP=0."
    echo "       Default is to run; this switch exists for kernels"
    echo "       that pre-date the S6b RESTORE_QP series in"
    echo "       mlx5_ib_dev_ops + uverbs dispatcher, where a"
    echo "       pd_cq_qp pass would only ever fail with"
    echo "       -EOPNOTSUPP / -ENOENT on the SEND_CQ NLDEV miss."
fi
if [[ "${UVERBS_CR_RUN_KS7_3:-1}" == "1" ]]; then
    # KS7.3 cross-slot / negative coverage. All three passes share
    # the cheapest holder geometry (pd_cq) -- they exercise the
    # resolver / refuse paths in vfmig_restore_init_all_vfs(),
    # not the per-class restore wire shape, so adding MR or QP
    # state would just burn dump/restore wall-clock for no
    # additional resolver coverage. Keep this block last in the
    # default pass set: a failure here is almost always a
    # regression in the Phase 2 UUID-driven discovery work
    # (vfmig_resolve_uuid_to_pf_vf or its callers in
    # vfmig_restore_init_all_vfs), not a regression in the
    # uverbs dispatcher / FW state machine that the earlier
    # passes cover.

    # Multi-VF positive: source ran on vf_id=0; destination
    # provisions sriov_numvfs=2 with the matching UUID
    # stamped on vf_id=0 and vf_id=1 left as a tracked-but-
    # unstamped slot (vf_uuid=all-zeros). The resolver MUST
    # iterate, see vf_id=0 carries the matching UUID, and
    # bind there. End-to-end positive (the kernel LOAD
    # works because per the KS7.3 §3.5.3.1 contract source
    # vf_id == dest vf_id == 0). The trivial pd_cq case
    # (sriov_numvfs=1) doesn't exercise the resolver's
    # iteration loop -- one slot to choose from = no
    # iteration coverage. The slot-misalign negative test
    # below covers iteration in the failure direction; this
    # pass covers it in the success direction.
    PASS_DEST_NUM_VFS=2 PASS_DEST_VF_ID=0 \
        run_pass pd_cq_multivf_pos    pd_cq 0

    # Negative: orchestrator forgot to call SET_VF_UUID on the
    # destination at all. Every dest slot stays vf_uuid=all-
    # zeros; the resolver must refuse the restore with the
    # KS7.3 "no VF on this host has vf_uuid=..." error
    # (uuid_mismatch reason). EXPECT_RESTORE_FAIL=1 means
    # run_pass treats a successful restore (or a restore
    # that failed for a different reason) as a pass failure,
    # since the negative-coverage value comes specifically
    # from confirming the *refuse path* fired.
    PASS_DEST_STAMP_MODE=none EXPECT_RESTORE_FAIL=1 \
        run_pass pd_cq_neg_no_stamp   pd_cq 0

    # Negative: orchestrator stamped a *different* UUID (e.g.
    # provisioned the destination VF for some other workload's
    # CRIU image and forgot to release it). The resolver does
    # exact 16-byte compare; a near-miss UUID must refuse just
    # like the empty case (uuid_mismatch reason). Catches a
    # regression where the resolver accidentally degrades to
    # fuzzy-match or first-wins (bind to whatever VF is
    # tracked, regardless of UUID).
    PASS_DEST_STAMP_MODE=wrong EXPECT_RESTORE_FAIL=1 \
        run_pass pd_cq_neg_wrong_stamp pd_cq 0

    # Negative: orchestrator stamped the right UUID but on
    # the *wrong* slot. Source ran on vf_id=0; destination
    # provisions sriov_numvfs=2 and stamps the matching UUID
    # on vf_id=1 instead of vf_id=0. The resolver finds the
    # UUID hit on vf_id=1, then enforces the KS7.3 §3.5.3.1
    # paired-match contract (dest vf_id MUST == source vf_id)
    # and refuses with the distinct slot_misalign error
    # ("found vf_uuid=... but image was dumped from vf_id=0").
    # CRIU surfaces this *before* hitting the kernel LOAD
    # wire so the operator gets a clear orchestrator-side
    # error instead of a kernel-side -EINVAL with a vfmig_iova
    # slot-grid warn buried in dmesg.
    PASS_DEST_NUM_VFS=2 PASS_DEST_VF_ID=1 PASS_DEST_STAMP_MODE=match \
        EXPECT_RESTORE_FAIL=1 EXPECT_RESTORE_FAIL_REASON=slot_misalign \
        run_pass pd_cq_neg_slot_misalign pd_cq 0
else
    echo
    echo "[skip] KS7.3 cross-slot/negative passes disabled by"
    echo "       UVERBS_CR_RUN_KS7_3=0. These passes prove the"
    echo "       restore-side resolver actually keys off vf_uuid"
    echo "       (cross-slot positive: stamp dest UUID on vf_id=1"
    echo "       with sriov_numvfs=2; negative cases: missing /"
    echo "       wrong UUID -> hard-refuse). Disable only on"
    echo "       hosts/kernels that can't provision sriov_numvfs>=2."
fi

echo
echo "ALL PASSES OK"
echo "PASS"
exit 0
