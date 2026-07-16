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
VFMIG_TOOL="${VFMIG_TOOL:-/opt/builds/linux/tools/testing/criu_rdma/tools/mlx5_vfmig}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PROG="$HERE/uverbs_ctx_holder"
WORKDIR="$(mktemp -d /tmp/vfmig-cr-XXXXXX)"

SRIOV_NUMVFS="/sys/bus/pci/devices/$PF/sriov_numvfs"

# --- Cross-host datapath barrier (D1/R1) knobs -----------------------
#
# The mlx5_vfmig plugin runs a symmetric in-plugin peer-to-peer barrier
# when it finds a rendezvous descriptor at
# $VFMIG_RZ_DIR/<vf_uuid-hex>.desc. This single-host harness stands in
# for the second host with vfmig_barrier_peer, which speaks the exact
# same wire protocol (plugins/.../vfmig_barrier_wire.h) and completes
# one READY exchange per phase.
#
# UVERBS_CR_BARRIER=1 (default) makes every positive pass run through
# the barrier flow (descriptor present -> SUSPEND(INITIATOR) / D1 /
# SUSPEND(RESPONDER) on dump, RESUME(INITIATOR) after R1 on restore).
# A dedicated legacy pass (PASS_NO_BARRIER=1) forces the descriptor
# absent so the byte-identical fused fallback stays regression-covered
# on every run. Negative (EXPECT_RESTORE_FAIL) passes never arm the
# barrier -- their restore aborts before RESUME_DEVICES_LATE.
UVERBS_CR_BARRIER="${UVERBS_CR_BARRIER:-1}"
BARRIER_PEER="${BARRIER_PEER:-$HERE/vfmig_barrier_peer}"
# Must match plugins/rdma/mlx5_sriov_vfmig/vfmig_internal.h VFMIG_RZ_DIR.
VFMIG_RZ_DIR="${VFMIG_RZ_DIR:-/run/criu-vfmig/rendezvous}"
# Loopback control endpoints: DUT (plugin) vs PEER (stub). Sequential
# passes reuse these; both sides set SO_REUSEADDR.
BARRIER_DUT_EP="${BARRIER_DUT_EP:-127.0.0.1:24601}"
BARRIER_PEER_EP="${BARRIER_PEER_EP:-127.0.0.1:24602}"
BARRIER_TIMEOUT_MS="${BARRIER_TIMEOUT_MS:-15000}"

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
# tools/testing/criu_rdma/design/vf_prerestore_split.md §3.5 for
# the full contract.
PASS_VF_UUID=
DMESG_SINCE_KTIME=
# Per-pass barrier state (set in run_pass when the barrier is armed).
PASS_USE_BARRIER=0
BARRIER_DESC=
BARRIER_SESSION=
BARRIER_PEER_PID=

record_dmesg_mark() {
    DMESG_SINCE_KTIME="$(awk '{print $1}' /proc/uptime)"
}

cleanup() {
    local pidfile p
    # Reap a barrier peer stub and drop the rendezvous descriptor if a
    # pass bailed (pass_fail/exit) mid-barrier.
    if [[ -n "${BARRIER_PEER_PID:-}" ]]; then
        kill "$BARRIER_PEER_PID" 2>/dev/null || true
    fi
    [[ -n "${BARRIER_DESC:-}" ]] && rm -f "$BARRIER_DESC"
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
# manual_prerestore_dest -- drive the destination LOAD lifecycle
# manually, before `criu restore` runs. Stand-in for the future
# `mlx5_vfmig_restore_vf` binary (the dlopen-the-plugin standalone
# binary spec'd in vf_prerestore_split.md §6.1). For Phase 3.1 we
# verify the plugin's soft-fallback branch with an out-of-band CLI
# sequence; Phase 3.2 swaps this for the real binary.
#
# The kernel-UAPI sequence we're reproducing matches the destination
# LOAD lifecycle in include/uapi/linux/mlx5_vfmig.h (also documented
# in vf_prerestore_split.md §3.1, the existing surface):
#
#   1. ENABLE_MIGRATABLE                              (latch: probe)
#   2. SET_TRACKED enable=1                            (already done
#                                                      by reprovision)
#   3. LOAD_VHCA_STATE -- write blob, close fd        (FW resume)
#   4. MARK_RESTORED                                   (sets restored=1)
#   5. driver_override + bind                          (probe applies LOAD)
#
# Steps 1, 3, 4 are mlx5_vfmig CLI verbs; step 5 is sysfs writes.
# After this returns the destination VF is bound, ibdev is up, and
# QUERY_VF.restored == 1 -- exactly the state the plugin's init()
# soft-fallback branch keys off of.
#
# Caller is responsible for calling reprovision_vf_for_restore()
# beforehand (so PASS_DEST_VF_ID is stamped + tracked + sized).
#
#
# Phase 3.2 path: drive the destination LOAD/bind via the
# standalone mlx5_vfmig_restore_vf binary (the prerestore tool
# spec'd in vf_prerestore_split.md §6.1). The binary dlopens
# rdma_mlx5_vfmig_plugin.so, dlsyms mlx5_vfmig_plugin_restore_vf_only,
# and runs the same Phase-A path the plugin's init() would --
# read mlx5_vfmig.img, KS7.3 discovery, LOAD_VHCA_STATE +
# MARK_RESTORED, driver_override + bind, wait for ibdev. In
# other words, this replaces the inline CLI sequence the Phase-3.1
# version of this helper used (enable_migratable + load_vhca_state
# + mark_restored + sysfs writes), with the same effective
# end-state but driven through the binary.
#
# Caller is responsible for calling reprovision_vf_for_restore()
# beforehand (so PASS_DEST_VF_ID is stamped + tracked + sized).
#
# Belt-and-braces: confirm the binary's success by checking the
# driver symlink under /sys -- that's the actual signal
# vfmig_is_vf_bound() in the plugin reads, so checking it here
# catches a regression where the binary returns 0 but the bind
# state isn't quite right (e.g. wait_for_dest_ibdev raced).
#
manual_prerestore_dest() {
    local dest_vf_id="${PASS_DEST_VF_ID:-0}"
    local blob_path="$DUMPDIR/mlx5_vfmig-pf$PF-vf$dest_vf_id.blob"
    local vf_bdf="$VF_BDF_DEST"
    local prerestore_bin="${VFMIG_RESTORE_VF_BIN:-mlx5_vfmig_restore_vf}"

    echo "=== Phase E.5 ($PASS_NAME): prerestore via $prerestore_bin on" \
         "$PF vf_id=$dest_vf_id ==="

    [[ -s "$blob_path" ]] || {
        echo "BUG: prerestore blob $blob_path missing or empty;" \
             "the dump-side capture should have written it" >&2
        echo "image dir contents:" >&2
        ls -la "$DUMPDIR" >&2
        pass_fail "prerestore blob missing"
    }

    # Pre-flight: make sure the binary is on PATH and resolves
    # to a callable executable. A common dev-box trip wire is
    # `make install` not running after a build; the resulting
    # silent fallback to the inline-CLI path would mask the
    # whole point of Phase 3.2.
    command -v "$prerestore_bin" >/dev/null 2>&1 || {
        pass_fail "prerestore binary $prerestore_bin not on PATH;" \
                  "did you run 'make install'?"
    }

    # Drive the prerestore. The binary is verbose by default
    # (info-level on stderr) so the harness log captures the
    # plugin's matching / soft-fallback / LOAD diagnostics
    # alongside the harness's own narrative.
    "$prerestore_bin" -D "$DUMPDIR" || {
        pass_fail "prerestore binary $prerestore_bin failed"
    }

    # Belt-and-braces 1: ibdev surfaced. The binary's
    # vfmig_wait_for_dest_ibdev should already have settled
    # this; if it didn't, the Phase-F criu restore would race
    # and emit a confusing "ibdev not found" error. Confirm
    # here so the failure is attributable to prerestore.
    local ibdev_path ibdev_name="" deadline=$((SECONDS + 5))
    while (( SECONDS < deadline )); do
        for ibdev_path in /sys/bus/pci/devices/$vf_bdf/infiniband/*; do
            [[ -d "$ibdev_path" ]] || continue
            ibdev_name="$(basename "$ibdev_path")"
            break
        done
        [[ -n "$ibdev_name" ]] && break
        sleep 0.1
    done
    [[ -n "$ibdev_name" ]] || {
        pass_fail "prerestore: ibdev did not surface within 5s of binary return"
    }

    # Belt-and-braces 2: confirm the VF is bound to mlx5_core.
    # The plugin's soft-fallback signal is the
    # /sys/bus/pci/devices/<vf_bdf>/driver symlink (the kernel's
    # QUERY_VF.restored bit is consumed at probe time and isn't
    # queryable post-bind -- see vfmig_is_vf_bound() in
    # vfmig_restore.c). If the binary returned 0 but the symlink
    # isn't present, the plugin's init() would mistakenly take
    # the monolithic path on the next criu restore and the smoke
    # would silently pass via that branch -- this assertion
    # catches that regression early.
    local driver_link="/sys/bus/pci/devices/$vf_bdf/driver"
    [[ -e "$driver_link" ]] || {
        echo "BUG: $driver_link missing post-binary; the plugin's" \
             "soft-fallback signal won't fire and the smoke will" \
             "silently take the monolithic path" >&2
        pass_fail "prerestore: VF not bound after binary returned"
    }

    echo "prerestore complete:" \
         "vf_id=$dest_vf_id vf_bdf=$vf_bdf ibdev=$ibdev_name" \
         "(driver symlink present, plugin should soft-fallback)"
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
# --- Barrier helpers -------------------------------------------------
#
# The descriptor is keyed by the raw 16-byte VF UUID rendered as 32 hex
# chars -- i.e. PASS_VF_UUID with the hyphens stripped, which is exactly
# what the plugin's uuid_to_hex() produces. Written once before dump and
# left in place: the plugin reads it again on restore (ensure_p2p at
# bind + the RESUME_DEVICES_LATE hook), all keyed off the same UUID.
barrier_desc_path() {
    local hex="${PASS_VF_UUID//-/}"
    echo "$VFMIG_RZ_DIR/$hex.desc"
}

barrier_write_desc() {
    BARRIER_DESC="$(barrier_desc_path)"
    BARRIER_SESSION="vfmig-cr-$$-$PASS_NAME"
    mkdir -p "$VFMIG_RZ_DIR"
    cat >"$BARRIER_DESC" <<EOF
session=$BARRIER_SESSION
vf_uuid=${PASS_VF_UUID//-/}
listen=$BARRIER_DUT_EP
peer=$BARRIER_PEER_EP
timeout_ms=$BARRIER_TIMEOUT_MS
retry_ms=200
EOF
    echo "barrier: wrote rendezvous descriptor $BARRIER_DESC" \
         "(session=$BARRIER_SESSION dut=$BARRIER_DUT_EP peer=$BARRIER_PEER_EP)"
    sed 's/^/  desc| /' "$BARRIER_DESC"
}

# Launch the stand-in peer for one phase (D1 on dump, R1 on restore).
# The stub is the mirror endpoint: it listens on the DUT's peer= and
# targets the DUT's listen=, so the shared tie-break yields exactly one
# connection. Runs concurrently with criu; reaped by barrier_wait_peer.
barrier_start_peer() {
    local phase="$1"
    "$BARRIER_PEER" \
        --listen "$BARRIER_PEER_EP" \
        --peer "$BARRIER_DUT_EP" \
        --session "$BARRIER_SESSION" \
        --phase "$phase" \
        --timeout-ms "$BARRIER_TIMEOUT_MS" \
        >"$PASS_DIR/barrier_peer_$phase.log" 2>&1 &
    BARRIER_PEER_PID=$!
    echo "barrier: started peer stub for $phase (pid=$BARRIER_PEER_PID)"
}

barrier_wait_peer() {
    local phase="$1" rc=0
    [[ -n "$BARRIER_PEER_PID" ]] || return 0
    wait "$BARRIER_PEER_PID" || rc=$?
    BARRIER_PEER_PID=
    if [[ "$rc" != "0" ]]; then
        echo "FAIL ($PASS_NAME): barrier peer stub for $phase exited rc=$rc" \
             "-- the plugin's $phase rendezvous did not complete" >&2
        sed 's/^/  peer| /' "$PASS_DIR/barrier_peer_$phase.log" >&2 || true
        pass_fail "barrier $phase rendezvous failed"
    fi
    echo "barrier: $phase rendezvous OK"
    sed 's/^/  peer| /' "$PASS_DIR/barrier_peer_$phase.log" || true
}

# Kill a still-running stub and drop the descriptor. Safe to call
# unconditionally at pass teardown.
barrier_teardown() {
    if [[ -n "$BARRIER_PEER_PID" ]]; then
        kill "$BARRIER_PEER_PID" 2>/dev/null || true
        wait "$BARRIER_PEER_PID" 2>/dev/null || true
        BARRIER_PEER_PID=
    fi
    [[ -n "$BARRIER_DESC" ]] && rm -f "$BARRIER_DESC"
    BARRIER_DESC=
}

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

    # Resolve barrier mode for this pass. Armed by default (the new
    # flow), but never for the negative refuse passes (restore aborts
    # before RESUME_DEVICES_LATE, so there is no R1 to complete) and
    # never when PASS_NO_BARRIER=1 forces the legacy fused fallback.
    PASS_USE_BARRIER=0
    BARRIER_DESC=
    BARRIER_SESSION=
    BARRIER_PEER_PID=
    if [[ "$UVERBS_CR_BARRIER" == "1" && \
          "${EXPECT_RESTORE_FAIL:-0}" != "1" && \
          "${PASS_NO_BARRIER:-0}" != "1" ]]; then
        [[ -x "$BARRIER_PEER" ]] || {
            echo "FAIL ($PASS_NAME): barrier armed but missing" \
                 "$BARRIER_PEER -- 'make -C $HERE' (or set" \
                 "UVERBS_CR_BARRIER=0)" >&2
            exit 1
        }
        PASS_USE_BARRIER=1
        echo "barrier: ARMED for pass=$PASS_NAME"
    else
        echo "barrier: not armed for pass=$PASS_NAME (legacy fused path)"
    fi

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
    # Arm the D1 barrier: write the descriptor (consumed by the plugin
    # on both dump and restore) and launch the stand-in peer so the
    # plugin's CHECKPOINT_DEVICES rendezvous has someone to complete
    # against. The stub retries/accepts until the plugin's endpoint is
    # up, so launch order vs criu is not load-bearing.
    if [[ "$PASS_USE_BARRIER" == "1" ]]; then
        barrier_write_desc
        barrier_start_peer D1
    fi
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
        # tools/testing/criu_rdma/uobject_restore/{qp,cq,mr}_
        # destroy_matrix harnesses). The CRIU plugin's per-QP
        # dump hook no longer refuses on meta.devx_uid != 0 or
        # on lib_uar_dyn=true; the v0 critical path (default
        # libmlx5 auto-DEVX source) round-trips cleanly. See
        # tools/testing/criu_rdma/design/pd_registration_wipe.md
        # for the full architectural argument.
        pass_fail "criu dump failed"
    }
    if kill -0 "$HOLDER_PID" 2>/dev/null; then
        echo "BUG: holder still alive after dump" >&2
        pass_fail "holder alive after dump"
    fi
    echo "dump OK; image dir contents:"
    ls -la "$DUMPDIR" | sed 's/^/  /'

    # D1 must have completed inside the dump; reap the peer stub and
    # fail the pass if it didn't rendezvous.
    if [[ "$PASS_USE_BARRIER" == "1" ]]; then
        barrier_wait_peer D1
    fi

    # ---- Phase D + E: teardown + reprovision --------------------------
    reprovision_vf_for_restore

    # ---- Phase E.5: optional manual prerestore (Phase 3.1
    # stand-in for the eventual mlx5_vfmig_restore_vf binary).
    # Drives the destination LOAD/bind out-of-band BEFORE criu
    # restore, so the plugin's init() should see restored=1
    # from QUERY_VF and take the soft-fallback branch. Gated
    # on PASS_PRERESTORE so the default (monolithic) path
    # remains the well-tested one for every other pass.
    if [[ "${PASS_PRERESTORE:-0}" == "1" ]]; then
        manual_prerestore_dest
    fi

    # ---- Phase F: criu restore ----------------------------------------
    # Arm the R1 barrier: the descriptor is already on disk from the
    # dump side (same VF UUID), and the plugin parks the initiator at
    # bind (ensure_p2p) then runs the R1 rendezvous in
    # RESUME_DEVICES_LATE before RESUME(INITIATOR). Launch the peer so
    # that late hook completes.
    if [[ "$PASS_USE_BARRIER" == "1" ]]; then
        barrier_start_peer R1
    fi
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

    # Restore succeeded => the RESUME_DEVICES_LATE R1 rendezvous must
    # have completed. Reap the peer stub and confirm.
    if [[ "$PASS_USE_BARRIER" == "1" ]]; then
        barrier_wait_peer R1
    fi

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

    # Soft-fallback path assertion (vf_prerestore_split.md §6.4):
    # the plugin's init() always emits exactly one of two
    # operator-readable status lines per VF, identifying which
    # path drove the LOAD_VHCA_STATE step:
    #
    #   PASS_PRERESTORE=1  (manual prerestore drove LOAD before
    #                       criu restore via the harness CLI
    #                       sequence in manual_prerestore_dest):
    #     "prerestore detected; skipping LOAD_VHCA_STATE"
    #
    #   PASS_PRERESTORE=0  (the default for every other pass --
    #                       no prerestore was run, plugin's init()
    #                       drives LOAD inline):
    #     "prerestore was NOT run; applying LOAD_VHCA_STATE in-line"
    #
    # The two log lines are mutually exclusive per VF; asserting
    # both directions catches a regression where the plugin
    # silently flips the branch (e.g. a stale `restored` cache
    # from QUERY_VF, or a typo'd `if (dest_restored)` ->
    # `if (!dest_restored)`).
    local prerestore_re prerestore_label antimatch_re
    if [[ "${PASS_PRERESTORE:-0}" == "1" ]]; then
        # Tolerate the optional "(vf_bdf=...)" diagnostic clause the
        # plugin emits between "detected" and "; skipping ...".
        prerestore_re='vfmig: VF dest_vf_id=[0-9]+: prerestore detected[^;]*; skipping LOAD_VHCA_STATE'
        antimatch_re='vfmig: VF dest_vf_id=[0-9]+: prerestore was NOT run'
        prerestore_label="prerestore detected (LOAD skipped)"
    else
        # Same -- tolerate the "(vf_bdf=... unbound)" clause between
        # "NOT run" and "; applying ...".
        prerestore_re='vfmig: VF dest_vf_id=[0-9]+: prerestore was NOT run[^;]*; applying LOAD_VHCA_STATE in-line'
        antimatch_re='vfmig: VF dest_vf_id=[0-9]+: prerestore detected'
        prerestore_label="monolithic fallback (LOAD applied in-line)"
    fi
    if ! grep -qE "$prerestore_re" "$DUMPDIR/restore.log"; then
        echo "FAIL ($PASS_NAME): expected the soft-fallback log" \
             "line for the $prerestore_label path" \
             "(PASS_PRERESTORE=${PASS_PRERESTORE:-0}) but" \
             "restore.log is missing it. Either the plugin's" \
             "init() flipped the branch or the bind-state signal" \
             "vfmig_is_vf_bound() reads doesn't match the" \
             "harness's pre-restore state." >&2
        echo "--- restore log soft-fallback lines ---" >&2
        grep -E 'vfmig: VF dest_vf_id=' "$DUMPDIR/restore.log" >&2 \
            || echo "(no soft-fallback lines at all)" >&2
        pass_fail "soft-fallback log line missing"
    fi
    if grep -qE "$antimatch_re" "$DUMPDIR/restore.log"; then
        echo "FAIL ($PASS_NAME): expected ONLY the" \
             "$prerestore_label log line but restore.log also" \
             "carries the *other* path's line. The two lines" \
             "are mutually exclusive per VF; both firing means" \
             "either the plugin's init() ran the soft-fallback" \
             "branch twice, or the test harness left a VF in a" \
             "weird state where one VF saw restored=1 and" \
             "another saw restored=0." >&2
        echo "--- restore log soft-fallback lines ---" >&2
        grep -E 'vfmig: VF dest_vf_id=' "$DUMPDIR/restore.log" >&2
        pass_fail "soft-fallback path branched both ways"
    fi
    echo "soft-fallback: $prerestore_label confirmed via restore.log"

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
    barrier_teardown
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
#   pd_cq_prerestore  : Phase 3.1 soft-fallback coverage. Same
#                       holder geometry as pd_cq, but the harness
#                       drives the destination LOAD_VHCA_STATE +
#                       MARK_RESTORED + bind sequence manually
#                       (via the mlx5_vfmig CLI) BEFORE criu
#                       restore runs -- a stand-in for the
#                       eventual mlx5_vfmig_restore_vf binary
#                       spec'd in vf_prerestore_split.md §6.1.
#                       Plugin's init() detects the bound VF via
#                       vfmig_is_vf_bound() (sysfs driver-symlink
#                       check; QUERY_VF.restored is consumed at
#                       probe time so it's useless post-bind --
#                       see vfmig_restore.c) and takes the
#                       soft-fallback branch (§6.3 + §6.4):
#                       skips its own LOAD/bind, only resolves
#                       the runtime tuple (vf_bdf / ibdev /
#                       cdev_path). The "prerestore detected;
#                       skipping LOAD_VHCA_STATE" status line in
#                       restore.log is the operator-readable
#                       confirmation. The default monolithic-path
#                       counterpart ("prerestore was NOT run;
#                       applying LOAD_VHCA_STATE in-line") is
#                       asserted on every other positive pass --
#                       both sides of the soft-fallback branch
#                       run on every smoke invocation.
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
#   UVERBS_CR_RUN_PRERESTORE=0 PF=... ./run_vfmig_cr.sh # no soft-fallback pass
#   UVERBS_CR_BARRIER=0      PF=... ./run_vfmig_cr.sh   # legacy fused path only
#   UVERBS_CR_RUN_LEGACY=0   PF=... ./run_vfmig_cr.sh   # drop the legacy pass
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
# Dedicated legacy (fused suspend/resume) regression. Forces the
# rendezvous descriptor absent (PASS_NO_BARRIER=1) so the plugin takes
# the byte-identical non-barrier fallback -- the single-host / non-CRIU
# contract the barrier work promised not to disturb. Only meaningful
# when the barrier is otherwise armed by default; with
# UVERBS_CR_BARRIER=0 every pass is already legacy, so this is skipped.
if [[ "$UVERBS_CR_BARRIER" == "1" && "${UVERBS_CR_RUN_LEGACY:-1}" == "1" ]]; then
    PASS_NO_BARRIER=1 run_pass pd_cq_legacy pd_cq 0
elif [[ "$UVERBS_CR_BARRIER" != "1" ]]; then
    echo
    echo "[skip] dedicated legacy pass -- barrier already disabled"
    echo "       globally (UVERBS_CR_BARRIER=0), so every pass exercises"
    echo "       the fused fallback."
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
if [[ "${UVERBS_CR_RUN_PRERESTORE:-1}" == "1" ]]; then
    # Phase 3.1 soft-fallback coverage. Two passes:
    #
    #   pd_cq_prerestore  : the harness drives LOAD_VHCA_STATE +
    #                       MARK_RESTORED + bind manually (via the
    #                       mlx5_vfmig CLI) BEFORE criu restore
    #                       runs. Stand-in for the eventual
    #                       mlx5_vfmig_restore_vf binary spec'd in
    #                       vf_prerestore_split.md §6.1. Plugin's
    #                       init() must detect the bound VF via
    #                       vfmig_is_vf_bound() (sysfs driver
    #                       symlink check; QUERY_VF.restored is
    #                       consumed at probe time and unusable
    #                       post-bind), log "prerestore detected
    #                       ...; skipping LOAD_VHCA_STATE" (§6.4),
    #                       and skip its own LOAD/bind -- only
    #                       resolving the runtime tuple (vf_bdf /
    #                       ibdev / cdev_path).
    #                       PASS_PRERESTORE=1 drives the manual
    #                       prerestore step; the soft-fallback log
    #                       assertion in run_pass keys off the
    #                       expected match line.
    #
    #                       The default monolithic-path log line
    #                       ("prerestore was NOT run; applying
    #                       LOAD_VHCA_STATE in-line") is asserted
    #                       on every other pass via the same
    #                       run_pass machinery -- both sides of
    #                       the soft-fallback branch are exercised
    #                       on every test run, not just the new
    #                       prerestore pass. That symmetry catches
    #                       a regression where the plugin flips
    #                       both branches into one or silently
    #                       loses one of the log lines.
    PASS_PRERESTORE=1 run_pass pd_cq_prerestore pd_cq 0
else
    echo
    echo "[skip] prerestore-soft-fallback pass disabled by"
    echo "       UVERBS_CR_RUN_PRERESTORE=0. Disable only on"
    echo "       hosts/kernels that can't drive the manual"
    echo "       LOAD_VHCA_STATE + MARK_RESTORED + bind sequence"
    echo "       via the mlx5_vfmig CLI (e.g. pre-KS7.3 kernel)."
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
