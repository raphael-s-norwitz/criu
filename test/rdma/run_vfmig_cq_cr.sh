#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# Per-CQ checkpoint/restore gate for the rdma_mlx5_vfmig plugin. This is
# the CQ sibling of run_vfmig_mr_cr.sh: the holder creates a completion
# queue (HOLDER_ALLOC_CQ=1, which needs no PD), so the dump captures and
# restore reinstalls a standalone CQ uobject.
#
# What this validates end to end, on one host, same VF slot (a rebind
# rather than a true migration):
#
#   dump (SAVE): `criu dump` of a process holding a uverbs context + CQ
#     on a tracked, migration-capable VF. Unlike an MR (captured by core's
#     generic QUERY_MR), a CQ carries driver-private state NLDEV cannot
#     express -- the FW cqn, the CQE-ring / doorbell source VAs, cqe_size
#     -- so it is captured via the RDMA_DUMP_UOBJ_CQ hook (QUERY_CQ into a
#     32-byte mlx5_ib_restore_cq_req plugin_blob, plus comp_vector/flags).
#
#   firmware prerestore: the standalone mlx5_vfmig_restore_vf tool loads
#     the VF firmware and binds the destination VF (the prerestore
#     contract `criu restore` assumes).
#
#   context + CQ restore: `criu restore` brings the process back. After
#     the ucontext is replayed (OPEN_UVERBS_CDEV), core's uobj DAG defers
#     RESTORE_CQ to the pie restorer (mlx5's RESTORE_CQ pins the source
#     CQE-ring / doorbell pages against the restored address space, so --
#     like RESTORE_MR -- it must run after the VMA pass; the
#     RDMA_RESTORE_UOBJ_CQ_NEEDS_PIE hook opts it in). The
#     RDMA_RESTORE_UOBJ_CQ_UHW_PACK hook reshapes the plugin_blob into the
#     verb's UHW so the kernel adopts the source FW cqn (preserved across
#     LOAD_VHCA_STATE) without CREATE_CQ.
#
#   functional check: the restored holder is signalled (SIGUSR1) to poll
#     the restored CQ (ibv_poll_cq walks the mmap'd ring) and then
#     ibv_destroy_cq it -- destroy resolves the CQ by its ufile handle, so
#     success proves the CQ came back as a live kernel object at the same
#     handle, not just that the process resumed.
#
# This gate is hardware-only: a real context C/R needs a provisioned VF.
# It self-skips to PASS when any precondition is missing (no root, no
# spare PF, no mlx5_vfmig support, no orchestrator CLI, ...), so it is
# safe to run on any host. Set VFMIG_CR_HW=1 to turn a skip into a hard
# failure.
#
# Usage:
#   sudo PF=0000:08:00.0 VFMIG_TOOL=/path/to/mlx5_vfmig \
#       test/rdma/run_vfmig_cq_cr.sh
#   sudo VFMIG_CR_HW=1 PF=... VFMIG_TOOL=... test/rdma/run_vfmig_cq_cr.sh
#
# Exits 0 on PASS (or a clean skip), non-zero on FAIL.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PLUGIN_DIR="$REPO/plugins/rdma/mlx5_sriov_vfmig"

MLX5_SO="${MLX5_SO:-$PLUGIN_DIR/rdma_mlx5_vfmig_plugin.so}"
RESTORE_TOOL="${RESTORE_TOOL:-$PLUGIN_DIR/mlx5_vfmig_restore_vf}"
HOLDER="$HERE/uverbs_ctx_holder"

if [[ -n "${CRIU:-}" ]]; then
	:
elif [[ -x "$REPO/criu/criu" ]]; then
	CRIU="$REPO/criu/criu"
else
	CRIU="/usr/local/sbin/criu"
fi

PF="${PF:-0000:08:00.0}"
VFMIG_TOOL="${VFMIG_TOOL:-mlx5_vfmig}"
DEV_DIR="/dev/mlx5_vfmig"
# auto (default) | 1 (require hardware, fail on skip)
WANT_HW="${VFMIG_CR_HW:-auto}"

WORKDIR="$(mktemp -d /tmp/vfmig-cq-cr-XXXXXX)"
HOLDER_PID=""
RESTORED_PID=""
SRIOV_TOUCHED=0

die()  { echo "FAIL: $*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }
sect() { printf '\n== %s ==\n' "$*"; }

cleanup() {
	[[ -n "$HOLDER_PID" ]]   && kill -KILL "$HOLDER_PID"   2>/dev/null || true
	[[ -n "$RESTORED_PID" ]] && kill -KILL "$RESTORED_PID" 2>/dev/null || true
	if [[ "$SRIOV_TOUCHED" == "1" ]]; then
		echo 0 >"/sys/bus/pci/devices/$PF/sriov_numvfs" 2>/dev/null || true
		echo 1 >"/sys/bus/pci/devices/$PF/sriov_drivers_autoprobe" 2>/dev/null || true
	fi
	# Debug affordance: VFMIG_KEEP=1 preserves the workdir (images + dump.log
	# + restore.log + fw_restore.log + holder.log) for post-mortem.
	if [[ "${VFMIG_KEEP:-0}" == "1" ]]; then
		echo "  [keep] workdir preserved at $WORKDIR" >&2
	else
		rm -rf "$WORKDIR"
	fi
}
trap cleanup EXIT

skip_hw() { echo "[skip] $*"; echo; echo "PASS (skipped)"; exit 0; }
need_hw() {
	[[ "$WANT_HW" == "1" ]] && die "hardware run required (VFMIG_CR_HW=1) but $*"
	skip_hw "$*"
}

resolve_vf_ibdev() {
	local vf_bdf="$1" ib target
	for ib in /sys/class/infiniband/*; do
		[[ -e "$ib/device" ]] || continue
		target="$(readlink "$ib/device" | xargs basename)"
		[[ "$target" == "$vf_bdf" ]] && { basename "$ib"; return 0; }
	done
	return 1
}

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
sect "Preconditions"

[[ -f "$MLX5_SO" ]]  || die "missing $MLX5_SO -- 'make -C $PLUGIN_DIR'"
[[ -x "$RESTORE_TOOL" ]] || die "missing $RESTORE_TOOL -- 'make -C $PLUGIN_DIR'"

[[ "$EUID" -eq 0 ]] || need_hw "not root (VF provisioning + cdev ioctls need root)"
command -v "$VFMIG_TOOL" >/dev/null 2>&1 \
	|| need_hw "orchestrator CLI '$VFMIG_TOOL' not found (set VFMIG_TOOL=...)"
[[ -x "$CRIU" ]]   || need_hw "missing criu at $CRIU (set CRIU=... or build the repo)"
[[ -x "$HOLDER" ]] || need_hw "uverbs_ctx_holder not built ('make -C $HERE')"
command -v systemd-run >/dev/null 2>&1 \
	|| need_hw "systemd-run not found (needed to launch the holder in a clean fd table)"
PF_DEV="/sys/bus/pci/devices/$PF"
[[ -d "$PF_DEV" ]] || need_hw "PF $PF not present ($PF_DEV missing; set PF=...)"
[[ "$(cat "$PF_DEV/sriov_totalvfs" 2>/dev/null || echo 0)" -ge 1 ]] \
	|| need_hw "PF $PF reports sriov_totalvfs=0 (not SR-IOV capable)"
[[ -d "$DEV_DIR" ]] || need_hw "$DEV_DIR missing (mlx5_vfmig kernel support not loaded)"

SRIOV_NUMVFS="$PF_DEV/sriov_numvfs"
VF_UUID="$(cat /proc/sys/kernel/random/uuid)"
note "PF=$PF vf_uuid=$VF_UUID"

# criu has no --disable-plugin; -L overrides the whole plugin dir. Point it
# at a sandbox holding only the mlx5_vfmig plugin so other device plugins
# stay out of the dump/restore.
SANDBOX="$WORKDIR/plugins"
mkdir -p "$SANDBOX"
ln -sf "$MLX5_SO" "$SANDBOX/$(basename "$MLX5_SO")"

# ---------------------------------------------------------------------------
# Provision + bind the source VF, hold a context + CQ, dump (SAVE)
# ---------------------------------------------------------------------------
sect "Provision the source VF"
SRIOV_TOUCHED=1
echo 0 >"$SRIOV_NUMVFS"
echo 0 >"$PF_DEV/sriov_drivers_autoprobe"
echo 1 >"$SRIOV_NUMVFS"
"$VFMIG_TOOL" "$PF" set_tracked 0 1
"$VFMIG_TOOL" "$PF" enable_migratable 0
# The plugin's dump-side capture refuses an all-zeros vf_uuid and the
# restore-side match keys off vf_uuid, so the harness plays orchestrator
# and stamps a stable identity here (and the same one on the destination).
"$VFMIG_TOOL" "$PF" set_vf_uuid 0 "$VF_UUID"

SRC_BDF="$(readlink "$PF_DEV/virtfn0" | xargs basename)"
echo mlx5_core >"/sys/bus/pci/devices/$SRC_BDF/driver_override"
echo "$SRC_BDF" >/sys/bus/pci/drivers/mlx5_core/bind
SRC_IBDEV=""
for _ in $(seq 1 60); do
	SRC_IBDEV="$(resolve_vf_ibdev "$SRC_BDF" || true)"
	[[ -n "$SRC_IBDEV" ]] && break
	sleep 0.5
done
[[ -n "$SRC_IBDEV" ]] || die "source VF ibdev did not appear (vf_bdf=$SRC_BDF)"
note "source VF: vf_bdf=$SRC_BDF ibdev=$SRC_IBDEV"

sect "Hold a uverbs context + CQ + criu dump (SAVE)"
STATUS="$WORKDIR/holder.status"
HLOG="$WORKDIR/holder.log"
# The default libmlx5 ucontext auto-allocates a DEVX uid (devx_uid != 0,
# e.g. uid=2) on every ibv_open_device -- that is the v0 critical path, not
# something to avoid: the CQ is adopted under the (uid=0) destination
# ucontext and RESTORE_UCONTEXT tolerates the devx_uid mismatch.
# systemd-run --scope: a bare child would inherit this shell's fds (a unix
# control socket criu refuses to dump). HOLDER_ALLOC_CQ makes the holder
# create a CQ (no PD needed) so the dump captures an R3UT_CQ uobject.
systemd-run --scope --quiet --unit="vfmig-cq-cr-holder-$$" \
	bash -c "exec </dev/null >'$HLOG' 2>&1; export HOLDER_ALLOC_CQ=1; exec '$HOLDER' '$SRC_IBDEV' '$STATUS'" &
disown "$!" 2>/dev/null || true
for _ in $(seq 1 50); do
	HOLDER_PID="$(pgrep -fx "$HOLDER $SRC_IBDEV $STATUS" | head -1 || true)"
	[[ -n "$HOLDER_PID" ]] && break
	sleep 0.1
done
[[ -n "$HOLDER_PID" ]] || { cat "$HLOG" >&2 2>/dev/null || true; die "holder did not start"; }
for _ in $(seq 1 50); do
	[[ "$(cat "$STATUS" 2>/dev/null || true)" == "READY" ]] && break
	sleep 0.1
done
[[ "$(cat "$STATUS" 2>/dev/null || true)" == "READY" ]] \
	|| { cat "$HLOG" >&2; die "holder failed to reach READY on $SRC_IBDEV"; }
# A created CQ has a non-negative ufile handle; cq=-1 means ibv_create_cq
# was skipped (HOLDER_ALLOC_CQ not honoured).
grep -qaE 'READY .* cq=[0-9]+' "$HLOG" \
	|| { cat "$HLOG" >&2; die "holder did not create a CQ (HOLDER_ALLOC_CQ not honoured?)"; }
note "holder ready (pid=$HOLDER_PID) on $SRC_IBDEV with a CQ"

IMG="$WORKDIR/img"
mkdir -p "$IMG"
"$CRIU" dump -t "$HOLDER_PID" -D "$IMG" -v4 -o dump.log --shell-job -L "$SANDBOX" \
	>/dev/null 2>&1 || { tail -80 "$IMG/dump.log" >&2 2>/dev/null || true; die "criu dump failed (see $IMG/dump.log)"; }
HOLDER_PID=""
note "criu dump completed"

[[ -s "$IMG/mlx5_vfmig.img" ]] || die "dump produced no mlx5_vfmig.img"
grep -qaE 'fini-DUMP drain: claimed_vfs=[0-9]+ records_written=[1-9][0-9]* failed=0' "$IMG/dump.log" \
	|| { grep -aE 'fini-DUMP drain|vfmig: captured' "$IMG/dump.log" >&2 || true; die "SAVE drain did not write >=1 record"; }
# The CQ dump hook must have QUERY_CQ'd the source cqn / cqe_size into the
# entry's plugin_blob (plus comp_vector/flags).
grep -qaE 'vfmig: dump-cq: ibdev=[^ ]+ handle=[0-9]+ cqn=[0-9]+ cqe_size=(64|128)' "$IMG/dump.log" \
	|| { grep -aE 'vfmig: dump-cq|per-CQ dispatch' "$IMG/dump.log" >&2 || true; die "RDMA_DUMP_UOBJ_CQ hook did not capture the CQ"; }
# The uobj DAG summary must report at least one emitted CQ. Only the cq(...)
# counter is constrained -- the pd/qp counters legitimately show dropped>0
# for objects owned by the kernel or other ucontexts, which the walk filters.
grep -qaE 'uobj DAG: ibdev=[^ ]+ .*cq\(emitted=[1-9][0-9]* dropped=[0-9]+\)' "$IMG/dump.log" \
	|| { grep -aE 'uobj DAG: ibdev=' "$IMG/dump.log" >&2 || true; die "uobj DAG did not emit a CQ (QUERY_CQ failed?)"; }
note "image dir has mlx5_vfmig.img + firmware blob + ucontext snapshot + CQ entry"

# ---------------------------------------------------------------------------
# Reprovision the destination VF (same slot), firmware prerestore
# ---------------------------------------------------------------------------
sect "Reprovision the destination VF (same slot, unbound)"
# Tear the source VF down first: the migrated VF "leaves" the source, and it
# guarantees exactly one VF carries VF_UUID so the restore-side scan is
# unambiguous. Same PF, same vf_id -- a same-slot rebind.
echo 0 >"$SRIOV_NUMVFS"
sleep 0.5
echo 0 >"$PF_DEV/sriov_drivers_autoprobe"
echo 1 >"$SRIOV_NUMVFS"
# Tracked so QUERY_VF surfaces the stamped vf_uuid; stamp the same UUID.
# Deliberately do NOT bind or enable_migratable -- the restore tool's LOAD
# path drives both.
"$VFMIG_TOOL" "$PF" set_tracked 0 1
"$VFMIG_TOOL" "$PF" set_vf_uuid 0 "$VF_UUID"
DEST_BDF="$(readlink "$PF_DEV/virtfn0" | xargs basename)"
[[ ! -e "/sys/bus/pci/devices/$DEST_BDF/driver" ]] \
	|| die "destination VF $DEST_BDF is already bound before prerestore (expected unbound)"
note "destination VF: vf_bdf=$DEST_BDF (unbound; UUID stamped)"

sect "Firmware prerestore (mlx5_vfmig_restore_vf: LOAD + bind)"
FLOG="$WORKDIR/fw_restore.log"
if ! "$RESTORE_TOOL" -D "$IMG" -p "$MLX5_SO" >"$FLOG" 2>&1; then
	cat "$FLOG" >&2 || true
	die "firmware prerestore tool returned non-zero"
fi
grep -qaE "vfmig: restored VF: vf_uuid=$VF_UUID .* dest_ibdev=[^ ]+ dest_cdev=[^ ]+" "$FLOG" \
	|| { cat "$FLOG" >&2; die "prerestore tool did not complete a VF restore for vf_uuid=$VF_UUID"; }
[[ -e "/sys/bus/pci/devices/$DEST_BDF/driver" ]] \
	|| die "destination VF $DEST_BDF not bound after firmware prerestore"
DEST_IBDEV=""
for _ in $(seq 1 50); do
	DEST_IBDEV="$(resolve_vf_ibdev "$DEST_BDF" || true)"
	[[ -n "$DEST_IBDEV" ]] && break
	sleep 0.1
done
[[ -n "$DEST_IBDEV" ]] || die "destination VF $DEST_BDF has no ibdev after prerestore"
note "destination VF bound, ibdev=$DEST_IBDEV up (firmware prerestored)"

# ---------------------------------------------------------------------------
# criu restore (context + CQ) + functional check
# ---------------------------------------------------------------------------
sect "criu restore (context + CQ)"
RLOG="$IMG/restore.log"
PIDFILE="$WORKDIR/restored.pid"
# -d daemonizes the restored tree and returns; --pidfile captures its root
# pid; --shell-job matches the dump. init(RESTORE) re-discovers the bound VF
# (skips LOAD), replays the ucontext, then the pie issues RESTORE_CQ after
# the VMA pass.
"$CRIU" restore -D "$IMG" -v4 -o restore.log -d --pidfile "$PIDFILE" --shell-job -L "$SANDBOX" \
	>/dev/null 2>&1 || { tail -120 "$RLOG" >&2 2>/dev/null || true; die "criu restore failed (see $RLOG)"; }
RESTORED_PID="$(cat "$PIDFILE" 2>/dev/null || true)"
[[ -n "$RESTORED_PID" ]] || die "criu restore wrote no pidfile"
kill -0 "$RESTORED_PID" 2>/dev/null || die "restored process (pid=$RESTORED_PID) is not alive"
note "criu restore completed (restored pid=$RESTORED_PID)"

# The ucontext replay must bitwise-verify before the CQ restore.
grep -qaE 'vfmig: post-restore re-QUERY ctxn=[0-9]+ \((static|dyn)\): bitwise match' "$RLOG" \
	|| { grep -aE 'vfmig: post-restore' "$RLOG" >&2 || true; die "ucontext replay did not bitwise-verify"; }
# The CQ is deferred to the pie (NEEDS_PIE), its UHW packed master-side by
# the plugin (cqn/cqe_size from the plugin_blob), then issued in the pie
# post-VMA. There must be NO master-side "RESTORE_CQ handle=.. ok" line.
grep -qaE 'uobj DAG: CQ handle=[0-9]+ queued for pie' "$RLOG" \
	|| { grep -aE 'uobj DAG: CQ' "$RLOG" >&2 || true; die "CQ was not queued for the pie restorer"; }
grep -qaE 'vfmig: RESTORE_CQ_UHW_PACK ufile_handle=[0-9]+ cqn=[0-9]+ cqe_size=(64|128)' "$RLOG" \
	|| { grep -aE 'vfmig: RESTORE_CQ_UHW_PACK|RESTORE_CQ' "$RLOG" >&2 || true; die "RDMA_RESTORE_UOBJ_CQ_UHW_PACK hook did not fire"; }
# The pie's minimal printf renders %x with a leading 0x (ufile_id);
# target_handle/cqe/driver_id are %u (decimal).
grep -qaE 'RDMA: ufile_id=0x[0-9a-f]+ RESTORE_CQ\(target_handle=[0-9]+, cqe=[0-9]+, driver_id=[0-9]+\) ok' "$RLOG" \
	|| { grep -aE 'RESTORE_CQ' "$RLOG" >&2 || true; die "pie RESTORE_CQ did not succeed"; }
note "restore-side path fired: ucontext replay + CQ UHW pack + pie RESTORE_CQ ok"

sect "Functional check (SIGUSR1 -> ibv_poll_cq + ibv_destroy_cq)"
# The restored holder blocks in pause(); SIGUSR1 makes it poll the restored
# CQ (ibv_poll_cq walks the mmap'd ring -- a faulted/garbage ring mapping
# would error or crash; a drained CQ returns 0) and then ibv_destroy_cq it.
# destroy resolves the CQ by its ufile handle, so a pass here proves the CQ
# came back as a live kernel object at the same handle.
: >"$STATUS"
kill -USR1 "$RESTORED_PID" 2>/dev/null || die "could not signal restored process"
FUNC=""
for _ in $(seq 1 50); do
	FUNC="$(cat "$STATUS" 2>/dev/null || true)"
	[[ -n "$FUNC" && "$FUNC" != "READY" ]] && break
	sleep 0.1
done
[[ "$FUNC" == "OK" ]] || die "restored CQ not functional (status='$FUNC', want OK)"
note "restored CQ answered ibv_poll_cq + ibv_destroy_cq: OK"

echo
echo "PASS"
