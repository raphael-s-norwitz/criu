#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# VF firmware-state round-trip gate for the rdma_mlx5_vfmig plugin's
# SAVE-on-dump path and the standalone mlx5_vfmig_restore_vf tool.
#
# What this validates end to end:
#
#   Dump (SAVE): a `criu dump` of a process holding a uverbs context on
#     a tracked, migration-capable VF triggers the plugin's per-context
#     claim hook, which records the VF in the claimed-VF cache; fini(DUMP)
#     then runs SAVE_VHCA_STATE per claimed VF and writes mlx5_vfmig.img
#     plus one firmware blob per VF into the image dir.
#
#   Restore (LOAD): mlx5_vfmig_restore_vf, pointed at that image dir,
#     dlopens the plugin, reads mlx5_vfmig.img, matches each entry's
#     vf_uuid to a destination VF on this host, and drives
#     LOAD_VHCA_STATE + MARK_RESTORED + bind on it. It does NOT run
#     `criu restore`: restoring the process itself and its RDMA verbs
#     objects (ucontext/PD/CQ/QP/MR) is a separate layer that is not part
#     of this build-up, so this gate stops at "VF firmware loaded, bound,
#     ibdev up".
#
# Two tiers:
#
#   Tier 1 (always runs, no hardware): run mlx5_vfmig_restore_vf against
#     an empty image dir and assert it dlopens the plugin, reads the
#     (missing) image, finds nothing to restore, and exits 0. A real
#     regression gate for the tool + plugin restore plumbing on any host,
#     including one with no VFs provisioned.
#
#   Tier 2 (hardware, self-skips): the real SAVE -> tool LOAD round-trip
#     on a provisioned VF. Needs root, a spare mlx5 PF, the out-of-band
#     mlx5_vfmig orchestrator CLI (the harness plays orchestrator and
#     stamps the per-VF UUID, which criu never does), and the
#     uverbs_ctx_holder. Skips gracefully -- still exits 0 on the tier-1
#     result -- when any precondition is missing (e.g. no VF can be
#     provisioned on this host).
#
# Usage:
#   test/rdma/run_vfmig_roundtrip.sh                       # tier 1 only
#   sudo PF=0000:08:00.0 VFMIG_TOOL=/path/to/mlx5_vfmig \
#       test/rdma/run_vfmig_roundtrip.sh                   # + tier 2
#   sudo VFMIG_ROUNDTRIP_HW=0 test/rdma/run_vfmig_roundtrip.sh  # force tier 1
#
# Exits 0 on PASS (every enabled tier green), non-zero on FAIL.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PLUGIN_DIR="$REPO/plugins/rdma/mlx5_sriov_vfmig"

MLX5_SO="${MLX5_SO:-$PLUGIN_DIR/rdma_mlx5_vfmig_plugin.so}"
RESTORE_TOOL="${RESTORE_TOOL:-$PLUGIN_DIR/mlx5_vfmig_restore_vf}"
HOLDER="$HERE/uverbs_ctx_holder"

# criu: prefer the in-tree build, fall back to an installed one.
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
# auto (default) | 0 (force tier 1 only) | 1 (require tier 2, fail on skip)
WANT_HW="${VFMIG_ROUNDTRIP_HW:-auto}"

WORKDIR="$(mktemp -d /tmp/vfmig-roundtrip-XXXXXX)"
HOLDER_PID=""
SRIOV_TOUCHED=0

die()  { echo "FAIL: $*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }
sect() { printf '\n== %s ==\n' "$*"; }

cleanup() {
	[[ -n "$HOLDER_PID" ]] && kill -KILL "$HOLDER_PID" 2>/dev/null || true
	# Tear the VFs back down if tier 2 provisioned any, and re-enable
	# driver autoprobe we disabled during source provisioning.
	if [[ "$SRIOV_TOUCHED" == "1" ]]; then
		echo 0 >"/sys/bus/pci/devices/$PF/sriov_numvfs" 2>/dev/null || true
		echo 1 >"/sys/bus/pci/devices/$PF/sriov_drivers_autoprobe" 2>/dev/null || true
	fi
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Tier 1: no-hardware tool + plugin restore plumbing.
# ---------------------------------------------------------------------------
sect "Tier 1: no-hardware tool round-trip"

[[ -x "$RESTORE_TOOL" ]] || die "missing $RESTORE_TOOL -- 'make -C $PLUGIN_DIR'"
[[ -f "$MLX5_SO" ]]      || die "missing $MLX5_SO -- 'make -C $PLUGIN_DIR'"

EMPTY="$WORKDIR/empty_img"
mkdir -p "$EMPTY"
T1LOG="$WORKDIR/tier1.log"
if ! "$RESTORE_TOOL" -D "$EMPTY" -p "$MLX5_SO" >"$T1LOG" 2>&1; then
	cat "$T1LOG" >&2 || true
	die "tier1: restore tool returned non-zero on an empty image dir"
fi
grep -qa 'nothing to restore' "$T1LOG" \
	|| { cat "$T1LOG" >&2; die "tier1: tool did not report the empty-image path"; }
grep -qa 'no state entries in image' "$T1LOG" \
	|| { cat "$T1LOG" >&2; die "tier1: plugin did not reach the no-entries restore path"; }
note "tool dlopened the plugin, read the empty image, found nothing to restore"
echo "tier1: PASS"

# ---------------------------------------------------------------------------
# Tier 2: real SAVE (criu dump) -> tool LOAD round-trip on a provisioned VF.
# ---------------------------------------------------------------------------
sect "Tier 2: VF firmware SAVE -> tool LOAD round-trip"

skip_hw() { echo "[skip] tier 2 -- $*"; echo; echo "PASS (tier1)"; exit 0; }
need_hw() {
	# WANT_HW=1 turns a would-be skip into a hard failure.
	[[ "$WANT_HW" == "1" ]] && die "tier 2 required (VFMIG_ROUNDTRIP_HW=1) but $*"
	skip_hw "$*"
}

[[ "$WANT_HW" != "0" ]]            || { echo "[skip] tier 2 -- disabled via VFMIG_ROUNDTRIP_HW=0"; echo; echo "PASS (tier1)"; exit 0; }
[[ "$EUID" -eq 0 ]]                || need_hw "not root (VF provisioning + cdev ioctls need root)"
command -v "$VFMIG_TOOL" >/dev/null 2>&1 \
	|| need_hw "orchestrator CLI '$VFMIG_TOOL' not found (set VFMIG_TOOL=...)"
[[ -x "$CRIU" ]]                   || need_hw "missing criu at $CRIU (set CRIU=... or build the repo)"
[[ -x "$HOLDER" ]]                 || need_hw "uverbs_ctx_holder not built ('make -C $HERE')"
command -v systemd-run >/dev/null 2>&1 \
	|| need_hw "systemd-run not found (needed to launch the holder in a clean fd table)"
PF_DEV="/sys/bus/pci/devices/$PF"
[[ -d "$PF_DEV" ]]                 || need_hw "PF $PF not present ($PF_DEV missing; set PF=...)"
TOTALVFS="$(cat "$PF_DEV/sriov_totalvfs" 2>/dev/null || echo 0)"
[[ "$TOTALVFS" -ge 1 ]]            || need_hw "PF $PF reports sriov_totalvfs=0 (not SR-IOV capable)"
[[ -d "$DEV_DIR" ]]                || need_hw "$DEV_DIR missing (mlx5_vfmig kernel support not loaded)"

SRIOV_NUMVFS="$PF_DEV/sriov_numvfs"
VF_UUID="$(cat /proc/sys/kernel/random/uuid)"
note "PF=$PF totalvfs=$TOTALVFS vf_uuid=$VF_UUID"

# criu has no --disable-plugin; -L overrides the whole plugin dir. Point
# it at a sandbox holding only the mlx5_vfmig plugin so amdgpu_plugin
# (which errors rather than declines on non-AMD hosts for any
# unrecognised /dev mapping) stays out of the dump.
SANDBOX="$WORKDIR/plugins"
mkdir -p "$SANDBOX"
ln -sf "$MLX5_SO" "$SANDBOX/$(basename "$MLX5_SO")"

resolve_vf_ibdev() {
	# echo the ibdev name behind /sys/.../virtfn<vf_id>, or nothing.
	local vf_bdf="$1" ib target
	for ib in /sys/class/infiniband/*; do
		[[ -e "$ib/device" ]] || continue
		target="$(readlink "$ib/device" | xargs basename)"
		[[ "$target" == "$vf_bdf" ]] && { basename "$ib"; return 0; }
	done
	return 1
}

# ---- provision the source VF -------------------------------------------
sect "Tier 2a: provision + bind the source VF"
SRIOV_TOUCHED=1
echo 0 >"$SRIOV_NUMVFS"
echo 0 >"$PF_DEV/sriov_drivers_autoprobe"
echo 1 >"$SRIOV_NUMVFS"
"$VFMIG_TOOL" "$PF" set_tracked 0 1
"$VFMIG_TOOL" "$PF" enable_migratable 0
# The plugin's dump-side capture refuses an all-zeros vf_uuid, and the
# restore-side match keys off vf_uuid, so the harness plays orchestrator
# and stamps a stable identity on the source VF here (and the same one on
# the destination VF below).
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

# ---- launch the holder + dump (SAVE) -----------------------------------
sect "Tier 2b: hold a uverbs context + criu dump (SAVE)"
STATUS="$WORKDIR/holder.status"
HLOG="$WORKDIR/holder.log"
# systemd-run --scope: a bare child would inherit this shell's fds
# (a unix control socket criu refuses to dump).
systemd-run --scope --quiet --unit="vfmig-rt-holder-$$" \
	bash -c "exec </dev/null >'$HLOG' 2>&1; exec '$HOLDER' '$SRC_IBDEV' '$STATUS'" &
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
note "holder ready (pid=$HOLDER_PID) on $SRC_IBDEV"

IMG="$WORKDIR/img"
mkdir -p "$IMG"
"$CRIU" dump -t "$HOLDER_PID" -D "$IMG" -v4 -o dump.log --shell-job -L "$SANDBOX" \
	>/dev/null 2>&1 || { tail -80 "$IMG/dump.log" >&2 2>/dev/null || true; die "criu dump failed (see $IMG/dump.log)"; }
HOLDER_PID=""
note "criu dump completed"

[[ -s "$IMG/mlx5_vfmig.img" ]] || die "dump produced no mlx5_vfmig.img"
BLOB="$IMG/mlx5_vfmig-pf$PF-vf0.blob"
[[ -s "$BLOB" ]] || { ls -la "$IMG" >&2; die "dump produced no non-empty firmware blob ($BLOB)"; }
grep -qaE 'fini-DUMP drain: claimed_vfs=[0-9]+ records_written=[1-9][0-9]* failed=0' "$IMG/dump.log" \
	|| { grep -aE 'fini-DUMP drain|vfmig: captured' "$IMG/dump.log" >&2 || true; die "SAVE drain did not write >=1 record"; }
note "image dir has mlx5_vfmig.img + $(basename "$BLOB") ($(stat -c%s "$BLOB") bytes)"

# CHECKPOINT_DEVICES parked the VF datapath at the freeze point, and
# fini(DUMP) resumed it. Assert both so a regression that drops the
# suspend/resume (and thus snapshots a live datapath, or strands a VF in
# STOP) is caught, not silently tolerated.
grep -qaE 'checkpoint: parked [1-9][0-9]* VF datapath' "$IMG/dump.log" \
	|| { grep -aE 'checkpoint:' "$IMG/dump.log" >&2 || true; die "CHECKPOINT_DEVICES did not park the VF datapath"; }
grep -qaE 'fini-DUMP resume: resumed=[1-9][0-9]* resume_failed=0' "$IMG/dump.log" \
	|| { grep -aE 'fini-DUMP resume' "$IMG/dump.log" >&2 || true; die "fini(DUMP) did not resume the parked VF datapath"; }
note "datapath parked at checkpoint and resumed at fini"

# ---- tear down source, reprovision the destination VF ------------------
sect "Tier 2c: reprovision the destination VF (unbound)"
echo 0 >"$SRIOV_NUMVFS"
sleep 0.5
echo 1 >"$SRIOV_NUMVFS"
# Tracked so QUERY_VF surfaces the stamped vf_uuid to the restore-side
# resolver. Stamp the same UUID the source carried. Deliberately do NOT
# bind or enable_migratable here -- the restore tool's LOAD path drives
# both itself.
"$VFMIG_TOOL" "$PF" set_tracked 0 1
"$VFMIG_TOOL" "$PF" set_vf_uuid 0 "$VF_UUID"
DEST_BDF="$(readlink "$PF_DEV/virtfn0" | xargs basename)"
[[ ! -e "/sys/bus/pci/devices/$DEST_BDF/driver" ]] \
	|| die "destination VF $DEST_BDF is already bound before restore (expected unbound)"
note "destination VF: vf_bdf=$DEST_BDF (unbound; UUID stamped)"

# ---- restore (LOAD) via the standalone tool ----------------------------
sect "Tier 2d: mlx5_vfmig_restore_vf (LOAD + bind)"
RLOG="$WORKDIR/restore.log"
if ! "$RESTORE_TOOL" -D "$IMG" -p "$MLX5_SO" >"$RLOG" 2>&1; then
	cat "$RLOG" >&2 || true
	die "restore tool returned non-zero"
fi
grep -qaE "vfmig: restored VF: vf_uuid=$VF_UUID .* dest_ibdev=[^ ]+ dest_cdev=[^ ]+" "$RLOG" \
	|| { cat "$RLOG" >&2; die "restore tool did not log a completed VF restore for vf_uuid=$VF_UUID"; }
note "$(grep -aoE 'vfmig: restored VF:.*' "$RLOG" | head -1)"

# Independent confirmation the LOAD path actually bound the VF and brought
# its ibdev up (the tool's own success signal is the log line above; this
# checks the resulting kernel state).
[[ -e "/sys/bus/pci/devices/$DEST_BDF/driver" ]] \
	|| die "destination VF $DEST_BDF not bound to a driver after restore"
DEST_IBDEV=""
for _ in $(seq 1 50); do
	DEST_IBDEV="$(resolve_vf_ibdev "$DEST_BDF" || true)"
	[[ -n "$DEST_IBDEV" ]] && break
	sleep 0.1
done
[[ -n "$DEST_IBDEV" ]] || die "destination VF $DEST_BDF has no ibdev after restore"
note "destination VF bound to mlx5_core, ibdev=$DEST_IBDEV up"

echo "tier2: PASS"
echo
echo "PASS"
