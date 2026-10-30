#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# Cross-VF (cross-slot) checkpoint/restore gate for the rdma_mlx5_vfmig
# plugin. This is the sibling of run_vfmig_cr.sh: that harness dumps and
# restores on the *same* VF slot (a rebind); this one dumps a context
# held on SRC_VF and restores it onto a *different* DST_VF of the same
# PF, exercising the kernel's common-IOVA-base change ("every VF reserves
# the same IOVA window") and the plugin's removal of the same-slot
# restriction.
#
# What this validates end to end, on one host:
#
#   dump (SAVE): a process holding a bare uverbs context on the tracked,
#     migration-capable source VF (vf_id=SRC_VF) is `criu dump`ed ->
#     mlx5_vfmig.img + firmware blob + ucontext snapshot. The UUID is
#     stamped on SRC_VF only.
#
#   destination provisioning: SR-IOV is reprovisioned and the checkpoint
#     UUID is stamped on DST_VF *only* (SRC_VF is left a fresh, unstamped
#     VF). This is the critical bit the UUID-first discovery relies on:
#     exactly one VF on the host carries the UUID, so the restore scan
#     cannot reselect the source slot and skip the LOAD.
#
#   firmware prerestore: the standalone mlx5_vfmig_restore_vf tool matches
#     the image's UUID to DST_VF, runs LOAD_VHCA_STATE against DST_VF
#     (asserted via "vfmig: loaded ... vf_id=DST_VF"; NOT a skipped
#     "already bound" shortcut), and binds the destination VF. The
#     source->dest mapping log must show vf_id=SRC_VF -> vf_id=DST_VF.
#
#   context restore: `criu restore` brings the process back on the
#     destination VF; the plugin's init(RESTORE) + OPEN_UVERBS_CDEV +
#     UPDATE_VMA_MAP hooks replay the ucontext and remap the UAR against
#     the DST_VF cdev.
#
#   functional check: SIGUSR1 -> the restored holder re-runs
#     ibv_query_device through the restored context and writes "OK".
#
# Set SRC_VF=N DST_VF=M to pick the slots (defaults 0 -> 1). SRC_VF ==
# DST_VF collapses to the same-slot case and is a useful regression check
# through this same code path (mirrors the kernel harness's SRC==DST).
#
# This gate is hardware-only and needs >= max(SRC_VF,DST_VF)+1 VFs. It
# self-skips to PASS when any precondition is missing, so it is safe to
# run anywhere. Set VFMIG_CR_HW=1 to turn a skip into a hard failure.
#
# Usage:
#   sudo PF=0000:08:00.0 VFMIG_TOOL=/path/to/mlx5_vfmig \
#       test/rdma/run_vfmig_xvf_cr.sh
#   sudo SRC_VF=0 DST_VF=1 VFMIG_CR_HW=1 PF=... VFMIG_TOOL=... \
#       test/rdma/run_vfmig_xvf_cr.sh
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
SRC_VF="${SRC_VF:-0}"
DST_VF="${DST_VF:-1}"
# auto (default) | 1 (require hardware, fail on skip)
WANT_HW="${VFMIG_CR_HW:-auto}"

# Provision enough VFs that both slots exist with stable virtfn indices.
NUMVFS=$(( (SRC_VF > DST_VF ? SRC_VF : DST_VF) + 1 ))

WORKDIR="$(mktemp -d /tmp/vfmig-xvf-XXXXXX)"
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
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

skip_hw() { echo "[skip] $*"; echo; echo "PASS (skipped)"; exit 0; }
need_hw() {
	[[ "$WANT_HW" == "1" ]] && die "hardware run required (VFMIG_CR_HW=1) but $*"
	skip_hw "$*"
}

# SET_TRACKED needs the VF in a managed DMA-IOMMU domain. On a host booted
# with iommu=pt a fresh VF lands in an identity domain and SET_TRACKED
# fails with EOPNOTSUPP; switch the VF's group to DMA while it is still
# unbound (the kernel only allows the change with no driver attached).
ensure_dma_domain() {
	local bdf="$1" type_f="/sys/bus/pci/devices/$1/iommu_group/type" t
	[[ -e "$type_f" ]] || die "VF $bdf has no iommu_group (IOMMU disabled?)"
	t="$(cat "$type_f")"
	case "$t" in
	DMA|DMA-FQ) return 0 ;;
	esac
	echo DMA >"$type_f" 2>/dev/null \
		|| die "VF $bdf iommu_group type is '$t' and could not be set to DMA (boot without iommu=pt)"
	note "VF $bdf iommu_group type $t -> $(cat "$type_f")"
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
[[ "$(cat "$PF_DEV/sriov_totalvfs" 2>/dev/null || echo 0)" -ge "$NUMVFS" ]] \
	|| need_hw "PF $PF has sriov_totalvfs < $NUMVFS (need slots SRC_VF=$SRC_VF, DST_VF=$DST_VF)"
[[ -d "$DEV_DIR" ]] || need_hw "$DEV_DIR missing (mlx5_vfmig kernel support not loaded)"

SRIOV_NUMVFS="$PF_DEV/sriov_numvfs"
VF_UUID="$(cat /proc/sys/kernel/random/uuid)"
note "PF=$PF SRC_VF=$SRC_VF DST_VF=$DST_VF numvfs=$NUMVFS vf_uuid=$VF_UUID"
[[ "$SRC_VF" == "$DST_VF" ]] && note "SRC_VF == DST_VF: same-slot regression run"

# criu has no --disable-plugin; -L overrides the whole plugin dir. Point it
# at a sandbox holding only the mlx5_vfmig plugin so other device plugins
# stay out of the dump/restore.
SANDBOX="$WORKDIR/plugins"
mkdir -p "$SANDBOX"
ln -sf "$MLX5_SO" "$SANDBOX/$(basename "$MLX5_SO")"

# ---------------------------------------------------------------------------
# Provision + bind the source VF (SRC_VF), hold a context, dump (SAVE)
# ---------------------------------------------------------------------------
sect "Provision the source VF (vf_id=$SRC_VF)"
SRIOV_TOUCHED=1
echo 0 >"$SRIOV_NUMVFS"
echo 0 >"$PF_DEV/sriov_drivers_autoprobe"
echo "$NUMVFS" >"$SRIOV_NUMVFS"
SRC_BDF="$(readlink "$PF_DEV/virtfn$SRC_VF" | xargs basename)"
ensure_dma_domain "$SRC_BDF"
"$VFMIG_TOOL" "$PF" set_tracked "$SRC_VF" 1
"$VFMIG_TOOL" "$PF" enable_migratable "$SRC_VF"
# Orchestrator stamps the source identity. Only SRC_VF carries it for now.
"$VFMIG_TOOL" "$PF" set_vf_uuid "$SRC_VF" "$VF_UUID"

echo mlx5_core >"/sys/bus/pci/devices/$SRC_BDF/driver_override"
echo "$SRC_BDF" >/sys/bus/pci/drivers/mlx5_core/bind
SRC_IBDEV=""
for _ in $(seq 1 60); do
	SRC_IBDEV="$(resolve_vf_ibdev "$SRC_BDF" || true)"
	[[ -n "$SRC_IBDEV" ]] && break
	sleep 0.5
done
[[ -n "$SRC_IBDEV" ]] || die "source VF ibdev did not appear (vf_bdf=$SRC_BDF)"
note "source VF: vf_id=$SRC_VF vf_bdf=$SRC_BDF ibdev=$SRC_IBDEV"

sect "Hold a bare uverbs context + criu dump (SAVE)"
STATUS="$WORKDIR/holder.status"
HLOG="$WORKDIR/holder.log"
# systemd-run --scope: a bare child would inherit this shell's fds (a unix
# control socket criu refuses to dump).
systemd-run --scope --quiet --unit="vfmig-xvf-holder-$$" \
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
grep -qaE 'fini-DUMP drain: claimed_vfs=[0-9]+ records_written=[1-9][0-9]* failed=0' "$IMG/dump.log" \
	|| { grep -aE 'fini-DUMP drain|vfmig: captured' "$IMG/dump.log" >&2 || true; die "SAVE drain did not write >=1 record"; }
note "image dir has mlx5_vfmig.img + firmware blob + ucontext snapshot"

# ---------------------------------------------------------------------------
# Reprovision; stamp the UUID on the DESTINATION VF only (DST_VF)
# ---------------------------------------------------------------------------
sect "Provision the destination VF (vf_id=$DST_VF, unbound)"
# Tear everything down and reprovision. Stamp the checkpoint UUID on
# DST_VF *only*: the migrated VF "leaves" the source, and -- critically --
# the restore-side scan matches the first VF carrying the UUID, so leaving
# it on SRC_VF (while that VF stays bound) could reselect the source and
# skip the LOAD. Here SRC_VF comes back as a fresh, unstamped VF.
echo 0 >"$SRIOV_NUMVFS"
sleep 0.5
echo 0 >"$PF_DEV/sriov_drivers_autoprobe"
echo "$NUMVFS" >"$SRIOV_NUMVFS"
DEST_BDF="$(readlink "$PF_DEV/virtfn$DST_VF" | xargs basename)"
ensure_dma_domain "$DEST_BDF"
# Tracked so QUERY_VF surfaces the stamped vf_uuid; stamp only on DST_VF.
# Deliberately do NOT bind or enable_migratable -- the restore tool's LOAD
# path drives both.
"$VFMIG_TOOL" "$PF" set_tracked "$DST_VF" 1
"$VFMIG_TOOL" "$PF" set_vf_uuid "$DST_VF" "$VF_UUID"
[[ ! -e "/sys/bus/pci/devices/$DEST_BDF/driver" ]] \
	|| die "destination VF $DEST_BDF is already bound before prerestore (expected unbound)"
if [[ "$SRC_VF" != "$DST_VF" ]]; then
	SRC_SLOT_BDF="$(readlink "$PF_DEV/virtfn$SRC_VF" | xargs basename)"
	[[ ! -e "/sys/bus/pci/devices/$SRC_SLOT_BDF/driver" ]] \
		|| die "source slot VF $SRC_SLOT_BDF is bound; it must not carry the UUID or be reselected"
	note "source slot vf_id=$SRC_VF (vf_bdf=$SRC_SLOT_BDF) left unbound/unstamped"
fi
note "destination VF: vf_id=$DST_VF vf_bdf=$DEST_BDF (unbound; UUID stamped)"

sect "Firmware prerestore (mlx5_vfmig_restore_vf: LOAD onto DST_VF + bind)"
FLOG="$WORKDIR/fw_restore.log"
if ! "$RESTORE_TOOL" -D "$IMG" -p "$MLX5_SO" >"$FLOG" 2>&1; then
	cat "$FLOG" >&2 || true
	die "firmware prerestore tool returned non-zero"
fi
# The source->dest mapping log must show the cross-slot pairing.
grep -qaE "vfmig: matched ctxn=[0-9]+ source\(pf=$PF vf_id=$SRC_VF\) -> dest\(pf=$PF vf_id=$DST_VF vf_bdf=$DEST_BDF\)" "$FLOG" \
	|| { cat "$FLOG" >&2; die "mapping log did not show source vf_id=$SRC_VF -> dest vf_id=$DST_VF"; }
# A real LOAD must have run against DST_VF -- not a skipped "already bound".
grep -qaE "vfmig: loaded pf=$PF vf_id=$DST_VF \([0-9]+ bytes\)" "$FLOG" \
	|| { cat "$FLOG" >&2; die "LOAD_VHCA_STATE did not run against dest vf_id=$DST_VF"; }
! grep -qaE 'already bound to mlx5_core; skipping LOAD_VHCA_STATE' "$FLOG" \
	|| { cat "$FLOG" >&2; die "restore skipped LOAD (dest already bound) -- UUID likely on the wrong VF"; }
grep -qaE "vfmig: restored VF: vf_uuid=$VF_UUID .*source\(pf=$PF vf_id=$SRC_VF\) -> dest\(pf=$PF vf_id=$DST_VF .* dest_ibdev=[^ ]+ dest_cdev=[^ ]+" "$FLOG" \
	|| { cat "$FLOG" >&2; die "prerestore tool did not complete a cross-slot VF restore"; }
[[ -e "/sys/bus/pci/devices/$DEST_BDF/driver" ]] \
	|| die "destination VF $DEST_BDF not bound after firmware prerestore"
DEST_IBDEV=""
for _ in $(seq 1 50); do
	DEST_IBDEV="$(resolve_vf_ibdev "$DEST_BDF" || true)"
	[[ -n "$DEST_IBDEV" ]] && break
	sleep 0.1
done
[[ -n "$DEST_IBDEV" ]] || die "destination VF $DEST_BDF has no ibdev after prerestore"
note "destination VF bound, ibdev=$DEST_IBDEV up (LOAD ran on vf_id=$DST_VF)"

# ---------------------------------------------------------------------------
# criu restore (context) + functional check
# ---------------------------------------------------------------------------
sect "criu restore (context) onto DST_VF"
RLOG="$IMG/restore.log"
PIDFILE="$WORKDIR/restored.pid"
"$CRIU" restore -D "$IMG" -v4 -o restore.log -d --pidfile "$PIDFILE" --shell-job -L "$SANDBOX" \
	>/dev/null 2>&1 || { tail -120 "$RLOG" >&2 2>/dev/null || true; die "criu restore failed (see $RLOG)"; }
RESTORED_PID="$(cat "$PIDFILE" 2>/dev/null || true)"
[[ -n "$RESTORED_PID" ]] || die "criu restore wrote no pidfile"
kill -0 "$RESTORED_PID" 2>/dev/null || die "restored process (pid=$RESTORED_PID) is not alive"
note "criu restore completed (restored pid=$RESTORED_PID)"

# The restore-side hooks must all have fired against the destination cdev.
grep -qaE 'vfmig: cached ctxn=[0-9]+ .* mode=(static|dyn-UAR) ' "$RLOG" \
	|| { grep -aE 'vfmig:' "$RLOG" >&2 || true; die "Phase B did not cache the ucontext snapshot"; }
grep -qaE 'vfmig: post-restore re-QUERY ctxn=[0-9]+ \((static|dyn)\): bitwise match' "$RLOG" \
	|| { grep -aE 'vfmig: post-restore' "$RLOG" >&2 || true; die "ucontext replay did not bitwise-verify"; }
grep -qaE 'vfmig: open_uverbs_cdev: ctxn=[0-9]+ -> dest_fd=[0-9]+' "$RLOG" \
	|| { grep -aE 'vfmig: open_uverbs_cdev' "$RLOG" >&2 || true; die "OPEN_UVERBS_CDEV hook did not fire"; }
grep -qaE 'vfmig: update_vma_map path=[^ ]+ .* -> dest_fd=[0-9]+' "$RLOG" \
	|| { grep -aE 'vfmig: update_vma_map' "$RLOG" >&2 || true; die "UPDATE_VMA_MAP hook did not remap the UAR"; }
note "restore-side hooks fired: cache + bitwise replay + cdev open + UAR remap"

sect "Functional check (SIGUSR1 -> ibv_query_device on restored context)"
: >"$STATUS"
kill -USR1 "$RESTORED_PID" 2>/dev/null || die "could not signal restored process"
FUNC=""
for _ in $(seq 1 50); do
	FUNC="$(cat "$STATUS" 2>/dev/null || true)"
	[[ -n "$FUNC" && "$FUNC" != "READY" ]] && break
	sleep 0.1
done
[[ "$FUNC" == "OK" ]] || die "restored context not functional (status='$FUNC', want OK)"
note "restored context answered ibv_query_device: OK (now on $DEST_IBDEV, vf_id=$DST_VF)"

echo
echo "PASS"
