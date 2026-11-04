#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# Ping-pong / rollback gate for the rdma_mlx5_vfmig plugin: a process is
# checkpointed and restored back and forth between two VFs of one PF,
# with the VFs recycled in place (no sriov_numvfs teardown between hops).
#
#   gen0: a holder on VF_A is dumped (img0), VF_A is recycled, and img0 is
#     restored onto VF_B (tool LOAD + bind, then criu restore). criu
#     restore must see VF_B as FROM_LOAD and not yet CLAIMED; once it is
#     done QUERY_VF must report VF_B CLAIMED.
#
#   gen1: the restored process is dumped from VF_B (img1). VF_B is left
#     bound, FROM_LOAD and CLAIMED, holding the UUID.
#
#   negative: img1 aimed back at VF_B without recycling it must be
#     refused in Phase A, by both the standalone tool and criu restore,
#     before any restore-mode ucontext is opened (so dmesg gains no
#     "VFMIG_RESTORE ucontext refused"). VF_B's state must be unchanged.
#
#   rollback: the UUID moves from VF_B to the recycled VF_A, and img1 is
#     restored onto VF_A, which must again come up FROM_LOAD and pass the
#     functional check.
#
#   recycle: VF_B, a claimed restored VF, is unbound and recycled; it
#     must come back with from_load=0 claimed=0 restored=0 tracked=0.
#
# Functional checks only (SIGUSR1 -> ibv_query_device -> "OK"), no timing.
#
# Unbinding a restored VF logs "poll_health ... Fatal error 3 detected"
# in dmesg; that is a known kernel issue, not a failure.
#
# Hardware-only; self-skips to PASS when a precondition is missing. Set
# VFMIG_CR_HW=1 to turn a skip into a hard failure, VFMIG_KEEP=1 to keep
# the work dir (images + logs).
#
# Usage:
#   sudo PF=0000:08:00.0 VFMIG_TOOL=/path/to/mlx5_vfmig \
#       test/rdma/run_vfmig_pingpong_cr.sh
#   sudo VF_A=0 VF_B=1 VFMIG_CR_HW=1 PF=... VFMIG_TOOL=... \
#       test/rdma/run_vfmig_pingpong_cr.sh
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
VF_A="${VF_A:-0}"
VF_B="${VF_B:-1}"
WANT_HW="${VFMIG_CR_HW:-auto}"

[[ "$VF_A" != "$VF_B" ]] || { echo "FAIL: VF_A and VF_B must differ" >&2; exit 1; }
NUMVFS=$(( (VF_A > VF_B ? VF_A : VF_B) + 1 ))

WORKDIR="$(mktemp -d /tmp/vfmig-pingpong-XXXXXX)"
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
	if [[ "${VFMIG_KEEP:-0}" == "1" ]]; then
		echo "kept $WORKDIR"
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

# SET_TRACKED needs the VF in a managed DMA-IOMMU domain; on an iommu=pt
# host switch the VF's group to DMA while it is still unbound.
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

vf_bdf()   { readlink "$PF_DEV/virtfn$1" | xargs basename; }
vf_query() { "$VFMIG_TOOL" "$PF" query_vf "$1"; }
vf_field() { vf_query "$1" | sed -nE "s/.* $2=([^ ]+).*/\1/p"; }
restore_refused_count() { dmesg | grep -c 'VFMIG_RESTORE ucontext refused' || true; }

# Each "field=value" must appear in VF $1's query_vf line.
expect_state() {
	local vf="$1" line kv
	shift
	line="$(vf_query "$vf")"
	for kv in "$@"; do
		[[ " $line " == *" $kv "* ]] || die "vf_id=$vf: want $kv, got: $line"
	done
	note "vf_id=$vf: $line"
}

unbind_vf() {
	local bdf
	bdf="$(vf_bdf "$1")"
	[[ -e "/sys/bus/pci/devices/$bdf/driver" ]] && echo "$bdf" >"/sys/bus/pci/devices/$bdf/driver/unbind"
	return 0
}

clear_uuid() {
	local uuid
	uuid="$(vf_field "$1" vf_uuid)"
	[[ -n "$uuid" && "$uuid" != "<unset>" ]] && "$VFMIG_TOOL" "$PF" clear_vf_uuid "$1" "$uuid"
	return 0
}

recycle_slot() {
	unbind_vf "$1"
	clear_uuid "$1"
	"$VFMIG_TOOL" "$PF" recycle_vf "$1"
}

# Make recycled, unbound VF $1 a restore destination for $2 (the UUID).
# No bind, no enable_migratable: the restore tool's LOAD path does both.
stamp_dest() {
	ensure_dma_domain "$(vf_bdf "$1")"
	"$VFMIG_TOOL" "$PF" set_tracked "$1" 1
	"$VFMIG_TOOL" "$PF" set_vf_uuid "$1" "$2"
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

wait_ibdev() {
	local bdf="$1" ib=""
	for _ in $(seq 1 60); do
		ib="$(resolve_vf_ibdev "$bdf" || true)"
		[[ -n "$ib" ]] && { echo "$ib"; return 0; }
		sleep 0.5
	done
	return 1
}

# criu dump pid $1 into image dir $2.
dump_into() {
	local pid="$1" img="$2"
	mkdir -p "$img"
	"$CRIU" dump -t "$pid" -D "$img" -v4 -o dump.log --shell-job -L "$SANDBOX" >/dev/null 2>&1 \
		|| { tail -80 "$img/dump.log" >&2 2>/dev/null || true; die "criu dump failed (see $img/dump.log)"; }
	[[ -s "$img/mlx5_vfmig.img" ]] || die "dump into $img produced no mlx5_vfmig.img"
	grep -qaE 'fini-DUMP drain: claimed_vfs=[0-9]+ records_written=[1-9][0-9]* failed=0' "$img/dump.log" \
		|| { grep -aE 'fini-DUMP drain|vfmig: captured' "$img/dump.log" >&2 || true; die "SAVE drain did not write >=1 record into $img"; }
	note "criu dump of pid=$pid into $(basename "$img") completed"
}

# Restore image $1 (dumped from vf_id=$2) onto unbound, stamped vf_id=$3:
# tool LOAD + bind, criu restore, functional check. Sets RESTORED_PID.
restore_onto() {
	local img="$1" src="$2" dst="$3" bdf flog rlog pidfile func
	bdf="$(vf_bdf "$dst")"
	flog="$img/fw_restore.log"
	rlog="$img/restore.log"
	pidfile="$img/restored.pid"

	"$RESTORE_TOOL" -D "$img" -p "$MLX5_SO" >"$flog" 2>&1 \
		|| { cat "$flog" >&2 || true; die "firmware prerestore of $(basename "$img") onto vf_id=$dst failed"; }
	grep -qaE "vfmig: matched ctxn=[0-9]+ source\(pf=$PF vf_id=$src\) -> dest\(pf=$PF vf_id=$dst vf_bdf=$bdf\)" "$flog" \
		|| { cat "$flog" >&2; die "mapping log did not show source vf_id=$src -> dest vf_id=$dst"; }
	grep -qaE "vfmig: dest vf_id=$dst \(vf_bdf=$bdf\) vf_state=0x0 .*: unbound -> LOAD_VHCA_STATE \+ bind" "$flog" \
		|| { cat "$flog" >&2; die "tool did not decide to LOAD unbound vf_id=$dst"; }
	grep -qaE "vfmig: loaded pf=$PF vf_id=$dst \([0-9]+ bytes\)" "$flog" \
		|| { cat "$flog" >&2; die "LOAD_VHCA_STATE did not run against vf_id=$dst"; }
	wait_ibdev "$bdf" >/dev/null || die "vf_id=$dst ($bdf) has no ibdev after prerestore"
	expect_state "$dst" bound=1 from_load=1 claimed=0

	"$CRIU" restore -D "$img" -v4 -o restore.log -d --pidfile "$pidfile" --shell-job -L "$SANDBOX" \
		>/dev/null 2>&1 || { tail -120 "$rlog" >&2 2>/dev/null || true; die "criu restore of $(basename "$img") failed (see $rlog)"; }
	RESTORED_PID="$(cat "$pidfile" 2>/dev/null || true)"
	[[ -n "$RESTORED_PID" ]] || die "criu restore wrote no pidfile"
	kill -0 "$RESTORED_PID" 2>/dev/null || die "restored process (pid=$RESTORED_PID) is not alive"
	grep -qaE "vfmig: dest vf_id=$dst \(vf_bdf=$bdf\) vf_state=0x3 .*claimed=0.*: came up from LOAD_VHCA_STATE -> skipping LOAD_VHCA_STATE" "$rlog" \
		|| { grep -aE 'vfmig: dest vf_id=' "$rlog" >&2 || true; die "criu restore did not see vf_id=$dst as restored and unclaimed"; }
	grep -qaE 'vfmig: post-restore re-QUERY ctxn=[0-9]+ \((static|dyn)\): bitwise match' "$rlog" \
		|| { grep -aE 'vfmig: post-restore' "$rlog" >&2 || true; die "ucontext replay did not bitwise-verify"; }

	: >"$STATUS"
	kill -USR1 "$RESTORED_PID" 2>/dev/null || die "could not signal restored process"
	func=""
	for _ in $(seq 1 50); do
		func="$(cat "$STATUS" 2>/dev/null || true)"
		[[ -n "$func" && "$func" != "READY" ]] && break
		sleep 0.1
	done
	[[ "$func" == "OK" ]] || die "restored context on vf_id=$dst not functional (status='$func', want OK)"
	note "restored pid=$RESTORED_PID on vf_id=$dst answered ibv_query_device: OK"
	expect_state "$dst" bound=1 from_load=1 claimed=1
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
[[ "$("$VFMIG_TOOL" 2>&1 || true)" == *recycle_vf* ]] \
	|| need_hw "orchestrator CLI '$VFMIG_TOOL' has no recycle_vf (rebuild it from the kernel tree)"
[[ -x "$CRIU" ]]   || need_hw "missing criu at $CRIU (set CRIU=... or build the repo)"
[[ -x "$HOLDER" ]] || need_hw "uverbs_ctx_holder not built ('make -C $HERE')"
command -v systemd-run >/dev/null 2>&1 \
	|| need_hw "systemd-run not found (needed to launch the holder in a clean fd table)"
PF_DEV="/sys/bus/pci/devices/$PF"
[[ -d "$PF_DEV" ]] || need_hw "PF $PF not present ($PF_DEV missing; set PF=...)"
[[ "$(cat "$PF_DEV/sriov_totalvfs" 2>/dev/null || echo 0)" -ge "$NUMVFS" ]] \
	|| need_hw "PF $PF has sriov_totalvfs < $NUMVFS (need VF_A=$VF_A, VF_B=$VF_B)"
[[ -d "$DEV_DIR" ]] || need_hw "$DEV_DIR missing (mlx5_vfmig kernel support not loaded)"

SRIOV_TOUCHED=1
echo 0 >"$PF_DEV/sriov_numvfs"
echo 0 >"$PF_DEV/sriov_drivers_autoprobe"
echo "$NUMVFS" >"$PF_DEV/sriov_numvfs"
[[ "$(vf_query "$VF_A")" == *claimed=* ]] \
	|| need_hw "QUERY_VF reports no claimed= (kernel or CLI predates VF_STATE_CLAIMED)"

VF_UUID="$(cat /proc/sys/kernel/random/uuid)"
note "PF=$PF VF_A=$VF_A VF_B=$VF_B numvfs=$NUMVFS vf_uuid=$VF_UUID"

SANDBOX="$WORKDIR/plugins"
mkdir -p "$SANDBOX"
ln -sf "$MLX5_SO" "$SANDBOX/$(basename "$MLX5_SO")"
STATUS="$WORKDIR/holder.status"

# ---------------------------------------------------------------------------
# gen0: hold a context on VF_A, dump, restore onto VF_B
# ---------------------------------------------------------------------------
sect "gen0: hold a context on vf_id=$VF_A and dump it"
A_BDF="$(vf_bdf "$VF_A")"
ensure_dma_domain "$A_BDF"
"$VFMIG_TOOL" "$PF" set_tracked "$VF_A" 1
"$VFMIG_TOOL" "$PF" enable_migratable "$VF_A"
"$VFMIG_TOOL" "$PF" set_vf_uuid "$VF_A" "$VF_UUID"
echo mlx5_core >"/sys/bus/pci/devices/$A_BDF/driver_override"
echo "$A_BDF" >/sys/bus/pci/drivers/mlx5_core/bind
A_IBDEV="$(wait_ibdev "$A_BDF")" || die "vf_id=$VF_A ibdev did not appear ($A_BDF)"

HLOG="$WORKDIR/holder.log"
systemd-run --scope --quiet --unit="vfmig-pingpong-holder-$$" \
	bash -c "exec </dev/null >'$HLOG' 2>&1; exec '$HOLDER' '$A_IBDEV' '$STATUS'" &
disown "$!" 2>/dev/null || true
for _ in $(seq 1 50); do
	HOLDER_PID="$(pgrep -fx "$HOLDER $A_IBDEV $STATUS" | head -1 || true)"
	[[ -n "$HOLDER_PID" ]] && break
	sleep 0.1
done
[[ -n "$HOLDER_PID" ]] || { cat "$HLOG" >&2 2>/dev/null || true; die "holder did not start"; }
for _ in $(seq 1 50); do
	[[ "$(cat "$STATUS" 2>/dev/null || true)" == "READY" ]] && break
	sleep 0.1
done
[[ "$(cat "$STATUS" 2>/dev/null || true)" == "READY" ]] \
	|| { cat "$HLOG" >&2; die "holder failed to reach READY on $A_IBDEV"; }
note "holder ready (pid=$HOLDER_PID) on $A_IBDEV"
dump_into "$HOLDER_PID" "$WORKDIR/img0"
HOLDER_PID=""

sect "gen0: recycle vf_id=$VF_A, restore img0 onto vf_id=$VF_B"
recycle_slot "$VF_A"
expect_state "$VF_A" restored=0 tracked=0 vf_uuid=\<unset\> bound=0 from_load=0 claimed=0
stamp_dest "$VF_B" "$VF_UUID"
restore_onto "$WORKDIR/img0" "$VF_A" "$VF_B"

# ---------------------------------------------------------------------------
# gen1: dump the restored process from VF_B
# ---------------------------------------------------------------------------
sect "gen1: dump the restored process from vf_id=$VF_B"
dump_into "$RESTORED_PID" "$WORKDIR/img1"
RESTORED_PID=""
expect_state "$VF_B" vf_uuid="$VF_UUID" bound=1 from_load=1 claimed=1

# ---------------------------------------------------------------------------
# negative: img1 back onto the claimed VF_B without recycling it
# ---------------------------------------------------------------------------
sect "negative: img1 onto claimed vf_id=$VF_B (not recycled) must be refused"
B_BDF="$(vf_bdf "$VF_B")"
REFUSED_BEFORE="$(restore_refused_count)"
NLOG="$WORKDIR/neg_tool.log"
if "$RESTORE_TOOL" -D "$WORKDIR/img1" -p "$MLX5_SO" >"$NLOG" 2>&1; then
	cat "$NLOG" >&2
	die "tool restored img1 onto claimed vf_id=$VF_B"
fi
grep -qaE "vfmig: dest vf_id=$VF_B \(vf_bdf=$B_BDF\) vf_state=0xb .*claimed=1.*: came up from LOAD_VHCA_STATE, but a restore already used that LOAD" "$NLOG" \
	|| { cat "$NLOG" >&2; die "tool did not refuse claimed vf_id=$VF_B for the right reason"; }
note "tool refused: $(grep -aoE 'a restore already used that LOAD[^.]*' "$NLOG" | head -1)"

NRLOG="$WORKDIR/img1/neg_restore.log"
if "$CRIU" restore -D "$WORKDIR/img1" -v4 -o neg_restore.log -d --pidfile "$WORKDIR/neg.pid" --shell-job \
	-L "$SANDBOX" >/dev/null 2>&1; then
	RESTORED_PID="$(cat "$WORKDIR/neg.pid" 2>/dev/null || true)"
	die "criu restore restored img1 onto claimed vf_id=$VF_B"
fi
grep -qaE "vfmig: dest vf_id=$VF_B .*: came up from LOAD_VHCA_STATE, but a restore already used that LOAD" "$NRLOG" \
	|| { grep -aE 'vfmig:' "$NRLOG" >&2 || true; die "criu restore did not refuse claimed vf_id=$VF_B in Phase A"; }
note "criu restore refused in Phase A"

[[ "$(restore_refused_count)" == "$REFUSED_BEFORE" ]] \
	|| die "a restore-mode ucontext reached the kernel on vf_id=$VF_B (dmesg 'VFMIG_RESTORE ucontext refused')"
expect_state "$VF_B" vf_uuid="$VF_UUID" bound=1 from_load=1 claimed=1

# ---------------------------------------------------------------------------
# rollback: move the UUID to the recycled VF_A, restore img1 there
# ---------------------------------------------------------------------------
sect "rollback: restore img1 onto recycled vf_id=$VF_A"
clear_uuid "$VF_B"
stamp_dest "$VF_A" "$VF_UUID"
restore_onto "$WORKDIR/img1" "$VF_B" "$VF_A"

# ---------------------------------------------------------------------------
# recycle the claimed restored VF_B
# ---------------------------------------------------------------------------
sect "recycle claimed restored vf_id=$VF_B"
unbind_vf "$VF_B"
"$VFMIG_TOOL" "$PF" recycle_vf "$VF_B"
expect_state "$VF_B" restored=0 tracked=0 vf_uuid=\<unset\> bound=0 from_load=0 claimed=0

echo
echo "PASS"
