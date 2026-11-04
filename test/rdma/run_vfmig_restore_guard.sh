#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# Negative gate for the rdma_mlx5_vfmig plugin's choice of destination
# VF. Restore must LOAD an unbound, clean destination and skip the LOAD
# only on a VF whose current probe came up from LOAD_VHCA_STATE
# (QUERY_VF vf_state BOUND|FROM_LOAD). Every other destination must be
# refused in Phase A, before anything is loaded or replayed -- not left
# for the kernel to reject the restore-mode ucontext in Phase B.
#
# One dump from SRC_VF, then three cases against DST_VF, each from a
# recycled DST_VF stamped with the checkpoint UUID:
#
#   A. bound normally: DST_VF is bound to mlx5_core without a LOAD. The
#      standalone tool and `criu restore` must both refuse it as "bound
#      but did not come up from LOAD_VHCA_STATE", and the kernel must not
#      have logged a refused restore-mode ucontext.
#
#   B. LOAD staged but unbound: a LOAD_VHCA_STATE of the image is staged
#      on DST_VF (restored=1) but the VF is not bound. The tool must
#      refuse rather than LOAD a second time.
#
#   C. restored, then recycled and bound normally: the tool restores
#      DST_VF (bound, from_load=1); it is then unbound, recycled, restamped
#      and bound normally (from_load=0). The tool must refuse it.
#
# Unbinding the restored VF in C logs "poll_health ... Fatal error 3
# detected" in dmesg; that is a known kernel issue, not a failure.
#
# Hardware-only; needs >= max(SRC_VF,DST_VF)+1 VFs and an mlx5_vfmig CLI
# with recycle_vf. Self-skips to PASS when a precondition is missing; set
# VFMIG_CR_HW=1 to turn a skip into a hard failure.
#
# Usage:
#   sudo PF=0000:08:00.0 VFMIG_TOOL=/path/to/mlx5_vfmig \
#       test/rdma/run_vfmig_restore_guard.sh
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

NUMVFS=$(( (SRC_VF > DST_VF ? SRC_VF : DST_VF) + 1 ))

WORKDIR="$(mktemp -d /tmp/vfmig-guard-XXXXXX)"
HOLDER_PID=""
SRIOV_TOUCHED=0

die()  { echo "FAIL: $*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }
sect() { printf '\n== %s ==\n' "$*"; }

cleanup() {
	[[ -n "$HOLDER_PID" ]] && kill -KILL "$HOLDER_PID" 2>/dev/null || true
	if [[ "$SRIOV_TOUCHED" == "1" ]]; then
		echo 0 >"/sys/bus/pci/devices/$PF/sriov_numvfs" 2>/dev/null || true
		echo 1 >"/sys/bus/pci/devices/$PF/sriov_drivers_autoprobe" 2>/dev/null || true
	fi
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

vf_bdf()   { readlink "$PF_DEV/virtfn$1" | xargs basename; }
vf_query() { "$VFMIG_TOOL" "$PF" query_vf "$1"; }

# Return VF $1 to its state right after SR-IOV enable without touching
# sriov_numvfs: unbind it, take its UUID off, RECYCLE_VF.
recycle_slot() {
	local vf="$1" bdf uuid
	bdf="$(vf_bdf "$vf")"
	if [[ -e "/sys/bus/pci/devices/$bdf/driver" ]]; then
		echo "$bdf" >"/sys/bus/pci/devices/$bdf/driver/unbind"
	fi
	uuid="$(vf_query "$vf" | sed -nE 's/.* vf_uuid=([^ ]+) .*/\1/p')"
	if [[ -n "$uuid" && "$uuid" != "<unset>" ]]; then
		"$VFMIG_TOOL" "$PF" clear_vf_uuid "$vf" "$uuid"
	fi
	"$VFMIG_TOOL" "$PF" recycle_vf "$vf"
}

# The orchestrator's bootstrap of a fresh or recycled VF, stamped with the
# checkpoint UUID. Leaves it unbound.
bootstrap_slot() {
	local vf="$1"
	ensure_dma_domain "$(vf_bdf "$vf")"
	"$VFMIG_TOOL" "$PF" set_tracked "$vf" 1
	"$VFMIG_TOOL" "$PF" enable_migratable "$vf"
	"$VFMIG_TOOL" "$PF" set_vf_uuid "$vf" "$VF_UUID"
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

# Bind VF $1 to mlx5_core the ordinary way, with no LOAD staged.
bind_normally() {
	local bdf
	bdf="$(vf_bdf "$1")"
	echo mlx5_core >"/sys/bus/pci/devices/$bdf/driver_override"
	echo "$bdf" >/sys/bus/pci/drivers/mlx5_core/bind
	wait_ibdev "$bdf" >/dev/null || die "VF $bdf bound normally but no ibdev appeared"
}

# Expect query_vf of VF $1 to contain $2.
expect_state() {
	local q
	q="$(vf_query "$1")"
	[[ "$q" == *"$2"* ]] || die "vf $1: expected '$2' in: $q"
	note "$q"
}

# Run the standalone tool and expect it to refuse with a log line matching
# $2, without loading anything. $1 names the case for the log file.
expect_tool_refusal() {
	local log="$WORKDIR/tool_$1.log"
	if "$RESTORE_TOOL" -D "$IMG" -p "$MLX5_SO" >"$log" 2>&1; then
		cat "$log" >&2
		die "case $1: restore tool succeeded; expected it to refuse"
	fi
	grep -qaE "$2" "$log" || { cat "$log" >&2; die "case $1: refusal did not match /$2/"; }
	! grep -qaE 'vfmig: loaded pf=' "$log" || { cat "$log" >&2; die "case $1: refused, but only after a LOAD"; }
	note "tool refused: $(grep -aoE "$2.*" "$log" | head -1 | cut -c1-140)"
}

restore_refused_count() { dmesg | grep -c 'VFMIG_RESTORE ucontext refused' || true; }

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
	|| need_hw "PF $PF has sriov_totalvfs < $NUMVFS (need slots SRC_VF=$SRC_VF, DST_VF=$DST_VF)"
[[ -d "$DEV_DIR" ]] || need_hw "$DEV_DIR missing (mlx5_vfmig kernel support not loaded)"
[[ "$SRC_VF" != "$DST_VF" ]] || die "SRC_VF and DST_VF must differ"

SRIOV_NUMVFS="$PF_DEV/sriov_numvfs"
VF_UUID="$(cat /proc/sys/kernel/random/uuid)"
note "PF=$PF SRC_VF=$SRC_VF DST_VF=$DST_VF vf_uuid=$VF_UUID"

SANDBOX="$WORKDIR/plugins"
mkdir -p "$SANDBOX"
ln -sf "$MLX5_SO" "$SANDBOX/$(basename "$MLX5_SO")"

# ---------------------------------------------------------------------------
# One dump from SRC_VF
# ---------------------------------------------------------------------------
sect "Provision the source VF (vf_id=$SRC_VF) and dump a context"
SRIOV_TOUCHED=1
echo 0 >"$SRIOV_NUMVFS"
echo 0 >"$PF_DEV/sriov_drivers_autoprobe"
echo "$NUMVFS" >"$SRIOV_NUMVFS"
bootstrap_slot "$SRC_VF"
SRC_BDF="$(vf_bdf "$SRC_VF")"
echo mlx5_core >"/sys/bus/pci/devices/$SRC_BDF/driver_override"
echo "$SRC_BDF" >/sys/bus/pci/drivers/mlx5_core/bind
SRC_IBDEV="$(wait_ibdev "$SRC_BDF")" || die "source VF ibdev did not appear (vf_bdf=$SRC_BDF)"

STATUS="$WORKDIR/holder.status"
HLOG="$WORKDIR/holder.log"
systemd-run --scope --quiet --unit="vfmig-guard-holder-$$" \
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

IMG="$WORKDIR/img"
mkdir -p "$IMG"
"$CRIU" dump -t "$HOLDER_PID" -D "$IMG" -v4 -o dump.log --shell-job -L "$SANDBOX" \
	>/dev/null 2>&1 || { tail -80 "$IMG/dump.log" >&2 2>/dev/null || true; die "criu dump failed (see $IMG/dump.log)"; }
HOLDER_PID=""
BLOB="$IMG/mlx5_vfmig-pf$PF-vf$SRC_VF.blob"
[[ -s "$BLOB" ]] || die "dump produced no firmware blob at $BLOB"
note "dumped from vf_id=$SRC_VF ($SRC_IBDEV)"

# The source is still bound and holds the UUID; give it up so DST_VF can
# take the UUID.
recycle_slot "$SRC_VF"
DST_BDF="$(vf_bdf "$DST_VF")"

# ---------------------------------------------------------------------------
# A. Destination bound normally
# ---------------------------------------------------------------------------
sect "A. destination bound normally (no LOAD)"
bootstrap_slot "$DST_VF"
bind_normally "$DST_VF"
expect_state "$DST_VF" "bound=1 from_load=0"
expect_tool_refusal A "bound but did not come up from LOAD_VHCA_STATE"

REFUSED_BEFORE="$(restore_refused_count)"
RLOG="$IMG/restore.log"
if "$CRIU" restore -D "$IMG" -v4 -o restore.log -d --pidfile "$WORKDIR/restored.pid" --shell-job \
	-L "$SANDBOX" >/dev/null 2>&1; then
	kill -KILL "$(cat "$WORKDIR/restored.pid" 2>/dev/null)" 2>/dev/null || true
	die "case A: criu restore succeeded onto a normally bound VF"
fi
grep -qaE 'bound but did not come up from LOAD_VHCA_STATE' "$RLOG" \
	|| { tail -60 "$RLOG" >&2; die "case A: criu restore failed, but not with the plugin's refusal"; }
! grep -qaE 'vfmig: (open_uverbs_cdev|post-restore)' "$RLOG" \
	|| { grep -aE 'vfmig: (open_uverbs_cdev|post-restore)' "$RLOG" >&2; die "case A: refusal came after Phase B started"; }
[[ "$(restore_refused_count)" == "$REFUSED_BEFORE" ]] \
	|| die "case A: the kernel refused a restore-mode ucontext; the plugin should have stopped first"
note "criu restore refused in Phase A; no restore-mode ucontext reached the kernel"

# ---------------------------------------------------------------------------
# B. LOAD staged but the VF is unbound
# ---------------------------------------------------------------------------
sect "B. LOAD staged, destination unbound"
recycle_slot "$DST_VF"
bootstrap_slot "$DST_VF"
"$VFMIG_TOOL" "$PF" load_vhca_state "$DST_VF" "$BLOB"
expect_state "$DST_VF" "restored=1"
expect_state "$DST_VF" "bound=0"
expect_tool_refusal B "LOAD_VHCA_STATE is already staged"

# ---------------------------------------------------------------------------
# C. Restored, then unbound, recycled and bound normally
# ---------------------------------------------------------------------------
sect "C. restored VF recycled and bound normally"
recycle_slot "$DST_VF"
bootstrap_slot "$DST_VF"
FLOG="$WORKDIR/tool_C_restore.log"
"$RESTORE_TOOL" -D "$IMG" -p "$MLX5_SO" >"$FLOG" 2>&1 \
	|| { cat "$FLOG" >&2; die "case C: the restore onto a recycled VF failed"; }
grep -qaE "vfmig: loaded pf=$PF vf_id=$DST_VF " "$FLOG" || { cat "$FLOG" >&2; die "case C: no LOAD ran"; }
wait_ibdev "$DST_BDF" >/dev/null || die "case C: restored VF has no ibdev"
expect_state "$DST_VF" "bound=1 from_load=1"
note "restored; now unbinding (dmesg 'Fatal error 3' is expected here)"
recycle_slot "$DST_VF"
bootstrap_slot "$DST_VF"
bind_normally "$DST_VF"
expect_state "$DST_VF" "bound=1 from_load=0"
expect_tool_refusal C "bound but did not come up from LOAD_VHCA_STATE"

echo
echo "PASS"
