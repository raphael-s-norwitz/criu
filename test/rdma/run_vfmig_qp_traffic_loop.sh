#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# Long-chain migration of one traffic-carrying QP between two VFs.
#
# qp_gid_holder (self-loop RC QP on the RoCEv2 GID of $IP) starts on VF_A.
# Each hop dumps it from the VF it is on, recycles that VF the way an
# orchestrator would, LOADs the image onto the other VF (VF_A == VF_B: the
# same one), restores it and requires the QP to pass traffic. From hop 2
# on, every dump is of a restored process on a restored VF.
#
# Per hop it checks: the fence suspended mlx5e and had mlx5_ib release its
# UMR QP and CQ, SAVE wrote the record, the
# IP's GID came back at the same index, the destination replayed
# frag_buf=0, and the restored QP passed a self-SEND. Every LEAVE_EVERY
# hops it first does a --leave-running dump of the restored process and
# requires the still-running QP to pass traffic.
#
# Across the run it checks for leaks and growth:
#   - the firmware blob size stays within GROWTH_TOL bytes of hop 2's (the
#     first SAVE of a restored VF);
#   - the PF's fw_pages_vfs (debugfs), the firmware pages it has given its
#     VFs: right after each hop's source is recycled, with no VF bound
#     ("idle"), it must settle within FW_PAGES_TOL pages of the count
#     before the chain started -- that is the leak check. The count with
#     one restored VF bound ("bound") is only reported: it moves by
#     hundreds of pages between hops with what firmware has asked for so far;
#   - kernel messages: firmware syndromes and WARN/BUG lines other than the
#     known ones (restored-VF teardown's Fatal error 3, DESTROY_EQ and
#     DEALLOC_UAR bad resource state, kmod dups) are counted per hop;
#     STRICT_DMESG=1 fails on any.
#
# HOLDER_KIND picks the workload, to split image growth by what the restore
# recreates: qp (default; qp_gid_holder, self-SEND each hop), ctx (bare
# ucontext; uverbs_ctx_holder, ibv_query_device each hop) or pd (ucontext +
# PD; HOLDER_PD_MR_PROBES reg/dereg pairs of an MR each hop, default 1).
#
# KRES_LOG=1 adds a kres column: the CQs mlx5_ib itself owns on the restored
# VF after the holder's check (its UMR CQ, cqe 255, once an MR was
# registered), from rdma res.
#
# One row per hop goes to stdout and $WORKDIR/hops.tsv.
#
# Usage:
#   sudo env PF=0000:08:00.0 VFMIG_TOOL=/path/to/mlx5_vfmig VFMIG_CR_HW=1 \
#       HOPS=100 test/rdma/run_vfmig_qp_traffic_loop.sh
#   sudo env ... VF_A=0 VF_B=0 HOPS=50 test/rdma/run_vfmig_qp_traffic_loop.sh
#
# Hardware-only; self-skips to PASS when a precondition is missing
# (VFMIG_CR_HW=1 makes that a failure). The work dir is kept on failure
# (KEEP=1 keeps it always); only the last two images are kept.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PLUGIN_DIR="$REPO/plugins/rdma/mlx5_sriov_vfmig"

MLX5_SO="${MLX5_SO:-$PLUGIN_DIR/rdma_mlx5_vfmig_plugin.so}"
RESTORE_TOOL="${RESTORE_TOOL:-$PLUGIN_DIR/mlx5_vfmig_restore_vf}"
HOLDER_KIND="${HOLDER_KIND:-qp}"
case "$HOLDER_KIND" in
qp) HOLDER="$HERE/qp_gid_holder" ;;
ctx|pd) HOLDER="$HERE/uverbs_ctx_holder" ;;
*) echo "FAIL: HOLDER_KIND must be qp, ctx or pd" >&2; exit 1 ;;
esac

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
HOPS="${HOPS:-50}"
LEAVE_EVERY="${LEAVE_EVERY:-5}"
GROWTH_TOL="${GROWTH_TOL:-131072}"
FW_PAGES_TOL="${FW_PAGES_TOL:-256}"
STRICT_DMESG="${STRICT_DMESG:-0}"
KRES_LOG="${KRES_LOG:-0}"
IP="${IP:-192.168.250.10}"
MAC="${MAC:-02:00:00:fa:00:10}"
WANT_HW="${VFMIG_CR_HW:-auto}"
NUMVFS=$(( (VF_A > VF_B ? VF_A : VF_B) + 1 ))

WORKDIR="$(mktemp -d /tmp/vfmig-qploop-XXXXXX)"
PF_DEV="/sys/bus/pci/devices/$PF"
FW_PAGES="/sys/kernel/debug/mlx5/$PF/pages/fw_pages_vfs"
SRIOV_TOUCHED=0
FAILED=1
HOLDER_PID=""

die()  { echo "FAIL: $*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }
sect() { printf '\n== %s ==\n' "$*"; }
kmark() { echo "vfmig_qp_loop: $*" >/dev/kmsg 2>/dev/null || true; }

cleanup() {
	[[ -n "$HOLDER_PID" ]] && kill -KILL "$HOLDER_PID" 2>/dev/null
	if [[ "$SRIOV_TOUCHED" == "1" ]]; then
		echo 0 >"$PF_DEV/sriov_numvfs" 2>/dev/null || true
		echo 1 >"$PF_DEV/sriov_drivers_autoprobe" 2>/dev/null || true
	fi
	if [[ "$FAILED" == "1" || "${KEEP:-0}" == "1" ]]; then
		echo "work dir kept: $WORKDIR"
	else
		rm -rf "$WORKDIR"
	fi
}
trap cleanup EXIT

skip_hw() { echo "[skip] $*"; echo; echo "PASS (skipped)"; FAILED=0; exit 0; }
need_hw() {
	[[ "$WANT_HW" == "1" ]] && die "hardware run required (VFMIG_CR_HW=1) but $*"
	skip_hw "$*"
}

ensure_dma_domain() {
	local type_f="/sys/bus/pci/devices/$1/iommu_group/type" t
	[[ -e "$type_f" ]] || die "VF $1 has no iommu_group (IOMMU disabled?)"
	t="$(cat "$type_f")"
	case "$t" in DMA|DMA-FQ) return 0 ;; esac
	echo DMA >"$type_f" 2>/dev/null \
		|| die "VF $1 iommu_group type is '$t' and could not be set to DMA (boot without iommu=pt)"
}

vf_bdf()   { readlink "$PF_DEV/virtfn$1" | xargs basename; }
vf_query() { "$VFMIG_TOOL" "$PF" query_vf "$1"; }

# Unbind, take the UUID off, RECYCLE_VF. The admin MAC survives.
recycle_slot() {
	local vf="$1" bdf uuid
	bdf="$(vf_bdf "$vf")"
	if [[ -e "/sys/bus/pci/devices/$bdf/driver" ]]; then
		echo "$bdf" >"/sys/bus/pci/devices/$bdf/driver/unbind" || return 1
	fi
	uuid="$(vf_query "$vf" | sed -nE 's/.* vf_uuid=([^ ]+) .*/\1/p')"
	if [[ -n "$uuid" && "$uuid" != "<unset>" ]]; then
		"$VFMIG_TOOL" "$PF" clear_vf_uuid "$vf" "$uuid" >/dev/null || return 1
	fi
	"$VFMIG_TOOL" "$PF" recycle_vf "$vf" >/dev/null
}

clear_mac() { ip link set "$PF_NET" vf "$1" mac 00:00:00:00:00:00 2>/dev/null || note "could not clear vf $1 admin MAC"; }

wait_ibdev() {
	local bdf="$1" ib
	for _ in $(seq 1 100); do
		for ib in /sys/class/infiniband/*; do
			[[ -e "$ib/device" ]] || continue
			[[ "$(readlink "$ib/device" | xargs basename)" == "$bdf" ]] \
				&& { basename "$ib"; return 0; }
		done
		sleep 0.1
	done
	return 1
}

vf_netdev() { ls "/sys/bus/pci/devices/$1/net" 2>/dev/null | head -1; }

wait_netdev() {
	local n
	for _ in $(seq 1 100); do
		n="$(vf_netdev "$1")"
		[[ -n "$n" ]] && { echo "$n"; return 0; }
		sleep 0.1
	done
	return 1
}

port_state() { cat "/sys/class/infiniband/$1/ports/1/state" 2>/dev/null || echo "?"; }

wait_active() {
	for _ in $(seq 1 100); do
		[[ "$(port_state "$1")" == *ACTIVE* ]] && return 0
		sleep 0.1
	done
	return 1
}

ipv4_gid() {
	local IFS=.
	set -- $IP
	printf '0000:0000:0000:0000:0000:ffff:%02x%02x:%02x%02x' "$1" "$2" "$3" "$4"
}

find_gid_index() {
	local p="/sys/class/infiniband/$1/ports/1" want g i
	want="$(ipv4_gid)"
	for _ in $(seq 1 100); do
		for g in "$p"/gids/*; do
			i="$(basename "$g")"
			[[ "$(cat "$g" 2>/dev/null)" == "$want" ]] || continue
			[[ "$(cat "$p/gid_attrs/types/$i" 2>/dev/null)" == "RoCE v2" ]] || continue
			echo "$i"
			return 0
		done
		sleep 0.1
	done
	return 1
}

configure_ip() { ip link set "$1" up && ip addr add "$IP/24" dev "$1"; }

holder_ask() {
	local sig="$1" pid="$2" s
	: >"$STATUS"
	kill "-$sig" "$pid" 2>/dev/null || { echo "(holder gone)"; return 1; }
	for _ in $(seq 1 150); do
		s="$(cat "$STATUS" 2>/dev/null)"
		[[ -n "$s" ]] && { echo "$s"; return 0; }
		sleep 0.1
	done
	echo "(no answer)"
}

dmesg_since() {
	dmesg | awk -v m="vfmig_qp_loop: $1" '{l[NR] = $0} index($0, m) {s = NR} END {for (i = s + 1; s && i <= NR; i++) print l[i]}'
}

# Kernel lines that point at a problem, minus the known noise.
unexpected_kmsgs() {
	grep -E 'syndrome|WARNING:|BUG:|Oops|kernel BUG' \
		| grep -vE 'Fatal error 3|DESTROY_EQ\(0x302\).*bad resource state\(0x9\)|DEALLOC_UAR\(0x[0-9a-f]+\).*bad resource state|kernel/module/dups\.c'
}

fw_pages() { cat "$FW_PAGES" 2>/dev/null || echo -; }

# fw_pages_vfs once it has stopped moving: a recycled VF's pages come back
# asynchronously. Gives up after ~10 s and returns the last value.
fw_pages_settled() {
	local v p=""
	for _ in $(seq 1 50); do
		v="$(fw_pages)"
		[[ "$v" == - ]] && { echo -; return; }
		[[ "$v" == "$p" ]] && break
		p="$v"
		sleep 0.2
	done
	echo "$v"
}

# After a recycle: poll up to ~30 s for fw_pages_vfs to drop back within
# FW_PAGES_TOL of the start. Prints "<pages> <seconds waited>".
fw_pages_returned() {
	local v t0 i
	t0="$(date +%s.%N)"
	for i in $(seq 1 150); do
		v="$(fw_pages)"
		[[ "$v" == - ]] && { echo "- 0"; return; }
		[[ $((v - FW_BASE)) -le "$FW_PAGES_TOL" ]] && break
		sleep 0.2
	done
	echo "$v $(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f", b - a }')"
}

now() { date +%s.%N; }
secs() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.1f", b - a }'; }

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
sect "Preconditions"

[[ -f "$MLX5_SO" ]]      || die "missing $MLX5_SO -- 'make -C $PLUGIN_DIR'"
[[ -x "$RESTORE_TOOL" ]] || die "missing $RESTORE_TOOL -- 'make -C $PLUGIN_DIR'"
[[ "$EUID" -eq 0 ]] || need_hw "not root (VF provisioning + cdev ioctls need root)"
command -v "$VFMIG_TOOL" >/dev/null 2>&1 \
	|| need_hw "orchestrator CLI '$VFMIG_TOOL' not found (set VFMIG_TOOL=...)"
[[ "$("$VFMIG_TOOL" 2>&1 || true)" == *recycle_vf* ]] \
	|| need_hw "orchestrator CLI '$VFMIG_TOOL' has no recycle_vf"
[[ -x "$CRIU" ]]   || need_hw "missing criu at $CRIU"
[[ -x "$HOLDER" ]] || need_hw "$(basename "$HOLDER") not built ('make -C $HERE')"
command -v systemd-run >/dev/null 2>&1 || need_hw "systemd-run not found"
[[ -d "$PF_DEV" ]] || need_hw "PF $PF not present (set PF=...)"
[[ "$(cat "$PF_DEV/sriov_totalvfs" 2>/dev/null || echo 0)" -ge "$NUMVFS" ]] \
	|| need_hw "PF $PF has sriov_totalvfs < $NUMVFS"
[[ -d "$DEV_DIR" ]] || need_hw "$DEV_DIR missing (mlx5_vfmig kernel support not loaded)"
PF_NET="$(ls "$PF_DEV/net" 2>/dev/null | head -1)"
[[ -n "$PF_NET" ]] || need_hw "PF $PF has no netdev (needed to set the VF admin MAC)"
[[ "$HOPS" =~ ^[1-9][0-9]*$ ]] || die "HOPS must be a positive integer"

[[ -r "$FW_PAGES" ]] || note "no $FW_PAGES (debugfs not mounted?); skipping the firmware page check"
note "PF=$PF ($PF_NET) VF_A=$VF_A VF_B=$VF_B hops=$HOPS leave_every=$LEAVE_EVERY holder=$HOLDER_KIND${HOLDER_PD_MR_PROBES:+ pd_mr_probes=$HOLDER_PD_MR_PROBES}"
note "growth_tol=${GROWTH_TOL}B fw_pages_tol=$FW_PAGES_TOL strict_dmesg=$STRICT_DMESG; work dir $WORKDIR"

SANDBOX="$WORKDIR/plugins"
mkdir -p "$SANDBOX"
ln -sf "$MLX5_SO" "$SANDBOX/$(basename "$MLX5_SO")"
STATUS="$WORKDIR/holder.status"
UUID="$(cat /proc/sys/kernel/random/uuid)"
TSV="$WORKDIR/hops.tsv"

echo 1 >/sys/bus/auxiliary/drivers_autoprobe
SRIOV_TOUCHED=1
echo 0 >"$PF_DEV/sriov_numvfs"
echo 0 >"$PF_DEV/sriov_drivers_autoprobe"
echo "$NUMVFS" >"$PF_DEV/sriov_numvfs"
recycle_slot "$VF_A" || die "recycle vf $VF_A"
[[ "$VF_B" != "$VF_A" ]] && { recycle_slot "$VF_B" || die "recycle vf $VF_B"; clear_mac "$VF_B"; }
FW_BASE="$(fw_pages_settled)"
note "fw_pages_vfs with no VF bound: $FW_BASE"

# ---------------------------------------------------------------------------
# Hop 0: a normally bound VF_A with the holder on it
# ---------------------------------------------------------------------------
sect "Start on vf $VF_A"
CUR_VF="$VF_A"
CUR_BDF="$(vf_bdf "$CUR_VF")"
ensure_dma_domain "$CUR_BDF"
ip link set "$PF_NET" vf "$CUR_VF" mac "$MAC" || die "set vf $CUR_VF admin MAC"
"$VFMIG_TOOL" "$PF" set_tracked "$CUR_VF" 1 >/dev/null || die "set_tracked $CUR_VF"
"$VFMIG_TOOL" "$PF" enable_migratable "$CUR_VF" >/dev/null || die "enable_migratable $CUR_VF"
"$VFMIG_TOOL" "$PF" set_vf_uuid "$CUR_VF" "$UUID" >/dev/null || die "set_vf_uuid $CUR_VF"
echo mlx5_core >"/sys/bus/pci/devices/$CUR_BDF/driver_override"
echo "$CUR_BDF" >/sys/bus/pci/drivers/mlx5_core/bind || die "bind $CUR_BDF"
CUR_IB="$(wait_ibdev "$CUR_BDF")" || die "no ibdev on $CUR_BDF"
CUR_NET="$(wait_netdev "$CUR_BDF")" || die "no netdev on $CUR_BDF"
configure_ip "$CUR_NET" || die "ip on $CUR_NET"
wait_active "$CUR_IB" || die "port not ACTIVE: $(port_state "$CUR_IB")"
IDX="$(find_gid_index "$CUR_IB")" || die "no RoCEv2 GID for $IP"

case "$HOLDER_KIND" in
qp)  HOLDER_ARGS="$CUR_IB $STATUS $IDX"; HOLDER_ENV="" ;;
ctx) HOLDER_ARGS="$CUR_IB $STATUS"; HOLDER_ENV="" ;;
pd)  HOLDER_ARGS="$CUR_IB $STATUS"
     HOLDER_ENV="export HOLDER_ALLOC_PD=1 HOLDER_PD_MR_PROBES=${HOLDER_PD_MR_PROBES:-1};" ;;
esac
systemd-run --scope --quiet --unit="vfmig-qploop-$$" \
	bash -c "exec </dev/null >'$WORKDIR/holder.log' 2>&1; $HOLDER_ENV exec '$HOLDER' $HOLDER_ARGS" &
disown "$!" 2>/dev/null || true
for _ in $(seq 1 100); do
	[[ -n "$(cat "$STATUS" 2>/dev/null)" ]] && break
	sleep 0.1
done
[[ "$(cat "$STATUS" 2>/dev/null)" == READY ]] || { cat "$WORKDIR/holder.log" >&2; die "holder did not reach READY"; }
HOLDER_PID="$(pgrep -fx "$HOLDER $HOLDER_ARGS" | head -1)"
[[ -n "$HOLDER_PID" ]] || die "holder pid not found"
note "$HOLDER_KIND holder pid=$HOLDER_PID on vf $CUR_VF ($CUR_IB, $CUR_NET), gid_index=$IDX"

# ---------------------------------------------------------------------------
# Hops
# ---------------------------------------------------------------------------
sect "Hops"
printf 'hop\tfrom\tto\tblob_bytes\tfw_pages_idle\tfw_pages_bound\tunexpected_kmsgs\tdump_s\tload_s\trestore_s\tleave_running\ttd\treplays\tkres\n' >"$TSV"
printf '  %4s %4s %4s %10s %8s %8s %5s %7s %7s %9s %5s %7s %-26s %s\n' hop from to blob fw_idle fw_bound kmsg dump_s load_s restore_s leave td \
	"replays cmd/fw/eq/frag/db/dma=total" kres
BLOB_REF=""
PREV_IMG=""

for hop in $(seq 1 "$HOPS"); do
	if [[ "$VF_A" == "$VF_B" ]]; then
		DST_VF="$VF_A"
	elif [[ "$CUR_VF" == "$VF_A" ]]; then
		DST_VF="$VF_B"
	else
		DST_VF="$VF_A"
	fi
	kmark "hop $hop begin"
	LR="-"

	if [[ "$LEAVE_EVERY" -gt 0 && $((hop % LEAVE_EVERY)) -eq 0 ]]; then
		LRIMG="$WORKDIR/leave-$hop"
		mkdir -p "$LRIMG"
		"$CRIU" dump -t "$HOLDER_PID" -D "$LRIMG" -v4 -o dump.log --shell-job -L "$SANDBOX" --leave-running \
			>/dev/null 2>&1 || { tail -60 "$LRIMG/dump.log" >&2; die "hop $hop: --leave-running dump failed"; }
		grep -qa ", mlx5e suspended" "$LRIMG/dump.log" || die "hop $hop: --leave-running: mlx5e was not suspended"
		grep -qa ", mlx5_ib released" "$LRIMG/dump.log" \
			|| { grep -a 'fenced RoCE RX' "$LRIMG/dump.log" >&2; die "hop $hop: --leave-running: mlx5_ib not released"; }
		grep -qa "mlx5e resumed; the tasks keep running" "$LRIMG/dump.log" \
			|| die "hop $hop: --leave-running: fence not lifted with mlx5e resumed"
		wait_active "$CUR_IB" || die "hop $hop: port not ACTIVE after --leave-running"
		i="$(find_gid_index "$CUR_IB")" || die "hop $hop: GID lost after --leave-running"
		[[ "$i" == "$IDX" ]] || die "hop $hop: GID moved to index $i after --leave-running"
		out="$(holder_ask USR1 "$HOLDER_PID")"
		[[ "$out" == OK ]] || die "hop $hop: QP after --leave-running: $out"
		rm -rf "$LRIMG"
		LR="OK"
	fi

	IMG="$WORKDIR/img-$hop"
	mkdir -p "$IMG"
	t0="$(now)"
	"$CRIU" dump -t "$HOLDER_PID" -D "$IMG" -v4 -o dump.log --shell-job -L "$SANDBOX" \
		>/dev/null 2>&1 || { tail -60 "$IMG/dump.log" >&2; die "hop $hop: criu dump from vf $CUR_VF failed"; }
	t1="$(now)"
	grep -qaE "vfmig: fenced RoCE RX pf=$PF vf_id=$CUR_VF .*, mlx5e suspended" "$IMG/dump.log" \
		|| { grep -a 'fenced RoCE RX' "$IMG/dump.log" >&2; die "hop $hop: mlx5e not suspended on vf $CUR_VF"; }
	grep -qaE "vfmig: fenced RoCE RX pf=$PF vf_id=$CUR_VF .*, mlx5_ib released" "$IMG/dump.log" \
		|| { grep -a 'fenced RoCE RX' "$IMG/dump.log" >&2; die "hop $hop: mlx5_ib did not release its UMR QP and CQ on vf $CUR_VF"; }
	grep -qaE 'vfmig SAVE: claimed_vfs=1 records_written=1 failed=0' "$IMG/dump.log" \
		|| die "hop $hop: SAVE did not write the record"
	BLOB="$(grep -aoE "vfmig: captured pf=$PF vf_id=$CUR_VF .* size=[0-9]+" "$IMG/dump.log" | tail -1 | sed -E 's/.*size=//')"
	[[ -n "$BLOB" ]] || die "hop $hop: no blob size in dump.log"

	recycle_slot "$CUR_VF" || die "hop $hop: recycle vf $CUR_VF after the dump"
	[[ "$DST_VF" != "$CUR_VF" ]] && clear_mac "$CUR_VF"
	read -r FW_IDLE FW_WAIT <<<"$(fw_pages_returned)"
	if [[ "$FW_IDLE" != - && $((FW_IDLE - FW_BASE)) -gt "$FW_PAGES_TOL" ]]; then
		dmesg_since "hop $hop begin" >"$IMG/dmesg.txt"
		"$VFMIG_TOOL" "$PF" query_vf "$CUR_VF" >"$IMG/query_vf.txt" 2>&1
		die "hop $hop: with no VF bound fw_pages_vfs is still $FW_IDLE after ${FW_WAIT}s, $((FW_IDLE - FW_BASE)) pages over the start: the recycled vf $CUR_VF kept firmware pages (see $IMG/dmesg.txt, $IMG/query_vf.txt)"
	fi
	awk -v w="$FW_WAIT" 'BEGIN { exit !(w > 2) }' && note "hop $hop: fw_pages_vfs took ${FW_WAIT}s to come back"
	DST_BDF="$(vf_bdf "$DST_VF")"
	ensure_dma_domain "$DST_BDF"
	ip link set "$PF_NET" vf "$DST_VF" mac "$MAC" || die "hop $hop: set vf $DST_VF admin MAC"
	"$VFMIG_TOOL" "$PF" set_tracked "$DST_VF" 1 >/dev/null || die "hop $hop: set_tracked $DST_VF"
	"$VFMIG_TOOL" "$PF" set_vf_uuid "$DST_VF" "$UUID" >/dev/null || die "hop $hop: set_vf_uuid $DST_VF"

	t2="$(now)"
	"$RESTORE_TOOL" -D "$IMG" -p "$MLX5_SO" >"$IMG/fw_restore.log" 2>&1 \
		|| { tail -30 "$IMG/fw_restore.log" >&2; die "hop $hop: prerestore onto vf $DST_VF failed"; }
	t3="$(now)"
	DST_IB="$(wait_ibdev "$DST_BDF")" || die "hop $hop: no ibdev on $DST_BDF"
	DST_NET="$(wait_netdev "$DST_BDF")" || die "hop $hop: no netdev on $DST_BDF"
	configure_ip "$DST_NET" || die "hop $hop: ip on $DST_NET"
	wait_active "$DST_IB" || die "hop $hop: port not ACTIVE on vf $DST_VF: $(port_state "$DST_IB")"
	i="$(find_gid_index "$DST_IB")" || die "hop $hop: no RoCEv2 GID for $IP on vf $DST_VF"
	[[ "$i" == "$IDX" ]] || die "hop $hop: GID at index $i on vf $DST_VF, $IDX on the source"

	t4="$(now)"
	"$CRIU" restore -D "$IMG" -v4 -o restore.log -d --pidfile "$IMG/restored.pid" --shell-job -L "$SANDBOX" \
		>/dev/null 2>&1 || { tail -60 "$IMG/restore.log" >&2; die "hop $hop: criu restore onto vf $DST_VF failed"; }
	t5="$(now)"
	HOLDER_PID="$(cat "$IMG/restored.pid")"
	TD="$(grep -aoE 'td (adopted|fresh)' "$IMG/restore.log" | head -1 | sed 's/^td //')"
	[[ -n "$TD" ]] || TD="?"
	out="$(holder_ask USR1 "$HOLDER_PID")"
	[[ "$out" == OK ]] || die "hop $hop: restored QP on vf $DST_VF: $out"

	dmesg_since "hop $hop begin" >"$IMG/dmesg.txt"
	drift="$(grep -E "$DST_BDF.*vf $DST_VF drift detection armed" "$IMG/dmesg.txt" | tail -1)"
	[[ -n "$drift" ]] || die "hop $hop: no drift-detection line for vf $DST_VF"
	[[ "$drift" == *" frag_buf=0 "* ]] || die "hop $hop: image carried mlx5e buffers: ${drift#*armed }"
	REPLAYS="$(sed -nE 's/.*cmd_ring=([0-9]+) fw_page=([0-9]+) eq_buf=([0-9]+) frag_buf=([0-9]+) db_page=([0-9]+) dma_coherent=([0-9]+), total=([0-9]+).*/\1\/\2\/\3\/\4\/\5\/\6=\7/p' <<<"$drift")"
	unexpected_kmsgs <"$IMG/dmesg.txt" >"$IMG/unexpected_kmsgs.txt"
	NK="$(wc -l <"$IMG/unexpected_kmsgs.txt")"
	FW="$(fw_pages)"
	KRES=-
	[[ "$KRES_LOG" == 1 ]] && KRES="$(rdma res show cq dev "$DST_IB" 2>/dev/null | grep '\[mlx5_ib\]' | grep -oE 'cqe [0-9]+' | tr ' ' = | paste -sd, -)" && KRES="${KRES:-none}"

	printf '%d\t%d\t%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$hop" "$CUR_VF" "$DST_VF" "$BLOB" "$FW_IDLE" "$FW" \
		"$NK" "$(secs "$t0" "$t1")" "$(secs "$t2" "$t3")" "$(secs "$t4" "$t5")" "$LR" "$TD" "$REPLAYS" "$KRES" >>"$TSV"
	printf '  %4d %4d %4d %10s %8s %8s %5d %7s %7s %9s %5s %7s %-26s %s\n' "$hop" "$CUR_VF" "$DST_VF" "$BLOB" "$FW_IDLE" "$FW" \
		"$NK" "$(secs "$t0" "$t1")" "$(secs "$t2" "$t3")" "$(secs "$t4" "$t5")" "$LR" "$TD" "$REPLAYS" "$KRES"

	if [[ "$NK" -gt 0 ]]; then
		sed 's/^/        /' "$IMG/unexpected_kmsgs.txt" | head -5
		[[ "$STRICT_DMESG" == 1 ]] && die "hop $hop: unexpected kernel messages"
	fi

	# Hop 1 dumps a normally bound VF; hop 2 is the first SAVE of a restored one.
	if [[ "$hop" -eq 2 ]]; then
		BLOB_REF="$BLOB"
	elif [[ -n "$BLOB_REF" && $((BLOB - BLOB_REF)) -gt "$GROWTH_TOL" ]]; then
		die "hop $hop: firmware blob grew to $BLOB bytes, $((BLOB - BLOB_REF)) over hop 2 (tolerance $GROWTH_TOL)"
	fi
	[[ -n "$PREV_IMG" ]] && rm -rf "$PREV_IMG"
	PREV_IMG="$IMG"
	CUR_VF="$DST_VF"
	CUR_BDF="$DST_BDF"
	CUR_IB="$DST_IB"
	CUR_NET="$DST_NET"
done

# ---------------------------------------------------------------------------
# Teardown: everything the chain gave the VFs must come back
# ---------------------------------------------------------------------------
sect "Teardown"
kill -TERM "$HOLDER_PID" 2>/dev/null
for _ in $(seq 1 50); do
	kill -0 "$HOLDER_PID" 2>/dev/null || break
	sleep 0.1
done
HOLDER_PID=""
recycle_slot "$CUR_VF" || die "final recycle of vf $CUR_VF"
FW_END="$(fw_pages_settled)"
note "fw_pages_vfs: $FW_BASE before the chain, $FW_END after recycling every VF"
if [[ "$FW_BASE" != - && "$FW_END" != - && $((FW_END - FW_BASE)) -gt "$FW_PAGES_TOL" ]]; then
	die "fw_pages_vfs did not come back: $((FW_END - FW_BASE)) pages over the start"
fi
awk -F'\t' 'NR > 1 { k += $7 } NR > 2 { if (min == "" || $4 < min) min = $4; if ($4 > max) max = $4 }
	NR == 3 { first = $4 } NR > 3 { last = $4; n = NR - 3 }
	END { printf "  blob bytes over hops 2..: min %d max %d (spread %d", min, max, max - min
	      if (n) printf ", %+.0f bytes/hop", (last - first) / n
	      printf "); unexpected kmsgs %d\n", k }' "$TSV"

FAILED=0
echo
echo "PASS ($HOPS hops)"
