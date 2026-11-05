#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# Traffic-carrying QP gate for the rdma_mlx5_vfmig plugin's source-side
# mlx5e suspend (MLX5_VFMIG_RX_FENCE_F_ETH_SUSPEND) and for what the dump
# puts back when the tasks keep running.
#
# The harness plays orchestrator: it sets the VF admin MAC before binding,
# adds $IP to the VF netdev, and recycles VFs (unbind, clear_vf_uuid,
# recycle_vf) between runs instead of tearing SR-IOV down. The holder
# (qp_gid_holder) connects a self-loop RC QP through the RoCEv2 GID of $IP
# and sends itself a zero-length SEND; on SIGUSR1 it requires RTS and
# sends again.
#
# Modes (MODES="..."; default all of them, each from a freshly recycled VF):
#
#   migrate   criu dump; the plugin's fence must suspend mlx5e and the
#             source netdev must survive. Recycle the source, LOAD onto
#             DST_VF with the same admin MAC and IP, check the IP's GID is
#             at the same index, criu restore, and the restored QP must
#             pass traffic. The destination's drift-detection line must
#             show frag_buf=0 (no mlx5e objects carried in the image).
#   leaverun  criu dump --leave-running: SAVE runs, then the plugin resumes
#             mlx5e and lifts the fence, and the still-running source QP
#             must pass traffic.
#   faildump  CRIU_FAULT=139 fails the dump after suspend and fence: no
#             SAVE, mlx5e resumed, fence down, source QP passes traffic.
#   postdump  a post-dump action script returns 1: SAVE runs, criu dump
#             reports the script's failure, and the tasks keep running
#             with mlx5e resumed and the fence down.
#   noeth     CRIU_VFMIG_NO_ETH_SUSPEND=1 criu dump --leave-running: fence
#             raised without the suspend, lifted, source QP passes traffic.
#
# Hardware-only; needs >= max(SRC_VF,DST_VF)+1 VFs and a PF netdev (for the
# VF admin MAC). Self-skips to PASS when a precondition is missing; set
# VFMIG_CR_HW=1 to make a skip a failure.
#
# Usage:
#   sudo env PF=0000:08:00.0 VFMIG_TOOL=/path/to/mlx5_vfmig VFMIG_CR_HW=1 \
#       test/rdma/run_vfmig_qp_traffic_cr.sh
#   sudo env ... SRC_VF=0 DST_VF=0 MODES=migrate test/rdma/run_vfmig_qp_traffic_cr.sh
#
# The work dir is kept on failure (KEEP=1 keeps it always). Exits 0 on PASS
# (or a clean skip), non-zero on FAIL.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PLUGIN_DIR="$REPO/plugins/rdma/mlx5_sriov_vfmig"

MLX5_SO="${MLX5_SO:-$PLUGIN_DIR/rdma_mlx5_vfmig_plugin.so}"
RESTORE_TOOL="${RESTORE_TOOL:-$PLUGIN_DIR/mlx5_vfmig_restore_vf}"
HOLDER="$HERE/qp_gid_holder"

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
MODES="${MODES:-migrate leaverun faildump postdump noeth}"
IP="${IP:-192.168.250.10}"
MAC="${MAC:-02:00:00:fa:00:10}"
WANT_HW="${VFMIG_CR_HW:-auto}"
NUMVFS=$(( (SRC_VF > DST_VF ? SRC_VF : DST_VF) + 1 ))
FI_DUMP_AFTER_RDMA_UNBIND=139

WORKDIR="$(mktemp -d /tmp/vfmig-qptraffic-XXXXXX)"
PF_DEV="/sys/bus/pci/devices/$PF"
SRIOV_TOUCHED=0
FAILED=0
declare -A RESULT DETAIL

die()  { echo "FAIL: $*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }
sect() { printf '\n== %s ==\n' "$*"; }
kmark() { echo "vfmig_qp_traffic: $*" >/dev/kmsg 2>/dev/null || true; }

cleanup() {
	pkill -KILL -f "^$HOLDER " 2>/dev/null || true
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

skip_hw() { echo "[skip] $*"; echo; echo "PASS (skipped)"; exit 0; }
need_hw() {
	[[ "$WANT_HW" == "1" ]] && die "hardware run required (VFMIG_CR_HW=1) but $*"
	skip_hw "$*"
}

# See run_vfmig_xvf_cr.sh: SET_TRACKED needs a DMA-IOMMU domain.
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

# Unbind, take the UUID off, RECYCLE_VF. The admin MAC survives. Unbinding
# a restored VF logs "poll_health ... Fatal error 3"; a known kernel issue.
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

# Index of the RoCE v2 GID carrying $IP, waiting for ib_core to add it.
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

# Signal the holder and wait for the status it writes back.
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

# Kernel log since the last "vfmig_qp_traffic: $1" marker.
dmesg_since() {
	dmesg | awk -v m="vfmig_qp_traffic: $1" '{l[NR] = $0} index($0, m) {s = NR} END {for (i = s + 1; s && i <= NR; i++) print l[i]}'
}

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
	|| need_hw "orchestrator CLI '$VFMIG_TOOL' has no recycle_vf (rebuild it from the kernel tree)"
[[ -x "$CRIU" ]]   || need_hw "missing criu at $CRIU (set CRIU=... or build the repo)"
[[ -x "$HOLDER" ]] || need_hw "qp_gid_holder not built ('make -C $HERE')"
command -v systemd-run >/dev/null 2>&1 || need_hw "systemd-run not found"
[[ -d "$PF_DEV" ]] || need_hw "PF $PF not present (set PF=...)"
[[ "$(cat "$PF_DEV/sriov_totalvfs" 2>/dev/null || echo 0)" -ge "$NUMVFS" ]] \
	|| need_hw "PF $PF has sriov_totalvfs < $NUMVFS"
[[ -d "$DEV_DIR" ]] || need_hw "$DEV_DIR missing (mlx5_vfmig kernel support not loaded)"
PF_NET="$(ls "$PF_DEV/net" 2>/dev/null | head -1)"
[[ -n "$PF_NET" ]] || need_hw "PF $PF has no netdev (needed to set the VF admin MAC)"
for m in $MODES; do
	case "$m" in migrate|leaverun|faildump|postdump|noeth) ;; *) die "unknown mode '$m'" ;; esac
done

note "PF=$PF ($PF_NET) SRC_VF=$SRC_VF DST_VF=$DST_VF numvfs=$NUMVFS IP=$IP MAC=$MAC"
note "modes: $MODES; work dir $WORKDIR"

SANDBOX="$WORKDIR/plugins"
mkdir -p "$SANDBOX"
ln -sf "$MLX5_SO" "$SANDBOX/$(basename "$MLX5_SO")"

POST_DUMP_FAIL="$WORKDIR/post_dump_fail.sh"
cat >"$POST_DUMP_FAIL" <<'EOF'
#!/bin/sh
[ "$CRTOOLS_SCRIPT_ACTION" = post-dump ] && exit 1
exit 0
EOF
chmod +x "$POST_DUMP_FAIL"

echo 1 >/sys/bus/auxiliary/drivers_autoprobe
SRIOV_TOUCHED=1
echo 0 >"$PF_DEV/sriov_numvfs"
echo 0 >"$PF_DEV/sriov_drivers_autoprobe"
echo "$NUMVFS" >"$PF_DEV/sriov_numvfs"

# ---------------------------------------------------------------------------
# One mode, in a subshell: fail() ends it, the main loop collects the result.
# ---------------------------------------------------------------------------
fail() {
	echo "FAIL [$MODE]: $*" >&2
	echo "$*" >"$W/detail"
	exit 1
}

# Provision SRC_VF from recycled, bind it, put $IP on it and start the holder.
start_source() {
	local st
	SRC_BDF="$(vf_bdf "$SRC_VF")"
	ensure_dma_domain "$SRC_BDF"
	ip link set "$PF_NET" vf "$SRC_VF" mac "$MAC" || fail "set source VF admin MAC"
	"$VFMIG_TOOL" "$PF" set_tracked "$SRC_VF" 1 >/dev/null || fail "set_tracked $SRC_VF"
	"$VFMIG_TOOL" "$PF" enable_migratable "$SRC_VF" >/dev/null || fail "enable_migratable $SRC_VF"
	"$VFMIG_TOOL" "$PF" set_vf_uuid "$SRC_VF" "$UUID" >/dev/null || fail "set_vf_uuid $SRC_VF"
	echo mlx5_core >"/sys/bus/pci/devices/$SRC_BDF/driver_override"
	echo "$SRC_BDF" >/sys/bus/pci/drivers/mlx5_core/bind || fail "bind $SRC_BDF"
	SRC_IB="$(wait_ibdev "$SRC_BDF")" || fail "no source ibdev"
	SRC_NET="$(wait_netdev "$SRC_BDF")" || fail "no source netdev"
	configure_ip "$SRC_NET" || fail "ip on source $SRC_NET"
	wait_active "$SRC_IB" || fail "source port not ACTIVE: $(port_state "$SRC_IB")"
	IDX="$(find_gid_index "$SRC_IB")" || fail "no RoCEv2 GID for $IP on source"
	note "source vf_id=$SRC_VF bdf=$SRC_BDF ib=$SRC_IB net=$SRC_NET gid_index=$IDX"

	systemd-run --scope --quiet --unit="vfmig-qptraffic-$$-$MODE" \
		bash -c "exec </dev/null >'$W/holder.log' 2>&1; exec '$HOLDER' '$SRC_IB' '$STATUS' '$IDX'" &
	disown "$!" 2>/dev/null || true
	for _ in $(seq 1 100); do
		st="$(cat "$STATUS" 2>/dev/null)"
		[[ -n "$st" ]] && break
		sleep 0.1
	done
	[[ "$st" == READY ]] || { cat "$W/holder.log" >&2; fail "holder: ${st:-no status}"; }
	HOLDER_PID="$(pgrep -fx "$HOLDER $SRC_IB $STATUS $IDX" | head -1)"
	[[ -n "$HOLDER_PID" ]] || fail "holder pid not found"
	note "holder pid=$HOLDER_PID: $(cat "$W/holder.log")"
}

# criu dump, expecting exit status $1 (0 or nonzero), with extra args after;
# environment for criu in DUMP_ENV.
dump() {
	local want="$1" rc
	shift
	kmark "$MODE dump"
	env "${DUMP_ENV[@]}" "$CRIU" dump -t "$HOLDER_PID" -D "$IMG" -v4 -o dump.log --shell-job -L "$SANDBOX" "$@" \
		>/dev/null 2>&1
	rc=$?
	if [[ "$want" == 0 && "$rc" != 0 ]]; then
		tail -60 "$IMG/dump.log" >&2
		fail "criu dump failed ($rc)"
	elif [[ "$want" != 0 && "$rc" == 0 ]]; then
		fail "criu dump succeeded, expected it to fail"
	fi
	dmesg_since "$MODE dump" >"$W/dmesg.dump"
	grep -aE 'uobj DAG: tasks resume: .*(failed|unbacked)' "$IMG/dump.log" >&2 \
		&& fail "core could not put the ibdev back"
	return 0
}

expect_raised() {
	local eth="$1"
	grep -qaE "vfmig: fenced RoCE RX pf=$PF vf_id=$SRC_VF \($SRC_IB\): table 0x[0-9a-f]+ group 0x[0-9a-f]+$eth" \
		"$IMG/dump.log" || { grep -a 'fenced RoCE RX' "$IMG/dump.log" >&2; fail "plugin fence line lacks '$eth'"; }
	if [[ "$eth" == ", mlx5e suspended" ]]; then
		grep -qE "RoCE RX fence up on vf $SRC_VF \(.*\), mlx5e suspended" "$W/dmesg.dump" \
			|| { grep 'RoCE RX fence' "$W/dmesg.dump" >&2; fail "kernel did not log the fence up with mlx5e suspended"; }
	fi
}

expect_saved() {
	grep -qaE 'vfmig SAVE: claimed_vfs=[0-9]+ records_written=[1-9][0-9]* failed=0' "$IMG/dump.log" \
		|| { grep -aE 'vfmig SAVE|vfmig: captured|saved the device state' "$IMG/dump.log" >&2; fail "SAVE did not write a record"; }
}

# The tasks kept running: mlx5e back (if $1), fence down, same GID, QP passes.
expect_source_back() {
	local resumed="$1" out i
	if [[ "$resumed" == 1 ]]; then
		grep -qaE "vfmig: lifted RoCE RX fence pf=$PF vf_id=$SRC_VF \($SRC_IB\), mlx5e resumed; the tasks keep running" \
			"$IMG/dump.log" || { grep -a 'lifted RoCE RX' "$IMG/dump.log" >&2; fail "plugin did not lift with mlx5e resumed"; }
		grep -qE "RoCE RX fence down on vf $SRC_VF \(.*\), mlx5e resumed" "$W/dmesg.dump" \
			|| { grep 'RoCE RX fence' "$W/dmesg.dump" >&2; fail "kernel did not log the fence down with mlx5e resumed"; }
		grep -qa "port 1 not ACTIVE" "$IMG/dump.log" && note "warning: plugin timed out waiting for port ACTIVE"
	else
		grep -qaE "vfmig: lifted RoCE RX fence pf=$PF vf_id=$SRC_VF \($SRC_IB\); the tasks keep running" \
			"$IMG/dump.log" || { grep -a 'lifted RoCE RX' "$IMG/dump.log" >&2; fail "plugin did not lift the fence"; }
	fi
	kill -0 "$HOLDER_PID" 2>/dev/null || fail "source holder did not keep running"
	[[ "$(vf_netdev "$SRC_BDF")" == "$SRC_NET" ]] || fail "source netdev $SRC_NET gone"
	wait_active "$SRC_IB" || fail "source port not ACTIVE after the dump: $(port_state "$SRC_IB")"
	i="$(find_gid_index "$SRC_IB")" || fail "source lost the RoCEv2 GID for $IP"
	[[ "$i" == "$IDX" ]] || fail "source IP GID moved from index $IDX to $i"
	out="$(holder_ask USR1 "$HOLDER_PID")"
	note "source QP after the dump: $out"
	[[ "$out" == OK ]] || fail "source QP: $out"
}

run_mode() {
	trap '[[ -n "${HOLDER_PID:-}" ]] && kill -KILL "$HOLDER_PID" 2>/dev/null; [[ -n "${RESTORED_PID:-}" ]] && kill -KILL "$RESTORED_PID" 2>/dev/null' EXIT
	W="$WORKDIR/$MODE"
	IMG="$W/img"
	STATUS="$W/holder.status"
	UUID="$(cat /proc/sys/kernel/random/uuid)"
	HOLDER_PID=""
	RESTORED_PID=""
	DUMP_ENV=()
	mkdir -p "$IMG"

	sect "[$MODE] source"
	recycle_slot "$SRC_VF" || fail "recycle source slot $SRC_VF"
	if [[ "$DST_VF" != "$SRC_VF" ]]; then
		recycle_slot "$DST_VF" || fail "recycle dest slot $DST_VF"
		# RECYCLE_VF keeps the admin MAC; one MAC on two VFs would clash.
		ip link set "$PF_NET" vf "$DST_VF" mac 00:00:00:00:00:00 || note "could not clear vf $DST_VF admin MAC"
	fi
	start_source

	case "$MODE" in
	leaverun)
		dump 0 --leave-running
		expect_raised ", mlx5e suspended"
		expect_saved
		expect_source_back 1
		;;
	noeth)
		DUMP_ENV=(CRIU_VFMIG_NO_ETH_SUSPEND=1)
		dump 0 --leave-running
		expect_raised ", mlx5e left up \(CRIU_VFMIG_NO_ETH_SUSPEND=1\)"
		grep -qE "RoCE RX fence up on vf $SRC_VF .*mlx5e suspended" "$W/dmesg.dump" \
			&& fail "kernel suspended mlx5e despite CRIU_VFMIG_NO_ETH_SUSPEND=1"
		expect_saved
		expect_source_back 0
		;;
	faildump)
		DUMP_ENV=(CRIU_FAULT=$FI_DUMP_AFTER_RDMA_UNBIND)
		dump 1
		grep -qa 'fault injection: failing the dump' "$IMG/dump.log" || fail "fault was not injected"
		expect_raised ", mlx5e suspended"
		grep -qaE 'vfmig: captured|vfmig SAVE:' "$IMG/dump.log" && fail "SAVE ran on a failed dump"
		expect_source_back 1
		;;
	postdump)
		dump 1 --action-script "$POST_DUMP_FAIL"
		# cr_system() folds the script's status into -1, so this reads 255.
		grep -qaE 'Post dump script passed with [1-9][0-9]*' "$IMG/dump.log" \
			|| { grep -aE 'Script .* exited|Post dump' "$IMG/dump.log" >&2; fail "post-dump script did not fail the dump"; }
		expect_raised ", mlx5e suspended"
		expect_saved
		expect_source_back 1
		;;
	migrate)
		dump 0
		HOLDER_PID=""
		expect_raised ", mlx5e suspended"
		expect_saved
		grep -qa 'lifted RoCE RX fence' "$IMG/dump.log" && fail "plugin lifted the fence after a dump that kills the tasks"
		[[ "$(vf_netdev "$SRC_BDF")" == "$SRC_NET" ]] || fail "source netdev $SRC_NET did not survive the suspend"
		note "dump ok: mlx5e suspended, netdev $SRC_NET kept, image $(du -sb "$IMG" | cut -f1) bytes"
		migrate_to_dest
		;;
	esac

	if [[ -n "$HOLDER_PID" ]]; then
		kill -TERM "$HOLDER_PID" 2>/dev/null
		HOLDER_PID=""
	fi
	exit 0
}

migrate_to_dest() {
	local dbdf dib dnet didx out

	sect "[$MODE] destination vf_id=$DST_VF"
	recycle_slot "$SRC_VF" || fail "recycle the dumped source (mlx5e suspended, fence up)"
	if [[ "$DST_VF" != "$SRC_VF" ]]; then
		ip link set "$PF_NET" vf "$SRC_VF" mac 00:00:00:00:00:00 \
			|| note "could not clear the source VF's admin MAC"
	fi
	dbdf="$(vf_bdf "$DST_VF")"
	ensure_dma_domain "$dbdf"
	ip link set "$PF_NET" vf "$DST_VF" mac "$MAC" || fail "set dest VF admin MAC"
	"$VFMIG_TOOL" "$PF" set_tracked "$DST_VF" 1 >/dev/null || fail "dest set_tracked"
	"$VFMIG_TOOL" "$PF" set_vf_uuid "$DST_VF" "$UUID" >/dev/null || fail "dest set_vf_uuid"

	kmark "$MODE prerestore"
	"$RESTORE_TOOL" -D "$IMG" -p "$MLX5_SO" >"$W/fw_restore.log" 2>&1 \
		|| { tail -30 "$W/fw_restore.log" >&2; fail "prerestore tool"; }
	dib="$(wait_ibdev "$dbdf")" || fail "no dest ibdev"
	dnet="$(wait_netdev "$dbdf")" || fail "no dest netdev"
	configure_ip "$dnet" || fail "ip on dest $dnet"
	wait_active "$dib" || fail "dest port not ACTIVE: $(port_state "$dib")"
	didx="$(find_gid_index "$dib")" || fail "no RoCEv2 GID for $IP on dest"
	note "dest bdf=$dbdf ib=$dib net=$dnet gid_index=$didx"
	[[ "$didx" == "$IDX" ]] || fail "IP GID at index $didx on dest, $IDX on source"

	kmark "$MODE restore"
	"$CRIU" restore -D "$IMG" -v4 -o restore.log -d --pidfile "$W/restored.pid" --shell-job \
		-L "$SANDBOX" >/dev/null 2>&1 || { tail -60 "$IMG/restore.log" >&2; fail "criu restore"; }
	RESTORED_PID="$(cat "$W/restored.pid")"

	dmesg_since "$MODE prerestore" >"$W/dmesg.restore"
	out="$(grep -E "$dbdf.*vf $DST_VF drift detection armed" "$W/dmesg.restore" | tail -1)"
	[[ -n "$out" ]] || fail "no drift-detection line for dest vf $DST_VF"
	note "dest replays: ${out#*armed }"
	[[ "$out" == *" frag_buf=0 "* ]] || fail "image carried mlx5e buffers: $out"
	out="$(holder_ask USR1 "$RESTORED_PID")"
	note "restored QP (pid $RESTORED_PID, $dib): $out"
	[[ "$out" == OK ]] || fail "restored QP: $out"
	kill -TERM "$RESTORED_PID" 2>/dev/null
	RESTORED_PID=""
}

for MODE in $MODES; do
	mkdir -p "$WORKDIR/$MODE"
	if (run_mode); then RESULT[$MODE]=PASS; else RESULT[$MODE]=FAIL; FAILED=1; fi
	DETAIL[$MODE]="$(cat "$WORKDIR/$MODE/detail" 2>/dev/null)"
done

sect "Summary (SRC_VF=$SRC_VF DST_VF=$DST_VF)"
for MODE in $MODES; do
	printf '  %-9s %s %s\n' "$MODE" "${RESULT[$MODE]}" "${DETAIL[$MODE]:-}"
done
echo
if [[ "$FAILED" == 1 ]]; then
	echo "FAIL"
	exit 1
fi
echo "PASS"
