#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# Dump-side D1 barrier gate for the rdma_mlx5_vfmig plugin. Validates the
# cross-host datapath rendezvous the plugin runs at CHECKPOINT_DEVICES on
# a barrier-mode VF: with a rendezvous descriptor present, the fused
# suspend is split into SUSPEND(INITIATOR) -> RUNNING_P2P, a D1 rendezvous
# with every peer, then SUSPEND(RESPONDER) -> STOP.
#
# Since a real rendezvous needs a second host, this single-host harness
# stands in for the peer with vfmig_barrier_peer, which speaks the exact
# wire contract in plugins/.../vfmig_barrier_wire.h and shares the same
# endpoint tie-break, so exactly one TCP connection is made on the edge.
# It runs concurrently with `criu dump`; the plugin's in-hook barrier
# completes against it, and the stub exits 0 iff the READY exchange
# succeeded.
#
# What this validates end to end, on one host:
#   - the plugin resolves barrier mode by reading the VF's vf_uuid
#     (QUERY_VF) and loading $VFMIG_RZ_DIR/<uuid-hex>.desc;
#   - CHECKPOINT_DEVICES splits the ladder and drives the D1 rendezvous;
#   - the peer stub completes the READY exchange (proves the DUT reached
#     RUNNING_P2P and spoke the wire protocol correctly);
#   - the dump still captures a firmware record (SAVE drain).
#
# The legacy (no-descriptor) fused-suspend path is already covered by the
# other vfmig C/R gates, which run without a descriptor.
#
# This gate is hardware-only: it needs a provisioned, tracked VF. It
# self-skips to PASS when any precondition is missing (no root, no spare
# PF, no mlx5_vfmig support, no orchestrator CLI, ...), so it is safe to
# run on any host. Set VFMIG_CR_HW=1 to turn a skip into a hard failure.
#
# Usage:
#   sudo PF=0000:08:00.0 VFMIG_TOOL=/path/to/mlx5_vfmig \
#       test/rdma/run_vfmig_d1_dump.sh
#   sudo VFMIG_CR_HW=1 PF=... VFMIG_TOOL=... test/rdma/run_vfmig_d1_dump.sh
#
# Exits 0 on PASS (or a clean skip), non-zero on FAIL.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PLUGIN_DIR="$REPO/plugins/rdma/mlx5_sriov_vfmig"

MLX5_SO="${MLX5_SO:-$PLUGIN_DIR/rdma_mlx5_vfmig_plugin.so}"
HOLDER="$HERE/uverbs_ctx_holder"
BARRIER_PEER="${BARRIER_PEER:-$HERE/vfmig_barrier_peer}"

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
VFMIG_RZ_DIR="${VFMIG_RZ_DIR:-/run/criu-vfmig/rendezvous}"
BARRIER_TIMEOUT_MS="${BARRIER_TIMEOUT_MS:-15000}"
# auto (default) | 1 (require hardware, fail on skip)
WANT_HW="${VFMIG_CR_HW:-auto}"

WORKDIR="$(mktemp -d /tmp/vfmig-d1-dump-XXXXXX)"
HOLDER_PID=""
PEER_PID=""
BARRIER_DESC=""
SRIOV_TOUCHED=0

die()  { echo "FAIL: $*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }
sect() { printf '\n== %s ==\n' "$*"; }

cleanup() {
	[[ -n "$HOLDER_PID" ]] && kill -KILL "$HOLDER_PID" 2>/dev/null || true
	if [[ -n "$PEER_PID" ]]; then
		kill "$PEER_PID" 2>/dev/null || true
		wait "$PEER_PID" 2>/dev/null || true
	fi
	[[ -n "$BARRIER_DESC" ]] && rm -f "$BARRIER_DESC" 2>/dev/null || true
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

[[ -f "$MLX5_SO" ]]      || die "missing $MLX5_SO -- 'make -C $PLUGIN_DIR'"
[[ -x "$BARRIER_PEER" ]] || die "vfmig_barrier_peer not built ('make -C $HERE')"

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

# criu has no --disable-plugin; -L overrides the whole plugin dir. Point it at
# a sandbox holding only the mlx5_vfmig plugin so other device plugins stay out.
SANDBOX="$WORKDIR/plugins"
mkdir -p "$SANDBOX"
ln -sf "$MLX5_SO" "$SANDBOX/$(basename "$MLX5_SO")"

# ---------------------------------------------------------------------------
# Provision + bind the source VF, hold a bare uverbs context
# ---------------------------------------------------------------------------
sect "Provision the source VF"
SRIOV_TOUCHED=1
echo 0 >"$SRIOV_NUMVFS"
echo 0 >"$PF_DEV/sriov_drivers_autoprobe"
echo 1 >"$SRIOV_NUMVFS"
"$VFMIG_TOOL" "$PF" set_tracked 0 1
"$VFMIG_TOOL" "$PF" enable_migratable 0
# The dump-side capture refuses an all-zeros vf_uuid, and barrier mode is keyed
# off vf_uuid -> descriptor, so the harness plays orchestrator and stamps a
# stable identity here.
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

sect "Hold a uverbs context"
STATUS="$WORKDIR/holder.status"
HLOG="$WORKDIR/holder.log"
# systemd-run --scope: a bare child would inherit this shell's fds (a unix
# control socket criu refuses to dump). A bare context is enough -- the D1
# barrier is about the VF datapath suspend, independent of any uobjects.
systemd-run --scope --quiet --unit="vfmig-d1-dump-holder-$$" \
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

# ---------------------------------------------------------------------------
# Arm the D1 rendezvous: write the descriptor + launch the stand-in peer
# ---------------------------------------------------------------------------
sect "Arm D1 rendezvous (descriptor + stand-in peer)"
HEX="${VF_UUID//-/}"
BARRIER_DESC="$VFMIG_RZ_DIR/$HEX.desc"
SESSION="vfmig-d1-$$"
BASE_PORT=$(( 34000 + ($$ % 20000) ))
DUT_PORT=$BASE_PORT
PEER_PORT=$(( BASE_PORT + 1 ))
DUT_EP="127.0.0.1:$DUT_PORT"
PEER_EP="127.0.0.1:$PEER_PORT"

mkdir -p "$VFMIG_RZ_DIR"
cat >"$BARRIER_DESC" <<EOF
session=$SESSION
listen=$DUT_EP
peer=$PEER_EP
timeout_ms=$BARRIER_TIMEOUT_MS
retry_ms=200
EOF
note "wrote $BARRIER_DESC (session=$SESSION dut=$DUT_EP peer=$PEER_EP)"
sed 's/^/  desc| /' "$BARRIER_DESC"

# The stub mirrors the DUT: it listens on the DUT's peer= and targets the
# DUT's listen=, so the shared tie-break yields exactly one connection.
PEER_LOG="$WORKDIR/barrier_peer_D1.log"
"$BARRIER_PEER" \
	--listen "$PEER_EP" \
	--peer "$DUT_EP" \
	--session "$SESSION" \
	--phase D1 \
	--timeout-ms "$BARRIER_TIMEOUT_MS" \
	>"$PEER_LOG" 2>&1 &
PEER_PID=$!
note "started peer stub for D1 (pid=$PEER_PID)"

# ---------------------------------------------------------------------------
# criu dump (SAVE) -- the D1 rendezvous fires inside CHECKPOINT_DEVICES
# ---------------------------------------------------------------------------
sect "criu dump (SAVE) with D1 rendezvous"
IMG="$WORKDIR/img"
mkdir -p "$IMG"
"$CRIU" dump -t "$HOLDER_PID" -D "$IMG" -v4 -o dump.log --shell-job -L "$SANDBOX" \
	>/dev/null 2>&1 || { tail -80 "$IMG/dump.log" >&2 2>/dev/null || true; die "criu dump failed (see $IMG/dump.log)"; }
HOLDER_PID=""
note "criu dump completed"

# Reap the peer stub: a non-zero exit means the plugin's D1 rendezvous never
# completed the READY exchange.
PEER_RC=0
wait "$PEER_PID" || PEER_RC=$?
PEER_PID=""
sed 's/^/  peer| /' "$PEER_LOG" >&2 || true
[[ "$PEER_RC" == "0" ]] || die "barrier peer stub exited rc=$PEER_RC -- D1 rendezvous did not complete"
note "peer stub rendezvous OK"

# ---------------------------------------------------------------------------
# Assertions on the plugin's dump-side barrier path
# ---------------------------------------------------------------------------
sect "Assertions"
[[ -s "$IMG/mlx5_vfmig.img" ]] || die "dump produced no mlx5_vfmig.img"

# The loader resolved barrier mode from the descriptor (session + 1 peer).
grep -qaE "vfmig: barrier: loaded .*/$HEX\.desc: session=$SESSION .* peers=1" "$IMG/dump.log" \
	|| { grep -aE 'vfmig: barrier: loaded' "$IMG/dump.log" >&2 || true; die "plugin did not load the D1 descriptor"; }
# The D1 rendezvous completed against the stand-in peer.
grep -qaE "vfmig: barrier\[D1\] session=$SESSION: all 1 peer\(s\) ready" "$IMG/dump.log" \
	|| { grep -aE 'vfmig: barrier\[D1\]' "$IMG/dump.log" >&2 || true; die "D1 rendezvous did not reach 'all peers ready'"; }
# The dump still captured a firmware record (SAVE drain ran after the barrier).
grep -qaE 'fini-DUMP drain: claimed_vfs=[0-9]+ records_written=[1-9][0-9]* failed=0' "$IMG/dump.log" \
	|| { grep -aE 'fini-DUMP drain|vfmig: captured' "$IMG/dump.log" >&2 || true; die "SAVE drain did not write >=1 record"; }
note "D1 descriptor loaded + rendezvous reached 'all peers ready' + SAVE drain wrote a record"

echo
echo "PASS"
