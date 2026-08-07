#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# Smoke gate for the rdma_mlx5_vfmig plugin at its early bring-up stage,
# where the plugin can only detect migration-capable VFs and claim their
# uverbs contexts -- it does not yet snapshot or restore any device
# state. Because there are no dump/restore hooks and a typical host has
# no tracked VFs, the full end-to-end SAVE/LOAD/restore harness cannot
# run yet. This gate validates the two behaviours that ARE live today
# and is a real regression gate for them:
#
#   Tier 1 -- presence detection (always runs):
#     Dump a trivial victim with only the mlx5_vfmig plugin loaded and
#     assert the plugin (a) loaded, (b) walked /dev/mlx5_vfmig and
#     probed each per-PF cdev via QUERY_VF, (c) reached a coherent
#     active/inactive verdict consistent with the host, and (d) ran
#     fini. Deterministic per host:
#       - no /dev/mlx5_vfmig      -> inactive via the opendir-miss path
#       - dir present, 0 tracked  -> "inactive ... N PF cdev(s) probed"
#                                     with N == #cdevs, sum(tracked)==0
#       - dir present, >0 tracked -> "active ... T tracked ... P PF(s)"
#                                     with T == sum(tracked) > 0
#
#   Tier 2 -- claim arbitration decline (auto when rxe is available,
#             or forced with VFMIG_GATE_CLAIM=1; skipped gracefully
#             otherwise):
#     Bring up an rxe context, dump it with BOTH the rxe and mlx5_vfmig
#     plugins loaded, and assert the core exactly-one-claim arbitration
#     (criu/rdma/plugin_api.c::rdma_arbitrate_plugin_claim) invoked the
#     mlx5 plugin's claim hook for the rxe ibdev and it DECLINED (rxe
#     wins). This exercises the claim path's negative branch without
#     needing a tracked mlx5 VF. Asserts: mlx5 emitted a decline line
#     for rxe0 ("plugin inactive" or "not RDMA_DRIVER_MLX5"), no
#     claim-conflict / claim-probe-failure error fired, and the dump
#     succeeded (rxe claimed).
#
# Usage:
#   sudo [CRIU=/path/to/criu] test/rdma/run_vfmig_presence.sh
#   sudo VFMIG_GATE_CLAIM=1 test/rdma/run_vfmig_presence.sh [<netdev>]
#   sudo VFMIG_GATE_CLAIM=0 test/rdma/run_vfmig_presence.sh   # tier 1 only
#
# Exits 0 on PASS (every enabled tier green), non-zero on FAIL.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
CRIU="${CRIU:-$REPO/criu/criu}"
NETDEV="${1:-}"
DEV_DIR=/dev/mlx5_vfmig

MLX5_SO="$REPO/plugins/rdma/mlx5_sriov_vfmig/rdma_mlx5_vfmig_plugin.so"
RXE_SO="$REPO/plugins/rdma/rxe/rdma_rxe_plugin.so"
HOLDER="$HERE/uverbs_ctx_holder"

WORKDIR="$(mktemp -d /tmp/vfmig-presence-XXXXXX)"
FAIL=0

cleanup() {
	local pidf p u
	for pidf in "$WORKDIR"/*.pid; do
		[[ -f "$pidf" ]] || continue
		p="$(cat "$pidf" 2>/dev/null || true)"
		[[ -n "$p" ]] && kill -KILL "$p" 2>/dev/null || true
	done
	for u in "${SCOPE_UNITS[@]:-}"; do
		[[ -n "$u" ]] && systemctl stop "$u.scope" 2>/dev/null || true
	done
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

die()  { echo "FAIL: $*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }
sect() { printf '\n== %s ==\n' "$*"; }

[[ "$EUID" -eq 0 ]] || die "must run as root (criu dump + cdev open + rxe link add)"
[[ -x "$CRIU" ]]    || die "missing criu at $CRIU (set CRIU=... or 'make' in $REPO)"
[[ -f "$MLX5_SO" ]] || die "missing $MLX5_SO -- 'make rdma_mlx5_vfmig_plugin' in $REPO"
command -v systemd-run >/dev/null 2>&1 \
	|| die "systemd-run not found -- needed to launch victims in a clean fd table (a bare child inherits this shell's unix control socket, which criu can't dump)"

# A plugin sandbox (-L dir) with only the plugins a tier needs. Keeps
# amdgpu_plugin (which errors rather than declines on non-AMD hosts for
# any unrecognised /dev/* mapping) out of the picture, and keeps the
# presence tier isolated from rxe's own init noise.
make_sandbox() {
	local dir="$1"; shift
	mkdir -p "$dir"
	local so
	for so in "$@"; do
		ln -sf "$so" "$dir/$(basename "$so")"
	done
	echo "$dir"
}

# Spawn a command in a fresh systemd scope so it does NOT inherit this
# shell's fds (the agent control unix socket in particular, which criu
# refuses to dump as "socket ... not found"). Its stdio is detached to
# @logfile. Echoes nothing; caller finds the pid via pgrep on the exact
# argv. Records the scope unit in SCOPE_UNITS for teardown.
SCOPE_UNITS=()
spawn_scope() {
	local unit="$1" logfile="$2"; shift 2
	local argv_q
	printf -v argv_q '%q ' "$@"
	SCOPE_UNITS+=("$unit")
	# systemd-run --scope runs the command in the foreground (blocks
	# until it exits), so background the client and disown it to keep
	# job-control "Killed" notices out of the gate's output.
	systemd-run --scope --quiet --unit="$unit" \
		bash -c "exec </dev/null >'$logfile' 2>&1; exec $argv_q" &
	disown "$!" 2>/dev/null || true
}

# Dump a victim pid with a given plugin sandbox into a per-call image
# dir. --shell-job because a scope-spawned process is not a session
# leader; -v4 so the plugin's pr_debug per-cdev probe lines are emitted.
dump_victim() {
	local pid="$1" libdir="$2" imgdir="$3"
	mkdir -p "$imgdir"
	"$CRIU" dump -t "$pid" -D "$imgdir" -v4 -o dump.log --shell-job \
		-L "$libdir" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Tier 1: presence detection.
# ---------------------------------------------------------------------------
sect "Tier 1: presence detection"

SB1="$(make_sandbox "$WORKDIR/sb_presence" "$MLX5_SO")"
spawn_scope "vfmig-gate-victim-$$" "$WORKDIR/t1.victim.log" sleep 600
V1=""
for _ in $(seq 1 50); do
	V1="$(pgrep -fx 'sleep 600' | head -1 || true)"
	[[ -n "$V1" ]] && break
	sleep 0.1
done
[[ -n "$V1" ]] || die "tier1 victim did not start"
echo "$V1" >"$WORKDIR/t1.pid"
IMG1="$WORKDIR/img_presence"
dump_victim "$V1" "$SB1" "$IMG1" || die "tier1 criu dump failed (see $IMG1/dump.log)"
LOG1="$IMG1/dump.log"
[[ -s "$LOG1" ]] || die "tier1 dump.log missing"

grep -qa 'Plugin "rdma_mlx5_vfmig_plugin"' "$LOG1" \
	|| die "mlx5_vfmig plugin did not load (no Plugin line in $LOG1)"
note "plugin loaded"

# Fini must run regardless of verdict.
grep -qaE 'rdma_mlx5_vfmig_plugin: fini \(stage [0-9]+ ret .*\): was (active|inactive)' "$LOG1" \
	|| die "no plugin fini line"
note "fini ran"

if [[ ! -d "$DEV_DIR" ]]; then
	# No kernel module / cdev dir: expect the opendir-miss inactive path.
	grep -qaE "rdma_mlx5_vfmig_plugin: opendir\($DEV_DIR\) failed" "$LOG1" \
		|| die "no cdev dir but plugin did not report the opendir-miss inactive path"
	grep -qa 'plugin inactive' "$LOG1" \
		|| die "no cdev dir but plugin did not declare itself inactive"
	note "no $DEV_DIR -> inactive via opendir-miss path (as expected)"
else
	# Independent host truth: number of cdev entries (plugin skips dotfiles).
	N_CDEV=0
	for e in "$DEV_DIR"/*; do
		[[ -e "$e" ]] || continue
		N_CDEV=$((N_CDEV + 1))
	done
	note "host has $N_CDEV cdev(s) under $DEV_DIR"

	# Per-cdev probe lines + summed tracked, straight from the plugin.
	# Note: the cdev name is a PCI BDF (e.g. 0000:08:00.1) which itself
	# contains colons, so match the name as [^ ]+ (up to the ": num_vfs").
	N_PROBE="$(grep -caE 'rdma_mlx5_vfmig_plugin: '"$DEV_DIR"'/[^ ]+: num_vfs=[0-9]+ tracked=[0-9]+' "$LOG1" || true)"
	SUM_TRACKED="$({ grep -oaE 'rdma_mlx5_vfmig_plugin: '"$DEV_DIR"'/[^ ]+: num_vfs=[0-9]+ tracked=[0-9]+' "$LOG1" || true; } \
		| { grep -oE 'tracked=[0-9]+' || true; } | awk -F= '{s+=$2} END{print s+0}')"
	note "plugin emitted $N_PROBE per-cdev probe line(s), sum(tracked)=$SUM_TRACKED"

	[[ "$N_PROBE" -eq "$N_CDEV" ]] \
		|| die "plugin probed $N_PROBE cdev(s) but host has $N_CDEV"

	ACTIVE_LINE="$(grep -aoE 'rdma_mlx5_vfmig_plugin: active \(stage [0-9]+\): [0-9]+ tracked VF\(s\) across [0-9]+ PF\(s\)' "$LOG1" | head -1 || true)"
	INACTIVE_LINE="$(grep -aoE 'rdma_mlx5_vfmig_plugin: inactive \(stage [0-9]+\): [0-9]+ PF cdev\(s\) probed, no tracked VFs' "$LOG1" | head -1 || true)"

	if [[ -n "$ACTIVE_LINE" ]]; then
		[[ -z "$INACTIVE_LINE" ]] || die "plugin logged BOTH active and inactive verdicts"
		local_T="$(sed -E 's/.*active \(stage [0-9]+\): ([0-9]+) tracked.*/\1/' <<<"$ACTIVE_LINE")"
		local_P="$(sed -E 's/.* across ([0-9]+) PF\(s\)/\1/' <<<"$ACTIVE_LINE")"
		[[ "$local_P" -eq "$N_CDEV" ]]     || die "active verdict PF count $local_P != host cdev count $N_CDEV"
		[[ "$local_T" -eq "$SUM_TRACKED" ]] || die "active verdict tracked $local_T != summed per-cdev tracked $SUM_TRACKED"
		[[ "$local_T" -gt 0 ]]             || die "active verdict but 0 tracked VFs"
		note "verdict: ACTIVE ($local_T tracked across $local_P PF) -- consistent"
	elif [[ -n "$INACTIVE_LINE" ]]; then
		[[ "$SUM_TRACKED" -eq 0 ]] || die "inactive verdict but sum(tracked)=$SUM_TRACKED > 0"
		local_P="$(sed -E 's/.*inactive \(stage [0-9]+\): ([0-9]+) PF cdev.*/\1/' <<<"$INACTIVE_LINE")"
		[[ "$local_P" -eq "$N_CDEV" ]] || die "inactive verdict PF count $local_P != host cdev count $N_CDEV"
		note "verdict: INACTIVE ($local_P PF cdev(s), 0 tracked) -- consistent"
	else
		die "plugin emitted neither an active nor an inactive verdict line"
	fi
fi

echo "tier1: PASS"

# ---------------------------------------------------------------------------
# Tier 2: claim arbitration decline (rxe context, both plugins loaded).
# ---------------------------------------------------------------------------
sect "Tier 2: claim arbitration decline"

want_claim="${VFMIG_GATE_CLAIM:-auto}"
skip_claim() { echo "[skip] claim tier -- $*"; echo; echo "PASS (tier1)"; exit 0; }

[[ "$want_claim" != "0" ]]        || skip_claim "disabled via VFMIG_GATE_CLAIM=0"
[[ -f "$RXE_SO" ]]                || skip_claim "rxe plugin not built ($RXE_SO)"
[[ -x "$HOLDER" ]]                || skip_claim "uverbs_ctx_holder not built ('make -C $HERE')"
command -v rdma >/dev/null 2>&1   || skip_claim "'rdma' tool not available"

# Ensure an rxe device exists (mirror run_uverbs_cr.sh).
modprobe rdma_rxe 2>/dev/null || true
if ! rdma link show 2>/dev/null | grep -qE '^link rxe0/'; then
	if [[ -z "$NETDEV" ]]; then
		NETDEV="$(ip -o -4 addr show up scope global | awk '{print $2; exit}')"
	fi
	[[ -n "$NETDEV" ]] || skip_claim "no netdev to bind rxe0 to"
	echo "creating rxe0 on $NETDEV"
	rdma link add rxe0 type rxe netdev "$NETDEV" || skip_claim "rdma link add rxe0 failed"
fi

SB2="$(make_sandbox "$WORKDIR/sb_claim" "$MLX5_SO" "$RXE_SO")"
STATUS="$WORKDIR/holder.status"
HLOG="$WORKDIR/holder.log"
spawn_scope "vfmig-gate-holder-$$" "$HLOG" "$HOLDER" rxe0 "$STATUS"
V2=""
for _ in $(seq 1 50); do
	V2="$(pgrep -fx "$HOLDER rxe0 $STATUS" | head -1 || true)"
	[[ -n "$V2" ]] && break
	sleep 0.1
done
[[ -n "$V2" ]] || { cat "$HLOG" >&2 2>/dev/null || true; die "tier2 holder did not start"; }
echo "$V2" >"$WORKDIR/t2.pid"
for _ in $(seq 1 50); do
	[[ -s "$STATUS" ]] && break
	sleep 0.1
done
[[ "$(cat "$STATUS" 2>/dev/null || true)" == "READY" ]] \
	|| { echo "holder failed to come up:" >&2; cat "$HLOG" >&2; die "tier2 holder not READY"; }
note "rxe holder ready (pid=$V2)"

IMG2="$WORKDIR/img_claim"
dump_victim "$V2" "$SB2" "$IMG2" || die "tier2 criu dump failed (see $IMG2/dump.log) -- rxe claim should have succeeded"
LOG2="$IMG2/dump.log"
note "dump succeeded (an RDMA plugin claimed the rxe context)"

grep -qa 'Plugin "rdma_mlx5_vfmig_plugin"' "$LOG2" || die "mlx5_vfmig plugin did not load in tier2"

# The mlx5 plugin's claim hook must have run for rxe0 and declined --
# either via the inactive short-circuit (this host) or the
# not-RDMA_DRIVER_MLX5 branch (a host with tracked mlx5 VFs).
grep -qaE 'rdma_mlx5_vfmig_plugin: claim\(rxe0,.*(plugin inactive|not RDMA_DRIVER_MLX5).*declining' "$LOG2" \
	|| die "mlx5 plugin did not emit a decline line for rxe0 (claim hook not wired into arbitration?)"
note "mlx5 declined the rxe context (claim hook reached + correct branch)"

# Arbitration must not have hit a conflict or a hard probe failure.
if grep -qaE 'RDMA plugin claim conflict|claim\(\) probe failed' "$LOG2"; then
	grep -aE 'RDMA plugin claim conflict|claim\(\) probe failed' "$LOG2" >&2
	die "claim arbitration reported a conflict / probe failure"
fi
note "no claim conflict / probe failure"

echo "tier2: PASS"
echo
echo "PASS"
