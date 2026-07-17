#!/bin/bash
#
# vfmig_barrier_ab.sh -- localize the post-restore reg_mr D-state wedge.
#
# The mlx5_vfmig cross-host barrier regresses staged no-live-QP restore
# cases: after a "successful" R1 (released=1 failed=0) a fresh post-restore
# ibv_reg_mr wedges forever in mlx5r_umr_post_send_wait. Removing the
# rendezvous descriptor makes it pass. This wrapper A/Bs the single-host
# harness (run_vfmig_cr.sh, pd_mr mode -- which does exactly one fresh
# post-restore ibv_reg_mr + Phase J RDMA-WRITE through the UMR path) to
# pin the regression to a specific half of the barrier.
#
# Configs, run GOOD-FIRST so we bank clean data before anything wedges:
#
#   legacy        UVERBS_CR_BARRIER=0        no descriptor (control; must PASS)
#   r1_park_off   VFMIG_R1_PARK=0            barrier armed, R1 rendezvous only
#                                            (no SUSPEND/RESUME(INITIATOR));
#                                            the fix candidate -- should PASS
#   barrier_full  (defaults)                 park->R1->resume (baseline repro;
#                                            HANGS if single-host reproduces)
#
# r1_park_off keeps the R1 *rendezvous* (so the harness R1 peer stub still
# completes) and only drops the park/unpark -- no harness coupling changes.
#
# SAFETY: a hung reg_mr leaves an unkillable D-state uverbs_ctx_holder
# holding its VF. After each config we scan for that; if found we STOP the
# whole run and DO NOT launch the next config (whose provision_vf would
# `echo 0 > sriov_numvfs` and wedge the box). The box then needs a reboot
# to reclaim the VF -- we report that rather than papering over it.
#
# Usage:  sudo PF=0000:08:00.0 ./vfmig_barrier_ab.sh
#   (env: PF, and any UVERBS_CR_* / BARRIER_* the runner honors)

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RUNNER="$HERE/run_vfmig_cr.sh"
PF="${PF:-0000:08:00.0}"
PER_CONFIG_TIMEOUT="${PER_CONFIG_TIMEOUT:-300}"
OUTDIR="$(mktemp -d /tmp/vfmig-ab-XXXXXX)"
PLUGIN_SO="${PLUGIN_SRC:-/usr/local/lib/criu}/rdma_mlx5_vfmig_plugin.so"

[[ -x "$RUNNER" ]] || { echo "missing runner $RUNNER" >&2; exit 1; }
[[ "$EUID" -eq 0 ]] || { echo "must run as root (sudo)" >&2; exit 1; }

# pd_mr-only, one thing per invocation; drop the other pass groups so each
# config is a fast, focused fresh-reg_mr probe.
COMMON_ENV=(
	UVERBS_CR_RUN_PD_MR=1
	UVERBS_CR_RUN_PD_CQ=0
	UVERBS_CR_RUN_PD_CQ_QP=0
	UVERBS_CR_RUN_PD_2CQ=0
	UVERBS_CR_RUN_PRERESTORE=0
	UVERBS_CR_RUN_KS7_3=0
	UVERBS_CR_RUN_LEGACY=0
	"PF=$PF"
)

# Optional: drive the destination LOAD/bind out-of-band BEFORE criu
# restore (manual_prerestore_dest), so the dest VF goes through
# consume_restored at probe and latches vfmig_self_restored=true -- the
# TX/UMR-gated "restored VF" state the inline-LOAD path never enters.
# This is the lever most likely to reproduce the cross-host wedge on a
# single host. Off by default (loopback stays safe); PASS_PRERESTORE=1
# ./vfmig_barrier_ab.sh to arm it.
if [[ "${PASS_PRERESTORE:-0}" == "1" ]]; then
	COMMON_ENV+=("PASS_PRERESTORE=1")
	echo "NOTE: PASS_PRERESTORE=1 -- dest VF will be self_restored"
	echo "      (TX/UMR-gated). barrier_full may WEDGE this box (D-state);"
	echo "      a reboot will be needed to reclaim the VF."
fi

# List D-state uverbs_ctx_holder processes (comm is truncated to 15 chars
# by the kernel, so match on the full argv via the [u]-glob grep trick).
dstate_holders() {
	ps -eo pid,stat,wchan:28,args 2>/dev/null \
		| grep -E '[u]verbs_ctx_holder' \
		| awk '$2 ~ /D/ { print }'
}

# Reap any *live* (non-D) leftover holder so it can't hold a VF into the
# next config. D-state ones are handled by the caller (we stop instead).
reap_live_holders() {
	local p
	for p in $(pgrep -f '[u]verbs_ctx_holder' 2>/dev/null || true); do
		kill -TERM "$p" 2>/dev/null || true
	done
	sleep 1
}

echo "=== vfmig barrier A/B ==="
echo "runner:   $RUNNER"
echo "PF:       $PF"
echo "plugin:   $PLUGIN_SO"
echo "outdir:   $OUTDIR"
echo "timeout:  ${PER_CONFIG_TIMEOUT}s per config"
echo
echo "plugin knob strings present:"
strings "$PLUGIN_SO" 2>/dev/null | grep -E 'VFMIG_R1_PARK|VFMIG_D1_BARRIER' \
	| sed 's/^/  /' || echo "  (WARNING: knob strings not found -- stale plugin?)"
echo

# Preflight: box must be clean of D-state holders before we touch SR-IOV.
if [[ -n "$(dstate_holders)" ]]; then
	echo "ABORT: pre-existing D-state uverbs_ctx_holder(s) -- reboot first:" >&2
	dstate_holders >&2
	exit 2
fi
reap_live_holders

# name | expectation | extra env...
CONFIGS=(
	"legacy|PASS (control)|UVERBS_CR_BARRIER=0"
	"r1_park_off|PASS (fix candidate)|UVERBS_CR_BARRIER=1|VFMIG_R1_PARK=0"
	"barrier_full|repro? (baseline)|UVERBS_CR_BARRIER=1"
)

declare -a SUMMARY
STOPPED=

for entry in "${CONFIGS[@]}"; do
	IFS='|' read -r name expect rest <<<"$entry"
	IFS='|' read -r -a cfg_env <<<"$rest"
	log="$OUTDIR/$name.log"

	echo "======================================================="
	echo ">>> config=$name  expect=$expect"
	echo "    extra env: ${cfg_env[*]}"
	echo "    log: $log"
	echo "======================================================="

	# Defensive: never launch a config while a D-state holder lingers.
	if [[ -n "$(dstate_holders)" ]]; then
		echo "STOP: D-state holder present before config=$name; not resetting VFs." >&2
		STOPPED="$name (pre-check)"
		break
	fi

	timeout "$PER_CONFIG_TIMEOUT" \
		env "${COMMON_ENV[@]}" "${cfg_env[@]}" bash "$RUNNER" \
		>"$log" 2>&1
	rc=$?

	sleep 1
	dstate="$(dstate_holders)"

	# Pull a few signal lines for the summary.
	r1line="$(grep -hE 'barrier\[R1\]|RESUME_DEVICES_LATE: released' "$log" | tail -2 | tr '\n' ';')"
	status="$(grep -hE 'post-restore status:' "$log" | tail -1)"
	txdis="$(grep -hcE 'TX disabled on restored VF|mlx5r_umr|Stage 1' "$log" 2>/dev/null)"
	txdis="${txdis:-0}"

	if [[ -n "$dstate" ]]; then
		result="HANG (D-state in UMR)"
		echo "!!! config=$name WEDGED -- D-state holder(s):"
		echo "$dstate" | sed 's/^/    /'
		SUMMARY+=("$name | $result | rc=$rc | TXdis=$txdis | $status")
		STOPPED="$name (D-state)"
		break
	elif [[ "$rc" -eq 0 ]]; then
		result="PASS"
	elif [[ "$rc" -eq 124 ]]; then
		result="TIMEOUT (${PER_CONFIG_TIMEOUT}s)"
		SUMMARY+=("$name | $result | rc=$rc | TXdis=$txdis | $status")
		STOPPED="$name (timeout)"
		break
	else
		result="FAIL (clean, rc=$rc)"
	fi

	echo "    result: $result   ${status:-<no status line>}"
	[[ -n "$r1line" ]] && echo "    R1: $r1line"
	SUMMARY+=("$name | $result | rc=$rc | TXdis=$txdis | $status")

	reap_live_holders
done

echo
echo "======================= SUMMARY ======================="
printf '%s\n' "${SUMMARY[@]}"
echo "======================================================="
echo "logs: $OUTDIR/*.log"
if [[ -n "$STOPPED" ]]; then
	echo
	echo "STOPPED after config: $STOPPED"
	echo "A holder is likely stuck in uninterruptible D-state holding a VF."
	echo "REBOOT to reclaim the VF before re-running. Interpret results from"
	echo "the configs that completed above."
	exit 3
fi
echo
echo "All configs completed without a D-state wedge."
