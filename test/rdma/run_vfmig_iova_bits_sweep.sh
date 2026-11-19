#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# Run a vfmig C/R gate once per IOVA window size, then once with the
# destination tracked with the wrong window and once with it untracked.
# Every gate takes IOVA_BITS and tracks its VFs with it, so this checks
# that dump records the window and restore follows it at each size; the
# mismatch run checks that restore refuses an image before LOAD when the
# destination's window differs, and the untracked run that the plugin
# tracks the destination with the image's window itself.
#
# A size the PF does not list in /sys/class/mlx5_vfmig/mlx5_vfmig!<PF>/
# iova_bits is skipped, and noted. The mismatch and untracked runs use
# the first two sizes that are run; they need run_vfmig_xvf_cr.sh, the
# only gate that takes MISMATCH_BITS and DST_TRACK.
#
# Environment:
#   PF            PF BDF (default 0000:08:00.0)
#   BITS          sizes to run (default "39 36 34")
#   TEST          gate to run (default run_vfmig_xvf_cr.sh)
#   MISMATCH      1 (default) to add the mismatch and untracked runs, 0 to
#                 skip them
#   VFMIG_CR_HW   passed to TEST; defaults to 1 here, so a skip fails
#   plus whatever else TEST takes (VFMIG_TOOL, SRC_VF, DST_VF, ...)
#
# Usage:
#   sudo PF=0000:08:00.0 VFMIG_TOOL=/path/to/mlx5_vfmig \
#       test/rdma/run_vfmig_iova_bits_sweep.sh
#   sudo BITS="38 35" TEST=run_vfmig_qp_cr.sh MISMATCH=0 ... \
#       test/rdma/run_vfmig_iova_bits_sweep.sh
#
# Exits 0 when every run passes, non-zero on the first failure.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export PF="${PF:-0000:08:00.0}"
# A gate that self-skips would otherwise count as a pass.
export VFMIG_CR_HW="${VFMIG_CR_HW:-1}"
BITS="${BITS:-39 36 34}"
TEST="${TEST:-run_vfmig_xvf_cr.sh}"
MISMATCH="${MISMATCH:-1}"

die()  { echo "FAIL: $*" >&2; exit 1; }
sect() { printf '\n==== %s ====\n' "$*"; }

[[ -x "$HERE/$TEST" ]] || die "no gate $HERE/$TEST"
WINDOWS_F="/sys/class/mlx5_vfmig/mlx5_vfmig!$PF/iova_bits"
[[ -r "$WINDOWS_F" ]] || die "$WINDOWS_F missing (kernel predates IOVA window selection)"
WINDOWS="$(cat "$WINDOWS_F")"
echo "PF $PF windows: $WINDOWS; running $TEST with BITS=\"$BITS\""

RAN=()
for b in $BITS; do
	if [[ " $WINDOWS " != *" $b "* ]]; then
		echo "[skip] $b bits: not listed for PF $PF"
		continue
	fi
	sect "$TEST IOVA_BITS=$b"
	IOVA_BITS="$b" "$HERE/$TEST" || die "$TEST failed with IOVA_BITS=$b"
	RAN+=("$b")
done
(( ${#RAN[@]} )) || die "none of BITS=\"$BITS\" is listed for PF $PF"

if [[ "$MISMATCH" == 1 ]]; then
	[[ "$TEST" == run_vfmig_xvf_cr.sh ]] || die "MISMATCH=1 needs TEST=run_vfmig_xvf_cr.sh"
	(( ${#RAN[@]} >= 2 )) || die "MISMATCH=1 needs two sizes that ran (ran: ${RAN[*]})"
	sect "$TEST IOVA_BITS=${RAN[0]} MISMATCH_BITS=${RAN[1]}"
	IOVA_BITS="${RAN[0]}" MISMATCH_BITS="${RAN[1]}" "$HERE/$TEST" \
		|| die "$TEST failed with IOVA_BITS=${RAN[0]} MISMATCH_BITS=${RAN[1]}"
	sect "$TEST IOVA_BITS=${RAN[1]} DST_TRACK=0"
	IOVA_BITS="${RAN[1]}" DST_TRACK=0 "$HERE/$TEST" \
		|| die "$TEST failed with IOVA_BITS=${RAN[1]} DST_TRACK=0"
fi

echo
echo "PASS (IOVA_BITS ${RAN[*]}; mismatch and untracked-destination runs: $([[ "$MISMATCH" == 1 ]] && echo yes || echo no))"
