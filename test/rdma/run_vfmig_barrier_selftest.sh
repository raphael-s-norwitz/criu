#!/usr/bin/env bash
#
# run_vfmig_barrier_selftest.sh -- build + run the no-hardware single-host
# gate for the mlx5_sriov_vfmig plugin's cross-host READY barrier
# (vfmig_barrier.c).
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# This gate needs NO tracked VF, NO running criu, and NO plugin .so: it
# compiles vfmig_barrier.c straight into a small test binary
# (vfmig_barrier_selftest.c) that fork()s an independent peer speaking the
# same wire contract and drives the real vfmig_barrier_run() against it on
# 127.0.0.1. It covers both tie-break roles (plugin connects / plugin
# accepts) and a session-mismatch rejection.
#
# Usage:  ./run_vfmig_barrier_selftest.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PLUGIN_DIR="$ROOT/plugins/rdma/mlx5_sriov_vfmig"
PBH="$ROOT/images/mlx5_vfmig.pb-c.h"
BIN="$(mktemp -u /tmp/vfmig_barrier_selftest.XXXXXX)"

case "$(uname -m)" in
x86_64) ARCH=x86 ;;
aarch64) ARCH=aarch64 ;;
*) ARCH="$(uname -m)" ;;
esac

# vfmig_internal.h pulls the generated pb-c headers; regenerate on demand.
if [ ! -f "$PBH" ]; then
	echo "== generating image pb-c =="
	make -C "$ROOT" images/mlx5_vfmig.pb-c.c >/dev/null
fi

echo "== compiling vfmig_barrier_selftest =="
# -iquote (not -I) for in-tree dirs so they only satisfy #include "..."
# and never shadow system <...> headers -- same as the plugin Makefile.
cc -O2 -Wall -g \
	-iquote"$ROOT" \
	-iquote"$ROOT/include" \
	-iquote"$ROOT/criu/include" \
	-iquote"$ROOT/criu/arch/$ARCH/include" \
	-iquote"$PLUGIN_DIR" \
	"$HERE/vfmig_barrier_selftest.c" \
	"$PLUGIN_DIR/vfmig_barrier.c" \
	-o "$BIN"

echo "== running vfmig_barrier_selftest =="
rc=0
"$BIN" || rc=$?
rm -f "$BIN"

if [ "$rc" -ne 0 ]; then
	echo "VFMIG BARRIER SELFTEST: FAIL (rc=$rc)"
	exit "$rc"
fi
echo "VFMIG BARRIER SELFTEST: PASS"
