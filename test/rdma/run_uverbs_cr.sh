#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# Validates that criu can dump and restore a process holding an open
# rxe uverbs cdev fd plus its implicitly-created async-event fd.
#
# Usage:
#   sudo [CRIU=/path/to/criu] test/rdma/run_uverbs_cr.sh [<netdev>]
#
# <netdev> defaults to the first up IPv4 netdev. Override if the
# autodetect picks the wrong one.
#
# Exits 0 on PASS, non-zero on FAIL.

set -euo pipefail

CRIU="${CRIU:-criu}"
NETDEV="${1:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PROG="$HERE/uverbs_ctx_holder"
WORKDIR="$(mktemp -d /tmp/uverbs-cr-XXXXXX)"
PIDFILE="$WORKDIR/holder.pid"
RESTORED_PIDFILE="$WORKDIR/restored.pid"
STATUS="$WORKDIR/status"
LOG="$WORKDIR/holder.log"
DUMPDIR="$WORKDIR/img"

cleanup() {
	local pid
	for pid in "$PIDFILE" "$RESTORED_PIDFILE"; do
		[[ -f "$pid" ]] || continue
		local p
		p="$(cat "$pid" 2>/dev/null || true)"
		[[ -n "$p" ]] || continue
		kill -KILL "$p" 2>/dev/null || true
	done
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

require() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "missing required tool: $1" >&2
		exit 1
	}
}

require rdma
require ibv_devices
require "$CRIU"

[[ -x "$PROG" ]] || {
	echo "build $PROG first: 'make -C $HERE'" >&2
	exit 1
}

[[ "$EUID" -eq 0 ]] || {
	echo "must run as root (criu dump + rdma link add)" >&2
	exit 1
}

#
# 1. Ensure rxe0 exists.
#
modprobe rdma_rxe 2>/dev/null || true
if ! rdma link show 2>/dev/null | grep -qE '^link rxe0/'; then
	if [[ -z "$NETDEV" ]]; then
		NETDEV="$(ip -o -4 addr show up scope global \
			  | awk '{print $2; exit}')"
	fi
	[[ -n "$NETDEV" ]] || {
		echo "no netdev available to bind rxe0 to" >&2
		exit 1
	}
	echo "creating rxe0 on $NETDEV"
	rdma link add rxe0 type rxe netdev "$NETDEV"
fi

ibv_devices

#
# 2. Launch the holder, daemonised so it has its own session.
#    setsid + & keeps it alive across this shell exit.
#
echo "launching holder..."
setsid "$PROG" rxe0 "$STATUS" >"$LOG" 2>&1 &
HOLDER_PID=$!
echo "$HOLDER_PID" >"$PIDFILE"

# Wait for READY.
for _ in $(seq 1 50); do
	[[ -s "$STATUS" ]] && break
	sleep 0.1
done
[[ "$(cat "$STATUS" 2>/dev/null || true)" == "READY" ]] || {
	echo "holder failed to come up:" >&2
	cat "$LOG" >&2
	exit 1
}
echo "holder ready (pid=$HOLDER_PID)"
grep -E '^READY ' "$LOG" || true

#
# 3. Dump.
#
mkdir -p "$DUMPDIR"
echo "criu dump -t $HOLDER_PID -D $DUMPDIR"
"$CRIU" dump -t "$HOLDER_PID" -D "$DUMPDIR" -v4 -o dump.log

if kill -0 "$HOLDER_PID" 2>/dev/null; then
	echo "BUG: holder still alive after dump" >&2
	exit 1
fi
echo "dump ok; holder gone"

#
# 4. Restore.
#
echo "criu restore -d -D $DUMPDIR"
"$CRIU" restore -D "$DUMPDIR" -v4 -o restore.log -d \
	--pidfile "$RESTORED_PIDFILE"
RESTORED_PID="$(cat "$RESTORED_PIDFILE")"
echo "restored pid=$RESTORED_PID"

#
# 5. Verify post-restore context is functional.
#
echo "WAITING" >"$STATUS"
kill -USR1 "$RESTORED_PID"
for _ in $(seq 1 50); do
	cur="$(cat "$STATUS" 2>/dev/null || true)"
	[[ "$cur" != "WAITING" ]] && break
	sleep 0.1
done
RESULT="$(cat "$STATUS" 2>/dev/null || true)"
echo "post-restore status: $RESULT"

if [[ "$RESULT" != "OK" ]]; then
	echo "FAIL"
	# 'FAIL: ibv_dealloc_pd of pre-dump PD' is the canonical
	# "kernel uobject state was not preserved across the cdev dump"
	# signal -- distinct from a real regression. The test goes
	# green when uobject save/replay lands; until then this is the
	# regression-test fixture for that work.
	case "$RESULT" in
	"FAIL: ibv_dealloc_pd of pre-dump PD"*)
		echo "(known PD-uobject preservation gap; not a regression)" >&2
		;;
	esac
	echo "--- dump log tail ---" >&2
	tail -80 "$DUMPDIR/dump.log" >&2 || true
	echo "--- restore log tail ---" >&2
	tail -80 "$DUMPDIR/restore.log" >&2 || true
	exit 1
fi

#
# 6. Tear down cleanly.
#
kill -TERM "$RESTORED_PID" 2>/dev/null || true
echo "PASS"
