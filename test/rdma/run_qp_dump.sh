#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# rxe QP dump-side discovery dev gate. The holder creates a PD, a CQ,
# and an RC QP sharing that CQ (HOLDER_ALLOC_QP). criu dumps the
# process; the R3 dump-side uobject walker enumerates the QP over NLDEV
# and emits an R3UT_QP entry into rdma-uobj.img with three typed xrefs:
# R3XR_PARENT_PD (RES_PDN), R3XR_SEND_CQ (RES_SEND_CQN) and R3XR_RECV_CQ
# (RES_RECV_CQN). This gate asserts that entry is present and correctly
# shaped by decoding the image with crit.
#
# This is dump-only: QP restore is a later milestone, so the process is
# not restored. The holder is killed by the dump (default criu
# behaviour) and the image dir inspected afterwards.
#
# Usage:
#   sudo [CRIU=/path/to/criu] [CRIT=/path/to/crit] \
#        test/rdma/run_qp_dump.sh [<netdev>]
#
# Exits 0 on PASS, non-zero on FAIL.

set -euo pipefail

CRIU="${CRIU:-criu}"
CRIT="${CRIT:-crit}"
NETDEV="${1:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PROG="$HERE/uverbs_ctx_holder"
WORKDIR="$(mktemp -d /tmp/qp-dump-XXXXXX)"
PIDFILE="$WORKDIR/holder.pid"
STATUS="$WORKDIR/status"
LOG="$WORKDIR/holder.log"
DUMPDIR="$WORKDIR/img"

cleanup() {
	local p
	if [[ -f "$PIDFILE" ]]; then
		p="$(cat "$PIDFILE" 2>/dev/null || true)"
		[[ -n "$p" ]] && kill -KILL "$p" 2>/dev/null || true
	fi
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

#
# crit decoder. The rdma-uobj image magic is recent, so an
# already-installed crit may not know it; prefer the in-tree crit
# (repo root two levels up) when its pycriu package is present, and
# fall back to $CRIT otherwise.
#
REPO="$(cd "$HERE/../.." && pwd)"
if [[ -d "$REPO/crit/crit" && -f "$REPO/lib/pycriu/images/magic.py" ]]; then
	crit_decode() { PYTHONPATH="$REPO/lib:$REPO/crit" python3 -m crit decode "$@"; }
	echo "using in-tree crit ($REPO/crit)"
else
	require "$CRIT"
	crit_decode() { "$CRIT" decode "$@"; }
fi

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
		NETDEV="$(ip -o -4 addr show up scope global | awk '{print $2; exit}')"
	fi
	[[ -n "$NETDEV" ]] || {
		echo "no netdev available to bind rxe0 to" >&2
		exit 1
	}
	echo "creating rxe0 on $NETDEV"
	rdma link add rxe0 type rxe netdev "$NETDEV"
fi

#
# 2. Launch the QP-holding holder, daemonised.
#
echo "launching holder (HOLDER_ALLOC_QP)..."
HOLDER_ALLOC_QP=1 setsid "$PROG" rxe0 "$STATUS" >"$LOG" 2>&1 &
HOLDER_PID=$!
echo "$HOLDER_PID" >"$PIDFILE"

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
# 3. Dump (kills the holder).
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
# 4. Decode rdma-uobj.img and assert exactly the QP entry we expect.
#
IMG="$DUMPDIR/rdma-uobj.img"
[[ -s "$IMG" ]] || {
	echo "FAIL: no rdma-uobj.img emitted" >&2
	tail -80 "$DUMPDIR/dump.log" >&2 || true
	exit 1
}

JSON="$WORKDIR/uobj.json"
crit_decode -i "$IMG" -o "$JSON"
echo "--- rdma-uobj.img ---"
cat "$JSON"

#
# Assertions (python: robust JSON walk over the entry list).
#   * exactly one R3UT_QP entry
#   * it carries all three xref roles PARENT_PD / SEND_CQ / RECV_CQ
#   * each xref target_type is the expected class (PD, CQ, CQ)
#   * qp_type / qp_num are populated
#
python3 - "$JSON" <<'PY'
import json, sys

with open(sys.argv[1]) as f:
    doc = json.load(f)

entries = doc.get("entries", doc if isinstance(doc, list) else [])
qps = [e for e in entries if e.get("type") == "R3UT_QP"]
if len(qps) != 1:
    sys.exit("FAIL: expected 1 R3UT_QP entry, got %d" % len(qps))

qp = qps[0]
attrs = qp.get("qp", {})
if "qp_type" not in attrs or "qp_num" not in attrs:
    sys.exit("FAIL: QP entry missing qp_type/qp_num: %r" % attrs)

want = {"R3XR_PARENT_PD": "R3UT_PD", "R3XR_SEND_CQ": "R3UT_CQ", "R3XR_RECV_CQ": "R3UT_CQ"}
got = {x["role"]: x.get("target_type") for x in qp.get("xref", [])}
for role, tt in want.items():
    if role not in got:
        sys.exit("FAIL: QP entry missing xref role %s (have %r)" % (role, got))
    if got[role] != tt:
        sys.exit("FAIL: xref %s target_type=%s, want %s" % (role, got[role], tt))

print("QP entry OK: qp_num=%s qp_type=%s state=%s xrefs=%r" %
      (attrs.get("qp_num"), attrs.get("qp_type"), attrs.get("state"), got))
PY

echo "PASS"
