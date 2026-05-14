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
WORKDIR="/tmp/uverbs-cr-keep-aeypy7"
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
# 3a. R3 (S1.b) dump-side DAG image assertion.
#
# rdma-uobj.img must exist and carry at least one entry. The
# holder allocates exactly one PD on rxe0 before its session is
# dumped, so the discovery walk should land one R3UT_PD record.
# We don't decode the protobuf body here -- crit's pycriu
# decoder doesn't know rdma-uobj yet (pre-existing crit/proto
# sync gap, tracked separately) -- but we do verify magic and
# that there's at least one length-prefixed entry past the
# IMG_COMMON + RDMA_UOBJ headers.
#
DAG_IMG="$DUMPDIR/rdma-uobj.img"
[[ -f "$DAG_IMG" ]] || {
	echo "FAIL: $DAG_IMG missing -- S1.b dump-side DAG walk" \
	     "didn't run or produced no image" >&2
	echo "--- dump log tail ---" >&2
	tail -40 "$DUMPDIR/dump.log" >&2 || true
	exit 1
}
DAG_SIZE=$(stat -c %s "$DAG_IMG")
[[ "$DAG_SIZE" -ge 18 ]] || {
	# 8 bytes of header + at least one nonzero-length entry.
	echo "FAIL: $DAG_IMG too small ($DAG_SIZE bytes) -- expected" \
	     "at least one rdma_uobj_entry" >&2
	exit 1
}
# uobj DAG: ibdev=... emitted=N dropped=M is the dump-side
# pr_info from rdma_dump_uobj_dag(). Confirm at least one
# entry was emitted (not dropped).
if ! grep -qE 'uobj DAG: ibdev=rxe0 emitted=[1-9]' \
	"$DUMPDIR/dump.log"; then
	echo "FAIL: dump.log shows no PD/CQ/QP/MR/SRQ uobjects" \
	     "emitted to rdma-uobj.img for ibdev=rxe0" >&2
	echo "--- dump log uobj DAG lines ---" >&2
	grep -E 'uobj DAG' "$DUMPDIR/dump.log" >&2 || \
		echo "(no uobj DAG lines at all)" >&2
	exit 1
fi
echo "rdma-uobj.img ok ($DAG_SIZE bytes; dump emitted >=1 uobject)"

#
# 4. Restore.
#
echo "criu restore -d -D $DUMPDIR"
"$CRIU" restore -D "$DUMPDIR" -v4 -o restore.log -d \
	--pidfile "$RESTORED_PIDFILE"
RESTORED_PID="$(cat "$RESTORED_PIDFILE")"
echo "restored pid=$RESTORED_PID"

#
# 4a. R3 (S1.c) restore-side DAG read+verify assertion.
#
# rdma_collect_uobj_dag() runs in crtools_prepare_shared() right
# after prepare_files(), and pr_info's a per-ufile DAG summary
# plus a "read+verify ok: N entries..." line on success. Confirm
# both showed up: the one-line-per-ufile summary (parameterised by
# the holder's hw_drv=RDMA_CRIU_DRIVER__RCD_RXE = 1) and the
# total-entries close-out.
#
if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ hw_drv=1 ' \
	"$DUMPDIR/restore.log"; then
	echo "FAIL: restore.log shows no R3 per-ufile DAG summary" \
	     "(rdma_collect_uobj_dag() didn't run, or didn't see" \
	     "any rxe ufile)" >&2
	echo "--- restore log uobj DAG lines ---" >&2
	grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
		echo "(no uobj DAG lines at all)" >&2
	exit 1
fi
if ! grep -qE 'uobj DAG: read\+verify ok' "$DUMPDIR/restore.log"; then
	echo "FAIL: restore.log shows no S1.c read+verify success" \
	     "line; the verify pass either errored or didn't run" >&2
	exit 1
fi

# K8a (kernel commit 0601c496b413, design/uobject_restore.md §7.5.1)
# emits ufile_handle alongside the existing per-class restrack id. The
# dump-side NLDEV walk picks it up for every entry that NLDEV emitted
# (PD/CQ/QP/MR/SRQ -- AH/CC/AEF flow via INFO_HANDLES, separate from
# this assertion). At least one of those entries must therefore arrive
# at restore with a populated ufile_handle, surfaced in the per-ufile
# summary as "handles=N/M" with N>0. Catch a regression where the new
# RES_HANDLE attr stops being parsed (compat shim wrong, kernel rev
# without K8a, the structured init path losing the field, etc.).
if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ .* handles=[1-9][0-9]*/[0-9]+' \
	"$DUMPDIR/restore.log"; then
	echo "FAIL: restore.log shows no per-ufile DAG summary with" \
	     "ufile_handle populated (handles=N/M, N>0)." \
	     "Either the kernel under test pre-dates K8a" \
	     "(0601c496b413), the build's compat shim doesn't match" \
	     "the kernel's RES_HANDLE numeric value, or the dump-side" \
	     "join lost the field." >&2
	echo "--- restore log uobj DAG lines ---" >&2
	grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
		echo "(no uobj DAG lines at all)" >&2
	exit 1
fi
echo "rdma-uobj.img verify pass ran clean on restore" \
     "(per-uobj ufile_handle populated)"

# S2 RESTORE_PD dispatch. uverbsfd_open() calls
# rdma_restore_uobj_dag_for_ufile() right after the plugin hands
# back the open cdev fd, which then issues UVERBS_METHOD_RESTORE_PD
# per PD entry recorded in rdma-uobj.img. The dispatcher logs a
# one-liner per-ufile when it actually issued any RESTORE_<TYPE>
# verbs. The holder allocates exactly one PD before dump, so we
# expect "restored 1 PD(s), skipped 0".
if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ restored [1-9][0-9]* PD\(s\), skipped 0' \
	"$DUMPDIR/restore.log"; then
	echo "FAIL: restore.log shows no RESTORE_PD dispatch by" \
	     "rdma_restore_uobj_dag_for_ufile() -- the per-ufile" \
	     "S2 restore pass either didn't run, found no PD entry," \
	     "or skipped the entry for missing ufile_handle." >&2
	echo "--- restore log uobj DAG lines ---" >&2
	grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
		echo "(no uobj DAG lines at all)" >&2
	exit 1
fi
echo "RESTORE_PD dispatched ok by rdma_restore_uobj_dag_for_ufile()"

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
	# Strict from S2 onward: ibv_dealloc_pd of the pre-dump PD
	# must succeed, because uverbsfd_open() now drives
	# UVERBS_METHOD_RESTORE_PD per rdma-uobj.img entry to
	# reinstall the kernel-side PD uobject at its original
	# ufile_handle. Any "FAIL: ibv_dealloc_pd of pre-dump PD"
	# from the holder is a real regression in that path -- one
	# of: rxe_send_get_context_restore() not opening the cdev
	# in restore mode (-> RESTORE_PD -EPERM), kernel rev pre-K3
	# /K4 (-> -EOPNOTSUPP), DAG-side dropping ufile_handle, or
	# the dispatcher passing the wrong driver_id (-> -EINVAL,
	# the bug found and fixed during S2 bring-up).
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
