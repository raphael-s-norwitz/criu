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
WORKDIR="$(mktemp -d /tmp/uverbs-cr.XXXXXX)"
PIDFILE="$WORKDIR/holder.pid"
RESTORED_PIDFILE="$WORKDIR/restored.pid"
STATUS="$WORKDIR/status"
LOG="$WORKDIR/holder.log"
DUMPDIR="$WORKDIR/img"

# Best-effort sweep of any zombie holders from earlier runs that
# would otherwise contend for /dev/infiniband/uverbsN. The pgrep
# pattern matches the same argv shape we exec below.
pkill -KILL -fx "$PROG rxe0 .* pd_mr" 2>/dev/null || true

cleanup() {
	local pid p
	for pid in "$PIDFILE" "$RESTORED_PIDFILE"; do
		[[ -f "$pid" ]] || continue
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
mkdir -p "$WORKDIR"
echo "launching holder (pd_mr mode: pre-dump PD + reg_mr)..."
# pd_mr mode (S4a): rxe holder also registers a 4 KiB local-write
# MR pre-dump alongside the PD. The destination kernel's RESTORE_MR
# (with rxe LKEY/RKEY hint adoption, kernel f422e6ba6bdc) must
# install the MR at the same per-ufile handle and same wire keys
# for the libibverbs cache on the restored process to remain
# consistent. The holder's post-restore acid test asserts both.
setsid "$PROG" rxe0 "$STATUS" pd_mr >"$LOG" 2>&1 &
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

# S2 RESTORE_PD + S4a RESTORE_MR dispatch. The restore runs in
# three stages:
#   Phase A           (criu master, in uverbsfd_open() during
#                      prepare_fds, pre-VMA): VA-independent verbs
#                      -- RESTORE_PD today.
#   Phase B-prep      (criu master, in restore_one_alive_task right
#                      after open_vmas): walks Phase-A's stash and
#                      serialises one rst_rdma_mr per MR into ta->
#                      rdma_mrs (RM_PRIVATE) for the pie blob.
#   Phase B (pie)     (criu/pie/restorer.c, post-VMA-placement):
#                      iterates ta->rdma_mrs and issues UVERBS_
#                      METHOD_RESTORE_MR ioctl. This stage runs in
#                      the restored task with user VMAs live, which
#                      is what rxe's pin_user_pages_fast needs.
#
# Per-ufile summary lines:
#   Phase A           "ufile_id=... Phase A: restored 1 PD(s) [...]; 1 MR(s) deferred to post-VMA Phase B"
#   Phase B-prep      "ufile_id=... Phase B-prep: serialised 1 MR(s) [skipped 0] for pie restorer"
#   Phase B (pie)     "pie: PID: RDMA: ufile_id=... RESTORE_MR(target_handle=..., lkey=..., rkey=...) ok"
#
# pd_mr mode: holder allocates exactly one PD + one MR pre-dump, so
# Phase A must show 1 PD restored + 1 MR deferred, Phase B-prep must
# show 1 MR serialised, and the pie blob must report 1 RESTORE_MR ok.
if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\]; [1-9][0-9]* MR\(s\) deferred' \
	"$DUMPDIR/restore.log"; then
	echo "FAIL: restore.log shows no RESTORE_PD Phase-A dispatch by" \
	     "rdma_restore_uobj_dag_for_ufile() with deferred MRs --" \
	     "the per-ufile restore pass either didn't run, found no" \
	     "PD/MR entries, or skipped them for missing ufile_handle /" \
	     "QUERY_MR fields." >&2
	echo "--- restore log uobj DAG lines ---" >&2
	grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
		echo "(no uobj DAG lines at all)" >&2
	exit 1
fi
if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase B-prep: serialised [1-9][0-9]* MR\(s\) \[skipped 0\] for pie restorer' \
	"$DUMPDIR/restore.log"; then
	echo "FAIL: restore.log shows no RESTORE_MR Phase-B-prep" \
	     "serialisation in restore_one_alive_task -- the post-" \
	     "VMA hand-off to the pie restorer didn't run or every" \
	     "MR was skipped." >&2
	echo "--- restore log uobj DAG lines ---" >&2
	grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
		echo "(no uobj DAG lines at all)" >&2
	exit 1
fi
if ! grep -qE 'pie: [0-9]+: RDMA: ufile_id=[^ ]+ RESTORE_MR\(target_handle=[0-9]+, lkey=[0-9a-fx]+, rkey=[0-9a-fx]+\) ok' \
	"$DUMPDIR/restore.log"; then
	echo "FAIL: restore.log shows no RESTORE_MR pie-restorer" \
	     "dispatch -- the pie blob either didn't see the queued" \
	     "MR(s) (rdma_mrs_n=0 / RST_MEM_FIXUP_PPTR misorder) or" \
	     "the ioctl returned an error. Without Phase B firing," \
	     "the libibverbs MR cache in the restored process points" \
	     "at slots that don't exist in the kernel ucontext." >&2
	echo "--- restore log pie RDMA lines ---" >&2
	grep -E 'pie:.* RDMA:' "$DUMPDIR/restore.log" >&2 || \
		echo "(no pie RDMA lines at all)" >&2
	exit 1
fi
echo "RESTORE_PD (Phase A) + RESTORE_MR (pie Phase B) dispatched ok"

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

if [[ "$RESULT" == "OK" ]]; then
	#
	# 5a. Phase J -- data-path acid test through the restored MR.
	#
	# The holder writes status=OK only once Phase J's two
	# subtests have both produced WC_SUCCESS *and* the byte
	# patterns matched, so a runner-side grep is strictly
	# defense-in-depth. We still cross-check the holder.log line
	# to surface, in CI artefacts, the qp/key parameters that
	# went over the wire (qpns, lkeys, rkeys) and to fail
	# loudly if a future holder change ever drops the print
	# without changing the status semantics.
	#
	if ! grep -qE 'PHASE_J: ok qp_a=0x[0-9a-f]+ qp_b=0x[0-9a-f]+ len=[1-9][0-9]* restored_lkey=0x[0-9a-f]+ restored_rkey=0x[0-9a-f]+ peer_lkey=0x[0-9a-f]+ peer_rkey=0x[0-9a-f]+' \
		"$LOG"; then
		echo "FAIL: holder reported OK but holder.log has no" \
		     "PHASE_J: ok line. The status-vs-log invariant" \
		     "is broken; either the holder dropped the print" \
		     "or run_phase_j was bypassed." >&2
		echo "--- holder log tail ---" >&2
		tail -40 "$LOG" >&2 || true
		exit 1
	fi
	echo "Phase J data path:" \
	     "$(grep -E '^PHASE_J: ' "$LOG" | head -1)"
fi

if [[ "$RESULT" != "OK" ]]; then
	echo "FAIL"
	# Holder runs the §S3b incremental-coverage acid test:
	# build a fresh CQ + QP + MR on top of the *restored* PD,
	# then tear them down in dependency order, then dealloc
	# the restored PD. The shape mirrors the orchestrator-level
	# multi-host migration test and avoids the v0
	# dealloc-ordering tripwire (S3b alone leaves source
	# dependents alive in FW; rxe ducks the issue because it
	# has no FW gating but the same shape carries to mlx5).
	#
	# Specific failure modes the holder distinguishes:
	#   - "ibv_query_device after restore": ucontext / cdev
	#     reattach broken (RDMA_OPEN_UVERBS_CDEV path).
	#   - "ibv_create_cq on restored ucontext": fresh-resource
	#     creation against the restore-mode ucontext broken --
	#     usually means GET_CONTEXT didn't actually run in
	#     restore mode or the kernel ucontext is wedged.
	#   - "ibv_create_qp on pre-dump PD": Model A pdn adoption
	#     broken -- the kernel resolved g_pd->handle to the
	#     restored ib_pd but FW rejected CREATE_QP with that
	#     pdn under the new ucontext's uid. (For rxe, no FW;
	#     a failure here means the kernel-side ib_uobject /
	#     ib_pd binding is broken.)
	#   - "ibv_reg_mr on pre-dump PD": same as above for
	#     CREATE_MKEY -- the second half of Model A's gate.
	#   - "ibv_dealloc_pd of pre-dump PD (after draining
	#     dependents)": dependency-ordered teardown reached
	#     PD with all dependents already gone, so DEALLOC_PD
	#     should be unconditional. A failure here means
	#     the kernel-side ib_uobject leaked a dependent or
	#     adopted mpd->pdn is stale.
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
