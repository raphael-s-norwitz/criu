#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# Validates that criu can dump and restore a process holding an open
# rxe uverbs cdev fd plus its implicitly-created async-event fd.
#
# Two passes per run, both end-to-end:
#
#   pass 1 (aligned)    legacy Phase J baseline. 4 KiB MR registered
#                       at the base of a 4 KiB page-aligned buffer;
#                       umem fits in one page so the source-side
#                       dom->pages registry holds a single sibling
#                       entry. Sanity-only on rxe (no vfmig_iova
#                       index in play); kept as a green-line baseline
#                       so a runtime regression localises which pass
#                       broke.
#
#   pass 2 (unaligned)  multi-page regression coverage for
#                       kernel commit "mlx5_vfmig: support multi-page
#                       user objects in the secondary index". 4 KiB
#                       MR registered at offset 0x800 inside an 8 KiB
#                       allocation, so the umem covers second half of
#                       page 0 + first half of page 1. On mlx5_vfmig
#                       this exercises the (instance_key, iova)
#                       composite index that pre-fix collapsed
#                       multi-page MRs to one tree slot and rolled
#                       them back to KIND_NONE on the second sibling
#                       insert. On rxe this is a CRIU-side wire-format
#                       sanity check: the kernel's rxe_restore_mr
#                       handler doesn't depend on iova ordering, but a
#                       regression in CRIU's QUERY_MR / image-format /
#                       restore-side mr->user_addr plumbing for
#                       offset-pinned umems would surface here as a
#                       restore-time failure.
#
# Usage:
#   sudo [CRIU=/path/to/criu] test/rdma/run_uverbs_cr.sh [<netdev>]
#
# <netdev> defaults to the first up IPv4 netdev. Override if the
# autodetect picks the wrong one.
#
# Exits 0 on PASS (both passes green), non-zero on FAIL (first
# failing pass). Per-pass artefacts are preserved in
# $WORKDIR/<pass-name>/ until the cleanup trap fires; on success
# the workdir is removed.

set -euo pipefail

CRIU="${CRIU:-criu}"
NETDEV="${1:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PROG="$HERE/uverbs_ctx_holder"
WORKDIR="$(mktemp -d /tmp/uverbs-cr.XXXXXX)"

# Best-effort sweep of any zombie holders from earlier runs that
# would otherwise contend for /dev/infiniband/uverbsN. The pgrep
# pattern matches the same argv shape we exec below for any of
# the holder modes this script drives.
pkill -KILL -fx "$PROG rxe0 .* (pd_mr|pd_cq)" 2>/dev/null || true

cleanup() {
	local pidfile p
	# Walk every per-pass holder/restored pidfile under $WORKDIR.
	for pidfile in "$WORKDIR"/*/holder.pid \
		       "$WORKDIR"/*/restored.pid; do
		[[ -f "$pidfile" ]] || continue
		p="$(cat "$pidfile" 2>/dev/null || true)"
		[[ -n "$p" ]] || continue
		kill -KILL "$p" 2>/dev/null || true
	done
	# UVERBS_CR_KEEP_WORKDIR=1 preserves the per-pass image dir + logs
	# on FAIL exit, so the operator can post-mortem the dump.log /
	# restore.log / holder.log without racing the cleanup trap. The
	# default removes the workdir after a green run to keep /tmp tidy.
	if [[ "${UVERBS_CR_KEEP_WORKDIR:-0}" == "1" ]]; then
		echo "preserving WORKDIR=$WORKDIR (UVERBS_CR_KEEP_WORKDIR=1)"
	else
		rm -rf "$WORKDIR"
	fi
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

# CRIU has no --disable-plugin CLI; the closest knob is -L/--libdir
# which overrides the entire plugin search dir. amdgpu_plugin
# unconditionally hooks CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA and
# returns an error (rather than declining) when /dev/kfd is absent
# on hosts without an AMD GPU, which fires for any unrecognised
# /dev/* mapping including any /dev/infiniband/uverbsN VMAs (rxe
# CQ/QP/SRQ rings; libmlx5 UAR/clock pages). Build a sandbox plugin
# dir with only the RDMA plugins (the ones this test cares about)
# and point criu at it via -L. Mirrors what run_vfmig_cr.sh does
# for the same reason.
PLUGIN_SRC="${PLUGIN_SRC:-/usr/local/lib/criu}"
PLUGIN_SANDBOX="$WORKDIR/plugins"
mkdir -p "$PLUGIN_SANDBOX"
for p in rdma_rxe_plugin.so rdma_mlx5_vfmig_plugin.so; do
	[[ -f "$PLUGIN_SRC/$p" ]] || {
		echo "missing plugin $PLUGIN_SRC/$p -- 'make install' first" >&2
		exit 1
	}
	ln -sf "$PLUGIN_SRC/$p" "$PLUGIN_SANDBOX/$p"
done
CRIU_LIB_FLAG="-L $PLUGIN_SANDBOX"

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
# run_pass <pass_name> <holder_mode> <unaligned: 0|1>
#
# One end-to-end dump+restore+post-restore-checks cycle, scoped to
# $WORKDIR/<pass_name>/ for image dir, holder log, status file, and
# pidfiles. Returns 0 on success, exits the script (non-zero) on
# failure with a descriptive message and a tail of the relevant
# CRIU log.
#
# Holder modes covered (see uverbs_ctx_holder.c::enum holder_mode):
#   pd_mr  -- S4a coverage: pre-dump PD + reg_mr; unaligned ∈ {0, 1}
#             switches between aligned baseline and the multi-page
#             non-page-aligned regression scenario.
#   pd_cq  -- S5a coverage: pre-dump PD + ibv_create_cq; the post-
#             restore acid test asserts the source's CQ ufile_handle
#             survived (g_cq->handle equality on the post-restore
#             READY-equivalent) and that ibv_destroy_cq on the
#             restored CQ succeeds. unaligned is a no-op (pd_cq has
#             no MR geometry axis); we still pass it for argument-
#             shape symmetry across modes.
#
# Splitting passes into per-pass sub-workdirs keeps each run
# independently triagable when one fails.
#
run_pass() {
	local pass="$1"
	local holder_mode="$2"
	local unaligned="$3"

	local PASS_DIR="$WORKDIR/$pass"
	local PIDFILE="$PASS_DIR/holder.pid"
	local RESTORED_PIDFILE="$PASS_DIR/restored.pid"
	local STATUS="$PASS_DIR/status"
	local LOG="$PASS_DIR/holder.log"
	local DUMPDIR="$PASS_DIR/img"

	mkdir -p "$DUMPDIR"

	echo
	echo "=========================="
	echo " pass=$pass mode=$holder_mode unaligned=$unaligned"
	echo "=========================="

	# Sweep any leftover holder from a previous pass before we
	# start a new one (we own /dev/infiniband/uverbsN exclusively).
	pkill -KILL -fx "$PROG rxe0 $STATUS $holder_mode" 2>/dev/null || true

	#
	# 2. Launch the holder, daemonised so it has its own session.
	#    setsid + & keeps it alive across this shell exit.
	#
	echo "launching holder (mode=$holder_mode; unaligned=$unaligned)..."
	# pd_mr (S4a): rxe holder also registers a 4 KiB local-write MR
	# pre-dump alongside the PD. The destination kernel's RESTORE_MR
	# (with rxe LKEY/RKEY hint adoption, kernel f422e6ba6bdc) must
	# install the MR at the same per-ufile handle and same wire keys
	# for the libibverbs cache on the restored process to remain
	# consistent. The holder's post-restore acid test asserts both.
	#
	# pd_cq (S5a): rxe holder also creates a CQ pre-dump alongside
	# the PD. The destination kernel's RESTORE_CQ (a77cc4d8e8b9)
	# must install the CQ at the source's ufile_handle; the holder
	# asserts identity preservation by destroying the restored CQ
	# (which would EINVAL if the IDR slot were empty).
	UVERBS_HOLDER_UNALIGNED_MR="$unaligned" \
	setsid "$PROG" rxe0 "$STATUS" "$holder_mode" >"$LOG" 2>&1 &
	local HOLDER_PID=$!
	echo "$HOLDER_PID" >"$PIDFILE"

	# Wait for READY.
	local _ cur
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

	# Cross-check that the pd_mr holder picked up the requested
	# geometry. A regression where UVERBS_HOLDER_UNALIGNED_MR is
	# read wrong (e.g. dropped by the env-stripping daemonisation,
	# or env parsing flipped) would silently turn pass=unaligned
	# into a duplicate of pass=aligned. pd_cq has no MR geometry
	# to validate.
	if [[ "$holder_mode" == "pd_mr" ]]; then
		if ! grep -qE "^READY .* mr_unaligned=$unaligned " "$LOG"; then
			echo "FAIL: holder READY line does not advertise" \
			     "mr_unaligned=$unaligned -- env-var plumbing" \
			     "broken or holder didn't honour" \
			     "UVERBS_HOLDER_UNALIGNED_MR" >&2
			grep -E '^READY ' "$LOG" >&2 || true
			exit 1
		fi
	fi

	#
	# 3. Dump.
	#
	echo "criu dump -t $HOLDER_PID -D $DUMPDIR"
	"$CRIU" $CRIU_LIB_FLAG dump -t "$HOLDER_PID" -D "$DUMPDIR" \
		-v4 -o dump.log

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
	local DAG_IMG="$DUMPDIR/rdma-uobj.img"
	[[ -f "$DAG_IMG" ]] || {
		echo "FAIL: $DAG_IMG missing -- S1.b dump-side DAG walk" \
		     "didn't run or produced no image" >&2
		echo "--- dump log tail ---" >&2
		tail -40 "$DUMPDIR/dump.log" >&2 || true
		exit 1
	}
	local DAG_SIZE=$(stat -c %s "$DAG_IMG")
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
	"$CRIU" $CRIU_LIB_FLAG restore -D "$DUMPDIR" -v4 \
		-o restore.log -d --pidfile "$RESTORED_PIDFILE"
	local RESTORED_PID="$(cat "$RESTORED_PIDFILE")"
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

	# S2 RESTORE_PD baseline assertion (every mode emits PDs).
	# RESTORE_CQ / RESTORE_MR / Phase B assertions are layered on
	# top per holder_mode.
	#
	#   Phase A           (criu master, in uverbsfd_open() during
	#                      prepare_fds, pre-VMA): VA-independent verbs
	#                      -- RESTORE_PD always; RESTORE_CQ in pd_cq.
	#   Phase B-prep      (criu master, in restore_one_alive_task right
	#                      after open_vmas): walks Phase-A's stash and
	#                      serialises one rst_rdma_mr per MR into ta->
	#                      rdma_mrs (RM_PRIVATE) for the pie blob.
	#                      Only fires when at least one MR is deferred
	#                      (pd_mr mode).
	#   Phase B (pie)     (criu/pie/restorer.c, post-VMA-placement):
	#                      iterates ta->rdma_mrs and issues UVERBS_
	#                      METHOD_RESTORE_MR ioctl. This stage runs in
	#                      the restored task with user VMAs live, which
	#                      is what rxe's pin_user_pages_fast needs.
	#                      Only fires when Phase B-prep ran.
	#
	# Per-ufile summary line shape (rdma.c::rdma_restore_uobj_dag_for_ufile):
	#   "Phase A: restored N PD(s) [skipped M], P CQ(s) [skipped Q]; R MR(s) deferred ..."
	#
	# Mode-specific minima:
	#   pd_mr  P=0  R>=1   : 1 PD, 0 CQ, >=1 MR deferred + pie ok
	#   pd_cq  P>=1 R=0    : 1 PD, >=1 CQ restored, 0 MR deferred
	if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\], [0-9]+ CQ\(s\) \[skipped [0-9]+\]; [0-9]+ MR\(s\) deferred' \
		"$DUMPDIR/restore.log"; then
		echo "FAIL: restore.log shows no RESTORE_PD Phase-A dispatch" \
		     "by rdma_restore_uobj_dag_for_ufile() -- the per-ufile" \
		     "restore pass either didn't run, found no PD entries, or" \
		     "skipped them for missing ufile_handle / QUERY_MR fields." >&2
		echo "--- restore log uobj DAG lines ---" >&2
		grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
			echo "(no uobj DAG lines at all)" >&2
		exit 1
	fi

	if [[ "$holder_mode" == "pd_mr" ]]; then
		if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\], [0-9]+ CQ\(s\) \[skipped [0-9]+\]; [1-9][0-9]* MR\(s\) deferred' \
			"$DUMPDIR/restore.log"; then
			echo "FAIL: pd_mr Phase-A summary line did not show" \
			     ">=1 MR deferred for post-VMA Phase B." >&2
			grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || true
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
	elif [[ "$holder_mode" == "pd_cq" ]]; then
		# pd_cq must restore >=1 CQ in Phase A and defer 0 MRs.
		# The summary line carries both counts; we assert
		# >=1 CQ restored and 0 MR deferred specifically.
		if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\], [1-9][0-9]* CQ\(s\) \[skipped 0\]; 0 MR\(s\) deferred' \
			"$DUMPDIR/restore.log"; then
			echo "FAIL: pd_cq Phase-A summary line did not show" \
			     ">=1 CQ restored with 0 MR deferred. Either the" \
			     "S5a RESTORE_CQ pass didn't run, the kernel under" \
			     "test pre-dates a77cc4d8e8b9 'RDMA/uverbs: Add" \
			     "RESTORE_CQ + rxe impl', or the dump-side R3 walk" \
			     "didn't emit a CQ entry for the holder's" \
			     "pre-dump ibv_create_cq." >&2
			echo "--- restore log uobj DAG lines ---" >&2
			grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
				echo "(no uobj DAG lines at all)" >&2
			exit 1
		fi
		echo "RESTORE_PD + RESTORE_CQ (Phase A) dispatched ok"
	fi

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
	local RESULT="$(cat "$STATUS" 2>/dev/null || true)"
	echo "post-restore status: $RESULT"

	if [[ "$RESULT" == "OK" && "$holder_mode" == "pd_mr" ]]; then
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
		echo "FAIL ($pass)"
		# Holder runs the §S3b incremental-coverage acid test:
		# build a fresh CQ + QP + MR on top of the *restored* PD,
		# then tear them down in dependency order, then dealloc
		# the restored PD. The shape mirrors the orchestrator-level
		# multi-host migration test and avoids the v0
		# dealloc-ordering tripwire (S3b alone leaves source
		# dependents alive in FW; rxe ducks the issue because it
		# has no FW gating but the same shape carries to mlx5).
		echo "--- dump log tail ---" >&2
		tail -80 "$DUMPDIR/dump.log" >&2 || true
		echo "--- restore log tail ---" >&2
		tail -80 "$DUMPDIR/restore.log" >&2 || true
		exit 1
	fi

	#
	# 6. Tear down cleanly. Restored holder gets SIGTERM so it
	#    deallocs its kernel resources and unbinds the uverbs cdev
	#    before the next pass tries to take it.
	#
	kill -TERM "$RESTORED_PID" 2>/dev/null || true
	# Give it a beat so /dev/infiniband/uverbsN isn't still busy
	# when the next pass tries to ibv_open_device().
	for _ in $(seq 1 20); do
		kill -0 "$RESTORED_PID" 2>/dev/null || break
		sleep 0.1
	done
	echo "pass=$pass: PASS"
}

# ---- driver ---------------------------------------------------------
# pd_mr passes:    aligned baseline + unaligned multi-page regression
#                  (kernel commit "mlx5_vfmig: support multi-page user
#                  objects in the secondary index"). On rxe these
#                  exercise CRIU's QUERY_MR + RESTORE_MR pipeline; on
#                  mlx5 the unaligned pass exercises the composite
#                  (instance_key, iova) secondary index.
# pd_cq pass:      S5a RESTORE_CQ regression -- pre-dump PD + CQ;
#                  asserts CQ ufile_handle preservation across
#                  dump+restore via ibv_destroy_cq round-trip, and
#                  exercises the full S5a-vma-remap path:
#                    1. kernel: rxe_restore_cq honours an UHW_IN
#                       source vm_pgoff, binding the new CQ's mmap
#                       region at the dumped offset (rxe_create_
#                       mmap_info(forced_offset)). The req struct
#                       is sized > 8 bytes to escape the uverbs
#                       inline-attr trap.
#                    2. CRIU: rdma_record_cdev_vma() (rxe plugin
#                       PROCESS_DEVICE_VMA) feeds the dump-side
#                       vm_pgoff into a side-table that
#                       rdma_send_restore_cq replays as UHW_IN at
#                       restore time.
#                    3. CRIU: the rxe plugin's UPDATE_VMA_MAP hook
#                       hands open_filemap a dup of the cdev fd
#                       open_uverbs_cdev minted with GET_CONTEXT
#                       (RESTORE_MODE), so the pie restorer's
#                       mmap lands on the *same struct file* that
#                       has the ucontext attached -- without the
#                       dup, ib_uverbs_mmap rejects via
#                       ib_uverbs_get_ucontext_file -EINVAL.
#                  UVERBS_CR_RUN_PD_CQ=0 still works as a kill
#                  switch for kernels missing the rxe forced-pgoff
#                  patch.
run_pass pd_mr_aligned   pd_mr 0
run_pass pd_mr_unaligned pd_mr 1
if [[ "${UVERBS_CR_RUN_PD_CQ:-1}" == "1" ]]; then
	run_pass pd_cq pd_cq 0
else
	echo
	echo "[skip] pd_cq pass disabled by UVERBS_CR_RUN_PD_CQ=0."
	echo "       Default is to run; this switch exists for"
	echo "       kernels that pre-date the rxe forced-vm_pgoff"
	echo "       support in rxe_restore_cq (S5a-vma-remap)."
fi

echo
echo "ALL PASSES OK"
echo "PASS"
