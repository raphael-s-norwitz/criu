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
pkill -KILL -fx "$PROG rxe0 .* (pd_mr|pd_cq|pd_2cq|pd_cq_qp|pd_cq_qp_sq)" 2>/dev/null || true

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
	#                      -- RESTORE_PD only. CQs and MRs are both
	#                      pin-sensitive (rxe / mlx5_ib pin user pages
	#                      via pin_user_pages_fast against current->mm)
	#                      so they're deferred to the pie blob below.
	#   Phase B-prep      (criu master, in restore_one_alive_task right
	#                      after open_vmas): walks Phase-A's pending
	#                      list and serialises one rst_rdma_{cq,mr}
	#                      per CQ / MR into ta->rdma_{cqs,mrs}
	#                      (RM_PRIVATE) for the pie blob, invoking the
	#                      plugin's UHW_PACK hook to stage driver-
	#                      opaque UHW_IN bytes + a verify-template
	#                      for UHW_OUT.
	#   Phase B (pie)     (criu/pie/restorer.c, post-VMA-placement):
	#                      iterates ta->rdma_cqs then ta->rdma_mrs and
	#                      issues UVERBS_METHOD_RESTORE_{CQ,MR} ioctls.
	#                      Runs in the restored task with user VMAs
	#                      live, which is what rxe's
	#                      pin_user_pages_fast needs.
	#
	# Per-ufile summary line shape (uobj_restore.c::rdma_restore_uobj_dag_for_ufile):
	#   "Phase A: restored N PD(s) [skipped M], R CQ(s) [skipped Q]; D CQ(s) + Q QP(s) [skipped V] + S MR(s) deferred ..."
	# where R = master-restored CQs (rxe path), D = pie-deferred
	# CQs (mlx5 path), Q = pie-deferred QPs (mlx5 vfmig only --
	# rxe never hits this column today since the rxe runner doesn't
	# build pre-dump QPs and rxe's QP path predates the v0
	# RESTORE_QP work). Their CQ split is per-driver-plugin via the
	# RDMA_RESTORE_UOBJ_CQ_NEEDS_PIE hook (default: master).
	#
	# Mode-specific minima:
	#   pd_mr  R=0  D=0  Q=0 S>=1 : 1 PD,  0 CQ,        >=1 MR deferred + pie MR ok
	#   pd_cq (rxe)  R>=1 D=0 Q=0 S=0 : 1 PD, >=1 CQ master-restored, 0 deferred
	#   pd_cq (mlx5) R=0 D>=1 Q=0 S=0 : 1 PD, 0 master, >=1 CQ pie-deferred + pie CQ ok
	if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\], [0-9]+ CQ\(s\) \[skipped [0-9]+\]; [0-9]+ CQ\(s\) \+ [0-9]+ QP\(s\) \[skipped [0-9]+\] \+ [0-9]+ MR\(s\) deferred' \
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
		if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\], 0 CQ\(s\) \[skipped 0\]; 0 CQ\(s\) \+ 0 QP\(s\) \[skipped 0\] \+ [1-9][0-9]* MR\(s\) deferred' \
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
		# Post-MR-refactor log shape (commit "criu/rdma: plugin-shape
		# UHW for RESTORE_MR via PACK/VERIFY hooks"): the pie restorer
		# no longer hard-codes mlx5 mkey_index in its OK line. The
		# generic shape is driver_id=%u + uhw_in=%u (the plugin-
		# packed UHW_IN length, 0 when no plugin hook registered as
		# is the case for rxe today).
		if ! grep -qE 'pie: [0-9]+: RDMA: ufile_id=[^ ]+ RESTORE_MR\(target_handle=[0-9]+, lkey=[0-9a-fx]+, rkey=[0-9a-fx]+, driver_id=[0-9]+, uhw_in=[0-9]+\) ok' \
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
	elif [[ "$holder_mode" == "pd_cq" || "$holder_mode" == "pd_2cq" ]]; then
		# pd_cq  -- exactly 1 CQ deferred + restored from pie.
		# pd_2cq -- exactly 2 CQs deferred + restored from pie
		#           (multi-CQ-per-ufile dispatch coverage;
		#           comp_vector axis is the holder's responsibility).
		# Both modes defer 0 MRs.
		local min_cq=1
		[[ "$holder_mode" == "pd_2cq" ]] && min_cq=2
		# rxe is in the master-restored camp (no NEEDS_PIE
		# hook), so the Phase A line shows R=$min_cq master-
		# restored CQs and 0 deferred. mlx5 is the inverse;
		# the mlx5 runner (run_vfmig_cr.sh) asserts that shape.
		if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\], '"$min_cq"' CQ\(s\) \[skipped 0\]; 0 CQ\(s\) \+ 0 QP\(s\) \[skipped 0\] \+ 0 MR\(s\) deferred' \
			"$DUMPDIR/restore.log"; then
			echo "FAIL: $holder_mode Phase-A summary line did" \
			     "not show $min_cq CQ(s) master-restored with" \
			     "0 deferred / 0 MR deferred. Either Phase A" \
			     "failed before the CQ loop, the kernel pre-" \
			     "dates a77cc4d8e8b9 'RDMA/uverbs: Add" \
			     "RESTORE_CQ + rxe impl', or the dump-side R3" \
			     "walk lost a CQ entry." >&2
			echo "--- restore log uobj DAG lines ---" >&2
			grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
				echo "(no uobj DAG lines at all)" >&2
			exit 1
		fi
		echo "RESTORE_PD + RESTORE_CQ x$min_cq (Phase A master) dispatched ok"
	elif [[ "$holder_mode" == "pd_cq_qp" ]]; then
		# pd_cq_qp -- PD + 1 CQ + 1 QP, all master-restored in
		# Phase A on rxe (no NEEDS_PIE hooks): the summary shows
		# 1 CQ [skipped 0] + 0 CQ/QP/MR deferred, plus the
		# appended "1 QP(s) master-restored in Phase A" tail.
		if ! grep -qE 'uobj DAG: ufile_id=[^ ]+ Phase A: restored [1-9][0-9]* PD\(s\) \[skipped 0\], 1 CQ\(s\) \[skipped 0\]; 0 CQ\(s\) \+ 0 QP\(s\) \[skipped 0\] \+ 0 MR\(s\) deferred to post-VMA Phase B; 1 QP\(s\) master-restored in Phase A' \
			"$DUMPDIR/restore.log"; then
			echo "FAIL: pd_cq_qp Phase-A summary line did not" \
			     "show 1 CQ + 1 QP master-restored with 0" \
			     "deferred. Either Phase A failed before the QP" \
			     "loop, the kernel pre-dates rxe RESTORE_QP, or" \
			     "the dump-side R3 walk lost the QP entry." >&2
			echo "--- restore log uobj DAG lines ---" >&2
			grep -E 'uobj DAG' "$DUMPDIR/restore.log" >&2 || \
				echo "(no uobj DAG lines at all)" >&2
			exit 1
		fi
		echo "RESTORE_PD + RESTORE_CQ + RESTORE_QP (Phase A master) dispatched ok"
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

	if [[ "$RESULT" == "OK" && "$holder_mode" == "pd_cq_qp_sq" ]]; then
		#
		# 5b. Non-drained-SQ in-flight replay
		#     (design/rxe_inflight_qp_restore.md §6.2).
		#
		# The holder posted a SEND into the SQ pre-dump and left it
		# outstanding (RNR-stalled, no recv), so the dump captured a
		# non-drained SQ. status=OK already means the post-restore
		# recv drew BOTH a send and a recv WC_SUCCESS and the payload
		# bytes matched -- i.e. the rewound SQ window survived
		# dump/restore and replayed without a fresh post_send. The
		# log grep is defense-in-depth on the status-vs-log invariant.
		#
		if ! grep -qE 'SQ_INFLIGHT: ok qp=0x[0-9a-f]+ payload=[1-9][0-9]* replayed send\+recv completed post-restore' \
			"$LOG"; then
			echo "FAIL: holder reported OK but holder.log has no" \
			     "SQ_INFLIGHT: ok line -- status-vs-log invariant" \
			     "broken (the in-flight completion print was" \
			     "dropped or the check was bypassed)." >&2
			echo "--- holder log tail ---" >&2
			tail -40 "$LOG" >&2 || true
			exit 1
		fi
		# The replay is driven by the rxe plugin's RESUME_DEVICES_LATE
		# thaw (FREEZE_CONTEXT(freeze=0)). If it never fired, the
		# born-frozen QP could not have replayed and the holder would
		# have timed out -- but assert the thaw line too so a future
		# regression that makes the SEND complete some other way (e.g.
		# the kernel stops born-freezing) is caught loudly rather than
		# silently passing for the wrong reason.
		if ! grep -qE 'resume_late: thawed restored ucontext' \
			"$DUMPDIR/restore.log"; then
			echo "FAIL: pd_cq_qp_sq passed but restore.log shows" \
			     "no rxe resume_late thaw -- the in-flight replay" \
			     "trigger (FREEZE_CONTEXT freeze=0) never fired;" \
			     "the SEND completed for the wrong reason." >&2
			echo "--- restore log resume_late lines ---" >&2
			grep -E 'resume_late' "$DUMPDIR/restore.log" >&2 || \
				echo "(no resume_late lines at all)" >&2
			exit 1
		fi
		echo "SQ in-flight replay:" \
		     "$(grep -E '^SQ_INFLIGHT: ' "$LOG" | head -1)"
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
#                    2. CRIU: the rxe plugin's DUMP_UOBJ_CQ hook
#                       reads the source vm_pgoff per CQ handle via
#                       RXE_IB_METHOD_VFMIG_QUERY_CQ and packs it
#                       into plugin_blob; RESTORE_CQ_UHW_PACK
#                       replays it as UHW_IN at restore time.
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
if [[ "${UVERBS_CR_RUN_PD_MR:-1}" == "1" ]]; then
	run_pass pd_mr_aligned   pd_mr 0
	run_pass pd_mr_unaligned pd_mr 1
else
	echo
	echo "[skip] pd_mr passes disabled by UVERBS_CR_RUN_PD_MR=0."
	echo "       Default is to run; this switch exists for hosts"
	echo "       where rxe's RDMA-WRITE data-path test (Phase J)"
	echo "       can't run -- e.g. an rxe link layered on lo with"
	echo "       no peer reachable for ibv_modify_qp(RTR), where"
	echo "       the dump+restore itself works but the post-restore"
	echo "       data-path verification fails environmentally. Pair"
	echo "       with UVERBS_CR_RUN_PD_CQ=1 to localise S5a CQ-"
	echo "       restore regression coverage on such hosts."
fi
if [[ "${UVERBS_CR_RUN_PD_CQ:-1}" == "1" ]]; then
	run_pass pd_cq pd_cq 0
else
	echo
	echo "[skip] pd_cq pass disabled by UVERBS_CR_RUN_PD_CQ=0."
	echo "       Default is to run; this switch exists for"
	echo "       kernels that pre-date the rxe forced-vm_pgoff"
	echo "       support in rxe_restore_cq (S5a-vma-remap)."
fi
# pd_2cq -- two CQs on one ibv_context, the canonical perftest
# multi-CQ pattern (separate send_cq + recv_cq). Each CQ's source
# vm_pgoff is sourced per handle via RXE_IB_METHOD_VFMIG_QUERY_CQ
# in the rxe plugin's DUMP_UOBJ_CQ hook, so the 1:1 join between
# vm_pgoff and per-CQ uobject that RESTORE_CQ.UHW_IN replay needs
# holds regardless of how many cdev VMAs a ufile maps. (This
# replaced the fragile /proc/<pid>/smaps cdev-VMA FIFO scrape,
# which could not tell a CQ ring apart from a QP's SQ/RQ ring on a
# shared ufile.) Switch retained so the pass can be skipped on
# kernels lacking the QUERY_CQ verb.
if [[ "${UVERBS_CR_RUN_PD_2CQ:-1}" == "1" ]]; then
	run_pass pd_2cq pd_2cq 0
fi
# pd_cq_qp -- PD + CQ + RC QP driven to RTS pre-dump, the first pass
# that exercises RESTORE_QP end-to-end on rxe. rxe is in the master-
# restored camp (no RDMA_RESTORE_UOBJ_QP_NEEDS_PIE hook), so both the
# CQ and the QP are dispatched from CRIU master in Phase A, before the
# user-VMA pass mmaps the cdev fd at the kernel-registered SQ/RQ ring
# vm_pgoff slots. The rxe plugin's DUMP_UOBJ_QP hook captures the full
# rxe_restore_qp_req wire state via RXE_IB_METHOD_VFMIG_QUERY_QP (after
# FREEZE_DATAPATH), and its RESTORE_UOBJ_QP_UHW_PACK hook replays it as
# RESTORE_QP UHW_IN. Switch retained so the pass can be skipped on
# kernels lacking the QUERY_QP / RESTORE_QP verbs.
if [[ "${UVERBS_CR_RUN_PD_CQ_QP:-1}" == "1" ]]; then
	run_pass pd_cq_qp pd_cq_qp 0
else
	echo
	echo "[skip] pd_cq_qp pass disabled by UVERBS_CR_RUN_PD_CQ_QP=0."
	echo "       Default is to run; this switch exists for kernels"
	echo "       that pre-date rxe RESTORE_QP / VFMIG_QUERY_QP."
fi
# pd_cq_qp_sq -- the non-drained-SQ in-flight QP restore case
# (design/rxe_inflight_qp_restore.md §6.2). Same shape as pd_cq_qp but
# the holder posts a SIGNALED SEND it leaves outstanding at snapshot
# (RNR-stalled, no recv), so the dump captures a non-drained SQ. On
# restore the QP is born datapath-frozen and the rxe plugin's
# RESUME_DEVICES_LATE thaw (FREEZE_CONTEXT freeze=0) replays the rewound
# SQ window; the holder posts the matching recv post-restore and proves
# the replayed SEND completes + moved the pre-dump payload, with no
# fresh post_send. This is the pass that actually exercises the
# born-frozen + thaw-and-replay datapath (pd_cq_qp only proves the
# drained QP is destroyable).
#
# Requires a kernel with the rxe in-flight SQ rewind-replay support:
#   - rxe_qp_resume() must arm req.need_retry so req_retry() resets the
#     replayed WQEs' DMA cursors (else the SEND replays 0 bytes), and
#   - rxe_qp_pause()/resume() must be idempotent (qp->dp_frozen) so the
#     redundant per-ucontext thaw cannot leak a send_task reservation
#     and hang ibv_destroy_qp() for the 50s pool-cleanup timeout.
# Set UVERBS_CR_RUN_PD_CQ_QP_SQ=0 to skip on kernels that pre-date that
# support. On a supported kernel expect "SQ_INFLIGHT: ok ..." with
# recv_byte_len=64 and a clean destroy (no rxe WARNs in dmesg).
if [[ "${UVERBS_CR_RUN_PD_CQ_QP_SQ:-1}" == "1" ]]; then
	run_pass pd_cq_qp_sq pd_cq_qp_sq 0
else
	echo
	echo "[skip] pd_cq_qp_sq pass disabled by UVERBS_CR_RUN_PD_CQ_QP_SQ=0"
	echo "       (non-drained-SQ in-flight replay; needs the rxe rewind-"
	echo "       replay + idempotent pause/resume kernel support)."
fi

echo
echo "ALL PASSES OK"
echo "PASS"
