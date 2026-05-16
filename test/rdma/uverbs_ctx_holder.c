/*
 * INTERNAL VALIDATION ONLY -- drop before upstream PR.
 *
 * Minimum-surface holder process for criu RDMA dump/restore validation.
 *
 * Design: drive the §S3b incremental-coverage test pattern -- pre-dump
 * the source ucontext only allocates a Protection Domain, and after
 * restore the holder *builds the rest of the resource graph on top of
 * the restored PD* (CQ, QP, MR), exercising the kernel's adoption of
 * the source's FW pdn under the destination ucontext. As subsequent
 * RESTORE_<TYPE> verbs land (S4 RESTORE_CQ, S5 RESTORE_QP, ...) the
 * pre-dump allocation set will grow and the post-restore "build new
 * resources" set will shrink correspondingly; the terminal state is
 * the orchestrator-level live-workload migration test.
 *
 * Why not "alloc PD + CQ + QP + MR pre-dump and dealloc them after
 * restore"? With v0 having only RESTORE_PD landed, dependent FW
 * resources (CQ/QP/MR) survive LOAD_VHCA_STATE in firmware but have
 * no kernel-side ib_uobject backing them. mlx5 firmware then refuses
 * DEALLOC_PD on the adopted PD with status BAD_RES_STATE because the
 * dependents are still alive; uverbs_destroy_uobject parks the uobj
 * waiting for a future RESTORE_{CQ,QP,MR} cascade to drain it. See
 * linux/tools/testing/mlx5_vfmig/design/uobject_restore.md §9.1 S3b
 * "v0 dealloc-ordering invariant" and the kernel-side regression test
 * pd_restore_probe_mlx5_vfmig subtest 7 for the canonical kernel-
 * level capture of that invariant. The CRIU-tree test deliberately
 * sidesteps it by not having any pre-dump dependents to begin with.
 *
 * Opens an ibv_context against the given RDMA device (default: rxe0).
 * The kernel implicitly creates an async-event fd inside the new
 * context, so a single ibv_open_device exercises both code paths in
 * criu/rdma.c (uverbsfd + uverbsasyncevfd).
 *
 * Then allocates a Protection Domain (PD) and holds it. On SIGUSR1
 * (sent by the runner script after restore) the post-restore
 * sequence runs and writes the first failure -- or "OK" -- to the
 * status file:
 *
 *   1. ibv_query_device on the restored ibv_context. Confirms the
 *      cdev fd + ucontext were re-established and that the context
 *      can satisfy attribute queries.
 *
 *   2. ibv_create_cq(ctx, ...). The CQ is created against the
 *      restored ucontext (not the pre-dump PD), and validates that
 *      the destination kernel can mint fresh per-resource state
 *      (kernel ib_uobject + firmware cqn) on a restore-mode
 *      ucontext.
 *
 *   3. ibv_create_qp(pre_dump_pd, ...). Acid test for PD adoption:
 *      the ibv_create_qp wire command carries pd=pre_dump_pd->handle,
 *      kernel resolves to the adopted ib_pd whose mpd->pdn is the
 *      source's FW pdn, and the FW CREATE_QP must accept that pdn
 *      under the destination ucontext's uid. If "Model A" pdn
 *      adoption is broken, this fails with FW BAD_PARAM or similar.
 *
 *   4. ibv_reg_mr(pre_dump_pd, ...). Same acid test for FW
 *      CREATE_MKEY pd=pdn under the new ucontext's uid. Together
 *      with step 3 these are the two halves of "Model A is
 *      functional in production" -- the kernel-side
 *      pd_restore_probe_mlx5_vfmig and pd_adopt tests validate the
 *      FW gate, this test validates the same gate is reached
 *      through the libibverbs path the workload actually uses.
 *
 *   5. Teardown in dependency order: ibv_destroy_qp -> ibv_dereg_mr
 *      -> ibv_destroy_cq -> ibv_dealloc_pd(pre_dump_pd). The final
 *      DEALLOC_PD must succeed because all three dependents have
 *      been torn down first; if it fails, either dependency
 *      tracking leaked or the pre-dump PD's adopted state is
 *      somehow stuck. (This is why we don't dealloc the pre-dump
 *      PD first, as the previous fixture shape did -- without S4+
 *      that path is intentionally broken in mlx5 firmware.)
 *
 * Then blocks until SIGTERM.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <infiniband/verbs.h>

static struct ibv_context *g_ctx;
static struct ibv_pd *g_pd;
/*
 * Pre-dump MR: registered alongside g_pd when @g_mode covers MR
 * (currently rxe S4a). Needs survive across SAVE_VHCA_STATE /
 * dump and re-emerge in the destination ucontext at the same
 * ufile_handle and with the same wire keys (lkey/rkey) so that
 * the libibverbs cache on @g_mr stays consistent. Validated
 * post-restore by ibv_dereg_mr (which would fail with
 * EINVAL/ENOENT if the kernel-side IDR hadn't been
 * re-established) and, when ulp_post_restore is set, also by
 * registering an SGE-shaped recv WR against the pre-dump MR --
 * exercising the actual data-path read of mr->lkey through
 * libibverbs.
 */
static struct ibv_mr *g_mr;
static void *g_mr_buf;
static const size_t g_mr_size = 4096;
static const char *g_status_path;
static volatile sig_atomic_t g_terminate;
static volatile sig_atomic_t g_query;

/*
 * Holder mode = "what set of pre-dump objects we hold". Selected
 * by argv[3] (default "pd").
 *
 *   "pd"     pre-dump alloc PD only. Used by mlx5_vfmig (S3b)
 *            because RESTORE_MR for mlx5 hasn't landed (S4b).
 *
 *   "pd_mr"  pre-dump alloc PD + reg MR. Used by rxe (S4a).
 *            Post-restore validates the MR survived with
 *            byte-identical lkey/rkey via ibv_dereg_mr success
 *            and (lkey/rkey unchanged) checks.
 *
 * The default is "pd" so existing call sites that don't pass
 * argv[3] (mlx5_vfmig run_vfmig_cr.sh) keep their current
 * pre-dump shape.
 */
enum holder_mode {
	HM_PD = 0,
	HM_PD_MR = 1,
};
static enum holder_mode g_mode = HM_PD;

static void on_sigterm(int sig) { (void)sig; g_terminate = 1; }
static void on_sigusr1(int sig) { (void)sig; g_query = 1; }

static void write_status(const char *line)
{
	FILE *f;

	if (!g_status_path)
		return;
	f = fopen(g_status_path, "w");
	if (!f)
		return;
	fputs(line, f);
	fputc('\n', f);
	fclose(f);
}

/*
 * Run the post-restore checks. Writes the first failure verbatim
 * to the status file and returns; if everything passes, writes "OK".
 *
 * All steps reference @g_pd (the pre-dump PD whose kernel ib_uobject
 * was reinstalled by RESTORE_PD); the test is meaningless without
 * it, so a missing g_pd is treated as a hard fail.
 */
static void run_post_restore_checks(void)
{
	struct ibv_device_attr dev_attr;
	struct ibv_qp_init_attr qp_attr;
	struct ibv_cq *cq = NULL;
	struct ibv_qp *qp = NULL;
	struct ibv_mr *mr = NULL;
	void *mr_buf = NULL;
	const size_t mr_size = 4096;
	char msg[384];
	int rc;

	/*
	 * Cached identity of the pre-dump MR taken before any
	 * teardown. We compare what libibverbs hands us *after*
	 * restore against what we recorded *before* dump (via the
	 * READY-line stdout) -- the runner script verifies them
	 * equal. Doing the read here only proves the userspace
	 * cache survived dump+restore (which is unsurprising: it
	 * lives in the holder's address space). The kernel-side
	 * identity preservation is what the post-restore
	 * RESP_LKEY/_RKEY assert in rdma_send_restore_mr already
	 * guarantees -- the same numbers showing up here is the
	 * libibverbs userspace consistent with kernel.
	 */
	uint32_t pre_dump_lkey = g_mr ? g_mr->lkey : 0;
	uint32_t pre_dump_rkey = g_mr ? g_mr->rkey : 0;

	if (!g_pd) {
		write_status("FAIL: post-restore: g_pd missing -- "
			     "holder lost the pre-dump PD reference");
		return;
	}
	if (g_mode == HM_PD_MR && !g_mr) {
		write_status("FAIL: post-restore: g_mr missing despite "
			     "HM_PD_MR -- holder lost the pre-dump MR "
			     "reference");
		return;
	}

	if (ibv_query_device(g_ctx, &dev_attr)) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_query_device after restore: %s",
			 strerror(errno));
		write_status(msg);
		return;
	}

	/*
	 * Step 2: fresh CQ on the restored ucontext. cqe=16 is enough
	 * to satisfy the kernel-side minimum + give the user-space
	 * doorbell room. Comp channel intentionally NULL -- exercising
	 * the ASYNC_EVENT path is already covered by ibv_open_device's
	 * implicit async-event fd; adding a comp channel here would
	 * mix two restore-flavors into one assertion.
	 */
	cq = ibv_create_cq(g_ctx, 16, NULL, NULL, 0);
	if (!cq) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_create_cq on restored ucontext: %s",
			 strerror(errno));
		write_status(msg);
		return;
	}

	/*
	 * Step 3: fresh MR on the *pre-dump* PD. Local-write only is
	 * the lightest-weight path; the kernel issues FW CREATE_MKEY
	 * with mkc.pd = adopted_pdn. This is the verb the kernel-side
	 * pd_adopt empirical test validated (see
	 * tools/testing/mlx5_vfmig/uobject_restore/pd_adopt/) and what
	 * pd_restore_probe_mlx5_vfmig confirms via PROBE_PD; running
	 * it before CREATE_QP isolates the FW-gate question from any
	 * libibverbs/libmlx5-side complexity in QP construction.
	 *
	 * The wire CREATE_MKEY carries pd_handle=g_pd->handle, which
	 * the destination kernel resolves to the adopted ib_pd whose
	 * mpd->pdn is the source's FW pdn. FW CREATE_MKEY referencing
	 * that pdn must succeed under the new ucontext's uid -- if
	 * Model A's "uid=0 ungated for CREATE_MKEY" premise is wrong
	 * this is where the test breaks.
	 */
	if (posix_memalign(&mr_buf, 4096, mr_size) != 0 || !mr_buf) {
		snprintf(msg, sizeof(msg),
			 "FAIL: posix_memalign(%zu): %s",
			 mr_size, strerror(errno));
		write_status(msg);
		goto cleanup_cq;
	}
	memset(mr_buf, 0, mr_size);
	mr = ibv_reg_mr(g_pd, mr_buf, mr_size, IBV_ACCESS_LOCAL_WRITE);
	if (!mr) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_reg_mr on pre-dump PD: %s "
			 "(FW CREATE_MKEY rejected adopted pdn -- the "
			 "Model A central premise; see "
			 "linux/.../uobject_restore/pd_adopt/)",
			 strerror(errno));
		write_status(msg);
		goto cleanup_buf;
	}

	/*
	 * Step 4: fresh QP on the *pre-dump* PD. This goes beyond
	 * what kernel-side pd_adopt empirically validates: pd_adopt
	 * only checks CREATE_MKEY uid=0; libmlx5's CREATE_QP path
	 * carries additional UHW (UAR offsets, doorbell records,
	 * WQ buffer descriptors) that the destination ucontext's
	 * dyn-UAR restore must have set up correctly. A failure
	 * here distinguishes "Model A CREATE_QP gate broken" from
	 * "libmlx5 CREATE_QP needs additional restore plumbing".
	 *
	 * RC QP, cap = (1, 1, 1, 1) -- the minimum kernel accepts
	 * (a strict-zero cap is rejected by ib_uverbs_create_qp).
	 */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.send_cq = cq;
	qp_attr.recv_cq = cq;
	qp_attr.qp_type = IBV_QPT_RC;
	qp_attr.cap.max_send_wr = 1;
	qp_attr.cap.max_recv_wr = 1;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.cap.max_recv_sge = 1;

	qp = ibv_create_qp(g_pd, &qp_attr);
	if (!qp) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_create_qp on pre-dump PD: %s "
			 "(adopted pdn accepted by FW CREATE_MKEY at "
			 "step 3 but FW CREATE_QP failed -- check kernel "
			 "dmesg for the FW syndrome)",
			 strerror(errno));
		write_status(msg);
		goto cleanup_mr;
	}

	/*
	 * Step 5: dependency-ordered teardown. Each FW destroy
	 * command (DESTROY_QP, DESTROY_MKEY, DESTROY_CQ, DEALLOC_PD)
	 * fires only after its dependents are gone, so all four must
	 * succeed. The ibv_dealloc_pd at the end is the symmetric
	 * counterpart to the previous fixture shape's broken
	 * pre-dependents dealloc -- here it succeeds because we
	 * built the dependency tree fresh on top of the adopted PD
	 * and we're tearing it down in the right order.
	 */
	rc = ibv_destroy_qp(qp);
	qp = NULL;
	if (rc) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_destroy_qp: %d (%s)", rc, strerror(rc));
		write_status(msg);
		goto cleanup_mr;
	}
	rc = ibv_dereg_mr(mr);
	mr = NULL;
	if (rc) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_dereg_mr: %d (%s)", rc, strerror(rc));
		write_status(msg);
		goto cleanup_buf;
	}
	free(mr_buf);
	mr_buf = NULL;

	/*
	 * For HM_PD_MR (rxe S4a) the pre-dump MR is alive in the
	 * destination ucontext at the same ufile_handle. Drain it
	 * before the cq + pd teardown so dealloc_pd has no
	 * dependents. ibv_dereg_mr on a restored MR is the cleanest
	 * proof of "the IDR slot exists and points at a valid
	 * ib_mr": EINVAL/ENOENT here would mean RESTORE_MR didn't
	 * install the MR at the source's ufile_handle.
	 *
	 * The lkey/rkey assert below is on the libibverbs cached
	 * values; identity preservation across dump+restore is what
	 * we want to verify. The kernel-side identity is already
	 * checked by rdma_send_restore_mr's RESP_LKEY assert; this
	 * one closes the userspace half of the loop.
	 */
	if (g_mode == HM_PD_MR && g_mr) {
		if (g_mr->lkey != pre_dump_lkey ||
		    g_mr->rkey != pre_dump_rkey) {
			snprintf(msg, sizeof(msg),
				 "FAIL: pre-dump MR libibverbs cache "
				 "drifted across restore: lkey %#x->%#x, "
				 "rkey %#x->%#x. The kernel installed "
				 "different keys than the source's; "
				 "wire-visible rkey is now stale",
				 pre_dump_lkey, g_mr->lkey,
				 pre_dump_rkey, g_mr->rkey);
			write_status(msg);
			goto cleanup_cq;
		}
		rc = ibv_dereg_mr(g_mr);
		g_mr = NULL;
		if (rc) {
			snprintf(msg, sizeof(msg),
				 "FAIL: ibv_dereg_mr of pre-dump MR after "
				 "restore: %d (%s) -- the source's MR "
				 "ufile_handle is missing in the "
				 "destination ucontext IDR. RESTORE_MR "
				 "did not run, or installed at a "
				 "different handle than the source's",
				 rc, strerror(rc));
			write_status(msg);
			goto cleanup_cq;
		}
		free(g_mr_buf);
		g_mr_buf = NULL;
	}

	rc = ibv_destroy_cq(cq);
	cq = NULL;
	if (rc) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_destroy_cq: %d (%s)", rc, strerror(rc));
		write_status(msg);
		return;
	}
	rc = ibv_dealloc_pd(g_pd);
	g_pd = NULL;
	if (rc) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_dealloc_pd of pre-dump PD (after "
			 "draining dependents): %d (%s) -- the kernel "
			 "should have torn down all FW dependents before "
			 "this DEALLOC_PD, so a failure here means either "
			 "kernel uobj cleanup leaked a dependent, or the "
			 "adopted PD's mpd->pdn was wrong",
			 rc, strerror(rc));
		write_status(msg);
		return;
	}

	write_status("OK");
	return;

/*
 * Cleanup labels: each callsite jumps in at the latest resource
 * that's still alive. The four checks all set their respective
 * pointers to NULL on a successful destroy / free, so the
 * fall-through if-guards in the labels are no-ops on the success
 * path and free the leak-on-error case correctly. PD is left to
 * ibv_close_device / process exit because FW DEALLOC_PD has its
 * own ordering invariant (see top of file).
 *
 * No path goes to cleanup_qp -- QP either fails creation (qp NULL,
 * goto cleanup_mr) or destroy (qp NULL after destroy attempt, goto
 * cleanup_mr) -- so it's elided to keep -Wunused-label clean.
 */
cleanup_mr:
	if (mr)
		ibv_dereg_mr(mr);
cleanup_buf:
	free(mr_buf);
cleanup_cq:
	if (cq)
		ibv_destroy_cq(cq);
}

int main(int argc, char **argv)
{
	const char *devname = "rxe0";
	const char *mode = "pd";
	struct ibv_device **list;
	struct ibv_device *dev = NULL;
	struct ibv_device_attr attr;
	int num = 0;
	int i;

	if (argc >= 2)
		devname = argv[1];
	if (argc >= 3)
		g_status_path = argv[2];
	if (argc >= 4)
		mode = argv[3];

	if (strcmp(mode, "pd") == 0) {
		g_mode = HM_PD;
	} else if (strcmp(mode, "pd_mr") == 0) {
		g_mode = HM_PD_MR;
	} else {
		fprintf(stderr, "unknown holder mode '%s' "
				"(expected pd|pd_mr)\n", mode);
		return 2;
	}

	list = ibv_get_device_list(&num);
	if (!list || num == 0) {
		fprintf(stderr, "ibv_get_device_list: %s\n", strerror(errno));
		return 2;
	}
	for (i = 0; i < num; i++) {
		if (strcmp(ibv_get_device_name(list[i]), devname) == 0) {
			dev = list[i];
			break;
		}
	}
	if (!dev) {
		fprintf(stderr, "no ibv device named '%s'\n", devname);
		ibv_free_device_list(list);
		return 2;
	}

	g_ctx = ibv_open_device(dev);
	ibv_free_device_list(list);
	if (!g_ctx) {
		fprintf(stderr, "ibv_open_device: %s\n", strerror(errno));
		return 2;
	}
	if (ibv_query_device(g_ctx, &attr)) {
		fprintf(stderr, "ibv_query_device baseline: %s\n",
			strerror(errno));
		return 2;
	}

	g_pd = ibv_alloc_pd(g_ctx);
	if (!g_pd) {
		fprintf(stderr, "ibv_alloc_pd baseline: %s\n", strerror(errno));
		return 2;
	}

	if (g_mode == HM_PD_MR) {
		/*
		 * 4 KiB local-write MR is the smallest registration
		 * libibverbs accepts and the cheapest exercise of
		 * the kernel's reg_user_mr -> ib_uverbs_reg_mr ->
		 * QUERY_MR-discoverable path. iova == addr (no
		 * remap), access flags = LOCAL_WRITE so the source
		 * and destination kernels both accept the MR
		 * without needing remote-key plumbing tested
		 * elsewhere.
		 */
		if (posix_memalign(&g_mr_buf, 4096, g_mr_size) != 0 ||
		    !g_mr_buf) {
			fprintf(stderr,
				"posix_memalign(%zu) for pre-dump MR: %s\n",
				g_mr_size, strerror(errno));
			return 2;
		}
		memset(g_mr_buf, 0, g_mr_size);
		g_mr = ibv_reg_mr(g_pd, g_mr_buf, g_mr_size,
				  IBV_ACCESS_LOCAL_WRITE);
		if (!g_mr) {
			fprintf(stderr,
				"ibv_reg_mr baseline (pre-dump MR): %s\n",
				strerror(errno));
			return 2;
		}
	}

	signal(SIGTERM, on_sigterm);
	signal(SIGINT, on_sigterm);
	signal(SIGUSR1, on_sigusr1);

	/*
	 * READY line: include pre-dump MR fields when present so
	 * the runner script can capture them as ground truth and
	 * compare to post-restore values reported in the status
	 * file (or the post-restore READY follow-up).
	 */
	if (g_mode == HM_PD_MR && g_mr) {
		printf("READY pid=%d ctx=%s async_fd=%d pd_handle=%u "
		       "mr_handle=%u mr_lkey=0x%x mr_rkey=0x%x "
		       "mr_addr=%p mr_length=%zu\n",
		       getpid(), devname, g_ctx->async_fd,
		       g_pd->handle,
		       g_mr->handle, g_mr->lkey, g_mr->rkey,
		       g_mr_buf, g_mr_size);
	} else {
		printf("READY pid=%d ctx=%s async_fd=%d pd_handle=%u\n",
		       getpid(), devname, g_ctx->async_fd, g_pd->handle);
	}
	fflush(stdout);
	write_status("READY");

	while (!g_terminate) {
		if (g_query) {
			g_query = 0;
			run_post_restore_checks();
		}
		pause();
	}

	if (g_mr)
		ibv_dereg_mr(g_mr);
	free(g_mr_buf);
	if (g_pd)
		ibv_dealloc_pd(g_pd);
	ibv_close_device(g_ctx);
	return 0;
}
