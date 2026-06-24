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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <infiniband/verbs.h>

static struct ibv_context *g_ctx;
static struct ibv_pd *g_pd;
/*
 * Pre-dump CQ: created alongside g_pd when @g_mode covers CQ
 * (currently rxe S5a). Needs to survive across CRIU dump+restore
 * and re-emerge in the destination ucontext at the same
 * ufile_handle so libibverbs's cached g_cq->handle stays consistent.
 * The kernel-side wire identity (cqn) is FW-private and not
 * user-visible on rxe; the only user-visible identity to assert
 * is the ufile_handle (validated post-restore by
 * ibv_destroy_cq() succeeding -- if the IDR slot is missing the
 * kernel returns -EINVAL on destroy).
 */
static struct ibv_cq *g_cq;
static struct ibv_cq *g_cq_b; /* HM_PD_2CQ second CQ, comp_vector=1 */
static int g_cq_b_comp_vector;
static const int G_CQ_CQE = 16;

/*
 * Pre-dump QP for HM_PD_CQ_QP. Created alongside g_pd / g_cq when
 * the mode is selected, modified through INIT -> RTR -> RTS via
 * self-loopback before READY so the dump captures a fully-connected
 * QP in RTS state (the most aggressive v0 RESTORE_QP-accepted
 * state). Post-restore the libibverbs cached qp->qp_num must equal
 * @g_qp_num (recorded pre-dump) -- the smoking gun for FW qpn
 * adoption surviving SAVE/LOAD_VHCA_STATE on the destination side.
 */
static struct ibv_qp *g_qp;
static uint32_t g_qp_num;
/*
 * Non-drained-SQ (HM_PD_CQ_QP_SQ) in-flight send buffer + its MR. One
 * page registered LOCAL_WRITE; the SEND reads [SQ_INFLIGHT_SEND_OFF]
 * and the post-restore recv lands into [SQ_INFLIGHT_RECV_OFF]. Kept
 * alive across dump/restore so the post-restore check can post the
 * matching recv and verify the replayed payload.
 */
static struct ibv_mr *g_sq_mr;
static void *g_sq_buf;
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
/*
 * @g_mr_buf is the address handed to ibv_reg_mr -- i.e. the start
 * of the umem the kernel pins. @g_mr_alloc is the underlying
 * allocation base returned by posix_memalign. They differ only in
 * "unaligned" geometry mode (UVERBS_HOLDER_UNALIGNED_MR=1), where
 * the underlying buffer is two pages and the MR is registered at
 * offset 0x800 inside it -- forcing the umem to span two pages and
 * therefore the source-side mlx5_vfmig retag path to stamp the
 * same (KIND_MR, mkey_index) onto N>=2 sibling registry entries.
 * The "aligned" geometry collapses to @g_mr_buf == @g_mr_alloc and
 * is the historical default exercised by the Phase J baseline.
 */
static void *g_mr_buf;
static void *g_mr_alloc;
static size_t g_mr_size;
static size_t g_mr_alloc_size;
/*
 * Geometry selector for the pre-dump MR. 0 = page-aligned 4 KiB
 * (legacy baseline). 1 = non-page-aligned, 4 KiB MR registered at
 * offset 0x800 inside an 8 KiB allocation (so umem covers second
 * half of page 0 + first half of page 1 -- guaranteed >= 2 sg
 * entries when the allocator hands back non-physically-contiguous
 * pages, and therefore guaranteed coverage of the multi-page
 * secondary-index path in mlx5/core/vfmig_iova.c regression-fixed
 * by kernel commit "mlx5_vfmig: support multi-page user objects in
 * the secondary index").
 */
static int g_mr_unaligned;
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
 *   "pd_cq"  pre-dump alloc PD + create CQ. Used by rxe (S5a).
 *            Post-restore validates the CQ survived at the
 *            source's ufile_handle by destroying it cleanly --
 *            ibv_destroy_cq returns -EINVAL on a missing IDR
 *            slot, so a successful destroy is the smoking gun
 *            that RESTORE_CQ installed at the right slot. CQ has
 *            no wire-spec identifier (cqn is internal driver/FW
 *            metadata), so libibverbs's cq->handle is the only
 *            user-visible identity to assert.
 *
 *   "pd_2cq" pre-dump alloc PD + create 2 CQs with different
 *            comp_vectors (cq_a: comp_vector=0, cq_b:
 *            comp_vector=1 if dev_attr.num_comp_vectors >= 2,
 *            else comp_vector=0 with a clear log line). Future
 *            mlx5_vfmig E2E coverage of:
 *              1. multi-CQ-per-ufile dispatching through the
 *                 R3 uobj-walker (one MLX5_IB_METHOD_VFMIG_QUERY_
 *                 CQ per CQ at dump, one UVERBS_METHOD_RESTORE_CQ
 *                 per CQ at restore, both keyed off the per-CQ
 *                 ufile_handle so CQ-to-CQ blob mixups surface).
 *              2. comp_vector=1 round-trip: the kernel's
 *                 mlx5_ib_create_cq stamps cq->mcq.vector at
 *                 create time (post-symmetry-fix) so QUERY_CQ
 *                 emits the source's vector verbatim and
 *                 RESTORE_CQ rebinds the destination CQ to the
 *                 same EQ slot. A pre-fix kernel would emit 0
 *                 for both and only cq_a would survive the
 *                 round-trip; a CRIU bug that drops the
 *                 RESP_COMP_VECTOR attr would manifest the
 *                 same way.
 *            Post-restore destroys both CQs in reverse-creation
 *            order (cq_b then cq_a) before the PD, exercising
 *            the teardown-order invariant documented in
 *            criu/rdma/uobj_restore.c (Pass-2 rollback comment)
 *            and in mlx5_vfmig design doc S3b. This mode is
 *            wired in the holder so the future mlx5 vfmig E2E
 *            runner (test/rdma/run_vfmig_cr.sh) can adopt it
 *            without another holder change; it is not yet on
 *            the rxe runner's default pass list because rxe
 *            num_comp_vectors typically caps at 1, which would
 *            collapse pd_2cq's coverage to be no different than
 *            pd_cq.
 *
 * The default is "pd" so existing call sites that don't pass
 * argv[3] (mlx5_vfmig run_vfmig_cr.sh) keep their current
 * pre-dump shape.
 */
enum holder_mode {
	HM_PD = 0,
	HM_PD_MR = 1,
	HM_PD_CQ = 2,
	HM_PD_2CQ = 3,
	/*
	 * "pd_cq_qp": pre-dump alloc PD + create CQ + create RC QP and
	 * advance through INIT -> RTR -> RTS via self-loopback (peer =
	 * own qpn, peer GID = own GID on port 1). Used by mlx5_vfmig
	 * (S6b B-series) once UVERBS_METHOD_RESTORE_QP and the
	 * supporting NLDEV emissions land. Post-restore validates the
	 * QP survived at the source's ufile_handle and same qp_num
	 * (libibverbs cache must agree), then tears down in
	 * dependency-order (QP -> CQ -> PD).
	 *
	 * RTS is the most aggressive state v0 RESTORE_QP accepts and
	 * exercises every modify_qp transition along the way; the
	 * simpler INIT/RTR/RESET cases are covered as side effects of
	 * the same handler. Pre-dump self-loopback connects qp_a to
	 * itself so we don't need a peer process for the modify
	 * chain. No data-path I/O pre-dump (the post-restore acid
	 * test currently stops at "QP is destroyable") -- a future
	 * Phase K could post a self-loopback RDMA WRITE through the
	 * restored QP, but the kernel-side qp_restore probe already
	 * validated FW QPC byte-equality so the v0 holder doesn't
	 * try to re-prove it from userspace.
	 */
	HM_PD_CQ_QP = 4,
	/*
	 * "pd_cq_qp_sq": same pre-dump shape as HM_PD_CQ_QP (PD + CQ +
	 * self-loopback RC QP at RTS) plus a registered MR and one
	 * SIGNALED SEND posted into the SQ but deliberately *left
	 * outstanding* at snapshot -- no recv is posted, so with
	 * rnr_retry=7 (infinite) the requester RNR-stalls and the WQE
	 * stays in [sq_consumer, sq_producer). This is the non-drained-SQ
	 * in-flight QP restore case (design/rxe_inflight_qp_restore.md
	 * §6.2). On restore the QP is born datapath-frozen; the rxe CRIU
	 * plugin's RESUME_DEVICES_LATE thaw (FREEZE_CONTEXT(freeze=0))
	 * replays the rewound SQ window. Post-restore the holder posts the
	 * matching recv and proves the replayed SEND completes (send +
	 * recv WC SUCCESS) and moved the pre-dump payload bytes -- without
	 * any fresh post_send. Distinct from pd_cq_qp, which drains before
	 * READY and only proves the QP is destroyable.
	 */
	HM_PD_CQ_QP_SQ = 5,
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
 * Phase J -- RDMA-WRITE data-path test through the restored MR.
 *
 * Two distinct byte patterns identify which side of the wire was
 * doing the move at any given subtest. We pick byte = (i ^ base)
 * over a constant fill so a misaligned or short transfer surfaces
 * as a localised mismatch rather than a "looks identical" zero
 * region. Bases are chosen so neither pattern is all-zero and
 * neither equals the other anywhere -- 0xa5 ^ 0x5a = 0xff.
 */
#define PHASE_J_RESTORED_BASE 0xa5u  /* stamped into g_mr_buf pre-dump */
#define PHASE_J_PEER_BASE     0x5au  /* stamped into peer mr_buf pre-J2 */

static void fill_pattern(void *buf, size_t len, uint8_t base)
{
	uint8_t *b = buf;
	size_t i;
	for (i = 0; i < len; i++)
		b[i] = (uint8_t)(i ^ base);
}

/* Returns -1 on full match, else the index of the first mismatch. */
static ssize_t verify_pattern(const void *buf, size_t len, uint8_t base)
{
	const uint8_t *b = buf;
	size_t i;
	for (i = 0; i < len; i++) {
		if (b[i] != (uint8_t)(i ^ base))
			return (ssize_t)i;
	}
	return -1;
}

struct phase_j_qp_info {
	uint32_t qpn;
	uint32_t psn;
	union ibv_gid gid;
	uint8_t port_num;
	enum ibv_mtu mtu;
};

static int phase_j_modify_init(struct ibv_qp *qp, uint8_t port_num)
{
	struct ibv_qp_attr attr = {
		.qp_state        = IBV_QPS_INIT,
		.pkey_index      = 0,
		.port_num        = port_num,
		.qp_access_flags = IBV_ACCESS_LOCAL_WRITE |
				   IBV_ACCESS_REMOTE_WRITE |
				   IBV_ACCESS_REMOTE_READ,
	};
	int mask = IBV_QP_STATE | IBV_QP_PKEY_INDEX |
		   IBV_QP_PORT  | IBV_QP_ACCESS_FLAGS;
	return ibv_modify_qp(qp, &attr, mask);
}

static int phase_j_modify_rtr(struct ibv_qp *qp,
			      const struct phase_j_qp_info *peer)
{
	struct ibv_qp_attr attr;
	int mask;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state              = IBV_QPS_RTR;
	attr.path_mtu              = peer->mtu;
	attr.dest_qp_num           = peer->qpn;
	attr.rq_psn                = peer->psn;
	attr.max_dest_rd_atomic    = 1;
	attr.min_rnr_timer         = 12;
	attr.ah_attr.is_global     = 1;
	attr.ah_attr.dlid          = 0;
	attr.ah_attr.sl            = 0;
	attr.ah_attr.src_path_bits = 0;
	attr.ah_attr.port_num      = peer->port_num;
	attr.ah_attr.grh.dgid      = peer->gid;
	attr.ah_attr.grh.sgid_index    = 0;
	attr.ah_attr.grh.hop_limit     = 1;
	attr.ah_attr.grh.traffic_class = 0;
	mask = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
	       IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
	       IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
	return ibv_modify_qp(qp, &attr, mask);
}

static int phase_j_modify_rts(struct ibv_qp *qp, uint32_t sq_psn)
{
	struct ibv_qp_attr attr;
	int mask;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state      = IBV_QPS_RTS;
	attr.timeout       = 14;
	attr.retry_cnt     = 7;
	attr.rnr_retry     = 7;
	attr.sq_psn        = sq_psn;
	attr.max_rd_atomic = 1;
	mask = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
	       IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN |
	       IBV_QP_MAX_QP_RD_ATOMIC;
	return ibv_modify_qp(qp, &attr, mask);
}

static int phase_j_post_write(struct ibv_qp *qp, uint64_t wr_id,
			      void *laddr, uint32_t lkey,
			      void *raddr, uint32_t rkey,
			      uint32_t length)
{
	struct ibv_sge sge = {
		.addr   = (uintptr_t)laddr,
		.length = length,
		.lkey   = lkey,
	};
	struct ibv_send_wr wr;
	struct ibv_send_wr *bad = NULL;
	memset(&wr, 0, sizeof(wr));
	wr.wr_id      = wr_id;
	wr.sg_list    = &sge;
	wr.num_sge    = 1;
	wr.opcode     = IBV_WR_RDMA_WRITE;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.wr.rdma.remote_addr = (uintptr_t)raddr;
	wr.wr.rdma.rkey        = rkey;
	return ibv_post_send(qp, &wr, &bad);
}

/*
 * Poll a single signaled completion off @cq. Spins up to @max_polls
 * iterations of 10ms each (~2s with the default of 200) -- a healthy
 * RC loopback completes in microseconds; the long ceiling is for the
 * pathological "FW silently dropped the WR" case where we want a clear
 * timeout error rather than an indefinite hang.
 */
static int phase_j_poll_one(struct ibv_cq *cq, uint64_t expected_wr_id,
			    int max_polls, struct ibv_wc *out_wc)
{
	int i;
	for (i = 0; i < max_polls; i++) {
		int n = ibv_poll_cq(cq, 1, out_wc);
		if (n < 0)
			return -EIO;
		if (n == 1) {
			if (out_wc->wr_id != expected_wr_id)
				return -EBADE;
			return 0;
		}
		usleep(10000);
	}
	return -ETIMEDOUT;
}

/*
 * Phase J orchestrator. Builds qp_b on @pd (qp_a is supplied alive
 * by the caller), connects qp_a <-> qp_b in self-loopback through
 * port 1's GID 0, then runs two RDMA-WRITE subtests:
 *
 *   J1  WRITE laddr=g_mr_buf, lkey=g_mr->lkey  (restored MR)
 *           raddr=mr_buf,    rkey=mr->rkey     (fresh peer MR)
 *       Sender = qp_a, responder = qp_b. After WC_SUCCESS the
 *       peer buffer must byte-equal the pre-dump pattern that
 *       the source process stamped into g_mr_buf before SAVE.
 *       This proves the kernel-side IOMMU binding installed by
 *       Stage-3 D4 (mlx5) / rxe_restore_mr (rxe) actually points
 *       at the pinned destination pages CRIU's mm replay seeded
 *       with the source bytes.
 *
 *   J2  WRITE laddr=mr_buf,    lkey=mr->lkey   (fresh peer MR)
 *           raddr=g_mr_buf,  rkey=g_mr->rkey   (restored MR)
 *       Sender = qp_b, responder = qp_a. Inverse direction --
 *       a peer-supplied pattern is written *into* the restored
 *       MR. After WC_SUCCESS g_mr_buf must byte-equal the new
 *       pattern. This proves the restored mr->rkey resolves on
 *       the responder side too: the FW data path walks
 *       rkey -> mkc -> iova -> IOMMU on responder, symmetric to
 *       the lkey walk on requester.
 *
 * Returns NULL on success; an error description in @errbuf
 * (also returned to the caller for convenience) on failure.
 *
 * qp_a stays alive on every exit path -- caller owns it. qp_b is
 * created and torn down internally.
 */
static const char *run_phase_j(struct ibv_context *ctx, struct ibv_pd *pd,
			       struct ibv_cq *cq, struct ibv_qp *qp_a,
			       struct ibv_mr *restored_mr,
			       void *restored_buf, size_t restored_len,
			       struct ibv_mr *peer_mr,
			       void *peer_buf, size_t peer_len,
			       char *errbuf, size_t errbuf_len)
{
	struct ibv_port_attr port_attr;
	struct phase_j_qp_info info_a;
	struct phase_j_qp_info info_b;
	struct ibv_qp *qp_b = NULL;
	struct ibv_qp_init_attr qp_init;
	struct ibv_wc wc;
	const uint64_t WR_ID_J1 = 0xCAFE0001ull;
	const uint64_t WR_ID_J2 = 0xCAFE0002ull;
	const uint32_t length = (uint32_t)(restored_len < peer_len ?
					   restored_len : peer_len);
	const char *ret = NULL;
	ssize_t miss;
	int err;

	if (length == 0) {
		snprintf(errbuf, errbuf_len,
			 "buffer length is zero (restored=%zu peer=%zu)",
			 restored_len, peer_len);
		return errbuf;
	}

	if (ibv_query_port(ctx, 1, &port_attr)) {
		snprintf(errbuf, errbuf_len,
			 "ibv_query_port(port=1): %s", strerror(errno));
		return errbuf;
	}
	memset(&info_a, 0, sizeof(info_a));
	memset(&info_b, 0, sizeof(info_b));
	if (ibv_query_gid(ctx, 1, 0, &info_a.gid)) {
		snprintf(errbuf, errbuf_len,
			 "ibv_query_gid(port=1, idx=0): %s",
			 strerror(errno));
		return errbuf;
	}
	info_b.gid = info_a.gid; /* same port == same GID */
	info_a.port_num = 1;
	info_b.port_num = 1;
	info_a.psn = 0;
	info_b.psn = 0;
	info_a.mtu = port_attr.active_mtu ? port_attr.active_mtu : IBV_MTU_1024;
	info_b.mtu = info_a.mtu;
	info_a.qpn = qp_a->qp_num;

	memset(&qp_init, 0, sizeof(qp_init));
	qp_init.qp_type = IBV_QPT_RC;
	qp_init.send_cq = cq;
	qp_init.recv_cq = cq;
	qp_init.cap.max_send_wr  = 1;
	qp_init.cap.max_recv_wr  = 1;
	qp_init.cap.max_send_sge = 1;
	qp_init.cap.max_recv_sge = 1;
	qp_b = ibv_create_qp(pd, &qp_init);
	if (!qp_b) {
		snprintf(errbuf, errbuf_len,
			 "ibv_create_qp(qp_b): %s", strerror(errno));
		return errbuf;
	}
	info_b.qpn = qp_b->qp_num;

	if ((err = phase_j_modify_init(qp_a, 1))) {
		snprintf(errbuf, errbuf_len,
			 "qp_a INIT: %d (%s)", err, strerror(err));
		ret = errbuf; goto out;
	}
	if ((err = phase_j_modify_init(qp_b, 1))) {
		snprintf(errbuf, errbuf_len,
			 "qp_b INIT: %d (%s)", err, strerror(err));
		ret = errbuf; goto out;
	}
	if ((err = phase_j_modify_rtr(qp_a, &info_b))) {
		snprintf(errbuf, errbuf_len,
			 "qp_a RTR (peer qpn=0x%x): %d (%s)",
			 info_b.qpn, err, strerror(err));
		ret = errbuf; goto out;
	}
	if ((err = phase_j_modify_rtr(qp_b, &info_a))) {
		snprintf(errbuf, errbuf_len,
			 "qp_b RTR (peer qpn=0x%x): %d (%s)",
			 info_a.qpn, err, strerror(err));
		ret = errbuf; goto out;
	}
	if ((err = phase_j_modify_rts(qp_a, info_a.psn))) {
		snprintf(errbuf, errbuf_len,
			 "qp_a RTS: %d (%s)", err, strerror(err));
		ret = errbuf; goto out;
	}
	if ((err = phase_j_modify_rts(qp_b, info_b.psn))) {
		snprintf(errbuf, errbuf_len,
			 "qp_b RTS: %d (%s)", err, strerror(err));
		ret = errbuf; goto out;
	}

	/*
	 * J1: restored MR -> peer MR. Zero peer first so a no-op
	 * "data path didn't move anything" is distinguishable from
	 * a successful copy.
	 */
	memset(peer_buf, 0, peer_len);
	err = phase_j_post_write(qp_a, WR_ID_J1,
				 restored_buf, restored_mr->lkey,
				 peer_buf, peer_mr->rkey, length);
	if (err) {
		snprintf(errbuf, errbuf_len,
			 "J1 post_send (lkey=%#x rkey=%#x): %d (%s)",
			 restored_mr->lkey, peer_mr->rkey, err,
			 strerror(err));
		ret = errbuf; goto out;
	}
	memset(&wc, 0, sizeof(wc));
	err = phase_j_poll_one(cq, WR_ID_J1, 200, &wc);
	if (err) {
		snprintf(errbuf, errbuf_len,
			 "J1 poll_cq: %d (%s)", err, strerror(-err));
		ret = errbuf; goto out;
	}
	if (wc.status != IBV_WC_SUCCESS) {
		snprintf(errbuf, errbuf_len,
			 "J1 wc.status=%d (%s) opcode=%d "
			 "(restored MR's lkey=%#x failed at requester FW "
			 "data path -- mkey -> iova -> IOMMU walk broken)",
			 wc.status, ibv_wc_status_str(wc.status),
			 wc.opcode, restored_mr->lkey);
		ret = errbuf; goto out;
	}
	miss = verify_pattern(peer_buf, length, PHASE_J_RESTORED_BASE);
	if (miss >= 0) {
		snprintf(errbuf, errbuf_len,
			 "J1 byte verify: peer_buf[%zd]=0x%02x expected 0x%02x "
			 "(restored MR's bytes did not survive WRITE end-to-end "
			 "-- IOMMU map likely points at wrong pages)",
			 miss, ((uint8_t *)peer_buf)[miss],
			 (uint8_t)(((size_t)miss) ^ PHASE_J_RESTORED_BASE));
		ret = errbuf; goto out;
	}

	/*
	 * J2: peer MR -> restored MR. Stamp peer with the inverse
	 * pattern so a successful round-trip (J1 then J2) demonstrably
	 * shows two different byte vectors moving in opposite
	 * directions; "still the J1 pattern" after J2 would mean the
	 * write didn't reach the responder.
	 */
	fill_pattern(peer_buf, length, PHASE_J_PEER_BASE);
	err = phase_j_post_write(qp_b, WR_ID_J2,
				 peer_buf, peer_mr->lkey,
				 restored_buf, restored_mr->rkey, length);
	if (err) {
		snprintf(errbuf, errbuf_len,
			 "J2 post_send (lkey=%#x rkey=%#x): %d (%s)",
			 peer_mr->lkey, restored_mr->rkey, err,
			 strerror(err));
		ret = errbuf; goto out;
	}
	memset(&wc, 0, sizeof(wc));
	err = phase_j_poll_one(cq, WR_ID_J2, 200, &wc);
	if (err) {
		snprintf(errbuf, errbuf_len,
			 "J2 poll_cq: %d (%s)", err, strerror(-err));
		ret = errbuf; goto out;
	}
	if (wc.status != IBV_WC_SUCCESS) {
		snprintf(errbuf, errbuf_len,
			 "J2 wc.status=%d (%s) opcode=%d "
			 "(restored MR's rkey=%#x failed at responder FW "
			 "data path -- responder mkey/iova/IOMMU broken)",
			 wc.status, ibv_wc_status_str(wc.status),
			 wc.opcode, restored_mr->rkey);
		ret = errbuf; goto out;
	}
	miss = verify_pattern(restored_buf, length, PHASE_J_PEER_BASE);
	if (miss >= 0) {
		snprintf(errbuf, errbuf_len,
			 "J2 byte verify: restored_buf[%zd]=0x%02x "
			 "expected 0x%02x (peer's bytes did not land in "
			 "restored MR's pages -- responder IOMMU map broken)",
			 miss, ((uint8_t *)restored_buf)[miss],
			 (uint8_t)(((size_t)miss) ^ PHASE_J_PEER_BASE));
		ret = errbuf; goto out;
	}

	printf("PHASE_J: ok qp_a=0x%x qp_b=0x%x len=%u "
	       "restored_lkey=%#x restored_rkey=%#x "
	       "peer_lkey=%#x peer_rkey=%#x\n",
	       info_a.qpn, info_b.qpn, length,
	       restored_mr->lkey, restored_mr->rkey,
	       peer_mr->lkey, peer_mr->rkey);
	fflush(stdout);

out:
	if (qp_b)
		ibv_destroy_qp(qp_b);
	return ret;
}

/*
 * Run the post-restore checks. Writes the first failure verbatim
 * to the status file and returns; if everything passes, writes "OK".
 *
 * All steps reference @g_pd (the pre-dump PD whose kernel ib_uobject
 * was reinstalled by RESTORE_PD); the test is meaningless without
 * it, so a missing g_pd is treated as a hard fail.
 */
/*
 * Post-restore checks for HM_PD_CQ (rxe S5a). Asserts that the
 * pre-dump CQ:
 *
 *   1. survived restore at the same libibverbs ufile_handle (the
 *      runner cross-checks pre-dump and post-restore READY lines
 *      for cq_handle equality; the holder's only job here is to
 *      hold a valid g_cq pointer and prove it's usable);
 *
 *   2. is destroyable cleanly via ibv_destroy_cq -- the smoking
 *      gun for the kernel-side IDR slot existing at the source's
 *      ufile_handle. ibv_destroy_cq returns -EINVAL if the slot
 *      is missing or points at a stale uobject.
 *
 * Then ibv_dealloc_pd(g_pd) closes the loop on PD adoption +
 * dependency-ordered teardown.
 *
 * Intentionally minimal: no fresh CQ/QP/MR build-up, no Phase J.
 * Those are pd_mr's job; pd_cq exists to localise CQ-restore
 * regressions to a tiny, fast-running pass without the rest of
 * the resource-graph noise.
 */
static void run_post_restore_checks_pd_cq(void)
{
	char msg[384];
	int rc;

	if (!g_pd) {
		write_status("FAIL: post-restore: g_pd missing -- "
			     "holder lost the pre-dump PD reference");
		return;
	}
	if (!g_cq) {
		write_status("FAIL: post-restore: g_cq missing despite "
			     "HM_PD_CQ/HM_PD_2CQ -- holder lost the "
			     "pre-dump CQ reference");
		return;
	}
	if (g_mode == HM_PD_2CQ && !g_cq_b) {
		write_status("FAIL: post-restore: g_cq_b missing despite "
			     "HM_PD_2CQ -- holder lost the second "
			     "pre-dump CQ reference");
		return;
	}

	/*
	 * Reverse-creation-order teardown so the source's
	 * UVERBS_OBJECT_CQ uobjects fall in the same order
	 * uverbs_destroy_ufile_hw would walk them on close. cq_b
	 * was created last -> destroyed first; cq_a -> next; PD
	 * last. This shape mirrors the rollback-order invariant
	 * documented in criu/rdma/uobj_restore.c (Pass-2 rollback
	 * comment): if any per-CQ destroy fails the chained PD
	 * dealloc is also surfaced, so a v0 CQ-restore regression
	 * that drops one of the two CQs (e.g. mlx5_blob keying bug)
	 * would surface here as either ibv_destroy_cq -EINVAL or
	 * ibv_dealloc_pd -EBUSY (FW BAD_RES_STATE on adopted
	 * mpd->pdn while a dependent CQ is still alive in
	 * firmware).
	 */
	if (g_mode == HM_PD_2CQ) {
		rc = ibv_destroy_cq(g_cq_b);
		g_cq_b = NULL;
		if (rc) {
			snprintf(msg, sizeof(msg),
				 "FAIL: ibv_destroy_cq of pre-dump cq_b "
				 "(comp_vector=%d) after restore: %d "
				 "(%s) -- second CQ's ufile_handle is "
				 "missing in the destination ucontext "
				 "IDR. Per-CQ dispatcher mis-keyed the "
				 "mlx5_blob, RESTORE_CQ ran with the "
				 "wrong source bytes, or RESP_COMP_"
				 "VECTOR didn't round-trip",
				 g_cq_b_comp_vector, rc, strerror(rc));
			write_status(msg);
			return;
		}
	}

	rc = ibv_destroy_cq(g_cq);
	g_cq = NULL;
	if (rc) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_destroy_cq of pre-dump CQ after "
			 "restore: %d (%s) -- the source's CQ "
			 "ufile_handle is missing in the destination "
			 "ucontext IDR. RESTORE_CQ did not run, or "
			 "installed at a different handle than the "
			 "source's", rc, strerror(rc));
		write_status(msg);
		return;
	}

	rc = ibv_dealloc_pd(g_pd);
	g_pd = NULL;
	if (rc) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_dealloc_pd of pre-dump PD after "
			 "tearing down the restored CQ(s): %d (%s) -- "
			 "kernel uobj cleanup leaked a dependent or "
			 "the adopted PD identity drifted",
			 rc, strerror(rc));
		write_status(msg);
		return;
	}

	write_status("OK");
}

/*
 * Post-restore checks for HM_PD_CQ_QP. Mirror of run_post_restore_
 * checks_pd_cq with an extra QP teardown wedged between QP and CQ
 * destruction (QP must drain before its parent CQ can be destroyed
 * cleanly under FW dependency-tracking).
 *
 * Three contracts are asserted:
 *
 *   1. qp->qp_num matches the pre-dump value @g_qp_num. The
 *      libibverbs ibv_qp struct lives in the holder's address space
 *      so the field survives by virtue of memory continuity --
 *      asserting it here just cross-checks that the kernel side
 *      didn't write back a different qpn at restore time (which
 *      would manifest as the pie restorer's resp_qpn != qpn_hint
 *      hard-fail, but we want the symmetrical userspace assertion
 *      so a regression on the kernel echo is caught even if the
 *      pie helper softened the assertion in the future).
 *
 *   2. ibv_destroy_qp(g_qp) succeeds. The libibverbs wire command
 *      walks ufile->idr at the cached g_qp->handle; -EINVAL would
 *      surface here if the kernel-side IDR slot for the QP is
 *      missing (i.e. RESTORE_QP didn't run, or installed at a
 *      different handle than the source's).
 *
 *   3. The chained ibv_destroy_cq + ibv_dealloc_pd both succeed in
 *      that order, exercising the FW dependency-tracking unwound
 *      via uverbs_destroy_uobject. A regression where the QP's
 *      kernel ib_uobject didn't link itself into the parent CQ's
 *      list_send_qp / list_recv_qp during RESTORE_QP would be
 *      caught here as ibv_destroy_cq -EBUSY ("FW reports CQ has
 *      outstanding QPs"). Same shape as the rolled-back DEALLOC_PD
 *      regression that broke S3b, applied to the QP layer.
 */
static void run_post_restore_checks_pd_cq_qp(void)
{
	char msg[384];
	int rc;
	uint32_t cur_qpn;

	if (!g_pd) {
		write_status("FAIL: post-restore: g_pd missing -- "
			     "holder lost the pre-dump PD reference");
		return;
	}
	if (!g_cq) {
		write_status("FAIL: post-restore: g_cq missing despite "
			     "HM_PD_CQ_QP -- holder lost the pre-dump CQ "
			     "reference");
		return;
	}
	if (!g_qp) {
		write_status("FAIL: post-restore: g_qp missing despite "
			     "HM_PD_CQ_QP -- holder lost the pre-dump QP "
			     "reference");
		return;
	}

	cur_qpn = g_qp->qp_num;
	if (cur_qpn != g_qp_num) {
		snprintf(msg, sizeof(msg),
			 "FAIL: pre-dump QP qp_num drifted across restore: "
			 "%u (pre-dump) != %u (post-restore). The kernel "
			 "installed a different qpn than the source's; "
			 "wire-visible peer state on remote endpoints "
			 "(if any) is now stale",
			 g_qp_num, cur_qpn);
		write_status(msg);
		return;
	}

	rc = ibv_destroy_qp(g_qp);
	g_qp = NULL;
	if (rc) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_destroy_qp of pre-dump QP after "
			 "restore: %d (%s) -- the source's QP "
			 "ufile_handle is missing in the destination "
			 "ucontext IDR. RESTORE_QP did not run, or "
			 "installed at a different handle than the "
			 "source's (qpn=%u)", rc, strerror(rc), cur_qpn);
		write_status(msg);
		return;
	}

	rc = ibv_destroy_cq(g_cq);
	g_cq = NULL;
	if (rc) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_destroy_cq of pre-dump CQ after "
			 "tearing down the restored QP: %d (%s) -- CQ's "
			 "ufile_handle missing in the destination ucontext "
			 "IDR, or the QP didn't unlink itself from "
			 "list_{send,recv}_qp on destroy (RESTORE_QP did "
			 "not link the QP into the parent CQ's qp lists)",
			 rc, strerror(rc));
		write_status(msg);
		return;
	}

	rc = ibv_dealloc_pd(g_pd);
	g_pd = NULL;
	if (rc) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_dealloc_pd of pre-dump PD after "
			 "tearing down the restored QP+CQ: %d (%s) -- "
			 "kernel uobj cleanup leaked a dependent or "
			 "the adopted PD identity drifted",
			 rc, strerror(rc));
		write_status(msg);
		return;
	}

	write_status("OK");
}

/*
 * Non-drained-SQ (HM_PD_CQ_QP_SQ) byte layout + identifiers. One
 * registered page; the SEND SGE reads the first SQ_INFLIGHT_PAYLOAD
 * bytes (stamped with the i^base pattern pre-dump) and the matching
 * recv lands into a well-separated region so a partial/short transfer
 * surfaces as a localised mismatch rather than overlapping the source.
 */
#define SQ_INFLIGHT_BASE     0x3cu
#define SQ_INFLIGHT_PAYLOAD  64u
#define SQ_INFLIGHT_SEND_OFF 0u
#define SQ_INFLIGHT_RECV_OFF 2048u
#define SQ_INFLIGHT_BUF_SZ   4096u
#define SQ_INFLIGHT_SEND_WR  0x5105ull
#define SQ_INFLIGHT_RECV_WR  0x5106ull

static int sq_inflight_post_send(void)
{
	struct ibv_sge sge = {
		.addr   = (uintptr_t)((uint8_t *)g_sq_buf + SQ_INFLIGHT_SEND_OFF),
		.length = SQ_INFLIGHT_PAYLOAD,
		.lkey   = g_sq_mr->lkey,
	};
	struct ibv_send_wr wr;
	struct ibv_send_wr *bad = NULL;
	memset(&wr, 0, sizeof(wr));
	wr.wr_id      = SQ_INFLIGHT_SEND_WR;
	wr.sg_list    = &sge;
	wr.num_sge    = 1;
	wr.opcode     = IBV_WR_SEND;
	wr.send_flags = IBV_SEND_SIGNALED;
	return ibv_post_send(g_qp, &wr, &bad);
}

static int sq_inflight_post_recv(void)
{
	struct ibv_sge sge = {
		.addr   = (uintptr_t)((uint8_t *)g_sq_buf + SQ_INFLIGHT_RECV_OFF),
		.length = SQ_INFLIGHT_PAYLOAD,
		.lkey   = g_sq_mr->lkey,
	};
	struct ibv_recv_wr wr;
	struct ibv_recv_wr *bad = NULL;
	memset(&wr, 0, sizeof(wr));
	wr.wr_id   = SQ_INFLIGHT_RECV_WR;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	return ibv_post_recv(g_qp, &wr, &bad);
}

/*
 * Post-restore checks for HM_PD_CQ_QP_SQ -- the non-drained-SQ
 * in-flight replay test (design/rxe_inflight_qp_restore.md §6.2).
 *
 * Pre-dump the holder posted one SIGNALED SEND into the SQ and left it
 * outstanding (no recv => RNR, rnr_retry=7 infinite), so the dump
 * captured a genuinely non-drained SQ (sq_consumer != sq_producer) and
 * the kernel restored the QP born datapath-frozen. The rxe CRIU
 * plugin's RESUME_DEVICES_LATE hook has, by the time this runs, issued
 * FREEZE_CONTEXT(freeze=0) -- which re-armed the requester and replayed
 * the rewound SQ window. The replayed SEND is now RNR-retrying against
 * our still-empty RQ.
 *
 * We post the matching recv; the replayed SEND then lands. Asserting
 * BOTH a send completion and a recv completion (WC_SUCCESS) plus the
 * payload bytes proves: (1) the in-flight SQ window survived
 * dump/restore byte-for-byte, (2) the thaw actually replayed it (no
 * fresh post_send was issued), and (3) the restored MR's lkey + pinned
 * pages resolve on the rxe data path. A born-frozen QP that never
 * thawed would time out here; a corrupt replay would surface as a
 * non-SUCCESS WC or a byte mismatch.
 */
static void run_post_restore_checks_pd_cq_qp_sq(void)
{
	char msg[512];
	struct ibv_wc wc;
	uint8_t *send_region, *recv_region;
	uint32_t recv_byte_len = 0;
	int rc, i;
	int got_send = 0, got_recv = 0;
	ssize_t miss;

	if (!g_pd || !g_cq || !g_qp || !g_sq_mr || !g_sq_buf) {
		write_status("FAIL: post-restore(sq_inflight): a restored "
			     "object reference (pd/cq/qp/mr/buf) is missing");
		return;
	}
	if (g_qp->qp_num != g_qp_num) {
		snprintf(msg, sizeof(msg),
			 "FAIL: sq_inflight QP qp_num drifted across restore: "
			 "%u (pre-dump) != %u (post-restore)",
			 g_qp_num, g_qp->qp_num);
		write_status(msg);
		return;
	}

	rc = sq_inflight_post_recv();
	if (rc) {
		snprintf(msg, sizeof(msg),
			 "FAIL: sq_inflight ibv_post_recv post-restore: "
			 "%d (%s)", rc, strerror(rc));
		write_status(msg);
		return;
	}

	/*
	 * ~5s ceiling (500 * 10ms). A healthy RC self-loopback completes
	 * in microseconds once the recv is posted; the long ceiling is for
	 * a clear timeout error rather than an indefinite hang if the thaw
	 * never replayed the SEND.
	 */
	for (i = 0; i < 500 && !(got_send && got_recv); i++) {
		int n = ibv_poll_cq(g_cq, 1, &wc);

		if (n < 0) {
			write_status("FAIL: sq_inflight ibv_poll_cq < 0");
			return;
		}
		if (n == 0) {
			usleep(10000);
			continue;
		}
		if (wc.status != IBV_WC_SUCCESS) {
			snprintf(msg, sizeof(msg),
				 "FAIL: sq_inflight wr_id=0x%llx wc.status=%d "
				 "(%s) opcode=%d -- the replayed in-flight SEND "
				 "did not complete cleanly post-restore (the "
				 "born-frozen QP's rewound SQ window is broken)",
				 (unsigned long long)wc.wr_id, wc.status,
				 ibv_wc_status_str(wc.status), wc.opcode);
			write_status(msg);
			return;
		}
		if (wc.wr_id == SQ_INFLIGHT_SEND_WR) {
			got_send = 1;
		} else if (wc.wr_id == SQ_INFLIGHT_RECV_WR) {
			got_recv = 1;
			recv_byte_len = wc.byte_len;
		}
	}
	if (!(got_send && got_recv)) {
		snprintf(msg, sizeof(msg),
			 "FAIL: sq_inflight timed out (send=%d recv=%d) -- the "
			 "in-flight SEND did not replay after the restore thaw. "
			 "The born-frozen QP never resumed, or "
			 "FREEZE_CONTEXT(freeze=0) (RESUME_DEVICES_LATE) did not "
			 "fire / did not reach this ucontext.",
			 got_send, got_recv);
		write_status(msg);
		return;
	}

	send_region = (uint8_t *)g_sq_buf + SQ_INFLIGHT_SEND_OFF;
	recv_region = (uint8_t *)g_sq_buf + SQ_INFLIGHT_RECV_OFF;
	/*
	 * Diagnostic: surface the recv byte_len and the *current* send
	 * region contents (read straight from the restored holder VA).
	 * This disambiguates a payload-zero failure: if send_region still
	 * holds the i^base pattern then the holder's memory restored fine
	 * and a zero/short delivery points at the kernel's replay (cursor
	 * rewind / DMA resid), whereas a zeroed send_region points at the
	 * MR-backed memory restore.
	 */
	printf("SQ_INFLIGHT_DIAG: recv_byte_len=%u send[0..3]=%02x%02x%02x%02x "
	       "recv[0..3]=%02x%02x%02x%02x\n",
	       recv_byte_len, send_region[0], send_region[1], send_region[2],
	       send_region[3], recv_region[0], recv_region[1], recv_region[2],
	       recv_region[3]);
	fflush(stdout);

	miss = verify_pattern(recv_region, SQ_INFLIGHT_PAYLOAD,
			      SQ_INFLIGHT_BASE);
	if (miss >= 0) {
		snprintf(msg, sizeof(msg),
			 "FAIL: sq_inflight byte verify: recv[%zd]=0x%02x "
			 "expected 0x%02x (recv_byte_len=%u, send[0]=0x%02x) -- "
			 "the replayed SEND completed but moved wrong/zero "
			 "bytes. send[0]==pattern => kernel replay rewind/DMA "
			 "resid bug; send[0]==0 => MR-backed memory restore lost "
			 "the payload",
			 miss, recv_region[miss],
			 (uint8_t)(((size_t)miss) ^ SQ_INFLIGHT_BASE),
			 recv_byte_len, send_region[0]);
		write_status(msg);
		return;
	}

	printf("SQ_INFLIGHT: ok qp=0x%x payload=%u replayed send+recv "
	       "completed post-restore\n", g_qp_num, SQ_INFLIGHT_PAYLOAD);
	fflush(stdout);

	/* Dependency-ordered teardown: QP -> MR -> CQ -> PD. */
	rc = ibv_destroy_qp(g_qp);
	g_qp = NULL;
	if (rc) {
		snprintf(msg, sizeof(msg),
			 "FAIL: sq_inflight ibv_destroy_qp: %d (%s)",
			 rc, strerror(rc));
		write_status(msg);
		return;
	}
	rc = ibv_dereg_mr(g_sq_mr);
	g_sq_mr = NULL;
	if (rc) {
		snprintf(msg, sizeof(msg),
			 "FAIL: sq_inflight ibv_dereg_mr: %d (%s)",
			 rc, strerror(rc));
		write_status(msg);
		return;
	}
	rc = ibv_destroy_cq(g_cq);
	g_cq = NULL;
	if (rc) {
		snprintf(msg, sizeof(msg),
			 "FAIL: sq_inflight ibv_destroy_cq: %d (%s)",
			 rc, strerror(rc));
		write_status(msg);
		return;
	}
	rc = ibv_dealloc_pd(g_pd);
	g_pd = NULL;
	if (rc) {
		snprintf(msg, sizeof(msg),
			 "FAIL: sq_inflight ibv_dealloc_pd: %d (%s)",
			 rc, strerror(rc));
		write_status(msg);
		return;
	}

	write_status("OK");
}

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
	/*
	 * LOCAL_WRITE | REMOTE_WRITE: peer MR plays both roles in
	 * Phase J -- J1 raddr (needs REMOTE_WRITE) and J2 laddr (needs
	 * LOCAL_WRITE). When @g_mode != HM_PD_MR Phase J is skipped
	 * and the extra REMOTE_WRITE bit is benign.
	 */
	mr = ibv_reg_mr(g_pd, mr_buf, mr_size,
			IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
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
	 * Phase J -- data-path acid test for the restored MR.
	 *
	 * Only meaningful when we actually pre-dumped an MR (HM_PD_MR);
	 * the HM_PD path stops at "PD adoption gate works" and Phase J
	 * has no restored MR to drive. We splice it in after qp_a is
	 * alive but before the dependency-ordered teardown so we can
	 * reuse the existing CQ + qp_a + peer MR; run_phase_j builds a
	 * second QP internally (qp_b) and tears it down before
	 * returning, leaving the rest of the resource graph untouched.
	 */
	if (g_mode == HM_PD_MR) {
		char j_err[256];
		const char *j_ret = run_phase_j(g_ctx, g_pd, cq, qp,
						g_mr, g_mr_buf, g_mr_size,
						mr, mr_buf, mr_size,
						j_err, sizeof(j_err));
		if (j_ret) {
			snprintf(msg, sizeof(msg),
				 "FAIL: Phase J data-path test: %s",
				 j_ret);
			write_status(msg);
			goto cleanup_mr;
		}
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
		free(g_mr_alloc);
		g_mr_alloc = NULL;
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
	} else if (strcmp(mode, "pd_cq") == 0) {
		g_mode = HM_PD_CQ;
	} else if (strcmp(mode, "pd_2cq") == 0) {
		g_mode = HM_PD_2CQ;
	} else if (strcmp(mode, "pd_cq_qp") == 0) {
		g_mode = HM_PD_CQ_QP;
	} else if (strcmp(mode, "pd_cq_qp_sq") == 0) {
		g_mode = HM_PD_CQ_QP_SQ;
	} else {
		fprintf(stderr, "unknown holder mode '%s' (expected "
				"pd|pd_mr|pd_cq|pd_2cq|pd_cq_qp|pd_cq_qp_sq)\n",
			mode);
		return 2;
	}

	/*
	 * MR geometry switch. Only meaningful in pd_mr mode; ignored
	 * (read but unused) in pd mode. Off by default so the legacy
	 * Phase J baseline is unchanged; runners flip it on for the
	 * post-fix multi-page regression pass.
	 */
	{
		const char *unalign = getenv("UVERBS_HOLDER_UNALIGNED_MR");
		g_mr_unaligned = (unalign && unalign[0] == '1') ? 1 : 0;
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

	if (g_mode == HM_PD_CQ) {
		/*
		 * Pre-dump CQ for S5a regression coverage. cqe=16 is
		 * the same size run_post_restore_checks's fresh-CQ
		 * uses; comp_channel=NULL (v0 RESTORE_CQ rejects
		 * comp_channel anyway), cq_context=NULL (so
		 * user_handle is 0 -- matches the v0 "user_handle
		 * isn't NLDEV-emitted" gap documented in
		 * rdma_uobj.proto::rdma_cq_attrs), comp_vector=0.
		 */
		g_cq = ibv_create_cq(g_ctx, G_CQ_CQE, NULL, NULL, 0);
		if (!g_cq) {
			fprintf(stderr,
				"ibv_create_cq baseline (pre-dump CQ): %s\n",
				strerror(errno));
			return 2;
		}
	} else if (g_mode == HM_PD_2CQ) {
		/*
		 * Two pre-dump CQs for the multi-CQ + comp_vector
		 * coverage. cq_a is comp_vector=0 (matches HM_PD_CQ);
		 * cq_b's comp_vector clamps to (num_comp_vectors - 1)
		 * but typically lands at 1 -- mlx5 hosts usually report
		 * num_comp_vectors == #cores, rxe defaults to 1 (so
		 * cq_b collapses to comp_vector=0 with a clear log
		 * line on rxe). The clamp keeps the ibv_create_cq
		 * call legal across drivers without forcing the
		 * caller to special-case num_comp_vectors==1.
		 */
		g_cq_b_comp_vector =
			(g_ctx->num_comp_vectors >= 2) ? 1 : 0;
		if (g_cq_b_comp_vector == 0) {
			fprintf(stderr,
				"pd_2cq: device %s reports "
				"num_comp_vectors=%d; cq_b will run on "
				"comp_vector=0, collapsing the multi-vector "
				"coverage to a multi-CQ-per-ufile smoke "
				"test (still useful for the per-CQ "
				"dispatcher / mlx5_blob keying / teardown-"
				"order invariant).\n",
				devname, g_ctx->num_comp_vectors);
		}
		g_cq = ibv_create_cq(g_ctx, G_CQ_CQE, NULL, NULL, 0);
		if (!g_cq) {
			fprintf(stderr,
				"ibv_create_cq baseline (cq_a, cv=0): "
				"%s\n", strerror(errno));
			return 2;
		}
		g_cq_b = ibv_create_cq(g_ctx, G_CQ_CQE, NULL, NULL,
				       g_cq_b_comp_vector);
		if (!g_cq_b) {
			fprintf(stderr,
				"ibv_create_cq (cq_b, cv=%d): %s\n",
				g_cq_b_comp_vector, strerror(errno));
			return 2;
		}
	} else if (g_mode == HM_PD_CQ_QP || g_mode == HM_PD_CQ_QP_SQ) {
		/*
		 * Pre-dump CQ + RC QP, advanced through INIT -> RTR ->
		 * RTS via self-loopback. Reuses the phase_j_modify_*
		 * helpers that already drive the same chain post-
		 * restore in HM_PD_MR's Phase J. HM_PD_CQ_QP_SQ then
		 * additionally registers an MR and posts one SEND it
		 * leaves outstanding (see below).
		 */
		struct ibv_qp_init_attr qp_init = {0};
		struct ibv_port_attr port_attr;
		struct phase_j_qp_info self;
		int err;

		g_cq = ibv_create_cq(g_ctx, G_CQ_CQE, NULL, NULL, 0);
		if (!g_cq) {
			fprintf(stderr,
				"ibv_create_cq baseline (pd_cq_qp): %s\n",
				strerror(errno));
			return 2;
		}

		qp_init.qp_type = IBV_QPT_RC;
		qp_init.send_cq = g_cq;
		qp_init.recv_cq = g_cq;
		qp_init.cap.max_send_wr = 1;
		qp_init.cap.max_recv_wr = 1;
		qp_init.cap.max_send_sge = 1;
		qp_init.cap.max_recv_sge = 1;
		g_qp = ibv_create_qp(g_pd, &qp_init);
		if (!g_qp) {
			fprintf(stderr,
				"ibv_create_qp baseline (pd_cq_qp): %s\n",
				strerror(errno));
			return 2;
		}
		g_qp_num = g_qp->qp_num;

		/*
		 * Self-loopback connection: peer = own qpn / GID /
		 * port. mlx5 VFs and rxe both expose port 1 with at
		 * least one valid GID; query_gid(idx=0) is the
		 * lightest path. active_mtu defaults to 1024 if the
		 * driver reports 0 (rxe in down state).
		 */
		if (ibv_query_port(g_ctx, 1, &port_attr)) {
			fprintf(stderr,
				"ibv_query_port(port=1) for pd_cq_qp: %s\n",
				strerror(errno));
			return 2;
		}
		memset(&self, 0, sizeof(self));
		if (ibv_query_gid(g_ctx, 1, 0, &self.gid)) {
			fprintf(stderr,
				"ibv_query_gid(port=1, idx=0) for "
				"pd_cq_qp: %s\n", strerror(errno));
			return 2;
		}
		self.port_num = 1;
		self.qpn = g_qp_num;
		self.psn = 0;
		self.mtu = port_attr.active_mtu ?
			   port_attr.active_mtu : IBV_MTU_1024;

		err = phase_j_modify_init(g_qp, 1);
		if (err) {
			fprintf(stderr,
				"pd_cq_qp: modify INIT: %d (%s)\n",
				err, strerror(err));
			return 2;
		}
		err = phase_j_modify_rtr(g_qp, &self);
		if (err) {
			fprintf(stderr,
				"pd_cq_qp: modify RTR (self qpn=0x%x): "
				"%d (%s)\n", self.qpn, err, strerror(err));
			return 2;
		}
		err = phase_j_modify_rts(g_qp, self.psn);
		if (err) {
			fprintf(stderr,
				"pd_cq_qp: modify RTS: %d (%s)\n",
				err, strerror(err));
			return 2;
		}

		if (g_mode == HM_PD_CQ_QP_SQ) {
			/*
			 * Register the in-flight MR and post one SIGNALED
			 * SEND, then deliberately do NOT post a recv and do
			 * NOT poll. With rnr_retry=7 (infinite, set in
			 * phase_j_modify_rts) the self-loopback SEND
			 * RNR-stalls -- it can never complete because our own
			 * RQ is empty -- so it stays in [sq_consumer,
			 * sq_producer) regardless of timing. The dump thus
			 * captures a genuinely non-drained SQ; the matching
			 * recv is posted only in the post-restore check, after
			 * the thaw has replayed the rewound window.
			 */
			if (posix_memalign(&g_sq_buf, 4096,
					   SQ_INFLIGHT_BUF_SZ) != 0 ||
			    !g_sq_buf) {
				fprintf(stderr,
					"posix_memalign(%u) for sq_inflight "
					"buf: %s\n", SQ_INFLIGHT_BUF_SZ,
					strerror(errno));
				return 2;
			}
			memset(g_sq_buf, 0, SQ_INFLIGHT_BUF_SZ);
			fill_pattern((uint8_t *)g_sq_buf + SQ_INFLIGHT_SEND_OFF,
				     SQ_INFLIGHT_PAYLOAD, SQ_INFLIGHT_BASE);
			g_sq_mr = ibv_reg_mr(g_pd, g_sq_buf,
					     SQ_INFLIGHT_BUF_SZ,
					     IBV_ACCESS_LOCAL_WRITE);
			if (!g_sq_mr) {
				fprintf(stderr,
					"ibv_reg_mr(sq_inflight): %s\n",
					strerror(errno));
				return 2;
			}
			err = sq_inflight_post_send();
			if (err) {
				fprintf(stderr,
					"sq_inflight: ibv_post_send "
					"(leave-outstanding): %d (%s)\n",
					err, strerror(err));
				return 2;
			}
		}
	}

	if (g_mode == HM_PD_MR) {
		/*
		 * 4 KiB local-write MR is the smallest registration
		 * libibverbs accepts and the cheapest exercise of
		 * the kernel's reg_user_mr -> ib_uverbs_reg_mr ->
		 * QUERY_MR-discoverable path.
		 *
		 * Geometry depends on @g_mr_unaligned:
		 *
		 *   0 (legacy baseline): 4 KiB allocation, 4 KiB MR
		 *     starting at the allocation base. iova == addr
		 *     (no remap), umem fits in one page so the source
		 *     side dom->pages registry holds a single sibling
		 *     entry; this is the only shape the Phase J test
		 *     baseline exercised pre-fix.
		 *
		 *   1 (multi-page regression coverage): 8 KiB allocation,
		 *     4 KiB MR registered at offset 0x800 inside it. The
		 *     registered umem covers the second half of page 0 +
		 *     the first half of page 1, so ib_umem_get pins both
		 *     pages and sg_alloc_append_table_from_pages produces
		 *     >= 2 sg entries on a typical anonymous-page layout.
		 *     vfmig_dma_ops.map_sg installs one external registry
		 *     entry per sg, all sharing the same (KIND_MR,
		 *     mkey_index) instance_key but at distinct iovas --
		 *     the exact failure shape that pre-fix
		 *     vfmig_iova_user_index_insert_locked rejected with
		 *     -EEXIST on the second sibling. The replicates
		 *     CRIU's swap_after_mr E2E failure, but inside our
		 *     own holder so the regression is observable
		 *     in-tree.
		 */
		if (g_mr_unaligned) {
			g_mr_alloc_size = 2 * 4096;
			g_mr_size = 4096;
		} else {
			g_mr_alloc_size = 4096;
			g_mr_size = 4096;
		}
		if (posix_memalign(&g_mr_alloc, 4096, g_mr_alloc_size) != 0 ||
		    !g_mr_alloc) {
			fprintf(stderr,
				"posix_memalign(%zu) for pre-dump MR: %s\n",
				g_mr_alloc_size, strerror(errno));
			return 2;
		}
		g_mr_buf = g_mr_unaligned
			? (void *)((uint8_t *)g_mr_alloc + 0x800)
			: g_mr_alloc;
		/*
		 * Stamp a pre-dump byte pattern (i ^ PHASE_J_RESTORED_BASE)
		 * so Phase J's J1 subtest can later verify, byte-by-byte,
		 * that the *source-time* contents of g_mr_buf survived
		 * SAVE_VHCA_STATE -> CRIU mm replay -> Stage-3 D4 IOMMU
		 * binding and showed up at the peer side of an RDMA WRITE
		 * issued through the restored MR's lkey. An all-zero buffer
		 * cannot distinguish "wrote zero bytes" from "wrote the
		 * source bytes -- they happened to be zero".
		 *
		 * Pattern is filled across the registered range only;
		 * the slack bytes outside the umem (when g_mr_unaligned
		 * is set) stay untouched and are deliberately not
		 * involved in Phase J's verify -- they don't belong to
		 * the MR's pinned umem, so a transfer touching them
		 * would mean kernel-side mr-out-of-bounds, not "patterns
		 * differ".
		 */
		fill_pattern(g_mr_buf, g_mr_size, PHASE_J_RESTORED_BASE);
		/*
		 * LOCAL_WRITE | REMOTE_WRITE: the restored MR is used both
		 * as J1 sender (laddr -> needs LOCAL_WRITE) and J2 receiver
		 * (raddr -> needs REMOTE_WRITE). REMOTE_READ omitted on
		 * purpose -- Phase J doesn't issue RDMA READ.
		 */
		g_mr = ibv_reg_mr(g_pd, g_mr_buf, g_mr_size,
				  IBV_ACCESS_LOCAL_WRITE |
				  IBV_ACCESS_REMOTE_WRITE);
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
		/*
		 * Expose @g_mr_unaligned, @g_mr_alloc, and @g_mr_alloc_size
		 * on the READY line so the runner can confirm the holder
		 * actually selected the requested geometry (and so a CI
		 * artefact captures the umem layout that drove the rest of
		 * the test). mr_addr == mr_alloc_base for the aligned
		 * default; mr_addr == mr_alloc_base + 0x800 for the
		 * multi-page regression mode.
		 */
		printf("READY pid=%d ctx=%s async_fd=%d pd_handle=%u "
		       "mr_handle=%u mr_lkey=0x%x mr_rkey=0x%x "
		       "mr_addr=%p mr_length=%zu mr_unaligned=%d "
		       "mr_alloc_base=%p mr_alloc_size=%zu\n",
		       getpid(), devname, g_ctx->async_fd,
		       g_pd->handle,
		       g_mr->handle, g_mr->lkey, g_mr->rkey,
		       g_mr_buf, g_mr_size, g_mr_unaligned,
		       g_mr_alloc, g_mr_alloc_size);
	} else if (g_mode == HM_PD_CQ && g_cq) {
		/*
		 * Expose pre-dump CQ ufile_handle + cqe_count so the
		 * runner can cross-check a post-restore READY-equivalent
		 * report (or just assert the value is what the source
		 * advertised, which is enough to catch a regression in
		 * the K8a ufile_handle plumbing).
		 */
		printf("READY pid=%d ctx=%s async_fd=%d pd_handle=%u "
		       "cq_handle=%u cq_cqe=%d\n",
		       getpid(), devname, g_ctx->async_fd,
		       g_pd->handle, g_cq->handle, g_cq->cqe);
	} else if (g_mode == HM_PD_2CQ && g_cq && g_cq_b) {
		printf("READY pid=%d ctx=%s async_fd=%d pd_handle=%u "
		       "cq_a_handle=%u cq_a_cqe=%d cq_a_cv=0 "
		       "cq_b_handle=%u cq_b_cqe=%d cq_b_cv=%d\n",
		       getpid(), devname, g_ctx->async_fd,
		       g_pd->handle,
		       g_cq->handle, g_cq->cqe,
		       g_cq_b->handle, g_cq_b->cqe, g_cq_b_comp_vector);
	} else if ((g_mode == HM_PD_CQ_QP || g_mode == HM_PD_CQ_QP_SQ) &&
		   g_cq && g_qp) {
		/*
		 * Expose pre-dump QP qp_num + ufile_handle so the
		 * runner can cross-check identity continuity post-
		 * restore. qp_state hard-coded to IBV_QPS_RTS (3) in
		 * the READY line because the holder unconditionally
		 * advances through the modify chain above; if the
		 * chain ever becomes mode-conditional, surface
		 * qp_state from a real ibv_query_qp instead.
		 */
		printf("READY pid=%d ctx=%s async_fd=%d pd_handle=%u "
		       "cq_handle=%u cq_cqe=%d "
		       "qp_handle=%u qp_num=0x%x qp_state=RTS\n",
		       getpid(), devname, g_ctx->async_fd,
		       g_pd->handle,
		       g_cq->handle, g_cq->cqe,
		       g_qp->handle, g_qp_num);
	} else {
		printf("READY pid=%d ctx=%s async_fd=%d pd_handle=%u\n",
		       getpid(), devname, g_ctx->async_fd, g_pd->handle);
	}
	fflush(stdout);
	write_status("READY");

	while (!g_terminate) {
		if (g_query) {
			g_query = 0;
			if (g_mode == HM_PD_CQ || g_mode == HM_PD_2CQ)
				run_post_restore_checks_pd_cq();
			else if (g_mode == HM_PD_CQ_QP)
				run_post_restore_checks_pd_cq_qp();
			else if (g_mode == HM_PD_CQ_QP_SQ)
				run_post_restore_checks_pd_cq_qp_sq();
			else
				run_post_restore_checks();
		}
		pause();
	}

	if (g_mr)
		ibv_dereg_mr(g_mr);
	free(g_mr_alloc);
	g_mr_alloc = NULL;
	g_mr_buf = NULL;
	if (g_sq_mr)
		ibv_dereg_mr(g_sq_mr);
	g_sq_mr = NULL;
	free(g_sq_buf);
	g_sq_buf = NULL;
	/* Reverse-creation-order teardown so dependents fall before
	 * their parents. QP -> CQ_b -> CQ_a -> PD. */
	if (g_qp)
		ibv_destroy_qp(g_qp);
	g_qp = NULL;
	if (g_cq_b)
		ibv_destroy_cq(g_cq_b);
	g_cq_b = NULL;
	if (g_cq)
		ibv_destroy_cq(g_cq);
	g_cq = NULL;
	if (g_pd)
		ibv_dealloc_pd(g_pd);
	ibv_close_device(g_ctx);
	return 0;
}
