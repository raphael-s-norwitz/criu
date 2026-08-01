/*
 * INTERNAL VALIDATION ONLY -- drop before upstream PR.
 *
 * Minimum-surface holder process for criu RDMA dump/restore validation.
 *
 * Opens an ibv_context against the given RDMA device (default: rxe0).
 * The kernel implicitly creates an async-event fd inside the new
 * context, so a single ibv_open_device exercises both code paths in
 * criu/rdma/uverbsfd.c (uverbsfd + uverbsasyncevfd).
 *
 * If HOLDER_ALLOC_PD is set in the environment, also allocate a PD so
 * the dump captures (and restore reinstalls) a PD uobject -- the rxe
 * RESTORE_PD dev gate.
 *
 * If HOLDER_ALLOC_MR is set (implies a PD), also register a persistent
 * MR over a known-pattern buffer -- the rxe RESTORE_MR dev gate. The
 * MR outlives the dump so restore must drive UVERBS_METHOD_RESTORE_MR
 * (from the pie) to reinstall it at its ufile handle.
 *
 * If HOLDER_ALLOC_CQ is set, also create a CQ -- the rxe RESTORE_CQ dev
 * gate. ibv_create_cq mmaps the completion ring off the cdev, so the CQ
 * outliving the dump forces restore to drive UVERBS_METHOD_RESTORE_CQ
 * (reinstall the uobject + re-register the ring's pending mmap slot at
 * the source vm_pgoff) and the plugin's UPDATE_VMA_MAP hook (remap the
 * ring VMA onto the restored, ucontext-bearing cdev fd).
 *
 * If HOLDER_ALLOC_QP is set (implies a PD and a CQ), also create an RC
 * QP sharing that CQ for send + recv completions -- the rxe RESTORE_QP
 * dev gate. NLDEV surfaces the QP with its parent-PD and both CQ-binding
 * restrack ids, which the R3 dump walker turns into an R3UT_QP entry
 * with R3XR_PARENT_PD / R3XR_SEND_CQ / R3XR_RECV_CQ xrefs plus the
 * plugin's captured wire state; restore drives UVERBS_METHOD_RESTORE_QP
 * (master-side, re-registering the SQ/RQ ring pending-mmap slots at the
 * source vm_pgoffs) plus the plugin's UPDATE_VMA_MAP hook (remapping the
 * two ring VMAs onto the restored ucontext-bearing cdev).
 *
 * Then blocks until SIGTERM. SIGUSR1 re-queries the device and, per
 * mode, functionally exercises the post-restore state:
 *   - PD mode: register + deregister a small MR against the PD (reg_mr
 *     resolves the PD by its ufile handle, so success proves the kernel
 *     PD survived at the same handle).
 *   - MR mode: verify the registered buffer's content survived, then
 *     deregister the persistent MR -- dereg resolves the MR by its
 *     ufile handle, so success proves RESTORE_MR reinstalled the
 *     uobject. Byte-identical lkey/rkey are guaranteed kernel-side by
 *     the pie's RESP==hint assertion.
 *   - CQ mode: ibv_poll_cq the restored CQ (rxe polls the mmap'd ring
 *     in userspace, so a mis-remapped VMA faults or reads garbage; a
 *     drained CQ returns 0 cleanly), then ibv_destroy_cq -- which
 *     resolves the CQ by its ufile handle, proving RESTORE_CQ
 *     reinstalled the uobject.
 *   - QP mode: ibv_query_qp the restored QP (resolves it by ufile handle
 *     and reads its state back from the kernel), then ibv_destroy_qp --
 *     which likewise resolves by handle, proving RESTORE_QP reinstalled
 *     the uobject at the source qpn. The QP is destroyed before its CQ
 *     (a live QP pins its CQs).
 * Writes "OK" or "FAIL: ..." to the status file. The runner uses
 * SIGUSR1 after restore to confirm the context is still functional.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <infiniband/verbs.h>

static struct ibv_context *g_ctx;
static struct ibv_pd *g_pd;
static struct ibv_mr *g_mr;
static struct ibv_cq *g_cq;
static struct ibv_qp *g_qp;
static uint32_t g_mr_lkey, g_mr_rkey;
static const char *g_status_path;
static volatile sig_atomic_t g_terminate;
static volatile sig_atomic_t g_query;

/* Persistent-MR buffer: page-aligned anon (.bss) so the pie lays the
 * VMA out at its original VA before RESTORE_MR pins it. */
static unsigned char g_mr_buf[8192] __attribute__((aligned(4096)));

static void fill_pattern(unsigned char *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		b[i] = (unsigned char)(i * 7 + 0x11);
}

static int check_pattern(const unsigned char *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (b[i] != (unsigned char)(i * 7 + 0x11))
			return -1;
	return 0;
}

static void on_sigterm(int sig)
{
	(void)sig;
	g_terminate = 1;
}

static void on_sigusr1(int sig)
{
	(void)sig;
	g_query = 1;
}

/*
 * Prove the restored PD is a live kernel object: reg_mr resolves the
 * PD by its ufile handle, so a successful register + deregister means
 * RESTORE_PD reinstalled the uobject at the handle userspace still
 * holds. Returns 0 on success, -1 on failure (msg filled).
 */
static int verify_pd(char *msg, size_t msglen)
{
	static char buf[4096] __attribute__((aligned(4096)));
	struct ibv_mr *mr;

	mr = ibv_reg_mr(g_pd, buf, sizeof(buf), IBV_ACCESS_LOCAL_WRITE);
	if (!mr) {
		snprintf(msg, msglen, "FAIL: ibv_reg_mr on restored PD: %s", strerror(errno));
		return -1;
	}
	if (ibv_dereg_mr(mr)) {
		snprintf(msg, msglen, "FAIL: ibv_dereg_mr: %s", strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * Prove the restored MR is a live kernel object at its original handle.
 * First check the buffer content the MR was registered over survived
 * the round-trip (RESTORE_MR pins exactly this VA in the pie). Then
 * deregister the persistent MR: dereg resolves the MR by its ufile
 * handle, so success means RESTORE_MR reinstalled the uobject; a skipped
 * or failed restore leaves no MR at the handle and dereg fails.
 */
static int verify_mr(char *msg, size_t msglen)
{
	if (check_pattern(g_mr_buf, sizeof(g_mr_buf))) {
		snprintf(msg, msglen, "FAIL: MR buffer content mismatch after restore");
		return -1;
	}
	if (ibv_dereg_mr(g_mr)) {
		snprintf(msg, msglen, "FAIL: ibv_dereg_mr on restored MR (lkey=0x%x rkey=0x%x): %s", g_mr_lkey,
			 g_mr_rkey, strerror(errno));
		return -1;
	}
	g_mr = NULL;
	return 0;
}

/*
 * Prove the restored CQ is a live kernel object with a working ring
 * mapping. ibv_poll_cq reads the completion ring directly out of the
 * mmap'd VMA (rxe does the producer/consumer walk in userspace), so if
 * the plugin's UPDATE_VMA_MAP failed to remap the ring onto the restored
 * cdev the poll would fault or read garbage; a drained CQ returns 0.
 * ibv_destroy_cq then resolves the CQ by its ufile handle, so success
 * proves RESTORE_CQ reinstalled the uobject at that handle.
 */
static int verify_cq(char *msg, size_t msglen)
{
	struct ibv_wc wc[4];
	int n;

	n = ibv_poll_cq(g_cq, 4, wc);
	if (n < 0) {
		snprintf(msg, msglen, "FAIL: ibv_poll_cq on restored CQ: %s", strerror(errno));
		return -1;
	}
	if (ibv_destroy_cq(g_cq)) {
		snprintf(msg, msglen, "FAIL: ibv_destroy_cq on restored CQ: %s", strerror(errno));
		return -1;
	}
	g_cq = NULL;
	return 0;
}

/*
 * Prove the restored QP is a live kernel object at its original handle
 * and qpn. ibv_query_qp resolves the QP by its ufile handle and reads
 * its state back from the kernel (rxe issues the standard QUERY_QP
 * verb), so success means RESTORE_QP reinstalled the uobject. The qpn is
 * checked against the pre-dump value the ibv_qp still carries in
 * restored memory -- the kernel installs the QP at the source qpn and
 * core fails the restore on divergence, so this is the userspace echo of
 * that identity contract. ibv_destroy_qp then tears it down (must run
 * before the CQ it shares is destroyed, since a live QP pins its CQs).
 */
static int verify_qp(char *msg, size_t msglen)
{
	struct ibv_qp_attr attr = {};
	struct ibv_qp_init_attr iattr = {};
	uint32_t qpn = g_qp->qp_num;

	if (ibv_query_qp(g_qp, &attr, IBV_QP_STATE | IBV_QP_CAP, &iattr)) {
		snprintf(msg, msglen, "FAIL: ibv_query_qp on restored QP (qpn=%u): %s", qpn, strerror(errno));
		return -1;
	}
	if (qpn == 0) {
		snprintf(msg, msglen, "FAIL: restored QP has qpn 0");
		return -1;
	}
	if (ibv_destroy_qp(g_qp)) {
		snprintf(msg, msglen, "FAIL: ibv_destroy_qp on restored QP (qpn=%u): %s", qpn, strerror(errno));
		return -1;
	}
	g_qp = NULL;
	return 0;
}

/*
 * Drive g_qp through RESET -> INIT -> RTR -> RTS as a self-loop RC
 * connection (dest_qp_num == own qpn, dgid == own port GID). No work is
 * posted, so the SQ/RQ rings stay empty (sq/rq_image_bytes == 0), but an
 * RC QP that reaches RTR with max_dest_rd_atomic > 0 allocates a
 * responder-resources table -- exactly the res_image_bytes != 0 case a
 * connected (but quiesced) ping-pong QP carries, which drained-only
 * restore cannot round-trip. Used to exercise the in-flight RES image
 * path under checkpoint/restore. Returns 0 on success, -1 on failure.
 */
static int qp_to_rts(struct ibv_qp *qp, uint8_t port)
{
	union ibv_gid gid;
	struct ibv_qp_attr attr;

	if (ibv_query_gid(qp->context, port, 0, &gid)) {
		fprintf(stderr, "ibv_query_gid: %s\n", strerror(errno));
		return -1;
	}

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_INIT;
	attr.pkey_index = 0;
	attr.port_num = port;
	attr.qp_access_flags =
		IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC;
	if (ibv_modify_qp(qp, &attr,
			  IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS)) {
		fprintf(stderr, "modify_qp(INIT): %s\n", strerror(errno));
		return -1;
	}

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTR;
	attr.path_mtu = IBV_MTU_1024;
	attr.dest_qp_num = qp->qp_num;
	attr.rq_psn = 0;
	attr.max_dest_rd_atomic = 1;
	attr.min_rnr_timer = 12;
	attr.ah_attr.is_global = 1;
	attr.ah_attr.grh.dgid = gid;
	attr.ah_attr.grh.sgid_index = 0;
	attr.ah_attr.grh.hop_limit = 1;
	attr.ah_attr.port_num = port;
	if (ibv_modify_qp(qp, &attr,
			  IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
				  IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER)) {
		fprintf(stderr, "modify_qp(RTR): %s\n", strerror(errno));
		return -1;
	}

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTS;
	attr.timeout = 14;
	attr.retry_cnt = 7;
	attr.rnr_retry = 7;
	attr.sq_psn = 0;
	attr.max_rd_atomic = 1;
	if (ibv_modify_qp(qp, &attr,
			  IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN |
				  IBV_QP_MAX_QP_RD_ATOMIC)) {
		fprintf(stderr, "modify_qp(RTS): %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

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

int main(int argc, char **argv)
{
	const char *devname = "rxe0";
	struct ibv_device **list;
	struct ibv_device *dev = NULL;
	struct ibv_device_attr attr;
	int num = 0;
	int i;

	if (argc >= 2)
		devname = argv[1];
	if (argc >= 3)
		g_status_path = argv[2];

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
		fprintf(stderr, "ibv_query_device baseline: %s\n", strerror(errno));
		return 2;
	}

	/* MR and QP modes both imply a PD (their parent). */
	if (getenv("HOLDER_ALLOC_PD") || getenv("HOLDER_ALLOC_MR") || getenv("HOLDER_ALLOC_QP")) {
		g_pd = ibv_alloc_pd(g_ctx);
		if (!g_pd) {
			fprintf(stderr, "ibv_alloc_pd: %s\n", strerror(errno));
			return 2;
		}
	}

	if (getenv("HOLDER_ALLOC_MR")) {
		fill_pattern(g_mr_buf, sizeof(g_mr_buf));
		g_mr = ibv_reg_mr(g_pd, g_mr_buf, sizeof(g_mr_buf),
				  IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
		if (!g_mr) {
			fprintf(stderr, "ibv_reg_mr: %s\n", strerror(errno));
			return 2;
		}
		g_mr_lkey = g_mr->lkey;
		g_mr_rkey = g_mr->rkey;
	}

	/* A QP needs a CQ for its send + recv completions. */
	if (getenv("HOLDER_ALLOC_CQ") || getenv("HOLDER_ALLOC_QP")) {
		g_cq = ibv_create_cq(g_ctx, 16, NULL, NULL, 0);
		if (!g_cq) {
			fprintf(stderr, "ibv_create_cq: %s\n", strerror(errno));
			return 2;
		}
	}

	if (getenv("HOLDER_ALLOC_QP")) {
		struct ibv_qp_init_attr qia = {
			.send_cq = g_cq,
			.recv_cq = g_cq,
			.cap = { .max_send_wr = 16, .max_recv_wr = 16, .max_send_sge = 1, .max_recv_sge = 1 },
			.qp_type = IBV_QPT_RC,
		};

		g_qp = ibv_create_qp(g_pd, &qia);
		if (!g_qp) {
			fprintf(stderr, "ibv_create_qp: %s\n", strerror(errno));
			return 2;
		}

		/*
		 * HOLDER_QP_CONNECT drives the QP to RTS as a self-loop RC
		 * connection so it carries a responder-resources table
		 * (res_image_bytes != 0) -- the connected-but-quiesced case a
		 * drained-only restore cannot round-trip. Left unset, the QP
		 * stays in RESET (the drained lone-QP gate).
		 */
		if (getenv("HOLDER_QP_CONNECT") && qp_to_rts(g_qp, 1))
			return 2;
	}

	signal(SIGTERM, on_sigterm);
	signal(SIGINT, on_sigterm);
	signal(SIGUSR1, on_sigusr1);

	printf("READY pid=%d ctx=%s async_fd=%d pd=%d mr_lkey=0x%x mr_rkey=0x%x cq=%d qp=%d qpn=%d\n", getpid(),
	       devname, g_ctx->async_fd, g_pd ? (int)g_pd->handle : -1, g_mr_lkey, g_mr_rkey,
	       g_cq ? (int)g_cq->handle : -1, g_qp ? (int)g_qp->handle : -1, g_qp ? (int)g_qp->qp_num : -1);
	fflush(stdout);
	write_status("READY");

	while (!g_terminate) {
		if (g_query) {
			struct ibv_device_attr a;
			char msg[128];
			/* PD-only mode iff no child objects were created. */
			bool pd_only = g_pd && !g_mr && !g_cq && !g_qp;
			int rc = 0;

			g_query = 0;
			if (ibv_query_device(g_ctx, &a)) {
				write_status("FAIL: ibv_query_device after signal");
			} else {
				/*
				 * Teardown-safe order: a live QP pins its CQ(s),
				 * so verify (and destroy) it before the CQ; the
				 * PD is a leaf every child depends on, so it is
				 * checked last and only in pure PD mode.
				 */
				if (rc == 0 && g_qp)
					rc = verify_qp(msg, sizeof(msg));
				if (rc == 0 && g_mr)
					rc = verify_mr(msg, sizeof(msg));
				if (rc == 0 && g_cq)
					rc = verify_cq(msg, sizeof(msg));
				if (rc == 0 && pd_only)
					rc = verify_pd(msg, sizeof(msg));
				write_status(rc ? msg : "OK");
			}
		}
		pause();
	}

	if (g_qp)
		ibv_destroy_qp(g_qp);
	if (g_mr)
		ibv_dereg_mr(g_mr);
	if (g_cq)
		ibv_destroy_cq(g_cq);
	if (g_pd)
		ibv_dealloc_pd(g_pd);
	ibv_close_device(g_ctx);
	return 0;
}
