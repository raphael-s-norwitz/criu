// SPDX-License-Identifier: GPL-2.0
/*
 * INTERNAL VALIDATION ONLY -- drop before upstream PR.
 *
 * Self-loop RC QP holder for run_vfmig_qp_traffic_cr.sh.
 *
 *   qp_gid_holder <ibdev> <status_path> <sgid_index>
 *
 * Creates a PD, CQ and RC QP, connects the QP to itself through GID
 * <sgid_index> on port 1, and exchanges one zero-length SEND with itself
 * (no MR needed). Writes "READY" once that worked, then waits:
 *
 *   SIGUSR2  write "STATE <n>" (ibv_query_qp), touching nothing else
 *   SIGUSR1  check the QP is still RTS, exchange another zero-length
 *            SEND, then write "OK" or "FAIL: ..."
 *   SIGTERM  exit
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <infiniband/verbs.h>

static struct ibv_context *ctx;
static struct ibv_pd *pd;
static struct ibv_cq *cq;
static struct ibv_qp *qp;
static const char *status_path;
static volatile sig_atomic_t want_state, want_check, terminate;

static void status(const char *fmt, ...)
{
	va_list ap;
	FILE *f = fopen(status_path, "w");

	if (!f)
		return;
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fputc('\n', f);
	fclose(f);
}

static int connect_self(int sgid_index)
{
	struct ibv_qp_attr a;
	union ibv_gid gid;

	if (ibv_query_gid(ctx, 1, sgid_index, &gid)) {
		fprintf(stderr, "ibv_query_gid(%d): %s\n", sgid_index, strerror(errno));
		return -1;
	}

	memset(&a, 0, sizeof(a));
	a.qp_state = IBV_QPS_INIT;
	a.port_num = 1;
	a.qp_access_flags = IBV_ACCESS_LOCAL_WRITE;
	if (ibv_modify_qp(qp, &a, IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS))
		return fprintf(stderr, "INIT: %s\n", strerror(errno)), -1;

	memset(&a, 0, sizeof(a));
	a.qp_state = IBV_QPS_RTR;
	a.path_mtu = IBV_MTU_1024;
	a.dest_qp_num = qp->qp_num;
	a.max_dest_rd_atomic = 1;
	a.min_rnr_timer = 12;
	a.ah_attr.is_global = 1;
	a.ah_attr.grh.dgid = gid;
	a.ah_attr.grh.sgid_index = sgid_index;
	a.ah_attr.grh.hop_limit = 64;
	a.ah_attr.port_num = 1;
	if (ibv_modify_qp(qp, &a,
			  IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
				  IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER))
		return fprintf(stderr, "RTR: %s\n", strerror(errno)), -1;

	memset(&a, 0, sizeof(a));
	a.qp_state = IBV_QPS_RTS;
	a.timeout = 14;
	a.retry_cnt = 7;
	a.rnr_retry = 7;
	a.max_rd_atomic = 1;
	if (ibv_modify_qp(qp, &a,
			  IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN |
				  IBV_QP_MAX_QP_RD_ATOMIC))
		return fprintf(stderr, "RTS: %s\n", strerror(errno)), -1;
	return 0;
}

static int qp_state(void)
{
	struct ibv_qp_attr a = {};
	struct ibv_qp_init_attr ia = {};

	if (ibv_query_qp(qp, &a, IBV_QP_STATE, &ia))
		return -errno;
	return a.qp_state;
}

/* Zero-length SEND to ourselves; both completions must succeed. */
static int exchange(char *msg, size_t len)
{
	struct ibv_recv_wr rwr = { .wr_id = 1 }, *brw;
	struct ibv_send_wr swr = { .wr_id = 2, .opcode = IBV_WR_SEND, .send_flags = IBV_SEND_SIGNALED }, *bsw;
	struct ibv_wc wc[2];
	struct timespec t0, t;
	int got = 0, n, i;

	if (ibv_post_recv(qp, &rwr, &brw))
		return snprintf(msg, len, "FAIL: post_recv: %s", strerror(errno)), -1;
	if (ibv_post_send(qp, &swr, &bsw))
		return snprintf(msg, len, "FAIL: post_send: %s", strerror(errno)), -1;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	while (got < 2) {
		n = ibv_poll_cq(cq, 2 - got, wc + got);
		if (n < 0)
			return snprintf(msg, len, "FAIL: poll_cq: %d", n), -1;
		got += n;
		clock_gettime(CLOCK_MONOTONIC, &t);
		if (got < 2 && t.tv_sec - t0.tv_sec > 10)
			return snprintf(msg, len, "FAIL: %d of 2 completions after 10s", got), -1;
	}
	for (i = 0; i < 2; i++)
		if (wc[i].status != IBV_WC_SUCCESS)
			return snprintf(msg, len, "FAIL: wr_id %lu: %s", (unsigned long)wc[i].wr_id,
					ibv_wc_status_str(wc[i].status)),
			       -1;
	return 0;
}

static void on_sig(int sig)
{
	if (sig == SIGUSR1)
		want_check = 1;
	else if (sig == SIGUSR2)
		want_state = 1;
	else
		terminate = 1;
}

int main(int argc, char **argv)
{
	struct ibv_device **list;
	struct sigaction sa = { .sa_handler = on_sig };
	sigset_t block, wait;
	char msg[160];
	int i, n, st;

	if (argc != 4)
		return fprintf(stderr, "usage: %s <ibdev> <status> <sgid_index>\n", argv[0]), 2;
	status_path = argv[2];

	list = ibv_get_device_list(&n);
	for (i = 0; list && i < n; i++)
		if (!strcmp(ibv_get_device_name(list[i]), argv[1]))
			ctx = ibv_open_device(list[i]);
	if (!ctx)
		return fprintf(stderr, "cannot open %s\n", argv[1]), 2;
	pd = ibv_alloc_pd(ctx);
	cq = pd ? ibv_create_cq(ctx, 16, NULL, NULL, 0) : NULL;
	if (cq) {
		struct ibv_qp_init_attr qia = {
			.send_cq = cq,
			.recv_cq = cq,
			.qp_type = IBV_QPT_RC,
			.cap = { .max_send_wr = 8, .max_recv_wr = 8, .max_send_sge = 1, .max_recv_sge = 1 },
		};
		qp = ibv_create_qp(pd, &qia);
	}
	if (!qp)
		return fprintf(stderr, "pd/cq/qp: %s\n", strerror(errno)), 2;
	if (connect_self(atoi(argv[3])))
		return 2;
	if (exchange(msg, sizeof(msg))) {
		fprintf(stderr, "pre-dump exchange: %s\n", msg);
		status("%s (before dump)", msg);
		return 2;
	}

	/* Signals stay blocked except inside sigsuspend(), so none is lost between checks. */
	sigemptyset(&block);
	sigaddset(&block, SIGUSR1);
	sigaddset(&block, SIGUSR2);
	sigaddset(&block, SIGTERM);
	sigaddset(&block, SIGINT);
	sigprocmask(SIG_BLOCK, &block, &wait);
	sigdelset(&wait, SIGUSR1);
	sigdelset(&wait, SIGUSR2);
	sigdelset(&wait, SIGTERM);
	sigdelset(&wait, SIGINT);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	printf("READY pid=%d qpn=0x%x sgid_index=%s\n", getpid(), qp->qp_num, argv[3]);
	fflush(stdout);
	status("READY");

	while (!terminate) {
		if (want_state) {
			want_state = 0;
			status("STATE %d", qp_state());
		}
		if (want_check) {
			want_check = 0;
			st = qp_state();
			if (st != IBV_QPS_RTS)
				status("FAIL: QP state %d, want RTS (%d)", st, IBV_QPS_RTS);
			else if (exchange(msg, sizeof(msg)))
				status("%s", msg);
			else
				status("OK");
		}
		if (!terminate && !want_state && !want_check)
			sigsuspend(&wait);
	}
	ibv_destroy_qp(qp);
	ibv_destroy_cq(cq);
	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	return 0;
}
