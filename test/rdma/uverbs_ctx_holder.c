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
 * Then blocks until SIGTERM. SIGUSR1 re-queries the device and, when a
 * PD was allocated, functionally exercises the (post-restore) PD by
 * registering + deregistering a small MR against it -- reg_mr looks the
 * PD up by its ufile handle, so success proves the kernel PD survived
 * the round-trip at the same handle. Writes "OK" or "FAIL: ..." to the
 * status file. The runner uses SIGUSR1 after restore to confirm the
 * context (and PD) are still functional.
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
static const char *g_status_path;
static volatile sig_atomic_t g_terminate;
static volatile sig_atomic_t g_query;

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

	if (getenv("HOLDER_ALLOC_PD")) {
		g_pd = ibv_alloc_pd(g_ctx);
		if (!g_pd) {
			fprintf(stderr, "ibv_alloc_pd: %s\n", strerror(errno));
			return 2;
		}
	}

	signal(SIGTERM, on_sigterm);
	signal(SIGINT, on_sigterm);
	signal(SIGUSR1, on_sigusr1);

	printf("READY pid=%d ctx=%s async_fd=%d pd=%d\n", getpid(), devname, g_ctx->async_fd,
	       g_pd ? (int)g_pd->handle : -1);
	fflush(stdout);
	write_status("READY");

	while (!g_terminate) {
		if (g_query) {
			struct ibv_device_attr a;
			char msg[128];

			g_query = 0;
			if (ibv_query_device(g_ctx, &a))
				write_status("FAIL: ibv_query_device after signal");
			else if (g_pd && verify_pd(msg, sizeof(msg)))
				write_status(msg);
			else
				write_status("OK");
		}
		pause();
	}

	if (g_pd)
		ibv_dealloc_pd(g_pd);
	ibv_close_device(g_ctx);
	return 0;
}
