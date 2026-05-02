/*
 * INTERNAL VALIDATION ONLY -- drop before upstream PR.
 *
 * Minimum-surface holder process for criu RDMA dump/restore validation.
 *
 * Opens an ibv_context against the given RDMA device (default: rxe0).
 * The kernel implicitly creates an async-event fd inside the new
 * context, so a single ibv_open_device exercises both code paths in
 * criu/rdma.c (uverbsfd + uverbsasyncevfd).
 *
 * Then allocates a Protection Domain (PD) and holds it. On SIGUSR1
 * (sent by the runner script after restore) it does three things in
 * order, and writes the first failure -- or "OK" -- to the status
 * file:
 *
 *   1. ibv_query_device on the restored ibv_context. Confirms the
 *      cdev fd + ucontext were re-established.
 *
 *   2. ibv_dealloc_pd on the *pre-dump* PD. This is the strict test:
 *      the kernel uobject behind the PD must have survived the
 *      cdev-close-and-reopen that the dump path performs. Today, in
 *      the absence of full uobject-state preservation, this is
 *      expected to fail; it's the regression test that turns green
 *      when uobject save/replay lands.
 *
 *   3. ibv_alloc_pd + ibv_dealloc_pd of a *fresh* PD. Confirms the
 *      restored ucontext can still issue commands to the kernel,
 *      independent of whether step 2 worked.
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
static const char *g_status_path;
static volatile sig_atomic_t g_terminate;
static volatile sig_atomic_t g_query;

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
 */
static void run_post_restore_checks(void)
{
	struct ibv_device_attr a;
	struct ibv_pd *fresh;
	char msg[256];
	int rc;

	if (ibv_query_device(g_ctx, &a)) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_query_device after restore: %s",
			 strerror(errno));
		write_status(msg);
		return;
	}

	/*
	 * Strict: the pre-dump PD's kernel uobject must still exist.
	 * If dealloc returns nonzero we've found the seam where
	 * uobject state is lost across the dump.
	 */
	if (g_pd) {
		rc = ibv_dealloc_pd(g_pd);
		if (rc != 0) {
			snprintf(msg, sizeof(msg),
				 "FAIL: ibv_dealloc_pd of pre-dump PD "
				 "returned %d (%s) -- pre-dump uobject "
				 "did not survive restore",
				 rc, strerror(rc));
			write_status(msg);
			return;
		}
		g_pd = NULL;
	}

	/*
	 * Fresh PD allocation proves the restored ucontext is still
	 * a functional handle for new kernel commands, even if the
	 * pre-dump uobject went away.
	 */
	fresh = ibv_alloc_pd(g_ctx);
	if (!fresh) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_alloc_pd post-restore: %s",
			 strerror(errno));
		write_status(msg);
		return;
	}
	rc = ibv_dealloc_pd(fresh);
	if (rc != 0) {
		snprintf(msg, sizeof(msg),
			 "FAIL: ibv_dealloc_pd of fresh PD returned "
			 "%d (%s)", rc, strerror(rc));
		write_status(msg);
		return;
	}

	write_status("OK");
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
		fprintf(stderr, "ibv_query_device baseline: %s\n",
			strerror(errno));
		return 2;
	}

	g_pd = ibv_alloc_pd(g_ctx);
	if (!g_pd) {
		fprintf(stderr, "ibv_alloc_pd baseline: %s\n", strerror(errno));
		return 2;
	}

	signal(SIGTERM, on_sigterm);
	signal(SIGINT, on_sigterm);
	signal(SIGUSR1, on_sigusr1);

	printf("READY pid=%d ctx=%s async_fd=%d pd_handle=%u\n",
	       getpid(), devname, g_ctx->async_fd, g_pd->handle);
	fflush(stdout);
	write_status("READY");

	while (!g_terminate) {
		if (g_query) {
			g_query = 0;
			run_post_restore_checks();
		}
		pause();
	}

	if (g_pd)
		ibv_dealloc_pd(g_pd);
	ibv_close_device(g_ctx);
	return 0;
}
