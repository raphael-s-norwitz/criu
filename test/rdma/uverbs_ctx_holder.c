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
 * Then blocks until SIGTERM. SIGUSR1 re-queries the device and writes
 * "OK" or "FAIL: ..." to the status file given on the command line.
 * The runner script uses SIGUSR1 after restore to confirm the context
 * is still functional.
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

	signal(SIGTERM, on_sigterm);
	signal(SIGINT, on_sigterm);
	signal(SIGUSR1, on_sigusr1);

	printf("READY pid=%d ctx=%s async_fd=%d\n",
	       getpid(), devname, g_ctx->async_fd);
	fflush(stdout);
	write_status("READY");

	while (!g_terminate) {
		if (g_query) {
			struct ibv_device_attr a;

			g_query = 0;
			if (ibv_query_device(g_ctx, &a))
				write_status("FAIL: ibv_query_device after signal");
			else
				write_status("OK");
		}
		pause();
	}

	ibv_close_device(g_ctx);
	return 0;
}
