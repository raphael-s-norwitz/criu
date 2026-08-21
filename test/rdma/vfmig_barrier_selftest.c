/*
 * vfmig_barrier_selftest.c -- no-hardware single-host gate for the
 * mlx5_sriov_vfmig plugin's cross-host READY barrier (plugins/rdma/
 * mlx5_sriov_vfmig/vfmig_barrier.c).
 *
 * INTERNAL VALIDATION ONLY -- drop before upstream PR.
 *
 * Exercises vfmig_barrier_run() in isolation, without a tracked VF, a
 * running criu, or the plugin .so: it compiles vfmig_barrier.c straight
 * into the test binary and, for each case, fork()s a peer that speaks
 * the same rendezvous. The parent runs the *real* vfmig_barrier_run();
 * the child is an independent stub that shares only the on-the-wire
 * contract (vfmig_barrier_wire.h) -- its own sockets, its own tie-break,
 * its own send/recv -- so a matching exchange proves both the barrier
 * logic and the byte-for-byte wire format, and an independent peer
 * catches drift the plugin alone could not.
 *
 * Both endpoints are 127.0.0.1 on ephemeral-ish ports derived from the
 * pid. Cases:
 *   1. plugin is the connector (its listen sorts below the peer)  -> ok
 *   2. plugin is the acceptor  (its listen sorts above the peer)  -> ok
 *   3. peer speaks a different session (short timeout)            -> the
 *      plugin rejects every exchange and times out (rc != 0)
 *
 * Built + run by run_vfmig_barrier_selftest.sh.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "vfmig_barrier_wire.h"
#include "vfmig_internal.h"

/* ---- shims for the criu-binary symbols vfmig_barrier.c references ---- */

unsigned int log_get_loglevel(void)
{
	return 4; /* LOG_DEBUG; the test prints everything to stderr */
}

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list ap;

	(void)loglevel;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

/* ---- test scaffolding ---- */

static int failures;

#define CHECK(cond, msg)                                      \
	do {                                                  \
		if (!(cond)) {                                \
			fprintf(stderr, "FAIL: %s\n", (msg)); \
			failures++;                           \
		} else {                                      \
			fprintf(stderr, "ok:   %s\n", (msg)); \
		}                                             \
	} while (0)

/* ---- independent peer stub (shares only vfmig_barrier_wire.h) ---- */

static int64_t peer_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int peer_write_full(int fd, const void *buf, size_t n)
{
	const char *p = buf;

	while (n) {
		ssize_t w = write(fd, p, n);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += w;
		n -= (size_t)w;
	}
	return 0;
}

static int peer_read_full(int fd, void *buf, size_t n, int64_t deadline)
{
	char *p = buf;

	while (n) {
		int64_t rem = deadline - peer_now_ms();
		struct timeval tv;
		ssize_t r;

		if (rem <= 0)
			return -1;
		tv.tv_sec = rem / 1000;
		tv.tv_usec = (rem % 1000) * 1000;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		r = read(fd, p, n);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0)
			return -1;
		p += r;
		n -= (size_t)r;
	}
	return 0;
}

static void peer_addr(struct sockaddr_in *sa, const char *ip, uint16_t port)
{
	memset(sa, 0, sizeof(*sa));
	sa->sin_family = AF_INET;
	sa->sin_port = htons(port);
	inet_pton(AF_INET, ip, &sa->sin_addr);
}

/*
 * Run the peer side of a single edge. Tie-break exactly as the plugin
 * does (endpoint string: smaller connects, larger accepts). Returns 0 on
 * a validated exchange, -1 otherwise.
 */
static int peer_run(const char *my_ip, uint16_t my_port, const char *peer_ip, uint16_t peer_port, const char *session,
		    const char *phase, const uint8_t uuid[16], int timeout_ms, int retry_ms)
{
	struct vfmig_barrier_msg mine, peer;
	int64_t deadline = peer_now_ms() + timeout_ms;
	int cmp = strcmp(my_ip, peer_ip);
	bool connector = cmp < 0 || (cmp == 0 && my_port < peer_port);
	int fd = -1, rc = -1, one = 1;

	memset(&mine, 0, sizeof(mine));
	mine.magic = VFMIG_BARRIER_MAGIC;
	mine.version = VFMIG_BARRIER_VERSION;
	mine.listen_port = my_port;
	snprintf(mine.phase, sizeof(mine.phase), "%s", phase);
	snprintf(mine.session, sizeof(mine.session), "%s", session);
	memcpy(mine.vf_uuid, uuid, 16);
	snprintf(mine.listen_ip, sizeof(mine.listen_ip), "%s", my_ip);

	if (connector) {
		while (peer_now_ms() < deadline) {
			struct sockaddr_in sa;
			int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

			peer_addr(&sa, peer_ip, peer_port);
			if (s >= 0 && !connect(s, (struct sockaddr *)&sa, sizeof(sa))) {
				fd = s;
				break;
			}
			if (s >= 0)
				close(s);
			usleep((useconds_t)retry_ms * 1000);
		}
	} else {
		struct sockaddr_in sa;
		struct timeval tv;
		int64_t rem;
		int ls = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

		peer_addr(&sa, my_ip, my_port);
		setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		if (ls < 0 || bind(ls, (struct sockaddr *)&sa, sizeof(sa)) || listen(ls, 4)) {
			if (ls >= 0)
				close(ls);
			return -1;
		}
		rem = deadline - peer_now_ms();
		if (rem < 0)
			rem = 0;
		tv.tv_sec = rem / 1000;
		tv.tv_usec = (rem % 1000) * 1000;
		setsockopt(ls, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		fd = accept(ls, NULL, NULL);
		close(ls);
	}
	if (fd < 0)
		return -1;

	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	if (!peer_write_full(fd, &mine, sizeof(mine)) && !peer_read_full(fd, &peer, sizeof(peer), deadline)) {
		if (peer.magic == VFMIG_BARRIER_MAGIC && peer.version == VFMIG_BARRIER_VERSION &&
		    !strncmp(peer.phase, phase, sizeof(peer.phase)) &&
		    !strncmp(peer.session, session, sizeof(peer.session)))
			rc = 0;
	}
	close(fd);
	return rc;
}

/* ---- driver ---- */

static const uint8_t g_uuid[16] = { 0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0 };
static const char g_ip[] = "127.0.0.1";
static const char g_phase[] = "R1";

/*
 * fork() a peer stub and run the real vfmig_barrier_run() against it.
 * @plugin_port is the plugin's listen; @peer_port the stub's. When
 * @peer_session differs from @session the exchange must be rejected.
 * Returns the plugin's rc (0 = barrier reached).
 */
static int run_case(uint16_t plugin_port, uint16_t peer_port, const char *session, const char *peer_session,
		    int timeout_ms)
{
	struct vfmig_rendezvous rz;
	pid_t pid;
	int prc, status;

	memset(&rz, 0, sizeof(rz));
	snprintf(rz.session, sizeof(rz.session), "%s", session);
	memcpy(rz.vf_uuid, g_uuid, 16);
	snprintf(rz.listen.ip, sizeof(rz.listen.ip), "%s", g_ip);
	rz.listen.port = plugin_port;
	snprintf(rz.peers[0].ip, sizeof(rz.peers[0].ip), "%s", g_ip);
	rz.peers[0].port = peer_port;
	rz.n_peers = 1;
	rz.timeout_ms = timeout_ms;
	rz.retry_ms = 50;

	pid = fork();
	if (pid == 0) {
		int r = peer_run(g_ip, peer_port, g_ip, plugin_port, peer_session, g_phase, g_uuid, timeout_ms, 50);

		_exit(r ? 1 : 0);
	}

	prc = vfmig_barrier_run(&rz, g_phase);
	waitpid(pid, &status, 0);
	return prc;
}

int main(void)
{
	uint16_t base = (uint16_t)(34100 + (getpid() % 500) * 12);

	/* 1. plugin is the connector (listen sorts below the peer). */
	CHECK(run_case(base + 0, base + 1, "sess-A", "sess-A", 4000) == 0, "plugin-as-connector rendezvous reaches READY");

	/* 2. plugin is the acceptor (listen sorts above the peer). */
	CHECK(run_case(base + 3, base + 2, "sess-B", "sess-B", 4000) == 0, "plugin-as-acceptor rendezvous reaches READY");

	/* 3. session mismatch: plugin rejects and times out. */
	CHECK(run_case(base + 4, base + 5, "sess-C", "sess-WRONG", 600) != 0,
	      "session mismatch is rejected (plugin times out)");

	if (failures) {
		fprintf(stderr, "\n%d check(s) FAILED\n", failures);
		return 1;
	}
	fprintf(stderr, "\nall checks passed\n");
	return 0;
}
