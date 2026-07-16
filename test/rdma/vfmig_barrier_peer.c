/*
 * vfmig_barrier_peer -- INTERNAL VALIDATION ONLY.
 *
 * A single-edge stand-in for the "other host" in the mlx5_vfmig
 * cross-host datapath barrier. The single-host CRIU harness
 * (run_vfmig_cr.sh) launches this alongside `criu dump` (D1) and
 * `criu restore` (R1) so the plugin's in-hook rendezvous has a peer to
 * complete against without a second physical host.
 *
 * It speaks the exact wire contract in the plugin's
 * vfmig_barrier_wire.h and uses the same tie-break (the
 * lexicographically smaller endpoint connects, the larger accepts), so
 * exactly one connection is made per edge. It completes one READY
 * exchange with the DUT and exits 0; any protocol/timeout error exits
 * non-zero.
 *
 * Usage:
 *   vfmig_barrier_peer --listen <ip>:<port> --peer <ip>:<port>
 *                      --session <id> --phase D1|R1
 *                      [--timeout-ms N] [--retry-ms N]
 *
 * --listen is THIS peer's control endpoint; --peer is the DUT's
 * (matching the DUT descriptor's peer= / listen= respectively).
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../../plugins/rdma/mlx5_sriov_vfmig/vfmig_barrier_wire.h"

struct endpoint {
	char	 ip[64];
	uint16_t port;
};

static int parse_endpoint(const char *s, struct endpoint *ep)
{
	const char *colon = strrchr(s, ':');
	unsigned long port;
	size_t iplen;
	char *end;

	if (!colon || colon == s)
		return -1;
	iplen = (size_t)(colon - s);
	if (iplen >= sizeof(ep->ip))
		return -1;
	memcpy(ep->ip, s, iplen);
	ep->ip[iplen] = '\0';
	errno = 0;
	port = strtoul(colon + 1, &end, 10);
	if (errno || *end != '\0' || port == 0 || port > 65535)
		return -1;
	ep->port = (uint16_t)port;
	return 0;
}

static int endpoint_cmp(const struct endpoint *a, const struct endpoint *b)
{
	int c = strcmp(a->ip, b->ip);

	return c ? c : (int)a->port - (int)b->port;
}

static int64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int write_full(int fd, const void *buf, size_t n)
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

static int read_full(int fd, void *buf, size_t n, int64_t deadline)
{
	char *p = buf;

	while (n) {
		int64_t rem = deadline - now_ms();
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

static int listen_on(const struct endpoint *ep)
{
	struct addrinfo hints, *res, *ai;
	char portstr[8];
	int fd = -1;

	snprintf(portstr, sizeof(portstr), "%u", ep->port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	if (getaddrinfo(ep->ip, portstr, &hints, &res))
		return -1;
	for (ai = res; ai; ai = ai->ai_next) {
		int one = 1;

		fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
			    ai->ai_protocol);
		if (fd < 0)
			continue;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		if (!bind(fd, ai->ai_addr, ai->ai_addrlen) && !listen(fd, 4))
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}

static int connect_once(const struct endpoint *ep)
{
	struct addrinfo hints, *res, *ai;
	char portstr[8];
	int fd = -1;

	snprintf(portstr, sizeof(portstr), "%u", ep->port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;
	if (getaddrinfo(ep->ip, portstr, &hints, &res))
		return -1;
	for (ai = res; ai; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
			    ai->ai_protocol);
		if (fd < 0)
			continue;
		if (!connect(fd, ai->ai_addr, ai->ai_addrlen))
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}

static int exchange(int fd, const struct vfmig_barrier_msg *mine,
		    const char *session, const char *phase, int64_t deadline)
{
	struct vfmig_barrier_msg peer;
	int one = 1;

	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	if (write_full(fd, mine, sizeof(*mine)))
		return -1;
	if (read_full(fd, &peer, sizeof(peer), deadline))
		return -1;
	if (peer.magic != VFMIG_BARRIER_MAGIC ||
	    peer.version != VFMIG_BARRIER_VERSION)
		return -1;
	if (strncmp(peer.phase, phase, sizeof(peer.phase)))
		return -1;
	if (strncmp(peer.session, session, sizeof(peer.session)))
		return -1;
	return 0;
}

static void usage(const char *a0)
{
	fprintf(stderr,
		"Usage: %s --listen <ip>:<port> --peer <ip>:<port> "
		"--session <id> --phase D1|R1 [--timeout-ms N] "
		"[--retry-ms N]\n", a0);
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "listen",	required_argument, NULL, 'l' },
		{ "peer",	required_argument, NULL, 'p' },
		{ "session",	required_argument, NULL, 's' },
		{ "phase",	required_argument, NULL, 'f' },
		{ "timeout-ms",	required_argument, NULL, 't' },
		{ "retry-ms",	required_argument, NULL, 'r' },
		{ NULL, 0, NULL, 0 },
	};
	struct endpoint listen_ep = { 0 }, peer_ep = { 0 };
	const char *session = NULL, *phase = NULL;
	int timeout_ms = 30000, retry_ms = 200;
	bool have_listen = false, have_peer = false;
	struct vfmig_barrier_msg mine;
	int64_t deadline;
	bool connector;
	int c, rc = 1, lfd = -1;

	while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (c) {
		case 'l':
			if (parse_endpoint(optarg, &listen_ep))
				return 2;
			have_listen = true;
			break;
		case 'p':
			if (parse_endpoint(optarg, &peer_ep))
				return 2;
			have_peer = true;
			break;
		case 's': session = optarg; break;
		case 'f': phase = optarg; break;
		case 't': timeout_ms = atoi(optarg); break;
		case 'r': retry_ms = atoi(optarg); break;
		default: usage(argv[0]); return 2;
		}
	}
	if (!have_listen || !have_peer || !session || !phase) {
		usage(argv[0]);
		return 2;
	}
	if (timeout_ms <= 0)
		timeout_ms = 30000;
	if (retry_ms <= 0)
		retry_ms = 200;

	memset(&mine, 0, sizeof(mine));
	mine.magic = VFMIG_BARRIER_MAGIC;
	mine.version = VFMIG_BARRIER_VERSION;
	mine.listen_port = listen_ep.port;
	snprintf(mine.phase, sizeof(mine.phase), "%s", phase);
	snprintf(mine.session, sizeof(mine.session), "%s", session);
	snprintf(mine.listen_ip, sizeof(mine.listen_ip), "%s", listen_ep.ip);

	/* Same tie-break as the plugin: smaller endpoint connects. */
	connector = endpoint_cmp(&listen_ep, &peer_ep) < 0;
	deadline = now_ms() + timeout_ms;

	fprintf(stderr,
		"vfmig_barrier_peer[%s]: session=%s listen=%s:%u peer=%s:%u "
		"role=%s timeout=%dms\n", phase, session, listen_ep.ip,
		listen_ep.port, peer_ep.ip, peer_ep.port,
		connector ? "connector" : "acceptor", timeout_ms);

	if (!connector) {
		lfd = listen_on(&listen_ep);
		if (lfd < 0) {
			fprintf(stderr, "vfmig_barrier_peer: listen %s:%u "
				"failed: %s\n", listen_ep.ip, listen_ep.port,
				strerror(errno));
			return 1;
		}
	}

	while (now_ms() < deadline) {
		int fd;

		if (connector) {
			fd = connect_once(&peer_ep);
			if (fd < 0) {
				struct timespec req = {
					.tv_sec = 0,
					.tv_nsec = (long)retry_ms * 1000000,
				};
				nanosleep(&req, NULL);
				continue;
			}
		} else {
			struct timeval tv;
			fd_set rfds;
			int64_t rem = deadline - now_ms();

			FD_ZERO(&rfds);
			FD_SET(lfd, &rfds);
			tv.tv_sec = rem / 1000;
			tv.tv_usec = (rem % 1000) * 1000;
			if (select(lfd + 1, &rfds, NULL, NULL, &tv) <= 0)
				continue;
			fd = accept(lfd, NULL, NULL);
			if (fd < 0)
				continue;
		}

		if (!exchange(fd, &mine, session, phase, deadline)) {
			close(fd);
			rc = 0;
			break;
		}
		close(fd);
		/* validation failed -- retry until deadline */
	}

	if (lfd >= 0)
		close(lfd);
	if (rc)
		fprintf(stderr, "vfmig_barrier_peer[%s]: FAILED to rendezvous "
			"within %dms\n", phase, timeout_ms);
	else
		fprintf(stderr, "vfmig_barrier_peer[%s]: rendezvous OK\n",
			phase);
	return rc;
}
