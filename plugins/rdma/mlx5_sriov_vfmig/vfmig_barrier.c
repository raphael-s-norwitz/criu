/*
 * vfmig_barrier.c
 *
 * Per-VHCA rendezvous descriptor for the rdma_mlx5_vfmig plugin: the
 * host-local key=value file that names this VHCA's control endpoint and
 * its migration peers. Loading it decides barrier mode (descriptor
 * present) vs legacy (absent). The cross-host READY barrier that
 * consumes this descriptor is layered on top.
 *
 * Descriptor (VFMIG_RZ_DIR/<uuid-hex>.desc, line-based key=value):
 *   session=<opaque migration id>
 *   vf_uuid=<32 hex>
 *   listen=<ip>:<port>          this VHCA's control endpoint
 *   peer=<ip>:<port>            repeatable; one per peer VHCA
 *   timeout_ms=<int>            optional (default below)
 *   retry_ms=<int>              optional connect backoff (default below)
 * Absent file => legacy (no barrier). A file with session= but no peer=
 * or no listen= is a config error (fail closed).
 */

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "criu-log.h"

#include "vfmig_internal.h"

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_mlx5_vfmig_plugin: "

#define VFMIG_BARRIER_DEFAULT_TIMEOUT_MS 30000
#define VFMIG_BARRIER_DEFAULT_RETRY_MS	 200

static void uuid_to_hex(const uint8_t uuid[16], char out[33])
{
	static const char hex[] = "0123456789abcdef";
	int i;

	for (i = 0; i < 16; i++) {
		out[i * 2] = hex[(uuid[i] >> 4) & 0xf];
		out[i * 2 + 1] = hex[uuid[i] & 0xf];
	}
	out[32] = '\0';
}

/* Parse "<ip>:<port>" (splitting on the LAST colon for IPv6 literals). */
static int parse_endpoint(const char *s, struct vfmig_rz_endpoint *ep)
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

/* Strip trailing newline/CR and surrounding blanks in place. */
static char *trim(char *s)
{
	char *e;

	while (*s == ' ' || *s == '\t')
		s++;
	e = s + strlen(s);
	while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t'))
		*--e = '\0';
	return s;
}

int vfmig_rendezvous_load(const uint8_t vf_uuid[16], struct vfmig_rendezvous *out)
{
	char path[PATH_MAX], hex[33];
	char line[256];
	bool have_listen = false, have_session = false;
	FILE *f;

	uuid_to_hex(vf_uuid, hex);
	snprintf(path, sizeof(path), "%s/%s.desc", VFMIG_RZ_DIR, hex);

	f = fopen(path, "re");
	if (!f) {
		if (errno == ENOENT)
			return 1;	/* legacy: no descriptor */
		pr_perror("vfmig: barrier: open(%s)", path);
		return -1;
	}

	memset(out, 0, sizeof(*out));
	memcpy(out->vf_uuid, vf_uuid, 16);
	out->timeout_ms = VFMIG_BARRIER_DEFAULT_TIMEOUT_MS;
	out->retry_ms = VFMIG_BARRIER_DEFAULT_RETRY_MS;

	while (fgets(line, sizeof(line), f)) {
		char *p = trim(line);
		char *val;

		if (*p == '\0' || *p == '#')
			continue;
		val = strchr(p, '=');
		if (!val) {
			pr_err("vfmig: barrier: %s: malformed line '%s'\n", path, p);
			goto malformed;
		}
		*val++ = '\0';
		val = trim(val);

		if (!strcmp(p, "session")) {
			snprintf(out->session, sizeof(out->session), "%s", val);
			have_session = true;
		} else if (!strcmp(p, "listen")) {
			if (parse_endpoint(val, &out->listen))
				goto bad_ep;
			have_listen = true;
		} else if (!strcmp(p, "peer")) {
			if (out->n_peers >= VFMIG_RZ_MAX_PEERS) {
				pr_err("vfmig: barrier: %s: too many peers (max %d)\n", path, VFMIG_RZ_MAX_PEERS);
				goto malformed;
			}
			if (parse_endpoint(val, &out->peers[out->n_peers]))
				goto bad_ep;
			out->n_peers++;
		} else if (!strcmp(p, "timeout_ms")) {
			out->timeout_ms = atoi(val);
		} else if (!strcmp(p, "retry_ms")) {
			out->retry_ms = atoi(val);
		}
		/* unknown keys ignored for forward-compat */
		continue;
bad_ep:
		pr_err("vfmig: barrier: %s: bad endpoint '%s' for '%s'\n", path, val, p);
		goto malformed;
	}
	fclose(f);

	if (!have_session || !have_listen || out->n_peers == 0) {
		pr_err("vfmig: barrier: %s: incomplete descriptor (session=%d listen=%d peers=%zu); failing closed\n",
		       path, have_session, have_listen, out->n_peers);
		return -1;
	}
	if (out->timeout_ms <= 0)
		out->timeout_ms = VFMIG_BARRIER_DEFAULT_TIMEOUT_MS;
	if (out->retry_ms <= 0)
		out->retry_ms = VFMIG_BARRIER_DEFAULT_RETRY_MS;

	pr_info("vfmig: barrier: loaded %s: session=%s listen=%s:%u peers=%zu timeout=%dms\n", path, out->session,
		out->listen.ip, out->listen.port, out->n_peers, out->timeout_ms);
	return 0;

malformed:
	fclose(f);
	return -1;
}

/* ---------------- barrier transport ---------------- */

static int64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Bind+listen a TCP socket on rz->listen. Returns fd or -1. */
static int barrier_listen(const struct vfmig_rendezvous *rz)
{
	struct addrinfo hints, *res, *ai;
	char portstr[8];
	int fd = -1;

	snprintf(portstr, sizeof(portstr), "%u", rz->listen.port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	if (getaddrinfo(rz->listen.ip, portstr, &hints, &res)) {
		pr_err("vfmig: barrier: getaddrinfo(listen %s:%s) failed\n", rz->listen.ip, portstr);
		return -1;
	}
	for (ai = res; ai; ai = ai->ai_next) {
		int one = 1;

		fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
		if (fd < 0)
			continue;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		if (!bind(fd, ai->ai_addr, ai->ai_addrlen) && !listen(fd, VFMIG_RZ_MAX_PEERS))
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0)
		pr_perror("vfmig: barrier: bind/listen %s:%u", rz->listen.ip, rz->listen.port);
	return fd;
}

/*
 * Cross-host rendezvous, accept side: block until every peer has
 * connected to our listen socket, or the descriptor timeout elapses. An
 * inbound connection means a peer has reached the barrier point;
 * completion is gated on the count.
 *
 * This establishes the rendezvous as the listener half -- it waits for
 * peers to connect to us. The connector half (we connect to peers,
 * tie-broken per edge so exactly one side connects) is layered on top,
 * as is the READY message that carries peer identity + phase/session (so
 * an accepted connection can be attributed to a specific edge). The
 * sockets are CRIU's own, opened and closed within the call. Returns 0
 * on success, -1 on timeout/error.
 */
int vfmig_barrier_run(const struct vfmig_rendezvous *rz, const char *phase)
{
	size_t remaining = rz->n_peers;
	int64_t deadline = now_ms() + rz->timeout_ms;
	int listen_fd = -1;
	int rc = -1;

	listen_fd = barrier_listen(rz);
	if (listen_fd < 0)
		return -1;

	pr_info("vfmig: barrier[%s] session=%s: waiting for %zu peer(s) to connect, timeout=%dms\n", phase,
		rz->session, rz->n_peers, rz->timeout_ms);

	while (remaining) {
		struct timeval tv;
		fd_set rfds;

		if (now_ms() >= deadline)
			break;
		FD_ZERO(&rfds);
		FD_SET(listen_fd, &rfds);
		tv.tv_sec = 0;
		tv.tv_usec = rz->retry_ms * 1000;
		if (select(listen_fd + 1, &rfds, NULL, NULL, &tv) > 0 && FD_ISSET(listen_fd, &rfds)) {
			int cfd = accept(listen_fd, NULL, NULL);

			if (cfd >= 0) {
				remaining--;
				pr_info("vfmig: barrier[%s]: accepted peer connection (%zu of %zu still pending)\n",
					phase, remaining, rz->n_peers);
				close(cfd);
			}
		}
	}

	if (remaining) {
		pr_err("vfmig: barrier[%s] session=%s TIMED OUT: %zu of %zu peer(s) still pending after %dms\n", phase,
		       rz->session, remaining, rz->n_peers, rz->timeout_ms);
		rc = -1;
	} else {
		pr_info("vfmig: barrier[%s] session=%s: all %zu peer(s) reached rendezvous\n", phase, rz->session,
			rz->n_peers);
		rc = 0;
	}

	close(listen_fd);
	return rc;
}
