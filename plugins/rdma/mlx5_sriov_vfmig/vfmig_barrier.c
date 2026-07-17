/*
 * vfmig_barrier.c
 *
 * Per-VHCA rendezvous descriptor + the symmetric in-plugin cross-host
 * datapath-state barrier for the rdma_mlx5_vfmig plugin. See
 * scratch/barrier_criu_design.md.
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
 *
 * Barrier: a peer-to-peer READY rendezvous. Each edge uses a single TCP
 * connection, tie-broken by endpoint string so exactly one side
 * connects and the other accepts (no double-connect). A node completes
 * the barrier once it has exchanged a matching READY with every listed
 * peer. Sockets are CRIU's own -- opened and closed within the call,
 * never captured/restored.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "criu-log.h"

#include "vfmig_barrier_wire.h"
#include "vfmig_internal.h"

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_mlx5_vfmig_plugin: "

#define VFMIG_BARRIER_DEFAULT_TIMEOUT_MS 30000
#define VFMIG_BARRIER_DEFAULT_RETRY_MS	 200

/* ---------------- descriptor parsing ---------------- */

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
	while (e > s && (e[-1] == '\n' || e[-1] == '\r' ||
			 e[-1] == ' ' || e[-1] == '\t'))
		*--e = '\0';
	return s;
}

int vfmig_rendezvous_load(const uint8_t vf_uuid[16],
			  struct vfmig_rendezvous *out)
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
			pr_err("vfmig: barrier: %s: malformed line '%s'\n",
			       path, p);
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
				pr_err("vfmig: barrier: %s: too many peers "
				       "(max %d)\n", path, VFMIG_RZ_MAX_PEERS);
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
		pr_err("vfmig: barrier: %s: bad endpoint '%s' for '%s'\n",
		       path, val, p);
		goto malformed;
	}
	fclose(f);

	if (!have_session || !have_listen || out->n_peers == 0) {
		pr_err("vfmig: barrier: %s: incomplete descriptor "
		       "(session=%d listen=%d peers=%zu); failing closed\n",
		       path, have_session, have_listen, out->n_peers);
		return -1;
	}
	if (out->timeout_ms <= 0)
		out->timeout_ms = VFMIG_BARRIER_DEFAULT_TIMEOUT_MS;
	if (out->retry_ms <= 0)
		out->retry_ms = VFMIG_BARRIER_DEFAULT_RETRY_MS;

	pr_info("vfmig: barrier: loaded %s: session=%s listen=%s:%u "
		"peers=%zu timeout=%dms\n", path, out->session,
		out->listen.ip, out->listen.port, out->n_peers,
		out->timeout_ms);
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

static void fill_msg(struct vfmig_barrier_msg *m,
		     const struct vfmig_rendezvous *rz, const char *phase)
{
	memset(m, 0, sizeof(*m));
	m->magic = VFMIG_BARRIER_MAGIC;
	m->version = VFMIG_BARRIER_VERSION;
	m->listen_port = rz->listen.port;
	snprintf(m->phase, sizeof(m->phase), "%s", phase);
	snprintf(m->session, sizeof(m->session), "%s", rz->session);
	memcpy(m->vf_uuid, rz->vf_uuid, 16);
	snprintf(m->listen_ip, sizeof(m->listen_ip), "%s", rz->listen.ip);
}

static int msg_valid(const struct vfmig_barrier_msg *m,
		     const struct vfmig_rendezvous *rz, const char *phase)
{
	if (m->magic != VFMIG_BARRIER_MAGIC ||
	    m->version != VFMIG_BARRIER_VERSION)
		return -1;
	if (strncmp(m->phase, phase, sizeof(m->phase)))
		return -1;
	if (strncmp(m->session, rz->session, sizeof(m->session)))
		return -1;
	return 0;
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
		struct timeval tv;
		int64_t rem = deadline - now_ms();
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
			return -1;	/* peer closed early */
		p += r;
		n -= (size_t)r;
	}
	return 0;
}

/* Exchange READY over one connected fd: send ours, read peer's, validate. */
static int exchange(int fd, const struct vfmig_barrier_msg *mine,
		    const struct vfmig_rendezvous *rz, const char *phase,
		    struct vfmig_barrier_msg *peer_out, int64_t deadline)
{
	int one = 1;

	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	if (write_full(fd, mine, sizeof(*mine)))
		return -1;
	if (read_full(fd, peer_out, sizeof(*peer_out), deadline))
		return -1;
	return msg_valid(peer_out, rz, phase);
}

static int endpoint_cmp(const struct vfmig_rz_endpoint *a,
			const struct vfmig_rz_endpoint *b)
{
	int c = strcmp(a->ip, b->ip);

	if (c)
		return c;
	return (int)a->port - (int)b->port;
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
		pr_err("vfmig: barrier: getaddrinfo(listen %s:%s) failed\n",
		       rz->listen.ip, portstr);
		return -1;
	}
	for (ai = res; ai; ai = ai->ai_next) {
		int one = 1;

		fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
			    ai->ai_protocol);
		if (fd < 0)
			continue;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		if (!bind(fd, ai->ai_addr, ai->ai_addrlen) &&
		    !listen(fd, VFMIG_RZ_MAX_PEERS))
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0)
		pr_perror("vfmig: barrier: bind/listen %s:%u",
			  rz->listen.ip, rz->listen.port);
	return fd;
}

/* One non-blocking-ish connect attempt to @ep. Returns fd or -1. */
static int barrier_connect_once(const struct vfmig_rz_endpoint *ep)
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

int vfmig_barrier_run(const struct vfmig_rendezvous *rz, const char *phase)
{
	struct vfmig_barrier_msg mine, peer;
	bool is_connector[VFMIG_RZ_MAX_PEERS];
	bool done[VFMIG_RZ_MAX_PEERS];
	size_t remaining = rz->n_peers;
	int64_t deadline = now_ms() + rz->timeout_ms;
	int listen_fd = -1;
	size_t i;
	int rc = -1;

	fill_msg(&mine, rz, phase);

	/*
	 * Tie-break each edge by endpoint string: the lexicographically
	 * smaller side connects, the larger accepts. Exactly one
	 * connection per peer, no double-connect.
	 */
	for (i = 0; i < rz->n_peers; i++) {
		is_connector[i] = endpoint_cmp(&rz->listen, &rz->peers[i]) < 0;
		done[i] = false;
	}

	listen_fd = barrier_listen(rz);
	if (listen_fd < 0)
		return -1;

	pr_info("vfmig: barrier[%s] session=%s: rendezvous with %zu peer(s), "
		"timeout=%dms\n", phase, rz->session, rz->n_peers,
		rz->timeout_ms);

	while (remaining) {
		bool progress = false;
		struct timeval tv;
		fd_set rfds;
		int64_t rem;

		/* Connector edges: one attempt each per pass. */
		for (i = 0; i < rz->n_peers; i++) {
			int fd;

			if (done[i] || !is_connector[i])
				continue;
			fd = barrier_connect_once(&rz->peers[i]);
			if (fd < 0)
				continue;	/* peer not listening yet */
			if (!exchange(fd, &mine, rz, phase, &peer, deadline)) {
				done[i] = true;
				remaining--;
				progress = true;
				pr_info("vfmig: barrier[%s]: connected peer "
					"%s:%u ok\n", phase, rz->peers[i].ip,
					rz->peers[i].port);
			}
			close(fd);
		}
		if (!remaining)
			break;

		/* Acceptor edges: poll the listen socket briefly. */
		rem = deadline - now_ms();
		if (rem <= 0)
			break;
		FD_ZERO(&rfds);
		FD_SET(listen_fd, &rfds);
		tv.tv_sec = 0;
		tv.tv_usec = rz->retry_ms * 1000;
		if (select(listen_fd + 1, &rfds, NULL, NULL, &tv) > 0 &&
		    FD_ISSET(listen_fd, &rfds)) {
			int cfd = accept(listen_fd, NULL, NULL);

			if (cfd >= 0) {
				if (!exchange(cfd, &mine, rz, phase, &peer,
					      deadline)) {
					/* Match accepted conn to a peer. */
					for (i = 0; i < rz->n_peers; i++) {
						if (done[i] || is_connector[i])
							continue;
						if (peer.listen_port ==
						    rz->peers[i].port &&
						    !strncmp(peer.listen_ip,
							     rz->peers[i].ip,
							     sizeof(peer.listen_ip))) {
							done[i] = true;
							remaining--;
							progress = true;
							pr_info("vfmig: barrier"
								"[%s]: accepted "
								"peer %s:%u ok\n",
								phase,
								rz->peers[i].ip,
								rz->peers[i].port);
							break;
						}
					}
				}
				close(cfd);
			}
		}

		if (now_ms() >= deadline)
			break;
		if (!progress) {
			struct timespec req = {
				.tv_sec = 0,
				.tv_nsec = (long)rz->retry_ms * 1000000,
			};
			nanosleep(&req, NULL);
		}
	}

	if (remaining) {
		pr_err("vfmig: barrier[%s] session=%s TIMED OUT: %zu of %zu "
		       "peer(s) still pending after %dms\n", phase,
		       rz->session, remaining, rz->n_peers, rz->timeout_ms);
		rc = -1;
	} else {
		pr_info("vfmig: barrier[%s] session=%s: all %zu peer(s) "
			"ready\n", phase, rz->session, rz->n_peers);
		rc = 0;
	}

	close(listen_fd);
	return rc;
}
