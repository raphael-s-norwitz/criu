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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
