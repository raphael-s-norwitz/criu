/*
 * RDMA netlink wrapper. See criu/include/rdma_netlink.h for what this
 * is and why.
 *
 * Implementation notes:
 *
 *   * We don't share criu/libnetlink.c -- that one's hardwired to
 *     the rtnetlink CR_NLMSG_SEQ / do_rtnl_req() shape. RDMA_NL_NLDEV
 *     speaks the same wire format (struct nlmsghdr + libnl3 nla
 *     payload) but encodes message type via RDMA_NL_GET_TYPE; reusing
 *     libnetlink would mean either generalising do_rtnl_req() across
 *     callers or threading a "type encoder" hook through it. Both
 *     are bigger surgery than just opening our own socket here.
 *
 *   * libnl3 attribute helpers (nla_get_*, nla_for_each_attr, the
 *     criu-wrapped nla_parse / nlmsg_parse) are reused -- they're
 *     netlink-family-agnostic.
 *
 *   * Two-step dump pattern is mandatory, not a nicety. The kernel's
 *     res_get_common_dumpit() (drivers/infiniband/core/nldev.c)
 *     rejects RDMA_NLDEV_CMD_RES_CTX_GET (and its sibling per-
 *     resource GETs) without an RDMA_NLDEV_ATTR_DEV_INDEX argument:
 *
 *         if (err || !tb[RDMA_NLDEV_ATTR_DEV_INDEX])
 *                 return -EINVAL;
 *
 *     The kernel comment says "it is possible to extend this code to
 *     return all devices in one shot ... but it is not needed for
 *     now". So we enumerate devices via the host-wide
 *     RDMA_NLDEV_CMD_GET dump first, then issue one per-device
 *     RDMA_NLDEV_CMD_RES_CTX_GET dump per ibdev. This is the same
 *     pattern iproute2's `rdma resource show` uses.
 *
 *   * Per-device per-context reply layout: one nlmsg per device with
 *     a top-level RDMA_NLDEV_ATTR_DEV_NAME / DEV_INDEX and a nested
 *     RDMA_NLDEV_ATTR_RES_CTX containing zero or more
 *     RDMA_NLDEV_ATTR_RES_CTX_ENTRY children. Each ENTRY is a nested
 *     table with at least RDMA_NLDEV_ATTR_RES_PID and
 *     RDMA_NLDEV_ATTR_RES_CTXN.
 */

#include <linux/types.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <libnl3/netlink/attr.h>
#include <libnl3/netlink/msg.h>
#include <rdma/rdma_netlink.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/compiler.h"
#include "log.h"
#include "rdma_netlink.h"

#undef LOG_PREFIX
#define LOG_PREFIX "rdma_netlink: "

#define RDMA_NL_SEQ 24681	/* arbitrary, distinct from libnetlink.c's */
#define RDMA_NL_BUF (64 * 1024)	/* per netlink dump chunk */

/*
 * Send a single nlmsghdr-only request and recv the full multi-msg
 * response into a malloc'd buffer. Caller invokes @per_msg for each
 * non-DONE/non-ERROR nlmsg in the reply with the matching seq.
 *
 * @req_data / @req_len are an optional payload appended after the
 * nlmsghdr (nla-formatted attributes); @req_len = 0 means a payload-
 * less request.
 *
 * Returns 0 on a clean DONE, the per_msg cb's first non-zero return
 * on early stop, or a negative errno on transport / kernel error.
 */
static int rdma_nl_dump(int sk, uint16_t nlmsg_type,
			const void *req_data, size_t req_len,
			int (*per_msg)(struct nlmsghdr *, void *),
			void *cb_arg)
{
	struct sockaddr_nl sa;
	struct iovec iov;
	struct msghdr msg;
	struct nlmsghdr *req;
	char *buf;
	int ret = 0;
	size_t req_total = NLMSG_LENGTH(req_len);

	req = malloc(req_total);
	if (!req)
		return -ENOMEM;
	memset(req, 0, req_total);
	req->nlmsg_len = req_total;
	req->nlmsg_type = nlmsg_type;
	req->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req->nlmsg_seq = RDMA_NL_SEQ;
	if (req_len)
		memcpy(NLMSG_DATA(req), req_data, req_len);

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	iov.iov_base = req;
	iov.iov_len = req->nlmsg_len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(sk, &msg, 0) < 0) {
		ret = -errno;
		pr_perror("sendmsg(rdma nl type=%#x) failed", nlmsg_type);
		free(req);
		return ret;
	}
	free(req);

	buf = malloc(RDMA_NL_BUF);
	if (!buf)
		return -ENOMEM;

	while (1) {
		struct nlmsghdr *hdr;
		ssize_t n;

		iov.iov_base = buf;
		iov.iov_len = RDMA_NL_BUF;
		memset(&msg, 0, sizeof(msg));
		msg.msg_name = &sa;
		msg.msg_namelen = sizeof(sa);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		n = recvmsg(sk, &msg, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			ret = -errno;
			pr_perror("recvmsg(rdma nl) failed");
			break;
		}
		if (n == 0)
			break;
		if (msg.msg_flags & MSG_TRUNC) {
			pr_err("RDMA netlink reply truncated; bump RDMA_NL_BUF\n");
			ret = -EMSGSIZE;
			break;
		}

		for (hdr = (struct nlmsghdr *)buf; NLMSG_OK(hdr, n);
		     hdr = NLMSG_NEXT(hdr, n)) {
			if (hdr->nlmsg_seq != RDMA_NL_SEQ)
				continue;
			if (hdr->nlmsg_type == NLMSG_DONE)
				goto done;
			if (hdr->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e =
					(struct nlmsgerr *)NLMSG_DATA(hdr);
				if (e->error == 0)
					goto done;
				pr_err("rdma nl request type=%#x failed: %d "
				       "(%s)\n", nlmsg_type, e->error,
				       strerror(-e->error));
				ret = e->error;
				goto done;
			}
			ret = per_msg(hdr, cb_arg);
			if (ret != 0)
				goto done;
		}
	}

done:
	free(buf);
	return ret;
}

/*
 * Per-device record we collect during the host-wide RDMA_NLDEV_CMD_GET
 * pass. The device name is copied so it survives past the netlink
 * recv buffer being recycled for the per-device follow-up dumps.
 */
struct nl_dev {
	uint32_t dev_index;
	char ibdev[64];
	struct nl_dev *next;
};

struct dev_collect_ctx {
	struct nl_dev *head;
	int n;
};

static int dev_collect_cb(struct nlmsghdr *hdr, void *arg)
{
	struct dev_collect_ctx *cc = arg;
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX];
	struct nl_dev *d;
	const char *name;

	if (nlmsg_parse(hdr, 0, tb, RDMA_NLDEV_ATTR_MAX - 1, NULL) < 0)
		return 0;
	if (!tb[RDMA_NLDEV_ATTR_DEV_INDEX] ||
	    !tb[RDMA_NLDEV_ATTR_DEV_NAME])
		return 0;

	d = malloc(sizeof(*d));
	if (!d)
		return -ENOMEM;
	d->dev_index = nla_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
	name = nla_get_string(tb[RDMA_NLDEV_ATTR_DEV_NAME]);
	snprintf(d->ibdev, sizeof(d->ibdev), "%.*s",
		 (int)(sizeof(d->ibdev) - 1), name);
	d->next = cc->head;
	cc->head = d;
	cc->n++;
	return 0;
}

/*
 * Parse one per-context entry into the caller's struct.
 * Mandatory attrs: PID + CTXN. dev_index + ibdev are inherited from
 * the enclosing per-device dump.
 */
static int parse_ctx_entry(struct nlattr *entry, pid_t *pid_out,
			   uint32_t *ctxn_out)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX];

	if (nla_parse(tb, RDMA_NLDEV_ATTR_MAX - 1,
		      nla_data(entry), nla_len(entry), NULL) < 0)
		return -1;
	if (!tb[RDMA_NLDEV_ATTR_RES_PID] ||
	    !tb[RDMA_NLDEV_ATTR_RES_CTXN])
		return -1;

	*pid_out = (pid_t)nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_PID]);
	*ctxn_out = nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_CTXN]);
	return 0;
}

struct ctx_walk_ctx {
	rdma_nl_ctx_cb_t user_cb;
	void *user_arg;
	const struct nl_dev *dev;	/* device this msg pertains to */
	int cb_ret;
};

static int ctx_per_msg_cb(struct nlmsghdr *hdr, void *arg)
{
	struct ctx_walk_ctx *cw = arg;
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX];
	struct nlattr *list, *entry;
	int rem;

	if (nlmsg_parse(hdr, 0, tb, RDMA_NLDEV_ATTR_MAX - 1, NULL) < 0)
		return 0;

	list = tb[RDMA_NLDEV_ATTR_RES_CTX];
	if (!list)
		return 0;

	nla_for_each_nested(entry, list, rem) {
		struct rdma_nl_ctx_info info = { 0 };
		int r;

		if (nla_type(entry) != RDMA_NLDEV_ATTR_RES_CTX_ENTRY)
			continue;
		if (parse_ctx_entry(entry, &info.pid, &info.ctxn) != 0)
			continue;

		info.dev_index = cw->dev->dev_index;
		snprintf(info.ibdev, sizeof(info.ibdev), "%.*s",
			 (int)(sizeof(info.ibdev) - 1), cw->dev->ibdev);

		r = cw->user_cb(&info, cw->user_arg);
		if (r != 0) {
			cw->cb_ret = r;
			return r;
		}
	}

	return 0;
}

int rdma_nl_for_each_context(rdma_nl_ctx_cb_t cb, void *arg)
{
	struct dev_collect_ctx devs = { 0 };
	struct nl_dev *d, *next;
	int sk, ret;

	if (!cb)
		return -EINVAL;

	sk = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_RDMA);
	if (sk < 0) {
		pr_perror("socket(NETLINK_RDMA) failed");
		return -errno;
	}

	/*
	 * Step 1: enumerate every ibdev on the host. RDMA_NLDEV_CMD_GET
	 * is the only RDMA_NLDEV CMD whose dumpit doesn't require a
	 * DEV_INDEX argument -- the kernel walks ib_enum_all_devs() on
	 * its behalf.
	 */
	ret = rdma_nl_dump(sk,
			   RDMA_NL_GET_TYPE(RDMA_NL_NLDEV,
					    RDMA_NLDEV_CMD_GET),
			   NULL, 0, dev_collect_cb, &devs);
	if (ret < 0) {
		close(sk);
		goto out;
	}

	pr_debug("device enum: %d ibdev(s) found\n", devs.n);

	/*
	 * Step 2: per-device, ask for that device's contexts via
	 * RES_CTX_GET. The DEV_INDEX attribute is mandatory; without
	 * it the kernel returns -EINVAL.
	 */
	ret = 0;
	for (d = devs.head; d != NULL; d = d->next) {
		struct {
			struct nlattr nla;
			uint32_t val;
		} __attribute__((aligned(NLA_ALIGNTO))) req_attr;
		struct ctx_walk_ctx cw = {
			.user_cb = cb,
			.user_arg = arg,
			.dev = d,
			.cb_ret = 0,
		};

		req_attr.nla.nla_type = RDMA_NLDEV_ATTR_DEV_INDEX;
		req_attr.nla.nla_len = NLA_HDRLEN + sizeof(uint32_t);
		req_attr.val = d->dev_index;

		ret = rdma_nl_dump(sk,
				   RDMA_NL_GET_TYPE(RDMA_NL_NLDEV,
						    RDMA_NLDEV_CMD_RES_CTX_GET),
				   &req_attr, sizeof(req_attr),
				   ctx_per_msg_cb, &cw);
		if (ret < 0) {
			pr_warn("ctx dump for ibdev %s (idx=%u) failed: %d\n",
				d->ibdev, d->dev_index, ret);
			break;
		}
		if (cw.cb_ret != 0) {
			ret = cw.cb_ret;
			break;
		}
	}

	close(sk);
out:
	for (d = devs.head; d != NULL; d = next) {
		next = d->next;
		free(d);
	}
	return ret;
}
