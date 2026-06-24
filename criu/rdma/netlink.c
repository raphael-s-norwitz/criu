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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/compiler.h"
#include "common/config.h"
#include "log.h"
#include "rdma_netlink.h"

/*
 * Compat shim for distros whose <rdma/rdma_netlink.h> pre-dates
 * upstream kernel commit 0601c496b413 ("RDMA/nldev: Expose ufile
 * handle alongside per-class restrack id", aka K8a in
 * linux/tools/testing/criu_rdma/design/uobject_restore.md §7.5.1).
 * The kernel emits the new u32 attribute by numeric value at
 * runtime; the build-side probe in scripts/feature-tests.mak only
 * checks whether the host header provides the symbolic name.
 *
 * The hard-coded value (105) matches the upstream enum slot the
 * kernel patch added; changing it would require an in-lockstep
 * kernel-side change. Drop this whole block once the distro
 * rdma-core that ships the symbol is the build's minimum.
 */
#ifndef CONFIG_HAS_RDMA_NLDEV_ATTR_RES_HANDLE
#define RDMA_NLDEV_ATTR_RES_HANDLE 105
#endif

/*
 * Compat shim for the per-QP CQ-binding NLDEV emission landing
 * alongside the Linux S6b QP-restore path. fill_res_qp_entry needs
 * to emit the source QP's send_cq.uobject->res.id and recv_cq.
 * uobject->res.id so a CRIU dump can build R3XR_SEND_CQ /
 * R3XR_RECV_CQ xref edges that resolve to ufile_handle through the
 * existing CQ handle_map. Without these, UVERBS_METHOD_RESTORE_QP's
 * MANDATORY IDR(UVERBS_OBJECT_CQ) attrs cannot be filled and the
 * dispatcher rejects with -ENOENT before the driver runs.
 *
 * Slot ids 106 / 107 reserve the first two free positions after K8a
 * (RES_HANDLE = 105). The kernel patch lands the symbolic names; the
 * runtime emission is u32, so this build picks them up by numeric
 * value once the kernel is updated.
 */
#ifndef RDMA_NLDEV_ATTR_RES_SEND_CQN
#define RDMA_NLDEV_ATTR_RES_SEND_CQN 106
#endif
#ifndef RDMA_NLDEV_ATTR_RES_RECV_CQN
#define RDMA_NLDEV_ATTR_RES_RECV_CQN 107
#endif

/*
 * libnl3's nla_parse stores attribute pointers in a caller-supplied
 * table indexed by nla_type, bounded by the @maxtype argument. We
 * size that argument off RDMA_NLDEV_ATTR_MAX, which on older host
 * headers (pre-K8a) is < RDMA_NLDEV_ATTR_RES_HANDLE -- so a literal
 * RDMA_NLDEV_ATTR_MAX cap silently drops the new attr and stack-
 * overruns reads past tb[]. Take the max of the host enum tail and
 * (compat constant + 1) to keep both the table and the parse range
 * large enough on either kernel. RES_RECV_CQN is the highest of the
 * three CRIU-extended slots so we anchor the cap there.
 */
#define CRIU_RDMA_NLDEV_ATTR_TBSZ \
	(RDMA_NLDEV_ATTR_MAX > (RDMA_NLDEV_ATTR_RES_RECV_CQN + 1) \
		? RDMA_NLDEV_ATTR_MAX \
		: (RDMA_NLDEV_ATTR_RES_RECV_CQN + 1))

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
	struct nlattr *tb[CRIU_RDMA_NLDEV_ATTR_TBSZ];
	struct nl_dev *d;
	const char *name;

	if (nlmsg_parse(hdr, 0, tb, CRIU_RDMA_NLDEV_ATTR_TBSZ - 1, NULL) < 0)
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
	struct nlattr *tb[CRIU_RDMA_NLDEV_ATTR_TBSZ];

	if (nla_parse(tb, CRIU_RDMA_NLDEV_ATTR_TBSZ - 1,
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
	struct nlattr *tb[CRIU_RDMA_NLDEV_ATTR_TBSZ];
	struct nlattr *list, *entry;
	int rem;

	if (nlmsg_parse(hdr, 0, tb, CRIU_RDMA_NLDEV_ATTR_TBSZ - 1, NULL) < 0)
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

/*
 * Run the host-wide RDMA_NLDEV_CMD_GET dump and collect each ibdev
 * the kernel knows about into @out. Caller frees the list with
 * free_dev_list(). Shared by rdma_nl_for_each_context (which then
 * issues per-device follow-up dumps) and rdma_nl_for_each_ibdev
 * (the bare-list public wrapper).
 */
static void free_dev_list(struct nl_dev *head)
{
	struct nl_dev *d, *next;

	for (d = head; d != NULL; d = next) {
		next = d->next;
		free(d);
	}
}

static int collect_devs(int sk, struct dev_collect_ctx *out)
{
	memset(out, 0, sizeof(*out));
	return rdma_nl_dump(sk,
			    RDMA_NL_GET_TYPE(RDMA_NL_NLDEV,
					     RDMA_NLDEV_CMD_GET),
			    NULL, 0, dev_collect_cb, out);
}

int rdma_nl_for_each_context(rdma_nl_ctx_cb_t cb, void *arg)
{
	struct dev_collect_ctx devs;
	struct nl_dev *d;
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
	ret = collect_devs(sk, &devs);
	if (ret < 0) {
		close(sk);
		return ret;
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
	free_dev_list(devs.head);
	return ret;
}

int rdma_nl_for_each_ibdev(rdma_nl_ibdev_cb_t cb, void *arg)
{
	struct dev_collect_ctx devs;
	struct nl_dev *d;
	int sk, ret;

	if (!cb)
		return -EINVAL;

	sk = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_RDMA);
	if (sk < 0) {
		pr_perror("socket(NETLINK_RDMA) failed");
		return -errno;
	}

	ret = collect_devs(sk, &devs);
	close(sk);
	if (ret < 0)
		return ret;

	for (d = devs.head; d != NULL; d = d->next) {
		ret = cb(d->dev_index, d->ibdev, arg);
		if (ret != 0)
			break;
	}

	free_dev_list(devs.head);
	return ret;
}

/*
 * Per-resource walker.
 *
 * For every R3-relevant uobject class (PD/CQ/QP/MR/SRQ) the kernel
 * exposes an RDMA_NLDEV_CMD_RES_<TYPE>_GET that dumps every
 * non-kernel resource of that type on a given ibdev (DEV_INDEX is
 * mandatory). The reply layout is uniform: one nlmsg per device
 * containing a top-level RDMA_NLDEV_ATTR_RES_<TYPE> nested table,
 * inside which sit zero or more RES_<TYPE>_ENTRY nested children,
 * each carrying that resource's per-attr leaves.
 *
 * Per-class field availability tracks fill_res_<type>_entry in the
 * upstream kernel; see the doc comment in rdma_netlink.h for what
 * the iterator promises to surface today.
 */
struct res_walk_ctx {
	rdma_nl_res_cb_t user_cb;
	void *user_arg;
	enum rdma_nl_res_type type;
	uint32_t dev_index;
	const char *ibdev;
	int cb_ret;
};

/*
 * Per-type metadata: which CMD code drives the dump, which top-level
 * NLDEV attribute IDs nest the entry list and the entries inside it,
 * and which kernel attr carries the resource's restrack_id.
 *
 * Keep the order matching enum rdma_nl_res_type so a switch can be
 * collapsed to indexed array access.
 */
static const struct res_type_info {
	uint16_t cmd;
	uint16_t list_attr;	/* RDMA_NLDEV_ATTR_RES_<TYPE>      */
	uint16_t entry_attr;	/* RDMA_NLDEV_ATTR_RES_<TYPE>_ENTRY */
	uint16_t restrack_attr;	/* RDMA_NLDEV_ATTR_RES_PDN/CQN/...  */
	const char *name;
} res_types[] = {
	[RDMA_NL_RES_PD]  = { RDMA_NLDEV_CMD_RES_PD_GET,
			      RDMA_NLDEV_ATTR_RES_PD,
			      RDMA_NLDEV_ATTR_RES_PD_ENTRY,
			      RDMA_NLDEV_ATTR_RES_PDN, "pd" },
	[RDMA_NL_RES_CQ]  = { RDMA_NLDEV_CMD_RES_CQ_GET,
			      RDMA_NLDEV_ATTR_RES_CQ,
			      RDMA_NLDEV_ATTR_RES_CQ_ENTRY,
			      RDMA_NLDEV_ATTR_RES_CQN, "cq" },
	[RDMA_NL_RES_QP]  = { RDMA_NLDEV_CMD_RES_QP_GET,
			      RDMA_NLDEV_ATTR_RES_QP,
			      RDMA_NLDEV_ATTR_RES_QP_ENTRY,
			      0, /* QP has no restrack_id attr today */ "qp" },
	[RDMA_NL_RES_MR]  = { RDMA_NLDEV_CMD_RES_MR_GET,
			      RDMA_NLDEV_ATTR_RES_MR,
			      RDMA_NLDEV_ATTR_RES_MR_ENTRY,
			      RDMA_NLDEV_ATTR_RES_MRN, "mr" },
	[RDMA_NL_RES_SRQ] = { RDMA_NLDEV_CMD_RES_SRQ_GET,
			      RDMA_NLDEV_ATTR_RES_SRQ,
			      RDMA_NLDEV_ATTR_RES_SRQ_ENTRY,
			      RDMA_NLDEV_ATTR_RES_SRQN, "srq" },
};

/*
 * Parse one RES_<TYPE>_ENTRY nested attribute into @e. Reads
 * everything fill_res_<type>_entry currently emits per type; the
 * caller's switch on @e->type already determines which union arm
 * the per-leaf code populates.
 */
static int parse_res_entry(struct nlattr *entry,
			   const struct res_type_info *info,
			   struct rdma_nl_res_entry *e)
{
	struct nlattr *tb[CRIU_RDMA_NLDEV_ATTR_TBSZ];

	if (nla_parse(tb, CRIU_RDMA_NLDEV_ATTR_TBSZ - 1,
		      nla_data(entry), nla_len(entry), NULL) < 0)
		return -1;

	if (info->restrack_attr && tb[info->restrack_attr]) {
		e->has_restrack_id = true;
		e->restrack_id = nla_get_u32(tb[info->restrack_attr]);
	}
	if (tb[RDMA_NLDEV_ATTR_RES_CTXN]) {
		e->has_ctxn = true;
		e->ctxn = nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_CTXN]);
	}
	if (tb[RDMA_NLDEV_ATTR_RES_PDN]) {
		e->has_pdn = true;
		e->pdn = nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_PDN]);
	}
	if (tb[RDMA_NLDEV_ATTR_RES_PID]) {
		e->has_pid = true;
		e->pid = (pid_t)nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_PID]);
	}
	/*
	 * RES_HANDLE is the per-uobject ib_uobject->id (the user-visible
	 * ufile handle) emitted alongside the per-class restrack id by
	 * the kernel patch K8a -- see compat shim above and
	 * design/uobject_restore.md §7.5.1. Only present on user-created
	 * resources (kernel-internal restrack entries -- no ib_uobject
	 * backing -- omit it by construction); has_ufile_handle stays
	 * false on older kernels and gates downstream consumers (the R3
	 * dump path that emits target_handle into rdma-uobj.img).
	 */
	if (tb[RDMA_NLDEV_ATTR_RES_HANDLE]) {
		e->has_ufile_handle = true;
		e->ufile_handle = nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_HANDLE]);
	}

	switch (e->type) {
	case RDMA_NL_RES_PD:
		if (tb[RDMA_NLDEV_ATTR_RES_USECNT])
			e->pd.usecnt = nla_get_u64(tb[RDMA_NLDEV_ATTR_RES_USECNT]);
		/*
		 * The PD's FW identity (mpd->pdn / mpd->uid) is no longer
		 * sourced from NLDEV driver TLVs. It now travels per-PD-
		 * handle via the mlx5 plugin's MLX5_IB_METHOD_VFMIG_QUERY_PD
		 * verb (dump-side hook CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_PD),
		 * mirroring how cqn/qpn come from QUERY_CQ/QUERY_QP. The
		 * RDMA_NLDEV_ATTR_DRIVER walk for "fw_pdn"/"fw_uid" was
		 * dropped here when the kernel removed those TLVs from
		 * fill_res_pd_entry.
		 */
		break;
	case RDMA_NL_RES_CQ:
		if (tb[RDMA_NLDEV_ATTR_RES_CQE])
			e->cq.cqe = nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_CQE]);
		if (tb[RDMA_NLDEV_ATTR_RES_USECNT])
			e->cq.usecnt = nla_get_u64(tb[RDMA_NLDEV_ATTR_RES_USECNT]);
		break;
	case RDMA_NL_RES_QP:
		if (tb[RDMA_NLDEV_ATTR_RES_LQPN])
			e->qp.lqpn = nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_LQPN]);
		if (tb[RDMA_NLDEV_ATTR_RES_RQPN]) {
			e->qp.has_rqpn = true;
			e->qp.rqpn = nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_RQPN]);
		}
		if (tb[RDMA_NLDEV_ATTR_RES_RQ_PSN]) {
			e->qp.has_rq_psn = true;
			e->qp.rq_psn = nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_RQ_PSN]);
		}
		if (tb[RDMA_NLDEV_ATTR_RES_SQ_PSN]) {
			e->qp.has_sq_psn = true;
			e->qp.sq_psn = nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_SQ_PSN]);
		}
		if (tb[RDMA_NLDEV_ATTR_RES_TYPE])
			e->qp.qp_type = nla_get_u8(tb[RDMA_NLDEV_ATTR_RES_TYPE]);
		if (tb[RDMA_NLDEV_ATTR_RES_STATE])
			e->qp.qp_state = nla_get_u8(tb[RDMA_NLDEV_ATTR_RES_STATE]);
		if (tb[RDMA_NLDEV_ATTR_PORT_INDEX]) {
			e->qp.has_port = true;
			e->qp.port = nla_get_u32(tb[RDMA_NLDEV_ATTR_PORT_INDEX]);
		}
		/*
		 * RES_SEND_CQN / RES_RECV_CQN are the parent CQ
		 * restrack ids the (pending) kernel patch will emit
		 * out of fill_res_qp_entry; presence-gated so a
		 * pre-patch host header silently leaves the fields
		 * unset and the QP entry lands without SEND_CQ /
		 * RECV_CQ xrefs. The R3 dump-side walker emits a
		 * pr_warn on absence so the kernel-version
		 * requirement surfaces at dump time rather than as a
		 * mid-restore -ENOENT from RESTORE_QP's IDR check.
		 */
		if (tb[RDMA_NLDEV_ATTR_RES_SEND_CQN]) {
			e->qp.has_send_cqn = true;
			e->qp.send_cqn =
				nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_SEND_CQN]);
		}
		if (tb[RDMA_NLDEV_ATTR_RES_RECV_CQN]) {
			e->qp.has_recv_cqn = true;
			e->qp.recv_cqn =
				nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_RECV_CQN]);
		}
		break;
	case RDMA_NL_RES_MR:
		if (tb[RDMA_NLDEV_ATTR_RES_MRLEN])
			e->mr.mrlen = nla_get_u64(tb[RDMA_NLDEV_ATTR_RES_MRLEN]);
		if (tb[RDMA_NLDEV_ATTR_RES_IOVA]) {
			e->mr.has_iova = true;
			e->mr.iova = nla_get_u64(tb[RDMA_NLDEV_ATTR_RES_IOVA]);
		}
		if (tb[RDMA_NLDEV_ATTR_RES_LKEY]) {
			e->mr.has_lkey = true;
			e->mr.lkey = nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_LKEY]);
		}
		if (tb[RDMA_NLDEV_ATTR_RES_RKEY]) {
			e->mr.has_rkey = true;
			e->mr.rkey = nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_RKEY]);
		}
		break;
	case RDMA_NL_RES_SRQ:
		if (tb[RDMA_NLDEV_ATTR_RES_TYPE])
			e->srq.srq_type = nla_get_u8(tb[RDMA_NLDEV_ATTR_RES_TYPE]);
		if (tb[RDMA_NLDEV_ATTR_RES_CQN]) {
			e->srq.has_cqn = true;
			e->srq.cqn = nla_get_u32(tb[RDMA_NLDEV_ATTR_RES_CQN]);
		}
		break;
	}
	return 0;
}

static int res_per_msg_cb(struct nlmsghdr *hdr, void *arg)
{
	struct res_walk_ctx *rw = arg;
	const struct res_type_info *info = &res_types[rw->type];
	struct nlattr *tb[CRIU_RDMA_NLDEV_ATTR_TBSZ];
	struct nlattr *list, *entry;
	int rem;

	if (nlmsg_parse(hdr, 0, tb, CRIU_RDMA_NLDEV_ATTR_TBSZ - 1, NULL) < 0)
		return 0;

	list = tb[info->list_attr];
	if (!list)
		return 0;

	nla_for_each_nested(entry, list, rem) {
		struct rdma_nl_res_entry e = { 0 };
		int r;

		if (nla_type(entry) != info->entry_attr)
			continue;

		e.type = rw->type;
		e.dev_index = rw->dev_index;
		snprintf(e.ibdev, sizeof(e.ibdev), "%.*s",
			 (int)(sizeof(e.ibdev) - 1), rw->ibdev);

		if (parse_res_entry(entry, info, &e) != 0)
			continue;

		r = rw->user_cb(&e, rw->user_arg);
		if (r != 0) {
			rw->cb_ret = r;
			return r;
		}
	}

	return 0;
}

int rdma_nl_for_each_resource(uint32_t dev_index, const char *ibdev,
			      enum rdma_nl_res_type type,
			      rdma_nl_res_cb_t cb, void *arg)
{
	const struct res_type_info *info;
	struct res_walk_ctx rw;
	struct {
		struct nlattr nla;
		uint32_t val;
	} __attribute__((aligned(NLA_ALIGNTO))) req_attr;
	int sk, ret;

	if (!cb || (unsigned)type >= ARRAY_SIZE(res_types))
		return -EINVAL;

	info = &res_types[type];

	sk = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_RDMA);
	if (sk < 0) {
		pr_perror("socket(NETLINK_RDMA) failed");
		return -errno;
	}

	rw.user_cb = cb;
	rw.user_arg = arg;
	rw.type = type;
	rw.dev_index = dev_index;
	rw.ibdev = ibdev;
	rw.cb_ret = 0;

	req_attr.nla.nla_type = RDMA_NLDEV_ATTR_DEV_INDEX;
	req_attr.nla.nla_len = NLA_HDRLEN + sizeof(uint32_t);
	req_attr.val = dev_index;

	ret = rdma_nl_dump(sk,
			   RDMA_NL_GET_TYPE(RDMA_NL_NLDEV, info->cmd),
			   &req_attr, sizeof(req_attr),
			   res_per_msg_cb, &rw);
	close(sk);

	if (ret < 0) {
		pr_warn("res %s dump for ibdev %s (idx=%u) failed: %d\n",
			info->name, ibdev, dev_index, ret);
		return ret;
	}
	return rw.cb_ret;
}
