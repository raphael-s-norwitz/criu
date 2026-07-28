/*
 * Pre-suspend RDMA checks.
 *
 * Pre-flight checks that run before any pid in the snapshot tree is
 * SIGSTOPped, so a hard failure surfaces with the entire pstree known
 * but before any image data has been written:
 *
 *   rdma_check_dump_coverage()
 *       For every live RDMA context held by a snapshot-tree pid,
 *       confirm exactly one loaded plugin claims the underlying
 *       device.
 *
 * The check walks the full host context list via
 * rdma_nl_for_each_context() rather than off /proc/<pid>/fdinfo so it
 * can see contexts that the per-fd dump path would otherwise discover
 * one pid at a time.
 *
 * Public surface declared in criu/include/rdma.h. No shared static
 * state with the rest of criu/rdma -- the check builds its own
 * pstree-membership oracle on entry and frees it on exit.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "log.h"
#include "pstree.h"
#include "rdma.h"
#include "rdma_netlink.h"
#include "xmalloc.h"

#undef LOG_PREFIX
#define LOG_PREFIX "rdma: "

/*
 * Pre-suspend RDMA dump-coverage check.
 *
 * The shape of the work:
 *
 *   1. Build a flat array of host pids in the snapshot tree from
 *      pstree (already populated by collect_pstree(), which is the
 *      caller's responsibility). This is the membership oracle for
 *      "is this context held by the snapshot tree?".
 *
 *   2. Issue a single RDMA netlink dump
 *      (rdma_nl_for_each_context()) and run our cb on every context
 *      the kernel reports.
 *
 *   3. For every context the cb sees that's held by a tree pid,
 *      resolve ibdev -> driver name -> RDMA_DRIVER_* enum and run
 *      the exactly-one-claim arbitration. First failure wins: cb
 *      returns 1 with the failure details stashed in the walk
 *      context, the iterator stops, and the caller surfaces a single
 *      actionable pr_err().
 *
 * Why fail closed on netlink errors: the only alternative would be
 * "skip the pre-flight, let dump_uverbsfile() discover the same
 * problem fd-by-fd", which is exactly the user-visible failure mode
 * this pre-flight exists to avoid. If RDMA netlink is unavailable
 * (kernel built without CONFIG_INFINIBAND, NETLINK_RDMA module not
 * loaded) but no pid in the tree holds an RDMA fd, we accept the
 * netlink error as best-effort -- but the typical case is "kernel
 * supports it" and the typical failure is a real kernel-side
 * problem worth surfacing.
 */
struct dump_cov_ctx {
	const pid_t *tree_pids;
	size_t n_tree_pids;
	/* On failure: filled in by the cb, read by the caller. */
	pid_t fail_pid;
	uint32_t fail_ctxn;
	char fail_ibdev[64];
	int fail_reason; /* 0 = no plugin claims, < 0 = arb error */
};

static bool pid_in_tree(const pid_t *pids, size_t n, pid_t pid)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (pids[i] == pid)
			return true;
	return false;
}

static int dump_cov_cb(const struct rdma_nl_ctx_info *info, void *arg)
{
	struct dump_cov_ctx *cov = arg;
	const char *claimer = NULL;
	char driver[64];
	uint32_t kdrv;
	int rcd;

	if (!pid_in_tree(cov->tree_pids, cov->n_tree_pids, info->pid)) {
		pr_debug("ctx pid=%d ibdev=%s ctxn=%u outside snapshot tree, skipping\n", info->pid, info->ibdev,
			 info->ctxn);
		return 0;
	}

	if (rdma_driver_name_from_ibdev(info->ibdev, driver, sizeof(driver))) {
		pr_err("pre-suspend coverage: pid %d holds context on ibdev=%s but kernel driver cannot be resolved "
		       "from sysfs. Refusing to dump.\n",
		       info->pid, info->ibdev);
		cov->fail_pid = info->pid;
		cov->fail_ctxn = info->ctxn;
		snprintf(cov->fail_ibdev, sizeof(cov->fail_ibdev), "%.*s", (int)(sizeof(cov->fail_ibdev) - 1),
			 info->ibdev);
		cov->fail_reason = -1;
		return 1;
	}

	kdrv = rdma_driver_name_to_id(driver);
	rcd = rdma_arbitrate_plugin_claim(info->ibdev, kdrv, &claimer);
	if (rcd < 0) {
		cov->fail_pid = info->pid;
		cov->fail_ctxn = info->ctxn;
		snprintf(cov->fail_ibdev, sizeof(cov->fail_ibdev), "%.*s", (int)(sizeof(cov->fail_ibdev) - 1),
			 info->ibdev);
		cov->fail_reason = rcd;
		return 1;
	}
	if (rcd == 0) {
		cov->fail_pid = info->pid;
		cov->fail_ctxn = info->ctxn;
		snprintf(cov->fail_ibdev, sizeof(cov->fail_ibdev), "%.*s", (int)(sizeof(cov->fail_ibdev) - 1),
			 info->ibdev);
		cov->fail_reason = 0;
		return 1;
	}

	pr_debug("pre-suspend coverage OK: pid=%d ibdev=%s ctxn=%u claimed by plugin '%s' rcd=%d\n", info->pid,
		 info->ibdev, info->ctxn, claimer, rcd);
	return 0;
}

int rdma_check_dump_coverage(struct pstree_item *root)
{
	struct dump_cov_ctx cov = { 0 };
	struct pstree_item *item;
	pid_t *pids;
	size_t n = 0, cap = 0;
	int ret;

	if (!root)
		return 0;

	for_each_pstree_item(item)
		cap++;

	if (cap == 0)
		return 0;

	pids = xmalloc(cap * sizeof(pid_t));
	if (!pids)
		return -1;

	for_each_pstree_item(item)
		pids[n++] = item->pid->real;

	cov.tree_pids = pids;
	cov.n_tree_pids = n;

	pr_debug("pre-suspend RDMA coverage check: enumerating live contexts for snapshot tree of %zu pid(s)\n", n);
	ret = rdma_nl_for_each_context(dump_cov_cb, &cov);
	xfree(pids);

	if (ret < 0) {
		pr_err("pre-suspend RDMA coverage check failed at netlink layer (%d). Failing closed: an unsupported "
		       "context in the tree would otherwise surface as a mid-dump error. If you're certain the "
		       "snapshot tree holds no RDMA contexts, this can be debugged by running 'rdma resource show "
		       "context' and confirming the subsystem is loaded.\n",
		       ret);
		return -1;
	}
	if (ret == 0)
		return 0;

	/* Iterator stopped early: cov has the failure details. */
	if (cov.fail_reason == 0) {
		pr_err("pre-suspend RDMA coverage: pid %d holds a context on ibdev=%s ctxn=%u that no loaded RDMA "
		       "plugin claims. Refusing to dump a tree that no plugin could restore. Load the appropriate "
		       "plugin via CRIU_LIBS_DIR or install it into /usr/lib/criu/.\n",
		       cov.fail_pid, cov.fail_ibdev, cov.fail_ctxn);
	} else {
		pr_err("pre-suspend RDMA coverage: pid %d ibdev=%s ctxn=%u arbitration error %d (plugin probe failure "
		       "or claim conflict; check earlier log lines).\n",
		       cov.fail_pid, cov.fail_ibdev, cov.fail_ctxn, cov.fail_reason);
	}
	return -1;
}
