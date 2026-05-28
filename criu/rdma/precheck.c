/*
 * Pre-suspend RDMA checks.
 *
 * Two pre-flight checks run before any pid in the snapshot tree
 * is SIGSTOPped, so a hard failure surfaces with the entire pstree
 * known but before any image data has been written:
 *
 *   rdma_check_dump_coverage()
 *       For every live RDMA context held by a snapshot-tree pid,
 *       confirm exactly one loaded plugin claims the underlying
 *       device.
 *
 *   rdma_check_cross_tree_exclusivity()
 *       For every snapshot-tree context, look at non-snapshot pids
 *       holding contexts on the same ibdev; reject the dump if the
 *       claiming plugin marks the device EXCLUSIVE (mlx5
 *       SR-IOV VF migration is the canonical EXCLUSIVE case).
 *
 * Both walk the full host context list via rdma_nl_for_each_context()
 * rather than off /proc/<pid>/fdinfo so they can see contexts that
 * the per-fd dump path would otherwise discover one pid at a time.
 *
 * Public surface declared in criu/include/rdma.h. No shared static
 * state with the rest of criu/rdma -- both checks build their own
 * pstree-membership oracle on entry and free it on exit.
 */

#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "common/list.h"
#include "criu-plugin.h"
#include "log.h"
#include "plugin.h"
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
 *      "is this context held by the snapshot tree?" -- the cross-
 *      tree exclusivity check (next commit) will use the same
 *      membership oracle to look at the *outside* set instead.
 *
 *   2. Issue a single RDMA netlink dump
 *      (rdma_nl_for_each_context()) and run our cb on every context
 *      the kernel reports.
 *
 *   3. For every context the cb sees that's held by a tree pid,
 *      resolve ibdev -> driver name -> RDMA_DRIVER_* enum and run
 *      the same exactly-one-claim arbitration the per-fd dump path
 *      runs. First failure wins: cb returns 1 with the failure
 *      details stashed in the walk context, the iterator stops
 *      iterating, and the caller surfaces a single actionable
 *      pr_err().
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
	int fail_reason;	/* 0 = no plugin claims, < 0 = arb error */
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
		pr_debug("ctx pid=%d ibdev=%s ctxn=%u outside snapshot tree, "
			 "skipping (handled by cross-tree exclusivity)\n",
			 info->pid, info->ibdev, info->ctxn);
		return 0;
	}

	if (rdma_driver_name_from_ibdev(info->ibdev, driver, sizeof(driver))) {
		pr_err("pre-suspend coverage: pid %d holds context on "
		       "ibdev=%s but kernel driver cannot be resolved from "
		       "sysfs. Refusing to dump.\n",
		       info->pid, info->ibdev);
		cov->fail_pid = info->pid;
		cov->fail_ctxn = info->ctxn;
		snprintf(cov->fail_ibdev, sizeof(cov->fail_ibdev),
			 "%.*s", (int)(sizeof(cov->fail_ibdev) - 1),
			 info->ibdev);
		cov->fail_reason = -1;
		return 1;
	}

	kdrv = rdma_driver_name_to_id(driver);
	rcd = rdma_arbitrate_plugin_claim(info->ibdev, kdrv, &claimer);
	if (rcd < 0) {
		cov->fail_pid = info->pid;
		cov->fail_ctxn = info->ctxn;
		snprintf(cov->fail_ibdev, sizeof(cov->fail_ibdev),
			 "%.*s", (int)(sizeof(cov->fail_ibdev) - 1),
			 info->ibdev);
		cov->fail_reason = rcd;
		return 1;
	}
	if (rcd == 0) {
		cov->fail_pid = info->pid;
		cov->fail_ctxn = info->ctxn;
		snprintf(cov->fail_ibdev, sizeof(cov->fail_ibdev),
			 "%.*s", (int)(sizeof(cov->fail_ibdev) - 1),
			 info->ibdev);
		cov->fail_reason = 0;
		return 1;
	}

	pr_debug("pre-suspend coverage OK: pid=%d ibdev=%s ctxn=%u "
		 "claimed by plugin '%s' rcd=%d\n",
		 info->pid, info->ibdev, info->ctxn, claimer, rcd);
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

	pr_debug("pre-suspend RDMA coverage check: enumerating live "
		 "contexts for snapshot tree of %zu pid(s)\n", n);
	ret = rdma_nl_for_each_context(dump_cov_cb, &cov);
	xfree(pids);

	if (ret < 0) {
		pr_err("pre-suspend RDMA coverage check failed at netlink "
		       "layer (%d). Failing closed: an unsupported context "
		       "in the tree would otherwise surface as a mid-dump "
		       "error. If you're certain the snapshot tree holds "
		       "no RDMA contexts, this can be debugged by running "
		       "'rdma resource show context' and confirming the "
		       "subsystem is loaded.\n",
		       ret);
		return -1;
	}
	if (ret == 0)
		return 0;

	/* Iterator stopped early: cov has the failure details. */
	if (cov.fail_reason == 0) {
		pr_err("pre-suspend RDMA coverage: pid %d holds a context "
		       "on ibdev=%s ctxn=%u that no loaded RDMA plugin "
		       "claims. Refusing to dump a tree that no plugin "
		       "could restore. Load the appropriate plugin via "
		       "CRIU_LIBS_DIR or install it into /usr/lib/criu/.\n",
		       cov.fail_pid, cov.fail_ibdev, cov.fail_ctxn);
	} else {
		pr_err("pre-suspend RDMA coverage: pid %d ibdev=%s ctxn=%u "
		       "arbitration error %d (plugin probe failure or "
		       "claim conflict; check earlier log lines).\n",
		       cov.fail_pid, cov.fail_ibdev, cov.fail_ctxn,
		       cov.fail_reason);
	}
	return -1;
}

/*
 * Cross-tree RDMA exclusivity check.
 *
 * The shape of the work:
 *
 *   1. One netlink pass collects every (pid, ibdev) tuple on the
 *      host. We materialise all tuples up front rather than try to
 *      do the analysis incrementally inside the iterator callback;
 *      the analysis is "for ibdev D, is there an in-tree pid AND
 *      an out-of-tree pid?", which is a join, not a stream filter.
 *
 *   2. Group tuples by ibdev. For each ibdev where any tree pid
 *      holds a context, look at the non-tree pids on the same
 *      ibdev (if any). For each such ibdev, ask the claiming
 *      plugin's exclusivity policy via dlsym of
 *      CR_PLUGIN_RDMA_SHARING_POLICY_SYM ("cr_rdma_sharing_policy"
 *      const int) on the plugin's dlhandle.
 *
 *   3. If the plugin is EXCLUSIVE (or doesn't declare a policy --
 *      safe default), fail with an actionable error naming both
 *      the in-tree and out-of-tree pids and pointing the operator
 *      at the offending non-snapshot process they need to deal
 *      with first.
 *
 *   4. There is a small TOCTOU window between this check and the
 *      eventual restore (or even between this check and SIGSTOP):
 *      a non-tree process could open a fresh context after we
 *      look. A future "freeze the RDMA subsystem to new uverbs
 *      opens" locking API will close that window; for now we
 *      document and accept it -- the same window already exists
 *      for the per-fd dump path's sysfs probes, so the
 *      cross-tree check isn't introducing a new class of race,
 *      just inheriting an existing one.
 */

#define CROSS_TREE_TUPLE_CAP 256
struct cross_tree_tuple {
	pid_t pid;
	char ibdev[64];
};

struct cross_tree_collect_ctx {
	const pid_t *tree_pids;
	size_t n_tree_pids;
	struct cross_tree_tuple *tuples;
	size_t n_tuples;
	size_t cap;
	int oom;
};

static int cross_tree_collect_cb(const struct rdma_nl_ctx_info *info,
				 void *arg)
{
	struct cross_tree_collect_ctx *cc = arg;
	struct cross_tree_tuple *t;

	if (cc->n_tuples >= cc->cap) {
		size_t newcap = cc->cap ? cc->cap * 2 : CROSS_TREE_TUPLE_CAP;
		struct cross_tree_tuple *nt;

		nt = xrealloc(cc->tuples,
			      newcap * sizeof(struct cross_tree_tuple));
		if (!nt) {
			cc->oom = 1;
			return -ENOMEM;
		}
		cc->tuples = nt;
		cc->cap = newcap;
	}

	t = &cc->tuples[cc->n_tuples++];
	t->pid = info->pid;
	snprintf(t->ibdev, sizeof(t->ibdev), "%.*s",
		 (int)(sizeof(t->ibdev) - 1), info->ibdev);
	return 0;
}

/*
 * Look up the per-plugin RDMA sharing policy by walking the loaded
 * plugin list, matching by name (the arbitration helper already gave
 * us the claimer's name, and that's the most stable identity we have
 * across both the hook chain and the dlhandle list).
 *
 * Returns CR_RDMA_SHARING_EXCLUSIVE if:
 *   - The plugin can't be located (shouldn't happen post-arbitration)
 *   - The plugin doesn't export the symbol
 *   - The symbol's value is not a recognised enum value
 *
 * That's deliberate: every "I don't know" path should fail closed.
 */
static int rdma_plugin_sharing_policy_by_name(const char *plugin_name)
{
	plugin_desc_t *this;

	if (!plugin_name)
		return CR_RDMA_SHARING_EXCLUSIVE;

	list_for_each_entry(this, &cr_plugin_ctl.head, list) {
		const int *p;

		if (!this->d || !this->d->name)
			continue;
		if (strcmp(this->d->name, plugin_name) != 0)
			continue;
		if (!this->dlhandle)
			return CR_RDMA_SHARING_EXCLUSIVE;
		p = (const int *)dlsym(this->dlhandle,
				       CR_PLUGIN_RDMA_SHARING_POLICY_SYM);
		if (!p) {
			pr_debug("plugin '%s' does not export %s; "
				 "defaulting to EXCLUSIVE\n",
				 plugin_name,
				 CR_PLUGIN_RDMA_SHARING_POLICY_SYM);
			return CR_RDMA_SHARING_EXCLUSIVE;
		}
		if (*p != CR_RDMA_SHARING_SHAREABLE &&
		    *p != CR_RDMA_SHARING_EXCLUSIVE) {
			pr_warn("plugin '%s' %s = %d is not a recognised "
				"enum value; defaulting to EXCLUSIVE\n",
				plugin_name,
				CR_PLUGIN_RDMA_SHARING_POLICY_SYM, *p);
			return CR_RDMA_SHARING_EXCLUSIVE;
		}
		return *p;
	}
	pr_debug("plugin '%s' not found in loaded list; defaulting "
		 "to EXCLUSIVE\n", plugin_name);
	return CR_RDMA_SHARING_EXCLUSIVE;
}

static bool tuple_pid_in_tree(const struct cross_tree_collect_ctx *cc,
			      pid_t pid)
{
	size_t i;
	for (i = 0; i < cc->n_tree_pids; i++)
		if (cc->tree_pids[i] == pid)
			return true;
	return false;
}

int rdma_check_cross_tree_exclusivity(struct pstree_item *root)
{
	struct cross_tree_collect_ctx cc = { 0 };
	struct pstree_item *item;
	pid_t *pids;
	size_t n = 0, cap = 0;
	int ret;
	size_t i, j;

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

	cc.tree_pids = pids;
	cc.n_tree_pids = n;

	ret = rdma_nl_for_each_context(cross_tree_collect_cb, &cc);
	if (ret < 0 || cc.oom) {
		pr_err("cross-tree RDMA exclusivity check failed at "
		       "netlink layer (%d). Failing closed.\n", ret);
		xfree(pids);
		xfree(cc.tuples);
		return -1;
	}

	pr_debug("cross-tree exclusivity: %zu (pid, ibdev) tuple(s) on host, "
		 "%zu pid(s) in snapshot tree\n", cc.n_tuples, n);

	/*
	 * O(N^2) over collected tuples. Real systems have a handful of
	 * ibdevs and at most low hundreds of contexts; not worth a
	 * proper hashmap until we see this in a profile.
	 */
	ret = 0;
	for (i = 0; i < cc.n_tuples && ret == 0; i++) {
		struct cross_tree_tuple *ti = &cc.tuples[i];
		const char *claimer = NULL;
		uint32_t kdrv;
		char driver[64];
		int policy;
		int rcd;

		if (!tuple_pid_in_tree(&cc, ti->pid))
			continue;

		for (j = 0; j < cc.n_tuples; j++) {
			struct cross_tree_tuple *tj = &cc.tuples[j];

			if (i == j)
				continue;
			if (strcmp(ti->ibdev, tj->ibdev) != 0)
				continue;
			if (tuple_pid_in_tree(&cc, tj->pid))
				continue;

			/*
			 * (ti->pid in tree) holds a context on ibdev,
			 * (tj->pid not in tree) also holds a context on
			 * the same ibdev. Ask the claiming plugin if
			 * that's a problem.
			 */
			if (rdma_driver_name_from_ibdev(ti->ibdev, driver,
							sizeof(driver))) {
				pr_err("cross-tree exclusivity: cannot "
				       "resolve driver for ibdev=%s\n",
				       ti->ibdev);
				ret = -1;
				break;
			}
			kdrv = rdma_driver_name_to_id(driver);
			rcd = rdma_arbitrate_plugin_claim(ti->ibdev, kdrv,
							  &claimer);
			if (rcd < 0 || rcd == 0) {
				/*
				 * Coverage check should have rejected this
				 * already. Treat as a hard failure -- if we
				 * got here something racy happened.
				 */
				pr_err("cross-tree exclusivity: ibdev=%s "
				       "lost its claim between coverage and "
				       "exclusivity checks (rcd=%d)\n",
				       ti->ibdev, rcd);
				ret = -1;
				break;
			}

			policy = rdma_plugin_sharing_policy_by_name(claimer);
			if (policy == CR_RDMA_SHARING_SHAREABLE) {
				pr_debug("cross-tree exclusivity: ibdev=%s "
					 "shared between in-tree pid %d and "
					 "out-of-tree pid %d, but plugin "
					 "'%s' is SHAREABLE -- OK\n",
					 ti->ibdev, ti->pid, tj->pid,
					 claimer);
				continue;
			}

			pr_err("cross-tree RDMA exclusivity: in-tree pid %d "
			       "and out-of-tree pid %d both hold contexts on "
			       "ibdev=%s, and the claiming plugin '%s' marks "
			       "this device EXCLUSIVE. Snapshotting and "
			       "restoring would destroy pid %d's context. "
			       "Either include pid %d in the snapshot, stop "
			       "it before dumping, or switch the device's "
			       "claiming plugin to a sharing-aware one.\n",
			       ti->pid, tj->pid, ti->ibdev, claimer,
			       tj->pid, tj->pid);
			ret = -1;
			break;
		}
	}

	xfree(pids);
	xfree(cc.tuples);
	return ret;
}
