/*
 * R3 dump-side: per-ucontext uobject DAG walker (single-pass).
 *
 * Runs once at end-of-dump, after every pstree task has been
 * dump_one_task'd -- so dump_uverbsfile() in uverbsfd.c has recorded
 * every checkpointed uverbs context (with its now-assigned uvfe_id)
 * onto rdma_dumped_ufiles. For each in-tree ucontext, asks NLDEV to
 * enumerate its uobjects and emits one rdma_uobj_entry per uobject
 * into rdma_uobj.img.
 *
 * Single-pass: the walk runs after file collection, so each ufile's
 * image id (uvfe_id) is already known and lands straight into the
 * emitted entry -- there is no early-capture / late-emit split. The
 * split (early pidfd_getfd capture, before the datapath freeze) is a
 * follow-on milestone for in-flight datapath state; PD carries no such
 * state, so a plain NLDEV walk after the freeze suffices here.
 *
 * v0 scope (rxe PD): PD discovery + image emission only. No per-driver
 * QUERY_PD dispatch (rxe PD has no FW state; the plugin_blob stays
 * empty) and no restore action. CQ/QP/MR/SRQ arms, the plugin dump
 * dispatch, and the early-capture split land with their milestones.
 *
 * Field provenance is documented inline in images/rdma_uobj.proto.
 * Briefly: PD has a direct CTXN (RES_CTXN), a restrack id (RES_PDN),
 * and -- on a K8a kernel -- the ufile handle (RES_HANDLE) the restore
 * side reinstalls the uobject at.
 *
 * Failure policy:
 *   * Netlink failure on the PD walk -> hard fail. We've already
 *     accepted the cost of the pre-suspend coverage netlink dump;
 *     failing closed here is consistent.
 *   * Image open / write failure -> hard fail.
 *   * An NLDEV PD whose ctxn doesn't map to any in-tree ufile ->
 *     silently dropped (kernel resource, or a userspace resource
 *     belonging to a non-snapshot-tree ucontext sharing the ibdev;
 *     the coverage check has already proven any in-tree ucontext is
 *     claimable).
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "common/compiler.h"
#include "common/list.h"
#include "image.h"
#include "log.h"
#include "protobuf.h"
#include "rdma.h"
#include "rdma/internal.h"
#include "rdma_netlink.h"
#include "xmalloc.h"

#include "images/rdma_uobj.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "rdma: "

LIST_HEAD(rdma_dumped_ufiles);

int rdma_note_dumped_ufile(uint32_t uvfe_id, bool has_ctxn, uint32_t ctxn, uint32_t criu_driver, pid_t pid,
			   const char *ibdev)
{
	struct rdma_dumped_ufile *uf = xzalloc(sizeof(*uf));

	if (!uf)
		return -1;
	uf->uvfe_id = uvfe_id;
	uf->has_ctxn = has_ctxn;
	uf->ctxn = ctxn;
	uf->criu_driver = criu_driver;
	uf->pid = pid;
	snprintf(uf->ibdev, sizeof(uf->ibdev), "%.*s", (int)(sizeof(uf->ibdev) - 1), ibdev);
	INIT_LIST_HEAD(&uf->link);
	list_add_tail(&uf->link, &rdma_dumped_ufiles);
	return 0;
}

static void rdma_drop_dumped_ufiles(void)
{
	struct rdma_dumped_ufile *uf, *n;

	list_for_each_entry_safe(uf, n, &rdma_dumped_ufiles, link) {
		list_del(&uf->link);
		xfree(uf);
	}
}

/* Per-ibdev book-keeping built up during a uobj DAG dump. */
struct uobj_ibdev {
	char ibdev[64];
	uint32_t dev_index;
	bool has_dev_index;

	/* In-tree ufiles using this ibdev. */
	struct rdma_dumped_ufile **ufiles;
	size_t n_ufiles;

	struct list_head link;
};

/* Cross-walk state shared with the per-resource callbacks. */
struct uobj_walk_ctx {
	struct uobj_ibdev *ib;
	struct cr_img *img;
	int n_emitted;
	int n_dropped;
	int err;
};

static struct uobj_ibdev *uobj_ibdev_find(struct list_head *head, const char *ibdev)
{
	struct uobj_ibdev *ib;

	list_for_each_entry(ib, head, link)
		if (strcmp(ib->ibdev, ibdev) == 0)
			return ib;
	return NULL;
}

static struct uobj_ibdev *uobj_ibdev_get_or_add(struct list_head *head, const char *ibdev)
{
	struct uobj_ibdev *ib = uobj_ibdev_find(head, ibdev);

	if (ib)
		return ib;
	ib = xzalloc(sizeof(*ib));
	if (!ib)
		return NULL;
	snprintf(ib->ibdev, sizeof(ib->ibdev), "%.*s", (int)(sizeof(ib->ibdev) - 1), ibdev);
	INIT_LIST_HEAD(&ib->link);
	list_add_tail(&ib->link, head);
	return ib;
}

/* Look up an in-tree ufile on this ibdev by ctxn. */
static struct rdma_dumped_ufile *uobj_ibdev_ufile_by_ctxn(const struct uobj_ibdev *ib, uint32_t ctxn)
{
	for (size_t i = 0; i < ib->n_ufiles; i++) {
		struct rdma_dumped_ufile *u = ib->ufiles[i];

		if (u->has_ctxn && u->ctxn == ctxn)
			return u;
	}
	return NULL;
}

/*
 * PD callback: direct CTXN join, emit one R3UT_PD entry. Single-pass,
 * so ufile_id is known now (uf->uvfe_id) and written straight into the
 * entry -- no capture buffer, no late-bind.
 */
static int uobj_pd_cb(const struct rdma_nl_res_entry *e, void *arg)
{
	struct uobj_walk_ctx *w = arg;
	struct rdma_dumped_ufile *uf;
	RdmaUobjEntry pe;
	RdmaPdAttrs attrs;

	if (!e->has_ctxn || !e->has_restrack_id) {
		w->n_dropped++;
		return 0;
	}
	uf = uobj_ibdev_ufile_by_ctxn(w->ib, e->ctxn);
	if (!uf) {
		w->n_dropped++;
		return 0;
	}

	rdma_uobj_entry__init(&pe);
	pe.ufile_id = uf->uvfe_id;
	pe.hw_driver_id = uf->criu_driver;
	pe.type = R3_UOBJ_TYPE__R3UT_PD;
	pe.has_restrack_id = true;
	pe.restrack_id = e->restrack_id;
	if (e->has_ufile_handle) {
		pe.has_ufile_handle = true;
		pe.ufile_handle = e->ufile_handle;
	} else {
		/*
		 * RES_HANDLE is the value restore reinstalls the uobject
		 * at (RESTORE_PD's target handle). Without it the entry is
		 * unrestorable, so surface the kernel-version requirement
		 * at dump time rather than as a mid-restore failure.
		 */
		pr_warn("uobj DAG: PD pdn=%u on ibdev=%s ctxn=%u has no RES_HANDLE "
			"(kernel pre-K8a); the entry cannot be restored\n",
			e->restrack_id, uf->ibdev, e->ctxn);
	}

	rdma_pd_attrs__init(&attrs);
	pe.pd = &attrs;

	if (pb_write_one(w->img, &pe, PB_RDMA_UOBJ) < 0) {
		pr_err("uobj DAG: pb_write_one(rdma_uobj.img) failed for ufile_id=%#x pdn=%u\n", pe.ufile_id,
		       e->restrack_id);
		return (w->err = -1);
	}

	w->n_emitted++;
	return 0;
}

struct devidx_resolver {
	struct list_head *ibdevs;
};

static int devidx_resolver_cb(uint32_t dev_index, const char *ibdev, void *arg)
{
	struct devidx_resolver *r = arg;
	struct uobj_ibdev *ib = uobj_ibdev_find(r->ibdevs, ibdev);

	if (ib) {
		ib->dev_index = dev_index;
		ib->has_dev_index = true;
	}
	return 0;
}

int rdma_dump_uobj_dag(void)
{
	struct rdma_dumped_ufile *uf;
	struct uobj_ibdev *ib, *ib_next;
	struct cr_img *img = NULL;
	LIST_HEAD(ibdevs);
	int ret = -1;

	if (list_empty(&rdma_dumped_ufiles)) {
		pr_debug("uobj DAG: no in-tree uverbs contexts, skipping per-uobject discovery\n");
		return 0;
	}

	/*
	 * 1. Group dumped ufiles by ibdev. Each per-ibdev bucket carries
	 * the in-tree ufile list the PD walk joins against by ctxn.
	 */
	list_for_each_entry(uf, &rdma_dumped_ufiles, link) {
		void *p;

		ib = uobj_ibdev_get_or_add(&ibdevs, uf->ibdev);
		if (!ib)
			goto out;
		p = xrealloc(ib->ufiles, (ib->n_ufiles + 1) * sizeof(*ib->ufiles));
		if (!p)
			goto out;
		ib->ufiles = p;
		ib->ufiles[ib->n_ufiles++] = uf;
	}

	/* 2. Resolve dev_index per ibdev (NLDEV walks need the index). */
	{
		struct devidx_resolver r = { .ibdevs = &ibdevs };

		if (rdma_nl_for_each_ibdev(devidx_resolver_cb, &r) < 0) {
			pr_err("uobj DAG: ibdev enumeration failed\n");
			goto out;
		}
	}

	img = open_image(CR_FD_RDMA_UOBJ, O_DUMP);
	if (!img) {
		pr_err("uobj DAG: open_image(rdma-uobj, O_DUMP) failed\n");
		goto out;
	}

	/* 3. Per-ibdev PD walk. */
	list_for_each_entry(ib, &ibdevs, link) {
		struct uobj_walk_ctx w = { .ib = ib, .img = img };
		int r;

		if (!ib->has_dev_index) {
			pr_err("uobj DAG: ibdev '%s' had no dev_index (disappeared between dump and uobj walk?); "
			       "aborting\n",
			       ib->ibdev);
			goto out;
		}

		r = rdma_nl_for_each_resource(ib->dev_index, ib->ibdev, RDMA_NL_RES_PD, uobj_pd_cb, &w);
		if (r < 0 || w.err) {
			pr_err("uobj DAG: pd walk failed on ibdev '%s' (idx=%u): r=%d err=%d\n", ib->ibdev,
			       ib->dev_index, r, w.err);
			goto out;
		}

		pr_info("uobj DAG: ibdev=%s emitted=%d dropped=%d (in-tree-ufiles=%zu)\n", ib->ibdev, w.n_emitted,
			w.n_dropped, ib->n_ufiles);
	}

	ret = 0;
out:
	if (img)
		close_image(img);
	list_for_each_entry_safe(ib, ib_next, &ibdevs, link) {
		list_del(&ib->link);
		xfree(ib->ufiles);
		xfree(ib);
	}
	rdma_drop_dumped_ufiles();
	return ret;
}
