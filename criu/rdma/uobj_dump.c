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
 * v0 scope (rxe PD + MR + CQ + QP): PD, MR, CQ and QP discovery +
 * image emission. PD carries no per-driver state (empty plugin_blob);
 * MR is queried in core (QUERY_MR is a generic core uverb); CQ is the
 * first type with driver-private per-uobject state, so it dispatches to
 * the owning plugin (RDMA_DUMP_UOBJ_CQ) for its QUERY_CQ. QP is
 * NLDEV-only at this milestone (identity + parent-PD/send-CQ/recv-CQ
 * xrefs); its per-driver QUERY_QP dispatch and standard-verb cap land
 * with the QP-query milestone. The SRQ arm and the early-capture split
 * land with their milestones.
 *
 * Field provenance is documented inline in images/rdma_uobj.proto.
 * Briefly:
 *   * PD has a direct CTXN (RES_CTXN), a restrack id (RES_PDN), and --
 *     on a K8a kernel -- the ufile handle (RES_HANDLE) restore
 *     reinstalls the uobject at.
 *   * MR carries no CTXN in NLDEV, so it joins to its owning ufile
 *     through its parent PD's restrack id (RES_PDN): the PD walk builds
 *     a pdn -> ufile map that the MR walk resolves against, and records
 *     the same pdn as the entry's R3XR_PARENT_PD xref. Its wire keys
 *     (lkey/rkey), shape (length/iova), and registration provenance
 *     (user_addr/access_flags) come from a QUERY_MR ioctl issued on the
 *     holder's dup'd cdev fd -- NLDEV exposes only len/lkey/rkey.
 *   * CQ has a direct CTXN (like PD) and a restrack id (RES_CQN);
 *     cqe_count comes from NLDEV (RES_CQE). Its driver-private ring
 *     state (rxe: the source ring mmap vm_pgoff) is not in NLDEV, so
 *     the owning plugin QUERY_CQ's the holder's dup'd cdev fd and packs
 *     it into the entry's plugin_blob.
 *
 * Failure policy:
 *   * Netlink failure on a PD/MR/CQ/QP walk -> hard fail. We've already
 *     accepted the cost of the pre-suspend coverage netlink dump;
 *     failing closed here is consistent.
 *   * QUERY_MR / per-CQ plugin dispatch failure on an in-tree uobject
 *     -> hard fail (we cannot emit a restorable entry without it).
 *   * An in-tree QP missing a restore prerequisite (RES_HANDLE, or
 *     either RES_SEND_CQN/RES_RECV_CQN) -> hard fail, surfacing the
 *     kernel-version requirement at dump time.
 *   * Image open / write failure -> hard fail.
 *   * An NLDEV PD/MR/CQ/QP that doesn't map to any in-tree ufile ->
 *     silently dropped (kernel resource, or a userspace resource
 *     belonging to a non-snapshot-tree ucontext sharing the ibdev;
 *     the coverage check has already proven any in-tree ucontext is
 *     claimable).
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <rdma/rdma_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_cmds.h>

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

int rdma_note_dumped_ufile(uint32_t uvfe_id, bool has_ctxn, uint32_t ctxn, uint32_t criu_driver,
			   uint32_t kernel_driver_id, pid_t pid, const char *ibdev, int holder_uctx_fd)
{
	struct rdma_dumped_ufile *uf = xzalloc(sizeof(*uf));

	if (!uf) {
		if (holder_uctx_fd >= 0)
			close(holder_uctx_fd);
		return -1;
	}
	uf->uvfe_id = uvfe_id;
	uf->has_ctxn = has_ctxn;
	uf->ctxn = ctxn;
	uf->criu_driver = criu_driver;
	uf->kernel_driver_id = kernel_driver_id;
	uf->pid = pid;
	uf->holder_uctx_fd = holder_uctx_fd;
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
		if (uf->holder_uctx_fd >= 0)
			close(uf->holder_uctx_fd);
		xfree(uf);
	}
}

/*
 * UAPI lag shim for the two QUERY_MR response attrs CRIU added to the
 * kernel (35fb92467f68). The object/method and the four legacy attrs
 * (LKEY/RKEY/LENGTH/IOVA) predate this and ship in every rdma-core we
 * build against, so only USER_ADDR (5) and ACCESS_FLAGS (6) need a
 * numeric fallback. uverbs matches attrs by integer at wire time, so a
 * stable copy is enough on a kernel that has the support; a pre-35fb92
 * kernel rejects the unknown attr and rdma_send_query_mr returns the
 * error. Drop once the build's minimum rdma-core ships these symbols.
 */
#ifndef UVERBS_ATTR_QUERY_MR_RESP_USER_ADDR
#define UVERBS_ATTR_QUERY_MR_RESP_USER_ADDR 5
#endif
#ifndef UVERBS_ATTR_QUERY_MR_RESP_ACCESS_FLAGS
#define UVERBS_ATTR_QUERY_MR_RESP_ACCESS_FLAGS 6
#endif

/*
 * Six-OUT reply payload for rdma_send_query_mr. All six attrs are
 * MANDATORY-from-userspace in the request, so a current kernel writes
 * them all or rejects the ioctl entirely (no partial-write outcome).
 */
struct rdma_query_mr_resp {
	uint32_t lkey;
	uint32_t rkey;
	uint64_t length;
	uint64_t iova;
	uint64_t user_addr;
	uint32_t access_flags;
};

/*
 * Issue UVERBS_METHOD_QUERY_MR on @cmd_fd (the holder's dup'd uverbs
 * cdev) for MR ufile-handle @handle. Harvests the MR's wire identity
 * (lkey, rkey), shape (length, iova), and registration provenance (user
 * VA, access_flags) so the destination's RESTORE_MR can replay them
 * verbatim.
 *
 * @cmd_fd MUST share the holder's ucontext IDR (it is a dup of the
 * dumpee's real struct file) so @handle resolves; the per-IDR access
 * check ("this MR belongs to that ucontext") is the security boundary
 * -- strictly tighter than NLDEV's CAP_NET_ADMIN gate, see kernel
 * commit 35fb92467f68.
 *
 * Returns 0 on success (with @resp populated); -errno on ioctl failure.
 * A kernel lacking the user_addr/access_flags attrs rejects the ioctl,
 * which the caller treats as a hard "kernel too old for MR restore".
 */
static int rdma_send_query_mr(int cmd_fd, uint32_t driver_id, uint32_t handle, struct rdma_query_mr_resp *resp)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[7];
	} cmd = {};
	unsigned int n = 0;

	memset(resp, 0, sizeof(*resp));

	cmd.hdr.object_id = UVERBS_OBJECT_MR;
	cmd.hdr.method_id = UVERBS_METHOD_QUERY_MR;
	/*
	 * QUERY_MR is a generic core uverb, but the ioctl dispatcher still
	 * validates @driver_id against the per-ucontext rdma_driver_id
	 * (uverbs_ioctl.c): a mismatch returns -EINVAL. Pass the ibdev's
	 * kernel driver id (RDMA_DRIVER_RXE / ...) so validation succeeds.
	 */
	cmd.hdr.driver_id = driver_id;

	/* HANDLE: IDR(MR) -- attr->data carries the per-ufile handle inline. */
	cmd.attrs[n].attr_id = UVERBS_ATTR_QUERY_MR_HANDLE;
	cmd.attrs[n].len = 0;
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = handle;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_QUERY_MR_RESP_LKEY;
	cmd.attrs[n].len = sizeof(resp->lkey);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp->lkey;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_QUERY_MR_RESP_RKEY;
	cmd.attrs[n].len = sizeof(resp->rkey);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp->rkey;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_QUERY_MR_RESP_LENGTH;
	cmd.attrs[n].len = sizeof(resp->length);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp->length;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_QUERY_MR_RESP_IOVA;
	cmd.attrs[n].len = sizeof(resp->iova);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp->iova;
	n++;

	/* Two CRIU additions (kernel 35fb92467f68): user VA + access flags. */
	cmd.attrs[n].attr_id = UVERBS_ATTR_QUERY_MR_RESP_USER_ADDR;
	cmd.attrs[n].len = sizeof(resp->user_addr);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp->user_addr;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_QUERY_MR_RESP_ACCESS_FLAGS;
	cmd.attrs[n].len = sizeof(resp->access_flags);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)&resp->access_flags;
	n++;

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	return ioctl(cmd_fd, RDMA_VERBS_IOCTL, &cmd) < 0 ? -errno : 0;
}

/* pdn -> owning in-tree ufile, built by the PD walk for the MR join. */
struct uobj_pd_ref {
	uint32_t pdn;
	struct rdma_dumped_ufile *uf;
};

/* Per-ibdev book-keeping built up during a uobj DAG dump. */
struct uobj_ibdev {
	char ibdev[64];
	uint32_t dev_index;
	bool has_dev_index;

	/* In-tree ufiles using this ibdev. */
	struct rdma_dumped_ufile **ufiles;
	size_t n_ufiles;

	/* pdn -> ufile map, populated by the PD walk, read by the MR walk. */
	struct uobj_pd_ref *pd_map;
	size_t n_pd_map;

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

/* Record a pdn -> ufile edge for the MR walk to resolve against. */
static int uobj_ibdev_pd_map_add(struct uobj_ibdev *ib, uint32_t pdn, struct rdma_dumped_ufile *uf)
{
	void *p = xrealloc(ib->pd_map, (ib->n_pd_map + 1) * sizeof(*ib->pd_map));

	if (!p)
		return -1;
	ib->pd_map = p;
	ib->pd_map[ib->n_pd_map].pdn = pdn;
	ib->pd_map[ib->n_pd_map].uf = uf;
	ib->n_pd_map++;
	return 0;
}

/* Resolve an MR's parent pdn to its owning in-tree ufile. */
static struct rdma_dumped_ufile *uobj_ibdev_ufile_by_pdn(const struct uobj_ibdev *ib, uint32_t pdn)
{
	for (size_t i = 0; i < ib->n_pd_map; i++)
		if (ib->pd_map[i].pdn == pdn)
			return ib->pd_map[i].uf;
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

	/*
	 * Remember pdn -> ufile so the MR walk (which sees only the parent
	 * pdn, no ctxn) can join each MR to this same context.
	 */
	if (uobj_ibdev_pd_map_add(w->ib, e->restrack_id, uf) < 0)
		return (w->err = -1);

	w->n_emitted++;
	return 0;
}

/*
 * MR callback: join to the owning ufile through the parent pdn (MRs
 * carry no ctxn in NLDEV), QUERY_MR the holder's cdev for the fields
 * NLDEV omits, and emit one R3UT_MR entry with a R3XR_PARENT_PD xref.
 */
static int uobj_mr_cb(const struct rdma_nl_res_entry *e, void *arg)
{
	struct uobj_walk_ctx *w = arg;
	struct rdma_dumped_ufile *uf;
	struct rdma_query_mr_resp resp;
	RdmaUobjEntry pe;
	RdmaMrAttrs attrs;
	RdmaUobjXref xref;
	RdmaUobjXref *xrefs[1];
	int rc;

	if (!e->has_restrack_id || !e->mr.has_pdn) {
		w->n_dropped++;
		return 0;
	}
	uf = uobj_ibdev_ufile_by_pdn(w->ib, e->mr.pdn);
	if (!uf) {
		/* Parent PD not in-tree (kernel/other-ucontext MR): drop. */
		w->n_dropped++;
		return 0;
	}

	/*
	 * ufile_handle is both the QUERY_MR target and the value restore
	 * reinstalls the uobject at; without it (pre-K8a kernel) the MR is
	 * unrestorable, so fail the dump rather than emit a dead entry.
	 */
	if (!e->has_ufile_handle) {
		pr_err("uobj DAG: MR mrn=%u on ibdev=%s (pdn=%u) has no RES_HANDLE "
		       "(kernel pre-K8a); cannot restore\n",
		       e->restrack_id, w->ib->ibdev, e->mr.pdn);
		return (w->err = -1);
	}
	if (uf->holder_uctx_fd < 0) {
		pr_err("uobj DAG: MR mrn=%u on ibdev=%s has no holder cdev fd (dup failed at dump); "
		       "cannot QUERY_MR\n",
		       e->restrack_id, w->ib->ibdev);
		return (w->err = -1);
	}

	rc = rdma_send_query_mr(uf->holder_uctx_fd, uf->kernel_driver_id, e->ufile_handle, &resp);
	if (rc) {
		pr_err("uobj DAG: QUERY_MR handle=%u on ibdev=%s driver=%u failed: %d (%s)\n", e->ufile_handle,
		       w->ib->ibdev, uf->kernel_driver_id, rc, strerror(rc < 0 ? -rc : rc));
		return (w->err = -1);
	}

	rdma_uobj_entry__init(&pe);
	pe.ufile_id = uf->uvfe_id;
	pe.hw_driver_id = uf->criu_driver;
	pe.type = R3_UOBJ_TYPE__R3UT_MR;
	pe.has_restrack_id = true;
	pe.restrack_id = e->restrack_id;
	pe.has_ufile_handle = true;
	pe.ufile_handle = e->ufile_handle;

	rdma_mr_attrs__init(&attrs);
	attrs.has_virt_addr = true;
	attrs.virt_addr = resp.user_addr;
	attrs.has_length = true;
	attrs.length = resp.length;
	attrs.has_access_flags = true;
	attrs.access_flags = resp.access_flags;
	attrs.has_lkey = true;
	attrs.lkey = resp.lkey;
	attrs.has_rkey = true;
	attrs.rkey = resp.rkey;
	attrs.has_iova = true;
	attrs.iova = resp.iova;
	pe.mr = &attrs;

	rdma_uobj_xref__init(&xref);
	xref.role = R3_XREF_ROLE__R3XR_PARENT_PD;
	xref.target_type = R3_UOBJ_TYPE__R3UT_PD;
	xref.target_restrack_id = e->mr.pdn;
	xrefs[0] = &xref;
	pe.n_xref = 1;
	pe.xref = xrefs;

	if (pb_write_one(w->img, &pe, PB_RDMA_UOBJ) < 0) {
		pr_err("uobj DAG: pb_write_one(rdma_uobj.img) failed for ufile_id=%#x mrn=%u\n", pe.ufile_id,
		       e->restrack_id);
		return (w->err = -1);
	}

	w->n_emitted++;
	return 0;
}

/*
 * CQ callback: direct CTXN join (like PD), then hand off to the owning
 * plugin for the driver-private per-CQ state NLDEV can't express (rxe:
 * the ring mmap vm_pgoff, via QUERY_CQ). Emits one R3UT_CQ entry with
 * the hw-agnostic cqe_count (RES_CQE) plus whatever comp_vector/flags
 * the plugin fills, and the plugin's opaque byte blob.
 */
static int uobj_cq_cb(const struct rdma_nl_res_entry *e, void *arg)
{
	struct uobj_walk_ctx *w = arg;
	struct rdma_dumped_ufile *uf;
	ProtobufCBinaryData plugin_blob = {};
	RdmaUobjEntry pe;
	RdmaCqAttrs attrs;
	int rc;

	if (!e->has_ctxn || !e->has_restrack_id) {
		w->n_dropped++;
		return 0;
	}
	uf = uobj_ibdev_ufile_by_ctxn(w->ib, e->ctxn);
	if (!uf) {
		w->n_dropped++;
		return 0;
	}

	/*
	 * ufile_handle is both the QUERY_CQ target and the value restore
	 * reinstalls the CQ at; without it (pre-K8a kernel) the CQ is
	 * unrestorable, so fail the dump rather than emit a dead entry.
	 */
	if (!e->has_ufile_handle) {
		pr_err("uobj DAG: CQ cqn=%u on ibdev=%s ctxn=%u has no RES_HANDLE "
		       "(kernel pre-K8a); cannot restore\n",
		       e->restrack_id, w->ib->ibdev, e->ctxn);
		return (w->err = -1);
	}
	if (uf->holder_uctx_fd < 0) {
		pr_err("uobj DAG: CQ cqn=%u on ibdev=%s has no holder cdev fd (dup failed at dump); "
		       "cannot QUERY_CQ\n",
		       e->restrack_id, w->ib->ibdev);
		return (w->err = -1);
	}

	rdma_uobj_entry__init(&pe);
	pe.ufile_id = uf->uvfe_id;
	pe.hw_driver_id = uf->criu_driver;
	pe.type = R3_UOBJ_TYPE__R3UT_CQ;
	pe.has_restrack_id = true;
	pe.restrack_id = e->restrack_id;
	pe.has_ufile_handle = true;
	pe.ufile_handle = e->ufile_handle;

	rdma_cq_attrs__init(&attrs);
	attrs.has_cqe_count = true;
	attrs.cqe_count = e->cq.cqe;
	pe.cq = &attrs;

	/*
	 * Per-driver CQ payload: the plugin issues its QUERY_CQ on the
	 * holder's dup'd cdev fd, fills comp_vector/flags in @attrs, and
	 * mallocs its ring-vm_pgoff schema into @plugin_blob. We attach
	 * those bytes onto the entry and free them after the write.
	 */
	rc = rdma_dispatch_dump_uobj_cq(uf->criu_driver, uf->ibdev, uf->kernel_driver_id, uf->holder_uctx_fd,
					e->ufile_handle, uf->pid, &attrs, &plugin_blob);
	if (rc) {
		pr_err("uobj DAG: per-CQ dispatch failed for cqn=%u on ibdev=%s handle=%u: %d (%s)\n", e->restrack_id,
		       w->ib->ibdev, e->ufile_handle, rc, strerror(rc < 0 ? -rc : rc));
		free(plugin_blob.data);
		return (w->err = -1);
	}

	if (plugin_blob.data && plugin_blob.len > 0) {
		pe.has_plugin_blob = true;
		pe.plugin_blob = plugin_blob;
	}

	if (pb_write_one(w->img, &pe, PB_RDMA_UOBJ) < 0) {
		pr_err("uobj DAG: pb_write_one(rdma_uobj.img) failed for ufile_id=%#x cqn=%u\n", pe.ufile_id,
		       e->restrack_id);
		free(plugin_blob.data);
		return (w->err = -1);
	}

	free(plugin_blob.data);
	w->n_emitted++;
	return 0;
}

/*
 * QP callback: join to the owning ufile through the parent pdn (QPs,
 * like MRs, carry no ctxn in NLDEV), and emit one R3UT_QP entry from
 * the hw-agnostic identity NLDEV surfaces (type/state/qpn/psns/port)
 * plus three typed xrefs: R3XR_PARENT_PD (RES_PDN), R3XR_SEND_CQ
 * (RES_SEND_CQN) and R3XR_RECV_CQ (RES_RECV_CQN).
 *
 * This milestone is NLDEV-only: no per-driver QUERY_QP dispatch and no
 * standard-verb cap yet, so the entry carries no plugin_blob and no
 * ib_qp_cap. The driver-private wire state (AV, cursors, ring
 * vm_pgoffs, user_handle) and the cap land with the QP-query milestone,
 * appended onto rdma_qp_attrs / plugin_blob at their reserved numbers.
 *
 * A QP with a parent PD not in-tree is dropped (kernel/other-ucontext
 * QP). A QP whose owning ufile is in-tree but which is missing a
 * restore prerequisite -- the ufile handle, or either CQ-binding
 * restrack id (needs the kernel patch that emits RES_SEND_CQN /
 * RES_RECV_CQN) -- fails the dump, surfacing the requirement here
 * rather than as a mid-restore -ENOENT from RESTORE_QP's IDR check.
 */
static int uobj_qp_cb(const struct rdma_nl_res_entry *e, void *arg)
{
	struct uobj_walk_ctx *w = arg;
	struct rdma_dumped_ufile *uf;
	RdmaUobjEntry pe;
	RdmaQpAttrs attrs;
	RdmaUobjXref xr_pd, xr_scq, xr_rcq;
	RdmaUobjXref *xrefs[3];

	if (!e->qp.has_pdn) {
		w->n_dropped++;
		return 0;
	}
	uf = uobj_ibdev_ufile_by_pdn(w->ib, e->qp.pdn);
	if (!uf) {
		/* Parent PD not in-tree (kernel/other-ucontext QP): drop. */
		w->n_dropped++;
		return 0;
	}

	if (!e->has_ufile_handle) {
		pr_err("uobj DAG: QP lqpn=%u on ibdev=%s (pdn=%u) has no RES_HANDLE "
		       "(kernel pre-K8a); cannot restore\n",
		       e->qp.lqpn, w->ib->ibdev, e->qp.pdn);
		return (w->err = -1);
	}
	if (!e->qp.has_send_cqn || !e->qp.has_recv_cqn) {
		pr_err("uobj DAG: QP lqpn=%u on ibdev=%s (pdn=%u) missing RES_%s_CQN "
		       "(kernel lacks the QP CQ-binding NLDEV attrs); cannot resolve "
		       "the SEND_CQ/RECV_CQ handles RESTORE_QP requires\n",
		       e->qp.lqpn, w->ib->ibdev, e->qp.pdn, e->qp.has_send_cqn ? "RECV" : "SEND");
		return (w->err = -1);
	}

	rdma_uobj_entry__init(&pe);
	pe.ufile_id = uf->uvfe_id;
	pe.hw_driver_id = uf->criu_driver;
	pe.type = R3_UOBJ_TYPE__R3UT_QP;
	pe.has_ufile_handle = true;
	pe.ufile_handle = e->ufile_handle;
	/* QP has no NLDEV restrack id of its own: an xref source, never a target. */

	rdma_qp_attrs__init(&attrs);
	attrs.has_qp_type = true;
	attrs.qp_type = e->qp.qp_type;
	attrs.has_state = true;
	attrs.state = e->qp.qp_state;
	attrs.has_qp_num = true;
	attrs.qp_num = e->qp.lqpn;
	if (e->qp.has_rqpn) {
		attrs.has_dest_qp_num = true;
		attrs.dest_qp_num = e->qp.rqpn;
	}
	if (e->qp.has_sq_psn) {
		attrs.has_sq_psn = true;
		attrs.sq_psn = e->qp.sq_psn;
	}
	if (e->qp.has_rq_psn) {
		attrs.has_rq_psn = true;
		attrs.rq_psn = e->qp.rq_psn;
	}
	if (e->qp.has_port) {
		attrs.has_port_num = true;
		attrs.port_num = e->qp.port;
	}
	pe.qp = &attrs;

	rdma_uobj_xref__init(&xr_pd);
	xr_pd.role = R3_XREF_ROLE__R3XR_PARENT_PD;
	xr_pd.target_type = R3_UOBJ_TYPE__R3UT_PD;
	xr_pd.target_restrack_id = e->qp.pdn;

	rdma_uobj_xref__init(&xr_scq);
	xr_scq.role = R3_XREF_ROLE__R3XR_SEND_CQ;
	xr_scq.target_type = R3_UOBJ_TYPE__R3UT_CQ;
	xr_scq.target_restrack_id = e->qp.send_cqn;

	rdma_uobj_xref__init(&xr_rcq);
	xr_rcq.role = R3_XREF_ROLE__R3XR_RECV_CQ;
	xr_rcq.target_type = R3_UOBJ_TYPE__R3UT_CQ;
	xr_rcq.target_restrack_id = e->qp.recv_cqn;

	xrefs[0] = &xr_pd;
	xrefs[1] = &xr_scq;
	xrefs[2] = &xr_rcq;
	pe.n_xref = 3;
	pe.xref = xrefs;

	if (pb_write_one(w->img, &pe, PB_RDMA_UOBJ) < 0) {
		pr_err("uobj DAG: pb_write_one(rdma_uobj.img) failed for ufile_id=%#x lqpn=%u\n", pe.ufile_id,
		       e->qp.lqpn);
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

	/*
	 * 3. Per-ibdev walk: PDs first (their pdn -> ufile map is the join
	 * key the MR walk resolves parents against), then MRs.
	 */
	list_for_each_entry(ib, &ibdevs, link) {
		struct uobj_walk_ctx w = { .ib = ib, .img = img };
		int pd_emitted, pd_dropped;
		int mr_emitted, mr_dropped;
		int cq_emitted, cq_dropped;
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
		pd_emitted = w.n_emitted;
		pd_dropped = w.n_dropped;
		w.n_emitted = w.n_dropped = 0;

		r = rdma_nl_for_each_resource(ib->dev_index, ib->ibdev, RDMA_NL_RES_MR, uobj_mr_cb, &w);
		if (r < 0 || w.err) {
			pr_err("uobj DAG: mr walk failed on ibdev '%s' (idx=%u): r=%d err=%d\n", ib->ibdev,
			       ib->dev_index, r, w.err);
			goto out;
		}
		mr_emitted = w.n_emitted;
		mr_dropped = w.n_dropped;
		w.n_emitted = w.n_dropped = 0;

		/*
		 * CQs join by ctxn like PDs (no pdn dependency), so ordering
		 * against the MR walk is immaterial; kept after MR to keep the
		 * emit order PD -> MR -> CQ.
		 */
		r = rdma_nl_for_each_resource(ib->dev_index, ib->ibdev, RDMA_NL_RES_CQ, uobj_cq_cb, &w);
		if (r < 0 || w.err) {
			pr_err("uobj DAG: cq walk failed on ibdev '%s' (idx=%u): r=%d err=%d\n", ib->ibdev,
			       ib->dev_index, r, w.err);
			goto out;
		}
		cq_emitted = w.n_emitted;
		cq_dropped = w.n_dropped;
		w.n_emitted = w.n_dropped = 0;

		/*
		 * QPs join by pdn like MRs, so the PD walk must precede them;
		 * their SEND_CQ/RECV_CQ xref targets are CQ entries, but image
		 * order is immaterial (restore topo-sorts via the xref graph),
		 * so the QP walk lands last to keep the emit order
		 * PD -> MR -> CQ -> QP.
		 */
		r = rdma_nl_for_each_resource(ib->dev_index, ib->ibdev, RDMA_NL_RES_QP, uobj_qp_cb, &w);
		if (r < 0 || w.err) {
			pr_err("uobj DAG: qp walk failed on ibdev '%s' (idx=%u): r=%d err=%d\n", ib->ibdev,
			       ib->dev_index, r, w.err);
			goto out;
		}

		pr_info("uobj DAG: ibdev=%s pd(emitted=%d dropped=%d) mr(emitted=%d dropped=%d) "
			"cq(emitted=%d dropped=%d) qp(emitted=%d dropped=%d) (in-tree-ufiles=%zu)\n",
			ib->ibdev, pd_emitted, pd_dropped, mr_emitted, mr_dropped, cq_emitted, cq_dropped,
			w.n_emitted, w.n_dropped, ib->n_ufiles);
	}

	ret = 0;
out:
	if (img)
		close_image(img);
	list_for_each_entry_safe(ib, ib_next, &ibdevs, link) {
		list_del(&ib->link);
		xfree(ib->ufiles);
		xfree(ib->pd_map);
		xfree(ib);
	}
	rdma_drop_dumped_ufiles();
	return ret;
}
