/*
 * R3 dump-side: per-ucontext uobject DAG walker.
 *
 * Runs once at end-of-dump, after every pstree task has been
 * dump_one_task'd (so dump_uverbsfile() in uverbsfd.c has
 * populated rdma_dumped_ufiles with every ufile we just
 * committed to the image). For each in-tree ucontext, asks
 * NLDEV to enumerate its PD/CQ/QP/MR/SRQ uobjects and emits
 * one rdma_uobj_entry per uobject into rdma_uobj.img.
 *
 * Owns:
 *
 *   rdma_dump_uobj_dag()              public via rdma.h
 *   uobj_pd_cb / uobj_cq_cb /
 *   uobj_qp_cb / uobj_mr_cb /
 *   uobj_srq_cb                       per-class NLDEV cbs
 *   rdma_send_query_mr                MR holder-fd ioctl
 *   uobj_ibdev_*                      per-ibdev book-keeping
 *
 * Reads (but does not own) struct rdma_dumped_ufile + the
 * rdma_dumped_ufiles list head, both declared in
 * criu/include/rdma/internal.h. dump_uverbsfile() in
 * uverbsfd.c is the producer; this file is the consumer.
 *
 * Owns the cleanup of per-entry holder_uctx_fd dups (this is
 * the only consumer) and triggers rdma_cdev_vma_recs_free()
 * on the side-table populated by the RDMA-class plugins'
 * CR_PLUGIN_HOOK__PROCESS_DEVICE_VMA hooks.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <rdma/rdma_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_verbs.h>

#include "common/compiler.h"
#include "common/list.h"
#include "image.h"
#include "imgset.h"
#include "int.h"
#include "log.h"
#include "protobuf.h"
#include "rdma.h"
#include "rdma/internal.h"
#include "rdma_netlink.h"
#include "xmalloc.h"

#include "images/rdma_uobj.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "rdma: "

/*
 * R3 dump-side: walk the per-ucontext uobject DAG.
 *
 * Runs once at end-of-dump, after every pstree task has been
 * dump_one_task'd (so dump_uverbsfile() has populated the
 * rdma_dumped_ufiles list with every ufile we just committed to
 * the image). For each in-tree ucontext, asks NLDEV to enumerate
 * its PD/CQ/QP/MR/SRQ uobjects and emits one rdma_uobj_entry per
 * uobject into rdma_uobj.img.
 *
 * S1.b scope: discovery + image emission only. No restore action.
 * Coverage:
 *   * AH                  deferred to S5 (needs K2 LIST_UOBJS).
 *   * comp-channel-fd /
 *     async-event-fd      deferred to S1.c follow-up (NLDEV does
 *                         not enumerate file-typed uobjects;
 *                         discovery is via fdinfo).
 *   * Plugin blob         empty in S1.b; first non-empty blob
 *                         lands at S3 (mlx5 PD restore).
 *
 * Field provenance per resource type is documented inline in
 * images/rdma_uobj.proto. Briefly: PD/CQ have direct CTXN; QP/MR/
 * SRQ get their owning ucontext via PDN-join (the K1 cleanup
 * collapses this to a one-hop filter but isn't required for v0).
 *
 * Failure policy:
 *   * Netlink failure on any per-resource walk -> hard fail.
 *     We've already accepted the cost of pre-suspend coverage's
 *     netlink dump; failing closed here is consistent.
 *   * Image open / write failure -> hard fail.
 *   * An NLDEV uobj whose pdn doesn't map to any in-tree PD ->
 *     silently dropped (kernel resource, or a userspace resource
 *     belonging to a non-snapshot-tree ucontext sharing the
 *     ibdev; coverage check has already proven any in-tree
 *     ucontext is claimable).
 *   * An NLDEV uobj whose direct ctxn doesn't map to any in-tree
 *     ufile -> silently dropped (same reason as above).
 */

/* Per-ibdev book-keeping built up during a uobj DAG dump. */
struct uobj_ibdev {
	char ibdev[64];
	uint32_t dev_index;
	bool has_dev_index;

	/* In-tree ufiles using this ibdev. */
	struct rdma_dumped_ufile **ufiles;
	size_t n_ufiles;

	/* PD inventory: pdn -> ufile (built from PD walk, then read by
	 * the QP/MR/SRQ walks for the PDN-join). */
	struct {
		uint32_t pdn;
		struct rdma_dumped_ufile *uf;
	} *pdn_map;
	size_t n_pdn;
	size_t pdn_cap;

	struct list_head link;
};

/* Cross-walk state shared by the per-resource callbacks. */
struct uobj_walk_ctx {
	struct uobj_ibdev *ib;
	struct cr_img *img;
	int n_emitted;
	int n_dropped;
	int err;
};

static struct uobj_ibdev *uobj_ibdev_find(struct list_head *head,
					  const char *ibdev)
{
	struct uobj_ibdev *ib;

	list_for_each_entry(ib, head, link)
		if (strcmp(ib->ibdev, ibdev) == 0)
			return ib;
	return NULL;
}

static struct uobj_ibdev *uobj_ibdev_get_or_add(struct list_head *head,
						const char *ibdev)
{
	struct uobj_ibdev *ib = uobj_ibdev_find(head, ibdev);

	if (ib)
		return ib;
	ib = xzalloc(sizeof(*ib));
	if (!ib)
		return NULL;
	snprintf(ib->ibdev, sizeof(ib->ibdev), "%.*s",
		 (int)(sizeof(ib->ibdev) - 1), ibdev);
	INIT_LIST_HEAD(&ib->link);
	list_add_tail(&ib->link, head);
	return ib;
}

/* Look up an in-tree ufile on this ibdev by ctxn. */
static struct rdma_dumped_ufile *uobj_ibdev_ufile_by_ctxn(
		const struct uobj_ibdev *ib, uint32_t ctxn)
{
	for (size_t i = 0; i < ib->n_ufiles; i++) {
		struct rdma_dumped_ufile *u = ib->ufiles[i];

		if (u->has_ctxn && u->ctxn == ctxn)
			return u;
	}
	return NULL;
}

static int uobj_ibdev_pdn_add(struct uobj_ibdev *ib, uint32_t pdn,
			      struct rdma_dumped_ufile *uf)
{
	if (ib->n_pdn == ib->pdn_cap) {
		size_t newcap = ib->pdn_cap ? ib->pdn_cap * 2 : 16;
		void *p = xrealloc(ib->pdn_map,
				   newcap * sizeof(*ib->pdn_map));
		if (!p)
			return -1;
		ib->pdn_map = p;
		ib->pdn_cap = newcap;
	}
	ib->pdn_map[ib->n_pdn].pdn = pdn;
	ib->pdn_map[ib->n_pdn].uf = uf;
	ib->n_pdn++;
	return 0;
}

static struct rdma_dumped_ufile *uobj_ibdev_pdn_lookup(
		const struct uobj_ibdev *ib, uint32_t pdn)
{
	for (size_t i = 0; i < ib->n_pdn; i++)
		if (ib->pdn_map[i].pdn == pdn)
			return ib->pdn_map[i].uf;
	return NULL;
}

/*
 * Common emission step: build an RdmaUobjEntry skeleton (ufile_id,
 * hw_driver_id, type, restrack_id, ufile_handle) populated from the
 * join result, leave per-class attrs and xrefs to the caller.
 *
 * ufile_handle is the per-ufile ib_uobject->id NLDEV emits via
 * RDMA_NLDEV_ATTR_RES_HANDLE on kernels carrying upstream commit
 * 0601c496b413 (K8a). On older kernels the flag stays unset and the
 * field is omitted from the image; the restore-side install uses
 * INFO_HANDLES fallbacks (none plumbed yet, see
 * design/uobject_restore.md §7.5.1 -- once the new attr is the
 * minimum, drop the conditional and require it).
 */
static void uobj_entry_init_common(RdmaUobjEntry *e,
				   const struct rdma_dumped_ufile *uf,
				   R3UobjType type,
				   bool has_restrack_id, uint32_t restrack_id,
				   bool has_ufile_handle, uint32_t ufile_handle)
{
	rdma_uobj_entry__init(e);
	e->ufile_id = uf->uvfe_id;
	e->hw_driver_id = uf->criu_driver;
	e->type = type;
	if (has_restrack_id) {
		e->has_restrack_id = true;
		e->restrack_id = restrack_id;
	}
	if (has_ufile_handle) {
		e->has_ufile_handle = true;
		e->ufile_handle = ufile_handle;
	}
}

static int uobj_emit(struct uobj_walk_ctx *w, RdmaUobjEntry *e)
{
	if (pb_write_one(w->img, e, PB_RDMA_UOBJ) < 0) {
		pr_err("rdma_dump_uobj_dag: pb_write_one(rdma_uobj.img) "
		       "failed for ufile_id=%#x type=%u\n",
		       e->ufile_id, e->type);
		return -1;
	}
	w->n_emitted++;
	return 0;
}

/* PD callback: direct CTXN, populate the ibdev's pdn_map for later
 * QP/MR/SRQ joins. */
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
	if (uobj_ibdev_pdn_add(w->ib, e->restrack_id, uf) < 0) {
		w->err = -1;
		return -1;
	}

	uobj_entry_init_common(&pe, uf, R3_UOBJ_TYPE__R3UT_PD,
			       e->has_restrack_id, e->restrack_id,
			       e->has_ufile_handle, e->ufile_handle);
	rdma_pd_attrs__init(&attrs);
	pe.pd = &attrs;

	/*
	 * mlx5-private FW identity. fw_pdn is the value RESTORE_PD's
	 * UHW (mlx5_ib_restore_pd_req.pdn) must ship -- rdma_send_
	 * restore_pd reads pe.fw_pdn at restore. fw_uid is recorded
	 * for image-inspection symmetry and is sourced from the
	 * same TLV; the per-ufile aggregate is captured separately
	 * by the mlx5 plugin's DUMP_UVERBS_CONTEXT hook (which does
	 * its own NLDEV PD walk). Absent on rxe and on pre-
	 * d4acb54ebd3d kernels; restore-side guards that and fails
	 * the dump as un-restorable on a re-dump-required diagnostic.
	 */
	if (e->has_fw_pdn) {
		pe.has_fw_pdn = true;
		pe.fw_pdn = e->fw_pdn;
	}
	if (e->has_fw_uid) {
		pe.has_fw_uid = true;
		pe.fw_uid = e->fw_uid;
	}
	return uobj_emit(w, &pe) < 0 ? (w->err = -1) : 0;
}

/* CQ callback: direct CTXN. */
static int uobj_cq_cb(const struct rdma_nl_res_entry *e, void *arg)
{
	struct uobj_walk_ctx *w = arg;
	struct rdma_dumped_ufile *uf;
	RdmaUobjEntry pe;
	RdmaCqAttrs attrs;

	if (!e->has_ctxn) {
		w->n_dropped++;
		return 0;
	}
	uf = uobj_ibdev_ufile_by_ctxn(w->ib, e->ctxn);
	if (!uf) {
		w->n_dropped++;
		return 0;
	}

	uobj_entry_init_common(&pe, uf, R3_UOBJ_TYPE__R3UT_CQ,
			       e->has_restrack_id, e->restrack_id,
			       e->has_ufile_handle, e->ufile_handle);
	rdma_cq_attrs__init(&attrs);
	attrs.has_cqe_count = true;
	attrs.cqe_count = e->cq.cqe;
	/*
	 * Source-side mmap cookie. Required by post-d3a79140ed26
	 * rxe kernels to honor the dumped vm_pgoff at restore time
	 * (otherwise the pie restorer's mmap of the dumped offset
	 * misses pending_mmaps and bails -EINVAL).
	 *
	 * Pop the next-FIFO cookie out of the process-global side-
	 * table fed by the RDMA-class plugin's
	 * CR_PLUGIN_HOOK__PROCESS_DEVICE_VMA implementation (see
	 * plugins/rdma/rxe/rdma_rxe_plugin.c::rdma_rxe_plugin_process_device_vma).
	 * Absence is not an error -- restore-side falls back to the
	 * kernel's monotonic counter, which only matches if the
	 * source's counter was untouched at dump time.
	 */
	{
		uint64_t mmap_offset;
		if (rdma_pop_cdev_vma_offset(uf->pid, uf->ibdev,
					     &mmap_offset) == 0) {
			attrs.has_mmap_offset = true;
			attrs.mmap_offset = mmap_offset;
		} else {
			pr_warn("uobj DAG: ufile pid=%d ibdev=%s ctxn=%u "
				"has no recorded cdev VMA offset for CQ "
				"restrack_id=%u; restore-side will fall "
				"back to monotonic counter (likely vm_pgoff "
				"mismatch on dest). Did the RDMA plugin "
				"register CR_PLUGIN_HOOK__PROCESS_DEVICE_VMA?\n",
				uf->pid, uf->ibdev, uf->ctxn,
				e->has_restrack_id ? e->restrack_id : 0);
		}
	}
	pe.cq = &attrs;
	return uobj_emit(w, &pe) < 0 ? (w->err = -1) : 0;
}

/*
 * Build a single PARENT_PD xref edge as a one-element repeated
 * field. Helper because QP/MR/SRQ all need exactly this shape.
 */
static void uobj_attach_parent_pd(RdmaUobjEntry *pe, RdmaUobjXref *xref,
				  RdmaUobjXref **xref_arr, uint32_t pdn)
{
	rdma_uobj_xref__init(xref);
	xref->role = R3_XREF_ROLE__R3XR_PARENT_PD;
	xref->target_type = R3_UOBJ_TYPE__R3UT_PD;
	xref->target_restrack_id = pdn;

	xref_arr[0] = xref;
	pe->n_xref = 1;
	pe->xref = xref_arr;
}

/* QP callback: PDN-join, NLDEV-derived qp identity hints. */
static int uobj_qp_cb(const struct rdma_nl_res_entry *e, void *arg)
{
	struct uobj_walk_ctx *w = arg;
	struct rdma_dumped_ufile *uf;
	RdmaUobjEntry pe;
	RdmaQpAttrs attrs;
	RdmaUobjXref xref;
	RdmaUobjXref *xref_arr[1];

	if (!e->has_pdn) {
		w->n_dropped++;
		return 0;
	}
	uf = uobj_ibdev_pdn_lookup(w->ib, e->pdn);
	if (!uf) {
		w->n_dropped++;
		return 0;
	}

	uobj_entry_init_common(&pe, uf, R3_UOBJ_TYPE__R3UT_QP,
			       e->has_restrack_id, e->restrack_id,
			       e->has_ufile_handle, e->ufile_handle);
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

	uobj_attach_parent_pd(&pe, &xref, xref_arr, e->pdn);
	return uobj_emit(w, &pe) < 0 ? (w->err = -1) : 0;
}

/*
 * UAPI lag shim for UVERBS_OBJECT_MR / UVERBS_METHOD_QUERY_MR /
 * UVERBS_ATTR_QUERY_MR_*. Used by the dump-side R3 walk
 * (uobj_mr_cb below) to harvest each MR's wire identity + shape +
 * registration provenance from the kernel.
 *
 * Upstream kernel: include/uapi/rdma/ib_user_ioctl_cmds.h carries
 *   UVERBS_OBJECT_MR                       = 7
 *   UVERBS_METHOD_QUERY_MR                 = 3   (within OBJECT_MR)
 *   UVERBS_ATTR_QUERY_MR_HANDLE            = 0
 *   UVERBS_ATTR_QUERY_MR_RESP_LKEY         = 1
 *   UVERBS_ATTR_QUERY_MR_RESP_RKEY         = 2
 *   UVERBS_ATTR_QUERY_MR_RESP_LENGTH       = 3
 *   UVERBS_ATTR_QUERY_MR_RESP_IOVA         = 4
 *   UVERBS_ATTR_QUERY_MR_RESP_USER_ADDR    = 5  (kernel 35fb92467f68)
 *   UVERBS_ATTR_QUERY_MR_RESP_ACCESS_FLAGS = 6  (kernel 35fb92467f68)
 *
 * Wire-format note: the OBJECT_MR / METHOD_QUERY_MR / four legacy
 * attr ids have been stable upstream since 6c01e6b218ae ("IB/uverbs:
 * Expose UAPI to query MR"). The two USER_ADDR / ACCESS_FLAGS attrs
 * are CRIU-driven additions (35fb92467f68 "RDMA/uverbs: surface
 * user_addr + access_flags via QUERY_MR"); a pre-35fb92 kernel
 * that doesn't recognise these attr_ids will reject the ioctl
 * outright (uverbs treats unknown attr ids as schema mismatch),
 * which uobj_mr_cb surfaces as a fallback to NLDEV-only field
 * capture.
 *
 * Drop the shim once the build's minimum rdma-core ships these
 * symbols upstream.
 */
#ifndef UVERBS_OBJECT_MR
#define UVERBS_OBJECT_MR			7
#endif
#ifndef UVERBS_METHOD_QUERY_MR
#define UVERBS_METHOD_QUERY_MR			3
#endif
#ifndef UVERBS_ATTR_QUERY_MR_HANDLE
#define UVERBS_ATTR_QUERY_MR_HANDLE		0
#endif
#ifndef UVERBS_ATTR_QUERY_MR_RESP_LKEY
#define UVERBS_ATTR_QUERY_MR_RESP_LKEY		1
#endif
#ifndef UVERBS_ATTR_QUERY_MR_RESP_RKEY
#define UVERBS_ATTR_QUERY_MR_RESP_RKEY		2
#endif
#ifndef UVERBS_ATTR_QUERY_MR_RESP_LENGTH
#define UVERBS_ATTR_QUERY_MR_RESP_LENGTH	3
#endif
#ifndef UVERBS_ATTR_QUERY_MR_RESP_IOVA
#define UVERBS_ATTR_QUERY_MR_RESP_IOVA		4
#endif
#ifndef UVERBS_ATTR_QUERY_MR_RESP_USER_ADDR
#define UVERBS_ATTR_QUERY_MR_RESP_USER_ADDR	5
#endif
#ifndef UVERBS_ATTR_QUERY_MR_RESP_ACCESS_FLAGS
#define UVERBS_ATTR_QUERY_MR_RESP_ACCESS_FLAGS	6
#endif

/*
 * Six-OUT reply payload for rdma_send_query_mr. has_<field> is
 * set on a successful ioctl: all six attrs are MANDATORY-from-
 * userspace in our request, so a current kernel writes them all
 * or the ioctl rejects entirely (no partial-write outcome).
 */
struct rdma_query_mr_resp {
	uint32_t lkey;
	uint32_t rkey;
	uint64_t length;
	uint64_t iova;
	uint64_t user_addr;
	uint32_t access_flags;
	bool has_lkey;
	bool has_rkey;
	bool has_length;
	bool has_iova;
	bool has_user_addr;
	bool has_access_flags;
};

/*
 * Issue UVERBS_METHOD_QUERY_MR on @cmd_fd against the holder's
 * ucontext for MR ufile-handle @handle. Used by the dump-side R3
 * walk to harvest the MR's wire identity (lkey, rkey), shape
 * (length, iova), and registration provenance (user VA,
 * access_flags) so the destination's RESTORE_MR can replay them
 * verbatim.
 *
 * @cmd_fd MUST be a dup of the holder's uverbs cdev fd so that
 * the handle resolves in the right ucontext IDR. The per-IDR
 * access check ('this MR belongs to that ucontext') is what pins
 * down the security boundary -- see the commit message of
 * 35fb92467f68 for the rationale, including why this is strictly
 * tighter than NLDEV's CAP_NET_ADMIN gate.
 *
 * Returns 0 on success (with @resp populated); -errno on ioctl
 * failure. -EPROTONOSUPPORT or -EOPNOTSUPP from a kernel that
 * lacks the user_addr/access_flags attrs is the caller's signal
 * to fall back to NLDEV-only field capture.
 */
static int rdma_send_query_mr(int cmd_fd, uint32_t driver_id,
			      uint32_t handle,
			      struct rdma_query_mr_resp *resp)
{
	struct {
		struct ib_uverbs_ioctl_hdr	hdr;
		struct ib_uverbs_attr		attrs[7];
	} cmd = {};
	unsigned int n = 0;

	memset(resp, 0, sizeof(*resp));

	cmd.hdr.object_id = UVERBS_OBJECT_MR;
	cmd.hdr.method_id = UVERBS_METHOD_QUERY_MR;
	/*
	 * QUERY_MR is a generic core uverb (no driver-id-keyed
	 * dispatch on the kernel's UAPI side), but the ioctl
	 * dispatcher still validates @driver_id against the per-
	 * ucontext rdma_driver_id (uverbs_ioctl.c::ib_uverbs_run_
	 * method): a mismatch returns -EINVAL. Pass the destination
	 * ibdev's kernel driver id (RDMA_DRIVER_RXE / _MLX5 / ...)
	 * so the validation succeeds.
	 */
	cmd.hdr.driver_id = driver_id;

	/* HANDLE: IDR(MR_OBJECT) -- attr->data carries the per-ufile handle. */
	cmd.attrs[n].attr_id = UVERBS_ATTR_QUERY_MR_HANDLE;
	cmd.attrs[n].len = 0;
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = handle;
	n++;

	/* Four legacy mandatory OUT attrs (since kernel 6c01e6b218ae). */
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

	/*
	 * Two CRIU-additions (kernel 35fb92467f68). Sent as
	 * F_MANDATORY-from-userspace so uverbs_copy_to actually
	 * writes them on a current kernel. On a pre-35fb92 kernel
	 * the ioctl rejects with -EPROTONOSUPPORT and uobj_mr_cb
	 * falls back to NLDEV-only emission.
	 */
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

	if (ioctl(cmd_fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;

	resp->has_lkey = true;
	resp->has_rkey = true;
	resp->has_length = true;
	resp->has_iova = true;
	resp->has_user_addr = true;
	resp->has_access_flags = true;
	return 0;
}

/*
 * MR callback: PDN-join + per-MR QUERY_MR ioctl on the holder's
 * stashed uverbsfd to harvest the full RESTORE_MR feed (lkey/rkey
 * identity, shape (length, iova), and registration provenance
 * (user_addr, access_flags)).
 *
 * QUERY_MR is the canonical source of all five fields on a current
 * kernel (35fb92467f68 + 6c01e6b218ae). NLDEV's RES_MR_GET supplies
 * the same lkey/rkey/length/iova subset gated by CAP_NET_ADMIN, but
 * not user_addr or access_flags -- those live on the new
 * core-owned struct ib_mr fields and are exposed exclusively
 * through the per-ucontext-IDR-gated uverbs ioctl path. Using
 * QUERY_MR for the entire field set (rather than NLDEV for some +
 * QUERY_MR for the rest) keeps a single source of truth and avoids
 * NLDEV-vs-uverbs skew when the MR was just rereg'd or when the
 * dump straddles a state transition.
 *
 * Ufile-handle source: NLDEV K8a (RDMA_NLDEV_ATTR_RES_HANDLE),
 * which is the same per-ufile id userspace and the kernel's QUERY_
 * MR IDR resolver agree on. Without K8a we cannot issue QUERY_MR
 * (no handle to feed it), so the entry is skipped.
 *
 * Fallback: if QUERY_MR fails (kernel pre-35fb92467f68, or the
 * stashed fd dup wasn't captured), we still emit the entry with
 * NLDEV-only fields. Restore-side rdma_send_restore_mr will then
 * fail loudly on the missing user_addr/access_flags rather than
 * silently registering the MR with sentinel values.
 */
static int uobj_mr_cb(const struct rdma_nl_res_entry *e, void *arg)
{
	struct uobj_walk_ctx *w = arg;
	struct rdma_dumped_ufile *uf;
	RdmaUobjEntry pe;
	RdmaMrAttrs attrs;
	RdmaUobjXref xref;
	RdmaUobjXref *xref_arr[1];
	struct rdma_query_mr_resp qresp = {};
	bool query_ok = false;

	if (!e->has_pdn) {
		w->n_dropped++;
		return 0;
	}
	uf = uobj_ibdev_pdn_lookup(w->ib, e->pdn);
	if (!uf) {
		w->n_dropped++;
		return 0;
	}

	uobj_entry_init_common(&pe, uf, R3_UOBJ_TYPE__R3UT_MR,
			       e->has_restrack_id, e->restrack_id,
			       e->has_ufile_handle, e->ufile_handle);
	rdma_mr_attrs__init(&attrs);

	/*
	 * Try QUERY_MR first when both the per-MR ufile_handle (K8a)
	 * and the per-ufile holder fd dup are present. On a current
	 * kernel this populates all five hw-agnostic fields plus the
	 * new user_addr / access_flags pair in a single ioctl.
	 */
	if (e->has_ufile_handle && uf->holder_uctx_fd >= 0) {
		int rc = rdma_send_query_mr(uf->holder_uctx_fd,
					    uf->kernel_driver_id,
					    e->ufile_handle, &qresp);
		if (rc) {
			pr_warn("uobj DAG: QUERY_MR(handle=%u) on "
				"ibdev=%s ufile_id=%#x failed: %d (%s) "
				"-- falling back to NLDEV-only fields, "
				"user_addr/access_flags will be absent "
				"and RESTORE_MR will refuse this entry "
				"(kernel needs 35fb92467f68 'RDMA/uverbs: "
				"surface user_addr + access_flags via "
				"QUERY_MR')\n",
				e->ufile_handle, uf->ibdev, uf->uvfe_id,
				rc, strerror(-rc));
		} else {
			query_ok = true;
		}
	} else if (!e->has_ufile_handle) {
		pr_debug("uobj DAG: MR pdn=%u on ibdev=%s has no "
			 "ufile_handle (kernel pre-K8a / RES_HANDLE not "
			 "emitted); skipping QUERY_MR, NLDEV-only "
			 "emission\n", e->pdn, uf->ibdev);
	} else {
		pr_warn("uobj DAG: MR pdn=%u on ibdev=%s ufile_id=%#x "
			"has no holder_uctx_fd dup; QUERY_MR skipped\n",
			e->pdn, uf->ibdev, uf->uvfe_id);
	}

	if (query_ok) {
		/* QUERY_MR is the canonical feed when available. */
		attrs.has_lkey = true;
		attrs.lkey = qresp.lkey;
		attrs.has_rkey = true;
		attrs.rkey = qresp.rkey;
		attrs.has_length = true;
		attrs.length = qresp.length;
		attrs.has_iova = true;
		attrs.iova = qresp.iova;
		attrs.has_virt_addr = true;
		attrs.virt_addr = qresp.user_addr;
		attrs.has_access_flags = true;
		attrs.access_flags = qresp.access_flags;
	} else {
		/*
		 * NLDEV-only fallback. lkey/rkey require CAP_NET_ADMIN
		 * upstream; CRIU runs as root, so they're populated in
		 * practice. virt_addr / access_flags stay unset --
		 * restore-side will refuse such an entry with a clear
		 * "needs QUERY_MR re-dump" message.
		 */
		attrs.has_length = true;
		attrs.length = e->mr.mrlen;
		if (e->mr.has_lkey) {
			attrs.has_lkey = true;
			attrs.lkey = e->mr.lkey;
		}
		if (e->mr.has_rkey) {
			attrs.has_rkey = true;
			attrs.rkey = e->mr.rkey;
		}
		if (e->mr.has_iova) {
			attrs.has_iova = true;
			attrs.iova = e->mr.iova;
		}
	}

	pe.mr = &attrs;

	uobj_attach_parent_pd(&pe, &xref, xref_arr, e->pdn);
	return uobj_emit(w, &pe) < 0 ? (w->err = -1) : 0;
}

/*
 * SRQ callback: PDN-join, plus an optional CQN xref for XRC SRQs
 * (the only SRQ flavour where the kernel emits RES_CQN today, per
 * fill_res_srq_entry's ib_srq_has_cq() gate). The CQN xref's
 * target_restrack_id is the CQ's restrack id, which the CQ walk
 * has already emitted for any in-tree CQ -- a restore-side reader
 * can join on it.
 */
static int uobj_srq_cb(const struct rdma_nl_res_entry *e, void *arg)
{
	struct uobj_walk_ctx *w = arg;
	struct rdma_dumped_ufile *uf;
	RdmaUobjEntry pe;
	RdmaSrqAttrs attrs;
	RdmaUobjXref xrefs[2];
	RdmaUobjXref *xref_arr[2];
	int n = 0;

	if (!e->has_pdn) {
		w->n_dropped++;
		return 0;
	}
	uf = uobj_ibdev_pdn_lookup(w->ib, e->pdn);
	if (!uf) {
		w->n_dropped++;
		return 0;
	}

	uobj_entry_init_common(&pe, uf, R3_UOBJ_TYPE__R3UT_SRQ,
			       e->has_restrack_id, e->restrack_id,
			       e->has_ufile_handle, e->ufile_handle);
	rdma_srq_attrs__init(&attrs);
	attrs.has_srq_type = true;
	attrs.srq_type = e->srq.srq_type;
	pe.srq = &attrs;

	rdma_uobj_xref__init(&xrefs[n]);
	xrefs[n].role = R3_XREF_ROLE__R3XR_PARENT_PD;
	xrefs[n].target_type = R3_UOBJ_TYPE__R3UT_PD;
	xrefs[n].target_restrack_id = e->pdn;
	xref_arr[n] = &xrefs[n];
	n++;

	if (e->srq.has_cqn) {
		rdma_uobj_xref__init(&xrefs[n]);
		/*
		 * Reuse SEND_CQ as the SRQ-CQ binding role. SRQ has
		 * exactly one CQ when it has any (XRC), so a dedicated
		 * R3XR_SRQ_CQ enumerant would carry no information
		 * SEND_CQ doesn't already carry; keeping the role set
		 * tight avoids adding values whose only purpose is
		 * shape-of-edge documentation.
		 */
		xrefs[n].role = R3_XREF_ROLE__R3XR_SEND_CQ;
		xrefs[n].target_type = R3_UOBJ_TYPE__R3UT_CQ;
		xrefs[n].target_restrack_id = e->srq.cqn;
		xref_arr[n] = &xrefs[n];
		n++;
	}

	pe.n_xref = n;
	pe.xref = xref_arr;
	return uobj_emit(w, &pe) < 0 ? (w->err = -1) : 0;
}

/*
 * dev_index resolver. We have ibdev names from dump_uverbsfile but
 * NLDEV per-resource walks need dev_index. Run a one-shot ibdev
 * enumeration and patch the dev_index into matching entries on the
 * per-ibdev list.
 */
struct devidx_resolver {
	struct list_head *ibdevs;
};

static int devidx_resolver_cb(uint32_t dev_index, const char *ibdev,
			      void *arg)
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
	LIST_HEAD(ibdevs);
	struct cr_img *img = NULL;
	int ret = -1;

	if (list_empty(&rdma_dumped_ufiles)) {
		pr_debug("uobj DAG: no in-tree uverbs contexts dumped, "
			 "skipping per-uobject discovery\n");
		return 0;
	}

	/*
	 * 1. Group dumped ufiles by ibdev. Each per-ibdev bucket
	 * carries the in-tree ufile list + (later) a pdn_map built
	 * from the PD walk.
	 */
	list_for_each_entry(uf, &rdma_dumped_ufiles, link) {
		void *p;
		ib = uobj_ibdev_get_or_add(&ibdevs, uf->ibdev);
		if (!ib)
			goto out;
		p = xrealloc(ib->ufiles,
			     (ib->n_ufiles + 1) * sizeof(*ib->ufiles));
		if (!p)
			goto out;
		ib->ufiles = p;
		ib->ufiles[ib->n_ufiles++] = uf;
	}

	/*
	 * 2. Resolve dev_index per ibdev (NLDEV per-resource walks
	 * need dev_index, not name).
	 */
	{
		struct devidx_resolver r = { .ibdevs = &ibdevs };
		if (rdma_nl_for_each_ibdev(devidx_resolver_cb, &r) < 0) {
			pr_err("uobj DAG: ibdev enumeration failed\n");
			goto out;
		}
	}

	/*
	 * 3. Open the image. Only do so once we know we have at
	 * least one ibdev to walk -- skipping the open-then-close
	 * dance saves an empty rdma_uobj.img landing on disk for
	 * dump trees with zero RDMA contexts (already guarded by
	 * the list_empty check, but defence in depth).
	 */
	img = open_image_at(AT_FDCWD, CR_FD_RDMA_UOBJ, O_DUMP);
	if (!img) {
		pr_err("uobj DAG: open_image(rdma-uobj, O_DUMP) failed\n");
		goto out;
	}

	/*
	 * 4. Per-ibdev: PD first (populates pdn_map), then CQ
	 * (direct ctxn), then QP/MR/SRQ (PDN-join through the just-
	 * built pdn_map). Order matters only for the PDN-join
	 * dependency; CQ could equally well run before or after PD.
	 */
	list_for_each_entry(ib, &ibdevs, link) {
		struct uobj_walk_ctx w = { .ib = ib, .img = img };
		static const struct {
			enum rdma_nl_res_type t;
			rdma_nl_res_cb_t cb;
			const char *name;
		} stages[] = {
			{ RDMA_NL_RES_PD,  uobj_pd_cb,  "pd"  },
			{ RDMA_NL_RES_CQ,  uobj_cq_cb,  "cq"  },
			{ RDMA_NL_RES_QP,  uobj_qp_cb,  "qp"  },
			{ RDMA_NL_RES_MR,  uobj_mr_cb,  "mr"  },
			{ RDMA_NL_RES_SRQ, uobj_srq_cb, "srq" },
		};

		if (!ib->has_dev_index) {
			pr_err("uobj DAG: ibdev '%s' had no dev_index "
			       "(disappeared between dump and uobj walk?); "
			       "aborting\n", ib->ibdev);
			goto out;
		}

		for (size_t i = 0; i < ARRAY_SIZE(stages); i++) {
			int r = rdma_nl_for_each_resource(ib->dev_index,
							  ib->ibdev,
							  stages[i].t,
							  stages[i].cb, &w);
			if (r < 0 || w.err) {
				pr_err("uobj DAG: %s walk failed on ibdev "
				       "'%s' (idx=%u): r=%d err=%d\n",
				       stages[i].name, ib->ibdev,
				       ib->dev_index, r, w.err);
				goto out;
			}
		}

		pr_info("uobj DAG: ibdev=%s emitted=%d dropped=%d "
			"(in-tree-ufiles=%zu pdn-map=%zu)\n",
			ib->ibdev, w.n_emitted, w.n_dropped,
			ib->n_ufiles, ib->n_pdn);
	}

	ret = 0;
out:
	if (img)
		close_image(img);
	list_for_each_entry_safe(ib, ib_next, &ibdevs, link) {
		list_del(&ib->link);
		xfree(ib->ufiles);
		xfree(ib->pdn_map);
		xfree(ib);
	}
	/*
	 * Drop the holder uverbsfd dups stashed by dump_uverbsfile. The
	 * walk above is the only consumer; from this point on the holder
	 * is being killed and the ucontext is gone anyway. Skipping
	 * close() here would just leak fds into criu's own image-write
	 * phase, which makes file-leak detectors angry on long-running
	 * dumps.
	 */
	{
		struct rdma_dumped_ufile *uf2;
		list_for_each_entry(uf2, &rdma_dumped_ufiles, link) {
			if (uf2->holder_uctx_fd >= 0) {
				close(uf2->holder_uctx_fd);
				uf2->holder_uctx_fd = -1;
			}
		}
	}
	/*
	 * Free the process-global cdev VMA side-table populated by
	 * RDMA-class plugins' CR_PLUGIN_HOOK__PROCESS_DEVICE_VMA
	 * hooks. Entries were consumed (rdma_pop_cdev_vma_offset
	 * marked each "consumed = true" once it was serialised into
	 * a per-CQ RdmaCqAttrs.mmap_offset); we drop everything
	 * unconditionally so a long-running criu service process
	 * doesn't carry stale entries into its next dump cycle.
	 */
	rdma_cdev_vma_recs_free();
	return ret;
}
