#include <dlfcn.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <rdma/rdma_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_verbs.h>

#include "common/compiler.h"
#include "common/list.h"
#include "imgset.h"
#include "image.h"
#include "files.h"
#include "files-reg.h"
#include "int.h"
#include "log.h"
#include "plugin.h"
#include "protobuf.h"
#include "pstree.h"
#include "rdma.h"
#include "rdma/internal.h"
#include "rdma_netlink.h"
#include "fdinfo.h"
#include "restorer.h"
#include "rst-malloc.h"
#include "xmalloc.h"

#include "images/fdinfo.pb-c.h"
#include "images/rdma_criu.pb-c.h"
#include "images/rdma_uobj.pb-c.h"
#include "images/uverbsfd.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "rdma: "

/*
 * uverbs cdev fd dump/restore, async-event evfd dump/restore,
 * and the plugin-claim arbitration + dispatch helpers shared
 * with the pre-suspend coverage path have moved to
 * criu/rdma/uverbsfd.c. The shared rdma_dumped_ufiles list +
 * struct rdma_dumped_ufile definition live in
 * criu/include/rdma/internal.h so the R3 dump-side DAG walker
 * (rdma_dump_uobj_dag, still in this file) can read the list.
 */

/* Pre-suspend coverage + cross-tree exclusivity checks have
 * moved to criu/rdma/precheck.c. The two public entry points
 * (rdma_check_dump_coverage, rdma_check_cross_tree_exclusivity)
 * remain declared in criu/include/rdma.h; the rest of the
 * implementation -- including the dump_cov_ctx and
 * cross_tree_collect_ctx walk-state structs -- now lives over
 * there.
 */

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

/*
 * R3 restore-side: read+verify pass on rdma-uobj.img.
 *
 * S1.c. Validates that what dump_uobj_dag wrote is internally
 * consistent: every xref edge resolves within its ufile group, and
 * (ufile_id, type, restrack_id) tuples are unique. No restore
 * action; per-uobject restore handlers land incrementally in S2+.
 */
struct uobj_collected {
	RdmaUobjEntry *e;
	struct list_head link;	/* link in uobj_ufile_group.entries */
};

struct uobj_ufile_group {
	uint32_t ufile_id;
	uint32_t hw_driver_id;	/* taken from first entry; verified equal */
	struct list_head entries;
	int n_pd, n_cq, n_qp, n_mr, n_srq, n_ah, n_cc, n_aef, n_other;
	int n_xref_total;
	int n_xref_resolved;
	int n_with_handle;	/* entries with has_ufile_handle set */
	int n_total;		/* total entries in this group */
	struct list_head link;
};

/*
 * The DAG built by rdma_collect_uobj_dag() (early in restore, before
 * file restore) and consumed by rdma_restore_uobj_dag_for_ufile()
 * (per cdev fd, called from uverbsfd_open() after the plugin hands
 * back the open fd). Lives for the rest of the restore; free is at
 * process exit so we deliberately don't have a release entry point.
 *
 * Local LIST_HEAD() inside rdma_collect_uobj_dag() would have been
 * nicer but the consumer phase is in a different translation unit's
 * call chain.
 */
static LIST_HEAD(rdma_uobj_groups);

static struct uobj_ufile_group *
rdma_uobj_group_lookup(uint32_t ufile_id)
{
	struct uobj_ufile_group *g;

	list_for_each_entry(g, &rdma_uobj_groups, link)
		if (g->ufile_id == ufile_id)
			return g;
	return NULL;
}

static struct uobj_ufile_group *uobj_ufile_group_get_or_add(
		struct list_head *head, uint32_t ufile_id, uint32_t hw_driver_id)
{
	struct uobj_ufile_group *g;

	list_for_each_entry(g, head, link)
		if (g->ufile_id == ufile_id) {
			if (g->hw_driver_id != hw_driver_id) {
				pr_err("uobj DAG: ufile_id=%#x has entries "
				       "claiming both hw_driver=%u and "
				       "hw_driver=%u; image is inconsistent\n",
				       ufile_id, g->hw_driver_id, hw_driver_id);
				return NULL;
			}
			return g;
		}
	g = xzalloc(sizeof(*g));
	if (!g)
		return NULL;
	g->ufile_id = ufile_id;
	g->hw_driver_id = hw_driver_id;
	INIT_LIST_HEAD(&g->entries);
	INIT_LIST_HEAD(&g->link);
	list_add_tail(&g->link, head);
	return g;
}

static void uobj_ufile_group_count(struct uobj_ufile_group *g,
				   R3UobjType type)
{
	switch (type) {
	case R3_UOBJ_TYPE__R3UT_PD:	g->n_pd++;	break;
	case R3_UOBJ_TYPE__R3UT_CQ:	g->n_cq++;	break;
	case R3_UOBJ_TYPE__R3UT_QP:	g->n_qp++;	break;
	case R3_UOBJ_TYPE__R3UT_MR:	g->n_mr++;	break;
	case R3_UOBJ_TYPE__R3UT_SRQ:	g->n_srq++;	break;
	case R3_UOBJ_TYPE__R3UT_AH:	g->n_ah++;	break;
	case R3_UOBJ_TYPE__R3UT_COMP_CHANNEL_FILE:
					g->n_cc++;	break;
	case R3_UOBJ_TYPE__R3UT_ASYNC_EVENT_FILE:
					g->n_aef++;	break;
	default:			g->n_other++;	break;
	}
}

/*
 * Find an entry by (type, restrack_id) within @g. Used to resolve
 * xref edges. Returns the entry pointer, or NULL if not found or
 * if the candidate has no restrack_id (matches against
 * has_restrack_id false should not resolve).
 */
static const RdmaUobjEntry *uobj_ufile_group_find(
		const struct uobj_ufile_group *g,
		R3UobjType target_type, uint32_t target_restrack_id)
{
	struct uobj_collected *c;

	list_for_each_entry(c, &g->entries, link) {
		const RdmaUobjEntry *e = c->e;

		if (!e->has_restrack_id)
			continue;
		if (e->type != target_type)
			continue;
		if (e->restrack_id != target_restrack_id)
			continue;
		return e;
	}
	return NULL;
}

/*
 * Per-group dedup check: (type, restrack_id) must be unique. So
 * must ufile_handle within the same ufile (it's the kernel's
 * ufile->uobjects xarray index -- unique by construction across
 * every uobject class). Returns -1 on duplicate. O(n^2) but
 * uobject counts per ufile are O(10s), not O(thousands), so the
 * simple sweep beats setting up a hash for the size we actually
 * see.
 */
static int uobj_ufile_group_check_unique(const struct uobj_ufile_group *g)
{
	struct uobj_collected *ci, *cj;

	list_for_each_entry(ci, &g->entries, link) {
		const RdmaUobjEntry *ei = ci->e;

		for (cj = list_entry(ci->link.next, struct uobj_collected, link);
		     &cj->link != &g->entries;
		     cj = list_entry(cj->link.next, struct uobj_collected, link)) {
			const RdmaUobjEntry *ej = cj->e;

			if (ei->has_restrack_id && ej->has_restrack_id &&
			    ei->type == ej->type &&
			    ei->restrack_id == ej->restrack_id) {
				pr_err("uobj DAG: ufile_id=%#x has duplicate "
				       "(type=%u, restrack_id=%u) entries; "
				       "image is inconsistent\n",
				       g->ufile_id, ei->type, ei->restrack_id);
				return -1;
			}
			/*
			 * ufile_handle uniqueness is cross-type within one
			 * ufile because the kernel's ufile->uobjects xarray
			 * is keyed by ib_uobject->id only (the type isn't
			 * part of the key). A duplicate here means the
			 * dump-side join logic merged two NLDEV walks
			 * incorrectly, the kernel emitted a stale id, or
			 * the image was hand-edited. Bail.
			 */
			if (ei->has_ufile_handle && ej->has_ufile_handle &&
			    ei->ufile_handle == ej->ufile_handle) {
				pr_err("uobj DAG: ufile_id=%#x has duplicate "
				       "ufile_handle=%u across types %u and %u; "
				       "image is inconsistent (ufile->uobjects "
				       "ids are unique per ufile by construction)"
				       "\n",
				       g->ufile_id, ei->ufile_handle,
				       ei->type, ej->type);
				return -1;
			}
		}
	}
	return 0;
}

static int uobj_ufile_group_check_xrefs(struct uobj_ufile_group *g)
{
	struct uobj_collected *c;

	list_for_each_entry(c, &g->entries, link) {
		const RdmaUobjEntry *e = c->e;

		for (size_t k = 0; k < e->n_xref; k++) {
			const RdmaUobjXref *xr = e->xref[k];

			g->n_xref_total++;
			if (uobj_ufile_group_find(g, xr->target_type,
						  xr->target_restrack_id)) {
				g->n_xref_resolved++;
				continue;
			}
			pr_err("uobj DAG: ufile_id=%#x entry "
			       "(type=%u, restrack_id=%s%u) has unresolvable "
			       "xref role=%u target_type=%u "
			       "target_restrack_id=%u\n",
			       g->ufile_id, e->type,
			       e->has_restrack_id ? "" : "?",
			       e->has_restrack_id ? e->restrack_id : 0,
			       xr->role, xr->target_type,
			       xr->target_restrack_id);
			return -1;
		}
	}
	return 0;
}

/*
 * UAPI lag shim for UVERBS_OBJECT_RESTORE / UVERBS_METHOD_RESTORE_PD /
 * UVERBS_ATTR_RESTORE_PD_HANDLE.
 *
 * Upstream kernel: include/uapi/rdma/ib_user_ioctl_cmds.h carries
 *   UVERBS_OBJECT_RESTORE       = 18
 *   UVERBS_METHOD_RESTORE_PD    = 0    (within OBJECT_RESTORE)
 *   UVERBS_ATTR_RESTORE_PD_HANDLE = 0  (within METHOD_RESTORE_PD)
 *
 * At wire time the kernel matches by integer, never by enumerator
 * name, so a stable numeric copy here is sufficient to talk to a
 * kernel that has the support, and a fresh-enough kernel is the
 * gate on the operation succeeding (it'll return -EOPNOTSUPP if
 * the dispatch table doesn't know the object_id, which is the
 * already-handled "kernel too old" signal).
 *
 * The mlx5_vfmig plugin uses the same self-contained-numeric pattern
 * for its own per-driver verbs (MLX5_IB_OBJECT_VFMIG_LOCAL etc).
 *
 * Drop the shim once the build's minimum rdma-core ships these
 * symbols upstream.
 */
#ifndef UVERBS_OBJECT_RESTORE
#define UVERBS_OBJECT_RESTORE			18
#endif
#ifndef UVERBS_METHOD_RESTORE_PD
#define UVERBS_METHOD_RESTORE_PD		0
#endif
#ifndef UVERBS_ATTR_RESTORE_PD_HANDLE
#define UVERBS_ATTR_RESTORE_PD_HANDLE		0
#endif

/*
 * UVERBS_METHOD_RESTORE_CQ is the third concrete method in the
 * UVERBS_OBJECT_RESTORE namespace (after RESTORE_PD = 0 and
 * RESTORE_MR = 1), landed by kernel commit a77cc4d8e8b9
 * "RDMA/uverbs: Add RESTORE_CQ + rxe impl". The dispatcher
 * reserves the target ufile handle, pre-allocates struct ib_cq +
 * its embedding ib_ucq_object, sets cq->{device,uobject,
 * comp_handler,event_handler,cq_context=NULL,usecnt=0}, and
 * delegates to ib_device_ops.restore_cq for the hw-side install.
 *
 * Eight attributes (mirrors enum uverbs_attrs_restore_cq in
 * include/uapi/rdma/ib_user_ioctl_cmds.h):
 *   _HANDLE       (PTR_IN u32)  target ufile handle
 *   _CQE          (PTR_IN u32)  source-requested cq depth
 *   _USER_HANDLE  (PTR_IN u64)  source-time cq_context tag
 *   _COMP_VECTOR  (PTR_IN u32)  source comp_vector
 *   _FLAGS        (FLAGS_IN)    optional ib_uverbs_ex_create_cq_flags
 *   _COMP_CHANNEL (FD optional) v0 dispatcher rejects -EOPNOTSUPP
 *                               if any caller passes one
 *   _EVENT_FD     (FD optional) absent -> ufile->default_async_file
 *   _RESP_CQE     (PTR_OUT u32) actual installed cqe count
 *   plus UVERBS_ATTR_UHW for driver-private payload.
 *
 * v0 CRIU policy:
 *   - never pass COMP_CHANNEL: the source-side comp_channel uobject
 *     is not yet restorable (UVERBS_METHOD_RESTORE_COMP_CHANNEL is
 *     a future S5c verb). Workloads that use a comp_channel are
 *     out of scope.
 *   - never pass EVENT_FD: the kernel falls back to the ufile's
 *     default_async_file, which is the same async-event endpoint
 *     CRIU's restored ucontext provides via the existing
 *     ASYNC_EVENT_FD plumbing in the plugin.
 *   - USER_HANDLE is currently always 0 -- NLDEV doesn't expose
 *     the source's cq_context tag, and the holders/workloads CRIU
 *     covers in v0 (rxe holder, ib_write_bw) all pass NULL for
 *     ibv_create_cq's cq_context arg. Non-zero cq_context isn't
 *     preserved across restore in v0; documented as a known v0
 *     wire-format gap (see rdma_uobj.proto::rdma_cq_attrs).
 *
 * Drop the shim once the build's minimum rdma-core ships these
 * symbols upstream.
 */
#ifndef UVERBS_METHOD_RESTORE_CQ
#define UVERBS_METHOD_RESTORE_CQ		2
#endif
#ifndef UVERBS_ATTR_RESTORE_CQ_HANDLE
#define UVERBS_ATTR_RESTORE_CQ_HANDLE		0
#endif
#ifndef UVERBS_ATTR_RESTORE_CQ_CQE
#define UVERBS_ATTR_RESTORE_CQ_CQE		1
#endif
#ifndef UVERBS_ATTR_RESTORE_CQ_USER_HANDLE
#define UVERBS_ATTR_RESTORE_CQ_USER_HANDLE	2
#endif
#ifndef UVERBS_ATTR_RESTORE_CQ_COMP_VECTOR
#define UVERBS_ATTR_RESTORE_CQ_COMP_VECTOR	3
#endif
#ifndef UVERBS_ATTR_RESTORE_CQ_FLAGS
#define UVERBS_ATTR_RESTORE_CQ_FLAGS		4
#endif
#ifndef UVERBS_ATTR_RESTORE_CQ_COMP_CHANNEL
#define UVERBS_ATTR_RESTORE_CQ_COMP_CHANNEL	5
#endif
#ifndef UVERBS_ATTR_RESTORE_CQ_EVENT_FD
#define UVERBS_ATTR_RESTORE_CQ_EVENT_FD		6
#endif
#ifndef UVERBS_ATTR_RESTORE_CQ_RESP_CQE
#define UVERBS_ATTR_RESTORE_CQ_RESP_CQE		7
#endif

/*
 * UHW is the generic driver-private blob attribute. attr_id 4096
 * (== UVERBS_ID_DRIVER_NS = 1 << UVERBS_ID_NS_SHIFT) is the kernel's
 * namespace boundary that splits core attrs from driver attrs.
 * Defined in include/uapi/rdma/ib_user_ioctl_cmds.h.
 *
 * UHW_IN  carries driver-private input (mlx5 RESTORE_PD's pdn,
 *         future RESTORE_<TYPE> driver payloads).
 * UHW_OUT carries driver-private output. rxe's restore_cq /
 *         restore_qp / restore_srq write a mminfo (mmap cookie +
 *         size) here so userspace can mmap the in-kernel queue;
 *         see drivers/infiniband/sw/rxe/rxe_verbs.c::rxe_restore_cq.
 */
#ifndef UVERBS_ATTR_UHW_IN
#define UVERBS_ATTR_UHW_IN			((uint16_t)4096)
#endif
#ifndef UVERBS_ATTR_UHW_OUT
#define UVERBS_ATTR_UHW_OUT			((uint16_t)4097)
#endif

/*
 * struct rxe_create_cq_resp -- driver-private UHW_OUT payload that
 * rxe_restore_cq writes (mirror of ibv_cmd_create_cq's resp shape).
 * Source-of-truth: include/uapi/rdma/rdma_user_rxe.h
 *   struct rxe_create_cq_resp { struct mminfo mi; };
 *   struct mminfo { __aligned_u64 offset; __u32 size; __u32 pad; };
 *
 * We don't dereference @offset / @size at v0 (the restore-side
 * mmap remap is the next slice -- kernel needs to either preserve
 * the source vm_pgoff or provide a way for the rxe plugin's
 * UPDATE_VMA_MAP to translate source -> dest pgoff). What we need
 * here is a response buffer sized to the kernel's expectation
 * (sizeof(struct rxe_create_cq_resp) == 16): without an
 * UHW_OUT attr of that size, rxe_restore_cq returns -EINVAL on
 * the (udata->outlen < sizeof(*uresp)) check before any of the
 * actual restore work runs.
 */
struct rxe_create_cq_resp_local {
	uint64_t	mi_offset;	/* mmap cookie (vm_pgoff << PAGE_SHIFT) */
	uint32_t	mi_size;	/* mmap region size, bytes */
	uint32_t	mi_pad;
};

/*
 * struct rxe_restore_cq_req -- driver-private UHW_IN payload for
 * rxe_restore_cq's "honor source vm_pgoff" mode (linux kernel
 * commit d3a79140ed26 + the inline-attr-trap fix that grew the
 * struct above 8 bytes).
 *
 * Source-of-truth: include/uapi/rdma/rdma_user_rxe.h
 *   struct rxe_restore_cq_req {
 *       __aligned_u64 vm_pgoff;
 *       __aligned_u64 reserved;
 *   };
 *
 * Despite the name, the field is a *byte* offset matching the
 * source-side rxe_create_cq_resp::mi.offset (which the kernel
 * compares against vma->vm_pgoff << PAGE_SHIFT in rxe_mmap). When
 * non-zero the kernel binds the new CQ's mmap region at exactly
 * this offset; -EEXIST on collision; on success the UHW_OUT
 * mi.offset returned to userspace equals this value verbatim.
 *
 * @reserved must be zero on send (kernel rejects -EINVAL otherwise
 * for forward-compat). Its sole purpose is making the struct
 * strictly larger than sizeof(__u64) so the uverbs ioctl bundle
 * takes the pointer (not inline-attr) path through
 * uverbs_fill_udata: with len <= 8 the dispatcher reuses
 * &user_attrs[i].data as inbuf, and ib_copy_from_udata then reads
 * the literal pointer-shaped value CRIU put in attr.data instead
 * of the buffer it points at. See the matching size note in
 * include/uapi/rdma/rdma_user_rxe.h. Same trap, same mitigation
 * as struct mlx5_ib_restore_pd_req_local below.
 *
 * Sent only when we have a captured source offset (RdmaCqAttrs::
 * mmap_offset present in the image). Absent UHW_IN -> kernel
 * falls back to the monotonic counter (legal, but typically
 * misses the dumped vm_pgoff -- the failure mode that motivated
 * this whole UHW_IN dance).
 */
struct rxe_restore_cq_req_local {
	uint64_t	vm_pgoff;
	uint64_t	reserved;
};

/*
 * UAPI lag shim for include/uapi/rdma/mlx5-abi.h's
 * struct mlx5_ib_restore_pd_req. Driver-private UHW payload for
 * UVERBS_METHOD_RESTORE_PD on mlx5; carries the source's FW pdn so
 * mlx5_ib_restore_pd can adopt it into a fresh kernel-side mlx5_ib_pd
 * via "Model A" (no destination FW round-trip; the source pdn is
 * already reserved in firmware after LOAD_VHCA_STATE). The
 * (independent) ufile target handle still travels in the core
 * UVERBS_ATTR_RESTORE_PD_HANDLE attribute.
 *
 * Layout details that matter for wire correctness:
 *   - sizeof > sizeof(u64) is intentional. The uverbs UHW dispatch
 *     path treats len <= sizeof(u64) as INLINE (stuffs attr->data
 *     into a kernel staging slot and rewrites udata->inbuf to a
 *     kernel pointer), which on x86_64 with masked-user-access
 *     support breaks ib_copy_from_udata's copy_from_user. Sizing
 *     above the threshold (12 + 8 = 24 with __aligned_u64 padding;
 *     here 16 with explicit __aligned_u64) takes the ptr path and
 *     ib_copy_from_udata works as expected. We pass by pointer in
 *     attr->data, matching what pd_restore_probe_mlx5_vfmig does.
 *   - reserved/reserved2 must be zero on send. Kernel-side
 *     mlx5_ib_restore_pd validates this for forward-compat
 *     (returns -EINVAL otherwise).
 *
 * Keep this in sync with struct mlx5_ib_restore_pd_req in
 * include/uapi/rdma/mlx5-abi.h. Drop once host rdma-core ships the
 * struct upstream.
 */
struct mlx5_ib_restore_pd_req_local {
	uint32_t	pdn;		/* source FW pdn to adopt */
	uint32_t	reserved;	/* must be 0 */
	uint64_t	reserved2;	/* must be 0; pads above the
					 * 8-byte inline-UHW threshold */
};

/*
 * Issue UVERBS_METHOD_RESTORE_PD on @cmd_fd, asking the kernel to
 * mint a PD uobject at the caller-chosen ufile handle
 * @target_handle.
 *
 * Per-driver UHW shape:
 *   - rxe: no UHW. rxe_restore_pd is a pure kernel-side wrapper;
 *     the only thing it cares about is the ufile target handle.
 *   - mlx5: UHW carries struct mlx5_ib_restore_pd_req with
 *     {pdn = source FW pdn, reserved = 0, reserved2 = 0}. The
 *     source pdn comes from the rdma-uobj.img PD entry's fw_pdn
 *     field, which the dump side sourced from the named
 *     "fw_pdn" driver TLV that mlx5_ib's fill_res_pd_entry
 *     emits under RDMA_NLDEV_ATTR_DRIVER (kernel
 *     d4acb54ebd3d). Earlier CRIUs shipped the entry's
 *     restrack_id here -- restrack_id is NLDEV's
 *     RDMA_NLDEV_ATTR_RES_PDN, *not* mpd->pdn; the two values
 *     coincide on freshly-booted hosts but diverge as the
 *     restrack idr wraps. Sending restrack_id where mpd->pdn
 *     was expected was the silent-correctness bug fixed in
 *     d4acb54ebd3d.
 *
 * @has_src_pdn / @src_pdn carry the source FW pdn captured at dump
 * time. They are mandatory for RDMA_DRIVER_MLX5 (the verb is
 * meaningless without an adoption target) and ignored for any
 * driver whose restore_pd doesn't read UHW.
 *
 * Returns 0 on success, -errno on ioctl failure or -EINVAL if a
 * required input is missing for the chosen driver.
 *
 * Wire-format references:
 *   tools/testing/mlx5_vfmig/uobject_restore/pd_restore/
 *     pd_restore_probe_rxe.c::do_restore_pd        (rxe shape)
 *     pd_restore_probe_mlx5_vfmig.c::do_restore_pd (mlx5 shape, UHW)
 */
static int rdma_send_restore_pd(int cmd_fd, uint32_t driver_id,
				uint32_t target_handle,
				bool has_src_pdn, uint32_t src_pdn)
{
	struct {
		struct ib_uverbs_ioctl_hdr	hdr;
		struct ib_uverbs_attr		attrs[2];
	} cmd = {};
	struct mlx5_ib_restore_pd_req_local mlx5_uhw = {};
	unsigned int n = 0;

	cmd.hdr.object_id = UVERBS_OBJECT_RESTORE;
	cmd.hdr.method_id = UVERBS_METHOD_RESTORE_PD;
	cmd.hdr.driver_id = driver_id;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_PD_HANDLE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = target_handle;
	n++;

	if (driver_id == RDMA_DRIVER_MLX5) {
		if (!has_src_pdn) {
			pr_err("RESTORE_PD on driver_id=%u (mlx5) requires "
			       "the source FW pdn (mpd->pdn) from rdma-"
			       "uobj.img, but the PD entry has no fw_pdn. "
			       "The image was dumped against a kernel "
			       "that pre-dates d4acb54ebd3d (RDMA/mlx5: "
			       "fix CRIU PD restore by exposing FW pdn): "
			       "re-dump against a current kernel and "
			       "restore against the new image. Note that "
			       "RES_PDN (== restrack_id) is NOT the FW "
			       "pdn -- the two only coincided on freshly-"
			       "booted hosts before this fix.\n",
			       driver_id);
			return -EINVAL;
		}
		mlx5_uhw.pdn = src_pdn;
		/* reserved/reserved2 already zero from designated init */
		cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_IN;
		cmd.attrs[n].len = sizeof(mlx5_uhw);
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)&mlx5_uhw;
		n++;
	}

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	if (ioctl(cmd_fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}

/*
 * Issue UVERBS_METHOD_RESTORE_CQ on @cmd_fd, asking the kernel to
 * mint a CQ uobject at the caller-chosen ufile handle
 * @target_handle.
 *
 * Per-driver UHW shape:
 *   - rxe: no UHW. rxe_restore_cq is a pure kernel-side wrapper;
 *     it ignores @target_handle for hw-id purposes (rxe CQs have
 *     no wire-spec cqn -- the rxe_pool elem index is internal
 *     restrack metadata only) and reuses rxe_cq_chk_attr +
 *     rxe_add_to_pool + rxe_cq_from_init exactly the way
 *     rxe_create_cq does.
 *   - mlx5: UHW will carry struct mlx5_ib_restore_cq_req with the
 *     source's FW cqn so mlx5_ib_restore_cq can adopt it via
 *     "Model A". The mlx5 ops.restore_cq landing is S5 B-series
 *     in the kernel; this helper's mlx5 branch is added when that
 *     lands. For now mlx5 callers will hit -EOPNOTSUPP from the
 *     dispatcher's !ib_dev->ops.restore_cq guard, which is the
 *     right backstop (the rxe-only drive-by uses the rxe path).
 *
 * @cqe / @comp_vector are mandatory inputs to the kernel verb.
 * @user_handle is the source-time ibv_create_cq() cq_context tag
 * (zero in the v0 holders / ib_write_bw, since those pass NULL).
 * @flags is the optional ib_uverbs_ex_create_cq_flags subset; pass
 * 0 (the common case) to omit the FLAGS attr entirely.
 *
 * @resp_cqe_out, when non-NULL, receives the actual installed cqe
 * count from the dispatcher's RESP_CQE post-callback (rxe rounds
 * up via roundup_pow_of_two; mlx5 may also round). Pass NULL to
 * ignore the response (the kernel still requires it as MANDATORY
 * out, so we always wire a sink even if the caller doesn't care).
 *
 * Returns 0 on success, -errno on ioctl failure.
 *
 * Wire-format references:
 *   tools/testing/mlx5_vfmig/uobject_restore/cq_restore/
 *     cq_restore_probe_rxe.c::do_restore_cq (rxe shape; no UHW)
 *   drivers/infiniband/core/uverbs_std_types_restore.c
 *     UVERBS_HANDLER(UVERBS_METHOD_RESTORE_CQ)
 */
static int rdma_send_restore_cq(int cmd_fd, uint32_t driver_id,
				uint32_t target_handle, uint32_t cqe,
				uint64_t user_handle, uint32_t comp_vector,
				uint32_t flags, uint64_t source_mmap_offset,
				uint32_t *resp_cqe_out)
{
	struct {
		struct ib_uverbs_ioctl_hdr	hdr;
		struct ib_uverbs_attr		attrs[8];
	} cmd = {};
	struct rxe_create_cq_resp_local rxe_uhw_out = {};
	struct rxe_restore_cq_req_local rxe_uhw_in = {};
	uint32_t resp_cqe_sink = 0;
	unsigned int n = 0;

	if (!resp_cqe_out)
		resp_cqe_out = &resp_cqe_sink;

	cmd.hdr.object_id = UVERBS_OBJECT_RESTORE;
	cmd.hdr.method_id = UVERBS_METHOD_RESTORE_CQ;
	cmd.hdr.driver_id = driver_id;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_HANDLE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = target_handle;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_CQE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = cqe;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_USER_HANDLE;
	cmd.attrs[n].len = sizeof(uint64_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = user_handle;
	n++;

	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_COMP_VECTOR;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = comp_vector;
	n++;

	/*
	 * FLAGS_IN is optional; only emit when non-zero so we don't
	 * spend a slot for the common "no special CQ flags" case.
	 * Kernel uverbs_get_flags32 treats absent as zero already.
	 */
	if (flags) {
		cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_FLAGS;
		cmd.attrs[n].len = sizeof(uint32_t);
		cmd.attrs[n].flags = 0;
		cmd.attrs[n].data = flags;
		n++;
	}

	/*
	 * RESP_CQE is MANDATORY out at the kernel side (the dispatcher
	 * uverbs_copy_to's cq->cqe through this attr after the driver
	 * stamps it). We always wire a u32 sink.
	 */
	cmd.attrs[n].attr_id = UVERBS_ATTR_RESTORE_CQ_RESP_CQE;
	cmd.attrs[n].len = sizeof(uint32_t);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)resp_cqe_out;
	n++;

	/*
	 * Driver UHW_OUT buffer. rxe's rxe_restore_cq insists on an
	 * outbuf of at least sizeof(struct rxe_create_cq_resp) bytes
	 * (== 16, struct mminfo) and writes the mmap cookie + size
	 * for the in-kernel CQ queue into it. Without an UHW_OUT
	 * attr the kernel returns -EINVAL before any of the actual
	 * restore work runs (see the (udata->outlen < sizeof(*uresp))
	 * guard at the top of rxe_restore_cq).
	 *
	 * For mlx5 the future ops.restore_cq will likely need its
	 * own UHW_IN (source FW cqn for adoption) and possibly its
	 * own UHW_OUT for any mlx5-side mmap cookies; that's S5 B-
	 * series in the kernel and the helper grows a per-driver
	 * branch when it lands. Until then the rxe-shaped UHW_OUT
	 * is sent unconditionally: it's a no-op for any driver
	 * whose ops.restore_cq doesn't read driver_udata->outbuf,
	 * and the kernel is happy to accept a larger-than-needed
	 * UHW_OUT.
	 */
	cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_OUT;
	cmd.attrs[n].len = sizeof(rxe_uhw_out);
	cmd.attrs[n].flags = 0;
	cmd.attrs[n].data = (uintptr_t)&rxe_uhw_out;
	n++;

	/*
	 * Driver UHW_IN: the source-side vm_pgoff (byte offset) we
	 * captured from /proc/<pid>/maps at dump time. Sent only when
	 * non-zero -- the kernel reads inlen and treats inlen == 0 as
	 * "legacy / pgoff-agnostic restore" (falls back to monotonic
	 * counter). Sending an explicit zero would also fall back
	 * (req.vm_pgoff == 0 is a no-op in rxe_create_mmap_info), but
	 * we omit the attr entirely on the !source_mmap_offset path
	 * to keep wire shape identical to pre-d3a79140ed26 callers
	 * (forward-compatibility: if this CRIU runs against an older
	 * kernel that still has UVERBS_METHOD_RESTORE_CQ but lacks
	 * the UHW_IN handling, the older kernel's strict inlen check
	 * -- inlen != 0 && < sizeof(req) -- would EINVAL us).
	 *
	 * For mlx5 the future ops.restore_cq's UHW_IN payload is
	 * different shape (FW cqn for adoption); when that lands the
	 * helper grows a per-driver branch keyed off driver_id.
	 */
	if (source_mmap_offset) {
		rxe_uhw_in.vm_pgoff = source_mmap_offset;
		cmd.attrs[n].attr_id = UVERBS_ATTR_UHW_IN;
		cmd.attrs[n].len = sizeof(rxe_uhw_in);
		cmd.attrs[n].flags = 0;
		cmd.attrs[n].data = (uintptr_t)&rxe_uhw_in;
		n++;
	}

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	if (ioctl(cmd_fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;

	/*
	 * Defense-in-depth: when we asked the kernel to honour a
	 * specific source offset, verify the kernel echoed it back
	 * via UHW_OUT. A mismatch would mean a kernel bug (the patch
	 * promises mi.offset == req.vm_pgoff on success); we'd
	 * rather catch that loudly here than have the pie restorer's
	 * mmap silently fail with -EINVAL in a place that's much
	 * harder to diagnose.
	 */
	if (source_mmap_offset && rxe_uhw_out.mi_offset != source_mmap_offset) {
		pr_err("rdma_send_restore_cq: kernel returned mmap_offset=%#"
		       PRIx64 " but caller asked for %#" PRIx64
		       " (kernel didn't honor UHW_IN; check rxe is on the "
		       "d3a79140ed26 patch or its successor)\n",
		       (uint64_t)rxe_uhw_out.mi_offset,
		       (uint64_t)source_mmap_offset);
		return -EPROTO;
	}
	return 0;
}

/*
 * UVERBS_METHOD_RESTORE_MR is issued from the pie restorer blob,
 * not from CRIU master -- see criu/pie/restorer.c::restore_rdma_mr
 * for the encoder + the rationale (rxe pin_user_pages_fast needs the
 * destination task's user mm laid out at its final VAs, which only
 * happens inside the pie blob during sigreturn_restore). CRIU master
 * just serialises the per-MR call args into ta->rdma_mrs via
 * rdma_prepare_rdma_mrs() below, and the pie blob iterates and
 * issues the ioctl.
 */

/*
 * Per-ufile handle map entry. Built up as we restore each uobject
 * in topological order; consumed by children that need to resolve
 * a parent xref ((target_type, target_restrack_id)) to the
 * parent's destination-side ufile_handle.
 *
 * Model A (handle preservation) means the destination handle
 * always equals the source's recorded ufile_handle, so
 * "destination handle" == "source's RdmaUobjEntry.ufile_handle"
 * and the map is really just a (type, restrack_id) -> uint32_t
 * table populated from each successfully-installed parent's image
 * entry. Doing the lookup the long way (via this map) keeps the
 * design symmetric with future drivers that may not preserve
 * handles -- the lookup interface stays the same; only the way we
 * populate the map changes.
 */
struct uobj_handle_map_entry {
	R3UobjType type;
	uint32_t restrack_id;
	uint32_t ufile_handle;
};

struct uobj_handle_map {
	struct uobj_handle_map_entry *e;
	size_t n;
	size_t cap;
};

static int uobj_handle_map_add(struct uobj_handle_map *m,
			       R3UobjType type, uint32_t restrack_id,
			       uint32_t ufile_handle)
{
	if (m->n == m->cap) {
		size_t newcap = m->cap ? m->cap * 2 : 8;
		void *p = xrealloc(m->e, newcap * sizeof(*m->e));
		if (!p)
			return -1;
		m->e = p;
		m->cap = newcap;
	}
	m->e[m->n].type = type;
	m->e[m->n].restrack_id = restrack_id;
	m->e[m->n].ufile_handle = ufile_handle;
	m->n++;
	return 0;
}

static bool uobj_handle_map_lookup(const struct uobj_handle_map *m,
				   R3UobjType type, uint32_t restrack_id,
				   uint32_t *ufile_handle)
{
	for (size_t i = 0; i < m->n; i++) {
		if (m->e[i].type == type &&
		    m->e[i].restrack_id == restrack_id) {
			*ufile_handle = m->e[i].ufile_handle;
			return true;
		}
	}
	return false;
}

/*
 * Look up the @role-typed parent reference on @e and return its
 * destination-side ufile_handle via @out. Returns false if the xref
 * is missing, the target's restrack_id was missing, or the target
 * hasn't been added to the map yet (i.e. wasn't restored in an
 * earlier topo pass).
 */
static bool uobj_resolve_parent(const RdmaUobjEntry *e,
				R3XrefRole role,
				const struct uobj_handle_map *m,
				uint32_t *out)
{
	for (size_t i = 0; i < e->n_xref; i++) {
		const RdmaUobjXref *xr = e->xref[i];

		if (xr->role != role)
			continue;
		if (uobj_handle_map_lookup(m, xr->target_type,
					   xr->target_restrack_id, out))
			return true;
		return false;
	}
	return false;
}

/*
 * Phase-B pending list: per-ufile restore state stashed by
 * rdma_restore_uobj_dag_for_ufile() (Phase A, pre-VMA) and consumed
 * by rdma_restore_uobj_dag_post_vma() (Phase B, post-VMA).
 *
 * Why split: verbs that pin user pages
 * (UVERBS_METHOD_RESTORE_MR -> pin_user_pages_fast(user_addr, ...))
 * need the restored task's user VMAs to already be mapped, but
 * uverbsfd_open() runs during prepare_fds() which is BEFORE
 * open_vmas(). Phase A handles VA-independent verbs (PD today;
 * CQ/QP/SRQ/AH later, none of which pin user pages) inline,
 * stashes the rest, and Phase B runs once after open_vmas() in
 * the same restored task.
 *
 * Held state per pending ufile:
 *   cmd_fd_dup       O_CLOEXEC dup of the plugin's open cdev fd.
 *                    Phase A's @cmd_fd is a transient passed-in
 *                    parameter; Phase B needs its own long-lived
 *                    handle on the same struct file because the
 *                    kernel ucontext IDR resolves through it.
 *                    Closed by Phase B at end-of-walk.
 *   ufile_id /
 *   kernel_driver_id Pass-through inputs to RESTORE_<TYPE>.
 *   g                The DAG group from rdma_uobj_group_lookup --
 *                    avoids a re-lookup; unchanged across phases.
 *   handle_map       Built up in Phase A (one entry per PD
 *                    successfully RESTORE_PD'd), consumed in
 *                    Phase B (every R3UT_MR's PARENT_PD xref is
 *                    resolved through it). Owned by this struct,
 *                    freed at end-of-Phase-B.
 */
struct uobj_pending_post_vma {
	int cmd_fd_dup;
	uint32_t ufile_id;
	uint32_t kernel_driver_id;
	struct uobj_ufile_group *g;
	struct uobj_handle_map handle_map;
	struct list_head link;
};
static LIST_HEAD(rdma_pending_post_vma);

static int rdma_pending_post_vma_add(int cmd_fd_dup, uint32_t ufile_id,
				     uint32_t kernel_driver_id,
				     struct uobj_ufile_group *g,
				     struct uobj_handle_map *handle_map)
{
	struct uobj_pending_post_vma *p;

	p = xzalloc(sizeof(*p));
	if (!p) {
		close(cmd_fd_dup);
		xfree(handle_map->e);
		return -1;
	}
	p->cmd_fd_dup = cmd_fd_dup;
	p->ufile_id = ufile_id;
	p->kernel_driver_id = kernel_driver_id;
	p->g = g;
	/* Move the handle_map -- caller no longer owns the storage. */
	p->handle_map = *handle_map;
	memset(handle_map, 0, sizeof(*handle_map));
	INIT_LIST_HEAD(&p->link);
	list_add_tail(&p->link, &rdma_pending_post_vma);
	return 0;
}

/*
 * Per-ufile restore dispatcher (Phase A, pre-VMA). Called from
 * uverbsfd_open() right after the plugin's RDMA_OPEN_UVERBS_CDEV
 * hook returns the open cdev fd. Walks the DAG group built by
 * rdma_collect_uobj_dag() for @ufile_id and issues the VA-
 * independent RESTORE_<TYPE> verbs (PD today; CQ/QP/SRQ/AH later)
 * in topological order, building a (restrack_id -> ufile_handle)
 * handle_map as it goes. VA-dependent verbs (MR; later DEVX_UMEM)
 * are deferred to rdma_restore_uobj_dag_post_vma() because their
 * kernel handlers pin_user_pages_fast() against current->mm and
 * the restored task's VMAs aren't laid out yet at this point in
 * the per-task restore flow (see rdma.h::rdma_restore_uobj_dag_
 * post_vma).
 *
 * S2 / S4a / S5a scope: PD + CQ pre-VMA + MR post-VMA (rxe). QP /
 * SRQ / AH RESTORE_<TYPE> verbs land as the kernel side gains the
 * corresponding driver callbacks; until then those entries are
 * silently skipped (the post-restore application sees the empty-
 * of-QP ucontext, which is the same situation pre-S2 had).
 *
 * Skips entries without ufile_handle (kernel pre-K8a / future
 * resource classes that aren't NLDEV-emitted) -- without a target
 * handle there's nothing to ask the kernel for.
 *
 * On success Phase A stashes (cmd_fd_dup, ufile_id, kernel_driver_
 * id, handle_map, group) onto the rdma_pending_post_vma list iff
 * the group has any VA-dependent entries (MRs); the dup'd fd is
 * O_CLOEXEC and is closed by Phase B. If the DAG has no VA-
 * dependent entries we don't bother stashing -- there's nothing
 * for Phase B to do for this ufile.
 *
 * Returns 0 on success (including the no-DAG case); -1 on the
 * first per-entry Phase-A restore failure, with the offending
 * (ufile_id, type, ufile_handle) in the pr_err.
 */
int rdma_restore_uobj_dag_for_ufile(int cmd_fd, uint32_t ufile_id,
				    uint32_t kernel_driver_id)
{
	struct uobj_ufile_group *g;
	struct uobj_collected *c;
	struct uobj_handle_map handle_map = {};
	int n_pd_restored = 0;
	int n_pd_skipped = 0;
	int n_cq_restored = 0;
	int n_cq_skipped = 0;
	int n_mr_pending = 0;
	int ret = -1;

	g = rdma_uobj_group_lookup(ufile_id);
	if (!g) {
		pr_debug("uobj DAG: ufile_id=%#x has no DAG group "
			 "(no rdma-uobj.img coverage); nothing to restore\n",
			 ufile_id);
		return 0;
	}

	/*
	 * Pass 1: PDs. PD has no parent xref so order within the
	 * pass doesn't matter; doing PDs first ensures every MR's
	 * parent_pd_handle is in handle_map for Phase B.
	 */
	list_for_each_entry(c, &g->entries, link) {
		const RdmaUobjEntry *e = c->e;
		int rc;

		if (e->type != R3_UOBJ_TYPE__R3UT_PD)
			continue;
		if (!e->has_ufile_handle) {
			/*
			 * Pre-K8a image, or NLDEV walk lost the
			 * field. Without target_handle we can't
			 * ask the kernel to install at a
			 * specific slot. Count + move on; the
			 * test fixture asserts handles>0 on a
			 * fresh image so this surfaces upstream.
			 */
			n_pd_skipped++;
			continue;
		}
		/*
		 * Source the FW pdn from the per-PD fw_pdn field
		 * (rdma_uobj.proto), which the dump side sourced
		 * from the kernel's named "fw_pdn" driver TLV.
		 * restrack_id is NOT the FW pdn -- it's
		 * RDMA_NLDEV_ATTR_RES_PDN's per-ibdev restrack
		 * counter -- and historically was passed here by
		 * accident (silently correct on freshly-booted
		 * hosts only). Falling back to restrack_id on
		 * an old image keeps backward-compat for rxe
		 * (which ignores UHW anyway), at the cost of
		 * mlx5 images dumped against a pre-fix kernel
		 * being rejected loudly by rdma_send_restore_pd.
		 */
		rc = rdma_send_restore_pd(cmd_fd, kernel_driver_id,
					  e->ufile_handle,
					  e->has_fw_pdn,
					  e->fw_pdn);
		if (rc) {
			pr_err("uobj DAG: ufile_id=%#x RESTORE_PD"
			       "(target_handle=%u, driver_id=%u, "
			       "fw_pdn=%s%u, fw_uid=%s%u) failed: "
			       "%d (%s)%s\n",
			       ufile_id, e->ufile_handle,
			       kernel_driver_id,
			       e->has_fw_pdn ? "" : "?",
			       e->has_fw_pdn ? e->fw_pdn : 0,
			       e->has_fw_uid ? "" : "?",
			       e->has_fw_uid ? e->fw_uid : 0,
			       rc, strerror(-rc),
			       rc == -EOPNOTSUPP
			       ? " -- kernel has no "
			         "ib_device_ops.restore_pd for this "
			         "driver (rxe needs the e06868342fce "
			         "patch; mlx5 needs 4baa782ba0af)"
			       : rc == -EPERM
			       ? " -- ucontext not in restore mode "
			         "(plugin's RDMA_OPEN_UVERBS_CDEV "
			         "must use a per-driver restore-mode "
			         "GET_CONTEXT: rxe needs "
			         "RXE_ALLOC_UCTX_RESTORE_MODE, mlx5 "
			         "needs MLX5_IB_ALLOC_UCTX_VFMIG_RESTORE)"
			       : rc == -EBUSY
			       ? " -- target_handle collision "
			         "(another uobject already at this "
			         "ufile slot; image is internally "
			         "inconsistent or the kernel ufile "
			         "is not pristine)"
			       : rc == -ENOENT &&
				 kernel_driver_id == RDMA_DRIVER_MLX5
			       ? " -- mlx5_ib_restore_pd FW probe "
			         "rejected (pdn, devx_uid). v0 "
			         "policy: dest ucontext is opened "
			         "WITHOUT DEVX so devx_uid=0 is the "
			         "expected probe lane; if -ENOENT "
			         "still fires, the image's fw_pdn "
			         "is stale (re-dump needed: kernel "
			         "ABI for fw_pdn is the named "
			         "driver TLV in RDMA_NLDEV_ATTR_"
			         "DRIVER, kernel d4acb54ebd3d). "
			         "DEVX-uid adoption is vestigial: "
			         "LOAD_VHCA_STATE does not preserve "
			         "the FW uctx registration table, "
			         "so non-zero uids are unrecoverable "
			         "(kernel 73c76f299c01, design "
			         "uobject_restore.md S3b). See dmesg "
			         "mlx5_ib_warn 'restore_pd: FW probe "
			         "rejected'."
			       : rc == -EINVAL &&
				 kernel_driver_id == RDMA_DRIVER_MLX5
			       ? " -- mlx5_ib_restore_pd rejected the "
			         "UHW (pdn=0 is reserved, reserved/"
			         "reserved2 must be 0, or udata size "
			         "mismatch -- check struct "
			         "mlx5_ib_restore_pd_req packing)"
			       : "");
			goto out;
		}
		n_pd_restored++;

		/*
		 * Add to handle_map so MRs (and future CQ/QP/SRQ/AH)
		 * in Pass 2+ can resolve PARENT_PD xrefs without
		 * doing a list-walk on every dispatch.
		 */
		if (e->has_restrack_id) {
			if (uobj_handle_map_add(&handle_map,
						R3_UOBJ_TYPE__R3UT_PD,
						e->restrack_id,
						e->ufile_handle) < 0) {
				pr_err("uobj DAG: ufile_id=%#x: handle_map "
				       "OOM after RESTORE_PD(handle=%u)\n",
				       ufile_id, e->ufile_handle);
				goto out;
			}
		} else {
			pr_warn("uobj DAG: ufile_id=%#x: PD entry handle=%u "
				"has no restrack_id; child MR/CQ/QP xrefs "
				"to this PD won't resolve\n",
				ufile_id, e->ufile_handle);
		}
	}

	/*
	 * Pass 2: CQs (S5a). RESTORE_CQ has no parent xref to resolve
	 * (CQ has no PARENT_PD), no user pages to pin, and the v0
	 * dispatcher gates COMP_CHANNEL out -- so the verb is purely
	 * "install at target_handle, allocate the rxe pool slot or
	 * adopt the FW cqn". Runs in Phase A inline; CQs go into
	 * handle_map so future QP/SRQ restore can resolve their
	 * SEND_CQ / RECV_CQ xrefs.
	 *
	 * Skips entries with no ufile_handle (kernel pre-K8a / NLDEV
	 * walk lost the field). Mismatch with the corresponding image-
	 * side rdma_cq_attrs absent-field handling: cqe_count defaults
	 * to 0 only on degenerate dumps; current dumpers always
	 * populate it from NLDEV's RES_CQE.
	 */
	list_for_each_entry(c, &g->entries, link) {
		const RdmaUobjEntry *e = c->e;
		const RdmaCqAttrs *attrs;
		uint32_t resp_cqe = 0;
		uint32_t cqe = 0;
		uint32_t comp_vector = 0;
		uint32_t flags = 0;
		uint64_t user_handle = 0;
		uint64_t mmap_offset = 0;
		int rc;

		if (e->type != R3_UOBJ_TYPE__R3UT_CQ)
			continue;
		if (!e->has_ufile_handle) {
			n_cq_skipped++;
			continue;
		}

		attrs = e->cq;
		if (attrs) {
			if (attrs->has_cqe_count)
				cqe = attrs->cqe_count;
			if (attrs->has_comp_vector)
				comp_vector = attrs->comp_vector;
			if (attrs->has_flags)
				flags = attrs->flags;
			if (attrs->has_mmap_offset)
				mmap_offset = attrs->mmap_offset;
		}
		/*
		 * user_handle (== source's ibv_create_cq cq_context)
		 * isn't NLDEV-emitted today; v0 callers (rxe holder,
		 * ib_write_bw) all pass NULL so 0 is the right default.
		 * When a future QUERY_CQ / NLDEV emission lands, plumb
		 * it through rdma_cq_attrs and feed it here. Documented
		 * in rdma_uobj.proto::rdma_cq_attrs.
		 *
		 * mmap_offset, when non-zero, instructs the kernel to
		 * pin the new CQ's mmap region at exactly this byte
		 * offset (see rxe_restore_cq_req in rdma_user_rxe.h).
		 * Captured at dump time by the RDMA-class plugin's
		 * CR_PLUGIN_HOOK__PROCESS_DEVICE_VMA hook, which feeds
		 * each per-(pid, ibdev) cdev VMA's pgoff (in bytes)
		 * into criu/rdma.c's process-global side-table via
		 * rdma_record_cdev_vma(); uobj_cq_cb pops one entry
		 * per CQ at NLDEV-walk time. Zero means the plugin
		 * didn't register PROCESS_DEVICE_VMA, the side-table
		 * was exhausted (multi-uobj ufile w/o per-class join
		 * key), or the snapshot pre-dated CQ creation. Zero
		 * falls back to the kernel's monotonic counter --
		 * matches the source iff the source's counter was
		 * also fresh, which is true only for very simple
		 * holders.
		 */
		rc = rdma_send_restore_cq(cmd_fd, kernel_driver_id,
					  e->ufile_handle, cqe,
					  user_handle, comp_vector,
					  flags, mmap_offset, &resp_cqe);
		if (rc) {
			pr_err("uobj DAG: ufile_id=%#x RESTORE_CQ"
			       "(target_handle=%u, driver_id=%u, "
			       "cqe=%u, comp_vector=%u, flags=0x%x) "
			       "failed: %d (%s)%s\n",
			       ufile_id, e->ufile_handle,
			       kernel_driver_id, cqe, comp_vector,
			       flags, rc, strerror(-rc),
			       rc == -EOPNOTSUPP
			       ? " -- kernel has no "
			         "ib_device_ops.restore_cq for this "
			         "driver (rxe needs a77cc4d8e8b9; "
			         "mlx5 ops.restore_cq is S5 B-series, "
			         "not yet in tree)"
			       : rc == -EPERM
			       ? " -- ucontext not in restore mode "
			         "(see RESTORE_PD's analogous error "
			         "for the per-driver flag matrix)"
			       : rc == -EBUSY
			       ? " -- target_handle collision "
			         "(another uobject already at this "
			         "ufile slot; image is internally "
			         "inconsistent or the kernel ufile "
			         "is not pristine)"
			       : rc == -EINVAL
			       ? " -- dispatcher rejected core attrs "
			         "(comp_vector >= dev->num_comp_vectors, "
			         "or invalid FLAGS bits, or driver UHW "
			         "size mismatch -- including a truncated "
			         "rxe_restore_cq_req UHW_IN)"
			       : rc == -EEXIST
			       ? " -- requested mmap_offset collides "
			         "with another pending mmap region on "
			         "the dest cdev (concurrent restore on "
			         "the same ibdev, or dump-side captured "
			         "an offset another sibling uobj already "
			         "claimed)"
			       : "");
			goto out;
		}
		n_cq_restored++;
		pr_debug("uobj DAG: ufile_id=%#x RESTORE_CQ"
			 "(target_handle=%u) ok: requested cqe=%u, "
			 "kernel installed resp_cqe=%u, mmap_offset=%#"
			 PRIx64 "\n",
			 ufile_id, e->ufile_handle, cqe, resp_cqe,
			 mmap_offset);

		if (e->has_restrack_id) {
			if (uobj_handle_map_add(&handle_map,
						R3_UOBJ_TYPE__R3UT_CQ,
						e->restrack_id,
						e->ufile_handle) < 0) {
				pr_err("uobj DAG: ufile_id=%#x: handle_map "
				       "OOM after RESTORE_CQ(handle=%u)\n",
				       ufile_id, e->ufile_handle);
				goto out;
			}
		} else {
			pr_warn("uobj DAG: ufile_id=%#x: CQ entry handle=%u "
				"has no restrack_id; child QP/SRQ xrefs "
				"to this CQ won't resolve\n",
				ufile_id, e->ufile_handle);
		}
	}

	/*
	 * Pass 3 (deferred): count VA-dependent entries (MRs) so we
	 * know whether to stash this ufile for Phase B. We don't
	 * issue RESTORE_MR here -- the kernel handler pins user
	 * pages and the restored task's VMAs aren't mapped yet.
	 */
	list_for_each_entry(c, &g->entries, link) {
		const RdmaUobjEntry *e = c->e;

		if (e->type == R3_UOBJ_TYPE__R3UT_MR && e->has_ufile_handle)
			n_mr_pending++;
	}

	if (n_mr_pending > 0) {
		int dup;

		/*
		 * Dup high. CRIU's per-task file restorer reinstalls
		 * source-side fds at their original numbers via
		 * move_fd_from -> fcntl(F_DUPFD, want_fd) (see util.c::
		 * reopen_fd_as_safe). Without allow_reuse_fd that's a
		 * hard "lowest >= want_fd that's free" allocator: if
		 * any of [0..want_fd) is occupied by a CRIU-internal
		 * fd, F_DUPFD returns a *higher* number than want_fd
		 * and CRIU errors with "fd N already in use". Our dup
		 * lands here too; if we let it grab fd 3 (or whatever
		 * the source's user-visible cdev fd was), the move-in
		 * for cmd_fd to fle->fe->fd fails. Starting the dup at
		 * a deliberately-high min keeps it out of the user-fd
		 * range that the per-task restorer needs to assign,
		 * while still being below CRIU's own service-fd range
		 * (service_fd_base ~= rlimit-256). 1<<14 is well above
		 * any plausible user-fd allocation in the restored
		 * task and well below service_fd_base on any current
		 * RLIMIT_NOFILE tuning.
		 */
		dup = fcntl(cmd_fd, F_DUPFD_CLOEXEC, 1 << 14);
		if (dup < 0) {
			pr_err("uobj DAG: ufile_id=%#x: F_DUPFD_CLOEXEC of "
			       "cdev fd for Phase B failed: %s\n",
			       ufile_id, strerror(errno));
			goto out;
		}
		if (rdma_pending_post_vma_add(dup, ufile_id,
					      kernel_driver_id, g,
					      &handle_map) < 0) {
			pr_err("uobj DAG: ufile_id=%#x: stashing Phase B "
			       "state failed (OOM); MR restore won't "
			       "run\n", ufile_id);
			goto out;
		}
		/*
		 * handle_map ownership was moved into the pending
		 * entry; the local copy is now zero-initialised so
		 * the cleanup path below is safe.
		 */
	}

	ret = 0;
out:
	if (n_pd_restored || n_pd_skipped || n_cq_restored ||
	    n_cq_skipped || n_mr_pending)
		pr_info("uobj DAG: ufile_id=%#x Phase A: restored %d PD(s) "
			"[skipped %d], %d CQ(s) [skipped %d]; %d MR(s) "
			"deferred to post-VMA Phase B\n",
			ufile_id, n_pd_restored, n_pd_skipped,
			n_cq_restored, n_cq_skipped, n_mr_pending);
	xfree(handle_map.e);
	return ret;
}

int rdma_prepare_rdma_mrs(struct task_restore_args *ta)
{
	struct uobj_pending_post_vma *p, *p_next;
	unsigned int n_total_serialised = 0;
	int ret = 0;

	/*
	 * Always anchor ta->rdma_mrs at the current RM_PRIVATE cursor
	 * before we know whether anything will land here -- that way
	 * the cursor stays consistent with rst_mems[RM_PRIVATE].size
	 * across the whole prepare_* sequence even on the no-RDMA
	 * fast path.
	 */
	ta->rdma_mrs = (struct rst_rdma_mr *)rst_mem_align_cpos(RM_PRIVATE);
	ta->rdma_mrs_n = 0;

	if (list_empty(&rdma_pending_post_vma))
		return 0;

	list_for_each_entry_safe(p, p_next, &rdma_pending_post_vma, link) {
		struct uobj_collected *c;
		unsigned int n_mr_serialised = 0;
		unsigned int n_mr_skipped = 0;
		int per_ret = 0;

		list_for_each_entry(c, &p->g->entries, link) {
			const RdmaUobjEntry *e = c->e;
			uint32_t parent_pd_handle = 0;
			const RdmaMrAttrs *attrs;
			struct rst_rdma_mr *r;
			int dup_fd;

			if (e->type != R3_UOBJ_TYPE__R3UT_MR)
				continue;
			if (!e->has_ufile_handle) {
				n_mr_skipped++;
				continue;
			}
			attrs = e->mr;
			if (!attrs ||
			    !attrs->has_lkey || !attrs->has_rkey ||
			    !attrs->has_length || !attrs->has_iova ||
			    !attrs->has_virt_addr ||
			    !attrs->has_access_flags) {
				pr_err("uobj DAG: ufile_id=%#x MR"
				       "(handle=%u, restrack_id=%s%u) "
				       "is missing one or more RESTORE_"
				       "MR feed fields (have lkey=%d "
				       "rkey=%d length=%d iova=%d "
				       "virt_addr=%d access_flags=%d). "
				       "RESTORE_MR needs the full set; "
				       "this image was dumped against a "
				       "kernel without QUERY_MR's user_"
				       "addr/access_flags attrs (kernel "
				       "35fb92467f68 'RDMA/uverbs: "
				       "surface user_addr + access_"
				       "flags via QUERY_MR'). Re-dump "
				       "against a current kernel.\n",
				       p->ufile_id, e->ufile_handle,
				       e->has_restrack_id ? "" : "?",
				       e->has_restrack_id ?
				       e->restrack_id : 0,
				       attrs ? attrs->has_lkey : 0,
				       attrs ? attrs->has_rkey : 0,
				       attrs ? attrs->has_length : 0,
				       attrs ? attrs->has_iova : 0,
				       attrs ? attrs->has_virt_addr : 0,
				       attrs ?
				       attrs->has_access_flags : 0);
				per_ret = -1;
				break;
			}
			if (!uobj_resolve_parent(
					e, R3_XREF_ROLE__R3XR_PARENT_PD,
					&p->handle_map,
					&parent_pd_handle)) {
				pr_err("uobj DAG: ufile_id=%#x MR"
				       "(handle=%u, restrack_id=%s%u) "
				       "has no resolvable PARENT_PD "
				       "xref (target PD missing from "
				       "handle_map -- either Phase A "
				       "didn't restore that PD, or the "
				       "dump-side xref was lost). "
				       "RESTORE_MR cannot proceed "
				       "without a parent PD.\n",
				       p->ufile_id, e->ufile_handle,
				       e->has_restrack_id ? "" : "?",
				       e->has_restrack_id ?
				       e->restrack_id : 0);
				per_ret = -1;
				break;
			}

			/*
			 * Per-MR fresh dup of the cdev fd. Each
			 * rst_rdma_mr owns its fd and the pie helper
			 * closes it after the ioctl, so that one MR's
			 * close doesn't poison a sibling MR's ioctl.
			 * Same high-min as Phase A so we stay above
			 * CRIU's user-fd reuse range.
			 */
			dup_fd = fcntl(p->cmd_fd_dup, F_DUPFD_CLOEXEC,
				       1 << 14);
			if (dup_fd < 0) {
				pr_err("uobj DAG: ufile_id=%#x MR"
				       "(handle=%u): F_DUPFD_CLOEXEC "
				       "of cdev fd for pie restorer "
				       "failed: %s\n",
				       p->ufile_id, e->ufile_handle,
				       strerror(errno));
				per_ret = -1;
				break;
			}

			r = rst_mem_alloc(sizeof(*r), RM_PRIVATE);
			if (!r) {
				pr_err("uobj DAG: ufile_id=%#x MR"
				       "(handle=%u): rst_mem_alloc("
				       "RM_PRIVATE, %zu) failed -- "
				       "cannot serialise into pie "
				       "restorer args\n",
				       p->ufile_id, e->ufile_handle,
				       sizeof(*r));
				close(dup_fd);
				per_ret = -1;
				break;
			}

			r->cmd_fd = dup_fd;
			r->ufile_id = p->ufile_id;
			r->kernel_driver_id = p->kernel_driver_id;
			r->target_handle = e->ufile_handle;
			r->parent_pd_handle = parent_pd_handle;
			r->addr = attrs->virt_addr;
			r->length = attrs->length;
			r->iova = attrs->iova;
			r->access_flags = attrs->access_flags;
			r->lkey_hint = attrs->lkey;
			r->rkey_hint = attrs->rkey;

			n_mr_serialised++;
			ta->rdma_mrs_n++;
		}

		pr_info("uobj DAG: ufile_id=%#x Phase B-prep: serialised "
			"%u MR(s) [skipped %u] for pie restorer\n",
			p->ufile_id, n_mr_serialised, n_mr_skipped);
		n_total_serialised += n_mr_serialised;

		/*
		 * Phase A's cmd_fd_dup is finished with: every MR has
		 * its own dup'd fd. The handle_map and group are pure
		 * CRIU-side bookkeeping and don't need to survive into
		 * the pie blob.
		 */
		close(p->cmd_fd_dup);
		list_del(&p->link);
		xfree(p->handle_map.e);
		xfree(p);

		if (per_ret < 0)
			ret = -1;
	}

	if (ret == 0)
		pr_info("uobj DAG: Phase B-prep: %u MR(s) total queued "
			"for pie-restorer dispatch\n", n_total_serialised);
	return ret;
}

int rdma_collect_uobj_dag(void)
{
	struct cr_img *img;
	struct uobj_ufile_group *g, *gnext;
	struct uobj_collected *c, *cnext;
	int ret = -1;
	int n_entries = 0;

	img = open_image(CR_FD_RDMA_UOBJ, O_RSTR);
	if (!img)
		return -1;
	if (empty_image(img)) {
		pr_debug("uobj DAG: no rdma-uobj.img in dump (no in-tree "
			 "RDMA at dump time); nothing to verify\n");
		close_image(img);
		return 0;
	}

	while (1) {
		RdmaUobjEntry *e = NULL;
		int r;

		r = pb_read_one_eof(img, &e, PB_RDMA_UOBJ);
		if (r < 0)
			goto out;
		if (r == 0)
			break;

		g = uobj_ufile_group_get_or_add(&rdma_uobj_groups,
						e->ufile_id,
						e->hw_driver_id);
		if (!g) {
			rdma_uobj_entry__free_unpacked(e, NULL);
			goto out;
		}

		c = xzalloc(sizeof(*c));
		if (!c) {
			rdma_uobj_entry__free_unpacked(e, NULL);
			goto out;
		}
		c->e = e;
		INIT_LIST_HEAD(&c->link);
		list_add_tail(&c->link, &g->entries);
		uobj_ufile_group_count(g, e->type);
		g->n_total++;
		if (e->has_ufile_handle)
			g->n_with_handle++;
		n_entries++;
	}

	/*
	 * Per-ufile validation. Run uniqueness + xref resolution per
	 * group; bail on the first inconsistency so the operator gets
	 * a single actionable error rather than a cascade.
	 */
	list_for_each_entry(g, &rdma_uobj_groups, link) {
		if (uobj_ufile_group_check_unique(g) < 0)
			goto out;
		if (uobj_ufile_group_check_xrefs(g) < 0)
			goto out;
		pr_info("uobj DAG: ufile_id=%#x hw_drv=%u "
			"pds=%d cqs=%d qps=%d mrs=%d srqs=%d ahs=%d "
			"ccs=%d aefs=%d xrefs=%d/%d handles=%d/%d\n",
			g->ufile_id, g->hw_driver_id,
			g->n_pd, g->n_cq, g->n_qp, g->n_mr, g->n_srq,
			g->n_ah, g->n_cc, g->n_aef,
			g->n_xref_resolved, g->n_xref_total,
			g->n_with_handle, g->n_total);
	}

	pr_info("uobj DAG: read+verify ok: %d entries across "
		"%d ufile_id group(s)\n",
		n_entries,
		({ int n = 0;
		   list_for_each_entry(g, &rdma_uobj_groups, link) n++;
		   n; }));

	close_image(img);
	return 0;
out:
	close_image(img);
	list_for_each_entry_safe(g, gnext, &rdma_uobj_groups, link) {
		list_for_each_entry_safe(c, cnext, &g->entries, link) {
			list_del(&c->link);
			rdma_uobj_entry__free_unpacked(c->e, NULL);
			xfree(c);
		}
		list_del(&g->link);
		xfree(g);
	}
	return ret;
}
