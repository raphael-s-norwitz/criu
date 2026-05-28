/*
 * R3 restore-side: per-uobject DAG dispatch + Phase A/B
 * orchestration.
 *
 * Public surface (declared in criu/include/rdma.h):
 *
 *   rdma_collect_uobj_dag()             read+verify pass on
 *                                       rdma-uobj.img, called once
 *                                       early in restore.
 *   rdma_restore_uobj_dag_for_ufile()   per-cdev-fd Phase A
 *                                       dispatcher; called from
 *                                       uverbsfd_open() in
 *                                       uverbsfd.c after the
 *                                       claiming plugin hands back
 *                                       an open cdev fd. Drives
 *                                       PD/CQ restore + queues MRs
 *                                       for Phase B.
 *   rdma_prepare_rdma_mrs()             Phase B serialiser; called
 *                                       once at end-of-restore to
 *                                       walk the per-ufile pending
 *                                       MR list and pack the
 *                                       restore_args view that the
 *                                       pie-restorer will later
 *                                       replay against per-task VMAs.
 *
 * File-private state owned by this file:
 *
 *   rdma_uobj_groups        LIST_HEAD of per-ufile groups, built
 *                           by rdma_collect_uobj_dag() and read by
 *                           rdma_restore_uobj_dag_for_ufile() +
 *                           rdma_prepare_rdma_mrs(). Lifetime is
 *                           the rest of the restore (free is at
 *                           process exit by design).
 *   rdma_pending_post_vma   LIST_HEAD of MR groups that need to
 *                           wait until per-task VMAs are mapped
 *                           (Phase B). Built incrementally by
 *                           Phase A, consumed once by
 *                           rdma_prepare_rdma_mrs().
 *
 * Reads but does not own:
 *
 *   uobj_handle_map         per-ufile (kernel-handle -> ufile_handle)
 *                           mapping built lazily during dispatch
 *                           by uverbs RESTORE_<TYPE> ioctls.
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
#include "restorer.h"
#include "rst-malloc.h"
#include "xmalloc.h"

#include "images/rdma_criu.pb-c.h"
#include "images/rdma_uobj.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "rdma: "

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
