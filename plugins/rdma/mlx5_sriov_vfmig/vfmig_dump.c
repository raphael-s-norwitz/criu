/*
 * mlx5_sriov_vfmig dump-side state.
 *
 * Two per-VF sets and the hooks that drive them:
 *
 *   - the claimed-VF cache. The claim hook
 *     (CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT) already resolves every
 *     snapshot-tree uverbs context's (ibdev, pf_bdf, vf_id) and confirms
 *     QUERY_VF.tracked=1 before it returns RCD_MLX5_SRIOV_VFMIG.
 *     Recording each VF we win the claim for lets the dump-side hooks
 *     act on exactly that set without re-walking /proc/<pid>/fd or
 *     re-querying sysfs.
 *
 *   - the suspended-VF set. The CHECKPOINT_DEVICES hook parks every
 *     claimed VF's datapath to STOP (SUSPEND_VHCA) at CRIU's freeze
 *     point, before any task memory is copied, so no peer RDMA or VF
 *     self-DMA lands in a pinned MR page mid-snapshot. fini(DUMP)
 *     resumes the set (RESUME_VHCA) once the snapshot is done.
 *
 *   - the fini(DUMP) SAVE drain. Runs SAVE_VHCA_STATE per claimed VF and
 *     writes one blob + one Mlx5VfmigStateEntry per VF into the image.
 *
 * Both sets are deduplicated by (pf_bdf, vf_id): a single VF can back
 * several uverbs contexts (e.g. one per worker thread, or across
 * several pids in the snapshot tree), and the firmware SAVE_VHCA_STATE /
 * SUSPEND_VHCA are per-VF, not per-context. Reset at init()/fini() via
 * vfmig_claimed_clear() / vfmig_suspended_clear().
 */

#include "criu-log.h"

#include <linux/mlx5_vfmig.h>

#include "vfmig_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_mlx5_vfmig_plugin: "

struct vfmig_claimed_vf {
	struct vfmig_claimed_vf *next;
	char ibdev[64];
	char pf_bdf[64];
	uint32_t vf_id;

	/*
	 * ucontext snapshot, attached by the RDMA_DUMP_UVERBS_CONTEXT
	 * hook (rdma_mlx5_vfmig_plugin_dump_uverbs_context) and consumed
	 * by the fini(DUMP) drain. v0 carries a single snapshot per VF:
	 * a VF backs one seed context on the bare-context critical path.
	 * uctx_is_dyn selects which of the two shapes below is live.
	 */
	bool uctx_captured;
	bool uctx_is_dyn;
	uint32_t ctxn;
	uint32_t source_devx_uid;
	char source_cdev_path[PATH_MAX];

	/* static-UAR shape (uctx_is_dyn == false) */
	struct mlx5_ib_vfmig_ucontext_meta_local uctx_meta;
	uint32_t *uctx_uar_table;
	size_t uctx_uar_n;
	uint32_t *uctx_bfreg_count;
	size_t uctx_bfreg_n;

	/* dyn-UAR shape (uctx_is_dyn == true) */
	struct mlx5_ib_vfmig_dyn_uar_record_local *uctx_dyn_records;
	size_t uctx_dyn_n;
};

static struct vfmig_claimed_vf *vfmig_claimed_head;

void vfmig_claimed_add(const char *ibdev, const char *pf_bdf, uint32_t vf_id)
{
	struct vfmig_claimed_vf *p;

	for (p = vfmig_claimed_head; p; p = p->next)
		if (p->vf_id == vf_id && !strcmp(p->pf_bdf, pf_bdf))
			return; /* already recorded -- one VF, many contexts */

	p = calloc(1, sizeof(*p));
	if (!p) {
		pr_err("claimed-VF cache: out of memory recording %s (pf=%s vf_id=%u)\n", ibdev, pf_bdf, vf_id);
		return;
	}

	snprintf(p->ibdev, sizeof(p->ibdev), "%s", ibdev);
	snprintf(p->pf_bdf, sizeof(p->pf_bdf), "%s", pf_bdf);
	p->vf_id = vf_id;
	p->next = vfmig_claimed_head;
	vfmig_claimed_head = p;

	pr_debug("claimed-VF cache: recorded %s (pf=%s vf_id=%u)\n", ibdev, pf_bdf, vf_id);
}

void vfmig_claimed_clear(void)
{
	struct vfmig_claimed_vf *p, *n;

	for (p = vfmig_claimed_head; p; p = n) {
		n = p->next;
		free(p->uctx_uar_table);
		free(p->uctx_bfreg_count);
		free(p->uctx_dyn_records);
		free(p);
	}
	vfmig_claimed_head = NULL;
}

/*
 * RDMA_DUMP_UVERBS_CONTEXT hook. Core RDMA dump calls this once per
 * uverbs context it walked, handing us @lfd -- a drained cdev fd that
 * shares the source ucontext's object IDR -- so we can snapshot the
 * ucontext's UAR state via the MLX5_IB_OBJECT_VFMIG QUERY verbs. The
 * snapshot is attached to the matching claimed-VF entry; the fini(DUMP)
 * SAVE drain folds it into that VF's image record.
 *
 * The claim hook runs immediately before this one over the same
 * context (both inside core's dump_uverbsfile), so the claimed entry is
 * already present; a missing entry is a structural error, not a
 * runtime condition, and fails the dump (an image record without its
 * ucontext snapshot is unrestorable).
 *
 * Returns 0 on success (including "not our device" / inactive), -1 on a
 * capture failure that must fail the dump. @kernel_driver_id and @pid
 * are unused -- the fd already targets the right context.
 */
int rdma_mlx5_vfmig_plugin_dump_uverbs_context(const char *ibdev, uint32_t kernel_driver_id, uint32_t ctxn, int lfd,
					       pid_t pid)
{
	struct mlx5_ib_vfmig_ucontext_meta_local meta;
	struct mlx5_ib_vfmig_dyn_uar_record_local *dyn = NULL;
	uint32_t *uar = NULL, *cnt = NULL;
	size_t uar_n = 0, cnt_n = 0, dyn_n = 0;
	char link[64], cdev_path[PATH_MAX];
	struct vfmig_claimed_vf *c;
	ssize_t ll;
	int rc;

	(void)kernel_driver_id;
	(void)pid;

	if (!vfmig_active)
		return 0;

	for (c = vfmig_claimed_head; c; c = c->next)
		if (!strcmp(c->ibdev, ibdev))
			break;
	if (!c) {
		pr_err("vfmig: dump-uctx: no claimed VF for ibdev=%s (claim / dump-uctx ordering broken)\n", ibdev);
		return -1;
	}

	if (c->uctx_captured) {
		pr_warn("vfmig: dump-uctx: ibdev=%s already snapshotted (ctxn=%u); v0 keeps the first, ignoring "
			"ctxn=%u\n",
			ibdev, c->ctxn, ctxn);
		return 0;
	}

	/*
	 * source_cdev_path via readlink of the drained fd, so the image
	 * records the exact cdev this context was opened against rather
	 * than re-deriving it from the ibdev at drain time.
	 */
	snprintf(link, sizeof(link), "/proc/self/fd/%d", lfd);
	ll = readlink(link, cdev_path, sizeof(cdev_path) - 1);
	if (ll < 0) {
		pr_perror("vfmig: dump-uctx: readlink(%s)", link);
		return -1;
	}
	cdev_path[ll] = '\0';

	/*
	 * Static-UAR first; -EOPNOTSUPP means a dyn-UAR ucontext, which
	 * QUERY_UCONTEXT rejects and QUERY_DYN_UARS handles instead.
	 * Exactly one of the two applies by construction.
	 */
	rc = vfmig_snapshot_uctx(lfd, &meta, &uar, &uar_n, &cnt, &cnt_n);
	if (rc == -EOPNOTSUPP) {
		rc = vfmig_snapshot_dyn_uars(lfd, &dyn, &dyn_n);
		if (rc) {
			pr_err("vfmig: dump-uctx: QUERY_DYN_UARS(ibdev=%s ctxn=%u) failed: %s\n", ibdev, ctxn,
			       strerror(-rc));
			return -1;
		}
		c->uctx_is_dyn = true;
		c->uctx_dyn_records = dyn;
		c->uctx_dyn_n = dyn_n;
		c->source_devx_uid = 0; /* dyn QUERY carries no meta.devx_uid */
	} else if (rc) {
		pr_err("vfmig: dump-uctx: QUERY_UCONTEXT(ibdev=%s ctxn=%u) failed: %s\n", ibdev, ctxn, strerror(-rc));
		return -1;
	} else {
		c->uctx_is_dyn = false;
		c->uctx_meta = meta;
		c->uctx_uar_table = uar;
		c->uctx_uar_n = uar_n;
		c->uctx_bfreg_count = cnt;
		c->uctx_bfreg_n = cnt_n;
		c->source_devx_uid = meta.devx_uid;
	}

	snprintf(c->source_cdev_path, sizeof(c->source_cdev_path), "%s", cdev_path);
	c->ctxn = ctxn;
	c->uctx_captured = true;

	pr_info("vfmig: dump-uctx: captured %s ucontext for ibdev=%s ctxn=%u devx_uid=%u\n",
		c->uctx_is_dyn ? "dyn-UAR" : "static-UAR", ibdev, ctxn, c->source_devx_uid);
	return 0;
}

/*
 * RDMA_DUMP_UOBJ_PD hook. Core's PD walker dispatches this once per mlx5
 * PD (keyed by criu_driver), handing us @lfd -- CRIU's dup of the
 * dumpee's uverbs cdev fd, sharing the source ucontext's object IDR --
 * and the PD's @ufile_handle. We QUERY_PD that handle for the source FW
 * pdn and pack it (as the verbatim RESTORE_PD UHW payload) into
 * @plugin_blob for the restore side to adopt.
 *
 * Unlike the per-ucontext hook this needs no claimed-VF bookkeeping: the
 * blob is self-contained and rides on the core RdmaUobjEntry, not the
 * per-VF image record. The by-driver dispatch already guarantees the PD
 * is ours, so there is no ibdev match to redo.
 *
 * QUERY_PD's RESP_UID (the source PD's mpd->uid) is dump-side diagnostic
 * only: PD dump does NOT refuse a non-zero uid. The default libmlx5
 * ucontext auto-allocates a DEVX uid on every ibv_open_device (so uid != 0
 * is the common case), and cross-uid PD teardown survives on restore --
 * mlx5_ib_dealloc_pd tolerates the "unknown PDN" syndrome on vfmig_restored
 * PDs, and RESTORE_UCONTEXT tolerates a devx_uid mismatch. RESTORE_PD takes
 * uid from the adopted (uid=0) destination ucontext, not from this value.
 * DEVX-direct manipulation of restored objects stays out of scope for v0.
 *
 * Returns 0 on success, -errno on failure (aborts the dump).
 * @kernel_driver_id and @pid are unused -- @lfd already targets the
 * right context.
 */
int rdma_mlx5_vfmig_plugin_dump_uobj_pd(const char *ibdev, uint32_t kernel_driver_id, int lfd, uint32_t ufile_handle,
					pid_t pid, ProtobufCBinaryData *plugin_blob)
{
	struct mlx5_ib_restore_pd_req_local blob = {};
	struct mlx5_ib_restore_pd_req_local *out;
	uint32_t uid = 0;
	int rc;

	(void)kernel_driver_id;
	(void)pid;

	if (lfd < 0) {
		pr_err("vfmig: dump-pd: ibdev=%s handle=%u has no holder cdev fd (dup failed at dump); "
		       "cannot QUERY_PD\n",
		       ibdev, ufile_handle);
		return -EBADF;
	}

	rc = vfmig_query_pd(lfd, ufile_handle, &blob, &uid);
	if (rc) {
		pr_err("vfmig: dump-pd: QUERY_PD(ibdev=%s handle=%u) failed: %d (%s)\n", ibdev, ufile_handle, rc,
		       strerror(-rc));
		return rc;
	}

	out = malloc(sizeof(*out));
	if (!out) {
		pr_err("vfmig: dump-pd: out of memory packing plugin_blob (handle=%u)\n", ufile_handle);
		return -ENOMEM;
	}
	*out = blob;

	plugin_blob->data = (uint8_t *)out;
	plugin_blob->len = sizeof(*out);

	pr_info("vfmig: dump-pd: ibdev=%s handle=%u pdn=%u uid=%u%s\n", ibdev, ufile_handle, blob.pdn, uid,
		uid ? " (DEVX lane; uid is dump-side diagnostic only, RESTORE_PD adopts under the dest ucontext)" : "");
	return 0;
}

/*
 * RDMA_DUMP_UOBJ_CQ hook. Core's CQ walker dispatches this per mlx5 CQ
 * with a shared-IDR cdev fd and the CQ's ufile handle; QUERY_CQ reads
 * the restore payload the destination cannot re-derive. Unlike PD, a CQ
 * has hw-agnostic per-class attrs NLDEV omits (comp_vector, flags) that
 * the plugin fills into @cq_attrs -- core has already stamped cqe_count
 * from NLDEV RES_CQE and we must not touch it (we cross-check it against
 * QUERY_CQ's RESP_CQE and warn on drift). The 32-byte
 * mlx5_ib_restore_cq_req (cqn, cqe_size, buf_addr, db_addr) rides in
 * @plugin_blob, byte-equal to what the restore UHW-pack hook re-emits.
 *
 * Returns 0 on success, -errno on failure (aborts the dump).
 * @kernel_driver_id and @pid are unused -- @lfd already targets the
 * right context.
 */
int rdma_mlx5_vfmig_plugin_dump_uobj_cq(const char *ibdev, uint32_t kernel_driver_id, int lfd, uint32_t ufile_handle,
					pid_t pid, RdmaCqAttrs *cq_attrs, ProtobufCBinaryData *plugin_blob)
{
	struct mlx5_ib_restore_cq_req_local blob = {};
	struct mlx5_ib_restore_cq_req_local *out;
	uint32_t resp_cqe = 0, comp_vector = 0, flags = 0;
	int rc;

	(void)kernel_driver_id;
	(void)pid;

	if (lfd < 0) {
		pr_err("vfmig: dump-cq: ibdev=%s handle=%u has no holder cdev fd (dup failed at dump); "
		       "cannot QUERY_CQ\n",
		       ibdev, ufile_handle);
		return -EBADF;
	}

	rc = vfmig_query_cq(lfd, ufile_handle, &blob, &resp_cqe, &comp_vector, &flags);
	if (rc) {
		pr_err("vfmig: dump-cq: QUERY_CQ(ibdev=%s handle=%u) failed: %d (%s)\n", ibdev, ufile_handle, rc,
		       strerror(-rc));
		return rc;
	}

	/*
	 * cqe_count is core's from NLDEV; leave it. A drift vs QUERY_CQ's
	 * RESP_CQE would mean the two sources disagree on the ring size --
	 * warn but keep the NLDEV value the restore verb's CQE attr uses.
	 */
	if (cq_attrs->has_cqe_count && cq_attrs->cqe_count != resp_cqe)
		pr_warn("vfmig: dump-cq: handle=%u NLDEV cqe_count=%u != QUERY_CQ resp_cqe=%u\n", ufile_handle,
			cq_attrs->cqe_count, resp_cqe);

	cq_attrs->has_comp_vector = true;
	cq_attrs->comp_vector = comp_vector;
	cq_attrs->has_flags = true;
	cq_attrs->flags = flags;

	out = malloc(sizeof(*out));
	if (!out) {
		pr_err("vfmig: dump-cq: out of memory packing plugin_blob (handle=%u)\n", ufile_handle);
		return -ENOMEM;
	}
	*out = blob;

	plugin_blob->data = (uint8_t *)out;
	plugin_blob->len = sizeof(*out);

	pr_info("vfmig: dump-cq: ibdev=%s handle=%u cqn=%u cqe_size=%u cqe=%u comp_vector=%u flags=%#x\n", ibdev,
		ufile_handle, blob.cqn, blob.cqe_size, resp_cqe, comp_vector, flags);
	return 0;
}

/*
 * RDMA_DUMP_UOBJ_QP hook. Core's QP walker dispatches this per mlx5 QP
 * with a shared-IDR cdev fd and the QP's ufile handle; QUERY_QP reads the
 * restore payload the destination cannot re-derive. Core has already
 * stamped the NLDEV-/query_qp-derived qp_type / qp_state / qpn / psns /
 * port / cap into @qp_attrs and we must not touch them; the plugin fills
 * only the hw-agnostic create user_handle (the async-event cookie NLDEV
 * omits). The 64-byte mlx5_ib_restore_qp_req (WQ-ring / doorbell source
 * VAs, FW qpn, WQ sizing) rides in @plugin_blob, byte-equal to what the
 * restore UHW-pack hook re-emits.
 *
 * v0 restores flag-less RC/UD QPs: create_flags is captured for
 * diagnostics but CRIU's RESTORE_QP path does not carry an IB_QP_CREATE_*
 * attr, so a non-zero value cannot round-trip -- warn if the source QP
 * had one.
 *
 * Returns 0 on success, -errno on failure (aborts the dump).
 * @kernel_driver_id and @pid are unused -- @lfd already targets the right
 * context.
 */
int rdma_mlx5_vfmig_plugin_dump_uobj_qp(const char *ibdev, uint32_t kernel_driver_id, int lfd, uint32_t ufile_handle,
					pid_t pid, RdmaQpAttrs *qp_attrs, ProtobufCBinaryData *plugin_blob)
{
	struct mlx5_ib_restore_qp_req_local blob = {};
	struct mlx5_ib_restore_qp_req_local *out;
	uint64_t user_handle = 0;
	uint32_t create_flags = 0;
	int rc;

	(void)kernel_driver_id;
	(void)pid;

	if (lfd < 0) {
		pr_err("vfmig: dump-qp: ibdev=%s handle=%u has no holder cdev fd (dup failed at dump); "
		       "cannot QUERY_QP\n",
		       ibdev, ufile_handle);
		return -EBADF;
	}

	rc = vfmig_query_qp(lfd, ufile_handle, &blob, &user_handle, &create_flags);
	if (rc) {
		pr_err("vfmig: dump-qp: QUERY_QP(ibdev=%s handle=%u) failed: %d (%s)\n", ibdev, ufile_handle, rc,
		       strerror(-rc));
		return rc;
	}

	if (create_flags)
		pr_warn("vfmig: dump-qp: handle=%u source create_flags=%#x will not round-trip (v0 restores "
			"flag-less QPs)\n",
			ufile_handle, create_flags);

	qp_attrs->has_user_handle = true;
	qp_attrs->user_handle = user_handle;

	out = malloc(sizeof(*out));
	if (!out) {
		pr_err("vfmig: dump-qp: out of memory packing plugin_blob (handle=%u)\n", ufile_handle);
		return -ENOMEM;
	}
	*out = blob;

	plugin_blob->data = (uint8_t *)out;
	plugin_blob->len = sizeof(*out);

	pr_info("vfmig: dump-qp: ibdev=%s handle=%u qpn=%u sq_wqe=%u rq_wqe=%u rq_shift=%u flags=%#x user_handle=%#llx\n",
		ibdev, ufile_handle, blob.qpn, blob.sq_wqe_count, blob.rq_wqe_count, blob.rq_wqe_shift, blob.flags,
		(unsigned long long)user_handle);
	return 0;
}

/*
 * The suspended-VF set: the (pf_bdf, vf_id) pairs CHECKPOINT_DEVICES
 * parked to STOP, so we suspend each VF exactly once (a VF backs several
 * contexts across several pids) and fini(DUMP) resumes exactly what we
 * parked.
 */
struct vfmig_suspended_vf {
	struct vfmig_suspended_vf *next;
	char pf_bdf[64];
	uint32_t vf_id;
};

static struct vfmig_suspended_vf *vfmig_suspended_head;

static struct vfmig_suspended_vf *vfmig_suspended_lookup(const char *pf_bdf, uint32_t vf_id)
{
	struct vfmig_suspended_vf *p;

	for (p = vfmig_suspended_head; p; p = p->next)
		if (p->vf_id == vf_id && !strcmp(p->pf_bdf, pf_bdf))
			return p;
	return NULL;
}

static int vfmig_suspended_add(const char *pf_bdf, uint32_t vf_id)
{
	struct vfmig_suspended_vf *p = calloc(1, sizeof(*p));

	if (!p)
		return -1;
	snprintf(p->pf_bdf, sizeof(p->pf_bdf), "%s", pf_bdf);
	p->vf_id = vf_id;
	p->next = vfmig_suspended_head;
	vfmig_suspended_head = p;
	return 0;
}

void vfmig_suspended_clear(void)
{
	struct vfmig_suspended_vf *p, *n;

	for (p = vfmig_suspended_head; p; p = n) {
		n = p->next;
		free(p);
	}
	vfmig_suspended_head = NULL;
}

/* Read the orchestrator-stamped vf_uuid for one VF (QUERY_VF). */
static int vfmig_query_vf_uuid(const char *pf_bdf, uint32_t vf_id, uint8_t out[16])
{
	struct mlx5_vfmig_query_vf qv;
	char cdev_path[PATH_MAX];
	int fd, rc;

	snprintf(cdev_path, sizeof(cdev_path), "%s/%s", MLX5_VFMIG_DEV_DIR, pf_bdf);
	fd = open(cdev_path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("vfmig: query_vf_uuid: open(%s)", cdev_path);
		return -1;
	}

	memset(&qv, 0, sizeof(qv));
	qv.vf_id = vf_id;
	rc = ioctl(fd, MLX5_VFMIG_IOC_QUERY_VF, &qv);
	close(fd);
	if (rc) {
		pr_perror("vfmig: query_vf_uuid: QUERY_VF(pf=%s vf_id=%u)", pf_bdf, vf_id);
		return -1;
	}

	memcpy(out, qv.vf_uuid, 16);
	return 0;
}

/*
 * Park one claimed VF's datapath to STOP and record it in the suspended
 * set so fini(DUMP) resumes exactly what we parked. The per-VF decision
 * lives in its own seam because the ladder differs by mode:
 *
 *   legacy  (no rendezvous descriptor for this vf_uuid): the fused
 *           RUNNING -> STOP suspend (all-or-nothing), as before.
 *   barrier (a per-VHCA descriptor exists): the fused suspend is split
 *           into its two ladder edges, SUSPEND(INITIATOR) -> RUNNING_P2P
 *           then SUSPEND(RESPONDER) -> STOP. This commit wires the split
 *           only; the D1 rendezvous that belongs between the edges (block
 *           until every peer's initiator is parked before we drop our
 *           responder) is added on top. Back-to-back the two edges are
 *           identical to the fused suspend, so behaviour is unchanged
 *           until that rendezvous lands.
 *
 * Barrier mode is resolved by vf_uuid -> descriptor: an unreadable uuid
 * is treated as legacy (the capture path refuses an unstamped VF anyway)
 * and a malformed descriptor fails closed. If we park a VF but cannot
 * remember it (OOM), roll the suspend back and fail rather than strand
 * the source in STOP -- the kernel's SR-IOV-teardown force-resume is only
 * a last resort. Returns 0 on success, -1 on resolve/suspend/tracking
 * failure.
 */
static int vfmig_suspend_one_vf(const char *pf_bdf, uint32_t vf_id)
{
	struct vfmig_rendezvous rz;
	uint8_t vf_uuid[16];
	int mode;

	if (vfmig_query_vf_uuid(pf_bdf, vf_id, vf_uuid))
		mode = 1; /* unreadable uuid -> legacy fused suspend */
	else
		mode = vfmig_rendezvous_load(vf_uuid, &rz);
	if (mode < 0)
		return -1;

	if (mode == 1) {
		if (vfmig_dp_suspend(pf_bdf, vf_id, 0))
			return -1;
	} else {
		if (vfmig_dp_suspend(pf_bdf, vf_id, MLX5_VFMIG_DIR_FLAG_INITIATOR))
			return -1;
		if (vfmig_dp_suspend(pf_bdf, vf_id, MLX5_VFMIG_DIR_FLAG_RESPONDER)) {
			(void)vfmig_dp_resume(pf_bdf, vf_id, 0);
			return -1;
		}
	}

	if (vfmig_suspended_add(pf_bdf, vf_id)) {
		pr_err("vfmig: checkpoint: OOM tracking suspended pf=%s vf_id=%u; rolling back suspend\n", pf_bdf,
		       vf_id);
		(void)vfmig_dp_resume(pf_bdf, vf_id, 0);
		return -1;
	}
	return 0;
}

/*
 * CHECKPOINT_DEVICES hook. Fires at CRIU's freeze point (seize.c), once
 * per alive task, before any task memory is copied into the image. Park
 * every claimed VF's datapath to STOP via SUSPEND_VHCA so no peer RDMA
 * WRITE/SEND and no VF self-DMA can land in a pinned MR page mid-
 * snapshot. The claimed set is tree-wide (the pre-suspend coverage check
 * already ran the claim hook over every context), so the whole set is
 * parked on the first call and later calls dedup via the suspended set;
 * @pid is unused.
 *
 * Returns -ENOTSUP when the plugin is inactive (so CRIU's hook chain
 * treats it as absent), 0 on success ("nothing to do" included), or -1
 * if a VF that must be parked fails to suspend -- a dump that cannot
 * quiesce the datapath must fail rather than snapshot a live one.
 */
int rdma_mlx5_vfmig_plugin_checkpoint_devices(int pid)
{
	struct vfmig_claimed_vf *c;
	int parked = 0;

	(void)pid;

	if (!vfmig_active)
		return -ENOTSUP;

	for (c = vfmig_claimed_head; c; c = c->next) {
		if (vfmig_suspended_lookup(c->pf_bdf, c->vf_id))
			continue;
		if (vfmig_suspend_one_vf(c->pf_bdf, c->vf_id))
			return -1;
		parked++;
	}

	if (parked)
		pr_info("vfmig: checkpoint: parked %d VF datapath(s) before memory dump\n", parked);
	return 0;
}

/*
 * Resume every VF this dump parked at CHECKPOINT_DEVICES. Called from
 * fini(DUMP) after the SAVE drain, on both the success and failure
 * paths: the snapshot is complete (or lost) either way, and a VF left in
 * STOP would make the orchestrator's sriov_numvfs=0 teardown walk a dead
 * command ring. RESUME_VHCA is idempotent, so a VF the kernel already
 * force-resumed is harmless. Best-effort: a failed resume is logged but
 * we still drop the entry and free the set.
 */
void vfmig_resume_suspended_vfs(void)
{
	struct vfmig_suspended_vf *p, *n;
	int resumed = 0, failed = 0;

	for (p = vfmig_suspended_head; p; p = n) {
		n = p->next;
		if (vfmig_dp_resume(p->pf_bdf, p->vf_id, 0))
			failed++;
		else
			resumed++;
		free(p);
	}
	vfmig_suspended_head = NULL;

	if (resumed || failed)
		pr_info("fini-DUMP resume: resumed=%d resume_failed=%d\n", resumed, failed);
}

/*
 * Per-VF capture result, produced by vfmig_capture_one_vf() and consumed
 * by vfmig_drain_claimed_in_fini() to build one image record.
 */
struct vfmig_saved_vf {
	uint32_t vhca_id;
	uint8_t vf_uuid[16];
	char blob_path[128];
	uint64_t blob_size;
};

/*
 * Capture the firmware blob for one (pf_bdf, vf_id) pair. Steps mirror
 * the source-side lifecycle in the kernel UAPI doc for
 * MLX5_VFMIG_IOC_SAVE_VHCA_STATE:
 *   1. open /dev/mlx5_vfmig/<pf_bdf>
 *   2. GET_VHCA_ID  (record vhca_id for diagnostics)
 *   3. QUERY_VF     (read the orchestrator-stamped vf_uuid; hard-refuse
 *      if all-zeros, BEFORE the expensive SAVE, since vf_uuid is the
 *      sole stable restore-side match key)
 *   4. SAVE_VHCA_STATE { vf_id, flags = 0 } -> read-only save_fd
 *   5. drain save_fd into a per-VF blob under the image dir
 *
 * flags=0 is correct in both cases the plugin produces. When the VF was
 * already parked to STOP by CHECKPOINT_DEVICES (the normal path -- that
 * hook runs at freeze, before this drain), SAVE captures it as-is and
 * leaves the resume to our fini RESUME_VHCA; KEEP_SUSPENDED would be a
 * no-op for a caller-parked VF. When the VF was not pre-parked, SAVE
 * transiently self-suspends and resumes it on close, leaving the source
 * runnable. Either way SAVE never changes the persistent SUSPEND_VHCA
 * datapath state this plugin owns.
 */
static int vfmig_capture_one_vf(const char *pf_bdf, uint32_t vf_id, struct vfmig_saved_vf *out)
{
	struct mlx5_vfmig_get_vhca_id gv;
	struct mlx5_vfmig_query_vf qv;
	struct mlx5_vfmig_save_state ss;
	uint8_t zero_uuid[16] = { 0 };
	char cdev_path[PATH_MAX];
	int cdev_fd;

	snprintf(cdev_path, sizeof(cdev_path), "%s/%s", MLX5_VFMIG_DEV_DIR, pf_bdf);
	cdev_fd = open(cdev_path, O_RDWR | O_CLOEXEC);
	if (cdev_fd < 0) {
		pr_perror("vfmig: open(%s)", cdev_path);
		return -1;
	}

	memset(&gv, 0, sizeof(gv));
	gv.vf_id = vf_id;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_GET_VHCA_ID, &gv)) {
		pr_perror("vfmig: GET_VHCA_ID(pf=%s vf_id=%u)", pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}
	out->vhca_id = gv.vhca_id;

	memset(&qv, 0, sizeof(qv));
	qv.vf_id = vf_id;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_QUERY_VF, &qv)) {
		pr_perror("vfmig: QUERY_VF(pf=%s vf_id=%u)", pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}
	if (!memcmp(qv.vf_uuid, zero_uuid, sizeof(zero_uuid))) {
		pr_err("vfmig: refusing to dump pf=%s vf_id=%u: orchestrator has not stamped a vf_uuid on this VF "
		       "(QUERY_VF.vf_uuid is all-zeros). It must call MLX5_VFMIG_IOC_SET_VF_UUID with a stable "
		       "16-byte identity on this PF cdev before the workload binds the VF, so restore can match the "
		       "dumped image to a destination VF by UUID.\n",
		       pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}
	memcpy(out->vf_uuid, qv.vf_uuid, sizeof(out->vf_uuid));

	memset(&ss, 0, sizeof(ss));
	ss.vf_id = vf_id;
	ss.flags = 0;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_SAVE_VHCA_STATE, &ss)) {
		pr_perror("vfmig: SAVE_VHCA_STATE(pf=%s vf_id=%u)", pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}

	snprintf(out->blob_path, sizeof(out->blob_path), "mlx5_vfmig-pf%s-vf%u.blob", pf_bdf, vf_id);
	if (vfmig_drain_save_fd_to_blob(ss.save_fd, out->blob_path, &out->blob_size)) {
		close(ss.save_fd);
		close(cdev_fd);
		return -1;
	}
	close(ss.save_fd);
	close(cdev_fd);

	pr_info("vfmig: captured pf=%s vf_id=%u vhca_id=%u blob='%s' size=%llu\n", pf_bdf, vf_id, out->vhca_id,
		out->blob_path, (unsigned long long)out->blob_size);
	return 0;
}

/*
 * Dump-side SAVE drain, called from fini(DUMP) on a successful dump.
 *
 * Walks the claimed-VF set (already deduplicated by (pf_bdf, vf_id) at
 * claim time), captures each VF's firmware blob, and appends one
 * Mlx5VfmigStateEntry per VF to mlx5_vfmig.img. SAVE_VHCA_STATE is the
 * most invasive thing the plugin does to the host, so it is deferred to
 * here -- after the rest of the dump has succeeded -- rather than run
 * inline at claim time.
 *
 * Best-effort per VF: a capture/append failure for one VF is logged and
 * skipped so the other VFs still land in the image. fini's return value
 * is dropped by criu, so the pr_err lines are the operator's surface for
 * "which VF didn't make it into the image".
 */
void vfmig_drain_claimed_in_fini(void)
{
	struct vfmig_claimed_vf *c;
	int total = 0, written = 0, failed = 0;

	for (c = vfmig_claimed_head; c; c = c->next) {
		struct vfmig_saved_vf sv;
		struct vfmig_uctx_image_blob uctx_blob;
		struct vfmig_uctx_image_blob *uctx = NULL;
		char cdev_path[PATH_MAX];
		const char *cdev_for_record;
		uint32_t ctxn = 0;

		total++;
		memset(&sv, 0, sizeof(sv));
		if (vfmig_capture_one_vf(c->pf_bdf, c->vf_id, &sv)) {
			pr_err("vfmig: capture failed for pf=%s vf_id=%u; no image record written\n", c->pf_bdf,
			       c->vf_id);
			failed++;
			continue;
		}

		/*
		 * source_cdev_path + ctxn come from the ucontext snapshot
		 * when one was captured (the readlink'd cdev the context
		 * was opened against). For a firmware-only VF (no seed
		 * context) fall back to re-resolving the cdev from the
		 * ibdev; a miss there is not fatal, so use an empty string.
		 */
		if (c->uctx_captured && c->source_cdev_path[0]) {
			cdev_for_record = c->source_cdev_path;
			ctxn = c->ctxn;
		} else {
			if (find_uverbs_cdev_for_ibdev(c->ibdev, cdev_path, sizeof(cdev_path)))
				cdev_path[0] = '\0';
			cdev_for_record = cdev_path;
		}

		if (c->uctx_captured) {
			memset(&uctx_blob, 0, sizeof(uctx_blob));
			if (c->uctx_is_dyn) {
				uctx_blob.dyn_uar_records = c->uctx_dyn_records;
				uctx_blob.dyn_uar_records_len = c->uctx_dyn_n * sizeof(*c->uctx_dyn_records);
			} else {
				uctx_blob.meta = &c->uctx_meta;
				uctx_blob.meta_len = sizeof(c->uctx_meta);
				uctx_blob.uar_table = c->uctx_uar_table;
				uctx_blob.uar_table_len = c->uctx_uar_n * sizeof(*c->uctx_uar_table);
				uctx_blob.bfreg_count = c->uctx_bfreg_count;
				uctx_blob.bfreg_count_len = c->uctx_bfreg_n * sizeof(*c->uctx_bfreg_count);
			}
			uctx_blob.source_devx_uid = c->source_devx_uid;
			uctx_blob.has_source_devx_uid = true;
			uctx = &uctx_blob;
		}

		if (vfmig_append_state_entry(ctxn, c->ibdev, cdev_for_record, c->pf_bdf, c->vf_id, sv.vhca_id,
					     sv.vf_uuid, sv.blob_path, sv.blob_size, uctx)) {
			pr_err("vfmig: failed to append state entry for pf=%s vf_id=%u\n", c->pf_bdf, c->vf_id);
			failed++;
			continue;
		}
		written++;
	}

	if (total)
		pr_info("fini-DUMP drain: claimed_vfs=%d records_written=%d failed=%d\n", total, written, failed);
}
