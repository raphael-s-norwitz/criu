/*
 * vfmig_dump.c
 *
 * Dump-side orchestration for the mlx5 SR-IOV VFMIG plugin.
 *
 * What lives here:
 *
 *   - Three per-dump linked lists with file-scope ownership:
 *     vfmig_saved_vfs   (per-VF SAVE dedup cache),
 *     vfmig_pending_ctxs (per-context queue drained at fini-time),
 *     vfmig_failed_vfs  (SAVE-failure cache so subsequent contexts
 *                       on a wedged VF skip cleanly).
 *
 *   - vfmig_capture_one_vf(): the SAVE_VHCA_STATE orchestrator.
 *     Opens /dev/mlx5_vfmig/<pf>, runs GET_VHCA_ID + SAVE_VHCA_STATE
 *     with KEEP_SUSPENDED, drains the kernel save_fd into a blob
 *     file under criu_get_image_dir() via vf_image.c.
 *
 *   - Per-uobject dump hooks RDMA_DUMP_UOBJ_{PD,CQ,QP}: drive the
 *     mlx5-private QUERY_{PD,CQ,QP} verbs on the holder's uctx fd and
 *     pack each uobject's byte-equal RESTORE_* request blob into the
 *     per-uobj plugin_blob. QUERY_PD supersedes the old NLDEV per-PD
 *     "fw_pdn"/"fw_uid" driver-TLV discovery.
 *
 *   - The two dump hooks: RDMA_DUMP_UVERBS_CONTEXT (queues onto
 *     the pending list) and HANDLE_DEVICE_VMA (claims uverbs-cdev
 *     VMAs belonging to a tracked-mlx5 VF so foreign plugins
 *     don't).
 *
 *   - vfmig_drain_pending_in_fini(): walks the pending queue at
 *     fini(DUMP), runs SAVE per unique VF (via vfmig_capture_one_vf),
 *     emits one Mlx5VfmigStateEntry per pending context (via
 *     vfmig_append_state_entry from vf_image.c).
 *
 * Cross-file API surface (declared in vfmig_internal.h):
 *   the vfmig_*_clear() entries called by plugin.c init/fini, the
 *   drain entry called by plugin.c fini, and the two hook entries
 *   referenced by plugin.c's CR_PLUGIN_REGISTER_HOOK macros.
 *
 * vfmig_active is read here (handle_device_vma's cheap-decline
 * gate) but defined in plugin.c.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/mlx5_vfmig.h>

#include "criu-log.h"
#include "criu-plugin.h"
#include "rdma_netlink.h"

#include "images/rdma_criu.pb-c.h"
#include "images/mlx5_vfmig.pb-c.h"

#include "mlx5_uapi.h"
#include "vfmig_internal.h"

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_mlx5_vfmig_plugin: "

/*
 * Per-dump deduplication cache.
 *
 * The mlx5 firmware SAVE_VHCA_STATE captures one blob per VF, not
 * per uverbs context. A process may legitimately hold several
 * contexts on the same VF (e.g. one per worker thread); without
 * deduplication we'd issue SAVE_VHCA_STATE multiple times against
 * the same VF and produce N copies of the same blob in the image
 * directory. Worse, the per-VF kernel SAVE session is exclusive
 * (-EBUSY on the second open), so every duplicate would fail.
 *
 * The cache is process-local (CRIU's lifetime) and is reset by
 * init() so a CRIU re-invocation starts fresh. Each entry remembers
 * the (pf_bdf, vf_id) tuple that already had its blob captured
 * during this dump, plus the per-VF state that the per-context
 * record needs (vhca_id, blob path, blob size). Subsequent contexts
 * on the same VF reuse this state.
 */
struct vfmig_saved_vf {
	struct vfmig_saved_vf *next;
	char pf_bdf[64];
	uint32_t vf_id;
	uint32_t vhca_id;
	/*
	 * Orchestrator-stamped per-VF UUID (KS7.3), captured at
	 * SAVE time via MLX5_VFMIG_IOC_QUERY_VF on the source PF
	 * cdev. Persisted into mlx5_vfmig_state_entry.vf_uuid so
	 * the destination CRIU plugin can iterate VFs across
	 * eligible PFs and bind this saved-state record to
	 * whichever VF QUERY_VF reports a matching UUID. A VF
	 * whose UUID comes back all-zeros at SAVE time is
	 * rejected up front by vfmig_capture_one_vf() -- the
	 * orchestrator is expected to have stamped a UUID onto
	 * the VF before workload bind, and a missing UUID would
	 * make the dump unrestorable on identity grounds.
	 */
	uint8_t vf_uuid[16];
	char blob_path[PATH_MAX];
	uint64_t blob_size;
};
static struct vfmig_saved_vf *vfmig_saved_head = NULL;

static struct vfmig_saved_vf *
vfmig_saved_lookup(const char *pf_bdf, uint32_t vf_id)
{
	struct vfmig_saved_vf *p;

	for (p = vfmig_saved_head; p; p = p->next)
		if (p->vf_id == vf_id && !strcmp(p->pf_bdf, pf_bdf))
			return p;
	return NULL;
}

void vfmig_saved_clear(void)
{
	struct vfmig_saved_vf *p, *n;

	for (p = vfmig_saved_head; p; p = n) {
		n = p->next;
		free(p);
	}
	vfmig_saved_head = NULL;
}

/*
 * Per-context dump-time queue.
 *
 * DUMP_UVERBS_CONTEXT runs once per uverbs cdev being dumped, while
 * SAVE_VHCA_STATE is per-VF firmware work and is the most invasive
 * thing this plugin does to the host. Decouple the two by having
 * the per-context hook just record (ctxn, ibdev, pf_bdf, vf_id)
 * onto this queue, and let fini(DUMP) drain it -- the kernel SAVE
 * is then the very last thing CRIU asks for, after every other
 * piece of dump work has either succeeded or surfaced a failure
 * the operator can act on without ever having touched the VF's
 * firmware. (See the cover-letter discussion of "fail early" vs.
 * "defer the most invasive thing".)
 */
struct vfmig_pending_ctx {
	struct vfmig_pending_ctx *next;
	uint32_t ctxn;
	char ibdev[64];
	char pf_bdf[64];
	uint32_t vf_id;
	/*
	 * Source-side cdev path the dumpee opened (resolved at dump
	 * time via readlink /proc/self/fd/<lfd>). Persisted into
	 * mlx5_vfmig_state_entry.source_cdev_path so the restore
	 * side's UPDATE_VMA_MAP can dispatch by source path.
	 */
	char source_cdev_path[PATH_MAX];

	/*
	 * VFMIG ucontext snapshot, captured during the per-context
	 * dump hook from the workload's lfd. The snapshot is owned by
	 * the pending entry; freed by vfmig_pending_clear(). Persisted
	 * into the proto entry by vfmig_append_state_entry() at fini-
	 * time.
	 *
	 * EXACTLY ONE of the static-mode (uctx_meta + uctx_uar_table +
	 * uctx_bfreg_count) or dyn-mode (uctx_dyn_records) slot blocks
	 * is populated, depending on which kernel verb succeeded:
	 *
	 *   - lib_uar_dyn=false ucontext: vfmig_snapshot_uctx() succeeds
	 *     via QUERY_UCONTEXT; uctx_uar_table != NULL, uctx_dyn_records
	 *     == NULL.
	 *   - lib_uar_dyn=true ucontext: QUERY_UCONTEXT returns
	 *     EOPNOTSUPP and the dump hook falls back to
	 *     vfmig_snapshot_dyn_uars() / QUERY_DYN_UARS;
	 *     uctx_dyn_records != NULL, uctx_uar_table == NULL.
	 *     uctx_meta is left zeroed -- the dyn path's RESTORE doesn't
	 *     need a meta cross-check (the kernel handler validates by
	 *     ucontext mode, not by per-field equality), and the
	 *     destination GET_CONTEXT call on restore uses libmlx5-
	 *     default (lib_caps, total_bfregs, ...) instead of
	 *     mirroring the source.
	 */
	struct mlx5_ib_vfmig_ucontext_meta_local uctx_meta;
	uint32_t *uctx_uar_table;
	size_t uctx_uar_n;
	uint32_t *uctx_bfreg_count;
	size_t uctx_bfreg_n;

	struct mlx5_ib_vfmig_dyn_uar_record_local *uctx_dyn_records;
	size_t uctx_dyn_n;

	/*
	 * Per-ucontext source devx_uid (mlx5_ib_ucontext.devx_uid as
	 * observed at dump time). 0 = non-DEVX ucontext, non-zero =
	 * DEVX-opted-in (libmlx5 default lib_uar_dyn=true silently
	 * sets this even with no explicit DEVX call). Sourced by the
	 * dump hook from QUERY_UCONTEXT's meta.devx_uid (kernel commit
	 * c659ab66483d); the old per-ucontext NLDEV PD-walk over each
	 * PD's "fw_uid" driver TLV was removed when the kernel dropped
	 * those TLVs. The per-PD uid is now available via QUERY_PD's
	 * RESP_UID (dump-side diagnostic only).
	 *
	 * Image-only metadata: persisted into
	 * mlx5_vfmig_state_entry.source_devx_uid but NOT consumed at
	 * restore -- the v0 restore path always opens the destination
	 * ucontext WITHOUT DEVX (adopt_devx_uid forced to 0).
	 */
	uint32_t source_devx_uid;
};
static struct vfmig_pending_ctx *vfmig_pending_head = NULL;

/*
 * Either-or factory: pass static-mode args (uctx_meta + uar table +
 * bfreg counts) and leave dyn args NULL, or pass dyn args (records +
 * count) and leave the static args NULL/zero. The dump hook decides
 * which path the source ucontext was in (QUERY_UCONTEXT vs
 * QUERY_DYN_UARS) and calls accordingly. Mixed input is a programming
 * error and is silently merged here -- the dump hook is the single
 * caller, so we don't bother defending against it at runtime.
 */
static int vfmig_pending_enqueue(uint32_t ctxn, const char *ibdev,
				 const char *pf_bdf, uint32_t vf_id,
				 const char *source_cdev_path,
				 const struct mlx5_ib_vfmig_ucontext_meta_local *uctx_meta,
				 uint32_t *uctx_uar_table, size_t uctx_uar_n,
				 uint32_t *uctx_bfreg_count, size_t uctx_bfreg_n,
				 struct mlx5_ib_vfmig_dyn_uar_record_local *uctx_dyn_records,
				 size_t uctx_dyn_n,
				 uint32_t source_devx_uid)
{
	struct vfmig_pending_ctx *p = calloc(1, sizeof(*p));

	if (!p)
		return -1;
	p->ctxn = ctxn;
	snprintf(p->ibdev, sizeof(p->ibdev), "%s", ibdev);
	snprintf(p->pf_bdf, sizeof(p->pf_bdf), "%s", pf_bdf);
	p->vf_id = vf_id;
	snprintf(p->source_cdev_path, sizeof(p->source_cdev_path),
		 "%s", source_cdev_path);
	if (uctx_meta)
		p->uctx_meta = *uctx_meta;
	p->uctx_uar_table = uctx_uar_table;
	p->uctx_uar_n = uctx_uar_n;
	p->uctx_bfreg_count = uctx_bfreg_count;
	p->uctx_bfreg_n = uctx_bfreg_n;
	p->uctx_dyn_records = uctx_dyn_records;
	p->uctx_dyn_n = uctx_dyn_n;
	p->source_devx_uid = source_devx_uid;
	p->next = vfmig_pending_head;
	vfmig_pending_head = p;
	return 0;
}

void vfmig_pending_clear(void)
{
	struct vfmig_pending_ctx *p, *n;

	for (p = vfmig_pending_head; p; p = n) {
		n = p->next;
		free(p->uctx_uar_table);
		free(p->uctx_bfreg_count);
		free(p->uctx_dyn_records);
		free(p);
	}
	vfmig_pending_head = NULL;
}

/*
 * Per-VF SAVE-failure cache.
 *
 * fini(DUMP) iterates the pending queue in arbitrary order. If
 * SAVE_VHCA_STATE fails for a given (pf_bdf, vf_id), every other
 * pending context against the same VF must be dropped too -- the
 * blob doesn't exist, so emitting a state entry referencing it
 * would leave the image internally inconsistent. Stash failed
 * tuples here so subsequent contexts on the same VF skip cleanly
 * without retrying the (now expensive and wedging) SAVE.
 */
struct vfmig_failed_vf {
	struct vfmig_failed_vf *next;
	char pf_bdf[64];
	uint32_t vf_id;
};
static struct vfmig_failed_vf *vfmig_failed_head = NULL;

static bool vfmig_failed_lookup(const char *pf_bdf, uint32_t vf_id)
{
	struct vfmig_failed_vf *p;

	for (p = vfmig_failed_head; p; p = p->next)
		if (p->vf_id == vf_id && !strcmp(p->pf_bdf, pf_bdf))
			return true;
	return false;
}

static void vfmig_failed_mark(const char *pf_bdf, uint32_t vf_id)
{
	struct vfmig_failed_vf *p = calloc(1, sizeof(*p));

	if (!p)
		return; /* best-effort; worst case is a redundant SAVE retry */
	snprintf(p->pf_bdf, sizeof(p->pf_bdf), "%s", pf_bdf);
	p->vf_id = vf_id;
	p->next = vfmig_failed_head;
	vfmig_failed_head = p;
}

void vfmig_failed_clear(void)
{
	struct vfmig_failed_vf *p, *n;

	for (p = vfmig_failed_head; p; p = n) {
		n = p->next;
		free(p);
	}
	vfmig_failed_head = NULL;
}

/*
 * Claimed-VF cache (snapshot-ordering pause input set).
 *
 * The dump-time coverage check (rdma_check_dump_coverage(), cr-dump.c)
 * runs the per-context claim arbitration over the whole snapshot tree
 * BEFORE CHECKPOINT_DEVICES fires -- and our CLAIM hook already
 * resolves each context's (pf_bdf, vf_id) and confirms QUERY_VF.tracked.
 * Rather than have CHECKPOINT_DEVICES re-walk /proc/<pid>/fd and redo
 * that sysfs+ioctl resolution, the CLAIM hook records every VF it wins
 * here; the early hook just parks this set. Deduped by (pf_bdf, vf_id),
 * since a VF can back several contexts across several pids.
 */
struct vfmig_claimed_vf {
	struct vfmig_claimed_vf *next;
	char ibdev[64];
	char pf_bdf[64];
	uint32_t vf_id;
};
static struct vfmig_claimed_vf *vfmig_claimed_head = NULL;

void vfmig_claimed_add(const char *ibdev, const char *pf_bdf, uint32_t vf_id)
{
	struct vfmig_claimed_vf *p;

	for (p = vfmig_claimed_head; p; p = p->next)
		if (p->vf_id == vf_id && !strcmp(p->pf_bdf, pf_bdf))
			return; /* already recorded */

	p = calloc(1, sizeof(*p));
	if (!p) {
		/*
		 * Best-effort: a missed cache entry means this VF won't be
		 * parked at CHECKPOINT_DEVICES and SAVE will fall back to
		 * self-suspend (with a loud warning). Not worth failing CLAIM.
		 */
		pr_warn("vfmig: OOM caching claimed pf=%s vf_id=%u; it may not "
			"be parked before the memory dump\n", pf_bdf, vf_id);
		return;
	}
	snprintf(p->ibdev, sizeof(p->ibdev), "%s", ibdev);
	snprintf(p->pf_bdf, sizeof(p->pf_bdf), "%s", pf_bdf);
	p->vf_id = vf_id;
	p->next = vfmig_claimed_head;
	vfmig_claimed_head = p;
}

void vfmig_claimed_clear(void)
{
	struct vfmig_claimed_vf *p, *n;

	for (p = vfmig_claimed_head; p; p = n) {
		n = p->next;
		free(p);
	}
	vfmig_claimed_head = NULL;
}

/*
 * Snapshot-ordering pause set (design/snapshot_ordering_pause_capture.md
 * Part A).
 *
 * The CHECKPOINT_DEVICES hook parks every tracked VF backing the
 * dumpee tree by issuing MLX5_VFMIG_IOC_SUSPEND_VHCA *before* CRIU
 * copies the dumpee's memory, so a peer can't DMA RDMA WRITE/SEND
 * payload into pinned MR pages mid-snapshot. This list remembers which
 * (pf_bdf, vf_id) pairs this dump parked, so:
 *   - we suspend each VF exactly once (a VF can back several contexts
 *     across several pids), and
 *   - fini(DUMP) resumes them all (vfmig_resume_suspended_vfs) -- the
 *     snapshot is complete by then, so the source is unconditionally
 *     brought back to runnable. We resume even on a successful kill
 *     dump: CRIU does not own VF teardown, and leaving a VF in STOP
 *     across the orchestrator's sriov_numvfs=0 makes teardown walk a
 *     dead command ring. A live-destination migration that wants the
 *     source left parked is a future explicit signal, not the default.
 * The kernel SAVE_VHCA_STATE is suspend-aware: for a VF already in this
 * set it skips its self-suspend and the resume-on-close, leaving the
 * resume to us. The kernel also force-resumes any still-parked VF at
 * SR-IOV teardown, so a crashed dumper can't strand one.
 */
struct vfmig_suspended_vf {
	struct vfmig_suspended_vf *next;
	char ibdev[64];
	char pf_bdf[64];
	uint32_t vf_id;
};
static struct vfmig_suspended_vf *vfmig_suspended_head = NULL;

static struct vfmig_suspended_vf *
vfmig_suspended_lookup(const char *pf_bdf, uint32_t vf_id)
{
	struct vfmig_suspended_vf *p;

	for (p = vfmig_suspended_head; p; p = p->next)
		if (p->vf_id == vf_id && !strcmp(p->pf_bdf, pf_bdf))
			return p;
	return NULL;
}

static int vfmig_suspended_add(const char *ibdev, const char *pf_bdf,
			       uint32_t vf_id)
{
	struct vfmig_suspended_vf *p = calloc(1, sizeof(*p));

	if (!p)
		return -1;
	snprintf(p->ibdev, sizeof(p->ibdev), "%s", ibdev);
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

/* Issue RESUME_VHCA on one parked VF (best-effort). */
static int vfmig_resume_one_vf(const char *pf_bdf, uint32_t vf_id)
{
	struct mlx5_vfmig_resume_vhca rv;
	char cdev_path[PATH_MAX];
	int fd, rc;

	snprintf(cdev_path, sizeof(cdev_path), "%s/%s",
		 MLX5_VFMIG_DEV_DIR, pf_bdf);
	fd = open(cdev_path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("vfmig: resume: open(%s)", cdev_path);
		return -1;
	}
	memset(&rv, 0, sizeof(rv));
	rv.vf_id = vf_id;
	rc = ioctl(fd, MLX5_VFMIG_IOC_RESUME_VHCA, &rv);
	close(fd);
	if (rc) {
		pr_perror("vfmig: RESUME_VHCA(pf=%s vf_id=%u)", pf_bdf, vf_id);
		return -1;
	}
	return 0;
}

/* Raw SUSPEND_VHCA ioctl on one VF (no parked-set bookkeeping). */
static int vfmig_suspend_vhca_ioctl(const char *pf_bdf, uint32_t vf_id)
{
	struct mlx5_vfmig_suspend_vhca sv;
	char cdev_path[PATH_MAX];
	int fd, rc;

	snprintf(cdev_path, sizeof(cdev_path), "%s/%s",
		 MLX5_VFMIG_DEV_DIR, pf_bdf);
	fd = open(cdev_path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("vfmig: suspend: open(%s)", cdev_path);
		return -1;
	}
	memset(&sv, 0, sizeof(sv));
	sv.vf_id = vf_id;
	rc = ioctl(fd, MLX5_VFMIG_IOC_SUSPEND_VHCA, &sv);
	close(fd);
	if (rc) {
		pr_perror("vfmig: SUSPEND_VHCA(pf=%s vf_id=%u)", pf_bdf, vf_id);
		return -1;
	}
	return 0;
}

/* Issue SUSPEND_VHCA on one VF and record it in the parked set. */
static int vfmig_suspend_one_vf(const char *ibdev, const char *pf_bdf,
				uint32_t vf_id)
{
	if (vfmig_suspend_vhca_ioctl(pf_bdf, vf_id))
		return -1;

	if (vfmig_suspended_add(ibdev, pf_bdf, vf_id)) {
		/*
		 * We parked the VF but can't remember it -> fini wouldn't
		 * resume it. Roll the suspend back and fail the dump rather
		 * than strand the source (the kernel's teardown force-resume
		 * is only a last-resort net for a crashed dumper).
		 */
		pr_err("vfmig: checkpoint: OOM tracking suspended pf=%s "
		       "vf_id=%u; rolling back suspend and failing dump\n",
		       pf_bdf, vf_id);
		(void)vfmig_resume_one_vf(pf_bdf, vf_id);
		return -1;
	}

	pr_info("vfmig: suspended pf=%s vf_id=%u datapath "
		"(snapshot-ordering pause)\n", pf_bdf, vf_id);
	return 0;
}

/*
 * CHECKPOINT_DEVICES hook -- the "pause" half of the stop-and-copy
 * snapshot-ordering fix. Runs after the tree is frozen and after the
 * RDMA coverage check (which already claimed every tree context and
 * populated the claimed-VF cache), but BEFORE the per-task memory-dump
 * loop. We park every claimed VF via SUSPEND_VHCA so the firmware
 * datapath is quiesced before any MR/recv-buffer page is copied into
 * the image.
 *
 * The hook is invoked once per alive pstree item, but the claimed set
 * is tree-wide, so we park the whole set on the first call; the parked
 * set dedups subsequent calls (and SUSPEND_VHCA is itself idempotent).
 * @pid is unused -- the claim-time cache already scoped the VFs to this
 * snapshot tree.
 *
 * Returns 0 on success (including "nothing to do"), -ENOTSUP when the
 * plugin is inactive (lets CRIU's hook chain treat us as absent), or -1
 * if a VF we must park fails to suspend (the dump cannot honor its
 * memory-consistency guarantee, so fail loudly rather than silently
 * snapshot a live datapath).
 */
int rdma_mlx5_vfmig_plugin_checkpoint_devices(int pid)
{
	struct vfmig_claimed_vf *c;
	int suspended_now = 0;

	(void)pid;

	if (!vfmig_active)
		return -ENOTSUP;

	for (c = vfmig_claimed_head; c; c = c->next) {
		if (vfmig_suspended_lookup(c->pf_bdf, c->vf_id))
			continue;
		if (vfmig_suspend_one_vf(c->ibdev, c->pf_bdf, c->vf_id))
			return -1;
		suspended_now++;
	}

	if (suspended_now)
		pr_info("vfmig: checkpoint: parked %d VF datapath(s) before "
			"memory dump\n", suspended_now);
	return 0;
}

/*
 * Resume (or deliberately leave parked) every VF this dump suspended.
 * Called from fini(DUMP). @keep_suspended leaves the source parked
 * rather than resuming it; today callers always pass false (the
 * snapshot is complete, so resuming is unconditionally correct -- see
 * rdma_mlx5_vfmig_plugin_fini). The parameter is retained for the
 * future live-destination migration hand-off, the only case that wants
 * the source left quiesced. Best-effort: a failed RESUME is logged but
 * we still drop the tracking entry (the kernel's SR-IOV-teardown
 * force-resume is the backstop). Frees the parked set.
 */
void vfmig_resume_suspended_vfs(bool keep_suspended)
{
	struct vfmig_suspended_vf *p, *n;
	int resumed = 0, kept = 0, failed = 0;

	for (p = vfmig_suspended_head; p; p = n) {
		n = p->next;
		if (keep_suspended) {
			kept++;
		} else if (vfmig_resume_one_vf(p->pf_bdf, p->vf_id)) {
			failed++;
		} else {
			pr_info("vfmig: resumed pf=%s vf_id=%u datapath\n",
				p->pf_bdf, p->vf_id);
			resumed++;
		}
		free(p);
	}
	vfmig_suspended_head = NULL;

	if (resumed || kept || failed)
		pr_info("fini-DUMP resume: resumed=%d left_parked=%d "
			"resume_failed=%d\n", resumed, kept, failed);
}

/*
 * Capture the firmware blob for one (pf_bdf, vf_id) pair.
 *
 * Steps (matching the source-side lifecycle in the kernel UAPI doc
 * on MLX5_VFMIG_IOC_SAVE_VHCA_STATE):
 *   1. open /dev/mlx5_vfmig/<pf_bdf>
 *   2. ioctl MLX5_VFMIG_IOC_GET_VHCA_ID    (record vhca_id for diags)
 *   3. ioctl MLX5_VFMIG_IOC_QUERY_VF       (read the orchestrator-
 *      stamped vf_uuid, KS7.3). Hard-refuse the dump if it comes
 *      back all-zeros: that means the orchestrator has not stamped
 *      an identity onto this VF, and the resulting image would have
 *      no way to bind to a destination VF on restore. We perform
 *      this check BEFORE SAVE_VHCA_STATE so the (expensive,
 *      VF-suspending) save is never run for a VF the dump is going
 *      to refuse anyway.
 *   4. ioctl MLX5_VFMIG_IOC_SAVE_VHCA_STATE { vf_id,
 *        flags = MLX5_VFMIG_SAVE_FLAG_KEEP_SUSPENDED }
 *      -> kernel quiesces the VF (SUSPEND_VHCA INITIATOR/RESPONDER),
 *         allocates DMA-mapped image pages, runs SAVE_VHCA_STATE,
 *         returns a read-only anon-inode fd.
 *   5. read the save_fd to EOF, write into the image dir.
 *   6. close(save_fd) WITHOUT issuing RESUME -- KEEP_SUSPENDED told
 *      the kernel to leave the source VF stopped; the orchestrator
 *      tears the VF down before any resume on the source. (See
 *      cover note: post-SAVE the VF is intentionally not runnable
 *      on the source side.)
 *
 * On success the @out fields are populated and the blob file
 * exists in the image directory; on failure the file may exist
 * partially-written (we don't unlink it; an aborted dump will
 * abort the image directory wholesale).
 */
static int vfmig_capture_one_vf(const char *pf_bdf, uint32_t vf_id,
				struct vfmig_saved_vf *out)
{
	struct mlx5_vfmig_get_vhca_id gv;
	struct mlx5_vfmig_query_vf qv;
	struct mlx5_vfmig_save_state ss;
	uint8_t zero_uuid[16] = { 0 };
	char cdev_path[PATH_MAX];
	int cdev_fd;

	snprintf(cdev_path, sizeof(cdev_path), "%s/%s",
		 MLX5_VFMIG_DEV_DIR, pf_bdf);
	cdev_fd = open(cdev_path, O_RDWR | O_CLOEXEC);
	if (cdev_fd < 0) {
		pr_perror("vfmig: open(%s)", cdev_path);
		return -1;
	}

	memset(&gv, 0, sizeof(gv));
	gv.vf_id = vf_id;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_GET_VHCA_ID, &gv)) {
		pr_perror("vfmig: GET_VHCA_ID(pf=%s, vf_id=%u)",
			  pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}
	out->vhca_id = gv.vhca_id;

	/*
	 * KS7.3 capture. Read the orchestrator-stamped vf_uuid and
	 * hard-refuse on all-zeros. The error message names the
	 * orchestrator-side step the operator is expected to have
	 * run (MLX5_VFMIG_IOC_SET_VF_UUID on this PF cdev with the
	 * desired 16-byte identity), so a harness that hits this is
	 * pointed at the lockstep work it owes us.
	 *
	 * Done BEFORE SAVE_VHCA_STATE: SAVE suspends the source VF
	 * (and with KEEP_SUSPENDED leaves it parked), so refusing
	 * after the save would mean we paid the most invasive cost
	 * the plugin has only to throw away the result.
	 */
	memset(&qv, 0, sizeof(qv));
	qv.vf_id = vf_id;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_QUERY_VF, &qv)) {
		pr_perror("vfmig: QUERY_VF(pf=%s, vf_id=%u)",
			  pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}
	if (!memcmp(qv.vf_uuid, zero_uuid, sizeof(zero_uuid))) {
		pr_err("vfmig: refusing to dump pf=%s vf_id=%u: "
		       "orchestrator has not stamped a vf_uuid on this VF "
		       "(QUERY_VF.vf_uuid is all-zeros). The orchestrator "
		       "must call MLX5_VFMIG_IOC_SET_VF_UUID with a stable "
		       "16-byte identity on this PF cdev before the "
		       "workload binds the VF, so CRIU's restore path can "
		       "match the dumped image to a destination VF by "
		       "UUID. See KS7.3 in tools/testing/criu_rdma/design/"
		       "vf_prerestore_split.md for the contract.\n",
		       pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}
	memcpy(out->vf_uuid, qv.vf_uuid, sizeof(out->vf_uuid));

	memset(&ss, 0, sizeof(ss));
	ss.vf_id = vf_id;

	/*
	 * SAVE flag policy. Who resumes the source VF depends only on
	 * whether it was parked at CHECKPOINT_DEVICES:
	 *
	 *   - parked at CHECKPOINT_DEVICES (the normal snapshot-ordering
	 *     path): KEEP_SUSPENDED so SAVE doesn't resume on close -- the
	 *     VF is in fini's tracked set and fini's
	 *     vfmig_resume_suspended_vfs() owns the (unconditional) resume.
	 *   - not parked (fallback: early hook didn't run / fd enumeration
	 *     missed it): flags=0 so the kernel resumes the VF on save_fd
	 *     close, since it is NOT in fini's set and nothing else will.
	 *
	 * Either way the source ends up resumed. We do not leave a VF in
	 * STOP across a dump: CRIU does not own VF teardown, and a parked
	 * VF makes the orchestrator's sriov_numvfs=0 walk a dead command
	 * ring (~15-25 min of 60s timeouts; see snapshot_ordering_pause_
	 * capture.md A.4). Leaving the source quiesced for a live-
	 * destination migration hand-off is a future explicit signal,
	 * handled in fini, not here.
	 */
	if (vfmig_suspended_lookup(pf_bdf, vf_id)) {
		/*
		 * Snapshot-ordering happy path: CHECKPOINT_DEVICES already
		 * parked this VF before the memory dump. Pass KEEP_SUSPENDED
		 * so SAVE doesn't resume on close -- the source resume is
		 * owned by fini's vfmig_resume_suspended_vfs(). (The kernel
		 * also infers this from its persistent vfmig_suspended bit
		 * via owns_suspend, so SAVE skips its self-suspend pair; we
		 * set the flag too so the intent is explicit and correct even
		 * against an older suspend-unaware kernel.)
		 */
		ss.flags = MLX5_VFMIG_SAVE_FLAG_KEEP_SUSPENDED;
	} else {
		/*
		 * Fallback: this VF was NOT pre-suspended at CHECKPOINT_
		 * DEVICES (e.g. the early hook didn't run, or fd enumeration
		 * missed it), so it is not in fini's resume set. SAVE will
		 * self-suspend now -- which means the dumpee's memory for
		 * this VF was copied while its datapath was still live (the
		 * stop-and-copy window this fix exists to close). Leave
		 * flags=0 so the kernel resumes this VF on save_fd close,
		 * since nothing else will. Warn either way.
		 */
		pr_warn("vfmig: pf=%s vf_id=%u not parked at CHECKPOINT_DEVICES; "
			"SAVE self-suspends + resumes on close -- memory "
			"snapshot for this VF may be inconsistent with a live "
			"peer\n", pf_bdf, vf_id);
	}

	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_SAVE_VHCA_STATE, &ss)) {
		pr_perror("vfmig: SAVE_VHCA_STATE(pf=%s, vf_id=%u, "
			  "flags=%#x)", pf_bdf, vf_id, ss.flags);
		close(cdev_fd);
		return -1;
	}

	snprintf(out->blob_path, sizeof(out->blob_path),
		 "mlx5_vfmig-pf%s-vf%u.blob", pf_bdf, vf_id);

	if (vfmig_drain_save_fd_to_blob(ss.save_fd, out->blob_path,
					&out->blob_size)) {
		close(ss.save_fd);
		close(cdev_fd);
		return -1;
	}

	close(ss.save_fd);
	close(cdev_fd);

	pr_info("vfmig: captured pf=%s vf_id=%u vhca_id=%u "
		"vf_uuid=%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
		"%02x%02x%02x%02x%02x%02x "
		"blob='%s' size=%llu (flags=%#x%s)\n",
		pf_bdf, vf_id, out->vhca_id,
		out->vf_uuid[0],  out->vf_uuid[1],  out->vf_uuid[2],
		out->vf_uuid[3],  out->vf_uuid[4],  out->vf_uuid[5],
		out->vf_uuid[6],  out->vf_uuid[7],  out->vf_uuid[8],
		out->vf_uuid[9],  out->vf_uuid[10], out->vf_uuid[11],
		out->vf_uuid[12], out->vf_uuid[13], out->vf_uuid[14],
		out->vf_uuid[15],
		out->blob_path,
		(unsigned long long)out->blob_size, ss.flags,
		(ss.flags & MLX5_VFMIG_SAVE_FLAG_KEEP_SUSPENDED)
			? "" : ", source-resumed-after-save");
	return 0;
}

/*
 * Per-context dump hook (CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT).
 *
 * Runs after CLAIM has named us as the winning plugin for this
 * uverbs context. The hook used to fire SAVE_VHCA_STATE inline,
 * but SAVE is the most invasive thing this plugin does to the
 * host -- it suspends the source VF's firmware and (with
 * KEEP_SUSPENDED) leaves it parked. We now defer the actual
 * SAVE to fini(DUMP), so it runs only after every other piece
 * of dump work has either succeeded or surfaced a failure the
 * operator can act on without ever having touched the VF's
 * firmware.
 *
 * The hook's job is therefore reduced to:
 *
 *   1. Resolve ibdev -> (pf_bdf, vf_id). Same sysfs walk CLAIM
 *      already did; we redo it here rather than threading the
 *      resolved tuple through the hook ABI. The cost is two
 *      readlink()s and a small directory scan, negligible.
 *
 *   2. Enqueue a (ctxn, ibdev, pf_bdf, vf_id) record onto the
 *      pending queue. fini(DUMP) walks this queue, dedups by
 *      (pf_bdf, vf_id), runs SAVE_VHCA_STATE per unique VF, and
 *      emits one Mlx5VfmigStateEntry per pending context. (See
 *      vfmig_drain_pending_in_fini below.)
 *
 * @lfd and @pid are unused for v0 (KEEP_SUSPENDED leaves the VF
 * suspended without consulting the source process; we don't need
 * an open fd against the cdev for SAVE). They remain in the
 * hook ABI so future plugins that do need them have them.
 */
/*
 * Per-ucontext source devx_uid is sourced from QUERY_UCONTEXT's
 * meta.devx_uid (kernel commit c659ab66483d), captured below by
 * vfmig_snapshot_uctx(). The earlier NLDEV PD-walk resolver (reading
 * each PD's "fw_uid" driver TLV) was removed when the kernel dropped
 * those TLVs from fill_res_pd_entry; the per-PD uid is now available
 * via MLX5_IB_METHOD_VFMIG_QUERY_PD's RESP_UID (dump-side diagnostic
 * only). source_devx_uid is image-only metadata -- the restore path
 * always opens the destination ucontext WITHOUT DEVX (adopt_devx_uid
 * = 0) under the v0 contract -- so the static-path meta.devx_uid is a
 * sufficient source; the dyn-UAR path leaves it 0, which is benign
 * because dyn/DEVX QP dumps are refused by the per-QP dump hook.
 */

int rdma_mlx5_vfmig_plugin_dump_uverbs_context(const char *ibdev,
						      uint32_t kernel_driver_id,
						      uint32_t ctxn,
						      int lfd, pid_t pid)
{
	char pf_bdf[64], proc_path[64], src_cdev[PATH_MAX];
	uint32_t vf_id;
	ssize_t n;

	(void)kernel_driver_id;
	(void)pid;

	if (vfmig_resolve_pf_vf(ibdev, pf_bdf, sizeof(pf_bdf), &vf_id))
		return -1;

	/*
	 * Capture the source-side cdev path the dumpee opened. The
	 * lfd we get here is criu's own dup() of the dumpee's fd, so
	 * /proc/self/fd/<lfd> resolves to the same kernel struct
	 * file backing path -- e.g. "/dev/infiniband/uverbs2". This
	 * is the join key the restore-side UPDATE_VMA_MAP hook
	 * receives from CRIU (CRIU records reg_file_entry.name
	 * verbatim from the dumpee's struct file, and replays that
	 * string as @path on UPDATE_VMA_MAP). Without it we'd have
	 * to walk every Mlx5VfmigStateEntry per VMA on restore to
	 * find a match.
	 */
	snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", lfd);
	n = readlink(proc_path, src_cdev, sizeof(src_cdev) - 1);
	if (n <= 0) {
		pr_perror("vfmig: readlink(%s) for source cdev path",
			  proc_path);
		return -1;
	}
	src_cdev[n] = '\0';

	/*
	 * Snapshot the workload's ucontext UAR table + bfreg counts +
	 * meta now, while the workload is suspended and the lfd
	 * references the live source ucontext. The snapshot is
	 * captured in user memory, written into the image at fini
	 * time, and replayed on the restored destination ucontext via
	 * RESTORE_UCONTEXT (post-LOAD_VHCA_STATE) -- see the
	 * mlx5_vfmig_state_entry.uctx_* doc in
	 * images/mlx5_vfmig.proto for the wire-format rationale.
	 *
	 * Hard fail on QUERY error: a missing snapshot would leave
	 * the image unrestorable (the destination's GET_CONTEXT
	 * after LOAD_VHCA_STATE EINVALs without VFMIG_RESTORE +
	 * RESTORE_UCONTEXT). Better to abort here than to write a
	 * silently-broken image. v0 also enforces "all bfreg counts
	 * must be zero" (no live QPs / dyn UARs) on the kernel side
	 * -- snapshotting non-zero counts would still serialize
	 * cleanly here, and the kernel's RESTORE_UCONTEXT handler is
	 * the one that rejects the restore.
	 */
	/*
	 * Snapshot the source ucontext. Try the static-UAR path first
	 * (QUERY_UCONTEXT). On -EOPNOTSUPP, the source ran in libmlx5's
	 * default lib_uar_dyn=true mode -- fall back to the dyn-UAR
	 * verb (QUERY_DYN_UARS). The two paths are mutually exclusive
	 * by kernel construction (each rejects the other ucontext mode),
	 * so exactly one will succeed.
	 *
	 * Hard fail on any other QUERY error: a missing snapshot would
	 * leave the image unrestorable -- the destination's GET_CONTEXT
	 * after LOAD_VHCA_STATE EINVALs without VFMIG_RESTORE +
	 * RESTORE_{UCONTEXT,DYN_UARS}. Better to abort the dump than to
	 * write a silently-broken image.
	 */
	{
		struct mlx5_ib_vfmig_ucontext_meta_local uctx_meta = {};
		uint32_t *uctx_uar = NULL, *uctx_cnt = NULL;
		size_t uctx_uar_n = 0, uctx_cnt_n = 0;
		struct mlx5_ib_vfmig_dyn_uar_record_local *uctx_dyn = NULL;
		size_t uctx_dyn_n = 0;
		uint32_t source_devx_uid = 0;
		int rc;

		rc = vfmig_snapshot_uctx(lfd, &uctx_meta,
					 &uctx_uar, &uctx_uar_n,
					 &uctx_cnt, &uctx_cnt_n);
		if (rc == -EOPNOTSUPP) {
			pr_info("vfmig: ctxn=%u: static QUERY_UCONTEXT "
				"returned EOPNOTSUPP (lib_uar_dyn=true "
				"ucontext) -- falling back to "
				"QUERY_DYN_UARS\n", ctxn);

			rc = vfmig_snapshot_dyn_uars(lfd, &uctx_dyn,
						     &uctx_dyn_n);
			if (rc) {
				pr_err("vfmig: QUERY_DYN_UARS(ctxn=%u, "
				       "ibdev=%s) failed: %d (%s)\n",
				       ctxn, ibdev, rc, strerror(-rc));
				return -1;
			}
			pr_info("vfmig: snapshotted ctxn=%u (dyn-UAR): "
				"%zu UAR uobject record(s)\n",
				ctxn, uctx_dyn_n);
		} else if (rc) {
			pr_err("vfmig: QUERY_UCONTEXT(ctxn=%u, ibdev=%s) "
			       "failed: %d (%s)\n", ctxn, ibdev,
			       rc, strerror(-rc));
			return -1;
		} else {
			pr_info("vfmig: snapshotted ctxn=%u (static): "
				"num_static=%u num_sys_pages=%u "
				"total_bfregs=%u lib_caps=%#llx 4k=%u "
				"dyn=%u cqe=%u devx_uid=%u\n",
				ctxn, uctx_meta.num_static_sys_pages,
				uctx_meta.num_sys_pages,
				uctx_meta.total_num_bfregs,
				(unsigned long long)uctx_meta.lib_caps,
				uctx_meta.lib_uar_4k,
				uctx_meta.lib_uar_dyn,
				uctx_meta.cqe_version,
				(unsigned)uctx_meta.devx_uid);
		}

		/*
		 * source_devx_uid is image-only metadata (the restore
		 * path always opens the destination ucontext WITHOUT
		 * DEVX under the v0 contract, so adopt_devx_uid is
		 * forced to 0). Source it from QUERY_UCONTEXT's
		 * meta.devx_uid (kernel commit c659ab66483d), which the
		 * static path filled above. The dyn-UAR / DEVX path
		 * leaves it 0 -- benign here because dyn/DEVX QP dumps
		 * are refused by the per-QP dump hook, and the per-PD
		 * QUERY_PD RESP_UID carries the authoritative per-PD uid
		 * for diagnostics. This replaces the removed NLDEV
		 * per-PD "fw_uid" driver-TLV walk.
		 */
		source_devx_uid = (uint32_t)uctx_meta.devx_uid;

		if (vfmig_pending_enqueue(ctxn, ibdev, pf_bdf, vf_id,
					  src_cdev,
					  uctx_uar ? &uctx_meta : NULL,
					  uctx_uar, uctx_uar_n,
					  uctx_cnt, uctx_cnt_n,
					  uctx_dyn, uctx_dyn_n,
					  source_devx_uid)) {
			pr_err("vfmig: enqueue(ctxn=%u, pf=%s, vf_id=%u, "
			       "src_cdev=%s) OOM\n", ctxn, pf_bdf,
			       vf_id, src_cdev);
			free(uctx_uar);
			free(uctx_cnt);
			free(uctx_dyn);
			return -1;
		}
	}

	pr_info("vfmig: queued ctxn=%u ibdev=%s pf=%s vf_id=%u "
		"src_cdev=%s for fini-time SAVE\n", ctxn, ibdev,
		pf_bdf, vf_id, src_cdev);
	return 0;
}

/*
 * Drain the pending queue at fini(DUMP) time. Per (pf_bdf, vf_id)
 * the first context "owns" the SAVE; subsequent contexts on the
 * same VF reuse the cached blob via vfmig_saved_lookup. SAVE
 * failure for one VF only kills that VF's records -- contexts on
 * other VFs continue to land in the image. This matches the
 * "partial image best-effort" policy: a more-complete partial
 * image is more useful for debugging than a wholesale dump abort,
 * especially when the failing VF is one of several being
 * snapshotted.
 *
 * Best-effort logging only: fini's signature is void (criu's
 * cr_plugin_fini drops any return) so we can't propagate a
 * partial-failure indication back up. The pr_err lines below
 * are the operator's surface for "which VF's records didn't make
 * it into the image".
 */
void vfmig_drain_pending_in_fini(void)
{
	struct vfmig_pending_ctx *p;
	int total = 0, written = 0, failed = 0, captured = 0;

	for (p = vfmig_pending_head; p; p = p->next) {
		struct vfmig_saved_vf *st;

		total++;

		if (vfmig_failed_lookup(p->pf_bdf, p->vf_id)) {
			pr_warn("vfmig: skipping ctxn=%u (pf=%s vf_id=%u "
				"already failed earlier in this dump)\n",
				p->ctxn, p->pf_bdf, p->vf_id);
			failed++;
			continue;
		}

		st = vfmig_saved_lookup(p->pf_bdf, p->vf_id);
		if (!st) {
			struct vfmig_saved_vf *nst = calloc(1, sizeof(*nst));

			if (!nst) {
				pr_err("vfmig: calloc(saved_vf) for ctxn=%u "
				       "pf=%s vf_id=%u; marking VF failed\n",
				       p->ctxn, p->pf_bdf, p->vf_id);
				vfmig_failed_mark(p->pf_bdf, p->vf_id);
				failed++;
				continue;
			}
			snprintf(nst->pf_bdf, sizeof(nst->pf_bdf), "%s",
				 p->pf_bdf);
			nst->vf_id = p->vf_id;

			if (vfmig_capture_one_vf(p->pf_bdf, p->vf_id, nst)) {
				pr_err("vfmig: SAVE_VHCA_STATE failed for "
				       "pf=%s vf_id=%u; dropping all "
				       "pending records for this VF\n",
				       p->pf_bdf, p->vf_id);
				free(nst);
				vfmig_failed_mark(p->pf_bdf, p->vf_id);
				failed++;
				continue;
			}
			nst->next = vfmig_saved_head;
			vfmig_saved_head = nst;
			st = nst;
			captured++;
		} else {
			pr_info("vfmig: dedup hit ibdev=%s pf=%s vf_id=%u "
				"ctxn=%u (reusing blob '%s')\n",
				p->ibdev, p->pf_bdf, p->vf_id, p->ctxn,
				st->blob_path);
		}

		if (vfmig_append_state_entry(p->ctxn, p->ibdev,
					     p->source_cdev_path,
					     st->pf_bdf, st->vf_id,
					     st->vhca_id,
					     st->vf_uuid,
					     st->blob_path, st->blob_size,
					     &p->uctx_meta,
					     p->uctx_uar_table,
					     p->uctx_uar_n,
					     p->uctx_bfreg_count,
					     p->uctx_bfreg_n,
					     p->uctx_dyn_records,
					     p->uctx_dyn_n,
					     p->source_devx_uid)) {
			pr_err("vfmig: failed to append state entry for "
			       "ctxn=%u (pf=%s vf_id=%u)\n",
			       p->ctxn, p->pf_bdf, p->vf_id);
			failed++;
			continue;
		}
		written++;
	}

	pr_info("fini-DUMP drain: total=%d captured_vfs=%d records_written=%d "
		"failed=%d\n", total, captured, written, failed);
}

/*
 * Per-CQ dump hook (CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ). Issues
 * MLX5_IB_METHOD_VFMIG_QUERY_CQ on @lfd against @ufile_handle, packs
 * the 32-byte RESP_BLOB byte-equal to mlx5_ib_restore_cq_req into
 * @plugin_blob (the entry-level opaque per-uobj container -- core
 * never inspects these bytes, the schema is mlx5-private and the
 * companion restore-side hook
 * rdma_mlx5_vfmig_plugin_restore_uobj_cq_uhw_pack reads them back
 * verbatim). The companion outs (comp_vector, flags) go into the
 * parallel hw-agnostic @cq_attrs fields. cqe_count was pre-filled
 * by the dispatcher from NLDEV (RES_CQE) and is left untouched --
 * the QUERY_CQ RESP_CQE is asserted for symmetry but not re-emitted.
 *
 * Allocates @plugin_blob->data via malloc; the caller
 * (criu/rdma/uobj_dump.c::uobj_cq_cb -> uobj_emit -> pb_write_one)
 * frees it after pb_write_one consumes the bytes.
 *
 * Kernel-mode CQ rejection (-ENXIO from QUERY_CQ) is propagated so
 * the dispatcher can demote it to a per-uobject skip rather than a
 * dump-fatal error -- the kernel handler returns -ENXIO when
 * mcq->buf.umem == NULL, which CRIU shouldn't observe in practice
 * (kernel CQs aren't in any user ufile's idr) but defending in
 * depth is cheap.
 */
int rdma_mlx5_vfmig_plugin_dump_uobj_cq(const char *ibdev,
					uint32_t kernel_driver_id,
					int lfd, uint32_t ufile_handle,
					pid_t pid,
					RdmaCqAttrs *cq_attrs,
					ProtobufCBinaryData *plugin_blob)
{
	struct mlx5_ib_restore_cq_req_local blob = {};
	uint32_t resp_cqe = 0, comp_vector = 0, flags = 0;
	uint8_t *blob_buf;
	int rc;

	(void)kernel_driver_id;	/* validated by the dispatcher */
	(void)pid;		/* mlx5 sources its CQ state from QUERY_CQ on @lfd, no
				 * (pid, ibdev) side-table consult; pid is the rxe plugin's
				 * concern. */

	rc = vfmig_query_cq(lfd, ufile_handle, &blob,
			    &resp_cqe, &comp_vector, &flags);
	if (rc) {
		if (rc == -ENXIO) {
			pr_debug("vfmig: QUERY_CQ(handle=%u) on ibdev=%s "
				 "returned -ENXIO (kernel-mode CQ); "
				 "skipping per-uobject capture\n",
				 ufile_handle, ibdev);
			return -ENXIO;
		}
		pr_err("vfmig: QUERY_CQ(handle=%u) on ibdev=%s failed: "
		       "%d (%s)\n",
		       ufile_handle, ibdev, rc, strerror(-rc));
		return rc;
	}

	/*
	 * Sanity belt: NLDEV's RES_CQE (which the dispatcher already
	 * stamped onto cq_attrs->cqe_count) and QUERY_CQ's RESP_CQE
	 * resolve through the same kernel field (ibcq->cqe). A
	 * mismatch would mean the IDR walker and NLDEV are looking at
	 * different objects, which is the kind of structural surprise
	 * we want to surface rather than paper over.
	 */
	if (cq_attrs->has_cqe_count && cq_attrs->cqe_count != resp_cqe) {
		pr_err("vfmig: CQ ufile_handle=%u on ibdev=%s: NLDEV "
		       "RES_CQE=%u disagrees with QUERY_CQ RESP_CQE=%u; "
		       "structural inconsistency, aborting dump\n",
		       ufile_handle, ibdev, cq_attrs->cqe_count, resp_cqe);
		return -EILSEQ;
	}

	blob_buf = malloc(sizeof(blob));
	if (!blob_buf) {
		pr_err("vfmig: out of memory packing CQ ufile_handle=%u "
		       "plugin_blob (mlx5_ib_restore_cq_req, 32 bytes)\n",
		       ufile_handle);
		return -ENOMEM;
	}
	memcpy(blob_buf, &blob, sizeof(blob));
	plugin_blob->data = blob_buf;
	plugin_blob->len = sizeof(blob);

	cq_attrs->has_comp_vector = true;
	cq_attrs->comp_vector = comp_vector;
	cq_attrs->has_flags = true;
	cq_attrs->flags = flags;

	pr_debug("vfmig: QUERY_CQ ibdev=%s ufile_handle=%u: cqn=%u "
		 "cqe_size=%u buf_addr=0x%llx db_addr=0x%llx cqe=%u "
		 "comp_vector=%u flags=0x%x\n",
		 ibdev, ufile_handle, blob.cqn, blob.cqe_size,
		 (unsigned long long)blob.buf_addr,
		 (unsigned long long)blob.db_addr,
		 resp_cqe, comp_vector, flags);
	return 0;
}

/*
 * Per-PD dump hook (CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_PD). Issues
 * MLX5_IB_METHOD_VFMIG_QUERY_PD on @lfd against @ufile_handle, packs
 * the 16-byte RESP_BLOB byte-equal to mlx5_ib_restore_pd_req into
 * @plugin_blob (the entry-level opaque per-uobj container -- core
 * never inspects these bytes, the schema is mlx5-private and the
 * companion restore-side hook
 * rdma_mlx5_vfmig_plugin_restore_uobj_pd_uhw_pack reads them back
 * verbatim into RESTORE_PD's UHW_IN). This supersedes the legacy
 * NLDEV "fw_pdn" / "fw_uid" driver-TLV discovery -- the FW pdn
 * RESTORE_PD adopts now travels in plugin_blob, learned on the
 * uverbs fd CRIU already holds.
 *
 * @pd_attrs is unused: v0 PD has no plugin-owned hw-agnostic fields
 * (PD allocation is access-flag-less in IB verbs); the whole per-
 * driver payload travels in @plugin_blob.
 *
 * RESP_UID (the source PD's mpd->uid) is dump-side diagnostic only:
 * unlike the per-QP hook, PD dump does NOT refuse a non-zero uid.
 * Cross-uid PD destroy survives the FW's asymmetric uid-acceptance
 * matrix (uid=0 host-priv accepted on DEALLOC_PD), so pd_cq / pd_mr
 * passes that use libmlx5 auto-DEVX (uid != 0) still round-trip; the
 * v0 refuse-on-DEVX gate lives only in the QP-class dump hook.
 *
 * Allocates @plugin_blob->data via malloc; the caller
 * (criu/rdma/uobj_dump.c::uobj_pd_cb -> uobj_emit -> pb_write_one)
 * frees it after pb_write_one consumes the bytes.
 *
 * Kernel-internal PD rejection (-ENXIO from QUERY_PD) is propagated
 * so the dispatcher can demote it to a per-uobject skip.
 */
int rdma_mlx5_vfmig_plugin_dump_uobj_pd(const char *ibdev,
					uint32_t kernel_driver_id,
					int lfd, uint32_t ufile_handle,
					pid_t pid,
					RdmaPdAttrs *pd_attrs,
					ProtobufCBinaryData *plugin_blob)
{
	struct mlx5_ib_restore_pd_req_local blob = {};
	uint32_t uid = 0;
	uint8_t *blob_buf;
	int rc;

	(void)kernel_driver_id;	/* validated by the dispatcher */
	(void)pid;		/* mlx5 sources its PD state from QUERY_PD on @lfd */
	(void)pd_attrs;		/* v0 PD has no plugin-owned hw-agnostic fields */

	rc = vfmig_query_pd(lfd, ufile_handle, &blob, &uid);
	if (rc) {
		if (rc == -ENXIO) {
			pr_debug("vfmig: QUERY_PD(handle=%u) on ibdev=%s "
				 "returned -ENXIO (kernel-internal PD); "
				 "skipping per-uobject capture\n",
				 ufile_handle, ibdev);
			return -ENXIO;
		}
		pr_err("vfmig: QUERY_PD(handle=%u) on ibdev=%s failed: "
		       "%d (%s)\n",
		       ufile_handle, ibdev, rc, strerror(-rc));
		return rc;
	}

	blob_buf = malloc(sizeof(blob));
	if (!blob_buf) {
		pr_err("vfmig: out of memory packing PD ufile_handle=%u "
		       "plugin_blob (mlx5_ib_restore_pd_req, 16 bytes)\n",
		       ufile_handle);
		return -ENOMEM;
	}
	memcpy(blob_buf, &blob, sizeof(blob));
	plugin_blob->data = blob_buf;
	plugin_blob->len = sizeof(blob);

	pr_debug("vfmig: QUERY_PD ibdev=%s ufile_handle=%u: pdn=%u "
		 "uid=%u%s\n", ibdev, ufile_handle, blob.pdn, uid,
		 uid ? " (source PD under a DEVX lane; uid is dump-side "
		       "diagnostic only, RESTORE_PD takes uid from the "
		       "adopted ucontext)" : "");
	return 0;
}

/*
 * Per-QP dump hook (CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_QP). Issues
 * MLX5_IB_METHOD_VFMIG_QUERY_QP on @lfd against @ufile_handle and
 * splits the seven outs across:
 *
 *   - @plugin_blob: the 64-byte mlx5_ib_restore_qp_req that
 *     RESTORE_QP's UHW.data will consume byte-equal at restore.
 *     Stored as the entry-level opaque blob; criu core never
 *     parses it. The companion restore-side hook
 *     rdma_mlx5_vfmig_plugin_restore_uobj_qp_uhw_pack reads it
 *     back verbatim into UHW_IN. Layout, sentinel discipline, and
 *     LOAD_VHCA_STATE byte-equality contract are owned by
 *     mlx5_uapi.h::struct mlx5_ib_restore_qp_req_local.
 *
 *   - @qp_attrs: the hw-agnostic per-class proto fields RESTORE_QP
 *     takes as core attrs (not in UHW). Five outs land here:
 *     create_flags, cap, user_handle, plus type+state cross-checks
 *     against the NLDEV-stamped values (see below).
 *
 * NLDEV vs QUERY_QP cross-checks. The dispatcher already stamped
 * qp_attrs->qp_type and qp_attrs->state from NLDEV's RES_TYPE /
 * RES_STATE before this hook ran (see uobj_qp_cb). QUERY_QP's
 * RESP_TYPE / RESP_STATE come from the same kernel mqp fields the
 * NLDEV walker reads. A divergence between the two sources is the
 * kind of structural surprise we want to surface (means the
 * walker and the per-handle ioctl are looking at different
 * objects, or one of the two paths has stale state). Treat as
 * fatal -- silently dropping wins us no portability and risks an
 * RTS-vs-RTR mistake at restore.
 *
 * RESTORE_QP gates @qp_attrs->qp_type on RC/UD (UC parked) and
 * @qp_attrs->state on {RESET,INIT,RTR,RTS}; the v0 pre-suspend
 * coverage filter (rdma_check_qp_restorability) is the canonical
 * place to enforce that contract. We do NOT re-check it here, the
 * dump hook is for marshaling, not policy.
 *
 * Kernel-mode QP rejection (-ENXIO from the QUERY_QP handler) is
 * propagated for symmetry with the CQ path; mlx5_ib_qp.umem can be
 * NULL on raw-packet split-SQ kernel-side QPs. The dispatcher
 * demotes -ENXIO to a per-uobject skip so a single internal QP
 * doesn't fail the whole dump.
 */
int rdma_mlx5_vfmig_plugin_dump_uobj_qp(const char *ibdev,
					uint32_t kernel_driver_id,
					int lfd, uint32_t ufile_handle,
					pid_t pid,
					RdmaQpAttrs *qp_attrs,
					ProtobufCBinaryData *plugin_blob)
{
	struct mlx5_ib_restore_qp_req_local blob = {};
	struct mlx5_ib_vfmig_ucontext_meta_local uctx_meta = {};
	uint32_t create_flags = 0;
	uint64_t user_handle = 0;
	uint8_t *blob_buf;
	int rc;

	(void)kernel_driver_id;
	(void)pid;

	/*
	 * Source-DEVX QP dumps are NO LONGER REFUSED.
	 *
	 * History (v0 / 2026-06-03): an earlier version of this hook
	 * refused the QP dump if the source ucontext was opened with
	 * DEVX (meta.devx_uid != 0) or with lib_uar_dyn=true (which
	 * silently implies DEVX in libmlx5). The refusal was based on
	 * the (then-current) belief that 2RST_QP / DESTROY_QP under
	 * uid=0 against a QPC owned by source.devx_uid != 0 silently
	 * no-op'd at FW, leaving the orphan QPC pinning the PD and
	 * surfacing the failure as DEALLOC_PD bad_resource_state at
	 * post-restore teardown.
	 *
	 * Empirical investigation (kernel-side
	 * tools/testing/criu_rdma/uobject_restore/qp_destroy_matrix,
	 * cq_destroy_matrix, mr_destroy_matrix, dealloc_pd_chain on
	 * FW 28.48.1000) refuted that hypothesis:
	 *
	 *   - DESTROY_QP / 2RST_QP HONOR cross-uid lanes for RESET-
	 *     state QPs; QPC is destroyed (post-op QUERY_QP returns
	 *     not-found) regardless of the asserting uid.
	 *   - DESTROY_CQ HONORS cross-uid (after dropping the
	 *     dependent QP first via DESTROY_QP, which itself works
	 *     cross-uid).
	 *   - DESTROY_MKEY HONORS cross-uid for vfmig-restored mkeys.
	 *   - DEALLOC_PD on a vfmig-restored PDN fails with status
	 *     0x9 syndrome 0xef0c8a regardless of asserting uid --
	 *     because LOAD_VHCA_STATE wipes the per-VHCA (pdn ->
	 *     owner_uid) registration table. The same shape is
	 *     returned for definitely-bogus pdns. The kernel's
	 *     mlx5_ib_dealloc_pd now suppresses exactly this
	 *     status/syndrome tuple for vfmig-restored PDs, freeing
	 *     the kernel-side mpd cleanly while trusting VHCA
	 *     close to reclaim FW state (commit ee27d8e391aa).
	 *
	 * Companion kernel relax: the strict-equality check on
	 * meta.devx_uid in MLX5_IB_METHOD_VFMIG_RESTORE_UCONTEXT
	 * (commit c659ab66483d) was relaxed to log-and-continue,
	 * since:
	 *   (a) the DEALLOC_PD failure is mitigated by the
	 *       vfmig_restored gate, independent of devx_uid match;
	 *   (b) cross-uid destroys honor uid for QP/CQ/MR;
	 *   (c) the standard-verbs data path (post-restore traffic
	 *       through HW doorbells/CQEs) does not consult the FW
	 *       registration tables and is uid-blind.
	 *
	 * See drivers/infiniband/hw/mlx5/vfmig_uctx.c and
	 * tools/testing/criu_rdma/design/pd_registration_wipe.md
	 * for the kernel-side artefacts. This hook now just records
	 * the source's devx_uid for diagnostics; the dump proceeds.
	 *
	 * Out of scope for v0:
	 *   - DEVX-direct manipulation (ibv_devx_obj_*) of restored
	 *     objects post-LM. Those use the wiped (uid -> uctx_attrs)
	 *     registration table for ownership validation. If a
	 *     workload relies on that, it is not yet restorable;
	 *     a future FW change is the path forward (see the
	 *     "FW-team escalation" section of the kernel design doc).
	 */
	rc = vfmig_query_uctx_meta(lfd, &uctx_meta);
	if (rc == -EOPNOTSUPP) {
		/*
		 * Source ran in lib_uar_dyn=true mode. QUERY_UCONTEXT
		 * is static-only by kernel construction, but the dyn-
		 * UAR path is exercised through QUERY_DYN_UARS at
		 * dump_uverbs_context() time. Fine for the QP hook --
		 * we only need uctx_meta.devx_uid for the diagnostic
		 * log below; the image's source_devx_uid is sourced
		 * from QUERY_UCONTEXT.meta.devx_uid at
		 * dump_uverbs_context() time (image-only metadata).
		 */
		pr_debug("vfmig: QP dump on dyn-mode ucontext "
			 "(handle=%u ibdev=%s): QUERY_UCONTEXT "
			 "EOPNOTSUPP -- proceeding (kernel relax of "
			 "RESTORE_UCONTEXT devx_uid check + "
			 "mlx5_ib_dealloc_pd vfmig_restored gate "
			 "make this safe; see "
			 "tools/testing/criu_rdma/design/"
			 "pd_registration_wipe.md)\n",
			 ufile_handle, ibdev);
		uctx_meta.devx_uid = 0;
	} else if (rc) {
		pr_err("vfmig: QUERY_UCONTEXT(lfd=%d, owning ucontext "
		       "for QP handle=%u) on ibdev=%s failed: %d (%s)\n",
		       lfd, ufile_handle, ibdev, rc, strerror(-rc));
		return rc;
	} else if (uctx_meta.devx_uid != 0) {
		pr_info("vfmig: QP dump (handle=%u ibdev=%s): source "
			"ucontext is DEVX-enabled (meta.devx_uid=%u). "
			"Proceeding -- the destination's freshly-"
			"allocated devx_uid will diverge from the "
			"source's, which is now tolerated by "
			"RESTORE_UCONTEXT and is harmless for the "
			"standard-verbs data path. DEVX-direct "
			"manipulation of restored objects remains "
			"out of scope for v0.\n",
			ufile_handle, ibdev,
			(unsigned)uctx_meta.devx_uid);
	}

	rc = vfmig_query_qp(lfd, ufile_handle, &blob,
			    &user_handle, &create_flags);
	if (rc) {
		if (rc == -ENXIO) {
			pr_debug("vfmig: QUERY_QP(handle=%u) on ibdev=%s "
				 "returned -ENXIO (kernel-mode QP); "
				 "skipping per-uobject capture\n",
				 ufile_handle, ibdev);
			return -ENXIO;
		}
		pr_err("vfmig: QUERY_QP(handle=%u) on ibdev=%s failed: "
		       "%d (%s)\n",
		       ufile_handle, ibdev, rc, strerror(-rc));
		return rc;
	}

	/*
	 * Master-side seam assertion: NLDEV RES_LQPN (qp_attrs->qp_num,
	 * set by uobj_qp_cb before dispatch) and the UHW-carried
	 * mlx5_ib_restore_qp_req.qpn must agree. They both resolve
	 * through ibqp->qp_num on the source mqp, so divergence means
	 * the IDR walker and the per-handle QUERY_QP ioctl resolved to
	 * different mqps -- a structural surprise. The PIE restorer's
	 * resp_qpn vs qpn_hint assertion is the final defence; this one
	 * catches the same regression class earlier (at dump time, with
	 * the source still online) where the operator can re-dump.
	 *
	 * (The former NLDEV-vs-QUERY_QP type/state cross-checks are
	 * gone: RESP_TYPE / RESP_STATE were dropped from the verb, and
	 * the HW-generic dump path now cross-checks NLDEV RES_STATE
	 * against the standard QUERY_QP verb's state instead.)
	 */
	if (qp_attrs->has_qp_num && qp_attrs->qp_num != blob.qpn) {
		pr_err("vfmig: QP ufile_handle=%u on ibdev=%s: NLDEV "
		       "RES_LQPN=%u disagrees with QUERY_QP UHW "
		       "blob.qpn=%u; the IDR walker and per-handle "
		       "QUERY_QP resolved to different QPs, aborting "
		       "dump\n",
		       ufile_handle, ibdev, qp_attrs->qp_num, blob.qpn);
		return -EILSEQ;
	}

	/*
	 * cap is NOT filled here: qp_attrs->cap is sourced by the
	 * HW-generic dump path (uobj_qp_cb) from the standard QUERY_QP
	 * verb. This hook only contributes the residue with no standard
	 * surface -- the FW blob (below), user_handle, create_flags.
	 */
	qp_attrs->has_create_flags = true;
	qp_attrs->create_flags = create_flags;
	qp_attrs->has_user_handle = true;
	qp_attrs->user_handle = user_handle;

	blob_buf = malloc(sizeof(blob));
	if (!blob_buf) {
		pr_err("vfmig: out of memory packing QP ufile_handle=%u "
		       "plugin_blob (mlx5_ib_restore_qp_req, %zu bytes)\n",
		       ufile_handle, sizeof(blob));
		return -ENOMEM;
	}
	memcpy(blob_buf, &blob, sizeof(blob));
	plugin_blob->data = blob_buf;
	plugin_blob->len = sizeof(blob);

	pr_debug("vfmig: QUERY_QP ibdev=%s ufile_handle=%u: qpn=%u "
		 "user_handle=0x%llx create_flags=0x%x sq_wqe_count=%u "
		 "rq_wqe_count=%u rq_wqe_shift=%u flags=0x%x (cap sourced "
		 "via standard QUERY_QP; type/state via NLDEV)\n",
		 ibdev, ufile_handle, blob.qpn,
		 (unsigned long long)user_handle, create_flags,
		 blob.sq_wqe_count, blob.rq_wqe_count, blob.rq_wqe_shift,
		 blob.flags);
	return 0;
}

/*
 * Per-VMA dump-side hook (CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA).
 *
 * mlx5 ibverbs userspace (libmlx5) memory-maps three or four pages
 * off /dev/infiniband/uverbsN per ibv_context: the UAR doorbell
 * page(s), the realtime-clock register, and (on some firmware) a
 * non-cached UAR. CRIU's proc_parse encounters those VMAs, sees
 * S_ISCHR, and asks every loaded plugin "is this VMA yours?".
 * Without us claiming them the dump aborts with the standard
 * "Can't handle non-regular mapping" error.
 *
 * The check we perform here is symmetric with the dump-side
 * predicate the rest of this plugin uses:
 *
 *   1. /sys/dev/char/<maj>:<min>/ibdev exists and reads as an
 *      ibdev name. (Fast pre-filter -- non-uverbs chrdev VMAs
 *      decline silently here.)
 *
 *   2. ibdev resolves via the standard sysfs walk to a
 *      (pf_bdf, vf_id) tuple, AND /dev/mlx5_vfmig/<pf_bdf>
 *      opens. Anything that doesn't (PFs, non-mlx5 ibdevs,
 *      hosts where vfmig isn't loaded) declines silently.
 *
 *   3. MLX5_VFMIG_IOC_QUERY_VF on (pf_bdf, vf_id) reports
 *      tracked=1. tracked=0 means "this is an mlx5 VF but it
 *      was never armed for migration", which is one of the few
 *      cases where we want to log loudly: the operator almost
 *      certainly meant to run SET_TRACKED before snapshotting,
 *      and silently declining would let CRIU fail the dump
 *      with a generic "Can't handle non-regular mapping"
 *      instead of a directed "VF X is not save/restorable".
 *      We still return -ENOTSUP (rather than a hard error) so
 *      the existing handle_vma_plugin() error path runs --
 *      that surfaces the original VMA address, which is more
 *      useful for triage than the bare ioctl() failure would
 *      be.
 *
 * Returns 0 on a successful claim, -ENOTSUP for any decline
 * (which lets run_plugins() fall through to the next hook, or to
 * proc_parse's "Can't handle non-regular mapping" if no plugin
 * claims). We deliberately never return any other negative value
 * here: a negative-but-not-ENOTSUP return short-circuits
 * run_plugins() and would prevent any future plugin (or future
 * hook in this plugin) from claiming a VMA we mishandled.
 *
 * @fd is unused: we do all the resolution off @stat->st_rdev,
 * because the source-side proc fd is opened against the dumpee's
 * /proc/<pid>/map_files/<addr> and can be revoked underneath us
 * if the dumpee races the dump (rare but possible).
 */
int rdma_mlx5_vfmig_plugin_handle_device_vma(int fd,
						    const struct stat *st)
{
	struct mlx5_vfmig_query_vf q;
	char ibdev[64];
	char pf_bdf[64];
	char cdev_path[PATH_MAX];
	uint32_t vf_id;
	int cdev_fd, rc;

	(void)fd;

	if (!vfmig_active)
		return -ENOTSUP;
	if (!S_ISCHR(st->st_mode))
		return -ENOTSUP;

	if (vfmig_chrdev_to_ibdev(st->st_rdev, ibdev, sizeof(ibdev)))
		return -ENOTSUP;
	if (vfmig_resolve_pf_vf_quiet(ibdev, pf_bdf, sizeof(pf_bdf),
				      &vf_id))
		return -ENOTSUP;

	snprintf(cdev_path, sizeof(cdev_path), "%s/%s",
		 MLX5_VFMIG_DEV_DIR, pf_bdf);
	cdev_fd = open(cdev_path, O_RDWR | O_CLOEXEC);
	if (cdev_fd < 0) {
		pr_debug("handle_vma(%s, pf=%s): open(%s) failed: %s; "
			 "declining\n", ibdev, pf_bdf, cdev_path,
			 strerror(errno));
		return -ENOTSUP;
	}

	memset(&q, 0, sizeof(q));
	q.vf_id = vf_id;
	rc = ioctl(cdev_fd, MLX5_VFMIG_IOC_QUERY_VF, &q);
	close(cdev_fd);
	if (rc) {
		pr_warn("handle_vma(%s, pf=%s, vf_id=%u): QUERY_VF "
			"failed: %s; declining\n",
			ibdev, pf_bdf, vf_id, strerror(errno));
		return -ENOTSUP;
	}
	if (!q.tracked) {
		pr_err("handle_vma(%s, pf=%s, vf_id=%u): VF is not "
		       "tracked (not save/restorable); CRIU dump "
		       "will fail. Run SET_TRACKED on this VF before "
		       "snapshotting.\n",
		       ibdev, pf_bdf, vf_id);
		return -ENOTSUP;
	}

	pr_info("handle_vma(%s, pf=%s, vf_id=%u): claiming "
		"uverbs-cdev mapping (UAR/clock/NC, tracked VF)\n",
		ibdev, pf_bdf, vf_id);
	return 0;
}
