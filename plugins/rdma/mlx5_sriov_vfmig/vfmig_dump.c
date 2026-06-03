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
 *   - vfmig_resolve_source_devx_uid() + its NLDEV walk callbacks:
 *     pin down mlx5_ib_ucontext.devx_uid via the kernel's named
 *     "fw_uid" PD-resource TLV (kernel d4acb54ebd3d), so the
 *     restore-side GET_CONTEXT can re-adopt the same uid.
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
	 * sets this even with no explicit DEVX call). Computed by
	 * the dump hook from a per-ucontext NLDEV PD walk: each PD's
	 * "fw_uid" driver TLV (kernel d4acb54ebd3d) is the same uid,
	 * and the dump hook validates uniqueness across the
	 * ucontext's PDs (a mismatch would be a kernel bug).
	 *
	 * Persisted into mlx5_vfmig_state_entry.source_devx_uid so
	 * the restore-side GET_CONTEXT can adopt it via
	 * MLX5_IB_ALLOC_UCTX_ADOPT_DEVX_UID + adopt_devx_uid; see
	 * vfmig_send_get_context_v2 for the call shape.
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
 * Capture the firmware blob for one (pf_bdf, vf_id) pair.
 *
 * Steps (matching the source-side lifecycle in the kernel UAPI doc
 * on MLX5_VFMIG_IOC_SAVE_VHCA_STATE):
 *   1. open /dev/mlx5_vfmig/<pf_bdf>
 *   2. ioctl MLX5_VFMIG_IOC_GET_VHCA_ID    (record vhca_id for diags)
 *   3. ioctl MLX5_VFMIG_IOC_SAVE_VHCA_STATE { vf_id,
 *        flags = MLX5_VFMIG_SAVE_FLAG_KEEP_SUSPENDED }
 *      -> kernel quiesces the VF (SUSPEND_VHCA INITIATOR/RESPONDER),
 *         allocates DMA-mapped image pages, runs SAVE_VHCA_STATE,
 *         returns a read-only anon-inode fd.
 *   4. read the save_fd to EOF, write into the image dir.
 *   5. close(save_fd) WITHOUT issuing RESUME -- KEEP_SUSPENDED told
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
	struct mlx5_vfmig_save_state ss;
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

	memset(&ss, 0, sizeof(ss));
	ss.vf_id = vf_id;

	/*
	 * SAVE flag policy: default flags=0 (kernel auto-RESUMEs the
	 * source VF on save_fd close), opt in to KEEP_SUSPENDED via
	 * the CRIU_VFMIG_KEEP_SUSPENDED=1 env var.
	 *
	 * Why default=0:
	 *
	 *   The kernel's reference vfmig test (tools/testing/mlx5_vfmig/
	 *   test_m2r_iova.sh) issues SAVE_VHCA_STATE with no flags and
	 *   then does sriov_numvfs=0 cheaply -- exactly the flow CRIU
	 *   needs to support same-host dump-and-restore validation. The
	 *   KEEP_SUSPENDED + sriov_numvfs=0 path that the kernel UAPI
	 *   doc gestures at ("CRIU dump-then-destroy where the VF is
	 *   about to be torn down via sriov_numvfs=0 anyway") is not
	 *   exercised by the kernel test suite, and on the current
	 *   kernel mlx5_core's release path walks the suspended VF's
	 *   own cmd ring -- DESTROY_QP, DESTROY_CQ, DESTROY_MKEY,
	 *   DEALLOC_PD, DEALLOC_UAR, DESTROY_UCTX, ... ~15-20 commands,
	 *   each timing out at the kernel's 60s MLX5_CMD_TIMEOUT --
	 *   making sriov_numvfs=0 take 15-25 minutes. Until the kernel
	 *   gains a fast-teardown path that detects suspended VHCAs
	 *   and skips per-resource DESTROY commands (or a vfmig-
	 *   specific destroy ioctl that bypasses the cmd ring), shipping
	 *   KEEP_SUSPENDED as the default makes CRIU's dump uncomposable
	 *   with the orchestrator's expected destroy step in any
	 *   reasonable timeframe.
	 *
	 * Why we keep an opt-in:
	 *
	 *   The KEEP_SUSPENDED semantic is genuinely useful for
	 *   production deployments where the orchestrator handles
	 *   destroy out-of-band asynchronously (paying the long
	 *   teardown off-line) and wants to guarantee no resumed-source
	 *   window between SAVE and destroy. Once kernel fast-teardown
	 *   lands, we may flip this default again.
	 *
	 * Implementation note: env var (not a build flag) so the same
	 * plugin .so works for both dev and prod -- CRIU's plugin
	 * loader doesn't differentiate.
	 */
	{
		const char *env = getenv("CRIU_VFMIG_KEEP_SUSPENDED");

		if (env && strcmp(env, "1") == 0) {
			ss.flags = MLX5_VFMIG_SAVE_FLAG_KEEP_SUSPENDED;
			pr_info("vfmig: SAVE with KEEP_SUSPENDED "
				"(CRIU_VFMIG_KEEP_SUSPENDED=1); source "
				"VF will be left suspended after save_fd "
				"close. Caller is responsible for tearing "
				"the VF down before any orchestrator "
				"action that would race a resume.\n");
		}
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
		"blob='%s' size=%llu (flags=%#x%s)\n",
		pf_bdf, vf_id, out->vhca_id, out->blob_path,
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
 * Per-ucontext source devx_uid resolver. Walks NLDEV PDs filtered
 * by ctxn, reads each PD's named "fw_uid" driver TLV (kernel
 * d4acb54ebd3d), validates that all PDs of this ucontext share
 * one value, and returns it.
 *
 * Why per-ucontext via NLDEV rather than a new mlx5-private ioctl
 * on the lfd? mlx5 doesn't expose mlx5_ib_ucontext.devx_uid via
 * uverbs today, but every PD allocated through a DEVX ucontext
 * carries mpd->uid == ucontext->devx_uid by construction (mlx5_ib_
 * alloc_pd's uid_offset path), and the kernel surfaces mpd->uid
 * via the new "fw_uid" TLV. So one PD per ucontext is enough to
 * pin down the value -- and the validation below ensures we
 * notice if the kernel ever drifts that invariant.
 *
 * Returns:
 *   0 on success. *@out_uid is the per-ucontext devx_uid (zero
 *   for non-DEVX ucontexts and for ucontexts with no PDs).
 *   -1 on a hard error (NLDEV walk failure, or the kernel emitted
 *   inconsistent fw_uid across the same ucontext's PDs -- both
 *   are CRIU-bug or kernel-bug territory and the dump must
 *   abort).
 *
 * Quiet path: if the kernel pre-dates d4acb54ebd3d (no fw_uid
 * TLVs), we leave *@out_uid = 0. Restore against a current kernel
 * will then send adopt_devx_uid=0 and the kernel's mlx5_ib_
 * restore_pd FW probe will reject any PD whose mpd->uid was
 * non-zero -- with a clear pr_warn naming the missing adoption.
 */
struct vfmig_devx_uid_walk_ctx {
	uint32_t target_ctxn;
	uint32_t devx_uid;
	bool seen_any;
	bool inconsistent;
	uint32_t first_seen;
};

struct vfmig_dev_index_lookup_ctx {
	const char *target_ibdev;
	uint32_t dev_index;
	bool found;
};

static int vfmig_dev_index_lookup_cb(uint32_t dev_index, const char *ibdev,
				     void *arg)
{
	struct vfmig_dev_index_lookup_ctx *ctx = arg;

	if (!strcmp(ibdev, ctx->target_ibdev)) {
		ctx->dev_index = dev_index;
		ctx->found = true;
		return 1;	/* short-circuit */
	}
	return 0;
}

static int vfmig_pd_devx_uid_cb(const struct rdma_nl_res_entry *e, void *arg)
{
	struct vfmig_devx_uid_walk_ctx *w = arg;

	/* Filter to PDs owned by this ucontext. */
	if (!e->has_ctxn || e->ctxn != w->target_ctxn)
		return 0;

	/*
	 * Pre-d4acb54ebd3d kernels emit no fw_uid; treat as 0
	 * (non-DEVX) but log so the operator can correlate restore-
	 * side FW-probe rejections against the missing kernel patch.
	 * Continue walking (don't return early) so a mixed image
	 * surfaces as "inconsistent" instead of silently picking up
	 * the first PD's uid.
	 */
	if (!e->has_fw_uid) {
		if (!w->seen_any) {
			w->seen_any = true;
			w->first_seen = 0;
		} else if (w->first_seen != 0) {
			w->inconsistent = true;
		}
		return 0;
	}

	if (!w->seen_any) {
		w->seen_any = true;
		w->first_seen = e->fw_uid;
		w->devx_uid = e->fw_uid;
	} else if (e->fw_uid != w->first_seen) {
		w->inconsistent = true;
	}
	return 0;
}

static int vfmig_resolve_source_devx_uid(const char *ibdev, uint32_t ctxn,
					 uint32_t *out_uid)
{
	struct vfmig_devx_uid_walk_ctx w = { .target_ctxn = ctxn };
	struct vfmig_dev_index_lookup_ctx idx = { .target_ibdev = ibdev };
	int rc;

	/*
	 * Resolve the kernel's per-ibdev dev_index first; the per-
	 * resource NLDEV dump REQUIRES RDMA_NLDEV_ATTR_DEV_INDEX as
	 * the ibdev filter (kernel res_get_common_dumpit() in
	 * drivers/infiniband/core/nldev.c rejects without it).
	 * Passing 0 silently filters to whatever ibdev happens to
	 * have index 0, which on a multi-ibdev host is rarely the
	 * VF we actually care about.
	 */
	rc = rdma_nl_for_each_ibdev(vfmig_dev_index_lookup_cb, &idx);
	if (rc < 0) {
		pr_err("vfmig: NLDEV ibdev enumeration to resolve "
		       "dev_index for ibdev=%s failed: %d (%s)\n",
		       ibdev, rc, strerror(-rc));
		return -1;
	}
	if (!idx.found) {
		pr_err("vfmig: NLDEV does not list ibdev=%s; cannot "
		       "resolve source devx_uid\n", ibdev);
		return -1;
	}

	rc = rdma_nl_for_each_resource(idx.dev_index, ibdev, RDMA_NL_RES_PD,
				       vfmig_pd_devx_uid_cb, &w);
	if (rc < 0) {
		pr_err("vfmig: NLDEV PD walk on ibdev=%s (dev_index=%u) "
		       "for source devx_uid resolution failed: %d (%s)\n",
		       ibdev, idx.dev_index, rc, strerror(-rc));
		return -1;
	}

	if (w.inconsistent) {
		pr_err("vfmig: ibdev=%s ctxn=%u: PDs of one ucontext "
		       "report different fw_uid values via NLDEV. This "
		       "is either a kernel bug (mlx5_ib_alloc_pd should "
		       "always set mpd->uid = ucontext->devx_uid) or a "
		       "race with a sibling process modifying the "
		       "ucontext's PDs concurrently. Aborting dump to "
		       "avoid producing an unrestorable image.\n",
		       ibdev, ctxn);
		return -1;
	}

	if (!w.seen_any) {
		/*
		 * No PDs on this ucontext yet (newly-opened context
		 * with no allocations). source_devx_uid stays 0; the
		 * restore-side GET_CONTEXT will skip ADOPT_DEVX_UID.
		 * If the user later allocates a PD that ends up DEVX-
		 * uid'd, the restore would still install it with
		 * uid=0 -- which the kernel's FW probe would reject
		 * loud. v0 punts on this edge case (user code that
		 * dumps an empty ucontext is unusual).
		 */
		pr_info("vfmig: ibdev=%s ctxn=%u: no PDs visible via "
			"NLDEV; source_devx_uid := 0\n", ibdev, ctxn);
		*out_uid = 0;
		return 0;
	}

	*out_uid = w.devx_uid;
	pr_info("vfmig: ibdev=%s ctxn=%u: resolved source_devx_uid="
		"%u (from %sfw_uid driver TLV)\n",
		ibdev, ctxn, w.devx_uid,
		w.devx_uid ? "" : "absent or zero ");
	return 0;
}

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

		/*
		 * Resolve the source ucontext's devx_uid via NLDEV PD
		 * walk + per-PD fw_uid TLV. Done before the
		 * QUERY_UCONTEXT calls because the latter would also
		 * fail loud on a kernel mismatch and we want to
		 * surface the more-specific "inconsistent fw_uid"
		 * diagnostic first if it triggers. Kernel pre-
		 * d4acb54ebd3d returns 0 here; that's fine for non-
		 * DEVX images (the common rxe-shape case) and gets
		 * caught at restore-time on DEVX images by mlx5_ib_
		 * restore_pd's FW probe.
		 */
		if (vfmig_resolve_source_devx_uid(ibdev, ctxn,
						  &source_devx_uid))
			return -1;

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
		 * Diagnostic only: log a uid-source consistency drift
		 * between QUERY_UCONTEXT.meta.devx_uid (kernel commit
		 * c659ab66483d) and the NLDEV-derived source_devx_uid.
		 * Both are 0 on the v0 critical path. The actual
		 * "refuse dump if source devx_uid != 0" gate lives in
		 * the per-QP dump hook (rdma_mlx5_vfmig_plugin_dump_
		 * uobj_qp), narrowed to the failing-class scenario:
		 * cross-uid PD/CQ/MR destroy survives the FW's
		 * asymmetric uid-acceptance matrix (uid=0 host-priv
		 * accepted on DEALLOC_PD/DESTROY_CQ/DESTROY_MR), only
		 * QP-class opcodes (2RST_QP, DESTROY_QP) silently no-op
		 * and surface as DEALLOC_PD bad_resource_state at
		 * teardown. So pd_cq and pd_mr passes -- which currently
		 * use libmlx5 auto-DEVX (rdma-core ca93d3b73054, source
		 * devx_uid = 2 in the failing trace) -- continue to
		 * round-trip cleanly; only QP-bearing dumps refuse.
		 */
		{
			uint32_t kernel_emit_uid = (uint32_t)uctx_meta.devx_uid;
			if (kernel_emit_uid && source_devx_uid &&
			    kernel_emit_uid != source_devx_uid) {
				pr_warn("vfmig: ctxn=%u ibdev=%s: "
					"QUERY_UCONTEXT.meta.devx_uid=%u != "
					"NLDEV-derived source_devx_uid=%u "
					"(kernel UAPI / NLDEV walker drift; "
					"both are 0 on the v0 critical path)\n",
					ctxn, ibdev, kernel_emit_uid,
					source_devx_uid);
			}
		}

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
	struct ib_uverbs_qp_cap_local cap = {};
	struct mlx5_ib_vfmig_ucontext_meta_local uctx_meta = {};
	uint32_t resp_type = 0, resp_state = 0, create_flags = 0;
	uint64_t user_handle = 0;
	uint8_t *blob_buf;
	int rc;

	(void)kernel_driver_id;
	(void)pid;

	/*
	 * v0 contract: refuse the dump if the source ucontext was
	 * opened with DEVX (meta.devx_uid != 0). This gate is QP-
	 * specific (rather than per-context) because the underlying
	 * FW failure mode is asymmetric across opcode families on
	 * FW 28.48.1000:
	 *
	 *   - DEALLOC_PD, DESTROY_CQ, DESTROY_MR with uid=0 against
	 *     a resource owned by uid != 0: ACCEPTED (uid=0 host-
	 *     priv lane). Existing pd_cq / pd_mr / pd_2cq passes
	 *     therefore round-trip cleanly under libmlx5 auto-DEVX
	 *     (rdma-core ca93d3b73054 makes every libmlx5 ibv_open_
	 *     device implicitly request MLX5_IB_ALLOC_UCTX_DEVX,
	 *     yielding source devx_uid=2 in the trace).
	 *
	 *   - 2RST_QP (modify-to-RESET) and DESTROY_QP with uid=0
	 *     against a QPC owned by uid != 0: SILENTLY NO-OP'd by
	 *     FW (status=0 returned, but FW state unchanged). The
	 *     destination kernel's destroy_qp_common warn-only-
	 *     logs and mlx5_ib_destroy_qp returns 0 to userspace,
	 *     so the user-visible failure surfaces only at the next
	 *     teardown step that propagates its FW errno verbatim
	 *     (typically DEALLOC_PD bad_resource_state, syndrome
	 *     0xef0c8a-class -- the orphan QPC is still pinning
	 *     the PD).
	 *
	 * Refusing only on QP dumps therefore preserves the v0
	 * critical path's working surface (PD/CQ/MR-only round
	 * trips) while surfacing the structural QP-destroy seam
	 * loudly at dump time, before any SAVE happens. A silent
	 * dump-then-broken-restore is the worst possible outcome
	 * and worth a clean -1 here. See kernel commit
	 * c659ab66483d ("RDMA/mlx5: expose VFMIG source devx_uid
	 * + harden destroy_qp diagnostics") for the asymmetric uid
	 * acceptance matrix and the kernel-side defense-in-depth
	 * (RESTORE_UCONTEXT now strict-equality-checks
	 * meta.devx_uid against c->devx_uid; runs after this
	 * filter would have triggered, as a backstop for older
	 * CRIU bypassing this gate).
	 *
	 * Unblocking DEVX-source dumps requires either a libmlx5
	 * patch that lets callers opt out of auto-DEVX (mlx5dv_
	 * open_device with a "no-DEVX" attr; rdma-core does not
	 * expose this today), a raw-uverbs holder that bypasses
	 * libmlx5, or a future FW that preserves the
	 * uctx-registration table across LOAD_VHCA_STATE so
	 * MLX5_IB_ALLOC_UCTX_ADOPT_DEVX_UID can re-claim the
	 * source's devx_uid on the destination.
	 */
	rc = vfmig_query_uctx_meta(lfd, &uctx_meta);
	if (rc == -EOPNOTSUPP) {
		/*
		 * Source ran in lib_uar_dyn=true mode (libmlx5 default
		 * for dyn-UAR-capable adapters). QUERY_UCONTEXT is
		 * static-only by kernel construction, but lib_uar_dyn=
		 * true silently implies DEVX in libmlx5 (the dyn-UAR
		 * verbs are mlx5dv_devx_alloc_uar / free_uar, gated on
		 * DEVX), so source devx_uid is non-zero by
		 * construction. Refuse the QP dump for the same reason
		 * as the explicit-DEVX case below.
		 */
		pr_err("vfmig: refusing QP dump (handle=%u ibdev=%s): "
		       "source ucontext is dyn-mode (lib_uar_dyn=true) "
		       "which silently implies DEVX in libmlx5; v0 "
		       "LOAD_VHCA_STATE on FW 28.48.1000 cannot honor "
		       "the resulting cross-uid QP destroy. Falls under "
		       "the same v0 contract as static-DEVX: source "
		       "must be opened non-DEVX (raw uverbs "
		       "GET_CONTEXT, req.flags=0).\n",
		       ufile_handle, ibdev);
		return -EOPNOTSUPP;
	}
	if (rc) {
		pr_err("vfmig: QUERY_UCONTEXT(lfd=%d, owning ucontext "
		       "for QP handle=%u) on ibdev=%s failed: %d (%s) "
		       "-- can't gate the QP dump on source devx_uid\n",
		       lfd, ufile_handle, ibdev, rc, strerror(-rc));
		return rc;
	}
	if (uctx_meta.devx_uid != 0) {
		pr_err("vfmig: refusing QP dump (handle=%u ibdev=%s): "
		       "source ucontext was opened with DEVX "
		       "(meta.devx_uid=%u). v0 LOAD_VHCA_STATE on FW "
		       "28.48.1000 does not preserve the FW uctx-"
		       "registration table, so the destination kernel "
		       "issues DESTROY_QP with uid=0 against a QPC "
		       "owned by source.devx_uid; FW silently no-ops "
		       "the destroy and the orphan QPC surfaces as "
		       "DEALLOC_PD bad_resource_state at post-restore "
		       "teardown. PD/CQ/MR-only dumps from the same "
		       "ucontext round-trip cleanly (different opcode-"
		       "family FW uid-acceptance matrix), so the gate "
		       "is QP-specific. To exercise QP restore, the "
		       "source process must open its ibv_context "
		       "without DEVX (libmlx5 auto-DEVX from rdma-core "
		       "ca93d3b73054 cannot be opted out of via "
		       "mlx5dv_open_device today; bypass libmlx5 with a "
		       "raw uverbs GET_CONTEXT, req.flags=0).\n",
		       ufile_handle, ibdev,
		       (unsigned)uctx_meta.devx_uid);
		return -EOPNOTSUPP;
	}

	rc = vfmig_query_qp(lfd, ufile_handle, &blob,
			    &resp_type, &resp_state, &user_handle,
			    &cap, &create_flags);
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
	 * NLDEV stamped qp_type / state on @qp_attrs from
	 * RES_TYPE / RES_STATE. QUERY_QP returns the same kernel
	 * fields. Mismatch indicates the IDR walker and per-handle
	 * ioctl resolved to different mqp's -- structural, fail
	 * loud rather than silently prefer one source.
	 */
	if (qp_attrs->has_qp_type && qp_attrs->qp_type != resp_type) {
		pr_err("vfmig: QP ufile_handle=%u on ibdev=%s: NLDEV "
		       "RES_TYPE=%u disagrees with QUERY_QP RESP_TYPE=%u; "
		       "structural inconsistency, aborting dump\n",
		       ufile_handle, ibdev, qp_attrs->qp_type, resp_type);
		return -EILSEQ;
	}
	if (qp_attrs->has_state && qp_attrs->state != resp_state) {
		pr_err("vfmig: QP ufile_handle=%u on ibdev=%s: NLDEV "
		       "RES_STATE=%u disagrees with QUERY_QP "
		       "RESP_STATE=%u; structural inconsistency, "
		       "aborting dump\n",
		       ufile_handle, ibdev, qp_attrs->state, resp_state);
		return -EILSEQ;
	}
	/*
	 * Step 6 master-side seam assertion: NLDEV RES_LQPN
	 * (qp_attrs->qp_num, set by uobj_qp_cb before dispatch) and
	 * the UHW-carried mlx5_ib_restore_qp_req.qpn must agree.
	 * They both resolve through ibqp->qp_num on the source mqp,
	 * so divergence means the IDR walker and the per-handle
	 * QUERY_QP ioctl resolved to different mqps -- the same
	 * "structural surprise" class we fail loud on for
	 * type/state. The PIE restorer's resp_qpn vs qpn_hint
	 * assertion is the final defence; this one catches the same
	 * regression class earlier (at dump time, with the source
	 * still online) where the operator can re-dump.
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
	 * @qp_attrs->cap is pre-attached by the dump-side caller
	 * (uobj_qp_cb) to a stack-local RdmaQpCap so cap memory is
	 * owned by the dump path, not the plugin. Filling fields
	 * in-place preserves a single ownership model and removes a
	 * malloc/free pair per QP.
	 */
	if (qp_attrs->cap) {
		qp_attrs->cap->has_max_send_wr = true;
		qp_attrs->cap->max_send_wr = cap.max_send_wr;
		qp_attrs->cap->has_max_recv_wr = true;
		qp_attrs->cap->max_recv_wr = cap.max_recv_wr;
		qp_attrs->cap->has_max_send_sge = true;
		qp_attrs->cap->max_send_sge = cap.max_send_sge;
		qp_attrs->cap->has_max_recv_sge = true;
		qp_attrs->cap->max_recv_sge = cap.max_recv_sge;
		qp_attrs->cap->has_max_inline_data = true;
		qp_attrs->cap->max_inline_data = cap.max_inline_data;
	}

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
		 "type=%u state=%u user_handle=0x%llx "
		 "create_flags=0x%x sq_wqe_count=%u rq_wqe_count=%u "
		 "rq_wqe_shift=%u flags=0x%x cap={ms_wr=%u mr_wr=%u "
		 "ms_sge=%u mr_sge=%u inline=%u}\n",
		 ibdev, ufile_handle, blob.qpn, resp_type, resp_state,
		 (unsigned long long)user_handle, create_flags,
		 blob.sq_wqe_count, blob.rq_wqe_count, blob.rq_wqe_shift,
		 blob.flags, cap.max_send_wr, cap.max_recv_wr,
		 cap.max_send_sge, cap.max_recv_sge, cap.max_inline_data);
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
