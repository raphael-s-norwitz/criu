/*
 * CRIU RDMA mlx5_sriov_vfmig plugin -- presence detection.
 *
 * Companion to plugins/rdma/rxe/. At criu startup the plugin walks
 * /dev/mlx5_vfmig/, opens each per-PF char device, and asks the
 * MLX5_VFMIG_IOC_QUERY_VF ioctl which (if any) of that PF's VFs
 * currently have the host-driver "vfmig tracked" bit set. A VF is
 * eligible for save/restore through this plugin iff QUERY_VF reports
 * tracked=1 -- that's the same bit that gates the per-VF unmanaged
 * IOMMU domain + deterministic IOVA allocator on the destination, so
 * any VF without it cannot round-trip a SAVE/LOAD blob even if its
 * firmware-side migratable bit is set. See linux/mlx5_vfmig.h
 * (kernel UAPI doc on MLX5_VFMIG_IOC_QUERY_VF and
 * MLX5_VFMIG_IOC_SET_TRACKED) for the gory details.
 *
 * Like the rxe plugin in the previous commit, this is just presence
 * detection. No checkpoint/restore hooks are wired in here; the per-
 * context claim API and dump-time arbitration land in the next
 * commit. Activation state is process-local.
 *
 * Vendored UAPI header:
 *   The plugin compiles against plugins/rdma/mlx5_sriov_vfmig/uapi/
 *   linux/mlx5_vfmig.h, vendored from the kernel source. This avoids
 *   making criu's build depend on a bleeding-edge kernel header on
 *   every contributor's host. Pass MLX5_VFMIG_UAPI_INCLUDE=<dir> to
 *   the plugin's make to override the include search root (e.g.
 *   pointing at a local kernel tree's include/uapi/), useful when
 *   iterating on the kernel UAPI in parallel. The Makefile emits a
 *   warning at build time if the system header at
 *   /usr/include/linux/mlx5_vfmig.h exists and disagrees with the
 *   vendored copy, so drift is at least loud.
 */

#include "criu-log.h"
#include "criu-plugin.h"

#include "images/rdma_criu.pb-c.h"

#include <linux/mlx5_vfmig.h>
#include <rdma/ib_user_ioctl_verbs.h>

#include "vfmig_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_mlx5_vfmig_plugin: "

/*
 * Process-global activation state. vfmig_active is exported via
 * vfmig_internal.h so the dump+restore hooks (now in
 * vfmig_dump.c / vfmig_restore.c) can short-circuit cheaply
 * when no tracked VFs are in flight on this host.
 */
bool vfmig_active = false;
static int  vfmig_tracked_vf_count = 0;
static int  vfmig_pf_count = 0;

static int rdma_mlx5_vfmig_plugin_init(int stage)
{
	DIR *d;
	struct dirent *de;

	vfmig_active = false;
	vfmig_tracked_vf_count = 0;
	vfmig_pf_count = 0;
	vfmig_saved_clear();
	vfmig_pending_clear();
	vfmig_failed_clear();
	vfmig_suspended_clear();
	vfmig_claimed_clear();

	d = opendir(MLX5_VFMIG_DEV_DIR);
	if (!d) {
		/*
		 * No mlx5_vfmig kernel module loaded (or no PFs that
		 * advertise migration capability) is the common case
		 * on hosts without ConnectX-7 + this work-in-progress
		 * driver. Treat as inactive rather than as an error so
		 * dropping the .so into CRIU_LIBS_DIR is safe on any
		 * host. (cr_lib_load() turns non-zero init() into a
		 * fatal startup failure -- see criu/plugin.c.)
		 */
		pr_info("opendir(%s) failed: %s; assuming no mlx5_vfmig "
			"capability, plugin inactive (stage %d)\n",
			MLX5_VFMIG_DEV_DIR, strerror(errno), stage);
		return 0;
	}

	while ((de = readdir(d)) != NULL) {
		char path[PATH_MAX];
		int n;

		if (de->d_name[0] == '.')
			continue;

		snprintf(path, sizeof(path), "%s/%s", MLX5_VFMIG_DEV_DIR,
			 de->d_name);
		vfmig_pf_count++;
		n = probe_pf_cdev(path);
		if (n > 0)
			vfmig_tracked_vf_count += n;
	}

	closedir(d);

	if (vfmig_tracked_vf_count > 0) {
		vfmig_active = true;
		pr_info("active (stage %d): %d tracked VF(s) across %d PF(s)\n",
			stage, vfmig_tracked_vf_count, vfmig_pf_count);
	} else {
		pr_info("inactive (stage %d): %d PF cdev(s) probed, no "
			"tracked VFs\n",
			stage, vfmig_pf_count);
	}

	/*
	 * On the restore side, drive the per-VF restore dance up
	 * front -- before CRIU's VMA-restore phase asks UPDATE_VMA_
	 * MAP to remap UAR/clock/NC pages off our cdev fds.
	 *
	 * Why eagerly here rather than lazily in UPDATE_VMA_MAP /
	 * RDMA_OPEN_UVERBS_CDEV:
	 *
	 *   1. UPDATE_VMA_MAP runs during VMA restore (early) but
	 *      RDMA_OPEN_UVERBS_CDEV runs during fdtable restore
	 *      (later). Both need a fd whose kernel ucontext is
	 *      already established (mlx5_ib_mmap requires it for
	 *      UAR mappings; the kernel rejects a second
	 *      GET_CONTEXT on the same struct file). If we did the
	 *      LOAD + bind + open + GET_CONTEXT lazily in either
	 *      hook the first one to fire would have to know to
	 *      cache for the other -- doable, but messier than
	 *      doing it once up front.
	 *
	 *   2. LOAD_VHCA_STATE + MARK_RESTORED + bind is
	 *      irreversible host-side state. If anything in the
	 *      restore is going to fail, we want it to fail before
	 *      CRIU starts wiring the dumpee's address space back
	 *      together; that gives the operator a clean rollback
	 *      window (sriov_numvfs cycle to discard the
	 *      half-restored VF) without having half-mapped the
	 *      restored process's VMAs.
	 *
	 * If init(RESTORE) returns non-zero CRIU treats the plugin
	 * as failed-init and the entire restore aborts. That is the
	 * desired behaviour -- a restore that can't establish the
	 * VF state will not produce a working RDMA process anyway.
	 */
	if (stage == CR_PLUGIN_STAGE__RESTORE) {
		if (vfmig_restore_init_all_vfs())
			return -1;
	}

	return 0;
}

static void rdma_mlx5_vfmig_plugin_fini(int stage, int ret)
{
	/*
	 * Drain the pending SAVE queue at the very end of dump and
	 * only when the rest of CRIU's dump pipeline succeeded. If
	 * @ret != 0 the dump has already been declared lost
	 * upstream and there is no point firing SAVE_VHCA_STATE --
	 * the resulting blob would never be paired with an image
	 * the orchestrator could restore from, and we would be
	 * needlessly suspending VFs (KEEP_SUSPENDED is permanent
	 * until the orchestrator does an SR-IOV teardown). On the
	 * RESTORE side the queue is empty -- DUMP_UVERBS_CONTEXT is
	 * not invoked during restore -- so the drain is effectively
	 * skipped there too.
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP && ret == 0)
		vfmig_drain_pending_in_fini();

	/*
	 * Snapshot-ordering resume (design/snapshot_ordering_pause_
	 * capture.md Part A). CHECKPOINT_DEVICES parked every tracked VF
	 * backing the dumpee tree before its memory was copied; now that
	 * the dump is done (or lost) decide the source datapath's fate
	 * from criu_dumpee_will_resume(): keep the VF parked only when
	 * the dumpee will NOT keep running (a successful migrate-and-kill
	 * dump, opts.final_state == TASK_DEAD). On --leave-running, an
	 * aborted dump, or a failed post-dump script the predicate is
	 * true and we resume, so a checkpoint that leaves the process
	 * alive never strands its VF stopped. No-op when the parked set
	 * is empty (no early hook ran / no tracked VFs / RESTORE stage).
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP)
		vfmig_resume_suspended_vfs(!criu_dumpee_will_resume());

	/*
	 * On restore, close the per-context cdev fds the eager init
	 * cached. We do this unconditionally on RESTORE (success or
	 * failure): on success the dumpee's restored fdtable holds
	 * dup()s of these fds (handed back from RDMA_OPEN_UVERBS_
	 * CDEV / UPDATE_VMA_MAP), so closing the plugin's copies
	 * here doesn't disturb the restored process; on failure we
	 * still want to drop our own references rather than leak.
	 */
	if (stage == CR_PLUGIN_STAGE__RESTORE)
		vfmig_restore_fini_close_all();

	pr_info("fini (stage %d ret %d): was %s, %d tracked VF(s) across "
		"%d PF(s)\n",
		stage, ret, vfmig_active ? "active" : "inactive",
		vfmig_tracked_vf_count, vfmig_pf_count);
	vfmig_saved_clear();
	vfmig_pending_clear();
	vfmig_failed_clear();
	vfmig_suspended_clear();
	vfmig_claimed_clear();
}

/*
 * Per-context claim hook (CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT).
 *
 * The claim chain for a context backed by an mlx5_core ibdev:
 *
 *   1. Plugin must be active (init() found at least one tracked
 *      VF on the host). If not, decline outright -- the dump-time
 *      arbitration's "no claim" failure mode names every loaded
 *      plugin so the operator gets a useful error.
 *
 *   2. Kernel driver must be RDMA_DRIVER_MLX5. mlx5_core ibdevs
 *      are the only ones this plugin knows how to handle.
 *
 *   3. The ibdev's PCI device must have a /physfn link, i.e. it
 *      must be a VF (not a PF). PFs are valid mlx5_core ibdevs
 *      but vfmig deliberately operates only on VFs. Decline if
 *      missing.
 *
 *   4. The VF must appear under the PF's virtfn<N> sysfs links
 *      (we need vf_id to drive QUERY_VF). Fail closed if not -- a
 *      missing virtfn link on a VF whose physfn we just resolved
 *      is a sysfs inconsistency, not a "decline" condition.
 *
 *   5. /dev/mlx5_vfmig/<pf_bdf> must open. Same reasoning as (4):
 *      if init() saw the cdev directory we expect the cdevs to
 *      still be present at claim time. Failure here propagates
 *      as a hard arbitration error.
 *
 *   6. MLX5_VFMIG_IOC_QUERY_VF on (pf_bdf, vf_id) must report
 *      tracked=1. tracked=0 -> decline (the per-VF unmanaged
 *      IOMMU domain isn't allocated, so SAVE/LOAD wouldn't
 *      round-trip even if we accepted the dump).
 *
 * Returns RCD_MLX5_SRIOV_VFMIG on a successful claim, RCD_UNKNOWN
 * on any decline (steps 1-3, 6), or a negative errno on the
 * sysfs-inconsistency / open / ioctl failure cases (steps 4, 5).
 */
static int rdma_mlx5_vfmig_plugin_claim_uverbs_context(const char *ibdev,
						       uint32_t kernel_driver_id)
{
	struct mlx5_vfmig_query_vf q;
	char sysfs_path[PATH_MAX];
	char cdev_path[PATH_MAX];
	char vf_bdf[64], pf_bdf[64];
	int vf_id, fd, rc;

	if (!vfmig_active) {
		pr_debug("claim(%s, kdrv=%u): plugin inactive, declining\n",
			 ibdev, kernel_driver_id);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}
	if (kernel_driver_id != RDMA_DRIVER_MLX5) {
		pr_debug("claim(%s, kdrv=%u): not RDMA_DRIVER_MLX5 (%u), "
			 "declining\n",
			 ibdev, kernel_driver_id, (uint32_t)RDMA_DRIVER_MLX5);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}

	snprintf(sysfs_path, sizeof(sysfs_path),
		 "/sys/class/infiniband/%s/device", ibdev);
	if (resolve_pci_bdf_via_symlink(sysfs_path, vf_bdf, sizeof(vf_bdf))) {
		pr_warn("claim(%s): cannot resolve VF BDF via %s\n", ibdev,
			sysfs_path);
		return -ENOENT;
	}

	snprintf(sysfs_path, sizeof(sysfs_path),
		 "/sys/bus/pci/devices/%s/physfn", vf_bdf);
	if (resolve_pci_bdf_via_symlink(sysfs_path, pf_bdf, sizeof(pf_bdf))) {
		pr_debug("claim(%s, vf_bdf=%s): no /physfn link, this is a "
			 "PF or non-SR-IOV mlx5_core ibdev; declining\n",
			 ibdev, vf_bdf);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}

	vf_id = find_vf_id_under_pf(pf_bdf, vf_bdf);
	if (vf_id < 0) {
		pr_warn("claim(%s, vf_bdf=%s, pf_bdf=%s): no virtfnN link "
			"under PF resolves to this VF -- sysfs inconsistency\n",
			ibdev, vf_bdf, pf_bdf);
		return -ENOENT;
	}

	snprintf(cdev_path, sizeof(cdev_path), "%s/%s", MLX5_VFMIG_DEV_DIR,
		 pf_bdf);
	fd = open(cdev_path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_warn("claim(%s): open(%s) failed: %s\n", ibdev, cdev_path,
			strerror(errno));
		return -errno;
	}

	memset(&q, 0, sizeof(q));
	q.vf_id = vf_id;
	rc = ioctl(fd, MLX5_VFMIG_IOC_QUERY_VF, &q);
	close(fd);
	if (rc != 0) {
		pr_warn("claim(%s): QUERY_VF(vf_id=%d) on %s failed: %s\n",
			ibdev, vf_id, cdev_path, strerror(errno));
		return -errno;
	}
	if (!q.tracked) {
		pr_info("claim(%s, vf_bdf=%s, pf=%s, vf_id=%d): VF not in "
			"tracked mode, declining\n",
			ibdev, vf_bdf, pf_bdf, vf_id);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}

	pr_info("claim(%s, vf_bdf=%s, pf=%s, vf_id=%d): claiming as "
		"RCD_MLX5_SRIOV_VFMIG\n",
		ibdev, vf_bdf, pf_bdf, vf_id);
	/*
	 * Record the VF so CHECKPOINT_DEVICES can park it before the
	 * memory dump without re-resolving it (snapshot-ordering pause).
	 * Dump-side only; harmless on the restore-side claim path (the
	 * cache is cleared at fini and CHECKPOINT_DEVICES never fires
	 * during restore).
	 */
	vfmig_claimed_add(ibdev, pf_bdf, (uint32_t)vf_id);
	return RDMA_CRIU_DRIVER__RCD_MLX5_SRIOV_VFMIG;
}

/*
 * mlx5_ib_restore_cq pins the source CQ ring + doorbell pages from
 * current->mm via ib_umem_get(udata, src_va, len, ...). Calling that
 * from CRIU master would pin master's mm, which is wrong; the ring
 * pages don't exist in master's address space at all. The pie blob
 * runs in the restored task's mm post-VMA-mmap, where the source
 * VAs are populated with the dump-side anonymous pages. Opt in.
 */
static int rdma_mlx5_vfmig_plugin_restore_uobj_cq_needs_pie(void)
{
	return 1;
}

/*
 * RDMA_RESTORE_UOBJ_QP_NEEDS_PIE hook (mlx5).
 *
 * mlx5_ib_restore_qp's UHW carries source-task user VAs (buf_addr,
 * db_addr; sq_buf_addr is unused for v0 RC/UD). The destination
 * kernel calls ib_umem_get on these, requiring the restored task's
 * mm to be active and the source VAs to map the dump-time anonymous
 * pages. Same constraint as RESTORE_CQ -- defer to PIE so we run
 * after VMAs are mapped, not before. Opt in.
 */
static int rdma_mlx5_vfmig_plugin_restore_uobj_qp_needs_pie(void)
{
	return 1;
}

CR_PLUGIN_REGISTER("rdma_mlx5_vfmig_plugin", rdma_mlx5_vfmig_plugin_init,
		   rdma_mlx5_vfmig_plugin_fini)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__CHECKPOINT_DEVICES,
			rdma_mlx5_vfmig_plugin_checkpoint_devices)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT,
			rdma_mlx5_vfmig_plugin_claim_uverbs_context)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT,
			rdma_mlx5_vfmig_plugin_dump_uverbs_context)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_PD,
			rdma_mlx5_vfmig_plugin_dump_uobj_pd)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ,
			rdma_mlx5_vfmig_plugin_dump_uobj_cq)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_QP,
			rdma_mlx5_vfmig_plugin_dump_uobj_qp)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_PD_UHW_PACK,
			rdma_mlx5_vfmig_plugin_restore_uobj_pd_uhw_pack)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_CQ_UHW_PACK,
			rdma_mlx5_vfmig_plugin_restore_uobj_cq_uhw_pack)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_MR_UHW_PACK,
			rdma_mlx5_vfmig_plugin_restore_uobj_mr_uhw_pack)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_QP_UHW_PACK,
			rdma_mlx5_vfmig_plugin_restore_uobj_qp_uhw_pack)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_CQ_NEEDS_PIE,
			rdma_mlx5_vfmig_plugin_restore_uobj_cq_needs_pie)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_QP_NEEDS_PIE,
			rdma_mlx5_vfmig_plugin_restore_uobj_qp_needs_pie)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA,
			rdma_mlx5_vfmig_plugin_handle_device_vma)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__UPDATE_VMA_MAP,
			rdma_mlx5_vfmig_plugin_update_vma_map)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV,
			rdma_mlx5_vfmig_plugin_open_uverbs_cdev)

/*
 * RDMA sharing policy: EXCLUSIVE.
 *
 * mlx5 SR-IOV VF migration snapshots and restores the entire VF as
 * one atomic unit (the QUERY_VF / SAVE_VF / LOAD_VF ioctls all
 * operate at VF granularity, not per-uverbs-context). Any context
 * any other process holds on the same VF will be invalidated by
 * the eventual LOAD_VF on the destination -- the device-side state
 * (queue pairs, completion queues, memory keys) gets fully replaced
 * with the snapshot, so by the time the restored process resumes
 * the cohabiting process's hardware-backed handles point at stale
 * or freed objects.
 *
 * Cross-tree exclusivity check (criu/rdma.c) consults this to
 * refuse a dump in which the snapshot tree shares a tracked VF
 * with any pid not in the snapshot. The operator's options at that
 * point are: include the cohabiting pid in the snapshot, stop it
 * before dumping, or, if they really know what they're doing,
 * detach its uverbs context first. EXCLUSIVE is also what we'd
 * default to anyway if this declaration were missing -- we
 * declare it explicitly so future maintainers see the intent.
 */
CR_PLUGIN_DECLARE_RDMA_SHARING(CR_RDMA_SHARING_EXCLUSIVE);

/*
 * RDMA provided driver: RCD_MLX5_SRIOV_VFMIG.
 *
 * Symmetric with the RCD_MLX5_SRIOV_VFMIG return value of
 * rdma_mlx5_vfmig_plugin_claim_uverbs_context() above. The
 * dispatchers in criu/rdma.c (rdma_dispatch_dump_uverbs_context
 * and rdma_dispatch_open_uverbs_cdev) use this constant to find
 * the right plugin to invoke when an image's
 * UverbsFileEntry.criu_driver names RCD_MLX5_SRIOV_VFMIG -- both
 * for dump-side capture and for restore-side cdev open + LOAD
 * dance. Without this declaration the plugin's CLAIM would still
 * succeed (CLAIM walks the hook chain by registration, not by
 * driver), but the dump-side dispatcher would fail to find the
 * winning plugin to invoke DUMP_UVERBS_CONTEXT on, and the
 * restore-side dispatcher would have no plugin to ask for the
 * destination cdev. Land both halves together.
 */
CR_PLUGIN_DECLARE_RDMA_PROVIDED_DRIVER(RDMA_CRIU_DRIVER__RCD_MLX5_SRIOV_VFMIG);
