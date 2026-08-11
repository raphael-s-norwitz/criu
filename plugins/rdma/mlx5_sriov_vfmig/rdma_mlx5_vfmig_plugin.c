/*
 * CRIU RDMA mlx5_sriov_vfmig plugin.
 *
 * Companion to plugins/rdma/rxe/. Host-driven save/restore of an mlx5
 * SR-IOV VF's firmware state (via the per-PF /dev/mlx5_vfmig char
 * device) plus its RDMA uverbs objects (shaped with mlx5-specific
 * UHW). Built up one capability at a time:
 *
 *   - the loadable skeleton.
 *   - presence detection: init() walks /dev/mlx5_vfmig, opens each
 *     per-PF char device, and counts tracked VFs via the
 *     MLX5_VFMIG_IOC_QUERY_VF ioctl. A VF is eligible for save/restore
 *     through this plugin iff QUERY_VF reports tracked=1 -- the same
 *     bit that gates the per-VF unmanaged IOMMU domain + deterministic
 *     IOVA allocator on the destination, so an untracked VF cannot
 *     round-trip a SAVE/LOAD blob even with its migratable bit set.
 *   - the per-context claim hook. Given a uverbs context's ibdev,
 *     resolve ibdev -> VF BDF -> PF BDF -> vf_id and re-check QUERY_VF
 *     tracked=1; on success claim the context as RCD_MLX5_SRIOV_VFMIG.
 *     The matching provided-driver + sharing declarations let dump-time
 *     arbitration route this driver's contexts to this plugin.
 *   - the claimed-VF cache (vfmig_dump.c). A successful claim records
 *     (ibdev, pf_bdf, vf_id) into a dedup'd set so the dump-side drain
 *     can act on exactly the VFs backing the snapshot tree without
 *     re-walking sysfs.
 *   - this commit: SAVE on dump. fini(DUMP) drains the claimed set,
 *     runs SAVE_VHCA_STATE per VF, writes one firmware blob per VF plus
 *     one Mlx5VfmigStateEntry per VF into the image dir. Still no
 *     restore-side hooks -- LOAD lands next.
 *   - next: the restore path (LOAD + MARK_RESTORED + bind).
 *
 * Vendored UAPI header:
 *   The plugin compiles against plugins/rdma/mlx5_sriov_vfmig/uapi/
 *   linux/mlx5_vfmig.h, vendored from the kernel source so criu's
 *   build does not depend on a bleeding-edge system header. Pass
 *   MLX5_VFMIG_UAPI_INCLUDE=<dir> to the plugin's make to override the
 *   include search root (e.g. a local kernel tree's include/uapi/)
 *   when iterating on the kernel UAPI in parallel; the Makefile warns
 *   at build time if the vendored copy drifts from the system header.
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
 * Process-global activation state, exported via vfmig_internal.h so
 * the hooks added in later commits can short-circuit cheaply when no
 * tracked VFs are in flight on this host.
 */
bool vfmig_active = false;
static int vfmig_tracked_vf_count;
static int vfmig_pf_count;

static int rdma_mlx5_vfmig_plugin_init(int stage)
{
	DIR *d;
	struct dirent *de;

	vfmig_active = false;
	vfmig_tracked_vf_count = 0;
	vfmig_pf_count = 0;
	vfmig_claimed_clear();

	d = opendir(MLX5_VFMIG_DEV_DIR);
	if (!d) {
		/*
		 * No mlx5_vfmig kernel module loaded (or no PFs that
		 * advertise migration capability) is the common case on
		 * hosts without ConnectX-7 + this work-in-progress driver.
		 * Treat as inactive rather than as an error so dropping the
		 * .so into CRIU_LIBS_DIR is safe on any host. (cr_lib_load()
		 * turns a non-zero init() into a fatal startup failure -- see
		 * criu/plugin.c.)
		 */
		pr_info("opendir(%s) failed: %s; assuming no mlx5_vfmig capability, plugin inactive (stage %d)\n",
			MLX5_VFMIG_DEV_DIR, strerror(errno), stage);
		return 0;
	}

	while ((de = readdir(d)) != NULL) {
		char path[PATH_MAX];
		int n;

		if (de->d_name[0] == '.')
			continue;

		snprintf(path, sizeof(path), "%s/%s", MLX5_VFMIG_DEV_DIR, de->d_name);
		vfmig_pf_count++;
		n = probe_pf_cdev(path);
		if (n > 0)
			vfmig_tracked_vf_count += n;
	}

	closedir(d);

	if (vfmig_tracked_vf_count > 0) {
		vfmig_active = true;
		pr_info("active (stage %d): %d tracked VF(s) across %d PF(s)\n", stage, vfmig_tracked_vf_count,
			vfmig_pf_count);
	} else {
		pr_info("inactive (stage %d): %d PF cdev(s) probed, no tracked VFs\n", stage, vfmig_pf_count);
	}

	return 0;
}

static void rdma_mlx5_vfmig_plugin_fini(int stage, int ret)
{
	/*
	 * Drain the SAVE queue at the very end of dump, and only when the
	 * rest of CRIU's dump pipeline succeeded (ret == 0). SAVE_VHCA_STATE
	 * is the most invasive thing this plugin does to the host; firing it
	 * for a dump that has already been declared lost would suspend VFs
	 * and produce blobs that can never be paired with a restorable
	 * image. On the RESTORE stage the claimed set is empty, so the drain
	 * is a no-op there too.
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP && ret == 0)
		vfmig_drain_claimed_in_fini();

	pr_info("fini (stage %d ret %d): was %s, %d tracked VF(s) across %d PF(s)\n", stage, ret,
		vfmig_active ? "active" : "inactive", vfmig_tracked_vf_count, vfmig_pf_count);
	vfmig_claimed_clear();
}

/*
 * Per-context claim hook (CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT).
 *
 * The claim chain for a context backed by an mlx5_core ibdev:
 *
 *   1. Plugin must be active (init() found at least one tracked VF on
 *      the host). If not, decline outright.
 *
 *   2. Kernel driver must be RDMA_DRIVER_MLX5. mlx5_core ibdevs are the
 *      only ones this plugin knows how to handle.
 *
 *   3. The ibdev's PCI device must have a /physfn link, i.e. it must be
 *      a VF (not a PF). PFs are valid mlx5_core ibdevs but vfmig
 *      deliberately operates only on VFs. Decline if missing.
 *
 *   4. The VF must appear under the PF's virtfn<N> sysfs links (we need
 *      vf_id to drive QUERY_VF). Fail closed if not -- a missing virtfn
 *      link on a VF whose physfn we just resolved is a sysfs
 *      inconsistency, not a "decline" condition.
 *
 *   5. /dev/mlx5_vfmig/<pf_bdf> must open. Same reasoning as (4): if
 *      init() saw the cdev directory we expect the cdevs to still be
 *      present at claim time. Failure here propagates as a hard error.
 *
 *   6. MLX5_VFMIG_IOC_QUERY_VF on (pf_bdf, vf_id) must report
 *      tracked=1. tracked=0 -> decline (the per-VF unmanaged IOMMU
 *      domain isn't allocated, so SAVE/LOAD wouldn't round-trip even if
 *      we accepted the dump).
 *
 * Returns RCD_MLX5_SRIOV_VFMIG on a successful claim, RCD_UNKNOWN on
 * any decline (steps 1-3, 6), or a negative errno on the
 * sysfs-inconsistency / open / ioctl failure cases (steps 4, 5).
 */
static int rdma_mlx5_vfmig_plugin_claim_uverbs_context(const char *ibdev, uint32_t kernel_driver_id)
{
	struct mlx5_vfmig_query_vf q;
	char sysfs_path[PATH_MAX];
	char cdev_path[PATH_MAX];
	char vf_bdf[64], pf_bdf[64];
	int vf_id, fd, rc;

	if (!vfmig_active) {
		pr_debug("claim(%s, kdrv=%u): plugin inactive, declining\n", ibdev, kernel_driver_id);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}
	if (kernel_driver_id != RDMA_DRIVER_MLX5) {
		pr_debug("claim(%s, kdrv=%u): not RDMA_DRIVER_MLX5 (%u), declining\n", ibdev, kernel_driver_id,
			 (uint32_t)RDMA_DRIVER_MLX5);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}

	snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/infiniband/%s/device", ibdev);
	if (resolve_pci_bdf_via_symlink(sysfs_path, vf_bdf, sizeof(vf_bdf))) {
		pr_warn("claim(%s): cannot resolve VF BDF via %s\n", ibdev, sysfs_path);
		return -ENOENT;
	}

	snprintf(sysfs_path, sizeof(sysfs_path), "/sys/bus/pci/devices/%s/physfn", vf_bdf);
	if (resolve_pci_bdf_via_symlink(sysfs_path, pf_bdf, sizeof(pf_bdf))) {
		pr_debug("claim(%s, vf_bdf=%s): no /physfn link, this is a PF or non-SR-IOV mlx5_core ibdev; declining\n",
			 ibdev, vf_bdf);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}

	vf_id = find_vf_id_under_pf(pf_bdf, vf_bdf);
	if (vf_id < 0) {
		pr_warn("claim(%s, vf_bdf=%s, pf_bdf=%s): no virtfnN link under PF resolves to this VF -- sysfs inconsistency\n",
			ibdev, vf_bdf, pf_bdf);
		return -ENOENT;
	}

	snprintf(cdev_path, sizeof(cdev_path), "%s/%s", MLX5_VFMIG_DEV_DIR, pf_bdf);
	fd = open(cdev_path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_warn("claim(%s): open(%s) failed: %s\n", ibdev, cdev_path, strerror(errno));
		return -errno;
	}

	memset(&q, 0, sizeof(q));
	q.vf_id = vf_id;
	rc = ioctl(fd, MLX5_VFMIG_IOC_QUERY_VF, &q);
	close(fd);
	if (rc != 0) {
		pr_warn("claim(%s): QUERY_VF(vf_id=%d) on %s failed: %s\n", ibdev, vf_id, cdev_path, strerror(errno));
		return -errno;
	}
	if (!q.tracked) {
		pr_info("claim(%s, vf_bdf=%s, pf=%s, vf_id=%d): VF not in tracked mode, declining\n", ibdev, vf_bdf,
			pf_bdf, vf_id);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}

	pr_info("claim(%s, vf_bdf=%s, pf=%s, vf_id=%d): claiming as RCD_MLX5_SRIOV_VFMIG\n", ibdev, vf_bdf, pf_bdf,
		vf_id);

	/*
	 * Record the VF we just won the claim for. The dump-side hooks
	 * added in later commits (CHECKPOINT_DEVICES suspend, fini(DUMP)
	 * SAVE drain) consume this set; the cache dedups by (pf_bdf,
	 * vf_id) so multiple contexts on the same VF record once.
	 */
	vfmig_claimed_add(ibdev, pf_bdf, (uint32_t)vf_id);
	return RDMA_CRIU_DRIVER__RCD_MLX5_SRIOV_VFMIG;
}

CR_PLUGIN_REGISTER("rdma_mlx5_vfmig_plugin", rdma_mlx5_vfmig_plugin_init, rdma_mlx5_vfmig_plugin_fini)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT, rdma_mlx5_vfmig_plugin_claim_uverbs_context)

/*
 * RDMA sharing policy: EXCLUSIVE.
 *
 * mlx5 SR-IOV VF migration snapshots and restores the entire VF as one
 * atomic unit (the QUERY_VF / SAVE_VF / LOAD_VF ioctls all operate at
 * VF granularity, not per-uverbs-context). Any context another process
 * holds on the same VF will be invalidated by the eventual LOAD_VF on
 * the destination -- the device-side state (queue pairs, completion
 * queues, memory keys) gets fully replaced with the snapshot, so by the
 * time the restored process resumes the cohabiting process's
 * hardware-backed handles point at stale or freed objects. The
 * cross-tree exclusivity check refuses a dump in which the snapshot
 * tree shares a tracked VF with any pid not in the snapshot.
 */
CR_PLUGIN_DECLARE_RDMA_SHARING(CR_RDMA_SHARING_EXCLUSIVE);

/*
 * RDMA provided driver: RCD_MLX5_SRIOV_VFMIG.
 *
 * Symmetric with the RCD_MLX5_SRIOV_VFMIG return value of the claim
 * hook above. Dump-time arbitration uses this constant to route a
 * context this plugin claimed back to this plugin for the eventual
 * DUMP_UVERBS_CONTEXT capture, and the restore side uses it to find the
 * plugin that owns the destination cdev open + LOAD dance. Declared
 * alongside the claim so the two halves land together even though the
 * dump/restore hooks themselves come in later commits.
 */
CR_PLUGIN_DECLARE_RDMA_PROVIDED_DRIVER(RDMA_CRIU_DRIVER__RCD_MLX5_SRIOV_VFMIG);
