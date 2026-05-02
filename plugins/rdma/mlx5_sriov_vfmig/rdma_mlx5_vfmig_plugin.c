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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_mlx5_vfmig_plugin: "

#define MLX5_VFMIG_DEV_DIR "/dev/mlx5_vfmig"

static bool vfmig_active = false;
static int  vfmig_tracked_vf_count = 0;
static int  vfmig_pf_count = 0;

/*
 * Probe one PF cdev. Returns the number of VFs on this PF that have
 * MLX5_VFMIG_IOC_SET_TRACKED { enable=1 } currently in effect, or -1
 * on a hard ioctl/open failure (which we report but treat as "no
 * tracked VFs from this PF" rather than as a fatal plugin error --
 * a misbehaving cdev should not poison criu startup).
 *
 * Discovery model: per the kernel UAPI doc on MLX5_VFMIG_IOC_QUERY_VF,
 * num_vfs is filled even when vf_id is out of range (the call returns
 * -ERANGE in that case but the output struct is still populated), so
 * one issuance with vf_id=0 tells us how many VFs to iterate over,
 * and a separate per-vf loop reads the @tracked bit. This is the
 * "iterate 0..num_vfs-1" pattern the kernel UAPI explicitly invites.
 */
static int probe_pf_cdev(const char *path)
{
	struct mlx5_vfmig_query_vf q;
	uint32_t num_vfs, vf;
	int fd, rc, tracked = 0;

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_warn("open(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}

	memset(&q, 0, sizeof(q));
	q.vf_id = 0;
	rc = ioctl(fd, MLX5_VFMIG_IOC_QUERY_VF, &q);
	if (rc != 0 && errno != ERANGE) {
		pr_warn("QUERY_VF(vf_id=0) on %s failed: %s\n", path,
			strerror(errno));
		close(fd);
		return -1;
	}

	num_vfs = q.num_vfs;
	if (rc == 0 && q.tracked)
		tracked++;

	for (vf = 1; vf < num_vfs; vf++) {
		struct mlx5_vfmig_query_vf qq;

		memset(&qq, 0, sizeof(qq));
		qq.vf_id = vf;
		if (ioctl(fd, MLX5_VFMIG_IOC_QUERY_VF, &qq) != 0) {
			pr_warn("QUERY_VF(vf_id=%u) on %s failed: %s\n", vf,
				path, strerror(errno));
			continue;
		}
		if (qq.tracked)
			tracked++;
	}

	pr_debug("%s: num_vfs=%u tracked=%d\n", path, num_vfs, tracked);
	close(fd);
	return tracked;
}

static int rdma_mlx5_vfmig_plugin_init(int stage)
{
	DIR *d;
	struct dirent *de;

	vfmig_active = false;
	vfmig_tracked_vf_count = 0;
	vfmig_pf_count = 0;

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

	return 0;
}

static void rdma_mlx5_vfmig_plugin_fini(int stage, int ret)
{
	pr_info("fini (stage %d ret %d): was %s, %d tracked VF(s) across "
		"%d PF(s)\n",
		stage, ret, vfmig_active ? "active" : "inactive",
		vfmig_tracked_vf_count, vfmig_pf_count);
}

/*
 * Resolve a /sys/.../device symlink under @sysfs_link_path to its
 * basename (the PCI BDF the symlink points at). Caller-supplied
 * @out is sized in @outsz. Returns 0 on success, -1 otherwise.
 *
 * Used to walk the chain
 *   /sys/class/infiniband/<ibdev>/device   ->  VF BDF
 *   /sys/bus/pci/devices/<vf>/physfn       ->  PF BDF
 * needed to map an ibdev to its owning mlx5 PF cdev.
 */
static int resolve_pci_bdf_via_symlink(const char *sysfs_link_path,
				       char *out, size_t outsz)
{
	char target[PATH_MAX];
	const char *base;
	ssize_t n;

	n = readlink(sysfs_link_path, target, sizeof(target) - 1);
	if (n <= 0)
		return -1;
	target[n] = '\0';
	base = strrchr(target, '/');
	snprintf(out, outsz, "%.*s", (int)(outsz - 1), base ? base + 1 : target);
	return 0;
}

/*
 * Map a VF's PCI BDF to its parent PF's vf_id (i.e. the index
 * @virtfnN under the PF's pci_dev sysfs node). Returns the vf_id
 * on success or -1 if no virtfn link matches @vf_bdf -- which is
 * the expected outcome for any non-VF mlx5_core ibdev (PFs land
 * here too) and is therefore not an error per se, just a "decline"
 * signal back up the claim chain.
 */
static int find_vf_id_under_pf(const char *pf_bdf, const char *vf_bdf)
{
	char path[PATH_MAX];
	struct dirent *de;
	DIR *d;
	int vf_id = -1;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s", pf_bdf);
	d = opendir(path);
	if (!d)
		return -1;

	while ((de = readdir(d)) != NULL) {
		char vlpath[PATH_MAX], vlbase[64];

		if (strncmp(de->d_name, "virtfn", 6) != 0)
			continue;
		if (snprintf(vlpath, sizeof(vlpath), "%s/%s", path,
			     de->d_name) >= (int)sizeof(vlpath))
			continue;
		if (resolve_pci_bdf_via_symlink(vlpath, vlbase,
						sizeof(vlbase)) != 0)
			continue;
		if (strcmp(vlbase, vf_bdf) == 0) {
			vf_id = atoi(de->d_name + strlen("virtfn"));
			break;
		}
	}

	closedir(d);
	return vf_id;
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
	return RDMA_CRIU_DRIVER__RCD_MLX5_SRIOV_VFMIG;
}

CR_PLUGIN_REGISTER("rdma_mlx5_vfmig_plugin", rdma_mlx5_vfmig_plugin_init,
		   rdma_mlx5_vfmig_plugin_fini)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT,
			rdma_mlx5_vfmig_plugin_claim_uverbs_context)

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
