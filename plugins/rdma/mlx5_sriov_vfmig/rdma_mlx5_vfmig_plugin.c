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
#include "plugin.h"

#include <linux/mlx5_vfmig.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
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

CR_PLUGIN_REGISTER("rdma_mlx5_vfmig_plugin", rdma_mlx5_vfmig_plugin_init,
		   rdma_mlx5_vfmig_plugin_fini)
