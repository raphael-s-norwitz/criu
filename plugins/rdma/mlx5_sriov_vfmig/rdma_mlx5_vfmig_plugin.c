/*
 * CRIU RDMA mlx5_sriov_vfmig plugin.
 *
 * Companion to plugins/rdma/rxe/. Host-driven save/restore of an mlx5
 * SR-IOV VF's firmware state (via the per-PF /dev/mlx5_vfmig char
 * device) plus its RDMA uverbs objects (shaped with mlx5-specific
 * UHW). Built up one capability at a time:
 *
 *   - the loadable skeleton (previous commit).
 *   - this commit: presence detection. init() walks /dev/mlx5_vfmig,
 *     opens each per-PF char device, and counts tracked VFs via the
 *     MLX5_VFMIG_IOC_QUERY_VF ioctl. A VF is eligible for save/restore
 *     through this plugin iff QUERY_VF reports tracked=1 -- the same
 *     bit that gates the per-VF unmanaged IOMMU domain + deterministic
 *     IOVA allocator on the destination, so an untracked VF cannot
 *     round-trip a SAVE/LOAD blob even with its migratable bit set.
 *   - next: the per-context claim hook, then the dump/restore hooks.
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

#include "vfmig_internal.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

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
	pr_info("fini (stage %d ret %d): was %s, %d tracked VF(s) across %d PF(s)\n", stage, ret,
		vfmig_active ? "active" : "inactive", vfmig_tracked_vf_count, vfmig_pf_count);
}

CR_PLUGIN_REGISTER("rdma_mlx5_vfmig_plugin", rdma_mlx5_vfmig_plugin_init, rdma_mlx5_vfmig_plugin_fini)
