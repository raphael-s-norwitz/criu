/*
 * CRIU RDMA mlx5_sriov_vfmig plugin.
 *
 * Companion to plugins/rdma/rxe/. Host-driven save/restore of an mlx5
 * SR-IOV VF's firmware state (via the per-PF /dev/mlx5_vfmig char
 * device) plus its RDMA uverbs objects (shaped with mlx5-specific
 * UHW). Built up one capability at a time:
 *
 *   - this commit: the loadable skeleton. init()/fini() are inert and
 *     the plugin is always inactive, so dropping the .so into
 *     CRIU_LIBS_DIR is a no-op on every host.
 *   - next: presence detection (walk /dev/mlx5_vfmig, count tracked
 *     VFs via MLX5_VFMIG_IOC_QUERY_VF).
 *   - then: the per-context claim hook, then the dump/restore hooks.
 *
 * Vendored UAPI header:
 *   Once presence detection lands the plugin compiles against
 *   plugins/rdma/mlx5_sriov_vfmig/uapi/linux/mlx5_vfmig.h, vendored
 *   from the kernel source so criu's build does not depend on a
 *   bleeding-edge system header. (Introduced with that commit.)
 */

#include "criu-log.h"
#include "criu-plugin.h"

#include "vfmig_internal.h"

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_mlx5_vfmig_plugin: "

/*
 * Process-global activation state, exported via vfmig_internal.h so
 * the hooks added in later commits can short-circuit cheaply when no
 * tracked VFs are in flight on this host. The skeleton leaves it
 * false unconditionally.
 */
bool vfmig_active = false;

static int rdma_mlx5_vfmig_plugin_init(int stage)
{
	vfmig_active = false;
	pr_info("init (stage %d): skeleton, inactive\n", stage);
	return 0;
}

static void rdma_mlx5_vfmig_plugin_fini(int stage, int ret)
{
	pr_info("fini (stage %d ret %d): was %s\n", stage, ret, vfmig_active ? "active" : "inactive");
}

CR_PLUGIN_REGISTER("rdma_mlx5_vfmig_plugin", rdma_mlx5_vfmig_plugin_init, rdma_mlx5_vfmig_plugin_fini)
