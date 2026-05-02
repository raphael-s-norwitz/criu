/*
 * Test-only CRIU plugin for cross-tree exclusivity validation.
 *
 * This plugin is a deliberately minimal variant of the production
 * rxe plugin (plugins/rdma/rxe/rdma_rxe_plugin.c) with one
 * difference: it declares CR_RDMA_SHARING_EXCLUSIVE instead of
 * SHAREABLE. It exists solely to exercise the failure path in
 * rdma_check_cross_tree_exclusivity() without needing real
 * exclusive-by-construction hardware (mlx5 SR-IOV VFs etc.).
 *
 * Usage:
 *   1. Build alongside the production plugins (see Makefile).
 *   2. Point CRIU_LIBS_DIR at a directory containing ONLY this
 *      .so (not the production rxe plugin -- two plugins both
 *      claiming rxe contexts is an arbitration conflict, by
 *      design).
 *   3. Run two rxe holders, criu dump one of them, observe a
 *      hard failure with "ibdev=rxe0 ... EXCLUSIVE" diagnostic.
 *
 * Do not ship or install this plugin; it intentionally lies about
 * rxe's sharing semantics. Lives under test/rdma/ so it never gets
 * picked up by /usr/lib/criu/ scans by accident.
 */

#include "criu-log.h"
#include "criu-plugin.h"
#include "images/rdma_criu.pb-c.h"

#include <rdma/ib_user_ioctl_verbs.h>
#include <stdint.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_rxe_test_exclusive: "

static int test_init(int stage)
{
	pr_info("test plugin loaded (stage %d) -- claims as RCD_RXE, "
		"declares EXCLUSIVE for cross-tree test\n", stage);
	return 0;
}

static void test_fini(int stage, int ret) {}

static int test_claim(const char *ibdev, uint32_t kernel_driver_id)
{
	if (kernel_driver_id != RDMA_DRIVER_RXE)
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	pr_info("test claim(%s, kdrv=%u): RCD_RXE\n", ibdev,
		kernel_driver_id);
	return RDMA_CRIU_DRIVER__RCD_RXE;
}

CR_PLUGIN_REGISTER("rdma_rxe_test_exclusive_plugin", test_init, test_fini)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT, test_claim)

CR_PLUGIN_DECLARE_RDMA_SHARING(CR_RDMA_SHARING_EXCLUSIVE);
