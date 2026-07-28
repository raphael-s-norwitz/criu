/*
 * RDMA plugin-arbitration glue.
 *
 * The seam between criu core and the per-provider RDMA plugins
 * (plugins/rdma/rxe, plugins/rdma/mlx5_sriov_vfmig, ...). Core never
 * hard-codes which plugin owns a given ibdev; instead it asks every
 * loaded RDMA-class plugin, via CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_
 * CONTEXT, and enforces an exactly-one-claim policy here.
 *
 * Public surface (declared in criu/include/rdma.h):
 *   rdma_arbitrate_plugin_claim()
 *
 * No shared static state: the arbitration is a pure function of the
 * (ibdev, kernel_driver_id) pair and the set of loaded plugins.
 */

#include <errno.h>
#include <stdint.h>

#include "common/list.h"
#include "criu-plugin.h"
#include "log.h"
#include "plugin.h"
#include "rdma.h"

#include "images/rdma_criu.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "rdma: "

/*
 * Walk every plugin that registered the RDMA_CLAIM_UVERBS_CONTEXT
 * hook and ask each one whether it claims the given uverbs context.
 *
 * Arbitration policy is exactly-one-claim:
 *   - 0 plugins claim   -> RCD_UNKNOWN return, treated by caller as
 *                          "no CRIU support for this device, fail
 *                          dump (or fail restore -- same iterator
 *                          runs in both directions)".
 *   - 1 plugin claims   -> return that plugin's RdmaCriuDriver value;
 *                          *claimer_name (if non-NULL) is set to the
 *                          plugin's name for diagnostics.
 *   - 2+ plugins claim  -> -EEXIST. The operator's plugin set is
 *                          inconsistent (e.g. two plugins both think
 *                          they own mlx5_core SAVE/LOAD) and we'd
 *                          rather fail loudly than pick arbitrarily.
 *   - any plugin fn returns < 0 -> propagated as a hard error
 *                          (probe failure is distinct from "decline").
 *
 * Iterates the plugin list in registration order; that order is not
 * stable across runs, hence no implicit "first wins" semantics.
 */
int rdma_arbitrate_plugin_claim(const char *ibdev, uint32_t kernel_driver_id,
				const char **claimer_name)
{
	plugin_desc_t *this;
	int winner = RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	const char *winner_name = NULL;

	list_for_each_entry(this, &cr_plugin_ctl.hook_chain[CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT],
			    link[CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT]) {
		CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT_t *fn =
			this->d->hooks[CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT];
		int r = fn(ibdev, kernel_driver_id);

		if (r < 0) {
			pr_err("plugin '%s' claim() probe failed for ibdev=%s kdrv=%u: %d\n", this->d->name, ibdev,
			       kernel_driver_id, r);
			return r;
		}
		if (r == RDMA_CRIU_DRIVER__RCD_UNKNOWN)
			continue;
		if (winner != RDMA_CRIU_DRIVER__RCD_UNKNOWN) {
			pr_err("RDMA plugin claim conflict on ibdev=%s: '%s' (rcd=%d) and '%s' (rcd=%d) both claim. "
			       "Operator's plugin set is inconsistent.\n",
			       ibdev, winner_name, winner, this->d->name, r);
			return -EEXIST;
		}
		winner = r;
		winner_name = this->d->name;
	}

	if (claimer_name)
		*claimer_name = winner_name;
	return winner;
}
