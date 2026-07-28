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
 *   rdma_arbitrate_plugin_claim()          -- "which plugin owns this?"
 *   rdma_plugin_sharing_policy_by_name()   -- "is that plugin's device
 *                                             safe to share?"
 *
 * No shared static state: both are pure functions of their inputs and
 * the set of loaded plugins.
 */

#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

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

/*
 * Look up a plugin's RDMA sharing policy by name.
 *
 * The companion to rdma_arbitrate_plugin_claim(): arbitration answers
 * "which plugin owns ibdev D?" via the hook chain, this answers "does
 * that plugin consider D safe to share with non-snapshot pids?" via a
 * dlsym of CR_PLUGIN_RDMA_SHARING_POLICY_SYM ("cr_rdma_sharing_policy",
 * a const int) on the plugin's dlhandle. We match by name because the
 * arbitration helper already hands the caller the claimer's name, and
 * that's the most stable identity we share across the hook chain and
 * the dlhandle list.
 *
 * Returns CR_RDMA_SHARING_EXCLUSIVE if:
 *   - plugin_name is NULL
 *   - the plugin can't be located (shouldn't happen post-arbitration)
 *   - the plugin doesn't export the symbol
 *   - the symbol's value is not a recognised enum value
 *
 * That's deliberate: every "I don't know" path fails closed, so a
 * plugin that forgot to declare its policy is treated as EXCLUSIVE
 * rather than silently allowing a share that might corrupt a
 * non-snapshot peer.
 */
int rdma_plugin_sharing_policy_by_name(const char *plugin_name)
{
	plugin_desc_t *this;

	if (!plugin_name)
		return CR_RDMA_SHARING_EXCLUSIVE;

	list_for_each_entry(this, &cr_plugin_ctl.head, list) {
		const int *p;

		if (!this->d || !this->d->name)
			continue;
		if (strcmp(this->d->name, plugin_name) != 0)
			continue;
		if (!this->dlhandle)
			return CR_RDMA_SHARING_EXCLUSIVE;
		p = (const int *)dlsym(this->dlhandle, CR_PLUGIN_RDMA_SHARING_POLICY_SYM);
		if (!p) {
			pr_debug("plugin '%s' does not export %s; defaulting to EXCLUSIVE\n", plugin_name,
				 CR_PLUGIN_RDMA_SHARING_POLICY_SYM);
			return CR_RDMA_SHARING_EXCLUSIVE;
		}
		if (*p != CR_RDMA_SHARING_SHAREABLE && *p != CR_RDMA_SHARING_EXCLUSIVE) {
			pr_warn("plugin '%s' %s = %d is not a recognised enum value; defaulting to EXCLUSIVE\n",
				plugin_name, CR_PLUGIN_RDMA_SHARING_POLICY_SYM, *p);
			return CR_RDMA_SHARING_EXCLUSIVE;
		}
		return *p;
	}
	pr_debug("plugin '%s' not found in loaded list; defaulting to EXCLUSIVE\n", plugin_name);
	return CR_RDMA_SHARING_EXCLUSIVE;
}
