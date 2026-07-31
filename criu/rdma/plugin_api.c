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

/*
 * Restore-side uverbs-cdev open dispatch.
 *
 * Walk the loaded plugin list and dispatch the OPEN_UVERBS_CDEV hook to
 * the single plugin whose cr_rdma_provided_driver constant matches the
 * image's criu_driver. Keying by criu_driver -- not by hook-chain order
 * -- is the restore-side replay of the dump-time exactly-one-claim
 * guarantee: the hook chain holds every plugin that registered the hook
 * in unspecified order, so a blind "call the first one" would happily
 * hand an rxe cdev to an mlx5 plugin (or vice versa) when both .so are
 * loaded.
 *
 * Failure modes (all hard):
 *   - image has no criu_driver (too old): fail.
 *   - two plugins declare the same provided-driver: operator's plugin
 *     set is inconsistent; we cannot know which the image was dumped
 *     against.
 *   - no plugin matches: the destination is missing the source's
 *     plugin (uverbsfd_validate_claim should have caught this; defence
 *     in depth).
 * The matching plugin's hook owns its own pr_err on failure.
 */
int rdma_dispatch_open_uverbs_cdev(const UverbsFileEntry *uvfe)
{
	plugin_desc_t *this;
	plugin_desc_t *winner = NULL;
	const char *winner_name = NULL;
	CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV_t *fn;

	if (!uvfe->has_criu_driver) {
		pr_err("uverbsfd id %#x: no criu_driver in image; cannot dispatch OPEN_UVERBS_CDEV. Image too old.\n",
		       uvfe->id);
		return -1;
	}

	list_for_each_entry(this, &cr_plugin_ctl.head, list) {
		const int *p;

		if (!this->d || !this->dlhandle)
			continue;
		if (!this->d->hooks[CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV])
			continue;
		p = (const int *)dlsym(this->dlhandle, CR_PLUGIN_RDMA_PROVIDED_DRIVER_SYM);
		if (!p)
			continue;
		if ((uint32_t)*p != uvfe->criu_driver)
			continue;

		if (winner) {
			pr_err("uverbsfd id %#x: multiple plugins declare cr_rdma_provided_driver=%d ('%s' and '%s'); "
			       "operator's plugin set is inconsistent.\n",
			       uvfe->id, (int)uvfe->criu_driver, winner_name, this->d->name);
			return -1;
		}
		winner = this;
		winner_name = this->d->name;
	}

	if (!winner) {
		pr_err("uverbsfd id %#x: no loaded RDMA plugin exports cr_rdma_provided_driver=%d for ibdev=%s. "
		       "Restore cannot proceed without a plugin to open the destination cdev.\n",
		       uvfe->id, (int)uvfe->criu_driver, uvfe->ib_dev ?: "?");
		return -1;
	}

	fn = winner->d->hooks[CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV];
	pr_debug("uverbsfd id %#x: dispatching OPEN_UVERBS_CDEV to plugin '%s' (criu_driver=%d ibdev=%s)\n", uvfe->id,
		 winner_name, (int)uvfe->criu_driver, uvfe->ib_dev ?: "?");
	return fn(uvfe);
}

/*
 * Dump-side per-CQ dispatch.
 *
 * The per-uobject twin of rdma_dispatch_open_uverbs_cdev(): the R3 CQ
 * walker resolves the CQ's driver-private state (rxe: the ring mmap
 * vm_pgoff, via RXE_IB_METHOD_QUERY_CQ) through the owning plugin, not
 * in core, since the query verb is driver-specific. We key by
 * @criu_driver -- the value the dump-time claim recorded on this
 * ucontext -- against each plugin's cr_rdma_provided_driver, for the
 * same reason the open dispatcher does: the DUMP_UOBJ_CQ hook chain
 * holds every RDMA plugin that registered it, so blind first-wins would
 * hand an rxe CQ to an mlx5 plugin when both .so are loaded.
 *
 * Failure modes (all hard, aborting the dump):
 *   - two plugins declare the same provided-driver: inconsistent
 *     operator plugin set (-EEXIST).
 *   - no plugin matches: -ENOENT (the coverage/claim gate should have
 *     caught this at pre-suspend; defence in depth).
 * The matching plugin's hook owns its own pr_err on QUERY_CQ failure.
 */
int rdma_dispatch_dump_uobj_cq(uint32_t criu_driver, const char *ibdev, uint32_t kernel_driver_id, int lfd,
			       uint32_t ufile_handle, pid_t pid, RdmaCqAttrs *cq_attrs, ProtobufCBinaryData *plugin_blob)
{
	plugin_desc_t *this;
	plugin_desc_t *winner = NULL;
	const char *winner_name = NULL;
	CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ_t *fn;

	list_for_each_entry(this, &cr_plugin_ctl.head, list) {
		const int *p;

		if (!this->d || !this->dlhandle)
			continue;
		if (!this->d->hooks[CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ])
			continue;
		p = (const int *)dlsym(this->dlhandle, CR_PLUGIN_RDMA_PROVIDED_DRIVER_SYM);
		if (!p)
			continue;
		if ((uint32_t)*p != criu_driver)
			continue;

		if (winner) {
			pr_err("CQ dump (ibdev=%s handle=%u): multiple plugins declare cr_rdma_provided_driver=%u "
			       "('%s' and '%s'); operator's plugin set is inconsistent.\n",
			       ibdev ?: "?", ufile_handle, criu_driver, winner_name, this->d->name);
			return -EEXIST;
		}
		winner = this;
		winner_name = this->d->name;
	}

	if (!winner) {
		pr_err("CQ dump (ibdev=%s handle=%u): no loaded RDMA plugin exports cr_rdma_provided_driver=%u; "
		       "cannot capture per-CQ driver state.\n",
		       ibdev ?: "?", ufile_handle, criu_driver);
		return -ENOENT;
	}

	fn = winner->d->hooks[CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ];
	pr_debug("CQ dump: dispatching DUMP_UOBJ_CQ to plugin '%s' (criu_driver=%u ibdev=%s handle=%u)\n", winner_name,
		 criu_driver, ibdev ?: "?", ufile_handle);
	return fn(ibdev, kernel_driver_id, lfd, ufile_handle, pid, cq_attrs, plugin_blob);
}

/*
 * Restore-side per-CQ UHW-pack dispatch.
 *
 * The restore-time twin of rdma_dispatch_dump_uobj_cq(): core builds the
 * driver-agnostic half of UVERBS_METHOD_RESTORE_CQ and delegates the
 * driver-private UHW (rxe: rxe_restore_cq_req + CQE image) back to the
 * owning plugin, keyed by @criu_driver against each plugin's
 * cr_rdma_provided_driver -- same reasoning as the dump dispatch (the
 * hook chain alone can't tell an rxe CQ from an mlx5 one).
 *
 * Unlike the dump dispatch we key on provided-driver alone, not on hook
 * presence: a matched plugin that exposes no UHW_PACK hook is a valid
 * "this driver has no per-CQ UHW" case and yields an empty @uhw (rc 0),
 * leaving core to issue a UHW-less RESTORE_CQ. Hard failures:
 *   - two plugins declare the same provided-driver (-EEXIST).
 *   - no plugin matches (-ENOENT).
 */
int rdma_dispatch_restore_cq_uhw_pack(uint32_t criu_driver, const RdmaUobjEntry *e, struct rdma_uhw_spec *uhw)
{
	plugin_desc_t *this;
	plugin_desc_t *winner = NULL;
	const char *winner_name = NULL;
	CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_CQ_UHW_PACK_t *fn;

	list_for_each_entry(this, &cr_plugin_ctl.head, list) {
		const int *p;

		if (!this->d || !this->dlhandle)
			continue;
		p = (const int *)dlsym(this->dlhandle, CR_PLUGIN_RDMA_PROVIDED_DRIVER_SYM);
		if (!p)
			continue;
		if ((uint32_t)*p != criu_driver)
			continue;

		if (winner) {
			pr_err("CQ restore (ufile_handle=%u): multiple plugins declare cr_rdma_provided_driver=%u "
			       "('%s' and '%s'); operator's plugin set is inconsistent.\n",
			       e && e->has_ufile_handle ? e->ufile_handle : 0, criu_driver, winner_name, this->d->name);
			return -EEXIST;
		}
		winner = this;
		winner_name = this->d->name;
	}

	if (!winner) {
		pr_err("CQ restore (ufile_handle=%u): no loaded RDMA plugin exports cr_rdma_provided_driver=%u; "
		       "cannot reshape per-CQ UHW.\n",
		       e && e->has_ufile_handle ? e->ufile_handle : 0, criu_driver);
		return -ENOENT;
	}

	fn = winner->d->hooks[CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_CQ_UHW_PACK];
	if (!fn) {
		pr_debug("CQ restore: plugin '%s' exposes no RESTORE_UOBJ_CQ_UHW_PACK; issuing UHW-less RESTORE_CQ "
			 "(criu_driver=%u)\n",
			 winner_name, criu_driver);
		return 0;
	}

	pr_debug("CQ restore: dispatching RESTORE_UOBJ_CQ_UHW_PACK to plugin '%s' (criu_driver=%u ufile_handle=%u)\n",
		 winner_name, criu_driver, e && e->has_ufile_handle ? e->ufile_handle : 0);
	return fn(e, uhw);
}
