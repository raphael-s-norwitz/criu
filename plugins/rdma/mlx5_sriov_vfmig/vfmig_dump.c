/*
 * mlx5_sriov_vfmig dump-side state.
 *
 * This commit introduces only the claimed-VF cache. The claim hook
 * (CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT) already resolves every
 * snapshot-tree uverbs context's (ibdev, pf_bdf, vf_id) and confirms
 * QUERY_VF.tracked=1 before it returns RCD_MLX5_SRIOV_VFMIG. Recording
 * each VF we win the claim for lets the dump-side hooks added in later
 * commits -- CHECKPOINT_DEVICES (suspend) and the fini(DUMP) SAVE drain
 * -- act on exactly that set without re-walking /proc/<pid>/fd or
 * re-querying sysfs.
 *
 * The set is deduplicated by (pf_bdf, vf_id): a single VF can back
 * several uverbs contexts (e.g. one per worker thread, or across
 * several pids in the snapshot tree), and the firmware SAVE_VHCA_STATE
 * is per-VF, not per-context. Reset at init()/fini() via
 * vfmig_claimed_clear().
 */

#include "criu-log.h"

#include "vfmig_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_mlx5_vfmig_plugin: "

struct vfmig_claimed_vf {
	struct vfmig_claimed_vf *next;
	char ibdev[64];
	char pf_bdf[64];
	uint32_t vf_id;
};

static struct vfmig_claimed_vf *vfmig_claimed_head;

void vfmig_claimed_add(const char *ibdev, const char *pf_bdf, uint32_t vf_id)
{
	struct vfmig_claimed_vf *p;

	for (p = vfmig_claimed_head; p; p = p->next)
		if (p->vf_id == vf_id && !strcmp(p->pf_bdf, pf_bdf))
			return; /* already recorded -- one VF, many contexts */

	p = malloc(sizeof(*p));
	if (!p) {
		pr_err("claimed-VF cache: out of memory recording %s (pf=%s vf_id=%u)\n", ibdev, pf_bdf, vf_id);
		return;
	}

	snprintf(p->ibdev, sizeof(p->ibdev), "%s", ibdev);
	snprintf(p->pf_bdf, sizeof(p->pf_bdf), "%s", pf_bdf);
	p->vf_id = vf_id;
	p->next = vfmig_claimed_head;
	vfmig_claimed_head = p;

	pr_debug("claimed-VF cache: recorded %s (pf=%s vf_id=%u)\n", ibdev, pf_bdf, vf_id);
}

void vfmig_claimed_clear(void)
{
	struct vfmig_claimed_vf *p, *n;

	for (p = vfmig_claimed_head; p; p = n) {
		n = p->next;
		free(p);
	}
	vfmig_claimed_head = NULL;
}
