/*
 * Plugin-facing RDMA API.
 *
 * This file holds the helpers RDMA-class plugins call directly,
 * decoupled from the rest of criu/rdma. Today that is just the
 * cdev-VMA recorder (rdma_record_cdev_vma) and the process-global
 * side-table that backs it; future plugin-facing entry points
 * land here too.
 *
 * Public declarations live in criu/include/criu-plugin.h.
 * Cross-file accessors used by the rest of criu/rdma live in
 * criu/include/rdma/internal.h.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "common/list.h"
#include "criu-plugin.h"
#include "log.h"
#include "rdma/internal.h"
#include "xmalloc.h"

#undef LOG_PREFIX
#define LOG_PREFIX "rdma: "

/*
 * Process-global side-table of source-side cdev-mapped VMA
 * offsets, populated by RDMA-class plugins from their
 * CR_PLUGIN_HOOK__PROCESS_DEVICE_VMA hook (see
 * plugins/rdma/rxe/rdma_rxe_plugin.c::rdma_rxe_plugin_process_device_vma)
 * and consumed by the per-uobj DAG dump callbacks (currently just
 * uobj_cq_cb; the future S6 RESTORE_QP/SRQ paths will read from the
 * same table).
 *
 * Why a separate, plugin-fed table rather than re-deriving from
 * /proc/<dumpee>/maps inside criu/rdma/ at uobj_cq_cb time:
 *
 *   - Source-of-truth is the dump-time VMA enumeration. proc_parse
 *     already walks /proc/<pid>/{maps,smaps,map_files} for every
 *     dumpee and surfaces each VMA's pgoff (in bytes) to the
 *     plugin layer via CR_PLUGIN_HOOK__PROCESS_DEVICE_VMA. Re-
 *     reading /proc/<pid>/maps from rdma right before NLDEV-uobj
 *     emission risks racing freezer-released task state on long
 *     dumps and duplicates work we already did.
 *
 *   - Decouples plugin policy from criu/rdma/. The rxe plugin
 *     decides what counts as "its" cdev VMA (driver name probe via
 *     /sys/dev/char) and what gets recorded; criu/rdma/ just
 *     consumes a (pid, ibdev) -> [pgoff_bytes...] map.
 *
 *   - Same dispatcher pattern lets future plugins (e.g. mlx5_vfmig
 *     UAR / blueflame VMAs) record per-VMA hints without coupling
 *     to rxe-specific code in criu/rdma/.
 *
 * Keys: (pid, ibdev). Values: an ordered list of vm_pgoff_bytes,
 * insertion order = source-time mmap() order = source-time
 * CMD_CREATE_<TYPE> order. Pop is FIFO, so the per-uobj callback
 * matches NLDEV's per-class enumeration order against the source's
 * creation order. v0 multi-uobj caveat (CQ/QP order is mixed
 * across types) is unchanged from the prior /proc-walk
 * implementation -- the plugin records exactly what the kernel
 * gave the source userspace via mmap, no more, no less.
 *
 * Lifecycle: entries are appended during the per-task vma walk
 * (proc_parse_smaps -> handle_vma_plugin -> plugin hook ->
 * rdma_record_cdev_vma), drained during rdma_dump_uobj_dag's
 * per-uobj callbacks (uobj_cq_cb -> rdma_pop_cdev_vma_offset),
 * and freed wholesale in rdma_dump_uobj_dag's cleanup path. The
 * single-threaded dump invariant (cr-dump.c walks pstree
 * sequentially, then NLDEV walks happen once, then cleanup)
 * removes the need for per-list locking.
 */
struct rdma_cdev_vma_rec {
	pid_t pid;
	char ibdev[64];
	uint64_t pgoff_bytes;
	bool consumed;
	struct list_head link;
};
static LIST_HEAD(rdma_cdev_vma_recs);

/*
 * Append a (pid, ibdev, pgoff_bytes) triple to the process-global
 * side-table. Called from RDMA-class plugins'
 * CR_PLUGIN_HOOK__PROCESS_DEVICE_VMA implementations once the
 * plugin has determined the VMA backs an ibdev it owns.
 *
 * Returns 0 on success, -1 on allocation failure (the caller
 * propagates -ENOMEM up to run_plugins, which is treated by
 * proc_parse.c::handle_vma_plugin as a hard dump error).
 *
 * Insertion order is preserved (list_add_tail). Plugins call this
 * once per VMA in the order /proc/<pid>/smaps emits them, which
 * for cdev mmaps is virtual-address order; that aligns with
 * source-time mmap() order on rxe (see drivers/infiniband/sw/rxe/
 * rxe_mmap.c: each new info gets the next monotonic vm_pgoff and
 * userspace mmap()s in CMD_CREATE_<TYPE> order). For mlx5 the
 * order across UAR/db/CQ-ring VMAs is more complex; that's a v0
 * limitation that doesn't affect rxe.
 */
int rdma_record_cdev_vma(pid_t pid, const char *ibdev,
			 uint64_t pgoff_bytes)
{
	struct rdma_cdev_vma_rec *r;

	r = xzalloc(sizeof(*r));
	if (!r)
		return -1;
	r->pid = pid;
	r->pgoff_bytes = pgoff_bytes;
	snprintf(r->ibdev, sizeof(r->ibdev), "%.*s",
		 (int)(sizeof(r->ibdev) - 1), ibdev);
	list_add_tail(&r->link, &rdma_cdev_vma_recs);
	pr_debug("uobj DAG: recorded cdev VMA pid=%d ibdev=%s "
		 "pgoff=%#" PRIx64 "\n", pid, r->ibdev, pgoff_bytes);
	return 0;
}

/*
 * Pop the next-in-FIFO unconsumed cdev VMA offset for (pid, ibdev).
 * Returns 0 + sets *out on success; -ENOENT if no unconsumed
 * record matches the key (caller -- typically the rxe plugin's
 * dump-uobj-cq hook -- treats that as "no source VMA captured for
 * this CQ" and packs an empty plugin_blob, so the restore side
 * falls back to the kernel's monotonic counter; matches the
 * source iff the source's counter was also fresh, which is true
 * only for very simple holders).
 */
int rdma_pop_cdev_vma_offset(pid_t pid, const char *ibdev,
			     uint64_t *out)
{
	struct rdma_cdev_vma_rec *r;

	list_for_each_entry(r, &rdma_cdev_vma_recs, link) {
		if (r->consumed)
			continue;
		if (r->pid != pid)
			continue;
		if (strncmp(r->ibdev, ibdev, sizeof(r->ibdev)) != 0)
			continue;
		r->consumed = true;
		*out = r->pgoff_bytes;
		return 0;
	}
	return -ENOENT;
}

/*
 * Drop every recorded cdev VMA offset. Called from the cleanup tail
 * of rdma_dump_uobj_dag() so the second invocation in a long-running
 * criu service process (post-restore criu service replay) doesn't
 * see stale entries from the prior dump.
 */
void rdma_cdev_vma_recs_free(void)
{
	struct rdma_cdev_vma_rec *r, *tmp;

	list_for_each_entry_safe(r, tmp, &rdma_cdev_vma_recs, link) {
		list_del(&r->link);
		xfree(r);
	}
}
