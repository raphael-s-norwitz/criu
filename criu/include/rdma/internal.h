#ifndef __CR_RDMA_INTERNAL_H__
#define __CR_RDMA_INTERNAL_H__

/*
 * Cross-file accessors shared between the criu/rdma/ sources.
 * Strictly NOT a public surface -- callers outside criu/rdma/
 * should include criu/include/rdma.h instead.
 */

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "common/list.h"
#include "plugin.h"		/* plugin_desc_t for cached per-ufile dispatch */

/*
 * plugin_api.c: process-global side-table of source-side
 * cdev-mapped VMA offsets. Producer is rdma_record_cdev_vma()
 * (declared in criu-plugin.h, called from RDMA-class plugins'
 * CR_PLUGIN_HOOK__PROCESS_DEVICE_VMA). Consumers live in
 * criu/rdma/rdma.c (the per-uobj DAG dump callbacks). See the
 * block comment over rdma_cdev_vma_rec in plugin_api.c for
 * lifecycle details.
 */
int rdma_pop_cdev_vma_offset(pid_t pid, const char *ibdev,
			     uint64_t *out);
void rdma_cdev_vma_recs_free(void);

/*
 * driver.c: chrdev (major,minor) -> ibdev name resolver. Used
 * by uverbsfd.c's dump_uverbsfile() to identify the source-side
 * uverbs cdev a held fd refers to. The two driver-name helpers
 * this calls into (rdma_driver_name_from_ibdev,
 * rdma_driver_name_to_id) are public and live in rdma.h.
 */
int rdma_ibdev_from_chrdev(unsigned int maj, unsigned int min,
			   char *out, size_t outsz);

/*
 * uverbsfd.c <-> rdma.c (R3 dump-side DAG walker) shared state.
 *
 * dump_uverbsfile() (in uverbsfd.c) appends one entry per
 * checkpointed uverbs context; rdma_dump_uobj_dag() (still in
 * rdma.c) walks the list at end-of-dump to drive per-ibdev
 * NLDEV walks and per-MR QUERY_MR ioctls.
 *
 * The list is single-threaded by construction (cr-dump.c walks
 * pstree sequentially, then NLDEV walks happen once, then
 * cleanup), grows monotonically during dump, and is freed by
 * rdma_dump_uobj_dag()'s cleanup path. holder_uctx_fd is the
 * O_CLOEXEC dup of the holder's cdev fd captured for the
 * QUERY_MR walk; -1 means "not stashed" (dup failed).
 *
 * @plugin caches the CRIU plugin that won CLAIM arbitration for
 * this ufile. Resolved once in dump_uverbsfile() (right after
 * rdma_arbitrate_plugin_claim() returns the criu_driver) and read
 * by every per-uobject dump dispatcher (DUMP_UVERBS_CONTEXT,
 * DUMP_UOBJ_CQ, future DUMP_UOBJ_QP / _MR / ...) so they don't
 * re-walk cr_plugin_ctl.head + dlsym() the provided-driver symbol
 * on every uobject. CLAIM has already enforced exactly-one-plugin-
 * per-ibdev exclusivity, so the cached pointer is unique by
 * construction. NULL is a hard error (CLAIM just succeeded against
 * this very criu_driver, so the plugin must be loaded).
 */
struct rdma_dumped_ufile {
	pid_t pid;
	uint32_t ctxn;
	bool has_ctxn;
	uint32_t uvfe_id;
	uint32_t criu_driver;
	uint32_t kernel_driver_id;
	uint32_t dev_index;	/* filled lazily in rdma_dump_uobj_dag */
	bool has_dev_index;
	char ibdev[64];
	int holder_uctx_fd;
	plugin_desc_t *plugin;
	struct list_head link;
};
extern struct list_head rdma_dumped_ufiles;

/*
 * Plugin lookup helper shared between dump-side (uverbsfd.c) and
 * restore-side (uobj_restore.c) dispatchers. Walks the loaded
 * plugin list and returns the (single) plugin whose dlhandle
 * exposes a cr_rdma_provided_driver constant equal to @criu_driver.
 *
 * Returns NULL on miss. Returns NULL with *@ambiguous set to true
 * if more than one plugin matches (caller decides whether to treat
 * that as a hard error). When non-NULL, *@first_name and
 * *@second_name are populated with the matching plugins' names for
 * diagnostics. Both name out-params may be NULL if the caller
 * doesn't care about diagnostics.
 *
 * Callers should resolve once per ucontext (at CLAIM time on the
 * dump side; at the top of rdma_restore_uobj_dag_for_ufile() on
 * the restore side) and cache the result -- not re-walk per
 * uobject.
 */
plugin_desc_t *rdma_find_plugin_by_provided_driver(uint32_t criu_driver,
						   bool *ambiguous,
						   const char **first_name,
						   const char **second_name);

#endif /* __CR_RDMA_INTERNAL_H__ */
