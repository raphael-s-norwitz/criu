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
 * uverbsfd.c -> uobj_dump.c (R3 dump-side DAG walker) shared state.
 *
 * dump_uverbsfile() (in uverbsfd.c) appends one entry per checkpointed
 * uverbs context via rdma_note_dumped_ufile(); rdma_dump_uobj_dag()
 * (in uobj_dump.c) walks the list once after every pstree task has
 * been dumped, joining NLDEV-enumerated uobjects back to their owning
 * ufile by ctxn.
 *
 * The list is single-threaded by construction (cr-dump.c walks pstree
 * sequentially, then the NLDEV walk happens once, then cleanup), grows
 * monotonically during dump, and is freed by rdma_dump_uobj_dag()'s
 * cleanup path.
 *
 * @uvfe_id is the per-context image id (UverbsFileEntry.id) already
 * assigned by dump_uverbsfile() -- the single-pass walker reads it
 * directly (no late-bind), so it becomes each rdma_uobj_entry.ufile_id.
 */
struct rdma_dumped_ufile {
	pid_t pid;
	uint32_t ctxn;
	bool has_ctxn;
	uint32_t uvfe_id;
	uint32_t criu_driver;
	uint32_t dev_index; /* filled lazily in rdma_dump_uobj_dag */
	bool has_dev_index;
	char ibdev[64];
	struct list_head link;
};
extern struct list_head rdma_dumped_ufiles;

/*
 * Record a just-dumped uverbs context for the end-of-dump uobject DAG
 * walk. Copies @ibdev; takes ownership of nothing. Returns 0 on
 * success, -1 on allocation failure.
 */
int rdma_note_dumped_ufile(uint32_t uvfe_id, bool has_ctxn, uint32_t ctxn,
			   uint32_t criu_driver, pid_t pid, const char *ibdev);

#endif /* __CR_RDMA_INTERNAL_H__ */
