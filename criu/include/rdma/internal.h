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
 *
 * @kernel_driver_id is the RDMA_DRIVER_* id of the ibdev backing this
 * context; the QUERY_MR ioctl dispatcher validates it against the
 * per-ucontext driver id, so the MR walk must pass it verbatim.
 *
 * @holder_uctx_fd is an O_CLOEXEC dup of the dumpee's uverbs cdev fd,
 * captured in dump_uverbsfile() from the parasite-drained (SCM_RIGHTS)
 * lfd -- i.e. the dumpee's real struct file, sharing its ucontext IDR,
 * not a fresh re-open. rdma_dump_uobj_dag() issues QUERY_MR on it to
 * harvest each MR's user_addr / iova / access_flags (fields NLDEV does
 * not expose) and closes it during cleanup. -1 means "not stashed"
 * (the dup failed); the MR walk then cannot query and fails closed.
 */
struct rdma_dumped_ufile {
	pid_t pid;
	uint32_t ctxn;
	bool has_ctxn;
	uint32_t uvfe_id;
	bool has_uvfe_id; /* uvfe_id back-filled by rdma_bind_dumped_ufile_id() */
	uint32_t criu_driver;
	uint32_t kernel_driver_id;
	uint32_t dev_index; /* filled lazily in rdma_dump_uobj_dag */
	bool has_dev_index;
	char ibdev[64];
	int holder_uctx_fd;
	struct list_head link;
};
extern struct list_head rdma_dumped_ufiles;

/*
 * Record a captured uverbs context for the uobject DAG walk. Copies
 * @ibdev; takes ownership of @holder_uctx_fd (closed by the capture
 * walk, or immediately here on allocation failure). @uvfe_id is left 0
 * at early-capture time and back-filled later by rdma_bind_dumped_ufile_id()
 * once file collection assigns the context its image id. Returns 0 on
 * success, -1 on allocation failure.
 */
int rdma_note_dumped_ufile(uint32_t uvfe_id, bool has_ctxn, uint32_t ctxn,
			   uint32_t criu_driver, uint32_t kernel_driver_id,
			   pid_t pid, const char *ibdev, int holder_uctx_fd);

/*
 * Back-fill the image id of an already-captured uverbs context. Called
 * from dump_uverbsfile() during file collection, once the fd has been
 * assigned its UverbsFileEntry.id: the early-capture pass recorded the
 * context (by pid + ctxn) with uvfe_id left 0, and the emit phase reads
 * it back off the ufile. Returns 0 if the context was found and bound,
 * -1 if no capture record matches (a context the early pass missed is a
 * dump bug -- fail closed). A process holding several fds to the same
 * ctxn binds the first; later fds keep it.
 */
int rdma_bind_dumped_ufile_id(pid_t pid, bool has_ctxn, uint32_t ctxn,
			      uint32_t uvfe_id);

/*
 * Capture phase (criu/rdma/uobj_dump.c). Runs from the early
 * uverbs-context capture pass, before the datapath freeze: walks each
 * in-tree ibdev's uobjects over NLDEV + per-driver plugin queries on the
 * live command ring, and packs each built entry into an in-memory
 * capture list with its ufile_id deferred. rdma_emit_uobj_dag() (in
 * rdma.h) serializes that list later, after file collection.
 */
int rdma_capture_uobj_dag(void);

#endif /* __CR_RDMA_INTERNAL_H__ */
