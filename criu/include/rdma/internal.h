#ifndef __CR_RDMA_INTERNAL_H__
#define __CR_RDMA_INTERNAL_H__

/*
 * Cross-file accessors shared between the criu/rdma/ sources.
 * Strictly NOT a public surface -- callers outside criu/rdma/
 * should include criu/include/rdma.h instead.
 */

#include <stdint.h>
#include <sys/types.h>

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

#endif /* __CR_RDMA_INTERNAL_H__ */
