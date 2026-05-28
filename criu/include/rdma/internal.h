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

/*
 * driver.c: chrdev (major,minor) -> ibdev name resolver. Used
 * by rdma.c's dump_uverbsfile() to identify the source-side
 * uverbs cdev a held fd refers to. The two driver-name helpers
 * this calls into (rdma_driver_name_from_ibdev,
 * rdma_driver_name_to_id) are public and live in rdma.h.
 */
int rdma_ibdev_from_chrdev(unsigned int maj, unsigned int min,
			   char *out, size_t outsz);

#endif /* __CR_RDMA_INTERNAL_H__ */
