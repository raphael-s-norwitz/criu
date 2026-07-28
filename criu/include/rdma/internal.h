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
 * driver.c: chrdev (major,minor) -> ibdev name resolver. Used
 * by uverbsfd.c's dump_uverbsfile() to identify the source-side
 * uverbs cdev a held fd refers to. The two driver-name helpers
 * this calls into (rdma_driver_name_from_ibdev,
 * rdma_driver_name_to_id) are public and live in rdma.h.
 */
int rdma_ibdev_from_chrdev(unsigned int maj, unsigned int min,
			   char *out, size_t outsz);

#endif /* __CR_RDMA_INTERNAL_H__ */
