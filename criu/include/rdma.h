#ifndef __CR_RDMA_H__
#define __CR_RDMA_H__

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

extern const struct fdtype_ops uverbs_dump_ops;
extern const struct fdtype_ops uverbs_async_eventfd_dump_ops;

extern struct collect_image_info uverbsfd_cinfo;
extern struct collect_image_info uverbsasyncevfd_cinfo;

bool is_async_eventfd(char *link);

/*
 * RDMA driver-name resolution (criu/rdma/driver.c):
 *
 *   rdma_driver_name_from_ibdev()
 *       Resolves an ibdev name (e.g. "rxe0") to its kernel
 *       driver name (e.g. "rxe", "mlx5_core"). PCI symlink
 *       first, then a hard-coded software-provider fallback.
 *
 *   rdma_driver_name_to_id()
 *       Driver-name -> RDMA_DRIVER_* enum value lookup. Returns
 *       RDMA_DRIVER_UNKNOWN if not in the static table.
 */
int rdma_driver_name_from_ibdev(const char *ibdev, char *out, size_t outsz);
uint32_t rdma_driver_name_to_id(const char *driver);

#endif /* __CR_RDMA_H__ */
