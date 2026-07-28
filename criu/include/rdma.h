#ifndef __CR_RDMA_H__
#define __CR_RDMA_H__

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

struct pstree_item;

extern const struct fdtype_ops uverbs_dump_ops;
extern const struct fdtype_ops uverbs_async_eventfd_dump_ops;

extern struct collect_image_info uverbsfd_cinfo;
extern struct collect_image_info uverbsasyncevfd_cinfo;

bool is_async_eventfd(char *link);

/*
 * Pre-suspend RDMA dump-coverage check (criu/rdma/precheck.c).
 *
 * For every live RDMA context held by a snapshot-tree pid, confirms
 * exactly one loaded plugin claims the underlying device, so a tree
 * holding a context no plugin can restore is rejected up front (with
 * the whole pstree in view) instead of mid-dump, fd by fd. Runs right
 * after collect_pstree(), before the freeze deepens. Fails closed on
 * netlink errors. Returns 0 if every tree context is covered, -1
 * otherwise.
 */
int rdma_check_dump_coverage(struct pstree_item *root);

/*
 * RDMA plugin claim arbitration (criu/rdma/plugin_api.c):
 *
 *   rdma_arbitrate_plugin_claim()
 *       Iterates every plugin registered for
 *       CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT and returns the
 *       single claiming plugin's RdmaCriuDriver value, 0 (=
 *       RCD_UNKNOWN) on no claim, or a negative errno on conflict /
 *       probe failure. *claimer_name receives the plugin name on a
 *       successful claim (may be NULL if the caller doesn't care).
 */
int rdma_arbitrate_plugin_claim(const char *ibdev, uint32_t kernel_driver_id, const char **claimer_name);

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
