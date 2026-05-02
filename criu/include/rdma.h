#ifndef __CR_RDMA_H__
#define __CR_RDMA_H__

#include <stdbool.h>
#include <stdint.h>

struct pstree_item;

extern const struct fdtype_ops uverbs_dump_ops;
extern const struct fdtype_ops uverbs_async_eventfd_dump_ops;

extern struct collect_image_info uverbsfd_cinfo;
extern struct collect_image_info uverbsasyncevfd_cinfo;

bool is_async_eventfd(char *link);

/*
 * Pre-suspend RDMA dump-coverage check.
 *
 * Walks every live RDMA context held by any pid in the snapshot
 * tree rooted at @root and runs the same per-context plugin
 * arbitration that dump_uverbsfile() does, with one critical
 * difference: it runs *before* the per-fd dump path, off the
 * RDMA netlink dump rather than off /proc/<pid>/fdinfo, so a
 * missing-plugin failure surfaces with the entire pstree set
 * known but before any image data has been written.
 *
 * Returns 0 if every RDMA context held by the tree is claimed
 * by exactly one loaded plugin; -1 otherwise (with a pr_err()
 * naming the offending pid + ibdev). On any netlink-layer
 * failure (socket, send/recv) the check is treated as a hard
 * dump error -- failing closed is right here, since the only
 * alternative is "let the per-fd dump path discover the same
 * problem one pid into the work" which is exactly what this
 * pre-flight exists to avoid.
 */
int rdma_check_dump_coverage(struct pstree_item *root);

/*
 * Internal-but-shared helpers used by both criu/rdma.c and the
 * pre-suspend coverage check above. Defined in criu/rdma.c.
 *
 *   rdma_arbitrate_plugin_claim()
 *       Iterates every plugin registered for
 *       CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT, returns the
 *       single claiming plugin's RdmaCriuDriver value, 0 (=
 *       RCD_UNKNOWN) on no claim, or a negative errno on
 *       conflict / probe failure. *claimer_name receives the
 *       plugin name on a successful claim.
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
int rdma_arbitrate_plugin_claim(const char *ibdev, uint32_t kernel_driver_id,
				const char **claimer_name);
int rdma_driver_name_from_ibdev(const char *ibdev, char *out, size_t outsz);
uint32_t rdma_driver_name_to_id(const char *driver);

#endif /* __CR_RDMA_H__ */
