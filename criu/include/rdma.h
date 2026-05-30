#ifndef __CR_RDMA_H__
#define __CR_RDMA_H__

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "plugin.h"		/* plugin_desc_t for cached dispatch */

struct pstree_item;
struct task_restore_args;

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
 * Cross-tree RDMA exclusivity check.
 *
 * Companion to rdma_check_dump_coverage(). Where coverage asks
 * "is every snapshot-tree context handled by some plugin?", this
 * one asks "for every snapshot-tree context, is there a non-
 * snapshot-tree pid sharing the same device, and does the
 * claiming plugin's exclusivity policy say that's a problem?".
 *
 * A non-snapshot pid sharing a device is fine when the claiming
 * plugin marks itself CR_RDMA_SHARING_SHAREABLE (rxe and other
 * software providers fit this); it's a hard dump failure when
 * the plugin marks itself CR_RDMA_SHARING_EXCLUSIVE (mlx5
 * SR-IOV VF migration, where any non-snapshot context on the
 * tracked VF is destroyed by the eventual restore). The default
 * for plugins that don't declare a policy is EXCLUSIVE -- safe
 * default, fail-closed.
 *
 * Runs after rdma_check_dump_coverage() so we already know every
 * snapshot-tree context has exactly one claiming plugin to ask.
 */
int rdma_check_cross_tree_exclusivity(struct pstree_item *root);

/*
 * R3 dump-side per-uobject DAG walk.
 *
 * Runs once at end-of-dump, after every pstree task has been
 * dumped. Walks NLDEV per in-tree ibdev to enumerate the PD/CQ/
 * QP/MR/SRQ uobjects under each in-tree ucontext, and writes one
 * rdma_uobj_entry per discovered uobject into rdma_uobj.img.
 *
 * S1.b scope: discovery and image emission only -- no restore-side
 * action consumes rdma_uobj.img yet (that lands in S1.c). Per-
 * uobject restore verbs come progressively across S2-S6 as kernel
 * support arrives, with the per-class tagging table in
 * linux/tools/testing/mlx5_vfmig/design/uobject_restore.md
 * gating which uobjects gain restore handlers when.
 *
 * No-op (returns 0 without opening rdma_uobj.img) when no in-tree
 * uverbs context was dumped, which is the common case for the vast
 * majority of CRIU dump targets (no RDMA workload).
 *
 * Returns 0 on success, -1 on netlink/image-emission failure.
 */
int rdma_dump_uobj_dag(void);

/*
 * R3 restore-side per-uobject DAG read+verify pass.
 *
 * S1.c. Opens rdma-uobj.img, reads every rdma_uobj_entry, groups
 * by ufile_id, and validates internal consistency:
 *
 *   * Every xref edge resolves to an entry of matching type within
 *     the same ufile_id group (PARENT_PD edge -> a PD entry with
 *     the matching target_restrack_id must exist).
 *
 *   * (ufile_id, type, restrack_id) is unique within the image
 *     for the types that emit restrack_id (PD/CQ/MR/SRQ); a
 *     duplicate indicates a dump-side bug.
 *
 * The verify pass is informational only -- it does NOT install any
 * uobjects on the destination. Per-uobject restore verbs land
 * incrementally across S2-S6 as kernel support arrives. Logs a
 * one-line per-ufile summary at pr_info so an operator inspecting
 * a restore log can confirm what the dump captured without
 * reaching for `crit decode`.
 *
 * No-op (returns 0) when the image is absent (no in-tree RDMA at
 * dump time). Returns -1 on any internal-inconsistency or read
 * error -- the dump is broken if this trips, so failing closed
 * surfaces it before any S2+ stage tries to act on the same image.
 */
int rdma_collect_uobj_dag(void);

/*
 * R3 restore-side per-ufile RESTORE_<TYPE> dispatcher.
 *
 * Called by uverbsfd_open() after the loaded RDMA plugin has handed
 * back an open uverbs cdev fd with a kernel ucontext established on
 * it. Walks the per-@ufile_id DAG group built earlier by
 * rdma_collect_uobj_dag() and issues RESTORE_<TYPE> verbs (currently
 * just UVERBS_METHOD_RESTORE_PD; CQ/QP/MR/SRQ/AH land as their
 * driver hooks come up) per uobject entry, installing each at the
 * kernel-side ufile_handle the dump captured.
 *
 * Restore-mode gating is the plugin's job: the cdev fd this gets is
 * already opened in the per-driver restore mode (rxe via
 * RXE_ALLOC_UCTX_RESTORE_MODE, mlx5 via
 * MLX5_IB_ALLOC_UCTX_VFMIG_RESTORE), so the kernel
 * ib_device_ops.ucontext_is_restore_mode predicate doesn't reject
 * the dispatch.
 *
 * No-op (returns 0) when @ufile_id has no DAG group -- e.g. the
 * dump pre-dated R3 image emission or skipped this ufile. Returns
 * -1 on the first per-entry restore failure (already pr_err'd with
 * driver/handle context).
 */
int rdma_restore_uobj_dag_for_ufile(int cmd_fd, uint32_t ufile_id,
				    uint32_t kernel_driver_id);

/*
 * Phase B: serialise VA-dependent uobject restore (MR; future
 * DEVX_UMEM) into rst_mem(RM_PRIVATE) for the pie restorer blob to
 * actually issue.
 *
 * Why this lives in the pie blob, not here: rxe's restore_mr ends up
 * in pin_user_pages_fast(addr, ...) on current->mm. Simple anon-
 * private VMAs (vma->pvma == NULL && pieok && !vma_force_premap;
 * criu/mem.c) are NOT premapped at the original VA by prepare_
 * mappings -- their content sits in vma_io until the pie blob mmaps
 * them at sigreturn_restore time. Issuing RESTORE_MR from
 * restore_one_alive_task therefore returns -EFAULT for any rxe MR
 * pinned against an aligned_alloc-style buffer. The restorer pie
 * blob runs after VMA placement, in the restored task's mm, with
 * user VAs live -- pin_user_pages_fast succeeds. mlx5_vfmig MR
 * restore re-attaches FW mkey identity without pinning user pages
 * and is unaffected, but goes through the same dispatch path to
 * keep the wire encoding in one place.
 *
 * The phase split is therefore:
 *   Phase A (in uverbsfd_open(), pre-VMA):
 *     Stash a long-lived high-fd dup of the cdev plus
 *     (ufile_id, kernel_driver_id, handle_map) on a global list,
 *     and run the no-VA RESTORE_<TYPE> verbs (PD today; CQ/QP/SRQ/
 *     AH later, none of which pin user pages).
 *   Phase B-prep (here, in restore_one_alive_task):
 *     Walk the stashed list, resolve PARENT_PD xrefs through the
 *     handle_map, append one struct rst_rdma_mr per MR entry into
 *     ta->rdma_mrs via rst_mem_alloc(RM_PRIVATE). The pie blob
 *     reads them post-VMA-placement and issues RESTORE_MR.
 *   Phase B (criu/pie/restorer.c::restore_rdma_mr, post-VMA):
 *     Issue UVERBS_METHOD_RESTORE_MR via sys_ioctl, close the dup
 *     fd so it doesn't leak into the restored task.
 *
 * Called from restore_one_alive_task() right after open_vmas().
 * No-op if no Phase-A entries were stashed (no in-tree RDMA
 * contexts, or every context's DAG group was empty).
 *
 * Returns 0 on success; -1 on the first per-entry serialisation
 * failure (rst_mem OOM, missing required attrs, unresolvable
 * PARENT_PD xref).
 */
int rdma_prepare_rdma_mrs(struct task_restore_args *ta);

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

/*
 * Dispatch the per-context cdev open to the loaded plugin whose
 * cr_rdma_provided_driver constant matches uvfe->criu_driver. Used
 * by uverbsfd_open() in place of the historical open_reg_by_id()
 * call so the destination cdev's actual minor (which may differ
 * from the source's) is resolved by the plugin via sysfs rather
 * than being assumed equal to the image-recorded path. Returns the
 * fd on success, -1 on failure (already pr_err'd).
 *
 * The pb-c.h is included here directly rather than forward-decl'd
 * because the underlying struct tag is not stable across
 * protobuf-c generator versions: older protoc-c emits
 *   struct _UverbsFileEntry  (with a leading underscore)
 * and newer emits
 *   struct UverbsFileEntry   (no leading underscore)
 * with the same typedef name in both cases. A header-side forward
 * decl that hard-codes either tag wedges the build on the other
 * generator, and a hand-written typedef collides with pb-c.h's
 * typedef on the version with the differently-tagged struct. The
 * one robust answer is to use only the typedef name and pull the
 * generator's definition in directly. Includers that don't touch
 * RDMA pay one transitive include; plugins that implement
 * OPEN_UVERBS_CDEV (rxe / mlx5_sriov_vfmig) already include pb-c.h
 * for field access.
 */
#include "images/uverbsfd.pb-c.h"
int rdma_dispatch_open_uverbs_cdev(const UverbsFileEntry *uvfe);

/*
 * Dump-side counterpart to rdma_dispatch_open_uverbs_cdev(). Calls
 * @plugin's CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT hook iff the
 * plugin registered one.
 *
 * @plugin is the cached plugin pointer the caller already resolved
 * via rdma_find_plugin_by_provided_driver() right after CLAIM
 * arbitration; the dispatcher does NOT re-walk the plugin list.
 * Stashed onto struct rdma_dumped_ufile.plugin (see
 * rdma/internal.h) so the per-uobject dispatchers below can reuse
 * the same lookup without redoing the walk per uobject. Must not
 * be NULL; a NULL pointer is the caller's responsibility to
 * diagnose at CLAIM time.
 *
 * Optional hook semantics: a plugin that does not register the
 * hook is a no-op success -- rxe is the canonical example, since
 * a software provider has no firmware-side state to capture beyond
 * what the generic UverbsFileEntry already records. mlx5_sriov_vfmig
 * uses the hook to fire SAVE_VHCA_STATE and persist the resulting
 * blob into the CRIU image directory.
 *
 * Returns 0 on success (including the no-op case), -1 on failure
 * (the hook itself returned -1).
 *
 * plugin_desc_t comes from criu/include/plugin.h; includers of this
 * header that touch the dispatcher signatures pull it in via
 * "plugin.h" (see criu/rdma/uverbsfd.c).
 */
int rdma_dispatch_dump_uverbs_context(plugin_desc_t *plugin,
				      const char *ibdev,
				      uint32_t kernel_driver_id,
				      uint32_t ctxn,
				      int lfd, pid_t pid);

#endif /* __CR_RDMA_H__ */
