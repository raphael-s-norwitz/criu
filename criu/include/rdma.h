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
 * Cross-tree RDMA exclusivity check (criu/rdma/precheck.c).
 *
 * Companion to rdma_check_dump_coverage(). Where coverage asks "is
 * every snapshot-tree context handled by some plugin?", this asks
 * "for every snapshot-tree context, is there a non-snapshot-tree pid
 * sharing the same ibdev, and does the claiming plugin mark that
 * device EXCLUSIVE?" -- rejecting the dump if so, because snapshot +
 * restore would destroy the non-snapshot peer's context. The default
 * for plugins that don't declare a policy is EXCLUSIVE (fail-closed).
 * Runs after coverage, so every snapshot-tree context already has
 * exactly one claiming plugin to ask. Returns 0 if safe, -1 otherwise.
 */
int rdma_check_cross_tree_exclusivity(struct pstree_item *root);

/*
 * R3 per-uobject DAG dump (criu/rdma/uobj_dump.c). Runs once at
 * end-of-dump, after every pstree task has been dumped (so
 * dump_uverbsfile() has recorded every checkpointed uverbs context).
 * For each dumped context, asks NLDEV to enumerate its uobjects and
 * writes one rdma_uobj_entry per uobject to rdma_uobj.img.
 *
ssh  * v0 scope (rxe PD + MR + CQ): emits R3UT_PD / R3UT_MR / R3UT_CQ
 * records. No-op (and writes no image) for trees that hold no RDMA
 * contexts. Returns 0 on success or a no-op skip, -1 on any netlink /
 * image-write failure (fails the dump closed, consistent with the
 * pre-suspend coverage gate).
 */
int rdma_dump_uobj_dag(void);

/*
 * R3 restore-side read+collect pass on rdma_uobj.img
 * (criu/rdma/uobj_restore.c). Called once early in restore: reads
 * every rdma_uobj_entry, groups them by ufile_id, and verifies basic
 * internal consistency (one hw_driver_id per ufile). No restore action
 * -- the per-uobject verbs are issued later, per cdev fd, by
 * rdma_restore_uobj_dag_for_ufile().
 *
 * No-op (returns 0) when the image is absent (no in-tree RDMA at dump
 * time). Returns -1 on a read or internal-consistency error.
 */
int rdma_collect_uobj_dag(void);

/*
 * R3 restore-side per-ufile RESTORE_<TYPE> dispatcher
 * (criu/rdma/uobj_restore.c). Called by uverbsfd_open() after the
 * loaded RDMA plugin hands back an open uverbs cdev fd carrying a
 * restore-mode kernel ucontext. Walks the per-@ufile_id DAG group
 * collected earlier and installs each uobject at the ufile_handle the
 * dump captured.
 *
 * v0 scope (rxe PD): the actual UVERBS_METHOD_RESTORE_PD verb lands in
 * the next commit; here the dispatcher builds the per-ufile handle map
 * and walks the PD entries as a no-op replay so the bare-context
 * round-trip is unaffected.
 *
 * @kernel_driver_id is the kernel's RDMA_DRIVER_* enum (what the
 * UVERBS_OBJECT_RESTORE ioctl header matches). No-op (returns 0) when
 * @ufile_id has no DAG group. Returns -1 on the first restore failure.
 */
int rdma_restore_uobj_dag_for_ufile(int cmd_fd, uint32_t ufile_id, uint32_t kernel_driver_id);

struct task_restore_args;

/*
 * R3 restore-side pie handoff (criu/rdma/uobj_restore.c). Called once
 * from the sigreturn-args prep in cr-restore.c, after every ufile's DAG
 * has been dispatched (PDs restored, MRs queued). Bursts the queued MRs
 * into the RM_PRIVATE restorer-args pool as ta->rdma_mrs[], each owning
 * a high-fd dup of its ucontext cdev; the pie blob issues RESTORE_MR
 * for them after the user VMAs are laid out at their original VAs (the
 * user_addr pages must be present for the kernel's pin_user_pages_fast).
 *
 * Always anchors ta->rdma_mrs at the current RM_PRIVATE cursor (even
 * with nothing queued) so the pool stays consistent across the
 * prepare_* sequence. Returns 0 on success (including the no-MR fast
 * path), -1 on a missing-field / unresolved-parent / dup / alloc error.
 */
int rdma_prepare_rdma_mrs(struct task_restore_args *ta);

/*
 * RDMA plugin queries (criu/rdma/plugin_api.c):
 *
 *   rdma_arbitrate_plugin_claim()
 *       Iterates every plugin registered for
 *       CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT and returns the
 *       single claiming plugin's RdmaCriuDriver value, 0 (=
 *       RCD_UNKNOWN) on no claim, or a negative errno on conflict /
 *       probe failure. *claimer_name receives the plugin name on a
 *       successful claim (may be NULL if the caller doesn't care).
 *
 *   rdma_plugin_sharing_policy_by_name()
 *       Returns the named plugin's CR_RDMA_SHARING_* policy, read via
 *       dlsym of its exported cr_rdma_sharing_policy symbol. Fails
 *       closed to CR_RDMA_SHARING_EXCLUSIVE for any unknown/undeclared
 *       plugin. Consumed by the cross-tree exclusivity check.
 */
int rdma_arbitrate_plugin_claim(const char *ibdev, uint32_t kernel_driver_id, const char **claimer_name);
int rdma_plugin_sharing_policy_by_name(const char *plugin_name);

/*
 * Restore-side uverbs-cdev open dispatch (criu/rdma/plugin_api.c):
 *
 *   rdma_dispatch_open_uverbs_cdev()
 *       Invokes CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV on the single
 *       loaded plugin whose exported cr_rdma_provided_driver matches
 *       the image's UverbsFileEntry.criu_driver, returning the fd
 *       (>= 0, already carrying a kernel ucontext) the plugin opens,
 *       or -1 on no/ambiguous match or hook failure.
 *
 * The pb-c header is pulled in directly rather than forward-declared
 * because the generated struct tag (struct UverbsFileEntry vs
 * struct _UverbsFileEntry) is not stable across protobuf-c versions;
 * only the typedef name is.
 */
#include "images/uverbsfd.pb-c.h"
int rdma_dispatch_open_uverbs_cdev(const UverbsFileEntry *uvfe);

/*
 * Dump-side per-ucontext dispatch (criu/rdma/plugin_api.c):
 *
 *   rdma_dispatch_dump_uverbs_context()
 *       Invokes CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT on the single
 *       loaded plugin whose exported cr_rdma_provided_driver matches
 *       @criu_driver (the context's claimed driver) -- the same
 *       by-driver keying as the open / per-uobject dispatchers. The
 *       plugin captures per-ucontext driver-private state on @lfd
 *       (criu's dup of the dumpee's uverbs cdev fd, sharing the
 *       ucontext IDR) keyed by @ibdev / @ctxn. The hook is OPTIONAL:
 *       returns 0 when no loaded plugin registers it for @criu_driver
 *       (nothing to capture beyond the generic UverbsFileEntry), and
 *       negative on a duplicate provided-driver declaration or hook
 *       failure.
 */
int rdma_dispatch_dump_uverbs_context(uint32_t criu_driver, const char *ibdev, uint32_t kernel_driver_id,
				      uint32_t ctxn, int lfd, pid_t pid);

/*
 * Dump-side per-CQ dispatch (criu/rdma/plugin_api.c):
 *
 *   rdma_dispatch_dump_uobj_cq()
 *       Invokes CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ on the single loaded
 *       plugin whose exported cr_rdma_provided_driver matches
 *       @criu_driver (the owning ucontext's, from the dump-side ufile
 *       record) -- the same by-driver keying as the open dispatcher,
 *       since the hook chain alone can't tell an rxe CQ from an mlx5
 *       one. The plugin QUERY_CQ's @lfd (criu's dup of the dumpee's
 *       uverbs cdev fd) for @ufile_handle, fills the fields it owns in
 *       @cq_attrs, and mallocs its per-CQ byte schema into
 *       @plugin_blob (caller frees). Returns 0 on success, negative on
 *       no/ambiguous match or hook failure.
 *
 * The rdma_uobj pb-c header is pulled in directly (not forward-
 * declared) for the same protobuf-c tag-stability reason as above.
 */
#include "images/rdma_uobj.pb-c.h"
int rdma_dispatch_dump_uobj_cq(uint32_t criu_driver, const char *ibdev, uint32_t kernel_driver_id, int lfd,
			       uint32_t ufile_handle, pid_t pid, RdmaCqAttrs *cq_attrs, ProtobufCBinaryData *plugin_blob);

/*
 * Dump-side per-QP dispatch (criu/rdma/plugin_api.c):
 *
 *   rdma_dispatch_dump_uobj_qp()
 *       The QP twin of rdma_dispatch_dump_uobj_cq(): invokes
 *       CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_QP on the single loaded plugin
 *       whose exported cr_rdma_provided_driver matches @criu_driver.
 *       The plugin reads the QP's driver-private wire state on @lfd
 *       (criu's dup of the dumpee's cdev, holder of the QP IDR that
 *       resolves @ufile_handle), fills the one hw-agnostic field it
 *       owns (@qp_attrs->user_handle), and mallocs its per-QP byte
 *       schema into @plugin_blob (caller frees). Returns 0 on success,
 *       negative on no/ambiguous match or hook failure.
 */
int rdma_dispatch_dump_uobj_qp(uint32_t criu_driver, const char *ibdev, uint32_t kernel_driver_id, int lfd,
			       uint32_t ufile_handle, pid_t pid, RdmaQpAttrs *qp_attrs, ProtobufCBinaryData *plugin_blob);

/*
 * Restore-side per-CQ UHW-pack dispatch (criu/rdma/plugin_api.c):
 *
 *   rdma_dispatch_restore_cq_uhw_pack()
 *       Invokes CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_CQ_UHW_PACK on the
 *       single loaded plugin whose exported cr_rdma_provided_driver
 *       matches @criu_driver (the R3UT_CQ entry's, same by-driver
 *       keying as the dump-side dispatch). The plugin reshapes the
 *       entry's opaque plugin_blob into @uhw (UHW_IN payload + required
 *       UHW_OUT size + optional verify template); core's
 *       rdma_send_restore_cq() then issues UVERBS_METHOD_RESTORE_CQ and
 *       frees @uhw's buffers. Returns 0 on success (including the no-op
 *       case where the plugin exposes no hook), negative errno on
 *       no/ambiguous match or hook failure.
 *
 * struct rdma_uhw_spec is defined in criu-plugin.h (the plugin ABI);
 * a bare forward declaration suffices for this pointer parameter.
 */
struct rdma_uhw_spec;
int rdma_dispatch_restore_cq_uhw_pack(uint32_t criu_driver, const RdmaUobjEntry *e, struct rdma_uhw_spec *uhw);

/*
 * Restore-side per-QP UHW-pack dispatch (criu/rdma/plugin_api.c):
 *
 *   rdma_dispatch_restore_qp_uhw_pack()
 *       The QP twin of rdma_dispatch_restore_cq_uhw_pack(): invokes
 *       CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_QP_UHW_PACK on the single
 *       loaded plugin whose exported cr_rdma_provided_driver matches
 *       @criu_driver (the R3UT_QP entry's). The plugin reshapes the
 *       entry's opaque plugin_blob into @uhw (UHW_IN payload + required
 *       UHW_OUT size + optional verify template); core's
 *       rdma_send_restore_qp() then issues UVERBS_METHOD_RESTORE_QP and
 *       frees @uhw's buffers. Returns 0 on success (including the no-op
 *       case where the plugin exposes no hook), negative errno on
 *       no/ambiguous match or hook failure.
 */
int rdma_dispatch_restore_qp_uhw_pack(uint32_t criu_driver, const RdmaUobjEntry *e, struct rdma_uhw_spec *uhw);

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
