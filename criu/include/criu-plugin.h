/*
 *  This file defines types and macros for CRIU plugins.
 *  Copyright (C) 2013-2014 Parallels, Inc
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __CRIU_PLUGIN_H__
#define __CRIU_PLUGIN_H__

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#define CRIU_PLUGIN_GEN_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#define CRIU_PLUGIN_VERSION_MAJOR	 0
#define CRIU_PLUGIN_VERSION_MINOR	 2
#define CRIU_PLUGIN_VERSION_SUBLEVEL	 0

#define CRIU_PLUGIN_VERSION_OLD CRIU_PLUGIN_GEN_VERSION(0, 1, 0)

#define CRIU_PLUGIN_VERSION \
	CRIU_PLUGIN_GEN_VERSION(CRIU_PLUGIN_VERSION_MAJOR, CRIU_PLUGIN_VERSION_MINOR, CRIU_PLUGIN_VERSION_SUBLEVEL)

/*
 * Plugin hook points and their arguments in hooks.
 */
enum {
	CR_PLUGIN_HOOK__DUMP_UNIX_SK = 0,
	CR_PLUGIN_HOOK__RESTORE_UNIX_SK = 1,

	CR_PLUGIN_HOOK__DUMP_EXT_FILE = 2,
	CR_PLUGIN_HOOK__RESTORE_EXT_FILE = 3,

	CR_PLUGIN_HOOK__DUMP_EXT_MOUNT = 4,
	CR_PLUGIN_HOOK__RESTORE_EXT_MOUNT = 5,

	CR_PLUGIN_HOOK__DUMP_EXT_LINK = 6,

	CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA = 7,

	CR_PLUGIN_HOOK__UPDATE_VMA_MAP = 8,

	CR_PLUGIN_HOOK__RESUME_DEVICES_LATE = 9,

	CR_PLUGIN_HOOK__PAUSE_DEVICES = 10,

	CR_PLUGIN_HOOK__CHECKPOINT_DEVICES = 11,

	CR_PLUGIN_HOOK__POST_FORKING = 12,

	CR_PLUGIN_HOOK__RESTORE_INIT = 13,

	CR_PLUGIN_HOOK__DUMP_DEVICES_LATE = 14,

	CR_PLUGIN_HOOK__UPDATE_INETSK = 15,

	/*
	 * RDMA per-context plugin claim. Invoked at dump time by
	 * criu/rdma.c for every uverbs cdev about to be checkpointed,
	 * once per loaded RDMA-class plugin. The plugin returns the
	 * RdmaCriuDriver value identifying itself if (and only if) it
	 * intends to own dump+restore for this context, or the sentinel
	 * value RCD_UNKNOWN (0) if it doesn't claim it. The arbitration
	 * helper in criu/rdma.c enforces "exactly one plugin claims";
	 * zero or multiple claims is a hard dump failure.
	 *
	 * Distinct from the existing per-fd hooks (DUMP_EXT_FILE etc.)
	 * because it runs *per uverbs context*, doesn't have an fd id
	 * yet at call time, and is read-only / side-effect-free --
	 * plugins may issue cheap probe ioctls (e.g. MLX5_VFMIG_IOC_
	 * QUERY_VF) but must not mutate state.
	 *
	 * Args:  ibdev (e.g. "rxe0", "mlx5_2"), kernel_driver_id
	 *        (RDMA_DRIVER_* enum value as resolved from sysfs).
	 * Return: RdmaCriuDriver value > 0 to claim, RCD_UNKNOWN to
	 *         decline. Returning a negative errno indicates the
	 *         plugin would normally claim but failed to probe, and
	 *         is treated as a dump error (different from "decline").
	 */
	CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT = 16,

	/*
	 * RDMA per-context cdev open. Invoked at restore time by
	 * criu/rdma.c after CLAIM arbitration has selected a winning
	 * plugin. The selected plugin (and only the selected plugin)
	 * is responsible for opening a fresh fd against whichever
	 * /dev/infiniband/uverbsN device is the *destination's*
	 * counterpart of the dumped context.
	 *
	 * Why this can't reuse the source-recorded path:
	 *   The image's reg_file_entry carries the source's cdev path
	 *   (e.g. "/dev/infiniband/uverbs5"). On the destination -- be
	 *   it a different host, the same host after a reboot, or even
	 *   the same host after rdma_link {add,delete} churn -- the
	 *   minor number that the kernel's ib_uverbs class assigned to
	 *   the same ibdev name may differ. open(source-path) then
	 *   either ENOENTs or, worse, succeeds against the wrong
	 *   device. The plugin walks
	 *   /sys/class/infiniband/<ibdev>/dev to resolve the *current*
	 *   cdev minor for the ibdev recorded in the image, and opens
	 *   that. For mlx5 SR-IOV VF migration the plugin additionally
	 *   drives ENABLE_MIGRATABLE / SET_TRACKED / LOAD_VHCA_STATE /
	 *   MARK_RESTORED / driver bind before the sysfs walk; for rxe
	 *   the sysfs walk is the entire job.
	 *
	 * Dispatched on uvfe->criu_driver: the dispatcher walks the
	 * loaded plugin list and calls only the plugin whose
	 * cr_rdma_provided_driver constant matches the image's
	 * recorded RdmaCriuDriver value (see CR_PLUGIN_DECLARE_RDMA_
	 * PROVIDED_DRIVER below). Loser plugins are not called.
	 *
	 * Args:  uvfe -- the dumped UverbsFileEntry, full image record
	 *        including ib_dev, driver_name, driver_id, criu_driver,
	 *        and (when present) any plugin-specific hint blob the
	 *        dump-side counterpart hook stashed there.
	 * Return: a freshly-opened, O_RDWR, O_CLOEXEC fd on the
	 *         destination cdev on success; -1 on failure (with the
	 *         plugin emitting its own pr_err for the operator).
	 *         CRIU's restore machinery dups the returned fd into
	 *         the target process's fd table; the plugin must not
	 *         hold its own reference after returning.
	 */
	CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV = 17,

	/*
	 * RDMA per-context dump-side state capture. Invoked at dump
	 * time by criu/rdma.c after CLAIM arbitration has selected a
	 * winning plugin and the generic UverbsFileEntry fields
	 * (id, ib_dev, driver_name, driver_id, criu_driver, ctxn)
	 * have been populated. The selected plugin (and only the
	 * selected plugin) is responsible for capturing whatever
	 * provider-specific state needs to survive the round-trip --
	 * for mlx5 SR-IOV VF migration that means
	 * MLX5_VFMIG_IOC_SAVE_VHCA_STATE plus persisting the returned
	 * firmware blob into the CRIU image directory; for rxe it's
	 * a no-op (rxe has no firmware state, hence the plugin does
	 * not register the hook at all).
	 *
	 * Optional. CLAIM is mandatory for any plugin that wants to
	 * own a context; DUMP_UVERBS_CONTEXT is registered only by
	 * plugins that have something to capture beyond what the
	 * generic UverbsFileEntry already records. The dispatcher in
	 * criu/rdma.c (rdma_dispatch_dump_uverbs_context) walks the
	 * loaded plugin list, finds the plugin whose
	 * cr_rdma_provided_driver constant matches the just-arbitrated
	 * criu_driver, and invokes this hook on it iff the plugin
	 * registered one. Plugins that do not register a hook are a
	 * no-op success.
	 *
	 * Plugins write their state into the CRIU image directory via
	 * openat(criu_get_image_dir(), ...) using whatever per-plugin
	 * file naming convention they choose. The companion restore-
	 * side OPEN_UVERBS_CDEV hook is responsible for reading those
	 * files back. The join key between this dump-side capture and
	 * the restore-side consumption is uvfe->ctxn (also recorded
	 * in the generic UverbsFileEntry image record) plus whatever
	 * device identification the plugin embeds in its private
	 * image (e.g. ibdev name, PF BDF, vf_id).
	 *
	 * Args:  ibdev (e.g. "mlx5_2"), kernel_driver_id, ctxn (the
	 *        per-process context number from /proc/<pid>/fdinfo),
	 *        lfd (an open fd against the source process's uverbs
	 *        cdev, valid for the duration of the call), pid (the
	 *        host pid of the dumped task).
	 * Return: 0 on success, -1 on failure (which fails the dump).
	 *         The plugin emits its own pr_err on failure paths.
	 */
	CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT = 18,

	/*
	 * Per-VMA dump-side post-claim notification. Invoked at dump
	 * time by criu/proc_parse.c::handle_vma_plugin AFTER one of
	 * the loaded plugins has already returned 0 from
	 * CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA -- i.e. after the binary
	 * "is this device VMA yours" decision has been made and the
	 * VMA has been admitted to the dump with VMA_EXT_PLUGIN.
	 *
	 * Distinct from HANDLE_DEVICE_VMA because:
	 *   - HANDLE is a *gate* (binary; first claimer wins), and
	 *     to keep its contract minimal it only sees (fd, stat).
	 *     Adding fields there would change the existing ABI for
	 *     amdgpu_plugin and any other consumer that registered
	 *     the cr_plugin_handle_device_vma symbol against the
	 *     historical signature.
	 *   - PROCESS is a *capture*: optional, runs after a
	 *     successful claim, and gets the VMA's bounds and
	 *     pgoff (in bytes) in addition to (fd, stat). Plugins
	 *     that don't need per-VMA metadata simply don't register
	 *     a cr_plugin_process_device_vma symbol -- the loader
	 *     treats absence as "no-op" rather than as a load
	 *     failure (mirrors the optional CHECKPOINT_DEVICES /
	 *     RDMA_DUMP_UVERBS_CONTEXT pattern).
	 *
	 * Concrete consumer (S5a CQ restore):
	 *   The rxe plugin uses PROCESS_DEVICE_VMA to record the
	 *   per-cdev-VMA mmap cookie (vma_pgoff_bytes == vma->vm_pgoff
	 *   << PAGE_SHIFT, equal to the kernel-allocated rxe_mmap_info.
	 *   info.offset returned at source-time CMD_CREATE_CQ) into a
	 *   small criu-side side-table keyed by (pid, ibdev). The
	 *   per-uobj DAG dump (rdma_dump_uobj_dag's CQ callback) then
	 *   queries the side-table and ships the source offset back
	 *   to the kernel as UHW_IN at restore time, so the dest's
	 *   rxe_create_mmap_info pins the new CQ's mmap region at
	 *   exactly the same offset the pie restorer's mmap is
	 *   targeting (linux kernel d3a79140ed26 +
	 *   rxe_restore_cq_req.vm_pgoff). Without PROCESS the dump
	 *   side has no reasonable join key between vm_pgoff and
	 *   the per-uobj DAG.
	 *
	 * Args:  pid -- host pid of the dumpee task (the owner of the
	 *               VMA). Indispensable in pstree dumps where
	 *               multiple tasks share the same cdev (same
	 *               st_rdev, same ibdev) -- the pid disambiguates
	 *               which dumpee a recorded vma_pgoff belongs to.
	 *        fd  -- the source dumpee's mapped-file fd, same as
	 *               HANDLE_DEVICE_VMA.
	 *        stat -- ditto.
	 *        vma_start, vma_end -- VMA bounds in source process
	 *               address space, bytes.
	 *        vma_pgoff_bytes -- vma->vm_pgoff << PAGE_SHIFT;
	 *               matches the file offset for fd-backed
	 *               mappings, which for /dev/infiniband/uverbsN
	 *               is the kernel-allocated mmap cookie.
	 * Return: 0 on success (the only meaningful return today;
	 *         any non-zero short-circuits run_plugins(), as with
	 *         the other CRIU per-VMA hooks).
	 */
	CR_PLUGIN_HOOK__PROCESS_DEVICE_VMA = 19,

	/*
	 * Per-CQ uobject dump-side capture, dispatched by the
	 * R3 uobj-walker (criu/rdma/uobj_dump.c::uobj_cq_cb)
	 * once per CQ entry returned by NLDEV. Mirrors the
	 * per-ucontext RDMA_DUMP_UVERBS_CONTEXT pattern but at
	 * the per-uobject scope.
	 *
	 * Distinct from RDMA_DUMP_UVERBS_CONTEXT because the
	 * per-CQ payload is per-uobject driver-private data,
	 * not per-ucontext aggregate state.
	 *
	 * Args:
	 *   ibdev             ibdev name of the source ucontext
	 *                     (diagnostic context).
	 *   kernel_driver_id  the dumpee's kernel-side driver id
	 *                     (RDMA_DRIVER_MLX5 / _RXE / ...).
	 *                     Plugins that handle multiple
	 *                     drivers via one .so use this to
	 *                     dispatch internally.
	 *   lfd               criu's dup of the dumpee's
	 *                     uverbs cdev fd. Same fd the
	 *                     per-uobject dispatcher already
	 *                     uses for QUERY_MR; the IDR
	 *                     resolution for HANDLE goes
	 *                     through this fd's ufile-idr.
	 *   ufile_handle      the source ufile-idr handle of
	 *                     the CQ uobject being dumped
	 *                     (NLDEV K8a RES_HANDLE; the same
	 *                     value RESTORE_CQ will install on
	 *                     the destination via
	 *                     UVERBS_ATTR_RESTORE_CQ_HANDLE).
	 *   pid               source-process pid of the
	 *                     dumpee. Join key for plugin-side
	 *                     side-table lookups (e.g. rxe's
	 *                     rdma_pop_cdev_vma_offset against
	 *                     the per-(pid, ibdev) cdev-VMA
	 *                     queue).
	 *   cq_attrs          generated protobuf attrs the
	 *                     plugin populates with the hw-
	 *                     agnostic per-class fields it
	 *                     can fill. The dispatcher pre-
	 *                     fills cqe_count from NLDEV
	 *                     (RES_CQE); the plugin SHOULD NOT
	 *                     touch that field. The plugin
	 *                     owns comp_vector and flags (not
	 *                     in NLDEV).
	 *   plugin_blob       caller-provided ProtobufCBinaryData
	 *                     the plugin fills with its driver-
	 *                     private per-CQ schema, malloc()'d
	 *                     by the plugin. Caller (uobj_cq_cb)
	 *                     attaches the bytes onto the
	 *                     RdmaUobjEntry.plugin_blob field,
	 *                     pb_write_one's into the image,
	 *                     then free()s. Plugin SHOULD set
	 *                     plugin_blob->data to NULL +
	 *                     plugin_blob->len to 0 if it has
	 *                     no driver-private state for this
	 *                     particular CQ -- caller treats
	 *                     that as "absent" and does not
	 *                     attach.
	 *
	 * Return: 0 on success, negative errno on failure.
	 *         A failed plugin call aborts the entire dump
	 *         (the ufile would be partially captured and
	 *         restore would not work). Plugins that don't
	 *         support a particular CQ (e.g. kernel CQs that
	 *         the dispatcher routed here by mistake) should
	 *         return -ENXIO; the dispatcher logs and treats
	 *         that as a per-uobject skip rather than a
	 *         dump-fatal error.
	 */
	CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ = 20,

	/*
	 * Per-CQ uobject restore-side UHW shape callbacks. The
	 * pair partitions driver-private knowledge for
	 * UVERBS_METHOD_RESTORE_CQ: criu core builds the driver-
	 * agnostic ioctl skeleton (HANDLE, CQE, USER_HANDLE,
	 * COMP_VECTOR, FLAGS, RESP_CQE) from rdma_cq_attrs +
	 * the ufile handle map; the per-driver RDMA plugin
	 * shapes UHW_IN/UHW_OUT around it from its own
	 * plugin_blob schema.
	 *
	 * UHW_PACK runs once per CQ before the ioctl. The
	 * plugin reads e->plugin_blob (its own packed schema --
	 * mlx5 stuffs the 32B mlx5_ib_restore_cq_req there at
	 * dump time, rxe stuffs an 8B vm_pgoff) and fills
	 * @uhw with malloc()'d UHW_IN bytes + UHW_OUT receive
	 * buffer. Either side may be empty (in_len=0 / out_len=0)
	 * for drivers that need only one direction. Core frees
	 * uhw->in_buf and uhw->out_buf after the ioctl + UHW_VERIFY
	 * round-trip via free(); plugin allocator MUST be
	 * malloc()-compatible.
	 *
	 * UHW_VERIFY is optional and runs once after the ioctl
	 * succeeds, before core frees the buffers. The plugin
	 * reads uhw->out_buf and asserts the kernel-echo matches
	 * what its UHW_IN asked for (rxe uses this for
	 * mi_offset == requested vm_pgoff defense in depth;
	 * mlx5 has no UHW_OUT and skips registering the hook).
	 * @resp_cqe is the kernel-stamped resp_cqe value the
	 * dispatcher already received via the core RESP_CQE
	 * attr, exposed here so the plugin can include it in any
	 * cross-attr correctness check.
	 *
	 * Both hooks are optional. A plugin that registers
	 * neither lets its CQs through with no UHW (the
	 * degenerate driver shape; no in-tree provider currently
	 * uses it). Plugins that need only PACK skip VERIFY.
	 *
	 * Return: 0 on success, negative errno on failure. PACK
	 * failures abort the restore for that CQ. VERIFY
	 * failures are surfaced as -EPROTO from the per-CQ
	 * helper -- catch a kernel that didn't honor a
	 * documented contract loudly, before returning to user
	 * code.
	 */
	CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_CQ_UHW_PACK = 21,

	/*
	 * Per-MR uobject restore-side UHW shape callback. Same shape
	 * as the CQ pack hook, applied to UVERBS_METHOD_RESTORE_MR:
	 * criu core builds the driver-agnostic ioctl skeleton (HANDLE,
	 * PD_HANDLE, ADDR, LENGTH, IOVA, ACCESS_FLAGS, LKEY_HINT,
	 * RKEY_HINT, RESP_LKEY, RESP_RKEY) from rdma_mr_attrs + the
	 * ufile handle map; the per-driver plugin shapes UHW_IN /
	 * UHW_OUT around it through the rdma_uhw_spec.
	 */
	CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_MR_UHW_PACK = 22,

	/*
	 * Per-driver opt-in: this driver's RESTORE_CQ ioctl needs to
	 * run from the pie blob (post-VMA-mmap, in the restored
	 * task's mm) rather than from CRIU master Phase A.
	 *
	 * Background: drivers split into two camps for RESTORE_CQ:
	 *   (a) "ring lives in user pages, kernel pins them at
	 *       restore_cq time" -- e.g. mlx5_ib_restore_cq calls
	 *       ib_umem_get(udata, src_va, len, ...) which pins
	 *       current->mm pages. Calling this from CRIU master
	 *       pins master's mm pages, which is wrong. Must run
	 *       in pie, *after* the user VMA pass has laid the
	 *       ring's pages at the source VAs.
	 *   (b) "ring lives in kernel-allocated pages exposed via
	 *       a vm_pgoff slot" -- e.g. rxe_restore_cq allocates
	 *       a kernel buffer and registers a vm_pgoff entry on
	 *       the uverbs cdev's mmap table. Calling this from
	 *       CRIU master is fine (no pin), but it MUST run
	 *       *before* the user VMA pass's mmap of the cdev fd
	 *       at that vm_pgoff -- otherwise the mmap fails
	 *       -EINVAL because the slot isn't registered yet.
	 *       Pie runs after VMA mmap, so pie is wrong here.
	 *
	 * Camps (a) and (b) demand opposite orderings, so a single
	 * dispatch site can't satisfy both. The plugin reports
	 * which camp its driver is in via this hook; absent / 0 =
	 * camp (b), master Phase A. Non-zero = camp (a), pie
	 * Phase B (post-VMA).
	 *
	 * No args, no per-CQ context: this is a static driver
	 * property, evaluated once per ufile_id at Phase A close
	 * to decide where to dispatch all CQs in that ufile.
	 *
	 * Hook absence is the default; only plugins that need
	 * pie-deferral register it. Keeps the sandbox cleanly
	 * "rxe-style works without any extra hook".
	 */
	CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_CQ_NEEDS_PIE = 23,

	CR_PLUGIN_HOOK__MAX
};

#define DECLARE_PLUGIN_HOOK_ARGS(__hook, ...) typedef int(__hook##_t)(__VA_ARGS__)

DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__DUMP_UNIX_SK, int fd, int id);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__RESTORE_UNIX_SK, int id);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__DUMP_EXT_FILE, int fd, int id);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__RESTORE_EXT_FILE, int id, bool *retry_needed);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__DUMP_EXT_MOUNT, char *mountpoint, int id);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__RESTORE_EXT_MOUNT, int id, char *mountpoint, char *old_root, int *is_file);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__DUMP_EXT_LINK, int index, int type, char *kind);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA, int fd, const struct stat *stat);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__PROCESS_DEVICE_VMA, pid_t pid, int fd,
			 const struct stat *stat, uint64_t vma_start,
			 uint64_t vma_end, uint64_t vma_pgoff_bytes);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__UPDATE_VMA_MAP, const char *path, const uint64_t addr,
			 const uint64_t old_pgoff, uint64_t *new_pgoff, int *plugin_fd);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, int pid);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__PAUSE_DEVICES, int pid);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__CHECKPOINT_DEVICES, int pid);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__POST_FORKING, void);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__RESTORE_INIT, void);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__DUMP_DEVICES_LATE, int id);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__UPDATE_INETSK, uint32_t family, uint32_t state, uint32_t *src_ip, uint32_t *dst_ip);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT, const char *ibdev, uint32_t kernel_driver_id);
/*
 * Pull in the protobuf-c definition of UverbsFileEntry directly.
 * A forward-declared struct tag would be cheaper but isn't
 * portable: protoc-c versions disagree on whether the generated
 * struct is named `struct UverbsFileEntry` or
 * `struct _UverbsFileEntry`. With only the typedef name visible
 * (which IS stable across generator versions), the trampoline
 * decl below stays consistent with both call sites in
 * criu/rdma.c and plugin OPEN_UVERBS_CDEV implementations
 * regardless of which protoc-c built images/uverbsfd.pb-c.h.
 */
#include "images/uverbsfd.pb-c.h"
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV, const UverbsFileEntry *uvfe);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT,
			 const char *ibdev, uint32_t kernel_driver_id,
			 uint32_t ctxn, int lfd, pid_t pid);
/*
 * Per-CQ dump+restore hooks. The RdmaCqAttrs / RdmaUobjEntry
 * typedefs and the ProtobufCBinaryData plugin-blob byteslice
 * resolve through images/rdma_uobj.pb-c.h -- same forward-include
 * style as UverbsFileEntry above for the OPEN_UVERBS_CDEV hook,
 * and the same protoc-c naming-stability concern applies (only
 * the typedef name is portable across generator versions).
 */
#include "images/rdma_uobj.pb-c.h"
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ,
			 const char *ibdev, uint32_t kernel_driver_id,
			 int lfd, uint32_t ufile_handle,
			 pid_t pid,
			 RdmaCqAttrs *cq_attrs,
			 ProtobufCBinaryData *plugin_blob);

/*
 * UHW pack scratch for per-class restore-side UHW hooks.
 *
 * Plugin malloc()'s in_buf / out_buf inside its UHW_PACK hook;
 * core stages them through the per-class rst_rdma_<TYPE> static
 * buffer (when the verb runs from the pie restorer -- CQ, MR,
 * future QP) or attaches them directly as UHW_IN / UHW_OUT attrs
 * on the UVERBS_METHOD_RESTORE_<TYPE> ioctl (when the verb runs
 * from CRIU master -- PD today). Either direction may be left as
 * {NULL, 0} if the driver shape doesn't use that direction.
 *
 * Output verification is byte-template-based (no per-class
 * VERIFY callback): the plugin pre-fills @out_buf at PACK time
 * with the bytes it expects the kernel to echo back, and
 * @verify_len tells core how many of those bytes the post-ioctl
 * memcmp must check. This keeps verification co-locatable with
 * the byte template through the master->pie boundary and avoids
 * a callback-from-pie design (plugins aren't loaded inside the
 * pie blob).
 *
 *   in_buf / in_len     -- bytes the kernel should consume as
 *                          UVERBS_ATTR_UHW_IN. Plugin malloc()'s,
 *                          core free()'s.
 *
 *   out_buf / out_len   -- two-purpose buffer:
 *                            (a) declares the size of the
 *                                UVERBS_ATTR_UHW_OUT attr core
 *                                attaches to the ioctl
 *                                (out_len = sizeof(driver_resp))
 *                            (b) carries the plugin's expected
 *                                kernel echo bytes pre-filled
 *                                into out_buf, used by core's
 *                                post-ioctl byte-equal verify.
 *                          Plugin malloc()'s, core free()'s.
 *                          Set to {NULL, 0} if the verb has no
 *                          UHW_OUT (mlx5 RESTORE_CQ, MR).
 *
 *   verify_len          -- size of the byte-equal subset to
 *                          check post-ioctl. Must satisfy
 *                          0 <= verify_len <= out_len. The first
 *                          @verify_len bytes of the kernel's
 *                          UHW_OUT echo must equal the first
 *                          @verify_len bytes of the staged
 *                          out_buf template. verify_len = 0
 *                          means no verify (out_buf is just a
 *                          receive area; common for kernel
 *                          handlers that require a UHW_OUT slot
 *                          but the plugin doesn't care about
 *                          the contents). verify_len < out_len
 *                          lets the plugin verify a leading
 *                          subset of fields and ignore later
 *                          ones (rxe RESTORE_CQ uses this:
 *                          rxe_create_cq_resp.mi_offset is the
 *                          8 leading bytes the plugin verifies;
 *                          mi_size + mi_pad after it are
 *                          kernel-determined and not checked).
 *
 * Lives at file scope (not inside any per-class block) because
 * the per-class hooks (UHW_PACK for RESTORE_CQ, _MR, ...) share
 * the same shape -- the per-class differences live in the
 * surrounding hook signature, not in this scratch.
 */
struct rdma_uhw_spec {
	void   *in_buf;
	size_t  in_len;
	void   *out_buf;
	size_t  out_len;
	size_t  verify_len;
};

DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_CQ_UHW_PACK,
			 const RdmaUobjEntry *e,
			 struct rdma_uhw_spec *uhw);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_MR_UHW_PACK,
			 const RdmaUobjEntry *e,
			 struct rdma_uhw_spec *uhw);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_CQ_NEEDS_PIE,
			 void);

/*
 * RDMA sharing policy.
 *
 * RDMA-class plugins SHOULD export a const int symbol named
 *   "cr_rdma_sharing_policy"
 * with one of the values below, telling criu whether snapshotting
 * (and later restoring) one process's contexts on a device this
 * plugin owns is safe in the presence of other, non-snapshot-tree
 * processes that also hold contexts on the same device.
 *
 *   CR_RDMA_SHARING_SHAREABLE  (= 0)
 *       Per-context state is fully isolated. Snapshotting one
 *       owner's context on device D and restoring it elsewhere
 *       does not perturb other live owners of device D on this
 *       host. Soft-RoCE (rxe) is the canonical example: rxe is
 *       a software provider whose per-uverbs-context state lives
 *       in the kernel module's per-fd objects, not in shared
 *       device-wide registers.
 *
 *   CR_RDMA_SHARING_EXCLUSIVE  (= 1)
 *       Snapshot+restore of any context on device D implies
 *       reconfiguring shared device-wide state. Other live owners
 *       of D would lose access. mlx5 SR-IOV VF migration is the
 *       canonical example: vfmig snapshots and restores the
 *       entire VF as one unit, and any non-snapshot context on
 *       that VF is destroyed by the restore.
 *
 * If a plugin does not export this symbol, criu treats it as
 * EXCLUSIVE -- safe default. Cross-tree exclusivity check (see
 * criu/rdma.c) hard-fails the dump if it finds a non-snapshot-tree
 * pid holding a context on a device that any snapshot-tree pid
 * also uses, when the claiming plugin's policy is EXCLUSIVE.
 */
enum {
	CR_RDMA_SHARING_SHAREABLE = 0,
	CR_RDMA_SHARING_EXCLUSIVE = 1,
};

#define CR_PLUGIN_RDMA_SHARING_POLICY_SYM "cr_rdma_sharing_policy"

#define CR_PLUGIN_DECLARE_RDMA_SHARING(__value) \
	const int cr_rdma_sharing_policy = (__value)

/*
 * RDMA provided driver -- the RdmaCriuDriver enum value (RCD_RXE,
 * RCD_MLX5_SRIOV_VFMIG, ...) that this plugin claims and serves.
 *
 * RDMA-class plugins that implement CR_PLUGIN_HOOK__RDMA_OPEN_
 * UVERBS_CDEV MUST export a const int symbol named
 *   "cr_rdma_provided_driver"
 * carrying the same RdmaCriuDriver value the plugin returns from
 * its CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT implementation.
 *
 * The dispatcher in criu/rdma.c uses this symbol to find which
 * loaded plugin should be invoked at restore time for a uverbs
 * cdev whose image-recorded UverbsFileEntry.criu_driver names a
 * specific provider. Walking the hook chain alone is not enough:
 * every plugin registers the same hook id, but only the one whose
 * provided-driver matches the image's criu_driver should run.
 *
 * Defaults: a plugin that does not export this symbol is treated
 * as "claims nothing" (RCD_UNKNOWN) by the open dispatcher and
 * will be skipped. That is intentional -- a plugin without a
 * provided-driver declaration cannot be safely matched to an
 * image record.
 */
#define CR_PLUGIN_RDMA_PROVIDED_DRIVER_SYM "cr_rdma_provided_driver"

#define CR_PLUGIN_DECLARE_RDMA_PROVIDED_DRIVER(__value) \
	const int cr_rdma_provided_driver = (__value)

enum {
	CR_PLUGIN_STAGE__DUMP,
	CR_PLUGIN_STAGE__PRE_DUMP,
	CR_PLUGIN_STAGE__RESTORE,

	CR_PLUGIN_STAGE_MAX
};

/*
 * Plugin descriptor.
 */
typedef struct {
	const char *name;
	int (*init)(int stage);
	void (*exit)(int stage, int ret);
	unsigned int version;
	unsigned int max_hooks;
	void *hooks[CR_PLUGIN_HOOK__MAX];
} cr_plugin_desc_t;

extern cr_plugin_desc_t CR_PLUGIN_DESC;

#define CR_PLUGIN_REGISTER(___name, ___init, ___exit) \
	cr_plugin_desc_t CR_PLUGIN_DESC = {           \
		.name = ___name,                      \
		.init = ___init,                      \
		.exit = ___exit,                      \
		.version = CRIU_PLUGIN_VERSION,       \
		.max_hooks = CR_PLUGIN_HOOK__MAX,     \
	};

static inline int cr_plugin_dummy_init(int stage)
{
	return 0;
}
static inline void cr_plugin_dummy_exit(int stage, int ret)
{
}

#define CR_PLUGIN_REGISTER_DUMMY(___name)         \
	cr_plugin_desc_t CR_PLUGIN_DESC = {       \
		.name = ___name,                  \
		.init = cr_plugin_dummy_init,     \
		.exit = cr_plugin_dummy_exit,     \
		.version = CRIU_PLUGIN_VERSION,   \
		.max_hooks = CR_PLUGIN_HOOK__MAX, \
	};

#define CR_PLUGIN_REGISTER_HOOK(__hook, __func)                                         \
	static void __attribute__((constructor)) cr_plugin_register_hook_##__func(void) \
	{                                                                               \
		CR_PLUGIN_DESC.hooks[__hook] = (void *)__func;                          \
	}

/* Public API */
extern int criu_get_image_dir(void);

/*
 * Issue an UVERBS_METHOD_GET_CONTEXT ioctl against an already-open
 * uverbs cdev fd, creating the kernel ucontext object on @fd.
 *
 * Exposed to plugins so the RDMA_OPEN_UVERBS_CDEV hook can return a
 * fully-armed fd (one with a kernel ucontext established) -- the
 * uniform contract that lets uverbsfd_open() avoid a second
 * GET_CONTEXT (which would fail: the kernel allows exactly one
 * ucontext per struct file). For a software provider like rxe this
 * is just a small wrapper around the verbs ioctl. For mlx5 vfmig
 * the same call is issued in the plugin's init(RESTORE) on each
 * eagerly-cached cdev fd, before any UPDATE_VMA_MAP can dup() that
 * fd to satisfy a UAR mmap (mlx5_ib_mmap requires an active
 * ucontext on the file).
 *
 * @driver_id is the RDMA_DRIVER_* enum value from the uverbs file
 * entry. Returns 0 on success or -errno on ioctl failure.
 */
extern int criu_ib_uverbs_get_context(int fd, uint32_t driver_id);

/*
 * Record a source-side cdev-mapped VMA's pgoff (in bytes) into
 * criu's process-global RDMA cdev VMA side-table, keyed by
 * (@pid, @ibdev).
 *
 * Intended caller: an RDMA-class plugin's
 * CR_PLUGIN_HOOK__PROCESS_DEVICE_VMA implementation, once it has
 * determined the just-claimed VMA backs an ibdev the plugin owns.
 * The plugin is responsible for resolving the VMA's @stat->st_rdev
 * to an ibdev name (e.g. "rxe0", "mlx5_2") via the kernel's
 * /sys/dev/char/<maj>:<min>/ibdev attribute -- criu/rdma.c keeps
 * that resolution in the plugin layer rather than in core because
 * each driver decides for itself which cdev VMAs it cares about
 * (rxe records all of them; mlx5 may filter UAR vs blueflame vs
 * CQ-ring, etc.).
 *
 * Insertion order matters: the per-uobj DAG dump
 * (criu/rdma.c::rdma_dump_uobj_dag, downstream of every per-task
 * VMA walk) pops entries FIFO via rdma_pop_cdev_vma_offset(); for
 * rxe each new mmap_info uses a monotonically growing vm_pgoff
 * and userspace mmap()s in CMD_CREATE_<TYPE> order, so insertion-
 * order pop matches NLDEV's per-class enumeration order against
 * the source's creation order. Plugins should call this hook once
 * per VMA, in the order /proc/<pid>/smaps emits them (which is
 * what the CR_PLUGIN_HOOK__PROCESS_DEVICE_VMA dispatcher provides
 * naturally).
 *
 * Returns 0 on success, -1 on allocation failure.
 */
extern int rdma_record_cdev_vma(pid_t pid, const char *ibdev,
				uint64_t pgoff_bytes);

/*
 * Companion FIFO pop for rdma_record_cdev_vma's process-global
 * side-table. Intended caller: an RDMA-class plugin's
 * CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ implementation, draining one
 * cookie per CQ from the queue its PROCESS_DEVICE_VMA filled
 * earlier. rxe is the canonical user: each rxe CQ has exactly one
 * matching cdev VMA whose vm_pgoff the kernel will compare against
 * UVERBS_METHOD_RESTORE_CQ's UHW_IN.vm_pgoff at restore-time, and
 * /proc/<pid>/smaps emits VMAs in the same kernel-internal order
 * NLDEV walks CQs, so a FIFO drain per CQ matches one-to-one.
 *
 * Out: writes the popped pgoff_bytes (vma->vm_pgoff << PAGE_SHIFT,
 * matching rxe_mmap_info::offset / rxe_restore_cq_req::vm_pgoff)
 * into *@out and returns 0 on a hit, -ENOENT if the queue has
 * nothing left for the (pid, ibdev) join (which the plugin can
 * treat as "no source VMA captured for this CQ" -- legitimate on
 * pre-K8a kernels that didn't surface the matching VMA, or on
 * holders that don't mmap the CQ ring).
 */
extern int rdma_pop_cdev_vma_offset(pid_t pid, const char *ibdev,
				    uint64_t *out);

/*
 * Deprecated, will be removed in next version.
 */
typedef int(cr_plugin_init_t)(void);
typedef void(cr_plugin_fini_t)(void);
typedef int(cr_plugin_dump_unix_sk_t)(int fd, int id);
typedef int(cr_plugin_restore_unix_sk_t)(int id);
typedef int(cr_plugin_dump_file_t)(int fd, int id);
typedef int(cr_plugin_restore_file_t)(int id);
typedef int(cr_plugin_dump_ext_mount_t)(char *mountpoint, int id);
typedef int(cr_plugin_restore_ext_mount_t)(int id, char *mountpoint, char *old_root, int *is_file);
typedef int(cr_plugin_dump_ext_link_t)(int index, int type, char *kind);
typedef int(cr_plugin_handle_device_vma_t)(int fd, const struct stat *stat);
typedef int(cr_plugin_update_vma_map_t)(const char *path, const uint64_t addr, const uint64_t old_pgoff,
					uint64_t *new_pgoff, int *plugin_fd);
typedef int(cr_plugin_resume_devices_late_t)(int pid);
typedef int(cr_plugin_post_forking_t)(void);
typedef int(cr_plugin_update_inetsk_t)(uint32_t family, uint32_t state, uint32_t *src_ip, uint32_t *dst_ip);

#endif /* __CRIU_PLUGIN_H__ */
