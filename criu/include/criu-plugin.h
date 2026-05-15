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
