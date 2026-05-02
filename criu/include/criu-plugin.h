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
