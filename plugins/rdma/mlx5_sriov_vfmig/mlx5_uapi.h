#ifndef __CR_MLX5_VFMIG_UAPI_H__
#define __CR_MLX5_VFMIG_UAPI_H__

/*
 * Inlined mlx5_ib uverbs UAPI surface for the SR-IOV VFMIG plugin.
 *
 * Carries the bits of the kernel uverbs ABI that aren't yet shipped by
 * every distribution's rdma-core-devel: the MLX5_IB_OBJECT_VFMIG object
 * / method / attr ids and the structs the VFMIG verbs marshal across
 * the kernel boundary. Inlined rather than pulled from
 * <rdma/mlx5_user_ioctl_cmds.h> because that header is not yet part of
 * every distribution's rdma-core-devel, so building criu against it
 * would require contributors to run `make headers_install` from a
 * bleeding-edge kernel tree.
 *
 * Names carry a _LOCAL / _local suffix so a future move to the system
 * headers can be staged without symbol clashes.
 *
 * Keep in sync with the kernel UAPI:
 *   include/uapi/rdma/ib_user_ioctl_cmds.h    (UVERBS_ID_NS_SHIFT)
 *   include/uapi/rdma/mlx5_user_ioctl_cmds.h  (VFMIG object/methods)
 *
 * This header grows one section at a time as the plugin's context
 * dump/restore layers land: today it carries only the static-UAR
 * dump-side QUERY surface (QUERY_UCONTEXT); the dyn-UAR QUERY verb, the
 * RESTORE verbs, and the GET_CONTEXT alloc structs arrive with later
 * commits.
 */

#include <stdint.h>

/*
 * VFMIG object/method/attr ids. The kernel header arithmetic is
 *   MLX5_IB_OBJECT_DEVX = (1u << UVERBS_ID_NS_SHIFT)
 *   ... 9 entries between DEVX and VFMIG ...
 *   MLX5_IB_OBJECT_VFMIG = DEVX + 10
 * Update if entries are inserted before VFMIG in the kernel enum.
 */
#define UVERBS_ID_NS_SHIFT_LOCAL 12
#define MLX5_IB_OBJECT_VFMIG_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 10)

/* Static-UAR (lib_uar_dyn=false) QUERY_UCONTEXT method + attrs. */
#define MLX5_IB_METHOD_VFMIG_QUERY_UCONTEXT_LOCAL \
	(1u << UVERBS_ID_NS_SHIFT_LOCAL)
#define MLX5_IB_ATTR_VFMIG_QUERY_UCONTEXT_UAR_TABLE_LOCAL \
	(1u << UVERBS_ID_NS_SHIFT_LOCAL)
#define MLX5_IB_ATTR_VFMIG_QUERY_UCONTEXT_BFREG_COUNT_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define MLX5_IB_ATTR_VFMIG_QUERY_UCONTEXT_META_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 2)

/*
 * Local mirror of include/uapi/rdma/mlx5_user_ioctl_cmds.h's struct
 * mlx5_ib_vfmig_ucontext_meta. Wire layout MUST match the kernel (40
 * bytes) so QUERY_UCONTEXT's uverbs_copy_to and RESTORE_UCONTEXT's
 * uverbs_copy_from line up byte-for-byte.
 *
 * @devx_uid is the source ucontext's firmware owner-id, commonly
 * non-zero because the default libmlx5 ucontext auto-allocates a DEVX
 * uid on every ibv_open_device. (CRIU built against an older kernel
 * that doesn't emit it reads zero.) Consumed by the dump path only as
 * image-only metadata (mlx5_vfmig_state_entry.source_devx_uid); it is
 * never enforced -- RESTORE_UCONTEXT tolerates a mismatch.
 */
struct mlx5_ib_vfmig_ucontext_meta_local {
	uint32_t num_static_sys_pages;
	uint32_t num_sys_pages;
	uint32_t num_dyn_bfregs;
	uint32_t num_low_latency_bfregs;
	uint32_t total_num_bfregs;
	uint32_t reserved0;
	uint64_t lib_caps;
	uint8_t lib_uar_4k;
	uint8_t lib_uar_dyn;
	uint8_t cqe_version;
	uint8_t reserved1[3];
	uint16_t devx_uid;
} __attribute__((aligned(8)));

#endif /* __CR_MLX5_VFMIG_UAPI_H__ */
