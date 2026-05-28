#ifndef __CR_MLX5_VFMIG_UAPI_H__
#define __CR_MLX5_VFMIG_UAPI_H__

/*
 * Inlined kernel UAPI surface for the mlx5 SR-IOV VFMIG plugin.
 *
 * This header carries the bits of the kernel uverbs ABI that
 * aren't yet shipped by every distribution's rdma-core-devel:
 *
 *   - mlx5_ib_alloc_ucontext_req_v2 / _resp + ALLOC_UCTX flags
 *     (legacy IB_USER_VERBS_CMD_GET_CONTEXT write() path; the
 *     ADOPT_DEVX_UID flag is the post-afb3b5614af3 addition).
 *   - MLX5_IB_OBJECT_VFMIG object/method/attr ids and the
 *     mlx5_ib_vfmig_ucontext_meta_local + dyn_uar_record_local
 *     structs the VFMIG verbs marshal across the kernel boundary.
 *
 * Why inlined rather than including <rdma/mlx5_user_ioctl_cmds.h>
 * + <rdma/mlx5-abi.h>: those headers aren't yet part of every
 * distribution's rdma-core-devel package, so building criu against
 * them would require contributors to run `make headers_install`
 * from a bleeding-edge kernel tree. The companion kernel reference
 * exerciser (tools/testing/mlx5_vfmig/mlx5_vfmig_uctx.c) inlines
 * the same surface for the same reason.
 *
 * If the kernel UAPI evolves, keep the constants in sync with:
 *   include/uapi/rdma/ib_user_ioctl_cmds.h    (UVERBS_ID_NS_SHIFT)
 *   include/uapi/rdma/mlx5_user_ioctl_cmds.h  (VFMIG object/methods)
 *   include/uapi/rdma/mlx5-abi.h              (ALLOC_UCTX flags)
 *
 * Names carry a _LOCAL / _local suffix so a future move to the
 * system headers can be staged without symbol clashes.
 */

#include <stdint.h>

/*
 * Inlined kernel UAPI for the VFMIG ucontext verbs and the
 * mlx5_ib_alloc_ucontext_req_v2 driver_data carried over the
 * legacy IB_USER_VERBS_CMD_GET_CONTEXT write() path.
 *
 * Core uverbs surface (cmd_hdr, get_context, ioctl_hdr/attr,
 * RDMA_VERBS_IOCTL, UVERBS_ATTR_F_*) comes from the system
 * rdma-core-devel headers above.
 *
 * Why inline the rest:
 *   - rdma/mlx5_user_ioctl_cmds.h and rdma/mlx5-abi.h are not yet
 *     part of every distribution's rdma-core-devel package, so
 *     building criu against them would require contributors to run
 *     `make headers_install` from a bleeding-edge kernel tree. The
 *     companion kernel reference exerciser
 *     (tools/testing/mlx5_vfmig/mlx5_vfmig_uctx.c) inlines the same
 *     surface for the same reason.
 *   - mlx5_ib_alloc_ucontext_req_v2 has been stable ABI for years.
 *
 * If the kernel UAPI evolves, keep this block in sync with:
 *   include/uapi/rdma/ib_user_ioctl_cmds.h    (UVERBS_ID_NS_SHIFT)
 *   include/uapi/rdma/mlx5_user_ioctl_cmds.h  (VFMIG object/methods)
 *   include/uapi/rdma/mlx5-abi.h              (ALLOC_UCTX flags)
 */

/* mlx5_ib_alloc_ucontext_req_v2 / _resp + ALLOC_UCTX flags */
enum {
	MLX5_LIB_CAP_4K_UAR = (uint64_t)1 << 0,
	MLX5_LIB_CAP_DYN_UAR = (uint64_t)1 << 1,
};
enum {
	MLX5_IB_ALLOC_UCTX_DEVX = 1 << 0,
	MLX5_IB_ALLOC_UCTX_VFMIG_RESTORE = 1 << 1,
	/*
	 * Tells mlx5_ib_alloc_ucontext to skip its usual
	 * mlx5_ib_devx_create() and adopt the caller-supplied
	 * @adopt_devx_uid as context->devx_uid verbatim. The
	 * subsequent ALLOC_TRANSPORT_DOMAIN doubles as a FW-
	 * liveness probe -- a stale uid surfaces here and aborts
	 * alloc_ucontext.
	 *
	 * Kernel-enforced consistency: requires VFMIG_RESTORE +
	 * DEVX both set, and adopt_devx_uid in [1, U16_MAX].
	 * Otherwise the kernel returns -EINVAL. Without the flag,
	 * @adopt_devx_uid must be zero.
	 *
	 * UAPI value tracks
	 * include/uapi/rdma/mlx5-abi.h::MLX5_IB_ALLOC_UCTX_ADOPT_DEVX_UID
	 * (kernel afb3b5614af3 "RDMA/mlx5: adopt source devx_uid on
	 * VFMIG-restore ucontext alloc").
	 */
	MLX5_IB_ALLOC_UCTX_ADOPT_DEVX_UID = 1 << 2,
};
/*
 * mlx5_ib_alloc_ucontext_req_v2 with the post-afb3b5614af3 tail.
 * The kernel ABI is "shorter input is OK -- ib_copy_from_udata
 * zero-extends" (commit cdb1a2b30a1d), so emitting the longer
 * struct against an older kernel is harmless: the trailing
 * adopt_devx_uid + reserved3 bytes get truncated by udata->inlen.
 * Conversely, emitting the shorter struct against the newer
 * kernel implicitly sets adopt_devx_uid = 0 -- which is the
 * required value when ADOPT_DEVX_UID is not set.
 */
struct mlx5_ib_alloc_ucontext_req_v2_local {
	uint32_t total_num_bfregs;
	uint32_t num_low_latency_bfregs;
	uint32_t flags;
	uint32_t comp_mask;
	uint8_t  max_cqe_version;
	uint8_t  reserved0;
	uint16_t reserved1;
	uint32_t reserved2;
	uint64_t lib_caps;
	uint32_t adopt_devx_uid;
	uint32_t reserved3;
} __attribute__((aligned(8)));
struct mlx5_ib_alloc_ucontext_resp_local {
	uint32_t qp_tab_size;
	uint32_t bf_reg_size;
	uint32_t tot_bfregs;
	uint32_t cache_line_size;
	uint16_t max_sq_desc_sz;
	uint16_t max_rq_desc_sz;
	uint32_t max_send_wqebb;
	uint32_t max_recv_wr;
	uint32_t max_srq_recv_wr;
	uint16_t num_ports;
	uint16_t flow_action_flags;
	uint32_t comp_mask;
	uint32_t response_length;
	uint8_t  cqe_version;
	uint8_t  cmds_supp_uhw;
	uint8_t  eth_min_inline;
	uint8_t  clock_info_versions;
	uint64_t hca_core_clock_offset;
	uint32_t log_uar_size;
	uint32_t num_uars_per_page;
	uint32_t num_dyn_bfregs;
	uint32_t dump_fill_mkey;
} __attribute__((aligned(8)));

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
#define MLX5_IB_METHOD_VFMIG_QUERY_UCONTEXT_LOCAL \
	(1u << UVERBS_ID_NS_SHIFT_LOCAL)
#define MLX5_IB_METHOD_VFMIG_RESTORE_UCONTEXT_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define MLX5_IB_ATTR_VFMIG_QUERY_UCONTEXT_UAR_TABLE_LOCAL \
	(1u << UVERBS_ID_NS_SHIFT_LOCAL)
#define MLX5_IB_ATTR_VFMIG_QUERY_UCONTEXT_BFREG_COUNT_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define MLX5_IB_ATTR_VFMIG_QUERY_UCONTEXT_META_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 2)
#define MLX5_IB_ATTR_VFMIG_RESTORE_UCONTEXT_UAR_TABLE_LOCAL \
	(1u << UVERBS_ID_NS_SHIFT_LOCAL)
#define MLX5_IB_ATTR_VFMIG_RESTORE_UCONTEXT_BFREG_COUNT_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define MLX5_IB_ATTR_VFMIG_RESTORE_UCONTEXT_META_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 2)
#define MLX5_IB_INVALID_UAR_INDEX_LOCAL (1u << 31)

struct mlx5_ib_vfmig_ucontext_meta_local {
	uint32_t num_static_sys_pages;
	uint32_t num_sys_pages;
	uint32_t num_dyn_bfregs;
	uint32_t num_low_latency_bfregs;
	uint32_t total_num_bfregs;
	uint32_t reserved0;
	uint64_t lib_caps;
	uint8_t  lib_uar_4k;
	uint8_t  lib_uar_dyn;
	uint8_t  cqe_version;
	uint8_t  reserved1[5];
} __attribute__((aligned(8)));

/*
 * Dynamic-UAR (lib_uar_dyn=true) snapshot/restore verbs and record.
 *
 * QUERY_DYN_UARS / RESTORE_DYN_UARS run on the same MLX5_IB_OBJECT_VFMIG
 * object as QUERY_UCONTEXT / RESTORE_UCONTEXT but cover the ucontext
 * mode where libmlx5 doesn't use bfregi->sys_pages[] -- UARs are
 * MLX5_IB_OBJECT_UAR uobjects with their own table, and snapshots are
 * arrays of (handle, uar_index, mmap_offset, alloc_type). The two
 * paths are mutually exclusive at runtime: the kernel rejects
 * QUERY_UCONTEXT with -EOPNOTSUPP on a dyn ucontext, and rejects
 * QUERY_DYN_UARS with -EINVAL on a static ucontext.
 *
 * Method id arithmetic mirrors the static path -- the dyn methods are
 * the next two slots in the VFMIG enum.
 */
#define MLX5_IB_METHOD_VFMIG_QUERY_DYN_UARS_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 2)
#define MLX5_IB_METHOD_VFMIG_RESTORE_DYN_UARS_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 3)
#define MLX5_IB_ATTR_VFMIG_QUERY_DYN_UARS_RECORDS_LOCAL \
	(1u << UVERBS_ID_NS_SHIFT_LOCAL)
#define MLX5_IB_ATTR_VFMIG_QUERY_DYN_UARS_COUNT_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define MLX5_IB_ATTR_VFMIG_RESTORE_DYN_UARS_RECORDS_LOCAL \
	(1u << UVERBS_ID_NS_SHIFT_LOCAL)

/*
 * Per-dynamic-UAR record (see include/uapi/rdma/mlx5_user_ioctl_cmds.h
 * for the full doc). Wire layout MUST match the kernel struct exactly
 * -- both QUERY and RESTORE consume/produce raw arrays of these.
 */
struct mlx5_ib_vfmig_dyn_uar_record_local {
	uint32_t handle;
	uint32_t uar_index;
	uint64_t mmap_offset;
	uint8_t  alloc_type;
	uint8_t  reserved0[7];
} __attribute__((aligned(8)));

#endif /* __CR_MLX5_VFMIG_UAPI_H__ */
