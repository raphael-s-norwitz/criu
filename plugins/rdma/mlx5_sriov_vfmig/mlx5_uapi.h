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
 * dump/restore layers land: it carries the dump-side QUERY surface
 * (QUERY_UCONTEXT / QUERY_DYN_UARS) and the restore surface for both
 * modes (RESTORE_UCONTEXT / RESTORE_DYN_UARS verbs + GET_CONTEXT alloc
 * structs).
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
 * Static-UAR RESTORE_UCONTEXT method + attrs. The restore side replays
 * the QUERY_UCONTEXT snapshot back into a freshly allocated
 * VFMIG_RESTORE ucontext; the attr ids mirror the QUERY_UCONTEXT ones
 * (uar_table, bfreg_count, meta) so the kernel's uverbs_copy_from lines
 * up byte-for-byte with what QUERY_UCONTEXT copied out.
 */
#define MLX5_IB_METHOD_VFMIG_RESTORE_UCONTEXT_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define MLX5_IB_ATTR_VFMIG_RESTORE_UCONTEXT_UAR_TABLE_LOCAL \
	(1u << UVERBS_ID_NS_SHIFT_LOCAL)
#define MLX5_IB_ATTR_VFMIG_RESTORE_UCONTEXT_BFREG_COUNT_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define MLX5_IB_ATTR_VFMIG_RESTORE_UCONTEXT_META_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 2)

/*
 * Dynamic-UAR (lib_uar_dyn=true) QUERY_DYN_UARS / RESTORE_DYN_UARS
 * method + attrs. The dyn methods are the next two slots in the VFMIG
 * enum after the static ones. RESTORE_DYN_UARS takes only the records
 * array (the kernel infers the count from the attr length).
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
 * QUERY_PD method + attrs. Dump-side counterpart to
 * UVERBS_METHOD_RESTORE_PD: for the PD resolved through UVERBS_OBJECT_PD
 * on the calling fd's ufile, the kernel emits the FW pdn (as a
 * mlx5_ib_restore_pd_req, RESP_BLOB) plus the source PD's mpd->uid
 * (RESP_UID). QUERY_PD is the fifth method in the VFMIG enum, after the
 * static/dyn ucontext query+restore methods. HANDLE is an IDR ref
 * (UVERBS_OBJECT_PD, ACCESS_READ); both RESP_* are PTR_OUT.
 */
#define MLX5_IB_METHOD_VFMIG_QUERY_PD_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 4)
#define MLX5_IB_ATTR_VFMIG_QUERY_PD_HANDLE_LOCAL \
	(1u << UVERBS_ID_NS_SHIFT_LOCAL)
#define MLX5_IB_ATTR_VFMIG_QUERY_PD_RESP_BLOB_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define MLX5_IB_ATTR_VFMIG_QUERY_PD_RESP_UID_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 2)

/*
 * Local mirror of include/uapi/rdma/mlx5-abi.h's struct
 * mlx5_ib_restore_pd_req: the driver-private UHW payload shared by
 * QUERY_PD (RESP_BLOB, dump) and UVERBS_METHOD_RESTORE_PD (UHW_IN,
 * restore). Wire layout MUST match the kernel (16 bytes): the kernel
 * emits it verbatim on dump and ib_copy_from_udata()s it on restore, so
 * a size/layout drift would corrupt the adopted pdn. reserved /
 * reserved2 must stay zero (the restore path's "must be 0" checks) and
 * pad the struct above uverbs' inline-UHW threshold so RESTORE_PD takes
 * the userspace-pointer UHW path.
 */
struct mlx5_ib_restore_pd_req_local {
	uint32_t pdn;
	uint32_t reserved;
	uint64_t reserved2;
} __attribute__((aligned(8)));

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

/*
 * Per-dynamic-UAR record (see include/uapi/rdma/mlx5_user_ioctl_cmds.h
 * for the full doc). Wire layout MUST match the kernel struct exactly
 * -- both QUERY and RESTORE consume/produce raw arrays of these.
 */
struct mlx5_ib_vfmig_dyn_uar_record_local {
	uint32_t handle;
	uint32_t uar_index;
	uint64_t mmap_offset;
	uint8_t alloc_type;
	uint8_t reserved0[7];
} __attribute__((aligned(8)));

/*
 * Library-capability bits carried in mlx5_ib_alloc_ucontext_req_v2's
 * lib_caps (mirror of the mlx5-abi MLX5_LIB_CAP_* bits). The dyn-UAR
 * restore path opens the destination ucontext with 4K_UAR | DYN_UAR so
 * the kernel takes the dynamic-UAR alloc branch (empty UAR uobject
 * list) that RESTORE_DYN_UARS then seeds.
 */
enum {
	MLX5_LIB_CAP_4K_UAR = (uint64_t)1 << 0,
	MLX5_LIB_CAP_DYN_UAR = (uint64_t)1 << 1,
};

/*
 * Restore-side alloc-ucontext flags (mirror of the mlx5-abi
 * MLX5_IB_ALLOC_UCTX_* bits). The legacy IB_USER_VERBS_CMD_GET_CONTEXT
 * write command carries these in mlx5_ib_alloc_ucontext_req_v2::flags.
 *
 * VFMIG_RESTORE tells mlx5_ib_alloc_ucontext to leave the fresh
 * ucontext's UAR table / sys_pages[] empty and arm vfmig_restore_pending
 * so the follow-up RESTORE_UCONTEXT verb can seed them from the image
 * snapshot. DEVX is defined only to document that bit 0 is taken; the
 * restore path always opens the destination without DEVX (the source's
 * devx_uid, commonly non-zero, is diagnostic-only and never adopted).
 */
enum {
	MLX5_IB_ALLOC_UCTX_DEVX = 1 << 0,
	MLX5_IB_ALLOC_UCTX_VFMIG_RESTORE = 1 << 1,
};

/*
 * Local mirror of the mlx5-abi GET_CONTEXT request/response payloads
 * (include/uapi/rdma/mlx5-abi.h: struct mlx5_ib_alloc_ucontext_req_v2 /
 * struct mlx5_ib_alloc_ucontext_resp). The restore side issues the
 * legacy write()-based IB_USER_VERBS_CMD_GET_CONTEXT with the driver
 * payload appended, so these must match the kernel wire layout exactly.
 * Only the request fields the restore path sets (total_num_bfregs,
 * num_low_latency_bfregs, flags, max_cqe_version, lib_caps) are
 * meaningful here; the rest are zeroed.
 */
struct mlx5_ib_alloc_ucontext_req_v2_local {
	uint32_t total_num_bfregs;
	uint32_t num_low_latency_bfregs;
	uint32_t flags;
	uint32_t comp_mask;
	uint8_t max_cqe_version;
	uint8_t reserved0;
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
	uint8_t cqe_version;
	uint8_t cmds_supp_uhw;
	uint8_t eth_min_inline;
	uint8_t clock_info_versions;
	uint64_t hca_core_clock_offset;
	uint32_t log_uar_size;
	uint32_t num_uars_per_page;
	uint32_t num_dyn_bfregs;
	uint32_t dump_fill_mkey;
} __attribute__((aligned(8)));

#endif /* __CR_MLX5_VFMIG_UAPI_H__ */
