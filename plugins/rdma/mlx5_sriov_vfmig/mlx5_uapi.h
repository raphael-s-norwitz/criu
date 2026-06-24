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
 * exerciser (tools/testing/criu_rdma/tools/ucontext_vendor_verbs.c)
 * inlines the same surface for the same reason.
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
 *     (tools/testing/criu_rdma/tools/ucontext_vendor_verbs.c) inlines
 *     the same surface for the same reason.
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

/*
 * Local mirror of include/uapi/rdma/mlx5_user_ioctl_cmds.h's
 * struct mlx5_ib_vfmig_ucontext_meta. Wire layout MUST match the
 * kernel (40 bytes) so QUERY_UCONTEXT's uverbs_copy_to and
 * RESTORE_UCONTEXT's uverbs_copy_from line up byte-for-byte.
 *
 * @devx_uid (kernel commit c659ab66483d "RDMA/mlx5: expose VFMIG
 * source devx_uid + harden destroy_qp diagnostics") is the source
 * ucontext's FW owner-id, repurposed from the original
 * reserved1[0..1] slot. Wire layout was preserved (still 40
 * bytes); CRIU built against an older kernel that doesn't emit
 * @devx_uid sees zero, which is correct only for the v0
 * critical path: a libibverbs ucontext opened without DEVX. Two
 * consumers in the plugin rely on @devx_uid:
 *
 *   1. vfmig dump path: refuses the dump if meta.devx_uid != 0.
 *      LOAD_VHCA_STATE on FW 28.48.1000 does NOT preserve the FW
 *      uctx-registration table (S3b "DEVX-adoption blind spot"
 *      matrix), so the destination kernel issues 2RST_QP /
 *      DESTROY_QP / DEALLOC_PD with c->devx_uid = 0 against FW
 *      resources owned by source.devx_uid; FW silently no-ops the
 *      QP-class opcodes (asymmetric uid acceptance: DESTROY_QP
 *      requires owner-uid match, DEALLOC_PD/DESTROY_CQ accept
 *      uid=0 host-priv) and the orphan QPC then surfaces as
 *      DEALLOC_PD bad_resource_state at the next teardown step.
 *
 *   2. RESTORE_UCONTEXT's strict-equality precondition #3: the
 *      kernel cross-checks meta.devx_uid against the destination
 *      c->devx_uid (set at GET_CONTEXT time) and returns -EINVAL
 *      on mismatch. Defense-in-depth -- if the dump-side filter
 *      at #1 is bypassed (e.g. CRIU running against an older
 *      kernel that didn't have the filter wired yet), the kernel
 *      fails restore loud and early instead of silently letting
 *      restore_pd/cq/qp stamp a uid that surfaces only at
 *      teardown.
 */
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
	uint8_t  reserved1[3];
	uint16_t devx_uid;
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

/*
 * Per-uobject CQ dump-side discovery verb.
 *
 * MLX5_IB_METHOD_VFMIG_QUERY_CQ runs on the same MLX5_IB_OBJECT_VFMIG
 * object as the ucontext / dyn-UAR verbs but is per-CQ-handle, not
 * per-ucontext. The HANDLE attr is an UVERBS_OBJECT_CQ IDR reference:
 * the caller's ufile-idr must own the CQ uobject, the kernel pins it
 * UVERBS_ACCESS_READ for the duration of the call. Same security
 * boundary as INFO_HANDLES(UVERBS_OBJECT_CQ): if you can see the
 * ucontext, you can read its metadata.
 *
 * Dump-side companion of UVERBS_METHOD_RESTORE_CQ. Closes the
 * cross-process gap that mlx5dv_init_obj() cannot: dvcq.{buf, dbrec}
 * are the calling process's userspace VAs (CRIU's, not the dumpee's),
 * and ibv_import_cq() does not exist in upstream rdma-core, so CRIU
 * cannot manufacture an ibv_cq* in its own address space against the
 * dumpee's underlying kernel CQ. The kernel handler reads its own
 * cq->buf.umem->address + cq->db.u.user_page->user_virt directly --
 * those are the dumpee's VAs, exactly what RESTORE_CQ's UHW expects.
 *
 * Outputs:
 *   RESP_BLOB         32-byte payload byte-equal to struct
 *                     mlx5_ib_restore_cq_req. CRIU memcpy's it into
 *                     protobuf at dump time and back into RESTORE_CQ's
 *                     UHW tail at restore time, no field-level
 *                     marshaling. The kernel handler zeroes the two
 *                     reserved u32s so the round-trip clears
 *                     RESTORE_CQ's "must be 0" guards.
 *   RESP_CQE          ibcq->cqe (entries-1 in verbs convention).
 *                     Goes into UVERBS_ATTR_RESTORE_CQ_CQE.
 *   RESP_COMP_VECTOR  mcq->mcq.vector (the source's comp_vector hint).
 *                     Stamped on by the create path post-symmetry-fix
 *                     -- earlier kernels returned 0 unconditionally
 *                     and broke restore-side EQ continuity, which is
 *                     the reason the create-path fix is part of the
 *                     same kernel patchset that landed this verb.
 *   RESP_FLAGS        cq->create_flags (IB_UVERBS_CQ_FLAGS_*).
 *
 * Method id slot is the next one in the VFMIG enum after
 * RESTORE_DYN_UARS (=+3), so this is +4. If the kernel inserts new
 * VFMIG methods between RESTORE_DYN_UARS and QUERY_CQ this header
 * needs a corresponding bump -- same upkeep policy as the existing
 * entries above.
 */
#define MLX5_IB_METHOD_VFMIG_QUERY_CQ_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 4)
#define MLX5_IB_ATTR_VFMIG_QUERY_CQ_HANDLE_LOCAL \
	(1u << UVERBS_ID_NS_SHIFT_LOCAL)
#define MLX5_IB_ATTR_VFMIG_QUERY_CQ_RESP_BLOB_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define MLX5_IB_ATTR_VFMIG_QUERY_CQ_RESP_CQE_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 2)
#define MLX5_IB_ATTR_VFMIG_QUERY_CQ_RESP_COMP_VECTOR_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 3)
#define MLX5_IB_ATTR_VFMIG_QUERY_CQ_RESP_FLAGS_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 4)

/*
 * Per-uobject QP dump-side discovery verb.
 *
 * MLX5_IB_METHOD_VFMIG_QUERY_QP runs on MLX5_IB_OBJECT_VFMIG and is
 * the dump-side companion of UVERBS_METHOD_RESTORE_QP, mirroring the
 * QUERY_CQ contract in shape (per-handle, byte-equal RESP_BLOB +
 * scalar outs that go straight into RESTORE_QP's core attrs).
 *
 * The HANDLE attr is UVERBS_ATTR_IDR(UVERBS_OBJECT_QP,
 * UVERBS_ACCESS_READ): caller's ufile-idr must own the QP, the IDR
 * pins the uobject for the call. Same security boundary as
 * INFO_HANDLES(UVERBS_OBJECT_QP).
 *
 * Outputs (all MANDATORY):
 *   RESP_BLOB         struct mlx5_ib_restore_qp_req (64 bytes); CRIU
 *                     copies verbatim into protobuf at dump time and
 *                     back into RESTORE_QP's UHW_IN at restore time,
 *                     no field-level marshaling. Kernel handler
 *                     zeroes reserved/reserved2 and emits sentinels
 *                     for uidx (0) / bfreg_index (MLX5_IB_INVALID_
 *                     BFREG) / ece_options (0) -- the QPC's
 *                     user_index / uar_page / ece_options round-trip
 *                     intact across LOAD_VHCA_STATE per K7 so the
 *                     restore handler validates-and-discards them.
 *   RESP_USER_HANDLE  u64, ibqp->uobject->user_handle. Goes into
 *                     UVERBS_ATTR_RESTORE_QP_USER_HANDLE.
 *   RESP_CREATE_FLAGS u32, mqp->flags. Goes into UVERBS_ATTR_RESTORE_
 *                     QP_CREATE_FLAGS.
 *
 * Trimmed set: RESP_TYPE / RESP_STATE / RESP_CAP were dropped. Those
 * are standard-queryable -- CRIU's HW-generic dump path sources
 * qp_type / state from NLDEV (RES_TYPE / RES_STATE) and the cap tuple
 * from the standard QUERY_QP verb (rdma_uverbs_query_qp), so a
 * driver-private verb re-exporting them was redundant. Only the two
 * fields with no standard/NLDEV surface remain alongside the opaque
 * blob. KEEP IN LOCKSTEP with the kernel enum in
 * include/uapi/rdma/mlx5_user_ioctl_cmds.h (enum
 * mlx5_ib_vfmig_query_qp_attrs); the attr ids below mirror its
 * post-trim renumbering.
 *
 * Method id slot is +5 in the VFMIG enum, after QUERY_CQ (=+4).
 */
#define MLX5_IB_METHOD_VFMIG_QUERY_QP_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 5)
#define MLX5_IB_ATTR_VFMIG_QUERY_QP_HANDLE_LOCAL \
	(1u << UVERBS_ID_NS_SHIFT_LOCAL)
#define MLX5_IB_ATTR_VFMIG_QUERY_QP_RESP_BLOB_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define MLX5_IB_ATTR_VFMIG_QUERY_QP_RESP_USER_HANDLE_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 2)
#define MLX5_IB_ATTR_VFMIG_QUERY_QP_RESP_CREATE_FLAGS_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 3)

/*
 * Per-uobject PD dump-side discovery verb.
 *
 * MLX5_IB_METHOD_VFMIG_QUERY_PD runs on MLX5_IB_OBJECT_VFMIG and is
 * the dump-side companion of UVERBS_METHOD_RESTORE_PD, in the same
 * family as QUERY_CQ / QUERY_QP: per-handle, byte-equal RESP_BLOB
 * that round-trips into RESTORE_PD's UHW with no field-level
 * marshaling.
 *
 * The HANDLE attr is UVERBS_ATTR_IDR(UVERBS_OBJECT_PD,
 * UVERBS_ACCESS_READ): caller's ufile-idr must own the PD, the IDR
 * pins the uobject for the call. Same security boundary as
 * INFO_HANDLES(UVERBS_OBJECT_PD).
 *
 * Outputs (all MANDATORY):
 *   RESP_BLOB  struct mlx5_ib_restore_pd_req (16 bytes); carries the
 *              FW pdn mlx5_ib_restore_pd adopts. CRIU copies it
 *              verbatim into the per-PD plugin_blob at dump time and
 *              back into RESTORE_PD's UHW_IN at restore time. The
 *              handler leaves req.reserved / req.reserved2 zero so
 *              the restore path's "must be 0" guards pass round-trip.
 *   RESP_UID   u32, the source PD's mpd->uid. Dump-side diagnostic
 *              only -- not consumed by RESTORE_PD (restore always
 *              adopts under the destination ucontext's uid).
 *
 * Method id slot is +6 in the VFMIG enum, after QUERY_QP (=+5).
 */
#define MLX5_IB_METHOD_VFMIG_QUERY_PD_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 6)
#define MLX5_IB_ATTR_VFMIG_QUERY_PD_HANDLE_LOCAL \
	(1u << UVERBS_ID_NS_SHIFT_LOCAL)
#define MLX5_IB_ATTR_VFMIG_QUERY_PD_RESP_BLOB_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define MLX5_IB_ATTR_VFMIG_QUERY_PD_RESP_UID_LOCAL \
	((1u << UVERBS_ID_NS_SHIFT_LOCAL) + 2)

/*
 * Driver-private UHW payload for UVERBS_METHOD_RESTORE_PD on mlx5,
 * carried from dump to restore as QUERY_PD's RESP_BLOB and
 * RESTORE_PD's UHW.data byte-for-byte.
 *
 * Layout MUST match include/uapi/rdma/mlx5-abi.h::mlx5_ib_restore_pd_req
 * exactly: 16 bytes, u32 pdn + u32 reserved + u64 reserved2.
 *
 * Wire-shape gotchas the criu plugin packer must respect:
 *
 *   - sizeof > sizeof(u64) is intentional. Kernel uverbs UHW dispatch
 *     treats len <= 8 as INLINE (stuffs attr->data into a kernel
 *     staging slot and rewrites udata->inbuf to a kernel pointer);
 *     on x86_64 with masked-user-access enabled that breaks
 *     ib_copy_from_udata's copy_from_user. The 8-byte reserved2
 *     pads us above the threshold so the kernel takes the ptr path.
 *     Same dodge as the CQ/MR/QP shims.
 *   - reserved/reserved2 must be zero on send; the kernel handler
 *     validates this for forward-compat (-EINVAL otherwise). QUERY_PD
 *     zeroes them on emit, so a verbatim memcpy round-trips.
 *   - pdn is 24 bits significant; QUERY_PD never emits 0 because a
 *     live PD always has a nonzero FW id.
 *
 * Drop once host rdma-core ships the struct upstream.
 */
struct mlx5_ib_restore_pd_req_local {
	uint32_t pdn;
	uint32_t reserved;
	uint64_t reserved2;
} __attribute__((aligned(8)));

/*
 * Driver-private UHW payload for UVERBS_METHOD_RESTORE_CQ on mlx5,
 * carried from dump to restore as QUERY_CQ's RESP_BLOB and the
 * RESTORE_CQ UHW.data byte-for-byte.
 *
 * Layout MUST match include/uapi/rdma/mlx5-abi.h::mlx5_ib_restore_cq_req
 * exactly: 32 bytes, __aligned_u64 on the leading two fields,
 * trailing two u32 reserveds. The kernel QUERY_CQ handler emits
 * reserved/reserved2 zero on its own; CRIU should not touch them.
 * RESTORE_CQ's "must be 0" guard rejects any non-zero reserved bit
 * on the inbound side, which is what makes a verbatim memcpy
 * round-trip work without field-level marshaling.
 *
 * @cqn is 24 bits significant (0 reserved as sentinel by the
 * RESTORE_CQ handler; QUERY_CQ never emits 0 because a live CQ
 * always has a nonzero FW id). @cqe_size is 64 or 128 (RESTORE_CQ
 * rejects anything else with -EINVAL). @buf_addr and @db_addr are
 * the source userspace VAs; @db_addr is page-aligned (the byte
 * offset within the page survives via FW cqc.dbr_addr).
 */
struct mlx5_ib_restore_cq_req_local {
	uint64_t buf_addr;
	uint64_t db_addr;
	uint32_t cqn;
	uint32_t cqe_size;
	uint32_t reserved;
	uint32_t reserved2;
} __attribute__((aligned(8)));

/*
 * Driver-private UHW payload for UVERBS_METHOD_RESTORE_MR on mlx5,
 * carrying the source's FW mkey_index so mlx5_ib_restore_mr can
 * adopt the destination-side mkey that LOAD_VHCA_STATE preserved
 * (Model A, no FW round-trip on adoption -- see Linux 85c651e7e4db).
 *
 * Layout MUST match include/uapi/rdma/mlx5-abi.h::mlx5_ib_restore_mr_req
 * exactly: 16 bytes, u32 mkey_index + u32 reserved + u64 reserved2.
 *
 * Wire-shape gotchas the criu plugin packer must respect:
 *
 *   - sizeof > sizeof(u64) is intentional. Kernel uverbs UHW dispatch
 *     treats len <= 8 as INLINE (stuffs attr->data into a kernel
 *     staging slot and rewrites udata->inbuf to a kernel pointer);
 *     on x86_64 with masked-user-access enabled that breaks
 *     ib_copy_from_udata's copy_from_user. The 8-byte reserved2
 *     pads us above the threshold so the kernel takes the ptr path
 *     and copy_from_user works. Same dodge as the PD/CQ shims.
 *   - reserved/reserved2 must be zero on send; the kernel handler
 *     validates this for forward-compat (-EINVAL otherwise).
 *   - mkey_index is 24 bits significant; the kernel rejects 0 and
 *     any value with bits set above 0xffffff. CRIU derives it from
 *     the source's lkey via the mlx5 invariant
 *     lkey == rkey == (mkey_index << 8) | variant_byte
 *     so mkey_index = lkey_hint >> 8.
 *
 * Drop once host rdma-core ships the struct upstream.
 */
struct mlx5_ib_restore_mr_req_local {
	uint32_t mkey_index;
	uint32_t reserved;
	uint64_t reserved2;
} __attribute__((aligned(8)));

/*
 * Driver-private UHW payload for UVERBS_METHOD_RESTORE_QP on mlx5,
 * carried from dump to restore as QUERY_QP's RESP_BLOB and
 * RESTORE_QP's UHW.data byte-for-byte.
 *
 * Layout MUST match include/uapi/rdma/mlx5-abi.h::mlx5_ib_restore_qp_req
 * exactly: 64 bytes, three __aligned_u64 leading addresses + nine
 * u32 fields. The dump-side handler emits sentinels for the FW-side
 * fields LOAD_VHCA_STATE preserves byte-equal (uidx = 0,
 * bfreg_index = MLX5_IB_INVALID_BFREG_LOCAL, ece_options = 0); the
 * RESTORE_QP handler validates-and-discards them on the restore
 * side. CRIU plugin code does not interpret these fields -- it
 * memcpy's the blob from RESP_BLOB at dump and back into UHW_IN at
 * restore.
 *
 * Wire-shape gotchas the criu plugin packer must respect:
 *
 *   - 64 bytes is well above the kernel uverbs UHW INLINE threshold
 *     (8). Same userspace-pointer-path dodge as the PD/CQ/MR shims.
 *   - reserved / reserved2 must be zero on send. RESTORE_QP's
 *     "must be 0" guard rejects any non-zero reserved bit on the
 *     inbound side; QUERY_QP zeroes them on emit, so a verbatim
 *     memcpy round-trips without per-field marshaling.
 *   - qpn is 24 bits significant; 0 is a sentinel rejected by
 *     RESTORE_QP. uidx is 24 bits significant. rq_wqe_shift in
 *     [4, 16] when rq_wqe_count > 0.
 *
 * MLX5_IB_INVALID_BFREG_LOCAL mirrors the kernel's
 * drivers/infiniband/hw/mlx5/mlx5_ib.h MLX5_IB_INVALID_BFREG
 * (= BIT(31) = 0x80000000U). The QUERY_QP handler emits this
 * constant for bfreg_index because the source's UAR mapping is
 * encoded in the adopted qpc.uar_page (preserved by
 * LOAD_VHCA_STATE), not re-derived from the BFREG slot. The
 * RESTORE_QP handler forces qp->bfregn = this same constant
 * regardless of what the UHW carried, so emitting the sentinel
 * here is purely informational: CRIU never constructs this value
 * itself (we memcpy the QUERY_QP RESP_BLOB straight into
 * RESTORE_QP UHW_IN), the constant lives here so a reader of the
 * UHW packing code can verify the sentinel without cross-tree
 * grepping.
 */
#define MLX5_IB_INVALID_BFREG_LOCAL ((uint32_t)0x80000000)

struct mlx5_ib_restore_qp_req_local {
	uint64_t buf_addr;	/* source userspace VA of WQ ring */
	uint64_t db_addr;	/* source userspace VA of DBR page */
	uint64_t sq_buf_addr;	/* raw_packet split-SQ; 0 for v0 RC/UD */
	uint32_t qpn;		/* FW qpn to adopt (24 bits) */
	uint32_t sq_wqe_count;
	uint32_t rq_wqe_count;
	uint32_t rq_wqe_shift;
	uint32_t flags;		/* MLX5_QP_FLAG_* bitmask */
	uint32_t uidx;		/* qpc.user_index sentinel; emit 0 */
	uint32_t bfreg_index;	/* emit MLX5_IB_INVALID_BFREG_LOCAL */
	uint32_t ece_options;	/* emit 0 */
	uint32_t reserved;	/* must be 0 */
	uint32_t reserved2;	/* must be 0 */
} __attribute__((aligned(8)));

/*
 * The QP capability tuple (struct ib_uverbs_qp_cap) is no longer
 * mirrored here: RESP_CAP was dropped from VFMIG QUERY_QP. CRIU's
 * HW-generic dump path sources the cap from the standard QUERY_QP
 * verb (criu/rdma/uverbsfd.c::rdma_uverbs_query_qp) and feeds it to
 * RESTORE_QP's UVERBS_ATTR_RESTORE_QP_CAP, so the plugin never
 * marshals cap.
 */

#endif /* __CR_MLX5_VFMIG_UAPI_H__ */
