/*
 * vfmig_uverbs.c
 *
 * mlx5 ucontext ioctl wrappers for the SR-IOV VFMIG plugin.
 *
 * Two kernel transports:
 *
 *   1. Legacy IB_USER_VERBS_CMD_GET_CONTEXT via write(uverbs_fd):
 *      vfmig_send_get_context_v2(). The new RDMA_VERBS_IOCTL
 *      UVERBS_METHOD_GET_CONTEXT path doesn't accept driver-private
 *      data, but we need MLX5_IB_ALLOC_UCTX_VFMIG_RESTORE to land
 *      in mlx5_ib_alloc_ucontext_req_v2.flags. The legacy write()
 *      path is the only way to get the flag through.
 *
 *   2. RDMA_VERBS_IOCTL on MLX5_IB_OBJECT_VFMIG:
 *      vfmig_query_uctx / vfmig_restore_uctx     (static UAR mode)
 *      vfmig_query_dyn_uars / vfmig_restore_dyn_uars (dyn-UAR mode)
 *      vfmig_snapshot_uctx / vfmig_snapshot_dyn_uars (two-pass
 *      QUERY+alloc orchestration over the above).
 *
 * All routines are pure marshaling -- no plugin state, no /sys
 * walks, no logging. Callers (the dump and restore paths) are
 * responsible for the orchestration around these calls.
 *
 * The two QUERY entries (vfmig_query_uctx, vfmig_query_dyn_uars)
 * are file-private to this translation unit; everything else is
 * declared in vfmig_internal.h.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <rdma/ib_user_verbs.h>
#include <rdma/ib_user_ioctl_verbs.h>
#include <rdma/rdma_user_ioctl_cmds.h>

#include "mlx5_uapi.h"
#include "vfmig_internal.h"

/*
 * Issue IB_USER_VERBS_CMD_GET_CONTEXT via the legacy write() path.
 *
 * The new RDMA_VERBS_IOCTL UVERBS_METHOD_GET_CONTEXT path doesn't
 * accept driver-specific data (no UHW attribute defined for it),
 * but the MLX5_IB_ALLOC_UCTX_VFMIG_RESTORE flag has to land in
 * mlx5_ib_alloc_ucontext_req_v2.flags. The legacy write() path is
 * the only way to get the flag to mlx5_ib's alloc_ucontext handler.
 *
 * The companion test in tools/testing/mlx5_vfmig/mlx5_vfmig_uctx.c
 * uses the same approach and is the reference for the wire layout.
 *
 * @flags carries MLX5_IB_ALLOC_UCTX_* bits.
 * @lib_caps carries MLX5_LIB_CAP_* bits (MLX5_LIB_CAP_4K_UAR is the
 *           v0 baseline; DYN_UAR is rejected by the kernel when
 *           combined with VFMIG_RESTORE).
 * @total_bfregs / @ll_bfregs / @max_cqe_version mirror the source
 *           ucontext's resolved meta so the destination's
 *           mlx5_ib_alloc_ucontext computes a meta that bitwise-
 *           matches the source's; RESTORE_UCONTEXT enforces this.
 *
 * Returns 0 on success, -errno on failure.
 */
int vfmig_send_get_context_v2(int fd, uint32_t flags,
				     uint64_t lib_caps,
				     uint32_t total_bfregs,
				     uint32_t ll_bfregs,
				     uint8_t max_cqe_version,
				     uint32_t adopt_devx_uid)
{
	struct {
		struct ib_uverbs_cmd_hdr hdr;
		struct ib_uverbs_get_context get_ctx;
		struct mlx5_ib_alloc_ucontext_req_v2_local req;
	} cmd = {};
	struct {
		struct ib_uverbs_get_context_resp resp;
		struct mlx5_ib_alloc_ucontext_resp_local drv;
	} resp = {};
	ssize_t n;

	cmd.hdr.command = IB_USER_VERBS_CMD_GET_CONTEXT;
	cmd.hdr.in_words = sizeof(cmd) / 4;
	cmd.hdr.out_words = sizeof(resp) / 4;
	cmd.get_ctx.response = (uintptr_t)&resp;
	cmd.req.total_num_bfregs = total_bfregs;
	cmd.req.num_low_latency_bfregs = ll_bfregs;
	cmd.req.flags = flags;
	cmd.req.max_cqe_version = max_cqe_version;
	cmd.req.lib_caps = lib_caps;
	/*
	 * Caller policy: if ADOPT_DEVX_UID is set in @flags, pass the
	 * source ucontext's devx_uid here (validated by the kernel
	 * to be in [1, U16_MAX] and to be paired with VFMIG_RESTORE +
	 * DEVX in @flags). Otherwise pass 0 -- the kernel rejects
	 * non-zero adopt_devx_uid without the flag set, to catch
	 * residual / stack-leak bugs.
	 */
	cmd.req.adopt_devx_uid = adopt_devx_uid;

	n = write(fd, &cmd, sizeof(cmd));
	if (n < 0)
		return -errno;
	if ((size_t)n != sizeof(cmd))
		return -EIO;
	/*
	 * The legacy IB_USER_VERBS_CMD_GET_CONTEXT path always installs
	 * a fresh async-event fd in our fdtable and returns its number
	 * via resp.async_fd. We don't use it -- criu reconstructs the
	 * workload's async-event fd separately via UverbsAsyncEvFile +
	 * UVERBS_METHOD_ASYNC_EVENT_ALLOC ioctl on the destination
	 * cdev (criu/rdma.c uverbsasyncevfd_open). Letting our
	 * vestigial async fd linger occupies a low fd slot the
	 * UverbsAsyncEvFile install will then collide with: the
	 * follow-up ioctl-allocated fd lands at the next free slot,
	 * which trips util.c reopen_fd_as ("fd N already in use") when
	 * criu wants the workload's async fd at our occupied slot.
	 * Drop it as soon as we've parsed the response.
	 */
	close((int)resp.resp.async_fd);
	return 0;
}

/*
 * Issue MLX5_IB_METHOD_VFMIG_QUERY_UCONTEXT via RDMA_VERBS_IOCTL.
 * Two-pass aware: pass uar_table=NULL/uar_n=0 and the same for
 * bfreg to learn array sizes from @meta only.
 *
 * Returns 0 on success, -errno on failure.
 */
static int vfmig_query_uctx(int fd,
			    uint32_t *uar_table, size_t uar_n,
			    uint32_t *bfreg_count, size_t bfreg_n,
			    struct mlx5_ib_vfmig_ucontext_meta_local *meta)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[3];
	} cmd = {};
	unsigned int n = 0;

	cmd.hdr.object_id = MLX5_IB_OBJECT_VFMIG_LOCAL;
	cmd.hdr.method_id = MLX5_IB_METHOD_VFMIG_QUERY_UCONTEXT_LOCAL;
	cmd.hdr.driver_id = RDMA_DRIVER_MLX5;

	if (uar_table) {
		cmd.attrs[n].attr_id =
			MLX5_IB_ATTR_VFMIG_QUERY_UCONTEXT_UAR_TABLE_LOCAL;
		cmd.attrs[n].len = (uint16_t)(uar_n * sizeof(*uar_table));
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)uar_table;
		n++;
	}
	if (bfreg_count) {
		cmd.attrs[n].attr_id =
			MLX5_IB_ATTR_VFMIG_QUERY_UCONTEXT_BFREG_COUNT_LOCAL;
		cmd.attrs[n].len = (uint16_t)(bfreg_n * sizeof(*bfreg_count));
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)bfreg_count;
		n++;
	}
	cmd.attrs[n].attr_id = MLX5_IB_ATTR_VFMIG_QUERY_UCONTEXT_META_LOCAL;
	cmd.attrs[n].len = sizeof(*meta);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)meta;
	n++;

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	if (ioctl(fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}

/*
 * Issue MLX5_IB_METHOD_VFMIG_RESTORE_UCONTEXT via RDMA_VERBS_IOCTL.
 *
 * Preconditions enforced by the kernel handler (see kernel UAPI doc):
 *   1. ucontext was created with MLX5_IB_ALLOC_UCTX_VFMIG_RESTORE
 *   2. lib_uar_dyn=false
 *   3. @meta bitwise-matches the destination's resolved meta
 *   4. uar_table length == meta.num_sys_pages * 4
 *   5. uar_table[0..num_static_sys_pages) all valid
 *   6. bfreg_count, if supplied, all-zero (v0)
 *
 * Returns 0 on success, -errno on failure.
 */
int vfmig_restore_uctx(int fd,
			      const uint32_t *uar_table, size_t uar_n,
			      const uint32_t *bfreg_count, size_t bfreg_n,
			      const struct mlx5_ib_vfmig_ucontext_meta_local *meta)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[3];
	} cmd = {};
	unsigned int n = 0;

	cmd.hdr.object_id = MLX5_IB_OBJECT_VFMIG_LOCAL;
	cmd.hdr.method_id = MLX5_IB_METHOD_VFMIG_RESTORE_UCONTEXT_LOCAL;
	cmd.hdr.driver_id = RDMA_DRIVER_MLX5;

	cmd.attrs[n].attr_id =
		MLX5_IB_ATTR_VFMIG_RESTORE_UCONTEXT_UAR_TABLE_LOCAL;
	cmd.attrs[n].len = (uint16_t)(uar_n * sizeof(*uar_table));
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)uar_table;
	n++;

	if (bfreg_count) {
		cmd.attrs[n].attr_id =
			MLX5_IB_ATTR_VFMIG_RESTORE_UCONTEXT_BFREG_COUNT_LOCAL;
		cmd.attrs[n].len = (uint16_t)(bfreg_n * sizeof(*bfreg_count));
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)bfreg_count;
		n++;
	}

	cmd.attrs[n].attr_id =
		MLX5_IB_ATTR_VFMIG_RESTORE_UCONTEXT_META_LOCAL;
	cmd.attrs[n].len = sizeof(*meta);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)meta;
	n++;

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	if (ioctl(fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}

/*
 * Snapshot a fully-populated source ucontext via the two-pass QUERY
 * idiom. On success, @meta_out is filled and @uar_out / @cnt_out
 * point to caller-owned arrays of size meta.num_sys_pages and
 * meta.total_num_bfregs respectively (free with free()).
 *
 * Returns 0 on success, -errno on failure (with all out-pointers
 * left NULL).
 */
/*
 * Meta-only QUERY_UCONTEXT wrapper. The caller wants
 * @meta_out->devx_uid (kernel commit c659ab66483d) without paying
 * for the second-pass uar_table / bfreg_count fetch + alloc. Used
 * by the per-QP dump hook's "refuse if source ucontext has DEVX"
 * gate; the full vfmig_snapshot_uctx is overkill there because the
 * per-context dump path has already snapshotted those arrays for
 * the image.
 *
 * Returns 0 on success, -errno on failure. -EOPNOTSUPP indicates
 * a dyn-mode (lib_uar_dyn=true) ucontext; the caller should treat
 * that as "DEVX-on by construction" rather than retry with
 * QUERY_DYN_UARS, because that verb returns the dyn-UAR records,
 * not meta.
 */
int vfmig_query_uctx_meta(int fd,
			  struct mlx5_ib_vfmig_ucontext_meta_local *meta_out)
{
	return vfmig_query_uctx(fd, NULL, 0, NULL, 0, meta_out);
}

int vfmig_snapshot_uctx(int fd,
			       struct mlx5_ib_vfmig_ucontext_meta_local *meta_out,
			       uint32_t **uar_out, size_t *uar_n_out,
			       uint32_t **cnt_out, size_t *cnt_n_out)
{
	struct mlx5_ib_vfmig_ucontext_meta_local meta = {};
	uint32_t *uar = NULL, *cnt = NULL;
	int rc;

	*uar_out = NULL;
	*cnt_out = NULL;
	*uar_n_out = 0;
	*cnt_n_out = 0;

	rc = vfmig_query_uctx(fd, NULL, 0, NULL, 0, &meta);
	if (rc)
		return rc;

	if (meta.num_sys_pages == 0 || meta.total_num_bfregs == 0)
		return -EINVAL;

	uar = calloc(meta.num_sys_pages, sizeof(*uar));
	cnt = calloc(meta.total_num_bfregs, sizeof(*cnt));
	if (!uar || !cnt) {
		free(uar);
		free(cnt);
		return -ENOMEM;
	}

	rc = vfmig_query_uctx(fd, uar, meta.num_sys_pages,
			      cnt, meta.total_num_bfregs, &meta);
	if (rc) {
		free(uar);
		free(cnt);
		return rc;
	}

	*meta_out = meta;
	*uar_out = uar;
	*uar_n_out = meta.num_sys_pages;
	*cnt_out = cnt;
	*cnt_n_out = meta.total_num_bfregs;
	return 0;
}

/*
 * Issue MLX5_IB_METHOD_VFMIG_QUERY_DYN_UARS via RDMA_VERBS_IOCTL.
 *
 * Two-pass aware:
 *   - Pass 1 (sizing): records=NULL, n_records=0; @count_out is filled.
 *   - Pass 2 (snapshot): records points at a caller-allocated buffer
 *     of @n_records elements; @count_out is filled with the number of
 *     records the kernel emitted (kernel cross-checks against
 *     @n_records and rejects with -EINVAL on mismatch, so a concurrent
 *     UAR_OBJ_ALLOC between passes surfaces here rather than silently
 *     truncating).
 *
 * The kernel rejects this verb with -EINVAL on a static-mode ucontext
 * (use vfmig_query_uctx instead). The caller distinguishes by trying
 * QUERY_UCONTEXT first.
 *
 * Returns 0 on success, -errno on failure.
 */
static int vfmig_query_dyn_uars(int fd,
				struct mlx5_ib_vfmig_dyn_uar_record_local *records,
				size_t n_records,
				uint32_t *count_out)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[2];
	} cmd = {};
	unsigned int n = 0;

	cmd.hdr.object_id = MLX5_IB_OBJECT_VFMIG_LOCAL;
	cmd.hdr.method_id = MLX5_IB_METHOD_VFMIG_QUERY_DYN_UARS_LOCAL;
	cmd.hdr.driver_id = RDMA_DRIVER_MLX5;

	if (records) {
		cmd.attrs[n].attr_id =
			MLX5_IB_ATTR_VFMIG_QUERY_DYN_UARS_RECORDS_LOCAL;
		cmd.attrs[n].len = (uint16_t)(n_records * sizeof(*records));
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)records;
		n++;
	}
	cmd.attrs[n].attr_id =
		MLX5_IB_ATTR_VFMIG_QUERY_DYN_UARS_COUNT_LOCAL;
	cmd.attrs[n].len = sizeof(*count_out);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)count_out;
	n++;

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	if (ioctl(fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}

/*
 * Issue MLX5_IB_METHOD_VFMIG_RESTORE_DYN_UARS via RDMA_VERBS_IOCTL.
 *
 * Preconditions enforced by the kernel handler:
 *   1. ucontext was created with MLX5_IB_ALLOC_UCTX_VFMIG_RESTORE
 *   2. lib_uar_dyn=true (i.e. opened with MLX5_LIB_CAP_DYN_UAR; the
 *      dyn-UAR alloc path bypasses sys_pages[] init and waits for
 *      this verb to seed the MLX5_IB_OBJECT_UAR uobjects).
 *   3. RECORDS length is a multiple of sizeof(record).
 *
 * Returns 0 on success, -errno on failure.
 */
int vfmig_restore_dyn_uars(int fd,
				  const struct mlx5_ib_vfmig_dyn_uar_record_local *records,
				  size_t n_records)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[1];
	} cmd = {};

	cmd.hdr.object_id = MLX5_IB_OBJECT_VFMIG_LOCAL;
	cmd.hdr.method_id = MLX5_IB_METHOD_VFMIG_RESTORE_DYN_UARS_LOCAL;
	cmd.hdr.driver_id = RDMA_DRIVER_MLX5;

	cmd.attrs[0].attr_id =
		MLX5_IB_ATTR_VFMIG_RESTORE_DYN_UARS_RECORDS_LOCAL;
	cmd.attrs[0].len = (uint16_t)(n_records * sizeof(*records));
	cmd.attrs[0].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[0].data = (uintptr_t)records;

	cmd.hdr.num_attrs = 1;
	cmd.hdr.length = sizeof(cmd.hdr) + sizeof(cmd.attrs[0]);

	if (ioctl(fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}

/*
 * Two-pass dyn-UAR snapshot for a source ucontext. On success,
 * *@records_out / *@n_out point at a caller-owned array (free()).
 *
 * A successful sizing pass that returns count==0 (a dyn-UAR ucontext
 * with no live UARs) is preserved as records=NULL, n=0 and reported
 * as success. The dump-side hook treats that as a valid snapshot --
 * the proto entry will carry a zero-length uctx_dyn_uar_records, and
 * RESTORE_DYN_UARS will be a no-op-effective call on the destination
 * (the kernel handler iterates 0 records and clears
 * vfmig_restore_pending).
 *
 * Returns 0 on success, -errno on failure.
 */
int vfmig_snapshot_dyn_uars(int fd,
				   struct mlx5_ib_vfmig_dyn_uar_record_local **records_out,
				   size_t *n_out)
{
	struct mlx5_ib_vfmig_dyn_uar_record_local *recs = NULL;
	uint32_t count = 0, count2 = 0;
	int rc;

	*records_out = NULL;
	*n_out = 0;

	rc = vfmig_query_dyn_uars(fd, NULL, 0, &count);
	if (rc)
		return rc;

	if (count == 0)
		return 0;

	recs = calloc(count, sizeof(*recs));
	if (!recs)
		return -ENOMEM;

	rc = vfmig_query_dyn_uars(fd, recs, count, &count2);
	if (rc) {
		free(recs);
		return rc;
	}
	if (count2 != count) {
		/*
		 * Concurrent UAR_OBJ_ALLOC/destroy between passes. The
		 * workload is CRIU-suspended at this point, so this is
		 * a structural surprise rather than a benign race; surface
		 * it.
		 */
		free(recs);
		return -EAGAIN;
	}

	*records_out = recs;
	*n_out = count;
	return 0;
}

/*
 * Issue MLX5_IB_METHOD_VFMIG_QUERY_CQ via RDMA_VERBS_IOCTL.
 *
 * Per-uobject (not per-ucontext): the HANDLE is an UVERBS_OBJECT_CQ
 * IDR reference resolved through the calling fd's ufile-idr. The
 * caller's ufile must own the CQ; the kernel pins it
 * UVERBS_ACCESS_READ for the duration of the call. CRIU dumps with
 * the dumpee's uverbsfd, so this is the same security boundary as
 * INFO_HANDLES(UVERBS_OBJECT_CQ).
 *
 * The five outputs together carry everything UVERBS_METHOD_RESTORE_CQ
 * consumes for an mlx5 user CQ:
 *
 *   @blob_out         32B byte-equal to mlx5_ib_restore_cq_req. CRIU
 *                     stores this verbatim in protobuf at dump time
 *                     and feeds it back into RESTORE_CQ's UHW.data
 *                     at restore time -- no field-level marshaling.
 *                     The kernel handler emits reserved/reserved2 = 0
 *                     and the UAPI doc warns CRIU not to touch them.
 *   @cqe_out          ibcq->cqe. Goes into UVERBS_ATTR_RESTORE_CQ_CQE.
 *   @comp_vector_out  mcq->mcq.vector. The post-symmetry-fix kernel
 *                     stamps this onto the create path; older kernels
 *                     emit 0 unconditionally and break restore-side
 *                     EQ continuity (the kernel's create-path fix is
 *                     part of the same patchset as this verb).
 *   @flags_out        cq->create_flags (IB_UVERBS_CQ_FLAGS_*).
 *
 * Kernel-mode CQs reject with -ENXIO (mcq->buf.umem == NULL or
 * the doorbell is a kernel-mode db slot). CRIU shouldn't see
 * those in INFO_HANDLES(CQ) anyway -- kernel CQs aren't in any
 * user ufile's idr -- but the rejection is defense-in-depth.
 *
 * Returns 0 on success, -errno on failure.
 */
int vfmig_query_cq(int fd,
		   uint32_t cq_handle,
		   struct mlx5_ib_restore_cq_req_local *blob_out,
		   uint32_t *cqe_out,
		   uint32_t *comp_vector_out,
		   uint32_t *flags_out)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[5];
	} cmd = {};

	/*
	 * Lock in the byte-equal contract at the source-of-marshaling
	 * site so any drift between this header and the kernel's
	 * mlx5_ib_restore_cq_req surfaces at compile time, not as a
	 * silent UHW corruption at restore.
	 */
	_Static_assert(sizeof(*blob_out) == 32,
		"mlx5_ib_restore_cq_req_local must be 32 bytes (kernel UAPI)");

	cmd.hdr.object_id = MLX5_IB_OBJECT_VFMIG_LOCAL;
	cmd.hdr.method_id = MLX5_IB_METHOD_VFMIG_QUERY_CQ_LOCAL;
	cmd.hdr.driver_id = RDMA_DRIVER_MLX5;

	/*
	 * HANDLE is an UVERBS_ATTR_IDR(UVERBS_OBJECT_CQ) attribute on
	 * the kernel side: uverbs_ioctl.c::uverbs_process_attr enforces
	 * len == 0 for the IDR class and reads the uobject handle
	 * directly from attrs[].data. Setting len = sizeof(u32) the way
	 * a PTR_IN(u32) attr does trips the dispatcher's `if (uattr->len
	 * != 0) return -EINVAL` guard before our handler runs. The
	 * matching probe is tools/testing/mlx5_vfmig/.../cq_query_probe.
	 */
	cmd.attrs[0].attr_id = MLX5_IB_ATTR_VFMIG_QUERY_CQ_HANDLE_LOCAL;
	cmd.attrs[0].len = 0;
	cmd.attrs[0].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[0].data = cq_handle;

	cmd.attrs[1].attr_id = MLX5_IB_ATTR_VFMIG_QUERY_CQ_RESP_BLOB_LOCAL;
	cmd.attrs[1].len = sizeof(*blob_out);
	cmd.attrs[1].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[1].data = (uintptr_t)blob_out;

	cmd.attrs[2].attr_id = MLX5_IB_ATTR_VFMIG_QUERY_CQ_RESP_CQE_LOCAL;
	cmd.attrs[2].len = sizeof(*cqe_out);
	cmd.attrs[2].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[2].data = (uintptr_t)cqe_out;

	cmd.attrs[3].attr_id =
		MLX5_IB_ATTR_VFMIG_QUERY_CQ_RESP_COMP_VECTOR_LOCAL;
	cmd.attrs[3].len = sizeof(*comp_vector_out);
	cmd.attrs[3].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[3].data = (uintptr_t)comp_vector_out;

	cmd.attrs[4].attr_id = MLX5_IB_ATTR_VFMIG_QUERY_CQ_RESP_FLAGS_LOCAL;
	cmd.attrs[4].len = sizeof(*flags_out);
	cmd.attrs[4].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[4].data = (uintptr_t)flags_out;

	cmd.hdr.num_attrs = 5;
	cmd.hdr.length = sizeof(cmd.hdr) + 5 * sizeof(cmd.attrs[0]);

	if (ioctl(fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}

/*
 * Issue MLX5_IB_METHOD_VFMIG_QUERY_QP on @fd against @qp_handle.
 * Mirror of vfmig_query_cq for QP: the byte-equal RESP_BLOB lands in
 * @blob_out (64 bytes; CRIU memcpy's it into protobuf, then back
 * into RESTORE_QP's UHW_IN), and the two residual scalar outs
 * (@user_handle_out, @create_flags_out) land in their pointers.
 *
 * Trimmed set: RESP_TYPE / RESP_STATE / RESP_CAP were dropped from
 * this verb (see mlx5_uapi.h). The dump path sources qp_type / state
 * from NLDEV and the cap tuple from the standard QUERY_QP verb, so
 * this private verb only carries what the standard surfaces cannot
 * express: the FW blob, the uobject user_handle, and create_flags.
 *
 * HANDLE is UVERBS_ATTR_IDR(UVERBS_OBJECT_QP); kernel-side
 * uverbs_process_attr enforces len == 0 for the IDR class and reads
 * the uobject handle from attrs[].data. Setting len = sizeof(u32)
 * the way a PTR_IN(u32) attr does trips the dispatcher's
 * `if (uattr->len != 0) return -EINVAL` guard before the handler
 * runs. Same shim as vfmig_query_cq above.
 */
int vfmig_query_qp(int fd,
		   uint32_t qp_handle,
		   struct mlx5_ib_restore_qp_req_local *blob_out,
		   uint64_t *user_handle_out,
		   uint32_t *create_flags_out)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[4];
	} cmd = {};

	/*
	 * Lock in the byte-equal contract at the source-of-marshaling
	 * site so any drift between this header and the kernel's
	 * mlx5_ib_restore_qp_req surfaces at compile time, not as a
	 * silent UHW corruption at restore.
	 */
	_Static_assert(sizeof(*blob_out) == 64,
		"mlx5_ib_restore_qp_req_local must be 64 bytes (kernel UAPI)");

	cmd.hdr.object_id = MLX5_IB_OBJECT_VFMIG_LOCAL;
	cmd.hdr.method_id = MLX5_IB_METHOD_VFMIG_QUERY_QP_LOCAL;
	cmd.hdr.driver_id = RDMA_DRIVER_MLX5;

	cmd.attrs[0].attr_id = MLX5_IB_ATTR_VFMIG_QUERY_QP_HANDLE_LOCAL;
	cmd.attrs[0].len = 0;
	cmd.attrs[0].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[0].data = qp_handle;

	cmd.attrs[1].attr_id = MLX5_IB_ATTR_VFMIG_QUERY_QP_RESP_BLOB_LOCAL;
	cmd.attrs[1].len = sizeof(*blob_out);
	cmd.attrs[1].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[1].data = (uintptr_t)blob_out;

	cmd.attrs[2].attr_id =
		MLX5_IB_ATTR_VFMIG_QUERY_QP_RESP_USER_HANDLE_LOCAL;
	cmd.attrs[2].len = sizeof(*user_handle_out);
	cmd.attrs[2].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[2].data = (uintptr_t)user_handle_out;

	cmd.attrs[3].attr_id =
		MLX5_IB_ATTR_VFMIG_QUERY_QP_RESP_CREATE_FLAGS_LOCAL;
	cmd.attrs[3].len = sizeof(*create_flags_out);
	cmd.attrs[3].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[3].data = (uintptr_t)create_flags_out;

	cmd.hdr.num_attrs = 4;
	cmd.hdr.length = sizeof(cmd.hdr) + 4 * sizeof(cmd.attrs[0]);

	if (ioctl(fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}

/*
 * Issue MLX5_IB_METHOD_VFMIG_QUERY_PD on @fd against @pd_handle.
 * Mirror of vfmig_query_cq / vfmig_query_qp for PD: the byte-equal
 * RESP_BLOB (struct mlx5_ib_restore_pd_req, 16 bytes; carries the FW
 * pdn) lands in @blob_out -- CRIU memcpy's it into the per-PD
 * plugin_blob, then back into RESTORE_PD's UHW_IN. @uid_out receives
 * the source PD's mpd->uid (dump-side diagnostic only, not a restore
 * input).
 *
 * HANDLE is UVERBS_ATTR_IDR(UVERBS_OBJECT_PD); kernel-side
 * uverbs_process_attr enforces len == 0 for the IDR class and reads
 * the uobject handle from attrs[].data. Setting len = sizeof(u32)
 * the way a PTR_IN(u32) attr does trips the dispatcher's
 * `if (uattr->len != 0) return -EINVAL` guard before the handler
 * runs. Same shim as vfmig_query_cq / vfmig_query_qp above.
 */
int vfmig_query_pd(int fd,
		   uint32_t pd_handle,
		   struct mlx5_ib_restore_pd_req_local *blob_out,
		   uint32_t *uid_out)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[3];
	} cmd = {};

	/*
	 * Lock in the byte-equal contract at the source-of-marshaling
	 * site so any drift between this header and the kernel's
	 * mlx5_ib_restore_pd_req surfaces at compile time, not as a
	 * silent UHW corruption at restore.
	 */
	_Static_assert(sizeof(*blob_out) == 16,
		"mlx5_ib_restore_pd_req_local must be 16 bytes (kernel UAPI)");

	cmd.hdr.object_id = MLX5_IB_OBJECT_VFMIG_LOCAL;
	cmd.hdr.method_id = MLX5_IB_METHOD_VFMIG_QUERY_PD_LOCAL;
	cmd.hdr.driver_id = RDMA_DRIVER_MLX5;

	cmd.attrs[0].attr_id = MLX5_IB_ATTR_VFMIG_QUERY_PD_HANDLE_LOCAL;
	cmd.attrs[0].len = 0;
	cmd.attrs[0].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[0].data = pd_handle;

	cmd.attrs[1].attr_id = MLX5_IB_ATTR_VFMIG_QUERY_PD_RESP_BLOB_LOCAL;
	cmd.attrs[1].len = sizeof(*blob_out);
	cmd.attrs[1].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[1].data = (uintptr_t)blob_out;

	cmd.attrs[2].attr_id = MLX5_IB_ATTR_VFMIG_QUERY_PD_RESP_UID_LOCAL;
	cmd.attrs[2].len = sizeof(*uid_out);
	cmd.attrs[2].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[2].data = (uintptr_t)uid_out;

	cmd.hdr.num_attrs = 3;
	cmd.hdr.length = sizeof(cmd.hdr) + 3 * sizeof(cmd.attrs[0]);

	if (ioctl(fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}
