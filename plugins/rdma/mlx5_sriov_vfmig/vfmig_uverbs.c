/*
 * vfmig_uverbs.c
 *
 * mlx5 ucontext uverbs-ioctl wrappers for the SR-IOV VFMIG plugin.
 *
 * Dump-side QUERY surface on the MLX5_IB_OBJECT_VFMIG object:
 *   vfmig_query_uctx / vfmig_snapshot_uctx       (static-UAR mode)
 *   vfmig_query_dyn_uars / vfmig_snapshot_dyn_uars (dyn-UAR mode)
 *
 * Restore-side surface:
 *   vfmig_send_get_context_v2  (legacy GET_CONTEXT alloc, VFMIG_RESTORE)
 *   vfmig_restore_uctx         (RESTORE_UCONTEXT, static-UAR replay)
 *
 * The snapshot helpers wrap the raw QUERY verbs in the two-pass
 * (size, then fetch) idiom the kernel UAPI uses for variable-length
 * arrays. All routines are pure marshaling -- no plugin state, no
 * /sys walks, no logging. Callers own the orchestration.
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
 * The QUERY/RESTORE handlers exchange these structs verbatim, so a
 * wire-layout drift between this build and the kernel would corrupt
 * the snapshot silently. Lock the sizes at compile time.
 */
_Static_assert(sizeof(struct mlx5_ib_vfmig_ucontext_meta_local) == 40,
	       "mlx5_ib_vfmig_ucontext_meta_local must be 40 bytes (kernel UAPI)");
_Static_assert(sizeof(struct mlx5_ib_vfmig_dyn_uar_record_local) == 24,
	       "mlx5_ib_vfmig_dyn_uar_record_local must be 24 bytes (kernel UAPI)");

/*
 * Issue MLX5_IB_METHOD_VFMIG_QUERY_UCONTEXT via RDMA_VERBS_IOCTL.
 * Two-pass aware: pass uar_table=NULL/uar_n=0 (and the same for
 * bfreg) to learn the array sizes from @meta only.
 *
 * Returns 0 on success, -errno on failure. -EOPNOTSUPP indicates a
 * dyn-mode (lib_uar_dyn=true) ucontext -- the caller should retry via
 * vfmig_query_dyn_uars() rather than treat it as a hard error.
 */
static int vfmig_query_uctx(int fd, uint32_t *uar_table, size_t uar_n, uint32_t *bfreg_count, size_t bfreg_n,
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
		cmd.attrs[n].attr_id = MLX5_IB_ATTR_VFMIG_QUERY_UCONTEXT_UAR_TABLE_LOCAL;
		cmd.attrs[n].len = (uint16_t)(uar_n * sizeof(*uar_table));
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)uar_table;
		n++;
	}
	if (bfreg_count) {
		cmd.attrs[n].attr_id = MLX5_IB_ATTR_VFMIG_QUERY_UCONTEXT_BFREG_COUNT_LOCAL;
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
 * Snapshot a static-UAR source ucontext via the two-pass QUERY idiom.
 * On success @meta_out is filled and @uar_out / @cnt_out point to
 * caller-owned arrays of size meta.num_sys_pages and
 * meta.total_num_bfregs respectively (free with free()).
 *
 * Returns 0 on success, -errno on failure (all out-pointers left
 * NULL). -EOPNOTSUPP propagates from vfmig_query_uctx() for a dyn-mode
 * ucontext so the caller can fall back to vfmig_snapshot_dyn_uars().
 */
int vfmig_snapshot_uctx(int fd, struct mlx5_ib_vfmig_ucontext_meta_local *meta_out, uint32_t **uar_out,
			size_t *uar_n_out, uint32_t **cnt_out, size_t *cnt_n_out)
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

	rc = vfmig_query_uctx(fd, uar, meta.num_sys_pages, cnt, meta.total_num_bfregs, &meta);
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
 * Two-pass aware: records=NULL/n_records=0 fills @count_out only.
 * The kernel rejects this verb with -EINVAL on a static-mode ucontext.
 *
 * Returns 0 on success, -errno on failure.
 */
static int vfmig_query_dyn_uars(int fd, struct mlx5_ib_vfmig_dyn_uar_record_local *records, size_t n_records,
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
		cmd.attrs[n].attr_id = MLX5_IB_ATTR_VFMIG_QUERY_DYN_UARS_RECORDS_LOCAL;
		cmd.attrs[n].len = (uint16_t)(n_records * sizeof(*records));
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)records;
		n++;
	}
	cmd.attrs[n].attr_id = MLX5_IB_ATTR_VFMIG_QUERY_DYN_UARS_COUNT_LOCAL;
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
 * Two-pass dyn-UAR snapshot for a source ucontext. On success
 * *@records_out / *@n_out point at a caller-owned array (free()).
 *
 * A dyn-UAR ucontext with no live UARs (sizing pass returns count==0)
 * is preserved as records=NULL, n=0 and reported as success: the
 * proto entry carries a zero-length uctx_dyn_uar_records and
 * RESTORE_DYN_UARS is effectively a no-op on the destination.
 *
 * Returns 0 on success, -errno on failure.
 */
int vfmig_snapshot_dyn_uars(int fd, struct mlx5_ib_vfmig_dyn_uar_record_local **records_out, size_t *n_out)
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
		 * A concurrent UAR alloc/destroy between the two passes.
		 * The workload is CRIU-suspended here, so this is a
		 * structural surprise rather than a benign race; surface
		 * it rather than snapshot a torn array.
		 */
		free(recs);
		return -EAGAIN;
	}

	*records_out = recs;
	*n_out = count;
	return 0;
}

/*
 * Allocate a fresh ucontext on @fd via the legacy write()-based
 * IB_USER_VERBS_CMD_GET_CONTEXT command, with the mlx5 driver payload
 * appended. @flags carries the MLX5_IB_ALLOC_UCTX_* bits (the restore
 * path sets MLX5_IB_ALLOC_UCTX_VFMIG_RESTORE so the kernel leaves the
 * UAR table empty and arms vfmig_restore_pending for the follow-up
 * RESTORE_UCONTEXT verb).
 *
 * The static path passes the source ucontext's resolved (lib_caps,
 * total_bfregs, ll_bfregs, max_cqe_version) verbatim so the
 * destination's alloc_ucontext computes a meta that bitwise-matches
 * the source; RESTORE_UCONTEXT enforces that equality on the
 * UAR-shape fields (devx_uid is excluded -- a mismatch there is
 * tolerated, log-and-continue).
 *
 * @adopt_devx_uid is always 0: the destination ucontext is opened
 * without DEVX and the source devx_uid is not adopted (diagnostic
 * only).
 *
 * Returns 0 on success, -errno on failure.
 */
int vfmig_send_get_context_v2(int fd, uint32_t flags, uint64_t lib_caps, uint32_t total_bfregs, uint32_t ll_bfregs,
			      uint8_t max_cqe_version, uint32_t adopt_devx_uid)
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
	cmd.req.adopt_devx_uid = adopt_devx_uid;

	n = write(fd, &cmd, sizeof(cmd));
	if (n < 0)
		return -errno;
	if ((size_t)n != sizeof(cmd))
		return -EIO;
	/*
	 * The legacy GET_CONTEXT path always installs a fresh
	 * async-event fd in our fdtable and returns its number via
	 * resp.async_fd. We don't use it -- criu reconstructs the
	 * workload's async-event fd separately -- and leaving it around
	 * occupies a low fd slot the later fd-install pass would collide
	 * with. Drop it as soon as the response is parsed.
	 */
	close((int)resp.resp.async_fd);
	return 0;
}

/*
 * Replay a static-UAR ucontext snapshot into a VFMIG_RESTORE ucontext
 * via MLX5_IB_METHOD_VFMIG_RESTORE_UCONTEXT. @uar_table / @bfreg_count
 * are the arrays captured by vfmig_snapshot_uctx(); @meta is the
 * matching meta struct. @bfreg_count may be NULL (attr omitted).
 *
 * The kernel enforces bitwise equality between @meta and the meta it
 * computed at GET_CONTEXT time, so a mismatch surfaces here as -EINVAL
 * rather than silently corrupting the restored context.
 *
 * Returns 0 on success, -errno on failure.
 */
int vfmig_restore_uctx(int fd, const uint32_t *uar_table, size_t uar_n, const uint32_t *bfreg_count, size_t bfreg_n,
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

	cmd.attrs[n].attr_id = MLX5_IB_ATTR_VFMIG_RESTORE_UCONTEXT_UAR_TABLE_LOCAL;
	cmd.attrs[n].len = (uint16_t)(uar_n * sizeof(*uar_table));
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)uar_table;
	n++;

	if (bfreg_count) {
		cmd.attrs[n].attr_id = MLX5_IB_ATTR_VFMIG_RESTORE_UCONTEXT_BFREG_COUNT_LOCAL;
		cmd.attrs[n].len = (uint16_t)(bfreg_n * sizeof(*bfreg_count));
		cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attrs[n].data = (uintptr_t)bfreg_count;
		n++;
	}

	cmd.attrs[n].attr_id = MLX5_IB_ATTR_VFMIG_RESTORE_UCONTEXT_META_LOCAL;
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
