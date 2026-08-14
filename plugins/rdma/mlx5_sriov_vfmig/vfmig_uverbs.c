/*
 * vfmig_uverbs.c
 *
 * mlx5 ucontext uverbs-ioctl wrappers for the SR-IOV VFMIG plugin.
 *
 * Dump-side QUERY surface on the MLX5_IB_OBJECT_VFMIG object:
 *   vfmig_query_uctx / vfmig_snapshot_uctx       (static-UAR mode)
 *
 * The snapshot helper wraps the raw QUERY verb in the two-pass
 * (size, then fetch) idiom the kernel UAPI uses for variable-length
 * arrays. All routines are pure marshaling -- no plugin state, no
 * /sys walks, no logging. Callers own the orchestration. The dyn-UAR
 * QUERY_DYN_UARS surface is added in a later commit.
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
 * The QUERY/RESTORE handlers exchange this struct verbatim, so a
 * wire-layout drift between this build and the kernel would corrupt
 * the snapshot silently. Lock the size at compile time.
 */
_Static_assert(sizeof(struct mlx5_ib_vfmig_ucontext_meta_local) == 40,
	       "mlx5_ib_vfmig_ucontext_meta_local must be 40 bytes (kernel UAPI)");

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
