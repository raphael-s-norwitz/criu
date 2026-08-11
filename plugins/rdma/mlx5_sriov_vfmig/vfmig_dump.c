/*
 * mlx5_sriov_vfmig dump-side state.
 *
 * This commit introduces only the claimed-VF cache. The claim hook
 * (CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT) already resolves every
 * snapshot-tree uverbs context's (ibdev, pf_bdf, vf_id) and confirms
 * QUERY_VF.tracked=1 before it returns RCD_MLX5_SRIOV_VFMIG. Recording
 * each VF we win the claim for lets the dump-side hooks added in later
 * commits -- CHECKPOINT_DEVICES (suspend) and the fini(DUMP) SAVE drain
 * -- act on exactly that set without re-walking /proc/<pid>/fd or
 * re-querying sysfs.
 *
 * The set is deduplicated by (pf_bdf, vf_id): a single VF can back
 * several uverbs contexts (e.g. one per worker thread, or across
 * several pids in the snapshot tree), and the firmware SAVE_VHCA_STATE
 * is per-VF, not per-context. Reset at init()/fini() via
 * vfmig_claimed_clear().
 */

#include "criu-log.h"

#include <linux/mlx5_vfmig.h>

#include "vfmig_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_mlx5_vfmig_plugin: "

struct vfmig_claimed_vf {
	struct vfmig_claimed_vf *next;
	char ibdev[64];
	char pf_bdf[64];
	uint32_t vf_id;
};

static struct vfmig_claimed_vf *vfmig_claimed_head;

void vfmig_claimed_add(const char *ibdev, const char *pf_bdf, uint32_t vf_id)
{
	struct vfmig_claimed_vf *p;

	for (p = vfmig_claimed_head; p; p = p->next)
		if (p->vf_id == vf_id && !strcmp(p->pf_bdf, pf_bdf))
			return; /* already recorded -- one VF, many contexts */

	p = malloc(sizeof(*p));
	if (!p) {
		pr_err("claimed-VF cache: out of memory recording %s (pf=%s vf_id=%u)\n", ibdev, pf_bdf, vf_id);
		return;
	}

	snprintf(p->ibdev, sizeof(p->ibdev), "%s", ibdev);
	snprintf(p->pf_bdf, sizeof(p->pf_bdf), "%s", pf_bdf);
	p->vf_id = vf_id;
	p->next = vfmig_claimed_head;
	vfmig_claimed_head = p;

	pr_debug("claimed-VF cache: recorded %s (pf=%s vf_id=%u)\n", ibdev, pf_bdf, vf_id);
}

void vfmig_claimed_clear(void)
{
	struct vfmig_claimed_vf *p, *n;

	for (p = vfmig_claimed_head; p; p = n) {
		n = p->next;
		free(p);
	}
	vfmig_claimed_head = NULL;
}

/*
 * Per-VF capture result, produced by vfmig_capture_one_vf() and consumed
 * by vfmig_drain_claimed_in_fini() to build one image record.
 */
struct vfmig_saved_vf {
	uint32_t vhca_id;
	uint8_t vf_uuid[16];
	char blob_path[128];
	uint64_t blob_size;
};

/*
 * Capture the firmware blob for one (pf_bdf, vf_id) pair. Steps mirror
 * the source-side lifecycle in the kernel UAPI doc for
 * MLX5_VFMIG_IOC_SAVE_VHCA_STATE:
 *   1. open /dev/mlx5_vfmig/<pf_bdf>
 *   2. GET_VHCA_ID  (record vhca_id for diagnostics)
 *   3. QUERY_VF     (read the orchestrator-stamped vf_uuid; hard-refuse
 *      if all-zeros, BEFORE the expensive SAVE, since vf_uuid is the
 *      sole stable restore-side match key)
 *   4. SAVE_VHCA_STATE { vf_id, flags = 0 } -> read-only save_fd
 *   5. drain save_fd into a per-VF blob under the image dir
 *
 * flags=0 means the kernel self-suspends the VF for the duration of the
 * save and resumes it when save_fd is closed, so the source is left
 * runnable. Pre-suspending at CHECKPOINT_DEVICES (with KEEP_SUSPENDED
 * here) is a separate snapshot-ordering step that matters once pinned
 * MR pages are copied into the image; it is not needed for the
 * VF-firmware-state capture on its own.
 */
static int vfmig_capture_one_vf(const char *pf_bdf, uint32_t vf_id, struct vfmig_saved_vf *out)
{
	struct mlx5_vfmig_get_vhca_id gv;
	struct mlx5_vfmig_query_vf qv;
	struct mlx5_vfmig_save_state ss;
	uint8_t zero_uuid[16] = { 0 };
	char cdev_path[PATH_MAX];
	int cdev_fd;

	snprintf(cdev_path, sizeof(cdev_path), "%s/%s", MLX5_VFMIG_DEV_DIR, pf_bdf);
	cdev_fd = open(cdev_path, O_RDWR | O_CLOEXEC);
	if (cdev_fd < 0) {
		pr_perror("vfmig: open(%s)", cdev_path);
		return -1;
	}

	memset(&gv, 0, sizeof(gv));
	gv.vf_id = vf_id;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_GET_VHCA_ID, &gv)) {
		pr_perror("vfmig: GET_VHCA_ID(pf=%s vf_id=%u)", pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}
	out->vhca_id = gv.vhca_id;

	memset(&qv, 0, sizeof(qv));
	qv.vf_id = vf_id;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_QUERY_VF, &qv)) {
		pr_perror("vfmig: QUERY_VF(pf=%s vf_id=%u)", pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}
	if (!memcmp(qv.vf_uuid, zero_uuid, sizeof(zero_uuid))) {
		pr_err("vfmig: refusing to dump pf=%s vf_id=%u: orchestrator has not stamped a vf_uuid on this VF "
		       "(QUERY_VF.vf_uuid is all-zeros). It must call MLX5_VFMIG_IOC_SET_VF_UUID with a stable "
		       "16-byte identity on this PF cdev before the workload binds the VF, so restore can match the "
		       "dumped image to a destination VF by UUID.\n",
		       pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}
	memcpy(out->vf_uuid, qv.vf_uuid, sizeof(out->vf_uuid));

	memset(&ss, 0, sizeof(ss));
	ss.vf_id = vf_id;
	ss.flags = 0;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_SAVE_VHCA_STATE, &ss)) {
		pr_perror("vfmig: SAVE_VHCA_STATE(pf=%s vf_id=%u)", pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}

	snprintf(out->blob_path, sizeof(out->blob_path), "mlx5_vfmig-pf%s-vf%u.blob", pf_bdf, vf_id);
	if (vfmig_drain_save_fd_to_blob(ss.save_fd, out->blob_path, &out->blob_size)) {
		close(ss.save_fd);
		close(cdev_fd);
		return -1;
	}
	close(ss.save_fd);
	close(cdev_fd);

	pr_info("vfmig: captured pf=%s vf_id=%u vhca_id=%u blob='%s' size=%llu\n", pf_bdf, vf_id, out->vhca_id,
		out->blob_path, (unsigned long long)out->blob_size);
	return 0;
}

/*
 * Dump-side SAVE drain, called from fini(DUMP) on a successful dump.
 *
 * Walks the claimed-VF set (already deduplicated by (pf_bdf, vf_id) at
 * claim time), captures each VF's firmware blob, and appends one
 * Mlx5VfmigStateEntry per VF to mlx5_vfmig.img. SAVE_VHCA_STATE is the
 * most invasive thing the plugin does to the host, so it is deferred to
 * here -- after the rest of the dump has succeeded -- rather than run
 * inline at claim time.
 *
 * Best-effort per VF: a capture/append failure for one VF is logged and
 * skipped so the other VFs still land in the image. fini's return value
 * is dropped by criu, so the pr_err lines are the operator's surface for
 * "which VF didn't make it into the image".
 */
void vfmig_drain_claimed_in_fini(void)
{
	struct vfmig_claimed_vf *c;
	int total = 0, written = 0, failed = 0;

	for (c = vfmig_claimed_head; c; c = c->next) {
		struct vfmig_saved_vf sv;
		char cdev_path[PATH_MAX];

		total++;
		memset(&sv, 0, sizeof(sv));
		if (vfmig_capture_one_vf(c->pf_bdf, c->vf_id, &sv)) {
			pr_err("vfmig: capture failed for pf=%s vf_id=%u; no image record written\n", c->pf_bdf,
			       c->vf_id);
			failed++;
			continue;
		}

		/*
		 * source_cdev_path is diagnostic in the VF-firmware layer
		 * (it becomes a join key for the later device-VMA remap
		 * layer); a resolution miss is not fatal, so fall back to
		 * an empty string rather than drop the record.
		 */
		if (find_uverbs_cdev_for_ibdev(c->ibdev, cdev_path, sizeof(cdev_path)))
			cdev_path[0] = '\0';

		/*
		 * ctxn is a per-uverbs-context number owned by the later
		 * context-dump layer; the VF-firmware layer emits one
		 * record per VF and has no context number, so record 0.
		 */
		if (vfmig_append_state_entry(0, c->ibdev, cdev_path, c->pf_bdf, c->vf_id, sv.vhca_id, sv.vf_uuid,
					     sv.blob_path, sv.blob_size)) {
			pr_err("vfmig: failed to append state entry for pf=%s vf_id=%u\n", c->pf_bdf, c->vf_id);
			failed++;
			continue;
		}
		written++;
	}

	if (total)
		pr_info("fini-DUMP drain: claimed_vfs=%d records_written=%d failed=%d\n", total, written, failed);
}
