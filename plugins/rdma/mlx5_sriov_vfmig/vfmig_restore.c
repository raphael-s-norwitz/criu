/*
 * mlx5_sriov_vfmig restore-side VF firmware-state path.
 *
 * This is the LOAD counterpart to the fini(DUMP) SAVE drain in
 * vfmig_dump.c, and it covers only the VF firmware layer. It does NOT
 * restore any uverbs context, PD/CQ/QP/MR, or process memory -- that is
 * a separate uverbs-object layer, which needs core CRIU hooks and is
 * not wired here.
 *
 * The single entry point is the exported symbol
 * mlx5_vfmig_plugin_restore_vf_only(), which the standalone
 * mlx5_vfmig_restore_vf tool dlopen()s and calls with an image-dir fd.
 * There is deliberately no hook into the plugin's own init(RESTORE): a
 * full `criu restore` also needs the uverbs-object layer, so wiring the
 * VF restore into init() before that layer exists would only ever half
 * restore a process. Driving it from the tool lets the VF firmware
 * round-trip be validated on its own.
 *
 * This commit adds the process-global restored-VF cache and a dedup
 * pass over the image entries: the image can reference the same vf_uuid
 * from more than one context, and each destination VF must be resolved
 * and restored only once. Resolving each unique vf_uuid to a
 * destination VF, and the LOAD_VHCA_STATE + bind that follows, are
 * added to the same per-entry loop in the following commits.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "criu-log.h"

#include "vfmig_internal.h"

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_mlx5_vfmig_plugin: "

/*
 * One entry per unique vf_uuid the image references. Carries the
 * destination-side tuple the UUID resolved to on this host. The list is
 * process-global and freed by vfmig_restore_fini_close_all().
 */
struct vfmig_restored_vf {
	struct vfmig_restored_vf *next;
	uint8_t vf_uuid[16];
	char pf_bdf[64];
	uint32_t vf_id;
	char vf_bdf[64];
};
static struct vfmig_restored_vf *vfmig_restored_vfs;

static struct vfmig_restored_vf *vfmig_restored_vf_lookup_by_uuid(const uint8_t uuid[16])
{
	struct vfmig_restored_vf *p;

	for (p = vfmig_restored_vfs; p; p = p->next)
		if (!memcmp(p->vf_uuid, uuid, 16))
			return p;
	return NULL;
}

/*
 * Read mlx5_vfmig.img, validate each entry's vf_uuid, and dedup the
 * entries by vf_uuid through the restored-VF cache. Resolving each
 * unique vf_uuid to a destination VF and driving the firmware LOAD are
 * added to this loop in the following commits.
 *
 * Any per-entry failure aborts the whole restore (goto err): a VF-level
 * restore is all-or-nothing from the operator's point of view.
 */
static int vfmig_restore_all_vfs(void)
{
	static const uint8_t zero_uuid[16] = { 0 };
	Mlx5VfmigStateEntry **entries = NULL;
	size_t n_entries = 0, i;

	if (vfmig_read_image(&entries, &n_entries))
		return -1;
	if (n_entries == 0) {
		pr_info("vfmig: restore: no state entries in image; nothing to do\n");
		return 0;
	}

	pr_info("vfmig: restore: %zu state entries in image\n", n_entries);

	/*
	 * Pre-flight: every entry must carry a well-formed, non-zero
	 * vf_uuid. The proto field is required so unpack already rejects an
	 * omitted field; what we still guard against is a malformed length
	 * (wire bug) or all-zeros bytes (an orchestrator bug that bypassed
	 * the dump-side capture refusal). The UUID-only identity model has
	 * no fallback for either.
	 */
	for (i = 0; i < n_entries; i++) {
		const Mlx5VfmigStateEntry *e = entries[i];

		if (e->vf_uuid.len != 16) {
			pr_err("vfmig: image entry ctxn=%u has malformed vf_uuid (len=%zu, want 16)\n", e->ctxn,
			       e->vf_uuid.len);
			goto err;
		}
		if (!memcmp(e->vf_uuid.data, zero_uuid, 16)) {
			pr_err("vfmig: image entry ctxn=%u has all-zeros vf_uuid -- malformed image (the dump-side "
			       "capture should have refused it). Cannot match to a destination VF; refusing the "
			       "restore.\n",
			       e->ctxn);
			goto err;
		}
	}

	for (i = 0; i < n_entries; i++) {
		Mlx5VfmigStateEntry *e = entries[i];

		if (vfmig_restored_vf_lookup_by_uuid(e->vf_uuid.data))
			continue;

		/*
		 * A cache miss is a vf_uuid we have not seen yet: the next
		 * commits resolve it to a destination VF, record it here, and
		 * drive the firmware LOAD. Until then the loop only dedups.
		 */
	}

	for (i = 0; i < n_entries; i++)
		mlx5_vfmig_state_entry__free_unpacked(entries[i], NULL);
	free(entries);
	return 0;

err:
	for (i = 0; i < n_entries; i++)
		mlx5_vfmig_state_entry__free_unpacked(entries[i], NULL);
	free(entries);
	vfmig_restore_fini_close_all();
	return -1;
}

void vfmig_restore_fini_close_all(void)
{
	struct vfmig_restored_vf *v, *vn;

	for (v = vfmig_restored_vfs; v; v = vn) {
		vn = v->next;
		free(v);
	}
	vfmig_restored_vfs = NULL;
}

/*
 * Exported entry point for the standalone mlx5_vfmig_restore_vf tool.
 *
 * Drives the VF firmware restore for every entry in the dump. It
 * restores only the VF firmware layer: uverbs contexts and RDMA objects
 * are a separate layer that needs a real `criu restore` and is not
 * driven here.
 *
 * The caller opens the image dir (typically O_PATH | O_DIRECTORY) and
 * owns the fd; the plugin only reads through it. image_dir_fd < 0
 * returns -1 without touching kernel state. Returns 0 on success, -1 on
 * any error.
 */
int mlx5_vfmig_plugin_restore_vf_only(int image_dir_fd)
{
	int rc;

	if (image_dir_fd < 0) {
		pr_err("vfmig: mlx5_vfmig_plugin_restore_vf_only: invalid image_dir_fd=%d\n", image_dir_fd);
		return -1;
	}

	vfmig_set_image_dir_override(image_dir_fd);
	rc = vfmig_restore_all_vfs();
	vfmig_clear_image_dir_override();

	/*
	 * Free the in-memory cache so a subsequent caller starts clean; the
	 * tool typically exits right after we return regardless.
	 */
	vfmig_restore_fini_close_all();
	return rc;
}
