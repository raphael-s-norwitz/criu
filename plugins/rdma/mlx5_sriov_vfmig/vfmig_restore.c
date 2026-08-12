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
 * This commit lands the entry point and the image read: it decodes
 * mlx5_vfmig.img and validates each entry's vf_uuid. Matching each
 * entry to a destination VF, and the LOAD_VHCA_STATE + bind that
 * follows, are added to the per-entry loop in the following commits.
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
 * Read mlx5_vfmig.img and walk its entries. Per entry this validates
 * the vf_uuid (the sole restore-side identity key); resolving the entry
 * to a destination VF and driving the firmware LOAD are added to this
 * loop in the following commits.
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

	for (i = 0; i < n_entries; i++) {
		const Mlx5VfmigStateEntry *e = entries[i];

		/*
		 * The vf_uuid proto field is required, so unpack already
		 * rejects an omitted field; what we still guard against here
		 * is a malformed length (wire bug) or all-zeros bytes (an
		 * orchestrator bug that bypassed the dump-side capture
		 * refusal). The UUID-only identity model has no fallback for
		 * either.
		 */
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

		pr_info("vfmig: image entry %zu: ctxn=%u source(pf=%s vf_id=%u vhca_id=%u) blob='%s' size=%llu\n", i,
			e->ctxn, e->pf_bdf, e->vf_id, e->vhca_id, e->blob_path, (unsigned long long)e->blob_size);
	}

	for (i = 0; i < n_entries; i++)
		mlx5_vfmig_state_entry__free_unpacked(entries[i], NULL);
	free(entries);
	return 0;

err:
	for (i = 0; i < n_entries; i++)
		mlx5_vfmig_state_entry__free_unpacked(entries[i], NULL);
	free(entries);
	return -1;
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
	return rc;
}
