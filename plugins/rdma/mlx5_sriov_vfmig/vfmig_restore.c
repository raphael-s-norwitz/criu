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
 * mlx5_vfmig_plugin_restore_vf_only(), which a standalone restore
 * binary dlopen()s and calls with an image-dir fd. There is
 * deliberately no hook into the plugin's own init(RESTORE): a full
 * `criu restore` also needs the uverbs-object layer, so wiring the VF
 * restore into init() before that layer exists would only ever half
 * restore a process. Driving it from a standalone binary lets the VF
 * firmware round-trip be validated on its own.
 *
 * This commit lands the skeleton and the destination-VF discovery step
 * only: read the image, and for each entry match a destination VF by
 * vf_uuid and record the resolved tuple. The invasive part --
 * LOAD_VHCA_STATE + MARK_RESTORED + bind -- lands in the next commit,
 * wired into the same per-entry loop.
 *
 * Identity model: the destination VF is found by matching the image
 * entry's 16-byte vf_uuid against MLX5_VFMIG_IOC_QUERY_VF on every VF
 * of every PF cdev under /dev/mlx5_vfmig. The orchestrator stamps the
 * same UUID on the source VF (consumed by the dump path) and on the
 * destination VF (consumed here). vhca_id is a per-PF allocator value
 * that is not stable across SAVE/LOAD, and vf_id is a per-PF slot that
 * the orchestrator may place differently on the destination, so the
 * UUID is the only key we bind on. CRIU never calls SET_VF_UUID: it is
 * purely the passive matcher.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/mlx5_vfmig.h>

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
 * Format a 16-byte UUID into the canonical 8-4-4-4-12 hex form so log
 * lines are greppable and round-trippable through the orchestrator's
 * set-uuid tooling. @out must hold at least VFMIG_UUID_STR_LEN bytes.
 */
#define VFMIG_UUID_STR_LEN 37
static void vfmig_uuid_to_str(const uint8_t u[16], char out[VFMIG_UUID_STR_LEN])
{
	snprintf(out, VFMIG_UUID_STR_LEN,
		 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
		 "%02x%02x%02x%02x%02x%02x",
		 u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14],
		 u[15]);
}

/*
 * Scan every PF cdev under /dev/mlx5_vfmig, run QUERY_VF on every VF,
 * and return the first (pf_bdf, vf_id) whose vf_uuid bitwise-matches
 * @target.
 *
 * QUERY_VF with vf_id=0 always populates @num_vfs even when it returns
 * -ERANGE (no VFs provisioned), so one ioctl tells us the iteration
 * bound; the per-vf outputs (including vf_uuid) are valid only when the
 * ioctl returned 0. A per-PF cdev that fails to open or errors on its
 * first ioctl is logged and skipped so one misbehaving PF does not
 * poison the search across the whole host.
 *
 * With a 2^128 UUID space, two VFs on one host reporting the same UUID
 * is an orchestrator bug, so first match wins. Returns 0 on match (with
 * @pf_bdf_out / @vf_id_out set), -ENOENT if no VF carries @target, or
 * -1 on a hard error (e.g. /dev/mlx5_vfmig unreadable).
 */
static int vfmig_resolve_uuid_to_pf_vf(const uint8_t target[16], char *pf_bdf_out, size_t pf_bdf_sz,
				       uint32_t *vf_id_out)
{
	DIR *d;
	struct dirent *de;

	d = opendir(MLX5_VFMIG_DEV_DIR);
	if (!d) {
		pr_perror("vfmig: opendir(%s)", MLX5_VFMIG_DEV_DIR);
		return -1;
	}

	while ((de = readdir(d)) != NULL) {
		char path[PATH_MAX];
		struct mlx5_vfmig_query_vf q;
		int fd, rc;
		uint32_t num_vfs, vf;

		if (de->d_name[0] == '.')
			continue;
		if (snprintf(path, sizeof(path), "%s/%s", MLX5_VFMIG_DEV_DIR, de->d_name) >= (int)sizeof(path))
			continue;

		fd = open(path, O_RDWR | O_CLOEXEC);
		if (fd < 0) {
			pr_warn("vfmig: open(%s) for UUID resolve: %s\n", path, strerror(errno));
			continue;
		}

		memset(&q, 0, sizeof(q));
		q.vf_id = 0;
		rc = ioctl(fd, MLX5_VFMIG_IOC_QUERY_VF, &q);
		if (rc != 0 && errno != ERANGE) {
			pr_warn("vfmig: QUERY_VF(%s, vf_id=0) for UUID resolve: %s\n", path, strerror(errno));
			close(fd);
			continue;
		}
		num_vfs = q.num_vfs;

		if (rc == 0 && !memcmp(q.vf_uuid, target, sizeof(q.vf_uuid))) {
			snprintf(pf_bdf_out, pf_bdf_sz, "%s", de->d_name);
			*vf_id_out = 0;
			close(fd);
			closedir(d);
			return 0;
		}

		for (vf = 1; vf < num_vfs; vf++) {
			struct mlx5_vfmig_query_vf qq;

			memset(&qq, 0, sizeof(qq));
			qq.vf_id = vf;
			if (ioctl(fd, MLX5_VFMIG_IOC_QUERY_VF, &qq) != 0) {
				pr_warn("vfmig: QUERY_VF(%s, vf_id=%u) for UUID resolve: %s\n", path, vf,
					strerror(errno));
				continue;
			}
			if (!memcmp(qq.vf_uuid, target, sizeof(qq.vf_uuid))) {
				snprintf(pf_bdf_out, pf_bdf_sz, "%s", de->d_name);
				*vf_id_out = vf;
				close(fd);
				closedir(d);
				return 0;
			}
		}
		close(fd);
	}

	closedir(d);
	return -ENOENT;
}

/*
 * Resolve a VF's PCI BDF on the current host from (pf_bdf, vf_id) via
 * the standard SR-IOV virtfn symlink.
 */
static int vfmig_resolve_vf_bdf(const char *pf_bdf, uint32_t vf_id, char *out, size_t outsz)
{
	char path[PATH_MAX], target[PATH_MAX];
	const char *base;
	ssize_t n;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/virtfn%u", pf_bdf, vf_id);
	n = readlink(path, target, sizeof(target) - 1);
	if (n <= 0) {
		pr_perror("vfmig: readlink(%s)", path);
		return -1;
	}
	target[n] = '\0';
	base = strrchr(target, '/');
	if (base)
		base++;
	else
		base = target;
	snprintf(out, outsz, "%s", base);
	return 0;
}

/*
 * Read mlx5_vfmig.img and, for each unique vf_uuid, resolve the
 * matching destination VF on this host and record it.
 *
 * Per entry: validate the vf_uuid, resolve it to a destination
 * (pf_bdf, vf_id), enforce that the destination vf_id equals the source
 * vf_id, resolve the destination VF's PCI BDF, and record the tuple.
 * The actual LOAD_VHCA_STATE + MARK_RESTORED + bind is added to this
 * loop in the next commit.
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

	pr_info("vfmig: restore: %zu state entries to resolve\n", n_entries);

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
		struct vfmig_restored_vf *v;
		char dest_pf_bdf[64];
		uint32_t dest_vf_id;
		char vf_bdf[64];
		char uuid_str[VFMIG_UUID_STR_LEN];
		int rc;

		if (vfmig_restored_vf_lookup_by_uuid(e->vf_uuid.data))
			continue;

		vfmig_uuid_to_str(e->vf_uuid.data, uuid_str);

		rc = vfmig_resolve_uuid_to_pf_vf(e->vf_uuid.data, dest_pf_bdf, sizeof(dest_pf_bdf), &dest_vf_id);
		if (rc == -ENOENT) {
			pr_err("vfmig: ctxn=%u source(pf=%s vf_id=%u): no VF on this host has vf_uuid=%s. The "
			       "orchestrator must stamp this UUID on a destination VF (SET_VF_UUID) before "
			       "restore.\n",
			       e->ctxn, e->pf_bdf, e->vf_id, uuid_str);
			goto err;
		}
		if (rc < 0)
			goto err;

		/*
		 * The destination vf_id slot must equal the source vf_id.
		 * The kernel's per-VF IOVA window is keyed on vf_id and the
		 * firmware E-Switch vport is keyed on vf_id+1, so cross-slot
		 * LOAD is not supported. Surface it as a distinct error so
		 * the operator fixes the destination provisioning rather
		 * than chasing a kernel-side LOAD-time -EINVAL.
		 */
		if (dest_vf_id != e->vf_id) {
			pr_err("vfmig: ctxn=%u source(pf=%s vf_id=%u): found vf_uuid=%s on (pf=%s, vf_id=%u) but "
			       "image was dumped from vf_id=%u; the orchestrator must provision the matching vf_id "
			       "slot on the destination and stamp the UUID there. Cross-slot LOAD is not "
			       "supported.\n",
			       e->ctxn, e->pf_bdf, e->vf_id, uuid_str, dest_pf_bdf, dest_vf_id, e->vf_id);
			goto err;
		}

		if (vfmig_resolve_vf_bdf(dest_pf_bdf, dest_vf_id, vf_bdf, sizeof(vf_bdf)))
			goto err;

		v = calloc(1, sizeof(*v));
		if (!v)
			goto err;
		memcpy(v->vf_uuid, e->vf_uuid.data, 16);
		snprintf(v->pf_bdf, sizeof(v->pf_bdf), "%s", dest_pf_bdf);
		v->vf_id = dest_vf_id;
		snprintf(v->vf_bdf, sizeof(v->vf_bdf), "%s", vf_bdf);
		v->next = vfmig_restored_vfs;
		vfmig_restored_vfs = v;

		pr_info("vfmig: matched ctxn=%u source(pf=%s vf_id=%u) -> dest(pf=%s vf_id=%u vf_bdf=%s) by "
			"vf_uuid=%s\n",
			e->ctxn, e->pf_bdf, e->vf_id, v->pf_bdf, v->vf_id, v->vf_bdf, uuid_str);
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
 * Exported entry point for the standalone mlx5_vfmig_restore_vf binary.
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
	 * binary typically exits right after we return regardless.
	 */
	vfmig_restore_fini_close_all();
	return rc;
}
