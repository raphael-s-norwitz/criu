/*
 * mlx5_sriov_vfmig restore-side path.
 *
 * The VF firmware layer here is the LOAD counterpart to the fini(DUMP)
 * SAVE drain in vfmig_dump.c: it matches each image entry's vf_uuid to
 * a destination VF, and -- unless the VF is already bound -- drives
 * ENABLE_MIGRATABLE + SET_TRACKED + LOAD_VHCA_STATE (streaming the
 * firmware blob off the image dir) + MARK_RESTORED and binds it to
 * mlx5_core, then waits for and resolves the destination ibdev and
 * uverbs cdev.
 *
 * Two callers drive that firmware layer (both via
 * vfmig_restore_init_all_vfs_internal):
 *
 *   - the standalone mlx5_vfmig_restore_vf tool, through the exported
 *     mlx5_vfmig_plugin_restore_vf_only() symbol. Firmware layer only
 *     (Phase A): it stops once the destination VFs are bound and their
 *     ibdev/cdev are up.
 *
 *   - the plugin's own init(RESTORE), through
 *     vfmig_restore_init_all_vfs(). It runs the same Phase A and then a
 *     Phase B that parses + validates each image entry's ucontext
 *     snapshot and builds a per-context cache keyed by the source ctxn.
 *     The restore-side uverbs-cdev open path (added in a following
 *     commit) consumes that cache to open the destination cdev and
 *     replay the ucontext.
 *
 * The prerestore contract for `criu restore`: the standalone tool (or
 * the orchestrator) has already loaded the VF firmware and bound the
 * VF, so init(RESTORE)'s Phase A finds every VF already bound and skips
 * LOAD -- it only re-discovers + caches. Dynamic-UAR ucontext restore
 * (RESTORE_DYN_UARS) is not wired here yet; a dyn-mode image entry is
 * refused in Phase B.
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
#include <sys/stat.h>
#include <sys/types.h>
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
 * destination-side tuple the UUID resolved to on this host plus the
 * post-bind ibdev and cdev path. The list is process-global and freed
 * by vfmig_restore_fini_close_all().
 */
struct vfmig_restored_vf {
	struct vfmig_restored_vf *next;
	uint8_t vf_uuid[16];
	char pf_bdf[64];
	uint32_t vf_id;
	char vf_bdf[64];
	char dest_ibdev[64];
	char dest_cdev_path[PATH_MAX];
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
 * One entry per source ucontext the image carries. Built by Phase B of
 * vfmig_restore_init_all_vfs() from the image's ucontext snapshot and
 * the destination cdev resolved for the entry's vf_uuid. Holds the
 * parsed snapshot plus the resolved destination cdev path; the cdev
 * open + ucontext replay are deferred to the restore-side open path
 * added in a following commit. Process-global, keyed by the source
 * ctxn; freed by vfmig_restore_fini_close_all().
 *
 * This commit carries the static-UAR (lib_uar_dyn=false) snapshot only;
 * the dyn-UAR record array arrives with the RESTORE_DYN_UARS commit.
 */
struct vfmig_restored_ctx {
	struct vfmig_restored_ctx *next;
	uint32_t source_ctxn;
	char source_ibdev[64];
	char source_cdev_path[PATH_MAX];
	char dest_cdev_path[PATH_MAX];
	int dest_cdev_fd;

	struct mlx5_ib_vfmig_ucontext_meta_local meta;
	uint32_t *uar_table;
	size_t uar_n;
	uint32_t *bfreg_count;
	size_t bfreg_n;

	/*
	 * Source-side mlx5_ib_ucontext.devx_uid (see
	 * mlx5_vfmig.proto::source_devx_uid). 0 means non-DEVX
	 * ucontext, which is the v0 contract. Carried as image-only
	 * diagnostic metadata; the static restore path opens the
	 * destination without DEVX and does not consume it.
	 */
	uint32_t source_devx_uid;
};
static struct vfmig_restored_ctx *vfmig_restored_ctxs;

static struct vfmig_restored_ctx *vfmig_ctx_lookup_by_source_path(const char *source_cdev_path)
{
	struct vfmig_restored_ctx *p;

	for (p = vfmig_restored_ctxs; p; p = p->next)
		if (!strcmp(p->source_cdev_path, source_cdev_path))
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
 * Is @vf_bdf bound to any kernel driver?
 *
 * Returns 1 if /sys/bus/pci/devices/<vf_bdf>/driver exists (the VF is
 * already bound -- e.g. a prior restore-vf run already drove LOAD +
 * bind on it), 0 if it does not (the orchestrator-provisioned-but-
 * unbound state this path expects), or -1 on a sysfs error the caller
 * should treat as fatal.
 *
 * We use the sysfs driver symlink rather than QUERY_VF.restored on
 * purpose: the kernel consumes the `restored` bit at VF-probe time (it
 * is cleared as soon as the bind triggers the VF's driver load), so any
 * post-bind QUERY_VF reads it back as 0 regardless of whether a LOAD +
 * MARK_RESTORED cycle ran moments earlier. Under the orchestrator
 * contract -- the destination VF is created unbound and only this path
 * binds it -- "bound to a driver" is a clean "already restored" signal.
 */
static int vfmig_is_vf_bound(const char *vf_bdf)
{
	char path[PATH_MAX];
	struct stat st;

	if (snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/driver", vf_bdf) >= (int)sizeof(path)) {
		pr_err("vfmig: vf_bdf=%s too long for sysfs path\n", vf_bdf);
		return -1;
	}
	if (lstat(path, &st) == 0)
		return 1;
	if (errno == ENOENT)
		return 0;
	pr_perror("vfmig: lstat(%s) for bind check", path);
	return -1;
}

/*
 * Drive ENABLE_MIGRATABLE + SET_TRACKED + LOAD_VHCA_STATE +
 * MARK_RESTORED on a single (pf_bdf, vf_id), streaming the firmware
 * blob at @blob_path (relative to the image dir) into the load fd.
 *
 * ENABLE_MIGRATABLE and SET_TRACKED are idempotent per the kernel UAPI:
 * the orchestrator may already have run them on the destination VF, in
 * which case the kernel returns 0 with no firmware traffic. Re-issuing
 * them lets the plugin tolerate a minimal orchestrator that only does
 * sriov_numvfs + SET_VF_UUID.
 */
static int vfmig_load_one_vf(const char *pf_bdf, uint32_t vf_id, const char *blob_path, uint64_t blob_size)
{
	char cdev_path[PATH_MAX];
	char buf[65536];
	int cdev_fd, blob_fd, img_dir, load_fd;
	struct mlx5_vfmig_enable_migratable em;
	struct mlx5_vfmig_set_tracked sttr;
	struct mlx5_vfmig_load_state ls;
	struct mlx5_vfmig_mark_restored mr;
	uint64_t total_written = 0;

	memset(&em, 0, sizeof(em));
	memset(&sttr, 0, sizeof(sttr));
	memset(&ls, 0, sizeof(ls));
	memset(&mr, 0, sizeof(mr));

	snprintf(cdev_path, sizeof(cdev_path), "%s/%s", MLX5_VFMIG_DEV_DIR, pf_bdf);
	cdev_fd = open(cdev_path, O_RDWR | O_CLOEXEC);
	if (cdev_fd < 0) {
		pr_perror("vfmig: open(%s)", cdev_path);
		return -1;
	}

	em.vf_id = vf_id;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_ENABLE_MIGRATABLE, &em)) {
		pr_perror("vfmig: ENABLE_MIGRATABLE pf=%s vf_id=%u", pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}

	sttr.vf_id = vf_id;
	sttr.enable = 1;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_SET_TRACKED, &sttr)) {
		pr_perror("vfmig: SET_TRACKED pf=%s vf_id=%u", pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}

	ls.vf_id = vf_id;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_LOAD_VHCA_STATE, &ls)) {
		pr_perror("vfmig: LOAD_VHCA_STATE pf=%s vf_id=%u", pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}
	load_fd = ls.load_fd;

	img_dir = vfmig_get_image_dir();
	if (img_dir < 0) {
		pr_err("vfmig: vfmig_get_image_dir() returned %d loading blob for pf=%s vf_id=%u\n", img_dir, pf_bdf,
		       vf_id);
		close(load_fd);
		close(cdev_fd);
		return -1;
	}
	blob_fd = openat(img_dir, blob_path, O_RDONLY | O_CLOEXEC);
	if (blob_fd < 0) {
		pr_perror("vfmig: openat(image_dir/%s) for blob", blob_path);
		close(load_fd);
		close(cdev_fd);
		return -1;
	}

	while (total_written < blob_size) {
		ssize_t r = read(blob_fd, buf, sizeof(buf));
		ssize_t w;

		if (r < 0) {
			pr_perror("vfmig: read(%s)", blob_path);
			close(blob_fd);
			close(load_fd);
			close(cdev_fd);
			return -1;
		}
		if (r == 0)
			break;
		for (w = 0; w < r;) {
			ssize_t k = write(load_fd, buf + w, r - w);

			if (k <= 0) {
				pr_perror("vfmig: write(load_fd) pf=%s vf_id=%u", pf_bdf, vf_id);
				close(blob_fd);
				close(load_fd);
				close(cdev_fd);
				return -1;
			}
			w += k;
		}
		total_written += r;
	}
	close(blob_fd);

	/*
	 * Closing load_fd commits the staged blob: per the UAPI the driver
	 * issues no firmware command against the destination VHCA until
	 * close(), so a failure here is meaningful and surfaces errors in
	 * the blob's DMA pipeline.
	 */
	if (close(load_fd)) {
		pr_perror("vfmig: close(load_fd) pf=%s vf_id=%u", pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}

	/*
	 * MARK_RESTORED latches the "skip re-init on next probe" bit. On
	 * current firmware, staging a LOAD_VHCA_STATE blob already sets that
	 * bit (QUERY_VF.restored reads 1 after the load fd is committed), so
	 * an explicit MARK_RESTORED here returns -EALREADY. That is the
	 * desired end state -- the bit is set -- so tolerate it; still issue
	 * the ioctl so the path also works on a kernel where LOAD does not
	 * implicitly latch the bit.
	 */
	mr.vf_id = vf_id;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_MARK_RESTORED, &mr) && errno != EALREADY) {
		pr_perror("vfmig: MARK_RESTORED pf=%s vf_id=%u", pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}

	close(cdev_fd);
	pr_info("vfmig: loaded pf=%s vf_id=%u (%llu bytes)\n", pf_bdf, vf_id, (unsigned long long)total_written);
	return 0;
}

/*
 * Set the VF's driver_override to mlx5_core and bind it. The
 * orchestrator left autoprobe disabled and the VF unbound; this is the
 * step that makes the kernel mlx5_core probe run against the loaded
 * VHCA blob.
 */
static int vfmig_driver_override_and_bind(const char *vf_bdf)
{
	char path[PATH_MAX];
	int fd;
	size_t bdf_len;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/driver_override", vf_bdf);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("vfmig: open(%s)", path);
		return -1;
	}
	if (write(fd, "mlx5_core\n", 10) != 10) {
		pr_perror("vfmig: write(%s)", path);
		close(fd);
		return -1;
	}
	close(fd);

	snprintf(path, sizeof(path), "/sys/bus/pci/drivers/mlx5_core/bind");
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("vfmig: open(%s)", path);
		return -1;
	}
	bdf_len = strlen(vf_bdf);
	if (write(fd, vf_bdf, bdf_len) != (ssize_t)bdf_len) {
		pr_perror("vfmig: write(bind, %s)", vf_bdf);
		close(fd);
		return -1;
	}
	close(fd);

	pr_info("vfmig: bound %s to mlx5_core\n", vf_bdf);
	return 0;
}

/*
 * Wait up to ~10s for /sys/bus/pci/devices/<vf_bdf>/infiniband/ to
 * appear and hold at least one entry, then resolve the dest ibdev
 * (basename of the first directory entry) into @out. mlx5_core probe is
 * asynchronous: the bind write returns as soon as the probe is
 * scheduled and the ibdev shows up some milliseconds later.
 */
static int vfmig_wait_for_dest_ibdev(const char *vf_bdf, char *out, size_t outsz)
{
	char path[PATH_MAX];
	int tries = 100;
	DIR *d;
	struct dirent *de;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/infiniband", vf_bdf);

	while (tries-- > 0) {
		d = opendir(path);
		if (d) {
			while ((de = readdir(d)) != NULL) {
				if (de->d_name[0] == '.')
					continue;
				snprintf(out, outsz, "%s", de->d_name);
				closedir(d);
				pr_info("vfmig: dest ibdev for %s -> %s\n", vf_bdf, out);
				return 0;
			}
			closedir(d);
		}
		usleep(100 * 1000);
	}
	pr_err("vfmig: timed out waiting for ibdev under %s\n", path);
	return -1;
}

/*
 * Resolve the dest uverbs cdev path for @ibdev by walking
 * /sys/class/infiniband_verbs/uverbs* /ibdev.
 */
static int vfmig_resolve_dest_cdev_path(const char *ibdev, char *out, size_t outsz)
{
	DIR *d;
	struct dirent *de;
	char path[PATH_MAX], buf[64];
	int fd;
	ssize_t n;

	d = opendir("/sys/class/infiniband_verbs");
	if (!d) {
		pr_perror("vfmig: opendir(/sys/class/infiniband_verbs)");
		return -1;
	}
	while ((de = readdir(d)) != NULL) {
		if (strncmp(de->d_name, "uverbs", 6) != 0)
			continue;
		snprintf(path, sizeof(path), "/sys/class/infiniband_verbs/%s/ibdev", de->d_name);
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			continue;
		n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n <= 0)
			continue;
		buf[n] = '\0';
		if (buf[n - 1] == '\n')
			buf[--n] = '\0';
		if (strcmp(buf, ibdev) != 0)
			continue;
		snprintf(out, outsz, "/dev/infiniband/%s", de->d_name);
		closedir(d);
		return 0;
	}
	closedir(d);
	pr_err("vfmig: no uverbsN matches ibdev=%s\n", ibdev);
	return -1;
}

/*
 * Read mlx5_vfmig.img and, for each unique vf_uuid, restore the
 * matching destination VF up to "firmware loaded, bound, ibdev up".
 *
 * Per entry: validate the vf_uuid, resolve it to a destination
 * (pf_bdf, vf_id), enforce that the destination vf_id equals the source
 * vf_id, resolve the destination VF's PCI BDF, then -- unless the VF is
 * already bound -- drive LOAD_VHCA_STATE + MARK_RESTORED and bind it to
 * mlx5_core; finally resolve the dest ibdev and cdev path and record
 * the tuple.
 *
 * Any per-entry failure aborts the whole restore (goto err): a VF-level
 * restore is all-or-nothing from the operator's point of view.
 *
 * @run_phase_b: false for the standalone tool (firmware layer only --
 * stops once the VFs are bound and ibdev/cdev are up); true for the
 * plugin's init(RESTORE), which then runs Phase B to parse each image
 * entry's ucontext snapshot into the per-context cache the
 * OPEN_UVERBS_CDEV hook consumes.
 */
static int vfmig_restore_init_all_vfs_internal(bool run_phase_b)
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
		int dest_bound;
		char vf_bdf[64], dest_ibdev[64];
		char dest_cdev_path[PATH_MAX];
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

		pr_info("vfmig: matched ctxn=%u source(pf=%s vf_id=%u) -> dest(pf=%s vf_id=%u vf_bdf=%s) by "
			"vf_uuid=%s\n",
			e->ctxn, e->pf_bdf, e->vf_id, dest_pf_bdf, dest_vf_id, vf_bdf, uuid_str);

		dest_bound = vfmig_is_vf_bound(vf_bdf);
		if (dest_bound < 0)
			goto err;

		if (dest_bound) {
			pr_info("vfmig: dest vf_id=%u (vf_bdf=%s) already bound to mlx5_core; skipping "
				"LOAD_VHCA_STATE\n",
				dest_vf_id, vf_bdf);
		} else {
			if (vfmig_load_one_vf(dest_pf_bdf, dest_vf_id, e->blob_path, e->blob_size))
				goto err;
			if (vfmig_driver_override_and_bind(vf_bdf))
				goto err;
		}

		if (vfmig_wait_for_dest_ibdev(vf_bdf, dest_ibdev, sizeof(dest_ibdev)))
			goto err;
		if (vfmig_resolve_dest_cdev_path(dest_ibdev, dest_cdev_path, sizeof(dest_cdev_path)))
			goto err;

		v = calloc(1, sizeof(*v));
		if (!v)
			goto err;
		memcpy(v->vf_uuid, e->vf_uuid.data, 16);
		snprintf(v->pf_bdf, sizeof(v->pf_bdf), "%s", dest_pf_bdf);
		v->vf_id = dest_vf_id;
		snprintf(v->vf_bdf, sizeof(v->vf_bdf), "%s", vf_bdf);
		snprintf(v->dest_ibdev, sizeof(v->dest_ibdev), "%s", dest_ibdev);
		snprintf(v->dest_cdev_path, sizeof(v->dest_cdev_path), "%s", dest_cdev_path);
		v->next = vfmig_restored_vfs;
		vfmig_restored_vfs = v;

		pr_info("vfmig: restored VF: vf_uuid=%s source(pf=%s vf_id=%u) -> dest(pf=%s vf_id=%u vf_bdf=%s) "
			"dest_ibdev=%s dest_cdev=%s\n",
			uuid_str, e->pf_bdf, e->vf_id, v->pf_bdf, v->vf_id, v->vf_bdf, v->dest_ibdev,
			v->dest_cdev_path);
	}

	if (!run_phase_b)
		goto done;

	/*
	 * Phase B: build the per-context restore cache from each entry's
	 * ucontext snapshot. The cdev open + ucontext replay are deferred
	 * to the OPEN_UVERBS_CDEV hook (vfmig_ensure_cdev_open); doing the
	 * fd work here, in criu main, would lose the fd to the fd-table
	 * teardown in every restored task.
	 */
	for (i = 0; i < n_entries; i++) {
		Mlx5VfmigStateEntry *e = entries[i];
		struct vfmig_restored_vf *v;
		struct vfmig_restored_ctx *c;
		const struct mlx5_ib_vfmig_ucontext_meta_local *m;
		size_t uar_n, cnt_n;

		v = vfmig_restored_vf_lookup_by_uuid(e->vf_uuid.data);
		if (!v) {
			pr_err("vfmig: restored_vf lookup miss for ctxn=%u (vf_uuid not found in cache; Phase A "
			       "logic bug)\n",
			       e->ctxn);
			goto err;
		}

		if (vfmig_ctx_lookup_by_source_path(e->source_cdev_path)) {
			pr_err("vfmig: multiple state entries reference source cdev path %s -- "
			       "multi-ctxn-per-VF restore is not supported in v0\n",
			       e->source_cdev_path);
			goto err;
		}

		/*
		 * The image must carry exactly one of the static pair
		 * {uctx_meta + uctx_uar_table (+ uctx_bfreg_count)} or the
		 * dyn buffer uctx_dyn_uar_records. An entry with neither
		 * predates VFMIG_RESTORE support; one with both is a
		 * malformed image. A dyn-mode entry is well-formed but not
		 * restorable by this commit -- RESTORE_DYN_UARS lands later.
		 */
		if (e->has_uctx_dyn_uar_records && !e->has_uctx_meta) {
			pr_err("vfmig: image entry ctxn=%u carries a dynamic-UAR ucontext snapshot; dyn-UAR "
			       "restore is not supported yet (arrives with the RESTORE_DYN_UARS commit)\n",
			       e->ctxn);
			goto err;
		}
		if (!e->has_uctx_meta || !e->has_uctx_uar_table) {
			pr_err("vfmig: image entry ctxn=%u missing static uctx snapshot (meta=%d uar_table=%d) -- "
			       "image predates VFMIG_RESTORE support and is not restorable; re-dump with a current "
			       "criu build\n",
			       e->ctxn, e->has_uctx_meta, e->has_uctx_uar_table);
			goto err;
		}
		if (e->has_uctx_dyn_uar_records) {
			pr_err("vfmig: image entry ctxn=%u carries BOTH static and dyn uctx snapshots -- malformed "
			       "image\n",
			       e->ctxn);
			goto err;
		}
		if (e->uctx_meta.len != sizeof(struct mlx5_ib_vfmig_ucontext_meta_local)) {
			pr_err("vfmig: image entry ctxn=%u static uctx_meta length=%zu != %zu\n", e->ctxn,
			       e->uctx_meta.len, sizeof(struct mlx5_ib_vfmig_ucontext_meta_local));
			goto err;
		}

		m = (const void *)e->uctx_meta.data;
		uar_n = e->uctx_uar_table.len / sizeof(uint32_t);
		cnt_n = e->has_uctx_bfreg_count ? (e->uctx_bfreg_count.len / sizeof(uint32_t)) : 0;

		if (uar_n != m->num_sys_pages) {
			pr_err("vfmig: image entry ctxn=%u uar_table len mismatch: %zu != meta.num_sys_pages=%u\n",
			       e->ctxn, uar_n, m->num_sys_pages);
			goto err;
		}
		if (cnt_n && cnt_n != m->total_num_bfregs) {
			pr_err("vfmig: image entry ctxn=%u bfreg_count len mismatch: %zu != "
			       "meta.total_num_bfregs=%u\n",
			       e->ctxn, cnt_n, m->total_num_bfregs);
			goto err;
		}

		c = calloc(1, sizeof(*c));
		if (!c)
			goto err;
		c->source_ctxn = e->ctxn;
		snprintf(c->source_ibdev, sizeof(c->source_ibdev), "%s", e->ibdev);
		snprintf(c->source_cdev_path, sizeof(c->source_cdev_path), "%s", e->source_cdev_path);
		snprintf(c->dest_cdev_path, sizeof(c->dest_cdev_path), "%s", v->dest_cdev_path);
		c->dest_cdev_fd = -1;
		c->source_devx_uid = e->has_source_devx_uid ? e->source_devx_uid : 0;
		c->meta = *m;
		c->uar_n = uar_n;
		c->uar_table = malloc(e->uctx_uar_table.len);
		if (!c->uar_table) {
			free(c);
			goto err;
		}
		memcpy(c->uar_table, e->uctx_uar_table.data, e->uctx_uar_table.len);
		if (cnt_n) {
			c->bfreg_n = cnt_n;
			c->bfreg_count = malloc(e->uctx_bfreg_count.len);
			if (!c->bfreg_count) {
				free(c->uar_table);
				free(c);
				goto err;
			}
			memcpy(c->bfreg_count, e->uctx_bfreg_count.data, e->uctx_bfreg_count.len);
		}

		c->next = vfmig_restored_ctxs;
		vfmig_restored_ctxs = c;
		pr_info("vfmig: cached ctxn=%u source_ibdev=%s source_cdev=%s dest_cdev=%s mode=static "
			"source_devx_uid=%u (snapshot deferred-open)\n",
			c->source_ctxn, c->source_ibdev, c->source_cdev_path, c->dest_cdev_path, c->source_devx_uid);
	}

done:
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
	struct vfmig_restored_ctx *c, *cn;

	for (c = vfmig_restored_ctxs; c; c = cn) {
		cn = c->next;
		if (c->dest_cdev_fd >= 0)
			close(c->dest_cdev_fd);
		free(c->uar_table);
		free(c->bfreg_count);
		free(c);
	}
	vfmig_restored_ctxs = NULL;

	for (v = vfmig_restored_vfs; v; v = vn) {
		vn = v->next;
		free(v);
	}
	vfmig_restored_vfs = NULL;
}

/*
 * criu-restore-side entry point, driven from the plugin's
 * init(RESTORE). Runs the full firmware discovery (Phase A) plus the
 * per-context cache build (Phase B) so the OPEN_UVERBS_CDEV hook can
 * lazily open + replay each context. Uses criu's own image dir (no
 * override). Returns 0 on success, -1 on any error.
 */
int vfmig_restore_init_all_vfs(void)
{
	return vfmig_restore_init_all_vfs_internal(true);
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
	rc = vfmig_restore_init_all_vfs_internal(false);
	vfmig_clear_image_dir_override();

	/*
	 * Free the in-memory cache so a subsequent caller starts clean; the
	 * tool typically exits right after we return regardless.
	 */
	vfmig_restore_fini_close_all();
	return rc;
}
