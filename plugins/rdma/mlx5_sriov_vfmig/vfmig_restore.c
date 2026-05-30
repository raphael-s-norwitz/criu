/*
 * vfmig_restore.c
 *
 * Restore-side orchestration for the mlx5 SR-IOV VFMIG plugin.
 *
 * What lives here:
 *
 *   - Two restore-side caches with file-scope ownership:
 *     vfmig_restored_vfs   one entry per unique (pf_bdf, vf_id)
 *                          the image references; carries the
 *                          resolved dest VF BDF, dest ibdev, and
 *                          dest cdev path.
 *     vfmig_restored_ctxs  one entry per Mlx5VfmigStateEntry;
 *                          holds source ctxn / source ibdev /
 *                          source cdev path (the lookup keys)
 *                          and the cached dest cdev fd.
 *
 *   - vfmig_load_one_vf(): the LOAD_VHCA_STATE orchestrator.
 *     ENABLE_MIGRATABLE + SET_TRACKED + LOAD_VHCA_STATE +
 *     MARK_RESTORED on a destination (pf_bdf, vf_id), reading
 *     the firmware blob off the image dir.
 *
 *   - VF-bring-up plumbing: vfmig_resolve_vf_bdf,
 *     vfmig_driver_override_and_bind, vfmig_wait_for_dest_ibdev,
 *     vfmig_resolve_dest_cdev_path. Drive the destination VF
 *     from "loaded firmware blob" to "ready uverbs cdev".
 *
 *   - vfmig_park_fd_high() + vfmig_ensure_cdev_open(): per-helper
 *     lazy-open of the destination cdev (the open is deferred
 *     out of init(RESTORE) into the first consumer hook because
 *     criu's restore-helper fork without CLONE_FILES purges
 *     non-service fds before prepare_fds runs; opening lazily
 *     lets each helper own its own fd).
 *
 *   - vfmig_restore_init_all_vfs(): Phase A reads mlx5_vfmig.img,
 *     Phase B drives ENABLE/SET/LOAD/MARK/bind on each unique VF.
 *     Called from plugin.c init(RESTORE). On success, the per-
 *     ctxn cache is populated; the actual cdev open lands later
 *     via vfmig_ensure_cdev_open() at first hook fire.
 *
 *   - vfmig_restore_fini_close_all(): close any cached fds at
 *     fini(RESTORE) regardless of restore success/failure.
 *
 *   - The two restore hooks: UPDATE_VMA_MAP (dispatch by source
 *     uverbs-cdev path, return cached dup of dest fd + remapped
 *     pgoff) and RDMA_OPEN_UVERBS_CDEV (dispatch by source ctxn,
 *     return cached dup of dest fd).
 *
 * Cross-file API surface (declared in vfmig_internal.h):
 *   the two init/fini entry points called from plugin.c
 *   init/fini, and the two hook entry points referenced by
 *   plugin.c's CR_PLUGIN_REGISTER_HOOK macros.
 *
 * vfmig_active is read here (every hook's cheap-decline gate)
 * but defined in plugin.c.
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
#include "criu-plugin.h"

#include "images/rdma_criu.pb-c.h"
#include "images/mlx5_vfmig.pb-c.h"
#include "images/uverbsfd.pb-c.h"

#include "mlx5_uapi.h"
#include "vfmig_internal.h"

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_mlx5_vfmig_plugin: "

/*
 * ============================================================
 * Restore-side eager-init plumbing.
 * ============================================================
 *
 * On restore the mlx5 plugin can't be lazy: by the time CRIU's VMA
 * restore phase fires UPDATE_VMA_MAP for the dumpee's UAR/clock/NC
 * pages, the kernel cdev fd we hand back must already have a kernel
 * ucontext on it (mlx5_ib_mmap insists), and the destination VHCA
 * the cdev points at must already be loaded + bound (or the cdev
 * doesn't exist yet). We do all of that up front in init(RESTORE),
 * cache one fd per source uverbs context, and then UPDATE_VMA_MAP
 * and RDMA_OPEN_UVERBS_CDEV just dup() out of the cache.
 *
 * Caches:
 *   vfmig_restored_vfs   - one entry per unique (pf_bdf, vf_id) the
 *                          image references; carries the resolved
 *                          dest VF BDF, dest ibdev, and dest cdev
 *                          path for diagnostics + reuse.
 *   vfmig_restored_ctxs  - one entry per Mlx5VfmigStateEntry; holds
 *                          the source ctxn / source ibdev / source
 *                          cdev path (the lookup keys for the two
 *                          consumer hooks) and the cached dest cdev
 *                          fd (already armed with GET_CONTEXT).
 *
 * Multi-ctxn-per-VF: not supported in v0. The protobuf contract on
 * the restore side allows multiple state entries against the same
 * (pf_bdf, vf_id), but UPDATE_VMA_MAP receives only the source path
 * as a discriminator -- two ctxns on the same source cdev path
 * would alias in the path-keyed cache. Phase 2 below refuses any
 * such image up front; if it ever needs to be supported, CRIU's
 * UPDATE_VMA_MAP plugin ABI needs to grow a reg_file id (or
 * equivalent disambiguator).
 *
 * Single-host vs cross-host: for v0 we assume the destination's
 * (pf_bdf, vf_id) tuple matches the source's (i.e. the orchestrator
 * has reproduced the source's SR-IOV layout on the destination).
 * Cross-host migration needs an explicit (source -> dest) remap
 * supplied by the orchestrator; that's a follow-up.
 */

struct vfmig_restored_vf {
	struct vfmig_restored_vf *next;
	char pf_bdf[64];
	uint32_t vf_id;
	char vf_bdf[64];
	char dest_ibdev[64];
	char dest_cdev_path[PATH_MAX];
};
static struct vfmig_restored_vf *vfmig_restored_vfs;

/*
 * Per-context restore cache.
 *
 * Populated by init(RESTORE) from the on-disk Mlx5VfmigStateEntry, but
 * the actual cdev open + GET_CONTEXT(VFMIG_RESTORE) + RESTORE_{UCONTEXT,
 * DYN_UARS} ioctls are deferred to vfmig_ensure_cdev_open(), called
 * from the first consumer hook (UPDATE_VMA_MAP or OPEN_UVERBS_CDEV).
 *
 * Why deferred: criu/files.c c7395f4cb (post-9/2025) forks per-task
 * restore helpers without CLONE_FILES, and the helper's
 * setup_newborn_fds calls close_old_fds() which purges any fd that
 * isn't a service-fd. An fd opened in init(RESTORE) (criu main's
 * fdtable) gets nuked in every helper before prepare_fds runs --
 * dup(8) on a closed slot returns EBADF, and the workload's fdtable
 * never receives the cdev. Lazy-opening from inside the helper
 * avoids the purge entirely: each helper opens its own fd and the
 * plugin's per-helper globals (this list is forked-from-criu, then
 * mutated independently per helper) hold helper-local fd state.
 *
 * Snapshot bytes (uctx_meta + uar_table + bfreg_count for static,
 * dyn_records for dyn) are deep-copied out of the unpacked
 * Mlx5VfmigStateEntry at init time so the entry array can be freed
 * before any helper forks. is_dyn picks which restore verb to issue
 * at lazy-open time.
 */
struct vfmig_restored_ctx {
	struct vfmig_restored_ctx *next;
	uint32_t source_ctxn;
	char source_ibdev[64];
	char source_cdev_path[PATH_MAX];
	char dest_cdev_path[PATH_MAX];
	int dest_cdev_fd;

	bool is_dyn;
	/* Static (lib_uar_dyn=false) snapshot, valid iff !is_dyn. */
	struct mlx5_ib_vfmig_ucontext_meta_local meta;
	uint32_t *uar_table;
	size_t uar_n;
	uint32_t *bfreg_count;
	size_t bfreg_n;
	/* Dyn (lib_uar_dyn=true) snapshot, valid iff is_dyn. */
	struct mlx5_ib_vfmig_dyn_uar_record_local *dyn_records;
	size_t dyn_n;

	/*
	 * Source-side mlx5_ib_ucontext.devx_uid (see
	 * mlx5_vfmig.proto::source_devx_uid). 0 means non-DEVX
	 * ucontext: GET_CONTEXT skips ADOPT_DEVX_UID. Non-zero
	 * means GET_CONTEXT must set MLX5_IB_ALLOC_UCTX_DEVX |
	 * ADOPT_DEVX_UID and pass adopt_devx_uid = source_devx_uid.
	 *
	 * Captured at vfmig_read_image() from the image entry,
	 * consumed by vfmig_ensure_cdev_open()'s GET_CONTEXT call
	 * (both static and dyn paths).
	 */
	uint32_t source_devx_uid;
};
static struct vfmig_restored_ctx *vfmig_restored_ctxs;

static struct vfmig_restored_vf *
vfmig_restored_vf_lookup(const char *pf_bdf, uint32_t vf_id)
{
	struct vfmig_restored_vf *p;

	for (p = vfmig_restored_vfs; p; p = p->next)
		if (p->vf_id == vf_id && !strcmp(p->pf_bdf, pf_bdf))
			return p;
	return NULL;
}

static struct vfmig_restored_ctx *
vfmig_ctx_lookup_by_source_path(const char *path)
{
	struct vfmig_restored_ctx *p;

	for (p = vfmig_restored_ctxs; p; p = p->next)
		if (!strcmp(p->source_cdev_path, path))
			return p;
	return NULL;
}

/* (moved to vf_image.c) */

/*
 * Drive ENABLE_MIGRATABLE + SET_TRACKED + LOAD_VHCA_STATE +
 * MARK_RESTORED on a single (pf_bdf, vf_id), reading the firmware
 * blob off @blob_path (relative to the CRIU image dir).
 *
 * ENABLE_MIGRATABLE and SET_TRACKED are idempotent per the kernel
 * UAPI -- the orchestrator may already have invoked them on the
 * destination VF, in which case the kernel returns 0 with no
 * firmware traffic and we just continue. Re-issuing them lets the
 * plugin tolerate "minimal-orchestrator" configurations where the
 * orchestrator only does sriov_numvfs + autoprobe.
 */
static int vfmig_load_one_vf(const char *pf_bdf, uint32_t vf_id,
			     const char *blob_path, uint64_t blob_size)
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

	snprintf(cdev_path, sizeof(cdev_path), "%s/%s",
		 MLX5_VFMIG_DEV_DIR, pf_bdf);
	cdev_fd = open(cdev_path, O_RDWR | O_CLOEXEC);
	if (cdev_fd < 0) {
		pr_perror("vfmig: open(%s)", cdev_path);
		return -1;
	}

	em.vf_id = vf_id;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_ENABLE_MIGRATABLE, &em)) {
		pr_perror("vfmig: ENABLE_MIGRATABLE pf=%s vf_id=%u",
			  pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}

	sttr.vf_id = vf_id;
	sttr.enable = 1;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_SET_TRACKED, &sttr)) {
		pr_perror("vfmig: SET_TRACKED pf=%s vf_id=%u",
			  pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}

	ls.vf_id = vf_id;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_LOAD_VHCA_STATE, &ls)) {
		pr_perror("vfmig: LOAD_VHCA_STATE pf=%s vf_id=%u",
			  pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}
	load_fd = ls.load_fd;

	img_dir = criu_get_image_dir();
	blob_fd = openat(img_dir, blob_path, O_RDONLY | O_CLOEXEC);
	if (blob_fd < 0) {
		pr_perror("vfmig: openat(image_dir/%s) for blob",
			  blob_path);
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
		for (w = 0; w < r; ) {
			ssize_t k = write(load_fd, buf + w, r - w);

			if (k <= 0) {
				pr_perror("vfmig: write(load_fd) pf=%s "
					  "vf_id=%u", pf_bdf, vf_id);
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
	 * Closing load_fd commits the staged blob (per UAPI: the
	 * driver doesn't issue any firmware command against the
	 * destination VHCA until close()). A failure here is
	 * meaningful -- it surfaces fsync()-equivalent errors in the
	 * blob's DMA pipeline.
	 */
	if (close(load_fd)) {
		pr_perror("vfmig: close(load_fd) pf=%s vf_id=%u",
			  pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}

	mr.vf_id = vf_id;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_MARK_RESTORED, &mr)) {
		pr_perror("vfmig: MARK_RESTORED pf=%s vf_id=%u",
			  pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}

	close(cdev_fd);
	pr_info("vfmig: loaded pf=%s vf_id=%u (%llu bytes)\n",
		pf_bdf, vf_id, (unsigned long long)total_written);
	return 0;
}

/*
 * Resolve a VF's PCI BDF on the current host from
 * (pf_bdf, vf_id) by reading the standard SR-IOV virtfn symlink.
 */
static int vfmig_resolve_vf_bdf(const char *pf_bdf, uint32_t vf_id,
				char *out, size_t outsz)
{
	char path[PATH_MAX], target[PATH_MAX];
	const char *base;
	ssize_t n;

	snprintf(path, sizeof(path),
		 "/sys/bus/pci/devices/%s/virtfn%u", pf_bdf, vf_id);
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
 * Set the VF's driver_override to mlx5_core and bind it. The
 * orchestrator left autoprobe disabled and the VF unbound; this is
 * the step that actually makes the kernel mlx5_core probe run
 * against the loaded VHCA blob.
 */
static int vfmig_driver_override_and_bind(const char *vf_bdf)
{
	char path[PATH_MAX];
	int fd;
	size_t bdf_len;

	snprintf(path, sizeof(path),
		 "/sys/bus/pci/devices/%s/driver_override", vf_bdf);
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

	snprintf(path, sizeof(path),
		 "/sys/bus/pci/drivers/mlx5_core/bind");
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
 * appear and contain at least one entry. mlx5_core probe is
 * asynchronous -- the bind() write returns as soon as the probe is
 * scheduled; the ibdev shows up some milliseconds later. Resolve
 * the dest ibdev (basename of the first directory entry) into
 * @out.
 */
static int vfmig_wait_for_dest_ibdev(const char *vf_bdf, char *out,
				     size_t outsz)
{
	char path[PATH_MAX];
	int tries = 100;
	DIR *d;
	struct dirent *de;

	snprintf(path, sizeof(path),
		 "/sys/bus/pci/devices/%s/infiniband", vf_bdf);

	while (tries-- > 0) {
		d = opendir(path);
		if (d) {
			while ((de = readdir(d)) != NULL) {
				if (de->d_name[0] == '.')
					continue;
				snprintf(out, outsz, "%s", de->d_name);
				closedir(d);
				pr_info("vfmig: dest ibdev for %s -> %s\n",
					vf_bdf, out);
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
 * Resolve dest cdev path for @ibdev by walking
 * /sys/class/infiniband_verbs/uverbs* /ibdev. Mirrors the rxe
 * plugin's resolution.
 */
static int vfmig_resolve_dest_cdev_path(const char *ibdev, char *out,
					size_t outsz)
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
		snprintf(path, sizeof(path),
			 "/sys/class/infiniband_verbs/%s/ibdev",
			 de->d_name);
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			continue;
		n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n <= 0)
			continue;
		buf[n] = '\0';
		if (n > 0 && buf[n - 1] == '\n')
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
 * Lazy open of the destination uverbs cdev for a per-context cache
 * entry. Idempotent: if c->dest_cdev_fd is already a live fd, return
 * it unchanged.
 *
 * Runs under whichever process the caller is in -- specifically, the
 * per-task restore helpers spawned by criu/files.c that don't share
 * fdtables with criu main (post c7395f4cb). Because criu's helper
 * setup_newborn_fds calls close_old_fds() on every fork, fds opened
 * in init(RESTORE) (criu main) are already gone by the time
 * UPDATE_VMA_MAP / OPEN_UVERBS_CDEV run, so we re-open here in the
 * helper's own fdtable. Each helper that calls into the plugin gets
 * its own copy of the fd; the snapshot bytes (read-only after init)
 * are forked-in unchanged.
 *
 * On success c->dest_cdev_fd holds an O_RDWR | O_CLOEXEC fd whose
 * underlying struct file has its ucontext seeded by RESTORE_UCONTEXT
 * (static path) or RESTORE_DYN_UARS (dyn path). The hooks dup() this
 * fd before handing it back to criu so c->dest_cdev_fd survives even
 * after criu installs the workload's fd into the restored task and
 * implicitly closes its own copy.
 *
 * Returns 0 on success, -1 on any failure (with c->dest_cdev_fd left
 * < 0 and the partial fd cleaned up, so a retry attempt is safe).
 */
/*
 * Park our long-lived helper-side cached fds at a high fd number so
 * they don't collide with the fd slots the workload is about to be
 * restored into. criu/util.c uses fcntl(F_DUPFD, want) and treats
 * "the requested slot is occupied" as a hard error -- so if open()
 * lands our cdev at fd 3 and the workload's UverbsFileEntry id 0x1b
 * also needs fd 3, the install of the workload's fd fails with
 * "fd 3 already in use". 1024 is comfortably above any plausible
 * workload's small-numbered fd table; F_DUPFD won't go there because
 * F_DUPFD picks the lowest free slot. CLOEXEC is preserved.
 */
#define VFMIG_CACHED_FD_FLOOR 1024

static int vfmig_park_fd_high(int fd)
{
	int hi = fcntl(fd, F_DUPFD_CLOEXEC, VFMIG_CACHED_FD_FLOOR);

	if (hi < 0) {
		pr_perror("vfmig: F_DUPFD_CLOEXEC(%d, >=%d)",
			  fd, VFMIG_CACHED_FD_FLOOR);
		return -1;
	}
	close(fd);
	return hi;
}

static int vfmig_ensure_cdev_open(struct vfmig_restored_ctx *c)
{
	int fd, rc;

	if (c->dest_cdev_fd >= 0)
		return 0;

	fd = open(c->dest_cdev_path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("vfmig: open(%s) for ctxn=%u",
			  c->dest_cdev_path, c->source_ctxn);
		return -1;
	}

	if (!c->is_dyn) {
		/*
		 * Static (lib_uar_dyn=false) restore path. GET_CONTEXT
		 * mirrors the source's resolved (lib_caps,
		 * total_bfregs, ll_bfregs, max_cqe_version) verbatim
		 * so the destination's mlx5_ib_alloc_ucontext computes
		 * a meta that bitwise-matches the source's;
		 * RESTORE_UCONTEXT enforces equality with -EINVAL.
		 */
		const struct mlx5_ib_vfmig_ucontext_meta_local *m = &c->meta;
		uint32_t flags = MLX5_IB_ALLOC_UCTX_VFMIG_RESTORE;

		/*
		 * v0 limitation: DEVX adoption is unworkable on current
		 * mlx5 FW. LOAD_VHCA_STATE preserves the FW
		 * next_free_uctx counter but NOT the uctx registration
		 * table -- the source's devx_uid is unregistered on the
		 * destination post-LOAD, so re-claiming it via
		 * MLX5_IB_ALLOC_UCTX_ADOPT_DEVX_UID lands on a uid that
		 * FW will reject with "unknown uid" on every subsequent
		 * CREATE_MKEY/CREATE_QP. See kernel commits
		 * 73c76f299c01 ("RDMA/mlx5: mark ADOPT_DEVX_UID
		 * vestigial; rewrite restore_pd pr_warn") and
		 * a10dc00106a1 ("mlx5_vfmig design: record DEVX-
		 * adoption blind spot in S3b"), and the DEVX-source
		 * matrix in tools/testing/mlx5_vfmig/uobject_restore/
		 * pd_adopt/test_pd_adopt.sh.
		 *
		 * Until either FW gains uctx-state preservation or we
		 * wire a fresh-uctx-with-PD-rebind path on the dest,
		 * the destination ucontext is opened WITHOUT DEVX and
		 * all adopted resources live under uid=0
		 * (host-privileged) -- the only lane that survives
		 * LOAD_VHCA_STATE. DEVX features (mlx5dv_*) are
		 * unavailable to the restored process; basic verbs
		 * work. c->source_devx_uid stays in the image for
		 * diagnostics but is intentionally not consumed here.
		 */
		rc = vfmig_send_get_context_v2(
			fd, flags,
			m->lib_caps, m->total_num_bfregs,
			m->num_low_latency_bfregs, m->cqe_version,
			/* adopt_devx_uid */ 0);
		if (rc) {
			pr_err("vfmig: GET_CONTEXT(VFMIG_RESTORE, static) "
			       "on %s ctxn=%u failed: %d (%s) "
			       "[source_devx_uid=%u (image-only, not "
			       "consumed at restore)]\n",
			       c->dest_cdev_path, c->source_ctxn,
			       rc, strerror(-rc), c->source_devx_uid);
			close(fd);
			return -1;
		}

		rc = vfmig_restore_uctx(fd, c->uar_table, c->uar_n,
					c->bfreg_count, c->bfreg_n, m);
		if (rc) {
			pr_err("vfmig: RESTORE_UCONTEXT on %s ctxn=%u "
			       "failed: %d (%s)\n",
			       c->dest_cdev_path, c->source_ctxn,
			       rc, strerror(-rc));
			close(fd);
			return -1;
		}

		/*
		 * Bitwise sanity: re-QUERY and confirm sys_pages[]
		 * matches. A divergence here means RESTORE was
		 * accepted but didn't actually seed sys_pages[].
		 */
		{
			struct mlx5_ib_vfmig_ucontext_meta_local meta_b = {};
			uint32_t *uar_b = NULL, *cnt_b = NULL;
			size_t uar_bn = 0, cnt_bn = 0;
			int qrc;

			qrc = vfmig_snapshot_uctx(fd, &meta_b,
						  &uar_b, &uar_bn,
						  &cnt_b, &cnt_bn);
			if (qrc) {
				pr_err("vfmig: post-restore re-QUERY on %s "
				       "ctxn=%u failed: %d (%s)\n",
				       c->dest_cdev_path, c->source_ctxn,
				       qrc, strerror(-qrc));
				close(fd);
				return -1;
			}
			if (memcmp(&meta_b, m, sizeof(*m)) != 0 ||
			    uar_bn != c->uar_n ||
			    memcmp(uar_b, c->uar_table,
				   c->uar_n * sizeof(*uar_b)) != 0) {
				pr_err("vfmig: post-restore re-QUERY on %s "
				       "ctxn=%u diverged from snapshot\n",
				       c->dest_cdev_path, c->source_ctxn);
				free(uar_b);
				free(cnt_b);
				close(fd);
				return -1;
			}
			free(uar_b);
			free(cnt_b);
			pr_info("vfmig: post-restore re-QUERY ctxn=%u "
				"(static): bitwise match (num_sys_pages="
				"%zu)\n", c->source_ctxn, c->uar_n);
		}
	} else {
		/*
		 * Dyn (lib_uar_dyn=true) restore path. The kernel's
		 * RESTORE_DYN_UARS handler gates only on the destination
		 * being lib_uar_dyn=true and vfmig_restore_pending; no
		 * per-field cross-check. We open with libmlx5-default
		 * payload values + DYN_UAR cap and let the alloc path's
		 * skip-allocate-uars branch leave sys_pages[]
		 * uninitialized + UAR uobject list empty for
		 * RESTORE_DYN_UARS to seed.
		 */
		uint32_t flags = MLX5_IB_ALLOC_UCTX_VFMIG_RESTORE;

		/*
		 * v0 limitation: DEVX adoption is unworkable on current
		 * mlx5 FW (see static-path comment above for the full
		 * empirical chain and kernel commit refs). lib_uar_dyn=
		 * true is the libmlx5 default and silently implies
		 * DEVX on the source, so dyn-mode source ucontexts
		 * commonly have source_devx_uid != 0. We still open
		 * the destination WITHOUT DEVX and let restored
		 * resources live under uid=0; downstream verbs that
		 * don't depend on DEVX continue to work.
		 */
		rc = vfmig_send_get_context_v2(
			fd, flags,
			MLX5_LIB_CAP_4K_UAR | MLX5_LIB_CAP_DYN_UAR,
			/* total_num_bfregs */ 8,
			/* num_low_latency_bfregs */ 0,
			/* max_cqe_version */ 1,
			/* adopt_devx_uid */ 0);
		if (rc) {
			pr_err("vfmig: GET_CONTEXT(VFMIG_RESTORE|DYN_UAR) "
			       "on %s ctxn=%u failed: %d (%s) "
			       "[source_devx_uid=%u (image-only, not "
			       "consumed at restore)]\n",
			       c->dest_cdev_path, c->source_ctxn,
			       rc, strerror(-rc), c->source_devx_uid);
			close(fd);
			return -1;
		}

		rc = vfmig_restore_dyn_uars(fd, c->dyn_records, c->dyn_n);
		if (rc) {
			pr_err("vfmig: RESTORE_DYN_UARS(%zu) on %s ctxn=%u "
			       "failed: %d (%s)\n",
			       c->dyn_n, c->dest_cdev_path,
			       c->source_ctxn, rc, strerror(-rc));
			close(fd);
			return -1;
		}

		/*
		 * Bitwise sanity by handle (record order isn't
		 * guaranteed -- the kernel emits in
		 * ufile->uobjects iteration order, which RESTORE
		 * mutates as it prepends each new uobj).
		 */
		{
			struct mlx5_ib_vfmig_dyn_uar_record_local *recs_b = NULL;
			size_t recs_bn = 0;
			int qrc;
			size_t i_a;
			bool ok = true;

			qrc = vfmig_snapshot_dyn_uars(fd, &recs_b, &recs_bn);
			if (qrc) {
				pr_err("vfmig: post-restore QUERY_DYN_UARS "
				       "on %s ctxn=%u failed: %d (%s)\n",
				       c->dest_cdev_path, c->source_ctxn,
				       qrc, strerror(-qrc));
				close(fd);
				return -1;
			}
			if (recs_bn != c->dyn_n) {
				pr_err("vfmig: post-restore QUERY_DYN_UARS "
				       "on %s ctxn=%u count mismatch: got "
				       "%zu, expected %zu\n",
				       c->dest_cdev_path, c->source_ctxn,
				       recs_bn, c->dyn_n);
				free(recs_b);
				close(fd);
				return -1;
			}
			for (i_a = 0; ok && i_a < c->dyn_n; i_a++) {
				const struct mlx5_ib_vfmig_dyn_uar_record_local
					*a = &c->dyn_records[i_a];
				size_t i_b;
				const struct mlx5_ib_vfmig_dyn_uar_record_local
					*b = NULL;

				for (i_b = 0; i_b < recs_bn; i_b++) {
					if (recs_b[i_b].handle == a->handle) {
						b = &recs_b[i_b];
						break;
					}
				}
				if (!b ||
				    b->uar_index   != a->uar_index ||
				    b->mmap_offset != a->mmap_offset ||
				    b->alloc_type  != a->alloc_type) {
					pr_err("vfmig: post-restore dyn "
					       "record drift on %s ctxn=%u "
					       "handle=%u\n",
					       c->dest_cdev_path,
					       c->source_ctxn, a->handle);
					ok = false;
				}
			}
			free(recs_b);
			if (!ok) {
				close(fd);
				return -1;
			}
			pr_info("vfmig: post-restore re-QUERY ctxn=%u "
				"(dyn): bitwise match (records=%zu)\n",
				c->source_ctxn, c->dyn_n);
		}
	}

	/*
	 * Move the cached fd up to the high range so the workload's
	 * fd-install pass at criu/util.c doesn't trip on us occupying
	 * the slot it wants for this same uverbsfd.
	 */
	fd = vfmig_park_fd_high(fd);
	if (fd < 0)
		return -1;

	c->dest_cdev_fd = fd;
	pr_info("vfmig: lazy-opened ctxn=%u dest_cdev=%s -> dest_fd=%d "
		"(parked above %d)\n",
		c->source_ctxn, c->dest_cdev_path, fd,
		VFMIG_CACHED_FD_FLOOR - 1);
	return 0;
}

int vfmig_restore_init_all_vfs(void)
{
	Mlx5VfmigStateEntry **entries = NULL;
	size_t n_entries = 0, i;

	if (vfmig_read_image(&entries, &n_entries))
		return -1;
	if (n_entries == 0)
		return 0;

	pr_info("vfmig: restore: %zu state entries to load\n", n_entries);

	for (i = 0; i < n_entries; i++) {
		Mlx5VfmigStateEntry *e = entries[i];
		struct vfmig_restored_vf *v;
		char vf_bdf[64], dest_ibdev[64];
		char dest_cdev_path[PATH_MAX];

		if (vfmig_restored_vf_lookup(e->pf_bdf, e->vf_id))
			continue;

		if (vfmig_load_one_vf(e->pf_bdf, e->vf_id,
				      e->blob_path, e->blob_size))
			goto err;
		if (vfmig_resolve_vf_bdf(e->pf_bdf, e->vf_id,
					 vf_bdf, sizeof(vf_bdf)))
			goto err;
		if (vfmig_driver_override_and_bind(vf_bdf))
			goto err;
		if (vfmig_wait_for_dest_ibdev(vf_bdf, dest_ibdev,
					      sizeof(dest_ibdev)))
			goto err;
		if (vfmig_resolve_dest_cdev_path(dest_ibdev,
						 dest_cdev_path,
						 sizeof(dest_cdev_path)))
			goto err;

		v = calloc(1, sizeof(*v));
		if (!v)
			goto err;
		snprintf(v->pf_bdf, sizeof(v->pf_bdf), "%s", e->pf_bdf);
		v->vf_id = e->vf_id;
		snprintf(v->vf_bdf, sizeof(v->vf_bdf), "%s", vf_bdf);
		snprintf(v->dest_ibdev, sizeof(v->dest_ibdev), "%s",
			 dest_ibdev);
		snprintf(v->dest_cdev_path, sizeof(v->dest_cdev_path),
			 "%s", dest_cdev_path);
		v->next = vfmig_restored_vfs;
		vfmig_restored_vfs = v;

		pr_info("vfmig: restored VF: pf=%s vf_id=%u vf_bdf=%s "
			"dest_ibdev=%s dest_cdev=%s\n",
			v->pf_bdf, v->vf_id, v->vf_bdf, v->dest_ibdev,
			v->dest_cdev_path);
	}

	for (i = 0; i < n_entries; i++) {
		Mlx5VfmigStateEntry *e = entries[i];
		struct vfmig_restored_vf *v;
		struct vfmig_restored_ctx *c;

		v = vfmig_restored_vf_lookup(e->pf_bdf, e->vf_id);
		if (!v) {
			pr_err("vfmig: restored_vf lookup miss for "
			       "ctxn=%u\n", e->ctxn);
			goto err;
		}

		if (vfmig_ctx_lookup_by_source_path(e->source_cdev_path)) {
			pr_err("vfmig: multiple state entries reference "
			       "source cdev path %s -- multi-ctxn-per-VF "
			       "restore is not supported in v0\n",
			       e->source_cdev_path);
			goto err;
		}

		/*
		 * Validate uctx snapshot presence before opening any
		 * fd. The image must carry exactly one of:
		 *
		 *   - static-mode snapshot (uctx_meta + uctx_uar_table,
		 *     plus optional uctx_bfreg_count): source ucontext
		 *     was opened in lib_uar_dyn=false mode (older
		 *     libmlx5 / static-UAR test holders).
		 *
		 *   - dyn-mode snapshot (uctx_dyn_uar_records): source
		 *     ucontext was opened in libmlx5's default
		 *     lib_uar_dyn=true mode.
		 *
		 * An image with neither was dumped before Step 3 landed;
		 * refuse here rather than issuing a flagless GET_CONTEXT
		 * that would EINVAL downstream and leave the destination
		 * VHCA half-initialized. An image carrying both is a
		 * structural bug -- the dump fork enforces exactly-one
		 * by construction.
		 */
		{
			bool has_static = e->has_uctx_meta &&
					  e->has_uctx_uar_table;
			bool has_dyn    = e->has_uctx_dyn_uar_records;

			if (!has_static && !has_dyn) {
				pr_err("vfmig: image entry ctxn=%u missing "
				       "uctx snapshot (static_present=%d "
				       "dyn_present=%d) -- image predates "
				       "VFMIG_RESTORE support and is not "
				       "restorable; re-dump with a current "
				       "criu build\n",
				       e->ctxn, has_static, has_dyn);
				goto err;
			}
			if (has_static && has_dyn) {
				pr_err("vfmig: image entry ctxn=%u carries "
				       "BOTH static and dyn uctx snapshots "
				       "-- malformed image\n", e->ctxn);
				goto err;
			}
			if (has_static &&
			    e->uctx_meta.len !=
				sizeof(struct mlx5_ib_vfmig_ucontext_meta_local)) {
				pr_err("vfmig: image entry ctxn=%u static "
				       "uctx_meta length=%zu != %zu\n",
				       e->ctxn, e->uctx_meta.len,
				       sizeof(struct mlx5_ib_vfmig_ucontext_meta_local));
				goto err;
			}
			if (has_dyn &&
			    e->uctx_dyn_uar_records.len %
				sizeof(struct mlx5_ib_vfmig_dyn_uar_record_local)) {
				pr_err("vfmig: image entry ctxn=%u dyn "
				       "records length=%zu not a multiple "
				       "of record size %zu\n", e->ctxn,
				       e->uctx_dyn_uar_records.len,
				       sizeof(struct mlx5_ib_vfmig_dyn_uar_record_local));
				goto err;
			}
		}

		/*
		 * Stash the snapshot bytes into the per-ctx cache and
		 * stop. The cdev open + GET_CONTEXT + RESTORE_{UCONTEXT,
		 * DYN_UARS} happen lazily on first consumer
		 * (vfmig_ensure_cdev_open, called from UPDATE_VMA_MAP /
		 * OPEN_UVERBS_CDEV in the per-task helper). Doing the
		 * fd work here, in criu main, would lose the fd to
		 * close_old_fds() in every newborn helper fdtable --
		 * see the cache struct's docstring above.
		 */
		c = calloc(1, sizeof(*c));
		if (!c)
			goto err;
		c->source_ctxn = e->ctxn;
		snprintf(c->source_ibdev, sizeof(c->source_ibdev), "%s",
			 e->ibdev);
		snprintf(c->source_cdev_path, sizeof(c->source_cdev_path),
			 "%s", e->source_cdev_path);
		snprintf(c->dest_cdev_path, sizeof(c->dest_cdev_path),
			 "%s", v->dest_cdev_path);
		c->dest_cdev_fd = -1;
		/*
		 * source_devx_uid is optional on the wire (zero default
		 * means "non-DEVX ucontext"). Pre-extension images
		 * decode with has_source_devx_uid=0 and we leave
		 * c->source_devx_uid at 0, which makes
		 * vfmig_ensure_cdev_open's GET_CONTEXT skip
		 * ADOPT_DEVX_UID -- equivalent to the legacy v0
		 * behaviour and correct for non-DEVX images.
		 */
		c->source_devx_uid = e->has_source_devx_uid ?
			e->source_devx_uid : 0;

		if (e->has_uctx_meta) {
			const struct mlx5_ib_vfmig_ucontext_meta_local *m =
				(const void *)e->uctx_meta.data;
			size_t uar_n = e->uctx_uar_table.len /
				sizeof(uint32_t);
			size_t cnt_n = e->has_uctx_bfreg_count ?
				(e->uctx_bfreg_count.len / sizeof(uint32_t))
				: 0;

			if (uar_n != m->num_sys_pages) {
				pr_err("vfmig: image entry ctxn=%u "
				       "uar_table len mismatch: %zu != "
				       "meta.num_sys_pages=%u\n",
				       e->ctxn, uar_n, m->num_sys_pages);
				free(c);
				goto err;
			}
			if (cnt_n && cnt_n != m->total_num_bfregs) {
				pr_err("vfmig: image entry ctxn=%u "
				       "bfreg_count len mismatch: %zu != "
				       "meta.total_num_bfregs=%u\n",
				       e->ctxn, cnt_n,
				       m->total_num_bfregs);
				free(c);
				goto err;
			}

			c->is_dyn = false;
			c->meta = *m;
			c->uar_n = uar_n;
			c->uar_table = malloc(e->uctx_uar_table.len);
			if (!c->uar_table) {
				free(c);
				goto err;
			}
			memcpy(c->uar_table, e->uctx_uar_table.data,
			       e->uctx_uar_table.len);
			if (cnt_n) {
				c->bfreg_n = cnt_n;
				c->bfreg_count = malloc(e->uctx_bfreg_count.len);
				if (!c->bfreg_count) {
					free(c->uar_table);
					free(c);
					goto err;
				}
				memcpy(c->bfreg_count,
				       e->uctx_bfreg_count.data,
				       e->uctx_bfreg_count.len);
			}
		} else {
			size_t recs_n = e->uctx_dyn_uar_records.len /
				sizeof(struct mlx5_ib_vfmig_dyn_uar_record_local);

			c->is_dyn = true;
			c->dyn_n = recs_n;
			if (recs_n) {
				c->dyn_records =
					malloc(e->uctx_dyn_uar_records.len);
				if (!c->dyn_records) {
					free(c);
					goto err;
				}
				memcpy(c->dyn_records,
				       e->uctx_dyn_uar_records.data,
				       e->uctx_dyn_uar_records.len);
			}
		}

		c->next = vfmig_restored_ctxs;
		vfmig_restored_ctxs = c;
		pr_info("vfmig: cached ctxn=%u source_ibdev=%s "
			"source_cdev=%s dest_cdev=%s mode=%s "
			"source_devx_uid=%u (snapshot deferred-open)\n",
			c->source_ctxn, c->source_ibdev,
			c->source_cdev_path, c->dest_cdev_path,
			c->is_dyn ? "dyn-UAR" : "static",
			c->source_devx_uid);
		continue;
	}

	for (i = 0; i < n_entries; i++)
		mlx5_vfmig_state_entry__free_unpacked(entries[i], NULL);
	free(entries);
	return 0;

err:
	if (entries) {
		for (i = 0; i < n_entries; i++)
			mlx5_vfmig_state_entry__free_unpacked(entries[i],
							      NULL);
		free(entries);
	}
	vfmig_restore_fini_close_all();
	return -1;
}

void vfmig_restore_fini_close_all(void)
{
	struct vfmig_restored_ctx *c, *cn;
	struct vfmig_restored_vf *v, *vn;

	for (c = vfmig_restored_ctxs; c; c = cn) {
		cn = c->next;
		if (c->dest_cdev_fd >= 0)
			close(c->dest_cdev_fd);
		free(c->uar_table);
		free(c->bfreg_count);
		free(c->dyn_records);
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
 * UPDATE_VMA_MAP hook: dispatch by source cdev path.
 *
 * CRIU's reg_file_entry records the dumpee's struct file path
 * verbatim; for our UAR/clock/NC mappings that's e.g.
 * "/dev/infiniband/uverbs2". We dispatch off that string into the
 * per-context cache populated by init(RESTORE), and hand back a
 * dup() of the cached fd plus the source's pgoff verbatim. The
 * pgoff replay is good enough for v0 -- multi-VF dumps with
 * pgoff-aliasing-across-VFs (and the kernel's UAR-table ioctl that
 * makes that disambiguation possible) is the next step.
 *
 * Returns 1 on a successful claim (CRIU's UPDATE_VMA_MAP convention),
 * -ENOTSUP on a non-claim (let other plugins or CRIU's default path
 * try), -1 on a hard error.
 */
int rdma_mlx5_vfmig_plugin_update_vma_map(const char *path,
						 const uint64_t addr,
						 const uint64_t old_pgoff,
						 uint64_t *new_pgoff,
						 int *plugin_fd)
{
	struct vfmig_restored_ctx *c;
	int dup_fd;

	(void)addr;

	if (!vfmig_active)
		return -ENOTSUP;

	c = vfmig_ctx_lookup_by_source_path(path);
	if (!c)
		return -ENOTSUP;

	if (vfmig_ensure_cdev_open(c))
		return -1;

	dup_fd = dup(c->dest_cdev_fd);
	if (dup_fd < 0) {
		pr_perror("vfmig: dup(dest_cdev_fd=%d) for path=%s",
			  c->dest_cdev_fd, path);
		return -1;
	}

	*new_pgoff = old_pgoff;
	*plugin_fd = dup_fd;
	pr_info("vfmig: update_vma_map path=%s pgoff=%#llx -> "
		"dest_fd=%d (dup of cached)\n",
		path, (unsigned long long)old_pgoff, dup_fd);
	return 1;
}

/*
 * RDMA_OPEN_UVERBS_CDEV hook: dispatch by source ctxn (the precise
 * key the dispatcher hands us via uvfe). Hand back a dup() of the
 * cached fd. The cached fd already has GET_CONTEXT issued, so the
 * uniform contract documented in criu/rdma.c uverbsfd_open() is
 * upheld.
 */
int
rdma_mlx5_vfmig_plugin_open_uverbs_cdev(const UverbsFileEntry *uvfe)
{
	const UverbsFileEntry *u = (const UverbsFileEntry *)uvfe;
	struct vfmig_restored_ctx *p, *c = NULL;
	int dup_fd;

	if (!vfmig_active) {
		pr_err("vfmig: open_uverbs_cdev called but plugin "
		       "inactive (no tracked VFs at restore-side init?)\n");
		return -1;
	}

	if (!u->has_ctxn) {
		pr_err("vfmig: open_uverbs_cdev: uvfe has no ctxn -- "
		       "image too old\n");
		return -1;
	}

	for (p = vfmig_restored_ctxs; p; p = p->next) {
		if (p->source_ctxn == u->ctxn) {
			c = p;
			break;
		}
	}
	if (!c) {
		pr_err("vfmig: open_uverbs_cdev: no cached ctx for "
		       "uvfe.ctxn=%u ibdev=%s\n", u->ctxn,
		       u->ib_dev ?: "?");
		return -1;
	}

	if (vfmig_ensure_cdev_open(c))
		return -1;

	dup_fd = dup(c->dest_cdev_fd);
	if (dup_fd < 0) {
		pr_perror("vfmig: dup(dest_cdev_fd=%d) for ctxn=%u",
			  c->dest_cdev_fd, u->ctxn);
		return -1;
	}

	pr_info("vfmig: open_uverbs_cdev: ctxn=%u -> dest_fd=%d (dup of "
		"cached fd=%d)\n", u->ctxn, dup_fd, c->dest_cdev_fd);
	return dup_fd;
}

/*
 * RDMA_RESTORE_UOBJ_CQ_UHW_PACK hook (mlx5).
 *
 * Reads the source-side 32B mlx5_ib_restore_cq_req packed at dump
 * time into e->plugin_blob (see rdma_mlx5_vfmig_plugin_dump_uobj_cq)
 * and hands core a malloc()'d copy as UHW_IN. mlx5_ib_restore_cq
 * is configured to require exactly sizeof(req) UHW_IN and reject
 * any UHW_OUT (drivers/infiniband/hw/mlx5/main.c::mlx5_ib_restore_cq:
 * udata->inlen < sizeof(req) || udata->outlen != 0 -> -EINVAL), so
 * we leave uhw->out_buf NULL.
 *
 * Allocator contract: malloc() here, free() in core after the
 * ioctl + (optional) UHW_VERIFY round-trip. We do not register
 * UHW_VERIFY since UHW_OUT is empty -- the kernel adopts cqn /
 * cqe_size / buf_addr / db_addr verbatim; a successful ioctl is
 * itself the byte-equality witness for those fields, and the
 * core RESP_CQE echo is verified by the criu/rdma per-CQ caller.
 */
int rdma_mlx5_vfmig_plugin_restore_uobj_cq_uhw_pack(const RdmaUobjEntry *e,
						    struct rdma_uhw_spec *uhw)
{
	const ProtobufCBinaryData *blob;

	if (!e || !uhw)
		return -EINVAL;
	if (!e->has_plugin_blob || e->plugin_blob.len == 0) {
		pr_err("vfmig: RESTORE_CQ_UHW_PACK called for ufile_handle=%u "
		       "with empty plugin_blob; image is missing the "
		       "32B mlx5_ib_restore_cq_req captured at dump via "
		       "MLX5_IB_METHOD_VFMIG_QUERY_CQ. Re-dump against a "
		       "kernel that has the VFMIG_QUERY_CQ method and a "
		       "CRIU plugin build that wires it.\n",
		       e->has_ufile_handle ? e->ufile_handle : 0);
		return -EINVAL;
	}

	blob = &e->plugin_blob;
	if (blob->len != sizeof(struct mlx5_ib_restore_cq_req_local)) {
		pr_err("vfmig: RESTORE_CQ_UHW_PACK plugin_blob len=%zu "
		       "ufile_handle=%u, expected %zu (mlx5_ib_restore_cq_req)\n",
		       blob->len,
		       e->has_ufile_handle ? e->ufile_handle : 0,
		       sizeof(struct mlx5_ib_restore_cq_req_local));
		return -EINVAL;
	}

	uhw->in_buf = malloc(blob->len);
	if (!uhw->in_buf) {
		pr_err("vfmig: RESTORE_CQ_UHW_PACK out of memory "
		       "(%zu bytes)\n", blob->len);
		return -ENOMEM;
	}
	memcpy(uhw->in_buf, blob->data, blob->len);
	uhw->in_len = blob->len;
	/* mlx5_ib_restore_cq rejects any UHW_OUT -- leave out_buf NULL. */
	uhw->out_buf = NULL;
	uhw->out_len = 0;
	return 0;
}

/*
 * Driver-private UHW for UVERBS_METHOD_RESTORE_MR (mlx5).
 * mlx5_ib_restore_mr requires a struct mlx5_ib_restore_mr_req
 * carrying the source's FW mkey_index so it can adopt the
 * destination-side mkey that LOAD_VHCA_STATE preserved (Model A,
 * no FW round-trip). Without this UHW the kernel handler fails at
 * its udata->inlen check before any useful work happens.
 *
 * The mlx5 invariant is lkey == rkey == (mkey_index << 8) |
 * variant_byte. We derive mkey_index from the dumped lkey rather
 * than carrying it through plugin_blob: the source lkey is already
 * captured generically in e->mr->lkey by the dump-side per-MR
 * walker (rxe and mlx5 both populate it). The kernel cross-checks
 * (lkey_hint >> 8) == req.mkey_index AND lkey_hint == rkey_hint
 * and rejects with -EINVAL on mismatch -- defense-in-depth that
 * catches a CRIU bug shipping a restrack id where the FW
 * mkey_index was expected.
 *
 * No UHW_OUT is needed (mlx5_ib_restore_mr writes nothing through
 * udata); we leave uhw->out_buf NULL and don't register a VERIFY
 * hook for MR.
 *
 * Pre-pie placement: this hook runs in CRIU master at
 * rdma_prepare_rdma_mrs() time, NOT inside the pie restorer
 * (plugins aren't available there -- see criu-plugin.h block on
 * the contract). Core memcpy's the bytes we malloc here into the
 * rst_rdma_mr.uhw_in_buf static buffer and free()s our copy
 * before pie hand-off.
 */
int rdma_mlx5_vfmig_plugin_restore_uobj_mr_uhw_pack(const RdmaUobjEntry *e,
						    struct rdma_uhw_spec *uhw)
{
	struct mlx5_ib_restore_mr_req_local req = {};
	const RdmaMrAttrs *mr;

	if (!e || !uhw)
		return -EINVAL;
	if (e->type != R3_UOBJ_TYPE__R3UT_MR) {
		pr_err("vfmig: RESTORE_MR_UHW_PACK called for non-MR uobject "
		       "(type=%d ufile_handle=%u); core dispatch bug\n",
		       e->type,
		       e->has_ufile_handle ? e->ufile_handle : 0);
		return -EINVAL;
	}
	mr = e->mr;
	if (!mr || !mr->has_lkey) {
		pr_err("vfmig: RESTORE_MR_UHW_PACK plugin_blob missing lkey "
		       "for ufile_handle=%u; image is missing the "
		       "RES_LKEY captured at dump via NLDEV. Re-dump "
		       "against a current kernel.\n",
		       e->has_ufile_handle ? e->ufile_handle : 0);
		return -EINVAL;
	}

	req.mkey_index = mr->lkey >> 8;
	/* reserved / reserved2 stay zero from designated init */

	uhw->in_buf = malloc(sizeof(req));
	if (!uhw->in_buf) {
		pr_err("vfmig: RESTORE_MR_UHW_PACK out of memory "
		       "(%zu bytes)\n", sizeof(req));
		return -ENOMEM;
	}
	memcpy(uhw->in_buf, &req, sizeof(req));
	uhw->in_len = sizeof(req);
	uhw->out_buf = NULL;
	uhw->out_len = 0;
	return 0;
}
