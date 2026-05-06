/*
 * CRIU RDMA mlx5_sriov_vfmig plugin -- presence detection.
 *
 * Companion to plugins/rdma/rxe/. At criu startup the plugin walks
 * /dev/mlx5_vfmig/, opens each per-PF char device, and asks the
 * MLX5_VFMIG_IOC_QUERY_VF ioctl which (if any) of that PF's VFs
 * currently have the host-driver "vfmig tracked" bit set. A VF is
 * eligible for save/restore through this plugin iff QUERY_VF reports
 * tracked=1 -- that's the same bit that gates the per-VF unmanaged
 * IOMMU domain + deterministic IOVA allocator on the destination, so
 * any VF without it cannot round-trip a SAVE/LOAD blob even if its
 * firmware-side migratable bit is set. See linux/mlx5_vfmig.h
 * (kernel UAPI doc on MLX5_VFMIG_IOC_QUERY_VF and
 * MLX5_VFMIG_IOC_SET_TRACKED) for the gory details.
 *
 * Like the rxe plugin in the previous commit, this is just presence
 * detection. No checkpoint/restore hooks are wired in here; the per-
 * context claim API and dump-time arbitration land in the next
 * commit. Activation state is process-local.
 *
 * Vendored UAPI header:
 *   The plugin compiles against plugins/rdma/mlx5_sriov_vfmig/uapi/
 *   linux/mlx5_vfmig.h, vendored from the kernel source. This avoids
 *   making criu's build depend on a bleeding-edge kernel header on
 *   every contributor's host. Pass MLX5_VFMIG_UAPI_INCLUDE=<dir> to
 *   the plugin's make to override the include search root (e.g.
 *   pointing at a local kernel tree's include/uapi/), useful when
 *   iterating on the kernel UAPI in parallel. The Makefile emits a
 *   warning at build time if the system header at
 *   /usr/include/linux/mlx5_vfmig.h exists and disagrees with the
 *   vendored copy, so drift is at least loud.
 */

#include "criu-log.h"
#include "criu-plugin.h"

#include "images/rdma_criu.pb-c.h"
#include "images/mlx5_vfmig.pb-c.h"
#include "images/uverbsfd.pb-c.h"

#include <linux/mlx5_vfmig.h>
#include <rdma/ib_user_ioctl_verbs.h>

#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_mlx5_vfmig_plugin: "

#define MLX5_VFMIG_DEV_DIR "/dev/mlx5_vfmig"
#define MLX5_VFMIG_IMG_NAME "mlx5_vfmig.img"

static bool vfmig_active = false;
static int  vfmig_tracked_vf_count = 0;
static int  vfmig_pf_count = 0;

/*
 * Per-dump deduplication cache.
 *
 * The mlx5 firmware SAVE_VHCA_STATE captures one blob per VF, not
 * per uverbs context. A process may legitimately hold several
 * contexts on the same VF (e.g. one per worker thread); without
 * deduplication we'd issue SAVE_VHCA_STATE multiple times against
 * the same VF and produce N copies of the same blob in the image
 * directory. Worse, the per-VF kernel SAVE session is exclusive
 * (-EBUSY on the second open), so every duplicate would fail.
 *
 * The cache is process-local (CRIU's lifetime) and is reset by
 * init() so a CRIU re-invocation starts fresh. Each entry remembers
 * the (pf_bdf, vf_id) tuple that already had its blob captured
 * during this dump, plus the per-VF state that the per-context
 * record needs (vhca_id, blob path, blob size). Subsequent contexts
 * on the same VF reuse this state.
 */
struct vfmig_saved_vf {
	struct vfmig_saved_vf *next;
	char pf_bdf[64];
	uint32_t vf_id;
	uint32_t vhca_id;
	char blob_path[PATH_MAX];
	uint64_t blob_size;
};
static struct vfmig_saved_vf *vfmig_saved_head = NULL;

static struct vfmig_saved_vf *
vfmig_saved_lookup(const char *pf_bdf, uint32_t vf_id)
{
	struct vfmig_saved_vf *p;

	for (p = vfmig_saved_head; p; p = p->next)
		if (p->vf_id == vf_id && !strcmp(p->pf_bdf, pf_bdf))
			return p;
	return NULL;
}

static void vfmig_saved_clear(void)
{
	struct vfmig_saved_vf *p, *n;

	for (p = vfmig_saved_head; p; p = n) {
		n = p->next;
		free(p);
	}
	vfmig_saved_head = NULL;
}

/*
 * Per-context dump-time queue.
 *
 * DUMP_UVERBS_CONTEXT runs once per uverbs cdev being dumped, while
 * SAVE_VHCA_STATE is per-VF firmware work and is the most invasive
 * thing this plugin does to the host. Decouple the two by having
 * the per-context hook just record (ctxn, ibdev, pf_bdf, vf_id)
 * onto this queue, and let fini(DUMP) drain it -- the kernel SAVE
 * is then the very last thing CRIU asks for, after every other
 * piece of dump work has either succeeded or surfaced a failure
 * the operator can act on without ever having touched the VF's
 * firmware. (See the cover-letter discussion of "fail early" vs.
 * "defer the most invasive thing".)
 */
struct vfmig_pending_ctx {
	struct vfmig_pending_ctx *next;
	uint32_t ctxn;
	char ibdev[64];
	char pf_bdf[64];
	uint32_t vf_id;
	/*
	 * Source-side cdev path the dumpee opened (resolved at dump
	 * time via readlink /proc/self/fd/<lfd>). Persisted into
	 * mlx5_vfmig_state_entry.source_cdev_path so the restore
	 * side's UPDATE_VMA_MAP can dispatch by source path.
	 */
	char source_cdev_path[PATH_MAX];
};
static struct vfmig_pending_ctx *vfmig_pending_head = NULL;

static int vfmig_pending_enqueue(uint32_t ctxn, const char *ibdev,
				 const char *pf_bdf, uint32_t vf_id,
				 const char *source_cdev_path)
{
	struct vfmig_pending_ctx *p = calloc(1, sizeof(*p));

	if (!p)
		return -1;
	p->ctxn = ctxn;
	snprintf(p->ibdev, sizeof(p->ibdev), "%s", ibdev);
	snprintf(p->pf_bdf, sizeof(p->pf_bdf), "%s", pf_bdf);
	p->vf_id = vf_id;
	snprintf(p->source_cdev_path, sizeof(p->source_cdev_path),
		 "%s", source_cdev_path);
	p->next = vfmig_pending_head;
	vfmig_pending_head = p;
	return 0;
}

static void vfmig_pending_clear(void)
{
	struct vfmig_pending_ctx *p, *n;

	for (p = vfmig_pending_head; p; p = n) {
		n = p->next;
		free(p);
	}
	vfmig_pending_head = NULL;
}

/*
 * Per-VF SAVE-failure cache.
 *
 * fini(DUMP) iterates the pending queue in arbitrary order. If
 * SAVE_VHCA_STATE fails for a given (pf_bdf, vf_id), every other
 * pending context against the same VF must be dropped too -- the
 * blob doesn't exist, so emitting a state entry referencing it
 * would leave the image internally inconsistent. Stash failed
 * tuples here so subsequent contexts on the same VF skip cleanly
 * without retrying the (now expensive and wedging) SAVE.
 */
struct vfmig_failed_vf {
	struct vfmig_failed_vf *next;
	char pf_bdf[64];
	uint32_t vf_id;
};
static struct vfmig_failed_vf *vfmig_failed_head = NULL;

static bool vfmig_failed_lookup(const char *pf_bdf, uint32_t vf_id)
{
	struct vfmig_failed_vf *p;

	for (p = vfmig_failed_head; p; p = p->next)
		if (p->vf_id == vf_id && !strcmp(p->pf_bdf, pf_bdf))
			return true;
	return false;
}

static void vfmig_failed_mark(const char *pf_bdf, uint32_t vf_id)
{
	struct vfmig_failed_vf *p = calloc(1, sizeof(*p));

	if (!p)
		return; /* best-effort; worst case is a redundant SAVE retry */
	snprintf(p->pf_bdf, sizeof(p->pf_bdf), "%s", pf_bdf);
	p->vf_id = vf_id;
	p->next = vfmig_failed_head;
	vfmig_failed_head = p;
}

static void vfmig_failed_clear(void)
{
	struct vfmig_failed_vf *p, *n;

	for (p = vfmig_failed_head; p; p = n) {
		n = p->next;
		free(p);
	}
	vfmig_failed_head = NULL;
}

/*
 * Probe one PF cdev. Returns the number of VFs on this PF that have
 * MLX5_VFMIG_IOC_SET_TRACKED { enable=1 } currently in effect, or -1
 * on a hard ioctl/open failure (which we report but treat as "no
 * tracked VFs from this PF" rather than as a fatal plugin error --
 * a misbehaving cdev should not poison criu startup).
 *
 * Discovery model: per the kernel UAPI doc on MLX5_VFMIG_IOC_QUERY_VF,
 * num_vfs is filled even when vf_id is out of range (the call returns
 * -ERANGE in that case but the output struct is still populated), so
 * one issuance with vf_id=0 tells us how many VFs to iterate over,
 * and a separate per-vf loop reads the @tracked bit. This is the
 * "iterate 0..num_vfs-1" pattern the kernel UAPI explicitly invites.
 */
static int probe_pf_cdev(const char *path)
{
	struct mlx5_vfmig_query_vf q;
	uint32_t num_vfs, vf;
	int fd, rc, tracked = 0;

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_warn("open(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}

	memset(&q, 0, sizeof(q));
	q.vf_id = 0;
	rc = ioctl(fd, MLX5_VFMIG_IOC_QUERY_VF, &q);
	if (rc != 0 && errno != ERANGE) {
		pr_warn("QUERY_VF(vf_id=0) on %s failed: %s\n", path,
			strerror(errno));
		close(fd);
		return -1;
	}

	num_vfs = q.num_vfs;
	if (rc == 0 && q.tracked)
		tracked++;

	for (vf = 1; vf < num_vfs; vf++) {
		struct mlx5_vfmig_query_vf qq;

		memset(&qq, 0, sizeof(qq));
		qq.vf_id = vf;
		if (ioctl(fd, MLX5_VFMIG_IOC_QUERY_VF, &qq) != 0) {
			pr_warn("QUERY_VF(vf_id=%u) on %s failed: %s\n", vf,
				path, strerror(errno));
			continue;
		}
		if (qq.tracked)
			tracked++;
	}

	pr_debug("%s: num_vfs=%u tracked=%d\n", path, num_vfs, tracked);
	close(fd);
	return tracked;
}

/* Forward declaration: drain is defined alongside the per-context dump
 * hook (after CLAIM and the SAVE helpers it depends on); fini() above
 * those needs to call it. */
static void vfmig_drain_pending_in_fini(void);

/*
 * Forward declarations for the restore-side eager-init block (defined
 * near the bottom of the file, alongside the new hook implementations).
 * init(RESTORE) reads mlx5_vfmig.img, drives ENABLE_MIGRATABLE +
 * SET_TRACKED + LOAD_VHCA_STATE + MARK_RESTORED + driver_override +
 * bind on each unique VF the image references, opens dest cdev fds
 * with criu_ib_uverbs_get_context() pre-issued, and caches them for
 * UPDATE_VMA_MAP / RDMA_OPEN_UVERBS_CDEV to dup() out later. fini
 * (RESTORE) closes the cached fds.
 */
static int vfmig_restore_init_all_vfs(void);
static void vfmig_restore_fini_close_all(void);

static int rdma_mlx5_vfmig_plugin_init(int stage)
{
	DIR *d;
	struct dirent *de;

	vfmig_active = false;
	vfmig_tracked_vf_count = 0;
	vfmig_pf_count = 0;
	vfmig_saved_clear();
	vfmig_pending_clear();
	vfmig_failed_clear();

	d = opendir(MLX5_VFMIG_DEV_DIR);
	if (!d) {
		/*
		 * No mlx5_vfmig kernel module loaded (or no PFs that
		 * advertise migration capability) is the common case
		 * on hosts without ConnectX-7 + this work-in-progress
		 * driver. Treat as inactive rather than as an error so
		 * dropping the .so into CRIU_LIBS_DIR is safe on any
		 * host. (cr_lib_load() turns non-zero init() into a
		 * fatal startup failure -- see criu/plugin.c.)
		 */
		pr_info("opendir(%s) failed: %s; assuming no mlx5_vfmig "
			"capability, plugin inactive (stage %d)\n",
			MLX5_VFMIG_DEV_DIR, strerror(errno), stage);
		return 0;
	}

	while ((de = readdir(d)) != NULL) {
		char path[PATH_MAX];
		int n;

		if (de->d_name[0] == '.')
			continue;

		snprintf(path, sizeof(path), "%s/%s", MLX5_VFMIG_DEV_DIR,
			 de->d_name);
		vfmig_pf_count++;
		n = probe_pf_cdev(path);
		if (n > 0)
			vfmig_tracked_vf_count += n;
	}

	closedir(d);

	if (vfmig_tracked_vf_count > 0) {
		vfmig_active = true;
		pr_info("active (stage %d): %d tracked VF(s) across %d PF(s)\n",
			stage, vfmig_tracked_vf_count, vfmig_pf_count);
	} else {
		pr_info("inactive (stage %d): %d PF cdev(s) probed, no "
			"tracked VFs\n",
			stage, vfmig_pf_count);
	}

	/*
	 * On the restore side, drive the per-VF restore dance up
	 * front -- before CRIU's VMA-restore phase asks UPDATE_VMA_
	 * MAP to remap UAR/clock/NC pages off our cdev fds.
	 *
	 * Why eagerly here rather than lazily in UPDATE_VMA_MAP /
	 * RDMA_OPEN_UVERBS_CDEV:
	 *
	 *   1. UPDATE_VMA_MAP runs during VMA restore (early) but
	 *      RDMA_OPEN_UVERBS_CDEV runs during fdtable restore
	 *      (later). Both need a fd whose kernel ucontext is
	 *      already established (mlx5_ib_mmap requires it for
	 *      UAR mappings; the kernel rejects a second
	 *      GET_CONTEXT on the same struct file). If we did the
	 *      LOAD + bind + open + GET_CONTEXT lazily in either
	 *      hook the first one to fire would have to know to
	 *      cache for the other -- doable, but messier than
	 *      doing it once up front.
	 *
	 *   2. LOAD_VHCA_STATE + MARK_RESTORED + bind is
	 *      irreversible host-side state. If anything in the
	 *      restore is going to fail, we want it to fail before
	 *      CRIU starts wiring the dumpee's address space back
	 *      together; that gives the operator a clean rollback
	 *      window (sriov_numvfs cycle to discard the
	 *      half-restored VF) without having half-mapped the
	 *      restored process's VMAs.
	 *
	 * If init(RESTORE) returns non-zero CRIU treats the plugin
	 * as failed-init and the entire restore aborts. That is the
	 * desired behaviour -- a restore that can't establish the
	 * VF state will not produce a working RDMA process anyway.
	 */
	if (stage == CR_PLUGIN_STAGE__RESTORE) {
		if (vfmig_restore_init_all_vfs())
			return -1;
	}

	return 0;
}

static void rdma_mlx5_vfmig_plugin_fini(int stage, int ret)
{
	/*
	 * Drain the pending SAVE queue at the very end of dump and
	 * only when the rest of CRIU's dump pipeline succeeded. If
	 * @ret != 0 the dump has already been declared lost
	 * upstream and there is no point firing SAVE_VHCA_STATE --
	 * the resulting blob would never be paired with an image
	 * the orchestrator could restore from, and we would be
	 * needlessly suspending VFs (KEEP_SUSPENDED is permanent
	 * until the orchestrator does an SR-IOV teardown). On the
	 * RESTORE side the queue is empty -- DUMP_UVERBS_CONTEXT is
	 * not invoked during restore -- so the drain is effectively
	 * skipped there too.
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP && ret == 0)
		vfmig_drain_pending_in_fini();

	/*
	 * On restore, close the per-context cdev fds the eager init
	 * cached. We do this unconditionally on RESTORE (success or
	 * failure): on success the dumpee's restored fdtable holds
	 * dup()s of these fds (handed back from RDMA_OPEN_UVERBS_
	 * CDEV / UPDATE_VMA_MAP), so closing the plugin's copies
	 * here doesn't disturb the restored process; on failure we
	 * still want to drop our own references rather than leak.
	 */
	if (stage == CR_PLUGIN_STAGE__RESTORE)
		vfmig_restore_fini_close_all();

	pr_info("fini (stage %d ret %d): was %s, %d tracked VF(s) across "
		"%d PF(s)\n",
		stage, ret, vfmig_active ? "active" : "inactive",
		vfmig_tracked_vf_count, vfmig_pf_count);
	vfmig_saved_clear();
	vfmig_pending_clear();
	vfmig_failed_clear();
}

/*
 * Resolve a /sys/.../device symlink under @sysfs_link_path to its
 * basename (the PCI BDF the symlink points at). Caller-supplied
 * @out is sized in @outsz. Returns 0 on success, -1 otherwise.
 *
 * Used to walk the chain
 *   /sys/class/infiniband/<ibdev>/device   ->  VF BDF
 *   /sys/bus/pci/devices/<vf>/physfn       ->  PF BDF
 * needed to map an ibdev to its owning mlx5 PF cdev.
 */
static int resolve_pci_bdf_via_symlink(const char *sysfs_link_path,
				       char *out, size_t outsz)
{
	char target[PATH_MAX];
	const char *base;
	ssize_t n;

	n = readlink(sysfs_link_path, target, sizeof(target) - 1);
	if (n <= 0)
		return -1;
	target[n] = '\0';
	base = strrchr(target, '/');
	snprintf(out, outsz, "%.*s", (int)(outsz - 1), base ? base + 1 : target);
	return 0;
}

/*
 * Map a VF's PCI BDF to its parent PF's vf_id (i.e. the index
 * @virtfnN under the PF's pci_dev sysfs node). Returns the vf_id
 * on success or -1 if no virtfn link matches @vf_bdf -- which is
 * the expected outcome for any non-VF mlx5_core ibdev (PFs land
 * here too) and is therefore not an error per se, just a "decline"
 * signal back up the claim chain.
 */
static int find_vf_id_under_pf(const char *pf_bdf, const char *vf_bdf)
{
	char path[PATH_MAX];
	struct dirent *de;
	DIR *d;
	int vf_id = -1;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s", pf_bdf);
	d = opendir(path);
	if (!d)
		return -1;

	while ((de = readdir(d)) != NULL) {
		char vlpath[PATH_MAX], vlbase[64];

		if (strncmp(de->d_name, "virtfn", 6) != 0)
			continue;
		if (snprintf(vlpath, sizeof(vlpath), "%s/%s", path,
			     de->d_name) >= (int)sizeof(vlpath))
			continue;
		if (resolve_pci_bdf_via_symlink(vlpath, vlbase,
						sizeof(vlbase)) != 0)
			continue;
		if (strcmp(vlbase, vf_bdf) == 0) {
			vf_id = atoi(de->d_name + strlen("virtfn"));
			break;
		}
	}

	closedir(d);
	return vf_id;
}

/*
 * Per-context claim hook (CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT).
 *
 * The claim chain for a context backed by an mlx5_core ibdev:
 *
 *   1. Plugin must be active (init() found at least one tracked
 *      VF on the host). If not, decline outright -- the dump-time
 *      arbitration's "no claim" failure mode names every loaded
 *      plugin so the operator gets a useful error.
 *
 *   2. Kernel driver must be RDMA_DRIVER_MLX5. mlx5_core ibdevs
 *      are the only ones this plugin knows how to handle.
 *
 *   3. The ibdev's PCI device must have a /physfn link, i.e. it
 *      must be a VF (not a PF). PFs are valid mlx5_core ibdevs
 *      but vfmig deliberately operates only on VFs. Decline if
 *      missing.
 *
 *   4. The VF must appear under the PF's virtfn<N> sysfs links
 *      (we need vf_id to drive QUERY_VF). Fail closed if not -- a
 *      missing virtfn link on a VF whose physfn we just resolved
 *      is a sysfs inconsistency, not a "decline" condition.
 *
 *   5. /dev/mlx5_vfmig/<pf_bdf> must open. Same reasoning as (4):
 *      if init() saw the cdev directory we expect the cdevs to
 *      still be present at claim time. Failure here propagates
 *      as a hard arbitration error.
 *
 *   6. MLX5_VFMIG_IOC_QUERY_VF on (pf_bdf, vf_id) must report
 *      tracked=1. tracked=0 -> decline (the per-VF unmanaged
 *      IOMMU domain isn't allocated, so SAVE/LOAD wouldn't
 *      round-trip even if we accepted the dump).
 *
 * Returns RCD_MLX5_SRIOV_VFMIG on a successful claim, RCD_UNKNOWN
 * on any decline (steps 1-3, 6), or a negative errno on the
 * sysfs-inconsistency / open / ioctl failure cases (steps 4, 5).
 */
static int rdma_mlx5_vfmig_plugin_claim_uverbs_context(const char *ibdev,
						       uint32_t kernel_driver_id)
{
	struct mlx5_vfmig_query_vf q;
	char sysfs_path[PATH_MAX];
	char cdev_path[PATH_MAX];
	char vf_bdf[64], pf_bdf[64];
	int vf_id, fd, rc;

	if (!vfmig_active) {
		pr_debug("claim(%s, kdrv=%u): plugin inactive, declining\n",
			 ibdev, kernel_driver_id);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}
	if (kernel_driver_id != RDMA_DRIVER_MLX5) {
		pr_debug("claim(%s, kdrv=%u): not RDMA_DRIVER_MLX5 (%u), "
			 "declining\n",
			 ibdev, kernel_driver_id, (uint32_t)RDMA_DRIVER_MLX5);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}

	snprintf(sysfs_path, sizeof(sysfs_path),
		 "/sys/class/infiniband/%s/device", ibdev);
	if (resolve_pci_bdf_via_symlink(sysfs_path, vf_bdf, sizeof(vf_bdf))) {
		pr_warn("claim(%s): cannot resolve VF BDF via %s\n", ibdev,
			sysfs_path);
		return -ENOENT;
	}

	snprintf(sysfs_path, sizeof(sysfs_path),
		 "/sys/bus/pci/devices/%s/physfn", vf_bdf);
	if (resolve_pci_bdf_via_symlink(sysfs_path, pf_bdf, sizeof(pf_bdf))) {
		pr_debug("claim(%s, vf_bdf=%s): no /physfn link, this is a "
			 "PF or non-SR-IOV mlx5_core ibdev; declining\n",
			 ibdev, vf_bdf);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}

	vf_id = find_vf_id_under_pf(pf_bdf, vf_bdf);
	if (vf_id < 0) {
		pr_warn("claim(%s, vf_bdf=%s, pf_bdf=%s): no virtfnN link "
			"under PF resolves to this VF -- sysfs inconsistency\n",
			ibdev, vf_bdf, pf_bdf);
		return -ENOENT;
	}

	snprintf(cdev_path, sizeof(cdev_path), "%s/%s", MLX5_VFMIG_DEV_DIR,
		 pf_bdf);
	fd = open(cdev_path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_warn("claim(%s): open(%s) failed: %s\n", ibdev, cdev_path,
			strerror(errno));
		return -errno;
	}

	memset(&q, 0, sizeof(q));
	q.vf_id = vf_id;
	rc = ioctl(fd, MLX5_VFMIG_IOC_QUERY_VF, &q);
	close(fd);
	if (rc != 0) {
		pr_warn("claim(%s): QUERY_VF(vf_id=%d) on %s failed: %s\n",
			ibdev, vf_id, cdev_path, strerror(errno));
		return -errno;
	}
	if (!q.tracked) {
		pr_info("claim(%s, vf_bdf=%s, pf=%s, vf_id=%d): VF not in "
			"tracked mode, declining\n",
			ibdev, vf_bdf, pf_bdf, vf_id);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}

	pr_info("claim(%s, vf_bdf=%s, pf=%s, vf_id=%d): claiming as "
		"RCD_MLX5_SRIOV_VFMIG\n",
		ibdev, vf_bdf, pf_bdf, vf_id);
	return RDMA_CRIU_DRIVER__RCD_MLX5_SRIOV_VFMIG;
}

/*
 * Resolve an ibdev name to its (pf_bdf, vf_id) pair via the same
 * sysfs walk the CLAIM hook performs. Returns 0 on success with
 * @pf_bdf (sized @pf_bdfsz) and @vf_id populated, -1 on any
 * resolution failure -- which here is treated as a hard error
 * because by the time we run, CLAIM has already accepted this
 * ibdev as ours, so a sysfs miss is an inconsistency, not a polite
 * decline.
 */
static int vfmig_resolve_pf_vf(const char *ibdev,
			       char *pf_bdf, size_t pf_bdfsz,
			       uint32_t *vf_id)
{
	char sysfs_path[PATH_MAX];
	char vf_bdf[64];
	int v;

	snprintf(sysfs_path, sizeof(sysfs_path),
		 "/sys/class/infiniband/%s/device", ibdev);
	if (resolve_pci_bdf_via_symlink(sysfs_path, vf_bdf,
					sizeof(vf_bdf))) {
		pr_err("dump(%s): cannot resolve VF BDF via %s\n",
		       ibdev, sysfs_path);
		return -1;
	}

	snprintf(sysfs_path, sizeof(sysfs_path),
		 "/sys/bus/pci/devices/%s/physfn", vf_bdf);
	if (resolve_pci_bdf_via_symlink(sysfs_path, pf_bdf, pf_bdfsz)) {
		pr_err("dump(%s, vf_bdf=%s): cannot resolve PF BDF via "
		       "%s\n", ibdev, vf_bdf, sysfs_path);
		return -1;
	}

	v = find_vf_id_under_pf(pf_bdf, vf_bdf);
	if (v < 0) {
		pr_err("dump(%s, vf_bdf=%s, pf=%s): no virtfnN link "
		       "matches\n", ibdev, vf_bdf, pf_bdf);
		return -1;
	}
	*vf_id = (uint32_t)v;
	return 0;
}

/*
 * Quiet variant of vfmig_resolve_pf_vf used by HANDLE_DEVICE_VMA.
 * Same sysfs walk, but failures (which here mean "this VMA's
 * backing chrdev is not a tracked-mlx5-VF uverbs cdev") log at
 * pr_debug instead of pr_err -- HANDLE_DEVICE_VMA is invoked on
 * every non-regular VMA in the dumped tree, including ones the
 * mlx5 plugin has no business claiming, so we mustn't spam the
 * log on the common decline path.
 */
static int vfmig_resolve_pf_vf_quiet(const char *ibdev,
				     char *pf_bdf, size_t pf_bdfsz,
				     uint32_t *vf_id)
{
	char sysfs_path[PATH_MAX];
	char vf_bdf[64];
	int v;

	snprintf(sysfs_path, sizeof(sysfs_path),
		 "/sys/class/infiniband/%s/device", ibdev);
	if (resolve_pci_bdf_via_symlink(sysfs_path, vf_bdf,
					sizeof(vf_bdf))) {
		pr_debug("handle_vma(%s): cannot resolve VF BDF via %s\n",
			 ibdev, sysfs_path);
		return -1;
	}

	snprintf(sysfs_path, sizeof(sysfs_path),
		 "/sys/bus/pci/devices/%s/physfn", vf_bdf);
	if (resolve_pci_bdf_via_symlink(sysfs_path, pf_bdf, pf_bdfsz)) {
		pr_debug("handle_vma(%s, vf_bdf=%s): no /physfn link "
			 "(PF or non-SR-IOV device); declining\n",
			 ibdev, vf_bdf);
		return -1;
	}

	v = find_vf_id_under_pf(pf_bdf, vf_bdf);
	if (v < 0) {
		pr_debug("handle_vma(%s, vf_bdf=%s, pf=%s): no virtfnN "
			 "link matches; declining\n",
			 ibdev, vf_bdf, pf_bdf);
		return -1;
	}
	*vf_id = (uint32_t)v;
	return 0;
}

/*
 * Resolve a char-device's dev_t to its ibdev name via
 * /sys/dev/char/<maj>:<min>/ibdev. Returns 0 with @out populated
 * (NUL-terminated, trailing newline stripped) on success, -1 if
 * @rdev does not name an InfiniBand uverbs char device -- the
 * only chrdev type whose /sys/dev/char node exposes an @ibdev
 * attribute. This is a cheap pre-filter for HANDLE_DEVICE_VMA,
 * which is invoked on every non-regular VMA in the dumped tree
 * (e.g. anonymous-shmem, DRM render-node mappings, anything a
 * foreign plugin handles).
 */
static int vfmig_chrdev_to_ibdev(dev_t rdev, char *out, size_t outsz)
{
	char path[PATH_MAX];
	int fd;
	ssize_t n;

	snprintf(path, sizeof(path), "/sys/dev/char/%u:%u/ibdev",
		 major(rdev), minor(rdev));
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, out, outsz - 1);
	close(fd);
	if (n <= 0)
		return -1;
	while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == ' '))
		n--;
	out[n] = '\0';
	return n > 0 ? 0 : -1;
}

/*
 * Stream the SAVE_VHCA_STATE save_fd byte-stream into a freshly-
 * created blob file under the CRIU image directory. Returns 0 on
 * success with @save_fd already drained and closed, and total
 * bytes written written into *@out_size; -1 on any I/O failure
 * (the partially-written blob file is left in place for
 * post-mortem -- CRIU will fail the dump regardless).
 */
static int vfmig_drain_save_fd_to_blob(int save_fd,
				       const char *blob_path,
				       uint64_t *out_size)
{
	int img_dir, blob_fd;
	uint64_t total = 0;
	ssize_t n;
	char buf[64 * 1024];

	img_dir = criu_get_image_dir();
	if (img_dir < 0) {
		pr_err("vfmig: criu_get_image_dir() returned %d -- "
		       "no image dir set, cannot write blob\n", img_dir);
		return -1;
	}

	blob_fd = openat(img_dir, blob_path,
			 O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (blob_fd < 0) {
		pr_perror("vfmig: openat(image_dir/%s) for blob write",
			  blob_path);
		return -1;
	}

	for (;;) {
		ssize_t off = 0;

		n = read(save_fd, buf, sizeof(buf));
		if (n == 0)
			break;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			pr_perror("vfmig: read(save_fd) for %s", blob_path);
			close(blob_fd);
			return -1;
		}
		while (off < n) {
			ssize_t w = write(blob_fd, buf + off, n - off);
			if (w < 0) {
				if (errno == EINTR)
					continue;
				pr_perror("vfmig: write(%s)", blob_path);
				close(blob_fd);
				return -1;
			}
			off += w;
		}
		total += (uint64_t)n;
	}

	if (close(blob_fd)) {
		pr_perror("vfmig: close(%s)", blob_path);
		return -1;
	}

	*out_size = total;
	return 0;
}

/*
 * Capture the firmware blob for one (pf_bdf, vf_id) pair.
 *
 * Steps (matching the source-side lifecycle in the kernel UAPI doc
 * on MLX5_VFMIG_IOC_SAVE_VHCA_STATE):
 *   1. open /dev/mlx5_vfmig/<pf_bdf>
 *   2. ioctl MLX5_VFMIG_IOC_GET_VHCA_ID    (record vhca_id for diags)
 *   3. ioctl MLX5_VFMIG_IOC_SAVE_VHCA_STATE { vf_id,
 *        flags = MLX5_VFMIG_SAVE_FLAG_KEEP_SUSPENDED }
 *      -> kernel quiesces the VF (SUSPEND_VHCA INITIATOR/RESPONDER),
 *         allocates DMA-mapped image pages, runs SAVE_VHCA_STATE,
 *         returns a read-only anon-inode fd.
 *   4. read the save_fd to EOF, write into the image dir.
 *   5. close(save_fd) WITHOUT issuing RESUME -- KEEP_SUSPENDED told
 *      the kernel to leave the source VF stopped; the orchestrator
 *      tears the VF down before any resume on the source. (See
 *      cover note: post-SAVE the VF is intentionally not runnable
 *      on the source side.)
 *
 * On success the @out fields are populated and the blob file
 * exists in the image directory; on failure the file may exist
 * partially-written (we don't unlink it; an aborted dump will
 * abort the image directory wholesale).
 */
static int vfmig_capture_one_vf(const char *pf_bdf, uint32_t vf_id,
				struct vfmig_saved_vf *out)
{
	struct mlx5_vfmig_get_vhca_id gv;
	struct mlx5_vfmig_save_state ss;
	char cdev_path[PATH_MAX];
	int cdev_fd;

	snprintf(cdev_path, sizeof(cdev_path), "%s/%s",
		 MLX5_VFMIG_DEV_DIR, pf_bdf);
	cdev_fd = open(cdev_path, O_RDWR | O_CLOEXEC);
	if (cdev_fd < 0) {
		pr_perror("vfmig: open(%s)", cdev_path);
		return -1;
	}

	memset(&gv, 0, sizeof(gv));
	gv.vf_id = vf_id;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_GET_VHCA_ID, &gv)) {
		pr_perror("vfmig: GET_VHCA_ID(pf=%s, vf_id=%u)",
			  pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}
	out->vhca_id = gv.vhca_id;

	memset(&ss, 0, sizeof(ss));
	ss.vf_id = vf_id;
	ss.flags = MLX5_VFMIG_SAVE_FLAG_KEEP_SUSPENDED;
	if (ioctl(cdev_fd, MLX5_VFMIG_IOC_SAVE_VHCA_STATE, &ss)) {
		pr_perror("vfmig: SAVE_VHCA_STATE(pf=%s, vf_id=%u, "
			  "KEEP_SUSPENDED)", pf_bdf, vf_id);
		close(cdev_fd);
		return -1;
	}

	snprintf(out->blob_path, sizeof(out->blob_path),
		 "mlx5_vfmig-pf%s-vf%u.blob", pf_bdf, vf_id);

	if (vfmig_drain_save_fd_to_blob(ss.save_fd, out->blob_path,
					&out->blob_size)) {
		close(ss.save_fd);
		close(cdev_fd);
		return -1;
	}

	close(ss.save_fd);
	close(cdev_fd);

	pr_info("vfmig: captured pf=%s vf_id=%u vhca_id=%u "
		"blob='%s' size=%llu (KEEP_SUSPENDED)\n",
		pf_bdf, vf_id, out->vhca_id, out->blob_path,
		(unsigned long long)out->blob_size);
	return 0;
}

/*
 * Append one Mlx5VfmigStateEntry record to <img-dir>/mlx5_vfmig.img,
 * length-prefixed (uint32 LE byte length, then the protobuf-packed
 * bytes). Each record is independent; the restore-side reader walks
 * length-prefixed records until EOF.
 *
 * Why hand-rolled framing instead of the criu/protobuf.c PB_*
 * helpers: those helpers are tied to criu_image_streamer + the
 * cr_img abstraction and live in the criu binary, not in the
 * plugin's address space. The plugin-private mlx5_vfmig.img is just
 * a flat file under criu_get_image_dir(); a fixed 4-byte little-
 * endian length prefix is plenty.
 */
static int vfmig_append_state_entry(uint32_t ctxn, const char *ibdev,
				    const char *source_cdev_path,
				    const struct vfmig_saved_vf *st)
{
	Mlx5VfmigStateEntry e = MLX5_VFMIG_STATE_ENTRY__INIT;
	int img_dir, fd;
	void *buf;
	size_t plen;
	uint32_t lenle;
	struct iovec iov[2];

	e.ctxn = ctxn;
	e.ibdev = (char *)ibdev;
	e.pf_bdf = (char *)st->pf_bdf;
	e.vf_id = st->vf_id;
	e.vhca_id = st->vhca_id;
	e.blob_path = (char *)st->blob_path;
	e.blob_size = st->blob_size;
	e.source_cdev_path = (char *)source_cdev_path;
	/* blob_sha256 is optional; leave unset for v0. */

	plen = mlx5_vfmig_state_entry__get_packed_size(&e);
	if (plen > 0xffffffffu) {
		pr_err("vfmig: state entry too large (%zu) for u32 prefix\n",
		       plen);
		return -1;
	}
	buf = malloc(plen);
	if (!buf) {
		pr_err("vfmig: malloc(%zu) for state entry\n", plen);
		return -1;
	}
	if (mlx5_vfmig_state_entry__pack(&e, buf) != plen) {
		pr_err("vfmig: pack returned unexpected size\n");
		free(buf);
		return -1;
	}

	img_dir = criu_get_image_dir();
	if (img_dir < 0) {
		pr_err("vfmig: criu_get_image_dir() returned %d\n", img_dir);
		free(buf);
		return -1;
	}
	fd = openat(img_dir, MLX5_VFMIG_IMG_NAME,
		    O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (fd < 0) {
		pr_perror("vfmig: openat(image_dir/%s)", MLX5_VFMIG_IMG_NAME);
		free(buf);
		return -1;
	}

	lenle = htole32((uint32_t)plen);
	iov[0].iov_base = &lenle;
	iov[0].iov_len = sizeof(lenle);
	iov[1].iov_base = buf;
	iov[1].iov_len = plen;

	if (writev(fd, iov, 2) != (ssize_t)(sizeof(lenle) + plen)) {
		pr_perror("vfmig: writev(%s)", MLX5_VFMIG_IMG_NAME);
		close(fd);
		free(buf);
		return -1;
	}

	if (close(fd)) {
		pr_perror("vfmig: close(%s)", MLX5_VFMIG_IMG_NAME);
		free(buf);
		return -1;
	}
	free(buf);

	pr_info("vfmig: appended state entry ctxn=%u ibdev=%s pf=%s vf_id=%u "
		"-> %s\n", ctxn, ibdev, st->pf_bdf, st->vf_id,
		MLX5_VFMIG_IMG_NAME);
	return 0;
}

/*
 * Per-context dump hook (CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT).
 *
 * Runs after CLAIM has named us as the winning plugin for this
 * uverbs context. The hook used to fire SAVE_VHCA_STATE inline,
 * but SAVE is the most invasive thing this plugin does to the
 * host -- it suspends the source VF's firmware and (with
 * KEEP_SUSPENDED) leaves it parked. We now defer the actual
 * SAVE to fini(DUMP), so it runs only after every other piece
 * of dump work has either succeeded or surfaced a failure the
 * operator can act on without ever having touched the VF's
 * firmware.
 *
 * The hook's job is therefore reduced to:
 *
 *   1. Resolve ibdev -> (pf_bdf, vf_id). Same sysfs walk CLAIM
 *      already did; we redo it here rather than threading the
 *      resolved tuple through the hook ABI. The cost is two
 *      readlink()s and a small directory scan, negligible.
 *
 *   2. Enqueue a (ctxn, ibdev, pf_bdf, vf_id) record onto the
 *      pending queue. fini(DUMP) walks this queue, dedups by
 *      (pf_bdf, vf_id), runs SAVE_VHCA_STATE per unique VF, and
 *      emits one Mlx5VfmigStateEntry per pending context. (See
 *      vfmig_drain_pending_in_fini below.)
 *
 * @lfd and @pid are unused for v0 (KEEP_SUSPENDED leaves the VF
 * suspended without consulting the source process; we don't need
 * an open fd against the cdev for SAVE). They remain in the
 * hook ABI so future plugins that do need them have them.
 */
static int rdma_mlx5_vfmig_plugin_dump_uverbs_context(const char *ibdev,
						      uint32_t kernel_driver_id,
						      uint32_t ctxn,
						      int lfd, pid_t pid)
{
	char pf_bdf[64], proc_path[64], src_cdev[PATH_MAX];
	uint32_t vf_id;
	ssize_t n;

	(void)kernel_driver_id;
	(void)pid;

	if (vfmig_resolve_pf_vf(ibdev, pf_bdf, sizeof(pf_bdf), &vf_id))
		return -1;

	/*
	 * Capture the source-side cdev path the dumpee opened. The
	 * lfd we get here is criu's own dup() of the dumpee's fd, so
	 * /proc/self/fd/<lfd> resolves to the same kernel struct
	 * file backing path -- e.g. "/dev/infiniband/uverbs2". This
	 * is the join key the restore-side UPDATE_VMA_MAP hook
	 * receives from CRIU (CRIU records reg_file_entry.name
	 * verbatim from the dumpee's struct file, and replays that
	 * string as @path on UPDATE_VMA_MAP). Without it we'd have
	 * to walk every Mlx5VfmigStateEntry per VMA on restore to
	 * find a match.
	 */
	snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", lfd);
	n = readlink(proc_path, src_cdev, sizeof(src_cdev) - 1);
	if (n <= 0) {
		pr_perror("vfmig: readlink(%s) for source cdev path",
			  proc_path);
		return -1;
	}
	src_cdev[n] = '\0';

	if (vfmig_pending_enqueue(ctxn, ibdev, pf_bdf, vf_id, src_cdev)) {
		pr_err("vfmig: enqueue(ctxn=%u, pf=%s, vf_id=%u, "
		       "src_cdev=%s) OOM\n", ctxn, pf_bdf, vf_id,
		       src_cdev);
		return -1;
	}

	pr_info("vfmig: queued ctxn=%u ibdev=%s pf=%s vf_id=%u "
		"src_cdev=%s for fini-time SAVE\n", ctxn, ibdev,
		pf_bdf, vf_id, src_cdev);
	return 0;
}

/*
 * Drain the pending queue at fini(DUMP) time. Per (pf_bdf, vf_id)
 * the first context "owns" the SAVE; subsequent contexts on the
 * same VF reuse the cached blob via vfmig_saved_lookup. SAVE
 * failure for one VF only kills that VF's records -- contexts on
 * other VFs continue to land in the image. This matches the
 * "partial image best-effort" policy: a more-complete partial
 * image is more useful for debugging than a wholesale dump abort,
 * especially when the failing VF is one of several being
 * snapshotted.
 *
 * Best-effort logging only: fini's signature is void (criu's
 * cr_plugin_fini drops any return) so we can't propagate a
 * partial-failure indication back up. The pr_err lines below
 * are the operator's surface for "which VF's records didn't make
 * it into the image".
 */
static void vfmig_drain_pending_in_fini(void)
{
	struct vfmig_pending_ctx *p;
	int total = 0, written = 0, failed = 0, captured = 0;

	for (p = vfmig_pending_head; p; p = p->next) {
		struct vfmig_saved_vf *st;

		total++;

		if (vfmig_failed_lookup(p->pf_bdf, p->vf_id)) {
			pr_warn("vfmig: skipping ctxn=%u (pf=%s vf_id=%u "
				"already failed earlier in this dump)\n",
				p->ctxn, p->pf_bdf, p->vf_id);
			failed++;
			continue;
		}

		st = vfmig_saved_lookup(p->pf_bdf, p->vf_id);
		if (!st) {
			struct vfmig_saved_vf *nst = calloc(1, sizeof(*nst));

			if (!nst) {
				pr_err("vfmig: calloc(saved_vf) for ctxn=%u "
				       "pf=%s vf_id=%u; marking VF failed\n",
				       p->ctxn, p->pf_bdf, p->vf_id);
				vfmig_failed_mark(p->pf_bdf, p->vf_id);
				failed++;
				continue;
			}
			snprintf(nst->pf_bdf, sizeof(nst->pf_bdf), "%s",
				 p->pf_bdf);
			nst->vf_id = p->vf_id;

			if (vfmig_capture_one_vf(p->pf_bdf, p->vf_id, nst)) {
				pr_err("vfmig: SAVE_VHCA_STATE failed for "
				       "pf=%s vf_id=%u; dropping all "
				       "pending records for this VF\n",
				       p->pf_bdf, p->vf_id);
				free(nst);
				vfmig_failed_mark(p->pf_bdf, p->vf_id);
				failed++;
				continue;
			}
			nst->next = vfmig_saved_head;
			vfmig_saved_head = nst;
			st = nst;
			captured++;
		} else {
			pr_info("vfmig: dedup hit ibdev=%s pf=%s vf_id=%u "
				"ctxn=%u (reusing blob '%s')\n",
				p->ibdev, p->pf_bdf, p->vf_id, p->ctxn,
				st->blob_path);
		}

		if (vfmig_append_state_entry(p->ctxn, p->ibdev,
					     p->source_cdev_path, st)) {
			pr_err("vfmig: failed to append state entry for "
			       "ctxn=%u (pf=%s vf_id=%u)\n",
			       p->ctxn, p->pf_bdf, p->vf_id);
			failed++;
			continue;
		}
		written++;
	}

	pr_info("fini-DUMP drain: total=%d captured_vfs=%d records_written=%d "
		"failed=%d\n", total, captured, written, failed);
}

/*
 * Per-VMA dump-side hook (CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA).
 *
 * mlx5 ibverbs userspace (libmlx5) memory-maps three or four pages
 * off /dev/infiniband/uverbsN per ibv_context: the UAR doorbell
 * page(s), the realtime-clock register, and (on some firmware) a
 * non-cached UAR. CRIU's proc_parse encounters those VMAs, sees
 * S_ISCHR, and asks every loaded plugin "is this VMA yours?".
 * Without us claiming them the dump aborts with the standard
 * "Can't handle non-regular mapping" error.
 *
 * The check we perform here is symmetric with the dump-side
 * predicate the rest of this plugin uses:
 *
 *   1. /sys/dev/char/<maj>:<min>/ibdev exists and reads as an
 *      ibdev name. (Fast pre-filter -- non-uverbs chrdev VMAs
 *      decline silently here.)
 *
 *   2. ibdev resolves via the standard sysfs walk to a
 *      (pf_bdf, vf_id) tuple, AND /dev/mlx5_vfmig/<pf_bdf>
 *      opens. Anything that doesn't (PFs, non-mlx5 ibdevs,
 *      hosts where vfmig isn't loaded) declines silently.
 *
 *   3. MLX5_VFMIG_IOC_QUERY_VF on (pf_bdf, vf_id) reports
 *      tracked=1. tracked=0 means "this is an mlx5 VF but it
 *      was never armed for migration", which is one of the few
 *      cases where we want to log loudly: the operator almost
 *      certainly meant to run SET_TRACKED before snapshotting,
 *      and silently declining would let CRIU fail the dump
 *      with a generic "Can't handle non-regular mapping"
 *      instead of a directed "VF X is not save/restorable".
 *      We still return -ENOTSUP (rather than a hard error) so
 *      the existing handle_vma_plugin() error path runs --
 *      that surfaces the original VMA address, which is more
 *      useful for triage than the bare ioctl() failure would
 *      be.
 *
 * Returns 0 on a successful claim, -ENOTSUP for any decline
 * (which lets run_plugins() fall through to the next hook, or to
 * proc_parse's "Can't handle non-regular mapping" if no plugin
 * claims). We deliberately never return any other negative value
 * here: a negative-but-not-ENOTSUP return short-circuits
 * run_plugins() and would prevent any future plugin (or future
 * hook in this plugin) from claiming a VMA we mishandled.
 *
 * @fd is unused: we do all the resolution off @stat->st_rdev,
 * because the source-side proc fd is opened against the dumpee's
 * /proc/<pid>/map_files/<addr> and can be revoked underneath us
 * if the dumpee races the dump (rare but possible).
 */
static int rdma_mlx5_vfmig_plugin_handle_device_vma(int fd,
						    const struct stat *st)
{
	struct mlx5_vfmig_query_vf q;
	char ibdev[64];
	char pf_bdf[64];
	char cdev_path[PATH_MAX];
	uint32_t vf_id;
	int cdev_fd, rc;

	(void)fd;

	if (!vfmig_active)
		return -ENOTSUP;
	if (!S_ISCHR(st->st_mode))
		return -ENOTSUP;

	if (vfmig_chrdev_to_ibdev(st->st_rdev, ibdev, sizeof(ibdev)))
		return -ENOTSUP;
	if (vfmig_resolve_pf_vf_quiet(ibdev, pf_bdf, sizeof(pf_bdf),
				      &vf_id))
		return -ENOTSUP;

	snprintf(cdev_path, sizeof(cdev_path), "%s/%s",
		 MLX5_VFMIG_DEV_DIR, pf_bdf);
	cdev_fd = open(cdev_path, O_RDWR | O_CLOEXEC);
	if (cdev_fd < 0) {
		pr_debug("handle_vma(%s, pf=%s): open(%s) failed: %s; "
			 "declining\n", ibdev, pf_bdf, cdev_path,
			 strerror(errno));
		return -ENOTSUP;
	}

	memset(&q, 0, sizeof(q));
	q.vf_id = vf_id;
	rc = ioctl(cdev_fd, MLX5_VFMIG_IOC_QUERY_VF, &q);
	close(cdev_fd);
	if (rc) {
		pr_warn("handle_vma(%s, pf=%s, vf_id=%u): QUERY_VF "
			"failed: %s; declining\n",
			ibdev, pf_bdf, vf_id, strerror(errno));
		return -ENOTSUP;
	}
	if (!q.tracked) {
		pr_err("handle_vma(%s, pf=%s, vf_id=%u): VF is not "
		       "tracked (not save/restorable); CRIU dump "
		       "will fail. Run SET_TRACKED on this VF before "
		       "snapshotting.\n",
		       ibdev, pf_bdf, vf_id);
		return -ENOTSUP;
	}

	pr_info("handle_vma(%s, pf=%s, vf_id=%u): claiming "
		"uverbs-cdev mapping (UAR/clock/NC, tracked VF)\n",
		ibdev, pf_bdf, vf_id);
	return 0;
}

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

struct vfmig_restored_ctx {
	struct vfmig_restored_ctx *next;
	uint32_t source_ctxn;
	char source_ibdev[64];
	char source_cdev_path[PATH_MAX];
	int dest_cdev_fd;
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

/*
 * Read mlx5_vfmig.img into an in-memory array of unpacked entries.
 * Returns 0 on success with @out_arr/@out_n populated; caller frees
 * the array (and each entry via mlx5_vfmig_state_entry__free_unpacked).
 * Empty or missing image is also success with @out_n == 0.
 */
static int vfmig_read_image(Mlx5VfmigStateEntry ***out_arr, size_t *out_n)
{
	int img_dir, fd;
	struct stat st;
	void *blob = NULL;
	size_t off = 0;
	Mlx5VfmigStateEntry **arr = NULL;
	size_t cap = 0, n = 0, i;

	*out_arr = NULL;
	*out_n = 0;

	img_dir = criu_get_image_dir();
	if (img_dir < 0) {
		pr_err("vfmig: criu_get_image_dir() returned %d on restore\n",
		       img_dir);
		return -1;
	}

	fd = openat(img_dir, MLX5_VFMIG_IMG_NAME, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT) {
			pr_info("vfmig: no %s in image dir; nothing to "
				"restore\n", MLX5_VFMIG_IMG_NAME);
			return 0;
		}
		pr_perror("vfmig: openat(image_dir/%s)", MLX5_VFMIG_IMG_NAME);
		return -1;
	}
	if (fstat(fd, &st)) {
		pr_perror("vfmig: fstat(%s)", MLX5_VFMIG_IMG_NAME);
		close(fd);
		return -1;
	}
	if (st.st_size == 0) {
		pr_info("vfmig: %s is empty; nothing to restore\n",
			MLX5_VFMIG_IMG_NAME);
		close(fd);
		return 0;
	}
	blob = malloc(st.st_size);
	if (!blob) {
		pr_err("vfmig: malloc(%lld) for image\n",
		       (long long)st.st_size);
		close(fd);
		return -1;
	}
	if (read(fd, blob, st.st_size) != st.st_size) {
		pr_perror("vfmig: read(%s)", MLX5_VFMIG_IMG_NAME);
		free(blob);
		close(fd);
		return -1;
	}
	close(fd);

	while (off < (size_t)st.st_size) {
		uint32_t plen;
		Mlx5VfmigStateEntry *e;

		if (off + sizeof(plen) > (size_t)st.st_size) {
			pr_err("vfmig: truncated length prefix in %s at "
			       "off %zu\n", MLX5_VFMIG_IMG_NAME, off);
			goto err;
		}
		memcpy(&plen, (char *)blob + off, sizeof(plen));
		plen = le32toh(plen);
		off += sizeof(plen);
		if (plen == 0 || plen > 0x10000000u ||
		    off + plen > (size_t)st.st_size) {
			pr_err("vfmig: bad record length %u at off %zu in "
			       "%s\n", plen, off, MLX5_VFMIG_IMG_NAME);
			goto err;
		}
		e = mlx5_vfmig_state_entry__unpack(NULL, plen,
						   (uint8_t *)blob + off);
		if (!e) {
			pr_err("vfmig: unpack failed at off %zu\n", off);
			goto err;
		}
		off += plen;
		if (n == cap) {
			size_t ncap = cap ? cap * 2 : 4;
			Mlx5VfmigStateEntry **na = realloc(arr,
							   ncap * sizeof(*arr));
			if (!na) {
				mlx5_vfmig_state_entry__free_unpacked(e, NULL);
				pr_err("vfmig: realloc(arr)\n");
				goto err;
			}
			arr = na;
			cap = ncap;
		}
		arr[n++] = e;
	}

	free(blob);
	*out_arr = arr;
	*out_n = n;
	return 0;
err:
	free(blob);
	if (arr) {
		for (i = 0; i < n; i++)
			mlx5_vfmig_state_entry__free_unpacked(arr[i], NULL);
		free(arr);
	}
	return -1;
}

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

static int vfmig_restore_init_all_vfs(void)
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
		int fd;

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

		fd = open(v->dest_cdev_path, O_RDWR | O_CLOEXEC);
		if (fd < 0) {
			pr_perror("vfmig: open(%s)", v->dest_cdev_path);
			goto err;
		}
		if (criu_ib_uverbs_get_context(fd, RDMA_DRIVER_MLX5)) {
			pr_err("vfmig: GET_CONTEXT on %s for ctxn=%u "
			       "failed\n", v->dest_cdev_path, e->ctxn);
			close(fd);
			goto err;
		}

		c = calloc(1, sizeof(*c));
		if (!c) {
			close(fd);
			goto err;
		}
		c->source_ctxn = e->ctxn;
		snprintf(c->source_ibdev, sizeof(c->source_ibdev), "%s",
			 e->ibdev);
		snprintf(c->source_cdev_path, sizeof(c->source_cdev_path),
			 "%s", e->source_cdev_path);
		c->dest_cdev_fd = fd;
		c->next = vfmig_restored_ctxs;
		vfmig_restored_ctxs = c;

		pr_info("vfmig: cached restored ctx ctxn=%u "
			"source_ibdev=%s source_cdev=%s -> dest_fd=%d\n",
			c->source_ctxn, c->source_ibdev,
			c->source_cdev_path, c->dest_cdev_fd);
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

static void vfmig_restore_fini_close_all(void)
{
	struct vfmig_restored_ctx *c, *cn;
	struct vfmig_restored_vf *v, *vn;

	for (c = vfmig_restored_ctxs; c; c = cn) {
		cn = c->next;
		if (c->dest_cdev_fd >= 0)
			close(c->dest_cdev_fd);
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
static int rdma_mlx5_vfmig_plugin_update_vma_map(const char *path,
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
static int
rdma_mlx5_vfmig_plugin_open_uverbs_cdev(const struct _UverbsFileEntry *uvfe)
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

	dup_fd = dup(c->dest_cdev_fd);
	if (dup_fd < 0) {
		pr_perror("vfmig: dup(dest_cdev_fd=%d) for ctxn=%u",
			  c->dest_cdev_fd, u->ctxn);
		return -1;
	}

	pr_info("vfmig: open_uverbs_cdev: ctxn=%u -> dest_fd=%d (dup of "
		"cached)\n", u->ctxn, dup_fd);
	return dup_fd;
}

CR_PLUGIN_REGISTER("rdma_mlx5_vfmig_plugin", rdma_mlx5_vfmig_plugin_init,
		   rdma_mlx5_vfmig_plugin_fini)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT,
			rdma_mlx5_vfmig_plugin_claim_uverbs_context)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT,
			rdma_mlx5_vfmig_plugin_dump_uverbs_context)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA,
			rdma_mlx5_vfmig_plugin_handle_device_vma)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__UPDATE_VMA_MAP,
			rdma_mlx5_vfmig_plugin_update_vma_map)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV,
			rdma_mlx5_vfmig_plugin_open_uverbs_cdev)

/*
 * RDMA sharing policy: EXCLUSIVE.
 *
 * mlx5 SR-IOV VF migration snapshots and restores the entire VF as
 * one atomic unit (the QUERY_VF / SAVE_VF / LOAD_VF ioctls all
 * operate at VF granularity, not per-uverbs-context). Any context
 * any other process holds on the same VF will be invalidated by
 * the eventual LOAD_VF on the destination -- the device-side state
 * (queue pairs, completion queues, memory keys) gets fully replaced
 * with the snapshot, so by the time the restored process resumes
 * the cohabiting process's hardware-backed handles point at stale
 * or freed objects.
 *
 * Cross-tree exclusivity check (criu/rdma.c) consults this to
 * refuse a dump in which the snapshot tree shares a tracked VF
 * with any pid not in the snapshot. The operator's options at that
 * point are: include the cohabiting pid in the snapshot, stop it
 * before dumping, or, if they really know what they're doing,
 * detach its uverbs context first. EXCLUSIVE is also what we'd
 * default to anyway if this declaration were missing -- we
 * declare it explicitly so future maintainers see the intent.
 */
CR_PLUGIN_DECLARE_RDMA_SHARING(CR_RDMA_SHARING_EXCLUSIVE);

/*
 * RDMA provided driver: RCD_MLX5_SRIOV_VFMIG.
 *
 * Symmetric with the RCD_MLX5_SRIOV_VFMIG return value of
 * rdma_mlx5_vfmig_plugin_claim_uverbs_context() above. The
 * dispatchers in criu/rdma.c (rdma_dispatch_dump_uverbs_context
 * and rdma_dispatch_open_uverbs_cdev) use this constant to find
 * the right plugin to invoke when an image's
 * UverbsFileEntry.criu_driver names RCD_MLX5_SRIOV_VFMIG -- both
 * for dump-side capture and for restore-side cdev open + LOAD
 * dance. Without this declaration the plugin's CLAIM would still
 * succeed (CLAIM walks the hook chain by registration, not by
 * driver), but the dump-side dispatcher would fail to find the
 * winning plugin to invoke DUMP_UVERBS_CONTEXT on, and the
 * restore-side dispatcher would have no plugin to ask for the
 * destination cdev. Land both halves together.
 */
CR_PLUGIN_DECLARE_RDMA_PROVIDED_DRIVER(RDMA_CRIU_DRIVER__RCD_MLX5_SRIOV_VFMIG);
