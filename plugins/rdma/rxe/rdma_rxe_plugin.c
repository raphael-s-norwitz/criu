/*
 * CRIU RDMA RXE plugin -- presence detection.
 *
 * This is the first slice of plugin coverage for RDMA: at criu startup it
 * walks /sys/class/infiniband/ and decides whether the host has any ibdev
 * backed by the soft-RoCE (rxe) driver. The decision is logged and stashed
 * for later commits to consume; no checkpoint/restore hooks are wired in
 * yet.
 *
 * Why a separate plugin per RDMA "CRIU driver" (instead of a single
 * monolithic rdma plugin):
 *   The kernel-side "driver" for an ibdev (rxe / mlx5_core / bnxt_re / ...)
 *   does not map 1:1 to "how should CRIU dump+restore this context".
 *   mlx5_core alone has, or will have, multiple distinct CRIU strategies
 *   (host-driven SAVE/LOAD via mlx5_vfmig, future fw-assisted IB-resource
 *   replay, possibly a vfio_mlx5_pci variant for guest-mode), and each
 *   wants its own arbitration logic at dump time. Splitting per CRIU
 *   driver from day one means the future RdmaCriuDriver enum lines up
 *   directly with one .so per enumerant.
 *
 * Detection logic for rxe specifically: rxe ibdevs are software-defined
 * (no PCI parent, so no /sys/class/infiniband/<dev>/device/driver
 * symlink), but they're trivially identifiable by name prefix and by the
 * existence of /sys/class/infiniband/rxe<N>. We deliberately do not try
 * to ENABLE rxe here -- if rdma_rxe is unloaded, the plugin simply
 * declares itself inactive and lets the dump-time arbitration in commit
 * 5 fail any process that holds an rxe context (there can't be one
 * without a live rxe ibdev, so this is symmetric anyway).
 */

#include "criu-log.h"
#include "criu-plugin.h"

#include "images/rdma_criu.pb-c.h"
#include "images/uverbsfd.pb-c.h"

#include <rdma/ib_user_ioctl_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/rdma_user_ioctl_cmds.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
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
#include <unistd.h>

/*
 * Inlined kernel UAPI for the rxe ucontext-restore-mode flag, lifted
 * from include/uapi/rdma/rdma_user_rxe.h. The installed rdma-core uapi
 * tree lags the in-tree kernel UAPI; this enum + struct land in
 * upstream rdma-core only after a `make headers_install` from a kernel
 * carrying f0623eb9659f ("RDMA/rxe: Wire ucontext_is_restore_mode
 * predicate"). Same self-contained-inline pattern as the mlx5_vfmig
 * plugin uses for its alloc-ucontext-req surface, and as the kernel-
 * side reference exerciser
 * tools/testing/mlx5_vfmig/uobject_restore/pd_restore/pd_restore_probe_rxe.c
 * uses for the same reason.
 *
 * If the kernel UAPI evolves, keep this block in sync with:
 *   include/uapi/rdma/rdma_user_rxe.h     (the flag enum + req struct)
 *   drivers/infiniband/sw/rxe/rxe_verbs.c (the parser side)
 */
enum {
	RXE_ALLOC_UCTX_RESTORE_MODE = 1u << 0,
};
struct rxe_alloc_ucontext_req_local {
	uint32_t flags;
	uint32_t reserved;
};

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_rxe_plugin: "

#define IBDEV_SYSFS_DIR "/sys/class/infiniband"

/*
 * Plugin activity is process-local state, queried via
 * rdma_rxe_plugin_is_active() once commit 5 wires up the per-context
 * claim API. Until then it's purely diagnostic.
 */
static bool rxe_active = false;
static int rxe_dev_count = 0;

/*
 * Restore-side cache of cdev fds that already have a kernel ucontext
 * attached (via rxe_send_get_context_restore in our open_uverbs_cdev
 * hook). Keyed by ibdev name so the UPDATE_VMA_MAP path can hand back
 * a dup() of the *same struct file* the per-uobject restore ioctls
 * ran on, which is the only file with a non-NULL ufile->ucontext --
 * exactly what ib_uverbs_mmap requires (it returns -EINVAL via
 * ib_uverbs_get_ucontext_file otherwise).
 *
 * Without this cache CRIU's open_filemap() would re-open
 * /dev/infiniband/uverbsN through the generic open_path() route,
 * mint a fresh ib_uverbs_file with no ucontext, and the pie
 * restorer's mmap of the cdev VMA would die at -EINVAL. See the
 * mirroring vfmig_restored_ctx cache in plugins/rdma/mlx5_sriov_
 * vfmig/rdma_mlx5_vfmig_plugin.c::rdma_mlx5_vfmig_plugin_update_vma
 * _map for the same trick on the mlx5 side.
 *
 * Lifetime: appended in open_uverbs_cdev, freed in fini(RESTORE).
 * Cross-restore process-local; no locking needed because CRIU
 * restore is single-threaded for these phases.
 *
 * Why we park the cached fd above 1024: criu/util.c installs
 * workload fds with fcntl(F_DUPFD, want) and treats "requested slot
 * is occupied" as a hard error. If our dup'd cache fd lands at e.g.
 * fd 3 and the workload's UVERBSFD also wants fd 3, the install
 * fails with "fd N already in use". 1024 is comfortably above any
 * plausible small-numbered workload fd table. Mirrors mlx5_vfmig's
 * VFMIG_CACHED_FD_FLOOR.
 */
#define RXE_CACHED_FD_FLOOR 1024
struct rxe_cdev_cache_entry {
	char ibdev[64];
	int fd; /* high-numbered dup of the GET_CONTEXT'd fd */
	struct rxe_cdev_cache_entry *next;
};
static struct rxe_cdev_cache_entry *rxe_cdev_cache = NULL;

/* defined later in the file (right after rxe_match_cdev_vma) */
static int rxe_chrdev_to_ibdev(dev_t rdev, char *out, size_t outsz);

static void rxe_cdev_cache_remember(const char *ibdev, int fd)
{
	struct rxe_cdev_cache_entry *e;

	if (!ibdev || ibdev[0] == '\0' || fd < 0)
		return;

	e = calloc(1, sizeof(*e));
	if (!e) {
		pr_perror("rxe_cdev_cache_remember(%s)", ibdev);
		return;
	}
	snprintf(e->ibdev, sizeof(e->ibdev), "%s", ibdev);
	e->fd = fd;
	e->next = rxe_cdev_cache;
	rxe_cdev_cache = e;
	pr_debug("rxe_cdev_cache: remembered ibdev=%s fd=%d\n", ibdev, fd);
}

static int rxe_cdev_cache_lookup(const char *ibdev)
{
	struct rxe_cdev_cache_entry *e;

	for (e = rxe_cdev_cache; e; e = e->next) {
		if (!strcmp(e->ibdev, ibdev))
			return e->fd;
	}
	return -1;
}

static void rxe_cdev_cache_drop_all(void)
{
	struct rxe_cdev_cache_entry *e, *next;

	for (e = rxe_cdev_cache; e; e = next) {
		next = e->next;
		if (e->fd >= 0)
			close(e->fd);
		free(e);
	}
	rxe_cdev_cache = NULL;
}

/*
 * Resolve the kernel driver backing /sys/class/infiniband/<ibdev>.
 *
 * For PCI-backed ibdevs the canonical answer comes from readlink() on
 * <sysfs>/<ibdev>/device/driver -- the basename of the symlink target is
 * the kernel module name (mlx5_core, mlx4_core, bnxt_re, ...).
 *
 * Software-defined providers (rxe, siw) have no PCI parent and no
 * device/driver symlink; in that case fall back to a name-prefix
 * heuristic. We mirror the same fallback used in criu/rdma.c
 * (rdma_driver_name_from_ibdev) so the two paths stay consistent --
 * if/when those helpers move to a shared header, this can collapse to
 * one call.
 *
 * Returns true and fills @out (must be at least @outsz bytes) if a
 * driver name was resolved.
 */
static bool resolve_ibdev_driver(const char *ibdev, char *out, size_t outsz)
{
	char path[PATH_MAX];
	char target[PATH_MAX];
	const char *base, *src;
	ssize_t n;

	if (outsz == 0)
		return false;

	snprintf(path, sizeof(path), "%s/%s/device/driver", IBDEV_SYSFS_DIR,
		 ibdev);
	n = readlink(path, target, sizeof(target) - 1);
	if (n > 0) {
		target[n] = '\0';
		base = strrchr(target, '/');
		src = base ? base + 1 : target;
		snprintf(out, outsz, "%.*s", (int)(outsz - 1), src);
		return true;
	}

	if (!strncmp(ibdev, "rxe", 3)) {
		snprintf(out, outsz, "%.*s", (int)(outsz - 1), "rxe");
		return true;
	}
	if (!strncmp(ibdev, "siw", 3)) {
		snprintf(out, outsz, "%.*s", (int)(outsz - 1), "siw");
		return true;
	}

	return false;
}

static int rdma_rxe_plugin_init(int stage)
{
	DIR *d;
	struct dirent *de;

	rxe_active = false;
	rxe_dev_count = 0;

	d = opendir(IBDEV_SYSFS_DIR);
	if (!d) {
		/*
		 * No infiniband subsystem mounted at all is the common case
		 * on a host without any RDMA gear -- treat as "no rxe" rather
		 * than as an error so the plugin stays out of the way.
		 */
		pr_info("opendir(%s) failed; assuming no rxe devices, plugin inactive (stage %d)\n",
			IBDEV_SYSFS_DIR, stage);
		return 0;
	}

	while ((de = readdir(d)) != NULL) {
		char drv[64];

		if (de->d_name[0] == '.')
			continue;

		if (!resolve_ibdev_driver(de->d_name, drv, sizeof(drv))) {
			pr_debug("ibdev %s: driver unresolved, skipping\n",
				 de->d_name);
			continue;
		}

		pr_debug("ibdev %s -> driver %s\n", de->d_name, drv);

		if (!strcmp(drv, "rxe"))
			rxe_dev_count++;
	}

	closedir(d);

	if (rxe_dev_count > 0) {
		rxe_active = true;
		pr_info("active (stage %d): %d rxe ibdev(s) found\n", stage,
			rxe_dev_count);
	} else {
		pr_info("inactive (stage %d): no rxe ibdevs on this host\n",
			stage);
	}

	/*
	 * Returning zero unconditionally so the .so stays loaded even when
	 * inactive: the dump-time arbitration in commit 5 still wants the
	 * plugin queryable so it can report "no, I do not claim this
	 * context" and let the missing-coverage error name us.
	 */
	return 0;
}

static void rdma_rxe_plugin_fini(int stage, int ret)
{
	pr_info("fini (stage %d ret %d): was %s, %d rxe ibdev(s)\n", stage,
		ret, rxe_active ? "active" : "inactive", rxe_dev_count);

	/*
	 * Drop the per-restore cdev fd cache. Holds dup()s of the
	 * fds open_uverbs_cdev minted with GET_CONTEXT(restore mode);
	 * by fini time the restored process has its own copies (via
	 * UPDATE_VMA_MAP -> dup -> pie restorer; via uverbsfd_open ->
	 * dumpee's fd table) so closing our copies here is safe.
	 */
	rxe_cdev_cache_drop_all();
}

/*
 * Per-context claim hook (CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT).
 *
 * Invoked at dump time for every uverbs context the target process
 * holds, and again at restore time as a "does the destination's
 * plugin set still cover this image?" check. Returns the plugin's
 * RdmaCriuDriver value (RCD_RXE) iff:
 *
 *   - the plugin is active on this host (rxe_active is set, i.e.
 *     init() found at least one rxe ibdev present);
 *   - AND the context's kernel driver is RDMA_DRIVER_RXE.
 *
 * Either condition failing -> return RCD_UNKNOWN to decline the
 * context. Negative returns are reserved for "I would normally
 * claim this but a probe failed" (none of which apply to rxe; rxe
 * has no host-side gate beyond the driver being loaded). The
 * plugin set arbitration in criu/rdma.c::rdma_arbitrate_plugin_claim()
 * enforces exactly-one-claim across all loaded RDMA plugins.
 */
static int rdma_rxe_plugin_claim_uverbs_context(const char *ibdev,
						uint32_t kernel_driver_id)
{
	if (!rxe_active) {
		pr_debug("claim(%s, kdrv=%u): plugin inactive, declining\n",
			 ibdev, kernel_driver_id);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}
	if (kernel_driver_id != RDMA_DRIVER_RXE) {
		pr_debug("claim(%s, kdrv=%u): kernel driver is not "
			 "RDMA_DRIVER_RXE (%u), declining\n",
			 ibdev, kernel_driver_id, (uint32_t)RDMA_DRIVER_RXE);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}

	pr_info("claim(%s, kdrv=%u): claiming as RCD_RXE\n", ibdev,
		kernel_driver_id);
	return RDMA_CRIU_DRIVER__RCD_RXE;
}

#define IB_UVERBS_CLASS_DIR "/sys/class/infiniband_verbs"

/*
 * Read a small sysfs file into @buf, NUL-terminate, strip a single
 * trailing newline. Returns >=0 (bytes read) on success, -1 on
 * any I/O error. @buflen must include space for the NUL.
 */
static int rxe_read_sysfs(const char *path, char *buf, size_t buflen)
{
	int fd, n;

	if (buflen == 0)
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, buflen - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	if (n > 0 && buf[n - 1] == '\n')
		buf[--n] = '\0';
	return n;
}

/*
 * Issue IB_USER_VERBS_CMD_GET_CONTEXT via the legacy write() path
 * with RXE_ALLOC_UCTX_RESTORE_MODE in the trailing
 * rxe_alloc_ucontext_req driver_data.
 *
 * The new RDMA_VERBS_IOCTL UVERBS_METHOD_GET_CONTEXT path doesn't
 * currently accept driver-specific data (no UHW attribute defined for
 * it), so the rxe restore-mode flag has to land in udata via the
 * legacy write() path. mlx5_vfmig has the same constraint and uses
 * the same shape (vfmig_send_get_context_v2 in the mlx5 plugin); a
 * future "add UHW to UVERBS_METHOD_GET_CONTEXT" kernel patch would
 * let both helpers migrate to the ioctl path -- until then, legacy
 * write is the canonical way to get a per-driver alloc-ucontext-req
 * to the driver hook.
 *
 * Restore mode is unconditional here. RDMA_OPEN_UVERBS_CDEV is only
 * invoked from CRIU's restore path, and the kernel-side
 * rxe_ucontext.restore_mode bit is sticky-and-harmless: it only gates
 * the per-class UVERBS_METHOD_RESTORE_<TYPE> dispatchers, which
 * non-restoring callers won't issue anyway. So every cdev we open
 * here gets opened in restore mode, no plugin-visible flag needed.
 *
 * Returns 0 on success, -errno on failure. Closes the vestigial
 * resp.async_fd the kernel installs; CRIU reconstructs the workload's
 * async-event fd separately via UverbsAsyncEvFile.
 */
static int rxe_send_get_context_restore(int fd)
{
	struct {
		struct ib_uverbs_cmd_hdr hdr;
		struct ib_uverbs_get_context get_ctx;
		struct rxe_alloc_ucontext_req_local req;
	} cmd = {};
	struct ib_uverbs_get_context_resp resp = {};
	ssize_t n;

	cmd.hdr.command = IB_USER_VERBS_CMD_GET_CONTEXT;
	cmd.hdr.in_words = sizeof(cmd) / 4;
	cmd.hdr.out_words = sizeof(resp) / 4;
	cmd.get_ctx.response = (uintptr_t)&resp;
	cmd.req.flags = RXE_ALLOC_UCTX_RESTORE_MODE;

	n = write(fd, &cmd, sizeof(cmd));
	if (n < 0)
		return -errno;
	if ((size_t)n != sizeof(cmd))
		return -EIO;
	close((int)resp.async_fd);
	return 0;
}

/*
 * Restore-side per-context cdev open
 * (CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV).
 *
 * The image's reg_file_entry carries the source's cdev path,
 * e.g. "/dev/infiniband/uverbs5". On the destination the same
 * ibdev name (e.g. "rxe0") may be at a different minor: the
 * kernel ib_uverbs class assigns minors in probe order, and probe
 * order is not stable across boots, hosts, or rdma_link
 * add/delete churn. The authoritative reverse-mapping (ibdev name
 * -> cdev) is kept under /sys/class/infiniband_verbs/uverbsN/
 * ibdev: each uverbs cdev exposes a one-line file naming the
 * ibdev it serves. Walking that directory and matching on the
 * recorded ib_dev string gives us the *current* destination cdev
 * regardless of minor drift.
 *
 * Note we deliberately do NOT use /sys/class/infiniband/<ibdev>/
 * for this reverse lookup: that subtree describes the InfiniBand
 * device class itself and does not expose a 'dev' file -- only
 * /sys/class/infiniband_verbs/ does, because the cdev *is* a
 * member of the infiniband_verbs class.
 *
 * For rxe specifically there is no further work to do at restore
 * time -- soft-RoCE is a software provider, the destination
 * ibdev is assumed to already exist (the orchestrator/operator
 * has run `rdma link add rxe0 ...`), and its uverbs cdev is just
 * the matching /dev/infiniband/uverbsN node.
 */
static int rdma_rxe_plugin_open_uverbs_cdev(const UverbsFileEntry *uvfe)
{
	const UverbsFileEntry *u = (const UverbsFileEntry *)uvfe;
	char path[PATH_MAX], ibdev[64], cdevpath[PATH_MAX];
	struct dirent *de;
	DIR *d;
	int fd = -1, rc;
	bool found = false;

	if (!u->ib_dev || u->ib_dev[0] == '\0') {
		pr_err("open_uverbs_cdev: image record missing ib_dev "
		       "(uvfe id %#x); cannot resolve cdev\n", u->id);
		return -1;
	}

	d = opendir(IB_UVERBS_CLASS_DIR);
	if (!d) {
		pr_perror("open_uverbs_cdev: opendir(%s)",
			  IB_UVERBS_CLASS_DIR);
		return -1;
	}

	while ((de = readdir(d)) != NULL) {
		if (strncmp(de->d_name, "uverbs", 6) != 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s/ibdev",
			 IB_UVERBS_CLASS_DIR, de->d_name);
		if (rxe_read_sysfs(path, ibdev, sizeof(ibdev)) < 0)
			continue;
		if (strcmp(ibdev, u->ib_dev) != 0)
			continue;

		snprintf(cdevpath, sizeof(cdevpath), "/dev/infiniband/%s",
			 de->d_name);
		fd = open(cdevpath, O_RDWR | O_CLOEXEC);
		if (fd < 0) {
			pr_perror("open_uverbs_cdev: open(%s) for ibdev=%s",
				  cdevpath, u->ib_dev);
			closedir(d);
			return -1;
		}
		pr_info("open_uverbs_cdev: ibdev=%s -> %s (fd=%d)\n",
			u->ib_dev, cdevpath, fd);
		found = true;
		break;
	}
	closedir(d);

	if (!found) {
		pr_err("open_uverbs_cdev: ibdev '%s' not found among "
		       "%s/uverbs* -- the destination is missing the "
		       "source's ibdev. For rxe: "
		       "`rdma link add %s type rxe netdev <iface>`.\n",
		       u->ib_dev, IB_UVERBS_CLASS_DIR, u->ib_dev);
		return -1;
	}

	/*
	 * Per the uniform RDMA_OPEN_UVERBS_CDEV contract, hand back a
	 * fd that already has a kernel ucontext on it -- uverbsfd_open
	 * no longer issues GET_CONTEXT itself.
	 *
	 * Open in restore mode (RXE_ALLOC_UCTX_RESTORE_MODE) so the
	 * generic UVERBS_METHOD_RESTORE_<TYPE> dispatchers in
	 * criu/rdma.c::rdma_restore_uobj_dag() are unblocked for the
	 * uobjects this ufile holds. Restore mode is sticky and harmless
	 * for callers that never issue RESTORE_<TYPE>, so no contract
	 * change is needed -- every restore-side cdev gets it.
	 */
	rc = rxe_send_get_context_restore(fd);
	if (rc) {
		pr_err("open_uverbs_cdev: GET_CONTEXT(restore mode) "
		       "on fd=%d for ibdev=%s failed: %d (%s)\n",
		       fd, u->ib_dev, rc, strerror(-rc));
		close(fd);
		return -1;
	}

	/*
	 * Stash a dup of the GET_CONTEXT'd fd so the later
	 * UPDATE_VMA_MAP hook (running from open_filemap during
	 * open_vmas, before pie hands over) can return a sibling
	 * fd referring to the *same struct file*. dup() on linux
	 * shares the underlying struct file, so the ucontext we
	 * just attached is visible through the dup'd fd too --
	 * which is precisely what ib_uverbs_mmap needs to find
	 * the ufile->ucontext during the cdev VMA's mmap. The
	 * caller-returned fd stays the original; CRIU plumbs it
	 * into the dumpee's fd table and may close/dup it
	 * elsewhere without affecting our cached copy. See the
	 * cache header comment for the lifetime contract.
	 *
	 * Park the cached dup at >= RXE_CACHED_FD_FLOOR so it
	 * stays out of the way of CRIU's dumpee-fd installation
	 * (F_DUPFD picks the lowest free slot; without parking,
	 * dup() would land at e.g. fd 3 and collide with a
	 * dumpee that wants fd 3).
	 */
	{
		int hi = fcntl(fd, F_DUPFD_CLOEXEC, RXE_CACHED_FD_FLOOR);

		if (hi < 0) {
			pr_perror("open_uverbs_cdev: F_DUPFD_CLOEXEC(fd=%d, "
				  ">=%d) for cache (ibdev=%s)",
				  fd, RXE_CACHED_FD_FLOOR, u->ib_dev);
			close(fd);
			return -1;
		}
		rxe_cdev_cache_remember(u->ib_dev, hi);
	}

	return fd;
}

/*
 * UPDATE_VMA_MAP hook for /dev/infiniband/uverbs* VMAs that the rxe
 * plugin claimed at dump time. Runs from open_filemap() during
 * open_vmas(), AFTER prepare_fds() (where uverbsfd_open ->
 * open_uverbs_cdev populated rxe_cdev_cache) and BEFORE the pie
 * restorer mmap() blob runs.
 *
 * Why we must intercept here instead of letting CRIU's generic
 * open_path() handle the cdev:
 *   - Each open() of /dev/infiniband/uverbsN mints a brand-new
 *     ib_uverbs_file with ufile->ucontext == NULL. RESTORE_*
 *     ioctls do not propagate to a sibling open: ucontext is per-
 *     struct-file. ib_uverbs_mmap calls ib_uverbs_get_ucontext_
 *     file which rejects ucontext==NULL with -EINVAL, *before*
 *     reaching device->ops.mmap (rxe_mmap). The pie restorer's
 *     mmap of a fresh-open cdev fd therefore always fails.
 *   - dup() of an existing fd that already has GET_CONTEXT issued
 *     shares the struct file -- the dup'd fd sees the same
 *     ucontext, and rxe_mmap is reached normally.
 *
 * Wiring contract (run_plugins / open_filemap):
 *   ret == 1   -- claimed: *plugin_fd is a fresh fd that CRIU
 *                 will hand to the pie restorer; new_pgoff is the
 *                 (unchanged here) byte offset.
 *   ret == 0   -- not claimed by us; let CRIU continue.
 *   ret < 0    -- hard error. Returning -ENOTSUP keeps CRIU's
 *                 fall-through path open (other plugins or
 *                 generic open_path).
 *
 * @path: source-side dumped cdev path (e.g. "/dev/infiniband/
 *        uverbs2"). On same-host restore this matches the
 *        destination minor; cross-host the minor may shift but
 *        we resolve through major:minor of the restore-time path
 *        below for the lookup, so the only stable join key is
 *        the ibdev name -- which we already cached at
 *        open_uverbs_cdev time.
 */
static int rdma_rxe_plugin_update_vma_map(const char *path,
					  const uint64_t addr,
					  const uint64_t old_pgoff,
					  uint64_t *new_pgoff,
					  int *plugin_fd)
{
	struct stat st;
	char ibdev[64];
	int cached_fd, dup_fd;

	(void)addr;

	if (!rxe_active)
		return -ENOTSUP;
	if (!path || strncmp(path, "/dev/infiniband/uverbs", 22) != 0)
		return -ENOTSUP;

	/*
	 * Resolve the destination cdev path (which may have a
	 * different minor than the source recorded) through
	 * major:minor -> ibdev sysfs, mirroring the dump-side
	 * rxe_match_cdev_vma() path. Matching by source `path`
	 * directly would silently misroute on cross-host restore.
	 */
	if (stat(path, &st) < 0 || !S_ISCHR(st.st_mode))
		return -ENOTSUP;
	if (rxe_chrdev_to_ibdev(st.st_rdev, ibdev, sizeof(ibdev)) < 0)
		return -ENOTSUP;

	cached_fd = rxe_cdev_cache_lookup(ibdev);
	if (cached_fd < 0) {
		pr_warn("update_vma_map: ibdev=%s not in cache (path=%s); "
			"open_uverbs_cdev did not run for this VMA's "
			"cdev. Falling through.\n", ibdev, path);
		return -ENOTSUP;
	}

	dup_fd = dup(cached_fd);
	if (dup_fd < 0) {
		pr_perror("update_vma_map: dup(cached_fd=%d) for ibdev=%s",
			  cached_fd, ibdev);
		return -1;
	}

	*new_pgoff = old_pgoff;
	*plugin_fd = dup_fd;
	pr_info("update_vma_map: path=%s ibdev=%s pgoff=%#" PRIx64
		" -> dest_fd=%d (dup of cached cdev w/ ucontext)\n",
		path, ibdev, old_pgoff, dup_fd);
	return 1;
}

/*
 * Resolve a char-device's dev_t to its ibdev name via
 * /sys/dev/char/<maj>:<min>/ibdev. Returns 0 with @out populated
 * (NUL-terminated, trailing newline stripped) on success, -1 if
 * @rdev does not name an InfiniBand uverbs char device. Mirrors
 * the symmetric helper in rdma_mlx5_vfmig_plugin -- if/when
 * shared, both can collapse into a common rdma-plugin runtime.
 */
static int rxe_chrdev_to_ibdev(dev_t rdev, char *out, size_t outsz)
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
 * Per-VMA dump-side hook (CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA).
 *
 * rxe ibverbs userspace memory-maps slices of /dev/infiniband/uverbsN
 * for the per-uobject in-kernel queues exposed to user space:
 *
 *   - CQ:  CQE ring + producer/consumer indices (this is the VMA
 *          first surfaced by the S5a HM_PD_CQ holder).
 *   - QP:  send queue + receive queue rings (S6 onward).
 *   - SRQ: shared-receive ring (S6 onward).
 *
 * CRIU's proc_parse encounters those VMAs, sees S_ISCHR, and asks
 * every loaded plugin "is this VMA yours?". Without us claiming
 * them the dump aborts with the standard "Can't handle non-regular
 * mapping" error -- which is what S5a hit on the first pd_cq pass
 * before this hook landed.
 *
 * The check is symmetric with the restore-side
 * rdma_rxe_plugin_open_uverbs_cdev path: a chrdev belongs to us if
 *
 *   1. /sys/dev/char/<maj>:<min>/ibdev exists and reads as an
 *      ibdev name. (Fast pre-filter -- non-uverbs chrdev VMAs
 *      decline silently here.)
 *
 *   2. That ibdev's resolve_ibdev_driver() resolves to "rxe" (the
 *      same heuristic init() uses to gate rxe_active). On a host
 *      with mixed providers (mlx5 + rxe) this declines mlx5 cdev
 *      VMAs and lets the mlx5 plugin's HANDLE_DEVICE_VMA claim
 *      them.
 *
 * Returns 0 on a successful claim; -ENOTSUP on any decline (so
 * run_plugins() falls through to other registered hooks, or to
 * proc_parse's "Can't handle non-regular mapping" if no plugin
 * claims). Never returns any other negative value here for the
 * same reason mlx5_vfmig's hook doesn't: a non-ENOTSUP negative
 * short-circuits run_plugins() and would silently prevent any
 * future plugin (or future hook in this plugin) from claiming a
 * VMA we mishandled.
 *
 * Restore-side mmap remap is solved end-to-end as of the S5a-
 * vma-remap landing. Two pieces:
 *
 *   1. kernel: UVERBS_METHOD_RESTORE_CQ accepts an UHW_IN
 *      struct rxe_restore_cq_req carrying vm_pgoff; rxe_create_
 *      mmap_info(forced_offset) binds the new CQ's mmap region
 *      at exactly that source-side offset, so the dest pgoff
 *      equals the source verbatim and the pie restorer's
 *      mmap-at-dumped-pgoff finds a matching pending_mmap entry
 *      under rxe_mmap. (The struct is sized > 8 bytes to escape
 *      the uverbs inline-attr trap; see the size note in
 *      include/uapi/rdma/rdma_user_rxe.h.)
 *
 *   2. plugin: rdma_rxe_plugin_update_vma_map() returns a dup()
 *      of the cdev fd open_uverbs_cdev() minted with GET_CONTEXT
 *      (RESTORE_MODE), so the pie restorer's mmap lands on the
 *      same struct file that has the ucontext attached. Without
 *      the dup, ib_uverbs_mmap fails at ib_uverbs_get_ucontext_
 *      file with -EINVAL before reaching rxe_mmap.
 *
 * No per-VMA join key is needed: source pgoff equals dest pgoff
 * once piece (1) lands, so UPDATE_VMA_MAP only substitutes the
 * fd. The source vm_pgoff each CQ's UHW_IN replays is sourced at
 * dump time from RXE_IB_METHOD_VFMIG_QUERY_CQ (rdma_rxe_plugin_
 * dump_uobj_cq below), keyed by the CQ's ufile_handle -- not from
 * a /proc/<pid>/smaps VMA scrape, which could not tell a CQ ring
 * apart from a QP's SQ/RQ ring on a shared ufile.
 *
 * @fd is unused: we resolve off @stat->st_rdev only, matching the
 * rationale spelled out on the mlx5_vfmig sibling hook.
 */
/*
 * Predicate behind HANDLE_DEVICE_VMA (claim): does this VMA's @st
 * resolve to an rxe-driven uverbs cdev?
 *
 * On a successful match, writes the ibdev name (e.g. "rxe0") to
 * @ibdev_out and returns 0. On any decline, returns -ENOTSUP and
 * leaves @ibdev_out untouched (callers don't read it on failure).
 */
static int rxe_match_cdev_vma(const struct stat *st, char *ibdev_out,
			      size_t ibdev_sz)
{
	char ibdev[64];
	char drv[64];

	if (!rxe_active)
		return -ENOTSUP;
	if (!S_ISCHR(st->st_mode))
		return -ENOTSUP;

	if (rxe_chrdev_to_ibdev(st->st_rdev, ibdev, sizeof(ibdev)))
		return -ENOTSUP;
	if (!resolve_ibdev_driver(ibdev, drv, sizeof(drv)))
		return -ENOTSUP;
	if (strcmp(drv, "rxe") != 0)
		return -ENOTSUP;

	if (ibdev_out && ibdev_sz)
		snprintf(ibdev_out, ibdev_sz, "%.*s",
			 (int)(ibdev_sz - 1), ibdev);
	return 0;
}

static int rdma_rxe_plugin_handle_device_vma(int fd, const struct stat *st)
{
	char ibdev[64];
	int rc;

	(void)fd;

	rc = rxe_match_cdev_vma(st, ibdev, sizeof(ibdev));
	if (rc)
		return rc;

	pr_info("handle_vma(%s): claiming uverbs-cdev mapping "
		"(rxe per-uobject queue: CQ ring / QP rings / SRQ)\n",
		ibdev);
	return 0;
}

/*
 * UAPI shims for the rxe VFMIG dump-side uverbs object, mirrors of
 *   include/uapi/rdma/rxe_user_ioctl_cmds.h
 *     enum rxe_ib_objects        { RXE_IB_OBJECT_VFMIG = (1<<NS_SHIFT) };
 *     enum rxe_ib_vfmig_methods  { ..._FREEZE_DATAPATH, ..._QUERY_QP,
 *                                  ..._QUERY_CQ };
 *     enum rxe_ib_vfmig_query_cq_attrs { ..._HANDLE, ..._RESP_BLOB };
 *
 * UVERBS_ID_NS_SHIFT is 12 across the uverbs UAPI; pinned locally here
 * (matching the mlx5_vfmig plugin's UVERBS_ID_NS_SHIFT_LOCAL) so a
 * header drift can't silently shift these ids. RXE_IB_OBJECT_VFMIG is
 * the first (and only) rxe driver object, so it sits at (1<<SHIFT)+0;
 * QUERY_CQ is the third method (FREEZE_DATAPATH=+0, QUERY_QP=+1,
 * QUERY_CQ=+2). Keep in sync with the kernel UAPI; remove once host
 * rdma-core ships rxe_user_ioctl_cmds.h.
 */
#define RXE_UVERBS_ID_NS_SHIFT_LOCAL 12
#define RXE_IB_OBJECT_VFMIG_LOCAL \
	(1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL)
#define RXE_IB_METHOD_VFMIG_QUERY_CQ_LOCAL \
	((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 2)
#define RXE_IB_ATTR_VFMIG_QUERY_CQ_HANDLE_LOCAL \
	(1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL)
#define RXE_IB_ATTR_VFMIG_QUERY_CQ_RESP_BLOB_LOCAL \
	((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 1)

/*
 * Byte-equal mirror of include/uapi/rdma/rdma_user_rxe.h::
 * rxe_query_cq_resp (16 bytes): the RXE_IB_METHOD_VFMIG_QUERY_CQ
 * PTR_OUT blob. @vm_pgoff is the CQ ring's mmap byte offset
 * (cq->queue->ip->info.offset); @cqe is the CQ's user-visible entry
 * count (cq->ibcq.cqe). Remove once host rdma-core ships the struct.
 */
struct rxe_query_cq_resp_local {
	uint64_t vm_pgoff;
	uint32_t cqe;
	uint32_t reserved;
};

/*
 * Issue RXE_IB_METHOD_VFMIG_QUERY_CQ on @fd against @cq_handle, the
 * dump-side counterpart of UVERBS_METHOD_RESTORE_CQ. @fd is criu's
 * dup of the dumpee's uverbs cdev fd (the holder of the CQ IDR), so
 * the security boundary is the ufile that owns the CQ. The kernel
 * fills @resp_out with the CQ ring's mmap offset + entry count read
 * straight from the live CQ -- the authoritative source that retires
 * the old /proc/<pid>/smaps cdev-VMA FIFO scrape (which a mixed
 * CQ+QP ufile would corrupt, since QP rings are cdev VMAs too).
 *
 * HANDLE is UVERBS_ATTR_IDR(UVERBS_OBJECT_CQ); the kernel enforces
 * len == 0 for the IDR class and reads the handle from attrs[].data
 * (same shim as the mlx5 QUERY_CQ helper). Kernel-mode CQs return
 * -ENXIO; a bogus handle returns -ENOENT from the IDR lookup.
 *
 * Returns 0 on success, -errno on failure.
 */
static int rxe_vfmig_query_cq(int fd, uint32_t cq_handle,
			      struct rxe_query_cq_resp_local *resp_out)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[2];
	} cmd = {};

	_Static_assert(sizeof(*resp_out) == 16,
		"rxe_query_cq_resp_local must be 16 bytes (kernel UAPI)");

	cmd.hdr.object_id = RXE_IB_OBJECT_VFMIG_LOCAL;
	cmd.hdr.method_id = RXE_IB_METHOD_VFMIG_QUERY_CQ_LOCAL;
	cmd.hdr.driver_id = RDMA_DRIVER_RXE;

	cmd.attrs[0].attr_id = RXE_IB_ATTR_VFMIG_QUERY_CQ_HANDLE_LOCAL;
	cmd.attrs[0].len = 0;
	cmd.attrs[0].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[0].data = cq_handle;

	cmd.attrs[1].attr_id = RXE_IB_ATTR_VFMIG_QUERY_CQ_RESP_BLOB_LOCAL;
	cmd.attrs[1].len = sizeof(*resp_out);
	cmd.attrs[1].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[1].data = (uintptr_t)resp_out;

	cmd.hdr.num_attrs = 2;
	cmd.hdr.length = sizeof(cmd.hdr) + 2 * sizeof(cmd.attrs[0]);

	if (ioctl(fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}

/*
 * Schema for the rxe-private CQ entry in the per-uobj
 * RdmaUobjEntry.plugin_blob byte slice.
 *
 * Just an 8-byte source vm_pgoff (in BYTES, matching kernel UAPI's
 * rxe_restore_cq_req::vm_pgoff which is byte-offset despite its
 * name -- compared against vma->vm_pgoff << PAGE_SHIFT in rxe_mmap).
 *
 * Rationale for owning the schema in the plugin (not via a per-
 * driver proto): the field is one fixed-size scalar; a protobuf
 * sub-message would be overkill, and the plugin is the only
 * producer + consumer. criu/rdma core treats the bytes as opaque.
 */
struct rxe_cq_plugin_blob_local {
	uint64_t vm_pgoff;
};

/*
 * UAPI lag shims for rxe's RESTORE_CQ UHW pair, mirrors of
 *   include/uapi/rdma/rdma_user_rxe.h
 *     struct rxe_create_cq_resp { struct mminfo mi; };
 *     struct rxe_restore_cq_req {
 *         __aligned_u64 vm_pgoff;
 *         __aligned_u64 reserved;
 *     };
 *
 * These used to live in criu/rdma/uobj_restore.c when core knew
 * the rxe UHW shape; they moved here when the per-driver UHW
 * pack/verify hooks took over (see
 * RDMA_RESTORE_UOBJ_CQ_UHW_PACK/_VERIFY in criu-plugin.h). The
 * @reserved tail on the IN side is the inline-attr-trap mitigation
 * the kernel UAPI carries (uverbs_fill_udata's len <= sizeof(u64)
 * inline path otherwise reads attr.data verbatim instead of
 * copying from userspace; sizing strictly above 8 bytes takes the
 * pointer path through ib_copy_from_udata). Keep in sync with the
 * upstream UAPI; remove once host rdma-core ships these structs.
 */
struct rxe_create_cq_resp_local {
	uint64_t	mi_offset;	/* mmap cookie (vm_pgoff << PAGE_SHIFT) */
	uint32_t	mi_size;	/* mmap region size, bytes */
	uint32_t	mi_pad;
};

struct rxe_restore_cq_req_local {
	uint64_t	vm_pgoff;
	uint64_t	reserved;	/* must be zero */
};

/*
 * RDMA_DUMP_UOBJ_CQ hook (rxe). Issues RXE_IB_METHOD_VFMIG_QUERY_CQ
 * on @lfd (criu's dup of the dumpee's uverbs cdev fd, the holder of
 * the CQ IDR) against @ufile_handle, packs the kernel-reported CQ
 * ring mmap offset as the 8-byte rxe_cq_plugin_blob into the entry-
 * level plugin_blob the caller attaches onto RdmaUobjEntry.
 * plugin_blob, and stamps comp_vector=0 / flags=0 (rxe has only one
 * comp vector and no non-zero create-CQ flags in v0).
 *
 * QUERY_CQ supersedes the old /proc/<pid>/smaps cdev-VMA FIFO
 * (PROCESS_DEVICE_VMA -> rdma_record/pop_cdev_vma_offset). That
 * scrape keyed nothing but FIFO order, so a ufile holding both a CQ
 * and a QP -- whose SQ/RQ rings are cdev VMAs too -- would hand the
 * CQ pop a QP ring's offset. Sourcing vm_pgoff straight off the live
 * CQ (cq->queue->ip->info.offset) makes it per-handle exact and
 * mirrors how QP rings are dumped via QUERY_QP.
 *
 * Allocates plugin_blob->data via malloc; criu/rdma/uobj_dump.c::
 * uobj_cq_cb frees it after pb_write_one consumes the bytes
 * (allocator contract identical to the mlx5 plugin's hook).
 *
 * @kernel_driver_id is unused -- the dispatcher already guaranteed
 * we only get rxe CQs. @pid is unused: unlike the retired FIFO
 * path, QUERY_CQ needs no (pid, ibdev) side-table consult.
 */
static int rdma_rxe_plugin_dump_uobj_cq(const char *ibdev,
					uint32_t kernel_driver_id,
					int lfd, uint32_t ufile_handle,
					pid_t pid,
					RdmaCqAttrs *cq_attrs,
					ProtobufCBinaryData *plugin_blob)
{
	struct rxe_query_cq_resp_local resp = {};
	struct rxe_cq_plugin_blob_local pb = {};
	uint8_t *buf;
	int rc;

	(void)kernel_driver_id;
	(void)pid;

	rc = rxe_vfmig_query_cq(lfd, ufile_handle, &resp);
	if (rc) {
		pr_err("rxe: dump_uobj_cq: QUERY_CQ(handle=%u) on ibdev=%s "
		       "failed: %d (%s)\n",
		       ufile_handle, ibdev, rc, strerror(-rc));
		return rc;
	}

	/*
	 * Sanity belt mirroring the mlx5 plugin: NLDEV's RES_CQE (which
	 * the dispatcher already stamped onto cq_attrs->cqe_count) and
	 * QUERY_CQ's cqe resolve through the same kernel field
	 * (ibcq->cqe). A mismatch means the IDR walker and NLDEV are
	 * looking at different objects -- surface it rather than paper
	 * over it.
	 */
	if (cq_attrs->has_cqe_count && cq_attrs->cqe_count != resp.cqe) {
		pr_err("rxe: CQ ufile_handle=%u on ibdev=%s: NLDEV "
		       "RES_CQE=%u disagrees with QUERY_CQ cqe=%u; "
		       "structural inconsistency, aborting dump\n",
		       ufile_handle, ibdev, cq_attrs->cqe_count, resp.cqe);
		return -EILSEQ;
	}

	pb.vm_pgoff = resp.vm_pgoff;
	buf = malloc(sizeof(pb));
	if (!buf) {
		pr_err("rxe: dump_uobj_cq: out of memory packing "
		       "plugin_blob (%zu bytes) for ufile_handle=%u\n",
		       sizeof(pb), ufile_handle);
		return -ENOMEM;
	}
	memcpy(buf, &pb, sizeof(pb));
	plugin_blob->data = buf;
	plugin_blob->len = sizeof(pb);

	cq_attrs->has_comp_vector = true;
	cq_attrs->comp_vector = 0;
	cq_attrs->has_flags = true;
	cq_attrs->flags = 0;

	pr_debug("rxe: dump_uobj_cq ibdev=%s ufile_handle=%u: "
		 "vm_pgoff=%#" PRIx64 " cqe=%u comp_vector=0 flags=0\n",
		 ibdev, ufile_handle, pb.vm_pgoff, resp.cqe);
	return 0;
}

/*
 * RDMA_RESTORE_UOBJ_CQ_UHW_PACK hook (rxe).
 *
 * Reads the source vm_pgoff packed at dump time into
 * e->plugin_blob and shapes the UHW pair for rxe's RESTORE_CQ:
 *
 *   - UHW_OUT is always present (sizeof rxe_create_cq_resp_local =
 *     16). rxe_restore_cq rejects (udata->outlen < sizeof(*uresp))
 *     before any of the actual restore work runs, so we always
 *     wire the receive buffer even when we don't intend to inspect
 *     it.
 *   - UHW_IN is present only when the dumped vm_pgoff is non-zero.
 *     Absent UHW_IN -> kernel falls back to its monotonic counter
 *     (legal but typically misses the dumped vm_pgoff -- the
 *     failure mode that motivated this whole UHW_IN dance, see
 *     d3a79140ed26).
 *
 * Output verification is byte-template-based per the rdma_uhw_spec
 * contract documented in criu-plugin.h: we pre-fill out_buf with
 * the leading 8 bytes of struct rxe_create_cq_resp (the mi_offset
 * field that should byte-equal our requested vm_pgoff) and set
 * verify_len = 8. Core memcmp's only the first 8 bytes of the
 * kernel's UHW_OUT echo against this template post-ioctl. The
 * trailing 8 bytes (mi_size + mi_pad) are kernel-determined and
 * deliberately left unverified.
 *
 * When vm_pgoff == 0 (rxe didn't ask for a specific offset at
 * dump time, or the dumped CQ predates the per-CQ vma capture)
 * we omit UHW_IN and skip verification: there's nothing to
 * compare mi_offset against. The kernel's monotonic counter
 * picks an offset and we accept it.
 */
static int rdma_rxe_plugin_restore_uobj_cq_uhw_pack(const RdmaUobjEntry *e,
						    struct rdma_uhw_spec *uhw)
{
	struct rxe_restore_cq_req_local *in = NULL;
	struct rxe_create_cq_resp_local *out = NULL;
	const struct rxe_cq_plugin_blob_local *pb;
	uint64_t vm_pgoff = 0;

	if (!e || !uhw)
		return -EINVAL;

	if (e->has_plugin_blob && e->plugin_blob.len > 0) {
		if (e->plugin_blob.len !=
		    sizeof(struct rxe_cq_plugin_blob_local)) {
			pr_err("rxe: RESTORE_CQ_UHW_PACK ufile_handle=%u "
			       "plugin_blob len=%zu, expected %zu "
			       "(rxe_cq_plugin_blob)\n",
			       e->has_ufile_handle ? e->ufile_handle : 0,
			       e->plugin_blob.len,
			       sizeof(struct rxe_cq_plugin_blob_local));
			return -EINVAL;
		}
		pb = (const struct rxe_cq_plugin_blob_local *)e->plugin_blob.data;
		vm_pgoff = pb->vm_pgoff;
	}

	/*
	 * out_buf doubles as the kernel's UHW_OUT receive area
	 * (sized to sizeof(rxe_create_cq_resp) = 16, the kernel's
	 * udata->outlen requirement) AND the byte-equal verify
	 * template. We pre-fill mi_offset with the requested
	 * vm_pgoff so a successful ioctl byte-equality the first 8
	 * bytes against this template. The remaining mi_size /
	 * mi_pad bytes stay zero in the template and are excluded
	 * from the verify by setting verify_len = 8.
	 */
	out = malloc(sizeof(*out));
	if (!out) {
		pr_err("rxe: RESTORE_CQ_UHW_PACK out of memory "
		       "(out_buf %zu bytes)\n", sizeof(*out));
		return -ENOMEM;
	}
	memset(out, 0, sizeof(*out));
	out->mi_offset = vm_pgoff;
	uhw->out_buf = out;
	uhw->out_len = sizeof(*out);
	uhw->verify_len = vm_pgoff ? sizeof(out->mi_offset) : 0;

	if (vm_pgoff) {
		in = malloc(sizeof(*in));
		if (!in) {
			free(out);
			uhw->out_buf = NULL;
			uhw->out_len = 0;
			uhw->verify_len = 0;
			pr_err("rxe: RESTORE_CQ_UHW_PACK out of memory "
			       "(in_buf %zu bytes)\n", sizeof(*in));
			return -ENOMEM;
		}
		in->vm_pgoff = vm_pgoff;
		in->reserved = 0;
		uhw->in_buf = in;
		uhw->in_len = sizeof(*in);
	} else {
		uhw->in_buf = NULL;
		uhw->in_len = 0;
	}
	return 0;
}

CR_PLUGIN_REGISTER("rdma_rxe_plugin", rdma_rxe_plugin_init,
		   rdma_rxe_plugin_fini)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT,
			rdma_rxe_plugin_claim_uverbs_context)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV,
			rdma_rxe_plugin_open_uverbs_cdev)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA,
			rdma_rxe_plugin_handle_device_vma)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__UPDATE_VMA_MAP,
			rdma_rxe_plugin_update_vma_map)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ,
			rdma_rxe_plugin_dump_uobj_cq)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_CQ_UHW_PACK,
			rdma_rxe_plugin_restore_uobj_cq_uhw_pack)

/*
 * RDMA provided driver: RCD_RXE.
 *
 * Tells the restore-side dispatcher in criu/rdma.c
 * (rdma_dispatch_open_uverbs_cdev) that this plugin is the one to
 * call when the image's UverbsFileEntry.criu_driver names
 * RCD_RXE. Symmetric with the RCD_RXE return value of
 * rdma_rxe_plugin_claim_uverbs_context() above.
 */
CR_PLUGIN_DECLARE_RDMA_PROVIDED_DRIVER(RDMA_CRIU_DRIVER__RCD_RXE);

/*
 * RDMA sharing policy: SHAREABLE.
 *
 * rxe is a software provider whose per-uverbs-context state lives
 * entirely inside the kernel module's per-fd objects (uobjs, GIDs,
 * QP numbers etc.). Snapshotting and restoring one process's context
 * on rxe<N> does not touch the kernel state of any other live owner
 * of rxe<N>: there is no shared device-wide register file to
 * reconfigure, no firmware to flash, no DMA mappings to invalidate.
 *
 * Concretely: cross-tree exclusivity check (criu/rdma.c) will see
 * other pids holding rxe<N> contexts and skip them on the strength
 * of this declaration. Without this, the safe default would be
 * EXCLUSIVE and we would refuse to dump any rxe-using process while
 * another rxe-using process exists on the same ibdev -- which is
 * the wrong call for a software provider.
 */
CR_PLUGIN_DECLARE_RDMA_SHARING(CR_RDMA_SHARING_SHAREABLE);
