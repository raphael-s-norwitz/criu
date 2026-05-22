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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
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

	return fd;
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
 * Note on restore-side mmap remap: this hook satisfies the
 * dump-side gate but the restore side still needs an
 * UPDATE_VMA_MAP counterpart. The kernel-side RESTORE_CQ
 * (a77cc4d8e8b9) writes a freshly-allocated mmap cookie into
 * UHW_OUT mminfo (rxe_create_cq_resp); that pgoff does NOT
 * match the source-time vm_pgoff CRIU captured in the VMA dump,
 * so the pie restorer's mmap-at-old-pgoff returns -EINVAL.
 *
 * Two complementary closing paths (S5a-vma-remap follow-on):
 *
 *   1. kernel: extend UVERBS_METHOD_RESTORE_CQ with an optional
 *      source_vm_pgoff UHW_IN attr; rxe_restore_cq xa_insert's at
 *      the source key instead of xa_alloc, so the dest pgoff
 *      equals the source verbatim. Symmetric extension when
 *      restore_qp / restore_srq land. Cleanest from CRIU's
 *      perspective -- the existing pie mmap path Just Works.
 *
 *   2. plugin: capture the kernel-returned mminfo.offset out of
 *      criu/rdma.c::rdma_send_restore_cq, side-table it under
 *      (source ufile + per-VMA join key), and have this plugin
 *      gain an UPDATE_VMA_MAP hook that translates source pgoff
 *      to dest pgoff for /dev/infiniband/uverbsN VMAs whose
 *      ibdev resolves to "rxe". Pure-userspace but needs new
 *      dump-side image plumbing (per-VMA -> per-CQ join key)
 *      because UPDATE_VMA_MAP only sees (path, addr, old_pgoff).
 *
 * Until either path lands, dumps with rxe CQs / QPs / SRQs
 * succeed but restore fails at VMA replay. The runner script
 * test/rdma/run_uverbs_cr.sh gates the pd_cq pass behind
 * UVERBS_CR_RUN_PD_CQ=1 for that reason.
 *
 * @fd is unused: we resolve off @stat->st_rdev only, matching the
 * rationale spelled out on the mlx5_vfmig sibling hook.
 */
/*
 * Predicate shared by HANDLE_DEVICE_VMA (claim) and
 * PROCESS_DEVICE_VMA (post-claim notify): does this VMA's @st
 * resolve to an rxe-driven uverbs cdev?
 *
 * On a successful match, writes the ibdev name (e.g. "rxe0") to
 * @ibdev_out and returns 0. On any decline, returns -ENOTSUP and
 * leaves @ibdev_out untouched (callers don't read it on failure).
 *
 * Centralising the predicate keeps the two hooks bit-for-bit in
 * agreement: a VMA HANDLE claims must also be a VMA PROCESS
 * records (and vice versa), even as the rxe-cdev test grows new
 * filters (e.g. multi-ibdev minor disambiguation).
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
 * Per-VMA dump-side post-claim notify
 * (CR_PLUGIN_HOOK__PROCESS_DEVICE_VMA).
 *
 * Fires once per cdev VMA after rdma_rxe_plugin_handle_device_vma
 * has already returned 0 on the same (fd, st) pair. Forwards
 * (pid, ibdev, vma_pgoff_bytes) into criu/rdma.c's process-global
 * cdev VMA side-table, so the per-uobj DAG dump (uobj_cq_cb in
 * rdma.c) can attach the source-time mmap cookie to each
 * RdmaCqAttrs.mmap_offset and round-trip it as UHW_IN at restore-
 * time RESTORE_CQ -- pinning the destination CQ's mmap region at
 * exactly the source's vm_pgoff so the pie restorer's mmap-at-
 * dumped-pgoff lands on a kernel pending_mmaps entry.
 *
 * The vma_pgoff_bytes argument is vma->vm_pgoff << PAGE_SHIFT,
 * already in the units rxe_mmap_info.info.offset (and therefore
 * rxe_restore_cq_req.vm_pgoff) takes.
 *
 * Returns 0 on success (the only meaningful return). Returns
 * -ENOMEM only on rdma_record_cdev_vma() allocation failure --
 * which run_plugins() will short-circuit, and which the
 * proc_parse caller treats as a hard dump error. Declines
 * (-ENOTSUP) for non-rxe cdev VMAs so runs with multiple RDMA
 * plugins behave correctly.
 */
static int rdma_rxe_plugin_process_device_vma(pid_t pid, int fd,
					      const struct stat *st,
					      uint64_t vma_start,
					      uint64_t vma_end,
					      uint64_t vma_pgoff_bytes)
{
	char ibdev[64];
	int rc;

	(void)fd;
	(void)vma_start;
	(void)vma_end;

	rc = rxe_match_cdev_vma(st, ibdev, sizeof(ibdev));
	if (rc)
		return rc;

	if (rdma_record_cdev_vma(pid, ibdev, vma_pgoff_bytes) < 0) {
		pr_err("process_vma(%s): rdma_record_cdev_vma failed for "
		       "pid=%d pgoff=%#" PRIx64 "\n",
		       ibdev, pid, vma_pgoff_bytes);
		return -ENOMEM;
	}

	pr_info("process_vma(%s, pid=%d): recorded cdev VMA pgoff=%#" PRIx64
		" for restore-time UHW_IN replay\n",
		ibdev, pid, vma_pgoff_bytes);
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
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__PROCESS_DEVICE_VMA,
			rdma_rxe_plugin_process_device_vma)

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
