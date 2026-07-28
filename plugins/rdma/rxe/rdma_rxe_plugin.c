/*
 * CRIU RDMA RXE plugin -- presence detection and context claim.
 *
 * The first slice of plugin coverage for RDMA: at criu startup it walks
 * /sys/class/infiniband/ and decides whether the host has any ibdev
 * backed by the soft-RoCE (rxe) driver. That presence decision then
 * gates the per-context claim hook (CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_
 * CONTEXT), through which this plugin tells criu core it owns dump and
 * restore for rxe uverbs contexts. The actual dump/restore hooks are
 * wired in later commits; here we establish presence + claim + the
 * static sharing/provided-driver identity core arbitrates on.
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
 * declares itself inactive and lets the dump-time arbitration added in a
 * later commit fail any process that holds an rxe context (there can't be
 * one without a live rxe ibdev, so this is symmetric anyway).
 */

#include "criu-log.h"
#include "plugin.h"

#include "images/rdma_criu.pb-c.h"

#include <rdma/ib_user_ioctl_verbs.h>

#include <dirent.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_rxe_plugin: "

#define IBDEV_SYSFS_DIR "/sys/class/infiniband"

/*
 * Plugin activity is process-local state set by init() and read by the
 * per-context claim hook: an inactive plugin (no rxe ibdev on this host)
 * declines every context.
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
 * heuristic. We mirror the same fallback used in criu/rdma/driver.c
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
	 * inactive: the dump-time arbitration (rdma_arbitrate_plugin_claim)
	 * still wants the plugin queryable so it can report "no, I do not
	 * claim this context" and let the missing-coverage error name us.
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
 * has no host-side gate beyond the driver being loaded). The plugin
 * set arbitration in criu/rdma/plugin_api.c (rdma_arbitrate_plugin_
 * claim) enforces exactly-one-claim across all loaded RDMA plugins.
 */
static int rdma_rxe_plugin_claim_uverbs_context(const char *ibdev, uint32_t kernel_driver_id)
{
	if (!rxe_active) {
		pr_debug("claim(%s, kdrv=%u): plugin inactive, declining\n", ibdev, kernel_driver_id);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}
	if (kernel_driver_id != RDMA_DRIVER_RXE) {
		pr_debug("claim(%s, kdrv=%u): kernel driver is not RDMA_DRIVER_RXE (%u), declining\n", ibdev,
			 kernel_driver_id, (uint32_t)RDMA_DRIVER_RXE);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}

	pr_info("claim(%s, kdrv=%u): claiming as RCD_RXE\n", ibdev, kernel_driver_id);
	return RDMA_CRIU_DRIVER__RCD_RXE;
}

CR_PLUGIN_REGISTER("rdma_rxe_plugin", rdma_rxe_plugin_init,
		   rdma_rxe_plugin_fini)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT,
			rdma_rxe_plugin_claim_uverbs_context)

/*
 * RDMA provided driver: RCD_RXE.
 *
 * The static twin of the RCD_RXE claim return value above. Tells the
 * restore-side cdev-open dispatcher (added later) that this plugin is
 * the one to call when an image's UverbsFileEntry.criu_driver names
 * RCD_RXE.
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
 * The cross-tree exclusivity check (added with the pre-suspend
 * netlink pass) reads this declaration and skips other pids holding
 * rxe<N> contexts. Without it the safe default would be EXCLUSIVE and
 * we would refuse to dump any rxe-using process while another
 * rxe-using process exists on the same ibdev -- the wrong call for a
 * software provider.
 */
CR_PLUGIN_DECLARE_RDMA_SHARING(CR_RDMA_SHARING_SHAREABLE);
