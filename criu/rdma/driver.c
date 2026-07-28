/*
 * RDMA driver-name resolution helpers.
 *
 * Pure utility code: no shared static state with the rest of
 * criu/rdma. Callers feed in a uverbs cdev (major,minor) or an
 * ibdev name and get back a kernel-module driver name and/or
 * the matching RDMA_DRIVER_* UAPI enum value.
 *
 * Public surface:
 *   rdma_driver_name_from_ibdev()  declared in criu/include/rdma.h
 *   rdma_driver_name_to_id()       declared in criu/include/rdma.h
 *
 * Internal cross-file accessor (used by criu/rdma/uverbsfd.c's
 * dump_uverbsfile path):
 *   rdma_ibdev_from_chrdev()       declared in criu/include/rdma/internal.h
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/limits.h>

#include <rdma/ib_user_ioctl_verbs.h>

#include "common/compiler.h"
#include "log.h"
#include "rdma.h"
#include "rdma/internal.h"

#undef LOG_PREFIX
#define LOG_PREFIX "rdma: "

/*
 * Read the entirety of a sysfs file into the caller's buffer, NUL-terminate,
 * and trim a single trailing newline if present. Returns 0 on success, -1
 * on any error. The caller-provided buffer must have room for the data plus
 * a NUL byte.
 */
static int read_sysfs_file(const char *path, char *buf, size_t buflen)
{
	int fd, n;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, buflen - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	if (n > 0 && buf[n - 1] == '\n')
		buf[n - 1] = '\0';
	return 0;
}

/*
 * Resolve the chrdev (major,minor) backing a uverbs cdev fd to its ibdev
 * name (e.g. "rxe0", "mlx5_0") via /sys/dev/char/<maj>:<min>/ibdev. Works
 * uniformly across PCI-backed and software-defined providers because the
 * "ibdev" attribute is exposed by the kernel ib_uverbs class for every
 * uverbs cdev. Result is written to @out (NUL-terminated). Returns 0 on
 * success.
 */
int rdma_ibdev_from_chrdev(unsigned int maj, unsigned int min,
			   char *out, size_t outsz)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/sys/dev/char/%u:%u/ibdev", maj, min);
	if (read_sysfs_file(path, out, outsz) < 0) {
		pr_perror("Can't read %s", path);
		return -1;
	}
	if (out[0] == '\0') {
		pr_err("Empty ibdev name from %s\n", path);
		return -1;
	}
	return 0;
}

/*
 * Resolve an ibdev name to its backing kernel-module driver name (e.g.
 * "mlx5_core", "rxe"). Strategy:
 *   1. PCI-backed devices expose /sys/class/infiniband/<name>/device/driver
 *      as a symlink whose basename is the driver module. This covers
 *      mlx5/mlx4/bnxt_re/qedr/irdma/etc.
 *   2. Software-defined providers (rxe, siw) have no PCI parent and no
 *      such symlink. Fall back to a name-prefix mapping for the small set
 *      of providers we explicitly support.
 *
 * Returns 0 on success with the driver name written to @out. Returns -1 if
 * neither lookup yields a driver name -- callers should treat that as
 * "unknown provider, fail dump."
 */
int rdma_driver_name_from_ibdev(const char *ibdev,
				char *out, size_t outsz)
{
	char path[PATH_MAX];
	char target[PATH_MAX];
	const char *base;
	ssize_t n;

	snprintf(path, sizeof(path),
		 "/sys/class/infiniband/%s/device/driver", ibdev);
	n = readlink(path, target, sizeof(target) - 1);
	if (n > 0) {
		const char *src;

		target[n] = '\0';
		base = strrchr(target, '/');
		src = base ? base + 1 : target;
		/* width-bounded format so -Wformat-truncation is happy */
		snprintf(out, outsz, "%.*s", (int)(outsz - 1), src);
		return 0;
	}

	if (!strncmp(ibdev, "rxe", 3)) {
		snprintf(out, outsz, "rxe");
		return 0;
	}
	if (!strncmp(ibdev, "siw", 3)) {
		snprintf(out, outsz, "siw");
		return 0;
	}

	return -1;
}

/*
 * Map a kernel-module driver name to the matching RDMA_DRIVER_* enum value
 * the kernel UAPI uses. Returns RDMA_DRIVER_UNKNOWN for unrecognized names;
 * dump_uverbsfile() treats that as a hard error so a checkpoint is never
 * written that the restoring criu would have no provider for.
 *
 * When adding a new entry here, also extend rdma_driver_name_from_ibdev()
 * if the new provider needs the name-prefix fallback (i.e. it is software-
 * defined and has no PCI parent in sysfs).
 */
uint32_t rdma_driver_name_to_id(const char *name)
{
	static const struct {
		const char *name;
		uint32_t id;
	} map[] = {
		{ "rxe", RDMA_DRIVER_RXE },
		{ "siw", RDMA_DRIVER_SIW },
		{ "mlx5_core", RDMA_DRIVER_MLX5 },
		{ "mlx4_core", RDMA_DRIVER_MLX4 },
		{ "bnxt_re", RDMA_DRIVER_BNXT_RE },
		{ "qedr", RDMA_DRIVER_QEDR },
		{ "irdma", RDMA_DRIVER_IRDMA },
		{ "i40iw", RDMA_DRIVER_I40IW },
		{ "hns_roce", RDMA_DRIVER_HNS },
		{ "ocrdma", RDMA_DRIVER_OCRDMA },
		{ "vmw_pvrdma", RDMA_DRIVER_VMW_PVRDMA },
		{ "iw_cxgb4", RDMA_DRIVER_CXGB4 },
		{ "iw_cxgb3", RDMA_DRIVER_CXGB3 },
		{ "ib_mthca", RDMA_DRIVER_MTHCA },
		{ "iw_nes", RDMA_DRIVER_NES },
		{ "usnic_verbs", RDMA_DRIVER_USNIC },
		{ "efa", RDMA_DRIVER_EFA },
		{ "hfi1", RDMA_DRIVER_HFI1 },
		{ "qib", RDMA_DRIVER_QIB },
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(map); i++)
		if (!strcmp(name, map[i].name))
			return map[i].id;
	return RDMA_DRIVER_UNKNOWN;
}
