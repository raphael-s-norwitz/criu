/*
 * vfmig_pci.c
 *
 * PCI / sysfs / per-PF cdev probe + resolution helpers for the mlx5
 * SR-IOV VFMIG plugin. Two responsibilities in this commit:
 *
 *   1. probe_pf_cdev() -- open a /dev/mlx5_vfmig/<pf> char device and
 *      count its tracked VFs via the MLX5_VFMIG_IOC_QUERY_VF ioctl.
 *      Called from init() at criu startup to decide whether the plugin
 *      should claim anything at all.
 *
 *   2. resolve_pci_bdf_via_symlink() / find_vf_id_under_pf() -- ibdev /
 *      PCI-BDF / vf_id name resolution via pure /sys walks; used by the
 *      claim hook that lands next.
 *
 * No plugin state owned here. Signatures are declared in
 * vfmig_internal.h so callers in the other carve-out files see them.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
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
 * Probe one PF cdev. Returns the number of VFs on this PF that have
 * MLX5_VFMIG_IOC_SET_TRACKED { enable=1 } currently in effect, or -1
 * on a hard ioctl/open failure (which we report but treat as "no
 * tracked VFs from this PF" rather than as a fatal plugin error -- a
 * misbehaving cdev should not poison criu startup).
 *
 * Discovery model: per the kernel UAPI doc on MLX5_VFMIG_IOC_QUERY_VF,
 * num_vfs is filled even when vf_id is out of range (the call returns
 * -ERANGE in that case but the output struct is still populated), so
 * one issuance with vf_id=0 tells us how many VFs to iterate over, and
 * a separate per-vf loop reads the @tracked bit. This is the "iterate
 * 0..num_vfs-1" pattern the kernel UAPI explicitly invites.
 */
int probe_pf_cdev(const char *path)
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
		pr_warn("QUERY_VF(vf_id=0) on %s failed: %s\n", path, strerror(errno));
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
			pr_warn("QUERY_VF(vf_id=%u) on %s failed: %s\n", vf, path, strerror(errno));
			continue;
		}
		if (qq.tracked)
			tracked++;
	}

	pr_debug("%s: num_vfs=%u tracked=%d\n", path, num_vfs, tracked);
	close(fd);
	return tracked;
}

/*
 * Resolve a /sys/.../device (or /physfn, /virtfnN) symlink at
 * @sysfs_link_path to its basename (the PCI BDF the symlink points at).
 * Caller-supplied @out is sized in @outsz. Returns 0 on success, -1
 * otherwise.
 *
 * Used to walk the chain
 *   /sys/class/infiniband/<ibdev>/device   ->  VF BDF
 *   /sys/bus/pci/devices/<vf>/physfn       ->  PF BDF
 * needed to map an ibdev to its owning mlx5 PF cdev.
 */
int resolve_pci_bdf_via_symlink(const char *sysfs_link_path, char *out, size_t outsz)
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
 * Map a VF's PCI BDF to its parent PF's vf_id (i.e. the index @virtfnN
 * under the PF's pci_dev sysfs node). Returns the vf_id on success or
 * -1 if no virtfn link matches @vf_bdf -- which is the expected outcome
 * for any non-VF mlx5_core ibdev (PFs land here too) and is therefore
 * not an error per se, just a "decline" signal back up the claim chain.
 */
int find_vf_id_under_pf(const char *pf_bdf, const char *vf_bdf)
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
		if (snprintf(vlpath, sizeof(vlpath), "%s/%s", path, de->d_name) >= (int)sizeof(vlpath))
			continue;
		if (resolve_pci_bdf_via_symlink(vlpath, vlbase, sizeof(vlbase)) != 0)
			continue;
		if (strcmp(vlbase, vf_bdf) == 0) {
			vf_id = atoi(de->d_name + strlen("virtfn"));
			break;
		}
	}

	closedir(d);
	return vf_id;
}
