#ifndef __CR_VFMIG_INTERNAL_H__
#define __CR_VFMIG_INTERNAL_H__

/*
 * Cross-file declarations shared between the rdma_mlx5_vfmig
 * plugin sources. Strictly NOT a public surface -- this header
 * lives next to the .c files that use it, never installed.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * vfmig_pci.c -- PCI / sysfs / per-PF cdev probe + resolution
 * helpers. Pure name resolution, no plugin state shared with
 * the dump or restore paths.
 */
int probe_pf_cdev(const char *path);
int resolve_pci_bdf_via_symlink(const char *sysfs_link_path,
				char *out, size_t outsz);
int find_vf_id_under_pf(const char *pf_bdf, const char *vf_bdf);
int vfmig_resolve_pf_vf(const char *ibdev,
			char *pf_bdf, size_t pf_bdfsz,
			uint32_t *vf_id);
int vfmig_resolve_pf_vf_quiet(const char *ibdev,
			      char *pf_bdf, size_t pf_bdfsz,
			      uint32_t *vf_id);
int vfmig_chrdev_to_ibdev(dev_t rdev, char *out, size_t outsz);

#endif /* __CR_VFMIG_INTERNAL_H__ */
