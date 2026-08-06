#ifndef __CR_VFMIG_INTERNAL_H__
#define __CR_VFMIG_INTERNAL_H__

/*
 * Cross-file declarations shared between the rdma_mlx5_vfmig plugin
 * sources. Strictly NOT a public surface -- this header lives next to
 * the .c files that use it, never installed. It grows one section at a
 * time as each milestone adds a source module.
 */

#include <stdbool.h>
#include <stddef.h>

/*
 * vfmig_pci.c -- PCI / sysfs / per-PF cdev probe + resolution helpers.
 * Pure name resolution, no plugin state.
 *
 *   probe_pf_cdev()               open a /dev/mlx5_vfmig/<pf> cdev and
 *                                 count its tracked VFs via QUERY_VF.
 *   resolve_pci_bdf_via_symlink() readlink a sysfs symlink to its BDF
 *                                 basename.
 *   find_vf_id_under_pf()         map a VF BDF to its virtfnN index
 *                                 under the owning PF.
 */
int probe_pf_cdev(const char *path);
int resolve_pci_bdf_via_symlink(const char *sysfs_link_path, char *out, size_t outsz);
int find_vf_id_under_pf(const char *pf_bdf, const char *vf_bdf);

/*
 * Process-global activation flag. Set true by init() iff at least one
 * tracked VF was found across the host's PF cdevs; read by the hooks
 * added in later commits to short-circuit cheaply on a host that has
 * no mlx5_vfmig cdevs at all.
 */
extern bool vfmig_active;

/*
 * Per-PF char-device directory. init() walks this directory and opens
 * every entry as a candidate cdev; the claim path constructs per-PF
 * cdev paths under it. Defined here so all .c files agree.
 */
#define MLX5_VFMIG_DEV_DIR "/dev/mlx5_vfmig"

#endif /* __CR_VFMIG_INTERNAL_H__ */
