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
#include <stdint.h>

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

/*
 * vfmig_dump.c -- dump-side plugin state.
 *
 * The claimed-VF cache. The claim hook (which core RDMA dump-time
 * arbitration runs over every snapshot-tree context) already resolves
 * each context's (pf_bdf, vf_id) and confirms QUERY_VF.tracked=1;
 * vfmig_claimed_add() records each VF we win the claim for so the
 * dump-side hooks added in later commits (CHECKPOINT_DEVICES suspend,
 * fini(DUMP) SAVE drain) can act on exactly that set without re-walking
 * /proc/<pid>/fd or re-querying sysfs. Deduplicated by (pf_bdf, vf_id)
 * since a VF can back several contexts. Reset by init()/fini() via
 * vfmig_claimed_clear().
 */
void vfmig_claimed_add(const char *ibdev, const char *pf_bdf, uint32_t vf_id);
void vfmig_claimed_clear(void);

#endif /* __CR_VFMIG_INTERNAL_H__ */
