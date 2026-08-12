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

#include "images/mlx5_vfmig.pb-c.h"

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
int find_uverbs_cdev_for_ibdev(const char *ibdev, char *out, size_t outsz);

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

/*
 * Dump-side SAVE drain. Called from fini(DUMP) on a successful dump:
 * walks the claimed-VF set, runs SAVE_VHCA_STATE per VF, drains each
 * blob to the image dir, and appends one Mlx5VfmigStateEntry per VF to
 * mlx5_vfmig.img. Deferred to fini so the invasive SAVE runs only after
 * the rest of the dump has succeeded.
 */
void vfmig_drain_claimed_in_fini(void);

/*
 * vf_image.c -- on-disk image format helpers. Take primitives + raw
 * buffers, no dependency on dump/restore aggregate types, so this file
 * is the canonical description of the on-disk shape.
 *
 *   vfmig_drain_save_fd_to_blob() streams the SAVE_VHCA_STATE fd into a
 *   per-VF blob file under the image dir.
 *
 *   vfmig_append_state_entry() appends one length-prefixed
 *   Mlx5VfmigStateEntry record to mlx5_vfmig.img.
 *
 *   vfmig_read_image() walks mlx5_vfmig.img and returns an in-memory
 *   array of unpacked entries (caller frees each via
 *   mlx5_vfmig_state_entry__free_unpacked + free() the array).
 */
int vfmig_drain_save_fd_to_blob(int save_fd, const char *blob_path, uint64_t *out_size);
int vfmig_append_state_entry(uint32_t ctxn, const char *ibdev, const char *source_cdev_path, const char *pf_bdf,
			     uint32_t vf_id, uint32_t vhca_id, const uint8_t vf_uuid[16], const char *blob_path,
			     uint64_t blob_size);
int vfmig_read_image(Mlx5VfmigStateEntry ***out_arr, size_t *out_n);

/*
 * Image-directory fd indirection. vfmig_get_image_dir() returns the
 * override fd if one is set (vfmig_set_image_dir_override()), else
 * criu_get_image_dir(). The override lets the standalone restore binary
 * drive the plugin's read/LOAD path against a plain directory fd,
 * outside criu; unset (fd = -1) it falls back to criu's service fd.
 */
int vfmig_get_image_dir(void);
void vfmig_set_image_dir_override(int fd);
void vfmig_clear_image_dir_override(void);

/*
 * vfmig_restore.c -- restore-side VF firmware-state path.
 *
 * mlx5_vfmig_plugin_restore_vf_only() is the exported entry point the
 * standalone mlx5_vfmig_restore_vf tool dlopen()s: given an image-dir
 * fd it reads mlx5_vfmig.img and drives the destination VF restore. It
 * handles only the VF firmware layer -- uverbs contexts and RDMA
 * objects are a separate layer, not restored here.
 *
 * vfmig_restore_fini_close_all() frees the process-global restored-VF
 * cache; safe to call regardless of restore success/failure.
 */
int mlx5_vfmig_plugin_restore_vf_only(int image_dir_fd);
void vfmig_restore_fini_close_all(void);

#endif /* __CR_VFMIG_INTERNAL_H__ */
