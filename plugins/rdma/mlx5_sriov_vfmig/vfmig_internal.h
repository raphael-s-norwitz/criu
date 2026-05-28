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

#include "images/mlx5_vfmig.pb-c.h"

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

/*
 * vfmig_uverbs.c -- mlx5 ucontext ioctl wrappers (legacy
 * IB_USER_VERBS_CMD_GET_CONTEXT write() path + RDMA_VERBS_IOCTL
 * MLX5_IB_OBJECT_VFMIG methods). Pure marshaling -- no plugin
 * state, no /sys or /dev side effects.
 *
 * vfmig_query_uctx and vfmig_query_dyn_uars are file-private to
 * vfmig_uverbs.c (only used by their snapshot wrappers); the
 * rest are reachable from the dump and restore paths.
 *
 * Forward-declared rather than including mlx5_uapi.h to keep
 * this header lightweight for callers that only need the PCI
 * helpers above.
 */
struct mlx5_ib_vfmig_ucontext_meta_local;
struct mlx5_ib_vfmig_dyn_uar_record_local;

int vfmig_send_get_context_v2(int fd, uint32_t flags,
			      uint64_t lib_caps,
			      uint32_t total_bfregs,
			      uint32_t ll_bfregs,
			      uint8_t max_cqe_version,
			      uint32_t adopt_devx_uid);

int vfmig_restore_uctx(int fd,
		       const uint32_t *uar_table, size_t uar_n,
		       const uint32_t *bfreg_count, size_t bfreg_n,
		       const struct mlx5_ib_vfmig_ucontext_meta_local *meta);

int vfmig_snapshot_uctx(int fd,
			struct mlx5_ib_vfmig_ucontext_meta_local *meta_out,
			uint32_t **uar_out, size_t *uar_n_out,
			uint32_t **cnt_out, size_t *cnt_n_out);

int vfmig_restore_dyn_uars(int fd,
			   const struct mlx5_ib_vfmig_dyn_uar_record_local *records,
			   size_t n_records);

int vfmig_snapshot_dyn_uars(int fd,
			    struct mlx5_ib_vfmig_dyn_uar_record_local **records_out,
			    size_t *n_out);

/*
 * vf_image.c -- on-disk format for the plugin's per-dump
 * sidecar image (mlx5_vfmig.img + per-VF SAVE_VHCA_STATE blob
 * files). Pure proto pack/unpack + flat-file I/O against
 * criu_get_image_dir(); no plugin state.
 *
 * vfmig_drain_save_fd_to_blob() writes the blob, given the
 * SAVE fd from MLX5_VFMIG_IOC_SAVE_VHCA_STATE and a caller-
 * chosen blob path under the image dir.
 *
 * vfmig_append_state_entry() takes primitives + buffers (no
 * dependency on dump.c-private aggregate types) and appends
 * one Mlx5VfmigStateEntry length-prefixed record to
 * mlx5_vfmig.img.
 *
 * vfmig_read_image() walks the file on restore and returns
 * an in-memory array of unpacked entries (caller frees with
 * mlx5_vfmig_state_entry__free_unpacked + free()).
 */
int vfmig_drain_save_fd_to_blob(int save_fd,
				const char *blob_path,
				uint64_t *out_size);

int vfmig_append_state_entry(uint32_t ctxn, const char *ibdev,
			     const char *source_cdev_path,
			     const char *pf_bdf, uint32_t vf_id,
			     uint32_t vhca_id,
			     const char *blob_path, uint64_t blob_size,
			     const struct mlx5_ib_vfmig_ucontext_meta_local *uctx_meta,
			     const uint32_t *uctx_uar, size_t uctx_uar_n,
			     const uint32_t *uctx_cnt, size_t uctx_cnt_n,
			     const struct mlx5_ib_vfmig_dyn_uar_record_local *uctx_dyn,
			     size_t uctx_dyn_n,
			     uint32_t source_devx_uid);

int vfmig_read_image(Mlx5VfmigStateEntry ***out_arr, size_t *out_n);

#endif /* __CR_VFMIG_INTERNAL_H__ */
