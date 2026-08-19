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
#include <sys/types.h>

#include "criu-plugin.h"
#include "images/mlx5_vfmig.pb-c.h"
#include "images/uverbsfd.pb-c.h"
#include "mlx5_uapi.h"

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
 *   vfmig_uverbs_rdev_to_ibdev()  map a uverbs cdev device number back
 *                                 to its ibdev (reverse cdev lookup).
 */
int probe_pf_cdev(const char *path);
int resolve_pci_bdf_via_symlink(const char *sysfs_link_path, char *out, size_t outsz);
int find_vf_id_under_pf(const char *pf_bdf, const char *vf_bdf);
int find_uverbs_cdev_for_ibdev(const char *ibdev, char *out, size_t outsz);
int vfmig_uverbs_rdev_to_ibdev(dev_t rdev, char *out, size_t outsz);

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
 * Per-ucontext dump capture. rdma_mlx5_vfmig_plugin_dump_uverbs_context()
 * is the RDMA_DUMP_UVERBS_CONTEXT hook: core RDMA dump hands it a
 * drained cdev fd sharing the source ucontext's IDR, and it snapshots
 * that ucontext (QUERY_UCONTEXT, falling back to QUERY_DYN_UARS) onto
 * the matching claimed-VF entry so the fini(DUMP) SAVE drain can write
 * it into mlx5_vfmig.img. See the claimed-set note above for why the
 * snapshot rides on the claimed entry rather than a separate queue.
 */
int rdma_mlx5_vfmig_plugin_dump_uverbs_context(const char *ibdev, uint32_t kernel_driver_id, uint32_t ctxn, int lfd,
					       pid_t pid);

/*
 * Per-PD dump capture. rdma_mlx5_vfmig_plugin_dump_uobj_pd() is the
 * RDMA_DUMP_UOBJ_PD hook: core's PD walker dispatches it per mlx5 PD
 * with a shared-IDR cdev fd and the PD's ufile handle, and it QUERY_PDs
 * the source FW pdn into @plugin_blob (a struct
 * mlx5_ib_restore_pd_req_local) for the restore side. The source PD's
 * owning uid (QUERY_PD RESP_UID) is dump-side diagnostic only -- it is
 * commonly non-zero (default libmlx5 auto-DEVX) and never enforced;
 * RESTORE_PD adopts the pdn under the destination ucontext's uid.
 */
int rdma_mlx5_vfmig_plugin_dump_uobj_pd(const char *ibdev, uint32_t kernel_driver_id, int lfd, uint32_t ufile_handle,
					pid_t pid, ProtobufCBinaryData *plugin_blob);

/*
 * Per-CQ dump capture. rdma_mlx5_vfmig_plugin_dump_uobj_cq() is the
 * RDMA_DUMP_UOBJ_CQ hook: core's CQ walker dispatches it per mlx5 CQ
 * with a shared-IDR cdev fd and the CQ's ufile handle, and it QUERY_CQs
 * the restore payload (cqn/cqe_size/buf_addr/db_addr into @plugin_blob)
 * plus the hw-agnostic comp_vector/flags into @cq_attrs.
 */
int rdma_mlx5_vfmig_plugin_dump_uobj_cq(const char *ibdev, uint32_t kernel_driver_id, int lfd, uint32_t ufile_handle,
					pid_t pid, RdmaCqAttrs *cq_attrs, ProtobufCBinaryData *plugin_blob);

/*
 * Per-QP dump capture. rdma_mlx5_vfmig_plugin_dump_uobj_qp() is the
 * RDMA_DUMP_UOBJ_QP hook: core's QP walker dispatches it per mlx5 QP with
 * a shared-IDR cdev fd and the QP's ufile handle, and it QUERY_QPs the
 * restore payload (WQ-ring / doorbell source VAs, FW qpn, WQ sizing into
 * @plugin_blob) plus the hw-agnostic create user_handle into @qp_attrs.
 */
int rdma_mlx5_vfmig_plugin_dump_uobj_qp(const char *ibdev, uint32_t kernel_driver_id, int lfd, uint32_t ufile_handle,
					pid_t pid, RdmaQpAttrs *qp_attrs, ProtobufCBinaryData *plugin_blob);

/*
 * vfmig_uverbs.c -- mlx5 ucontext uverbs-ioctl QUERY wrappers. Pure
 * marshaling over MLX5_IB_OBJECT_VFMIG; no plugin state.
 *
 *   vfmig_snapshot_uctx()      two-pass QUERY_UCONTEXT: fills @meta and
 *                              allocates the UAR-index / bfreg-count
 *                              arrays (static-UAR mode). Returns
 *                              -EOPNOTSUPP for a dyn-UAR ucontext.
 *   vfmig_snapshot_dyn_uars()  two-pass QUERY_DYN_UARS: allocates the
 *                              dyn-UAR record array (dyn-UAR mode).
 *   vfmig_query_pd()           QUERY_PD: fills @blob_out (source FW pdn,
 *                              the verbatim RESTORE_PD UHW) and @uid_out
 *                              (source PD's mpd->uid) for the PD the
 *                              caller resolves by ufile handle.
 *
 * Exactly one of the two applies to any given ucontext; the dump hook
 * tries the static path first and falls back on -EOPNOTSUPP. Arrays
 * are caller-owned (free()).
 */
int vfmig_snapshot_uctx(int fd, struct mlx5_ib_vfmig_ucontext_meta_local *meta_out, uint32_t **uar_out,
			size_t *uar_n_out, uint32_t **cnt_out, size_t *cnt_n_out);
int vfmig_snapshot_dyn_uars(int fd, struct mlx5_ib_vfmig_dyn_uar_record_local **records_out, size_t *n_out);
int vfmig_query_pd(int fd, uint32_t pd_handle, struct mlx5_ib_restore_pd_req_local *blob_out, uint32_t *uid_out);
int vfmig_query_cq(int fd, uint32_t cq_handle, struct mlx5_ib_restore_cq_req_local *blob_out, uint32_t *cqe_out,
		   uint32_t *comp_vector_out, uint32_t *flags_out);
int vfmig_query_qp(int fd, uint32_t qp_handle, struct mlx5_ib_restore_qp_req_local *blob_out,
		   uint64_t *user_handle_out, uint32_t *create_flags_out);

/*
 * Restore-side ucontext replay (static-UAR mode). Mirror of the QUERY
 * surface above, consumed by the restore-side cdev-open path:
 *
 *   vfmig_send_get_context_v2()  legacy IB_USER_VERBS_CMD_GET_CONTEXT
 *                                alloc with the mlx5 driver payload;
 *                                @flags carries VFMIG_RESTORE so the
 *                                kernel arms the restore-pending gate.
 *   vfmig_restore_uctx()         MLX5_IB_METHOD_VFMIG_RESTORE_UCONTEXT:
 *                                replays the captured uar_table +
 *                                bfreg_count + meta into the ucontext.
 *   vfmig_restore_dyn_uars()     MLX5_IB_METHOD_VFMIG_RESTORE_DYN_UARS:
 *                                replays the captured dyn-UAR record
 *                                array into the ucontext.
 *
 * All are pure marshaling; the caller owns the fd and the arrays.
 */
int vfmig_send_get_context_v2(int fd, uint32_t flags, uint64_t lib_caps, uint32_t total_bfregs, uint32_t ll_bfregs,
			      uint8_t max_cqe_version, uint32_t adopt_devx_uid);
int vfmig_restore_uctx(int fd, const uint32_t *uar_table, size_t uar_n, const uint32_t *bfreg_count, size_t bfreg_n,
		       const struct mlx5_ib_vfmig_ucontext_meta_local *meta);
int vfmig_restore_dyn_uars(int fd, const struct mlx5_ib_vfmig_dyn_uar_record_local *records, size_t n_records);

/*
 * Snapshot-ordering datapath suspend. rdma_mlx5_vfmig_plugin_checkpoint_devices()
 * is the CHECKPOINT_DEVICES hook: it parks every claimed VF to STOP
 * (SUSPEND_VHCA) at CRIU's freeze point, before task memory is copied.
 * vfmig_resume_suspended_vfs() resumes that set (RESUME_VHCA) from
 * fini(DUMP); vfmig_suspended_clear() drops it at init()/fini() reset.
 */
int rdma_mlx5_vfmig_plugin_checkpoint_devices(int pid);
void vfmig_resume_suspended_vfs(void);
void vfmig_suspended_clear(void);

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
 *
 * The optional ucontext-snapshot buffers (uctx_*) are opaque to this
 * file: it copies the raw bytes into the matching optional proto
 * fields when the pointer is non-NULL and the length is non-zero, and
 * leaves the field unset otherwise. A firmware-only record (no seed
 * context) passes NULL for all of them. Exactly one of the static
 * pair {uctx_meta, uctx_uar_table [+ uctx_bfreg_count]} or the dyn
 * buffer uctx_dyn_uar_records is populated for a context-bearing VF;
 * the shaping/validation is the dump hook's job, not this writer's.
 */
struct vfmig_uctx_image_blob {
	const void *meta;
	size_t meta_len;
	const void *uar_table;
	size_t uar_table_len;
	const void *bfreg_count;
	size_t bfreg_count_len;
	const void *dyn_uar_records;
	size_t dyn_uar_records_len;
	uint32_t source_devx_uid;
	bool has_source_devx_uid;
};

int vfmig_drain_save_fd_to_blob(int save_fd, const char *blob_path, uint64_t *out_size);
int vfmig_append_state_entry(uint32_t ctxn, const char *ibdev, const char *source_cdev_path, const char *pf_bdf,
			     uint32_t vf_id, uint32_t vhca_id, const uint8_t vf_uuid[16], const char *blob_path,
			     uint64_t blob_size, const struct vfmig_uctx_image_blob *uctx);
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
 *
 * vfmig_restore_init_all_vfs() is the criu-restore-side entry point,
 * driven from the plugin's init(RESTORE). It runs the same VF firmware
 * discovery as the standalone tool (Phase A -- resolve dest VF by
 * vf_uuid, LOAD-unless-already-bound, resolve dest ibdev/cdev) and then
 * builds the per-context restore cache from the image's uctx snapshots
 * (Phase B) that the restore-side uverbs-cdev open path consumes.
 *
 * rdma_mlx5_vfmig_plugin_open_uverbs_cdev() is the RDMA_OPEN_UVERBS_CDEV
 * hook: given a source uverbs-file image entry it looks up the cached
 * destination context by source ctxn, lazily opens the destination cdev
 * + replays the ucontext snapshot on first use, and returns a dup'd fd
 * for core RDMA restore to install as the workload's uverbs fd.
 *
 * rdma_mlx5_vfmig_plugin_update_vma_map() is the UPDATE_VMA_MAP hook:
 * for a device VMA whose backing file is one of our source cdev paths,
 * it ensures the destination context is open + replayed and hands core
 * a dup'd cdev fd (and unchanged page offset) to mmap the UAR from.
 */
int mlx5_vfmig_plugin_restore_vf_only(int image_dir_fd);
void vfmig_restore_fini_close_all(void);
int vfmig_restore_init_all_vfs(void);
int rdma_mlx5_vfmig_plugin_open_uverbs_cdev(const UverbsFileEntry *uvfe);
int rdma_mlx5_vfmig_plugin_update_vma_map(const char *path, const uint64_t addr, const uint64_t old_pgoff,
					  uint64_t *new_pgoff, int *plugin_fd);

/*
 * Per-PD restore UHW pack. rdma_mlx5_vfmig_plugin_restore_uobj_pd_uhw_pack()
 * is the RDMA_RESTORE_UOBJ_PD_UHW_PACK hook: it reshapes the per-PD
 * plugin_blob the dump hook emitted (a struct mlx5_ib_restore_pd_req_local)
 * into the UHW_IN of core's UVERBS_METHOD_RESTORE_PD, so the kernel
 * adopts the source FW pdn without ALLOC_PD.
 */
int rdma_mlx5_vfmig_plugin_restore_uobj_pd_uhw_pack(const RdmaUobjEntry *e, struct rdma_uhw_spec *uhw);

/*
 * Per-MR restore UHW pack. rdma_mlx5_vfmig_plugin_restore_uobj_mr_uhw_pack()
 * is the RDMA_RESTORE_UOBJ_MR_UHW_PACK hook: unlike the PD hook it reads
 * no plugin_blob (an MR carries none) and instead derives the FW
 * mkey_index from the entry's wire-visible lkey (mlx5 invariant
 * lkey == rkey == (mkey_index << 8) | variant), packing a struct
 * mlx5_ib_restore_mr_req_local into the UHW_IN of core's
 * UVERBS_METHOD_RESTORE_MR so the kernel adopts the source FW mkey
 * (preserved across LOAD_VHCA_STATE) without CREATE_MKEY.
 */
int rdma_mlx5_vfmig_plugin_restore_uobj_mr_uhw_pack(const RdmaUobjEntry *e, struct rdma_uhw_spec *uhw);

/*
 * Per-CQ restore UHW pack. rdma_mlx5_vfmig_plugin_restore_uobj_cq_uhw_pack()
 * is the RDMA_RESTORE_UOBJ_CQ_UHW_PACK hook: it reshapes the 32-byte
 * blob captured at dump into the struct mlx5_ib_restore_cq_req the
 * kernel's UVERBS_METHOD_RESTORE_CQ expects in UHW_IN (cqn, cqe_size,
 * source buf_addr / db_addr), validating the blob before it does.
 */
int rdma_mlx5_vfmig_plugin_restore_uobj_cq_uhw_pack(const RdmaUobjEntry *e, struct rdma_uhw_spec *uhw);

/*
 * Per-QP restore UHW pack. rdma_mlx5_vfmig_plugin_restore_uobj_qp_uhw_pack()
 * is the RDMA_RESTORE_UOBJ_QP_UHW_PACK hook: it reshapes the 64-byte blob
 * captured at dump into the struct mlx5_ib_restore_qp_req the kernel's
 * UVERBS_METHOD_RESTORE_QP expects in UHW_IN (WQ-ring / doorbell source
 * VAs, FW qpn, WQ sizing), validating the blob before it does.
 */
int rdma_mlx5_vfmig_plugin_restore_uobj_qp_uhw_pack(const RdmaUobjEntry *e, struct rdma_uhw_spec *uhw);

/*
 * Per-CQ restore timing. rdma_mlx5_vfmig_plugin_restore_uobj_cq_needs_pie()
 * is the RDMA_RESTORE_UOBJ_CQ_NEEDS_PIE hook: it returns 1 because mlx5's
 * RESTORE_CQ pins the source CQE-ring / doorbell pages from current->mm,
 * so the verb must run in the pie after the user VMAs are laid out.
 */
int rdma_mlx5_vfmig_plugin_restore_uobj_cq_needs_pie(void);

#endif /* __CR_VFMIG_INTERNAL_H__ */
