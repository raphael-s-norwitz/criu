#ifndef __CR_VFMIG_INTERNAL_H__
#define __CR_VFMIG_INTERNAL_H__

/*
 * Cross-file declarations shared between the rdma_mlx5_vfmig
 * plugin sources. Strictly NOT a public surface -- this header
 * lives next to the .c files that use it, never installed.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "images/mlx5_vfmig.pb-c.h"
#include "images/rdma_uobj.pb-c.h"
#include "images/uverbsfd.pb-c.h"

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
struct mlx5_ib_restore_cq_req_local;
struct mlx5_ib_restore_qp_req_local;
struct mlx5_ib_restore_pd_req_local;

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

int vfmig_query_uctx_meta(int fd,
			  struct mlx5_ib_vfmig_ucontext_meta_local *meta_out);

int vfmig_restore_dyn_uars(int fd,
			   const struct mlx5_ib_vfmig_dyn_uar_record_local *records,
			   size_t n_records);

int vfmig_snapshot_dyn_uars(int fd,
			    struct mlx5_ib_vfmig_dyn_uar_record_local **records_out,
			    size_t *n_out);

/*
 * Per-CQ dump-side discovery via MLX5_IB_METHOD_VFMIG_QUERY_CQ.
 * @cq_handle is the source ufile-idr CQ handle from the R3 walk.
 * On success @blob_out is byte-equal to the payload RESTORE_CQ's
 * UHW.data will consume on the destination -- the dump path stores
 * it in protobuf verbatim, no field-level marshaling. The companion
 * outs (@cqe_out, @comp_vector_out, @flags_out) are the per-CQ
 * inputs RESTORE_CQ takes as core attrs (not in the UHW blob).
 */
int vfmig_query_cq(int fd,
		   uint32_t cq_handle,
		   struct mlx5_ib_restore_cq_req_local *blob_out,
		   uint32_t *cqe_out,
		   uint32_t *comp_vector_out,
		   uint32_t *flags_out);

/*
 * Per-QP dump-side discovery via MLX5_IB_METHOD_VFMIG_QUERY_QP.
 * @qp_handle is the source ufile-idr QP handle from the R3 walk.
 * On success @blob_out is byte-equal to the payload RESTORE_QP's
 * UHW.data will consume on the destination; the dump path stores it
 * in protobuf verbatim. The residual outs (@user_handle_out,
 * @create_flags_out) are the per-QP RESTORE_QP core attrs that have
 * no standard/NLDEV surface. qp_type / state come from NLDEV and the
 * cap tuple from the standard QUERY_QP verb (rdma_uverbs_query_qp),
 * so they are no longer queried here.
 */
int vfmig_query_qp(int fd,
		   uint32_t qp_handle,
		   struct mlx5_ib_restore_qp_req_local *blob_out,
		   uint64_t *user_handle_out,
		   uint32_t *create_flags_out);

/*
 * Per-PD dump-side discovery via MLX5_IB_METHOD_VFMIG_QUERY_PD.
 * @pd_handle is the source ufile-idr PD handle from the R3 walk.
 * On success @blob_out is byte-equal to the payload RESTORE_PD's
 * UHW.data will consume on the destination (carries the FW pdn); the
 * dump path stores it in the per-PD plugin_blob verbatim. @uid_out is
 * the source PD's mpd->uid -- dump-side diagnostic only, not a
 * restore input.
 */
int vfmig_query_pd(int fd,
		   uint32_t pd_handle,
		   struct mlx5_ib_restore_pd_req_local *blob_out,
		   uint32_t *uid_out);

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
			     const uint8_t vf_uuid[16],
			     const char *blob_path, uint64_t blob_size,
			     const struct mlx5_ib_vfmig_ucontext_meta_local *uctx_meta,
			     const uint32_t *uctx_uar, size_t uctx_uar_n,
			     const uint32_t *uctx_cnt, size_t uctx_cnt_n,
			     const struct mlx5_ib_vfmig_dyn_uar_record_local *uctx_dyn,
			     size_t uctx_dyn_n,
			     uint32_t source_devx_uid);

int vfmig_read_image(Mlx5VfmigStateEntry ***out_arr, size_t *out_n);

/*
 * Image-directory fd indirection.
 *
 * vfmig_get_image_dir() returns the override fd if one is set
 * (see vfmig_set_image_dir_override()), else criu_get_image_dir().
 * All plugin paths that openat() into the image directory go
 * through this helper so the standalone prerestore binary
 * (mlx5_vfmig_restore_vf, the eventual Phase 3.2 deliverable)
 * can drive the LOAD/bind dance against an image dir of its
 * own choosing without depending on criu's service-fd table.
 *
 * Override invariants:
 *   - Caller owns the fd lifetime; the plugin only reads from it.
 *   - Process-global; safe under both criu's and the prerestore
 *     binary's single-threaded, one-call-at-a-time invariant.
 *   - Cleared back to -1 before the prerestore symbol returns
 *     so a subsequent in-process criu invocation falls back
 *     cleanly to criu_get_image_dir().
 */
int vfmig_get_image_dir(void);
void vfmig_set_image_dir_override(int fd);
void vfmig_clear_image_dir_override(void);

/*
 * Process-global activation flag. Set true by init() iff at
 * least one tracked VF was found across the host's PF cdevs.
 * Read by every dump+restore hook to short-circuit when no
 * mlx5_vfmig work is in flight, so a stray hook call on a
 * host that doesn't have the cdevs at all is a cheap decline.
 */
extern bool vfmig_active;

/*
 * vfmig_barrier.c -- per-VHCA cross-host rendezvous descriptor + the
 * symmetric in-plugin datapath-state barrier (design/barrier_criu_
 * design.md). The descriptor is a host-local key=value file, a property
 * of the provisioned VHCA, written by the pre-restore binary /
 * orchestrator; its absence means legacy (no barrier). The barrier is a
 * peer-to-peer READY rendezvous run inside the CHECKPOINT_DEVICES (D1)
 * and RESUME_DEVICES_LATE (R1) hooks, using CRIU's own sockets.
 */
#define VFMIG_RZ_MAX_PEERS 15
#define VFMIG_RZ_DIR	   "/run/criu-vfmig/rendezvous"

/* Barrier phase labels (on the wire and in logs). */
#define VFMIG_BARRIER_PHASE_DUMP    "D1"
#define VFMIG_BARRIER_PHASE_RESTORE "R1"

struct vfmig_rz_endpoint {
	char	 ip[64];	/* IPv4/IPv6 literal or hostname */
	uint16_t port;
};

struct vfmig_rendezvous {
	char			 session[64];	/* per-migration id */
	uint8_t			 vf_uuid[16];	/* this VHCA's identity */
	struct vfmig_rz_endpoint listen;	/* our control endpoint */
	struct vfmig_rz_endpoint peers[VFMIG_RZ_MAX_PEERS];
	size_t			 n_peers;
	int			 timeout_ms;	/* whole-barrier deadline */
	int			 retry_ms;	/* connect backoff */
};

/*
 * Load the rendezvous descriptor for @vf_uuid from
 * VFMIG_RZ_DIR/<uuid-hex>.desc. Returns 0 loaded (barrier mode, *out
 * populated), 1 absent (legacy mode, *out untouched), -1 malformed or
 * unreadable (fail closed).
 */
int vfmig_rendezvous_load(const uint8_t vf_uuid[16],
			  struct vfmig_rendezvous *out);

/*
 * Run the cross-host P2P barrier described by @rz at @phase (one of
 * VFMIG_BARRIER_PHASE_*). Blocks until every peer has exchanged a
 * matching READY at this phase, or the descriptor timeout elapses.
 * Returns 0 on success, -1 on timeout/error.
 */
int vfmig_barrier_run(const struct vfmig_rendezvous *rz, const char *phase);

/*
 * vfmig_dpstate.c -- shared SUSPEND/RESUME_VHCA ioctl helpers.
 * @dir_flags is 0 (fused RUNNING<->STOP) or a subset of
 * MLX5_VFMIG_DIR_FLAG_* for a single ladder edge (INITIATOR:
 * RUNNING<->P2P, RESPONDER: P2P<->STOP). Both idempotent; each opens
 * /dev/mlx5_vfmig/<pf_bdf> for the one ioctl. Return 0 or -1.
 */
int vfmig_dp_suspend(const char *pf_bdf, uint32_t vf_id, uint32_t dir_flags);
int vfmig_dp_resume(const char *pf_bdf, uint32_t vf_id, uint32_t dir_flags);

/*
 * vfmig_dump.c -- dump-side state lists, capture orchestration,
 * source devx_uid resolver, dump+VMA hooks, fini-time drain.
 *
 * The four entries below are reachable from plugin.c (the
 * lifecycle file): vfmig_*_clear() are called from init()
 * (so a CRIU re-invocation starts fresh) and fini() (so we
 * release per-dump state regardless of which path tore down
 * the dump). vfmig_drain_pending_in_fini() is the SAVE-time
 * drain the fini() handler invokes after all DUMP_UVERBS_
 * CONTEXT hooks have queued.
 *
 * The two hook entries are reachable from plugin.c's
 * CR_PLUGIN_REGISTER_HOOK macros.
 */
void vfmig_saved_clear(void);
void vfmig_pending_clear(void);
void vfmig_failed_clear(void);
void vfmig_drain_pending_in_fini(void);

/*
 * Snapshot-ordering pause/resume (design/snapshot_ordering_pause_
 * capture.md Part A). vfmig_suspended_clear() resets the per-dump
 * suspended-VF set (called from init/fini like the lists above).
 *
 * rdma_mlx5_vfmig_plugin_checkpoint_devices() is the CHECKPOINT_DEVICES
 * hook: it runs after the dumpee tree is frozen but BEFORE its memory
 * is copied, enumerates the pid's tracked mlx5 VFs and issues
 * MLX5_VFMIG_IOC_SUSPEND_VHCA on each so no peer DMA lands in
 * mid-snapshot MR pages.
 *
 * vfmig_resume_suspended_vfs() issues MLX5_VFMIG_IOC_RESUME_VHCA on
 * every VF this dump parked. Called from fini(DUMP); callers pass
 * @keep_suspended=false today (the snapshot is done, so resuming is
 * unconditional). @keep_suspended is retained for the future live-
 * destination migration hand-off that wants the source left quiesced.
 */
void vfmig_suspended_clear(void);
int rdma_mlx5_vfmig_plugin_checkpoint_devices(int pid);
void vfmig_resume_suspended_vfs(bool keep_suspended);

/*
 * Claimed-VF cache. CLAIM (rdma_check_dump_coverage -> per-context
 * arbitration) already resolves every snapshot-tree context's
 * (pf_bdf, vf_id) and confirms QUERY_VF.tracked just before
 * CHECKPOINT_DEVICES runs. vfmig_claimed_add() records each VF we win
 * the claim for so the CHECKPOINT_DEVICES hook can park exactly that
 * set without re-walking /proc/<pid>/fd or re-querying sysfs.
 * Deduplicated (a VF can back several contexts). Reset by init/fini
 * via vfmig_claimed_clear().
 */
void vfmig_claimed_add(const char *ibdev, const char *pf_bdf, uint32_t vf_id);
void vfmig_claimed_clear(void);

int rdma_mlx5_vfmig_plugin_dump_uverbs_context(const char *ibdev,
					       uint32_t kernel_driver_id,
					       uint32_t ctxn,
					       int lfd, pid_t pid);

int rdma_mlx5_vfmig_plugin_dump_uobj_cq(const char *ibdev,
					uint32_t kernel_driver_id,
					int lfd, uint32_t ufile_handle,
					pid_t pid,
					RdmaCqAttrs *cq_attrs,
					ProtobufCBinaryData *plugin_blob);

int rdma_mlx5_vfmig_plugin_dump_uobj_qp(const char *ibdev,
					uint32_t kernel_driver_id,
					int lfd, uint32_t ufile_handle,
					pid_t pid,
					RdmaQpAttrs *qp_attrs,
					ProtobufCBinaryData *plugin_blob);

int rdma_mlx5_vfmig_plugin_dump_uobj_pd(const char *ibdev,
					uint32_t kernel_driver_id,
					int lfd, uint32_t ufile_handle,
					pid_t pid,
					RdmaPdAttrs *pd_attrs,
					ProtobufCBinaryData *plugin_blob);

struct rdma_uhw_spec;
int rdma_mlx5_vfmig_plugin_restore_uobj_cq_uhw_pack(const RdmaUobjEntry *e,
						    struct rdma_uhw_spec *uhw);
int rdma_mlx5_vfmig_plugin_restore_uobj_mr_uhw_pack(const RdmaUobjEntry *e,
						    struct rdma_uhw_spec *uhw);
int rdma_mlx5_vfmig_plugin_restore_uobj_qp_uhw_pack(const RdmaUobjEntry *e,
						    struct rdma_uhw_spec *uhw);
int rdma_mlx5_vfmig_plugin_restore_uobj_pd_uhw_pack(const RdmaUobjEntry *e,
						    struct rdma_uhw_spec *uhw);

struct stat;
int rdma_mlx5_vfmig_plugin_handle_device_vma(int fd,
					     const struct stat *st);

/*
 * vfmig_restore.c -- restore-side eager-init + the two
 * restore hooks. Caches one cdev fd per dumpee uverbs
 * context (already armed with GET_CONTEXT(VFMIG_RESTORE) +
 * RESTORE_{UCONTEXT,DYN_UARS}) so UPDATE_VMA_MAP and
 * RDMA_OPEN_UVERBS_CDEV can dup() out of it.
 *
 * The two init/fini-time entries are called from plugin.c
 * lifecycle code; the two hook entries are referenced by
 * plugin.c's CR_PLUGIN_REGISTER_HOOK macros.
 */
int vfmig_restore_init_all_vfs(void);
void vfmig_restore_fini_close_all(void);

/*
 * RESUME_DEVICES_LATE hook: the restore-side (R1) cross-host barrier.
 * For every barrier-mode VF, parks the initiator (RUNNING -> RUNNING_P2P),
 * runs the rendezvous, then RESUME(INITIATOR). The initiator is left
 * RUNNING across the rest of restore (vfmig_barrier_arm() does not park
 * at bind); the park/release straddle the rendezvous here.
 * -ENOTSUP when the plugin is inactive.
 */
int rdma_mlx5_vfmig_plugin_resume_devices_late(int pid);

int rdma_mlx5_vfmig_plugin_update_vma_map(const char *path,
					  const uint64_t addr,
					  const uint64_t old_pgoff,
					  uint64_t *new_pgoff,
					  int *plugin_fd);

int rdma_mlx5_vfmig_plugin_open_uverbs_cdev(const UverbsFileEntry *uvfe);

/*
 * Per-PF char-device directory. The plugin's init() walks this
 * directory and opens every entry as a candidate cdev; both the
 * dump path (capture, HANDLE_DEVICE_VMA) and the restore path
 * (load, ensure_cdev_open) construct per-PF cdev paths under it.
 * Defined here so all three .c files agree.
 */
#define MLX5_VFMIG_DEV_DIR "/dev/mlx5_vfmig"

#endif /* __CR_VFMIG_INTERNAL_H__ */
