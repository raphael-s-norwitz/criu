/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * UAPI for mlx5 host-driven VF migration / CRIU restore.
 *
 * One char device per mlx5_core PF, exposed as /dev/mlx5_vfmig/<bdf>,
 * exposes SAVE/LOAD/SUSPEND/RESUME of an mlx5 VF's firmware state from
 * the host PF, modelled on the VFIO mlx5 variant driver but driven by
 * the host's PF mlx5_core rather than by VFIO.
 *
 * Source-side lifecycle (capture a VHCA snapshot):
 *   1. sriov_drivers_autoprobe = 0 on the PF
 *   2. sriov_numvfs = N on the PF                    (VFs created, unbound)
 *   3. ioctl(MLX5_VFMIG_IOC_ENABLE_MIGRATABLE, vf_id)
 *   4. driver_override + bind the VF to mlx5_core    (workload runs)
 *   5. open /dev/mlx5_vfmig/<pf_bdf>
 *   6. ioctl(MLX5_VFMIG_IOC_SAVE_VHCA_STATE, vf_id)
 *      -> returns a read-only anon-inode fd. read() the blob to EOF,
 *         close(). By default the source VHCA is RESUMEd on close;
 *         pass MLX5_VFMIG_SAVE_FLAG_KEEP_SUSPENDED to leave it stopped
 *         (e.g. CRIU dump-then-destroy).
 *
 * Destination-side lifecycle (apply a VHCA snapshot):
 *   1. sriov_drivers_autoprobe = 0 on the PF
 *   2. sriov_numvfs = N on the PF                    (VFs created, unbound)
 *   3. ioctl(MLX5_VFMIG_IOC_ENABLE_MIGRATABLE, vf_id)
 *   4. open /dev/mlx5_vfmig/<pf_bdf>
 *   5. ioctl(MLX5_VFMIG_IOC_LOAD_VHCA_STATE, vf_id)
 *      -> returns a write-only anon-inode fd. write() the blob,
 *         close(). The blob's DMA-mapped pages and MKEY are staged
 *         on the PF's per-VF pending_load slot; no firmware command
 *         has been issued yet against the destination VHCA.
 *   6. ioctl(MLX5_VFMIG_IOC_MARK_RESTORED, vf_id)
 *   7. driver_override + bind the VF to mlx5_core
 *      -> mlx5_core's probe runs the deferred SUSPEND + LOAD_VHCA_STATE
 *         + RESUME pair via the PF mdev, then skips SET_ISSI / boot
 *         pages / INIT_HCA on the destination VHCA.
 *
 * Note on round-trip behaviour:
 *   The SAVE blob references DMA addresses (cmd ring, EQ buffers, MR
 *   backing pages, ...) captured from the source's mlx5_core. After
 *   LOAD on a destination that runs native mlx5_core (i.e. not behind
 *   vfio_mlx5_pci in a guest VM), those addresses do not point at the
 *   destination's buffers. The plumbing here exercises SAVE + LOAD
 *   end-to-end and the destination probe completes through LOAD, but
 *   subsequent VHCA-side firmware commands time out until the
 *   destination can reproduce the source's address layout (which on
 *   bare metal requires an IOMMU and a deterministic-IOVA allocator).
 *   That extension is not covered by this UAPI.
 */

#ifndef _UAPI_LINUX_MLX5_VFMIG_H
#define _UAPI_LINUX_MLX5_VFMIG_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define MLX5_VFMIG_IOC_MAGIC	0xB5

/*
 * MLX5_VFMIG_IOC_MARK_RESTORED:
 *   Mark VF @vf_id as having had its firmware state restored. The next
 *   mlx5_core probe of that VF will skip INIT_HCA.
 *   Returns 0 on success, -EINVAL if vf_id is out of range, -EALREADY if
 *   the flag was already set.
 */
struct mlx5_vfmig_mark_restored {
	__u32 vf_id;
	__u32 reserved;
};
#define MLX5_VFMIG_IOC_MARK_RESTORED \
	_IOW(MLX5_VFMIG_IOC_MAGIC, 0x01, struct mlx5_vfmig_mark_restored)

/*
 * MLX5_VFMIG_IOC_GET_VHCA_ID:
 *   PF-side query of the VF's vhca_id via QUERY_HCA_CAP(other_function=1).
 *   Debug helper that lets userspace confirm the PF can address the VF
 *   without binding any driver to it.
 */
struct mlx5_vfmig_get_vhca_id {
	__u32 vf_id;	/* in  */
	__u16 vhca_id;	/* out */
	__u16 reserved;
};
#define MLX5_VFMIG_IOC_GET_VHCA_ID \
	_IOWR(MLX5_VFMIG_IOC_MAGIC, 0x02, struct mlx5_vfmig_get_vhca_id)

/*
 * MLX5_VFMIG_IOC_QUERY_VF:
 *   Diagnostic snapshot of one VF on the owning PF. Returns the VF's
 *   live vhca_id (queried via QUERY_HCA_CAP(other_function=1)), the
 *   "restored" / "tracked" bits, the orchestrator-stamped vf_uuid (if
 *   any), and the total number of VFs the PF has provisioned.
 *   Userspace iterates 0..num_vfs-1 to enumerate; that's intentionally
 *   cheaper to maintain than a variable-length list ioctl.
 *
 *   Output fields:
 *     vhca_id:   live VHCA identifier from
 *                QUERY_HCA_CAP(other_function=1).
 *     restored:  1 if MLX5_VFMIG_IOC_MARK_RESTORED was issued for
 *                this VF (i.e. its next probe should skip the
 *                ENABLE_HCA / SET_ISSI / boot-pages / INIT_HCA
 *                sequence and apply the staged LOAD blob instead).
 *     tracked:   1 if MLX5_VFMIG_IOC_SET_TRACKED { enable=1 } is
 *                currently in effect for this VF -- i.e. its
 *                per-VF unmanaged IOMMU domain is allocated and
 *                attached, and probe-time DMA buffers will route
 *                through the deterministic IOVA allocator instead
 *                of dma_alloc_coherent. CRIU's mlx5_sriov_vfmig
 *                plugin uses this at startup to discover which
 *                PFs/VFs are eligible for save/restore without
 *                binding any driver. Returned as 0 on out-of-range
 *                vf_id (alongside -ERANGE), so it's safe to read
 *                in the error-path.
 *     vf_uuid:   16-byte orchestrator-stamped per-VF identity tag
 *                set via MLX5_VFMIG_IOC_SET_VF_UUID on the PF cdev
 *                (write side; called by the orchestrator only --
 *                the CRIU plugin never writes a UUID). All-zeros
 *                means the orchestrator has not (yet) stamped a
 *                UUID on this slot. Cleared on SR-IOV teardown
 *                (sriov_numvfs=0). The CRIU dump path captures
 *                this into the plugin image; the CRIU restore path
 *                iterates eligible PFs/VFs and matches by UUID to
 *                bind a saved-state image to a destination VF.
 *                See KS7.3 in
 *                tools/testing/mlx5_vfmig/design/vf_prerestore_split.md
 *                §3.5 for the dump-side / restore-side contract.
 *                Returned as all-zeros on out-of-range vf_id.
 *
 *   ABI note: this struct grew to add @vf_uuid + @reserved_out after
 *   the initial release. The encoded ioctl number changes with the
 *   struct size (sizeof in the _IOWR macro), so old userspace built
 *   against the smaller struct will get -ENOTTY from a new kernel
 *   rather than reading a partial / misaligned result. Recompile
 *   the plugin against this header.
 */
struct mlx5_vfmig_query_vf {
	__u32 vf_id;		/* in  */
	__u32 num_vfs;		/* out: total VFs provisioned on this PF */
	__u16 vhca_id;		/* out */
	__u8  restored;		/* out: 1 if MARK_RESTORED was issued */
	__u8  tracked;		/* out: 1 if SET_TRACKED { enable=1 }
				 *      currently in effect on this VF
				 */
	__u8  vf_uuid[16];	/* out: orchestrator-stamped UUID,
				 *      all-zeros if unset
				 */
	__u8  reserved_out[8];	/* out: zeroed */
};
#define MLX5_VFMIG_IOC_QUERY_VF \
	_IOWR(MLX5_VFMIG_IOC_MAGIC, 0x03, struct mlx5_vfmig_query_vf)

/*
 * MLX5_VFMIG_IOC_LOAD_VHCA_STATE:
 *   Open a write-only data session that consumes a previously-saved VF
 *   state blob and installs it into the firmware via LOAD_VHCA_STATE.
 *
 *   The returned @load_fd is an anon-inode fd. Userspace write()s the
 *   blob to it (chunked or whole; partial writes are fine) and close()s
 *   it. The driver runs LOAD_VHCA_STATE per parsed image record.
 *
 *   Wire format:
 *     The blob is byte-compatible with the migration data stream
 *     produced by the VFIO mlx5 variant driver in
 *     drivers/vfio/pci/mlx5/. It is a sequence of records, each
 *     prefixed by a 16-byte header (record_size:le64, flags:le32,
 *     tag:le32). Records carrying firmware state use tag 0
 *     (MLX5_MIGF_HEADER_TAG_FW_DATA, kernel-internal name) and are
 *     mandatory; unknown tags marked optional in flags are skipped,
 *     unknown mandatory tags fail the write with -EOPNOTSUPP.
 *     Userspace should treat the entire byte stream as opaque.
 *
 *   Returns 0 with @load_fd populated on success, -EINVAL if vf_id is
 *   out of range or @flags is non-zero, -ENODEV if the PF is gone.
 *   Closing the fd without writing anything is a no-op (no firmware
 *   commands issued).
 */
struct mlx5_vfmig_load_state {
	__u32 vf_id;	/* in  */
	__u32 flags;	/* in: must be 0 for now */
	__s32 load_fd;	/* out */
	__u32 reserved;
};
#define MLX5_VFMIG_IOC_LOAD_VHCA_STATE \
	_IOWR(MLX5_VFMIG_IOC_MAGIC, 0x04, struct mlx5_vfmig_load_state)

/*
 * MLX5_VFMIG_IOC_SAVE_VHCA_STATE:
 *   Open a read-only data session that captures a VF's current firmware
 *   state into a blob byte-compatible with LOAD_VHCA_STATE's input.
 *
 *   On the ioctl call, the driver synchronously:
 *     - queries the VF's vhca_id via QUERY_HCA_CAP(other_function=1)
 *     - SUSPEND_VHCA(INITIATOR), SUSPEND_VHCA(RESPONDER) to quiesce
 *     - QUERY_VHCA_MIGRATION_STATE to size the snapshot
 *     - allocates a PD + image pages + MKEY (DMA_FROM_DEVICE)
 *     - SAVE_VHCA_STATE to populate the pages
 *   then returns @save_fd, an anon-inode fd. Userspace read()s the blob
 *   from it (any chunk size) until EOF. The first read also emits a
 *   16-byte FW_DATA record header (record_size, flags=0, tag=0) so the
 *   resulting byte stream can be fed verbatim back into
 *   MLX5_VFMIG_IOC_LOAD_VHCA_STATE.
 *
 *   Resume policy on close():
 *     By default the driver issues RESUME_VHCA(RESPONDER) and
 *     RESUME_VHCA(INITIATOR) when the fd is released, leaving the source
 *     VF runnable again. Set MLX5_VFMIG_SAVE_FLAG_KEEP_SUSPENDED to
 *     skip the resume (e.g. CRIU dump-then-destroy where the VF is
 *     about to be torn down via sriov_numvfs=0 anyway).
 *
 *   Returns 0 with @save_fd populated on success, -EINVAL if vf_id is
 *   out of range or @flags has unknown bits, -EBUSY if a save session
 *   already exists for this vf_id, -ENODEV if the PF is gone, or any
 *   firmware error code (negated) if a SUSPEND/QUERY/SAVE step fails.
 *   On firmware failure no fd is returned and the VHCA is left as
 *   undisturbed as possible (failed SUSPENDs are not "undone").
 */
#define MLX5_VFMIG_SAVE_FLAG_KEEP_SUSPENDED	(1u << 0)
#define MLX5_VFMIG_SAVE_FLAG_ALL \
	(MLX5_VFMIG_SAVE_FLAG_KEEP_SUSPENDED)

struct mlx5_vfmig_save_state {
	__u32 vf_id;	/* in  */
	__u32 flags;	/* in: subset of MLX5_VFMIG_SAVE_FLAG_* */
	__s32 save_fd;	/* out */
	__u32 reserved;
};
#define MLX5_VFMIG_IOC_SAVE_VHCA_STATE \
	_IOWR(MLX5_VFMIG_IOC_MAGIC, 0x05, struct mlx5_vfmig_save_state)

/*
 * MLX5_VFMIG_IOC_ENABLE_MIGRATABLE:
 *   Set the per-VF cmd_hca_cap_2.migratable bit, which is the firmware
 *   gate for SUSPEND/SAVE/LOAD/RESUME. This MUST be called while the
 *   VF is unbound (no driver attached): the firmware accepts a
 *   modify-cap on a VHCA in pre-ENABLE_HCA state but rejects it
 *   ("bad resource state") on a VHCA that mlx5_core has already
 *   probed.
 *
 *   Standard ordering for SAVE on a freshly-provisioned VF:
 *     1. sriov_drivers_autoprobe = 0
 *     2. sriov_numvfs = N            (VFs created, unbound)
 *     3. ioctl(MLX5_VFMIG_IOC_ENABLE_MIGRATABLE, vf_id) for each VF
 *     4. driver_override + bind on the VF -> ENABLE_HCA latches
 *        migratable=1
 *     5. run workload, eventually issue MLX5_VFMIG_IOC_SAVE_VHCA_STATE
 *
 *   Idempotent: returns 0 (with no firmware traffic) if the bit is
 *   already set. Returns -EOPNOTSUPP if the PF firmware does not
 *   advertise migration / vhca_resource_manager. The bit is intentionally
 *   left set across mlx5_core probes -- a VF that's been migration-
 *   enabled once stays migration-enabled until sriov_numvfs is dropped.
 */
struct mlx5_vfmig_enable_migratable {
	__u32 vf_id;
	__u32 reserved;
};
#define MLX5_VFMIG_IOC_ENABLE_MIGRATABLE \
	_IOW(MLX5_VFMIG_IOC_MAGIC, 0x06, struct mlx5_vfmig_enable_migratable)

/*
 * MLX5_VFMIG_IOC_SET_TRACKED:
 *   Toggle the host-driver-side "vfmig tracked" mode on a VF. When set,
 *   the PF allocates a per-VF unmanaged IOMMU domain and attaches it
 *   to the VF's pci_dev, and subsequent host-side allocators in the
 *   destination VF's mlx5_core probe (cmd ring, MANAGE_PAGES pages,
 *   EQ buffers, ...) route through a deterministic IOVA allocator
 *   instead of the kernel's default DMA allocator. This is the
 *   plumbing that lets a SAVE/LOAD round-trip preserve every IOVA
 *   captured in the firmware blob across host changes -- without it,
 *   LOAD_VHCA_STATE accepts the blob but the destination VHCA's
 *   cmd ring is dead afterwards (every command 60s timeout).
 *
 *   This flag is orthogonal to MLX5_VFMIG_IOC_ENABLE_MIGRATABLE: the
 *   migratable bit is the firmware gate for the SUSPEND/SAVE/LOAD/
 *   RESUME command family; @vfmig_tracked is the host-driver gate for
 *   the IOMMU/IOVA layer that makes those commands semantically
 *   correct on a native (non-VFIO) destination. Userspace will
 *   typically call both, in either order, before binding the VF.
 *
 *   Lifetime semantics:
 *     - @enable=1 must be called while the VF is unbound (no driver
 *       attached). Returns -EBUSY otherwise. Allocates the per-VF
 *       IOMMU domain (idempotent: returns 0 if the flag is already
 *       set).
 *     - @enable=0 must also be called while the VF is unbound. Frees
 *       the domain and clears the flag. Returns -EBUSY if the VF is
 *       currently bound or if a LOAD blob is staged-but-unapplied
 *       (the staged blob references IOVAs in this domain).
 *     - The domain survives a VF unbind/rebind cycle. It is destroyed
 *       implicitly when sriov_numvfs is dropped (the VF goes away) or
 *       when the PF is unloaded. This avoids repeated
 *       iommu_domain_alloc()/teardown across SAVE -> destroy -> create
 *       -> LOAD cycles, which is the common case for HW-failure
 *       recovery.
 *
 *   Returns 0 on success, -EINVAL if vf_id is out of range or @flags
 *   has unknown bits, -EBUSY per the above, -ENODEV if the PF is
 *   gone, -EOPNOTSUPP if the platform has no IOMMU coverage for the
 *   VF's pci_dev (no IOMMU group, etc.).
 *
 *   The flag's current state is observable via
 *   MLX5_VFMIG_IOC_QUERY_VF -- the @tracked output field on
 *   struct mlx5_vfmig_query_vf reflects whether SET_TRACKED is in
 *   effect for a given vf_id without requiring the caller to bind
 *   the VF or otherwise touch it. Userspace orchestrators (e.g.
 *   CRIU's mlx5_sriov_vfmig plugin) rely on QUERY_VF for cheap
 *   discovery of vfmig-eligible VFs at startup.
 */
struct mlx5_vfmig_set_tracked {
	__u32 vf_id;	/* in  */
	__u32 enable;	/* in: 0 = detach domain + clear flag,
			 *     1 = attach domain + set flag
			 */
	__u32 flags;	/* in: reserved, must be 0 */
	__u32 reserved;
};
#define MLX5_VFMIG_IOC_SET_TRACKED \
	_IOW(MLX5_VFMIG_IOC_MAGIC, 0x07, struct mlx5_vfmig_set_tracked)

/*
 * MLX5_VFMIG_IOC_SUSPEND_VHCA:
 *   Quiesce VF @vf_id's datapath by issuing SUSPEND_VHCA(INITIATOR)
 *   followed by SUSPEND_VHCA(RESPONDER) on its vhca_id (PF-issued,
 *   other_function=1). This is the "pause" half of the stop-and-copy
 *   snapshot-ordering fix: CRIU calls it at the early CHECKPOINT_DEVICES
 *   hook, BEFORE the dumpee's memory is copied, so no peer RDMA
 *   WRITE/SEND (and no VF self-DMA) lands in pinned MR pages mid-
 *   snapshot. The heavy state capture stays in the late
 *   MLX5_VFMIG_IOC_SAVE_VHCA_STATE.
 *
 *   Latches the per-VF vfmig_suspended bit. Idempotent: returns 0 with
 *   no firmware traffic if the VF is already suspended. The VF may be
 *   bound or unbound. Requires the migratable cap, same gate as SAVE.
 *
 *   Relationship to SAVE_VHCA_STATE: if the VF is already suspended via
 *   this ioctl, a subsequent SAVE skips its in-SAVE SUSPEND pair and
 *   does NOT auto-resume on save_fd close -- the caller owns the resume
 *   via MLX5_VFMIG_IOC_RESUME_VHCA. If SAVE is used standalone (no prior
 *   SUSPEND), it self-suspends and resumes on close as before.
 *
 *   Returns 0 on success; -EINVAL if @vf_id is out of range or @flags
 *   is non-zero; -EOPNOTSUPP if the VF is not migration-enabled;
 *   -ENODEV if the PF is gone; any negative firmware-error code if a
 *   SUSPEND step fails.
 */
struct mlx5_vfmig_suspend_vhca {
	__u32 vf_id;	/* in  */
	__u32 flags;	/* in: must be 0 */
	__u32 reserved[2];
};
#define MLX5_VFMIG_IOC_SUSPEND_VHCA \
	_IOW(MLX5_VFMIG_IOC_MAGIC, 0x13, struct mlx5_vfmig_suspend_vhca)

/*
 * MLX5_VFMIG_IOC_RESUME_VHCA:
 *   Un-quiesce VF @vf_id's datapath by issuing RESUME_VHCA(RESPONDER)
 *   followed by RESUME_VHCA(INITIATOR) (reverse order of suspend). This
 *   is the "resume" half of the snapshot-ordering fix:
 *     - on the source after dump completes (or is aborted), to bring
 *       the VF back to runnable;
 *     - on the destination at RESUME_DEVICES_LATE, after a
 *       MARK_RESTORED { DEFER_RESUME } + bind has applied
 *       LOAD_VHCA_STATE and left the VHCA parked, once all MR/ring VMAs
 *       are restored.
 *
 *   Clears the per-VF vfmig_suspended / vfmig_defer_resume bits.
 *   Idempotent: returns 0 with no firmware traffic if the VF is not
 *   currently suspended.
 *
 *   Returns 0 on success; -EINVAL if @vf_id is out of range or @flags
 *   is non-zero; -ENODEV if the PF is gone; any negative firmware-error
 *   code if a RESUME step fails.
 */
struct mlx5_vfmig_resume_vhca {
	__u32 vf_id;	/* in  */
	__u32 flags;	/* in: must be 0 */
	__u32 reserved[2];
};
#define MLX5_VFMIG_IOC_RESUME_VHCA \
	_IOW(MLX5_VFMIG_IOC_MAGIC, 0x14, struct mlx5_vfmig_resume_vhca)

#endif /* _UAPI_LINUX_MLX5_VFMIG_H */
