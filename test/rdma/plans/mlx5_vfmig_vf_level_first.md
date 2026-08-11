# mlx5_sriov_vfmig — VF-firmware-state first (a restorable VF without context/uobject restore)

Companion to `mlx5_vfmig_kickoff.md`. That note sequences the plugin as
[core uobj hooks] → [PIE CQ/QP] → [mlx5 verbs] → [VF firmware state], i.e. it
builds the RDMA-verbs layer (Layer A) *before* the VF-firmware layer (Layer B).

This note records a deliberate reordering: **do Layer B first, on its own.**
The goal is a *restorable VF* — a VF whose firmware state is snapshotted on one
host and reinstated on another — with **no** uverbs-context restore and **no**
ib_uobject (PD/CQ/QP/MR) restore. That is a self-contained, independently
useful milestone, and it turns out to need **zero core-CRIU changes**.

Grounded in a re-read on 2026-04-29:
- kernel `/opt/builds/linux@rebase-1` (HEAD `cd365fb909c1`): the driver-side
  deterministic-IOVA "retag user MRs / SRQs·QPs·CQs / doorbell pages" work has
  landed, which is what makes the *tracked* `SAVE`/`LOAD` path functional. The
  vfmig UAPI header (`include/uapi/linux/mlx5_vfmig.h`) is unchanged and
  byte-identical to the plugin's vendored copy.
- build-up `/opt/builds/criu@criu-rebase-t1.1-rxe-pd-wip`: presence-detect +
  claim skeleton in place (`rdma_mlx5_vfmig_plugin.c`, `vfmig_pci.c`,
  `vfmig_internal.h`, vendored UAPI, `RCD_MLX5_SRIOV_VFMIG=2`).
- oracle `/opt/builds/criu-poc-ref@criu-dev-poc-rebase`: full Layer A + Layer B.

## 1. Why Layer B can go first, and needs no core changes

The oracle already separates the two layers cleanly, and Layer B is the lower,
self-contained one:

- **Layer A** (uverbs context + PD/CQ/QP/MR) needs new **core** hooks
  (`RDMA_DUMP_UVERBS_CONTEXT`, `RDMA_DUMP_UOBJ_*`, `RESTORE_*_NEEDS_PIE`) and
  PIE surgery. This is the large, deferred piece.
- **Layer B** (VF firmware state) is driven entirely by the plugin plus a
  **standalone `mlx5_vfmig_restore_vf` binary** that `dlopen`s the plugin `.so`
  and calls the exported `mlx5_vfmig_plugin_restore_vf_only(int image_dir_fd)`.
  **No `criu restore` is involved on the restore side.**

The dump side triggers `SAVE_VHCA_STATE` off hooks that already exist in
build-up core:

| Hook | Enum | Role in Layer B |
|------|------|-----------------|
| `RDMA_CLAIM_UVERBS_CONTEXT` | 16 | already wired; records the claimed `(ibdev, pf_bdf, vf_id, vf_uuid)` set |
| `CHECKPOINT_DEVICES` | 11 | `SUSPEND_VHCA` the claimed VF set before CRIU copies task memory |
| `fini(DUMP)` | — | drain: dedup by `(pf_bdf, vf_id)`, `SAVE_VHCA_STATE` per unique VF, write image |

Crucially, we do **not** need `RDMA_DUMP_UVERBS_CONTEXT` (absent in build-up
core) for Layer B: the claim cache + `CHECKPOINT_DEVICES` + `fini` give us the
`(pf, vf)` set and a post-memory drain point without a per-context dump hook.

## 2. The milestone, and how it is validated without any restore engine

Round-trip proving a restorable VF using only VF-level machinery:

1. **Victim** opens a bare `ibv_context` on the VF's ibdev (no PD/CQ/QP/MR — so
   there are no ib_uobjects to dump).
2. **`criu dump`**: claim names the plugin → `CHECKPOINT_DEVICES` suspends the
   claimed VF → `fini(DUMP)` runs `SAVE_VHCA_STATE` (KEEP_SUSPENDED) per unique
   VF → writes `mlx5_vfmig.img` + one raw blob per VF. Dump succeeds because the
   process holds no uobjects.
3. **Teardown** the source VF; **reprovision** a destination VF (orchestrator
   responsibility: `sriov_numvfs`, `SET_TRACKED`, `ENABLE_MIGRATABLE`,
   `SET_VF_UUID`).
4. **`mlx5_vfmig_restore_vf -D <image-dir>`**: read image → resolve the
   destination VF by UUID → `LOAD_VHCA_STATE` + `MARK_RESTORED` →
   `driver_override`+bind → wait for the destination ibdev to come up.
5. **Assert**: destination VF bound to `mlx5_core`, ibdev up, restore returned
   success.

The validation is **standalone-binary only** — we never run `criu restore`,
which would require Layer A.

## 3. Commit sequence (each independently buildable; on top of presence+claim)

1. **Image format proto.** Add `images/mlx5_vfmig.proto` carrying the VF-level
   *required* fields only — `ctxn`, `ibdev`, `pf_bdf`, `vf_id`, `vhca_id`,
   `blob_path`, `blob_size`, `source_cdev_path`, `vf_uuid`; the `uctx_*`
   ucontext-snapshot fields (Layer A) are left out for now and reintroduced when
   context restore lands. Wire into `images/Makefile` (`proto-obj-y`), regen.
2. **Dump-side VF cache.** Extend the claim hook to record
   `(ibdev, pf_bdf, vf_id, vf_uuid)` into a claimed-VF set.
3. **`vf_image.c` (ported, slimmed).** `drain_save_fd_to_blob`,
   `append_state_entry`, `read_image`, plus the image-dir-fd override
   (`set/clear/get`) so the standalone binary can drive reads outside CRIU.
4. **SAVE on dump.** Register `CHECKPOINT_DEVICES` (SUSPEND the claimed set) and
   a `fini(DUMP)` drain: dedup by `(pf, vf)`, `SAVE_VHCA_STATE` (KEEP_SUSPENDED),
   drain `save_fd` → blob, append one image entry. Refuse VFs whose UUID reads
   back all-zeros.
5. **Restore-vf-only.** Ported/slimmed `vfmig_restore.c`:
   `resolve_uuid_to_pf_vf`, `load_one_vf`
   (`ENABLE_MIGRATABLE`+`SET_TRACKED`+`LOAD_VHCA_STATE`+`MARK_RESTORED`),
   `driver_override_and_bind`, `wait_for_dest_ibdev`; export
   `mlx5_vfmig_plugin_restore_vf_only(int)`.
6. **Standalone `mlx5_vfmig_restore_vf` binary.** dlopen shims
   (`print_on_level`, `log_get_loglevel`, `criu_get_image_dir`) + Makefile
   target.
7. **`[NOT-FOR-MERGE]` VF round-trip gate.** Extends the presence gate: dump →
   teardown → reprovision → `mlx5_vfmig_restore_vf` → assert bound / ibdev-up.
   **Hardware-gated**: needs real tracked VFs.

## 4. Explicitly deferred (out of scope for this milestone)

- **Layer A**: uverbs-context + ib_uobject dump/restore, the PIE CQ/QP path, and
  the core RDMA hooks that back them (`RDMA_DUMP_UVERBS_CONTEXT`,
  `RDMA_DUMP_UOBJ_*`, `RESTORE_*_NEEDS_PIE`). The proto reserves room for the
  `uctx_*` fields to be re-added without an ABI break.
- **Cross-host rendezvous**: `vfmig_barrier.c` / `vfmig_dpstate.c` directional
  suspend barrier. Single-host dump-then-restore first.

## 5. Practical blocker to clear before step 7 can run

Steps 1–6 build and unit-check with no hardware. Step 7 (and any real
save/restore) needs VFs provisioned + `SET_TRACKED` + a stamped `vf_uuid`. As of
this writing both PFs report `sriov_numvfs=0` and no orchestration CLI is built,
so the orchestration path (kernel CLI or a small sysfs+ioctl helper) must be
sorted before the round-trip gate is exercisable.
