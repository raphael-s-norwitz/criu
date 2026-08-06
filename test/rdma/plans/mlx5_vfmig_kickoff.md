# mlx5_sriov_vfmig kickoff — core-CRIU delta + start sequence

Concrete companion to `criu_build_up_plan.md` §3 Phase **T2**. That doc owns the
milestone spine (T2.0–T2.6); this doc is the *"we are here, here is what core
CRIU still needs, here is the order to start"* note written as T1 (rxe) wraps up.

Grounded in a three-tree read on 2026-08-06:
- kernel `/opt/builds/linux@rebase-2` (vfmig subsystem landed),
- our build-up `/opt/builds/criu@criu-rebase-t1.1-rxe-pd-wip` (rxe T1.x + A1 thaw),
- oracle `/opt/builds/criu-poc-ref@criu-dev-poc-rebase` (full plugin stack).

## 1. Current state

**Kernel (`rebase-2`) — the vfmig UAPI is essentially complete.** One char device
per PF at `/dev/mlx5_vfmig/<bdf>` (`include/uapi/linux/mlx5_vfmig.h`), with:

- introspection / identity: `GET_VHCA_ID`, `QUERY_VF` (`tracked`, `restored`,
  `vf_uuid`, `num_vfs`), `SET_VF_UUID`, `SET_TRACKED` (per-VF deterministic IOVA
  domain),
- migration gate: `ENABLE_MIGRATABLE` (VF must be unbound),
- datapath ladder: `SUSPEND_VHCA` / `RESUME_VHCA` (directional INITIATOR/RESPONDER,
  RUNNING↔RUNNING_P2P↔STOP),
- state transfer: `SAVE_VHCA_STATE` (→ read-only `save_fd`, FW_DATA blob),
  `LOAD_VHCA_STATE` (→ write-only `load_fd`, staged + applied at next VF probe),
  `MARK_RESTORED`.

**Our build-up tree — T1/rxe framework is in place.** From the rxe milestones we
already have the core uverbs-uobj walker (dumps `R3UT_PD/MR/CQ/QP`) plus these
RDMA hooks wired end-to-end: `RDMA_CLAIM_UVERBS_CONTEXT`, `RDMA_OPEN_UVERBS_CDEV`,
`RDMA_DUMP_UOBJ_CQ`, `RDMA_RESTORE_UOBJ_CQ_UHW_PACK`, `RDMA_DUMP_UOBJ_QP`,
`RDMA_RESTORE_UOBJ_QP_UHW_PACK`, and the generic device hooks
(`CHECKPOINT_DEVICES`, `RESUME_DEVICES_LATE` (A1 thaw), `PAUSE_DEVICES`,
`HANDLE_DEVICE_VMA`, `UPDATE_VMA_MAP`). Core RDMA lives under `criu/rdma/*`
(already split out of the oracle's monolithic `criu/rdma.c`).

## 2. The plugin is two layers on one uobj spine

`plugins/rdma/mlx5_sriov_vfmig/` (~7.8k LOC, 11 files) stacks:

- **Layer A — RDMA verbs objects (like rxe, but real HW).** ucontext/PD/CQ/QP/MR
  captured + restored through the uobj walker with mlx5-specific UHW blobs.
  Critical difference from rxe: mlx5's kernel `restore_cq`/`restore_qp` pin source
  user VAs via `ib_umem_get` from the *restored task's* mm, so CQ/QP restore must
  run **in the PIE** (restorer blob, post-VMA-mmap), not from criu master →
  `RESTORE_UOBJ_{CQ,QP}_NEEDS_PIE`.
- **Layer B — VF firmware-state migration** via the PF char device. Gates on
  `QUERY_VF.tracked=1`, claims as `RCD_MLX5_SRIOV_VFMIG`, `SAVE` on dump
  (`CHECKPOINT_DEVICES` park + `fini` drain), `LOAD`+`MARK_RESTORED`+bind eagerly
  at `init(RESTORE)`, `SUSPEND/RESUME` for snapshot ordering, a cross-host
  directional-suspend rendezvous barrier, PCI/BDF resolution, per-VF IOVA. Declares
  `CR_RDMA_SHARING_EXCLUSIVE` (whole-VF atomic unit).

Plugin file map: `rdma_mlx5_vfmig_plugin.c` (init/fini/claim/hook reg),
`vfmig_dump.c`, `vfmig_restore.c`, `mlx5_vfmig_restore_vf.c` (standalone prerestore
binary), `vf_image.c`, `vfmig_uverbs.c`, `vfmig_pci.c`, `vfmig_dpstate.c`,
`vfmig_barrier.c` + `vfmig_barrier_wire.h`, `mlx5_uapi.h`, `vfmig_internal.h`.

## 3. Core-CRIU delta — needed BEFORE the plugin compiles

The plugin registers all its hooks in one file, so (as with rxe) it cannot build
until the hooks exist in core. Verified-missing pieces in our tree:

| Core piece | Where | Note |
|-----------|-------|------|
| `RCD_MLX5_SRIOV_VFMIG` enum value | `images/rdma_criu.proto` | today only *reserved in a comment*; make it a real append-only value (→ 2) |
| `CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT` + `rdma_dispatch_dump_uverbs_context` | `criu-plugin.h`, `criu/rdma/*` | dispatcher is **0 occurrences** in our tree; mlx5 ucontext carries device data |
| `RDMA_DUMP_UOBJ_PD` + `RDMA_RESTORE_UOBJ_PD_UHW_PACK` | `criu-plugin.h`, `uobj_dump.c`/`uobj_restore.c`, `plugin_api.c` | mlx5 alloc_pd UHW (rxe needed no per-driver PD hook) |
| `RDMA_RESTORE_UOBJ_MR_UHW_PACK` | same | mlx5 reg_mr UHW |
| `RDMA_RESTORE_UOBJ_CQ_NEEDS_PIE` + `RDMA_RESTORE_UOBJ_QP_NEEDS_PIE` | `criu-plugin.h` + `uobj_restore.c` | **the meaty one** — see below |

Already present (no core work): the sharing machinery (`CR_RDMA_SHARING_EXCLUSIVE`,
`CR_PLUGIN_DECLARE_RDMA_SHARING`/`_PROVIDED_DRIVER`), and every generic device hook
the plugin uses. `PROCESS_DEVICE_VMA` appears in the oracle enum but the mlx5
plugin does **not** use it — ignore for T2.

**NEEDS_PIE is restore-engine surgery, not just an enum entry.** Today our CQ/QP
UHW-pack + RESTORE ioctl run from criu master; the oracle plumbs pack+ioctl into
the restorer PIE blob (`criu/rdma/uobj_restore.c`) so `ib_umem_get` pins the
restored task's pages. Land + prove this **against rxe first** (rxe can run either
way) before mlx5 depends on it — it is the single riskiest T2 prerequisite.

## 4. Start sequence

Mirror the rxe cadence — **[core hook/plumbing] → [plugin capability] →
[`[NOT-FOR-MERGE]` gate]** — mapped onto the `criu_build_up_plan.md` §3 T2 spine:

1. **K0 — driver identity + bootstrap (→ T2.0 start).** proto `RCD_MLX5_SRIOV_VFMIG`
   + `PROVIDED_DRIVER` routing; plugin skeleton: `init/fini` presence detect over
   `/dev/mlx5_vfmig`, `QUERY_VF.tracked` gate, `CLAIM`. (cf. `origin/…-2.1-vfmig-bootstrap`.)
2. **K1 — core uobj hook expansion (→ prereq for T2.1–T2.3).** `DUMP_UVERBS_CONTEXT`
   (+dispatcher), `DUMP/RESTORE PD`, `RESTORE MR` hooks; exercise minimally with rxe
   where possible.
3. **K2 — core NEEDS_PIE (→ prereq for T2.4/T2.5).** pie-side CQ/QP restore, proven
   on rxe first.
4. **K3 — mlx5 verbs objects (→ T2.1–T2.5 Layer A).** ucontext/PD/CQ/QP/MR UHW on
   K1/K2.
5. **K4 — VF firmware state (→ T2.0/T2.5 Layer B).** SAVE dump-side, LOAD+MARK+bind
   restore-side, SUSPEND/RESUME snapshot ordering.
6. **K5 — cross-host hardening (→ T2.6).** `vf_uuid` capture/discovery, standalone
   `mlx5_vfmig_restore_vf`, directional-suspend rendezvous barrier, device-VMA
   remap (UAR/BF/doorbell) onto restored cdev fds.

Ordering note: K2 (NEEDS_PIE) is the risk gate — land it before K3/K4 even though
the kernel ordering would let us rush to Layer B.

## 5. Mechanics + open items

- **Per-commit buildable:** land each core hook adjacent to the plugin code that
  first uses it (or behind a `[NOT-FOR-MERGE]` stub), same as rxe.
- **Layout mapping:** oracle comments still say `criu/rdma.c`; we port that logic
  into our split `criu/rdma/*.c`.
- **Branch naming:** the master plan assumes `criu-dev-build-up-rebase`; our actual
  build-up branch is `criu-rebase-t1.1-rxe-pd-wip`. Reconcile before T2 curation.
- **Rig:** T2 whole-workflow gate is CX-7 rig-bound and needs the vermagic-matched
  build-up kernel booted (kernel §8 boot-tree item).
