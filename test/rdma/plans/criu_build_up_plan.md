# CRIU-side build-up plan (`criu-dev-build-up-rebase` ⟶ `criu-dev-poc-rebase`)

Companion to the kernel plan
(`linux.git:tools/testing/criu_rdma/plans/upstream_series_inventory.md`, esp. §8).
Same two-agent workflow, same **vertical per-object milestone spine**; this doc is
the criu (userspace) half. Where the kernel doc owns the ABI/verbs, this doc owns
the plugin + core RDMA dump/restore that consumes them.

## 0. End state + workspace

- **Goal:** curate `criu-dev-build-up-rebase` up to `criu-dev-poc-rebase` (107
  commits over base `28558bcc4` "criu: rdma: Support opening uverbs async event
  fds"), as a clean, **incrementally-tested** series, advancing in lockstep with
  the kernel build-up.
- **Worktrees** (shared clone under `/opt/builds`):

  | Path | Branch | Role |
  |------|--------|------|
  | `/opt/builds/criu` | `criu-dev-build-up-rebase` | **Curation** — build the clean series here |
  | `/opt/builds/criu-poc-ref` | `criu-dev-poc-rebase` | **Oracle** (diff/behaviour) + home of these plan docs |

- Oracle tip carries the full plugin stack: `criu/rdma/*` core, `plugins/rdma/rxe`,
  `plugins/rdma/mlx5_sriov_vfmig`, the R3 per-uobject DAG, the standalone
  `mlx5_vfmig_restore_vf` prerestore binary, and the cross-host barrier
  (rendezvous-only R1).

## 1. What ships vs. scaffold

- **Ships:** `criu/rdma/*` (core RDMA dump/restore: `plugin_api.c`, `driver.c`,
  `precheck.c`, `uverbsfd.c`, `uobj_dump.c`, `uobj_restore.c`), `plugins/rdma/rxe`,
  `plugins/rdma/mlx5_sriov_vfmig/*`, and the `images/rdma_uobj*` schemas.
- **Scaffold (path-disjoint; kept for test, dropped at export):** `test/rdma/*`
  (the `run_vfmig_cr.sh` pass matrix, the out-of-band rxe validator), `scratch/*`.

The path-disjoint invariant mirrors the kernel plan: a curated FUNCTIONAL commit
touches only shipping paths; its harness lands as a separate `test/rdma` commit, so
the upstream export is a mechanical path filter.

## 2. Two-agent handoff protocol

Per milestone (see the kernel §8 spine):

1. **Kernel agent** lands the milestone's kernel slice on the kernel build-up and
   ships to the criu agent:
   - synced UAPI headers into the plugin's vendored mirror
     (`plugins/rdma/mlx5_sriov_vfmig/uapi/...` and any rxe/core uapi shims),
   - a short consumption note: which verbs/ioctls, UHW payload shapes, ordering
     constraints (e.g. GET_CONTEXT-before-X, RESUME_DEVICES_LATE timing),
   - the **RXE reference behaviour** to mirror.
2. **criu agent** builds the plugin/core support, `make`s, and runs the milestone's
   acceptance (dev testcase, then the whole-workflow migration — see below).
3. **Guided consensus** (both agents + human) on ABI/behaviour; only then freeze
   the milestone and advance. Any mismatch loops back to the kernel agent before
   curation continues — never work around a kernel gap in the plugin silently.

Two acceptance tiers per milestone:
- **Dev testcase (setup 1):** the synthetic, targeted round-trip (`run_vfmig_cr.sh`
  pass / the out-of-band rxe validator). Fast dev loop; advances curation.
- **Whole-workflow E2E gate (setup 2):** a *live workload* migrated across hosts in
  the end-to-end migration environment (e.g. `ib_write_bw` swapped between the two
  VMs). **Passing this incremental testcase is the final gate to move to the next
  step** — it, not the synthetic pass, freezes the milestone.

Phase order (per the kernel §8): **RXE (T1) is completed end-to-end first, then
mlx5 (T2) is layered on top.** RXE + core is independently mergeable and merges long
before vfmig; finishing it first proves the criu restore framework on a rig-cheap,
soft-RoCE base before any CX-7 rig time is spent. Safe because we curate from a
proven oracle (the ABI already serves both).

## 3. Milestone spine (criu column; mirror of kernel §8)

Two phases; within each, vertical per-object. Dev testcase (setup 1) → whole-workflow
migration (setup 2) is the advance gate.

**Phase T1 — core RDMA + RXE plugin (complete first; rig-cheap):**

| M | Round-trip | criu deliverable | Image/schema | Dev testcase → whole-workflow gate |
|---|-----------|------------------|--------------|------------------------------------|
| T1.1 | PD | plugin claim arbitration, presence detect (rxe), plugin-owned uverbs cdev open, GET_CONTEXT ownership, R3 uobject DAG (S1.b/S1.c), PD restore via `UVERBS_METHOD_RESTORE_PD` | `images/rdma_uobj` per-uobject schema | rxe PD strict round-trip → rxe `ib_write_bw` migrate |
| T1.2 | MR | RESTORE_MR via the pie restorer blob (PACK/VERIFY UHW hooks) | +MR records | rxe MR + RDMA-WRITE acid → " |
| T1.3 | CQ | per-CQ save/restore (plugin-shaped UHW), RESTORE_CQ pie deferral + per-plugin opt-in | +CQ records | rxe CQ → " |
| T1.4 | QP (drained) | per-QP dump + restore UHW (`needs_pie`), master/PIE RESTORE_QP, pre-suspend QP coverage filter | +QP records | rxe QP → " |
| T1.5 | QP (in-flight) | non-drained-SQ in-flight replay, thaw restored ucontexts at RESUME_DEVICES_LATE, dump pipeline reorder (early uverbs capture) + resume-on-abort | in-flight ring subspan | rxe in-flight → rxe `ib_write_bw` mid-flight migrate |

**T1 exit gate:** full rxe suite green + a whole-workflow rxe migration passes — a
postable core+rxe series, independent of the mlx5 plugin.

**Phase T2 — mlx5_sriov_vfmig plugin (on the complete T1 core; rig-bound):**

| M | Round-trip | criu deliverable | Dev testcase → whole-workflow gate |
|---|-----------|------------------|------------------------------------|
| T2.0 | VHCA foundation | mlx5 presence plugin, SAVE_VHCA_STATE dump-side, cdev-VMA claim, KEEP_SUSPENDED opt-in | VF migrates + RC ping-pong survives → — |
| T2.1 | UAR + restore-mode uctx | VFMIG QUERY/RESTORE ucontext (static + dyn UAR), eager init(RESTORE) + UPDATE_VMA_MAP + cdev open | uctx round-trip → — |
| T2.2 | PD | mlx5 PD via UHW (adopt under uid=0) | `pd` → `ib_write_bw` swap |
| T2.3 | MR | mlx5 MR UHW, ship pie RESTORE_MR | `pd_mr` + RDMA-WRITE acid → `ib_write_bw` swap |
| T2.4 | CQ | per-CQ UHW, HANDLE attr wire fix | `pd_cq`, `pd_2cq` → `ib_write_bw` swap |
| T2.5 | QP (+ in-flight) | per-QP UHW, snapshot-ordering pause + QP-stage thaw, source-devx_uid contract | `pd_cq_qp`, `pd_cq_qp_sq` → `ib_write_bw` swap |
| T2.6 | Cross-host hardening | KS7.x `vf_uuid` capture/discovery, standalone `mlx5_vfmig_restore_vf` prerestore binary, cross-host directional-suspend **rendezvous barrier** (R1 rendezvous-only) | cross-host `pd_cq_qp_sq` → `ib_write_bw` swap across hosts (final) |

Notes:
- **T1.1 is the heaviest criu milestone** — it stands up the whole restore framework
  (DAG, claim, cdev open) in addition to PD. Budget accordingly.
- Verbs migration (source PD/CQ/QP identity via standard `QUERY_PD`/`QUERY_CQ`/
  `QUERY_QP` verbs, retiring the NLDEV/cdev-FIFO paths) rides the T1 CQ/QP
  milestones as the kernel verbs land; keep the plugin on the verb path once
  available.
- The rxe out-of-band validator and the `run_vfmig_cr.sh` pass are cumulative:
  each milestone *adds* a pass and must keep prior passes green (regression lane).

## 4. Curation mechanics (criu)

Mirror of kernel §4:
1. `git switch criu-dev-build-up-rebase` (curation tree `/opt/builds/criu`).
2. Per FUNCTIONAL commit: `git checkout criu-dev-poc-rebase -- <shipping paths>`
   then `git add -p` to take only that commit's hunks (drop scratch/debug); write a
   real message + `Signed-off-by: Raphael Norwitz <rnorwitz@nvidia.com>`.
3. **Build every patch** (`make` + the plugins); land the matching `test/rdma`
   scaffold as a separate path-disjoint commit so the pass is runnable immediately.
4. Run the milestone pass: RXE (rig-free) then mlx5 (rig).
5. Acceptance gate (losslessness): `git diff criu-dev-build-up-rebase
   criu-dev-poc-rebase -- criu plugins images` empty (modulo intentional cleanups)
   once all milestones land.

## 5. Rig / cadence (2-3 two-VM CX-7 setups)

- **Phase T1 (RXE) is rig-cheap:** dev testcases run single-host / loopback; the
  whole-workflow rxe migration runs over a plain VM-pair netdev (no CX-7 vfmig
  path). The reserved CX-7 rigs are barely touched until T2.
- **Phase T2 (mlx5) is rig-bound:** the whole-workflow migration is the CX-7
  back-to-back host swap and the milestone freeze condition.
- Setup roles: **setup 1** = dev / incremental testcases; **setup 2** = the
  whole-workflow migration environment (the final gate, `ib_write_bw` swapped across
  hosts); **setup 3** (if available) = regression baseline of the last-green
  milestone. T2.6 wants a dedicated setup.
- The **criu agent is the rig-bound throughput limiter**; the kernel agent runs 1-2
  milestones ahead (compile-only).
- **Boot dependency:** the T2 whole-workflow gate needs the **vermagic-matched
  build-up kernel** booted on the rig. Track this jointly with the kernel §8 "which
  worktree is the boot tree" item — the E2E gate is blocked until a bootable
  build-up kernel is available on a setup.

## 6. TODO — detailed commit inventory (mirror kernel §6)

Not yet built. Map the 107 `28558bcc4..criu-dev-poc-rebase` commits to
`(phase/milestone, disposition U/S, feeds)`, verified against the final
`base..criu-dev-poc-rebase` diff, and flag mixed commits to hunk-split. Because the
POC interleaved rxe and mlx5, several per-object commits **split across phases** at
curation: the rxe/core hunks feed a **T1** milestone, the mlx5-plugin hunks feed the
matching **T2** milestone. First-pass natural slices (phase-agnostic; branch order):

- **Framework:** rxe/mlx5 presence plugins, claim arbitration, cross-tree
  exclusivity, plugin-driven cdev open, GET_CONTEXT ownership, R3 S1.b/S1.c DAG,
  install/plugin-search-path plumbing. (rxe+core → T1.1; mlx5 presence → T2.0.)
- **PD:** `rdma_uobj` schema, R3 S2 PD restore (→ T1.1); "Slice 2" mlx5 PD via UHW +
  E2E harness, FW pdn / devx_uid adoption then uid=0-only (→ T2.2).
- **MR:** rxe MR wiring via pie restorer (→ T1.2); mlx5 MR UHW, RDMA-WRITE acid,
  multi-page non-aligned regression (→ T2.3).
- **Source-tree reorg:** `criu/rdma/*` extraction + `plugins/.../vfmig_*.c`
  extraction — a large path-move cluster; curate as reorg commits (core reorg → T1,
  plugin reorg → T2), not per-object.
- **CQ:** rxe CQ ring (→ T1.3); per-CQ UHW, RESTORE_CQ pie deferral + opt-in,
  `pd_cq`/`pd_2cq` (→ T2.4).
- **QP:** rxe QP + master/PIE RESTORE_QP, coverage filter (→ T1.4); per-QP UHW +
  `needs_pie`, `pd_cq_qp` (→ T2.5).
- **In-flight:** rxe thaw-and-replay, dump-pipeline reorder + resume-on-abort
  (→ T1.5); mlx5 snapshot-ordering pause + QP-stage thaw, non-drained-SQ replay,
  `pd_cq_qp_sq` (→ T2.5).
- **Cross-host (T2.6):** KS7.x `vf_uuid` capture/discovery/paired-match/soft-fallback,
  `mlx5_vfmig_restore_vf` prerestore binary, standard `QUERY_*` verb migration,
  directional-suspend barrier (add → bisect-knobs → revert-knobs →
  rendezvous-only), CQ ring round-trip.
