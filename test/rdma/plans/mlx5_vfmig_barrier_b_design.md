# vfmig datapath barrier — `[b]` robustness rework (design scratch)

Status: **design agreed, not yet implemented.** Captured 2026-08-22 before a context reload.
Prior transcript: `80082eff-4d50-4d9e-9d15-8ddb4fafe0f4`.
Todo id for this work: `d1c` (was "[b] robustness: two-phase + cross-host-consistent barrier ordering; also applies to restore R1").

This picks up right after the per-VF `[a]` D1 barrier landed and was HW-validated. `[a]`
runs the full `INITIATOR -> barrier -> RESPONDER` ladder **per VF**; that cannot satisfy a
global cohort invariant, so `[b]` reworks it. Nothing below is committed yet.

---

## 1. The invariant driving everything

**Truly global cohort invariant:** the whole participating VF set — every VF on every host
in the migration — must be sitting at `RUNNING_P2P` before *any* member leaves that rung
(to `STOP` on dump, or to `RUNNING` on restore). Motivated by PCI device-ordering /
connection-integrity concerns the datapath maintains across VFs.

Consequence: the ladder must be staged as **three passes over the whole cohort**, not a
per-VF ladder:
1. all local VFs `-> RUNNING_P2P` (INITIATOR edge)
2. one cross-host barrier: block until every *remote* VF is also at `RUNNING_P2P`
3. all local VFs `-> STOP` (RESPONDER edge)  [dump]  /  `-> RUNNING` (RESUME INITIATOR) [restore]

Pass boundaries *are* the invariant: nobody leaves the rung until local (passes) + remote
(barrier) are all on it.

---

## 2. Hook placement (dump) — RESOLVED

CRIU dump timeline (`criu/criu/cr-dump.c`):
- `2252` `rdma_capture_uverbs_contexts()` — uobject DAG capture, datapath still live
- `2255` `checkpoint_devices()` — only plugin hook **before** memory
- `2258–2285` prep: `collect_pstree_ids`, `network_lock`, file/namespace collection, etc.
- `2286` `for_each_pstree_item { dump_one_task }` — **MEMORY SNAPSHOT** (reads pinned MR pages)
- `2298` `rdma_emit_uobj_dag()`
- `2301` `run_plugins(DUMP_DEVICES_LATE, ...)` — **after** memory

`checkpoint_devices()` (`criu/criu/seize.c:1133`) calls the plugin hook **per alive task**;
the plugin dedups on the suspended set. The claimed cohort is fully known by `2255` (claim
happens during capture at `2252`).

Hard constraints:
- **STOP must precede the memory snapshot** (else peer WRITE / VF self-DMA tears pinned MR pages).
- **STOP must follow the barrier** (the invariant).
- => `barrier -> STOP -> memory`, so the barrier must finish **before line 2286**.

Therefore:
- `DUMP_DEVICES_LATE` (2301) is **too late** — it's post-memory. Rejected as the join point.
- A **new pre-memory hook** (at 2286) is only needed if we want to run the barrier on a
  worker thread and `pthread_join` it late (to overlap barrier latency with the 2258–2285
  prep block). The overlap window is only the prep block (usually milliseconds), so the win
  is marginal; the invariant forbids overlapping the barrier with the *memory* copy.
- **DECISION: go single-caller / synchronous, no thread.** Once synchronous there is no
  deferred join, so the whole ladder collapses back into the **existing `CHECKPOINT_DEVICES`
  hook**. **No new core hook, no `cr-dump.c` change at all.**

Restore is asymmetric: `RESUME_DEVICES_LATE` already fires after bind/arm and before the
final RESUME, so the restore barrier lives inside that **existing** hook. No new restore hook.

---

## 3. One-hook structure (dump) — the three-pass cohort

Rewrite `rdma_mlx5_vfmig_plugin_checkpoint_devices` (`vfmig_dump.c:584`) so the current
per-VF loop calling `vfmig_suspend_one_vf` (INITIATOR->barrier->RESPONDER for one VF)
becomes three passes over the whole claimed cohort with **one** barrier in the middle:

```
if (!vfmig_active) return -ENOTSUP;
if (cohort already parked) return 0;         /* run-once: first alive-task call does it all */

/* Pass 1: everyone onto the rung */
for each claimed VF not yet suspended:
    resolve vf_uuid -> load descriptor        /* see section 5: no more legacy 'mode' */
    SUSPEND(INITIATOR) -> RUNNING_P2P
    record {pf_bdf, vf_id, rz} in a cohort array

/* Pass 2: one multiplexed rendezvous over the whole cohort */
vfmig_barrier_run_set(cohort_rz[], n_cohort, "D1")

/* Pass 3: now everyone leaves the rung */
for each cohort VF:
    SUSPEND(RESPONDER) -> STOP
    vfmig_suspended_add(...)                   /* track for fini(DUMP) resume */

rollback on any failure: resume everything parked so far -> RUNNING, fail the dump
```

Notes:
- **Dedup shifts from per-VF `vfmig_suspended_lookup` skip to a cohort-once gate** (a `ran`
  flag or "all claimed already suspended") — otherwise a 2nd alive-task invocation re-enters
  mid-ladder.
- `vfmig_suspend_one_vf` dissolves; its INITIATOR/RESPONDER edges become passes 1 and 3.
- Cohort storage: **fixed `cohort[VFMIG_MAX_VFS]` stack array** with a defined cap (claimed
  set is already bounded). (Open: confirm the cap constant.)
- Restore mirrors this in `resume_devices_late`: arm-all at RUNNING_P2P -> `vfmig_barrier_run_set(..., "R1")` -> RESUME(INITIATOR)-all -> RUNNING.

---

## 4. Barrier transport rework — set-scoped, multiplexed, symmetric (no tie-break)

Replace the per-edge `vfmig_barrier_run(rz, phase)` with a **set-scoped**
`vfmig_barrier_run_set(rz[], n, phase)`:

- One `select()` loop owning **a listen fd per `rz`** plus non-blocking connect fds on
  every edge; **one overall deadline** for the whole set.
- **Symmetric: every endpoint both listens and connects to every peer, unconditionally.**
  No `endpoint_cmp` / lexical tie-break. Each edge therefore carries **two** TCP
  connections (A->B and B->A), one per direction, each delivering that sender's READY.
- **Delete `endpoint_cmp` / `is_connector[]`** (the current tie-break in `vfmig_barrier.c`,
  declared around `vfmig_internal.h:217`). The whole reason it existed was to force exactly
  one connection per edge; dropping that requirement removes it.
- Per-endpoint, per-peer completion, no ordering:
  ```
  sent[p]  = we connected to p and wrote our READY
  recvd[p] = we accepted a conn and read p's valid READY   /* matched by vf_uuid in the wire msg */
  done     = all sent[] && all recvd[]
  ```
  Retry connects until `sent[p]`; keep accepting until `recvd[p]`. Attribution is by
  `vf_uuid`/session already in the wire record, not by who dialed.
- **Wire format unchanged** (`vfmig_barrier_wire.h`, `struct vfmig_barrier_msg`).
- `n_peers == 0` => nothing to connect, nothing to accept => **done immediately** (native
  no-op in the new loop; this is what makes peerless descriptors work — section 5).

---

## 5. Kill `mode` (legacy vs barrier) — DECISION PENDING ONE CONFIRMATION

`mode` in `vfmig_suspend_one_vf` / `vfmig_barrier_arm` is **descriptor-presence** (legacy =
no `.desc`), **not** the lexical tie-break — two different things that both got called
"mode" in discussion. The tie-break is already being deleted in section 4. `mode` itself:

`vfmig_rendezvous_load` (`vfmig_barrier.c:99`) today returns `1` (ENOENT/legacy), `0`
(loaded, >=1 peer), `-1` (malformed). Removing `mode` collapses it to `0`/`-1`:
1. **Loader:** `ENOENT -> -1` (fail closed, no more legacy). Drop `n_peers == 0` from the
   incomplete check (`vfmig_barrier.c:164`) so a **peerless descriptor (session+listen, 0
   peers) is valid**.
2. **`vfmig_suspend_one_vf`:** delete `mode` + the `if (mode == 1)` fused branch; unreadable
   uuid becomes an error, not a fallback. (Folds into the pass-1/pass-3 rewrite.)
3. **`vfmig_barrier_arm` + `struct vfmig_restored_vf`:** drop the `rc == 1` branch and the
   `barrier_mode` field; every restored VF is armed (`barrier_done` stays for dedup).
4. **`resume_devices_late`:** remove the `!barrier_mode` skip.
5. **Barrier:** no-op cleanly on `n_peers == 0` (free in the section-4 rewrite).

**Consequence to confirm before stripping the fallback:** a rendezvous descriptor becomes
**mandatory for every claimed VF**. No `.desc` => dump fails closed. This is the right
production contract *iff* the orchestrator always stamps a descriptor (n_peers=0 when no
peers), mirroring how it already always stamps `vf_uuid`. **But** every existing non-barrier
gate that stamps a uuid but not a descriptor — the QP / PD / MR / CQ C/R harnesses — will
start failing at `checkpoint_devices` and must each drop a trivial `n_peers=0` descriptor.
Only the D1 gate writes one today.

User's stated intent: **"I would like to get rid of mode."** Recommendation: fold `mode`
removal into the section-4 barrier rewrite (peerless no-op is native there), and update the
affected `[NOT-FOR-MERGE]` gates to stamp the trivial descriptor.

Last open question to the user (unanswered at reload): confirm
**descriptor-mandatory-for-every-VF** is the desired operational contract. If yes -> strip
`mode` as above. If they want to keep tolerating undescribed VFs -> `mode` cannot be fully
deleted.

---

## 6. Decisions locked vs still open

Locked:
- Single synchronous barrier, **no worker thread** (v1). Thread was considered and dropped
  (marginal dump win; only overlaps the small prep block, never the memory copy).
- **No new core hook.** Everything lives in existing `CHECKPOINT_DEVICES` (dump) and
  `RESUME_DEVICES_LATE` (restore).
- Three-pass cohort ladder; invariant enforced by pass boundaries + one barrier between.
- Set-scoped multiplexed **symmetric** transport; **delete tie-break** (`endpoint_cmp`).
- One overall deadline for the whole set.
- Completion = per-peer `sent[] && recvd[]`; attribution by `vf_uuid`, no ordering.
- Wire format unchanged.
- Intent to remove `mode`.

Open:
- Confirm descriptor-mandatory contract (blocks final `mode` removal).
- Cohort array cap constant (`VFMIG_MAX_VFS` name/value).
- Legacy handling during transition — moot once `mode` is gone; until then, whether the
  peerless case is n_peers=0 descriptor.
- Exact `vfmig_barrier_run_set` signature (array of `struct vfmig_rendezvous` + count + phase).
- Commit breakdown for `[b]` (keep granular / upstream-reviewable per standing constraints).

---

## 7. Key references

- `criu/criu/cr-dump.c` — dump timeline; 2255 checkpoint_devices, 2286 memory loop, 2301 DUMP_DEVICES_LATE.
- `criu/criu/seize.c:1133` — `checkpoint_devices()` per-alive-task loop.
- `criu/criu/include/criu-plugin.h` — hook enum (`CHECKPOINT_DEVICES`=11, `RESUME_DEVICES_LATE`=9, `DUMP_DEVICES_LATE`=14).
- `criu/plugins/rdma/mlx5_sriov_vfmig/vfmig_dump.c:584` — `rdma_mlx5_vfmig_plugin_checkpoint_devices`; `:479` `vfmig_query_vf_uuid`; `:~530` `vfmig_suspend_one_vf`.
- `criu/plugins/rdma/mlx5_sriov_vfmig/vfmig_barrier.c:99` `vfmig_rendezvous_load`; `:164` incomplete check; `:193` `endpoint_cmp`; `vfmig_barrier_run`.
- `criu/plugins/rdma/mlx5_sriov_vfmig/vfmig_restore.c:1131` `vfmig_barrier_arm`; `resume_devices_late`.
- `criu/plugins/rdma/mlx5_sriov_vfmig/vfmig_internal.h:209` loader decl; `:211-213` phase labels; `:215-223` `vfmig_barrier_run` decl/comment.
- `criu/plugins/rdma/mlx5_sriov_vfmig/vfmig_barrier_wire.h` — wire record (unchanged).
- Gates: `test/rdma/run_vfmig_d1_dump.sh` (writes a descriptor), `run_vfmig_qp_cr.sh`,
  and PD/MR/CQ gates (do NOT write descriptors — will need trivial n_peers=0 descriptor once `mode` is gone).

## Standing constraints (unchanged)
- Granular, upstream-reviewable commits; core stays HW-agnostic; drivers/plugins own driver-private shaping.
- Avoid "R3" stage-shorthand in prose (generated protobuf identifiers exempt).
- Never mix upstream plugin/core code with `test/rdma/` harness in one commit; `[NOT-FOR-MERGE]` prefix for dev/test commits.
- No dead code; "producer without consumer" intermediate commits OK if they compile and are reachable.
- Commit-msg hook auto-appends `Assisted-by:` + `Signed-off-by:` — omit from body. Subject <=52 chars; plugin subject `plugins/rdma/mlx5_sriov_vfmig: <short>`; core `rdma: <short>`.
- `sudo`/`ldd` blocked; don't provision VFs / mutate `sriov_numvfs` (user runs the harness).
