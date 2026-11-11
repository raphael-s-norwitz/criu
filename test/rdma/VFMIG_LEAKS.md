# INTERNAL VALIDATION ONLY -- drop before upstream PR.

# mlx5 vfmig: firmware state a CRIU restore chain leaks, fixed and open

Status 2026-11-07, Q counter result 2026-11-09. Kernel `func-devel-5` at `ba66ce1f`. CRIU branch
`criu-rdma-dev-7.2-func-devel` with `875e3dcf6` (TD adoption) and
`d16dc8800` (F_IB_RELEASE). Measured with `run_vfmig_qp_traffic_loop.sh`,
CX-7, VF 0 <-> VF 1.

## The pattern

SAVE_VHCA_STATE captures every firmware object on the VF's VHCA, whoever
owns it. LOAD brings them all back on the destination. The process's own
objects (PD, CQ, QP, MR, UARs) are adopted by the restore path. A kernel
driver's objects are not: the destination's mlx5_core / mlx5_ib / mlx5e
probe from scratch and create their own, and the loaded copies stay
allocated with no owner. Each hop then carries one more set, so the SAVE
blob grows linearly and the VHCA's firmware resources run down.

So every firmware object a kernel driver on the VF creates is a candidate,
in particular ones created lazily on first use, which a fresh probe does
not account for. The fix is one of:

- destroy it on the source before SAVE, under the RX fence (mlx5e suspend,
  F_IB_RELEASE), and let the driver create it again on demand; or
- adopt the loaded copy on the destination (EQs, the TD).

## Fixed

| Object | Created by | Growth | Fix |
|---|---|---|---|
| mlx5e's queues, RQTs, TIRs, flow tables | mlx5e probe | ~1 MiB/hop | F_ETH_SUSPEND: mlx5e suspended under the fence |
| mlx5_core EQs | mlx5_core probe | generation limit (CREATE_EQ failed) | kernel adopts the restored EQs |
| Transport domain | every ucontext | ~8.5 KiB/hop | ADOPT_TD (`9ae49bbc`, `875e3dcf6`) |
| UMR QP + CQ, cached mkeys, one doorbell page | first MR registration | ~24 KiB/hop | F_IB_RELEASE (`ba66ce1f`, `d16dc8800`) |

After all four, 20-hop chains of a bare ucontext, a PD with an MR
registered and deregistered each hop, and a self-loop RC QP passing
traffic are flat to within a few pages; the 60-hop QP chain is in the
next section.

## Open

### 1. mlx5_ib's port Q counter: one per hop, fatal at hop 125

200-hop QP chain (2026-11-09): the blob grows linearly with no levelling
off, 5,963,496 bytes at hop 2 to 6,102,760 at hop 124 (+1,141 bytes/hop;
the 60-hop chain showed +918, and the PD chain +680 over 20 hops). Replay
counts stay constant throughout. Hop 125 then failed: LOAD and bind
succeeded, but mlx5_ib's probe on the destination did not:

    mlx5_ib_alloc_counters:995: couldn't allocate queue counter for port 1, err -12
    mlx5_ib.rdma mlx5_core.rdma.2: probe with driver mlx5_ib.rdma failed with error -12

so no ibdev appeared and the plugin timed out waiting for it.

`mlx5_ib_alloc_counters()` (ib_counters stage) allocates one Q counter per
port with ALLOC_Q_COUNTER, uid = MLX5_SHARED_RESOURCE_UID. Nothing in the
vfmig paths frees it: `mlx5_ib_vfmig_release()` releases only the UMR
resources, cached mkeys and the doorbell page, and `counters.c` has no
vfmig hook. So the source's counter travels in every SAVE and the
destination allocates another. mlx5e's two counters (`q_counter`,
`drop_rq_q_counter`) do not leak: F_ETH_SUSPEND detaches the netdev and
`mlx5e_cleanup_nic_rx()` deallocates them before SAVE. One leaked counter
per hop running out after 124 hops is consistent with a per-function cap
(`max_qp_cnt`) of about 128. mlx5e's allocation fails silently when
counters run out, so mlx5_ib is the first thing to notice. That the
~1.1 KiB/hop blob drift is exactly this counter is likely but not proven.

The loop gate did not catch it: blob growth stayed inside `GROWTH_TOL`, and
neither firmware pages nor replays move.

Fix options (kernel):

- Adopt: on a from_load probe, take the source's set_id for each port
  instead of allocating, like the EQs and the TD. The restored QPs already
  reference the source's set_id, so this also keeps their counters live.
  It needs the source's set_id at probe time (the vfmig metadata, or a
  firmware query).
- Release under the fence and allocate again on lift. That is harder: the
  source's QPs reference the counter, and DEALLOC_Q_COUNTER while it is in
  use will likely be refused.

The same applies to any counter allocated with `rdma statistic qp set` (a
per-QP or auto-mode counter), which goes through the same
ALLOC_Q_COUNTER path.

Also seen every hop, not related: on recycle of the old source VF,
DESTROY_EQ of comp EQ 0x6 fails with bad resource state (syndrome
0x30f433), followed by `poll_health: Fatal error 3`. It is on the loop's
allowed-kmsg list.

Also unexplained: the PD chain's `dma_coherent` replays fall from 13 to 0
with F_IB_RELEASE (1 for hops 2-4, 0 from hop 5), but the QP chain keeps 13
on every hop although its fences also report `mlx5_ib released`.

### 2. GPU (dma-buf) and ODP MRs: F_IB_RELEASE is refused

`mlx5_ib_vfmig_release()` returns -EBUSY while `dev->odp_mkeys` is
non-empty. That xarray holds:

- every ODP MR (`create_user_odp_mr`), and
- every dma-buf MR whose exporter can move its pages
  (`umem_dmabuf->pinned == 0`, the dynamic attachment); see
  `mlx5_ib_reg_user_mr_dmabuf` in `mr.c`.

A dma-buf MR from an exporter that cannot move its pages is attached
statically (`ib_umem_dmabuf_get_auto`), is not in `odp_mkeys`, and does
not block the release. Whether a given GPU stack's dma-buf is pinned
decides which case it is in, so it has to be checked per exporter
(NVIDIA `cuMemGetHandleForAddressRange` dma-buf vs. a movable one such as
amdgpu's).

When the release is refused, the plugin logs
`, mlx5_ib kept (not bound, or it holds an ODP or dma-buf MR)` on the
fence line and the dump goes ahead. That VF's SAVE then carries:

- the UMR QP and CQ, the cached mkeys and the doorbell page (~24 KiB/hop,
  as before F_IB_RELEASE), and
- the **ODP page-fault EQ** (`dev->odp_pf_eq`, `mlx5r_odp_create_eq`),
  created on the first ODP or movable dma-buf MR and destroyed only at
  device unload (`odp.c`). The destination's mlx5_ib creates another on
  its first ODP use. Not measured yet; an EQ also carries its own
  doorbell, IRQ and EQ buffer, and we already know orphaned EQs used to
  exhaust CREATE_EQ.

Why it is refused: an ODP page fault or a dma-buf move notification posts
a UMR from a context that cannot create the UMR QP again. Under CRIU the
tasks are frozen and the fence is up, but a fault on an ODP MR can still
come from the device for in-flight work, and a move notification from the
exporter at any time.

Fix options, for the kernel side:

1. Quiesce, then release anyway: with the VHCA's RX fenced and its SQs
   drained (already true before SAVE), invalidate every ODP/dynamic
   dma-buf mkey's mapping, destroy the page-fault EQ and the UMR pair, and
   let the first fault after resume recreate both from a sleepable
   context (the page-fault work queue is sleepable). Needs the UMR
   recreate on the fault path.
2. Adopt on the destination: have the restored mlx5_ib take over the
   loaded UMR QP/CQ and page-fault EQ by id (carried in the VF image like
   the TD), instead of creating new ones.
3. Refuse the dump of a VF with ODP/movable dma-buf MRs, so it fails
   loudly instead of leaking. Stopgap only.

There is also a known CRIU-side gap on this path: the CUDA plugin's fini
resumes the GPU on `ret != 0` or `final_state == TASK_ALIVE` but not when
only a post-dump script failed, so with GPU dma-buf MRs a failing
post-dump script leaves the VF fenced.

Test needed: a holder registering (a) an ODP MR, (b) a pinned dma-buf MR,
(c) a movable dma-buf MR, run through the chain with the `kres` column
(`KRES_LOG=1`) and the fence line's `mlx5_ib released|kept`.

### 3. Other lazily created kernel objects (untested)

None of these is exercised by the chain today. Each is a kernel-owned
firmware object created on first use that a restored VF's driver would
create again:

| Trigger | Object | Where | Expected |
|---|---|---|---|
| first SRQ (`ibv_create_srq`) | `devr` PD + CQ (`mlx5_ib_dev_res_cq_init`) | `srq.c`, `main.c` | leak per hop; CREATE_PD/CQ are not gated on restored VFs |
| first XRC or GSI QP | `devr` XRC SRQs s0/s1 | `mlx5_ib_dev_res_srq_init` | refused on a restored VF (-EOPNOTSUPP), so XRC does not work there at all |
| ODP MR / movable dma-buf MR | page-fault EQ | `odp.c` | see section 2 |
| `rdma statistic` per-QP counters (manual bind or auto mode) | ALLOC_Q_COUNTER | `counters.c` | leak per hop if set on the source |
| multicast attach (`ibv_attach_mcast`, UD) | MCG attachment | `qp.c` | unknown: is it captured at all? |

The GSI note matters beyond XRC: `mlx5_ib_dev_res_srq_init` refusing on a
restored VF means ib_core's MAD agent does not open QP1 there ("Couldn't
open port 1"). RDMA CM over RoCE needs QP1, so check whether a restored VF
can still set up a new RDMA CM connection; the chain's QPs are connected
by hand.

QP types: the plugin's QUERY_QP takes RC, UC and UD. Only RC has been
through the chain. UC and UD create no extra kernel-owned objects that we
know of, but neither has been run, and UD's address handles and multicast
have not been looked at.

## How to test a candidate

1. A holder that creates the object (extend `uverbs_ctx_holder` with a
   `HOLDER_ALLOC_*` mode or `qp_gid_holder` with a QP type).
2. `run_vfmig_qp_traffic_loop.sh` with `HOPS=20 GROWTH_TOL=4000000
   KRES_LOG=1` and the new `HOLDER_KIND`. Flat `blob` from hop 2 means no
   leak; a steady per-hop step is the object's size in the SAVE.
3. A 0-vs-1-vs-2 split as with `HOLDER_PD_MR_PROBES` tells per-use state
   from per-VF state.
