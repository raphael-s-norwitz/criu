# test/rdma -- internal validation, drop before upstream PR

Out-of-band validators for the criu RDMA work-in-progress. Used while
iterating on the rdma plugin framework before the work is mature
enough for a proper zdtm test.

## Files

- `uverbs_ctx_holder.c` -- minimal program that opens an rxe `ibv_context`
  (which implicitly creates an async-event fd inside the kernel context)
  and blocks on SIGTERM. If `HOLDER_ALLOC_PD` is set it also allocates a
  PD; if `HOLDER_ALLOC_MR` is set it additionally registers a persistent
  MR over a known-pattern buffer. SIGUSR1 re-queries the device and, per
  mode, exercises the post-restore state (PD: register + deregister an MR
  against it; MR: verify the buffer content survived and deregister the
  persistent MR) and writes the result to a status file. Used to confirm
  the context / PD / MR are still functional after restore.
- `run_uverbs_cr.sh` -- brings up an `rxe0` link if needed, launches the
  holder, calls `criu dump` then `criu restore`, signals the restored
  process to verify its context still works.
- `run_pd_cr.sh` -- thin wrapper over `run_uverbs_cr.sh` that sets
  `HOLDER_ALLOC_PD=1`, exercising the rxe `RESTORE_PD` path: the dump
  captures a PD uobject and restore reinstalls it at its ufile handle,
  which the post-restore `reg_mr` check then proves is live.
- `run_mr_cr.sh` -- thin wrapper that sets `HOLDER_ALLOC_MR=1`,
  exercising the rxe `RESTORE_MR` path: the dump captures an MR uobject
  and the pie restorer reinstalls it at its ufile handle after the
  buffer VMA is laid out, which the post-restore content + `dereg_mr`
  check proves is live (byte-identical lkey/rkey asserted by the pie).
- `run_vfmig_presence.sh` -- smoke gate for the `rdma_mlx5_vfmig`
  plugin at its early bring-up stage, where it can only detect
  migration-capable VFs and claim their uverbs contexts -- it does not
  yet snapshot or restore any device state. This is NOT a
  checkpoint/restore round-trip (the full C/R harness needs tracked VFs
  + the kernel deterministic-IOVA path); it validates the two live
  behaviours:
    - Tier 1 (presence, always): dumps a trivial victim with only the
      mlx5 plugin loaded and asserts the plugin loaded, probed each
      `/dev/mlx5_vfmig/<bdf>` cdev via `QUERY_VF`, and reached an
      active/inactive verdict consistent with the host (PF count ==
      #cdevs, summed per-cdev `tracked` == the verdict's count). On a
      host with no tracked VFs the expected verdict is INACTIVE.
    - Tier 2 (claim decline, auto when `rxe` is available; force with
      `VFMIG_GATE_CLAIM=1`, skip with `=0`): dumps an rxe context with
      BOTH plugins loaded and asserts the core exactly-one-claim
      arbitration invoked the mlx5 plugin's claim hook for the rxe
      ibdev and it DECLINED (rxe wins, no conflict). Exercises the
      claim path's negative branch without a tracked mlx5 VF.
  Victims are launched via `systemd-run --scope` so they don't inherit
  the caller's fds (a bare child inherits a unix control socket criu
  can't dump).

## Run

```
make -C test/rdma
# bare context + async-event fd:
sudo CRIU=/usr/local/sbin/criu test/rdma/run_uverbs_cr.sh [<netdev>]
# same, plus a PD round-trip (RESTORE_PD dev gate):
sudo CRIU=/usr/local/sbin/criu test/rdma/run_pd_cr.sh [<netdev>]
# same, plus an MR round-trip (RESTORE_MR dev gate):
sudo CRIU=/usr/local/sbin/criu test/rdma/run_mr_cr.sh [<netdev>]
# mlx5_vfmig plugin bring-up gate (presence detection + claim decline):
sudo CRIU=/usr/local/sbin/criu test/rdma/run_vfmig_presence.sh [<netdev>]
```

`<netdev>` defaults to the first up IPv4 netdev.

The script prints `PASS` and exits 0 on success, `FAIL` and exits
non-zero otherwise. On failure the criu dump/restore logs are tailed
to stderr.

## Drop-before-PR

This whole directory is checkpointed-validation scaffolding. It is
not intended to be part of the upstream submission. Delete the
directory in the final PR cleanup commit.
