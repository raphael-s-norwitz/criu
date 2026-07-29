# test/rdma -- internal validation, drop before upstream PR

Out-of-band validators for the criu RDMA work-in-progress. Used while
iterating on the rdma plugin framework before the work is mature
enough for a proper zdtm test.

## Files

- `uverbs_ctx_holder.c` -- minimal program that opens an rxe `ibv_context`
  (which implicitly creates an async-event fd inside the kernel context)
  and blocks on SIGTERM. If `HOLDER_ALLOC_PD` is set it also allocates a
  PD. SIGUSR1 re-queries the device (and, when a PD exists, registers +
  deregisters a small MR against it) and writes the result to a status
  file. Used to confirm the context / PD are still functional after
  restore.
- `run_uverbs_cr.sh` -- brings up an `rxe0` link if needed, launches the
  holder, calls `criu dump` then `criu restore`, signals the restored
  process to verify its context still works.
- `run_pd_cr.sh` -- thin wrapper over `run_uverbs_cr.sh` that sets
  `HOLDER_ALLOC_PD=1`, exercising the rxe `RESTORE_PD` path: the dump
  captures a PD uobject and restore reinstalls it at its ufile handle,
  which the post-restore `reg_mr` check then proves is live.

## Run

```
make -C test/rdma
# bare context + async-event fd:
sudo CRIU=/usr/local/sbin/criu test/rdma/run_uverbs_cr.sh [<netdev>]
# same, plus a PD round-trip (RESTORE_PD dev gate):
sudo CRIU=/usr/local/sbin/criu test/rdma/run_pd_cr.sh [<netdev>]
```

`<netdev>` defaults to the first up IPv4 netdev.

The script prints `PASS` and exits 0 on success, `FAIL` and exits
non-zero otherwise. On failure the criu dump/restore logs are tailed
to stderr.

## Drop-before-PR

This whole directory is checkpointed-validation scaffolding. It is
not intended to be part of the upstream submission. Delete the
directory in the final PR cleanup commit.
