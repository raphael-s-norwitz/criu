# test/rdma -- internal validation, drop before upstream PR

Out-of-band validators for the criu RDMA work-in-progress. Used while
iterating on the rdma plugin framework before the work is mature
enough for a proper zdtm test.

## Files

- `uverbs_ctx_holder.c` -- minimal program that opens an rxe `ibv_context`
  (which implicitly creates an async-event fd inside the kernel context)
  and blocks on SIGTERM. SIGUSR1 re-queries the device and writes the
  result to a status file. Used to confirm the context is still
  functional after restore.
- `run_uverbs_cr.sh` -- brings up an `rxe0` link if needed, launches the
  holder, calls `criu dump` then `criu restore`, signals the restored
  process to verify its context still works.

## Run

```
make -C test/rdma
sudo CRIU=/usr/local/sbin/criu test/rdma/run_uverbs_cr.sh [<netdev>]
```

`<netdev>` defaults to the first up IPv4 netdev.

The script prints `PASS` and exits 0 on success, `FAIL` and exits
non-zero otherwise. On failure the criu dump/restore logs are tailed
to stderr.

## Drop-before-PR

This whole directory is checkpointed-validation scaffolding. It is
not intended to be part of the upstream submission. Delete the
directory in the final PR cleanup commit.
