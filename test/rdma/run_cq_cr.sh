#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# rxe CQ strict round-trip dev gate. Same dump/restore flow as
# run_uverbs_cr.sh, but the holder additionally creates a CQ
# (HOLDER_ALLOC_CQ), which mmaps a completion ring off the cdev. The
# dump captures a CQ uobject (QUERY_CQ: ring vm_pgoff + cursors +
# in-flight image) and restore drives UVERBS_METHOD_RESTORE_CQ
# (master-side, re-registering the ring's pending mmap slot) plus the
# plugin's UPDATE_VMA_MAP hook (remapping the ring VMA onto the restored
# ucontext-bearing cdev). The post-restore SIGUSR1 check ibv_poll_cq's
# the CQ -- which dereferences the mmap'd ring, so a botched remap
# faults -- then ibv_destroy_cq's it, which fails unless the kernel CQ
# was reinstalled at its original ufile handle.
#
# Usage:
#   sudo [CRIU=/path/to/criu] test/rdma/run_cq_cr.sh [<netdev>]
#
# Exits 0 on PASS, non-zero on FAIL.

set -euo pipefail

export HOLDER_ALLOC_CQ=1
exec "$(cd "$(dirname "$0")" && pwd)/run_uverbs_cr.sh" "$@"
