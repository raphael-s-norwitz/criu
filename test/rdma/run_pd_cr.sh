#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# rxe PD strict round-trip dev gate. Same dump/restore flow as
# run_uverbs_cr.sh, but the holder additionally allocates a PD
# (HOLDER_ALLOC_PD) so the dump captures a PD uobject and restore
# drives UVERBS_METHOD_RESTORE_PD. The post-restore SIGUSR1 check
# registers + deregisters an MR against the restored PD, which fails
# unless the kernel PD was reinstalled at its original ufile handle.
#
# Usage:
#   sudo [CRIU=/path/to/criu] test/rdma/run_pd_cr.sh [<netdev>]
#
# Exits 0 on PASS, non-zero on FAIL.

set -euo pipefail

export HOLDER_ALLOC_PD=1
exec "$(cd "$(dirname "$0")" && pwd)/run_uverbs_cr.sh" "$@"
