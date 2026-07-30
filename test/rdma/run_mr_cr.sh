#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# rxe MR strict round-trip dev gate. Same dump/restore flow as
# run_uverbs_cr.sh, but the holder additionally allocates a PD and
# registers a persistent MR over a known-pattern buffer (HOLDER_ALLOC_MR)
# so the dump captures an MR uobject and restore drives
# UVERBS_METHOD_RESTORE_MR from the pie restorer (after the buffer VMA is
# laid out at its original VA). The post-restore SIGUSR1 check verifies
# the buffer content survived and deregisters the MR, which fails unless
# the kernel MR was reinstalled at its original ufile handle. Byte-
# identical lkey/rkey are asserted kernel-side by the pie (RESP==hint).
#
# Usage:
#   sudo [CRIU=/path/to/criu] test/rdma/run_mr_cr.sh [<netdev>]
#
# Exits 0 on PASS, non-zero on FAIL.

set -euo pipefail

export HOLDER_ALLOC_MR=1
exec "$(cd "$(dirname "$0")" && pwd)/run_uverbs_cr.sh" "$@"
