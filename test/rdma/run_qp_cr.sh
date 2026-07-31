#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# rxe QP strict round-trip dev gate. Same dump/restore flow as
# run_uverbs_cr.sh, but the holder additionally creates a PD, a CQ and an
# RC QP sharing that CQ (HOLDER_ALLOC_QP). The QP mmaps SQ + RQ rings off
# the cdev, so the dump captures a QP uobject (QUERY_QP: the drained
# rxe_restore_qp_req wire state incl. the ring vm_pgoffs, plus the
# parent-PD / send-CQ / recv-CQ xrefs) and restore drives
# UVERBS_METHOD_RESTORE_QP (master-side, re-registering both ring pending
# mmap slots) plus the plugin's UPDATE_VMA_MAP hook (remapping the SQ/RQ
# ring VMAs onto the restored ucontext-bearing cdev). The post-restore
# SIGUSR1 check ibv_query_qp's the QP (resolves it by handle, reads state
# from the kernel) then ibv_destroy_qp's it -- which fails unless the
# kernel QP was reinstalled at its original ufile handle and qpn.
#
# Usage:
#   sudo [CRIU=/path/to/criu] test/rdma/run_qp_cr.sh [<netdev>]
#
# Exits 0 on PASS, non-zero on FAIL.

set -euo pipefail

export HOLDER_ALLOC_QP=1
exec "$(cd "$(dirname "$0")" && pwd)/run_uverbs_cr.sh" "$@"
