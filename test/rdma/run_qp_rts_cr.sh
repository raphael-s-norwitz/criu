#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# rxe connected-QP round-trip dev gate. Same flow as run_qp_cr.sh, but the
# holder additionally drives the QP to RTS as a self-loop RC connection
# (HOLDER_QP_CONNECT). No work is posted, so the SQ/RQ rings stay empty,
# but an RC QP at RTS with max_dest_rd_atomic > 0 allocates a
# responder-resources table -- so the dump captures a non-zero
# res_image_bytes and restore must round-trip the QUERY_QP responder
# image through the RESTORE_QP UHW_IN tail. This is the connected (but
# quiesced) case a drained-only restore rejects with -EOPNOTSUPP.
#
# Usage:
#   sudo [CRIU=/path/to/criu] test/rdma/run_qp_rts_cr.sh [<netdev>]
#
# Exits 0 on PASS, non-zero on FAIL.

set -euo pipefail

export HOLDER_ALLOC_QP=1
export HOLDER_QP_CONNECT=1
exec "$(cd "$(dirname "$0")" && pwd)/run_uverbs_cr.sh" "$@"
