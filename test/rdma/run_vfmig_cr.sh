#!/usr/bin/env bash
#
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# End-to-end CRIU dump+restore of an mlx5_sriov_vfmig holder process,
# exercising the full plugin pipeline:
#
#   Dump path:
#     1. uverbs_ctx_holder opens an ibv_context against the VF ibdev,
#        allocates a PD, and waits.
#     2. criu dump triggers the mlx5_sriov_vfmig plugin:
#          - DUMP_UVERBS_CONTEXT snapshots the ucontext via the
#            new dyn-UAR verbs (libmlx5 default lib_uar_dyn=true) and
#            queues a per-VF SAVE.
#          - HANDLE_DEVICE_VMA persists the UAR mappings.
#          - fini(DUMP) drains the queue: SAVE_VHCA_STATE per VF +
#            mlx5_vfmig.img with one entry per ucontext.
#
#   Restore path:
#     3. Orchestrator tears down the source VF (sriov_numvfs=0) and
#        reprovisions a fresh "destination" VF with set_tracked=1,
#        but does NOT bind mlx5_core -- the plugin's init(RESTORE)
#        does LOAD_VHCA_STATE, driver_override+bind, then opens the
#        destination uverbs cdev with VFMIG_RESTORE | DYN_UAR and
#        replays the dyn-UAR records.
#     4. UPDATE_VMA_MAP hands the workload a dup of the dest cdev fd
#        with the source's pgoff verbatim.
#     5. SIGUSR1 to the restored holder -> ibv_query_device +
#        ibv_alloc_pd checks.
#
# Usage:
#   sudo PF=0000:08:00.0 ./run_vfmig_cr.sh
#
# Exits 0 on PASS, non-zero on FAIL with a tail of dump/restore logs.

set -euo pipefail

PF="${PF:-0000:08:00.0}"
CRIU="${CRIU:-/usr/local/sbin/criu}"
VFMIG_TOOL="${VFMIG_TOOL:-/opt/builds/linux/tools/testing/mlx5_vfmig/mlx5_vfmig}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PROG="$HERE/uverbs_ctx_holder"
WORKDIR="$(mktemp -d /tmp/vfmig-cr-XXXXXX)"
PIDFILE="$WORKDIR/holder.pid"
RESTORED_PIDFILE="$WORKDIR/restored.pid"
STATUS="$WORKDIR/status"
LOG="$WORKDIR/holder.log"
DUMPDIR="$WORKDIR/img"

SRIOV_NUMVFS="/sys/bus/pci/devices/$PF/sriov_numvfs"

cleanup() {
    local pid
    for pid in "$PIDFILE" "$RESTORED_PIDFILE"; do
        [[ -f "$pid" ]] || continue
        local p
        p="$(cat "$pid" 2>/dev/null || true)"
        [[ -n "$p" ]] || continue
        kill -KILL "$p" 2>/dev/null || true
    done
    echo "(workdir preserved at $WORKDIR for triage)"
}
trap cleanup EXIT

[[ "$EUID" -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
[[ -x "$PROG" ]]    || { echo "missing $PROG -- 'make -C $HERE'" >&2; exit 1; }
[[ -x "$CRIU" ]]    || { echo "missing $CRIU" >&2; exit 1; }
[[ -x "$VFMIG_TOOL" ]] || { echo "missing $VFMIG_TOOL" >&2; exit 1; }

vf_path() { echo "/sys/bus/pci/devices/$1"; }

resolve_vf_ibdev() {
    local pf=$1 vf_id=$2 vf_bdf
    vf_bdf="$(readlink "$pf/virtfn$vf_id" | xargs basename)"
    for ib in /sys/class/infiniband/*; do
        local target
        target="$(readlink "$ib/device" | xargs basename)"
        [[ "$target" == "$vf_bdf" ]] && { basename "$ib"; return; }
    done
    return 1
}

provision_vf() {
    local label=$1
    echo "=== $label: provision VF ==="
    echo 0 >"$SRIOV_NUMVFS"
    echo 0 | tee "/sys/bus/pci/devices/$PF/sriov_drivers_autoprobe" >/dev/null
    echo 1 >"$SRIOV_NUMVFS"
    "$VFMIG_TOOL" "$PF" set_tracked 0 1
    "$VFMIG_TOOL" "$PF" enable_migratable 0
    local vf_bdf
    vf_bdf="$(readlink "/sys/bus/pci/devices/$PF/virtfn0" | xargs basename)"
    echo mlx5_core >"/sys/bus/pci/devices/$vf_bdf/driver_override"
    echo "$vf_bdf" >/sys/bus/pci/drivers/mlx5_core/bind
    # Wait for ibdev to appear.
    local ib
    for _ in $(seq 1 60); do
        ib="$(resolve_vf_ibdev "$(vf_path "$PF")" 0 || true)"
        [[ -n "$ib" ]] && break
        sleep 0.5
    done
    [[ -n "$ib" ]] || { echo "FAIL: VF ibdev did not appear" >&2; exit 1; }
    echo "VF ibdev: $ib (vf_bdf=$vf_bdf)"
    "$VFMIG_TOOL" "$PF" query_vf 0
    VF_IBDEV="$ib"
    VF_BDF="$vf_bdf"
}

reprovision_vf_for_restore() {
    echo "=== Phase D: tear down source VF ==="
    echo 0 >"$SRIOV_NUMVFS"
    sleep 0.5
    echo "=== Phase E: provision destination VF (no bind -- plugin handles it) ==="
    echo 1 >"$SRIOV_NUMVFS"
    "$VFMIG_TOOL" "$PF" set_tracked 0 1
    # Plugin's init(RESTORE) does enable_migratable + driver_override + bind.
    local vf_bdf
    vf_bdf="$(readlink "/sys/bus/pci/devices/$PF/virtfn0" | xargs basename)"
    VF_BDF_DEST="$vf_bdf"
    "$VFMIG_TOOL" "$PF" query_vf 0
    echo "destination VF prepared: $vf_bdf (no driver bound)"
}

# ---- Phase A: source VF provisioning ----------------------------------
provision_vf "Phase A"

# ---- Phase B: launch holder -------------------------------------------
echo "=== Phase B: launch uverbs_ctx_holder against $VF_IBDEV ==="
# systemd-run --scope to avoid inheriting the agent's unix sockets/fds.
systemd-run --scope --quiet --unit="vfmig-holder-$$" \
    bash -c "exec </dev/null >'$LOG' 2>&1; '$PROG' '$VF_IBDEV' '$STATUS'" &
SCOPE_PID=$!
# Find the actual holder pid (child of the scope).
HOLDER_PID=
for _ in $(seq 1 50); do
    HOLDER_PID="$(pgrep -fx "$PROG $VF_IBDEV $STATUS" || true)"
    [[ -n "$HOLDER_PID" ]] && break
    sleep 0.1
done
[[ -n "$HOLDER_PID" ]] || { echo "FAIL: holder did not start" >&2; cat "$LOG" >&2; exit 1; }
echo "$HOLDER_PID" >"$PIDFILE"
for _ in $(seq 1 50); do
    [[ -s "$STATUS" ]] && break
    sleep 0.1
done
[[ "$(cat "$STATUS")" == "READY" ]] || {
    echo "FAIL: holder status=$(cat "$STATUS"):" >&2
    cat "$LOG" >&2
    exit 1
}
echo "holder ready (pid=$HOLDER_PID)"
grep -E '^READY ' "$LOG" || true

# ---- Phase C: criu dump -----------------------------------------------
mkdir -p "$DUMPDIR"
echo "=== Phase C: criu dump ==="
echo "criu dump -t $HOLDER_PID -D $DUMPDIR -v4"
"$CRIU" dump -t "$HOLDER_PID" -D "$DUMPDIR" -v4 -o dump.log --shell-job || {
    echo "FAIL: criu dump returned $?"
    echo "--- dump log tail ---"
    tail -120 "$DUMPDIR/dump.log" || true
    exit 1
}
if kill -0 "$HOLDER_PID" 2>/dev/null; then
    echo "BUG: holder still alive after dump" >&2
    exit 1
fi
echo "dump OK; image dir contents:"
ls -la "$DUMPDIR" | sed 's/^/  /'

# ---- Phase D + E: teardown + reprovision ------------------------------
reprovision_vf_for_restore

# ---- Phase F: criu restore --------------------------------------------
echo "=== Phase F: criu restore ==="
"$CRIU" restore -D "$DUMPDIR" -v4 -o restore.log -d \
    --pidfile "$RESTORED_PIDFILE" --shell-job || {
    echo "FAIL: criu restore returned $?"
    echo "--- restore log tail ---"
    tail -120 "$DUMPDIR/restore.log" || true
    exit 1
}
RESTORED_PID="$(cat "$RESTORED_PIDFILE")"
echo "restored pid=$RESTORED_PID"

# ---- Phase G: verify --------------------------------------------------
echo "=== Phase G: post-restore checks ==="
echo "WAITING" >"$STATUS"
kill -USR1 "$RESTORED_PID"
for _ in $(seq 1 50); do
    cur="$(cat "$STATUS" 2>/dev/null || true)"
    [[ "$cur" != "WAITING" ]] && break
    sleep 0.1
done
RESULT="$(cat "$STATUS" 2>/dev/null || true)"
echo "post-restore status: $RESULT"

if [[ "$RESULT" == "OK" ]]; then
    kill -TERM "$RESTORED_PID" 2>/dev/null || true
    echo "PASS"
    exit 0
fi

echo "FAIL ($RESULT)"
case "$RESULT" in
"FAIL: ibv_dealloc_pd of pre-dump PD"*)
    echo "(known PD-uobject preservation gap; not a regression)" >&2
    ;;
esac
echo "--- dump log tail ---" >&2
tail -120 "$DUMPDIR/dump.log" >&2 || true
echo "--- restore log tail ---" >&2
tail -120 "$DUMPDIR/restore.log" >&2 || true
exit 1
