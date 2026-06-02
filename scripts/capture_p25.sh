#!/usr/bin/env bash
# Slice-2 P2.5 long capture (≥900 s).
#
# Reach the historical ~4.8 GB plateau under the new Phase-2.5
# instrumentation:
#   - boot-time + action-loop CSV samplers (mem_csv + smaps fields)
#   - init-step markers (mem_marker sidecar CSV)
#   - modifier-type-index back-fill counters (record_modifier_index_event)
#
# `ERGO_MEM_MAPS=1` enables the /proc/self/maps category summary on
# every marker row. Off by default (parse is O(N) over hundreds of
# mappings); on for this capture so we can attribute the plateau to
# heap / anon / redb / so / bin.
#
# Output:
#   logs/memory-resume-p25-<TS>.csv          — sampler rows
#   logs/memory-resume-p25-<TS>.markers.csv  — init-step markers
#   logs/node-resume-p25-<TS>.log            — node stderr/stdout
set -e
cd /home/rkadias/coding/arkadianet/node/ergo-rust-node
TS="$(date +%Y%m%d-%H%M%S)"
MEM_CSV="logs/memory-resume-p25-${TS}.csv"
NODE_LOG="logs/node-resume-p25-${TS}.log"
DURATION=900   # 900 s = 15 min, enough loop time to reach the plateau
mkdir -p logs
RUST_LOG=warn ERGO_MEM_CSV="${MEM_CSV}" ERGO_MEM_MAPS=1 \
  ./target/release/ergo-node \
  --data-dir ergo-data-cow \
  -c ergo-node/ergo-node.toml \
  > "${NODE_LOG}" 2>&1 &
NODE_PID=$!
echo "[capture_p25] node pid=${NODE_PID} csv=${MEM_CSV} log=${NODE_LOG}"
sleep "${DURATION}"
echo "[capture_p25] sending SIGTERM after ${DURATION}s"
kill -TERM "${NODE_PID}" 2>/dev/null || true
for _ in 1 2 3 4 5 6 7 8 9 10; do
  kill -0 "${NODE_PID}" 2>/dev/null || break
  sleep 1
done
kill -KILL "${NODE_PID}" 2>/dev/null || true
wait "${NODE_PID}" 2>/dev/null || true
echo "[capture_p25] done. csv=${MEM_CSV}"
