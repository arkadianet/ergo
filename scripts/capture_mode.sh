#!/usr/bin/env bash
# Generic memory capture for the post-P3.1 scoreboard.
#
# Usage: scripts/capture_mode.sh <mode-tag> <config-path> <duration-seconds> [extra ergo-node args...]
#
#   <mode-tag>     short label embedded in output filenames, e.g. "mode2", "mode4"
#   <config-path>  TOML file passed via -c (selects indexer on/off, etc.)
#   <duration-s>   capture wallclock seconds before SIGTERM
#   [extra args]   forwarded verbatim to ergo-node (e.g. --cache-bytes 268435456)
#
# Always reads from ergo-data-cow (so it doesn't conflict with whatever
# is currently running against ./ergo-data) and emits:
#   logs/memory-<mode-tag>-<TS>.csv          — sampler rows
#   logs/memory-<mode-tag>-<TS>.markers.csv  — init-step markers
#   logs/node-<mode-tag>-<TS>.log            — node stdout/stderr
set -e
cd /home/rkadias/coding/arkadianet/node/ergo-rust-node

if [ "$#" -lt 3 ]; then
  echo "usage: $0 <mode-tag> <config-path> <duration-seconds> [extra ergo-node args...]" >&2
  exit 2
fi

TAG="$1"
CONFIG="$2"
DURATION="$3"
shift 3
EXTRA_ARGS=("$@")

TS="$(date +%Y%m%d-%H%M%S)"
MEM_CSV="logs/memory-${TAG}-${TS}.csv"
NODE_LOG="logs/node-${TAG}-${TS}.log"
mkdir -p logs

RUST_LOG=warn ERGO_MEM_CSV="${MEM_CSV}" ERGO_MEM_MAPS=1 \
  ./target/release/ergo-node \
  --data-dir ergo-data-cow \
  -c "${CONFIG}" \
  "${EXTRA_ARGS[@]}" \
  > "${NODE_LOG}" 2>&1 &
NODE_PID=$!
echo "[capture_mode ${TAG}] node pid=${NODE_PID} csv=${MEM_CSV} log=${NODE_LOG}"
sleep "${DURATION}"
echo "[capture_mode ${TAG}] sending SIGTERM after ${DURATION}s"
kill -TERM "${NODE_PID}" 2>/dev/null || true
for _ in 1 2 3 4 5 6 7 8 9 10; do
  kill -0 "${NODE_PID}" 2>/dev/null || break
  sleep 1
done
kill -KILL "${NODE_PID}" 2>/dev/null || true
wait "${NODE_PID}" 2>/dev/null || true
echo "[capture_mode ${TAG}] done. csv=${MEM_CSV} log=${NODE_LOG}"
