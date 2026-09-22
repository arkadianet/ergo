#!/usr/bin/env bash
# Run M3 campaign scenarios detached, with a trap that stops the devnet.
#
# A scenario runs for tens of minutes and the operator's shell will not
# be there for all of it, so the whole thing is backgrounded and logged.
# The trap matters more than the backgrounding: an interrupted run that
# left a JVM miner and a follower holding 19570-19572 would block every
# later attempt and go on mining on this host indefinitely.
#
#   scripts/devnet-matrix/run-campaign.sh steady fork ...
#
# Environment:
#   MATRIX_CLASSPATH  the pinned weak-blocks build (required; the
#                     provisioned copy may live in a sibling worktree)
#   RUST_NODE         the follower binary (defaults to this checkout's
#                     release build)
#   CAMPAIGN_TIMEOUT  override the per-scenario polling budget, seconds
#                     (by default each scenario gets the budget below,
#                     sized from the measured ~40 s per ordering block on
#                     this recipe's difficulty plus the miner's F11
#                     stalls; a scenario that runs short REPORTS the
#                     shortfall rather than passing on a window that
#                     never opened)
set -uo pipefail
cd "$(dirname "$0")/../.."

WORK="scripts/devnet-matrix/.work"
LOG="$WORK/campaign/run.log"
mkdir -p "$WORK/campaign"

cleanup() {
  echo "[run-campaign] stopping the devnet ($(date -Is))" >>"$LOG"
  python3 scripts/devnet-matrix/lifecycle.py stop >>"$LOG" 2>&1 || true
}
trap cleanup EXIT INT TERM

budget() {
  case "$1" in
    steady)           echo 6000 ;;   # 60 ordering blocks + the funded workload
    reconstruct_rate) echo 9000 ;;   # 100 ordering blocks
    fork|rollback)    echo 6000 ;;   # two miners, and a private branch to overtake
    flood)            echo 3600 ;;
    *)                echo 2400 ;;   # restart, evict: a handful of blocks each
  esac
}

status=0
for scenario in "$@"; do
  timeout_s="${CAMPAIGN_TIMEOUT:-$(budget "$scenario")}"
  echo "[run-campaign] === $scenario timeout=${timeout_s}s ($(date -Is)) ===" >>"$LOG"
  python3 scripts/devnet-matrix/campaign.py --scenario "$scenario" \
      --timeout "$timeout_s" --fresh >>"$LOG" 2>&1 || status=1
  echo "[run-campaign] $scenario finished rc=$? ($(date -Is))" >>"$LOG"
  # Between scenarios the ports must be free: each one starts its own
  # nodes, and a leftover process would fail the next bind with a
  # message about the port rather than about the scenario.
  MATRIX_NODES=scala,scala2,rust \
    MATRIX_P2P_SCALA=19570 MATRIX_P2P_SCALA2=19571 MATRIX_P2P_RUST=19572 \
    MATRIX_REST_SCALA=19590 MATRIX_REST_SCALA2=19591 MATRIX_REST_RUST=19592 \
    python3 scripts/devnet-matrix/lifecycle.py stop >>"$LOG" 2>&1 || true
done
echo "[run-campaign] all done status=$status ($(date -Is))" >>"$LOG"
exit "$status"
