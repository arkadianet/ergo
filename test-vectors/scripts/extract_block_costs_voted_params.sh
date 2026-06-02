#!/usr/bin/env bash
set -euo pipefail

# Voted-parameters Phase 2e cost-parity corpus extractor.
#
# Runs the Scala oracle (ComputeTransactionCosts.scala) against a live node
# with extraIndex enabled and produces a JSON corpus of per-tx block costs.
#
# Output format: JSON array of {tx_id, height, block_cost} records.
#   Only passing transactions are included (~50% at 700k range; DEX/oracle-pool
#   contracts that call error() are excluded with a stderr warning).
#
# Usage:
#   NODE_URL=http://localhost:9053 \
#   ./extract_block_costs_voted_params.sh <start_height> <end_height> [output_file]
#
# Default output: test-vectors/mainnet/tx_costs_<start>_<end>.json
#
# The Scala oracle (ComputeTransactionCosts.scala) handles:
#   - Seeding params from the most recent epoch-start extension (correct
#     activatedScriptVersion, maxBlockCost, and all cost constants)
#   - Refreshing params at each epoch boundary
#   - Using the previous block's stateRoot as lastBlockUtxoRoot
#
# Remaining approximations in the oracle (documented limitations):
#   - CONTEXT.headers = empty (scripts that index CONTEXT.headers may differ)
#   - ValidationRules = current (sigma validation settings; stable on mainnet)
#
# Path (a) POST /transactions/check: unavailable for historical txs — the node
# rejects them because their inputs are no longer in the UTXO set (verified
# 2026-04-28).

START="${1:?start height required}"
END="${2:?end height required}"
DEFAULT_OUT="$(dirname "$0")/../mainnet/tx_costs_${START}_${END}.json"
OUTPUT="${3:-$DEFAULT_OUT}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCALA_ORACLE="$SCRIPT_DIR/scala/ComputeTransactionCosts.scala"

if [ ! -f "$SCALA_ORACLE" ]; then
  echo "ERROR: Scala oracle not found: $SCALA_ORACLE" >&2
  exit 1
fi

if ! command -v scala-cli &>/dev/null; then
  echo "ERROR: scala-cli not found in PATH" >&2
  exit 1
fi

NODE_URL="${NODE_URL:-http://localhost:9053}"
mkdir -p "$(dirname "$OUTPUT")"

echo "[extract] Running Scala oracle for h=$START..$END → $OUTPUT" >&2
echo "[extract] NODE_URL=$NODE_URL" >&2

NODE_URL="$NODE_URL" scala-cli run "$SCALA_ORACLE" -- "$START" "$END" > "$OUTPUT"

RECORD_COUNT=$(python3 -c "import json; d=json.load(open('$OUTPUT')); print(len(d))" 2>/dev/null || echo "?")
echo "[extract] done: $RECORD_COUNT records written to $OUTPUT" >&2
