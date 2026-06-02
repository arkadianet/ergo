#!/usr/bin/env bash
set -euo pipefail

# Extract per-transaction costs using the Scala sigmastate-interpreter.
# Produces a JSON test vector for differential comparison against Rust.
#
# Requires: scala-cli, running Ergo node with extraIndex enabled.
#
# Usage: ./extract_tx_costs.sh [start_height] [end_height] [output_file]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCALA_CLI="${SCALA_CLI:-/home/rkadias/.cache/scalacli/local-repo/bin/scala-cli/scala-cli}"
SCALA_SCRIPT="${SCRIPT_DIR}/scala/ComputeTransactionCosts.scala"

START_HEIGHT="${1:-700000}"
END_HEIGHT="${2:-700200}"
OUTPUT_FILE="${3:-${SCRIPT_DIR}/../mainnet/tx_costs_${START_HEIGHT}_${END_HEIGHT}.json}"

echo "Compiling Scala cost extraction script..." >&2
$SCALA_CLI compile "$SCALA_SCRIPT" 2>/dev/null

echo "Extracting costs for heights $START_HEIGHT to $END_HEIGHT..." >&2
echo "Node: ${NODE_URL:-http://localhost:9053}" >&2
echo "" >&2

$SCALA_CLI run "$SCALA_SCRIPT" -- "$START_HEIGHT" "$END_HEIGHT" > "$OUTPUT_FILE" 2>/tmp/cost_extract_stderr.txt

cat /tmp/cost_extract_stderr.txt >&2

TX_COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT_FILE'))))" 2>/dev/null || echo "?")

echo "" >&2
echo "=== Cost Extraction Complete ===" >&2
echo "  Output:  $OUTPUT_FILE ($TX_COUNT entries)" >&2
