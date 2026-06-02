#!/usr/bin/env bash
set -euo pipefail

# Extract bytes_to_sign for transactions from a given transactions vector file.
#
# Usage: ./extract_bytes_to_sign.sh <transactions_json> <output_file>
#
# Reads a transactions vector file (output of extract_transactions.sh),
# passes each tx's bytes through PrintBytesToSign.scala to independently
# verify the bytes_to_sign field.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCALA_CLI="${SCALA_CLI:-/home/rkadias/.cache/scalacli/local-repo/bin/scala-cli/scala-cli}"
SCALA_HELPER="${SCRIPT_DIR}/scala/PrintBytesToSign.scala"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <transactions_json> <output_file>" >&2
    exit 1
fi

INPUT_FILE=$1
OUTPUT_FILE=$2

echo "Warming up Scala helper..." >&2
echo "00" | $SCALA_CLI run "$SCALA_HELPER" 2>/dev/null || true

NUM_TXS=$(jq 'length' "$INPUT_FILE")
echo "Verifying bytes_to_sign for $NUM_TXS transactions..." >&2

RESULTS="["
FIRST=true
MATCHES=0
MISMATCHES=0

for idx in $(seq 0 $(( NUM_TXS - 1 ))); do
    TX_ID=$(jq -r ".[$idx].id" "$INPUT_FILE")
    TX_BYTES=$(jq -r ".[$idx].bytes" "$INPUT_FILE")
    EXPECTED_BTS=$(jq -r ".[$idx].bytesToSign" "$INPUT_FILE")

    ACTUAL_BTS=$(echo "$TX_BYTES" | $SCALA_CLI run "$SCALA_HELPER" 2>/dev/null | grep -E '^[0-9a-f]' || echo "FAILED")

    if [ "$ACTUAL_BTS" = "$EXPECTED_BTS" ]; then
        MATCHES=$((MATCHES + 1))
        STATUS="match"
    else
        MISMATCHES=$((MISMATCHES + 1))
        STATUS="MISMATCH"
        echo "  MISMATCH: tx=$TX_ID" >&2
    fi

    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        RESULTS="${RESULTS},"
    fi

    RESULTS="${RESULTS}
  {\"id\":\"${TX_ID}\",\"bytesToSign\":\"${ACTUAL_BTS}\",\"status\":\"${STATUS}\"}"

    echo "  tx[$idx] id=${TX_ID:0:16}... $STATUS" >&2
done

RESULTS="${RESULTS}
]"

echo "$RESULTS" | jq '.' > "$OUTPUT_FILE"
echo "Results: $MATCHES matches, $MISMATCHES mismatches" >&2
