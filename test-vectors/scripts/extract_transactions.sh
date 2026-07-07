#!/usr/bin/env bash
set -euo pipefail

# Extract canonical transaction serialization vectors from a running Ergo node.
#
# Usage: ./extract_transactions.sh <start_height> <end_height> <output_file>
# Example: ./extract_transactions.sh 1 10 ../mainnet/transactions_1_10.json
#
# Extracts all transactions from blocks in the given height range.
# For each transaction, emits canonical signed-tx bytes and bytes_to_sign.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCALA_CLI="${SCALA_CLI:-$HOME/.cache/scalacli/local-repo/bin/scala-cli/scala-cli}"
NODE_URL="${NODE_URL:-http://localhost:9053}"
SCALA_HELPER="${SCRIPT_DIR}/scala/PrintTransactionBytes.scala"

if [ $# -lt 3 ]; then
    echo "Usage: $0 <start_height> <end_height> <output_file>" >&2
    exit 1
fi

START_HEIGHT=$1
END_HEIGHT=$2
OUTPUT_FILE=$3

echo "Warming up Scala helper..." >&2
echo '{}' | $SCALA_CLI run "$SCALA_HELPER" 2>/dev/null || true

echo "Extracting transactions from height $START_HEIGHT to $END_HEIGHT..." >&2

RESULTS="["
FIRST=true

for height in $(seq "$START_HEIGHT" "$END_HEIGHT"); do
    HEADER_IDS=$(curl -sf "${NODE_URL}/blocks/at/${height}")
    if [ -z "$HEADER_IDS" ] || [ "$HEADER_IDS" = "[]" ]; then
        continue
    fi

    HEADER_ID=$(echo "$HEADER_IDS" | jq -r '.[0]')
    BLOCK_TXS=$(curl -sf "${NODE_URL}/blocks/${HEADER_ID}/transactions")
    if [ -z "$BLOCK_TXS" ]; then
        echo "  Failed to fetch transactions for block at height $height" >&2
        continue
    fi

    NUM_TXS=$(echo "$BLOCK_TXS" | jq '.transactions | length')
    for idx in $(seq 0 $(( NUM_TXS - 1 ))); do
        TX_JSON=$(echo "$BLOCK_TXS" | jq ".transactions[$idx]")
        TX_ID=$(echo "$TX_JSON" | jq -r '.id')

        SCALA_OUT=$(echo "$TX_JSON" | $SCALA_CLI run "$SCALA_HELPER" 2>/dev/null | grep -E '^[0-9a-f]')
        if [ -z "$SCALA_OUT" ]; then
            echo "  Scala helper failed for tx $TX_ID at height $height" >&2
            continue
        fi

        TX_HEX=$(echo "$SCALA_OUT" | awk '{print $1}')
        BTS_HEX=$(echo "$SCALA_OUT" | awk '{print $2}')

        if [ "$FIRST" = true ]; then
            FIRST=false
        else
            RESULTS="${RESULTS},"
        fi

        RESULTS="${RESULTS}
  {\"id\":\"${TX_ID}\",\"bytes\":\"${TX_HEX}\",\"bytesToSign\":\"${BTS_HEX}\",\"height\":${height}}"

        echo "  height=$height tx[$idx] id=${TX_ID:0:16}... bytes=${#TX_HEX} bts=${#BTS_HEX}" >&2
    done
done

RESULTS="${RESULTS}
]"

echo "$RESULTS" | jq '.' > "$OUTPUT_FILE"
echo "Wrote $(echo "$RESULTS" | jq 'length') transaction vectors to $OUTPUT_FILE" >&2
