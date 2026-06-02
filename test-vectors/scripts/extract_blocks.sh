#!/usr/bin/env bash
set -euo pipefail

# Extract full block vectors (header + transactions + extension) from a running Ergo node.
#
# Usage: ./extract_blocks.sh <start_height> <end_height> <output_file>
#
# For each block, emits the header ID, all transactions with canonical bytes,
# and the block extension fields.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCALA_CLI="${SCALA_CLI:-/home/rkadias/.cache/scalacli/local-repo/bin/scala-cli/scala-cli}"
NODE_URL="${NODE_URL:-http://localhost:9053}"
TX_HELPER="${SCRIPT_DIR}/scala/PrintTransactionBytes.scala"

if [ $# -lt 3 ]; then
    echo "Usage: $0 <start_height> <end_height> <output_file>" >&2
    exit 1
fi

START_HEIGHT=$1
END_HEIGHT=$2
OUTPUT_FILE=$3

echo "Warming up Scala helper..." >&2
echo '{}' | $SCALA_CLI run "$TX_HELPER" 2>/dev/null || true

echo "Extracting blocks from height $START_HEIGHT to $END_HEIGHT..." >&2

RESULTS="["
FIRST_BLOCK=true

for height in $(seq "$START_HEIGHT" "$END_HEIGHT"); do
    HEADER_IDS=$(curl -sf "${NODE_URL}/blocks/at/${height}")
    if [ -z "$HEADER_IDS" ] || [ "$HEADER_IDS" = "[]" ]; then
        continue
    fi

    HEADER_ID=$(echo "$HEADER_IDS" | jq -r '.[0]')

    # Fetch full block
    FULL_BLOCK=$(curl -sf "${NODE_URL}/blocks/${HEADER_ID}")
    if [ -z "$FULL_BLOCK" ]; then
        echo "  Failed to fetch block at height $height" >&2
        continue
    fi

    # Extract extension
    EXTENSION=$(echo "$FULL_BLOCK" | jq '{headerId: .extension.headerId, digest: .extension.digest, fields: .extension.fields}')

    # Extract transactions
    BLOCK_TXS=$(curl -sf "${NODE_URL}/blocks/${HEADER_ID}/transactions")
    NUM_TXS=$(echo "$BLOCK_TXS" | jq '.transactions | length')

    TX_ARRAY="["
    FIRST_TX=true
    for idx in $(seq 0 $(( NUM_TXS - 1 ))); do
        TX_JSON=$(echo "$BLOCK_TXS" | jq ".transactions[$idx]")
        TX_ID=$(echo "$TX_JSON" | jq -r '.id')

        SCALA_OUT=$(echo "$TX_JSON" | $SCALA_CLI run "$TX_HELPER" 2>/dev/null | grep -E '^[0-9a-f]' || echo "")
        if [ -z "$SCALA_OUT" ]; then
            echo "  Scala helper failed for tx $TX_ID at height $height" >&2
            TX_HEX=""
        else
            TX_HEX=$(echo "$SCALA_OUT" | awk '{print $1}')
        fi

        if [ "$FIRST_TX" = true ]; then
            FIRST_TX=false
        else
            TX_ARRAY="${TX_ARRAY},"
        fi
        TX_ARRAY="${TX_ARRAY}{\"id\":\"${TX_ID}\",\"bytes\":\"${TX_HEX}\"}"
    done
    TX_ARRAY="${TX_ARRAY}]"

    if [ "$FIRST_BLOCK" = true ]; then
        FIRST_BLOCK=false
    else
        RESULTS="${RESULTS},"
    fi

    RESULTS="${RESULTS}
  {\"headerId\":\"${HEADER_ID}\",\"height\":${height},\"transactions\":${TX_ARRAY},\"extension\":${EXTENSION}}"

    echo "  height=$height id=${HEADER_ID:0:16}... txs=$NUM_TXS" >&2
done

RESULTS="${RESULTS}
]"

echo "$RESULTS" | jq '.' > "$OUTPUT_FILE"
echo "Wrote $(echo "$RESULTS" | jq 'length') block vectors to $OUTPUT_FILE" >&2
