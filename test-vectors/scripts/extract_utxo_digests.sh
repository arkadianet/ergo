#!/usr/bin/env bash
set -euo pipefail

# Extract UTXO state root digests from block headers.
#
# Usage: ./extract_utxo_digests.sh <start_height> <end_height> <output_file>
#
# For each height, fetches the block header and extracts the stateRoot field.
# stateRoot is the AVL+ tree digest of the UTXO set after applying that block.

NODE_URL="${NODE_URL:-http://localhost:9053}"

if [ $# -lt 3 ]; then
    echo "Usage: $0 <start_height> <end_height> <output_file>" >&2
    exit 1
fi

START_HEIGHT=$1
END_HEIGHT=$2
OUTPUT_FILE=$3

echo "Extracting UTXO digests from height $START_HEIGHT to $END_HEIGHT..." >&2

RESULTS="["
FIRST=true

for height in $(seq "$START_HEIGHT" "$END_HEIGHT"); do
    HEADER_IDS=$(curl -sf "${NODE_URL}/blocks/at/${height}")
    if [ -z "$HEADER_IDS" ] || [ "$HEADER_IDS" = "[]" ]; then
        continue
    fi

    HEADER_ID=$(echo "$HEADER_IDS" | jq -r '.[0]')
    HEADER_JSON=$(curl -sf "${NODE_URL}/blocks/${HEADER_ID}/header")
    if [ -z "$HEADER_JSON" ]; then
        echo "  Failed to fetch header at height $height" >&2
        continue
    fi

    STATE_ROOT=$(echo "$HEADER_JSON" | jq -r '.stateRoot')

    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        RESULTS="${RESULTS},"
    fi

    RESULTS="${RESULTS}
  {\"height\":${height},\"stateRoot\":\"${STATE_ROOT}\"}"

    echo "  height=$height stateRoot=${STATE_ROOT:0:16}..." >&2
done

RESULTS="${RESULTS}
]"

echo "$RESULTS" | jq '.' > "$OUTPUT_FILE"
echo "Wrote $(echo "$RESULTS" | jq 'length') UTXO digest vectors to $OUTPUT_FILE" >&2
