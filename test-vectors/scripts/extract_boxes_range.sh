#!/usr/bin/env bash
set -euo pipefail

# Extract box serialization vectors from a range of block heights.
#
# Usage: ./extract_boxes_range.sh <start_height> <end_height> <output_file>
#
# Collects box IDs from outputs of all blocks in the range, then fetches
# canonical bytes from /utxo/byIdBinary/{boxId}. Only unspent boxes succeed.

NODE_URL="${NODE_URL:-http://localhost:9053}"

if [ $# -lt 3 ]; then
    echo "Usage: $0 <start_height> <end_height> <output_file>" >&2
    exit 1
fi

START_HEIGHT=$1
END_HEIGHT=$2
OUTPUT_FILE=$3

echo "Collecting box IDs from heights $START_HEIGHT to $END_HEIGHT..." >&2

RESULTS="["
FIRST=true
FOUND=0
SKIPPED=0

for height in $(seq "$START_HEIGHT" "$END_HEIGHT"); do
    HEADER_IDS=$(curl -sf "${NODE_URL}/blocks/at/${height}")
    if [ -z "$HEADER_IDS" ] || [ "$HEADER_IDS" = "[]" ]; then
        continue
    fi

    HEADER_ID=$(echo "$HEADER_IDS" | jq -r '.[0]')
    BOX_IDS=$(curl -sf "${NODE_URL}/blocks/${HEADER_ID}/transactions" | jq -r '.transactions[].outputs[].boxId' 2>/dev/null || echo "")

    while IFS= read -r BOX_ID; do
        [ -z "$BOX_ID" ] && continue

        RESPONSE=$(curl -sf "${NODE_URL}/utxo/byIdBinary/${BOX_ID}" 2>/dev/null || echo "")
        if [ -z "$RESPONSE" ] || echo "$RESPONSE" | jq -e '.error' >/dev/null 2>&1; then
            SKIPPED=$((SKIPPED + 1))
            continue
        fi

        BOX_BYTES=$(echo "$RESPONSE" | jq -r '.bytes')
        if [ -z "$BOX_BYTES" ] || [ "$BOX_BYTES" = "null" ]; then
            SKIPPED=$((SKIPPED + 1))
            continue
        fi

        BOX_JSON=$(curl -sf "${NODE_URL}/utxo/byId/${BOX_ID}" 2>/dev/null || echo "")
        ERGO_TREE=""
        if [ -n "$BOX_JSON" ] && ! echo "$BOX_JSON" | jq -e '.error' >/dev/null 2>&1; then
            ERGO_TREE=$(echo "$BOX_JSON" | jq -r '.ergoTree // empty')
        fi

        if [ "$FIRST" = true ]; then
            FIRST=false
        else
            RESULTS="${RESULTS},"
        fi

        RESULTS="${RESULTS}
  {\"boxId\":\"${BOX_ID}\",\"bytes\":\"${BOX_BYTES}\",\"ergoTree\":\"${ERGO_TREE}\",\"height\":${height}}"

        FOUND=$((FOUND + 1))
        echo "  height=$height boxId=${BOX_ID:0:16}... bytes=${#BOX_BYTES} chars" >&2
    done <<< "$BOX_IDS"
done

RESULTS="${RESULTS}
]"

echo "$RESULTS" | jq '.' > "$OUTPUT_FILE"
echo "Wrote $FOUND box vectors to $OUTPUT_FILE ($SKIPPED skipped/spent)" >&2
