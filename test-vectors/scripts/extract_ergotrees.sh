#!/usr/bin/env bash
set -euo pipefail

# Extract ErgoTree byte vectors from blocks at given heights.
#
# Usage: ./extract_ergotrees.sh <start_height> <end_height> <output_file>
#
# Collects all unique ErgoTree hex strings from transaction outputs
# in the given height range.

NODE_URL="${NODE_URL:-http://localhost:9053}"

if [ $# -lt 3 ]; then
    echo "Usage: $0 <start_height> <end_height> <output_file>" >&2
    exit 1
fi

START_HEIGHT=$1
END_HEIGHT=$2
OUTPUT_FILE=$3

echo "Extracting ErgoTrees from height $START_HEIGHT to $END_HEIGHT..." >&2

# Collect unique ergoTree hex strings with a source label
declare -A SEEN_TREES

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
        continue
    fi

    # Extract all ergoTree values from outputs
    TREES=$(echo "$BLOCK_TXS" | jq -r '.transactions[].outputs[].ergoTree')

    while IFS= read -r TREE_HEX; do
        [ -z "$TREE_HEX" ] && continue

        # Deduplicate
        if [ -n "${SEEN_TREES[$TREE_HEX]+x}" ]; then
            continue
        fi
        SEEN_TREES[$TREE_HEX]=1

        if [ "$FIRST" = true ]; then
            FIRST=false
        else
            RESULTS="${RESULTS},"
        fi

        RESULTS="${RESULTS}
  {\"source\":\"height_${height}\",\"bytes\":\"${TREE_HEX}\"}"

        echo "  height=$height tree=${TREE_HEX:0:32}... (${#TREE_HEX} chars)" >&2
    done <<< "$TREES"
done

RESULTS="${RESULTS}
]"

echo "$RESULTS" | jq '.' > "$OUTPUT_FILE"
echo "Wrote $(echo "$RESULTS" | jq 'length') ErgoTree vectors to $OUTPUT_FILE" >&2
