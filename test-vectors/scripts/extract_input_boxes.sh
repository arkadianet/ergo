#!/usr/bin/env bash
set -euo pipefail

# Extract all input boxes needed for transaction validation in a height range.
#
# Usage: ./extract_input_boxes.sh <start_height> <end_height> <output_file>
#
# For each transaction in the range, fetches full box data for all inputs
# and data inputs via /blockchain/box/byId/{boxId}. Deduplicates box IDs.
# Includes serialized box bytes via Scala helper for test consumption.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCALA_CLI="${SCALA_CLI:-$HOME/.cache/scalacli/local-repo/bin/scala-cli/scala-cli}"
NODE_URL="${NODE_URL:-http://localhost:9053}"

if [ $# -lt 3 ]; then
    echo "Usage: $0 <start_height> <end_height> <output_file>" >&2
    exit 1
fi

START_HEIGHT=$1
END_HEIGHT=$2
OUTPUT_FILE=$3
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Phase 1: Collecting input box IDs from blocks $START_HEIGHT to $END_HEIGHT..." >&2

BOX_IDS_FILE="$TMPDIR/box_ids.txt"
> "$BOX_IDS_FILE"

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

    # Collect input box IDs
    echo "$BLOCK_TXS" | jq -r '.transactions[].inputs[].boxId' >> "$BOX_IDS_FILE"
    # Collect data input box IDs
    echo "$BLOCK_TXS" | jq -r '.transactions[].dataInputs[]?.boxId // empty' >> "$BOX_IDS_FILE" 2>/dev/null || true

    if (( height % 50 == 0 )); then
        echo "  Scanned up to height $height..." >&2
    fi
done

# Deduplicate
sort -u "$BOX_IDS_FILE" > "$TMPDIR/unique_ids.txt"
TOTAL=$(wc -l < "$TMPDIR/unique_ids.txt")
echo "Phase 1 done: $TOTAL unique input box IDs." >&2

echo "Phase 2: Fetching box data from blockchain API..." >&2

RESULTS="["
FIRST=true
FOUND=0
FAILED=0

while IFS= read -r BOX_ID; do
    [ -z "$BOX_ID" ] && continue

    BOX_JSON=$(curl -sf "${NODE_URL}/blockchain/box/byId/${BOX_ID}" 2>/dev/null || echo "")
    if [ -z "$BOX_JSON" ] || echo "$BOX_JSON" | jq -e '.error' >/dev/null 2>&1; then
        echo "  FAILED: $BOX_ID" >&2
        FAILED=$((FAILED + 1))
        continue
    fi

    VALUE=$(echo "$BOX_JSON" | jq -r '.value')
    ERGO_TREE=$(echo "$BOX_JSON" | jq -r '.ergoTree')
    CREATION_HEIGHT=$(echo "$BOX_JSON" | jq -r '.creationHeight')
    TX_ID=$(echo "$BOX_JSON" | jq -r '.transactionId')
    INDEX=$(echo "$BOX_JSON" | jq -r '.index')
    ASSETS=$(echo "$BOX_JSON" | jq -c '.assets // []')
    REGISTERS=$(echo "$BOX_JSON" | jq -c '.additionalRegisters // {}')

    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        RESULTS="${RESULTS},"
    fi

    RESULTS="${RESULTS}
  {\"boxId\":\"${BOX_ID}\",\"value\":${VALUE},\"ergoTree\":\"${ERGO_TREE}\",\"creationHeight\":${CREATION_HEIGHT},\"transactionId\":\"${TX_ID}\",\"index\":${INDEX},\"assets\":${ASSETS},\"additionalRegisters\":${REGISTERS}}"

    FOUND=$((FOUND + 1))
    if (( FOUND % 50 == 0 )); then
        echo "  Fetched $FOUND / $TOTAL boxes..." >&2
    fi
done < "$TMPDIR/unique_ids.txt"

RESULTS="${RESULTS}
]"

echo "$RESULTS" | jq '.' > "$OUTPUT_FILE"
echo "Wrote $FOUND input box vectors to $OUTPUT_FILE ($FAILED failed)" >&2
