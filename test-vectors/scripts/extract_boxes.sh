#!/usr/bin/env bash
set -euo pipefail

# Extract box serialization vectors from a running Ergo node.
#
# Usage: ./extract_boxes.sh <mode> <arg> <output_file>
#
# Modes:
#   ids   <box_ids_file>  - Read box IDs from file (one per line), fetch binary
#   block <height>        - Discover boxes from outputs of block at <height>
#
# Uses /utxo/byIdBinary/{boxId} which returns hex-encoded canonical box bytes
# for boxes currently in the UTXO set. Spent boxes will return 404.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NODE_URL="${NODE_URL:-http://localhost:9053}"

if [ $# -lt 3 ]; then
    echo "Usage: $0 <mode: ids|block> <arg> <output_file>" >&2
    echo "  ids   <file>   - file with box IDs, one per line" >&2
    echo "  block <height> - extract from block outputs at height" >&2
    exit 1
fi

MODE=$1
ARG=$2
OUTPUT_FILE=$3

collect_box_ids() {
    if [ "$MODE" = "ids" ]; then
        cat "$ARG"
    elif [ "$MODE" = "block" ]; then
        local height=$ARG
        local header_id
        header_id=$(curl -sf "${NODE_URL}/blocks/at/${height}" | jq -r '.[0]')
        curl -sf "${NODE_URL}/blocks/${header_id}/transactions" | jq -r '.transactions[].outputs[].boxId'
    else
        echo "Unknown mode: $MODE" >&2
        exit 1
    fi
}

echo "Extracting boxes (mode=$MODE)..." >&2

RESULTS="["
FIRST=true
FOUND=0
SKIPPED=0

while IFS= read -r BOX_ID; do
    [ -z "$BOX_ID" ] && continue

    # Try binary endpoint (only works for unspent boxes in UTXO set)
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

    # Also fetch the box JSON to get ergoTree
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
  {\"boxId\":\"${BOX_ID}\",\"bytes\":\"${BOX_BYTES}\",\"ergoTree\":\"${ERGO_TREE}\"}"

    FOUND=$((FOUND + 1))
    echo "  boxId=${BOX_ID:0:16}... bytes=${#BOX_BYTES} chars" >&2
done < <(collect_box_ids)

RESULTS="${RESULTS}
]"

echo "$RESULTS" | jq '.' > "$OUTPUT_FILE"
echo "Wrote $FOUND box vectors to $OUTPUT_FILE ($SKIPPED skipped/spent)" >&2
