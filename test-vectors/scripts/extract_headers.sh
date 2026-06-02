#!/usr/bin/env bash
set -euo pipefail

# Extract canonical header serialization vectors from a running Ergo node.
#
# Usage: ./extract_headers.sh <start_height> <end_height> <output_file>
# Example: ./extract_headers.sh 1 10 ../mainnet/headers_1_10.json
#
# Requires: curl, jq, scala-cli with ergo-wallet dependency.
# The Ergo node must be running at NODE_URL (default http://localhost:9053).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCALA_CLI="${SCALA_CLI:-/home/rkadias/.cache/scalacli/local-repo/bin/scala-cli/scala-cli}"
NODE_URL="${NODE_URL:-http://localhost:9053}"
SCALA_HELPER="${SCRIPT_DIR}/scala/PrintHeaderBytes.scala"

if [ $# -lt 3 ]; then
    echo "Usage: $0 <start_height> <end_height> <output_file>" >&2
    exit 1
fi

START_HEIGHT=$1
END_HEIGHT=$2
OUTPUT_FILE=$3

# Warm up scala-cli compilation (first run downloads deps + compiles)
echo "Warming up Scala helper..." >&2
echo '{}' | $SCALA_CLI run "$SCALA_HELPER" 2>/dev/null || true

echo "Extracting headers from height $START_HEIGHT to $END_HEIGHT..." >&2

RESULTS="["
FIRST=true

for height in $(seq "$START_HEIGHT" "$END_HEIGHT"); do
    # Get header IDs at this height
    HEADER_IDS=$(curl -sf "${NODE_URL}/blocks/at/${height}")
    if [ -z "$HEADER_IDS" ] || [ "$HEADER_IDS" = "[]" ]; then
        echo "  Skipping height $height (no blocks)" >&2
        continue
    fi

    # Take the first (canonical) header ID
    HEADER_ID=$(echo "$HEADER_IDS" | jq -r '.[0]')

    # Fetch header JSON
    HEADER_JSON=$(curl -sf "${NODE_URL}/blocks/${HEADER_ID}/header")
    if [ -z "$HEADER_JSON" ]; then
        echo "  Failed to fetch header $HEADER_ID at height $height" >&2
        continue
    fi

    # Run through Scala helper to get canonical bytes
    SCALA_OUT=$(echo "$HEADER_JSON" | $SCALA_CLI run "$SCALA_HELPER" 2>/dev/null | grep -E '^[0-9a-f]')
    if [ -z "$SCALA_OUT" ]; then
        echo "  Scala helper failed for height $height" >&2
        continue
    fi

    HWP_HEX=$(echo "$SCALA_OUT" | awk '{print $1}')
    FULL_HEX=$(echo "$SCALA_OUT" | awk '{print $2}')
    COMPUTED_ID=$(echo "$SCALA_OUT" | awk '{print $3}')

    # Sanity check: computed ID should match the header ID from the API
    if [ "$COMPUTED_ID" != "$HEADER_ID" ]; then
        echo "  WARNING: ID mismatch at height $height: computed=$COMPUTED_ID expected=$HEADER_ID" >&2
    fi

    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        RESULTS="${RESULTS},"
    fi

    RESULTS="${RESULTS}
  {\"height\":${height},\"id\":\"${HEADER_ID}\",\"bytes\":\"${FULL_HEX}\",\"headerWithoutPow\":\"${HWP_HEX}\"}"

    echo "  height=$height id=${HEADER_ID:0:16}... bytes=${#FULL_HEX} chars" >&2
done

RESULTS="${RESULTS}
]"

echo "$RESULTS" | jq '.' > "$OUTPUT_FILE"
echo "Wrote $(echo "$RESULTS" | jq 'length') header vectors to $OUTPUT_FILE" >&2
