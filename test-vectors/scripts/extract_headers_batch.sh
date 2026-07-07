#!/usr/bin/env bash
set -euo pipefail

# Fast batch header extraction: fetches all headers from the API first,
# then processes them through a single scala-cli JVM invocation.
#
# Usage: ./extract_headers_batch.sh <start_height> <end_height> <output_file>

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCALA_CLI="${SCALA_CLI:-$HOME/.cache/scalacli/local-repo/bin/scala-cli/scala-cli}"
NODE_URL="${NODE_URL:-http://localhost:9053}"
SCALA_HELPER="${SCRIPT_DIR}/scala/BatchPrintHeaderBytes.scala"

if [ $# -lt 3 ]; then
    echo "Usage: $0 <start_height> <end_height> <output_file>" >&2
    exit 1
fi

START_HEIGHT=$1
END_HEIGHT=$2
OUTPUT_FILE=$3
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Phase 1: Fetching headers from API ($START_HEIGHT to $END_HEIGHT)..." >&2

HEIGHTS_FILE="$TMPDIR/heights.txt"
HEADERS_FILE="$TMPDIR/headers.jsonl"
> "$HEIGHTS_FILE"
> "$HEADERS_FILE"

for height in $(seq "$START_HEIGHT" "$END_HEIGHT"); do
    HEADER_IDS=$(curl -sf "${NODE_URL}/blocks/at/${height}")
    if [ -z "$HEADER_IDS" ] || [ "$HEADER_IDS" = "[]" ]; then
        echo "  Skipping height $height (no blocks)" >&2
        continue
    fi

    HEADER_ID=$(echo "$HEADER_IDS" | jq -r '.[0]')
    HEADER_JSON=$(curl -sf "${NODE_URL}/blocks/${HEADER_ID}/header")
    if [ -z "$HEADER_JSON" ]; then
        echo "  Failed to fetch header at height $height" >&2
        continue
    fi

    # One-line JSON per header
    echo "$HEADER_JSON" | jq -c '.' >> "$HEADERS_FILE"
    echo "$height $HEADER_ID" >> "$HEIGHTS_FILE"

    if (( height % 50 == 0 )); then
        echo "  Fetched up to height $height..." >&2
    fi
done

TOTAL=$(wc -l < "$HEIGHTS_FILE")
echo "Phase 1 done: $TOTAL headers fetched." >&2

echo "Phase 2: Compiling Scala helper..." >&2
$SCALA_CLI compile "$SCALA_HELPER" 2>/dev/null

echo "Phase 3: Processing $TOTAL headers through Scala serializer..." >&2
RESULTS_FILE="$TMPDIR/results.txt"
$SCALA_CLI run "$SCALA_HELPER" < "$HEADERS_FILE" 2>/dev/null > "$RESULTS_FILE"

echo "Phase 4: Assembling JSON output..." >&2
paste "$HEIGHTS_FILE" "$RESULTS_FILE" \
  | awk -F'\t' '
    $2 !~ /^ERROR/ {
      split($1, meta, " ");
      split($2, res, " ");
      height = meta[1]; hid = meta[2];
      hwp = res[1]; full = res[2]; cid = res[3];
      if (cid != hid) {
        print "  WARNING: ID mismatch at height " height ": computed=" cid " expected=" hid > "/dev/stderr"
      }
      printf "%s\t%s\t%s\t%s\n", height, hid, full, hwp
    }
    $2 ~ /^ERROR/ {
      split($1, meta, " ");
      print "  ERROR at height " meta[1] ": " $2 > "/dev/stderr"
    }
  ' \
  | jq -R -s '
    [split("\n")[] | select(length > 0) | split("\t") |
     {height: (.[0] | tonumber), id: .[1], bytes: .[2], headerWithoutPow: .[3]}]
  ' > "$OUTPUT_FILE"
echo "Wrote $(jq 'length' "$OUTPUT_FILE") header vectors to $OUTPUT_FILE" >&2
