#!/usr/bin/env bash
set -euo pipefail

# Fast batch transaction extraction: fetches all txs from the API first,
# then processes them through a single scala-cli JVM invocation.
#
# Usage: ./extract_transactions_batch.sh <start_height> <end_height> <output_file>

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCALA_CLI="${SCALA_CLI:-/home/rkadias/.cache/scalacli/local-repo/bin/scala-cli/scala-cli}"
NODE_URL="${NODE_URL:-http://localhost:9053}"
SCALA_HELPER="${SCRIPT_DIR}/scala/BatchPrintTransactionBytes.scala"

if [ $# -lt 3 ]; then
    echo "Usage: $0 <start_height> <end_height> <output_file>" >&2
    exit 1
fi

START_HEIGHT=$1
END_HEIGHT=$2
OUTPUT_FILE=$3
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Phase 1: Fetching transactions from API ($START_HEIGHT to $END_HEIGHT)..." >&2

META_FILE="$TMPDIR/meta.txt"
TXS_FILE="$TMPDIR/txs.jsonl"
> "$META_FILE"
> "$TXS_FILE"

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
        TX_JSON=$(echo "$BLOCK_TXS" | jq -c ".transactions[$idx]")
        TX_ID=$(echo "$TX_JSON" | jq -r '.id')

        echo "$TX_JSON" >> "$TXS_FILE"
        echo "$height $TX_ID" >> "$META_FILE"
    done

    if (( height % 50 == 0 )); then
        echo "  Fetched up to height $height..." >&2
    fi
done

TOTAL=$(wc -l < "$META_FILE")
echo "Phase 1 done: $TOTAL transactions fetched." >&2

echo "Phase 2: Compiling Scala helper..." >&2
$SCALA_CLI compile "$SCALA_HELPER" 2>/dev/null

echo "Phase 3: Processing $TOTAL transactions through Scala serializer..." >&2
RESULTS_FILE="$TMPDIR/results.txt"
$SCALA_CLI run "$SCALA_HELPER" < "$TXS_FILE" 2>/dev/null > "$RESULTS_FILE"

echo "Phase 4: Assembling JSON output..." >&2
paste "$META_FILE" "$RESULTS_FILE" \
  | awk -F'\t' '
    $2 !~ /^ERROR/ {
      split($1, meta, " ");
      split($2, res, " ");
      printf "%s\t%s\t%s\t%s\n", meta[2], res[1], res[2], meta[1]
    }
    $2 ~ /^ERROR/ {
      split($1, meta, " ");
      print "  ERROR at height " meta[1] " tx " meta[2] ": " $2 > "/dev/stderr"
    }
  ' \
  | jq -R -s '
    [split("\n")[] | select(length > 0) | split("\t") |
     {id: .[0], bytes: .[1], bytesToSign: .[2], height: (.[3] | tonumber)}]
  ' > "$OUTPUT_FILE"
echo "Wrote $(jq 'length' "$OUTPUT_FILE") transaction vectors to $OUTPUT_FILE" >&2
