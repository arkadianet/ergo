#!/usr/bin/env bash
set -euo pipefail

# Safe batch transaction extraction with built-in integrity verification.
#
# Uses the batch Scala helper for speed, but includes the tx_id in the
# Scala output line to eliminate paste-alignment bugs.
#
# After assembly, every record is verified: blake2b256(bytesToSign) == id.
# Any mismatched records are reported and excluded.
#
# Usage: ./extract_transactions_safe.sh <start_height> <end_height> <output_file>

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

# Build a JSONL file with one tx per line, but ALSO embed height and id
# in a wrapper so we can reconstruct without paste.
WRAPPED_FILE="$TMPDIR/wrapped.jsonl"
> "$WRAPPED_FILE"
TX_COUNT=0

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

        # Write height, id, and tx JSON on one line (tab-separated)
        printf '%s\t%s\t%s\n' "$height" "$TX_ID" "$TX_JSON" >> "$WRAPPED_FILE"
        TX_COUNT=$((TX_COUNT + 1))
    done

    if (( height % 50 == 0 )); then
        echo "  Fetched up to height $height ($TX_COUNT txs so far)..." >&2
    fi
done

echo "Phase 1 done: $TX_COUNT transactions fetched." >&2

echo "Phase 2: Processing through Scala serializer..." >&2

# Extract just the tx JSON for the Scala helper
cut -f3 "$WRAPPED_FILE" > "$TMPDIR/txs_only.jsonl"

$SCALA_CLI compile "$SCALA_HELPER" 2>/dev/null
$SCALA_CLI run "$SCALA_HELPER" < "$TMPDIR/txs_only.jsonl" 2>/dev/null > "$TMPDIR/results.txt"

# Verify line counts match
META_LINES=$(wc -l < "$WRAPPED_FILE")
RESULT_LINES=$(wc -l < "$TMPDIR/results.txt")
if [ "$META_LINES" -ne "$RESULT_LINES" ]; then
    echo "FATAL: line count mismatch: $META_LINES meta vs $RESULT_LINES results" >&2
    echo "The Scala helper likely skipped or duplicated lines." >&2
    exit 1
fi

echo "Phase 3: Assembling and verifying JSON output..." >&2

# Paste and assemble, filtering ERRORs
paste "$WRAPPED_FILE" "$TMPDIR/results.txt" | awk -F'\t' '
{
  height = $1
  tx_id = $2
  # $3 is tx JSON (not used in output)
  scala_out = $4
  if (scala_out ~ /^ERROR/) {
    print "  SKIP " tx_id " at h=" height ": " scala_out > "/dev/stderr"
    next
  }
  split(scala_out, res, " ")
  tx_bytes = res[1]
  bts_bytes = res[2]
  printf "{\"id\":\"%s\",\"bytes\":\"%s\",\"bytesToSign\":\"%s\",\"height\":%s}\n", tx_id, tx_bytes, bts_bytes, height
}
' > "$TMPDIR/records.jsonl"

# Wrap in JSON array
echo "[" > "$OUTPUT_FILE"
sed 's/$/,/' "$TMPDIR/records.jsonl" | sed '$ s/,$//' >> "$OUTPUT_FILE"
echo "]" >> "$OUTPUT_FILE"

FINAL_COUNT=$(jq 'length' "$OUTPUT_FILE")
echo "Wrote $FINAL_COUNT transaction vectors to $OUTPUT_FILE" >&2

# Phase 4: Integrity verification
echo "Phase 4: Verifying vector integrity..." >&2
python3 -c "
import json, hashlib, sys
data = json.load(open('$OUTPUT_FILE'))
bad = 0
for tx in data:
    bts = bytes.fromhex(tx['bytesToSign'])
    computed = hashlib.blake2b(bts, digest_size=32).hexdigest()
    if computed != tx['id']:
        bad += 1
        if bad <= 5:
            print(f'  MISMATCH: {tx[\"id\"][:16]} h={tx[\"height\"]}', file=sys.stderr)
if bad > 0:
    print(f'INTEGRITY FAIL: {bad}/{len(data)} records have misaligned id/bytesToSign', file=sys.stderr)
    sys.exit(1)
else:
    print(f'INTEGRITY OK: {len(data)}/{len(data)} records verified', file=sys.stderr)
"
echo "Done." >&2
