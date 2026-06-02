#!/usr/bin/env bash
set -euo pipefail

# Extract a compact state replay file for genesis-to-target replay.
#
# Usage: ./extract_state_replay.sh <start_height> <end_height> <output_file>
#
# Output format: one JSON line per block (JSONL), then gzip compressed.
# Each line: {"h":<height>,"i":"<header_id>","s":"<state_root>","t":["<tx_hex>",...]}
#
# Uses the batch transaction extraction for canonical Scala-serialized bytes.
# Designed for large ranges (100k+ blocks) where full JSON vectors are too large.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCALA_CLI="${SCALA_CLI:-/home/rkadias/.cache/scalacli/local-repo/bin/scala-cli/scala-cli}"
NODE_URL="${NODE_URL:-http://localhost:9053}"
SCALA_HELPER="${SCRIPT_DIR}/scala/BatchPrintTransactionBytes.scala"

if [ $# -lt 3 ]; then
    echo "Usage: $0 <start_height> <end_height> <output_file>" >&2
    echo "Output file should end in .jsonl.gz" >&2
    exit 1
fi

START_HEIGHT=$1
END_HEIGHT=$2
OUTPUT_FILE=$3
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

TOTAL_BLOCKS=$(( END_HEIGHT - START_HEIGHT + 1 ))
echo "Extracting state replay data for $TOTAL_BLOCKS blocks ($START_HEIGHT to $END_HEIGHT)..." >&2

# Phase 1: Fetch all block data (header IDs, state roots, transaction JSON)
echo "Phase 1: Fetching block data from API..." >&2

BLOCK_META="$TMPDIR/block_meta.txt"   # height header_id state_root
TXS_JSONL="$TMPDIR/txs.jsonl"          # transaction JSON, one per line
TX_META="$TMPDIR/tx_meta.txt"           # height tx_index

> "$BLOCK_META"
> "$TXS_JSONL"
> "$TX_META"

for height in $(seq "$START_HEIGHT" "$END_HEIGHT"); do
    HEADER_IDS=$(curl -sf "${NODE_URL}/blocks/at/${height}")
    if [ -z "$HEADER_IDS" ] || [ "$HEADER_IDS" = "[]" ]; then
        continue
    fi

    HEADER_ID=$(echo "$HEADER_IDS" | jq -r '.[0]')

    # Get state root from header
    HEADER_JSON=$(curl -sf "${NODE_URL}/blocks/${HEADER_ID}/header")
    STATE_ROOT=$(echo "$HEADER_JSON" | jq -r '.stateRoot')

    # Get transactions
    BLOCK_TXS=$(curl -sf "${NODE_URL}/blocks/${HEADER_ID}/transactions")
    NUM_TXS=$(echo "$BLOCK_TXS" | jq '.transactions | length')

    echo "$height $HEADER_ID $STATE_ROOT $NUM_TXS" >> "$BLOCK_META"

    for idx in $(seq 0 $(( NUM_TXS - 1 ))); do
        TX_JSON=$(echo "$BLOCK_TXS" | jq -c ".transactions[$idx]")
        echo "$TX_JSON" >> "$TXS_JSONL"
        echo "$height $idx" >> "$TX_META"
    done

    if (( height % 500 == 0 )); then
        echo "  Fetched $height / $END_HEIGHT..." >&2
    fi
done

TOTAL_TXS=$(wc -l < "$TX_META")
echo "Phase 1 done: $TOTAL_BLOCKS blocks, $TOTAL_TXS transactions." >&2

# Phase 2: Serialize all transactions through Scala
echo "Phase 2: Compiling Scala helper..." >&2
$SCALA_CLI compile "$SCALA_HELPER" 2>/dev/null

echo "Phase 3: Processing $TOTAL_TXS transactions through Scala serializer..." >&2
RESULTS_FILE="$TMPDIR/tx_results.txt"
$SCALA_CLI run "$SCALA_HELPER" < "$TXS_JSONL" 2>/dev/null > "$RESULTS_FILE"

# Phase 4: Assemble JSONL output
echo "Phase 4: Assembling compact JSONL..." >&2
JSONL_FILE="$TMPDIR/replay.jsonl"

# Build a map from (height, tx_index) -> tx_hex
paste "$TX_META" "$RESULTS_FILE" > "$TMPDIR/tx_combined.txt"

# Process block by block
python3 - "$BLOCK_META" "$TMPDIR/tx_combined.txt" "$JSONL_FILE" <<'PYEOF'
import sys, json

block_meta_file = sys.argv[1]
tx_combined_file = sys.argv[2]
output_file = sys.argv[3]

# Load transaction hex by (height, index)
tx_hex = {}
with open(tx_combined_file) as f:
    for line in f:
        parts = line.strip().split('\t')
        if len(parts) < 2:
            continue
        meta_parts = parts[0].split()
        height = int(meta_parts[0])
        idx = int(meta_parts[1])
        result = parts[1].split()
        if result[0].startswith('ERROR'):
            continue
        tx_hex[(height, idx)] = result[0]  # signed tx hex

# Write JSONL
with open(output_file, 'w') as out:
    with open(block_meta_file) as f:
        for line in f:
            parts = line.strip().split()
            height = int(parts[0])
            header_id = parts[1]
            state_root = parts[2]
            num_txs = int(parts[3])
            txs = []
            for idx in range(num_txs):
                key = (height, idx)
                if key in tx_hex:
                    txs.append(tx_hex[key])
            entry = {"h": height, "i": header_id, "s": state_root, "t": txs}
            out.write(json.dumps(entry, separators=(',', ':')) + '\n')

print(f"Wrote {output_file}", file=sys.stderr)
PYEOF

# Phase 5: Compress
echo "Phase 5: Compressing..." >&2
gzip -9 < "$JSONL_FILE" > "$OUTPUT_FILE"

RAW_SIZE=$(stat -c%s "$JSONL_FILE")
GZ_SIZE=$(stat -c%s "$OUTPUT_FILE")
echo "Done: ${RAW_SIZE} bytes raw → ${GZ_SIZE} bytes compressed ($(( GZ_SIZE * 100 / RAW_SIZE ))%)" >&2
LINES=$(wc -l < "$JSONL_FILE")
echo "Total blocks: $LINES" >&2
