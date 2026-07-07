#!/usr/bin/env bash
set -euo pipefail

# Extract input boxes from the explorer PostgreSQL database.
# ~1000x faster than the API-based extract_input_boxes.sh.
#
# Usage: ./extract_input_boxes_db.sh <start_height> <end_height> <output_file>
#
# Requires: psql, jq, a running Ergo node at NODE_URL for tx scanning,
# and the explorer DB at MAINNET_DB_URL.

NODE_URL="${NODE_URL:-http://localhost:9053}"
DB_URL="${MAINNET_DB_URL:-postgres://localhost-db-user:PASSWORD@localhost:5432/mainnet}"

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
    HEADER_IDS=$(curl -sf "${NODE_URL}/blocks/at/${height}" 2>/dev/null || echo "[]")
    HEADER_ID=$(echo "$HEADER_IDS" | jq -r '.[0] // empty')
    [ -z "$HEADER_ID" ] && continue

    BLOCK_TXS=$(curl -sf "${NODE_URL}/blocks/${HEADER_ID}/transactions" 2>/dev/null || echo '{}')
    echo "$BLOCK_TXS" | jq -r '.transactions[].inputs[].boxId' >> "$BOX_IDS_FILE" 2>/dev/null || true
    echo "$BLOCK_TXS" | jq -r '.transactions[].dataInputs[]?.boxId // empty' >> "$BOX_IDS_FILE" 2>/dev/null || true

    if (( height % 100 == 0 )); then
        echo "  Scanned up to height $height..." >&2
    fi
done

sort -u "$BOX_IDS_FILE" > "$TMPDIR/unique_ids.txt"
TOTAL=$(wc -l < "$TMPDIR/unique_ids.txt")
echo "Phase 1 done: $TOTAL unique input box IDs." >&2

echo "Phase 2: Fetching box data from explorer DB..." >&2

# Build a SQL VALUES list from the box IDs
awk '{printf "(\x27%s\x27),\n", $0}' "$TMPDIR/unique_ids.txt" | sed '$ s/,$//' > "$TMPDIR/values.sql"

# Query boxes with registers and assets in one shot
psql "$DB_URL" -t -A -F $'\t' <<SQLEOF > "$TMPDIR/boxes_raw.tsv"
WITH target_ids AS (
    SELECT unnest(ARRAY[
        $(cat "$TMPDIR/unique_ids.txt" | awk '{printf "\x27%s\x27,", $0}' | sed 's/,$//')
    ]) AS box_id
)
SELECT
    b.box_id,
    b.value,
    b.ergo_tree,
    b.creation_height,
    b.tx_id,
    b.index_in_tx,
    COALESCE((
        SELECT json_agg(json_build_object(
            'registerId', r.register_id,
            'serializedValue', r.serialized_value
        ) ORDER BY r.register_id)
        FROM box_registers r WHERE r.box_id = b.box_id
    ), '[]'::json) AS registers,
    COALESCE((
        SELECT json_agg(json_build_object(
            'tokenId', a.token_id,
            'amount', a.amount::text
        ))
        FROM box_assets a WHERE a.box_id = b.box_id
    ), '[]'::json) AS assets
FROM boxes b
JOIN target_ids t ON b.box_id = t.box_id;
SQLEOF

FOUND=$(wc -l < "$TMPDIR/boxes_raw.tsv")
echo "Phase 2 done: $FOUND boxes fetched from DB." >&2

echo "Phase 3: Converting to JSON..." >&2

python3 - "$TMPDIR/boxes_raw.tsv" "$OUTPUT_FILE" <<'PYEOF'
import sys, json, csv

input_file = sys.argv[1]
output_file = sys.argv[2]

boxes = []
with open(input_file) as f:
    reader = csv.reader(f, delimiter='\t')
    for row in reader:
        if len(row) < 8:
            continue
        box_id, value, ergo_tree, creation_height, tx_id, index_in_tx, regs_json, assets_json = row

        # Parse registers into {R4: hex, R5: hex, ...} format
        additional_registers = {}
        for reg in json.loads(regs_json):
            additional_registers[reg['registerId']] = reg['serializedValue']

        # Parse assets into [{tokenId, amount}, ...] format
        assets = []
        for asset in json.loads(assets_json):
            assets.append({
                'tokenId': asset['tokenId'],
                'amount': int(asset['amount'])
            })

        boxes.append({
            'boxId': box_id,
            'value': int(value),
            'ergoTree': ergo_tree,
            'creationHeight': int(creation_height),
            'transactionId': tx_id,
            'index': int(index_in_tx),
            'additionalRegisters': additional_registers,
            'assets': assets,
        })

with open(output_file, 'w') as f:
    json.dump(boxes, f, indent=2)

print(f"Wrote {len(boxes)} boxes to {output_file}", file=sys.stderr)
PYEOF

echo "Done." >&2
