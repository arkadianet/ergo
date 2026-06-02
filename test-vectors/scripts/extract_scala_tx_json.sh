#!/usr/bin/env bash
set -euo pipefail

# Capture real Scala node `/blocks/{id}/transactions` JSON for the
# Track B differential corpus. Output is a JSON array of
#   {"height": N, "txId": "...", "scalaJson": {...}}
# objects. Canonical bytes are NOT included here — they live in
# `test-vectors/mainnet/transactions_*.json` (extracted by
# `extract_transactions.sh` via the Scala helper). Join them by
# `txId` to produce the {height, txId, bytes, scalaJson} shape the
# `b4_scala_captured_json_decodes_to_canonical_bytes` test expects.
#
# Example join (post-capture):
#   jq --slurpfile lookup <(jq -c '[.[] | {(.id): .bytes}] | add' \
#       transactions_1_10.json) \
#     'map(. + {bytes: ($lookup[0][.txId])})' diff_corpus.json
#
# Usage: ./extract_scala_tx_json.sh <output-file> <height-range>...
# Example: ./extract_scala_tx_json.sh ../mainnet/scala_tx_json/diff_corpus.json 2-10 700000-700010

NODE_URL="${NODE_URL:-http://213.239.193.208:9053}"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <output-file> <start-end>..." >&2
    exit 1
fi

OUTPUT_FILE=$1
shift

mkdir -p "$(dirname "$OUTPUT_FILE")"

ACC="[]"
TOTAL=0

for RANGE in "$@"; do
    START=${RANGE%-*}
    END=${RANGE#*-}
    for height in $(seq "$START" "$END"); do
        for attempt in 1 2 3; do
            HEADER_IDS=$(curl -sf -m 12 --retry 2 --retry-delay 2 "${NODE_URL}/blocks/at/${height}" 2>/dev/null || echo "")
            [ -n "$HEADER_IDS" ] && break
            sleep 2
        done
        HID=$(echo "$HEADER_IDS" | jq -r '.[0] // empty' 2>/dev/null || echo "")
        if [ -z "$HID" ]; then
            echo "  skip height=$height (no header)" >&2
            sleep 1
            continue
        fi

        for attempt in 1 2 3; do
            BTX=$(curl -sf -m 20 --retry 2 --retry-delay 2 "${NODE_URL}/blocks/${HID}/transactions" 2>/dev/null || echo "")
            [ -n "$BTX" ] && break
            sleep 2
        done
        if [ -z "$BTX" ]; then
            echo "  skip height=$height (no btx)" >&2
            sleep 1
            continue
        fi

        N=$(echo "$BTX" | jq '.transactions | length' 2>/dev/null || echo 0)
        for idx in $(seq 0 $((N - 1))); do
            TX=$(echo "$BTX" | jq ".transactions[$idx]")
            TXID=$(echo "$TX" | jq -r '.id')
            ACC=$(echo "$ACC" | jq --arg h "$height" --arg id "$TXID" --argjson tx "$TX" \
                '. + [{"height": ($h|tonumber), "txId": $id, "scalaJson": $tx}]')
            TOTAL=$((TOTAL + 1))
        done
        echo "  height=$height txs=$N (total=$TOTAL)" >&2
        sleep 0.3  # be polite to public nodes
    done
done

echo "$ACC" | jq '.' > "$OUTPUT_FILE"
echo "Wrote $TOTAL Scala-JSON tx vectors to $OUTPUT_FILE" >&2
