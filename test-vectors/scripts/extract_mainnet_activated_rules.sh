#!/usr/bin/env bash
set -euo pipefail

# Phase 2.0 live extraction: walks every epoch boundary on mainnet,
# dumps the (0x00, 124) SoftForkDisablingRulesKey blob hex.
#
# Output: test-vectors/mainnet/voted_params_softfork_blobs.json
#   [ { height: u32, header_id: hex, blob_hex: hex } ... ]
#
# Usage: extract_mainnet_activated_rules.sh [scala_url]
#   Default: http://127.0.0.1:9053

SCALA_URL="${1:-http://127.0.0.1:9053}"
OUT_FILE="test-vectors/mainnet/voted_params_softfork_blobs.json"
mkdir -p "$(dirname "$OUT_FILE")"

TIP=$(curl -fsS "$SCALA_URL/info" | jq -r '.fullHeight')
LAST_EPOCH=$(( TIP / 1024 * 1024 ))

echo "[extract] tip=$TIP, last_epoch=$LAST_EPOCH"

echo "[" > "$OUT_FILE"
FIRST=1

for H in $(seq 1024 1024 "$LAST_EPOCH"); do
    HID=$(curl -fsS "$SCALA_URL/blocks/at/$H" 2>/dev/null | jq -r '.[0] // empty')
    if [[ -z "$HID" ]]; then
        echo "[extract] skip h=$H (no header)" >&2
        continue
    fi

    BLOB=$(curl -fsS "$SCALA_URL/blocks/$HID/extension" 2>/dev/null \
        | jq -r '.extension.fields | map(select(.[0] | startswith("007c"))) | .[0][1] // empty')
    if [[ -z "$BLOB" ]]; then
        echo "[extract] skip h=$H (no 007c entry)" >&2
        continue
    fi

    if [[ $FIRST -eq 1 ]]; then
        FIRST=0
    else
        echo "," >> "$OUT_FILE"
    fi
    printf '  {"height": %d, "header_id": "%s", "blob_hex": "%s"}' \
        "$H" "$HID" "$BLOB" >> "$OUT_FILE"

    if (( H % 51200 == 0 )); then
        echo "[extract] progress h=$H" >&2
    fi
done

echo "" >> "$OUT_FILE"
echo "]" >> "$OUT_FILE"

# Summary: how many distinct non-empty blobs?
DISTINCT=$(jq -r '[.[] | .blob_hex] | unique | length' "$OUT_FILE")
NONEMPTY=$(jq -r '[.[] | select(.blob_hex != "0000")] | length' "$OUT_FILE")
TOTAL=$(jq -r 'length' "$OUT_FILE")

echo "[extract] done"
echo "[extract] total epochs walked: $TOTAL"
echo "[extract] distinct blob shapes: $DISTINCT"
echo "[extract] non-empty blobs (rules_to_disable or status_updates set): $NONEMPTY"
echo "[extract] output: $OUT_FILE"
