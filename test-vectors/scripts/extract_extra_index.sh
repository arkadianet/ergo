#!/usr/bin/env bash
set -euo pipefail

# Capture Scala-node /blockchain/* responses into a JSON oracle vector,
# used by `ergo-api/tests/blockchain_scala_parity.rs` to assert byte/JSON
# parity of the Rust extra-index API against the Scala reference node.
#
# Vectors are pulled by tx_id / box_id directly from the Scala node.
# Volatile fields (`numConfirmations`) are stripped at capture time so
# the oracle stays stable across re-runs and against a Rust indexer
# that's only synced to the test backfill range.
#
# Usage: ./extract_extra_index.sh <input_corpus> <output_file>
#
# Inputs:
#   - test-vectors/mainnet/transactions_1_200.json (or another corpus
#     with the same shape: array of `{id, bytes, ...}` tx objects).
#
# Output: a single JSON object:
#   {
#     "node":  { "name": "...", "appVersion": "...", "stateType": "...",
#                "captured_at": <unix-ts> },
#     "transactions": { "<tx_id>": <scala /blockchain/transaction/byId json> },
#     "boxes":        { "<box_id>": <scala /blockchain/box/byId json> }
#   }
#
# Env vars:
#   NODE_URL  Scala node base URL  (default: http://localhost:9053)
#   JOBS      curl parallelism      (default: 8)

NODE_URL="${NODE_URL:-http://localhost:9053}"
JOBS="${JOBS:-8}"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <input_corpus.json> <output_file.json>" >&2
    exit 1
fi

INPUT="$1"
OUTPUT="$2"

if [ ! -f "$INPUT" ]; then
    echo "Input corpus not found: $INPUT" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"

# Verify the Scala node is reachable and has extraIndex enabled.
INFO=$(curl -sf "${NODE_URL}/info") || {
    echo "Cannot reach Scala node at ${NODE_URL}" >&2
    exit 1
}
NODE_NAME=$(echo "$INFO" | jq -r '.name')
NODE_VERSION=$(echo "$INFO" | jq -r '.appVersion')
NODE_STATE=$(echo "$INFO" | jq -r '.stateType')

# Probe the indexer surface; bail early if extraIndex is not enabled
# on this node, otherwise the captured corpus would be all 404s.
PROBE=$(curl -sf -o /dev/null -w '%{http_code}' \
    "${NODE_URL}/blockchain/transaction/byIndex/0" || true)
if [ "$PROBE" != "200" ]; then
    echo "Scala node at ${NODE_URL} does not have extraIndex enabled" >&2
    echo "(probe returned HTTP ${PROBE} for /blockchain/transaction/byIndex/0)" >&2
    exit 1
fi

echo "Scala node:  ${NODE_NAME} (${NODE_VERSION}, ${NODE_STATE})" >&2
echo "Reading tx ids + box ids from ${INPUT}..." >&2

# Build the (tx_id, box_id[]) pair list from the input corpus.
# Box IDs are derived deterministically from tx.bytes via a one-shot
# JSON-mode call to Scala's /utils/transactionToken? No — simpler:
# Scala's `/blockchain/transaction/byId` returns the tx's outputs with
# their box_ids, so we look those up first to find the box ids.
TX_IDS=$(jq -r '.[].id' "$INPUT")
TX_COUNT=$(echo "$TX_IDS" | wc -l | tr -d ' ')
echo "  -> ${TX_COUNT} transactions" >&2

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

TX_DIR="${WORK_DIR}/txs"
BOX_DIR="${WORK_DIR}/boxes"
mkdir -p "$TX_DIR" "$BOX_DIR"

fetch_tx() {
    local id="$1"
    local out="${TX_DIR}/${id}.json"
    # `del(.numConfirmations)` strips the only volatile top-level field on
    # IndexedErgoTransaction. Per-input/output objects on the tx are pure
    # IndexedErgoBox records and don't carry `numConfirmations`.
    curl -sf "${NODE_URL}/blockchain/transaction/byId/${id}" \
        | jq 'del(.numConfirmations)' > "$out" \
        || { echo "FAIL tx ${id}" >&2; rm -f "$out"; }
}

fetch_box() {
    local id="$1"
    local out="${BOX_DIR}/${id}.json"
    curl -sf "${NODE_URL}/blockchain/box/byId/${id}" \
        | jq '.' > "$out" \
        || { echo "FAIL box ${id}" >&2; rm -f "$out"; }
}

export -f fetch_tx fetch_box
export NODE_URL TX_DIR BOX_DIR

echo "Fetching transactions (${JOBS} parallel)..." >&2
echo "$TX_IDS" | xargs -P"$JOBS" -I{} bash -c 'fetch_tx "$@"' _ {}

# Collect every box id referenced in any captured tx (outputs + inputs).
# Inputs are resolved to their *creating* box id, which is the one we
# need to look up via /blockchain/box/byId. Use sort -u so a box that
# appears in both an output (creation) and an input (spend) is only
# fetched once.
echo "Collecting box ids from captured transactions..." >&2
BOX_IDS=$(find "$TX_DIR" -name '*.json' -print0 \
    | xargs -0 jq -r '.outputs[].boxId, .inputs[].boxId' \
    | sort -u)
BOX_COUNT=$(echo "$BOX_IDS" | grep -cv '^$' || true)
echo "  -> ${BOX_COUNT} unique boxes" >&2

echo "Fetching boxes (${JOBS} parallel)..." >&2
echo "$BOX_IDS" | xargs -P"$JOBS" -I{} bash -c 'fetch_box "$@"' _ {}

echo "Assembling oracle vector..." >&2
# Stage the per-id JSON files into intermediate slurp files. Passing
# the whole captured corpus through `--argjson` would blow past
# ARG_MAX (each shard is ~MB-scale once the corpus has a few hundred
# records); `--slurpfile` reads the value from disk instead.
TX_INTERMEDIATE="${WORK_DIR}/transactions.json"
BOX_INTERMEDIATE="${WORK_DIR}/boxes.json"
find "$TX_DIR" -name '*.json' -exec cat {} + \
    | jq -s 'reduce .[] as $tx ({}; .[$tx.id] = $tx)' > "$TX_INTERMEDIATE"
find "$BOX_DIR" -name '*.json' -exec cat {} + \
    | jq -s 'reduce .[] as $b ({}; .[$b.boxId] = $b)' > "$BOX_INTERMEDIATE"

NOW=$(date -u +%s)
jq -n \
    --slurpfile txs "$TX_INTERMEDIATE" \
    --slurpfile boxes "$BOX_INTERMEDIATE" \
    --arg name "$NODE_NAME" \
    --arg version "$NODE_VERSION" \
    --arg state "$NODE_STATE" \
    --argjson ts "$NOW" \
    '{
        node: { name: $name, appVersion: $version, stateType: $state, captured_at: $ts },
        transactions: $txs[0],
        boxes: $boxes[0]
    }' > "$OUTPUT"

CAP_TX=$(jq '.transactions | length' "$OUTPUT")
CAP_BOX=$(jq '.boxes | length' "$OUTPUT")
echo "Wrote ${OUTPUT}: ${CAP_TX} txs, ${CAP_BOX} boxes" >&2
