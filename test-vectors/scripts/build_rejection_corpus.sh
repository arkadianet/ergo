#!/usr/bin/env bash
set -euo pipefail

# Build a Scala-sourced rejection corpus by constructing invalid transactions
# and validating them against the running Ergo node.
#
# Each mutation is: (1) constructed and serialized by Scala, (2) submitted
# to the node's /transactions/check endpoint, (3) the node's rejection
# response is recorded as the oracle verdict.
#
# Usage: ./build_rejection_corpus.sh <output_file>

NODE_URL="${NODE_URL:-http://localhost:9053}"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <output_file>" >&2
    exit 1
fi

OUTPUT_FILE=$1
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Building rejection corpus..." >&2

# Get source box info
SOURCE_BOX_ID=""
BOX_VALUE=""

# Find an unspent box
HEIGHT=$(curl -sf "$NODE_URL/info" | jq '.fullHeight')
echo "  Node height: $HEIGHT" >&2

for h in $(seq "$HEIGHT" -1 $((HEIGHT - 100))); do
    HEADER_IDS=$(curl -sf "$NODE_URL/blocks/at/$h" 2>/dev/null || echo "[]")
    HEADER_ID=$(echo "$HEADER_IDS" | jq -r '.[0] // empty')
    [ -z "$HEADER_ID" ] && continue

    BLOCK_TXS=$(curl -sf "$NODE_URL/blocks/$HEADER_ID/transactions" 2>/dev/null || echo '{}')
    FIRST_OUTPUT_ID=$(echo "$BLOCK_TXS" | jq -r '.transactions[0].outputs[0].boxId // empty')
    [ -z "$FIRST_OUTPUT_ID" ] && continue

    # Check if in UTXO
    UTXO_CHECK=$(curl -sf "$NODE_URL/utxo/byId/$FIRST_OUTPUT_ID" 2>/dev/null || echo "")
    if [ -n "$UTXO_CHECK" ]; then
        SOURCE_BOX_ID="$FIRST_OUTPUT_ID"
        BOX_VALUE=$(echo "$UTXO_CHECK" | jq -r '.value')
        ERGO_TREE=$(echo "$UTXO_CHECK" | jq -r '.ergoTree')
        SOURCE_BOX_JSON=$(curl -sf "$NODE_URL/blockchain/box/byId/$SOURCE_BOX_ID")
        echo "  Found unspent box: $SOURCE_BOX_ID (value=$BOX_VALUE) at height $h" >&2
        break
    fi
done

[ -z "$SOURCE_BOX_ID" ] && { echo "ERROR: no unspent box found" >&2; exit 1; }

SIMPLE_TREE="0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

# Helper to submit a transaction JSON and capture the node's response
submit_and_record() {
    local label="$1" category="$2" tx_json="$3" tx_hex="$4"

    RESPONSE=$(curl -s -w "\n%{http_code}" "$NODE_URL/transactions/check" -X POST \
        -H "Content-Type: application/json" -d "$tx_json" 2>/dev/null)
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    if [ "$HTTP_CODE" = "200" ]; then
        echo "  WARNING: $label ACCEPTED (expected rejection)" >&2
        return
    fi

    SCALA_ERROR=$(echo "$BODY" | jq -r '.detail // .reason // "unknown"' 2>/dev/null | head -c 300)
    echo "  $label -> REJECTED ($HTTP_CODE): ${SCALA_ERROR:0:100}" >&2

    echo "{\"label\":\"$label\",\"expectedCategory\":\"$category\",\"txHex\":\"$tx_hex\",\"scalaError\":$(echo "$SCALA_ERROR" | jq -Rs '.'),\"height\":$HEIGHT,\"sourceBoxId\":\"$SOURCE_BOX_ID\"}"
}

echo "  Generating and validating mutations..." >&2

RESULTS="["
FIRST=true

# Use the Scala-generated mutations for hex, but construct JSON for the API
# --- Mutation 1: ERG inflation ---
INFLATED=$((BOX_VALUE + 1000000000))
TX1_JSON="{\"inputs\":[{\"boxId\":\"$SOURCE_BOX_ID\",\"spendingProof\":{\"proofBytes\":\"\",\"extension\":{}}}],\"dataInputs\":[],\"outputs\":[{\"value\":$INFLATED,\"ergoTree\":\"$SIMPLE_TREE\",\"creationHeight\":$HEIGHT,\"assets\":[],\"additionalRegisters\":{}}]}"
RESULT=$(submit_and_record "erg_inflation" "MONETARY" "$TX1_JSON" "")
if [ -n "$RESULT" ]; then
    [ "$FIRST" = true ] && FIRST=false || RESULTS="${RESULTS},"
    RESULTS="${RESULTS}${RESULT}"
fi

# --- Mutation 2: Duplicate inputs ---
TX2_JSON="{\"inputs\":[{\"boxId\":\"$SOURCE_BOX_ID\",\"spendingProof\":{\"proofBytes\":\"\",\"extension\":{}}},{\"boxId\":\"$SOURCE_BOX_ID\",\"spendingProof\":{\"proofBytes\":\"\",\"extension\":{}}}],\"dataInputs\":[],\"outputs\":[{\"value\":$((BOX_VALUE - 1000000)),\"ergoTree\":\"$SIMPLE_TREE\",\"creationHeight\":$HEIGHT,\"assets\":[],\"additionalRegisters\":{}}]}"
RESULT=$(submit_and_record "duplicate_inputs" "STRUCTURAL" "$TX2_JSON" "")
if [ -n "$RESULT" ]; then
    [ "$FIRST" = true ] && FIRST=false || RESULTS="${RESULTS},"
    RESULTS="${RESULTS}${RESULT}"
fi

# --- Mutation 3: Invalid proof ---
TX3_JSON="{\"inputs\":[{\"boxId\":\"$SOURCE_BOX_ID\",\"spendingProof\":{\"proofBytes\":\"abababababababababababababababababababababababababababababababababab\",\"extension\":{}}}],\"dataInputs\":[],\"outputs\":[{\"value\":$((BOX_VALUE - 1000000)),\"ergoTree\":\"$SIMPLE_TREE\",\"creationHeight\":$HEIGHT,\"assets\":[],\"additionalRegisters\":{}}]}"
RESULT=$(submit_and_record "invalid_proof" "PROOF" "$TX3_JSON" "")
if [ -n "$RESULT" ]; then
    [ "$FIRST" = true ] && FIRST=false || RESULTS="${RESULTS},"
    RESULTS="${RESULTS}${RESULT}"
fi

# --- Mutation 4: Empty proof on non-trivial script ---
TX4_JSON="{\"inputs\":[{\"boxId\":\"$SOURCE_BOX_ID\",\"spendingProof\":{\"proofBytes\":\"\",\"extension\":{}}}],\"dataInputs\":[],\"outputs\":[{\"value\":$((BOX_VALUE - 1000000)),\"ergoTree\":\"$SIMPLE_TREE\",\"creationHeight\":$HEIGHT,\"assets\":[],\"additionalRegisters\":{}}]}"
RESULT=$(submit_and_record "empty_proof_nontrivial" "SCRIPT" "$TX4_JSON" "")
if [ -n "$RESULT" ]; then
    [ "$FIRST" = true ] && FIRST=false || RESULTS="${RESULTS},"
    RESULTS="${RESULTS}${RESULT}"
fi

# --- Mutation 5: Missing input box ---
FAKE_ID="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
TX5_JSON="{\"inputs\":[{\"boxId\":\"$FAKE_ID\",\"spendingProof\":{\"proofBytes\":\"\",\"extension\":{}}}],\"dataInputs\":[],\"outputs\":[{\"value\":1000000,\"ergoTree\":\"$SIMPLE_TREE\",\"creationHeight\":$HEIGHT,\"assets\":[],\"additionalRegisters\":{}}]}"
RESULT=$(submit_and_record "missing_input_box" "STRUCTURAL" "$TX5_JSON" "")
if [ -n "$RESULT" ]; then
    [ "$FIRST" = true ] && FIRST=false || RESULTS="${RESULTS},"
    RESULTS="${RESULTS}${RESULT}"
fi

# --- Mutation 6: Output value too low ---
TX6_JSON="{\"inputs\":[{\"boxId\":\"$SOURCE_BOX_ID\",\"spendingProof\":{\"proofBytes\":\"\",\"extension\":{}}}],\"dataInputs\":[],\"outputs\":[{\"value\":1,\"ergoTree\":\"$SIMPLE_TREE\",\"creationHeight\":$HEIGHT,\"assets\":[],\"additionalRegisters\":{}}]}"
RESULT=$(submit_and_record "output_value_too_low" "MONETARY" "$TX6_JSON" "")
if [ -n "$RESULT" ]; then
    [ "$FIRST" = true ] && FIRST=false || RESULTS="${RESULTS},"
    RESULTS="${RESULTS}${RESULT}"
fi

# --- Mutation 7: No inputs ---
TX7_JSON="{\"inputs\":[],\"dataInputs\":[],\"outputs\":[{\"value\":1000000,\"ergoTree\":\"$SIMPLE_TREE\",\"creationHeight\":$HEIGHT,\"assets\":[],\"additionalRegisters\":{}}]}"
RESULT=$(submit_and_record "no_inputs" "STRUCTURAL" "$TX7_JSON" "")
if [ -n "$RESULT" ]; then
    [ "$FIRST" = true ] && FIRST=false || RESULTS="${RESULTS},"
    RESULTS="${RESULTS}${RESULT}"
fi

RESULTS="${RESULTS}]"

# Now get the Scala-serialized tx bytes for each mutation
# Pass the SAME source box ID to ensure deterministic box selection
echo "  Getting Scala-serialized bytes (source box: $SOURCE_BOX_ID)..." >&2
SCALA_CLI="${SCALA_CLI:-$HOME/.cache/scalacli/local-repo/bin/scala-cli/scala-cli}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
$SCALA_CLI run "$SCRIPT_DIR/scala/BuildMutations.scala" -- "$SOURCE_BOX_ID" \
  2>/dev/null > "$TMPDIR/scala_mutations.jsonl"

# Merge Scala hex bytes into results
python3 -c "
import json, sys
results = json.loads('''$RESULTS''')
scala = {}
with open('$TMPDIR/scala_mutations.jsonl') as f:
    for line in f:
        m = json.loads(line)
        scala[m['label']] = m['txHex']
for r in results:
    if r['label'] in scala:
        r['txHex'] = scala[r['label']]
# Also add source box JSON
import subprocess
box_json = subprocess.check_output([
    'curl', '-sf', '$NODE_URL/blockchain/box/byId/$SOURCE_BOX_ID'
]).decode()
for r in results:
    r['sourceBox'] = json.loads(box_json)
json.dump(results, open('$OUTPUT_FILE', 'w'), indent=2)
print(f'Wrote {len(results)} rejection vectors to $OUTPUT_FILE', file=sys.stderr)
" 2>&1

echo "Done." >&2
