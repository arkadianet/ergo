#!/usr/bin/env bash
set -euo pipefail

# Extract transaction bytes, headers, and Scala cost vectors for multiple
# block ranges across the Ergo mainnet.  Produces the three files per range
# that the cost_parity test needs:
#
#   transactions_<start>_<end>.json
#   headers_<start>_<end+300>.json
#   tx_costs_<start>_<end>.json
#
# Requires: scala-cli, running Ergo node with extraIndex enabled.
#
# Usage:
#   ./extract_all_cost_vectors.sh            # all ranges
#   ./extract_all_cost_vectors.sh 3           # only range #3
#   PARALLEL=4 ./extract_all_cost_vectors.sh  # 4 ranges in parallel

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/../mainnet"
NODE_URL="${NODE_URL:-http://localhost:9053}"
PARALLEL="${PARALLEL:-1}"

# ── Stratified ranges ────────────────────────────────────────────────
# 10 windows × 1000 blocks each, spanning the full chain history.
# Each covers a different era / contract family for maximum diversity.
RANGES=(
    # idx  start     end        description
    "1  500000  501000"   # early mainnet: P2PK, emission, basic scripts
    "2  700000  701000"   # oracle pools v2, early Spectrum, emission v1
    "3  750000  751000"   # pre-emission-change, oracle + AMM mix
    "4  889000  890000"   # JIT soft fork boundary (889856)
    "5  900000  901000"   # first JIT-era blocks
    "6  1000000 1001000"  # mature DeFi, lending protocols
    "7  1100000 1101000"  # Rosen Bridge relay scripts appear
    "8  1300000 1301000"  # dense modern traffic
    "9  1500000 1501000"  # near-current, broadest script diversity
    "10 1750000 1751000"  # chain tip, latest scripts
)

HEADER_PAD=300  # extra blocks beyond range end for header context

# ── Functions ────────────────────────────────────────────────────────

extract_range() {
    local idx=$1 start=$2 end=$3
    local header_end=$((end + HEADER_PAD))
    local tx_file="${OUT_DIR}/transactions_${start}_${end}.json"
    local hdr_file="${OUT_DIR}/headers_${start}_${header_end}.json"
    local cost_file="${OUT_DIR}/tx_costs_${start}_${end}.json"

    echo "━━━ Range $idx: blocks $start–$end ━━━" >&2

    # Skip files that already exist (idempotent re-runs)
    local need_tx=true need_hdr=true need_cost=true
    [[ -s "$tx_file" ]]   && need_tx=false   && echo "  transactions: exists, skipping" >&2
    [[ -s "$hdr_file" ]]  && need_hdr=false  && echo "  headers: exists, skipping" >&2
    [[ -s "$cost_file" ]] && need_cost=false && echo "  costs: exists, skipping" >&2

    if $need_tx; then
        echo "  [1/3] Extracting transactions..." >&2
        "${SCRIPT_DIR}/extract_transactions_batch.sh" "$start" "$end" "$tx_file" 2>&1 | sed 's/^/    /' >&2
    fi

    if $need_hdr; then
        echo "  [2/3] Extracting headers..." >&2
        "${SCRIPT_DIR}/extract_headers_batch.sh" "$start" "$header_end" "$hdr_file" 2>&1 | sed 's/^/    /' >&2
    fi

    if $need_cost; then
        echo "  [3/3] Computing Scala costs..." >&2
        "${SCRIPT_DIR}/extract_tx_costs.sh" "$start" "$end" "$cost_file" 2>&1 | sed 's/^/    /' >&2
    fi

    # Summary
    local n_tx n_cost
    n_tx=$(python3 -c "import json; print(len(json.load(open('$tx_file'))))" 2>/dev/null || echo "?")
    n_cost=$(python3 -c "import json; print(len(json.load(open('$cost_file'))))" 2>/dev/null || echo "?")
    echo "  ✓ Range $idx done: $n_tx transactions, $n_cost cost vectors" >&2
    echo "" >&2
}

# ── Main ─────────────────────────────────────────────────────────────

echo "╔══════════════════════════════════════════════════════════╗" >&2
echo "║  Cost Parity Vector Extraction — 10 Stratified Ranges   ║" >&2
echo "╠══════════════════════════════════════════════════════════╣" >&2
echo "║  Node:     $NODE_URL" >&2
echo "║  Output:   $OUT_DIR" >&2
echo "║  Parallel: $PARALLEL" >&2
echo "╚══════════════════════════════════════════════════════════╝" >&2
echo "" >&2

# Check node is reachable
if ! curl -sf "${NODE_URL}/info" > /dev/null 2>&1; then
    echo "ERROR: Ergo node not reachable at $NODE_URL" >&2
    echo "Start your node or set NODE_URL=http://host:port" >&2
    exit 1
fi

CHAIN_HEIGHT=$(curl -sf "${NODE_URL}/info" | python3 -c "import sys,json; print(json.load(sys.stdin)['fullHeight'])" 2>/dev/null || echo "unknown")
echo "Chain height: $CHAIN_HEIGHT" >&2
echo "" >&2

mkdir -p "$OUT_DIR"

# Filter to specific range if argument provided
SELECTED="${1:-all}"

if [[ "$SELECTED" == "all" ]]; then
    for entry in "${RANGES[@]}"; do
        read -r idx start end <<< "$entry"
        # Skip ranges beyond chain height
        if [[ "$CHAIN_HEIGHT" != "unknown" ]] && (( start > CHAIN_HEIGHT )); then
            echo "Skipping range $idx ($start–$end): beyond chain height $CHAIN_HEIGHT" >&2
            continue
        fi
        extract_range "$idx" "$start" "$end"
    done
else
    for entry in "${RANGES[@]}"; do
        read -r idx start end <<< "$entry"
        if [[ "$idx" == "$SELECTED" ]]; then
            extract_range "$idx" "$start" "$end"
            break
        fi
    done
fi

echo "════════════════════════════════════════════════════════════" >&2
echo "All extractions complete. Run the parity test:" >&2
echo "  cargo test -p ergo-validation --test cost_parity -- --nocapture" >&2
echo "════════════════════════════════════════════════════════════" >&2
