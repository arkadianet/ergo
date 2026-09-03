#!/usr/bin/env bash
# capture-utxo-manifest.sh — capture a Scala-produced UTXO snapshot manifest
# and the header state_root at the same height, as an oracle fixture for
# `verify_manifest_against_state_root` (ergo-sync snapshot bootstrap, Mode 2).
#
# The consume-side trust rule is `manifest_id == state_root[..32]`. That rule
# is currently pinned only against our own serve-side construction — a
# self-oracle. This script produces the external vector that replaces it.
#
# Usage:
#   scripts/capture-utxo-manifest.sh <node-url> <height> [out-file]
#
#   <node-url>  Scala node REST base, e.g. http://127.0.0.1:9062
#   <height>    Snapshot height to capture (must appear in
#               /utxo/getSnapshotsInfo on that node)
#   [out-file]  Defaults to
#               test-vectors/testnet/utxo_snapshot_manifest_<height>.json
#
# The node must be running with `ergo.node.utxo.storingUtxoSnapshots > 0` and
# must already have produced the snapshot at <height> (snapshots are made every
# `makeSnapshotEvery` blocks; the node only stores them going forward, so this
# is a wall-clock wait after reconfiguring).
#
# After capturing, un-ignore `manifest_prefix32_rule_matches_scala_manifest`
# in ergo-sync/src/snapshot_bootstrap/tests.rs and run:
#   cargo test -p ergo-sync manifest_prefix32_rule_matches_scala_manifest -- --ignored

set -euo pipefail

if [ $# -lt 2 ]; then
    sed -n '2,27p' "$0"
    exit 2
fi

NODE_URL="${1%/}"
HEIGHT="$2"
OUT="${3:-test-vectors/testnet/utxo_snapshot_manifest_${HEIGHT}.json}"

command -v jq >/dev/null || { echo "error: jq is required" >&2; exit 1; }

echo "==> /utxo/getSnapshotsInfo"
SNAPSHOTS="$(curl -fsS "${NODE_URL}/utxo/getSnapshotsInfo")"

# Scala serves availableManifests as { "<height>": "<manifestId>", ... }.
MANIFEST_ID="$(printf '%s' "$SNAPSHOTS" | jq -r --arg h "$HEIGHT" '
    (.availableManifests // {}) | to_entries
    | map(select(.key == $h)) | .[0].value // empty')"

if [ -z "$MANIFEST_ID" ]; then
    echo "error: node advertises no manifest at height ${HEIGHT}." >&2
    echo "available: $(printf '%s' "$SNAPSHOTS" | jq -c '.availableManifests // {}')" >&2
    exit 1
fi

echo "==> /blocks/at/${HEIGHT}"
HEADER_ID="$(curl -fsS "${NODE_URL}/blocks/at/${HEIGHT}" | jq -r '.[0]')"
[ -n "$HEADER_ID" ] && [ "$HEADER_ID" != "null" ] || {
    echo "error: no block id at height ${HEIGHT}" >&2; exit 1; }

echo "==> /blocks/${HEADER_ID}/header"
HEADER="$(curl -fsS "${NODE_URL}/blocks/${HEADER_ID}/header")"
STATE_ROOT="$(printf '%s' "$HEADER" | jq -r '.stateRoot')"

mkdir -p "$(dirname "$OUT")"
jq -n \
    --argjson height "$HEIGHT" \
    --arg manifest_id "$MANIFEST_ID" \
    --arg header_id "$HEADER_ID" \
    --arg state_root "$STATE_ROOT" \
    --arg source "$NODE_URL" \
    --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{height: $height,
      manifest_id: $manifest_id,
      header_id: $header_id,
      state_root: $state_root,
      source: $source,
      captured_at: $captured_at}' > "$OUT"

echo "==> wrote ${OUT}"
cat "$OUT"

# Local sanity check of the rule this fixture exists to pin.
PREFIX="$(printf '%s' "$STATE_ROOT" | cut -c1-64)"
if [ "$PREFIX" = "$MANIFEST_ID" ]; then
    echo "==> prefix-32 rule HOLDS on this capture"
else
    echo "==> prefix-32 rule DOES NOT hold on this capture — the Rust consume-side" >&2
    echo "    trust check is wrong and must be corrected before Mode 2 is trusted." >&2
    exit 3
fi
