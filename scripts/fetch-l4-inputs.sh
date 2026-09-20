#!/usr/bin/env bash
# Fetch the L4 mainnet replay inputs (test-vectors/mainnet/*.json.gz) from the
# hash-pinned data release, verify them, and extract in place. Idempotent.
#
# The inputs are 1,179 gzip-compressed JSON captures (~208 MB) extracted from
# a Scala reference node for the 388 required replay ranges; they are too
# large to track in git and are published as a GitHub Release asset instead.
# Re-extracting from a node (test-vectors/scripts/extract_all_cost_vectors.sh)
# must reproduce the same bytes; the sha256 below pins the bundle CI uses.
set -euo pipefail
TAG="l4-inputs-2026-09-20"
ASSET="l4-inputs-2026-09-20.tar.gz"
SHA256="8b51c4873ea953eafa26047aa6f5a7f7fe7a03b9354847b704e3948a1e93bad8"
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
dest="$repo_dir/test-vectors/mainnet"
marker="$dest/.l4-inputs.sha256"
if [[ -f "$marker" && "$(cat "$marker")" == "$SHA256" ]]; then
  echo "L4 inputs already present ($SHA256)"; exit 0
fi
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
if command -v gh >/dev/null 2>&1; then
  gh release download "$TAG" --repo arkadianet/ergo --pattern "$ASSET" --dir "$tmp"
else
  curl --proto '=https' --tlsv1.2 --retry 5 --location --fail --silent --show-error \
    -o "$tmp/$ASSET" "https://github.com/arkadianet/ergo/releases/download/$TAG/$ASSET"
fi
echo "$SHA256  $tmp/$ASSET" | sha256sum --check --quiet
mkdir -p "$dest"
tar -xzf "$tmp/$ASSET" -C "$dest"
echo "$SHA256" > "$marker"
echo "L4 inputs extracted to $dest ($(ls "$dest"/*.json.gz | wc -l) files)"
