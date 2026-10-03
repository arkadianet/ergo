#!/usr/bin/env bash
# Generate all Scala mutation bytes/JSON before submitting them. Publish only a
# complete set of structured validation rejections observed at one stable tip.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_dir/rejection_corpus.py" "$@"
