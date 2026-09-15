#!/usr/bin/env bash
# Every point is executed independently by the pinned JVM oracle.
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
exec python3 scripts/gen_cost_sweep.py "$@"
