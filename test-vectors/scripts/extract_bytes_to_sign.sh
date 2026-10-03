#!/usr/bin/env bash
# Compare all saved messages with the pinned Scala implementation. Mismatches
# and helper failures remain in the output report and cause a nonzero exit.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_dir/verify_bytes_to_sign.py" "$@"
