#!/usr/bin/env bash
# Fetch or repair the hash-pinned L4 replay inputs. The tracked manifest binds
# all 1,179 compressed captures to the published archive. A readiness marker is
# accepted only when every expected capture is present with the pinned hash.
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$repo_dir/scripts/l4_inputs.py"
