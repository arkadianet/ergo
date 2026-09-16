#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
# Standard miner rewards mature after 720 blocks. campaign.py mines at least
# 720 difficulty-one blocks to scalar one, then funds the campaign wallet
# from a matured reward. It never substitutes spendable genesis allocations.
python3 scripts/devnet-mixed/campaign.py "$@"
