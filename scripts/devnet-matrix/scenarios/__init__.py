"""The M3 campaign's scenarios (plan 2 task 9).

Each module states the node set it needs (`NODES`), any config the
scenario moves (`RUST_OVERRIDES`, `SCALA_EXTRA`), and a `run(ctx)` that
records what it observed on `ctx` and fails loudly for anything it could
not observe. `campaign.py` owns starting, stopping and evidence.
"""
from . import evict, flood, fork, reconstruct_rate, restart, rollback, steady

SCENARIOS = {
    'steady': steady,
    'fork': fork,
    'rollback': rollback,
    'reconstruct_rate': reconstruct_rate,
    'restart': restart,
    'evict': evict,
    'flood': flood,
}
