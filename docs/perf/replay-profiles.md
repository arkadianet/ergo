# Maintained offline replay profiles

`ergo-node`'s `ibd_replay` example and `scripts/bench-ibd.py` compare
independent AVL and state-redb budgets, or two builds, on identical disposable
copies of a closed mainnet UTXO snapshot. A snapshot at any mainnet height is
supported when it retains the requested rollback interval, canonical headers,
block sections and voted-parameter history. Full transaction/script validation,
current voted parameters, EIP-27 rules and authenticated state roots run through
production `process_block`; no script checkpoint is used. Header PoW and
network acquisition are outside this body-replay workload.

## Prepare and run

Build before measuring, using the repository-pinned Rust toolchain:

```sh
CARGO_BUILD_JOBS=4 cargo build --release --locked -p ergo-node --example ibd_replay
```

For a self-contained smoke, prepare the committed first 1,000 mainnet blocks
in a new, owned directory. Preparation verifies real header PoW/difficulty,
section commitments, scripts, final root and a clean reopen. It generates the
proofs required by `verify-shipped` outside the measured interval:

```sh
target/release/examples/ibd_replay prepare /scratch/owned-smoke-seed
sha256sum /scratch/owned-smoke-seed/state.redb
```

A representative later-chain comparison requires a separately owned, closed,
consistent snapshot from the interval being investigated. Preserve its exact
file hash; rebuilding logically equivalent state can change allocation/layout.
Do not copy a running database. The runner takes an exclusive nonblocking
`flock` compatible with redb's Unix file ownership before hashing or copying;
a node-owned database or symlink is refused. It never opens the source through
redb, stops a service, or changes a node configuration.

```sh
python3 scripts/bench-ibd.py \
  --binary target/release/examples/ibd_replay \
  --source-commit "$(git rev-parse HEAD)" \
  --snapshot /scratch/owned-smoke-seed/state.redb \
  --snapshot-sha256 HASH_FROM_SHA256SUM \
  --output-dir /scratch/new-profile-results \
  --runs 3 --blocks 150 \
  --profile constrained:16:16 small_redb:1024:16 small_avl:16:1024 default:1024:1024
```

Profile syntax is `NAME:AVL_MIB:REDB_MIB`. Crossed budgets separate AVL effects
from database-cache effects. Zero explicitly disables the corresponding cache.
The default proof policy is `regenerate`, matching the current UTXO production
path. Pass `--proof-policy verify-shipped` to study retained network proofs as
an independent workload; do not compare different policies as a code speedup.
Persistence defaults are 64 input-channel jobs and IBD flush interval 500.
The rollback interval is checked against the store's retained window.

A code comparison additionally takes `--baseline-binary` and
`--baseline-source-commit`. Build the maintained example against both revisions
with the same flags and use identical snapshots, budgets, proof policy and
persist settings. The runner rotates profile/build order across iterations,
requires the same replay heights and final root, verifies clean reopen, and
checks that source and executable hashes remain unchanged. Every run has a
bounded timeout; only its own temporary directory is removed. Failed stdout,
stderr and partial memory samples remain available. Output directories must be
new.

## Interpret the results

The report retains per-run JSON, stdout/stderr, memory CSVs, source/binary hashes,
CPU/RAM/OS/filesystem/toolchain and load averages. `committed_seconds` includes
the persistence barrier; `durable_seconds` additionally includes clean shutdown.
The shutdown monitor can add roughly 0.5 seconds, so show both throughputs and
use longer intervals before drawing conclusions. The timer includes periodic
memory sampling. Phase sums do not equal wall time because persistence overlaps
validation. The proof phase is now measured separately.

Memory CSVs retain resident/anonymous/file samples, AVL clean occupancy, pinned
unpersisted AVL bytes, effective state-redb budget and active cumulative eviction
counts. Input-channel job counts exclude the current worker batch and result
queue. Observed peaks are lower bounds and a configured cache budget is not an
RSS measurement. The default three retained samples are a short idle
observation; use `--retained-seconds` to lengthen it. They do not prove absence
of leaks.

This workload excludes peer/event/download queues, indexing, wallet scans,
mining graphs and API load. Run a separate combined-load soak for those owners.
Do not overlap compilation or tests with matched comparisons. Warm OS page
cache is recorded honestly; no global cache drop is performed.

The early smoke's small working set cannot choose a universal mainnet budget.
The [September baseline](ibd-baseline-2026-09-30.md) also documents why its live
120-second RSS growth was neither a memory leak diagnosis nor a before/after
comparison. Use later intervals and long retained-memory observations before
changing production defaults.

## Read-only live observation

The maintained Linux sampler accepts an explicitly selected PID and public API
address. It records executable hash and process start identity to detect
restarts/PID reuse, rejects reorg windows as throughput comparisons, captures
mapping residency at both ends, and sends no signals:

```sh
python3 scripts/sample-live-ibd.py \
  --url http://127.0.0.1:9063 --pid NODE_PID \
  --output-dir /scratch/new-live-results --duration 600 --interval 1
```

Include sanitized deployment settings and build provenance. Public gauges are
sampled observations rather than cumulative phase timings. Read-only live
observations do not provide a controlled budget comparison.

Runner safety tests:

```sh
python3 scripts/test-bench-ibd.py
```
