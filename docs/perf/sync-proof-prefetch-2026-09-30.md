# Bounded node prefetch for UTXO proof generation

Base revision: `5d62fd5851e74fcb965b4aba50e1b423127f46f1`.
Worktree branch: `codex/sync-performance`.

## Problem and change

Local regeneration of a block's ADProofs uses a scoped worker because the upstream prover graph is not Send. The AVL arena remains on its owning thread. Previously, every expanded node required a blocking request/reply handoff between those threads, including nodes already in memory. On the measured historical interval, proof regeneration occupied most of the offline block-processing time; the old pipeline timing logs omitted that phase.

The reader now returns the requested node plus up to two levels of children (at most seven nodes). A per-proof LRU retains at most 128 speculative node copies. Nodes are still authenticated against their expected labels when the prover actually expands them. Unused child read errors do not reject an unvisited path; required-node errors still fail the proof. The upstream prover, canonical operation order, proof-hash comparison, script validation, and state-root verification remain in place. No unsafe code, database schema changes, or durability changes were introduced.

Added `proof_ms` to the block and heartbeat phase logs. Corrected comments and CLI help that incorrectly described redb 2.6.3 Eventual durability as asynchronous on Linux: its Unix file backend calls `File::sync_data`, and quick-repair uses two-phase commits.

AVL-write coalescing was explored but discarded: it helped an overlap-heavy synthetic workload without a meaningful improvement on the real-block replay.

## Benchmark method

- Host: AMD Ryzen 7 7800X3D, 64 GiB RAM, Pop!_OS; repository-pinned Rust 1.95.0, release builds.
- A clean service stop produced a consistent 12 GiB state database snapshot, then the unchanged production service resumed. No live database was opened by the benchmark.
- Both executables use the same benchmark harness and proof timing instrumentation. Only the lazy-prover implementation differs between baseline and candidate.
- Every run starts with a fresh disposable copy. The runner flushes the initial copy before timing, so copying 12 GiB is not charged to block processing.
- Roll back to height 563842, replay mainnet blocks **563843 through 563992**, and verify each block through the normal process_block path.
- Full transaction/script validation; no script checkpoint. Local proof regeneration, 2 GiB arena budget, queue depth 64, IBD interval 500, undo retention 200.
- Reported durable time includes replay, persistence drain, final durable flush and clean shutdown; excludes opening, rollback, snapshot copying and final reopen validation.
- Reopen after replay and assert the exact original height and authenticated state root.
- Alternate baseline/candidate order between repetitions. OS-drive comparison uses three runs per version with production sync continuing. Optane comparison uses two runs per version with the production node paused to remove competing disk writes.
- Network delivery, optional extra indexing, mining, wallet scanning and API scheduling are outside this offline replay benchmark. These results must not be presented as a measured live sync-speed improvement.

## Results

| Measurement | Baseline | Prefetch | Improvement |
|---|---:|---:|---:|
| Optane durable replay, median of two | 9.102 s | 6.662 s | 26.8% less time |
| Optane throughput from median time | 16.48 blocks/s | 22.52 blocks/s | 36.6% higher |
| Optane proof-generation phase | 6.791 s | 4.310 s | 36.5% less time |
| OS-drive durable replay, median of three | 10.333 s | 7.877 s | 23.8% less time |

The Optane result is the relevant storage comparison for this host. There were only two Optane runs per version and a single 150-block historical interval, so this does not establish a whole-chain speedup. OS-drive runs showed more variance with production sync active. All raw records are in [the results JSON](sync-proof-prefetch-2026-09-30-results.json).

The original authenticated root was restored in every run: `ee64f369c27d696f26cb665e5e05b8eb88ee1064e4e30d94dd52e34857003cca17`.

The unchanged production node was paused for 92.3 seconds for the Optane comparison and resumed automatically. The temporary snapshot and disposable replay databases were removed after preserving these measurements.

## Validation

All selected checks passed:

- ergo-state library: 381 passed, 2 ignored.
- ergo-state integration: 361 passed, 4 ignored.
- ergo-sync library: 289 passed.
- ergo-sync integration: 56 passed, 3 ignored.
- ergo-node heartbeat tests: 3 passed.
- Formatting, git diff whitespace checks and Clippy on all targets of the three affected crates with warnings denied.
- Release node build and repeated full-validation historical replay, including durable close/reopen root checks.

The two new regression tests cover failure on a corrupted prefetched leaf and tolerance of failed speculative reads on unvisited children. Existing tests cover byte-identical proof output against full hydration, mixed mutations, cold disk, uncommitted arena nodes, bounded path reads, legacy nodes, corrupted roots, failure recovery, committed snapshots, rollback and restart.

## Repeating the comparison

Build `cargo build --release --locked -p ergo-sync --example replay_persist` for each implementation. The baseline used this branch's benchmark harness and instrumentation with only `ergo-state/src/store/lazy_prover.rs` restored to the base revision. Preserve both executables before switching implementations.

Create a consistent offline snapshot only after a clean node stop, then resume the node. Never copy an actively written redb file. The replay executable requires a `.benchmark-copy` marker next to its disposable input; the runner creates that marker and removes its temporary copies automatically.

```sh
python3 scripts/bench-sync-replay.py \
  --snapshot /path/to/offline-snapshot.redb \
  --baseline /path/to/replay-baseline \
  --candidate /path/to/replay-prefetch \
  --work-dir /path/to/disposable-copies \
  --output /path/to/new-results.json \
  --runs 3 --blocks 150
```

The replay example intentionally refuses post-EIP-27 snapshots until their chain-spec re-emission rules are supplied. It runs without peers or API listeners. The benchmark needs enough free space for one snapshot-sized disposable copy at a time.

## Remaining investigation

Live logging also showed intermittent 11–13 second database commit stalls. This change reduces proof-processing latency; it does not establish the cause of those flush stalls or eliminate them. Further work should correlate actual flush latency, state and indexer write volume, foreground writer-lock waits and peer-delivery gaps. Keep quick-repair and crash/restart correctness while evaluating changes.

The existing heartbeat blocks/sec calculation can use a timestamp captured before lengthy tick work; the benchmark uses real elapsed time instead. No live binary deployment was performed for this change.
