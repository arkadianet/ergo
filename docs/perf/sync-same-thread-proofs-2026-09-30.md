# Same-thread authenticated UTXO proof generation

Original baseline: `5d62fd5851e74fcb965b4aba50e1b423127f46f1`.
Intermediate prefetch baseline: `1a7a5d89b9909252333b1ce1a6f577f83dc1faf7`.

## Change

The upstream prover accepts a function-pointer resolver and stores its graph in non-Send `Rc<RefCell<Node>>` objects. Previously, a new scoped worker generated each proof and synchronously requested arena nodes from the owning thread. Prefetching reduced the number of requests, but preserved thread creation, blocking handoffs and speculative reads.

The final implementation constructs the prover graph on the arena owner's thread. A borrowed scoped callback adapts the function-pointer API using `scoped-tls-hkt` 0.1.5, a dependency with no transitive dependencies. The caller retains its arena or committed snapshot read view; nothing requires Send, a static reader, a vendored prover, or handwritten unsafe lifetime conversion. The callback is restored on both normal return and unwinding, including nested proofs.

Only visited nodes are loaded and authenticated against their expected parent labels. Untouched subtrees remain label stubs. Canonical operation order, generated proof bytes, verifier replay, header proof-hash comparison, full script validation and post-state root checks are retained. Database schema, cache budgets, pipeline queue size, batching limit, durability and quick-repair settings are unchanged. The same resolver also serves committed-snapshot proofs used by mining.

Added persistence diagnostics for writer acquisition, table mutation, commit and queue waits, including single-job transactions. Heartbeat and API publication timestamps now include time spent draining blocks earlier in the same tick, preventing that work from being omitted from throughput denominators.

## Replay method

The host is a Ryzen 7 7800X3D with 64 GiB RAM and an Intel Optane P1600X. Builds use the repository's Rust 1.95.0 toolchain and default release profile. No native CPU flags were added.

Two consistent snapshots were captured after clean service stops; the production service automatically restarted afterward. Each run rolls back and replays 150 historical blocks on a fresh disposable database copy on Optane. The initial copy is fsynced before timing. The service is paused during paired Optane runs to remove its competing writes and restarted in a finally block.

Each primary comparison has three runs per executable, alternating order. The same harness uses full script validation, a 2 GiB arena budget, queue depth 64, IBD flush interval 500 and undo retention 200. Timed duration includes replay, queued persistence, final durable flush and clean shutdown. It excludes copying, opening, rollback and the final verification reopen. After reopening, both height and authenticated root must match the original snapshot. All checks succeeded.

The original baseline executable uses the replay harness and phase counters from the intermediate branch with only the resolver restored to the original revision. The final executable includes the dormant diagnostic logging but does not enable its subscriber during timed comparisons. Binary checksums and all raw records are in [the results JSON](sync-same-thread-proofs-2026-09-30-results.json).

## Results

| Comparator and interval | Comparator median | Same-thread median | Throughput gain |
|---|---:|---:|---:|
| Original, blocks 650486–650635 | 3.285 s | 1.783 s | +84.2% |
| Original, blocks 678724–678873 | 4.576 s | 2.569 s | +78.1% |
| Prefetch, blocks 650486–650635 | 2.650 s | 1.787 s | +48.3% |

Median proof-phase time fell by 74.1% and 68.3% versus the original implementation on the two intervals, and by 62.6% versus intermediate prefetch on the first interval. Script validation and actual AVL application remain in the measured path.

These are offline replay results for 300 distinct historical blocks, each replayed repeatedly. They are not a measured live-network or whole-chain speedup. Copies and repeated reads affect the OS page cache; this is not a controlled cold-device benchmark. The existing shutdown code also polls its worker every 500 ms, contributing a roughly fixed shutdown floor in these short runs. That code was not changed. Do not multiply this report's ratios by the earlier report's ratio from a different interval.

## Persistence experiment

An Optane trace of the first interval recorded 46 persistence transactions for 150 blocks and no queue waits of at least 1 ms. Writer acquisition totaled 0.062 ms. Table mutation totaled 767.1 ms and commits 409.0 ms, overlapping foreground block processing. Because 150 blocks is less than the 500-block IBD flush interval, those individual commits were non-durable; the replay still includes its final durable flush. This trace does not reproduce or explain the 11–13 second periodic commit stalls seen in the earlier live diagnostic.

Coalescing repeated AVL mutations within existing atomic transactions was tested again after removing proof handoffs. It retained every block's undo and other records and passed a write/delete/reuse ordering regression. The first two-run comparison overlapped another local build/benchmark and appeared faster. A three-run repeat produced 2.425 s without coalescing versus 2.427 s with it: no useful replay improvement. The experimental code and test were removed. Its records are retained as discarded experiments, not evidence for the final speedup.

## Validation

- State library: 384 passed, 2 ignored; state integration: 361 passed, 4 ignored.
- Sync library: 289 passed; sync integration: 56 passed, 3 ignored.
- Node library: 824 passed, 3 ignored. Total selected passing tests: 1,914.
- Regression coverage includes canonical byte parity for large mixed batches, repeated lookups, nested success and panic recovery, independent concurrent readers, corrupt node rejection, legacy nodes, cold arena reads, uncommitted nodes, committed snapshots, rollback, persistence and restart.
- Formatting and whitespace checks, Clippy with warnings denied on affected targets, dependency policy/security checks, unused dependency check and release node build.

## Reproduction and remaining limits

Use the existing `scripts/bench-sync-replay.py` with the snapshot, baseline, candidate and disposable work-directory paths. Build each executable with `cargo build --release --locked -p ergo-sync --example replay_persist`, preserving it before changing source. Only capture snapshots after a clean node stop. The harness requires its disposable-copy marker and currently limits replay to 150 pre-EIP-27 blocks; it never opens the live database.

For transaction diagnosis only, set `ERGO_REPLAY_TRACE=1` when running the replay example directly on a marked disposable copy. For the installed node, the existing targeted `ergo_state::persist=debug` logging now exposes the extra phases, while heartbeat block timings already include `proof_ms`. Logging should be enabled for short diagnostic captures rather than during baseline timing comparisons.

Further live-sync work should correlate periodic state/indexer fsync stalls, contention from per-section foreground transactions and peer-delivery gaps. The executor can also synchronously drain an entire available run of blocks before servicing more events; bounded drains need an immediate continuation mechanism and reorg/wallet/relay validation to avoid replacing long stalls with idle timer waits. Independent transaction layers already use Rayon. Consecutive AVL state roots remain dependent, so spare CPU cores alone do not make whole blocks independently applicable.

The production service remains on its existing binary. The optimized release binary was built for review; these changes were not deployed by this investigation. Temporary snapshot files were removed after preserving the measurements.
