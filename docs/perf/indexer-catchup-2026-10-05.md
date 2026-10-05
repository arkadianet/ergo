# Archival indexer catch-up, October 5, 2026

While more than 32 blocks behind the applied tip, the driver now groups up to
256 blocks, one second of work or 32 MiB of serialized transactions into one
redb write transaction. Within 32 blocks of the tip it commits each block, so
API readers and rent self-claims see new blocks promptly. These limits replace the 16-block,
50-ms and 8-MiB batches of the
[September 26 note](indexer-batches-2026-09-26.md). Budgets and cancellation
are checked between blocks, so one large block can exceed a budget; it still
finishes atomically. Only one decoded block is loaded at a time.

Every block still writes its own undo, metadata and rollback-window pruning.
Readers see the previous checkpoint until a batch commits. Apply errors, chain
read errors and detected fork changes abort the whole uncommitted batch; missing
later sections and cancellation commit the completed prefix; a repair marker
ends the batch before the existing repair gate runs. Observers receive block
changes in order, after commit.

The writer scratch also retains template hashes across blocks, keyed by exact
script bytes and bounded by 4,096 keys and 4 MiB of retained keys. Failed
derivations are never retained. Only the current derivation is memoized; the
fixed legacy derivation used by migration fixtures always derives.

## Durability

Every catch-up commit keeps `Durability::Immediate` and redb quick repair.
redb 4 offers only `None` and `Immediate`. State commits its applied chain with
`None` during initial sync, so after a hard crash the index can hold blocks
that State no longer has; the task waits for State to reapply them unless the
best-header chain shows a competing branch. Committing intermediate index
batches with `None` would need a defined checkpoint contract between the two
databases and was not attempted.

## Measurement

A read-only mainnet archive (all block sections to height 1,887,400, converted
to redb 4) is replayed through the real `IndexerTask` into a fresh index. The
harness opens the archive with `redb::ReadOnlyDatabase` and writes only under
the worktree's `target/`. `legacy` runs the previous budgets without the
template-hash cache; `adaptive` runs the new defaults.

```bash
cargo test --locked --profile release-prof -p ergo-indexer --lib --no-run
# EXE: the ergo_indexer unit-test executable Cargo reports.
python3 scripts/benchmark-indexer-catchup.py --executable "$EXE" \
  --state "$ARCHIVE" --end 10000 --name early --modes legacy adaptive
# Build a base index once, then time continuations from copies of it.
INDEXER_BENCH_STATE="$ARCHIVE" INDEXER_BENCH_END=900000 \
  INDEXER_BENCH_INDEX="$PWD/target/indexer-bench/base.redb" \
  INDEXER_BENCH_MODE=adaptive "$EXE" --exact \
  task::task_mainnet_bench::benchmark_archival_catchup --ignored --nocapture
python3 scripts/benchmark-indexer-catchup.py --executable "$EXE" \
  --state "$ARCHIVE" --base "$PWD/target/indexer-bench/base.redb" \
  --end 910000 --name dense --modes legacy adaptive
```

The runner takes one warm-up and three measured samples per mode, rotates
their order, and copies and fsyncs the base before each continuation; copying
and opening are outside the timed interval. It then compares every row of
every table in the final indexes. CPU seconds sum process user and system
time; written bytes are the process's `/proc/self/io` `write_bytes`.

## Results

Ryzen 7 7800X3D (8 cores, 16 threads), 61 GiB RAM, Linux 7.1.5, release-prof
build, 1 GiB redb cache for the archive and for the index. Other work ran on
the host, so wall-clock figures are noisy. Medians of three runs, with
minimum–maximum in brackets.

### Early chain: genesis to height 10,000

| Mode | Blocks/s | CPU seconds | Commits | Written |
| --- | ---: | ---: | ---: | ---: |
| legacy | 1,965 [1,961–1,988] | 1.76 [1.76–1.78] | 625 | 265 MB |
| adaptive | 6,042 [5,609–6,085] | 1.14 [1.13–1.15] | 71 | 105 MB |

### Dense history: heights 900,001 to 910,000

| Mode | Blocks/s | CPU seconds | Commits | Written |
| --- | ---: | ---: | ---: | ---: |
| legacy | 69.1 [67.5–81.4] | 81.1 [79.3–83.5] | 1,055 [1,031–1,066] | 98 GB [51–140] |
| adaptive | 101.8 [85.0–103.2] | 56.3 [55.7–56.3] | 107 [101–110] | 67 GB [62–90] |

MB and GB are 10^6 and 10^9 bytes. In the early chain, adaptive catch-up is
3.1 times faster and writes 61% fewer bytes. In dense history it is about 1.5
times faster and uses 31% less CPU: commit time per run halves (51 to 25
seconds) and the template-hash cache cuts apply time by 13% (83 to 72 seconds).
Bytes written in dense history varied by up to 2.8 times between identical
runs, so this measurement does not establish a reduction there. Both modes'
final indexes are identical in every table.

## Where dense time goes

Batching removes per-commit overhead, which dominates small early blocks. In
dense history most time is CPU spent applying blocks. Two 30-second
`perf record` samples of earlier builds of this change attribute the largest
self-time to VLQ decoding, allocation and freeing, memory copies, redb page
reads, script parsing and segment decoding and validation. Loading blocks
takes under a tenth of the time. Faster full rebuilds need less work inside
apply, or per-block deltas prepared in parallel ahead of the writer, rather
than fewer commits.

Also tried and not retained: overlapping the next block's decode with the
current apply, a 4 GiB index cache, shorter budgets, and per-block spill-bound
probes. None measurably improved the dense range.

## Validation

Tests compare adaptive catch-up with per-block commits in every table, including
after reopening, after rollback across a committed batch boundary, at the
maximum batch with undo pruning and spills, and after resuming a cancelled
prefix. A subprocess exits without running destructors both inside an
uncommitted batch and after a committed one; the reopened index resumes to the
same rows. Other tests cover the block, byte and time budgets, per-block
commits near the tip, and the template-hash cache's reuse and bounds. These
abrupt-exit tests exercise redb recovery; they do not simulate power loss.
