# Node performance workstream

Integration target: `performance-improvements`. This initial work is on
`codex/node-performance`, based at `1136c5dd8edfae18995c4ef71952e866c9bc6636`.
Keep changes in individually reviewable commits. This branch is independent of
the dashboard PR and is not deployed to the running archival node.

## Extra-index reference and design

Scala's [Segment.findAndModBox](https://github.com/ergoplatform/ergo/blob/23aabead88774d27f2c9190ace3c9abbc8f1d5cb/src/main/scala/org/ergoplatform/nodeView/history/extra/Segment.scala#L63)
already binary-searches segment ranges and buffers the matching segment.
This is an algorithmic fit for Rust's existing ordered global box numbers;
there is no need to add a persisted box-to-segment locator or rebuild the index.
Rust must additionally preserve sign-aware duplicate consumption, including
duplicates crossing segment boundaries, and typed corruption errors.

The baseline implementation instead walks spills newest-to-oldest and stages
every visited row for writing. Ship selective writes and ordered lookup together:
an intermediate selective-write-only experiment reduced writes but made repeated
linear scans slower (4096-spill oldest-entry lookup pair: 116.174 ms), because
unchanged rows were no longer retained between lookups in the same block.

The Rust implementation borrows rows already staged for mutation and owns newly
decoded rows only temporarily, retaining the selected row. It searches spill
boundaries and then the matching equal-number range. Duplicate entries can cross
boundaries, so it checks older equal-number boundaries when necessary and keeps
the existing newest-first, sign-aware consumption order. Inspected rows are
validated; this is not a full scrub of unrelated segments. There is no schema,
wire-format or consensus change, and no extra persistent index.

## Reproducible segment measurement

Run from the repository root:

```text
cargo test -p ergo-indexer --lib historical_spend_benchmark -- --ignored --nocapture --test-threads=1
```

Environment: Windows, Ryzen 9 5950X (16 cores / 32 threads), 128 GiB RAM;
default workspace test profile (`opt-level = 1`). A live node is also running,
so wall-clock timings are illustrative rather than a controlled machine-wide
comparison. The fixture uses a separate temporary redb database, 512 entries
per spill, one warm-up and five measured samples per case. Lookup is a
spend/unspend pair; flush includes the transaction commit with production
`Eventual` durability and quick repair. Each sample restores the same logical
history. Setup is excluded. Reported times are medians.

This is a synthetic segment hot-path benchmark, not a measurement of complete
block indexing or a forecast of live-node speedup. Staged-row counts are exact;
they count writes requested, not physical disk writes.

| Version | Spills | Target | Lookup pair, ms | Flush + commit, ms | Staged rows |
| --- | ---: | --- | ---: | ---: | ---: |
| Baseline | 64 | Oldest | 0.512 | 10.454 | 64 |
| Baseline | 64 | Middle | 0.245 | 11.072 | 32 |
| Baseline | 64 | Head | <0.001 | 10.893 | 0 |
| Baseline | 4096 | Oldest | 32.308 | 59.298 | 4096 |
| Baseline | 4096 | Middle | 15.751 | 36.641 | 2048 |
| Baseline | 4096 | Head | <0.001 | 8.750 | 0 |
| Ordered lookup + selective writes | 64 | Oldest | 0.080 | 9.519 | 1 |
| Ordered lookup + selective writes | 64 | Middle | 0.061 | 9.475 | 1 |
| Ordered lookup + selective writes | 64 | Head | 0.001 | 9.508 | 0 |
| Ordered lookup + selective writes | 4096 | Oldest | 0.159 | 8.394 | 1 |
| Ordered lookup + selective writes | 4096 | Middle | 0.144 | 8.326 | 1 |
| Ordered lookup + selective writes | 4096 | Head | <0.001 | 8.192 | 0 |

Lookup-change validation: 180 unit tests and 142 integration tests pass, plus the manual
benchmark above. Added regression tests compare against the previous linear
semantics across duplicates, boundaries, gaps and rollback; enforce at most 14
spill reads for an oldest entry among 4096 spills; check unchanged persisted
rows; and retain fatal errors for malformed or missing inspected rows.

A direct box-to-segment locator remains an alternative if whole-block profiling
shows this lookup is still material. It would add storage, write amplification,
migration and rollback maintenance; the current measured improvement does not
justify that complexity yet.

## Resident-memory measurement

The live RSS sampler now uses the existing `sysinfo` dependency off Linux,
refreshing only this process. Windows reports working-set bytes converted to
KiB, consistent with the host endpoint; Linux retains `smaps_rollup`. This fixes
the misleading zero in `/metrics` on Windows. It measures total resident memory,
not ownership by the AVL cache, mining graph or redb caches, and does not itself
reduce memory consumption.

## Dedicated extra-index worker

The persistent catch-up loop now runs on one named OS thread. The driver uses
ordinary blocking waits; database reads, writes and rebuilding stay off the
shared node runtime, without creating a second runtime. Tokio is now a test-only
dependency of the indexer crate. Within this workspace, `IndexerTask::run` becomes
blocking and node boot uses `IndexerTask::spawn` instead of `tokio::spawn(run(...))`.
This follows [Tokio's guidance for long-lived blocking workloads](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html#when-to-use-spawn_blocking-vs-dedicated-threads).
It retains the single writer, per-block transaction boundaries, retry and reorg
semantics. It does not parallelize block application or promise higher indexing
throughput.

Idle/retry waits check cancellation at most every 50 ms, including when a long
idle interval is configured. Explicit node shutdown joins the worker after its
current atomic step or cancellable rebuild chunk. A slow step produces a warning
after five seconds and remains awaited: aborting a blocking write cannot safely
release its database ownership. Dropping the worker requests cancellation, also
covering failure during node boot; callers requiring a completed drain must join.

Tests hold a chain read blocked while a single-threaded host runtime runs a timer,
verify join waits for that read, exercise reorg/cancellation, and reopen the index
database after shutdown. A node integration test boots and shuts down twice with
a 60-second idle interval, checking the public status API and immediate DB reopen.

## Validation of the combined branch

- `cargo fmt --all --check` and Clippy for all targets of `ergo-indexer`,
  `ergo-node`, and `ergo-api` with warnings denied: pass.
- Indexer: 180 unit + 145 integration tests pass; the ignored manual benchmark
  was also run separately as documented above.
- API: 407 unit + 857 integration tests pass (4 integration tests ignored).
- Node: 84 integration tests pass, including the added worker lifecycle test.
  The combined parallel unit run had 742 passing tests, 2 ignored, and one
  failure in the existing
  `match_boxes_registry_load_failure_invalidates_for_rescan` test. Its isolated
  rerun passes. That unchanged test calls a hook gated by the process-wide
  `SCAN_REBUILD_IN_PROGRESS` flag while other tests mutate that flag; it has
  also failed in earlier work outside this branch. This parallel run is not
  reported as fully green, and the wallet test is not changed here.

## Follow-up gates

- Validate each change against indexer apply, rollback, duplicate-token and
  repair tests. Preserve on-disk encoding and schema version.
- Measure a fixed historical block interval before claiming end-to-end gains.
  Record blocks/transactions/boxes per second, phase time, write traffic and
  peak/retained memory.
- Evaluate bounded apply batching only after identifying remaining commit
  overhead. Preserve durable checkpoints, reorg handling and prompt shutdown.
- Keep cache budgets separate: the existing `store.cache_bytes` controls the
  AVL arena, not redb's per-database caches or mining's retained prover graph.
- Attribute retained mining memory and record cold-cache fallback reasons
  before changing prover storage or adding multi-block advancement. Existing
  root/proof equivalence and failure-poisoning safeguards must remain.
