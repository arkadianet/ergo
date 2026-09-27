# Bounded indexer catch-up transactions

The driver groups consecutive canonical blocks into one redb write transaction,
stopping after 16 blocks, 50 ms of work, or 8 MiB of serialized transaction data.
Limits are checked between blocks: one slow or large block still completes,
and the byte counter is not a strict memory limit. Only one decoded block is
loaded at a time. `step()` retains its single-block contract; the driver uses
`step_batch()`. Database schema and Eventual durability remain unchanged.

Each block still writes its own undo, metadata, and rollback-window pruning.
Readers see only committed batch checkpoints. Missing later sections or
cancellation commit the completed prefix; apply errors and detected fork flips
abort the entire uncommitted batch. Secondary-index drift ends the batch so
the existing repair gate runs before further apply or rollback work.

## Measurement

```powershell
cargo test -p ergo-indexer --lib benchmark_mainnet_index_batches -- --ignored --nocapture --test-threads=1
```

September 26, 2026, Windows / Ryzen 5950X / 128 GiB RAM / NVMe, workspace test
profile (`opt-level = 1`). The fixture replays the repository's first 200
mainnet blocks into a new database. Database creation is outside the measured
driver loop. One warm-up precedes five measured samples; these are medians.

| Block limit | Commits in last sample | Elapsed |
| ---: | ---: | ---: |
| 1 | 200 | 2,056.924 ms |
| 4 | 50 | 509.802 ms |
| 16 | 13 | 157.334 ms |

These early blocks are small and mostly emission transactions. This measures
commit overhead on that fixture, not expected full-chain sync duration or
today's larger-block workload. Busy blocks may hit the time/byte thresholds
before the block limit, reducing batching's benefit. No live deployment was
used, and filesystem/device power-loss behavior was not tested.

## Validation

The full indexer suite passes (184 unit tests, 142 integration tests, one
manual benchmark ignored in normal runs). Additional coverage compares batches
against single commits over the 200-block interval, including boxes, address
segments, transactions, rent rows, metadata and per-height undo. It rolls back
ten blocks across batch boundaries and compares with a fresh index at that tip.

Tests also cover reader visibility, mid-batch fork changes, missing sections,
cancellation and budgets, failed-batch scratch reuse, reopen after abort and
commit, and secondary-index repair before continuing forward. All-target Clippy
with warnings denied passes for the indexer and node.
