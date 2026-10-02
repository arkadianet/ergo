# Resource-safety and wire-codec measurements

These synthetic workloads make the compiler/evaluator allocation problem
repeatable and retain raw observations, rather than setting a timing threshold.
They do not estimate full-node throughput or allocator operation counts.

## Repeat the candidate workloads

```sh
cargo build --locked --release -p ergo-compiler --example resource_profile
cargo build --locked --release -p ergo-ser --example serialization_profile
/usr/bin/time -v target/release/examples/resource_profile 1000 > compiler.csv
target/release/examples/serialization_profile 1000 > serialization.csv
```

The compiler example independently compiles a version-3 fold over 1, 5, 10,
16, 32 and 64 items. Each step combines its accumulator with itself. It reports
source/tree bytes, logical and uniquely stored proposition nodes, evaluator and
crypto costs, compilation/reduction time and amortized clone/estimate time.
`stored_nodes` counts unique proposition addresses reachable from the result;
it is a storage-sharing measure, not a heap allocation counter. Logical size
saturates at `usize::MAX`; crypto cost saturates at Scala's signed-cost ceiling.
Those large cases measure reduction/ownership, not successful proof verification.

The old owned representation can be measured at `1ffa9c20` by copying the
example into a separate worktree, restricting its layer list to `[1,5,10,16]`
and replacing `prop.size()` with an iterative logical-node count (one per node,
four per DHT leaf). Run with 20 repeats. Do not run 32/64 layers on that revision:
the original representation expands every occurrence. Fixture setup and the
logical/stored-node walks are excluded from the operation timers.

## Recorded sample

[Raw CSVs and binary/host provenance](data/resource-safety-2026-10-03/provenance.json)
were captured on Linux with Rust 1.95.0, release optimization, before combined
subsystem integration. Other builds and desktop activity were present. Times
are observations from one process, not statistical speedup claims. The candidate
source was uncommitted when sampled and its exact tree hash was not captured;
retained binary hashes identify those runs but cannot bind them to an exact
source revision. The commands above reproduce the current workload.

| Fold steps | Logical nodes | Old stored nodes | Shared stored nodes | Old reduction, µs | Shared reduction, µs |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 3 | 3 | 3 | 30 | 31 |
| 5 | 63 | 63 | 11 | 19 | 8 |
| 10 | 2,047 | 2,047 | 21 | 494 | 11 |
| 16 | 131,071 | 131,071 | 33 | 32,314 | 18 |

The baseline process peaked at 50,904 KiB RSS over layers 1–16; the candidate
peaked at 5,184 KiB over layers 1–64. Different layer ranges and repeat counts
make these process totals illustrative, not a controlled allocation comparison.
The structural result is repeatable: shared storage grows linearly while
logical occurrences double. Cost-aware serialization and verification still
account for logical work before materializing it.

The codec workload reads all 26 committed mainnet `boxes_1759500.json` boxes
(2,225 wire bytes), checks canonical round trips before timing, then measures
parse/drop, allocated serialization and scratch-writer box-id hashing. One
warm-up sample is discarded; five samples perform 1,000 corpus repetitions.
Median observations were 410 ns parse, 152 ns write and 233 ns scratch-id per
box. This is a small, warm corpus with caller-supplied tree boundaries, not an
independent streaming-parser or cold-disk measurement.

## Related production-path workloads and limits

[Maintained replay profiles](replay-profiles.md) cover real state validation,
queued persistence, committed/durable boundaries, residency and clean reopen.
The [matched 1,000-block smoke](replay-profiles-2026-10-02.md) retains hashes,
workload dimensions and 12 complete records. The [remediation replay smoke](data/resource-safety-2026-10-03/state-replay-assurance.json)
repeated three 150-block constrained-profile runs on the integrated fixes,
retaining provenance, every raw sample and root/reopen checks. All three ended
at the expected mainnet root; host load was uncontrolled. The dataset is too
small to choose production cache budgets; a representative later-chain replay needs a closed,
consistent, separately owned snapshot. None is substituted with a live database.

[Node performance measurements](node-performance-2026-09-26.md) retain repeatable
indexer lookup/flush and mining publication workloads. API/mempool publication
measurements are recorded separately with explicit prepared-DTO/synthetic
validation exclusions. Microbenchmarks complement external replay and faults;
they do not establish power-cut durability, latency bounds or consensus parity.

[Scala resource/proof fixtures](../../scripts/jvm_sigma_growth_oracle/README.md)
separately establish canonical bytes, cost and verdict parity for bounded cases
and disclose the cached-size overflow domain. Unmetered verifier primitives
require trusted/bounded inputs; budgeted variants reject expensive logical proof
expansion before constructing the flat proof arena.
