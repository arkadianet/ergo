# Resource-safety and wire-codec measurements

These synthetic workloads make the compiler/evaluator allocation problem
repeatable and retain raw observations, rather than setting a timing threshold.
They do not estimate full-node throughput or allocator operation counts.

## Run the workloads

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

## Wire-codec workload

The codec workload reads all 26 committed mainnet `boxes_1759500.json` boxes
(2,225 wire bytes), checks canonical round trips before timing, then measures
parse/drop, allocated serialization and scratch-writer box-id hashing. One
warm-up sample is discarded; five samples perform 1,000 corpus repetitions.
This is a small, warm corpus with caller-supplied tree boundaries, not an
independent streaming-parser or cold-disk measurement.

## Related production-path workloads and limits

[Maintained replay profiles](replay-profiles.md) cover real state validation,
queued persistence, committed/durable boundaries, residency and clean reopen.
A representative later-chain replay needs a closed, consistent, separately owned
snapshot. Microbenchmarks complement external replay and faults; they do not
establish power-cut durability, latency bounds or consensus parity.

[Scala resource/proof fixtures](../../scripts/jvm_sigma_growth_oracle/README.md)
separately establish canonical bytes, cost and verdict parity for bounded cases
and disclose the cached-size overflow domain. Unmetered verifier primitives
require trusted/bounded inputs; budgeted variants reject expensive logical proof
expansion before constructing the flat proof arena.
