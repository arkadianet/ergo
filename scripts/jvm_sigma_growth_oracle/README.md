# Shared proposition oracle

`SigmaGrowthOracle.scala` independently compiles the accumulator-doubling
program with sigma-state 6.0.6 and records its canonical proposition digest,
logical size, evaluator/crypto costs and full verifier outcome. The verifier
uses an empty proof and a 100,000-block-unit limit. The small cases reject the
proof; the larger cases reject the crypto cost before proof verification.

Use Java 17, Scala CLI and locally published Ergo 6.0.6 jars as described in
`scripts/jvm_serde_oracle/ErgoSerdeOracle.scala`, then run from the repository:

```sh
scala-cli run scripts/jvm_sigma_growth_oracle/SigmaGrowthOracle.scala \
  --server=false --jvm 17 --suppress-outdated-dependency-warning -- \
  test-vectors/scala/sigma_shared_growth.json
cargo test --locked -p ergo-sigma --test it shared_fold
```

The fixture includes SHA-256 digests of the loaded reference artifacts. These
four bounded cases demonstrate preservation of reference results and costs;
they do not establish equivalence for every possible evaluator program.

The same generator creates and verifies five fresh Scala proofs combining AND,
OR and thresholds. Their committed proof bytes independently test traversal,
challenge propagation and Fiat-Shamir ordering, including wrong messages and
truncated challenges. Proof generation uses reference randomness, so reruns
produce different valid proofs rather than a byte-identical fixture file.

The `size_overflow_cases` inspect cheap shared graphs at 30–64 layers without
serializing them or recursively estimating their reference crypto cost. Scala's
cached signed `Int` size wraps; at 31+ doubling layers it is `-1`, and its raw
propBytes cost arithmetic returns 29 JIT. Rust's logical-size bookkeeping
saturates instead and an enforcing budget rejects oversized materialization.
These observations document the overflow domain; they do not claim full
Scala/Rust execution parity there. Running reference serialization for billions
of logical nodes would consume unbounded resources and is deliberately excluded.

The low-level verifier and hint extractor remain unmetered protocol primitives;
callers must precharge or bound logical size. Their new `*_with_cost` entrypoints
charge reference crypto cost before expanding proof nodes. Production spending
validation already performs that charge under the active protocol budget.
