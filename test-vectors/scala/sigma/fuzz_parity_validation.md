# Fuzz seed reference verdicts

`fuzz_parity_validation.tsv` contains actual JVM sigma-state 6.0.2 results,
captured 2026-09-28 using Scala 2.12.20 and activated version 3. Tree versions
come from their headers. The capture tool is
`scripts/jvm_serde_oracle/ReviewRegressionOracle.scala`.

Replay by selecting TSV columns 1, 2 and 5 into `inputs.tsv`, then running:

```sh
scala-cli run scripts/jvm_serde_oracle/ReviewRegressionOracle.scala -- inputs.tsv
```

The four uppercase names are the exact crash seeds embedded in the difftest
tests. The tree seed throws ClassCastException because its BlockValue item list
contains a constant. The sigma-expression seed rejects an unresolved SBox method
in a sizeless tree. Neither is evidence for accepting arbitrary cast rewrites.

The header constant accepts, consuming 213 bytes. The box candidate accepts a
41-byte prefix of its 104-byte input; this is a prefix-deserialization fixture,
not a claim that the entire input is a well-formed box candidate.

The final two rows isolate the non-binding BlockValue item rejection under
sizeless and sized headers. Its ClassCastException is never soft-fork-wrapped.

Rows from `cc_item_type_mismatch` on were captured 2026-09-29 with the same
tool, which gained a `tx` surface (`ErgoLikeTransactionSerializer.parse`).
`ConcreteCollectionSerializer.parse` asserts that every item's type equals the
declared element type. The `AssertionError` is not a `ValidationException`, so
the sized variant is rejected rather than wrapped. `nightly_20260929_transaction`
is the scheduled-run crash that exposed it: a context-extension collection of
`Coll[Boolean]` holding an empty `Coll[Short]` constant. `scheduled_20260929_constant`
is the same run's constant crash, which both implementations reject.
