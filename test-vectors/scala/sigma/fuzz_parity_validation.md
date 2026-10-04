# Fuzz seed reference verdicts

`fuzz_parity_validation.tsv` contains actual JVM sigma-state 6.0.6 results,
captured 2026-09-30 using Scala 2.12.20 and activated version 3. Tree versions
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
`Coll[Boolean]` holding an empty `Coll[Short]` constant; since sigma-state 6.0.5 it is
rejected before that collection is read (see below). `scheduled_20260929_constant`
is the same run's constant crash, which both implementations reject.

The `tagged_var_*` rows pin `TaggedVariableSerializer` reading a type after the
id. The `option_get_apply_xor`, `apply_*`, `box_reshape_reencoded` and
`pr435_fuzz_*` rows pin Scala's `Apply.tpe`, where a callee that is not a
function or collection gives `NoType`.

Later rows pin the comparison builder constraints (`lt_*`, `eq_*`), a numeric
cast used as an `Apply` callee, zero-length big integers, and the reader-wide
binding store: `tx_valuse_bound_by_prior_output` is accepted because the first
output's `ValDef` stays visible to the second output's tree. The `pr435_*`
rows are fuzz inputs from this branch's CI and local runs.

Since sigma-state 6.0.5, `ContextExtension.serializer.parse` rejects a negative
variable id with `SerializerException` ("Negative id of context extension
variable") before reading its value. Three `tx` rows have such an id in their
first input's extension and reject there: `nightly_20260929_transaction` and
`pr435_ci_tx_cc_tuple_item` (id byte 0x97, -105), and
`pr435_local_tx_box_lookahead` (id byte 0xd9, -39). So these three rows no longer
reach the collection-item assertion or the retained-box lookahead. The
`cc_item_*`, `cc_tuple_item_*` and `box_lookahead_prefix` rows still cover those.

`pr435_ci_bigint_zero_len` is a zero-length `SBigInt` inside a nested box's tree.
The `NumberFormatException` from `new BigInteger` is an `IllegalArgumentException`.
`ErgoTreeSerializer.deserializeErgoTree` catches that and rethrows it as a
`SerializerException`, so the row records `SerializerException`, not the bare
`NumberFormatException` that the standalone `bigint_zero_len` constant throws.
