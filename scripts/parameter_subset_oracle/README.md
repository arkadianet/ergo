With Java 21, Scala CLI, locally published ergo-core / ergo-wallet 6.0.7:

```bash
export COURSIER_REPOSITORIES='ivy2Local|https://repo.maven.apache.org/maven2'
scala-cli run scripts/parameter_subset_oracle/ParameterSubsetOracle.scala \
  --server=false --jvm system -- /path/to/ergo-v6.0.7/src/main/resources \
  test-vectors/mainnet/headers_1_2000.json \
  test-vectors/reference-6.0.7/block-cost/remainders.json \
  test-vectors/reference-6.0.7/parameters/subsets.json
```

Each core-id omission and the complete-table control goes through
`ErgoStateContext.appendFullBlock` and `ErgoTransaction.validateStateful`. The
following block reuses the adopted table, with interlinks validation isolated
by omitting the previous extension. The oracle also records storage-rent
fallback with the fee parameter present or absent. Rust tests check parsing,
epoch validation, both block validators, persistence and the script fallback.
