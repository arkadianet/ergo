Run with Java 21, Scala CLI, and locally published ergo-core / ergo-wallet 6.0.7:

```bash
export COURSIER_REPOSITORIES='ivy2Local|https://repo.maven.apache.org/maven2'
scala-cli run scripts/block_cost_oracle/BlockRemainderOracle2.scala \
  --server=false --jvm system -- /path/to/ergo-v6.0.7/src/main/resources \
  test-vectors/reference-6.0.7/block-cost/remainders.json
```

The oracle calls `ErgoTransaction.validateStateless` and `validateStateful`,
threading accumulated block cost as `ErgoState.execTransactions` does. The JSON
records wire bytes, verdicts, per-transaction costs and failed transaction names.
The companion TSV lists transaction order, block limit, verdict, accumulated
accepted cost and failed transaction. `reference_block_cost` checks both Rust
full-block validators against the JSON.

`BlockBudgetProbeOracle.scala` uses the same invocation, writing `budget-probes.json`.
It records the pre-A6 deserialization budget check that is discarded from the
returned cost, including the first accepting boundary and reversed block order.

`BlockRecoveryBudgetOracle.scala` writes `recovery-probes.json` under block version 4,
with rule 1000 replaced. It pins discarded embedded-script checks during soft-fork
recovery, using the same ordered/reversed and single-transaction controls. The
Rust tests fold checked peaks separately from returned costs for these cases.
