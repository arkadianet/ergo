With Java 21, Scala CLI and locally published ergo-core / ergo-wallet 6.0.7:

```bash
export COURSIER_REPOSITORIES='ivy2Local|https://repo.maven.apache.org/maven2'
scala-cli run scripts/rule_gating_oracle/RuleGatingOracle.scala \
  --server=false --jvm system -- /path/to/ergo-v6.0.7/src/main/resources \
  test-vectors/reference-6.0.7/rule-gating/transactions.json
scala-cli run scripts/rule_gating_oracle/BlockRulesOracle.scala \
  --server=false --jvm system -- /path/to/ergo-v6.0.7/src/main/resources \
  test-vectors/mainnet/headers_1_2000.json \
  test-vectors/reference-6.0.7/block-cost/remainders.json \
  test-vectors/reference-6.0.7/rule-gating/blocks.json
```

The transaction oracle serializes and reparses transactions and input boxes
before calling `ErgoTransaction.validateStateful`. It records the size-limit
parse controls as well as acceptance-changing node rule deactivations and
successful costs. The block oracle calls `ErgoStateContext.appendFullBlock`
with each rule active or disabled, including epoch parsing and adopted
settings. Rust tests run both full block validators; unavailable prior context
(rule 413) uses their shared extension helper. The settings replacement is also
checked through forward apply, restart and rollback in the state store.

Rule 118 is registered but unused in the reference node; rule 403 cannot be
deactivated; rule 414 is absent from the initial node rule map and remains
active even if listed in an update. Disabling rules 408/411 does not suppress
the mandatory subsequent `validateTry` parse failure. Oversized propositions
and 255-token standalone boxes remain rejected by the wire reader position
limit. A 123-token box passes parsing and becomes valid with rule 120 disabled.
