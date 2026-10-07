Run with Java 21, Scala CLI, and locally published ergo-core / ergo-wallet 6.0.7:

```bash
export COURSIER_REPOSITORIES='ivy2Local|https://repo.maven.apache.org/maven2'
scala-cli run scripts/reemission_rules_oracle/ReemissionRulesOracle.scala \
  --server=false --jvm system -- /path/to/ergo-v6.0.7/src/main/resources \
  test-vectors/reference-6.0.7/reemission/spending.json
```

Each allocation and reward-spending case runs through `validateStateful` with
`checkReemissionRules` both off and on. The JSON includes transaction and input
box bytes, verdicts, and accepted costs; the companion TSV records those outcomes.
