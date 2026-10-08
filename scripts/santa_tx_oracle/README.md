The transaction oracle uses sigma-state **6.0.7** and locally published ergo-core
**6.0.7**. See [the wire oracle setup](../santa_wire_oracle/README.md) for Java,
Scala CLI, repository configuration and regeneration of every companion.

To inspect one fixture:

```bash
export COURSIER_REPOSITORIES='ivy2Local|https://repo.maven.apache.org/maven2'
export JAVA_TOOL_OPTIONS='-XX:ActiveProcessorCount=8'
scala-cli run scripts/santa_tx_oracle/SantaTxOracle.scala \
  --server=false --jvm system --workspace /tmp/santa-tx-607 -- \
  test-vectors/santa/transaction/v6/authored/methodcall-canonicalization.json
```

Wire serialization, transaction acceptance and accepted costs are independently
checked against the JVM. Each stdout line is an entry name and a TSV verdict.
