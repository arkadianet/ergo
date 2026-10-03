# Mixed collection carrier fixtures

Six ordinary contracts were compiled, serialized, reduced and verified with
sigma-state / locally published ergo-core 6.0.6. The full emitted transcript,
compiler source and artifact/source hashes are retained here. The evaluator is
[the pinned oracle source](../collection-types/ErgoSerdeOracle.scala).
Expected propositions and costs come from Scala.

The two token-pair cases alternate 32-byte and one-byte values, in both orders.
Their common element type is `(Coll[Byte], Long)` even though Rust uses a token
carrier only for 32-byte pairs. Two box cases alternate `Coll(SELF).reverse`
and `Coll(SELF)`, and two alternate lazy `INPUTS` and materialized `Coll(SELF)`.
All use HEIGHT 0 and tree/activated version 3. Verification uses the existing
ordinary dummy SELF/input context with empty proof/message.

Reproduce from this directory with Java 17 and Scala CLI:

```sh
COURSIER_REPOSITORIES='ivy2Local|https://repo.maven.apache.org/maven2' \
scala-cli run Capture.scala ../collection-types/ErgoSerdeOracle.scala \
  --server=false --jvm system --main-class AuditMixedCollectionProbe
```

`ergo-core` must first be locally published as described in the oracle source.
The capture used Scala CLI1.12.1 and Scala2.12.21; see `cases.json` for the exact
published sigma-state and locally built ergo-core JAR hashes. These finite
comparisons do not establish full transaction validity or chain occurrence.
