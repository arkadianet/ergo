# JVM evaluator transaction vectors

These fixtures pin transaction verdicts and accepted costs from ergo-core and
sigma-state 6.0.7. The test uses the node's production transaction parser and
validator; decode errors and evaluation errors are both rejection verdicts.
The neighboring `.jvm.tsv` files are independent oracle output, in fixture order.

Regenerate from the repository root with the JVM toolchain loaded:

```bash
source ~/.local/kdex-toolchain/env.sh
scala-cli run scripts/reference_evaluator_oracle/ReferenceEvaluatorOracle.scala \
  --server=false --jvm system -- test-vectors/reference-6.0.7/evaluator/deserialize.json
```

The oracle uses testnet chain settings with re-emission disabled, as the fixture
contract specifies. It never reads `expected`; that field mirrors the captured
TSV for review. Diagnostics go to stderr. The dependency directives pin 6.0.7.

`method-table.jvm.tsv` records the complete 6.0.7 wire method registry for
versions 0–3, with reflection resolution through `MethodSweep.scala`. This
inventory is distinct from transaction verdicts: a resolved method can still
fail on its input, and the v3 parser rejects argument-free MethodCall forms.
`methods-extra.json` pins those version-dependent wire outcomes, option None,
context results, and multiplication with the group identity.
