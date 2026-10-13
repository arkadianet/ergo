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

`evaluation-order.tsv` contains expression hex, tree version and a JIT budget;
`evaluation-order.jvm.tsv` records the evaluated result or error and the JIT cost
retained at that point. Generate it with `EvaluationOrderOracle.scala` using the
same Scala/JVM options above. These cases run through the public reduction path,
including short-circuit and exhausted-budget controls.

`arith-upcast-type-reads` places arithmetic over an operand whose type read
fails (a `filter` over a number) in output, input, nested box, `deserializeTo`,
`DeserializeContext` and `DeserializeRegister` code, at tree versions 0, 1 and 3
and several block versions, with valid-upcast controls.

`lambda-sweep` covers map, filter, exists, forall, flatMap and option map/filter,
with empty/nonempty inputs and valid and invalid callback values.

`zip-columns` covers the size, indexing, slicing, nesting and append of zips
over unequal context variables, in JIT and pre-JIT blocks. A JIT zip truncates
the longer column first, so appending two zips is limited by the zipped
length; a pre-JIT zip keeps both columns, and appending can exceed the
100,000-item limit.

`avl-value-length` covers AVL proofs for trees without a fixed value length,
where each leaf carries a 4-byte value length: 0, a 200-byte value, negative
lengths (including -37 and -40, which would move the read position back onto
an end-of-tree marker earlier in the proof and give a consistent tree), a
length past the end of the proof, 0x7fffffff and 4 MiB + 1. It runs
`contains`, `get`, `getMany`, `insert`, `update`, `remove` and
`insertOrUpdate` at tree versions 0 and 3 against one- and two-leaf trees,
with ordinary encodings of the same trees as controls. Where a method returns
an Option and the proof fails, a `-defined`/`-undefined` pair tells a script
failure (both rejected) from a None result (`-undefined` accepted). scrypto
3.1.1 rejects a negative length, one above 4 MiB and one past the end of the
proof.
