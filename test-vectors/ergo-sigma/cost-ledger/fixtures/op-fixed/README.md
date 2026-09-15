# Fixed opcode fixtures

These 23 trees are hand-serialized. Each JSON's `construction.body_hex` is the
exact body after the `00` ErgoTree header, and its description identifies the
operation and evaluated branch. No ErgoScript compiler is used. The synthetic
context is copied from `../interpreter/p2pk.json`; none of these trees reads the
self box, whose guard remains the original P2PK tree.

Coverage is the Fixed-cost OP rows still OPEN at task dispatch (Apply, ModQ,
PlusModQ, MinusModQ, TaggedVariable, and the six BitOps), plus both If branches
and both short-circuit paths of BinOr/BinAnd. Arithmetic and casts are type-based
and belong to the later dynamic family. Existing CLOSED fixed source-pin rows
are not duplicated wholesale.

## Wire construction

- `01 00/01`: Boolean constant; `04 02`: Int(1); `06 01 01`: BigInt(1).
- `08 d3`: constant SigmaProp(true).
- `d1`: BoolToSigmaProp; `ef`: LogicalNot; `95`: If with three expression operands.
- `ec/ed`: BinOr/BinAnd with two Boolean expression operands.
- `d9 01 01 01 72 01`: a Boolean identity closure with argument id 1.
  `da <closure> 01 01 01` applies it to one Boolean(true) argument.
- `d8 01 d6 00 <operation> 08 d3`: one block binding (id 0), followed by a
  SigmaProp(true) result. Rejection happens in the binding RHS, before the
  environment update or result. This avoids surrounding charges on failure.
- `71 00 08`: a SigmaProp-typed TaggedVariable at the root.
- `d8 00 95 01 01 <rejecting block> 08 d3`: the BitOp boundary prefix.
  An empty block and a true If precede the rejecting block. All comparisons
  use independently measured JVM block costs, not a Rust cost formula.

## Reproduce

From the worktree root, for each JSON file:

```sh
scripts/gen-cost-fixture.sh test-vectors/ergo-sigma/cost-ledger/fixtures/op-fixed/<name>.json
cargo test -p ergo-sigma --test it cost_ledger_fixtures -- --nocapture
python3 scripts/cost-ledger.py check
```

The generator alone writes `expected` and its JVM provenance manifest. Rejection
fixtures request `observe_evaluator_failure`. Full `verify` leaves unexposed
costs as `unavailable`. The optional `evaluator_failure_block_cost` is a separate
JVM evaluator run using the same parsed tree/context and a retained accumulator;
it is restricted to zero-init, non-rent trees without deserialization nodes.
It does not replace the full verify result or claim access to its accumulator.

The runner compares available block costs, verdicts, and JVM failure classes
through its documented typed Rust semantic-equivalence table. Non-executable,
deprecated, and internal opcode errors map to the inherited Value.eval
java.lang.RuntimeException; unrelated Rust failures need an explicit mapping.

BitOp boundary fixtures measure 1 BC on both implementations; minimal bindings
measure 0 BC. Both reject without charging the declared BitOp Fixed(1).
The six OP rows and ORDER-bitop-charge-then-reject are CLOSED against these
unchanged JVM expectations. The runner requires exact observed cost equality.
