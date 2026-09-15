# Interpreter substitution divergence

Tracking: Task 3.4e discovery; controller dispatch Task 0.5 owns the fix.
Classification: **cost-only**, with limit-boundary risk. No production Rust code
changes are included. `INTERP-embedded-script-deser` is DIVERGENT.

## JVM evidence

`deserialize-substitution.json.gz` contains four hand-serialized, segregated v3
ErgoTrees with `activated_version=3`, `init_cost_block=17`, and a 1,000,000 BC
limit. SELF carries the exact tree bytes. Each tree is
`If(ConstantPlaceholder(0), DeserializeContext[SigmaProp](0), TrueSigmaProp)`
or the equivalent `DeserializeRegister[SigmaProp](R4, None)`, with a segregated
true Boolean condition. Embedded expressions are a 2-byte SigmaProp true constant
and a **300-byte** BoolToSigmaProp(EQ(Coll[Byte](146 zeros), same)). No compiler is
used. Every embedded byte belongs to the expression; there is no trailing padding.

| Case | Tree bytes | Embedded bytes | JVM eval BC | Rust eval BC | JVM total BC | Rust total BC |
|---|---:|---:|---:|---:|---:|---:|
| context-tiny | 13 | 2 | 32 | 29 | 49 | 46 |
| context-long | 13 | 300 | 632 | 35 | 649 | 52 |
| register-tiny | 14 | 2 | 34 | 31 | 51 | 48 |
| register-long | 14 | 300 | 634 | 37 | 651 | 54 |

All cases return Accept, crypto cost 0, and no failure class on both sides.
JVM expectations were generated only by `scripts/gen-cost-fixture.sh`, using
its pinned sigma-state/ergo 6.0.2 verify oracle. The JSON manifest includes source
pins, tool versions, input/output hashes, command, and execution counts.

The source-backed decomposition explains both measurements: JVM eval includes
2 BC per tree byte, 2 BC per embedded byte, and the substituted expression's
normal evaluation (2 BC tiny, 6 BC long, including If and constant-reference
charges). Thus context costs are `26 + 4 + 2 = 32` and
`26 + 600 + 6 = 632`. Register trees add two more BC for their extra byte.
Rust instead charges the descriptor's 11 JIT units for two embedded bytes and
31 JIT units for 300 embedded bytes; after snapping these contribute 1 and 3 BC.
The resulting deficits are **3 BC** and **597 BC**. These decompositions explain
oracle observations; they do not supply the fixture expectations.

## Authority and disposition

Pinned sigmastate v6.0.2:

- `interpreter/shared/src/main/scala/sigmastate/interpreter/Interpreter.scala:95-105`
  parses an embedded expression and adds `scriptBytes.length * 2` **block units**
  to initCost; context substitution calls this before expression evaluation.
- `interpreter/shared/src/main/scala/org/ergoplatform/ErgoLikeInterpreter.scala:17-24`
  uses the same measured deserialization for SELF register bytes.
- `Interpreter.scala:246-267` charges whole-tree substitution and retains it at
  V6 activation, then evaluates the substituted proposition.
- `data/shared/src/main/scala/sigma/ast/transformers.scala:551-572` declares the
  OP descriptors without an evaluator invoking them. The substituted expression
  replaces these nodes before evaluation.

The controller's reviewed disposition for OP-0xD4 and OP-0xD5 is **N-A** once
JVM evidence confirms non-charging. These measurements confirm that disposition:
adding the declared descriptor would change both observed totals. L1 descriptor
extraction or direct cost(n) evaluation cannot close this execution obligation.

`INTERP-deser-subst` stays OPEN: these fixtures meet its segregated-tree and
nonzero-init requirements, but their complete oracle parity fails. The controller
requires stopping on discovery, so crypto shape/threshold and exact-limit fixture
expansion is deferred. No claim is made about those unexecuted obligations.

## Reproduce

```sh
python3 ergo-difftest/src/gen/interpreter_cost.py
scripts/gen-cost-fixture.sh test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter/deserialize-substitution.json.gz
cargo test -p ergo-sigma --test it cost_ledger_fixtures -- --nocapture
python3 scripts/cost-ledger.py render
python3 scripts/cost-ledger.py check
```

On first authoring, the runner failed with missing `expected`. After JVM
population, it executed 21,597 cases and reported exactly four unexplained
mismatches. The four `known_divergence` annotations now assert those exact
mismatches, require the DIVERGENT row and this tracking path, and fail if the
mismatch changes or disappears. Passing this regression test means the known
mismatch is stable; it does not mean interpreter cost parity is achieved.
