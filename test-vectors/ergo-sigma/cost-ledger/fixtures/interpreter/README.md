# Interpreter cost fixtures

The generators hand-serialize every expression and SigmaBoolean; they do not
invoke the ErgoScript compiler. `scripts/gen-cost-fixture.sh` supplies all
expectations through the pinned JVM 6.0.2 full-verification oracle. Each JSON
includes its reproducibility manifest. `cost_ledger_fixtures_jvm_verify_fields_match`
compares every exposed cost, verdict, and failure class.

## Substitution

`deserialize-substitution.json.gz` uses segregated v3 trees with init cost 17 BC.
Context and register variants cover 2-byte and 300-byte scripts, a dead branch,
and absent variables on live/dead branches. The dead branch still pays for its
script bytes; an absent live variable raises RuntimeException, while an absent
dead variable does not fail. All ten cases match after Task 0.8's eager,
bottom-up substitution fix. The original four before/after measurements are in
[DIVERGENCES.md](DIVERGENCES.md).

## Substitution types

`deserialize-types.json.gz` contains 80 JVM probes with segregated v3 trees and
init=17: absent R4 with a true default, present Int/Coll[Int]/Coll[Byte] R4,
and embedded IntConstant/ConcreteCollection[Int] expressions where SigmaProp
is required. Every shape runs on both live and dead branches.

Only absence selects the register default. A present incompatible register
causes the unchecked byte-array cast to fail inside `Rewriter.strategy`
(sigmastate v6.0.2 `core/shared/src/main/scala/sigma/kiama/rewriting/Rewriter.scala:180-190`).
The strategy catches ClassCastException and leaves the deserialize node in
place: live evaluation rejects with RuntimeException, while a dead branch
accepts. This full-verification result refines the cast-only interpretation.

Both sources reject embedded type mismatches even on dead branches. Register
mismatches produce RuntimeException (`RejectOther` in the oracle classifier);
context mismatches produce ValidationException (`RejectScript`). Rejection
costs are unavailable from the JVM and are not replaced with invented totals.
Rust requires a precise static type from the shared serializer typer; unknown
or sentinel types reject. Accepted absent/default cases total 51 BC and
accepted byte-script/default cases total 55 BC, on either branch.

The 64 positive probes run 16 expression shapes through both sources and both
branches: tuple selection, ByIndex, Option.getOrElse, a SigmaProp-returning
method, If, BlockValue, Slice, Map, Append, Filter, Fold, Apply, method Map,
method size used as an index, Option.get after Global.some, and Context.HEIGHT.
All accept on both JVM and Rust. The shared serializer typer preserves component
and function types and specializes the complete 199-method JVM signature registry.
The verify-surface corpus test in ergo-difftest independently checks verdicts.

Regenerate method signatures with:

```sh
scala-cli --skip-cli-updates run scripts/jvm_serde_oracle/MethodTypes.scala --server=false --suppress-outdated-dependency-warning > ergo-ser/src/ergo_tree/type_infer/method_registry.rs
cargo fmt --all
```

## Crypto shapes

`crypto-shapes.json.gz` wraps serialized SigmaBoolean constants in v0 ErgoTrees.
All cases use init cost 17 BC and charge 5 BC for trivial reduction. Nontrivial
propositions use an empty proof, which rejects after the crypto charge.

| Shape | JVM crypto BC | JVM total BC | Rust crypto before → after |
|---|---:|---:|---:|
| True / False | 0 | 22 | 0 → 0 |
| Dlog | 398 | 420 | 398 → 398 |
| DHT | 714 | 736 | 714 → 714 |
| AND / OR (Dlog + DHT) | 1113 | 1135 | 1113 → 1113 |
| Threshold 3-of-3 Dlog | 1197 | 1219 | 1199 → 1197 |
| Threshold 2-of-3 Dlog | 1199 | 1221 | 1199 → 1199 |
| Threshold 1-of-3 Dlog | 1201 | 1223 | 1201 → 1201 |

The serialized 3-of-3 constant preserves CTHRESHOLD with zero coefficients.
`Interpreter.scala:580-587` uses `nCoefs = nChildren - k` without a minimum of
one. The JVM confirms the resulting base-only polynomial charge; removing
Rust's clamp resolves the measured 2 BC overcharge. The pre-fix runner reported
exactly this one mismatch among 21,616 cases; the fixed runner reports none.

## Exact limits

The boundary generator copies **JVM-measured** totals into requests and then
runs those requests through the JVM again. `cost-limit.json.gz` exercises the
trivial path: limit 22 accepts, limit 21 rejects with charged total 22 BC.
`deserialize-cost-limit.json.gz` exercises the segregated evaluator path: limit 49
accepts, limit 48 rejects with charged-to-failure total 48 BC (485 JIT units
versus a 480-JIT limit). Both sides reject strictly above their respective
limits. Unavailable rejection components remain the literal `unavailable`.

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 ergo-difftest/src/gen/interpreter_deserialize_types.py
scripts/gen-cost-fixture.sh test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter/deserialize-types.json.gz
python3 ergo-difftest/src/gen/interpreter_cost.py
scripts/gen-cost-fixture.sh test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter/deserialize-substitution.json.gz
python3 ergo-difftest/src/gen/interpreter_crypto_cost.py
scripts/gen-cost-fixture.sh test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter/crypto-shapes.json.gz
python3 ergo-difftest/src/gen/interpreter_crypto_cost.py --limits
scripts/gen-cost-fixture.sh test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter/cost-limit.json.gz
scripts/gen-cost-fixture.sh test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter/deserialize-cost-limit.json.gz.gz
cargo test -p ergo-sigma --test it cost_ledger_fixtures -- --nocapture
python3 scripts/cost-ledger.py check
```
