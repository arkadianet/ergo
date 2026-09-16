# EVAL fixture divergence tracking

This file tracks the task-3.4c findings locally; no remote issue or PR was
created. Most findings are **cost-only**: the recorded high-limit verdicts
agree, but costs can affect decisions near a limit. Bare String equality is
**accept-invalid**: Rust accepts a guard rejected by the JVM. No evaluator fix
belongs in this fixture commit.

`expected` is the verbatim `scripts/gen-cost-fixture.sh` JVM response. The
separate `known_divergence.differences` object records observed Rust and JVM
block-cost fields from the fixture runner. These observations never close a
ledger row. The runner checks every comparison-contract field, requires the named ledger row to
remain DIVERGENT, rejects changed observations, and rejects stale annotations
when parity is restored. Its final count distinguishes known divergences from
unexplained failures; none are skipped.

## EVAL-eq-coll-descriptor

Scala `DataValueComparer.equalCOA_Prim` (v6.0.2, lines 159–176) charges elements
actually compared for both primitive and descriptor-backed collections.
Rust's primitive carriers agree. Its generic descriptor and Box/Header
carriers charge full length on an early mismatch.

| Fixture, prefix 0 | Rust eval/total BC | JVM eval/total BC |
|---|---:|---:|
| collection-avl, early mismatch, length 5 | 13 | 12 |
| collection-bigint, early mismatch, length 11 | 20 | 18 |
| collection-unsigned-bigint, early mismatch, length 11 | 20 | 18 |
| collection-group, early mismatch, length 3 | 11 | 10 |
| collection-box, early mismatch, length 3 | 11 | 10 |
| collection-header, early mismatch, length 3 | 11 | 10 |

All six have ten failing prefixes, exposing the block-rounding effects.
Boolean, Byte, Short, Int and Long early mismatches match the JVM.

String equality is reached recursively through a `(String, Int)` constant:
Scala `EQ` rejects a bare SString operand in `SType.isValueOfType` before the
comparer. Tuple checking is shallow, so recursion reaches its String arm.
Scala uses `EQ_COA_Short` over the full String length, even on early mismatch
(`DataValueComparer.scala:395–406`). Rust uses the Byte descriptor. Six prefix
cases diverge: `string-equal-n97` prefixes 4 and 7, `string-equal-n193` prefixes
3 and 6, and `string-early-mismatch` prefixes 0 and 7. Consult each fixture's
JVM `expected` and Rust observation for exact costs.

`strings-direct.json.gz` retains the bare String finding separately: all ten
prefixes are Accept in Rust, versus RejectOther / java.lang.RuntimeException
(`Unknown type SString`) in JVM verification. Costs on the JVM rejection are
unavailable and are not compared to successful Rust costs. This is an
accept-invalid finding, independent of the recursive String tariff mismatch.

All descriptors have lengths `0, 1, k−1, k, k+1, 2k+1`, with duplicates removed.
PreHeader uses the sole `CONTEXT.preHeader` value. There is no unequal second
PreHeader constructible in one context: `SPreHeaderMethods` only exposes
fields, and neither `DataSerializer` nor `CoreDataSerializer` supplies its
constant serializer. Its equal and length-mismatch cases are covered; an
early-element mismatch is consequently not claimed.

## EVAL-eq-boxcollection

`equality-edges.json.gz`, `lazy-boxes-early-mismatch-prefix0`: three lazy input and
output boxes, with the first pair unequal. Rust charges all three comparisons
instead of the JVM's one. All ten prefixes differ. This specifically reaches
the lazy BoxCollection carrier, independently of ConcreteCollection[Box].
The equal chunk boundaries and length-mismatch early return are also pinned.

## EVAL-eq-mismatch-and-unit-E032

`equality-scalars.json.gz`, `unit-prefix1`, `unit-prefix2`, `unit-prefix9`:
Rust adds primitive equality cost (3 JIT); JVM Unit equality adds no cost
(`DataValueComparer.scala:409`). Rust/JVM block totals are respectively 3/2,
3/2, and 5/4. Other prefixes conceal this difference by rounding.
Collection length-mismatch early-false cases agree. This work does not claim
to establish the separate element-type-mismatch branch of this row.

## EVAL-deferred-charge-on-exception

`sigma-booleans.json.gz` contains forty throwing cases wrapped in BoolToSigmaProp.
Both sides report RejectOther with `java.lang.RuntimeException`, following the
oracle's existing failure classification. Full verify costs are unavailable;
the supplementary evaluator failure observation is compared in block units.

Rust charges BoolToSigmaProp's 15 JIT before its operand, whereas Scala
`trees.scala:37–39` evaluates the operand before charging. Thus a throwing
conjecture comparison leaves that extra Rust charge. For example,
`sigma-shape3-constructor-mismatch-prefix0` is Rust 2 / JVM 1 BC, and
`sigma-collection-throw-prefix0` is Rust 6 / JVM 5 BC.

`sigma-throws.json.gz` isolates the same throwing comparisons as BlockValue RHS
expressions, eliminating the BoolToSigmaProp ancestor. All forty isolated
failure observations match, including skipped outer collection scan cost.
This establishes equalSigmaBoolean and Coll[SigmaProp] behavior while keeping
the ancestor charge-order finding DIVERGENT.
