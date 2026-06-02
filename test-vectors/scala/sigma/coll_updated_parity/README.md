# Coll.updated index-bounds rejection parity

**Audit reference:** `docs/audit-2.md` C7 (negative collection index parity).

## Oracle source

Primary: `reference/sigmastate-interpreter/core/shared/src/main/scala/sigma/data/CollsOverArrays.scala:100-104`:

```scala
override def updated(index: Int, elem: A): Coll[A] = {
  // TODO optimize: avoid using `updated` as it do boxing
  val res = toArray.updated(index, elem)
  builder.fromArray(res)
}
```

`Coll[A].updated` delegates directly to Scala stdlib `Array[A].updated(index: Int, elem: B): Array[B]`,
whose Scaladoc pins:

> Throws: IndexOutOfBoundsException — if `index < 0 || index >= length`.

This is the rejection-parity oracle for the Rust implementation in
`ergo-sigma/src/evaluator/opcodes/method_call.rs` (12, 20) dispatch arm.
Pre-Phase-8a, the Rust code silently no-op'd both negative-index (via
`as usize` wrap to `usize::MAX`) and positive-out-of-range (via implicit
`if idx < coll.len()` skip), accepting scripts Scala would reject.

## Cost-ordering oracle

`reference/sigmastate-interpreter/data/shared/src/main/scala/sigma/ast/methods.scala::updated_eval`:

```scala
def updated_eval[A](mc, coll, index, elem) = {
  val costKind = m.costKind.asInstanceOf[PerItemCost]
  E.addSeqCost(costKind, coll.length, m.opDesc) { () =>
    coll.updated(index, elem)  // throws here on out-of-range
  }
}
```

Cost is charged on `coll.length` BEFORE the closure runs — the throw
fires inside the closure, after cost has been accumulated. Our Rust
implementation mirrors this: `add_cost_per_item` precedes the bounds
check `return Err`.

Pre-existing cost-parity debt (separate from Phase 8a scope): our
`add_cost_per_item(cx.cost, 0xDC, n)` charge resolves to
`cost_table::opcode_cost(0xDC) = Fixed(4)`, which does NOT scale with
`n`. Scala's `UpdatedMethod` declares `PerItemCost(20, 1, 10)`. A
follow-up phase needs to land an inline `PerItemCost` charge for this
method (and mainnet-scan `Coll.updated` usage to confirm no historical
block trips the new cost limit).

## Live-node oracle (re-capture procedure)

A running Scala node at `localhost:9053` can confirm the
`IndexOutOfBoundsException` rejection via `POST /script/executeWithContext`.
The endpoint requires a full `ErgoLikeContext` JSON (12 fields per
`reference/sigmastate-interpreter/sdk/.../JsonCodecs.scala:440-454`:
`lastBlockUtxoRoot`, `headers`, `preHeader`, `dataBoxes`,
`boxesToSpend`, `spendingTransaction`, `selfIndex`, `extension`,
`validationSettings`, `costLimit`, `initCost`, `scriptVersion`).
Constructing that JSON from scratch is non-trivial; a helper script
that builds it from a known mainnet box id would let future Phase 8a
extensions capture byte vectors here for additional collection
methods.

For Phase 8a's bounds-check fix, the source-level citation above is
the rejection-parity oracle. The Rust tests in
`ergo-sigma/src/evaluator/tests.rs::coll_updated_*` exercise the
behavior; they assert against `EvalError::RuntimeException(...)` which
is the typed surfacing of the Scala `IndexOutOfBoundsException`.

## What is in scope for Phase 8a

- `Coll.updated(idx, elem)`: throw on `idx < 0` AND `idx >= coll.len()`.

## What is NOT in scope (verified Scala-saturate, not bugs)

- `Coll.patch(from, _, replaced)`: both `from < 0` and `replaced < 0`
  saturate to 0 in Scala (`Array.patch` semantics). Our implementation
  matches.
- `Coll.indexOf(elem, from)`: `from < 0` saturates to 0. Matches.
- `Coll.take(n)` / `Coll.drop(n)`: `n < 0` saturates. Matches (not
  changed in Phase 8a; pre-existing parity).
