# Emit-time source map — design pass (P5 deliverable B)

Status: DESIGN ONLY — deliverable A (positions threaded through the typer) is
landed; this doc specifies B for a follow-up implementation, co-designed with
the ergo-forge workbench side.

## What A landed (the substrate B builds on)

Every `TypedExpr` node now carries `pos: Pos` (byte offset into the authored
source; `span::line_col` converts to Scala's 1-based UTF-16 line:col on
demand). Position semantics by origin:

| origin | pos |
|---|---|
| binder-built bound node | offset of the untyped `Expr` it was built from |
| env-substituted constant | offset of the replaced `Ident` (mirrors Scala's `liftAny` `currentSrcCtx` pinning) |
| typer rebuild | offset of the node being rewritten (Scala's `currentSrcCtx`) |
| synthesized (predef/env constants, wire-deserialized) | `0` = unset SourceContext (Scala `Nullable.None`, oracle prints `0:0`) |

`CompileError::pos()` returns real offsets for `Parse`/`Bind`/`Type`; and
`seed_reject_records_position_parity` pins the typer's citations against the
fresh-JVM oracle positions recorded in `golden_seed.txt`.

## Problem B solves

A downstream audit finding is about a node in the COMPILED tree (the
`ergo_ser` opcode IR that serializes into ErgoTree bytes, or the workbench's
lifted AST over those bytes). To cite source text, the finding needs a mapping
from compiled-tree-node identity back to a source offset. The typed tree's
`pos` fields do not survive into the IR: emit lowers, and the fold/lowering
stages collapse and rewrite nodes (`MethodCallLike` → op nodes, constant
folding, CSE-materialized `ValDef`s), so the IR is NOT isomorphic to the typed
tree. The map must therefore be recorded AT EMIT TIME, when each IR node's
origin `TypedExpr` (and its `pos`) is still at hand.

## Proposed design

### 1. Origin tree, not position fields on the wire type

`ergo_ser::opcode::Expr`/`IrNode` are wire-faithful consensus types — they must
not grow source positions. Instead, emit builds a parallel **origin tree**
(`Origin`) with the exact shape of the produced `Expr`:

```rust
enum Origin {
    /// IR node originated from the typed node at this offset.
    Pos(Pos),
    /// IR node was synthesized by emit (Upcast insertions, placeholder
    /// wiring, scope glue) — no source construct.
    None,
}

enum OriginTree {
    Leaf(Origin),
    Node(Origin, Vec<OriginTree>), // shape-mirrors Payload arms
}
```

Mechanics: `Scope::emit` currently produces `Expr` via a `node(opcode,
payload)` helper (~50 call sites across `emit/mod.rs`, `dispatch.rs`,
`method_call.rs`, `select.rs`). Each call site gains the origin of the
`TypedExpr` being lowered (`node_pos(&e)` or `Origin::None` for synthesized
nodes) and returns `(Expr, OriginTree)` — or, cheaper on churn, `Scope`
accumulates a `Vec<(u64 creation_id, Origin)>` and the FINAL `Expr` walk
assigns preorder ids that zip against creation order via a deterministic
construction protocol. The parallel-tree zip is the recommended variant: it is
order-independent and cannot drift.

### 2. Keying: preorder index of the IR tree

The map handed to consumers is keyed by the **preorder index of the IR tree**
(`0` = root, DFS children in payload field order):

```rust
pub struct SourceMap {
    offsets: BTreeMap<u64, Pos>, // absent key = synthesized node
    node_count: u64,             // consumer asserts its walk agrees
}
```

Preorder index is the only identity available on BOTH sides of the wire:
- emit can assign it (zip of `Expr` and the origin tree);
- the forge lift walks the same tree (it parses the ErgoTree bytes with
  `ergo_ser::opcode::parse_expr` and lifts to its `Node` AST).

**The index MUST come from one shared walk — not be recomputed on each side.**
An earlier draft of this doc had the lift "compute the identical index while
lifting". That contract is unsound, and it fails silently rather than loudly.
Verified against the forge lift as it stands today:

- `lift()` returns `L::Raw` at `MAX_LIFT_DEPTH` **without descending**
  (`ergo-sandbox/src/decompile.rs`). Every IR node in the skipped subtree is
  never visited, so an independently-maintained counter drifts by that
  subtree's size for the whole remainder of the walk — every citation after the
  first deep contract points at the wrong node, with no test that would notice.
- `lift_const` recurses through collection elements that live inside a single
  `Expr::Const` and are not separate IR nodes, so the lift's recursion shape is
  not the IR's node shape.
- Any later early-return or child reordering in `lift_op` breaks alignment the
  same way.

Required instead — one canonical walk in `ergo-ser`, consumed by both sides:

```rust
// ergo-ser
pub fn preorder(root: &Expr) -> impl Iterator<Item = (u64, &Expr)>;
```

Emit keys its origin tree from this iterator; the lift takes ids **from** it
rather than deriving its own. Ids then travel with nodes, so truncation and
restructuring cannot desync anything.

**Alignment must also be checkable.** `SourceMap` carries the total IR node
count (and ideally a per-index opcode tag or hash) so a consumer whose walk
disagrees fails loudly. Silent mis-citation in an auditing tool is worse than
no citation at all.

A serialized-BYTE-OFFSET keying was considered and rejected: byte offsets are
only known after serialization, emit-time nodes have no stable address to
correlate with them, and the ErgoTree header/constant-segregation offsets
would force the map to be regenerated per wire shape. Preorder ids survive
constant-segregation rewrites only if the map is taken over the PRE-segregation
IR root — which is exactly what `emit` produces and what the lift re-parses
(segregation keeps the proposition tree; the constants table is separate data,
not part of the walked tree).

### 3. Public API (additive)

```rust
// emit/mod.rs
pub fn emit_with_source_map(expr: &TypedExpr)
    -> Result<(Expr, SourceMap), EmitError>;

// tree/mod.rs (compile route)
pub struct CompileResult { ..., }                       // unchanged
pub fn compile_with_source_map(env, source, tree_version, network)
    -> Result<(CompileResult, SourceMap), CompileError>;

// lib.rs re-exports SourceMap; ergo-forge calls this instead of compile_source
// (compile_source itself is UNCHANGED — additive API only).
```

The map covers the IR root produced by emit — i.e. the tree bytes BEFORE the
v0 header prefix, matching what `parse_expr` returns to the lift. Serialization
(order) is unchanged; the map is pure side-channel metadata.

### 4. Consumer contract (ergo-forge side)

- The lift takes each node's id from the shared `ergo_ser::preorder` walk (NOT
  from its own counter — see §2) and stores it on the lifted node as `ir_id`.
  The forge spec adds that slot in its P2.5 AST split
  (`docs/superpowers/specs/2026-08-31-lift-target-ast-design.md`), deliberately
  as an **id rather than a `Pos`**: a contract lifted from a mainnet address has
  no source and therefore no map, but still needs stable node identity for lint
  findings. Source citation is a lookup layered on top — `map.get(node.ir_id)`,
  then `line_col(source, pos)` via `ergo_compiler::span::line_col`.
- The consumer asserts its walk length equals `SourceMap::node_count` before
  citing anything, and reports a tooling bug if not.
- Nodes absent from the map (synthesized: inserted Upcasts, CSE-materialized
  ValDefs, placeholder wiring) must NOT be citable — workbench lints either
  skip them or attach to the nearest mapped ancestor (lift-side policy).
- RANGES: the parser records a single START offset per node (`ast.rs`), so the
  map carries points, not spans. Span (start..end) support would require
  end-offset capture in the parser first (ast.rs + parse/*) — out of scope
  here, tracked as a follow-up if the workbench needs underlining rather than
  caret diagnostics.

### 5. Parity risk

None, by construction: the IR bytes are bit-identical (the origin tree is side
data), `compile_source` is untouched, and existing oracle suites grade bytes
and verdicts only. The only new test surface is the map's own correctness
(zip-order test, synthesized-node exclusion test, and a golden test compiling
a representative source and asserting a handful of node→offset pairs against
hand-computed offsets).

## Estimate

- Shared `ergo_ser::preorder` walk: small, but land it FIRST — both this crate
  and the forge lift key off it, and it is the thing that makes the contract
  sound.
- `Origin`/`OriginTree` + `node()` threading: ~60 mechanical call-site edits in
  `emit/*`.
- Preorder-id zip + `SourceMap` + API: small, self-contained.
- Integration + tests: `tree/mod.rs` route change, one golden test.
- Forge-side lift changes: separate repo, needs the contract above frozen
  first (forge pins this repo by git rev — the API must land before their
  lift consumes it).
