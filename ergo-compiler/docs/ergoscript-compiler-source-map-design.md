# Compiler source-map contract

`compile_with_source_map(env, source, tree_version, network)` returns
`(CompileResult, SourceMap)`. The map links compiled IR nodes to byte offsets in
the authored source. It is side-channel metadata: ordinary compilation and
serialization produce the same tree bytes and addresses. The implementation is
in [`source_map.rs`](../src/source_map.rs), with regression coverage in
[`tests/it/source_map.rs`](../tests/it/source_map.rs).

## Source positions

Every `TypedExpr` carries a `pos: Pos`. Binder-built nodes inherit the untyped
expression's offset; env-substituted constants inherit the replaced identifier's
offset; typer rebuilds retain the rewritten node's position. Synthesized nodes
use `0`, the unset SourceContext sentinel, and are not recorded as citations.
`span::line_col` converts a byte offset to Scala's 1-based UTF-16 line/column.
`CompileError::pos()` exposes offsets for parse, bind and type errors.

Positions describe a start point, rather than a range. The parser does not
capture end offsets for source-map underlining.

## Node identity and alignment

The map uses preorder IDs (`0` for the root, then DFS children in payload field
order) from the shared [`ergo_ser::opcode::preorder`](../../ergo-ser/src/opcode/walk.rs)
walk. A consumer must take IDs from that walk and retain them when lifting or
truncating subtrees. An independent recursion counter can drift when a lift
stops at a depth limit or traverses collection elements inside a single constant.

`SourceMap` exposes `offset(id)`, `node_count()`, `tags()` and
`aligns_with(walk)`. Check the parsed tree's preorder opcode tags with
`aligns_with` before using any citation. A missing offset means the node is
synthesized or could not be aligned confidently; consumers can omit the citation
or attach a finding to a mapped ancestor according to their own policy.

Offsets come from the final pre-segregation root. Tags describe the segregated
body a consumer parses. Constant segregation replaces inline constants with
placeholders one-for-one, preserving preorder shape and IDs. Wire types carry
no source-position fields, so maps are optional for contracts obtained from
on-chain bytes without authored source.

## Recording and resolving origins

Emit records the serialized IR subtree and source position for each typed node
it lowers. On the untouched emit output, those records are pinned onto an
emit-time tree. The compiler's graph-building passes then fold, lower and
restructure that tree before serialization; simply exporting the original
origin tree would misalign citations.

After graph building, resolution aligns the emit-time tree top-down with the
final root. Matching opcode and arity preserve a citation and align children
pairwise. A fold inside a subtree can leave the folded node uncited while
preserving its ancestors. The resolver also handles these rewrite shapes:

- A CSE `BlockValue` wrapper aligns through its result; hoisted `ValDef` right
  sides are located among emit-time subtrees by bytes.
- A `ValUse` replacing a hoisted subtree is cited at that spelling when its
  right-side bytes match; an inlined emit-time binding is followed to its right
  side.
- Blocks align results and pair items by binding ID.
- An arity change leaves the node uncited and searches for its children by bytes.

Anything resolution cannot place remains uncited. A typer-inserted `Upcast` can
still carry its operand's position because the typer records rebuilt-node
positions. This conservative alignment avoids threading source metadata through
every oracle-graded rewrite pass and never changes consensus wire bytes.
