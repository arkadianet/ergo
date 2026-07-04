# ErgoScript compiler for the Rust node — design

- **Status:** Design only. Not scheduled — a near-future project behind other work.
- **Date:** 2026-06-18
- **Author:** design captured with Claude (brainstorming pass)
- **Location:** `dev-docs/` (gitignored; local working notes, not committed)

> This document is a complete design for adding an **ErgoScript → ErgoTree
> compiler** to the Rust node. No code has been written. The acceptance bar is
> **byte-identical ErgoTree output** versus the Scala `SigmaCompiler`
> (sigma-state v6.0.2), because that is the only bar under which a contract
> compiled here yields the *same P2S address* as every other Ergo tool.

---

## 1. Goal & non-goals

### Goal

Let an end user hand the node ErgoScript **source text** (plus an optional
named-constant environment) and get back a compiled **ErgoTree** and its
**P2S/P2SH address**, such that the bytes are **identical** to what the Scala
`SigmaCompiler` produces for the same input. Combined with the node's existing
transaction-build and submission paths, this closes the loop:

```
ErgoScript source
   → [NEW: compile]        → ErgoTree (typed AST → opcode IR → bytes)
   → [exists: tree→address]→ P2S address
   → [exists: build tx with an output box guarded by that tree]
   → [exists: POST /transactions] → on-chain
```

"Deploy a contract" in Ergo's eUTXO model is **not** an EVM-style deployment:
there is no contract account or deploy opcode. A contract is simply the
guarding ErgoTree of a box; you "deploy" by creating an output box at the
compiled script's P2S address. The node already does every step except the
compile.

### Non-goals

- **Not** an interpreter/evaluator — that is `ergo-sigma` and already exists.
- **Not** costing. The Scala compiler runs a costing graph, but cost does not
  affect the serialized tree bytes; cost limits are a *validation* concern the
  node already enforces. We skip costing for the compile→bytes path (see §7.5).
- **Not** a consensus surface. A compiler bug produces the *wrong tree* (your
  contract is not what you meant), never a fork — the network validates the
  resulting bytes regardless of who produced them. This shapes where the crate
  sits (§4). **But (codex) do not under-rank the product risk:** wrong bytes mean
  a wrong contract *address* — funds sent there can be **stranded/lost**. The
  correctness bar stays *stricter* than ordinary API correctness, even though
  it is not consensus.
- **Not** wiring `sigma-rust` into production. Per repo convention `sigma-rust`
  stays a test oracle only. Its `ergoscript-compiler` may be *studied* as a
  Rust precedent, but it covers a subset and is not a dependency.

---

## 2. What exists today (reuse) vs what is new

The interpreter-side AST, type system, serialization, and address encoding are
**already mirrored in the Rust node** (`ergo-ser` ≈ the Scala `interpreter`
module, ~5.9k lines of Scala AST/serialization that we do not re-implement).
The compiler is almost entirely a **frontend + a normalization middle**; the
backend is largely present.

| Stage | Scala home | Rust today | Status |
|---|---|---|---|
| Lexing/parsing | `parsers/SigmaParser` (~1.2k L) | — | **NEW** |
| Untyped AST | `sigma.ast.Value` (untyped) | — (only the opcode IR exists) | **NEW** |
| Name binding / predefs / `PK` | `phases/SigmaBinder` (122 L) | — | **NEW** |
| Type inference / method resolution | `phases/SigmaTyper` (641 L) | — | **NEW** (hardest phase) |
| Lowering + subexpression sharing | Graph IR `GraphBuilding`/`TreeBuilding` (~1.9k L of ~10.6k IR) | — | **NEW** (byte-determinism crux, §7.5) |
| Constant segregation (transform) | `ErgoTreeSerializer` | — (node only *reads* segregated trees) | **NEW** |
| Opcode IR (codegen target) | `sigma.ast` nodes | `ergo-ser opcode::{Expr, IrNode, Payload}` | reuse |
| Type representation | `SType` | `ergo-ser sigma_type::SigmaType` | reuse |
| Tree+constants → bytes | `ErgoTreeSerializer` | `ergo-ser opcode::write_expr`, `ergo_tree::write_ergo_tree` | reuse |
| Bytes → P2S/P2SH/P2PK address | `ErgoAddressEncoder` | `ergo-ser address::{encode_address_from_tree_bytes, encode_p2s}` | reuse |
| Behaviour check (tests) | interpreter | `ergo-sigma` evaluator | reuse (dev) |
| JVM oracle harness | — | `ergo-difftest` + `scripts/jvm_serde_oracle` scala-cli pattern | reuse/extend |

**Net: the backend is *mostly* built. The new work is the frontend
(lexer→parser→binder→typer), the lowering/normalization layer, and the
constant-segregation transform.**

> **Caveat (codex review, verified):** "reuse the `ergo-ser` writer" is
> *overstated* — the writer emits the IR it is handed but is **not fully
> Scala-canonical today**. Confirmed example: a `Relation2` with two boolean
> *constant* args is serialized by Scala in a compact `0x85`+packed-bits form;
> `ergo-ser` *parses* that form (`parse.rs` ~433) but `write.rs`'s `Payload::Two`
> **re-emits it expanded** as two `Const` children → not byte-identical. (This is
> likely one of the harness's ~50 untriaged `ergo_tree` canonical divergences.)
> Byte parity therefore requires a **writer-canonicalization audit/fix pass** as
> explicit scope — the backend reuse is real but not free.

---

## 3. The reference pipeline (the spec to mirror)

From `sc/.../SigmaCompiler.scala`, the Scala compile is:

```
compile(env, code):
  parsed  = SigmaParser(code)                       // String → untyped SValue
  bound   = SigmaBinder(env, predefs, net).bind(parsed)
  typed   = SigmaTyper(...).typecheck(bound)        // Value[SType], fully typed
  graph   = IR.buildGraph(env + placeholders, typed)// Scalan staged graph (cost+lowering)
  tree    = IR.buildTree(graph)                     // graph → ErgoTree SValue
  // then (caller): constant segregation + ErgoTreeSerializer → bytes → address
```

Key observations that drive our design:

1. **It is a classic 3-phase frontend** (parse → bind → type) producing a fully
   typed AST. These map cleanly to Rust modules.
2. **The Graph IR round-trip (`buildGraph`∘`buildTree`) is not a frontend
   concern** — it exists to (a) compute cost and (b) **lower** generic
   `MethodCall` nodes to dedicated, more compact opcodes (`coll.map(..)` →
   `MapCollection`, `Fold`, `Exists`, `ForAll`, `Slice`, `Append`,
   `MultiplyGroup`, `Exponentiate`, …) and (c) introduce **shared `ValDef`s**
   via the graph's hash-consing (common-subexpression elimination). Only (b)
   and (c) affect the serialized bytes.
3. `lowerMethodCalls = true` is the default; `unlowerMethodCalls` in the
   orchestrator enumerates the inverse rewrites and is a near-complete catalog
   of the lowerings we must reproduce.
4. `PK("addr")` is resolved in the **binder** by decoding an Ergo address to a
   `ProveDlog` over the address's group element — pure bytes, no curve math, so
   the compiler can stay crypto-free.

---

## 4. Architecture & layering

A new crate **`ergo-compiler`**, sitting **above `ergo-ser`** and **parallel to
`ergo-sigma`** (it never evaluates, so it does not depend on the interpreter):

```
ergo-primitives  (crypto-free: readers/writers, digests, GE bytes)
      ↑
ergo-ser         (crypto-free wire codecs: opcode IR, SigmaType, write/address)
      ↑                                   ↑
ergo-compiler (NEW)                    ergo-sigma (crypto/eval)
      ↑                                   ↑
            ergo-validation / ergo-api …
```

- **Dependencies:** `ergo-compiler` → `ergo-ser`, `ergo-primitives`. It is
  **crypto-free by default** (address→GE-bytes decoding is already crypto-free
  in `ergo-ser`; `ProveDlog`/`ProveDHTuple` nodes just carry GE bytes), which
  keeps it consistent with the node's crypto-free boundary and does not push
  curve math down a layer. **Caveat:** to reject a malformed `PK("addr")`
  *exactly* as Scala does, an on-curve check at compile time is needed (Scala's
  address decode runs `decodePoint`). Two options (Open Q4): (a) defer — emit
  the tree and let the validator's deserialize-time curve check (the GE fix in
  `tx::ge`) reject it downstream, staying crypto-free; (b) curve-check at
  compile for early rejection, which means an optional `ergo-sigma` (or a small
  curve util) dependency *only* on the `PK` path. **Revised default: (b)**
  (codex). Scala rejects a malformed/off-curve P2PK *at address decode*, so a
  compile/API that defers would **accept input Scala rejects** — a compile-time
  accept/reject divergence, exactly the parity class we care about. Since
  `ergo-ser`'s address decode only length-checks today, the `PK` path needs a
  real on-curve check at compile (small curve util or a scoped `ergo-sigma`
  dep). Keep the rest of the crate crypto-free; isolate crypto to the `PK`/
  address-decode path.
- **Dev-dependencies:** `ergo-sigma` (evaluate compiled trees in tests),
  `ergo-difftest`/scala-cli oracle.
- **Module pattern** (matches the repo's `constants.rs`/`db.rs`/`service.rs`
  convention, adapted to a compiler): one module per phase, each a
  single-responsibility unit with a typed input/output and no shared mutable
  state.

```
ergo-compiler/src/
  lib.rs            // public API: compile(env, src, target) -> CompileResult
  token.rs          // lexer: source → token stream (+ source spans)
  ast.rs            // untyped + typed AST node enums (NOT the opcode IR)
  parse.rs          // tokens → untyped AST (the grammar)
  predef.rs         // predefined-function + global-method registry
  bind.rs           // name resolution, env substitution, PK address decode
  typer/            // type inference + method/overload resolution (the big phase)
    mod.rs
    unify.rs        // type-variable unification
    methods.rs      // SMethod tables + implicit numeric upcast rules
  lower.rs          // MethodCall→dedicated-node lowering + CSE/ValDef sharing
  segregate.rs      // constant-segregation transform (collect/order/dedup)
  emit.rs           // typed AST → ergo-ser opcode IR (Expr/IrNode)
  tree.rs           // assemble ErgoTree (version/header), call ergo-ser write, address
  error.rs          // typed errors with source spans
  env.rs            // ScriptEnv: named constants/types
```

Each phase is independently testable: parser tests assert AST shapes; typer
tests assert inferred types; emit/lower tests assert opcode-IR structure;
end-to-end tests assert byte-identical output vs the JVM oracle.

---

## 5. Acceptance bar — byte-identical, and how it is measured

**Definition of correct:** for a source string `s` and environment `e`,
`ergo-compiler::compile(e, s, target).tree_bytes ==
scala_SigmaCompiler.compile(e, s).tree_bytes`, hence identical P2S address.

**Why byte-identical (not "semantic"):** the on-chain artifact and the address
are functions of the *exact bytes*. A semantically-equivalent-but-different tree
produces a different address, so a contract compiled here would not match an
address a user obtained from standard tooling — defeating the purpose. Bytes are
the contract.

**How measured:** a `scala-cli` oracle wrapping the real `SigmaCompiler`
(extending the existing `scripts/jvm_serde_oracle` pattern), driven over a large
corpus of ErgoScript sources, comparing hex. A divergence is a bug. Confirmed
parity cases are promoted to committed `ergo-compiler` oracle vectors (seed +
source + JVM-blessed expected bytes) — the same "fuzzer is the searchlight,
committed vectors are the ratchet" discipline used for the codecs.

---

## 6. The AST and type system

- **A new typed AST (`ast.rs`), distinct from the opcode IR.** The opcode IR
  (`ergo-ser opcode::Expr` = `Const | Op{opcode, payload}`) is *ErgoTree
  assembly* — positional, opcode-indexed, built for byte round-tripping. A
  compiler needs a *semantic* AST (named operations, method calls with receiver
  types, lambdas with typed params, blocks with `val`s) carrying **source spans**
  for diagnostics and a **type slot per node** filled by the typer. Lowering to
  the opcode IR happens in `emit.rs` as the final step.
- **Reuse `SigmaType`** (`ergo-ser sigma_type::SigmaType`) as the type
  representation — it already models the full type grammar (primitives,
  collections, options, tuples, functions, type vars, `SBox`/`SHeader`/… ). The
  typer annotates AST nodes with `SigmaType`; serialized type tags then come "for
  free" from the existing writer, which is essential for byte parity.
- **Version-gated types** must be honored: the validator rejects
  `Option`/`Header`/`UnsignedBigInt` in some positions pre-v3, etc. The compiler
  must refuse to emit, or emit only at, the appropriate `ergoTreeVersion` (see
  §9).

---

## 7. Phase designs

### 7.1 Lexer (`token.rs`)
Source → tokens with byte spans. ErgoScript's lexical grammar (identifiers,
numeric literals with type suffixes like `1L`, `2.toBigInt`, hex `0x..`,
`Coll(..)`, string literals, operators, `{ } ( ) [ ]`, `=>`, `.`, `,`, `:`,
comments `//` and `/* */`). The Scala parser is `fastparse` (PEG, scanner-less);
we can either mirror that scanner-less style or use an explicit lexer. Explicit
lexer recommended for clearer error spans.

### 7.2 Parser (`parse.rs`)
Tokens → untyped AST. Mirror `SigmaParser` grammar precisely: blocks
(`{ val x = ..; .. }`), lambdas (`(x: Int) => ..`), `if/else`, method/property
calls (`box.value`, `coll.map(..)`), operators with Scala precedence/
associativity, tuples, collection/option literals, numeric literals and their
default types, type ascriptions. Precedence and default literal typing must match
Scala exactly (they change which nodes/types are produced → bytes). The
`ContractParser` layer (`@contract` annotations, doc comments, parameter
metadata) is **optional / phase 2** — base scripts compile without it.

### 7.3 Binder (`bind.rs` + `predef.rs`)
Untyped AST → bound AST:
- Resolve identifiers against the environment, lexical scopes, and the
  **predefined-function registry** (`predef.rs`: `min`, `max`, `allOf`,
  `anyOf`, `atLeast`, `sigmaProp`, `getVar`, `proveDlog`, `decodePoint`, …).
- Substitute environment constants (`ScriptEnv`).
- **`PK("addr")`/`deserialize`/address-literals:** decode the Ergo address to a
  `ProveDlog` over its group element (crypto-free byte decode — already in
  `ergo-ser address`).
- Network prefix matters for address decoding → carried in compiler settings.

### 7.4 Typer (`typer/`) — the hardest phase
Bound AST → fully typed AST. Faithful port of `SigmaTyper` (641 L) + method
tables:
- **Type inference / unification** (`unify.rs`): type variables for
  polymorphic methods (`Coll[A].map[B]`), function types, fold accumulators.
- **Method/overload resolution** (`methods.rs`): the `SMethod` tables per
  receiver type with full type signatures, overloads, type params, per-version
  method availability, and property-vs-method resolution. **Correction (codex,
  verified):** `ergo-ser` does **not** carry typer-grade tables — it has opcode
  *shapes* plus only six `(type_id, method_id)` explicit-type-arg pairs
  (`types.rs` ~535), not signatures/overloads. So these tables are **ported
  fresh from Scala `SMethod`**; reuse `ergo-ser` only for the final
  `(type_id, method_id)` numbering, not for type-checking.
- **Implicit numeric upcasts** (`Byte→Int→Long→BigInt`) and their exact
  insertion points. This is a known parity hazard — see the node's pre-v3
  numeric auto-upcast handling; the compiler must insert `Upcast` nodes exactly
  where Scala does or the bytes differ.
- Output: every node carries a concrete `SigmaType`. Type errors → typed
  diagnostics with spans.

### 7.5 Lowering & subexpression sharing (`lower.rs`) — the byte-determinism crux
This reproduces the **observable net effect** of the Scala Graph IR round-trip
(`buildGraph`∘`buildTree`) **without** building the Scalan staged framework.

Two transformations matter for bytes:
1. **MethodCall lowering** — `unlowerMethodCalls` lists the *core* rewrites
   (`map/fold/exists/forall/slice/append`, `GroupElement.multiply/exp`, …) but
   is **not the whole catalog** (codex). There are **context-dependent special
   cases**: e.g. `SELF.getReg[Int](4)` with a *literal* index folds to the
   legacy `ExtractRegisterAs` primitive (`0xc6`, no MethodCall, no type byte),
   while a *dynamic* index (`getReg[Int](INPUTS.size)`) stays a
   `MethodCall(99,19)` (verified in the test-vectors; matches the node's known
   getReg behavior). The catalog must be built **empirically from the oracle**,
   not assumed from `unlowerMethodCalls` alone. Gated by `lowerMethodCalls`
   (Scala default `true`).
2. **Common-subexpression sharing / `ValDef` introduction** — the Scalan graph
   hash-conses identical subexpressions; `buildTree` then materializes shared
   nodes as `ValDef`s referenced by `ValUse`. **This changes tree structure and
   bytes** and is the single highest-risk parity item. **Sharpened (codex): a
   generic structural CSE pass will NOT match** — the sharing observably depends
   on graph **node identity**, **hash-cons insertion order**, **lowering order**,
   **lambda/`ValDef` id allocation**, **env placeholders**, and source-level
   `val`s. Reproducing it byte-exactly likely means modelling the graph's
   *observable* identity/ordering semantics, not just deduping equal subtrees.

> **Central design decision — replicate Scalan vs. short-circuit it.**
>
> - **Option A — port the Scalan Graph IR (~10.6k L).** Maximum fidelity by
>   construction, but enormous, and most of it (`wrappers/`, costing) is
>   irrelevant to bytes. **Rejected** as disproportionate.
> - **Option B (recommended) — direct AST→AST normalization.** Implement the
>   lowering rewrite set + a dedicated CSE/`ValDef`-numbering pass that
>   reproduces the graph's *observable* sharing, validated to byte-parity by the
>   oracle over a large corpus. Far smaller; the risk is concentrated and
>   directly measurable (any mismatch is an oracle divergence to chase).
> - **Option C — defer sharing.** Emit without CSE first (correct semantics,
>   different bytes), reach byte-parity later. Useful as a **milestone**, not an
>   end state — addresses won't match until sharing is exact.
>
> Recommendation: **B**, reached via **C** as an intermediate milestone. The
> CSE/`ValDef`-numbering rules will likely be the longest pole and may need
> empirical reverse-engineering against the oracle (generate, diff, deduce the
> rule, repeat — exactly the `ergo-difftest` loop, pointed at the compiler).

### 7.6 Constant segregation (`segregate.rs`)
Walk the lowered tree, collect `Const` nodes into the constants table, replace
them with `ConstPlaceholder{index}`. Must match Scala's **collection order and
deduplication** exactly (placeholder indices are serialized → bytes). The node
already *encodes* a segregated tree (`write_ergo_tree` writes the table +
placeholders); only the *transform* is new. Segregation on/off and its default
must match the Scala P2S compile path.

### 7.7 Emit + assemble (`emit.rs`, `tree.rs`)
- `emit.rs`: typed+lowered AST → `ergo-ser opcode::Expr`/`IrNode` (choose
  opcodes, write `ValDef`/`ValUse`/`FuncValue` shapes).
- `tree.rs`: pick the **header byte (default v0 `0x10`, see §9)** + flags, run
  segregation, call the existing `write_ergo_tree` → bytes, then encode.
- **Address construction is route-specific (codex), not a single helper:**
  `encode_address_from_tree_bytes` emits **P2PK** for a bare `ProveDlog` and
  `ergo-ser` deliberately does **not** emit **P2SH**. So `/script/p2sAddress`
  must force the **P2S** encoding over the tree bytes (`encode_p2s`) even for a
  bare-ProveDlog tree, and `/script/p2shAddress` needs its own P2SH construction
  — neither can just call the generic helper.

---

## 8. Public API & delivery surface

Two layers, both thin over `compile()`:

1. **Library API (always):** `ergo_compiler::compile(env, source, target) ->
   Result<CompileResult, CompileError>` where `CompileResult { tree_bytes,
   ergo_tree, address, .. }`. This is the unit other crates/tests use.
2. **REST (the Scala-parity surface):** implement the **compile-requiring
   `/script/*` members** the node currently omits (documented as omitted in
   `ergo-api/src/utils.rs:25`):
   - `POST /script/p2sAddress` `{ "source": "..", "namedConstants": {..} }` →
     `{ "address": ".." }`
   - `POST /script/p2shAddress` → `{ "address": ".." }`
   - (optional) `POST /script/compile`-style returning the ErgoTree hex.
   Response shapes must match Scala `ScriptApiRoute` JSON exactly, consistent
   with the node's existing Scala-compat discipline. `executeWithContext` is a
   later/optional extra (it also needs the evaluator).

Recommendation: build the **library API first** (fully oracle-tested), then add
the REST endpoints as a thin adapter once parity holds.

---

## 9. Language / ErgoTree version targeting — THREE distinct axes

**Correction (codex review, 2026-06-18, verified against
`test-vectors/scala/sigma/v6_methodcall_typeargs_v0_header/`):** do **not**
conflate the request's `treeVersion` with the emitted ErgoTree header version.
The Scala 6.1.2 compiler, given `/script/p2sAddress` with `treeVersion: 3`,
**still emits a v0 header byte `0x10`** (version 0 + constant-segregation, no
size). `treeVersion` gates compiler **method visibility** only (with
`treeVersion` 0/1/2 the same v6-method sources fail to compile), and the header
byte stays `0x10` regardless. Three separate axes must be modelled — collapsing
them will break parity:

1. **Language / method visibility** — which methods/types the *frontend* admits
   (the `treeVersion` request knob). Gates compile accept/reject.
2. **Emitted wire header** — the ErgoTree header byte: version bits, the
   constant-segregation flag, the has-size flag. **Default to the v0 header
   `0x10`** to match Scala; this is a wire-format selector, *not* the language
   version. Getting this wrong changes byte 0 and every address.
3. **Activated-script-version evaluation gates** — what the *validator/evaluator*
   accepts at a given network-activated version (e.g. `SOption`/`SHeader` data
   constants gated on `ergoTreeVersion >= 3`; v6 types rejected in
   registers/context-vars). The compiler's frontend gates must agree with the
   node's validator gates (reuse the validator's version predicates as the
   single source of truth) — but these are distinct from axis 2.

- Byte parity is defined **per (language-version, header) setting**; the oracle
  is invoked with the matching compiler settings, and committed vectors pin both.

---

## 10. Error handling

- Typed errors (`thiserror`) with **source spans**: lexical, syntax, binding
  (unresolved name), type (mismatch/ambiguous overload), version (feature not
  available at target). Each carries a span for caret diagnostics.
- Whether to match Scala's exact error *messages* is a non-goal (messages are
  not consensus/address-bearing); matching error *classification* (does it
  reject what Scala rejects?) is in scope and oracle-checkable (accept/reject
  parity, same as the codec differential surfaces).

---

## 11. Testing & oracle strategy

- **Unit tests per phase** (parser AST shapes, typer inferred types, segregation
  ordering, emit IR shapes) — in-file `#[cfg(test)]` per repo convention, with
  the standard section dividers.
- **JVM byte-parity oracle (the gate):** `scala-cli` process wrapping
  `SigmaCompiler` (extend `scripts/jvm_serde_oracle/`), `compile(source,env)` →
  ErgoTree hex; Rust compiles the same and asserts equal bytes. Drive with:
  - a **curated corpus** (every language construct, the standard library method
    surface, real mainnet contract sources: SigmaUSD, Dexy, Duckpools,
    Spectrum), and
  - a **generative fuzzer** (extend `ergo-difftest`: generate well-typed
    ErgoScript, diff Rust vs JVM bytes) to find the long-tail lowering/sharing
    divergences.
- **Behaviour cross-check:** evaluate compiled trees with `ergo-sigma` (dev-dep)
  to confirm they reduce as expected — a second, independent signal beyond byte
  equality.
- **Oracle-parity rule:** expected bytes always come from the JVM oracle, never
  from our own compiler (no self-oracles), per the repo's consensus-test
  discipline. Committed vectors live under `test-vectors/`.

**Refinements (codex review):**
- **A compile oracle is more than the serde oracle.** The existing
  `scripts/jvm_serde_oracle` is deserialize-only. The compiler oracle must pin,
  in **every committed vector**, the exact Scala **jar/version**, **network
  prefix**, **`treeVersion`**, **namedConstants and their types**, and the
  route/library settings — these all change output bytes.
- **Existing corpus to reuse:** `test-vectors/scala/sigma/` already holds
  Scala-compiler-produced golden vectors (e.g.
  `v6_methodcall_typeargs_v0_header/`, `sbigint_cap_parity/`,
  `coll_updated_parity/`) captured via `/script/p2sAddress` and
  `/script/executeWithContext`. These are a ready starting oracle set and
  document the re-extraction procedure.
- **Avoid fuzzer self-bias:** a Rust-generated "well-typed ErgoScript" corpus
  only explores *Rust's* accepted subset, hiding cases Rust wrongly rejects. The
  strategy needs **independent generation** (mutate Scala-accepted sources /
  real contracts) plus **negative accept/reject cases** checked against Scala,
  not just byte-diffs on Rust-accepted inputs.

---

## 12. Effort & phasing

LOC signals (Scala): parser ~1.2k, binder 122, typer 641, lowering catalog
~1.9k (of a ~10.6k IR we do **not** port wholesale). Rust equivalent is plausibly
**5–9k lines incl. tests**. The cost is **parity debugging, not LOC** — the
typer and the CSE/`ValDef`-sharing pass are the long poles. Realistically a
**multi-month** effort, matching the "full parity" expectation.

Suggested milestones (each independently useful and oracle-gated):

1. **M1 — frontend skeleton:** lexer + parser + untyped AST; round-trip a corpus
   of sources to AST and back to source (sanity), no types yet.
2. **M2 — typer:** binding + type inference + method resolution; assert inferred
   types vs a JVM type-dump oracle.
3. **M3 — emit + *semantic* parity:** typed AST → opcode IR → bytes → address;
   assert the compiled tree **evaluates** identically (via `ergo-sigma`).
   **Note (codex): treat M3 as a *semantic* gate, not a byte-parity gate** —
   "emit without sharing" is **not** a clean byte-parity subset, because header
   choice, segregation, relation compression, lowering, and `ValDef`/id
   allocation must *all* already be correct before any bytes match. Don't read
   partial byte-parity at M3/M4 as progress toward parity.
4. **M4 — writer canonicalization + lowering + segregation:** fix the
   non-canonical writer cases (e.g. Relation2 `0x85`), add MethodCall lowering +
   the special-case catalog + constant segregation. Byte parity becomes
   *possible* (only now).
5. **M5 — CSE/`ValDef` sharing + id allocation:** reach **full byte parity**
   across the corpus and fuzzer (the hard milestone; see R1).
6. **M6 — REST `/script/p2sAddress` + `/script/p2shAddress`** thin adapters,
   Scala-compat JSON.
7. **M7 — `ContractParser` (`@contract`, named params)** and any remaining
   stdlib surface.

A pre-M1 **spike** is recommended: pick ~20 representative mainnet contracts,
dump the JVM compiler's intermediate (typed tree, pre/post-lowering, segregated
tree) and study where sharing/`ValDef`s appear — this de-risks M5 before
committing to M1–M4.

---

## 13. Risks & open questions

- **R1 (highest): CSE/`ValDef` sharing & id numbering.** Reproducing the Scalan
  graph's observable subexpression sharing byte-exactly may require empirical
  reverse-engineering. Mitigation: the M5 milestone + oracle-driven loop; accept
  that full parity may lag semantic parity by a while.
- **R2: typer fidelity.** Implicit upcast insertion, overload resolution, and
  type-var unification must match exactly. Mitigation: a JVM *typed-tree* oracle
  (not just bytes) at M2 so type bugs surface before they become byte bugs.
- **R3: version-gate drift.** Compiler gates must equal validator gates.
  Mitigation: reuse the validator's version predicates as the single source of
  truth rather than duplicating them.
- **R4: stdlib surface size.** The `SMethod` tables are large; partial coverage
  means "compiles a subset." Mitigation: drive coverage from the real-contract
  corpus first (highest user value), expand via fuzzer.
- **Open Q1:** Do we expose `executeWithContext` (needs the evaluator → would
  add an `ergo-sigma` runtime dep to the API path)? Default: **no**, keep the
  compiler crypto-/eval-free; revisit if there's demand.
- **Open Q2:** Should the REST endpoints be feature-gated/off by default (they
  are user-facing compute)? Likely yes, behind config, like other optional API
  surfaces.
- **Open Q3:** Reuse vs. fork of `ergo-ser`'s method tables — confirm they carry
  enough signature info for the typer, or whether the typer needs a richer
  side-table.
- **Open Q4:** `PK`/address curve-check at compile (early reject, needs crypto on
  that path) vs. defer to the validator's deserialize-time check (stay
  crypto-free). Default: defer. See §4.

---

## 14. Decisions captured

- **Compile correctness bar:** byte-identical to Scala `SigmaCompiler` →
  identical P2S address. (User decision, 2026-06-18.)
- **Scope:** full-language parity (not a subset). (User decision.)
- **Placement:** new crypto-free `ergo-compiler` crate above `ergo-ser`,
  parallel to `ergo-sigma`; not below the crypto-free boundary; `sigma-rust`
  stays oracle-only. **M3 resolution of the §4 curve-check option (b):** the
  EC decompress/on-curve primitive lives in `ergo-crypto`
  (`group_element::decompress_to_affine_hex` — it already owned `k256`), and
  `ergo-compiler` depends on `ergo-crypto` (downward-only). Used on the
  `PK`/env-GroupElement paths (D-T5) and the typed-printer rendering (D-T4/6).
- **Graph IR:** do **not** port the Scalan framework; reproduce its observable
  lowering + sharing via direct AST normalization (Option B via C).
- **Costing:** skipped for the compile→bytes path.
- **Status:** design only; implementation deferred to a future cycle.

---

## 15. Codex review (2026-06-18) — findings & disposition

A codex pass reviewed this doc against the repo. 15 findings; the two P0s most
material were **verified directly against repo files**. Disposition:

| # | Sev | Finding | Disposition |
|---|---|---|---|
| 1 | P0 | `treeVersion` ≠ emitted header version (Scala emits v0 `0x10` even at `treeVersion:3`) | **Verified** (test-vector README). §9 rewritten — three version axes. |
| 2 | P0 | `ergo-ser` writer not fully Scala-canonical (Relation2 `0x85` re-emitted expanded) | **Verified** (parse.rs ~433 vs write.rs Two). §2 caveat + M4 writer-canon pass. |
| 3 | P0 | CSE without modelling graph hash-consing/identity/order will fail | Folded into §7.5 + R1 (sharpened). |
| 4 | P0 | Lowering catalog under-specified (literal `getReg`→`ExtractRegisterAs` vs dynamic→MethodCall) | **Verified** (test-vector). §7.5 item 1 — build catalog empirically. |
| 5 | P0 | `ergo-ser` has no typer-grade SMethod tables (only shapes + 6 type-arg pairs) | Folded into §7.4 — port tables from Scala. |
| 6 | P1 | Named-constant/env substitution affects table order/dedup/CSE/placeholder ids | **Noted** — `bind.rs`/`segregate.rs` must reproduce Scala's `env + placeholders` ordering exactly; spec at M4/M5. |
| 7 | P1 | Constant segregation needs stricter spec (order, dedup equality, post-lowering traversal, ValDef interaction) | **Noted** — §7.6 to be specified precisely against the oracle before M4. |
| 8 | P1 | Deferring `PK` curve check breaks compile accept/reject parity | Folded into §4 — **default flipped to curve-check at compile**. |
| 9 | P1 | `/script/p2sAddress`/`p2shAddress` can't reuse the generic address helper | Folded into §7.7 — route-specific construction. |
| 10 | P1 | Version gating = 3 distinct axes | Folded into §9. |
| 11 | P1 | M3–M5 phasing gives misleading byte-parity signals | Folded into §12 — M3 reframed as a *semantic* gate. |
| 12 | P1 | Rust-generated corpus self-biases to Rust's accepted subset | Folded into §11 — independent generation + negative cases. |
| 13 | P1 | Compile oracle must pin jar/version/network/`treeVersion`/namedConstants | Folded into §11. |
| 14 | P2 | M6 (`/script/*`) before `ContractParser` ⇒ advertised route still rejects valid Scala input | **Noted** — either reorder `ContractParser` (M7) before the REST claim, or document the REST surface as "base scripts only" until M7. |
| 15 | P2 | "Not a consensus surface" under-ranks product risk (stranded funds) | Folded into §1 non-goals. |
