# Codex Audit Prompt — ErgoScript→ErgoTree compiler (`ergo-compiler`)

> Give this file (and repo access at branch `feat/ergoscript-compiler`) to the auditor.
> It is self-contained: scope, ground truth, how to drive the oracle, the exclusion gate,
> and the evidence bar. **Status at audit time: M1–M4 complete (M5 not yet started).**

## 1. What you are auditing

A from-scratch **ErgoScript source → ErgoTree compiler** implemented in Rust as the
in-workspace leaf crate `ergo-compiler`, plus its writer-side support in `ergo-ser` and an
EC helper in `ergo-crypto`. It mirrors the Scala reference compiler
`sigmastate.lang.SigmaCompiler` at **sigma-state 6.0.2**. The pipeline:

```
source → parse (token.rs, parse.rs) → bind (binder.rs) → typecheck (typer/, typecheck.rs)
       → emit (emit.rs: typed AST → ergo-ser opcode::Expr IR)
       → transform passes (tree.rs::compile, in this exact order):
           D-C5 reject gates → fold_direct_const_casts → isProven(1) → inline_vals
           → fold(1) → prune_dead_vals → renumber_dense → v0-data gate
           → lower (lower.rs) → fold(2) → isProven(2) → tuple_lambdas
       → segregate (write-time constant sink) → write_ergo_tree → P2S/P2SH address
```
Public API: `ergo_compiler::compile(env, source, tree_version, network) -> CompileResult
{ tree_bytes, ergo_tree, p2s_address, p2sh_address }`, plus `parse`/`typecheck`.

**The bar is BYTE parity**, not semantic equivalence: a wrong tree = wrong address =
stranded funds. The end goal is `compile()` output byte-identical to Scala 6.0.2 for the
full language. **M5 (CSE/ValDef sharing) is NOT done** — see §5 for the exact known gap.

## 2. Ground truth — where "correct" is defined

**Scala is the sole authority.** Two forms, both pinned to 6.0.2:

1. **Pinned source checkout:** `ergo-core/sigmastate-interpreter-v6.0.2`.
   ⚠️ The *plain* `sigmastate-interpreter` checkout is 6.0.3+ and **differs** — never cite it.
   Every behavioral claim in the crate's doc-comments cites this tree as `file:line`.

2. **Live JVM oracle** (`scripts/jvm_typer_oracle/TyperOracle.scala`, scala-cli, sigma-state
   6.0.2 from Maven Central). Drive it:
   ```
   printf '<verb> %s\n' "$(printf '<source>' | od -A n -t x1 | tr -d ' \n')" \
     | scala-cli run scripts/jvm_typer_oracle 2>/dev/null | grep -E '^(OK|REJECT|ERR)'
   ```
   Verbs: `tc`/`tce`/`tcs` = typecheck (→ canonical typed-AST s-expr); `cc`/`cce`/`ccs` =
   full compile (→ `OK <tree_hex> <p2s> <p2sh>` | `REJECT <line>:<col> <ExClass>` | `ERR`).
   Envs: `c*` empty; `*ce` demo (`a,b:Coll[Byte]; col1,col2:Coll[Long]; g1,g2=G; g3=7·G;
   n1:BigInt=5; bb1,bb2:Byte`); `*cs` SigmaTyperTest (`x,y:Int; height1,height2:Long;
   b1,b2:Byte; arr1,arr2:Coll[Byte]; g1,g2=2·G; p1,p2:SigmaProp; n1,n2,big:BigInt` — NOTE
   `ccs` `col1`/`col2` are a per-element `ConcreteCollection` env artifact the real API can't
   produce; don't use them for byte probes). Knobs: `ORACLE_TREE_VERSION` (default 3),
   `ORACLE_NETWORK` (default testnet). Batch probes per JVM spawn; retry transient failures.

**Do not accept a finding grounded in anything but these two.** cannonQ (a prior fork) is
6.1.2-derived and is NOT authority; the crate's own tests are consistency checks, not oracles.

## 3. The corpus and the gates (your regression surface)

- `test-vectors/ergoscript/compile/compile_seed.json` — **110 committed compile vectors**
  (85+ ACCEPT carry the oracle's `tree_hex` + P2S + P2SH; REJECTs carry verdict + class).
  Regenerated ONLY by the `#[ignore]` recapture test from `compile_probes.txt`; oracle
  fields are **never hand-edited**.
- `test-vectors/ergoscript/typer/golden_seed.txt` — the typed-AST oracle corpus (M1/M2).
- `ergo-compiler/tests/compile_semantic_parity.rs` — the always-on gate: every ACCEPT
  vector must (a) compile, (b) reduce to the **same SigmaBoolean** as the oracle tree under a
  pinned dummy context (semantic parity, cost-free), and (c) its byte/P2S/P2SH status is
  tracked by **set-based** asserts: `DC7_P2SH_MISMATCH_SET` and `P2S_DC1_MISMATCH_SET` are the
  *exact* committed sets of still-diverging labels — a vector entering OR leaving without a
  deliberate edit fails loudly. `AUDITED_ERR_PAIRS` similarly pins every Err/Err class-pair.
- Current standing: **95/110 byte-exact, 110/110 semantic, 0 skips.** The 15 byte-mismatches
  are the M5 set (§5).
- Run the whole gate: `cargo test --workspace` (and the `#[ignore]` recapture needs scala-cli).

## 4. The deviation ledger = the KNOWN-EXCLUSION gate (read before reporting)

`ergo-compiler/src/lib.rs` carries an exhaustive deviation ledger: M1 lexical deviations,
**D-T1..D-T12** (typer), **D-E1..D-E3** (ergo-ser accept-set), **D-C1..D-C8** (compile/byte).
Each entry states the exact divergence, its direction, why it is bounded, and its closer.

**A divergence already in the ledger is NOT a finding** — it is a documented, deliberate,
oracle-grounded decision. Report it only if you can show the ledger's *characterization* is
wrong (e.g. it claims "both sides reject" but the oracle accepts — that kind of error has
been found and fixed before, and is exactly what we want you to hunt). An **un-ledgered**
divergence, or a ledger entry contradicted by a live probe, IS a finding.

## 5. The known M5 gap — OUT OF SCOPE as a "bug"

The 15 residual byte-mismatches (all semantically correct, all in `DC7_P2SH_MISMATCH_SET`)
are the **CSE/ValDef-sharing** class, deferred to M5: chaincash-basis ×7, crystalpool ×5,
dexy/gort-dev emission, rosen-bridge/GuardSign, `proveDHTuple(g1,g2,g1,g2)`. Scala's Scalan
graph hash-conses repeated subexpressions into `ValDef`s with schedule-order ids; we don't
yet. This is expected and planned (`dev-docs/ergoscript-compiler-ROADMAP.md` M5 section +
the `spike-scope-chain.md` model). **Do not report these as bugs.** DO report if you find a
16th byte-mismatch outside this set, or a mismatch in this set that is *also* a **semantic**
divergence (that would be a real bug, not just missing CSE).

## 6. Where to spend your effort (highest-risk surfaces)

Ranked by consequence (wrong bytes = wrong address):

1. **The opcode/emit table** (`emit.rs`, `ergo-ser/src/opcode/`) — a wrong opcode byte or
   payload shape that still round-trips (e.g. swapped relation bytes with swapped operands)
   is the worst silent-failure class. Cross-check against `OpCodes.scala` (pinned,
   `data/shared/.../serialization/OpCodes.scala`) and `methods.scala` wire ids.
2. **The fold engine** (`fold.rs`) — over-folding (we fold where Scala keeps a node) is a
   byte divergence; a fold that changes a *value* is a consensus-class semantic bug. Probe
   the boundaries: div/mod (folds only on non-zero divisor), Negation (never folded),
   BigInt arith (never folded), min/max, De Morgan flips, all-const collections.
3. **Constant segregation** (`ergo-ser/src/opcode/write.rs` constant sink + `tree.rs`) — slot
   ordering (append-only, NO dedup, serialization-traversal order), the Relation2 `0x85`
   bool-pair carve-out, the header flip (bare `SigmaPropConstant` → `0x00`, else `0x10`).
   This is consensus-adjacent: verify the sink is byte-inert for non-compiler `write_ergo_tree`
   callers (the crate proves it via a ~4,564-tree mainnet round-trip — re-run it).
4. **EC / curve handling** (`ergo-crypto/src/group_element.rs`, D-T4/5/6) — GroupElement is
   stored as 33 SEC1 bytes; on-curve validation at `env::lift`/`bind_pk`; the printer
   decompresses to Scala's *unpadded* `BigInteger.toString(16)` affine hex (a leading-zero
   coordinate is the trap — already caught once, verify it stays fixed).
5. **The reject gates** (`tree.rs::graph_building_lambda_reject`, the D-C5 gates) — verdict
   parity AND error-class parity where reproducible; the direction matters (reject-valid
   strands nothing; accept-invalid can).
6. **Address construction** (`tree.rs` + `ergo-ser/src/address.rs`) — P2S forced over tree
   bytes; P2SH = `blake2b256(inlined-proposition).take(24)` (NOT the tree bytes); network
   prefix arithmetic; the bare-const vs segregated header branch.

## 7. The evidence bar (same standard held internally)

Every reported finding must carry: the **source probe**, the **verbatim oracle reply**, the
**verbatim `compile()`/`typecheck()` output**, the **divergence class** (verdict / semantic /
unevaluable / byte-or-address), an **exclusion-gate check** (confirm it is NOT in the D-ledger,
the mismatch sets, or the 15-vector M5 set), and **reproduction** (twice, both sides). A
finding without an oracle probe is not a finding — it is a hypothesis. Rank by fund-risk
direction: accept-invalid (we accept a tree Scala rejects, or emit bytes Scala wouldn't) is
the severe class; reject-valid and byte-only-with-equal-semantics are lower.

Two milestone-end in-house adversarial passes (M3: 10 finders; M4: 5 finders, ~150 probes)
found zero surviving verdict/semantic/evaluability divergences — so the reachable-from-real-
contracts surface is already hardened. The highest-value new findings will be in the long
tail: exotic language constructs, deep nesting, unusual constant shapes, version-gate edges
(tree_version 0/1/2 vs 3), and any place a doc-comment's Scala citation doesn't actually say
what the code assumes.
