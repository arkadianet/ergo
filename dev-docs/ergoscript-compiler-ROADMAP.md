# ErgoScript Compiler — Roadmap (living doc)

> Single source of truth for milestone status. Grounded in the design doc
> (`ergoscript-compiler-design.md` §12) and what has actually shipped on
> `feat/ergoscript-compiler`. Update the checkboxes + "Last updated" as work lands.
> (dev-docs is gitignored; this file is deliberately committed via `git add -f` as the
> project's status anchor, like `m2-deferred-items.md`.)

**Last updated:** 2026-07-07 (M4 complete at `19409da` + adversarial-clean close-out)
**Branch:** `feat/ergoscript-compiler` (worktree `ergoscript-compiler`) — pushed for external
audit (branch only, NO PR / NO merge until the compiler is finalized)
**End goal:** byte-identical ErgoTree output vs Scala `SigmaCompiler` (sigma-state 6.0.2)
→ identical P2S/P2SH address. Bytes are the contract; a wrong tree = wrong address =
stranded funds, so the bar is byte-parity, not semantic equivalence.

---

## Progress at a glance

| Milestone | Scope | Effort weight | Status |
|---|---|---|---|
| **M1** | Lexer + parser + untyped AST | ~20% | ✅ **DONE** — 14-round codex-clean |
| **M2** | Binder + typer (typed AST) | ~20% | ✅ **DONE** — oracle-parity + adversarial-clean |
| **M3** | Emit → opcode IR → bytes → address; *semantic* parity | ~10% | ✅ **DONE** — semantic + address gate, adversarial-clean |
| **M4** | Writer canonicalization + lowering catalog + constant segregation | ~15% | ✅ **DONE** — 95/110 byte-exact, adversarial-clean |
| **M5** | CSE / ValDef-sharing → **full byte parity** (the hard one) | ~25% | ⬜ TODO (next) — spike DONE, model validated 6/6 |
| **M6** | REST `/script/p2sAddress` + `/script/p2shAddress` | ~3% | ⬜ TODO |
| **M7** | `ContractParser` (`@contract`, named params) + stdlib tail | ~7% | ⬜ TODO |

**Overall: ≈ 65% by effort** (M1–M4 shipped). The remaining fat tail is **M5** (Scalan CSE/
ValDef byte-parity) — the M4-recon spike (`dev-docs/ergoscript-compiler-m5-recon/spike-scope-chain.md`,
gitignored-local) validated a source-grounded scope-chain hash-cons model 6/6 against the live
oracle, so M5 is de-risked from "research" to "empirical implementation against a known model"
(~450-650 LOC, HIGH risk concentrated in intra-scope schedule order).

**M4 result:** 95/110 committed compile vectors are **byte-identical** to Scala 6.0.2
(`tree_bytes` + P2S + P2SH); the 15 residual mismatches are **exactly** the CSE/ValDef-sharing
class = the M5 acceptance benchmark (chaincash ×7, crystalpool ×5, dexy emission, rosen-bridge,
proveDHTuple). Semantic parity is 110/110 (every vector reduces to the same SigmaBoolean; 0
semantic skips). Two milestone-end adversarial passes (M3: 10 finders, M4: 5 finders) found
zero surviving verdict/semantic/evaluability divergences; all byte residuals are ledgered
(D-C1..D-C8) as M5 or bounded-known.

---

## Shipped assets (carry forward to every later milestone)

- **`ergo-compiler` crate** — leaf crate, deps: `thiserror` + `ergo-ser`/`ergo-primitives`
  (downward-only; `ergo-sigma` dev-dep for the M3 semantic gate). Public API today:
  `parse()`, `parse_type()`, `typecheck()`/`typecheck_with_network()`, `compile()` →
  `CompileResult` (tree bytes + P2S + P2SH). M3 also added `encode_p2sh` to `ergo-ser`.
- **JVM oracles** (scala-cli, sigma-state 6.0.2, Maven Central):
  - `scripts/jvm_parser_oracle/ParserOracle.scala` — accept/reject + position (M1)
  - `scripts/jvm_typer_oracle/TyperOracle.scala` — typed-AST s-expr (tc/tce/tcs verbs +
    `tc1.sh` fresh-JVM mode for reject positions) (M2) **+ compile verbs cc/cce/ccs**
    (source → ErgoTree hex + P2S/P2SH addresses) (M3)
- **Test corpora:** 229-record typer golden seed; **271-vector compile seed**
  (`test-vectors/ergoscript/compile/compile_seed.json` — the 85 ACCEPT vectors carry the
  ORACLE's tree hex + addresses = ready M4/M5 byte targets; REJECTs carry verdict +
  class); 79 real contracts (M1 parse-verdicts + M2
  typed-verdicts + M3 compile-verdicts, all 0-divergence); 29 CC0 contracts vendored from
  the cannonQ fork (`test-vectors/ergoscript/cannonq/` — **sources only; bytes must be
  re-derived vs 6.0.2**).
- **Gates** (M3, `tests/compile_semantic_parity.rs`): semantic gate — every swept accept
  reduces to the SAME SigmaBoolean as the oracle tree under a dummy context; address
  gate — per-vector P2SH pin with the D-C7 mismatch count hard-asserted
  (`EXPECTED_DC7_P2SH_MISMATCHES = 44`, counts DOWN as M4/M5 lowerings land).
- **Deviation ledger** (`ergo-compiler/src/lib.rs`): M1 deviations + M2 `D-T1..D-T12` +
  M3 `D-E1..D-E3` (emit) + `D-C1..D-C7` (tree/compile). Doubles as the fuzzer/oracle
  exclusion gate.
- **cannonQ fork = spec mine for M4/M5** (`dev-docs/cannonq-fork-evaluation/`): CC0,
  reached ecosystem 14/14 byte-MATCH but hit an *admitted architectural ceiling* at
  exactly the M5 CSE crux — independent proof the design's Scalan-faithful approach is
  necessary. Harvest their lowering-shape catalog + 80-falsified-hypothesis map; do NOT
  port their heuristic-CSE code.

---

## M1 — Frontend ✅ DONE

Lexer + recursive-descent parser + untyped AST, production-faithful to `SigmaParser`.
87/87 `SigmaParserTest` properties ported (verbatim fail positions); 14 codex rounds
(each found real emergent-grammar divergences — bare `{}` rejects, `⇒` is an op-id,
lone-CR untokenizable, etc.). Codex-clean at round 14.

## M2 — Binder + Typer ✅ DONE

`SigmaBinder` + `SigmaTyper` port → typed AST byte-matching the reference typer's
canonical s-expr. Full `SigmaTyperTest` port (59+1 props, reject classes *tighter* than
Scala); 79/79 corpus typed-verdict parity (empty allowlist). Because codex was
rate-limited, ran an in-house 6-finder adversarial-oracle-differential substitute
(~600 probes) → found + fixed 10 real divergences the per-task reviews missed
(type-param-method rejection, `min`/`max` env gap, `Global.xor` lowering, v5 numeric
owner, SFunc `[T]` printing, serialize untyped-args, string folds). Re-verified vs the
live oracle AND the real `compiler.compile` pipeline.

**Known deferrals into M3+** (lib.rs `D-T*` + `m2-deferred-items.md`): GroupElement/
ProveDlog constant-payload rendering (D-T4/D-T6 — `SWEEP_SKIP`'d, 8 records — the "7"
previously stated here was corrected by the M3 recon), on-curve PK check,
`deserialize`/`unsignedBigInt` canonical node build, `bigInt` literal canonicalization.
**All closed in M3** (D-T2 fromBase58/64 + D-T3/D-T4/D-T5/D-T6/D-T12 folds; `SWEEP_SKIP`
emptied) except `deserialize`, re-scoped to M4 — see the M4 worklist.

---

## M3 — Emit + semantic parity ✅ DONE

Typed AST → opcode IR (`emit.rs`) → ErgoTree bytes + P2S/P2SH (`tree.rs`; `encode_p2sh`
added to `ergo-ser`); `compile()` live end-to-end, `PK(...)` bare-constant class byte-
and address-EXACT vs the oracle. Oracle infrastructure: `cc`/`cce`/`ccs` compile verbs
on the JVM oracle + the 271-vector `compile_seed.json` (85 ACCEPT vectors carry the
oracle's tree hex + addresses). Gate: SigmaBoolean-exact semantic parity on all 80 swept accepts
(after 5 D-C3 `SEMANTIC_SKIP`), exact reject-class parity on the reject vectors, and a
per-vector P2SH address gate (D-C7 mismatches pinned at 44). All M2 deferrals closed
(D-T2 base58/64, D-T3, D-T4/D-T5/D-T6, D-T12 folds; `SWEEP_SKIP` emptied) except
`deserialize` (re-scoped to M4). Codex still rate-limited → same in-house 6-finder
adversarial-oracle-differential substitute (~400 probes) → 10 root-cause families fixed
across 4 waves (GraphBuilding reject-gate parity D-C5, evaluability lowerings D-C6,
constant-fold overflow check, P2SH re-scope + address gate D-C7); regression re-verify
(150 live probes): 13 CLOSED / 5 LEDGERED / 0 REGRESSED / 2 NEW reject-valid
(NF-1/NF-2, dispositioned into the ledger). 5389 workspace tests green.

## M4 — Writer canon + lowering + segregation ✅ DONE (`19409da`)

Ten reviewed tasks (`2d63e0b`..`19409da`), each landed as an AST→AST pass over the
`ergo-ser opcode::Expr` IR between emit and write, graduating committed vectors out of the
set-based mismatch gates. Final: **95/110 byte-exact**, 110/110 semantic, 0 skips.

- [x] **Constant segregation (D-C1 flip)** — write-time constant-sink through `ergo-ser`'s
      `write_expr` mirroring Scala's `withSegregation` serialize→getAll→re-read exactly
      (append-only `ConstantStore`, slot = first-write order, NO dedup); consensus paths
      proven byte-unchanged (396 ergo-ser tests + ~4,564-tree mainnet round-trip). Flipped
      34 vectors.
- [x] **Constant-fold engine** (`fold.rs`) — a faithful port of the `rewriteDef` cascade
      (algebraic identities, both-const arith with fold-time overflow reject, env-const
      propagation, div/mod on non-zero divisor, De Morgan / `!Const` flips, `SizeOf`
      literal fold, all-const `anyOf`/`allOf`) — NOT a general evaluator. Closed NF-1.
- [x] **Explicit-cast folds, both directions** (`tree.rs::fold_direct_const_casts`) —
      fold single const casts (Scala AST-match, non-cascading so chains keep) AND stop
      over-folding literal chains Scala keeps.
- [x] **D-C2** `CreateProveDlog/DHTuple(const)` → `SigmaPropConstant` + single-element
      sigma unwraps (`lower.rs`).
- [x] **D-C3** `SigmaPropIsProven` elimination + Bool↔Sigma reconstruction (`isproven.rs`)
      — emptied `SEMANTIC_SKIP`; every vector semantic-gated again.
- [x] **D-C4** multi-arg lambda TUPLING (`tuple.rs`) — 1-arg `FuncValue(STuple)` +
      `SelectField`, fold-slot lambdas now evaluable.
- [x] **Singleton PropertyCall lowering + `deserialize`** (`emit.rs` + `predef_ir.rs`
      reverse map) — closed the D-T2 residual; `lower_method_calls` dead flag deleted;
      **D-C8** records the `allZK`/`anyZK`/`outerJoin` upstream-unimplemented predefs
      (both sides reject `StagingException`, sigmastate#543).
- [x] **`val` inlining + block flattening + dead-`val` pruning + dense renumbering**
      (`inline.rs`) — GraphBuilding-exact usage-count materialization; closed NF-2 and the
      D-C6 val-bound-`getReg` residual; dense id renumber for `ValDef`-free trees (per-
      disjoint-scope restart, `processAstGraph` curId parity).
- [x] **Adversarial re-verify** (5 finders) + **M5 spike** — see close-out below.

**Canonical `compile()` pass order** (the actual pipeline, superseding the plan's original
locked-decision-1 literal ordering — order is probe-pinned to mirror Scala's `rewriteDef`
cascade; each step cites `tree.rs::compile`):
`emit → D-C5 reject gates → fold_direct_const_casts → isProven(1) → inline_vals →
fold(1) → prune_dead_vals → renumber_dense → v0-data gate → lower (D-C2/unwraps/
singletons/getReg) → fold(2, D-C2-exposed Const==Const) → isProven(2) → tuple_lambdas →
segregate → write_ergo_tree`. Segregation is LAST; folds run before the v0 gate (closes
NF-1); `fold` runs twice (saturating; the second pass only sees `lower`-newly-exposed
`Const==Const`).

**The 15 residual byte-mismatches = the M5 acceptance benchmark** (all semantically equal,
all in `DC7_P2SH_MISMATCH_SET`): chaincash-basis ×7 + crystalpool ×5 + dexy/gort-dev
emission + rosen-bridge/GuardSign + `proveDHTuple(g1,g2,g1,g2)`. Each is CSE/ValDef-sharing
+ schedule-order id allocation — decoded oracle trees show multi-use `ValDef`s with dense
schedule-order ids that source-level `val` inlining cannot reproduce.

**Deferred out of M4 (unchanged):** D-E1 `CreateAvlTree` 0xB6 ergo-ser↔Scala accept-set
divergence → fuzz-differential backlog; D-T12 string-fold residual (opaque env SigmaProp,
ByteColl/LongColl RHS); D-C6 item-3 deeper-constant-receiver v6-method folds; D-C7
`Coll(true,false)==Coll(true,false)` leaf-triviality fold-lift (a bounded accept-side
residual, fenced for self-readability).

## M5 — CSE / ValDef byte parity ⬜ TODO (next; highest risk, now de-risked)

**Spike DONE** — `dev-docs/ergoscript-compiler-m5-recon/spike-scope-chain.md` (gitignored-
local) is the validated spec: a source-grounded model of Scala's CSE machinery, **6/6
oracle predictions correct** (hand-decoded trees), anchored on a 29-`ValDef` chaincash
vector. Key facts the M5 plan builds on:

- **Identity = scope-chained hash-cons, decided by FIRST-BUILD SITE** (`Base.scala:777-808`,
  `Thunks.scala:180-226`): a `Def` interns globally when the thunk stack is empty, else into
  the innermost open `ThunkScope.bodyDefs`; siblings are never on each other's parent chain,
  so a subexpression first built inside one branch is invisible to its sibling. The keystone
  experiment (two sources differing only in an `if` condition → one shares a ValDef, the other
  emits two copies) **falsifies every use-count-or-LCA model**, cannonQ's included.
- **Which builders push a thunk scope:** `If` branches, `&&`/`||` right arms, `getOrElse`
  defaults — **NOT** `FuncValue`/lambda bodies (a cannonQ error corrected: `Functions.scala:359`
  pushes only `lambdaStack`; body membership is decided later by dependency scheduling).
- **ValDef placement** = the one scope whose schedule contains the symbol
  (`TreeBuilding:501-517`), gated by `hasManyUsagesGlobal && !IsContextProperty &&
  !IsInternalDef && !IsConstantDef`; usage count is over the FLAT schedule (the phase that
  reconciles scope-chained identity with global counting).
- **Ids assigned serially once, top-down, NO renumber pass** (root ValDef starts at 1;
  lambda arg = `defId+1`; **tuple arg = one id → `+1` not the M4-provisional `+2`**). The M4
  `inline`/`renumber_dense` passes RETIRE into the M5 pass.

- [ ] Build `mir/cse.rs` (~450-650 LOC): scope-stack hash-cons over our `Expr` + flat usage
      count + per-scope schedule + ValDef materialize + assign-ids-once threading. Retire the
      M4 inline/renumber passes into it. Gate on BOTH the ValDef set+ids AND the constant-pool
      multiset+order (never byte-total).
- [ ] **Top remaining risk (ORACLE-NEEDED):** intra-scope schedule order — which same-scope
      multi-use symbol gets id 1 vs 2 (Scala `depthFirstOrderFrom(deps)`); our build order must
      match byte-for-byte. Reverse-engineer against the 15-vector benchmark (generate/diff/
      deduce/repeat) — this is where cannonQ plateaued.

## M6 — REST endpoints ⬜ TODO

- [ ] `POST /script/p2sAddress` + `/script/p2shAddress` in `ergo-api` (calls DOWN into
      `ergo-compiler`; documented-omitted at `ergo-api/src/utils.rs:25`). Scala-compat JSON.
- [ ] Optional: feature-gate behind config (user-facing compute).
- [ ] **Recursion depth guards before untrusted input** (final M3 review): `parse`,
      `emit`, and the tree.rs walks are recursion-unbounded — fine for trusted CLI/test
      input, a stack-overflow DoS surface once REST exposes them. Bound or iterative-ize
      before the endpoints ship.

## M7 — ContractParser + stdlib tail ⬜ TODO

- [ ] `@contract` annotations, doc comments, named-parameter metadata (the parser layer
      M1 deliberately deferred).
- [ ] Remaining stdlib method-surface coverage driven by the real-contract corpus + fuzzer.

---

## Cross-cutting / open decisions

- **Placement:** in-workspace leaf crate, "node now, library later" — keep deps downward
  only so a future crates.io extraction stays a lift-and-shift.
- **`sigma-rust` stays oracle/reference-only**, never linked into production (repo rule).
- **PR strategy:** nothing pushed yet. M1+M2 could go as one "frontend" PR when ready;
  or hold until M3 gives an end-to-end source→address demo. User's call.
- **Codex:** rate-limited until ~Aug 3 — use the in-house adversarial-oracle-differential
  substitute (6 region-scoped finders vs the live oracle) as the SANTA-conformance
  stand-in until it's back.
