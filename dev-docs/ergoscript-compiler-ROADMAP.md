# ErgoScript Compiler — Roadmap (living doc)

> Single source of truth for milestone status. Grounded in the design doc
> (`ergoscript-compiler-design.md` §12) and what has actually shipped on
> `feat/ergoscript-compiler`. Update the checkboxes + "Last updated" as work lands.
> (dev-docs is gitignored; this file is deliberately committed via `git add -f` as the
> project's status anchor, like `m2-deferred-items.md`.)

**Last updated:** 2026-07-07 (M3 complete at `7fadf32` + close-out)
**Branch:** `feat/ergoscript-compiler` (worktree `ergoscript-compiler`) — NOT pushed / NOT PR'd
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
| **M4** | Writer canonicalization + lowering catalog + constant segregation | ~15% | ⬜ TODO (next) |
| **M5** | CSE / ValDef-sharing → **full byte parity** (the hard one) | ~25% | ⬜ TODO |
| **M6** | REST `/script/p2sAddress` + `/script/p2shAddress` | ~3% | ⬜ TODO |
| **M7** | `ContractParser` (`@contract`, named params) + stdlib tail | ~7% | ⬜ TODO |

**Overall: ≈ 50% by effort** (M1 + M2 + M3 shipped). The fat tail is **M5** (Scalan CSE/ValDef
byte-parity) — deliberately front-loaded in the design as the top risk.

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
  (`test-vectors/ergoscript/compile/compile_seed.json` — every vector carries the ORACLE's
  tree hex = ready M4/M5 byte targets); 79 real contracts (M1 parse-verdicts + M2
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
on the JVM oracle + the 271-vector `compile_seed.json` (every vector carries the
oracle's tree hex). Gate: SigmaBoolean-exact semantic parity on all 80 swept accepts
(after 5 D-C3 `SEMANTIC_SKIP`), exact reject-class parity on the reject vectors, and a
per-vector P2SH address gate (D-C7 mismatches pinned at 44). All M2 deferrals closed
(D-T2 base58/64, D-T3, D-T4/D-T5/D-T6, D-T12 folds; `SWEEP_SKIP` emptied) except
`deserialize` (re-scoped to M4). Codex still rate-limited → same in-house 6-finder
adversarial-oracle-differential substitute (~400 probes) → 10 root-cause families fixed
across 4 waves (GraphBuilding reject-gate parity D-C5, evaluability lowerings D-C6,
constant-fold overflow check, P2SH re-scope + address gate D-C7); regression re-verify
(150 live probes): 13 CLOSED / 5 LEDGERED / 0 REGRESSED / 2 NEW reject-valid
(NF-1/NF-2, dispositioned into the ledger). 5389 workspace tests green.

## M4 — Writer canon + lowering + segregation ⬜ TODO (next)

- [ ] **Writer-canonicalization audit** — `ergo-ser`'s writer is NOT fully Scala-canonical
      today (e.g. Relation2 `0x85` compact form re-emitted expanded). Verified design §2 gap.
- [ ] MethodCall→primitive **lowering catalog** — build empirically from the oracle
      (`unlowerMethodCalls` is not the whole set). M3 already landed the literal-`getReg`→
      `ExtractRegisterAs` split (D-C6 item 1; dynamic stays MethodCall, val-bound const
      propagation still open) and the explicit-type-arg irBuilder routing (D-C6 item 2).
      Harvest cannonQ's LOWERING-SHAPE-AUDIT.
- [ ] **Constant segregation** transform (collect/order → ConstPlaceholder); placeholder
      indices are serialized — see the worklist below for the exact Scala shape.
- [ ] typer-grade SMethod tables already ported in M2 — reuse for M4 numbering agreement.

### M4 worklist (from M3 — read before starting)

Sources: the lib.rs D-ledger, the `dev-docs/ergoscript-compiler-m3-recon/` dossiers +
adversarial-findings reports + `regression-reverify.md` (gitignored-local; the facts
below are self-contained).

**Segregation transform (the D-C1 flip):**
- Scala `withSegregation` (`ErgoTree.scala:384-398`) collects constants as a SIDE EFFECT
  of serialization: single traversal, **slot = position = order of first write** during
  the serialization traversal; then a **serialize→re-read round-trip** materializes the
  `ConstantPlaceholder` nodes (step 5-6 of the recon §3 walkthrough) — reproduce the
  shape, not just the effect.
- **NO dedup** of equal constants — each occurrence gets its own slot
  (`TreeBuilding.scala:506-509` "two equal constants don't always have the same meaning"
  strongly implies; recon OPEN QUESTION 1: confirm in `ConstantStore.scala` FIRST).
- Bare-`SigmaPropConstant` roots stay `withoutSegregation` `0x00` on BOTH sides, and
  `proveDlog(<any const point>)` FOLDS into that class in Scala's IR (M3 Task-1 oracle
  fact) — segregated test fixtures need non-foldable scripts.
- `ergo-ser`'s writer auto-compacts a Relation2 over two literal-Boolean `Const`s into
  `BoolCollection` `0x85` (`write.rs` `relation2_bool_pair`) — emit must NOT double-handle.

**Lowering/fold catalog = the D-C7 no-IR-optimization family** (each landed rule moves
`EXPECTED_DC7_P2SH_MISMATCHES` — 44 today — DOWN, deliberately; the oracle tree hexes in
`compile_seed.json` are the ready byte targets, and the gate's byte-parity telemetry
becomes the M4/M5 progress meter):
- **constant folding**: env consts (`ccs` closures fold to `sigmaProp(true)`),
  whole-expression folds, non-overflowing arith (the OVERFLOW check already landed as a
  D-C5 gate), `== false` → `LogicalNot`; the **UBI-fold family (NF-1)** — equality /
  tuple-select / val-bound UBI-constant shapes — closes here too (do NOT weaken the v0
  UBI-data gate; non-foldable shapes still need it);
- **`val` inlining + unused-`val` pruning** — also closes NF-2 (SFunc-param lambda nested
  in an unused val's rhs body) and the D-C6 item-1 residual (val-bound `getReg` index
  const-propagation);
- **explicit-cast folds, BOTH directions**: Scala folds argument casts we keep as
  `Downcast` nodes, while WE fold literal upcast chains Scala keeps
  (`1.toByte.toLong.toBigInt` — numerics N-3 probe 34); either direction moves bytes;
- **`CreateProveDlog(const)` → `SigmaPropConstant`** (D-C2);
- **D-C3 `isProven` → `isValid` elimination** and **D-C4 multi-arg-lambda TUPLING**
  (1-arg `FuncValue` over `STuple` + `SelectField` projections) — the two families whose
  current output is unevaluable on both sides;
- single-element `anyOf`/`atLeast` **unwrap**; bare-ident context/global singletons →
  `PropertyCall` lowering; env `Coll[Long]` **per-element lift** (`Coll[Byte]` lifts as
  one constant on both sides);
- **CSE/ValDef sharing** of repeated subterms → M5 (do not fake it with heuristics here).

**Also at M4:**
- **`deserialize` predef** (D-T2 residual, re-scoped here): needs the
  opcode-IR→`TypedExpr` reverse mapping — build it alongside the lowering catalog, which
  wants the same mapping.
- **`TyperCtx.lower_method_calls` is a DEAD flag** (`typer/mod.rs`; recon-typed-ast.md) —
  wire it up or delete it when the catalog lands.
- **D-E1 `CreateAvlTree` 0xB6** ergo-ser↔Scala accept-set divergence → hand to the
  **fuzz-differential backlog**, not a compiler fix (a Scala tree carrying it would
  mis-parse in ergo-ser).
- Residuals that stay until real partial evaluation exists: D-T12 string-fold residual
  (opaque env SigmaProp, ByteColl/LongColl RHS), D-C6 item-3 deeper-constant-receiver
  v6-method folds (arith results, multi-cast chains).

## M5 — CSE / ValDef byte parity ⬜ TODO (highest risk)

- [ ] Reproduce the Scalan graph's **observable** subexpression sharing + ValDef
      introduction + id numbering — WITHOUT porting the ~10.6k-line Scalan framework
      (design decision: Option B via C). This is the top risk; may need empirical
      reverse-engineering against the oracle (generate/diff/deduce/repeat).
- [ ] cannonQ proved heuristic-counting + patches plateaus below parity here; their
      end-state note says the fix is Scalan-faithful hash-cons + serial per-scope id
      emission (which they identified but never built). Start from that architecture.

## M6 — REST endpoints ⬜ TODO

- [ ] `POST /script/p2sAddress` + `/script/p2shAddress` in `ergo-api` (calls DOWN into
      `ergo-compiler`; documented-omitted at `ergo-api/src/utils.rs:25`). Scala-compat JSON.
- [ ] Optional: feature-gate behind config (user-facing compute).

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
