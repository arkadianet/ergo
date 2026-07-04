# ErgoScript Compiler — Roadmap (living doc)

> Single source of truth for milestone status. Grounded in the design doc
> (`ergoscript-compiler-design.md` §12) and what has actually shipped on
> `feat/ergoscript-compiler`. Update the checkboxes + "Last updated" as work lands.
> (dev-docs is gitignored; this file is deliberately committed via `git add -f` as the
> project's status anchor, like `m2-deferred-items.md`.)

**Last updated:** 2026-07-04 (M2 complete at `c883cd5`)
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
| **M3** | Emit → opcode IR → bytes → address; *semantic* parity | ~10% | ⬜ TODO (next) |
| **M4** | Writer canonicalization + lowering catalog + constant segregation | ~15% | ⬜ TODO |
| **M5** | CSE / ValDef-sharing → **full byte parity** (the hard one) | ~25% | ⬜ TODO |
| **M6** | REST `/script/p2sAddress` + `/script/p2shAddress` | ~3% | ⬜ TODO |
| **M7** | `ContractParser` (`@contract`, named params) + stdlib tail | ~7% | ⬜ TODO |

**Overall: ≈ 40% by effort** (M1 + M2 shipped). The fat tail is **M5** (Scalan CSE/ValDef
byte-parity) — deliberately front-loaded in the design as the top risk.

---

## Shipped assets (carry forward to every later milestone)

- **`ergo-compiler` crate** — leaf crate, deps: `thiserror` + (M2) `ergo-ser`/`ergo-primitives`
  (downward-only). Public API today: `parse()`, `parse_type()`, `typecheck()`.
- **JVM oracles** (scala-cli, sigma-state 6.0.2, Maven Central):
  - `scripts/jvm_parser_oracle/ParserOracle.scala` — accept/reject + position (M1)
  - `scripts/jvm_typer_oracle/TyperOracle.scala` — typed-AST s-expr (tc/tce/tcs verbs +
    `tc1.sh` fresh-JVM mode for reject positions) (M2)
  - **M3 needs a compile oracle** (source → ErgoTree hex) — extend the pattern or use the
    node REST `/script/p2sAddress` route (precedent: `test-vectors/scala/sigma/v6_*`).
- **Test corpora:** 143-record typer golden seed; 79 real contracts (M1 parse-verdicts +
  M2 typed-verdicts, both 0-divergence); 29 CC0 contracts vendored from the cannonQ fork
  (`test-vectors/ergoscript/cannonq/` — **sources only; bytes must be re-derived vs 6.0.2**).
- **Deviation ledger** (`ergo-compiler/src/lib.rs`): M1 deviations + M2 `D-T1..D-T12`.
  Doubles as the fuzzer/oracle exclusion gate.
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
ProveDlog constant-payload rendering (D-T4/D-T6 — `SWEEP_SKIP`'d, 7 records), on-curve PK
check, `deserialize`/`unsignedBigInt` canonical node build, `bigInt` literal canonicalization.

---

## M3 — Emit + semantic parity ⬜ TODO (next)

**Goal:** typed AST → `ergo-ser` opcode IR → ErgoTree bytes → P2S address; assert the
compiled tree **evaluates identically** via `ergo-sigma` (dev-dep). Design §12 M3 note:
treat this as a *semantic* gate, NOT byte-parity — header/segregation/lowering/ValDef
must ALL already be right before any bytes match, so don't read partial byte-parity here
as progress.

**M3-first tasks (from the M2 final review — do these before lowering):**
- [ ] Stand up the compile oracle (source → ErgoTree hex, 6.0.2).
- [ ] Re-capture the deferred typed-shape records: golden_seed §17 accept shapes,
      postfix-ident method calls (`xs size`), tuple dynamic-index — freeze before building.
- [ ] Fix **D-T6** (GroupElement storage form: 33-byte key, not hex placeholder) early —
      flips the 7 `SWEEP_SKIP` records into byte-sweep coverage, widening the always-on net.
- [ ] emit.rs: typed AST → `opcode::Expr`/`IrNode` (opcode selection, ValDef/ValUse/
      FuncValue shapes).
- [ ] tree.rs: header byte (default v0 `0x10`, §9), assemble, `write_ergo_tree`, address.
      Note the 3 version axes (language-visibility ≠ wire-header ≠ activated-eval-gate).
- [ ] Address construction is route-specific (§7.7): `/script/p2sAddress` forces P2S even
      for bare-ProveDlog; P2SH needs its own path.

## M4 — Writer canon + lowering + segregation ⬜ TODO

- [ ] **Writer-canonicalization audit** — `ergo-ser`'s writer is NOT fully Scala-canonical
      today (e.g. Relation2 `0x85` compact form re-emitted expanded). Verified design §2 gap.
- [ ] MethodCall→primitive **lowering catalog** — build empirically from the oracle
      (`unlowerMethodCalls` is not the whole set; literal `getReg`→`ExtractRegisterAs` vs
      dynamic→MethodCall is context-dependent). Harvest cannonQ's LOWERING-SHAPE-AUDIT.
- [ ] **Constant segregation** transform (collect/order/dedup → ConstPlaceholder); match
      Scala's exact order + dedup (placeholder indices are serialized).
- [ ] typer-grade SMethod tables already ported in M2 — reuse for M4 numbering agreement.

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
