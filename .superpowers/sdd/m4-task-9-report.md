# M4 Task 9 — `val` inlining + block flattening + dead-`val` pruning

**Status:** DONE (graduation short of the Task-9 header's optimism on chaincash —
that shortfall is M5-blocking evidence, decoded and reported below, exactly the
`DONE_WITH_CONCERNS` case the brief anticipated).

**Commit:** `feat(compiler): val inlining + pruning (GraphBuilding-exact)` (pending).

## What landed

New module `ergo-compiler/src/inline.rs` with two passes, plus a reject-gate
rewrite and the pipeline wiring in `tree.rs::compile`.

- **`inline_vals`** — reproduces `buildGraph`'s env-threading inline
  (`GraphBuilding.scala:583-604`): single-use `val`s and constant-valued `val`s
  are substituted into every use site; **multi-use non-constant `val`s KEEP
  their `ValDef`** (the M5 CSE surface, untouched); **dead `val`s are LEFT IN
  PLACE** here.
- **`prune_dead_vals`** — reproduces the schedule DCE
  (`ProgramGraphs.scala:35-64`): removes every `val` unreachable from its block
  result and flattens an emptied block to its bare result. Runs AFTER the folds
  and recomputes reachability (so a fold-induced-dead `val`, e.g. sole use erased
  by `x*0→0`, is dropped too).
- **`live_def_ids`** — whole-tree reachability, consumed by the reject gate.

## Rules verified against the pinned checkout (v6.0.2)

| Rule | Scala pin | Verified |
|------|-----------|----------|
| `buildGraph` inlines every `val` via env threading (no `ValDef` in graph) | `GraphBuilding.scala:583-604` (`Block`/`BlockValue` arms) | read source |
| Dead `val`s pruned by schedule DFS from roots | `ProgramGraphs.scala:35-64` | read source |
| `buildTree` re-introduces a `ValDef` only for `hasManyUsagesGlobal && !IsContextProperty && !IsInternalDef && !IsConstantDef` | `TreeBuilding.scala:502-516` (`processAstGraph`) | read source |
| Constants NEVER get a `ValDef` even when multi-use (segregation "equal constants distinct") | `TreeBuilding.scala:508-509` (`IsConstantDef` carve-out) | read source |
| Kept `ValDef` id allocation is schedule-order, `defId=0` top-level, lambda arg `= defId+1` | `TreeBuilding.scala:499/511-513/544`, `buildValue:187-189` | read source |

## Live-oracle probes (committed to `compile_probes.txt` + recaptured into the seed)

All `cc`, testnet, `ORACLE_TREE_VERSION` as noted; each drove a decision:

| Probe | Oracle | Pins |
|-------|--------|------|
| `{ val x = 2; sigmaProp(x + 1 == 3) }` | `sigmaProp(true)` (`10010101d17300`) | inline BEFORE arith fold |
| `{ val x = 2; sigmaProp(x.toByte < 0.toByte) }` | keeps `Downcast(2,Byte)` (`100204040200d18f7d7300027301`) | cast fold BEFORE inline (AST-pattern, `GraphBuilding.scala:514-518`) |
| `{ val unused = 300.toByte; sigmaProp(true) }` | REJECT ArithmeticException | dead-`val` overflow rejects → prune AFTER fold |
| `{ val unused = 2147483647 + 1; sigmaProp(true) }` | REJECT ArithmeticException | (same) eager `buildNode` over dead binds |
| `{ val unused = Coll({(f: Int => Int) => 1}); sigmaProp(true) }` | **OK** | NF-2: nested SFunc-param lambda in a dead `val` ACCEPTS |
| `{ val unused = Coll({() => 1}); sigmaProp(true) }` | REJECT GraphBuildingException | zero-arg lambda rejects even in dead code (NOT exempt) |
| `{ val f = {(x,y)=>..}; val unused = f(1,2); sigmaProp(true) }` | REJECT GraphBuildingException | multi-arg apply rejects even in dead code |
| `{ val unused = Coll[BigInt](); sigmaProp(true) }` | OK | prune BEFORE the v0 gate |
| `{ val a=HEIGHT; val b=a; val c=b; sigmaProp(c>5) }` | `GT(Height,5)` (`1001040ad191a37300`) | chained transitive inline |

Baseline recapture confirmed **zero drift** on the 282 committed vectors; the
8 new probes added with the exact oracle verdicts above (no existing vector
changed).

## Pipeline-order decision (documented in `inline.rs` + `tree.rs`)

Scala interleaves inline (env threading) with the `rewriteDef` fold fixpoint and
runs eager per-bind checks over dead binds before the schedule prunes. The
literal "lowering block, after folds" of locked decision 1 is FALSIFIED by the
probes (it cannot fold `{ val x = 2; x+1==3 }`). Faithful ordering, oracle-pinned:

```
graph_building_lambda_reject   (reachability-based SFunc exemption — NF-2)
fold_direct_const_casts        (cast fold is an AST-pattern; must precede inline)
isProven fusion
inline_vals                    (single-use + const inline; dead + multi-use KEPT)
fold::fold                     (arith fold sees inlined consts; rejects dead-val overflow)
prune_dead_vals                (remove unreachable; before the v0 gate)
v0-data gate → lower → isProven → tuple → segregation
```

This split (inline before fold, prune after) mirrors Scala's
`buildNode`-then-`schedule` exactly: the fold sees inlined constants AND still
rejects overflow in dead `val`s, and the v0 gate never sees v3-only data a
dead `val` (or an inline-then-fold) erases.

## Renumbering decision — NOT done, and why (decoded evidence)

Kept `ValDef`s are NOT renumbered. Decoded the chaincash oracle props from
`compile_seed.json` (`basis-tracker-basis`, `note`): their surviving `ValDef`s
carry **DENSE ids `1,2,3,…`** allocated by `TreeBuilding.processAstGraph` over
the **post-CSE** graph (recon-targets: `basis-tracker` `ValDef:60→25`,
`redemption` `163→58`, `ValUse` counts changing non-trivially). Reproducing
those ids requires the M5 hash-cons / `hasManyUsagesGlobal` model + schedule
order — NOT source-`val` inlining. Two facts make skipping renumbering the sound
choice:

1. **No Task-9 graduation target needs it.** Both pure-inline vectors (2 and
   `lsp/test_contract.es`) inline to a bare body with **zero surviving `ValDef`s**
   — verified byte-exact (`1001040ad191a37300`, `1000d191a3e4c6a70404`).
2. **Renumbering is under-determined without M5** (schedule order + which shared
   subterms become `ValDef`s). Any scheme I invent would be a hack that M5 must
   rewrite. Per the brief's STOP guidance, the chaincash dense-id + CSE pattern
   is M5-blocking evidence, left honest.

A non-renumbered tree stays self-consistent (`ValUse` references by id); it is
byte-divergent from Scala only where M5 is owed. No currently-matching vector has
a surviving `ValDef` (our pre-Task-9 emit kept ALL `val`s, so any match implies
no `val` or all-multi-use → my pass is a no-op there) — so **no MATCH
regression** is possible from skipping renumbering; confirmed by the gate.

## Chaincash outcome

**Do NOT flip** (the Task-9 header's "all 7 should flip — assert it" is
contradicted by the decoded evidence). All 7 stay in `DC7_P2SH_MISMATCH_SET`,
CSE/`ValDef`-sharing-blocked on M5 (surviving multi-use `ValDef`s with dense M5
ids). This is the anticipated M5-blocking spike input, not a hack to force.

## HasSigmas disposition

**Stays deferred.** `val` inlining does NOT expose the `HasSigmas`
SigmaAnd-reconstruction gap (Task 6 deferral) as the SOLE last blocker for any
chaincash vector — each is still CSE-blocked (a strictly larger gap), so there is
still no chaincash vector down to a lone surviving-sigma reconstruction to pin a
byte target against. No reconstruction implemented; documented in `lib.rs` D-C3.

## Graduation summary (telemetry)

- Mismatch SET: **17 → 15** (`DC7_P2SH_MISMATCH_SET` / `P2S_DC1_MISMATCH_SET`).
  Graduated: `{ val x = HEIGHT; x > 5 }`, `corpus:lsp/test_contract.es`. Zero
  regressions (nothing entered).
- byte-parity telemetry: **78/95 → 80/95** on the original seed; **85/100** after
  the 8 recaptured probes (all 5 new ACCEPT probes byte-match).
- **NF-2 CLOSED** (D-C5 class 3): reachability-based transitive dead-flag
  exemption; ledger graduated in `lib.rs`.
- **D-C6 self-check narrowed** (bonus graduation, not in the seed): the val-bound
  `Coll[UnsignedBigInt]().size` case now inlines+folds to the oracle-identical
  `10010400d1937e730005c1a7` (byte + address exact) — the NF-1 "val-behind"
  closure; `tree.rs` self-pin updated from reject to byte-exact accept.
- The val-bound `getReg` self-pin now inlines the index (Task 9), leaving only
  the getReg dynamic→static lowering as the residual (updated in `tree.rs`).
- Residual 15 = the M5 acceptance benchmark: 7 chaincash + 5 crystalpool +
  `dexy/gort-dev/emission.es` + `rosen-bridge/GuardSign.es` + `proveDHTuple`.

## Self-review

- **Correctness:** live-use counting is over the reachable subtree (dead-`val`
  uses excluded), so a once-live-once-dead `val` inlines exactly as Scala's
  post-DCE count dictates (unit + full-pipeline tests). Global-unique emit ids
  mean no scope shadowing; substitution is dependency-ordered so env values are
  fully resolved.
- **Reject parity:** the gate keeps zero-arg / multi-arg-apply rejects
  unconditional (eager) and dead-exempts only SFunc-param `MatchError`
  (schedule-pruned) — all 5 boundary probes match.
- **Known single-pass limitation (documented):** a multi-use `val` a fold later
  reduces to single-use is not re-inlined (Scala's `toExp` fixpoint would); no
  Task-9 target hits it (those are M5-CSE-blocked regardless).
- **Gate:** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets
  --all-features -D warnings`, `cargo test --workspace` all green; no `#[allow]`.

## Follow-up: controller-probe divergence — dense id renumbering (commit cd492b3)

**Finding.** New probe `{ val t = HEIGHT + 1;
sigmaProp(OUTPUTS.exists({(b: Box) => b.creationInfo._1 < t})) }` graduated the
cross-lambda inline correctly (Plus(Height, 1) landed inside the lambda body)
but left a numbering gap: our M3 emit allocates ids over the PRE-inline source
tree, so `val t` took id 1 and the lambda arg `b` took id 2; inlining `t` erased
its `ValDef` but not the id, so `b` stayed at 2 (`d90102`) while the oracle's
post-inline schedule gives it id 1 (`d90101`). Surfaced as a 1-entered
`DC7_P2SH_MISMATCH_SET` failure.

**Fix.** Added `crate::inline::renumber_dense` (runs immediately after
`prune_dead_vals`): fires ONLY when the tree has no surviving `ValDef`/`FunDef`
anywhere (every remaining id is then a `FuncValue` arg with no M5 sharing
decision outstanding), renumbers those ids 1..N in pre-order first-appearance
order, and rewrites both the `FuncValue` arg slots and their `ValUse`
references. A tree that keeps a `ValDef` — the M5 schedule-order/CSE surface —
is left completely untouched, per the brief's boundary. Documented in the
`crate::inline` module docs ("Dense id renumbering" section) alongside the
existing pipeline-order rationale.

**Printing question (item 3): verdict (a), cosmetic.** The gate's D-C7 triage
`eprintln!` computed `ours_prop` from `ours.ergo_tree.body` — the
POST-segregation body, still carrying `ConstPlaceholder`s — while `oracle_prop`
re-inlined the oracle's placeholders first. The two were never on equal
footing for a segregated `ours` tree, independent of any real bug: `compile()`
itself always hashed the PRE-segregation, genuinely-inlined `root` for
`p2sh_address` (tree.rs, unchanged), so the actual P2SH computation was never
wrong. Fixed the test's `ours_prop` to run through `inline_placeholders` with
`ours.ergo_tree.constants`, matching the oracle side; re-verified the fix
against the corpus (p2sh_match count and the mismatch-set membership are
identical before/after — only the diagnostic hex printed for the
still-diverging D-C7 vectors changed from placeholder bytes to inlined-constant
bytes).

**Verification.** `cargo test -p ergo-compiler --test compile_semantic_parity`:
`DC7_P2SH_MISMATCH_SET` / `P2S_DC1_MISMATCH_SET` back to 15/15, zero entered,
zero left. Added 4 `crate::inline` unit tests (gap-closing happy path,
surviving-`ValDef` no-op, nested-lambda density, already-dense no-op) and 1
`tree.rs` full-pipeline byte-exact oracle test (tree bytes + both addresses
against the captured 2026-07-07 vector). Full workspace gate (`cargo fmt --all
-- --check`, `cargo clippy --workspace --all-targets --all-features -D
warnings`, `cargo test --workspace`) green; no `#[allow]`. Duplicate probe
`{ val unused = 2147483647 + 1; sigmaProp(true) }` verified as an
already-committed REJECT/ArithmeticException vector (pre-existing coverage,
no new fix needed).
  11 `inline` unit tests + 6 `tree` full-pipeline byte-exact tests added.
