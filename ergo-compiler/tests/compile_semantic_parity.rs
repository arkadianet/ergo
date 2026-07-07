//! Compile-vector corpus + SigmaBoolean semantic-parity gate (M3 Task 10).
//!
//! The M3 acceptance test for [`ergo_compiler::compile`]: our compiled trees
//! must EVALUATE identically to the Scala-compiled trees across the whole
//! corpus, even though the byte representations legitimately differ until the
//! M4 constant-segregation transform (we emit non-segregated header `0x00`;
//! Scala segregates every non-bare-constant root, header `0x10`).
//!
//! **Vector corpus** (`test-vectors/ergoscript/compile/compile_seed.json`):
//! every typecheck-ACCEPT source in `golden_seed.txt` fed through the matching
//! compile verb of the JVM oracle (`tc`→`cc`, `tce`→`cce`, `tcs`→`ccs`;
//! `scripts/jvm_typer_oracle/TyperOracle.scala`, sigma-state 6.0.2,
//! `ORACLE_TREE_VERSION=3`, `ORACLE_NETWORK=testnet`), plus the 79-contract
//! real-world corpus (`test-vectors/ergoscript/corpus/`) under `cc`, plus
//! the compile-only probe list (`compile_probes.txt`, Task-11 wave-1
//! GraphBuilding gate vectors, per-line `ORACLE_TREE_VERSION`). Oracle
//! REJECTs for golden-seed/probe sources are recorded verbatim (a
//! typecheck-accept may compile-reject — that verdict is signal, cf.
//! golden_seed §22); corpus compile-REJECTs are counted in the JSON
//! `_source` note and excluded, per the task brief. No oracle field is ever
//! hand-edited.
//!
//! **The gate** ([`compile_seed_semantic_parity`], always-on, committed JSON
//! only):
//! - oracle REJECT → our `compile()` must also reject (class advisory only);
//! - oracle ACCEPT → our `compile()` must accept, and BOTH our
//!   `ergo_tree.body` and the parsed oracle `tree_hex` body must reduce — via
//!   `ergo_sigma::evaluator::reduce_expr` under the difftest-pinned dummy
//!   context (`ergo-difftest/src/oracle.rs:400-431`, field-for-field) — to
//!   the SAME `write_sigma_boolean` hex (NO cost comparison). `Err/Err` is
//!   parity (both error strings recorded as telemetry — the design for
//!   context-bound scripts that read registers/OUTPUTS the dummy context
//!   lacks); mixed `Ok`/`Err` is a FAIL.
//! - byte telemetry (non-gating): counts `tree_bytes == tree_hex`; equality
//!   is ASSERTED for the bare-constant class, keyed on the ORACLE tree's
//!   root (`Const SigmaProp` — the one class where Scala also takes the
//!   `withoutSegregation` branch, generalizing Task 9's single PK pin).
//!   An oracle-bare vector where OUR root is not bare fails loudly unless
//!   listed in `ORACLE_BARE_FOLD_EXCLUSIONS` (D-C2), so a PK-class
//!   regression cannot silently demote itself out of the byte gate
//!   (Task-11 finding H-3).
//! - address gate (Task-11 findings H-1/H-2): the oracle's committed
//!   `p2sh_address` must be reproducible from its OWN tree via placeholder
//!   substitution + `encode_p2sh` (pins the substitution helper on every
//!   vector); wherever our proposition bytes equal the oracle's
//!   constant-inlined proposition, our P2SH address MUST equal the
//!   oracle's (P2SH is segregation-invariant — D-C1's true scope); the
//!   byte-diverging remainder is the D-C7 "no IR optimization pass" family
//!   (lib.rs ledger), SET-pinned to `DC7_P2SH_MISMATCH_SET` (M4 Task 1,
//!   recon-gap.md Finding 5: a set, not a count — a compensating regression
//!   must fail loudly). P2S must match exactly where the tree bytes match
//!   (bare-const class) and differs everywhere else by D-C1 construction (we
//!   never segregate; Scala always does for non-bare roots) — SET-pinned to
//!   `P2S_DC1_MISMATCH_SET` the same way (nearly empties out once Task 2's
//!   segregation transform lands).
//!
//! **Live recapture** ([`compile_seed_live_recapture`], `#[ignore]`): spawns
//! the oracle once (batch stdin, EOF-close, grammar grep-filter — the
//! `corpus_smoke.rs` pattern), regenerates the JSON, and diffs it against the
//! committed file (capture-date field excluded); on drift it refreshes the
//! file on disk and fails so the diff can be reviewed. Needs `scala-cli` on
//! PATH (+ network on first run):
//!
//! ```text
//! cargo test -p ergo-compiler --test compile_semantic_parity -- --ignored --nocapture
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ergo_compiler::{compile, CompileResult, EnvValue, GroupElement, NetworkPrefix, ScriptEnv};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::address::encode_p2sh;
use ergo_ser::ergo_tree::{read_ergo_tree, ErgoTree};
use ergo_ser::opcode::{write_expr, Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{write_sigma_boolean, AvlTreeData, SigmaValue};
use ergo_sigma::evaluator::{reduce_expr, EvalBox, ReductionContext, SECP256K1_GENERATOR};

// =============================================================================
// SEMANTIC_SKIP — semantic-gate exclusions (same discipline as SWEEP_SKIP).
// =============================================================================
//
// `(source, reason + ledger tag)` pairs excluded from the semantic-parity
// sweep. Every entry needs a reason and a lib.rs ledger D-tag.
//
// EMPTY as of M4 Task 6 — the list is EMPTIED, every ACCEPT vector is
// semantic-gated again. It formerly held the five D-C3 sources (sources mixing
// SigmaProp and Boolean in a logical context: `sigmaProp(true) && (1 == 1)` &
// mirror, `sigmaProp(true) ^ (1 == 1)` & mirror, `allOf(Coll(proveDlog(g1)))`).
// Those typecheck into trees carrying `BoolToSigmaProp`/`SigmaPropIsProven`
// round-trip coercions (wire opcode 0xCF, which no evaluator accepts). The
// D-C3 elimination pass (`crate::isproven`, GraphBuilding.scala:188-189/245-252
// `sigmaProp(bool).isValid → bool` / `sigmaProp(p.isValid) → p`) now cancels
// them before/after the fold+lower block, so all five compile to the same
// folded, EVALUABLE tree Scala emits (byte-identical to the oracle) and pass the
// semantic gate with no skip. Kept as a documented mechanism for the next
// unevaluable-output class this discipline would catch — e.g. the
// surviving-sigma `HasSigmas` `SigmaAnd`/`SigmaOr` reconstruction that the five
// chaincash/rosen corpus contracts still need (a residual 0xCF, MULTI-blocked
// on val-inline/CSE, Tasks 8/9 — those stay in `DC7_P2SH_MISMATCH_SET`, not
// here, because verdict parity holds via Err/Err on the dummy context).
//
// EMPTY as of M4 Task 6 (D-C3 CLOSED for these five). The
// `SigmaPropIsProven` elimination pass (`crate::isproven`) now cancels the
// `BoolToSigmaProp`/`SigmaPropIsProven` round-trip coercions before/after the
// fold+lower block, so all five sources compile to the folded, EVALUABLE tree
// Scala emits — byte-identical to the oracle (`allOf(Coll(proveDlog(g1)))` →
// bare `SigmaPropConstant` `0008cd02…`; `sigmaProp(true) && (1 == 1)` →
// `BoolToSigmaProp(BinAnd(true, true))` `1000d1ed8503`; the `^` forms →
// segregated `false` `10010100d17300`). They are semantic-gated again — no
// skip needed. Kept as a documented mechanism for the next unevaluable-output
// class this discipline would catch (the surviving-sigma `HasSigmas`
// SigmaAnd/SigmaOr reconstruction is Tasks 8/9 corpus work, not a skip here).
const SEMANTIC_SKIP: &[(&str, &str)] = &[];

// =============================================================================
// Address-parity constants (Task-11 wave 3: findings H-1/H-2/H-3).
// =============================================================================

// Sources where the ORACLE tree root is a bare `SigmaPropConstant` but OURS
// deliberately is not — the ONE tolerated class of oracle-bare/ours-not
// asymmetry; any other vector where the oracle root is bare and ours is not
// is a PK-class regression and fails loudly (finding H-3: the old gate keyed
// the byte check on OUR OWN output class, so such a regression could
// silently demote a vector to semantic-only parity). D-C3's
// `allOf(Coll(proveDlog(g1)))` is also oracle-bare but sits in SEMANTIC_SKIP
// above, so it never reaches this classification. Every entry must fire — a
// stale entry fails the sweep.
//
// EMPTY as of M4 Task 3: the two prior entries (`proveDlog(g1)`,
// `proveDlog(g3)`) existed because Scala folds `CreateProveDlog(<GroupElement
// const>)` into a bare `SigmaPropConstant` while we emitted the unfolded
// `0xCD` node. `crate::lower`'s D-C2 fold now runs before `build_tree`, so
// both vectors are bare on OUR side too (D-C2 CLOSED) — they graduated into
// the ordinary `bare_total`/`bare_match` counters below instead. Kept as a
// mechanism (not deleted) for the next partial-fold gap this class of
// asymmetry can recur under.
const ORACLE_BARE_FOLD_EXCLUSIONS: &[(&str, &str)] = &[];

/// `(verb, source)` label for a vector, used as the key in the SET-based
/// parity gates below (M4 Task 1, recon-gap.md Finding 5). Corpus-sourced
/// vectors key on `corpus:<relative path>` instead of their `source` (a
/// whole `.es` contract is unfit as a `&'static str` literal in a committed
/// constant); seed/probe vectors key on the literal source text, matching
/// the `label` computed in the sweep below minus its debug-quoting.
fn mismatch_label(v: &Vector) -> (String, String) {
    match &v.corpus_path {
        Some(p) => (v.verb.clone(), format!("corpus:{p}")),
        None => (v.verb.clone(), v.source.clone()),
    }
}

/// Compare a freshly-swept mismatch-label SET against a committed constant,
/// failing loudly in EITHER direction (recon-gap.md Finding 5): a vector
/// ENTERING the set (a regression, or an un-triaged new probe) is just as
/// much a test-integrity failure as one LEAVING it silently (a landed
/// lowering that graduated a vector without updating the constant — the
/// cannonQ "count stayed put, so nobody noticed the compensating
/// regression" anti-pattern this whole mechanism exists to catch). The
/// failure message prints both diffs as ready-to-paste `(verb, source)`
/// tuple lines so updating the constant after a deliberate graduation is a
/// copy-paste, not a hand-transcription.
fn assert_mismatch_set_matches(
    gate_name: &str,
    actual: &std::collections::BTreeSet<(String, String)>,
    committed: &[(&str, &str)],
) {
    let committed_set: std::collections::BTreeSet<(&str, &str)> =
        committed.iter().copied().collect();
    let actual_borrowed: std::collections::BTreeSet<(&str, &str)> = actual
        .iter()
        .map(|(verb, src)| (verb.as_str(), src.as_str()))
        .collect();
    let entered: Vec<&(&str, &str)> = actual_borrowed.difference(&committed_set).collect();
    let left: Vec<&(&str, &str)> = committed_set.difference(&actual_borrowed).collect();
    let fmt = |xs: &[&(&str, &str)]| -> String {
        xs.iter()
            .map(|(verb, src)| format!("    ({verb:?}, {src:?}),"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert!(
        entered.is_empty() && left.is_empty(),
        "{gate_name} mismatch SET changed — {} entered (regression or un-triaged new \
         probe; investigate before adding), {} left (a lowering graduated them — remove \
         deliberately, never silently):\nENTERED (not in the committed constant):\n{}\n\
         LEFT (in the committed constant but no longer mismatching):\n{}",
        entered.len(),
        left.len(),
        fmt(&entered),
        fmt(&left),
    );
}

/// Committed SET of `(verb, source)` labels whose P2SH address differs from
/// the oracle's — the D-C7 "no IR optimization pass" family (lib.rs ledger):
/// P2SH hashes the constant-inlined proposition, so it diverges exactly
/// where Scala's GraphBuilding transforms the tree shape (const folds, val
/// inlining/pruning, CSE/ValDef sharing, single-element anyOf/atLeast
/// unwrapping, explicit-cast folds, bare-ident PropertyCall lowerings). The
/// set INCLUDES the D-C2 and D-C6-residual instances of the family (e.g. the
/// two `proveDlog(const)` fold vectors) — every P2SH divergence shares the
/// one root cause.
///
/// SET, not a count (M4 Task 1, recon-gap.md Finding 5): a count assert is
/// blind to a compensating regression — a fold that un-matches a previously
/// exact vector while a coincidental shape change matches a different one
/// leaves the total unchanged. The set catches both directions. GRADUATION:
/// every M4 task that lands a lowering must remove the vectors it fixes from
/// this set EXPLICITLY (never silently, never widen it to paper over a new
/// regression — fix the regression instead, the cannonQ anti-pattern this
/// gate exists to prevent).
///
/// History: 39 → 44 (wave-4 review follow-up: 5 new ACCEPT probes, all
/// fold-family instances) → 43 (M4 Task 1: `sigmaProp(col1.slice[Long](0,
/// 1).size == 1)` re-captured under `cce` instead of `ccs` — gap F2, its
/// `ccs`-only mismatch was an oracle-env artifact, not a real IR-transform
/// divergence; the `cce` capture is byte-identical to ours and graduates
/// out) → 39 (M4 Task 3: the D-C2 `proveDlog(const)` fold + single-element
/// `anyOf`/`atLeast`-Coll unwrap graduate `anyOf(Coll(HEIGHT > 5))`,
/// `atLeast(1, Coll(proveDlog(g1)))`, `proveDlog(g1)`, `proveDlog(g3)` —
/// recon-targets.md vectors #12/#15/#14/#29; `proveDHTuple(g1, g2, g1, g2)`
/// (#17) stays — it needs M5 CSE/ValDef sharing, not this fold: Scala's
/// hash-consing turns the REPEATED point into a shared `ValDef` before
/// `buildValue`'s fold-check runs, so the fold-check's four-`Constant` guard
/// never fires on the oracle side either) → 36 (M4 Task 4: the explicit-cast
/// direct-constant fold graduates `arr1.exists`/`arr1.filter`/
/// `arr1.getOrElse` (recon-targets.md vectors #61/#60/#62 — the `0.toByte`/
/// `9.toByte`/`1.toByte` literal argument casts now fold, matching the
/// oracle exactly); #73/#84/#85 (`bitwiseAnd`/`bitwiseOr`/`bitwiseXor` over
/// folded-cast Byte operands) stay MULTI — the surrounding `Eq` only folds
/// once Task 5's generic constant-folding engine lands). 36 vectors, derived
/// from a full gate run against the M4 Task-1 seed (`compile_seed.json`, 272
/// vectors, 80 ACCEPT swept; byte-parity telemetry 44/80 → 45/81 after the M4
/// Task 4 crux-regression pin `sigmaProp(1.toByte.toLong.toBigInt >
/// 0.toBigInt)`, which byte-matches the oracle and so is ordinary telemetry,
/// not this set) → 17 (M4 Task 5: the generic constant fold graduates 19
/// CONST-FOLD vectors — `!true`, `1 < 2L`, the four `+`/`-` overflow-boundary
/// arith folds (#49/#50/#51/#83), `min`/`max` (#81/#82), the three `.size`
/// folds (#77/#79/#80), `true && (1 == 1)`, `true ^ false`, and the six ccs/cc
/// bitwise-then-relational MULTI vectors (#70/#71/#72/#73/#84/#85) that now
/// FULLY fold to `sigmaProp(true)`. Five div/mod + two anyOf/allOf ACCEPT
/// probes were added to `compile_probes.txt` in lockstep — division/modulo DO
/// fold on a NON-ZERO constant divisor (`DivOp.shouldPropagate = rhs != 0`,
/// source-authoritative, correcting the dossier's "never folded" note). The 17
/// residual are all MULTI: 12 corpus (CSE/val-inline/lowering, Tasks 8/9/M5) +
/// `{ val x = HEIGHT; x > 5 }` (val-inline, Task 9) + `proveDHTuple(g1, g2, g1,
/// g2)` (CSE repeated-point, M5); byte-parity telemetry 45/81 → 71/88.
///
/// M4 Task 6 (D-C3): the set is UNCHANGED at 17. The five graduated D-C3
/// SEMANTIC_SKIP sources were never in this set — they were skip-gated, so
/// removing the skip (they now byte-match, byte-parity 72/89-swept → 77/94-swept
/// with 0 skipped) adds five clean matches without touching the residual. The
/// D-C3 corpus ingredients that DO sit here (recon-targets #31/#32/#35/#36/#48 =
/// the chaincash-basis + `rosen-bridge/GuardSign.es` `cc` entries) stay MULTI:
/// their `SigmaPropIsProven:1→0`/`SigmaAnd:0→1` needs the surviving-sigma
/// `HasSigmas` reconstruction (NOT the coercion cancellation Task 6 landed) AND
/// they are co-blocked on val-inline/CSE (Tasks 8/9) — so they only flip when
/// those land, left here honestly per the plan's graduation discipline.
///
/// M4 Task 9 (`val` inlining + dead-`val` pruning + block flattening): 17 → 15.
/// The two PURE single-use-inline vectors graduate — `{ val x = HEIGHT; x > 5 }`
/// (→ `GT(Height, 5)`, no block) and `corpus:lsp/test_contract.es`
/// (`{ val deadline = SELF.R4[Int].get; sigmaProp(HEIGHT > deadline) }` →
/// `GT(Height, SELF.R4[Int].get)`, oracle `1000d191a3e4c6a70404`) — both inline
/// to a bare body with ZERO surviving `ValDef`s, so no id renumbering is needed.
/// The seven chaincash-basis `cc` entries do NOT graduate: their oracle props
/// carry surviving `ValDef`s with DENSE ids `1,2,3,…` allocated by
/// `TreeBuilding.processAstGraph` over the POST-CSE graph (e.g.
/// `basis-tracker` `ValDef:60→25`, `redemption` `163→58`). Reproducing that
/// needs the M5 hash-cons/`hasManyUsagesGlobal` model + schedule-order id
/// allocation, not source-`val` inlining — decoded, M5-blocking, left here
/// honestly (see `.superpowers/sdd/m4-task-9-report.md`). `proveDHTuple(g1, g2,
/// g1, g2)` (repeated-point CSE), the five crystalpool + `dexy/gort-dev` (pure
/// CSE) and `rosen-bridge/GuardSign.es` entries stay MULTI on M5 too — the 15
/// residual are exactly the M5 acceptance-benchmark set. byte-parity telemetry
/// 78/95 → 80/95.
///
/// M5 Task 4 (CSE wired as the SOLE sharing pass, `inline_vals`/`renumber_dense`
/// retired): 15 → 11. FOUR corpus vectors graduate now that CSE's scope-chain
/// hash-cons + `hasManyUsagesGlobal` ValDef materialization is live in
/// `compile()` — `chaincash/layer2-old/redemption.es`, `.../redproducer.es`,
/// `crystalpool/deposit.es` and `dexy/gort-dev/emission.es` reach byte-exact
/// ValDef sets/ids. ZERO regressions (every previously-matching vector still
/// matches — CSE fully subsumes the retired inline/renumber). The 11 residual
/// are the multi-ValDef SCHEDULE-ORDER + lambda-float-up vectors (chaincash ×5,
/// crystalpool ×4, `GuardSign.es`, `proveDHTuple(g1,g2,g1,g2)`) — placement is
/// right, intra-scope id order / float-up is Task 5. byte-parity 95/110 →
/// 99/110.
///
/// M5 Task 5 Fix 2 (type-aware P4 `is_const`): 11 → 10. `proveDHTuple(g1,g2,g1,
/// g2)` graduates. A `GroupElement` literal is a `LiftedConst`, not Scala's
/// narrow `Const[_]`, so P4 cannot suppress it — the repeated point CSE-hoists to
/// `ValDef(1)` (oracle `d801 d601 7300 ce 7201 7201 7201 7201`). Two coupled
/// edits made it live: `cse::is_const` now keys on the SType, and
/// `lower::fold_prove_dlog_dhtuple` folds the 4-const proveDHTuple only when the
/// points are pairwise DISTINCT (a repeat means CSE shares it first, exactly as
/// Scala hash-conses before its four-`Constant` fold-guard). byte-parity
/// 99/110 → 100/110.
///
/// M5 Task 5 Fix 1a (per-scope `depthFirstOrderFrom` + freeVars-as-deps +
/// deps-based lambda float-up): 10 → 8. `note.es` and `reserve.es` graduate —
/// their nested-scope ValDef schedule (sibling id-range reset, lambda-arg id
/// collision) now matches the oracle byte-for-byte. Of the 8 residual, THREE
/// (`basis-tracker-basis`, `offchain/basis`, `GuardSign`) are now byte-identical
/// to the oracle EXCEPT the HasSigmas `SigmaAnd`(0xea)/`SigmaPropIsProven`(0xcf)
/// reconstruction — the CSE schedule is correct; they stay blocked on the
/// surviving-sigma reconstruction (D-C3, Tasks 8/9), NOT on schedule order. The
/// other FIVE (`basis-token`, crystalpool `buy`/`sell`/`swap-tokens-denom`/
/// `swap-tokens`) need a NOT-yet-modelled rule: a PURE-CONSTANT expression
/// (`sigmaProp(false)`, the default `Coll[SigmaProp]`, `Coll[Byte]()`) built
/// inside a `getOrElse`-default thunk is placed at ROOT by Scala (global-constant
/// sharing) but stays thunk-local here — so we under-share it (e.g. buy hoists
/// 13 root ValDefs vs the oracle's 15). Characterized + oracle-pinned, deferred:
/// it is a distinct mechanism from the validated schedule rule (the dossiers
/// simulated over the decoded oracle tree, where those constants were already
/// global). byte-parity 100/110 → 102/110.
///
/// M5 Task 5b (D-C3 `HasSigmas` reconstruction): 8 → 5. The THREE vectors that
/// were byte-identical to the oracle EXCEPT the `SigmaAnd`(0xea)/
/// `SigmaPropIsProven`(0xcf) reconstruction shape — `basis-tracker-basis`,
/// `offchain/basis` (the `&&`-chain `BinAnd` form) and `GuardSign` (the
/// `allOf(Coll(..))` form) — now emit the oracle's `SigmaAnd` over sigma
/// operands (`crate::isproven::reconstruct_binop`/`reconstruct_collop`,
/// `GraphBuilding.scala:167-203`). ZERO regressions: the reconstruction fires
/// only on a mixed Bool/Sigma logical op and leaves every already-matching tree
/// untouched. The remaining FIVE (`basis-token`, crystalpool ×4) stay MULTI on
/// the distinct pure-constant `getOrElse`-default global-sharing rule (M5,
/// characterized + deferred). byte-parity 102/110 → 105/110.
///
/// M5 Task 5c/R2 (getOrElse default = enclosing scope, NOT a thunk): 5 → 1. The
/// FOUR crystalpool vectors (`buy`/`sell`/`swap-tokens`/`swap-tokens-denom`)
/// graduate. The recon (`m5-r2-floatup.md`) corrected the single wrong premise —
/// Scala builds a `getOrElse` default EAGERLY in the enclosing scope
/// (`GraphBuilding.scala:441,962,1013-1035`), then wraps the already-built ref in
/// an EMPTY-body Thunk (`Thunks.scala:261,283-286`). `cse.rs` no longer pushes a
/// thunk scope for the `OptionGetOrElse` default, so its lambda-invariant
/// constant compound (`sigmaProp(false)`, the default `Coll[SigmaProp](v,v)`,
/// the swaps' `(Coll[Byte](),Coll[Byte]())` tuple) floats up via Fix-1a and
/// hash-cons-shares into ONE root `ValDef`. buy now hoists the oracle's 15 root
/// ValDefs (was 13); the swaps' `maxDenom` construction-order tie-break fell out
/// with the unblocked ValDef set (no extra rule). ZERO regressions (0 ENTERED).
/// byte-parity 105/110 → 109/110. The sole residual is `basis-token` — a DIFFERENT
/// site (no getOrElse const-default): the oracle hoists one extra `SelectField`
/// tuple-access ValDef we leave inline; characterized + oracle-pinned as its own
/// residual (see `.superpowers/sdd/m5-task-5c-report.md`).
const DC7_P2SH_MISMATCH_SET: &[(&str, &str)] = &[(
    "cc",
    "corpus:chaincash-basis/chaincash/offchain/basis-token.es",
)];

/// Committed SET of `(verb, source)` labels whose P2S address differs from
/// the oracle's — the D-C1 "we never segregate" family. Scala segregates every
/// non-bare-constant root (header `0x10`, constants table + placeholders); P2S
/// embeds the tree bytes verbatim (header included), so it diverges wherever
/// our tree bytes diverge.
///
/// POST-TASK-2 (the D-C1 flip): `compile()` now segregates non-bare roots
/// exactly like Scala. Because a segregated tree's bytes are equal iff its
/// constant-inlined proposition is equal, P2S now matches iff P2SH matches —
/// so this set has collapsed onto the D-C7 residual and stays IDENTICAL to
/// [`DC7_P2SH_MISMATCH_SET`] (17 vectors post-Task-5: the remaining IR-shape
/// divergences — CSE, val inlining, lowering — that reshape the proposition
/// itself). The D-C1 segregation axis is CLOSED; what remains is the D-C7 axis.
///
/// History: 78 (M3/M4-Task-1: every non-bare-const ACCEPT vector) → 43 (M4
/// Task 2: 35 SEGREGATION-ONLY vectors graduated — the 37 P2S/byte matches are
/// those 35 plus the 2 already-matching bare-const vectors) → 39 (M4 Task 3:
/// the same 4 D-C2/unwrap graduations as `DC7_P2SH_MISMATCH_SET` — P2S moves
/// in lockstep with P2SH post-Task-2) → 36 (M4 Task 4: the same 3
/// explicit-cast-fold graduations as `DC7_P2SH_MISMATCH_SET`) → 17 (M4 Task 5:
/// the same 19 generic-constant-fold graduations as `DC7_P2SH_MISMATCH_SET`).
/// Each graduation is a vector whose proposition was already (or is now)
/// oracle-identical, so only the header/segregation differed; the set form
/// (not a count) confirmed it dropped the RIGHT vectors — the remainder
/// stays converged EXACTLY onto the DC7 set, as the segregation-invariance
/// of P2SH predicts. M4 Task 6 (D-C3) leaves this set UNCHANGED at 17 for the
/// same reason as `DC7_P2SH_MISMATCH_SET` — the five graduated D-C3 sources
/// byte-match (so P2S matches too, never entering here), and the D-C3 corpus
/// ingredients stay MULTI-blocked. M4 Task 9 (`val` inlining) → 15, tracking
/// `DC7_P2SH_MISMATCH_SET` in lockstep: the two pure single-use-inline vectors
/// (`{ val x = HEIGHT; x > 5 }`, `corpus:lsp/test_contract.es`) now segregate to
/// oracle-identical bytes so P2S matches too; chaincash + CSE residuals stay
/// (M5). M5 Task 4 (CSE live) → 11, in lockstep with `DC7_P2SH_MISMATCH_SET`:
/// the same four vectors (`redemption`/`redproducer`/`deposit`/`emission`) whose
/// propositions CSE now shapes byte-exactly graduate here too. M5 Task 5 Fix 2
/// → 10, lockstep with `DC7_P2SH_MISMATCH_SET`: `proveDHTuple(g1,g2,g1,g2)`'s
/// CSE-hoisted `GroupElement` ValDef now matches, so its segregated bytes (and
/// thus P2S) match too.
/// M5 Task 5 Fix 1a → 8, lockstep with `DC7_P2SH_MISMATCH_SET`: `note.es` and
/// `reserve.es` graduate (their segregated bytes now match once the schedule
/// order does).
/// M5 Task 5b (D-C3 `HasSigmas` reconstruction) → 5, lockstep with
/// `DC7_P2SH_MISMATCH_SET`: `basis-tracker-basis`, `offchain/basis` and
/// `GuardSign` now segregate to oracle-identical bytes once their proposition
/// carries the `SigmaAnd` reconstruction, so P2S matches too.
/// M5 Task 5c/R2 (getOrElse default = enclosing scope) → 1, lockstep with
/// `DC7_P2SH_MISMATCH_SET`: the four crystalpool vectors' propositions now share
/// the getOrElse-default constant compound exactly, so their segregated bytes
/// (and thus P2S) match. Only `basis-token` remains.
const P2S_DC1_MISMATCH_SET: &[(&str, &str)] = &[(
    "cc",
    "corpus:chaincash-basis/chaincash/offchain/basis-token.es",
)];

// =============================================================================
// Environment builders (mirror TyperOracle.scala demo/sigmaTyperTest envs;
// same construction as tests/typer_oracle_parity.rs:127-175).
// =============================================================================

/// The secp256k1 generator point, SEC1-compressed (g1/g2 in both envs).
fn generator_ge() -> GroupElement {
    let mut bytes = [0u8; 33];
    bytes[0] = 0x02;
    let x = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        .expect("valid hex");
    bytes[1..].copy_from_slice(&x);
    GroupElement::from_bytes(bytes)
}

/// `g^7` — the fixed NON-generator point, `TyperOracle.scala:demoEnv`'s `g3`.
fn non_generator_ge() -> GroupElement {
    let mut bytes = [0u8; 33];
    bytes[0] = 0x02;
    let x = hex::decode("5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")
        .expect("valid hex");
    bytes[1..].copy_from_slice(&x);
    GroupElement::from_bytes(bytes)
}

/// Demo env (`cce`): matches `TyperOracle.scala:demoEnv`.
fn demo_env() -> ScriptEnv {
    let ge = generator_ge();
    let mut env = ScriptEnv::new();
    env.insert("a", EnvValue::ByteArray(vec![1, 2]));
    env.insert("b", EnvValue::ByteArray(vec![3, 4]));
    env.insert("col1", EnvValue::LongArray(vec![1, 2]));
    env.insert("col2", EnvValue::LongArray(vec![3, 4]));
    env.insert("g1", EnvValue::GroupElement(ge));
    env.insert("g2", EnvValue::GroupElement(ge));
    env.insert("g3", EnvValue::GroupElement(non_generator_ge()));
    env.insert("n1", EnvValue::BigInt("5".to_string()));
    env.insert("bb1", EnvValue::Byte(1));
    env.insert("bb2", EnvValue::Byte(2));
    env
}

/// `2·G` — the SigmaTyperTest env's `g2` (`LangTests.scala:52-69` binds
/// `g2 = g.multiply(g)`, i.e. the generator squared, NOT the generator).
/// Value oracle-pinned by the folded compile capture
/// `ccs proveDlog(g2)` → `OK 0008cd02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5 …`
/// (sigma-state 6.0.2, ORACLE_NETWORK=testnet, captured 2026-07-07 — the wire
/// carries the normalized SEC1-compressed point). NOTE the typed-tree RENDER
/// caveat: the oracle's `tcs g2` prints a NON-normalized Jacobian
/// `Ecp @(x,y,z≠1)` (Scala's multiply leaves the point unnormalized), so
/// typer records referencing `g2` are rendering-unmatchable — see the
/// golden-seed §26 SWEEP_SKIP entry.
fn two_g_ge() -> GroupElement {
    let mut bytes = [0u8; 33];
    bytes[0] = 0x02;
    let x = hex::decode("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
        .expect("valid hex");
    bytes[1..].copy_from_slice(&x);
    GroupElement::from_bytes(bytes)
}

/// SigmaTyperTest env (`ccs`): mirrors `LangTests.scala:52-69`, including
/// `g2 = 2·G` (the M2-era twin bound `g2 = G`, inert under type-only grading;
/// the value grading of this gate made faithfulness load-bearing — final
/// whole-M3 review finding 1).
fn typer_test_env() -> ScriptEnv {
    let ge = generator_ge();
    let mut env = ScriptEnv::new();
    env.insert("x", EnvValue::Int(10));
    env.insert("y", EnvValue::Int(11));
    env.insert("c1", EnvValue::Bool(true));
    env.insert("c2", EnvValue::Bool(false));
    env.insert("height1", EnvValue::Long(100));
    env.insert("height2", EnvValue::Long(200));
    env.insert("b1", EnvValue::Byte(1));
    env.insert("b2", EnvValue::Byte(2));
    env.insert("arr1", EnvValue::ByteArray(vec![1, 2]));
    env.insert("arr2", EnvValue::ByteArray(vec![10, 20]));
    env.insert("col1", EnvValue::LongArray(vec![1, 2]));
    env.insert("col2", EnvValue::LongArray(vec![10, 20]));
    env.insert("g1", EnvValue::GroupElement(ge));
    env.insert("g2", EnvValue::GroupElement(two_g_ge()));
    env.insert("p1", EnvValue::SigmaProp("p1".to_string()));
    env.insert("p2", EnvValue::SigmaProp("p2".to_string()));
    env.insert("n1", EnvValue::BigInt("10".to_string()));
    env.insert("n2", EnvValue::BigInt("20".to_string()));
    env
}

/// The Rust env matching an oracle compile verb.
fn env_for_verb(verb: &str) -> ScriptEnv {
    match verb {
        "cc" => ScriptEnv::new(),
        "cce" => demo_env(),
        "ccs" => typer_test_env(),
        other => panic!("unknown compile verb {other:?}"),
    }
}

// =============================================================================
// Vector model + JSON I/O.
// =============================================================================

/// `<crate>/../test-vectors/ergoscript/compile/compile_seed.json`.
fn seed_json_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-vectors/ergoscript/compile/compile_seed.json")
}

/// One committed compile vector (decision-8 schema).
#[derive(Debug, Clone)]
struct Vector {
    verb: String,
    source: String,
    network: String,
    tree_version: u8,
    /// `"ACCEPT"` or `"REJECT"` — the oracle's compile verdict.
    oracle: String,
    tree_hex: Option<String>,
    /// Oracle `Pay2SAddress` over its (segregated) tree bytes — ACCEPT only.
    p2s_address: Option<String>,
    /// Oracle `Pay2SHAddress` over its constant-inlined proposition — ACCEPT only.
    p2sh_address: Option<String>,
    reject_class: Option<String>,
    /// Corpus-relative `.es` path for corpus-sourced vectors (provenance).
    corpus_path: Option<String>,
}

fn str_field(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|s| s.as_str()).map(|s| s.to_string())
}

/// Load the committed `compile_seed.json` into `(full JSON, vectors)`.
fn load_vectors() -> (serde_json::Value, Vec<Vector>) {
    let raw = std::fs::read_to_string(seed_json_path()).expect(
        "read compile_seed.json — regenerate it with \
         `cargo test -p ergo-compiler --test compile_semantic_parity -- --ignored`",
    );
    let json: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
    let vectors = json["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .map(|v| Vector {
            verb: str_field(v, "verb").expect("verb"),
            source: str_field(v, "source").expect("source"),
            network: str_field(v, "network").expect("network"),
            tree_version: v["tree_version"].as_u64().expect("tree_version") as u8,
            oracle: str_field(v, "oracle").expect("oracle"),
            tree_hex: str_field(v, "tree_hex"),
            p2s_address: str_field(v, "p2s_address"),
            p2sh_address: str_field(v, "p2sh_address"),
            reject_class: str_field(v, "reject_class"),
            corpus_path: str_field(v, "corpus_path"),
        })
        .collect();
    (json, vectors)
}

fn network_of(v: &Vector) -> NetworkPrefix {
    match v.network.as_str() {
        "testnet" => NetworkPrefix::Testnet,
        "mainnet" => NetworkPrefix::Mainnet,
        other => panic!("unknown network {other:?}"),
    }
}

// =============================================================================
// Reduction under the difftest-pinned dummy context.
// =============================================================================

/// Construct the dummy SELF box exactly as `EvalCore.dummyContext` does —
/// field-for-field copy of `ergo-difftest/src/oracle.rs::build_dummy_self_box`
/// (`new ErgoBox(value = 1M, ergoTree = tree, transactionId = 32 zeros,
/// index = 0, creationHeight = 0)`), with serialized bytes + Blake2b id
/// populated so `SELF.bytes` / `SELF.id` reduce to real values. Each side's
/// box is built from its OWN tree/bytes — mirroring what Scala's dummy eval
/// would see for that tree.
fn build_dummy_self_box(tree: &ErgoTree, script_bytes: Vec<u8>) -> Result<EvalBox, String> {
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
    use ergo_ser::register::AdditionalRegisters;

    // Empty register block on the wire is a single count byte (0).
    let register_bytes = vec![0u8];
    let candidate = ErgoBoxCandidate::from_trusted_raw_parts(
        1_000_000,
        tree.clone(),
        script_bytes.clone(),
        0,
        vec![],
        AdditionalRegisters::empty(),
        register_bytes.clone(),
    );
    let boxed = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes([0u8; 32]),
        index: 0,
    };
    let raw_bytes = serialize_ergo_box(&boxed)
        .map_err(|e| format!("dummy SELF box serialization failed: {e:?}"))?;
    let id = boxed
        .box_id()
        .map(|d| *d.as_bytes())
        .map_err(|e| format!("dummy SELF box id failed: {e:?}"))?;
    Ok(EvalBox {
        value: 1_000_000,
        script_bytes,
        creation_height: 0,
        id,
        transaction_id: [0u8; 32],
        output_index: 0,
        registers: [None, None, None, None, None, None],
        tokens: vec![],
        raw_bytes,
        register_bytes,
    })
}

/// Reduce a tree's body to its `write_sigma_boolean` hex under the
/// difftest-pinned dummy context (`ergo-difftest/src/oracle.rs:400-431`
/// field-for-field): SELF = the tree at 1M nanoErg (sole input),
/// pre-header version 4 / timestamp 3 / generator miner key,
/// `AvlTreeData.dummy` UTXO root, activated v6 (`minimal`'s default 3), and
/// `ergo_tree_version` = the tree's OWN header version. The tree's own
/// `constants` slice resolves `ConstPlaceholder` bodies in segregated oracle
/// trees; our non-segregated trees pass an empty slice. NO cost comparison
/// (recording-only accumulator inside `reduce_expr`).
fn reduce_to_sigma_hex(tree: &ErgoTree, wire_bytes: &[u8]) -> Result<String, String> {
    let self_box = build_dummy_self_box(tree, wire_bytes.to_vec())?;
    let inputs = [self_box];
    let ctx = ReductionContext {
        self_box: Some(&inputs[0]),
        inputs: &inputs,
        pre_header_version: 4, // activated(3) + 1, matching EvalCore.dummyPreHeader
        pre_header_timestamp: 3, // CPreHeader.timestamp = 3L
        miner_pubkey: SECP256K1_GENERATOR, // dlogGroup.generator
        // AvlTreeData.dummy: 33 zero bytes, all ops allowed, keyLength 32.
        last_block_utxo_root: Some(AvlTreeData {
            digest: vec![0u8; 33],
            insert_allowed: true,
            update_allowed: true,
            remove_allowed: true,
            key_length: 32,
            value_length_opt: None,
        }),
        ergo_tree_version: tree.version,
        ..ReductionContext::minimal(0, 0)
    };
    match reduce_expr(&tree.body, &ctx, &tree.constants) {
        Ok(sb) => {
            let mut w = VlqWriter::new();
            write_sigma_boolean(&mut w, &sb);
            Ok(hex::encode(w.result()))
        }
        Err(e) => Err(format!("{e:?}")),
    }
}

/// First identifier of an error's Debug string — the "class" used for the
/// Err/Err telemetry pairs (e.g. `TypeError { .. }` → `TypeError`).
fn err_head(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// `true` when the tree is the bare-constant `SigmaProp` class — the ONE
/// byte-gated class at M3 (Scala's `fromProposition` also takes the
/// `withoutSegregation` branch for a bare `SigmaPropConstant`). The gate
/// keys this classification on the ORACLE tree (finding H-3): our own
/// output's class must FOLLOW the oracle's, never define the gate's scope.
fn is_bare_sigma_const(tree: &ErgoTree) -> bool {
    !tree.constant_segregation
        && matches!(
            &tree.body,
            Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(_),
            }
        )
}

/// Replace every `ConstPlaceholder { index }` in `expr` with the matching
/// `Const` from the segregated constants table — the substitution step of
/// Scala's `Pay2SHAddress.apply(script: ErgoTree)`
/// (`script.toProposition(replaceConstants = true)`,
/// `ErgoAddress.scala:201-204` → `substConstants`). ergo-ser exposes no
/// public substitution helper (the node never re-inlines placeholders on the
/// consensus path), so this walk derives the oracle's constant-inlined
/// proposition for the address gate. Pinned against the oracle for EVERY
/// ACCEPT vector: `encode_p2sh` over the walk's output must reproduce the
/// committed `p2sh_address`.
fn inline_placeholders(expr: &Expr, constants: &[(SigmaType, SigmaValue)]) -> Expr {
    fn boxed(e: &Expr, c: &[(SigmaType, SigmaValue)]) -> Box<Expr> {
        Box::new(inline_placeholders(e, c))
    }
    fn many(es: &[Expr], c: &[(SigmaType, SigmaValue)]) -> Vec<Expr> {
        es.iter().map(|e| inline_placeholders(e, c)).collect()
    }
    let c = constants;
    let node = match expr {
        Expr::Const { .. } | Expr::Unparsed(_) => return expr.clone(),
        Expr::Op(node) => node,
    };
    let payload = match &node.payload {
        Payload::ConstPlaceholder { index } => {
            let (tpe, val) = c.get(*index as usize).unwrap_or_else(|| {
                panic!(
                    "ConstPlaceholder index {index} out of range ({} constants)",
                    c.len()
                )
            });
            return Expr::Const {
                tpe: tpe.clone(),
                val: val.clone(),
            };
        }
        Payload::Zero => Payload::Zero,
        Payload::One(a) => Payload::One(boxed(a, c)),
        Payload::Two(a, b) => Payload::Two(boxed(a, c), boxed(b, c)),
        Payload::Three(a, b, d) => Payload::Three(boxed(a, c), boxed(b, c), boxed(d, c)),
        Payload::Four(a, b, d, e) => {
            Payload::Four(boxed(a, c), boxed(b, c), boxed(d, c), boxed(e, c))
        }
        p @ (Payload::ValUse { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::DeserializeContext { .. }
        | Payload::NoneValue { .. }) => p.clone(),
        Payload::ValDef { id, tpe, rhs } => Payload::ValDef {
            id: *id,
            tpe: tpe.clone(),
            rhs: boxed(rhs, c),
        },
        Payload::FunDef {
            id,
            tpe,
            tpe_args,
            rhs,
        } => Payload::FunDef {
            id: *id,
            tpe: tpe.clone(),
            tpe_args: tpe_args.clone(),
            rhs: boxed(rhs, c),
        },
        Payload::BlockValue { items, result } => Payload::BlockValue {
            items: many(items, c),
            result: boxed(result, c),
        },
        Payload::FuncValue { args, body } => Payload::FuncValue {
            args: args.clone(),
            body: boxed(body, c),
        },
        Payload::MethodCall {
            type_id,
            method_id,
            obj,
            args,
            type_args,
        } => Payload::MethodCall {
            type_id: *type_id,
            method_id: *method_id,
            obj: boxed(obj, c),
            args: many(args, c),
            type_args: type_args.clone(),
        },
        Payload::ConcreteCollection { elem_type, items } => Payload::ConcreteCollection {
            elem_type: elem_type.clone(),
            items: many(items, c),
        },
        Payload::Tuple { items } => Payload::Tuple {
            items: many(items, c),
        },
        Payload::SigmaCollection { items } => Payload::SigmaCollection {
            items: many(items, c),
        },
        Payload::SelectField { input, field_idx } => Payload::SelectField {
            input: boxed(input, c),
            field_idx: *field_idx,
        },
        Payload::ExtractRegisterAs { input, reg_id, tpe } => Payload::ExtractRegisterAs {
            input: boxed(input, c),
            reg_id: *reg_id,
            tpe: tpe.clone(),
        },
        Payload::DeserializeRegister {
            reg_id,
            tpe,
            default,
        } => Payload::DeserializeRegister {
            reg_id: *reg_id,
            tpe: tpe.clone(),
            default: default.as_deref().map(|d| boxed(d, c)),
        },
        Payload::ByIndex {
            input,
            index,
            default,
        } => Payload::ByIndex {
            input: boxed(input, c),
            index: boxed(index, c),
            default: default.as_deref().map(|d| boxed(d, c)),
        },
        Payload::NumericCast { input, tpe } => Payload::NumericCast {
            input: boxed(input, c),
            tpe: tpe.clone(),
        },
        Payload::FuncApply { func, args } => Payload::FuncApply {
            func: boxed(func, c),
            args: many(args, c),
        },
    };
    Expr::Op(IrNode {
        opcode: node.opcode,
        payload,
    })
}

/// Serialize a body to PROPOSITION bytes (root expression only, no tree
/// header/constants wrapper) — the `Pay2SHAddress` hash input, matching
/// `compile()`'s own `write_expr(.., false)` call (tree.rs).
fn proposition_bytes(body: &Expr) -> Vec<u8> {
    let mut w = VlqWriter::new();
    write_expr(&mut w, body, false).expect("proposition serialization");
    w.result()
}

/// Writer-child-order oracle check (M4 Task 1, locked decision 3): the ONE
/// mechanism for byte-comparing OUR emitted wire output against the
/// oracle's `tree_hex`, used by both the main gate's bare-constant assertion
/// and [`inline_placeholders_reproduces_our_proposition_for_shape_identical_vectors`]
/// — there was previously no single shared path, just two independent
/// comparisons that happened to agree.
///
/// POST-TASK-2 (the D-C1 flip has landed; `compile()` now segregates every
/// non-bare root exactly like Scala): both sides carry real placeholders and
/// real constants tables, so the check is a DIRECT full-tree-bytes diff —
/// `ours.tree_bytes` against the oracle's `tree_hex`. This is the true
/// writer-child-order check locked decision 3 demands: the constants-table
/// slot order AND the placeholder emission order (not just a flattened
/// proposition shape) must match Scala's `ConstantStore` append order. The
/// bare-`SigmaPropConstant` class (Scala's `withoutSegregation` branch, header
/// `0x00`) has no placeholders on either side, so the same direct diff covers
/// it. `oracle_tree` is no longer needed (the pre-Task-2 inline path is gone).
///
/// Every task from Task 2 onward that makes emit produce a NEW shape must run
/// this function against at least one vector whose SEGREGATED bytes are diffed
/// against `tree_hex` — see
/// [`inline_placeholders_reproduces_our_proposition_for_shape_identical_vectors`].
fn full_bytes_match_oracle(ours: &CompileResult, oracle_bytes: &[u8]) -> Result<(), String> {
    if ours.tree_bytes == oracle_bytes {
        Ok(())
    } else {
        Err(format!(
            "full tree bytes diverge (writer-child-order check): ours={} oracle={}",
            hex::encode(&ours.tree_bytes),
            hex::encode(oracle_bytes),
        ))
    }
}

// =============================================================================
// The M3 gate (always-on; committed JSON only).
// =============================================================================

/// Semantic-parity sweep over every committed compile vector. See the module
/// docs for the comparison rules. Prints the byte-parity telemetry line and
/// the Err/Err class-pair telemetry (visible with `--nocapture`).
#[test]
fn compile_seed_semantic_parity() {
    let (_, vectors) = load_vectors();
    assert!(
        vectors.len() >= 140,
        "only {} compile vectors — the seed may have shrunk",
        vectors.len()
    );

    let mut divergences: Vec<String> = Vec::new();
    let mut class_advisories: Vec<String> = Vec::new();
    // (our-error head, oracle-tree-error head) -> (count, first vector label).
    let mut err_pairs: BTreeMap<(String, String), (usize, String)> = BTreeMap::new();
    let mut accept_total = 0usize;
    let mut byte_match = 0usize;
    let mut bare_total = 0usize;
    let mut bare_match = 0usize;
    let mut skipped = 0usize;
    // Address-parity counters (wave 3, findings H-1/H-2) + the M4 Task-1
    // SET-based upgrade (recon-gap.md Finding 5) alongside them.
    let mut p2s_match = 0usize;
    let mut p2s_dc1_mismatch_set: std::collections::BTreeSet<(String, String)> =
        std::collections::BTreeSet::new();
    let mut p2sh_match = 0usize;
    let mut p2sh_dc7_mismatch_set: std::collections::BTreeSet<(String, String)> =
        std::collections::BTreeSet::new();
    let mut fired_bare_exclusions: std::collections::BTreeSet<&str> =
        std::collections::BTreeSet::new();

    for v in &vectors {
        let label = v
            .corpus_path
            .as_deref()
            .map(|p| format!("{} corpus:{p}", v.verb))
            .unwrap_or_else(|| format!("{} {:?}", v.verb, v.source));
        if let Some(&(_, reason)) = SEMANTIC_SKIP.iter().find(|(s, _)| *s == v.source) {
            eprintln!("SEMANTIC_SKIP {label}: {reason}");
            skipped += 1;
            continue;
        }
        let env = env_for_verb(&v.verb);
        let result = compile(&env, &v.source, v.tree_version, network_of(v));

        if v.oracle == "REJECT" {
            match result {
                Ok(_) => divergences.push(format!(
                    "{label}: oracle compile-REJECTs ({}) but our compile() ACCEPTs",
                    v.reject_class.as_deref().unwrap_or("?"),
                )),
                Err(e) => {
                    // Verdict parity holds; the class is advisory telemetry only
                    // (Scala rejects at GraphBuilding/IR stages we don't mirror).
                    let oracle_class = v.reject_class.as_deref().unwrap_or("?");
                    if e.class() != oracle_class {
                        class_advisories
                            .push(format!("{label}: oracle={oracle_class} rust={}", e.class()));
                    }
                }
            }
            continue;
        }

        // Oracle ACCEPT.
        let ours = match result {
            Ok(r) => r,
            Err(e) => {
                divergences.push(format!(
                    "{label}: oracle compile-ACCEPTs but our compile() rejects: {e:?}"
                ));
                continue;
            }
        };
        accept_total += 1;
        let oracle_bytes = hex::decode(v.tree_hex.as_deref().expect("ACCEPT vector has tree_hex"))
            .expect("tree_hex is hex");
        let mut r = VlqReader::new(&oracle_bytes);
        let oracle_tree = match read_ergo_tree(&mut r) {
            Ok(t) => t,
            Err(e) => {
                divergences.push(format!("{label}: oracle tree_hex does not parse: {e:?}"));
                continue;
            }
        };

        // Byte telemetry (non-gating except for the bare-constant class).
        if ours.tree_bytes == oracle_bytes {
            byte_match += 1;
        }

        // Bare-constant byte gate, keyed on the ORACLE tree's class (finding
        // H-3: the old gate required BOTH sides bare, so a regression that
        // stopped emitting a bare `SigmaPropConstant` for a PK-class vector
        // silently demoted it to semantic-only parity). An oracle-bare vector
        // must be bare AND byte-identical on our side, unless it is a known
        // D-C2 fold asymmetry listed in `ORACLE_BARE_FOLD_EXCLUSIONS`.
        if is_bare_sigma_const(&oracle_tree) {
            if let Some(&(src, reason)) = ORACLE_BARE_FOLD_EXCLUSIONS
                .iter()
                .find(|(s, _)| *s == v.source)
            {
                eprintln!("bare-fold exclusion {label}: {reason}");
                fired_bare_exclusions.insert(src);
            } else {
                bare_total += 1;
                if !is_bare_sigma_const(&ours.ergo_tree) {
                    divergences.push(format!(
                        "{label}: oracle root is a bare SigmaPropConstant but ours is not \
                         (PK-class regression; ours={})",
                        hex::encode(&ours.tree_bytes),
                    ));
                } else {
                    // Wired through the ONE writer-child-order comparison
                    // path (locked decision 3) — a bare-const oracle tree is
                    // never segregated, so this is the direct tree_bytes diff.
                    match full_bytes_match_oracle(&ours, &oracle_bytes) {
                        Ok(()) => bare_match += 1,
                        Err(e) => divergences.push(format!(
                            "{label}: bare-const SigmaProp class must be byte-identical: {e}"
                        )),
                    }
                }
            }
        }

        // Address-parity gate (finding H-2: every vector records both
        // addresses but the gate never compared either).
        let oracle_p2s = v
            .p2s_address
            .as_deref()
            .expect("ACCEPT vector has p2s_address");
        let oracle_p2sh = v
            .p2sh_address
            .as_deref()
            .expect("ACCEPT vector has p2sh_address");
        // The oracle's constant-inlined proposition (Pay2SHAddress substitutes
        // placeholders before hashing) — and the helper's per-vector pin: our
        // substitution + encode_p2sh over the ORACLE's own tree must reproduce
        // the ORACLE's committed P2SH exactly.
        let oracle_prop = proposition_bytes(&inline_placeholders(
            &oracle_tree.body,
            &oracle_tree.constants,
        ));
        let recomputed_p2sh = encode_p2sh(network_of(v), &oracle_prop);
        if recomputed_p2sh != oracle_p2sh {
            divergences.push(format!(
                "{label}: encode_p2sh over the inlined ORACLE proposition ({}) gives {} \
                 but the oracle committed {} — substitution helper or encode_p2sh is wrong",
                hex::encode(&oracle_prop),
                recomputed_p2sh,
                oracle_p2sh,
            ));
        }
        // P2SH: hard assert wherever the proposition BYTES agree (pins
        // encode_p2sh and the D-C1 claim's true scope — P2SH is
        // segregation-invariant); byte-diverging propositions are the D-C7
        // family, SET-gated against `DC7_P2SH_MISMATCH_SET` below.
        //
        // `ours.ergo_tree.body` is POST-segregation (a `ConstPlaceholder` in
        // place of every literal once `constant_segregation` is set), so it
        // must be re-inlined the same way `oracle_prop` is above — otherwise
        // this print compares an inlined oracle proposition against a
        // placeholder-bearing one of ours, which can never agree even when
        // the ACTUAL P2SH hash (computed in `compile()` from the
        // pre-segregation root, never from `ergo_tree.body`) matches. This is
        // a triage-print symmetry fix only: `compile()`'s own `p2sh_address`
        // was always computed correctly (see `tree.rs`'s `proposition_bytes`
        // call on the pre-segregation `root`); only this test's diagnostic
        // recomputation was asymmetric.
        let ours_prop = proposition_bytes(&inline_placeholders(
            &ours.ergo_tree.body,
            &ours.ergo_tree.constants,
        ));
        if ours_prop == oracle_prop && ours.p2sh_address != oracle_p2sh {
            divergences.push(format!(
                "{label}: byte-equal propositions must give equal P2SH: ours={} oracle={}",
                ours.p2sh_address, oracle_p2sh,
            ));
        }
        if ours.p2sh_address == oracle_p2sh {
            p2sh_match += 1;
        } else {
            p2sh_dc7_mismatch_set.insert(mismatch_label(v));
            // Triage telemetry for the D-C7 class (visible with
            // --nocapture): which vector, and both proposition byte strings
            // so the diverging IR transform is identifiable at a glance.
            eprintln!(
                "p2sh-divergence (D-C7) {label}: ours_prop={} oracle_prop={}",
                hex::encode(&ours_prop),
                hex::encode(&oracle_prop)
            );
        }
        // P2S: byte-equal trees (the bare-const class gated above) must agree;
        // everything else diverges by construction — Scala segregates every
        // non-bare root (header 0x10) while we emit header 0x00 (D-C1).
        if ours.p2s_address == oracle_p2s {
            p2s_match += 1;
            if ours.tree_bytes != oracle_bytes {
                divergences.push(format!(
                    "{label}: P2S addresses agree but tree bytes differ — impossible \
                     (P2S embeds the tree bytes verbatim)"
                ));
            }
        } else {
            p2s_dc1_mismatch_set.insert(mismatch_label(v));
            if ours.tree_bytes == oracle_bytes {
                divergences.push(format!(
                    "{label}: byte-equal trees must give equal P2S: ours={} oracle={}",
                    ours.p2s_address, oracle_p2s,
                ));
            }
        }

        // The semantic gate: reduce both bodies under the dummy context.
        let mine = reduce_to_sigma_hex(&ours.ergo_tree, &ours.tree_bytes);
        let theirs = reduce_to_sigma_hex(&oracle_tree, &oracle_bytes);
        match (mine, theirs) {
            (Ok(a), Ok(b)) => {
                if a != b {
                    divergences.push(format!(
                        "{label}: SigmaBoolean divergence: ours={a} oracle-tree={b}"
                    ));
                }
            }
            (Err(a), Err(b)) => {
                // Err/Err = parity — USUALLY a context-bound script (the dummy
                // context lacks the registers/outputs it reads, both sides err
                // the same way). The (RuntimeException, TypeError) pair was
                // D-C4's mask (multi-arg fold lambdas emitting an unevaluable
                // multi-arg FuncValue); M4 Task 7 CLOSED D-C4 by tupling, so
                // that vector now errs for a genuine dummy-context reason (a
                // fold-derived divide-by-zero vs the oracle's context-read
                // short-circuit) — see AUDITED_ERR_PAIRS. Any pair OUTSIDE the
                // audited set still flips to a LOUD failure below when the
                // reduction context is enriched or a lowering lands.
                // Record the class pair, with the first vector's full errors.
                let entry = err_pairs
                    .entry((err_head(&a), err_head(&b)))
                    .or_insert_with(|| (0, format!("{label}: ours={a} oracle-tree={b}")));
                entry.0 += 1;
            }
            (Ok(a), Err(b)) => divergences.push(format!(
                "{label}: ours reduces (={a}) but the oracle tree errs: {b}"
            )),
            (Err(a), Ok(b)) => divergences.push(format!(
                "{label}: oracle tree reduces (={b}) but ours errs: {a}"
            )),
        }
    }

    // Telemetry (non-gating counters; the bare-const class is gated above).
    println!(
        "byte-parity telemetry: {byte_match}/{accept_total} (bare-const {bare_match}/{bare_total})"
    );
    println!(
        "p2sh-parity: {p2sh_match}/{accept_total} (D-C7 mismatches: {})",
        p2sh_dc7_mismatch_set.len()
    );
    println!(
        "p2s-parity: {p2s_match}/{accept_total} (D-C1 segregation mismatches: {})",
        p2s_dc1_mismatch_set.len()
    );
    if !err_pairs.is_empty() {
        println!("Err/Err parity class pairs (ours, oracle-tree) x count [first vector]:");
        for ((a, b), (n, first)) in &err_pairs {
            println!("  ({a}, {b}) x {n} [{first}]");
        }
    }
    if !class_advisories.is_empty() {
        println!(
            "reject-class advisories ({} — verdict parity holds):",
            class_advisories.len()
        );
        for a in &class_advisories {
            println!("  {a}");
        }
    }
    println!("skipped {skipped} (SEMANTIC_SKIP)");

    assert!(
        divergences.is_empty(),
        "{} semantic-parity divergence(s):\n  {}",
        divergences.len(),
        divergences.join("\n  ")
    );
    // The bare-constant class must actually be exercised (PK vectors).
    assert!(bare_total >= 1, "no bare-const SigmaProp vector swept");
    // Every listed bare-fold exclusion must fire — a stale entry would widen
    // the H-3 gate's blind spot without anyone noticing.
    for (src, _) in ORACLE_BARE_FOLD_EXCLUSIONS {
        assert!(
            fired_bare_exclusions.contains(src),
            "ORACLE_BARE_FOLD_EXCLUSIONS entry {src:?} matched no oracle-bare ACCEPT \
             vector — remove or re-derive it"
        );
    }
    // The D-C7 P2SH-mismatch class and the D-C1 P2S-mismatch class are each a
    // SET-gated, audited deviation (recon-gap.md Finding 5) — they move only
    // when an M4/M5 lowering (or a regression) changes which propositions/
    // trees we emit IR-identically to Scala. Never edit either constant to
    // make a red run green without triaging what moved, in EITHER direction
    // (a vector entering OR leaving the set).
    assert_mismatch_set_matches("DC7 P2SH", &p2sh_dc7_mismatch_set, DC7_P2SH_MISMATCH_SET);
    assert_mismatch_set_matches("D-C1 P2S", &p2s_dc1_mismatch_set, P2S_DC1_MISMATCH_SET);
    // Err/Err composition pin: D-C4 proved a masked shape divergence can hide
    // as Err/Err parity. Any pair class OUTSIDE this audited set is a NEW,
    // un-triaged masking candidate — fail loudly instead of letting it ride
    // as telemetry nobody reads on green runs. Extend the set ONLY with a
    // ledger entry explaining the new pair (audit trail: lib.rs D-C3/D-C4).
    const AUDITED_ERR_PAIRS: &[(&str, &str)] = &[
        // Context-bound scripts (both sides read registers/outputs the dummy
        // context lacks): a context-read short-circuits first on both sides, so
        // they Err/Err regardless of tree shape. The three D-C3 reconstruction
        // vectors (`basis-tracker-basis`, `offchain/basis`, `GuardSign`) landed
        // in M5 Task 5b and now emit the oracle's `SigmaAnd` byte-for-byte — so
        // both sides reduce the IDENTICAL tree and stay TypeError/TypeError (the
        // predicted "flip to mixed Ok/Err" did NOT occur: the byte-match made the
        // two reductions converge on the same context-read error, not diverge).
        // They graduate out of DC7_P2SH_MISMATCH_SET on bytes, not on verdict.
        ("TypeError", "TypeError"),
        // D-C4 (CLOSED, M4 Task 7): `crystalpool/sell-token-for-erg.es`. The
        // fold-slot multi-arg lambda now TUPLES to the evaluable 1-arg
        // `FuncValue(STuple)+SelectField` form (`crate::tuple`), so the tree is
        // no longer unevaluable — the pre-Task-7 mask ("FuncValue must have
        // exactly 1 argument") is GONE. Both sides still ERR under the dummy
        // context, for a genuine reason: OUR tupled tree now evaluates the fold
        // (returning 0 over the empty context) and hits the contract's
        // `<fold> / tokensIn` division by that zero ("Long./ divide by zero"),
        // while the oracle's tupled+inlined+CSE tree short-circuits earlier on a
        // context register read (TypeError None). Verdict parity holds (neither
        // yields a spendable Ok). This vector stays byte-mismatched in
        // DC7_P2SH_MISMATCH_SET pending val-inline/CSE (Tasks 8/9); when those
        // land its bytes converge on the oracle's and both reductions align.
        ("RuntimeException", "TypeError"),
        // D-C6 wave-2 fold-boundary controls: dynamic-index `getReg[T](HEIGHT)`
        // and non-folded v6 numeric MethodCalls (`HEIGHT.toBytes`, `n1.toBytes`,
        // `x.shiftLeft(1)`) — BOTH compilers keep the residual MethodCall
        // (oracle bodies byte-match ours) and the v0 wire header makes the v6
        // wire pair unevaluable on BOTH sides. Genuine parity, not masking.
        ("PreV3V6Method", "PreV3V6Method"),
        // Wave-4 Negation-disposition probe (`-(0 + 2147483647) - 2`):
        // NEITHER compiler folds the Negation node (lib.rs D-C5 fold note;
        // the oracle tree keeps 0xF0 over its folded constant, ours over the
        // unfolded Plus — the D-C7 shape delta), so BOTH trees hit the
        // eval-time exact `-` on -2147483647 - 2 and err identically
        // ("Int.- overflow"). Genuine parity, not masking.
        ("RuntimeException", "RuntimeException"),
    ];
    for (pair, (n, first)) in &err_pairs {
        assert!(
            AUDITED_ERR_PAIRS.contains(&(pair.0.as_str(), pair.1.as_str())),
            "un-audited Err/Err class pair ({}, {}) x {n} — a new masked-divergence \
             candidate; triage it (ledger + audit-set entry) before accepting: {first}",
            pair.0,
            pair.1,
        );
    }
}

/// Placeholder-substitution round-trip (wave 3): a segregated oracle tree's
/// constant-inlined proposition must byte-match OUR `compile()`'s
/// proposition for vectors Scala's IR left shape-identical — one
/// real-constant substitution (`sigmaProp(HEIGHT > 100)`: body `d191a37300`
/// inlines placeholder 0 to `04c801`) and one wave-2 lowered vector
/// (`SELF.getReg[Int](5)` → `ExtractRegisterAs`, a zero-constant segregated
/// header where substitution is the identity).
#[test]
fn inline_placeholders_reproduces_our_proposition_for_shape_identical_vectors() {
    let (_, vectors) = load_vectors();
    for (src, expected_prop_hex) in [
        ("sigmaProp(HEIGHT > 100)", Some("d191a304c801")),
        ("sigmaProp(SELF.getReg[Int](5).isDefined)", None),
    ] {
        let v = vectors
            .iter()
            .find(|v| v.source == src && v.oracle == "ACCEPT")
            .unwrap_or_else(|| panic!("vector {src:?} missing from compile_seed.json"));
        let oracle_bytes = hex::decode(v.tree_hex.as_deref().expect("tree_hex")).expect("hex");
        let mut r = VlqReader::new(&oracle_bytes);
        let oracle_tree = read_ergo_tree(&mut r).expect("oracle tree parses");
        assert!(
            oracle_tree.constant_segregation,
            "{src}: oracle tree is segregated"
        );
        let inlined = inline_placeholders(&oracle_tree.body, &oracle_tree.constants);
        let oracle_prop = proposition_bytes(&inlined);
        if let Some(expected) = expected_prop_hex {
            assert_eq!(hex::encode(&oracle_prop), expected, "{src}: inlined prop");
        }
        let ours = compile(
            &env_for_verb(&v.verb),
            &v.source,
            v.tree_version,
            network_of(v),
        )
        .expect("our compile accepts");
        // Routed through the ONE writer-child-order comparison path (locked
        // decision 3) shared with the main gate's bare-const assertion — now a
        // DIRECT segregated-bytes diff: OUR `sigmaProp(HEIGHT > 100)` tree is
        // byte-identical to the oracle's segregated `tree_hex`.
        full_bytes_match_oracle(&ours, &oracle_bytes).unwrap_or_else(|e| panic!("{src}: {e}"));
        // Both roads to the same P2SH: encode_p2sh over the inlined oracle
        // prop, and our compile()'s own address, must equal the committed
        // oracle field.
        let committed = v.p2sh_address.as_deref().expect("p2sh_address");
        assert_eq!(encode_p2sh(network_of(v), &oracle_prop), committed);
        assert_eq!(ours.p2sh_address, committed, "{src}: P2SH address");
    }
}

// =============================================================================
// Live recapture (spawns the JVM oracle; regenerates + diffs the JSON).
// =============================================================================

/// Golden-seed record parsing (same format as `typer_oracle_parity.rs`).
fn parse_seed_line(line: &str) -> Option<(&str, &str, &str)> {
    if line.starts_with('#') || line.trim().is_empty() {
        return None;
    }
    let parts: Vec<&str> = line.splitn(3, '\t').collect();
    if parts.len() == 3 {
        Some((parts[0], parts[1], parts[2]))
    } else {
        None
    }
}

/// All vendored corpus `.es` files, keyed by corpus-relative path (the
/// `corpus_smoke.rs` loader).
fn corpus_files() -> BTreeMap<String, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-vectors/ergoscript/corpus");
    let mut out = BTreeMap::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read corpus dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("es") {
                let rel = path
                    .strip_prefix(&root)
                    .expect("under corpus root")
                    .to_str()
                    .expect("utf-8 path")
                    .replace('\\', "/");
                let src =
                    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
                out.insert(rel, src);
            }
        }
    }
    out
}

/// One capture request: compile verb, source, oracle tree version, corpus
/// provenance.
struct Request {
    verb: String,
    source: String,
    /// `ORACLE_TREE_VERSION` for this request (3 for seed/corpus sources;
    /// per-line for `compile_probes.txt` — the wave-1 SNumericType vectors
    /// are v2-only).
    tree_version: u8,
    corpus_path: Option<String>,
    /// `true` for `compile_probes.txt` sources (counted separately in the
    /// `_source` note; probe REJECTs are kept like seed REJECTs).
    probe: bool,
}

/// The full request list: every unique typecheck-ACCEPT golden-seed source
/// through its matching compile verb (seed order), then the whole 79-contract
/// corpus under `cc` (path order), then the compile-only probe list
/// (`compile_probes.txt`, the Task-11 wave-1 GraphBuilding gate vectors —
/// provenance notes in that file).
fn capture_requests() -> Vec<Request> {
    let seed = include_str!("../../test-vectors/ergoscript/typer/golden_seed.txt");
    let mut seen = std::collections::BTreeSet::new();
    let mut requests = Vec::new();
    for line in seed.lines() {
        let Some((verb, src, expected)) = parse_seed_line(line) else {
            continue;
        };
        if !expected.starts_with("OK ") {
            continue; // only typecheck-ACCEPT sources feed the compile corpus
        }
        let cverb = match verb {
            "tc" => "cc",
            "tce" => "cce",
            "tcs" => "ccs",
            other => panic!("unknown seed verb {other:?}"),
        };
        if seen.insert((cverb.to_string(), src.to_string(), 3u8)) {
            requests.push(Request {
                verb: cverb.to_string(),
                source: src.to_string(),
                tree_version: 3,
                corpus_path: None,
                probe: false,
            });
        }
    }
    for (rel, src) in corpus_files() {
        requests.push(Request {
            verb: "cc".to_string(),
            source: src,
            tree_version: 3,
            corpus_path: Some(rel),
            probe: false,
        });
    }
    let probes = include_str!("../../test-vectors/ergoscript/compile/compile_probes.txt");
    for line in probes.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        let [verb, version, src] = parts[..] else {
            panic!("malformed compile_probes.txt line: {line:?}");
        };
        let tree_version: u8 = version
            .parse()
            .unwrap_or_else(|_| panic!("bad tree_version in compile_probes.txt line: {line:?}"));
        if seen.insert((verb.to_string(), src.to_string(), tree_version)) {
            requests.push(Request {
                verb: verb.to_string(),
                source: src.to_string(),
                tree_version,
                corpus_path: None,
                probe: true,
            });
        }
    }
    requests
}

/// One parsed oracle compile reply.
enum Reply {
    Accept {
        tree_hex: String,
        p2s: String,
        p2sh: String,
    },
    Reject {
        pos: String,
        class: String,
    },
}

/// Run the whole request list through the oracle, ONE process per distinct
/// `tree_version` (`ORACLE_TREE_VERSION` is a process-level pin); replies
/// come back in the original request order.
fn run_oracle_batch(requests: &[Request]) -> Vec<Reply> {
    let versions: std::collections::BTreeSet<u8> =
        requests.iter().map(|r| r.tree_version).collect();
    let mut replies: Vec<Option<Reply>> = requests.iter().map(|_| None).collect();
    for version in versions {
        let idx: Vec<usize> = (0..requests.len())
            .filter(|&i| requests[i].tree_version == version)
            .collect();
        let subset: Vec<&Request> = idx.iter().map(|&i| &requests[i]).collect();
        for (i, reply) in idx
            .into_iter()
            .zip(run_oracle_batch_version(&subset, version))
        {
            replies[i] = Some(reply);
        }
    }
    replies
        .into_iter()
        .map(|r| r.expect("every request answered by its version batch"))
        .collect()
}

/// Run one same-version batch through ONE oracle process (the
/// `corpus_smoke.rs` spawn pattern — batch stdin, EOF-close, grammar filter,
/// `child.wait()` — with one adaptation: the stdin feed runs on its OWN
/// thread while this thread drains stdout. Compile replies carry full tree
/// hexes, so writing the whole request batch before reading deadlocks once
/// both 64 KiB pipe buffers fill (the parse oracle's one-word verdicts never
/// hit this). Retries up to 3× on a reply-count mismatch; panics on an `ERR`
/// reply.
fn run_oracle_batch_version(requests: &[&Request], tree_version: u8) -> Vec<Reply> {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    let oracle_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("scripts/jvm_typer_oracle");

    let lines_to_send: Vec<String> = requests
        .iter()
        .map(|req| {
            let hex: String = req
                .source
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            format!("{} {hex}", req.verb)
        })
        .collect();

    for attempt in 1..=3 {
        let mut child = Command::new("scala-cli")
            .arg("run")
            .arg(&oracle_path)
            .env("ORACLE_TREE_VERSION", tree_version.to_string())
            .env("ORACLE_NETWORK", "testnet")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn scala-cli (is it on PATH?)");
        let mut stdin = child.stdin.take().expect("piped stdin");
        let batch = lines_to_send.clone();
        let feeder = std::thread::spawn(move || {
            for line in &batch {
                writeln!(stdin, "{line}").expect("write to oracle");
            }
            // Drop stdin -> EOF -> the oracle's read loop terminates.
        });
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let lines: Vec<String> = stdout
            .lines()
            .map(|l| l.expect("read oracle line"))
            .filter(|l| l.starts_with("OK ") || l.starts_with("REJECT ") || l.starts_with("ERR "))
            .collect();
        feeder.join().expect("stdin feeder thread");
        child.wait().expect("oracle exit");

        if lines.len() != requests.len() {
            eprintln!(
                "attempt {attempt}: oracle returned {} replies for {} requests — retrying",
                lines.len(),
                requests.len()
            );
            continue;
        }
        return lines
            .iter()
            .zip(requests)
            .map(|(line, req)| {
                if let Some(rest) = line.strip_prefix("OK ") {
                    let mut it = rest.split_whitespace();
                    Reply::Accept {
                        tree_hex: it.next().expect("tree hex").to_string(),
                        p2s: it.next().expect("p2s").to_string(),
                        p2sh: it.next().expect("p2sh").to_string(),
                    }
                } else if let Some(rest) = line.strip_prefix("REJECT ") {
                    let mut it = rest.split_whitespace();
                    Reply::Reject {
                        pos: it.next().expect("pos").to_string(),
                        class: it.next().unwrap_or("?").to_string(),
                    }
                } else {
                    panic!("oracle ERR for {} {:?}: {line}", req.verb, req.source);
                }
            })
            .collect();
    }
    panic!("oracle reply count never matched request count after 3 attempts");
}

/// Regenerate `compile_seed.json` from the live oracle and diff it against
/// the committed file (ignoring the `_captured` date). On drift the file is
/// refreshed on disk and the test fails so the change lands in git review.
#[test]
#[ignore = "live oracle recapture: needs scala-cli; run after editing golden_seed.txt or the corpus"]
fn compile_seed_live_recapture() {
    let requests = capture_requests();
    let replies = run_oracle_batch(&requests);

    let mut vectors: Vec<serde_json::Value> = Vec::new();
    let (mut seed_accepts, mut seed_rejects) = (0usize, 0usize);
    let (mut probe_accepts, mut probe_rejects) = (0usize, 0usize);
    let (mut corpus_fed, mut corpus_kept, mut corpus_rejected) = (0usize, 0usize, 0usize);
    for (req, reply) in requests.iter().zip(&replies) {
        let is_corpus = req.corpus_path.is_some();
        if is_corpus {
            corpus_fed += 1;
        }
        let mut record = serde_json::json!({
            "verb": req.verb,
            "source": req.source,
            "network": "testnet",
            "tree_version": req.tree_version,
        });
        let obj = record.as_object_mut().expect("record object");
        match reply {
            Reply::Accept {
                tree_hex,
                p2s,
                p2sh,
            } => {
                obj.insert("oracle".into(), "ACCEPT".into());
                obj.insert("tree_hex".into(), tree_hex.as_str().into());
                obj.insert("p2s_address".into(), p2s.as_str().into());
                obj.insert("p2sh_address".into(), p2sh.as_str().into());
                obj.insert("reject_class".into(), serde_json::Value::Null);
                if is_corpus {
                    corpus_kept += 1;
                } else if req.probe {
                    probe_accepts += 1;
                } else {
                    seed_accepts += 1;
                }
            }
            Reply::Reject { pos, class } => {
                if is_corpus {
                    // Brief step 2: corpus compile-REJECTs are counted in the
                    // `_source` note and excluded from the vector set.
                    corpus_rejected += 1;
                    continue;
                }
                if req.probe {
                    probe_rejects += 1;
                } else {
                    seed_rejects += 1;
                }
                obj.insert("oracle".into(), "REJECT".into());
                obj.insert("tree_hex".into(), serde_json::Value::Null);
                obj.insert("p2s_address".into(), serde_json::Value::Null);
                obj.insert("p2sh_address".into(), serde_json::Value::Null);
                obj.insert("reject_class".into(), class.as_str().into());
                obj.insert("reject_pos".into(), pos.as_str().into());
            }
        }
        if let Some(rel) = &req.corpus_path {
            obj.insert("corpus_path".into(), rel.as_str().into());
        }
        vectors.push(record);
    }

    let captured: String = String::from_utf8(
        std::process::Command::new("date")
            .arg("+%Y-%m-%d")
            .output()
            .expect("date")
            .stdout,
    )
    .expect("utf8 date")
    .trim()
    .to_string();
    let fresh = serde_json::json!({
        "_source": format!(
            "TyperOracle.scala cc/cce/ccs verbs, scala-cli sigma-state 6.0.2, \
             ORACLE_TREE_VERSION per-record (one oracle spawn per version) \
             ORACLE_NETWORK=testnet; golden_seed.txt \
             typecheck-ACCEPT sources: {} vectors ({} compile-ACCEPT, {} \
             compile-REJECT recorded verbatim); corpus: {} sources fed under \
             cc, {} compile-ACCEPT kept, {} compile-REJECT excluded (counted \
             here per the Task-10 brief); compile_probes.txt (Task-11 wave-1 \
             GraphBuilding gate): {} vectors ({} compile-ACCEPT, {} \
             compile-REJECT recorded verbatim); M4 Task-1 (gap F2, \
             recon-gap.md Finding 2): `sigmaProp(col1.slice[Long](0, 1).size \
             == 1)` moved from `ccs` to `cce` — the `ccs` capture bound \
             `col1` to a per-element ConcreteCollection SValue \
             (TyperOracle.scala:176), an oracle-harness artifact our \
             EnvValue cannot represent and the real compile API never \
             produces; `cce`'s `col1` is a single LongArrayConstant \
             (TyperOracle.scala:141), API-reachable and now a genuine \
             same-shape probe",
            seed_accepts + seed_rejects,
            seed_accepts,
            seed_rejects,
            corpus_fed,
            corpus_kept,
            corpus_rejected,
            probe_accepts + probe_rejects,
            probe_accepts,
            probe_rejects,
        ),
        "_format": "verb: cc|cce|ccs; oracle reply fields verbatim (never hand-edited); \
                    settings pinned per-record",
        "_captured": captured,
        "vectors": vectors,
    });

    let path = seed_json_path();
    let committed: Option<serde_json::Value> = std::fs::read_to_string(&path)
        .ok()
        .map(|raw| serde_json::from_str(&raw).expect("committed compile_seed.json is valid JSON"));

    // Diff everything EXCEPT the capture date (which changes every run).
    let strip_date = |v: &serde_json::Value| {
        let mut c = v.clone();
        c.as_object_mut().map(|o| o.remove("_captured"));
        c
    };
    let up_to_date = committed
        .as_ref()
        .map(|c| strip_date(c) == strip_date(&fresh))
        .unwrap_or(false);
    if !up_to_date {
        std::fs::create_dir_all(path.parent().expect("parent dir")).expect("mkdir");
        let mut pretty = serde_json::to_string_pretty(&fresh).expect("serialize");
        pretty.push('\n');
        std::fs::write(&path, pretty).expect("write compile_seed.json");
        panic!(
            "compile_seed.json was stale (or missing) — refreshed on disk at {}; \
             review the git diff, re-run the always-on gate, and commit",
            path.display()
        );
    }
}
