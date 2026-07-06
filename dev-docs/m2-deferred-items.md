# M2 Deferred Items

> **Note:** `dev-docs/` is normally gitignored. This file is deliberately committed
> (via `git add -f`) as the M3 worklist so the deferred items survive branch handoff.

Minor issues deferred from M2 reviews that are not closed by deviation-ledger
entries.  Items that resolved into lib.rs D-Tn entries (D-T7 through D-T11) are
NOT listed here — they are tracked in the ledger.

All items below are low-priority cosmetics, gap tests, or M3-scope completions.
Each row is marked **FIX-LATER** (address in M3) or **WON'T-FIX** (cosmetic /
intentionally deferred).

> **M3 close-out (2026-07-07):** every FIX-LATER row is now LANDED or RE-SCOPED —
> disposition annotated inline per row (task ranges cite the M3 commit spans from
> `.superpowers/sdd/progress.md`). WON'T-FIX rows are unchanged. This file is now
> historical; the live worklist is the roadmap's "M4 worklist (from M3)" section.

---

## From M2 Task 11 (cannonQ corpus lift)

- **WON'T-FIX** MANIFEST.md has a "14-vs-15" cross-reference parenthetical that does not match
  the actual source counts.  Cosmetic; fix when MANIFEST is next touched.
- **WON'T-FIX** Trailing-newline note (all vendored `.es` files); no action needed.
- **WON'T-FIX** `significant15` directory naming inconsistency in MANIFEST vs actual dir name.
  Cosmetic; fix when the corpus is extended at M3.

## From M2 Task 1 (TypedExpr enum + printer)

- **FIX-LATER → LANDED (M3)** `seed_expected` in tests uses first-match on the source column; fine while all
  sources in the seed are unique.  If duplicate sources are added in a later
  section, add verb-column disambiguation.
  *Landed: the lookup now matches on the `(verb, src)` pair
  (`tests/typer_oracle_parity.rs`, `seed_expected` closure).*
- **FIX-LATER → LANDED (M3 Task 3, follow-up `1272078`)** `seed_accept_skip_set` in `tests/typer_oracle_parity.rs` is a hand-maintained
  `HashSet` literal.  Derive it from a typed constant or a macro so the list is
  DRY and typo-safe.  Low risk now (set is small); add as M3 cleanup.
  *Landed: derived from `SWEEP_SKIP` (single source of truth); `SWEEP_SKIP` itself
  was then EMPTIED by the D-T4/D-T6 fix and remains as the mechanism.*

## From M2 Task 2 (unification + numeric machinery)

- **FIX-LATER → RE-SCOPED to WON'T-FIX (M3 Task 6, `97339d4..4c3d54a`)** `is_prim_type` in `typer/unify.rs` is not version-gated for `SUnsignedBigInt`
  (unreachable pre-v3 because the type is unconstructable; leave until M3 adds
  actual UnsignedBigInt support).
  *Adjudicated SOUND not to gate: the `unsignedBigInt`/`bigInt` predefs are NOT
  version-gated on the oracle (golden_seed §24(e)); the reviewer traced all `unify`
  call paths.  Full oracle-backed argument in the function's doc comment.*
- **WON'T-FIX** Rule-10/11 `SAny-SAny` test name in `typer/unify.rs` is slightly misleading
  (tests the SAny ∪ SAny → SAny path of rule 11).  Rename when convenient.

## From M2 Task 3 (SMethod tables)

- **WON'T-FIX** `has_ir_builder` 2-way flag note from Task 3 review is stale — Tasks 5-7
  consumed the flag completely.  No action.

## From M2 Task 4 (binder)

- **WON'T-FIX** Parity tests in `tests/sigma_typer_spec.rs` hardcode seed strings for the
  SigmaTyperTest env (`tcs` verb) because the oracle was captured at task time.
  These remain accurate; refresh with `cargo test seed_live_oracle_parity` if the
  oracle format ever changes.
- **FIX-LATER → LANDED (M3 Task 8, `29f091b..d874f42`)** The standalone `Val` path in `binder.rs` (a bare `ValDef` as the top-level
  expression, not inside a `Block`) is untested.  No real contract uses this
  form; add a test when M3 exercises it.
  *Landed: oracle-proved a bare top-level `val x = 1` REJECTS at PARSE on both sides
  (`ParserException` parity; golden_seed §25 record +
  `standalone_top_level_val_rejects_matching_oracle` in `emit.rs`) — the binder path
  is unreachable, so emit's ValNode arm is a pipeline-bug surface (`InvalidShape`).*

## From M2 Task 6 (typer core II)

- **FIX-LATER → LANDED (M3 Task 2, `8e4dc09..b530cac`)** Tuple non-const-index path (dynamic tuple index) has no golden-seed record.
  The runtime reject is exercised indirectly; add an oracle capture at M3 if
  needed.
  *Landed: golden_seed §23(b) captures the shape — the oracle ACCEPTs (STuple →
  `SCollection[SAny]` by design, `SType.scala:822-825`); Task 8 emits it.*
- **FIX-LATER → LANDED (M3 Task 6, `97339d4..4c3d54a`)** `bigInt` literal canonicalization (large-decimal round-trip form) is M3 scope
  — already noted in D-T3.
  *Landed: D-T3 CLOSED — leading-zero canonicalization + the version-gated range caps
  (255-bit v3-only for BigInt, 256-bit unconditional for UnsignedBigInt), oracle-pinned
  golden_seed §24.*

## From M2 Task 7 (typer core III — MethodCallLike)

- **FIX-LATER (M3-first) → LANDED (M3 Task 2, `8e4dc09..b530cac`)** `SCollectionMethods` postfix-ident sub-arm (e.g. `coll.size` via the
  `Select` path rather than `MethodCallLike`) has zero dedicated oracle coverage.
  Add a golden-seed record as the first M3 task to confirm the Select path fires
  for postfix-ident calls before extending it.
  *Landed: golden_seed §23(a) captures BOTH shapes (dot-form → Select, space-form
  `arr1 size` → residual `MethodCall(12,1)`); the space-form was later gated as a
  GraphBuilding reject in oracle parity (Task-11 wave 1, lib.rs D-C5 class 4).*
- **FIX-LATER → LANDED (M3 Tasks 7-8, `c36e26b..d874f42`)** `Box`-id else-arm in `assign_type` (the passthrough path for an already-typed
  `TypedExpr::Box`) has no dedicated unit test.  Add at M3.
  *Landed via the Task-7/8 frontend round-trips: the `SELF`-source tests (all six Box
  `Extract*` properties + `SELF.R0/R4/R9[T]` register reads) exercise the already-typed
  Box passthrough end-to-end.*

## From M2 Task 8 (public API + SigmaTyperTest port)

- **WON'T-FIX** `g2` in the SigmaTyperTest env is the generator G (secp256k1 base point), but
  the Scala test comment says "generator²".  Our type-only assertions are
  unaffected; leave the cosmetic discrepancy for the human-readable comments.
- **WON'T-FIX** `serialize` helper env in `tests/sigma_typer_spec.rs` uses the `tcs` demo env
  inconsistently in one test.  Cosmetic; does not affect correctness.

## From M2 Task 9 (differential batteries + corpus verdicts)

- **FIX-LATER → LANDED (M3 Task 5, `c2f8c01..ab01afa`)** `§17` accept probes (`fromBase58("")`, `fromBase64("")`, `fromBase64("YWJj")`)
  are deferred to M3 — not committed as golden-seed test records.  Shape:
  `Apply` survives unlowered in M2; M3 decodes to `ByteArrayConstant` once
  `ValueSerializer` is wired in.  Oracle captures are in the `§17` comment block
  of `golden_seed.txt`.
  *Landed: D-T2 CLOSED for fromBase58/64 — valid literals fold to `ByteColl`
  constants (`JAVA_BASE64` engine parity); byte-exact §17 records committed incl.
  the unpadded `fromBase64("ab")` case.*
- **FIX-LATER → RE-SCOPED to M4 (M3 Task 5 + Task 12 decision)** `deserialize` is honestly deferred (D-T2); no corpus contract uses it, so the
  accept-invalid deviation is bounded and safe to leave for M3.
  *Re-scoped: closing it requires an opcode-IR→`TypedExpr` reverse mapping — build it
  at M4 alongside the lowering catalog (which wants the same mapping); the adversarial
  pass surfaced no real-contract need. See the roadmap M4 worklist.*

## From M2 final-review wave (2026-07-04)

- **FIX-LATER (D-T6 flip-early) → LANDED (M3 Task 3, `6930809..990df2c` + `1272078`)** D-T6 (GroupElement hex lift shape) should be aligned
  early in M3 because it unblocks D-T4 (ProveDlog placeholder rendering) and D-T5
  (on-curve validation).  Fix `env::lift` to store the decompressed `(x,y,z)` affine
  form before starting new M3 features; doing it late risks cascading churn.
  *Landed: D-T4/D-T5/D-T6 CLOSED — storage form is the 33-byte SEC1-compressed key
  (NOT the affine form this row guessed; the printer decompresses on demand), on-curve
  check at `env::lift`/`bind_pk`, `SWEEP_SKIP` emptied.  The unpadded-hex printer
  correction followed at Task 4 (`c2f8c01`).*
- **FIX-LATER → LANDED (M3 Task 3 follow-up, `1272078`)** `seed_accept_skip_set` derive-from-constant: the hand-maintained skip set
  in `tests/typer_oracle_parity.rs` should be derived from a named constant shared
  with the test that exercises it, eliminating the risk of the two lists diverging.
  See also the note under Task 1 above.
- **FIX-LATER (M3-first) → LANDED (M3 Task 2, `8e4dc09..b530cac`)** §12 postfix-ident golden-seed capture: add an oracle record for
  `xs size` (or `col1.size`) via the postfix-ident path before building other M3
  features, to confirm the Select arm fires correctly for zero-arg postfix calls.
  This is the highest-priority gap-test for the M3 typer work.
  *Landed: golden_seed §23(a) — see the Task 7 row above for both captured shapes.*
