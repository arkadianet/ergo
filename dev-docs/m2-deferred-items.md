# M2 Deferred Items

> **Note:** `dev-docs/` is normally gitignored. This file is deliberately committed
> (via `git add -f`) as the M3 worklist so the deferred items survive branch handoff.

Minor issues deferred from M2 reviews that are not closed by deviation-ledger
entries.  Items that resolved into lib.rs D-Tn entries (D-T7 through D-T11) are
NOT listed here — they are tracked in the ledger.

All items below are low-priority cosmetics, gap tests, or M3-scope completions.
Each row is marked **FIX-LATER** (address in M3) or **WON'T-FIX** (cosmetic /
intentionally deferred).

---

## From M2 Task 11 (cannonQ corpus lift)

- **WON'T-FIX** MANIFEST.md has a "14-vs-15" cross-reference parenthetical that does not match
  the actual source counts.  Cosmetic; fix when MANIFEST is next touched.
- **WON'T-FIX** Trailing-newline note (all vendored `.es` files); no action needed.
- **WON'T-FIX** `significant15` directory naming inconsistency in MANIFEST vs actual dir name.
  Cosmetic; fix when the corpus is extended at M3.

## From M2 Task 1 (TypedExpr enum + printer)

- **FIX-LATER** `seed_expected` in tests uses first-match on the source column; fine while all
  sources in the seed are unique.  If duplicate sources are added in a later
  section, add verb-column disambiguation.
- **FIX-LATER** `seed_accept_skip_set` in `tests/typer_oracle_parity.rs` is a hand-maintained
  `HashSet` literal.  Derive it from a typed constant or a macro so the list is
  DRY and typo-safe.  Low risk now (set is small); add as M3 cleanup.

## From M2 Task 2 (unification + numeric machinery)

- **FIX-LATER** `is_prim_type` in `typer/unify.rs` is not version-gated for `SUnsignedBigInt`
  (unreachable pre-v3 because the type is unconstructable; leave until M3 adds
  actual UnsignedBigInt support).
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
- **FIX-LATER** The standalone `Val` path in `binder.rs` (a bare `ValDef` as the top-level
  expression, not inside a `Block`) is untested.  No real contract uses this
  form; add a test when M3 exercises it.

## From M2 Task 6 (typer core II)

- **FIX-LATER** Tuple non-const-index path (dynamic tuple index) has no golden-seed record.
  The runtime reject is exercised indirectly; add an oracle capture at M3 if
  needed.
- **FIX-LATER** `bigInt` literal canonicalization (large-decimal round-trip form) is M3 scope
  — already noted in D-T3.

## From M2 Task 7 (typer core III — MethodCallLike)

- **FIX-LATER (M3-first)** `SCollectionMethods` postfix-ident sub-arm (e.g. `coll.size` via the
  `Select` path rather than `MethodCallLike`) has zero dedicated oracle coverage.
  Add a golden-seed record as the first M3 task to confirm the Select path fires
  for postfix-ident calls before extending it.
- **FIX-LATER** `Box`-id else-arm in `assign_type` (the passthrough path for an already-typed
  `TypedExpr::Box`) has no dedicated unit test.  Add at M3.

## From M2 Task 8 (public API + SigmaTyperTest port)

- **WON'T-FIX** `g2` in the SigmaTyperTest env is the generator G (secp256k1 base point), but
  the Scala test comment says "generator²".  Our type-only assertions are
  unaffected; leave the cosmetic discrepancy for the human-readable comments.
- **WON'T-FIX** `serialize` helper env in `tests/sigma_typer_spec.rs` uses the `tcs` demo env
  inconsistently in one test.  Cosmetic; does not affect correctness.

## From M2 Task 9 (differential batteries + corpus verdicts)

- **FIX-LATER** `§17` accept probes (`fromBase58("")`, `fromBase64("")`, `fromBase64("YWJj")`)
  are deferred to M3 — not committed as golden-seed test records.  Shape:
  `Apply` survives unlowered in M2; M3 decodes to `ByteArrayConstant` once
  `ValueSerializer` is wired in.  Oracle captures are in the `§17` comment block
  of `golden_seed.txt`.
- **FIX-LATER** `deserialize` is honestly deferred (D-T2); no corpus contract uses it, so the
  accept-invalid deviation is bounded and safe to leave for M3.

## From M2 final-review wave (2026-07-04)

- **FIX-LATER (D-T6 flip-early)** D-T6 (GroupElement hex lift shape) should be aligned
  early in M3 because it unblocks D-T4 (ProveDlog placeholder rendering) and D-T5
  (on-curve validation).  Fix `env::lift` to store the decompressed `(x,y,z)` affine
  form before starting new M3 features; doing it late risks cascading churn.
- **FIX-LATER** `seed_accept_skip_set` derive-from-constant: the hand-maintained skip set
  in `tests/typer_oracle_parity.rs` should be derived from a named constant shared
  with the test that exercises it, eliminating the risk of the two lists diverging.
  See also the note under Task 1 above.
- **FIX-LATER (M3-first)** §12 postfix-ident golden-seed capture: add an oracle record for
  `xs size` (or `col1.size`) via the postfix-ident path before building other M3
  features, to confirm the Select arm fires correctly for zero-arg postfix calls.
  This is the highest-priority gap-test for the M3 typer work.
