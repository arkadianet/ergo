# Fuzz-differential — findings, acceptance methodology, triage queue

Written by the lead engineer after running the generators through the re-injection
gate and the live JVM oracle, then **root-causing the divergence output with
systematic debugging**. An earlier revision of this doc reported a "signal-integrity
bug" (non-reproducing divergences); that was a **triage error on my part** and is
corrected below. This is the evidence-backed picture. Nothing here auto-resolves a
which-side-is-right call.

## What is PROVEN

1. **Generator coverage.** The SER structure-aware generators reach 16/16 declared
   adversarial features (`cargo test -p ergo-difftest --test gen_coverage`, 9/9),
   honestly `intended_valid`-tagged.

2. **Divergences are real and reproducible.** Re-injecting `relation2-0x85` (#12)
   and running the **structured generator through the JVM oracle** on `ergo_tree`
   shows a clean-vs-patched Canonical delta (356→1321 / 4000, seed 1) — the
   rediscovery signal. Individual findings reproduce via their `input_hex`
   (`difftest --oracle --repro <input_hex> --surface <s>`).

3. **The consensus-complete `reduce` surface is a CLEAN signal.** Running the
   structured generator through the `reduce` oracle surface (which curve-checks
   group elements and actually reduces the tree to `(sigma-prop, JIT-cost)`) on
   **clean HEAD** yields **0 divergences / 1500** (seed 1). On correct code it is
   silent — so any divergence it reports is a genuine candidate. **This is the
   surface to hunt consensus divergences on.**

## Corrected finding — bare `ergo_tree` over-reports; it is a PARSE surface

The bare `ergo_tree` oracle surface has a ~24% clean-code divergence rate
(~358/1500). Root-caused: these are **parse-surface artifacts, not consensus
bugs**. Two sub-classes, both confirmed to **agree on the `reduce` surface**:

- **Canonical writer differences.** e.g. input `080108d3` → the node's
  `write_ergo_tree` emits `080208d3` while the JVM keeps `080108d3`. Real writer
  difference, but **benign for consensus**: box scripts retain their *original*
  wire bytes (propositionBytes / bytesWithNoRef use original bytes since #91), so
  the node never re-serializes a tree on a consensus path. `reduce` → agree.
- **Deferred / parse-only verdicts.** e.g. `00728080808008` (a `ValUse` with an
  undefined val id: node accepts at parse, JVM throws `NoSuchElementException` at
  deserialize) and `0008cd02ff…ff` (off-curve group element: the bare surface
  defers the curve-check, documented in `oracle.rs`). Both **agree on `reduce`**
  (the undefined ValUse fails identically at eval; the off-curve point is
  curve-checked). Not consensus bugs.

### My earlier error (corrected, for the record)
The prior doc claimed some divergences "do not reproduce." I had grepped the
`rust=Accept("<canonical>")` field from the **campaign** output and repro'd *that*
(the node's canonical *output*, e.g. `080208d3`) instead of the actual **input**
(`080108d3`). The canonical output round-trips to itself, so it agreed — which I
misread as "the finding is a phantom." Instrumenting the campaign to print the
full input showed the findings reproduce exactly. **There is no signal-integrity
bug.** (A minor UX foot-gun remains: the campaign prints `rust=Accept(<canonical>)`
directly above `repro: … <input_hex>`; grab the `--repro` hex, not the `rust=`
payload.)

## Acceptance methodology (this STANDS, and is now sharper)

The generator-acceptance gate must be:
1. **Per-surface** — hunt each bug on the surface where its gate/effect actually
   lives: parse/canonical bugs on `ergo_tree`; eval/cost bugs (#2, #3, #13, #15,
   #16) on `reduce`; box-script gates on `ergo_box_candidate`; monetary/structural
   on `transaction`. Bare `ergo_tree` is a *parse diagnostic*, not the consensus
   surface.
2. **Differential** — assert a clean-vs-patched delta on the bug's class, never an
   absolute divergence count (the ergo_tree parse floor would otherwise mask it).

The clean `reduce` surface (0 baseline) makes it the ideal home for the automated
acceptance gate: re-inject an eval/cost bug, and the delta from 0 is unambiguous.

## Triage queue

**Empty of confirmed consensus candidates from the clean-HEAD SER sample** — every
divergence observed reconciles on the `reduce` surface. TRIAGE-001 (ValUse
undefined-id), reported earlier as a candidate, is **downgraded to a bare-surface
artifact** (agrees on `reduce`). This is the expected outcome of fuzzing *current
main* (a believed-correct target); real candidates are expected when (a) the
richer SIGMA/eval generators (Slice 2c) exercise the `reduce` surface deeply, or
(b) the streamed replay driver hits historical heights. Any future candidate is
minimized + repro-verified on `reduce`/box/tx before a human sees it; the
which-side-is-right call stays with the human.

## Slice 2c — eval-rich SIGMA generators on the `reduce` surface (BUILT)

The `sigma_expr` generator (`src/gen/sigma_expr.rs`) assembles **well-typed
ErgoTree bodies that reduce non-trivially** and feeds them to the consensus-
complete `reduce` oracle surface (mapped in `difftest.rs::structured_oracle_bytes`:
`reduce → sigma_expr`). Vocabulary: sigma props (ProveDlog/DHTuple/sigmaAnd/Or +
Bool→SigmaProp), boolean logic, Int/Long/BigInt arithmetic, comparisons,
collection ops (map/filter/fold/exists/forall/slice/byIndex/size), context
accessors (HEIGHT/SELF/INPUTS/getVar), registers/tuples/options, and the bug-
bearing edges: `atLeast` (#13), early-vs-late `Coll` equality (#15), token-
collection equality (#16), deserialize nodes (#3).

**Clean baseline (the whole point).**
`difftest --structured --oracle --surface reduce --iters 3000 --seed 1` →
`checks=3000 unique_classes=0 total_divergences=0`. The eval-rich trees reduce to
an IDENTICAL `P:<prop>|<cost>` on both sides on clean HEAD — so any divergence the
generator surfaces is a genuine candidate, never generator noise.

**Re-injection deltas (clean=agree → patched=diverge, on `reduce`).** Each mapped
bug is rediscovered by a pinned trigger (`known_bugs/manifest.toml`, patches in
`known_bugs/patches/`):

| bug | trigger | clean | patched (bug re-injected into ergo-sigma) |
|-----|---------|-------|-------------------------------------------|
| #13 atLeast >255 cap | `atLeast(1, [256×sigmaProp(true)])` | both REJECT (agree) | node `Accept P:d3\|1481` vs jvm `Reject` → **AcceptReject** |
| #15 coll-eq cost | `sigmaProp(Coll[Byte](200) == flip@0)` | both `P:d2\|43` | node `P:d2\|45` vs jvm `P:d2\|43` → **Canonical/cost** |
| #16 token-eq cost | `sigmaProp(tokens == flip first id)` | both `P:d2\|60` | node `P:d2\|168` vs jvm `P:d2\|60` → **Canonical/cost** |

**Coverage gap (reported, not hidden): #3 deser-subst cost.** The deserialize-
substitution INIT cost lives in `reduce.rs::verify_spending` (the Scala
`Interpreter.reductionWithDeserialize` twin). The `reduce` oracle surface calls
`reduce_expr_with_cost` directly (`oracle.rs::reduce_verdict`) and the JVM oracle
calls `CErgoTreeEvaluator.eval` with `initCost=0` — BOTH bypass that init-cost
pass, so re-injecting `reduce.rs:211` yields **no delta on this surface**. The
generator still emits the deserialize-node vocabulary (`Feature::EvalDeserializeNode`,
a `DeserializeRegister/Context` on a dead `If` branch) for coverage. Closing #3
needs both sides of the reduce surface to route through the full verify path — a
lead-engineer oracle-contract change (deferred), or the replay driver.

## Recommended next steps (revised by these findings)
1. **Point consensus-bug hunting at `reduce`** (and box/tx/header), not bare
   `ergo_tree`. The `reduce` surface's 0-baseline is the clean signal.
2. **SIGMA/eval generators (Slice 2c)** are now the high-value next build: they
   generate eval-rich trees to exercise the clean `reduce` surface, where the
   eval/cost bug class (#2, #3, #13, #15, #16) lives.
3. **Automated per-surface differential acceptance gate** — re-inject an eval/cost
   bug, assert `reduce` divergences go 0 → >0. Cleaner than the ergo_tree delta.
4. **Slice 3 (minimize + auto-file)** remains useful for real candidates, but is
   **no longer justified as a phantom-divergence filter** — there are no phantoms.
   Its job is minimize + classify-known-artifact + queue-genuine-candidate.
