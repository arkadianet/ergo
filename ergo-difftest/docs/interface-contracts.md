# Fuzz-differential harness — interface contracts

Authoritative spec for the continuous fuzz-differential harness (Rust Ergo node
vs the Scala reference at `reference/ergo-core` v6.0.2). Every slice builds
against the contracts here. Changing a contract is a lead-engineer decision, not
a slice-local one.

Status legend: **[BUILT]** landed + gated · **[SPEC]** contract fixed, not yet
built · **[DEFERRED]** out of this session's scope, contract reserved.

---

## 0. Ground truth (verified 2026-07-03)

| Fact | Value |
|------|-------|
| Scala oracle | `scripts/jvm_serde_oracle/ErgoSerdeOracle.scala`, scala-cli, sigma-state 6.0.2 (Maven) + ergo-core 6.0.2 (publishLocal). **Live-confirmed** — answers `ACCEPT <canon-hex>` on a real tree. |
| Oracle wire | long-lived process; stdin line `<surface> <hex>`; stdout one line `ACCEPT <hex>` / `ACCEPT` / `REJECT <ExcName>` / `ERR <msg>`; special `reduce`→`ACCEPT P:<sigmahex>\|<cost>`, `mc_root`→`SIGMA`/`WRAP`/`THROW`. |
| Oracle surfaces (today) | ergo_tree, sigma_type, constant, ergo_box_candidate, transaction, header, reduce, mc_root |
| Archival node | Scala `:9053`, `fullHeight` ≈ 1,820,888, `appVersion` 6.0.2. Serves `GET /blocks/at/{h}` → `[headerId]`, `GET /blocks/{id}` → full block JSON (header, blockTransactions, extension, adProofs). **Block source AND per-tx/state oracle.** |
| Rust dev nodes | `:9073/:9072` **down** → replay applies blocks **in-process**, not over REST. |
| Rust block-apply | `ergo_validation::block::validate_full_block_parallel(checked_header, &block_txs, &extension, &ctx) -> Result<CheckedBlock,_>` then `ergo_state::StateStore::apply_block(&checked, voted_params, hook)`; root via `StateStore::root_digest() -> ADDigest` (33 bytes). test-helpers: `apply_block_checked_for_test(height, id, expected_digest, &[CheckedTransaction])`. |
| Rust reduce | `ergo_sigma::…::reduce_expr_with_cost(&expr, &ctx, &constants, &mut cost)`. |
| JSON decode | `ergo_rest_json::decode_scala_transaction_with_mode`, `DecodedFullBlock`, `ScalaFullBlock`. |
| Hermetic harness | `ergo-difftest` (own PRNG `rng.rs`; **byte-mutation** `generate.rs` — the silent-failure risk); `--oracle` Phase 2; `tests/selftest.rs` proves the detector has teeth. |
| Toolchain | **stable 1.95.0 pinned, NO nightly** → cargo-fuzz/libFuzzer cannot run here or in CI. |
| Bulk fixtures | `test-vectors/mainnet` = 101 MB; range extractions already `.gitignore`d; committed ranges consumed by ~10 CI-run tests. |

---

## 1. Sidecar RPC contract  (Slice 1a)

**Generalize the existing scala-cli oracle — do NOT invent a new mechanism.**
Keep the process model (long-lived, one input line → one output line) and the
`ACCEPT/REJECT/ERR` verdict grammar. Add two surfaces:

### `validate <hex>`  [SPEC]
Stateless transaction validity (the context-free half of Scala
`ErgoTransaction.validateStateless`). Input `<hex>` = a serialized
`ErgoLikeTransaction`.
- `ACCEPT` — `statelessValidity()` returned `Success`.
- `REJECT <RuleId-or-ExcName>` — refused; carry the Scala validation rule id when
  available (e.g. `txNoOutputs`), else the exception class.
- `ERR <msg>` — oracle could not run (not a finding).

Stateful validation (`validateStateful`, needs boxesToSpend + stateContext) is
**[DEFERRED]** to the replay driver (§2), which already has full state — the
sidecar stays context-free so it can be driven purely from wire bytes.

### `verify_avl <hex>`  [SPEC]
AVL+ batch-proof verification twin of `ergo_sigma::avl::AvlVerifier`. Input
`<hex>` = a length-framed blob: `startingDigest(33) ‖ keyLen(u8) ‖
valueLenOpt(1 tag + optional u8) ‖ proofLen(vlq) ‖ proof ‖ opCount(vlq) ‖
[opTag(u8) ‖ keyLen? key ‖ valLen? val]*`. Framing is defined once in
`ergo-difftest/src/avl_frame.rs` and shared by both sides so the exact same bytes
drive Rust and JVM. Output:
- `ACCEPT <digestHex>` — all ops applied, final `verifier.digest` = `<digestHex>`.
- `REJECT <ExcName>` — a `performOneOperation` returned failure / threw.
- `ERR <msg>` — framing/oracle problem.

The whole point is the panic-isolation bug (catalog #6): a valid-but-wrong proof
that the Scala side turns into `REJECT` but an unguarded Rust side **panics**.

**Invariant:** a surface answers deterministically or it visibly errors. No
surface may hang; the harness enforces a per-query timeout and treats a timeout
as `ERR`, never as `ACCEPT`.

---

## 2. Replay driver I/O contract  (Slice 1b)

New binary `ergo-difftest --replay` (or `src/bin/replay.rs`). Purpose: make the
immutable chain the oracle instead of committed block bytes.

**Input:**
```
--from <height> --to <height>
--node <url>            default http://127.0.0.1:9053
--pins <path>          height→hash pin file (default ergo-difftest/docs/replay-pins.json)
--offline <dir>        replay from a committed hermetic seed dir instead of the node
```

**Per-height loop (streamed, one block at a time — never materialize the range):**
1. `GET /blocks/at/{h}` → header id; **assert** it equals the pinned hash for `h`
   (reproducibility without committing bytes). Mismatch ⇒ hard error (a reorg or
   wrong node), never silently continue.
2. `GET /blocks/{id}` → full block JSON → decode via `ergo-rest-json`.
3. Apply to Rust in-process: `validate_full_block_parallel` → `apply_block`.
   Forced full-block validation = `script_validation_checkpoint: None` (no skip).
4. Diff:
   - **state root**: Rust `root_digest()` vs the block header's `stateRoot`
     (which the Scala node already committed) → `RootMismatch`.
   - **per-tx validity**: each tx's Rust verdict vs the Scala node's (a tx in a
     committed block is valid-by-definition; a Rust `REJECT` is a reject-valid
     divergence) → `TxValidityMismatch`.
5. On any diff: emit a `Divergence` (§4 schema) and continue (collect, don't
   abort — one bad block shouldn't blind the rest of the range).

**Output:** a JSONL stream of `Divergence` records + a final summary
`{from, to, blocks, tx_total, divergences, pins_verified}`. Exit non-zero iff any
divergence OR any pin mismatch.

**Pin file** `replay-pins.json`: `{ "network":"mainnet", "node_version":"6.0.2",
"heights": { "<h>": "<headerIdHex>" } }`. Generated once from `:9053`, committed.
This is how a retired range stays reproducible with zero committed block bytes.

---

## 3. Generator output contract  (Slice 2b/2c)

The generators are the silent-failure surface — this contract exists so a weak
generator is *detectable*, not just green.

A generator is a `fn(&mut Rng, &GenCtx) -> GenOutput` where:

```rust
pub struct GenOutput {
    /// The bytes fed to BOTH implementations. This is the whole product.
    pub bytes: Vec<u8>,
    /// The surface these bytes target (must be an oracle surface name).
    pub surface: &'static str,
    /// Structural provenance for triage + coverage (NOT fed to decoders):
    /// which constructors/opcodes/type-codes this input was built from.
    pub features: FeatureSet,
    /// Whether the generator INTENDS these bytes to be well-formed (parse-OK on
    /// the reference). A generator reporting `intended_valid=true` whose bytes
    /// the reference REJECTs at >5% rate is miscalibrated — the acceptance gate
    /// fails it. This is the anti-"trivially-rejected garbage" check.
    pub intended_valid: bool,
}
```

`FeatureSet` = a bitset/summary over the wire vocabulary the input touched
(opcode ids, type codes, register forms, header flags, sigma-op tags). Coverage
is measured as the union of `FeatureSet` across a campaign — a generator that
never sets, say, the `FunDef`/`STypeVar`/`SUnsignedBigInt` bits *cannot* find the
bugs that live there, and the acceptance gate says so.

**Generator acceptance gate (MANDATORY, §5).** A generator is done only when:
- (a) **coverage**: its campaign `FeatureSet` union covers the target surface's
  declared vocabulary above the per-surface threshold; AND
- (b) **rediscovery**: run against each re-injected known bug (§5), it produces
  an input the differential flags, within a bounded iteration budget.
Compiles + runs-green is **not** done.

Generators live in `ergo-difftest/src/gen/` as a library, consumed by:
- the stable hermetic runner (`--structured`, CI default), and
- a thin `fuzz/` cargo-fuzz target reusing the same `gen` + decoders (nightly,
  opt-in — see §6 decision).

---

## 4. Divergence record schema  (Slice 3 — minimize + auto-file)

One schema for every producer (oracle Phase 2, replay driver, structured
campaign):

```jsonc
{
  "surface":   "ergo_tree",           // oracle surface or "block:<height>"
  "kind":      "AcceptReject" | "Canonical" | "Reduce" | "Cost"
             | "RootMismatch" | "TxValidity" | "Panic",
  "input_hex": "…",                   // the MINIMIZED input (post-shrink)
  "rust":      { "verdict": "Accept|Reject|Panic", "detail": "…" },
  "jvm":       { "verdict": "Accept|Reject",       "detail": "…" },
  "repro":     "difftest --repro <hex> --surface <s>",
  "seed":      { "seed": 7, "iter": 12345 } | null,
  "minimized": true,
  "provenance":"structured-gen|oracle-mutation|replay:h<height>",
  "triage":    "PENDING"              // never auto-resolved; a human sets the verdict
}
```

**Minimization:** greedy byte-ndelta shrink that preserves the divergence
predicate (same `kind` + same rust/jvm verdict split). Auto-file writes the
minimized record to `ergo-difftest/regressions/<surface>/<hash>.json` and appends
a line to `ergo-difftest/regressions/QUEUE.md`. **The which-side-is-right call is
never made by the harness** — `triage: PENDING` until a human edits it.

---

## 5. Known-bug rediscovery suite  (Slice 5 — the anti-theater gate)

Catalog: `ergo-difftest/docs/known-bug-catalog.md` (25 entries, fix
locations verified). Machine-readable manifest:
`ergo-difftest/known_bugs/manifest.toml`, one entry per re-injectable bug:

```toml
[[bug]]
id = "utf8-stypevar-sstring"
surface = "ergo_tree"
class = "accept-reject"          # detection channel the fuzzer must observe
wire_reachable = true            # false ⇒ replay-only, excluded from wire-gen gate
fix_file = "ergo-ser/src/sigma_type.rs"
reinject = "replace `crate::jvm_utf8::decode(name_bytes)` with `String::from_utf8(...)?`"
budget_iters = 200000            # max iters the generator gets to rediscover it
```

**Re-injection runner** (scratch branch, never committed): applies each
`reinject` patch, runs the target generator/differential for `budget_iters`,
asserts a divergence of the declared `class` on the declared `surface` is found,
reverts. A generator that cannot rediscover its wire-reachable bugs is **rejected
and re-dispatched** — no exceptions. Wire-unreachable bugs (state-dependent:
1808895, deser-subst cost, adproofs, eip27) are gated by the **replay driver**,
not the wire generators.

---

## 6. Decisions (lead engineer)

**D1 — cargo-fuzz vs hermetic runner.** No nightly here or in CI, and the repo is
pinned to stable 1.95.0; a libFuzzer target would "run green" only by never
running — the exact theater the mission forbids. **Decision:** the generators are
a *library* (`src/gen/`). The primary consumer is the stable hermetic runner
(`--structured`), which runs in CI and against the live oracle. A thin `fuzz/`
cargo-fuzz target reuses the same library for coverage-guided runs **when nightly
is available** (opt-in, not CI-gating). This delivers "cargo-fuzz targets per
surface" without making the gate depend on a toolchain we don't have. Recorded as
a "remaining risk / offline trade" in the final report.

**D2 — fixture retirement scope.** Deleting the 101 MB committed ranges breaks
~10 CI-run tests. **Decision:** (1) harvest interesting structures from the ranges
into the seed corpus FIRST; (2) rewire the affected tests to a *small* committed
hermetic seed (genesis + a handful of known-gnarly heights: 836113, plus 1–200)
that still runs offline in CI; (3) move full-range coverage to the streamed replay
driver, pinned by height+hash (§2). Net: CI stays hermetic on a small seed; deep
coverage is the streamed oracle, reproducible without committing bytes.

**D3 — consensus-truth.** Any divergence where the correct side is unclear (incl.
"is this a JVM quirk to bug-for-bug match?") is escalated to the human via the
triage queue. No subagent, and not the lead engineer, silently resolves it or
"fixes" the Rust side to match itself.

---

## 7. Slice sequencing + model ledger

| Slice | What | Model | Why |
|-------|------|-------|-----|
| 1a | Sidecar `validate`+`verify_avl` surfaces | Sonnet | loud-fail: answers or visibly doesn't |
| 5  | Known-bug manifest + re-injection runner | Sonnet (lead reviews hard) | infra, but it's the gate — verify teeth |
| 2b | **SER structure-aware generators** | **Opus** | silent-fail; highest bug density; hardest review |
| 1b | Streamed replay driver | Sonnet | loud-fail: replays+diffs or doesn't |
| 2c | SIGMA generators | Opus | silent-fail |
| 3  | Divergence minimize + auto-file | Sonnet | loud-fail infra |
| 1c | Corpus harvest + fixture retirement | Sonnet | mechanical, but destructive — lead gates |
| 6  | cargo-fuzz scaffold (opt-in) + nightly CI | Sonnet | loud-fail wiring |

Consensus-truth triage = HUMAN only, every slice.
