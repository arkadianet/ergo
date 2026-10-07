# Fuzz-differential harness — interface contracts

These contracts describe the current differential harness and its limitations.
The JVM serde oracle pins sigma-state and ergo-core 6.0.6 in
[`ErgoSerdeOracle.scala`](../../scripts/jvm_serde_oracle/ErgoSerdeOracle.scala).
The hermetic runner is the stable PR gate. Coverage-guided campaigns use the
nightly and cargo-fuzz versions in [the shared tool pins](../../.github/ci-tools.toml);
see [the fuzz workflow](../fuzz/README.md) for setup.

## 1. Sidecar RPC contract

**Generalize the existing scala-cli oracle — do NOT invent a new mechanism.**
Keep the process model (long-lived, one input line → one output line) and the
`ACCEPT/REJECT/ERR` verdict grammar. Add two surfaces:

### `validate <hex>`  [BUILT]
Stateless transaction validity (the context-free half of Scala
`ErgoTransaction.validateStateless`). Input `<hex>` = a serialized
`ErgoLikeTransaction`.
- `ACCEPT` — `statelessValidity()` returned `Success`.
- `REJECT <RuleId-or-ExcName>` — refused; carry the Scala validation rule id when
  available (e.g. `txNoOutputs`), else the exception class.
- `ERR <msg>` — oracle could not run (not a finding).

Stateful validation (`validateStateful`, needs boxesToSpend + stateContext) is
**[DEFERRED]** as a general sidecar contract. The early-mainnet replay driver
(§2) owns a narrower fixed context; the sidecar remains context-free.

### `verify_avl <hex>`  [BUILT]
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

## 2. Replay driver I/O contract

The standalone `replay` binary compares early-mainnet application with a supplied
archival node. Its fixed context supports contiguous heights **1..=200** from
genesis. Later epochs need historical voted parameters, soft-fork state and
parent extensions; the driver refuses a larger window before network or state I/O.

```sh
cargo run --locked -p ergo-difftest --bin replay -- \
  --from 1 --to 200 --node http://127.0.0.1:9053 \
  --pins ergo-difftest/replay-pins.json
```

`--from` must be 1; `--to` is required. The node and pins shown are defaults.
There is no `--offline` option. Committed fixture unit tests exercise genesis
application separately from live archival replay.

For each height the driver fetches its served header id and full-block JSON,
decodes wire sections, and binds the requested height, served id, decoded header
id and any pin's header id/state root. An inconsistent source is a hard integrity
error. Genesis uses `apply_genesis`; later blocks use
`validate_full_block_parallel` with full script validation and then `apply_block`.
A pin contributes to `pins_verified` only after successful application and a
matching computed state root, including height 1. The already checked genesis
header seeds the parent window without a second node fetch.

Validation or root differences emit block-specific JSONL records with
`triage: PENDING`. A failed block stops replay because later blocks require the
state at that height. The final summary contains
`{from,to,blocks,tx_total,divergences,pins_verified}`; divergence or fatal integrity
failure returns nonzero.

Pin entries have the actual shape:
```json
{"network":"mainnet", "node_version":"6.0.2", "heights": {
  "1": {"headerId":"<32-byte hex>", "stateRoot":"<33-byte hex>"}
}}
```
The historical reference version records capture attribution, not a current
runtime guarantee. Later-height entries remain historical metadata even though
the fixed context cannot replay them. Pins do not guarantee an archive remains
available or authenticate every served section.

This is a diagnostic comparison: genesis is unchecked, PoW is trusted from the
supplied node, parent-extension validation is omitted, and downloaded AD proofs
are not passed to state application. A green early replay is not a complete
consensus/bootstrap proof. CI explicitly reports an unset `REPLAY_NODE_URL` as
**not tested**. Source/unit-test validation does not claim live node execution.

---

## 3. Generator output contract

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

## 4. Divergence record schema

One schema for every producer (oracle Phase 2, replay driver, structured
campaign):

```jsonc
{
  "surface":   "ergo_tree",           // oracle surface or "block:<height>"
  "kind":      "AcceptReject" | "Canonical" | "Reduce" | "Cost"
             | "RootMismatch" | "TxValidity" | "Panic",
  "input_hex": "…",                   // minimized, or preserved original on failure
  "rust":      { "verdict": "Accept|Reject|Panic", "detail": "…" },
  "jvm":       { "verdict": "Accept|Reject",       "detail": "…" },
  "repro":     "difftest --repro <hex> --surface <s>",
  "seed":      { "seed": 7, "iter": 12345 } | null,
  "minimized": true | false,
  "processing_error": "…",             // optional; failed processing, harness exit 3
  "execution": {                       // CLI oracle producer; optional for legacy records
    "metadata": "runs/<sha256>.json", "metadata_sha256": "…",
    "comparison_contract": { "…": "source/compiler/oracle/context identity" },
    "authority_complete": true, "baseline_key": "…"
  },
  "provenance":"structured-gen|oracle-mutation|replay:h<height>",
  "triage":    "PENDING"              // never auto-resolved; a human sets the verdict
}
```

**Minimization:** greedy byte-ndelta shrink that preserves the divergence
predicate (same `kind` + same rust/jvm verdict split). Auto-file writes the
minimized record to `<output>/<surface>/<full-record-sha256>.json` and regenerates
the derived `<output>/QUEUE.md` under a filing lock. **The which-side-is-right call is
never made by the harness** — new records stay `triage: PENDING`. Agreement
in one dummy reduction context cannot automatically mark a difference benign.
Any minimization failure retains the original input/verdicts and marks the
campaign incomplete, even when fallback filing succeeds. Campaign records retain
the first concrete generating iteration and distinguish structured generation
from mutation.

CLI oracle execution archives exact primary and verify-sidecar Scala sources
and immutable journals under `<output>/runs/`. Build-time source/compiler
metadata and the running binary hash are recorded separately. Actual JVM
properties and resolved JAR hashes identify reference execution; unavailable
identity is an incomplete run. Repro commands select the archived sources.
The guard decodes records and validates full JSON, source archive and journal
identities before considering a baseline. Its separate semantic key binds the
input/verdicts to source/compiler/oracle/context authority, excluding volatile
seed/iteration/path evidence. Legacy short input keys cannot mute new records.
Output initialization preserves existing files; the default is a fresh
`regressions-run.*` directory. These are diagnostic integrity guarantees, not
signed build attestations or power-loss durability certification. Replay block
reports use the replay driver's block-specific schema rather than `auto_file`.

---

## 5. Known-bug rediscovery suite

Catalog: `ergo-difftest/docs/known-bug-catalog.md`. Machine-readable manifest
(currently 39 entries; entry presence is not executed rediscovery evidence):
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

**Existing trigger runner:** `scripts/reinject_gate.sh` takes owned source copies,
checks clean exit 0, applies the catalog patch, and requires finding exit 1 with
its declared class/surface marker. Locked build failures, missing binaries and
unrelated nonzero detector exits fail the check. Source copies and release build
directories are removed; build/detector logs are retained. A run with no
executed pair is incomplete (exit 3), even when every skipped entry has an
explanation. `--generated` is currently unsupported and fails usage 2 before
any planned work; it does not certify generator rediscovery. Independent
clean/patched detector execution and
bounded generated rediscovery remain separate assurance obligations. Pure saved-
log classification unit tests do not discharge either obligation. State-dependent
catalog cases require their own correctly contextualized replay evidence.

---

## 6. Assurance policy

**D1 — cargo-fuzz vs hermetic runner.** Stable Rust 1.99.0 drives the PR
hermetic runner. The detached workspace uses the exact nightly and cargo-fuzz
versions in `.github/ci-tools.toml`; PR CI checks locked metadata, while scheduled
and manual jobs build/run all 12 native targets with address sanitizer.
`libfuzzer-sys` compiles bundled C++ libFuzzer sources. Nightly enables the unstable
Rust sanitizer/SanitizerCoverage instrumentation; a missing stable library is
not the reason. Generator and fixed-point coverage, native crash/artifact
assurance, and independent JVM comparisons are different evidence obligations.
Workflow wiring or a collector unit pass does not prove an executed campaign.

**D2 — fixture retirement plan.** Committed full ranges still support hermetic
Rust tests. Retirement requires small externally sourced seeds and replacement
receipts before deletion. The current replay driver only models heights 1–200;
deep epoch/context reconstruction and retained later incident pins do not provide
replacement deep coverage. Do not retire fixtures based on a skipped workflow
or an unimplemented historical plan.

**D3 — consensus-truth.** Any divergence where the correct side is unclear (incl.
"is this a JVM quirk to bug-for-bug match?") is escalated to the human via the
triage queue. No subagent, and not the lead engineer, silently resolves it or
"fixes" the Rust side to match itself.


## 7. Surface selection and triage

Reproduce a finding with its `input_hex` or the hex after `--repro`, rather than
Rust's canonical output from the `rust=Accept(...)` field. Re-serializing the
output can remove the input difference being investigated.

Select the surface that owns the behavior: parse/canonical differences on
`ergo_tree`, evaluation and cost on `reduce`, box-script gates on
`ergo_box_candidate`, and monetary/structural checks on `transaction`. The bare
`ergo_tree` surface is a parse diagnostic: retained original script bytes and
checks deferred to validation can make a writer/parse difference irrelevant to
a particular consensus path. Agreement under one reduction context alone cannot
establish that a difference is benign; retain the input, context and authority
record for human review.

Acceptance comparisons use a clean-versus-patched delta on the bug's declared
class and surface, rather than an absolute divergence count. Structured sigma
generation lives in `src/gen/sigma_expr.rs` and supplies the `reduce` surface
with typed trees covering sigma propositions, arithmetic, collections, context
access, registers, tuples, options and deserialize nodes.

The reduction surfaces call `reduce_expr_with_cost` directly. They bypass
`verify_spending`'s deserialize-substitution initialization cost, so they cannot
rediscover that cost bug merely by emitting a deserialize node. Use a fully
contextualized verification or replay test for that seam. Both reduction contexts
also have an empty `CONTEXT.headers` window; they do not establish last-header
window parity. These limitations are documented in `src/oracle.rs`.
