# ergo-difftest

**Purpose:** Continuous fuzz-differential harness that finds consensus divergences
between the Rust node and the Scala reference implementation without a shared test
runner. The crate operates in two phases: Phase 1 is oracle-free — it generates and
mutates byte inputs, feeds them through the `ergo-ser` / `ergo-sigma` / `ergo-validation`
decoders, and asserts two hermetic invariants (no decode ever panics; a
`decode → encode → decode` round-trip reaches a byte-stable fixed point). Phase 2
layers the JVM oracle on top: a long-lived `scala-cli` process runs `ErgoSerdeOracle.scala`
(the real sigmastate 6.0.2 runtime) while the harness streams inputs over a pipe and
diffs accept/reject verdicts and canonical re-serializations. A structure-aware
generator (`src/gen/`) covers a 28-variant `Feature` vocabulary (27 adversarial + an on-manifold
baseline), each mapped where applicable to a named catalog bug, with a measurable coverage ratio. A greedy delta-debugging minimizer
shrinks findings, a triage classifier distinguishes genuine bugs from parse-surface
artifacts, and a `known_bugs/manifest.toml` (27 entries) drives a re-injection gate
that confirms each fix still blocks its trigger. Not compiled into the node binary.

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-sigma, ergo-state,
ergo-validation, ergo-rest-json
**Depended on by:** none — dev/test-only crate (`publish = false`), not linked into
the node binary
**Approx LOC:** ~7,540 (src only, including `src/bin/`)

## Start here
- `run_campaign` / `run_structured_campaign` (`src/lib.rs:78` / `:130`) — the two
  campaign entry points; `run_campaign` uses byte-mutation from a seed corpus while
  `run_structured_campaign` feeds the grammar-aware generators and measures adversarial
  feature coverage.
- `surfaces::registry` (`src/surfaces.rs:104`) — the complete list of 26 named
  hermetic surfaces (23 read-write fixed-point checks + `batch_merkle_proof`
  read-only no-panic + `validate` stateless check + `verify_avl`); this is where
  every decoder surface is wired to its invariant.
- `oracle::oracle_surfaces` + `oracle::diff` (`src/oracle.rs:145` / `:558`) — Phase 2
  differential layer: 7 oracle-diffable surfaces (`ergo_tree`, `ergo_box_candidate`,
  `transaction`, `header`, `reduce`, `validate`, `verify_avl`), the `reduce` surface
  being the eval/cost differential that catches cost-accounting bugs invisible to the
  parse surfaces.
- `src/bin/difftest.rs` — the primary CLI entry point (also the `default-run` binary);
  every mode (`--oracle`, `--structured`, `--repro`, `--methodcall`, `--minimize`,
  `--check-canonical`, `--selftest`) is dispatched here.
- `src/bin/replay.rs` — the archival block-replay driver: pulls full blocks from a
  live Scala node over plain HTTP/1.1, applies them in-process through
  `validate_full_block_parallel` + `StateStore::apply_block`, and diffs the resulting
  state root against the Scala-committed `stateRoot` field.

## Modules
- `src/lib.rs` — campaign API: `run_campaign`, `run_structured_campaign`, `run_input`,
  `selftest`; `Outcome` / `Finding` / `Stats` types; `SilencePanics` RAII hook guard
  that suppresses the default panic hook so decoder panics are caught, not printed.
- `src/surfaces.rs` — surface registry and invariant checks: `Surface` / `RunFn`
  types; `rw_check` read-write fixed-point helper shared by 23 `ergo-ser` codec
  surfaces; plus `batch_merkle_proof` (read-only), `validate` (`ergo-validation`
  stateless check), and `verify_avl` (`ergo-sigma` AvlVerifier).
- `src/oracle.rs` — Phase 2 JVM oracle: `Oracle` process handle (long-lived `scala-cli`
  child with pipe I/O); `Verdict` / `Divergence` / `DivergenceKind` / `SurfaceSpec`
  types; `oracle_surfaces`; per-surface verdict functions including `ergo_tree_verdict`
  (with all four post-parse consensus gates), `reduce_verdict` (full eval+cost
  differential against `EvalCore.dummyContext`), `validate_verdict`, `verify_avl_verdict`;
  `diff` combinator.
- `src/regressions.rs` — divergence record schema, classification, and auto-filing:
  `DivergenceRecord` / `VerdictInfo` / `SeedInfo` (§4 of interface-contracts.md);
  `Triage` enum (`KnownArtifact` / `Pending`); `classify` (reduce-reconciliation rule
  for parse surfaces); `auto_file` (content-addressed path under `regressions_dir`,
  QUEUE.md append for Pending only); `classify_and_file` pipeline.
- `src/minimize.rs` — greedy delta-debugging minimizer: `minimize` (three-phase
  chunk-removal / truncation / single-byte-deletion, O(n²) terminating);
  `minimize_divergence` (oracle-wired wrapper with re-verify step);
  `divergence_class_key` (root-cause dedup key).
- `src/methodcall.rs` — MethodCall typechecker-registry harness: constructs a
  `MethodCall`-root tree for every `(type_id, method_id)` from the TSV dump
  (`test-vectors/scala/sigma/method_result_types.tsv`) and diffs against the JVM
  oracle `mc_root` surface; three passes (SELF, landmine, wrapper) verify rule-1001
  classification safety.
- `src/avl_frame.rs` — shared AVL+ batch-proof frame layout (`AvlOp` / `AvlFrame`);
  binary wire format defined once for both the Rust harness and the Scala oracle
  sidecar so framing errors show up immediately.
- `src/gen/mod.rs` — structured generator framework: `Feature` enum (28 adversarial
  variants each mapped to a catalog bug id); `FeatureSet` (u32 bitset); `GenMode`
  (`OnManifold` / `Adversarial`); `GenOutput`; `gen_structured_at` (deterministic
  `(seed, iter, surface)` dispatch); `declared_vocabulary`; `Coverage` /
  `SurfaceCoverage` with a measurable coverage ratio.
- `src/gen/asm.rs` — byte-level assembly primitives for adversarial hand-building:
  `put_vlq`, `VLQ_JUST_ABOVE_I32_MAX`, `STYPEVAR_CODE`, `ILL_FORMED_UTF8_NAME`,
  `VALID_GENERATOR_GE`, `off_curve_group_element`, `TREE_TRUE_PROP` / `TREE_FALSE_PROP`.
- `src/gen/ergo_tree.rs` — ErgoTree generator (on-manifold + adversarial); covers the
  largest declared vocabulary: 12 features including `FunDefNTpeArgsHighBit`,
  `STypeVarIllFormedUtf8`, `Relation2CompactBoolPair`, `OffCurveGroupElement`.
- `src/gen/sigma_expr.rs` — eval-rich ErgoTree generator (952 lines); targets the
  `reduce` oracle surface with well-typed bodies that reduce non-trivially against the
  dummy context; covers 13 eval/cost features including `EvalAtLeast` (#13),
  `EvalCollEqEarly` (#15), `EvalTokenEq` (#16), `EvalDeserializeNode` (#3).
- `src/gen/box_candidate.rs` — `ErgoBoxCandidate` generator (on-manifold + adversarial;
  6 declared features including `RegisterV6Type` and `OffCurveGroupElement`).
- `src/gen/transaction.rs` — transaction generator (on-manifold + adversarial;
  `TxEmptyOutputs` and `TxZeroAmountToken` surfaces).
- `src/gen/header.rs` — block header generator (`OnManifoldValid` + `HeaderVersionHighBit`).
- `src/gen/constant.rs` — constant generator (`OnManifoldValid` + `OffCurveGroupElement`
  + `VlqAboveI32Max`).
- `src/generate.rs` — Phase 1 byte-level input generation: `gen_input` (random or
  corpus-mutated, ~50/50); `mutate` (6 mutation operators — bit-flip, boundary-byte-set,
  truncate, insert, region-duplicate, random-overwrite; `MAX_INPUT_LEN = 4096`);
  `BOUNDARY` constant (19 bytes sitting on UTF-8/VLQ/length decision boundaries).
- `src/rng.rs` — `Rng` (SplitMix64; no external dependency; a `(seed, iter)` pair
  reproduces identical inputs on any machine).
- `src/fuzz.rs` — stable `fuzz_one` entry point consumed by the nightly cargo-fuzz
  shims; panics on `Outcome::Bug` (libFuzzer crash signal), returns `()` otherwise.
- `src/bin/difftest.rs` — CLI campaign runner; dispatches all modes; hermetic
  `--check-canonical` gate for canonical-class re-injection (no JVM required).
- `src/bin/replay.rs` — archival block-replay driver; genesis boxes embedded at
  compile time via `include_str!("../../../test-vectors/mainnet/genesis_boxes.json")`;
  plain HTTP/1.1 client over `std::net::TcpStream` (no new runtime dep).

## Key types, traits & functions
- `Outcome` (enum) — `Accepted` / `Rejected` / `WriteRejected` / `Bug(String)`;
  the single return type of every surface run — `src/lib.rs:35`
- `Finding` (struct) — `surface`, `seed`, `iter`, `input_hex`, `detail`; a
  reproducible invariant violation — `src/lib.rs:57`
- `run_campaign` (fn) — byte-mutation campaign, returns `(Stats, Vec<Finding>)` —
  `src/lib.rs:78`
- `run_structured_campaign` (fn) — grammar-aware campaign, returns
  `(Stats, Coverage, Vec<Finding>)` — `src/lib.rs:130`
- `run_input` (fn) — replay one hex input through all (or one) surfaces — `src/lib.rs:196`
- `selftest` (fn) — asserts the `catch_unwind` path actually catches and reports a
  panic as `Outcome::Bug`; run out-of-process by `tests/selftest.rs` — `src/lib.rs:219`
- `Surface` (struct) — `name: &'static str` + `run: RunFn`; one named invariant check
  — `src/surfaces.rs:24`
- `surfaces::registry` (fn) — build the 26-surface hermetic registry, optionally
  filtered by name — `src/surfaces.rs:104`
- `Oracle` (struct) — long-lived `scala-cli` process with pipe I/O; `spawn`,
  `query`, `query_raw`; kills + reaps the child on `Drop` — `src/oracle.rs:56`
- `oracle_surfaces` (fn) — 7 oracle-diffable `SurfaceSpec` entries — `src/oracle.rs:145`
- `SurfaceSpec` (struct) — `name`, `rust_verdict`, `compare_canonical`,
  `soft_fork_header`; drives the `diff` combinator — `src/oracle.rs:128`
- `Divergence` (struct) — `surface`, `kind` (`AcceptReject` / `Canonical`),
  `input_hex`, `rust`, `jvm` verdicts — `src/oracle.rs:39`
- `diff` (fn) — compare the node and JVM on one input for a given `SurfaceSpec`;
  returns `None` when they agree — `src/oracle.rs:558`
- `minimize` (fn) — greedy delta-debugger; predicate-driven; `O(n²)` terminating —
  `src/minimize.rs:42`
- `minimize_divergence` (fn) — oracle-wired minimizer with re-verify invariant;
  errors on minimizer bugs — `src/minimize.rs:150`
- `DivergenceRecord` (struct) — minimized + classified finding persisted as JSON;
  `surface`, `kind`, `input_hex`, `rust`/`jvm` verdicts, `repro` CLI command,
  `seed`, `minimized`, `provenance`, `triage` — `src/regressions.rs:46`
- `Triage` (enum) — `KnownArtifact(String)` / `Pending`; the harness never sets
  which side is right — `src/regressions.rs:93`
- `classify` (fn) — reduce-reconciliation rule: parse-surface divergences that
  reconcile on `reduce` are `KnownArtifact`; those that don't (or that originated
  on `reduce`) are `Pending` — `src/regressions.rs:131`
- `auto_file` (fn) — content-addressed write (`SHA-256(input_hex)[..16].json`);
  `Pending` → `<surface>/`; `KnownArtifact` → `artifacts/<surface>/`; QUEUE.md
  append for Pending only; idempotent — `src/regressions.rs:235`
- `classify_and_file` (fn) — classify + build record + file in one call —
  `src/regressions.rs:293`
- `Feature` (enum, 28 variants) — adversarial wire vocabulary; each variant has a
  `name()` (stable report id) and optional `bug_id()` (catalog entry it surfaces)
  — `src/gen/mod.rs:53`
- `FeatureSet` (struct) — compact u32 bitset over `Feature::ALL`; `insert`,
  `contains`, `union`, `intersect`, `difference`, `iter` — `src/gen/mod.rs:234`
- `GenOutput` (struct) — `surface`, `bytes`, `intended_valid`, `mode`, `features`
  — `src/gen/mod.rs:311`
- `gen_structured_at` (fn) — deterministic `(seed, iter, surface)` → `GenOutput`;
  SplitMix-mixed sub-seed decorrelates surfaces — `src/gen/mod.rs:362`
- `declared_vocabulary` (fn) — per-surface `FeatureSet` the generator must cover;
  the CI coverage gate asserts the campaign touches all declared features —
  `src/gen/mod.rs:391`
- `fuzz_one` (fn) — stable libFuzzer entry point; panics on `Bug`, silent otherwise
  — `src/fuzz.rs:31`
- `AvlFrame` / `AvlOp` (structs) — shared AVL+ batch-proof frame encoding
  (startingDigest 33B + keyLen + valueLenOpt + proofLen/proof + opCount/ops) —
  `src/avl_frame.rs:47` / `:34`
- `Rng` (struct) — SplitMix64 PRNG; `new`, `next_u64`, `below`, `byte`, `coin`,
  `range` — `src/rng.rs:4`

## Invariants & contracts
- **Phase 1 is oracle-free.** Every hermetic campaign (including the CI gate) needs
  only a stable Rust toolchain — no `scala-cli`, no network. The JVM oracle is
  optional and must be explicitly requested with `--oracle` (`src/lib.rs`,
  `src/surfaces.rs`).
- **Determinism.** A `(seed, iter)` pair always reproduces an identical input:
  `Rng` is SplitMix64 with no OS-entropy calls; structured generation uses
  `derive_seed(seed, iter, surface)` so each triple is decorrelated without
  interfering with others (`src/rng.rs`, `src/gen/mod.rs:369`).
- **Panics are caught, not propagated.** `SilencePanics` installs a no-op hook and
  `run_one` wraps every surface call in `catch_unwind`; a decoder panic becomes
  `Outcome::Bug("PANIC: …")`, never aborts the process. The selftest confirms this
  machinery has teeth (`src/lib.rs:206`,`:219`).
- **SER-003 type-depth exclusion.** The `MAX_TYPE_DEPTH = 100` guard in `ergo-ser` is
  a conservative stack-overflow safeguard that Scala's `TypeSerializer` does not
  apply (the JVM's limit is the 4096-byte proposition cap). A re-decode that trips
  ONLY this guard is not a `Bug`; the exclusion is documented inline so it cannot
  silently hide a real codec inconsistency (`src/surfaces.rs:56-70`).
- **`fuzz_one` panics on Bug, silent otherwise.** libFuzzer treats a panic as a
  crash and saves the input; non-Bug outcomes (`Accepted`, `Rejected`,
  `WriteRejected`) and unknown surface names return `()` without a false-positive
  crash (`src/fuzz.rs:31`).
- **Read-write fixed point.** For every `rw!` surface: `decode(encode(decode(x))) ==
  decode(x)` AND `encode(decode(x)) == encode(decode(encode(decode(x))))`. An
  intentional `WriteError` (e.g. a field that overflows the single-byte wire form,
  which the JVM also throws on) is `WriteRejected`, not a Bug (`src/surfaces.rs:30`).
- **`reduce` surface matches `EvalCore.dummyContext` field-for-field.** The dummy
  SELF box, pre-header timestamp (3L), miner pubkey (secp256k1 generator), AvlTreeData
  digest (33 zero bytes), and cost limit (1,000,000 block cost) are wired to match
  Scala exactly so a false canonical divergence from a context mismatch cannot mask or
  invent a finding (`src/oracle.rs:428-452`).
- **Minimize re-verifies.** After `minimize`, `minimize_divergence` calls `diff` once
  more on the shrunk bytes; if the divergence class key changes or the divergence
  disappears, the function returns `InvalidData` — that is a minimizer bug, not a
  finding (`src/minimize.rs:193-213`).
- **Triage never assigns fault.** `classify` only records `Pending` or
  `KnownArtifact`; which side of a divergence is correct is always a human decision
  (`src/regressions.rs:92-99`).
- **Known-bug gate.** `known_bugs/manifest.toml` (27 entries) pairs each catalog bug
  with a `trigger_hex`, a `class` (`canonical` / `accept-reject` / `cost` / `panic`),
  and a `reinject` recipe. CI uses `--repro <trigger_hex> --check-canonical` or
  `--oracle --repro` to confirm each fix still blocks its trigger. The cargo-fuzz
  subcrate (`ergo-difftest/fuzz/`) is a detached workspace excluded from the stable
  workspace; its 6 targets (`ergo_tree`, `constant`, `ergo_box_candidate`,
  `transaction`, `header`, `sigma_expr`) are thin 3-line nightly shims that call
  `fuzz_one`.
