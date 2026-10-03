# `ergo-difftest` reference-quality audit prompt

Audit `ergo-difftest` as the measurement system used to justify consensus,
serialization, evaluation/cost, proof verification, and replay compatibility.
Read `docs/audit-prompts/COMMON.md` first, then `CONTRIBUTING.md`,
`docs/compatibility.md`, `docs/codemap/ergo-difftest.md`, `ergo-difftest/README.md`,
and `ergo-difftest/docs/interface-contracts.md`. Follow the common review-only
workflow, full file ledger, evidence rules, and report format. Harness reliability
is a separate object of review; a clean campaign is only meaningful if it checked
the intended inputs against the intended independent authority.

## Mission and boundaries

Trace seed/corpus/grammar → named surface → Rust invariant/verdict → independent
JVM verdict → reconciliation/diff → minimization → classified durable artifact →
baseline/reinjection/CI exit. Separately trace fetched archival JSON → canonical
bytes → validated/applied state → compared and pinned IDs/roots. Identify false
negatives, false positives, missing work reported as success, and unreproducible
findings before using this crate's output to judge another crate.

This is development tooling, not a runtime node dependency. Verify that stable
hermetic checks, optional JVM checks, network archival replay, and detached nightly
libFuzzer runs have distinct prerequisites and clearly reported coverage.

## Source landmarks and associated material

- Read `Cargo.toml`, `src/lib.rs`, `rng.rs`, `generate.rs`, `fuzz.rs`,
  `surfaces.rs`, `surfaces_parity.rs`, and all their inline tests.
- Read all `src/gen/` files, including Rust generators and Python fragments/
  generators even when they are not compiled Rust targets. Resolve their generated
  output, provenance, regeneration commands, and feature vocabulary ownership.
- Read `src/oracle.rs`, `src/oracle/verify.rs`, `avl_frame.rs`, `methodcall.rs`,
  `minimize.rs`, `regressions.rs`, and both `src/bin/{difftest,replay}.rs`.
- Inventory every module in `tests/it/main.rs`, all test fixtures, gzip/include
  inputs, regression records/queues if present, corpus paths, and replay pins.
- Read `ergo-difftest/docs/{findings-and-triage,known-bug-catalog,nightly-2026-09-29}.md`,
  `known_bugs/{manifest,baseline}.toml`, every reinjection patch/recipe, and
  `scripts/{difftest-guard,reinject_gate}.sh` plus their selftest scripts.
- Review `scripts/jvm_serde_oracle/` scripts, method TSV and Scala parity vectors,
  cost-ledger fixtures, protocol-genesis fixtures, and extraction tools they cite.
- Review `.github/workflows/{ci,fuzz}.yml`, shard selection where used, and
  `ergo-difftest/fuzz/`; audit that detached crate with its dedicated prompt too.

## Inventory, invariants, and independent authority

1. Enumerate actual hermetic, oracle, structured-generator, and fuzz-target surface
   registries, including `reduce_ctx`, `verify`, and context-expression surfaces
   where present. Compare names/counts/filters/CLI help/tests/workflows; do not
   carry historical counts from codemaps into a coverage claim.
2. For every surface, document the actual reader/writer, parse gates, EOF policy,
   canonical output, accept/reject meaning, context/version/parameter authority,
   and checks executed. Confirm a stateless parse check is never described as
   full semantic validation or proof validity.
3. Prove `rw_check`'s logical and byte fixed-point conditions are sufficient for
   its stated invariant and cannot pass vacuously on writer/redecode failures.
   Inspect every `WriteRejected`, opaque soft-fork exception, normalization,
   and parity special case in `surfaces_parity.rs` against independent evidence.
4. Review exception scope for AST reshape, depth limits, node-form normalization,
   size-delimited wrappers, and canonical transformations. A broad ignore rule
   must not conceal a novel Rust-only defect or change accept/reject semantics.
5. Pin JVM scripts/dependencies/reference node/source commits and record Java/
   Scala/toolchain versions. Check local published jars, caches, and sidecars
   actually resolve the intended reference; shared Rust code is not an oracle.
6. Verify per-surface Rust/JVM framing, EOF handling, parse gates, soft-fork flags,
   activated versions, method registries, cost units/limits, and context fields.
   Compare SELF/inputs/data inputs/outputs/headers/extensions/AVL state field by
   field for dummy and context-rich reduce/verify paths.
7. Review MethodCall TSV generation and all passes: receiver/argument/result
   types, wrappers, unknown methods, invalid type arguments, rule classification,
   and independent accept/reject evidence. A generator's own well-typed claim
   needs verification before its rejection is classified as a node fault.
8. Verify AVL frame lengths/optional lengths/operations/counts/results match the
   Scala parser, not simply a copied layout comment. Cover malformed framing,
   missing/mismatched operation output, zero operations, and proof panics.

## Determinism, coverage, and bounded execution

9. Specify reproducibility precisely: seed, iteration, surface, generator mode,
   revision, corpus contents/order, configuration, context, and oracle version.
   Check seed derivation/hash/arithmetic portability and iteration reporting.
10. Review random range endpoints/modulo bias for testing usefulness, mutation
    operators and caps, corpus sort/filter/load semantics, empty/binary input,
    and memory growth from findings. Inspect CLI bounds and library callers too.
11. Verify on-manifold and adversarial generators reach the feature they claim:
    a feature label is not evidence that the intended parser/evaluator branch ran.
    Cover combination interactions, rare valid paths, version boundaries,
    short-circuiting, malformed-but-early-rejected payloads, and costly evaluation.
12. Review vocabulary bitset capacity, feature enumeration, per-surface declared
    sets, denominator/union ratio, missing-surface handling, valid/adversarial
    balance, and minimum-coverage flags. High aggregate coverage must not hide
    an entirely unchecked surface, context, cost path, or protocol version.
13. Inspect subprocess startup/query deadlines, pipe framing, response size, EOF,
    stdout pollution, malformed verdicts, stderr diagnosis, transcript flushes,
    write failures, process death/reaping, and multiple-oracle sidecar lifetimes.
    Unknown/ERR/indeterminate verdicts are harness failures, never clean agreement.
14. Audit panic-hook installation/restoration, concurrency/nesting, `catch_unwind`
    scope, release panic mode, stack overflow/OOM boundaries, and selftest behavior.
    Prove a real injected panic becomes `Bug` and reaches a failing process exit.
15. Verify planned/completed check accounting, zero iterations, unknown surfaces,
    invalid flag combinations, malformed repro hex/corpus paths, early termination,
    stop-on-first, oracle failure, and empty campaigns cannot produce a passing
    coverage claim. Match documented exit codes to all actual paths and shell pipes.

## Findings, minimization, baselines, and reinjection

16. Verify divergence classification never assigns fault merely from disagreement.
    Parse/reduce reconciliation must distinguish agreement, disagreement, and
    unavailable evidence; canonical exceptions must not suppress cost/proof faults.
17. Check minimization preserves the original divergence class and context and
    independently re-verifies the final bytes. Examine flaky predicates, bytewise
    complexity, query budgets/timeouts, empty inputs, and partial/minimizer errors.
18. Review content-addressed artifact identity, collision/context/surface separation,
    idempotence, concurrent queue writes, atomic record publication, malformed
    existing records, provenance fields, and copied reproduction command validity.
19. Inspect baseline matching and known-artifact handling: narrow exact triggers,
    version/surface/kind binding, existing versus new divergences, obsolete entries,
    and fresh evidence. A baseline must not mask unrelated new cases with a broad
    category or turn missing checks into an accepted exception.
20. Audit reinjection patches and recipes in disposable checkouts: baseline clean
    must pass, each injected defect must fail for the intended reason, restoration
    must be complete, and no patch may silently fail or mutate the user's tree.
    Review script quoting, path handling, exit traps, timeout, and pipeline status.

## Archival replay and evidence requirements

21. Review replay's CLI ranges, pin schema, URL parsing, HTTP status/framing,
    chunked/body-size handling, timeouts, truncation, reconnects, and bounded memory.
    Network failure or wrong-node data must never become a successful shorter run.
22. Verify genesis initialization, from-height assumptions, contiguous parents,
    canonical section decoding, version/epoch/voted parameters, header validation
    authority, full-block/proof/cost validation, and exact state apply order.
23. Verify pins independently bind height/header ID/state root and cannot be
    satisfied by a chain supplied by the same untrusted source without an anchor.
    State-root comparison must use the appropriate committed/validated header and
    report exact first mismatch and validated range. Do not infer replay coverage
    from a CI job skipped because `REPLAY_NODE_URL` was absent.

- Required evidence: seeded byte reproduction, all-surface inventory parity,
  at least one forced Rust panic/invariant fault, fake malformed/dead/slow oracle,
  known genuine divergence, legitimate normalization exception, class-preserving
  minimization, baseline near-miss, reinjection detection, and corrupted artifact.
- Independently compare at least a captured valid, invalid, noncanonical, cost,
  context-dependent, and proof-verification witness where supported. Record which
  registry/generator/workflow misses each category and why.
- Use the common checks plus `cargo test --locked -p ergo-difftest` and the stable campaign
  `cargo run --locked --release -p ergo-difftest -- --structured --iters 50000 --min-coverage 0.80`.
  Preflight scripts/tool versions before optional JVM/guard/replay runs; bound
  campaigns and use disposable artifact directories rather than altering baselines.

Complete when every surface/generator/normalizer/script/test/comment/fixture is
ledgered, the measurement system demonstrably detects faults and rejects missing
work, oracle independence and reproduction are explicit, and skipped coverage,
budget limitations, exceptions, and replay authority are in the common report.
