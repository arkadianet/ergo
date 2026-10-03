# Common audit contract

This file is part of every crate prompt in this directory. Read it in full,
then the selected crate prompt, before starting work. The target is a Rust
node whose correctness, compatibility, security, operations, and clarity can
support eventual use as a reference implementation. That aspiration does not
establish the current node's readiness or replace its Scala compatibility
contract.

## Assignment and operating mode

Act as a demanding Rust reviewer, consensus engineer, security auditor, test
engineer, and technical editor. Review the entire target crate and every
external surface needed to understand its contracts. Treat implementation,
tests, comments, documentation, fixtures, manifests, and tooling as first-class
deliverables. Apply every relevant item below and every crate-specific item;
record a reason when an item does not apply.

Run commands from the repository root unless explicitly stated otherwise.
Root-prefixed paths identify their package; abbreviated `src/`, `tests/`,
`examples/`, and similar source paths in a crate prompt are relative to that
crate. Rediscover renamed paths and verify test/module registration.

Default to **review only**. Produce evidence and an actionable remediation plan;
do not change implementation, tests, oracle outputs, or existing documentation
unless the user requests remediation. Temporary reproductions and report files
are allowed. Use isolated temporary data, deterministic public test keys, and
local test services. Preserve pre-existing changes. Do not publish findings,
open issues, send messages, or touch an operator's live node, database, wallet,
or credentials as part of the review.

Be exhaustive without manufacturing objections. Prefer conservative behavior,
simple ownership, explicit invariants, and readable Rust. A style preference is
not a correctness defect. Explain the practical benefit of each proposed
refactor. Do not demand abstraction, optimization, extra traits, genericity,
`unsafe`, dependency replacement, or file splitting without an observed need.
Do not promise perfection or use a numerical quality score as a substitute for
evidence. Passing tests and clean lints are necessary signals, not proof.

## 1. Establish scope and a reproducible baseline

1. Record commit, branch, dirty/untracked state, toolchain, OS/architecture,
   package version, Cargo profiles, features, configuration, and audit date.
   Distinguish observations about HEAD from observations about local changes.
2. Read applicable `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`,
   `ARCHITECTURE.md`, `docs/architecture.md`, `docs/compatibility.md`, the crate
   map, manifests, toolchain file, and relevant CI workflows. Maps and historical
   audit reports are navigation and leads; verify every claim against this
   checkout. Never inherit a prior report's completed status without checking.
3. Inventory all tracked crate files and relevant untracked source files.
   Reach first for `rg --files`; include ignored source deliberately where
   appropriate. Enumerate `src`, tests, doctests, examples, benches, features,
   binaries, build scripts, macros, generated assets, `include!`/`include_str!`/
   `include_bytes!`, `#[path]` fragments, regression seeds, manifests, and data.
   Follow shared fixtures, generators, extraction scripts, CI jobs, and docs
   outside the crate. Build output, vendored dependencies, local runtime data,
   and private secrets are outside the default file-reading scope; record
   exclusions and inspect relevant dependency contracts separately.
4. Maintain a **per-file coverage ledger**: path, role, review status, applicable
   feature/target, reviewed contracts, evidence, linked finding IDs, and gaps.
   Read all authored text completely, including test helpers and comments.
   For binary/large generated data, inspect its format, provenance, integrity,
   generator, representative content, and automated semantic verification;
   record exactly what was validated. Searching or reading a map does not count
   as reading a file. Do not silently sample authored source.
5. Enumerate public entry points, error variants, types, state machines,
   dependencies, callers, configuration switches, persistent schemas, external
   inputs, capabilities, and secrets. Map input to validation, computation,
   mutation, commit, and publication. Identify who owns each invariant and
   which caller can bypass the intended route.
6. Run a relevant baseline before experimentation. Keep existing failures
   separate from review-introduced changes. Capture exit codes and full logs,
   not just a success message or aggregate test count.

If coverage cannot be completed, persist the ledger and an exact continuation
plan. Mark the review incomplete. Continue across sessions without skipping
low-profile files, rereading completed work, or presenting partial coverage as
an exhaustive audit.

## 2. Correctness, compatibility, and invariant ownership

- For each function, examine preconditions, successful results, failure paths,
  side effects, ordering, rollback, and interactions with callers. Check every
  match arm, feature gate, fallback, TODO, stub, dead path, and exceptional case.
- Identify invalid states permitted by public construction, mutable fields,
  derived traits, deserialization, unchecked conversions, or test helpers.
  Distinguish raw, parsed, validated, applied, committed, and durable values.
  Check that capabilities and `Checked*` values cannot be forged or reused in
  an incompatible context. Verify cached bytes/IDs agree with semantic values.
- Inspect arithmetic by unit and domain: signedness, narrowing, overflow,
  underflow, wrapping, saturation, division, shifts, intermediate precision,
  ordering, inclusive ranges, and maximum counts. Check debug and optimized
  behavior, `usize`/32-bit assumptions, endianness, timestamps, and height zero.
  Checked arithmetic is not automatically correct when Scala semantics require
  wrapping or a particular overflow verdict; prove the intended behavior.
- Check deterministic iteration, hashing, canonical ordering, duplicate
  handling, content-addressed identity, byte equality, and serialization
  stability. Trace context/network/version/activation/epoch parameters through
  every caller. Cover before, at, and after each relevant transition.
- Distinguish consensus rules, local policy, transport/resource limits, API
  compatibility, and implementation safety. A local anti-DoS limit must not
  silently change valid block acceptance. A cleanup must not alter historical
  byte formats, costs, or rejection behavior without a documented decision.
- Use mainnet bytes and pinned Scala/sigma-state behavior according to
  `docs/compatibility.md`. Record reference commit/version, network, height,
  context, capture/generation command, and fixture integrity. Mainnet acceptance
  establishes positive examples; malformed and rejected inputs need independent
  reference verdicts. Specs, comments, and another Rust implementation do not
  automatically settle a disagreement with observed reference behavior.
- Cross-crate review is mandatory: follow constructors, mutators, consumers,
  serialization, persistence, and APIs. A local assumption checked by one
  caller does not protect an independently callable public entry point.

## 3. Rust design, readability, and maintainability

- Assess ownership and borrowing, lifetime requirements, mutability, aliasing,
  iterator use, RAII cleanup, interior mutability, globals, clones, and allocations.
  Prefer the clearest correct implementation over the shortest expression.
  Explain where immutable sharing helps and where it obscures lifetime or state.
- Assess names, module boundaries, visibility, cohesion, duplication, type
  aliases/newtypes, trait laws, API ergonomics, and dependency direction. Keep
  consensus logic separate from I/O/policy when contracts require it. Check
  `Eq`/`Ord`/`Hash`, conversions, defaults, custom `Debug`, and `Display` agree
  with semantics and do not expose secrets.
- Check error enums and context for actionable diagnostics without losing the
  source. Distinguish missing, invalid, unsupported, unavailable, corrupt, and
  failed operations. Inspect `.ok()`, default fallbacks, discarded `Result`s,
  catch-all errors, and logs followed by success. Preserve transactional state
  when errors propagate; a better error string cannot repair partial mutation.
- Inspect every `unwrap`, `expect`, assert, panic, unreachable branch, index,
  cast, and unchecked operation in its actual reachable context. Trusted static
  data and direct test assertions can justify these; peer/API/database input
  cannot justify them merely because an earlier layer usually validates it.
- Review `allow` attributes, lint scopes, `cfg`s, macros, custom destructors,
  hidden APIs, generated fragments, and compile-time assertions. A lint
  suppression needs a specific invariant or compatibility rationale. Cosmetic
  warning removal must not hide a bug, skip tests, or relax validation.
- Identify incidental complexity, stale compatibility branches, misleading
  abstraction, and undocumented cleverness. Suggest focused changes with a
  measurable reviewability, correctness, or performance benefit. Follow local
  conventions where they support clarity; surface convention defects honestly.

## 4. Memory safety and unsafe dependencies

- Inventory all authored `unsafe` blocks, unsafe functions/traits/impls, FFI,
  raw pointers, manual Send/Sync, unchecked indexing, initialization tricks,
  and memory mapping. Trace relevant transitive unsafe dependencies too.
- For each unsafe operation, state the exact safety obligations and prove them
  at every call site: validity, alignment, initialization, aliasing/provenance,
  lifetime, concurrency, and panic/drop behavior. A `SAFETY` comment must explain
  the proof, not merely assert that the operation is safe.
- Check safe public APIs cannot violate internal unsafe invariants. Verify
  unwind/error cleanup and destruction of deeply nested structures. Mark an
  unavailable dependency source or platform proof as an evidence gap.
- Use Miri, sanitizers, or model checking when supported and material to a
  concrete risk; record toolchain, target, assumptions, and unsupported paths.
  A clean run supplements the reasoning and covers only exercised executions.
  Consult the [Rust Reference](https://doc.rust-lang.org/stable/reference/behavior-considered-undefined.html)
  for undefined-behavior obligations; use documentation matching the pinned
  compiler when version details matter.

## 5. Adversarial input and resource bounds

- Treat peer bytes, JSON, scripts, proofs, lengths, counts, identifiers, stored
  rows, compressed data, and configuration as separate trust boundaries.
  Check admission before allocation/expensive work, integer-to-size conversions,
  full-input consumption, trailing data, duplicate keys, ambiguous encodings,
  and parser state after failure. Preserve deliberate legacy acceptance.
- Bound bytes, element counts, structural depth, evaluation work, allocation,
  proof materialization, response size, decompression, queue depth, retries,
  fanout, connections, disk use, and wall time where appropriate. Trace limits
  to actual enforcement rather than declarations. Small inputs can expand into
  huge trees, exponential work, or recursively dangerous destruction.
- Inspect aggregate limits across requests/peers/workers/nodes, not just one
  input. Validate that caches, negative caches, telemetry labels, logs, retained
  responses, error formatting, and failed requests do not become growth paths.
- Review keys, nonces, entropy, signature/proof malleability, timing comparisons,
  key derivation, secret ownership/erasure, crash dumps, logs, filesystem
  permissions, and external-process arguments where applicable. Use established
  crypto primitives. Require positive and malformed external vectors for
  cryptographic and consensus claims; do not invent new cryptography.
- Trace authorization/configuration from actual node loading to mounted routes
  and background tasks. Check insecure/misspelled options cannot silently
  appear effective. Test realistic production wiring and feature combinations.

## 6. Concurrency, lifecycle, and storage

- Identify writers, snapshots, lock ordering, critical sections, atomics and
  memory order, channels, shutdown signals, task/thread owners, and supervision.
  Check races, deadlocks, starvation, contention, stale snapshots, ABA-like
  reuse, and multiple node instances in one process.
- Follow every async await, `select!`, timeout, task abort, failed send,
  disconnect, panic, and dropped caller. Prove state/permit/queue ownership
  survives cancellation. Blocking work may outlive its awaiting request; its
  capacity permit and join ownership must survive until actual completion.
  Check fairness and bounded service latency under continuously ready traffic.
  Use the pinned Tokio docs for [selection, fairness, and cancellation](https://docs.rs/tokio/latest/tokio/macro.select.html).
- Verify admission closes before teardown; workers drain or cancel explicitly;
  long work has safe cancellation boundaries; required tasks are joined;
  shutdown errors reach the operator. `Drop` best effort is distinct from an
  explicit fallible successful shutdown. Cancelled shutdown callers must not
  abandon cleanup ownership.
- Distinguish in-memory visibility, queued writes, committed transactions,
  durability, acknowledgement, and publication. Verify atomic ownership of
  metadata/undo/index updates, ordering of competing writers, terminal errors,
  and consistent reads across related state.
- Classify persistence by its promised contract: consensus state, wallet secrets,
  rebuildable indexes, and advisory peer/diagnostic data have different failure
  policies. Verify that a documented best-effort write cannot compromise a
  stronger guarantee or silently claim durable success.
- Examine failure after every persistent step, partial writes, disk full,
  corruption, worker panic, torn/truncated records, reopen, migration, rollback,
  prune, and interrupted snapshot install. For durable files, examine file and
  directory sync, atomic publication, overwrite prevention, permissions,
  symlinks, and platform semantics. Chain-data recovery and wallet-secret
  recovery have different consequences.
- Use fault injection and barrier-controlled concurrency tests where necessary.
  State the model: returning an injected error, killing a process, and physical
  power failure establish different evidence. Native platform behavior cannot
  be certified by compilation or a different operating system's tests.

## 7. Review the tests themselves

- Inventory tests by behavioral contract, not count. Separate unit, integration,
  doctest, property, mutation, oracle, fuzz, replay, concurrency, crash,
  performance, and manual/feature/platform coverage. Flag untested invariants.
- Read setup, helpers, mocks, inputs, assertions, and teardown. Determine whether
  a plausible broken implementation would still pass. Check exact expected
  values/errors/state changes, missing assertions, swallowed failure, accidental
  success paths, setup that bypasses real wiring, overly broad acceptance, and
  stale comments/names. Avoid tests that just mirror private implementation.
- Round trips, fixed points, signing followed by same-stack verification, and
  internally recomputed expected values establish consistency. They do not
  establish Scala parity. Pin independent bytes/verdicts/costs/roots where the
  contract demands external correctness, and test rejection as well as success.
- Review fixture provenance, hashes, regeneration, expected results, migrations,
  generators, regression seeds, shrinking, and replay commands. Ensure a
  generator's declared vocabulary matches actual production and a coverage
  denominator cannot shrink to hide omitted cases. Never overwrite oracle
  expectations just to make the implementation pass.
- Exercise zero/one/maximum, limit minus one/at/plus one, empty/duplicate/invalid,
  truncated input at meaningful positions, deeply nested/wide/flat structures,
  activation boundaries, reused context, repeated failure, and reopen where
  applicable. Use targeted cases justified by a contract, not rote combinations.
- Check deterministic seeds, reproducible failure artifacts, independent tests,
  temp directories, parallel execution, no shared globals, platform assumptions,
  timeout meaning, and barriers instead of timing sleeps. Inspect ignored tests,
  early returns, missing-prerequisite paths, placeholder tests, `should_panic`,
  `no_run`, and cfgs. A skipped or compile-only oracle test is not a parity pass.
- Propose the smallest regression that fails for the observed defect. For a
  coverage gap, state the invariant, input, independent oracle if needed, and
  assertion. Add meaningful reproductions in temporary work only in review mode.

## 8. Comments, documentation, and public contract quality

- Read every authored comment and Rustdoc block, including tests and manifests.
  Check technical accuracy, present-tense invariants, units, examples, references,
  version claims, feature assumptions, and safety/error descriptions. Explain
  why surprising behavior exists; remove obsolete history and code narration
  when it obscures the contract. Preserve useful compatibility rationale.
- Public APIs should document purpose, input/output meaning, validation/trust,
  side effects, errors/panics, feature gates, resource limits, cancellation,
  durability, and examples as relevant. Do not require boilerplate sections for
  trivial accessors. Make unchecked and policy-sensitive operations unmistakable.
- Check README/codemap/architecture/configuration/operator docs, OpenAPI/JSON
  schemas, CLI help, example configs, changelog, and generated/embedded assets
  against actual behavior. Follow every local link and command. Document
  intentional API/reference deviations, unfinished work, and supported modes.
- Check prose grammar, spelling, naming consistency, terminology, useful error
  messages, logging fields/levels, and privacy. A log saying success before
  commit or docs promising an unenforced security setting is a contract defect.
- Compile and execute valid Rustdoc examples where appropriate; review hidden
  setup, `ignore`/`no_run`, invalid HTML, broken intra-doc links, feature-only
  symbols, and platform-specific examples. Documentation should teach a correct
  usage pattern and state actual limitations, not imply unsupported readiness.

## 9. Manifests, features, tooling, performance, and portability

- Check dependency justification, runtime vs dev separation, crypto choice,
  feature propagation, default features, duplicate versions, license/source
  policy, lockfiles, Rust-version/edition claims, and build scripts. Inspect
  actual production dependency trees; test/oracle/RNG helpers must not become
  unintended runtime dependencies or change production semantics.
- Test packages alone as well as within the workspace. Feature unification can
  hide missing declarations or enable a test-helper path. Default, supported
  minimal/no-default, individual meaningful features, supported combinations,
  and all-feature builds have distinct coverage; all-features is not the
  complete matrix. Use the [Cargo feature reference](https://doc.rust-lang.org/stable/cargo/reference/features.html)
  and resolved `cargo tree -e features` output to verify the actual graph.
- Check Linux/macOS/Windows and supported release targets, host widths, file
  rename/permission/lock behavior, path/encoding issues, clocks, and cleanup.
  Separate native execution from cross-compilation and untested targets.
- Inspect CI/test sharding, doctest and included-fragment coverage, ignored
  manual tests, supply-chain exceptions, artifact integrity, release commit
  verification, packaging, and runnable example configs. A passing required
  check must correspond to all required work actually running and succeeding.
- Examine hot-path complexity, copies, allocations, hashing, scans, batching,
  cache eviction, blocking runtime work, queueing latency, and adversarial
  worst-case cost. Use representative workloads and bounded adversarial ones.
  Record dataset, hardware, features, profile, repetitions, and distribution;
  a microbenchmark alone cannot establish end-to-end performance. Optimize only
  with evidence and revalidate semantics afterward.

## 10. Verification commands and evidence accounting

Derive commands from the current manifest, CI, and crate prompt; do not assume
features, targets, tools, or external prerequisites exist. From the repository
root, the per-workspace-crate starting point is:

```bash
cargo test --locked -p <crate>
cargo clippy --locked -p <crate> --all-targets --all-features -- -D warnings
cargo test --locked -p <crate> --doc
RUSTDOCFLAGS="-D warnings" cargo doc --locked -p <crate> --no-deps --all-features
```

Add supported feature/minimal builds and targeted reproductions. Run
all-feature tests only after classifying external/manual prerequisites; inspect
and compile gated bodies even when they cannot execute. Keep test-only features
out of production validation. The detached fuzz package has its own toolchain,
manifest, lockfile, and commands in its prompt and README.

Coordinate these shared workspace gates once for the reviewed revision:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --doc
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
cargo deny check
cargo machete
```

Run `cargo audit` with the current repository's documented CI flags and reviewed
advisory exceptions. Record current advisory/tool database provenance and assess
exceptions; neither remove nor add ignores casually. Check separately formatted
included fragments and detached packages that workspace formatting misses.
Use appropriate targeted scripts/cost-ledger checks from actual workflows.
Optional coverage, sanitizer, dependency, fuzz, or model-checking tools are
useful when they address a stated question; absence is a tooling limitation.

For each command record working directory, complete command, toolchain/features,
exit code, result, log/artifact path, tested revision, and counts of passed,
failed, ignored/skipped/manual tests. Distinguish **PASS**, **FAIL**,
**COMPILE_ONLY**, **NOT_RUN**, and **UNAVAILABLE**. State prerequisites and the
exact next command for missing evidence. Do not label an unavailable oracle as
pass, an infrastructure failure as a code defect, or a historical run as a
current run. Rerun verification after relevant edits; avoid repeating expensive
workspace gates unchanged for every crate.

## 11. Required deliverable

Write a durable report at `audit/reports/<crate>.md` unless the user specifies
another destination. `audit/` is currently ignored; clearly state that report
files are local artifacts. Store coverage and evidence alongside the report
(for example `<crate>-coverage.md` and `<crate>-evidence/`). Do not overwrite a
previous audit; use a revision/session subdirectory when needed.

The report must contain:

1. **Scope and baseline:** revision, local changes, platform/toolchain, mode,
   features, file inventory, exclusions, authorities, and external prerequisites.
2. **Contract map:** owned invariants, trust/resource boundaries, entry points,
   relevant state machines, callers/dependencies, and intentional deviations.
3. **Findings:** ordered by severity, then practical impact; each independently
   actionable and linked to precise file/line/function locations.
4. **Coverage and evidence:** complete ledger, test-to-invariant gaps, actual
   command results/artifacts, unreviewed paths, and unsupported/unrun scenarios.
5. **Remediation plan:** dependency-ordered, focused changes; preservation of
   compatibility; exact regression/acceptance evidence; remaining uncertainties.
6. **Readiness judgment:** `NOT_READY`, `NEEDS_EXTERNAL_VALIDATION`,
   `READY_WITHIN_REVIEWED_SCOPE`, or `INCOMPLETE_REVIEW`. State the reasons and
   limitations. An incomplete inventory always means `INCOMPLETE_REVIEW`;
   readiness requires coverage and resolved material risks for the stated scope.

For **each finding**, include:

- Stable ID; category; severity; and evidence status (`REPRODUCED`,
  `SOURCE_CONFIRMED`, or `HYPOTHESIS_REQUIRING_VALIDATION`). Keep hypotheses in
  an explicitly separate unresolved-risk list, not the confirmed-defect count.
- Concrete expected contract and its authority; actual behavior; exact location
  and cross-crate causal path. Describe attacker/operator preconditions,
  reachable input, affected mode/features, frequency, and impact.
- Minimal reproduction or source proof, observed results, oracle provenance
  where needed, and distinctions between demonstrated and inferred consequences.
- Smallest robust fix direction, compatibility/storage/API risks, and a specific
  regression test or validation criterion. Explain why existing tests miss it.

Severity meanings:

| Severity | Meaning |
| --- | --- |
| P0 | Demonstrated critical reachable failure requiring immediate attention: consensus split, exploitable key/fund compromise, or comparably catastrophic integrity failure. State the evidence and preconditions. |
| P1 | High-impact reachable correctness/security/durability/availability defect, including substantial remote DoS or a broken critical lifecycle/compatibility contract. |
| P2 | Material defect or important validation gap with a narrower trigger or consequence; actionable reliability, API, performance, testing, or documentation failure. |
| P3 | Low-impact polish or maintainability improvement with a concrete benefit. Do not inflate preferences into blockers. |

Category, confidence, and severity are independent. A missing critical oracle
is a validation gap, not proof of consensus divergence. Documentation can merit
high severity when it falsely promises a relied-upon security/recovery control.
Deduplicate shared root causes and link related symptoms across reports; record
the owning crate and the integration test required to close each shared gap.

If no defects are confirmed, say so and still deliver coverage, evidence, gaps,
and limitations. The review ends when all files and applicable contracts are
accounted for and the requested report is complete, not when the linter passes
or the first few interesting findings have been found.
