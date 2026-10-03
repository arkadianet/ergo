# `ergo-difftest/fuzz` reference-quality audit prompt

Audit the supporting `ergo-difftest-fuzz` package at `ergo-difftest/fuzz` as the
detached nightly libFuzzer integration for the stable `ergo-difftest` harness.
Read `docs/audit-prompts/COMMON.md` first, then `CONTRIBUTING.md`,
`docs/compatibility.md`, `docs/codemap/ergo-difftest.md`,
`ergo-difftest/fuzz/README.md`, and the parent harness interface contracts.
Apply the common review-only workflow, complete file ledger, evidence rules,
and report format. This is a separate supporting crate, intentionally excluded
from the stable workspace; root workspace checks do not establish its coverage.

## Mission and boundaries

Trace binary corpus input → libFuzzer target → stable `fuzz_one` → selected
hermetic surface → invariant verdict → deliberate crash signal → saved artifact
→ reproduction/minimization → curated regression and corpus. The crucial
question is whether each nightly target performs meaningful checks and whether
faults survive sanitizer/toolchain/process/artifact handling to become actionable
evidence. This crate's targets do not automatically run the JVM oracle.

## Source landmarks and associated material

- Read `ergo-difftest/fuzz/Cargo.toml` and the root workspace exclusion; inspect
  detached workspace resolution and any lockfile actually present.
- Read every `fuzz_targets/*.rs` file: `ergo_tree`, `constant`,
  `ergo_box_candidate`, `transaction`, `header`, and `sigma_expr`.
- Inventory every binary file under `corpus/<target>/`, including newly added
  nightly/parity regression seeds; check target mapping and provenance.
- Read all parent `ergo-difftest/src/fuzz.rs` code/tests, `ergo-difftest/src/lib.rs`
  panic handling, actual `ergo-difftest/src/surfaces.rs` registries, and
  `ergo-difftest/src/surfaces_parity.rs`
  exception handling; use the parent audit prompt for shared logic depth.
- Read `ergo-difftest/tests/it/nightly_fuzz_regressions.rs`, associated fixture
  references, and parent docs linking historical crashes and their resolution.
- Read `.github/workflows/fuzz.yml`, stable campaign selection in `ci.yml`,
  `.gitignore` artifact/build rules, and any documented minimization commands.
- Resolve crate-local documentation claims about stable/nightly pins, target
  counts, crash findings, corpus growth, CI gating, and JVM/replay invocation.

## Wiring and false-negative review

1. Build a target matrix: manifest name/path, target string, parent surface,
   invariant/exception policy, corpus directory, workflow leg, timeout, memory
   cap, toolchain/instrumentation, and artifact upload path.
2. Verify every shim's literal surface exists in the actual hermetic registry.
   `fuzz_one` silently accepts unknown names; prove no typo or retired surface
   makes a target run millions of iterations with zero checks.
3. Check `sigma_expr`'s actual parser/invariant rather than assuming it performs
   evaluator/cost differential testing from its name. State what untested
   evaluator, context, proof, or JVM surfaces require separate campaigns.
4. Verify `Outcome::Bug` reaches a libFuzzer-visible panic and non-Bug rejection
   paths return normally. Inspect panic-hook/catch-unwind and target panic mode;
   the parent must not swallow the deliberate crash signal emitted by the shim.
5. Review every suppressed `WriteRejected`/opaque/normalization exception for
   narrow independent evidence. A clean target must not simply be dominated by
   rejected inputs or a blanket exception covering valuable valid cases.
6. Verify detached dependencies/features use the intended parent checkout and
   instrumentation without pulling nightly flags into production workspace
   builds. Review libfuzzer-sys dependency provenance and resolution reproducibility.
7. Check thin shims contain no extra allocation, unbounded preprocessing, unsafe
   behavior, implicit shared state, or differently configured parser path that
   undermines the parent invariants or makes corpus replay disagree.

## Corpus, resource bounds, and nightly operation

8. Inventory corpus bytes as evidence rather than opaque filenames: content hash,
   source/witness, minimum validity, target decoder, expected interesting branch,
   and associated fixed or pending defect. Detect empty/wrong-surface duplicates.
9. Check corpus seed balance includes valid witnesses and boundary mutations,
   historical versions, soft-fork/canonical forms, length/depth/numeric limits,
   and known parser edge cases. Corpus presence alone does not prove a branch ran.
10. Review corpus minimization/growth/pruning instructions against actual cargo-fuzz
    and libFuzzer flags. Generated inputs must be curated and independently
    classified before becoming long-term reference regressions.
11. Inspect `-max_total_time`, runs, RSS, input-size, timeout, and parallel job
    settings together. Distinguish sanitizer overhead, execution timeout, OOM,
    compiler failure, and invariant panic in logs and exit status.
12. Review `ASAN_OPTIONS` and other sanitizer environment settings: determine
    which evidence is suppressed and whether security-relevant detection remains
    enabled. Preserve a way to replay memory failures with diagnostic defaults.
13. Check pinned versus floating nightly/tool versions, cache keys, host/platform
    assumptions, tool installation behavior, and compiler/sanitizer incompatibility
    reporting. Record versions with artifacts so old crashes remain reproducible.
14. Verify scheduled/manual matrix includes every target, independent failures
    continue other legs, each failure has a nonzero exit, and crash/corpus upload
    runs under the intended conditions with paths relative to the actual workdir.
15. Confirm workspaces/permissions/cache/artifact retention cannot silently drop
    crashes or accidentally commit artifacts/build trees. CI green after skipping
    a target/build must never be reported as that target's clean campaign.

## Required evidence and scoped verification

- Prove one valid and one malformed input per target invokes the intended parent
  surface; retain evidence of a known/injected Bug reaching a failing process
  and saved artifact. Perform mutation injection only in a disposable checkout.
- Replay every committed nightly regression through stable parent tests and its
  mapped target; independently inspect the expected result and exception class.
- Reproduce a crash from raw bytes, minimize it, then independently confirm the
  minimized failure still has the same cause. Record hex/hash, target, toolchain,
  parent revision, sanitizer settings, full command, and whether it is a genuine
  implementation defect or an environmental/resource failure.
- Separate run counts, elapsed time, branch/feature coverage where measurable,
  accepted/rejected distribution, and unique findings; avoid presenting elapsed
  fuzzing time or zero crashes as proof of correctness or consensus parity.
- Use `cargo test --locked -p ergo-difftest` for stable shared logic. With existing nightly
  prerequisites, run `cargo +nightly fuzz list` and `cargo +nightly fuzz build`
  from `ergo-difftest/fuzz`. Account for every target before a bounded campaign.
- For an existing corpus, a bounded example from that directory is
  `cargo +nightly fuzz run ergo_tree -- -max_total_time=60 -rss_limit_mb=2048`.
  Run equivalent target-specific checks only within an explicit review budget;
  use disposable corpus/artifact locations because libFuzzer grows corpora.
- Verify minimization paths against workdir: from `ergo-difftest`, the documented
  layout is `fuzz/artifacts/<target>/crash-<hash>`; from the detached fuzz directory
  it is `artifacts/<target>/crash-<hash>`. Do not execute placeholder paths.

Complete when every target/seed/workflow/documentation file is ledgered, surface
mapping and crash signaling have evidence, stable/nightly/JVM/replay coverage is
clearly distinguished, and unavailable instrumentation, resource limits, missing
regressions, and reproducibility gaps are explicit in the common report.
