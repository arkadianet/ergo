# Detached ergo-difftest-fuzz review

Readiness: INCOMPLETE_REVIEW. All detached authored source, comments, manifest and documentation were read in full. Native compilation and the stable harness tests passed, but the 26 committed binary files have integrity inventory only. The required native seed semantics, deliberate Bug-to-failing-process-to-artifact proof, crash minimization and campaigns were not executed. Repeated automated content-filter interruptions left runtime obligations unexecuted. The reviewer finalized saved source and evidence documentation with those gaps explicit.

## Scope and baseline

Reviewed revision 5d62fd5851e74fcb965b4aba50e1b423127f46f1, workspace version0.10.0, native Linux x86_64. Stable checks used Rust/Cargo1.95.0 with CARGO_BUILD_JOBS=6. The detached package is version0.0.0/edition2021, declares its own workspace, uses libfuzzer-sys0.4 and the current parent path dependency, and has six binary targets with test/doc/bench disabled. Stable root workspace checks do not cover these detached binaries.

The exact 9 authored detached files total 250 lines/9065 bytes: Cargo.toml, README.md, .gitignore and all six six-line shims. The mandatory prompt is a separate primary path. All source comments and helper/test code in the required parent fuzz.rs95, lib.rs339, surfaces.rs1490, surfaces_parity.rs555 and nightly_fuzz_regressions.rs99 were also read in full. The parent manifest/readme/interface contracts/catalog/nightly triage/findings documents, COMMON, assignment, codemap and fuzz workflow were fully read. Root Cargo.toml1–80 and stable ci.yml276–316 are explicitly scoped external boundaries; their full ownership belongs to WORKSPACE. Contribution/compatibility full reads are reused at unchanged exact hashes. The stable parent owner owns the remaining harness and generator/evaluator/replay/oracle files.

No repository source, tests, configuration, prompts, fixtures, corpora or locks were changed. No live node, wallet, external oracle, signing exercise, reinjection, failure demonstration or adaptive campaign was used. Preexisting user changes were preserved. Earlier reports describe other revisions and are not runtime evidence for this HEAD.

Coverage and receipt indices: [exact source/file ledger](/home/arkadias/Coding/remote/ergo/audit/reports/20261003T085740Z-5d62fd58/ergo-difftest-fuzz-coverage.json), [binary inventory](/home/arkadias/Coding/remote/ergo/audit/reports/20261003T085740Z-5d62fd58/ergo-difftest-fuzz-evidence/corpus-inventory.json), [target matrix](/home/arkadias/Coding/remote/ergo/audit/reports/20261003T085740Z-5d62fd58/ergo-difftest-fuzz-evidence/target-matrix.json), [exact reused receipt hashes](/home/arkadias/Coding/remote/ergo/audit/reports/20261003T085740Z-5d62fd58/ergo-difftest-fuzz-evidence/receipt-index.json).

## Contract and target map

Each shim invokes exactly one literal registered parent surface through fuzz_one. The six manifest names, paths, literals, corpus directories and workflow matrix names agree. There is no retired-name or typo no-op among these targets, although fuzz_one deliberately returns normally for an unknown name. The shims add no preprocessing, mutable global state, unsafe code or extra parser allocation.

| Target / shim / corpus directory | Current parent invariant | Seeds | Native evidence |
|---|---|---:|---|
| constant | Constant read/write, structural comparison and bounded byte fixed point | 4 | LIST + instrumented COMPILE_ONLY; run NOT_RUN |
| header | Header read/write and structural/byte fixed point | 1 | LIST + instrumented COMPILE_ONLY; run NOT_RUN |
| transaction | Transaction read/write, retained box/tree and context-extension parity view | 2 | LIST + instrumented COMPILE_ONLY; run NOT_RUN |
| sigma_expr | ErgoTree parser and consensus tree gates, structural/write fixed point | 7 | LIST + instrumented COMPILE_ONLY; run NOT_RUN |
| ergo_tree | Same tree parser/gates/invariants as sigma_expr | 8 | LIST + instrumented COMPILE_ONLY; run NOT_RUN |
| ergo_box_candidate | Box-candidate read/write and retained-tree/register parity view | 4 | LIST + instrumented COMPILE_ONLY; run NOT_RUN |

The sigma_expr native target does not execute evaluation, reduction, JIT cost comparison, proof verification or a JVM differential. Other hermetic surfaces, historical activated contexts, governance settings, state replay and oracle channels require separate evidence. These six targets parse with activated script version3. A parsed/fixed-point Accepted outcome is not transaction validity or chain acceptance, and several readers intentionally accept a prefix.

run_input selects the registry, runs the surface inside catch_unwind and converts a caught panic into Outcome::Bug. fuzz_one inspects those returned outcomes and panics afterward for Bug. Rejected and WriteRejected return normally. This placement provides source evidence that the deliberate wrapper panic is outside the parent's surface catch. Saved receipts do not demonstrate its final libFuzzer process status, panic mode, sanitizer handling, artifact bytes or upload.

The shared invariant exceptions were read completely. First-encode errors become WriteRejected. Failed re-decodes can be excepted for byte-preserved retained boxes, pending pre-v3 Upcast stripping, or opaque soft-fork bodies. Successful values compare explicit fields/private wire caches; opacity provenance alone is excluded, header IDs are independently matched to consumed header spans before comparison, and only direct Upcast(Const) stripping in pre-v3 trees gets bounded convergence, at most110 rounds. Existing synthetic structural-drift tests preserve unrelated fields, cast targets, header-ID corruption and fixed-point failures. These tests provide Rust regression evidence; they do not independently prove every broad exception against current Scala. The parent audit owns shared invariant root causes, including any exception false negative.

The nightly matrix has all six legs and fail-fast:false. It requests -max_total_time=600, -error_exitcode=1, -rss_limit_mb=2048 and final stats, with ASAN_OPTIONS=malloc_context_size=0. The workflow comments explicitly say this loses allocation/free stacks and advise diagnostic-default replay; it is not evidence that sanitizer detection was disabled. Per-input timeout/default maximum input size and wall-time effectiveness were not dynamically established. Crash upload runs on failure and corpus upload always, from repository-relative paths; missing artifact files are ignored. Thus a setup/build failure can produce no crash input while still leaving the job failed. No current GitHub run was observed.

## Findings

Three findings: P0=0, P1=0, P2=2, P3=1. EFF001 is a validation gap; EFF002 is a reproducibility assurance gap; EFF003 is a documentation mismatch. No runtime implementation failure was demonstrated.

### EFF001 — P2: Native crash signaling remains an important validation gap

Kind: validation gap; no demonstrated broken signaling implementation. Source locations: ergo-difftest/src/fuzz.rs31–36, its tests49–94, and lib.rs209–218. The wrapper's current tests check that valid, garbage, empty and unknown-name inputs do not panic. The parent selftest checks a surface panic becomes Bug inside run_one. Neither assertion exercises a Bug returned to fuzz_one and then verifies the native failure/artifact channel. The six compiled targets and selected ASAN/coverage symbols establish linkage only.

Trigger/precondition: an actual invariant Bug found by any native target. Consequence: the exact end-to-end operational assertion requested by the audit is unverified; no claim is made that Bug is swallowed or a real artifact was lost. Stable positive/non-Bug results cannot substitute for this assertion.

Evidence: complete source reads, current stable test logs, native build/instrumentation receipts. No new Bug injection or failure process was run. Recommended acceptance: in a permitted disposable validation environment, use a controlled known Bug to assert a nonzero native exit and matching saved raw artifact, then reproduce it and verify artifact upload. Keep environment/resource failures distinct. This work remains NOT_RUN here.

### EFF002 — P2: Floating detached resolution and crash uploads lack a self-contained provenance record

Kind: source-confirmed reproducibility/assurance gap, not an observed wrong dependency or memory defect. Locations: fuzz/Cargo.toml10–21, fuzz/.gitignore, .github/workflows/fuzz.yml181–202 and225–243. The package allows libfuzzer-sys0.4, ignores its generated Cargo.lock, installs an unversioned cargo-fuzz with --locked, selects floating nightly and caches the executable with a v0.13 label. The crash/corpus upload steps do not include a resolved dependency lock, compiler/tool version manifest, binary hash, full effective flags or transcript. A cache label is not an executable version assertion. --locked on cargo install does not pin the installed package version or detached target graph.

Trigger/precondition: later resolution, nightly or cached tool differs when someone attempts to reproduce an archived input. Consequence: the uploaded bytes alone cannot identify the exact compiled/toolchain context. GitHub job logs/source commit may help while retained; this is not proof that all existing artifacts are unreproducible.

The saved native build demonstrates why a graph receipt matters without proving a defect: it used cached nightly2026-09-30/cargo-fuzz0.13.2 and libfuzzer-sys0.4.13. The disposable build was not --locked; its copied ignored lock changed from original121 packages to120. Nine stale local path packages changed0.11.0→current0.10.0 and scoped-tls-hkt0.1.5 disappeared. All common package/source/checksum/dependency rows were unchanged. Original ignored lock SHA256 remained5e955068776b5f78c2883f7028e2046843e5e67500b7ffb9efec1d7a840a0319. The resolved copy is c5a5711f7d8cb0fc77788d18f68f8a5af16d8a25ddbfd0e279f31dd617f38a72. This preexisting ignored artifact is not counted as a repository bug.

Recommended acceptance: attach an environment/graph/command/input-hash record and relevant logs to each crash artifact; verify cache/tool versions and document the deliberate pin/update policy. A fresh and cached benign build should report its exact versions/graph. Current isolated receipts already model this provenance; no dependency update or new execution is recommended by this report.

### EFF003 — P3: The detached README misstates current replay/oracle CI coverage

Kind: source-confirmed documentation mismatch. Locations: fuzz/README.md142–145, parent Cargo.toml replay binary declaration, .github/workflows/fuzz.yml125–162 and246–356. The detached README says JVM differential and replay are not in CI and labels replay as difftest --replay. The current workflow contains a streamed replay job using the separate replay binary and a workflow_dispatch-only JVM consensus guard. Replay visibly skips when REPLAY_NODE_URL is unset. A workflow leg's existence does not prove it executed.

Consequence: a reviewer/operator can choose the wrong command or infer the wrong coverage boundary. Historical interface-contract decisions saying nightly cannot run in CI are also stale, but the parent owner owns that document's broader correction. Recommended acceptance: update the detached README to name the separate replay binary, the conditional replay job and manual JVM job, and retain explicit skipped/unexecuted distinctions. Validate commands from each stated working directory. The grow-corpus flag example and placeholder minimization paths were read; their actual libFuzzer behavior was not executed or independently checked, so no additional confirmed flag defect is asserted.

## Verification accounting

| Check / receipt | Actual result | Scope |
|---|---|---|
| cargo test --locked -p ergo-difftest, parent owner tests.result.json/tests.log | PASS124 / ignored2; exit0,6.530s | lib94, difftest binary3, replay binary0, integration27, doctests0 |
| Own locked lib + integration repetitions before final scope restriction | PASS94 +27, ignored2; exit0 | Saved results.json and full logs; not additional unique coverage |
| Minimal parent library check, --no-default-features | COMPILE_ONLY PASS, exit0,0.097s | Parent feature graph; no detached runtime proof |
| Parent normal/build/features tree | PASS, exit0,0.091s | Stable parent graph |
| Strict scoped parent Rustdoc, all-features/-D warnings | FAIL, exit101,0.528s | Three link diagnostics at gen/mod.rs36, minimize.rs14, regressions.rs149; parent-owned documentation issue |
| Parent doctests | PASS0, exit0,0.174s | Zero executable documentation examples |
| Shared warning-denying Clippy/fmt/dependency gates | Reused current-HEAD PASS | Stable workspace only; detached Clippy/fmt/dependency audit NOT_RUN |
| cargo fuzz list in isolated current-source copy | PASS_LIST_ONLY, exit0,0.0155s | Lists all six existing targets |
| cargo fuzz build in same disposable copy | COMPILE_ONLY PASS, exit0,24.246s | All six native Linux ASAN binaries, default sanitizer/debug overflow/build-std, codegen-units16/jobs6/offline |
| nm selected ASAN + coverage symbols | PASS all6 | __asan_init and selected counters/PCs/trace-compare linkage; no runtime efficacy proof |
| Every committed binary file | HASH_ONLY26 /4740 bytes | Exact hashes/sizes, nonempty and intended target mapping; consumer/provenance authentication NOT_RUN |
| Native valid/malformed input pairs, exact-file replay and campaigns | NOT_RUN | No native executions/run counts/branch features/accepted distribution |
| Known/injected Bug, saved artifact, reproduction and minimization | NOT_RUN | No process or artifact assertion was replaced |
| Fresh JVM, archival state replay, native non-Linux platforms | NOT_RUN | No parity, chain occurrence or broad node-readiness claim |

The two ignored tests are oracle::tests::reduce_diff_serialize_and_flatmap_match_jvm_oracle and oracle::tests::valdef_type_store_shapes_match_jvm_oracle, both requiring a live scala-cli oracle. Existing seven nightly regression tests passed in the parent integration suite: their current source-literal expected outcomes include tree empty/mid-VLQ WriteRejected, empty bool collection Accepted, box size-zero Rejected/size-one WriteRejected, transaction size-zero Rejected, and structural drift accepted after the intended comparison corrections. This does not assert these literals are identical to every named committed binary file. No new exact-file replay was executed.

Native binaries use exact current source copied from2340 tracked files plus the original ignored detached lock, with source/copy/tool/lock receipts under shared-evidence/native-fuzz. That root-created copy and build were reused; no second native build was run. Native executable hashes and instrumentation receipts are included by reference. ASAN compilation, elapsed build time, stable tests and archived historical zero-crash reports are not native campaign results.

## Binary corpus inventory

All entries below remain HASH_ONLY. Directory labels are intended target mappings, not minimum-validity/decoder verdict assertions. Filename provenance is recorded as intended historical/public fixture provenance in corpus-inventory.json; no current chain membership or independent JVM authentication is claimed. Four identical-byte groups occur across ergo_tree/sigma_expr: failing_tree_219, failing_tree_755, failing_tree_87 and fee_proposition. They intentionally feed two targets that currently share the same tree parser, and do not establish distinct branch coverage. There are no zero-byte entries. Four ignored historical crash files were inventoried by path in initial-inventory.json and not executed, minimized or promoted.

| Target | File | Bytes | SHA256 | Status |
|---|---|---:|---|---|
| constant | parity_header_id_219.bin | 219 | 32426b7997b9b82ae81ed33d03848ddd238d39484283147044676fe1b044a9fd | HASH_ONLY / NOT_RUN |
| constant | sboolean_false.bin | 2 | 47dc540c94ceb704a23875c11273e16bb0b8a87aed84de911f2133568115f254 | HASH_ONLY / NOT_RUN |
| constant | sboolean_true.bin | 2 | 9dcf97a184f32623d11a73124ceb99a5709b083721e878a16d78f596718ba7b2 | HASH_ONLY / NOT_RUN |
| constant | sint_42.bin | 2 | 1b8b7b2ebbcb7a948678b350d45b0381213f6a70708e6104cefc8c941ce77792 | HASH_ONLY / NOT_RUN |
| ergo_box_candidate | box_recent_0.bin | 161 | 6215faf6288f40b07082ad54e349015231c7166d501fe9c2e2097ced3e17472f | HASH_ONLY / NOT_RUN |
| ergo_box_candidate | nightly_size0_unparsed.bin | 29 | e6f5b8557ac872218075c9c50e8b6f7291a668180406f7a4d0caf331b7c6a3ef | HASH_ONLY / NOT_RUN |
| ergo_box_candidate | nightly_size1_reshape.bin | 8 | 568dc88a6ddede5372015272266715e0d6d91aac710095ce5cb121f1cf94d395 | HASH_ONLY / NOT_RUN |
| ergo_box_candidate | parity_softfork_flip_104.bin | 104 | 8a4035ecc5c8915b076e61c4e801559b6edbade2205ffe8e7ade7ff1adbc045a | HASH_ONLY / NOT_RUN |
| ergo_tree | failing_tree_219.bin | 413 | cadc6c25b68a9ff768ba15205a9495b47cbab10b5846a2a5f98526cc32b3b5cf | HASH_ONLY / NOT_RUN |
| ergo_tree | failing_tree_755.bin | 450 | e9ebf94a20c81ccb42fd0eaf7a9308eef21ecd7f5de019179cedf9f4e518cdef | HASH_ONLY / NOT_RUN |
| ergo_tree | failing_tree_87.bin | 415 | cb75a0c439ebc3d43f543c7c7127a6b9b370dc3152e479b3f6e74f17d6d5e41b | HASH_ONLY / NOT_RUN |
| ergo_tree | fee_proposition.bin | 105 | 744c727d6a1478912d1e7052957c2ba466bf9a5a89e9347309a58e2032473278 | HASH_ONLY / NOT_RUN |
| ergo_tree | nightly_empty_unparsed.bin | 25 | 97f82b82d164da33e627e403e32c00be42a941deeabfc21d45ac9cff29ae76b7 | HASH_ONLY / NOT_RUN |
| ergo_tree | nightly_mid_vlq_cut.bin | 8 | cd1a4247309c235b8a1ca9f70a728a9701fb10791966e83d52b4d27be0784dff | HASH_ONLY / NOT_RUN |
| ergo_tree | parity_upcast_chain_8.bin | 8 | 4fcfcc32033e673943173eb557372d5de68af3adfd12d2e2018898cee9bd43a1 | HASH_ONLY / NOT_RUN |
| ergo_tree | parity_upcast_const_137.bin | 137 | 7ef50c3ebd068d203475ea84f4d485a27a1dca94b1450c1e197cc112b23c94fe | HASH_ONLY / NOT_RUN |
| header | height_1.bin | 310 | 3f389406beabbbc27858ea1db4f42305a9679ed29461d1a7d1059edd2845eb03 | HASH_ONLY / NOT_RUN |
| sigma_expr | failing_tree_219.bin | 413 | cadc6c25b68a9ff768ba15205a9495b47cbab10b5846a2a5f98526cc32b3b5cf | HASH_ONLY / NOT_RUN |
| sigma_expr | failing_tree_755.bin | 450 | e9ebf94a20c81ccb42fd0eaf7a9308eef21ecd7f5de019179cedf9f4e518cdef | HASH_ONLY / NOT_RUN |
| sigma_expr | failing_tree_87.bin | 415 | cb75a0c439ebc3d43f543c7c7127a6b9b370dc3152e479b3f6e74f17d6d5e41b | HASH_ONLY / NOT_RUN |
| sigma_expr | fee_proposition.bin | 105 | 744c727d6a1478912d1e7052957c2ba466bf9a5a89e9347309a58e2032473278 | HASH_ONLY / NOT_RUN |
| sigma_expr | nightly_empty_bool_coll.bin | 100 | 28b00eebbd7a363618eee5c7e6cfe2045c10ef69e69cd5617d3eae1a2f9e87f0 | HASH_ONLY / NOT_RUN |
| sigma_expr | parity_upcast_chain_10.bin | 10 | 43fc8317dffa9bbd03f1f1043cd65c62135aff919d2720caff8d62d1113713dd | HASH_ONLY / NOT_RUN |
| sigma_expr | parity_upcast_const_415.bin | 415 | febb509c20bd2d3ea68576e834fddd8ee83a988eccecb930f5b2192d82dce5a5 | HASH_ONLY / NOT_RUN |
| transaction | genesis_tx0.bin | 367 | c41841a292621ed3cbcde65a1abfc69fc206db1f5783e06b8ffef06e2917a508 | HASH_ONLY / NOT_RUN |
| transaction | nightly_size0_unparsed.bin | 67 | 7a2e8fc9ce13cd1629b7093c3217d490579f8cefcab37488bcf13a9e1093d5fb | HASH_ONLY / NOT_RUN |


Root static supplement: [root-fuzz-static-content.json](/home/arkadias/Coding/remote/ergo/audit/reports/20261003T085740Z-5d62fd58/root-fuzz-static-content.json) (SHA256 b6cd73b1239ddfeae073058ee545aa66a3d87c0af8b5048a2858034404c21c93) records all26 complete seed byte strings,12 exact matches to current source literals, and3 exact captured JSON wire prefixes followed by ASCII annotation suffixes. This narrows byte/provenance comparisons beyond the initial inventory; it does not provide a fresh exact-file consumer run, native replay, complete semantic validation or chain authentication. The suffixes do not establish a defect: rw_check permits initial prefix decoding. Canonical HASH_ONLY statuses, native replay NOT_RUN and readiness INCOMPLETE_REVIEW are unchanged.

## Coverage limits and remediation order

The ledger has 59 records. All9 detached authored files and the mandatory prompt are FULL_READ;26 primary binary paths remain HASH_ONLY. External boundaries retain their exact read ranges rather than inheriting parent/workspace full coverage. Source-only source maps/generator and oracle claims are distinct from fully read source. Generated locks are read-only parsed/hash-compared in lock-integrity.json; they are not authored code review or third-party library review. No complete libfuzzer-sys/cargo-fuzz source audit or independent current JVM recapture was performed.

First attach precise provenance to native artifacts and correct the local coverage/command documentation. In a future permitted runtime validation, close EFF001 using the native signaling/artifact/minimization channel and replay exact binary files through all six mappings, preserving accepted/rejected/WriteRejected outcomes and per-target counts. Only after those receipts exist should a bounded campaign be interpreted; zero crashes alone cannot establish parser correctness, evaluator/cost parity, reference authority or consensus readiness.

This concludes the documentation finalization after the automated interruptions. INCOMPLETE_REVIEW specifically records the unexecuted semantic/native evidence, with no P0/P1 finding or claimed accepted-chain split, lost secret, runtime resource failure or crash-channel defect.
