# ergo-difftest independent audit

Readiness: **NOT_READY** as reference-quality compatibility measurement tooling.
The authored parent crate inventory is complete, and the ordinary Rust checks
and structured campaign pass. Material defects allow missing or inconclusive
work to become a successful guard or rediscovery result. This report does not
demonstrate a production-node consensus divergence or key/fund compromise.

Confirmed findings: **14 P2, 3 P3; no P0/P1**. Five are reproduced (four saved
local observations plus the strict Rustdoc failure); twelve are source-confirmed
defects or important validation gaps. Unresolved risks are separated below and
are not counted as defects.

## Scope, baseline, and authority

- Review-only audit of `ergo-difftest` v0.10.0 at
  `5d62fd5851e74fcb965b4aba50e1b423127f46f1`, branch `main`, 2026-10-03 UTC.
  Baseline and original dirty-file hashes are in [baseline.json](baseline.json).
- Linux 7.1.5 x86_64, glibc 2.39; rustc 1.95.0
  `(59807616e 2026-04-14)`, cargo 1.95.0 `(f2d3ce0bd 2026-03-21)`.
  Commands ran from `/home/arkadias/Coding/remote/ergo` with
  `CARGO_BUILD_JOBS=6`, the existing shared Cargo target, and the locked graph.
- Original local state: modified root `README.md`; untracked
  `docs/audit-2026-10-03.md`, `docs/audit-remediation-todo.md`, and
  `docs/audit-prompts/`. They were preserved. No implementation, test, fixture,
  corpus, baseline, prompt, toolchain, or configuration was changed.
- Complete parent scope: **75/75 tracked files**, excluding the separate
  `ergo-difftest/fuzz` package. This includes every authored Rust/Python file,
  inline/integration test and comment, four crate documents, both binaries,
  manifests/pins, and all 21 reinjection patches. The `.gitignore` is included.
- **52 associated files fully read**, including common/crate audit contracts,
  contribution/security/compatibility/architecture documents, codemap,
  root manifest/toolchain, guard/reinjection scripts and selftests, JVM serde
  and evaluated-value oracles, cost-fixture helpers, AVL producer,
  CI/shard/probe tooling, fixture provenance documents, and the detached fuzz
  manifest/README/six target shims as parent-library seams.
- **221 associated data files validated separately**, including 204 cost
  fixtures, the ledger metadata, verify JSON/JSONL streams, TSVs, genesis boxes,
  selected parser/signature fixtures and Scala AVL vectors. Their exact
  per-file hashes and validation scope are in the ledger. The total is
  **348 entries: 127 FULLY_READ + 221 GENERATED_DATA_VALIDATED**.
- [Coverage ledger](ergo-difftest-coverage.json) and
  [coverage summary](ergo-difftest-evidence/coverage-summary.json) are local
  ignored audit artifacts. No parent authored path is unreviewed. Generated
  data status means the recorded validation was executed; it never substitutes
  for reading authored source or for a fresh independent oracle run.

The repository's compatibility contract and the checked-in Scala scripts are
the authorities for intended reconciliation. `interface-contracts.md` is an
explicit spec but is partly historical; current source takes precedence for
describing actual behavior. Captured fixture manifests identify sigma-state,
ergo-core and ergo-wallet 6.0.6, the capture-time source revisions, scripts,
Java/Scala tools, context, and stream hashes. These pins are recorded evidence,
not proof that a future local dependency resolution uses those same jars.

No fresh Scala/JVM execution or live-node request occurred in this audit.
Available neighbor Scala checkouts and JVM tools were not used as substitute
authority without resolving and hashing the actual pinned artifacts.
Historical L4/L6 manifests and closure reports remain historical evidence;
their counts were not relabeled as current campaigns.

External node implementation files and transitive dependency implementations
remain owned by their independent crate audits. The cost ledger was parsed and
its records/references inspected as fixture metadata; its full historical
Scala enumeration and inventory-audit narratives were not re-audited here.
The separate fuzz audit owns its complete corpus, detached lockfile/nightly
toolchain, native libFuzzer execution and sanitizer/platform claims. Build
outputs, third-party vendored source and runtime/private data were excluded.

## Contract and surface map

The hermetic state machine is input generation → named reader/check →
`Accepted`, `Rejected`, `WriteRejected`, or `Bug` → campaign statistics/findings
→ CLI exit. Fixed points establish Rust codec consistency on the parsed prefix;
they do not establish independent Scala acceptance, proof validity, or full
transaction/block validity. Panic catching is an unwind boundary, not an OOM,
stack-overflow or abort guarantee.

The current **28 hermetic surfaces** are:
`sigma_type`, `constant`, `ergo_tree`, `sigma_expr`, `ergo_box_candidate`,
`ergo_box`, `transaction`, `unsigned_transaction`, `header`,
`block_transactions`, `extension`, `popow_header`, `nipopow_proof`, `input`,
`unsigned_input`, `context_extension`, `spending_proof`, `register`,
`ad_proofs`, `token`, `nbits_difficulty`, `autolykos_v1`, `autolykos_v2`,
`ctx_expr`, `verify`, `batch_merkle_proof`, `validate`, and `verify_avl`.

The **seven structured generators** cover `ergo_tree`, `constant`,
`ergo_box_candidate`, `transaction`, `header`, `ctx_expr`, and `sigma_expr`.
The recorded 50k campaign reached **35/35 declared labels**, including the
on-manifold label; it did not run all 28 hermetic surfaces, evaluate all
generated scripts, cover all protocol versions, or query a JVM.

The **nine Rust/JVM differential surfaces** are `ergo_tree`,
`ergo_box_candidate`, `transaction`, `header`, `reduce`, `reduce_ctx`,
`verify`, `validate`, and `verify_avl`. MethodCall registry checking separately
uses the `mc_root` protocol and 199 captured method signatures. Scala exposes
additional direct protocol commands; those are not automatically Rust
differential surfaces.

| Boundary | Actual contract and ownership |
| --- | --- |
| Byte generators/corpora | Own seed/iteration/mode and bounded mutation; corpus admission and ordering currently weaken reproducibility (DIFF-07). Feature labels measure declared constructors, not executed semantic branches. |
| Hermetic codec checks | Reader/writer fixed points and structural comparisons, with explicit opaque/soft-fork, Upcast and Header normalization. Retained-wire hashes have independent hashing checks, but share Rust parsing for their spans. Prefix consumption is deliberate and must remain distinct from EOF validity. |
| `reduce` / `reduce_ctx` | Reduction under fixed dummy context, activation 3, synthetic SELF/inputs, empty last-headers window, fixed AVL context and parameters. The context frame supplies extension/register values; it is not arbitrary chain context. Reduction charges are not full verifier/proof/transaction costs. |
| `verify` | Full-verification JSON request/typed comparison record. It uses a separate hardcoded evaluated-value sidecar even if a different serde `--oracle-script` is supplied. `unavailable` cost components are not numeric parity evidence. Advanced producer request fields are not all supported by the difftest Rust request type. |
| `validate` | Stateless transaction structure under default mainnet parameters. It has no UTXO or chain-state authority. Reader activation differs between the hermetic default reader and explicit oracle readers. |
| `verify_avl` | Framed digest/proof/operations, rejection and final digest comparison. Operation return values are discarded, so lookup/previous-value correctness is outside this differential contract. Both Rust and Scala framing must be maintained; Rust round trips alone do not prove it. |
| JVM subprocesses | Line-framed pipes, EOF/error handling, optional flushed transcript, kill/wait of direct children. Startup/query wall time and response length are unbounded (DIFF-08). |
| Minimization/classification | Deterministic greedy shrinking and final re-query; class preservation is the current coarse surface/kind/verdict class, not proof of a common root cause. Reconciliation can mark parse-only differences KnownArtifact; evidential limits matter (DIFF-09). |
| Artifact/baseline/guard | JSON records, a pending queue, and exact surface/short-input-hash filenames. The guard currently trusts filenames and lacks complete divergence-to-artifact accounting (DIFF-01/11). |
| Reinjection | Disposable worktree patches and clean/patched detection commands. General exit classification and generated-mode implementation are insufficient (DIFF-02/03). No patches were newly applied during the final static review. |
| Archival replay | Contiguous-from-genesis mainnet replay with trusted archival PoW and production validation/apply dependencies. It uses fixed parameters and incomplete later-era context; genesis and pin accounting have separate limits (DIFF-12/13). |

The package has no selectable crate features, examples, benches, build script,
or authored unsafe blocks. Its unconditional dependencies enable
`ergo-sigma/cost-trace` and `ergo-validation/test-helpers`. The isolated
`ergo-node` normal/feature trees include neither `ergo-difftest` nor those
features. Workspace all-feature tests can unify helper features, so production
graph validation remains separate.

## Confirmed findings

### DIFF-01 — guard loses a detected divergence when minimization errors

**P2 · test/CI accounting · REPRODUCED.** Authority: the guard's documented
contract is every planned check completed and every unbaselined pending
divergence fails. In `src/bin/difftest.rs:719`, minimizer errors other than
`UnexpectedEof`/`BrokenPipe` only print `FAILED` and continue; the record is
neither filed nor marked as a harness failure. `scripts/difftest-guard.sh:225`
accepts campaign exits 0/1 and checks only the error marker and input count,
then discovers findings by existing JSON filenames at line 248.

Saved [guard log](ergo-difftest-evidence/guard-missing-record.log) used the real
Rust binary with a local scripted oracle: one check/one divergence was reported,
the subsequent oracle/minimizer error produced zero records, and the wrapper
returned **0/PASS**. This proves harness accounting failure, not JVM or node
correctness. Exact arguments/exit are in the adjacent `.result.json`.

Make any failed minimization/classification an explicit incomplete-work error,
or retain the original divergence as pending before optional shrinking. Require
`unique_divergences == filed + explicitly explained outcomes`; validate a
structured campaign result rather than recovering all status from text. Add a
regression for oracle `ERR`/invalid verdict during minimization and an ordinary
local shrink failure. The current guard selftest covers a missing summary,
which does not exercise this completed-summary/missing-record path.

### DIFF-02 — general reinjection calls unrelated process failure detection

**P2 · test authority · SOURCE_CONFIRMED.** Authority: the manifest/interface
require rediscovery of the declared divergence class on the declared surface.
In `scripts/reinject_gate.sh:377`, the patched build pipeline ends `|| true`;
line 394 treats **any nonzero detection exit** as PASS. A compile failure and
missing executable, CLI usage error, or oracle harness error therefore satisfy
the general branch without detecting the injected defect. The separate verify
branch correctly requires exit 1 and a verify divergence marker, which
demonstrates the narrower behavior needed elsewhere.

Preserve/fail on the build status, require the appropriate finding exit plus a
typed matching surface/class result, and report infrastructure errors
separately. An isolated script test should distinguish build failure, harness
exit 3, wrong-surface finding and intended finding. The existing reinjection
selftest tests calendar validation only; no new reinjection run was performed.

### DIFF-03 — generated rediscovery mode skips every eligible check

**P2 · generator validation · SOURCE_CONFIRMED.** Authority:
`interface-contracts.md` section 3/5 requires bounded generated rediscovery,
and script help advertises `--generated`. `scripts/reinject_gate.sh:278`
unconditionally skips generated mode for both oracle classes and hermetic
classes. It says structured generators are absent despite `src/gen/mod.rs`
being present, and returns a successful all-skip summary at line 410.

Implement the advertised generator/surface/budget dispatch, or reject the
unsupported option explicitly. Require nonzero completed coverage for an
explicit selected wire-reachable entry. Test one generated oracle class and
one hermetic class with typed outcomes and bounded budgets. Existing grammar
label-coverage tests and the 50k campaign do not establish rediscovery.

### DIFF-04 — canonical gate succeeds without checking a canonical value

**P2 · missing-work detection · REPRODUCED.** Authority: an explicit
`--check-canonical` invocation asserts the known trigger's output. At
`src/bin/difftest.rs:311`, a Rust reader rejection prints SKIP and returns
success, so rejection of a formerly valid trigger can be a clean reinjection
baseline. [Saved log](ergo-difftest-evidence/canonical-skip.log) shows exit 0
with no canonical comparison.

Return a distinct incomplete/invalid-trigger outcome for this path; the
reinjection caller must require an actual canonical result and the intended
patched failure class. Test a valid expected value, a changed value and an
unreadable trigger. This changes tooling exits, not consensus acceptance.

### DIFF-05 — coverage option accepts invalid thresholds and unsupported modes

**P2 · CLI validation · REPRODUCED.** Help promises `0.0..1.0` and a measured
coverage assertion. `src/bin/difftest.rs:94` only parses `f64`; line 502 uses
`union_ratio < min`. NaN makes that comparison false. Other negative/out-of-range
values are also accepted, and threshold handling occurs only in the hermetic
structured path, so other modes can ignore an explicitly supplied assertion.

[Saved log](ergo-difftest-evidence/nan-coverage.log) records zero iterations,
zero reached labels, and **coverage-gate PASS** for NaN. Require a finite
threshold in the documented interval, validate flag combinations before mode
dispatch, and distinguish an intentionally empty diagnostic run from a coverage
gate. Test NaN/infinity/out-of-range and each supported mode combination. Normal
finite-threshold coverage tests miss these admission paths.

### DIFF-06 — structured oracle mode generates the wrong framing for verify

**P2 · important coverage gap · SOURCE_CONFIRMED.** Authority: generated bytes
must reach the requested semantic surface rather than agree at schema rejection.
`src/bin/difftest.rs:902` maps reduce/ctx/validate correctly, then falls back to
`ergo_tree` for unsupported generator names. Both `verify` and `verify_avl`
are selectable oracle surfaces but lack generator mappings.

`verify` thus receives ErgoTree bytes where JSON is required; Rust maps schema
failure to RejectOther, while the JVM sidecar receives `null` and rejects its
schema. Agreement can be counted without full verification. `verify_avl`
receives a tree instead of an AVL frame and usually fails at framing. These are
source-proven dispatch errors; no fresh JVM campaign was run to assign rates.

Provide valid/invalid request/frame generators with proof/context controls, or
reject `--structured` for those surfaces. Require at least one successful parse
and semantic witness per generated surface. The current seven-surface
hermetic campaign cannot catch this nine-surface oracle dispatch gap.

### DIFF-07 — corpus loading silently loses requested work and seed ordering

**P2 · reproducibility/admission · REPRODUCED.** `--corpus` requests seeded
mutation. `src/bin/difftest.rs:967` returns an empty corpus on `read_dir`
failure, ignores entry/file/decode failures, and uses unsorted filesystem order.
The same RNG seed can select different seed bytes after directory-order changes.
Quoted-string extraction also scans textual JSON instead of a fixture schema.

[Saved log](ergo-difftest-evidence/missing-corpus.log) shows an explicitly
missing corpus followed by a successful unseeded one-iteration campaign. Make
corpus loading fallible, report selected/rejected counts and reasons, require a
usable corpus when explicitly requested, and sort stable path/content identities.
Record a corpus digest in campaign provenance. Test equivalent directories with
different creation order and unusable requested input. Current deterministic
generator tests do not exercise filesystem corpus determinism.

### DIFF-08 — promised oracle query timeout is unenforced

**P2 · bounded execution/diagnostics · SOURCE_CONFIRMED.** The authoritative
interface says the harness enforces per-query timeout and no surface may hang.
`src/oracle.rs:79` spawns piped subprocesses; both query paths synchronously
flush stdin and use unrestricted `read_line` at lines 177/193. There is no
startup/query deadline or response cap, and stderr is discarded at line 105.
Drop cannot execute while a query remains blocked. The direct child is killed
and waited after a completed query; descendant cleanup is not established.

Add bounded startup/query I/O, a maximum response length, typed timeout/protocol
failure, retained bounded stderr and explicit lifecycle ownership for both
sidecars. Ensure a timed-out child cannot continue participating in subsequent
queries. Use existing/mocked subprocess tests for incomplete output, delayed
output, long output and startup failure. No slow-oracle demonstration was newly
run. EOF/malformed-verdict tests do not prove a deadline.

### DIFF-09 — generic reduction agreement is insufficient to certify benignity

**P2 · important classification gap · SOURCE_CONFIRMED.** The public triage
contract calls KnownArtifact “explained benign, no consensus impact.” At
`src/regressions.rs:177`, any `Reconciliation::Agree` becomes that disposition.
`src/oracle.rs:935` defines both rejections as agreement. Reducing under one
fixed dummy context can reject before a context-dependent parse difference has
observable semantic effect. Even accepting agreement in one context does not
identify the stated retained-byte/deferred-curve reason.

The transaction/header reconciliation misuse has already been correctly removed;
the remaining tree/box channels still need a narrower evidential rule. This is
a confirmed insufficient classification contract, not a demonstrated hidden
node fault or claim that every current KnownArtifact is wrong.

Keep unexplained agreement/rejection pending and use explicit, source/fixture
backed normalization reasons; record which contexts were tested. Add captured
context-dependent controls where both dummy reductions reject and preserve the
parse difference for review. Existing tests prove indeterminate errors remain
pending, not that ordinary rejected agreement establishes benignity.

### DIFF-10 — filed campaign provenance loses the generating iteration/mode

**P2 · reproducibility · SOURCE_CONFIRMED.** `SeedInfo` promises the generating
seed/iteration and the schema distinguishes structured generation from mutation.
`src/bin/difftest.rs:741` records every minimized campaign class with `iter: 0`
and line 662 passes `oracle-mutation` even for structured oracle campaigns.
`src/regressions.rs:228` builds a repro command without custom oracle script,
sidecar hashes, context/activation pins or revision. An input literal remains
available, but regenerating it and identifying its actual authority is unreliable.

Retain the first concrete iteration and actual mode with the divergence, record
oracle/script/revision/corpus/context metadata, and render a replay command that
uses it. Keep unavailable capture metadata explicit rather than inventing it.
Test a later-iteration structured finding and a custom oracle configuration.
Current JSON round-trip tests check representation rather than provenance truth.

### DIFF-11 — artifact publication/identity is too weak for concurrent evidence

**P2 · diagnostic storage/baseline integrity · SOURCE_CONFIRMED.** The artifact
contract is replayable, content-addressed evidence. `src/regressions.rs:266`
hashes only input hex to a 64-bit filename prefix; lines 284/287 overwrite JSON
in place. Different findings/authorities on the same surface/input can replace
each other, and interruption can leave partial JSON. Queue check-then-append
is unsynchronized and is separate from record publication. It is idempotent
only under the single-writer successful-write assumptions.

`scripts/difftest-guard.sh:248` trusts matching filenames without decoding the
record or binding kind/context/oracle version, so damaged or stale evidence can
still become a baseline hit. No crash/concurrency experiment was newly run.

Use atomic complete record publication, an identity incorporating contract and
authority, and validated baseline metadata. Either make the queue a derived
view or synchronize its update with explicit recovery; do not promise wallet-
grade durability for these diagnostic files. Add two-writer/idempotence and
truncated-record baseline tests. Existing tests cover sequential same-path filing.

### DIFF-12 — genesis root pin is not verified by the replay pin counter

**P2 · replay authority/accounting · SOURCE_CONFIRMED.** The checked-in pins
promise height/header ID/state root binding. `src/bin/replay.rs:749` checks the
height-1 ID returned by `/blocks/at`, increments `pins_verified` immediately,
then uses the fetched header root in `apply_genesis`. It never compares the
computed/applied root with `pin.state_root`, unlike the later-height branch at
line 960. Genesis also bypasses the later CheckedHeader construction.

All eleven current pins have valid ID/root shape; this finding is not about
malformed current data. An inconsistent genesis root field is untested despite
being reported verified, and fetched genesis bytes are trusted more broadly
than normal-height bytes. Bind the fetched genesis bytes to the pinned ID and
compare the resulting state with both header and pin before counting verification.
Validate pin schemas/normalized height uniqueness and report which commitments
actually ran. Add offline genesis pin disagreement and ID/body consistency tests;
the replay binary currently has zero unit/integration tests of its own.

### DIFF-13 — replay accepts heights outside its faithful context model

**P2 · important replay validation gap · SOURCE_CONFIRMED.** The CLI accepts
arbitrary `--to` while `src/bin/replay.rs:666` uses fixed mainnet defaults for
every height. The validation context at line 892 always has voting length 1024,
active unknown-vote rule, no parent extension/soft-fork/reemission state; its own
comments justify those choices only for early heights. It does not derive
historical voted parameters or later protocol state. CI's optional replay range
extends beyond the earliest documented context. `--to 0` is also accepted and
the driver applies genesis then returns success at line 631.

Without a validated era model, rejection at later heights cannot be attributed
to the node as a reference-validity mismatch. This is a source-confirmed
validation gap, not an observed later-block divergence. Enforce supported range
and `to >= from` immediately, or build the same historical epoch/context state
as production with captured independent checkpoints. Add offline transition
tests and exact selected/completed range accounting. No live replay ran here;
historical cost replay performed by other tools does not validate this binary.

### DIFF-14 — guard clears any caller-selected directory under the repository

**P2 · local tooling data safety · SOURCE_CONFIRMED.** The guard intends to clear
a dedicated regression output directory and claims typo protection.
`scripts/difftest-guard.sh:157` authorizes every path beneath `REPO_ROOT`, then
line 164 recursively removes it unless `--keep-regressions` is set. Repository
membership does not prove that a directory is owned diagnostic output.

An operator's mistaken existing project subdirectory is therefore within the
deletion condition. No deletion demonstration was performed. Use a fresh
dedicated session directory, or require an explicit ownership marker and safe
canonical path policy before clearing prior output. Test refusal of ordinary
repository directories and directory traversal/symlink ambiguity in isolated
temporary projects. The current keep-regressions selftest does not exercise
destructive output initialization.

### DIFF-15 — warning-as-error public Rustdoc fails

**P3 · documentation/build quality · REPRODUCED.** The required strict package
Rustdoc build exits **101** with three diagnostics:
`src/gen/mod.rs:36` publicly links private `crate::run_one`;
`src/minimize.rs:14` has unresolved `DivergenceKind`;
`src/regressions.rs:149` publicly links private `reduction_channel`.
[Full log](ergo-difftest-evidence/docs.log) is preserved.

Use qualified public links or plain code references where internals are intended.
Require the same strict command to pass without suppressing link warnings.
Clippy and the zero-example doctest run do not check these failures.

### DIFF-16 — present-tense spec/map and regeneration instructions are stale

**P3 · documentation correctness · SOURCE_CONFIRMED.**
`docs/codemap/ergo-difftest.md:29/34` reports 26 hermetic/7 oracle surfaces;
current counts are 28/9. `interface-contracts.md` mixes 6.0.2 historical ground
truth, [SPEC] labels for implemented surfaces, an obsolete pin path/schema,
unimplemented `--offline`, a never-auto-resolved triage schema, and claims that
nightly cannot run in CI despite the current optional nightly fuzz workflow.
The regression module's introductory classification list also contradicts its
correct current transaction/header channel exclusion.

Associated fixture instructions have concrete command errors:
interpreter README line 99 adds `.json.gz.gz`, while the op-per-item README
names absent `scripts/gen-op-per-item.py` instead of
`ergo-difftest/src/gen/op_per_item.py` and loops only gzip files although that
family currently has plain JSON fixtures. Historical divergence prose also
needs explicit historical labeling when adjacent closure prose is current.

Rewrite current contracts around actual registries/commands and move historical
plans under dated history. Generate inventory tables from the registries and
check referenced paths/suffixes. Preserve capture-time producer provenance;
do not rewrite old manifests to claim regeneration. Existing Rust lint/tests
cannot validate these prose and shell-example contracts.

### DIFF-17 — panic hook suppression is process-global and unsynchronized

**P3 · library concurrency/diagnostics · SOURCE_CONFIRMED.** Public campaign,
input and fuzz entry points use `SilencePanics`; `src/lib.rs:294` takes/replaces
the process panic hook and Drop restores it at line 303 without synchronizing
concurrent uses. Interleaving two calls can restore the no-op hook permanently,
and unrelated threads' panics are suppressed while a campaign runs. The unwind
catch still returns Bug for its own panic; the issue is hook ownership and
diagnostics rather than a demonstrated missed decoder panic.

Avoid per-call global hook mutation, or install a coordinated scoped policy
with documented process ownership and nesting/concurrency behavior. Verify
restoration and an unrelated thread's hook in a barrier-controlled test.
Single-thread panic selftests establish catch behavior but miss hook races.

## Executed checks and saved observations

All check logs and exact argv/cwd/HEAD/exit/time are in
[ergo-difftest-evidence](ergo-difftest-evidence/). Each check has
`<name>.log` and `<name>.result.json`. **12 ordinary checks** ran: 10 PASS,
1 COMPILE_ONLY and 1 FAIL. Four earlier saved defect observations are separate
from pass counts.

| Evidence name | Command/result | Meaning |
| --- | --- | --- |
| `tests` | `cargo test --locked -p ergo-difftest` — PASS, 124 passed, 2 ignored | 94 lib + 3 CLI + 27 integration; replay has 0 tests; 0 doctests. Both ignored cases require a fresh JVM. |
| `clippy` | `cargo clippy --locked -p ergo-difftest --all-targets --all-features -- -D warnings` — PASS | All current targets compile/lint; no crate feature matrix exists. |
| `doctests` | `cargo test --locked -p ergo-difftest --doc` — PASS, 0 tests | Successful empty doctest suite, not executed examples. |
| `docs` | `RUSTDOCFLAGS="-D warnings" cargo doc --locked -p ergo-difftest --no-deps --all-features` — FAIL/101 | Three package documentation link errors, DIFF-15. |
| `minimal` | `cargo check --locked -p ergo-difftest --no-default-features --all-targets` — COMPILE_ONLY | No selectable features; unconditional helper dependencies remain enabled. |
| `features` | `cargo tree --locked -p ergo-difftest -e features` — PASS | Test helper/cost tracing graph inspected. |
| `production`, `production-features` | `cargo tree --locked -p ergo-node -e normal` and `-e normal,features` — PASS | No difftest, cost-trace or test-helpers in that normal production graph. |
| `structured-50k` | `cargo run --release --locked -p ergo-difftest --bin difftest -- --structured --iters 50000 --seed 20261003 --min-coverage 1.0` — PASS | 350,000 runs; 294,368 accepted, 55,632 rejected, 0 WriteRejected, 0 Bug. Seven surface ratios 1.00; 35/35 declared labels. Hermetic only. |
| `guard-selftest` | `bash scripts/difftest-guard.selftest.sh` — PASS | Existing missing-summary diagnostic test in temporary data. |
| `reinject-parser-selftest` | `bash scripts/reinject_gate.selftest.sh` — PASS | Existing manifest calendar/blocked-entry test only; no patches applied. |
| `data-integrity` | `python3 -B .../ergo-difftest-evidence/validate_data.py` — PASS | Detailed limits and hashes in `data-validation.json`; 18 Python AST parses and 5 `bash -n` checks included. |

The read-only data check decoded JSON/gzip with CRC validation, checked nonempty
request/expected arrays and ledger references, reconstructed request and response
JSONL hashes for **204 fixtures/70,276 cases** (all match), and verified external
verify manifest hashes and paired case/stream equality (**14 + 8 + 10 cases**).
It checked TSV column consistency, verdict/hex/consumption bounds, and all eleven
pin ID/root shapes. It inspected source/tool/context/run metadata and gzip header
timestamps. It did **not** execute 70,276 Rust/JVM cost comparisons; those are
stored records whose integrity was checked. The package tests do execute their
selected captured-verdict consumers, including deserialize-type fixture verdicts.

Saved observations from before the final static-only steering:
`guard-missing-record`, `canonical-skip`, `nan-coverage`, `missing-corpus`.
Their logs and exit records are preserved unchanged. The guard observation uses
a local scripted oracle and is explicitly not a reference JVM result. No new
reinjection patches, attack simulations, exploit payloads or failure
demonstrations were created during the final review.

Root-coordinated workspace evidence is under [shared-evidence](shared-evidence/).
Root reported nextest **7,629 passed/98 skipped**, fmt/Clippy/doctests/dependency
and ledger gates passing, strict workspace Rustdoc failing, and **63 JavaScript
unit tests passing** with an isolated runtime. Those are shared results, not
duplicate commands or additional package pass counts from this auditor.

## Evidence gaps and unsupported scenarios

| Contract/category | Current evidence | Missing evidence / next authorized validation |
| --- | --- | --- |
| Panic/invariant detector | Existing selftest and targeted unit/integration tests PASS | Hook concurrency remains untested (DIFF-17); abort/OOM/stack overflow are not catch-unwind claims. |
| Legitimate normalization | Captured TSV + exact Rust regression outcomes PASS; normalizer comments/source fully read | No fresh JVM recapture of all opaque/redecode/reshape exception families. |
| Oracle crash/protocol | Existing malformed/indeterminate/EOF unit checks; saved scripted ERR during minimization | Slow/dead/oversized child lifecycle and timeouts NOT_RUN; must close DIFF-08 before unattended campaigns. |
| True independent divergence/minimization | Captured external expectations and final-query source reviewed; greedy minimizer tests PASS | Fresh class-preserving JVM finding → artifact → reproducible replay NOT_RUN. Saved fake verdict is not genuine consensus evidence. |
| Baseline near miss/corrupt evidence | Exact input-key source reviewed, sequential filing tests PASS | Near-miss authority/class binding, partial JSON and concurrent publication NOT_RUN; DIFF-11. |
| Rediscovery | All manifest entries and 21 patches read; existing calendar selftest PASS | Patched clean/fault typed detection and bounded generated rediscovery NOT_RUN; DIFF-02/03 prevent a trustworthy green result today. |
| Methods/context/cost/proofs | 199-signature TSV, typed requests, captured verify streams and Scala producers read; selected captured-verdict tests PASS | Fresh JVM methods/well-typedness, activation matrix, proof operation outputs, unavailable failure costs and full context combinations NOT_RUN. |
| Archival replay | All source/pins/genesis fixtures reviewed; pin shapes valid | No local/live archival request, full-chain replay or offline binary tests. Unsupported era context, genesis pin accounting and range admission require fixes first. |
| Nightly/native/platform | Stable shared fuzz logic and six target shims reviewed | Detached fuzz campaigns, sanitizer/Miri runs, 32-bit/non-Linux execution, process-tree cleanup and crash durability NOT_RUN; separate fuzz/native audit owns these. |
| Performance/resource envelopes | Actual stable campaign timing logged; generator/mutation/shrink complexity reviewed | No benchmark distribution or worst-case JVM/minimization budget validation. Short cached-build campaign timing is not node performance evidence. |

Exact commands for later evidence, after fixes and isolated pinned-tool preflight:

```sh
# Run one existing ignored JVM test at a time, in an isolated checkout/workspace.
cargo test --locked -p ergo-difftest --lib oracle::tests::reduce_diff_serialize_and_flatmap_match_jvm_oracle -- --ignored --exact
cargo test --locked -p ergo-difftest --lib oracle::tests::valdef_type_store_shapes_match_jvm_oracle -- --ignored --exact

# Guard and replay need an approved pinned oracle / isolated archival fixture source.
# Use a fresh owned artifact path; do not reset shared baselines or production data.
DIFFTEST_ORACLE_LOG=/absolute/isolated-evidence/oracle.log scripts/difftest-guard.sh --iters 2000 --keep-regressions --regressions-dir /absolute/isolated-evidence/regressions
cargo run --locked --release -p ergo-difftest --bin replay -- --from 1 --to 5 --node http://127.0.0.1:ISOLATED_ARCHIVAL_PORT --pins /absolute/isolated-evidence/reviewed-pins.json
```

These are **NOT_RUN continuation commands**, not results. Resolve/cache/hash
the script dependencies, choose a valid isolated port/path and set JVM PATH per
command before execution. Current root JVM tool availability is insufficient to
certify capture-time artifact resolution. Do not use later-era replay ranges
until DIFF-13 is resolved.

Unconfirmed risks requiring independent validation, outside the defect counts:

- Broad opaque retained-byte/redecode exceptions can potentially hide an
  unrelated serialization fault; existing precise captured controls constrain
  several families, but no new independent counterexample was demonstrated.
- Greedy byte shrinking can be expensive and can preserve only a coarse
  verdict class; no globally minimal/root-cause-equivalent result is proved.
- AVL framing uses independent Scala/Rust implementations, discarded operation
  results and prefix/EOF conventions; lookup/previous-value correctness and all
  integer/count boundaries need an expanded independent contract before broader
  proof-compatibility claims.

## Remediation and acceptance order

1. Repair failure accounting first: DIFF-01/02/03/04/05/06. Guards must distinguish
   completed matching findings, clean evaluated agreement, explicit unsupported
   scope and harness failures. Keep original evidence when shrinking fails.
2. Bind repeatability and authority: DIFF-07/09/10/11. Sort/validate corpora,
   retain real iteration/mode, record exact oracle/context identity, keep
   unexplained cases pending and atomically publish validated evidence.
3. Bound subprocess work and lifecycle: DIFF-08. Require deadlines, response
   limits, useful stderr and cleanup of both oracle sidecars before unattended CI.
4. Correct replay's supported scope and commitments: DIFF-12/13. Add hermetic
   binary tests before any fresh archival campaign; preserve historical Scala
   parameters rather than treating defaults as every era's authority.
5. Make output initialization safe (DIFF-14), fix strict docs and current
   commands/maps (DIFF-15/16), and correct process-global hook ownership (DIFF-17).
6. Rerun the locked package gates, captured fixture consumers, guard result
   matrix and meaningful typed rediscovery checks. Then obtain explicitly
   pinned independent JVM/context/cost/proof and isolated replay evidence.

Compatibility-preserving fixes should target harness policy, accounting and
evidence schemas. They must not rewrite oracle expectations or change consensus
acceptance merely to make a campaign green. Diagnostic artifact/baseline schema
changes need explicit migration or refusal of incompatible historical records.
The review is complete within the stated parent authored scope; the material
tooling defects and independent execution gaps prevent a reference-quality
readiness claim.
