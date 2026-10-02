# Audit remediation checklist

The [historical audit](audit-2026-10-03.md) reviewed `5d62fd58` (0.10.0).
Remediation was revalidated against `a6b193ef` (0.11.0), incorporating already
merged upstream fixes. The five draft PRs form a dependency stack; review and
merge them from persistence through engineering. Each changes at most 100 paths
relative to its own base, including fixtures, tests and documentation.

This checklist distinguishes implemented fixes from validation that needs
external infrastructure. It does not establish an exhaustive audit, cryptographic
proof, live-mainnet performance or perfection.

## Completed implementation

- [x] F01: Give header and full-state transactions separate metadata ownership;
  exercise queued writes, advancement, same-height forks and database reopen.
- [x] F02: Make persistence failure terminal and sticky, including full
  notification channels and repeated shutdown/re-enable attempts.
- [x] F03: Retain frame admission and byte permits across cancelled reads;
  cover resume, completion, disconnect and aggregate connection limits.
- [x] F04: Bound constructed AST/type depth, including flat operators and
  suffixes; test compilation and destruction on a bounded stack.
- [x] F05: Publish restrictive encrypted wallet files atomically; sync before
  success and cover injected write/publication failures.
- [x] F06: Wire validated script authentication and cost settings through
  production boot; reject unknown security keys and check every script route.
- [x] F07: Return persistence and join failures from explicit shutdown.
- [x] F08: Own, cancel and join wallet writers/rescans before final storage close;
  check database reopen and per-node isolation.
- [x] F09: Service ready API/mining work under continuously ready peer input,
  preserving shutdown priority; retain a regression against old selection.
- [x] F10: Propagate indexer read/decode failures to routes and degraded health;
  distinguish corrupt rows from missing balances and bound range queries.
- [x] F11: Encapsulate parsed registers and cached bytes; replace them atomically
  through a fallible operation and preserve canonical box identity.
- [x] F12: Enforce the Scala writer's 127-entry context-extension boundary using
  freshly generated external fixtures, including constructor propagation.
- [x] F13: Own API services, worker pools and stores per node; close admission
  and retain task ownership when a shutdown caller is cancelled.
- [x] F14: Inventory and zeroize owned secrets; reduce copies and document
  concrete limits of memory erasure.
- [x] F15: Generate Scala wallet encryption/storage/legacy derivation fixtures;
  correct authenticated encryption layout and execute bidirectional interop.
- [x] F16: Repair strict workspace Rustdoc links/HTML and gate documentation.
- [x] R01: Share immutable Sigma propositions; make drop, proof traversal and
  comparison iterative; charge logical materialization before allocation.
  Preserve bounded Scala byte/cost/verdict and malformed-proof parity.
- [x] R02: Distinguish committed and synchronously durable persistence; make
  IBD policy transitions fallible and drained.
- [x] R03: Bound per-node blocking read/compute admission; retain permits until
  work completes after cancellation/timeout and document service responses.
- [x] R04: Remove global rescan state and supervise wallet lifecycle tasks.
- [x] R05 implementation review: Revalidate IPv6 `/48` admission grouping,
  webhook DNS/address policy, operating modes and reorg coverage against current
  upstream behavior. Record the external evidence still needed below.
- [x] Split large node and evaluator test modules by behavior, preserving test
  bodies and oracle provenance; explicitly format included Rust fragments.
- [x] Move the historical compiler design ledger out of current API docs;
  reconcile crate maps, configuration, lifecycle and compatibility guidance.
- [x] Inherit workspace MSRV/lints; pin CI actions, tools and nightly; use locked
  resolution and configure automated dependency updates.
- [x] Require validation of the exact release commit, bundle runnable config
  and operator docs, and smoke-test extracted archives with shutdown/reopen.
- [x] Add compiler/evaluator fuzz workloads and curated seeds; record bounded
  campaigns, serialization/resource measurements, mempool/API publication
  samples and three fresh replay/root/reopen runs with workload limitations.
- [x] Make diagnostics that depend on external nodes or optional captures
  explicit manual tests; missing prerequisites must fail when requested.

## Delivery and verification

All five draft PRs are open. The delivery table records the completed local
gates; hosted CI is verified separately on the corrected stack. The PR base defines the file count, rather than `main`
for every layer. The complete stack changes 440 unique paths, requiring at least five PRs under
the requested limit; this stack uses five.

| Order | Scope | Draft PR | Changed paths | Checks |
| --- | --- | --- | ---: | --- |
| 1 | Persistence/wallet | [#481](https://github.com/arkadianet/ergo/pull/481) | 85 | Format/Clippy; 7,779 workspace tests passed, 97 ignored |
| 2 | Runtime/API | [#482](https://github.com/arkadianet/ergo/pull/482) | 99 | Format/Clippy; 7,796 workspace tests passed, 97 ignored |
| 3 | Query/codec contracts | [#483](https://github.com/arkadianet/ergo/pull/483) | 93 | Format/Clippy; 7,801 workspace tests passed, 97 ignored |
| 4 | Compiler/evaluator | [#484](https://github.com/arkadianet/ergo/pull/484) | 99 | Format/Clippy; 7,820 workspace tests passed, 97 ignored |
| 5 | Engineering/release | [#485](https://github.com/arkadianet/ergo/pull/485) | 100 | 7,821 default / 7,882 all-feature tests passed; final follow-up checks passed |

All five layers passed their required local gates. Hosted CI is
separate and may still be running. Layer 1 additionally passed 249 wallet
test-utils/proving tests (one intentional oracle ignore); layer 4 passed its
cost-trace suite.

Required per-layer checks are locked workspace tests, all-target/all-feature
Clippy with warnings denied, and Rust formatting. Included fragments are checked
from the layer that introduces them. The complete stack additionally runs strict
all-feature Rustdoc, all-feature tests, cost-trace and wallet proving targets,
CI/release policy checks, browser model tests, dependency checks and a Linux
archive smoke. Existing intentional ignores are reported, not counted as passes. Hosted Scala
wallet interoperability has passed. A Windows persistence test exposed a
notification/commit assertion race; the assertions now run after joining the
worker and passed 100 concurrent repeated runs. The final state unit suite
passed 395 tests (two intentional ignores), followed by strict Clippy/Rustdoc.
Two empty ignored activation placeholders were removed and are tracked as
missing evidence below; full-suite totals above precede that test-only cleanup.
The complete-stack suites reported 100 default and 111 all-feature ignores
before the two placeholder removals. Strict fetched cost-ledger evidence passed
all three manual tests, including the 101,187-transaction required replay; the
aggregate closure check validated 299 rows (274 CLOSED, 25 N-A). Raw normal
and manual results are retained separately, and the strict merge rejects missing,
failed or duplicate manual results. CI/release policy (13 tests), the ledger
checker (16 tests), all 65 browser model tests, dependency checks and Linux GNU
release archive smoke passed. The documented bincode unmaintained exception
remains; no known vulnerabilities were reported.

Recorded measurements and oracle provenance are linked from
[resource safety](perf/resource-safety-profile.md),
[wallet remediation](audit-remediation-storage-wallet.md), and
[operating evidence](operating-mode-evidence.md).

## External validation still open

- [ ] R05: Run Mode 2 against a Scala-produced trust snapshot and retain roots,
  provenance and reopen evidence.
- [ ] R05: Complete a live Mode 3 activation campaign and a long Mode 4 soak.
- [ ] R05: Broaden Mode 5 cold-open/replay coverage using a closed, separately
  owned historical snapshot; the early-mainnet smoke is insufficient.
- [ ] Obtain external full-block cost fixtures at v2/EIP-37 activation. Empty
  placeholder tests are removed; existing boundary tests do not establish these
  missing full-context oracle comparisons.
- [ ] Run streamed archival replay with an available `REPLAY_NODE_URL` and the
  explicitly manual live-Scala/capture diagnostics on their required datasets.
- [ ] Execute the native macOS, Windows and musl release archive smoke in CI;
  local validation covers Linux GNU only. Physical power-cut durability and
  Windows directory persistence require platform-specific validation.

The final bounded-evaluator ASan campaign used seed `20261003`, pinned
`cargo-fuzz 0.13.1` and `nightly-2026-09-30`: 9,163 executions in 31 seconds,
480 MiB peak RSS, no findings and no lockfile drift. Earlier source-compiler
and evaluator campaigns completed 191,677 and 16,219 executions respectively.
These bounded campaigns do not replace scheduled long runs. The measured
replay source [`5a67cd65`](https://github.com/arkadianet/ergo/commit/5a67cd6580cae9f1682f08636d21b74998b189da)
is retained on `codex/audit-integration` for reproduction independently of the
repacked PR history.

Cooperative distributed multisig orchestration and the compact-selector external
oracle are deliberately deferred features in the compatibility inventory.
Existing signed-size overflow asymmetries are disclosed in the Scala growth
fixture README. These are not marked as completed validation campaigns.
