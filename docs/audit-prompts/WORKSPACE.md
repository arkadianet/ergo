# Workspace integration audit prompt

Read and apply [COMMON.md](COMMON.md) in full. Audit the node as one system after
the crate reviews, or alongside them with explicitly assigned seam ownership.
The individual reports do not establish that their assumptions compose.
Default to review only. Produce `audit/reports/workspace.md`, a coverage ledger,
and an evidence bundle using the common report format.

## Mission and complete scope

Evaluate whether this reviewed revision can meet a reference implementation's
behavioral, engineering, operational, and documentation standard. Review all
root files and shared assets that a crate report has not already covered:
workspace manifests/lockfiles/profiles, toolchain, `.github`, scripts,
test-vector provenance, root project/governance/security/license documents,
configuration examples, and the complete `docs/` tree. Inventory remaining
non-Rust assets rather than treating them as somebody else's responsibility.
Inspect manifests to rediscover all workspace members and detached packages.

Start with `Cargo.toml`, `rust-toolchain.toml`, `CONTRIBUTING.md`,
`ARCHITECTURE.md`, `docs/architecture.md`, `docs/compatibility.md`,
`docs/configuration.md`, `docs/operating.md`, `docs/events.md`,
`docs/logging.md`, `deny.toml`, and the actual `.github/workflows/` inventory.
Current workflows include `ci.yml`, `fuzz.yml`, `cost-ledger.yml`, and
`release.yml`. Revalidate their names and commands on this checkout.

## Cross-crate contract matrix

For every boundary below, record producer, consumer, invariant, failure policy,
visibility/publication point, configuration/features/mode, and integration
test/oracle evidence. Trace concrete source call paths, not just architecture
arrows. Include normal flow, rejection, interruption, restart, and reorg.

1. Raw peer/API/database bytes -> primitive reader -> consensus serializer ->
   validated types -> storage or mempool. Check canonical identity, complete
   consumption, structural limits, context/activation parameters, rejection
   classification, and absence of alternate unchecked admission paths.
2. Source -> compiler -> serialized tree/address -> evaluator -> verifier ->
   wallet signer. Compare external tree/address/proof/cost/verdict oracles.
   Internal signing/verification consistency is a separate evidence class.
3. Header/extension -> difficulty/votes/active parameters -> transaction script
   contexts -> state roots. Check network genesis, historical header windows,
   voting epochs, soft-fork/version activation, full-block and mempool contexts.
4. Sync -> validated block -> authenticated state -> undo/index/metadata ->
   persistent commit/durability -> mempool/wallet/index/API/event publication.
   Determine what each observer is allowed to see, and what remains after
   failure before or after each handoff. A committed root cannot describe a
   different full-block tip, parameter state, or index epoch.
5. Fork selection -> detach/attach -> state/wallet/index/mempool/mining updates
   -> snapshots and public events. Test partial-attach abort, same-height fork,
   interrupted recovery, deep rollback limits, and prune/bootstrap sentinels.
6. Submission -> admission/queue -> node action loop -> result -> propagation.
   Separate transaction validation, mempool policy acceptance, durable block
   application, and acknowledgements. Check continuously ready peer traffic,
   full/closed queues, cancelled callers, deduplication, and bounded latency.
7. Mining candidate -> parent/state/mempool snapshot -> proofs/rewards/roots ->
   external miner -> stale/repeated/malformed solution -> ordinary validation.
   Prove candidate construction and submitted solution use one coherent context.
8. Query -> immutable reader/index status -> REST conversion -> HTTP/WS and any
   other advertised stream transport.
   Define consistency and staleness explicitly. Corruption, failed reads, stale
   indexes, and missing rows must not all become an authoritative empty result.
9. Configuration -> resolved mode/network/auth/resource settings -> boot ->
   mounted routes/handshake/background services. Test the production path with
   examples from the operator documentation, including misspelled security keys.
10. Admission -> work permit -> task/thread -> shutdown/reopen. Follow ownership
    after timeout, abort, failed send, and dropped shutdown caller. Check two
    nodes in one process for shared globals, resource leakage, and interference.

## Operating modes and historical compatibility

- Build a matrix for Modes 1–6, network choices, pruning, UTXO snapshot
  bootstrap, NiPoPoW bootstrap, indexer, wallet, mining, API authentication,
  debug/diagnostic features, and supported persistent-state versions. Identify
  valid combinations and rejected configurations from actual resolved code.
- For each supported mode, verify fresh boot, progress, advertised capabilities,
  steady state, restart, shutdown, peer interaction, read APIs, failure recovery,
  and rollback boundaries. Test the real activation path rather than injecting
  a final sentinel/state into a helper. Distinguish logical tests from live
  mixed-peer/reference-node evidence and native durability tests.
- Verify trust anchors and provenance for snapshot/NiPoPoW installation,
  combined bootstrap orderings, voted-parameter anchors, epoch alignment,
  sentinel monotonicity, and proof/header/state agreement after reopen.
- Require both valid and invalid historical oracle cases around every relevant
  protocol activation, network, state backend, and transaction rule. Full-chain
  replay, a narrow corpus, cost fixtures, and a live soak demonstrate different
  things; report their actual ranges and limitations.
- Preserve deliberately observed Scala quirks. Record policy/API deviations
  independently of consensus verdicts. Do not infer completeness from a
  historical successful IBD or a roadmap checkbox.

## Shared tooling, documentation, and release chain

- Reconcile every crate inventory with manifests, test targets, included
  fragments, scripts, docs, embedded UI/assets, and fixtures. Assign a reviewer
  to every remaining authored file. Validate generated data through provenance,
  generators, integrity, and semantic checks without silently sampling source.
- Audit `scripts/ci-shards.py`: no omitted/duplicated packages or test targets,
  independent doctest coverage, correct feature coverage, and failure propagation.
  Inspect shell/Python/Scala/JavaScript tooling for errors, shell interpolation,
  locale/path portability, environment prerequisites, retries, and false success.
- Review `scripts/cost-ledger.py`, `scripts/cost-ledger-diff.py`,
  `scripts/l4-results-manifest.py`, fixture generators/extractors, JVM oracle
  scripts, fetched-input hashes, and ledger closure rules. Missing, duplicated,
  failed, stale, or skipped oracle evidence must not close a row or shrink the
  denominator. Check equivalent feature/context on both sides of comparisons.
- Review `.github/workflows/fuzz.yml` and `scripts/difftest-guard.sh`: bounded
  runs, seed retention, reproductions, declared vs reached generator vocabulary,
  oracle prerequisites, non-zero exits, artifact retention, and honest labels.
- Review workflow permissions, third-party action/tool pins, PR/tag input
  handling, dependency updates, package/license/source policy, advisory
  exceptions, cache trust boundaries, and reproducible locked resolution.
- Verify the exact release commit passes required gates before packaging or
  publication. A workflow that compiles archives without validating that commit
  is incomplete evidence. Check tag/ref resolution, release-note extraction,
  binaries/config/docs/licenses, checksums/provenance, and all claimed targets.
- Extract each supported release archive in an isolated directory and exercise
  documented commands, config, help/version, temporary startup, shutdown and
  immediate reopen where supported. Check packaged links and paths. Distinguish
  native smoke tests from cross-compilation and unsupported local platforms.
- Reconcile README/status, architecture, codemaps, comments, OpenAPI, operator
  docs, example configs, security claims, release notes, and actual behavior.
  The node's reference-quality aspiration must not erase current limitations.
- Evaluate representative replay, resource-safety, query, mempool publication,
  storage, and shutdown workloads. Report sustained throughput, tails, memory,
  disk/queue growth, and adversarial limits with dataset/hardware provenance;
  keep performance claims proportional to measurements.

## Verification and closure

Run the shared commands from `COMMON.md` once against the final reviewed
revision. Add feature-specific cost/value-trace and wallet test-helper targets,
diagnostics compile/runtime evidence, structured differential campaign,
cost-ledger checks, detached fuzz checks, embedded UI tests, native platform
coverage, and release smoke tests according to current workflows/manifests.
Do not run external-state diagnostics blindly or count skips as passes.

Reconcile every crate report and coverage ledger. Deduplicate shared defects,
name the root-cause owner, and retain affected consumers and integration
acceptance criteria. Independently challenge critical findings, key/fund
handling, state/durability conclusions, oracle independence, and remaining
readiness claims. A second reader's agreement without evidence is not closure.

The final report must include a complete crate/root-file coverage matrix,
cross-crate invariant/evidence matrix, exact validation results, prioritized
fix sequence, unresolved external campaigns, and a readiness judgment using
`COMMON.md`. Every omission must be visible. Review completion means accounted
scope and a finished report; reference readiness additionally requires closed
material risks and the evidence appropriate to the claimed use.
