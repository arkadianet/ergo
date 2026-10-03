# `ergo-sync` reference-node audit prompt

Audit `ergo-sync` as the chain-selection, validation orchestration and bootstrap layer of a reference-quality Ergo Rust node.
First read `docs/audit-prompts/COMMON.md` and apply its entire audit contract and report format.
Then read `CONTRIBUTING.md`, `docs/compatibility.md`, and `docs/codemap/ergo-sync.md`.
This is a review-only audit unless the invoking user explicitly authorizes remediation.
Verify documentation against current code; do not assume earlier audits establish current correctness.
Independently inventory every crate file, inline/integration test, include fragment and referenced fixture/script/benchmark.
Apply COMMON to production code, test helpers, comments, rustdoc, manifests and dependency/feature configurations.

## Mission and trust boundaries

Determine whether every reachable sync path selects the correct chain, validates under the right context and advances state only after successful application.
Track untrusted peer announcements/headers/sections/proofs into validation, durable storage and coordinator feedback.
Separate pure event-to-action logic from IO execution and node-level transport/cancellation.
Distinguish consensus rejection, missing local context, corrupt local data, persistence failure, and legitimate waiting/retry states.
The current Scala reference and mainnet behavior are acceptance/byte authorities; local implementation agreement is supplementary evidence.

## Current source landmarks

- `src/lib.rs`, `src/coordinator/mod.rs`: facade, `Action`, coordinator ownership and configuration.
- `src/coordinator/{chain_view,events,scheduling,transactions,section_verify,tests}.rs`: chain seam, event reducers, requests, tx gossip and receive-time ID verification.
- `src/header_proc.rs`: parse/PoW pre-validation, checked-header capability, linkage/difficulty finalization.
- `src/executor/{mod,startup,header_pipeline,peer_requests,block_apply,reorg}.rs`: startup caches, batched headers, peer requests, sequential apply and forks.
- `src/executor/{tests,relay_tests,failed_tx_tests}.rs`: review each distinct test module and registration.
- `src/block_proc/{mod,utxo,digest,failed_tx_tests}.rs`: section loading, context, validation, AD-proof paths and state application.
- `src/snapshot_bootstrap/{mod,manifest,chunks,tests}.rs`: manifest votes, checkpoint/root/height trust and chunk ownership.
- `src/popow_bootstrap.rs`: NiPoPoW consume reducer, quorum, verification and apply terminal.
- `src/perf.rs`, `src/apply_phase.rs`: counters and live RAII apply gauges.
- `tests/it/main.rs`, startup/hydration, header EOF/curve, epoch boundaries, pruning and Mode 5 replay tests.
- `tests/it/mode5_failed_tx_tests.rs`, `restart_benchmark.rs`: verify compilation/registration and prerequisites independently.
- Caller seams in `ergo-node/src/node/{events,sync_tick,peer_actions}.rs`, `node/messaging/`, and storage/validation/P2P trait implementations.

These are landmarks, not the inventory. Follow every module/include and discover remaining shared files yourself.

## Coordinator and delivery state

- Enumerate event preconditions/postconditions for SyncInfo, Inv, modifier receive, validated header, applied block, timeout, disconnect and local block.
- Preserve coordinator purity/determinism apart from telemetry; every external effect must be represented and consumed in the action stream.
- Verify all emitted actions are flushed by callers, including drain actions after `process_local_header`, retries and reorgs.
- SyncInfo V1/V2 parsing and comparison must handle no overlap, duplicate IDs, forged heights, sparse histories and network/version capability differences.
- Preliminary peer classification must not substitute height for cumulative-work fork choice.
- Check headers-synced latches against advertised height lies, stale peers, absence of peers, fresh startup and operator overrides at the node seam.
- Delivery registration and pending-block state must follow mode/prune gates before creating requests or receiving/storing bodies.
- Bound download windows, orphan buffers, duplicate caches, failed requests and pending assemblies under adversarial out-of-order announcements.
- Verify capacity partitioning, fairness, refill thresholds, head-of-line hedging, late arrivals and disconnect ownership release.
- A send failure or local dropped action cannot legitimately charge non-delivery to a peer that never received the request.
- Transaction inventory/request bookkeeping must respect local invalidation caches without poisoning block delivery or implying network consensus rejection.
- Receive-time section ID verification must occur before persistence/assembly and bind declared ID, section type, canonical bytes and correct dual-root rules.
- Cross-layer Mode 6/per-bootstrap suppression must cover announcements, receive, pending registration, persistence, request and apply.

## Header pipeline and fork choice

- Establish what `PreValidatedHeader` and checked-header capabilities prove; finalization may consume only evidence for the exact parsed bytes/header ID.
- PoW must be verified once for valid production paths while orphan retries preserve the checked proof and reject forged capability construction.
- Review parallel parse/PoW plus sequential finalization against the single-header path: verdict, ordering, parent lookup, persisted metadata and feedback must agree.
- Header batch order, siblings, duplicate IDs, unknown parents and retry promotion must not produce a missing child or nondeterministic best chain.
- Verify genesis/network checks, public-key curve checks, checkpoint enforcement, timestamps, version activation, difficulty epochs and cumulative score arithmetic.
- Difficulty/context caches must follow the candidate parent branch, not whichever header currently occupies a canonical height.
- Equal-work/tie policy must match pinned authority; enormous score/height/timestamp values must not overflow or distort comparisons.
- Retryable `ParentNotFound`/`EpochContextIncomplete` must retain bounded useful work without persisting acceptance or penalizing honest peers.
- Missing local rows, corrupt stored bytes and IO failures must remain distinguishable from a definitive invalid header.
- Permanent/session invalidity classification must follow current `HeaderMeta` semantics, including definitive full-block rule rejects and descendants.
- Marking an invalid branch must re-anchor best-header/index/cache state correctly; restart must not repeatedly choose the durably rejected best chain.

## Block validation and committed-state seams

- Assemble only the next canonical block extending the applied full tip, while keeping best-header and best-full identities separate.
- Validate section roots/IDs/header association, transaction order/version, extension rules and cumulative state under the exact applied parent.
- `CONTEXT.headers`, active protocol parameters, cumulative validation settings and voted epoch state must come from the correct branch and activation height.
- Epoch boundary recomputation must be byte/acceptance equivalent to validation, including early epochs, soft forks and Mode 2 first-epoch trust transitions.
- UTXO mode must regenerate AD proofs from parent state, check root hash and apply only checked transactions; downloaded proofs cannot silently become authoritative.
- Inspect the 114,688-block AD-proof insertion window relative to best header, exact boundary arithmetic and insertion-versus-eviction distinction.
- Digest mode must require and verify shipped proof, resolve inputs/data inputs correctly and enforce the same full transaction rules.
- Compare the assemble-action path and sequential drain path for identical failures, wallet wiring, failed-tx recording and coordinator outcomes.
- `TransactionValidation` must retain the actual failed transaction ID and reject reason; draining IDs must invalidate only appropriate local mempool entries.
- Distinguish missing sections from malformed stored sections, invalid consensus bytes, stale roots, parent mismatch and persist worker failure.
- Audit every `Err`/`None`/empty-actions return for suppressed storage failure; observable success, applied feedback and cache advancement require the promised state operation to succeed.
- Persistence poisoning must stop unsafe progress and reach node health/lifecycle policy; it cannot be transformed into retryable absence or a peer fault.
- Wallet hooks share the state's transactional apply/rollback contract; failures must not make block/chain caches disagree with committed storage.
- Apply-phase RAII gauges and perf counters must clear on every exit and identify attempts versus successes without affecting consensus.

## Reorg, retention and startup recovery

- Walk fork ancestry using IDs and retained applied-chain history; equal-height swaps must be recognized.
- Flush pending persistence before rollback where required and rebuild all relevant context/window caches after successful rollback.
- Check rollback horizon and prune sentinel before any partial rollback; a too-deep fork must become an honest wedge requiring recovery, not silent acceptance.
- Failed rollback/reapply must restore or re-anchor to committed state; failed recovery cannot permit later apply against guessed roots.
- Clear/reseed pending deliveries and assembly state correctly when old-branch requests arrive after a reorg.
- Mode 3 sentinel activation and receive/request/serve gates must agree at the exact boundary and across restart/bootstrap orderings.
- Hydrate from durable canonical/applied pointers, not uncommitted memory; verify header-index coverage before trusting cached height lookup.
- Missing/corrupt rows and score/index coverage gaps must fail with explicit startup errors; sparse NiPoPoW gaps must remain distinguishable from corruption.
- Recovered pending blocks must reconstruct expected sections and backend requirements without requesting pruned bodies or losing retained incomplete blocks.
- Review startup/reorg effects on protocol parameters, validation settings, orphan caches and failed-branch flags.

## Bootstrap and trust establishment

- NiPoPoW requests, peer proof ownership, retry/timeout and quorum must remain bounded and resist duplicate/Sybil vote amplification.
- Verify proofs through pinned consensus authority and apply only a verified winning proof; reducer terminal state requires successful backend installation.
- Snapshot discovery must count unique eligible peer votes, handle equivocation, select the documented highest qualifying height and rotate failed manifest owners.
- A quorum is discovery evidence, not cryptographic root authority; bind manifest label AND AVL height to the canonical header's full state root.
- `snapshot_install_anchor_check` must require a configured checkpoint to be materialized with its pinned ID when the snapshot is at/above it.
- A sparse/missing checkpoint row must refuse, while a below-checkpoint install must retain later header-level checkpoint enforcement.
- Re-fetch/re-verify after canonical-chain changes between selection, download, reconstruction and installation.
- Chunk assembly must enforce subtree IDs/shape/count/bytes, reject incompatible/duplicate/malformed chunks and correctly release timed-out ownership.
- Successive snapshot selections must discard old manifests/chunks safely without mixing different roots or stranding permits at the node seam.
- Mode 2/4 plus NiPoPoW ordering must have explicit safe transitions, restart resume and fail-closed install behavior.

## Required evidence and meaningful verification

Start with `cargo test --locked -p ergo-sync --lib` and `cargo test --locked -p ergo-sync --test it`; inspect dev-feature effects on state/P2P/validation.
Demand external header/section/epoch rejection vectors and single-versus-batched verdict/state comparisons.
Exercise duplicate/out-of-order action sequences, equal-height forks, valid-work rejected bodies, missing context and IO/persist failures separately.
Include Mode 5 genesis/replay/failed-transaction tests, UTXO regenerated-proof vectors, prune activation and bootstrap checkpoint/root-height negatives.
Inspect ignored boundary tests and `restart_benchmark` prerequisites; a missing captured corpus or populated DB is an explicit gap.
Run benchmarks only on an isolated copy of suitable state; startup code may backfill/write and is not guaranteed read-only.
Review node integration tests for actual action flushing, runtime mode gates, read-budget ownership and deferred snapshot installs.
Record reproducible cache/memory/request bounds and pipeline throughput under representative headers, bodies and adversarial peers.

## Crate-specific completion criteria

Provide event/action and error-classification matrices, mode/backend gate coverage, and a startup/reorg recovery map under COMMON.
List independent accept/reject/byte parity evidence and remaining Mode 2/4/5 or sparse-chain corpus gaps precisely.
Explain each failure's chain state, coordinator state, persistence status, peer attribution and next legal transition.
Do not certify reference readiness if a local fault can permanently invalidate a valid branch, suppress a necessary action, bypass bootstrap trust or advance caches past failed apply.
