# `ergo-mempool` reference-node audit prompt

Audit `ergo-mempool` as the transaction policy, dependency ordering and anti-DoS layer of a reference-quality Ergo Rust node.
First read `docs/audit-prompts/COMMON.md` and apply its entire audit contract and report format.
Then read `CONTRIBUTING.md`, `docs/compatibility.md`, and `docs/codemap/ergo-mempool.md`.
This is a review-only audit unless the invoking user explicitly authorizes remediation.
Verify claims against current code; do not assume earlier audit status or pre-extraction codemap paths remain valid.
Independently inventory all files, inline/integration tests, features, includes, fixtures and diagnostic/extraction scripts.
Apply COMMON to production code, tests, mock helpers, comments, rustdoc, manifests and supporting materials.

## Mission and trust boundaries

Determine whether hostile, conflicting, chained and reorg-sensitive transactions receive correct admission outcomes without corrupting pool indexes or exceeding resource budgets.
Consensus checks belong to `ergo-validation`; this crate owns local relay/order/replacement/staging/revalidation policy.
Distinguish a local policy rejection, unresolved input, transient local read failure, and definitive transaction invalidity.
Treat API, wallet, peer and revalidation sources as distinct attribution/budget paths while requiring the same consensus context.
The pool is owned by one writer; audit callers to ensure that check/commit assumptions remain true.

## Current source landmarks

- `src/lib.rs`, `src/mempool.rs`: public contract, `Mempool`, observer and package/staging orchestration.
- `src/admission/{mod,context,outcome,revalidate,mock,tests}.rs`: decision/commit split, validator capability, error taxonomy and rechecks.
- `src/pool.rs`, `src/pool/tests.rs`: ordered keys, reverse indexes, family weights, collisions and bounded removal.
- `src/staging.rs`, `src/staging/tests.rs`: orphan/held entries, waiter/output indexes, caps, expiry and promotion facts.
- `src/{weight,budget,invalidation,unresolved}.rs`: scoring, accounting and TTL/LRU caches.
- `src/{overlay,reorg,revalidation,snapshot,types,telemetry}.rs`: box views, tip transitions, queues, snapshots and events.
- `src/validator.rs`, `src/validator/reemission_tests.rs`: production validation adapter, fee-tree identity and reemission context.
- `src/mempool/{invalidate_tests,recheck_tests,staging_tests}.rs`: mutation, policy and package regressions.
- `tests/it/main.rs`, lifecycle/observer/span tests, `m7_*` ordering, cost, corpus and Scala diagnostics.
- Caller seams `ergo-node/src/node/{admission,action_loop,tip_context}.rs`, `ergo-node/src/notifier.rs`, API submit/check and mining selection.

Use these as starting points and discover all remaining reachable/dead support files yourself.

## Admission and validation context

- Reconstruct admission stages from raw bytes through cheap parse/fee/structure gates, budget, full validation, policy checks and committed insertion.
- No rejected pre-commit candidate may accidentally remove incumbents or insert output/input indexes; identify deliberate budget/cache side effects separately.
- Cheap `peek_fee`/`peek_structure` and full `validate` must agree on canonical transaction ID, bytes, fee, input/output identities and data inputs.
- Fee recognition must use the canonical fee proposition and conservation semantics; no arbitrary output can spoof fees or overflow aggregation.
- Exact parse consumption, version/canonical encoding, size limits and malformed bytes must use the same interpretation as block validation.
- Pool-aware regular inputs may resolve committed or pool-created boxes; data inputs must remain committed-only where consensus requires it.
- A pool-created box already spent by another pool tx must be detected, including parent/child conflicts and repeated input IDs.
- `Validated` facts and checked transactions are context sensitive; reuse must prove identical applied tip/parameters/settings, not merely equal height.
- Header windows, epoch settings, network/reemission rules, activation heights and Mode 2 provisional settings must be supplied from the applied parent context.
- IBD/header-gap gating must be honest about local readiness and not blame peers for unavailable chain context.
- Validator absence/error paths must not convert corrupt state or IO failure into definitive invalidity or successful empty resolution.
- `Mempool::check` must honor its documented no-admission/no-relay semantics while enforcing deliberate anti-DoS accounting consistently.
- Error-to-penalty classification must distinguish spam, malformed/invalid consensus bytes, fee/policy limits, missing inputs and local faults.

## Ordered pool, conflicts and replacement

- Verify weight DESC/tx-ID ASC total ordering and identical deterministic ties across snapshots, APIs and mining consumers.
- Widened multiplication/division, zero size/cost, maximum fees, saturation and cumulative family arithmetic need explicit policy justification and boundary evidence.
- Every mutation must preserve `ordered`, ID/input/output indexes, parent/child edges, total bytes and revision.
- Insert collision checks must occur before partial mutation; test duplicate IDs, colliding outputs and a second spender introduced by package admission.
- Materialized output boxes must align exactly with derived output IDs; missing synthetic test boxes must not hide production overlay bugs.
- Enumerate same-input replacement conditions and full loser/descendant sets; a failed insert after eviction must not silently destroy previously valid entries.
- Compare family/CPFP weight propagation with pinned Scala policy, including diamonds, shared ancestors, fan-out and partial bounded walks.
- Depth/time bounds may have different semantics from a hard operation cap; prove incomplete propagation/removal preserves all structural invariants.
- Every descendant removal must revoke relay and clean every edge/index; unrelated siblings must survive.
- Capacity count/byte eviction must evaluate the entire victim set before applying it when later refusal is possible.
- Audit confirmation removal, conflict removal, targeted invalidation, suspect eviction, manual test mutation and demotion for coherent revision changes.
- A same-tip mining refresh must observe every actual relevant pool change without spurious unbounded rebuild triggers.

## Staging and package admission

- Distinguish Orphan facts (cheap structure only) from Held facts (fully validated but lost fee/capacity/conflict policy).
- Holding must never retain a definitively invalid transaction as though it has validated outputs/cost.
- Orphan arrival and held-parent/booster-child arrival must produce topological packages with no missing regular inputs or pool-only data inputs.
- Bound package ancestry, number of members, repeated reevaluations, promotions per event/tick, dependency depth and family update work.
- Detect cycles, duplicate members, multiple creators, intra-package double spends, diamond ancestry and dependency on removed/stale staging entries.
- Prove full package validation and eviction decisions precede committed pool mutation; rollback any partial commit failure without losing incumbents.
- A held member can reuse validation facts only under the exact recorded tip identity and matching rules; same-height reorgs must force revalidation.
- Charge all newly executed scripts, including promotions and repeated orphan retries, to `CostBudgets`; cached cost facts must not enable uncharged script work.
- Preserve reeval counts across removal/re-staging so retry limits cannot be reset by the normal promotion path.
- Caps must cover global/per-peer count and allocation bytes, waiters per missing input and all retained output boxes/metadata.
- Expiry uses wall-clock TTL and block horizon deliberately; tip rollback and zero-config limits must not cause underflow, panic or immortal staging.
- Prune staged regular AND data inputs consumed on-chain; confirmation/reorg transitions must not keep a package built on impossible boxes.
- Disconnect must release per-peer accounting and follow the documented retention/re-attribution policy for staged transactions.
- Waiter/output/FIFO indexes and bytes/peer counters must stay coherent after eviction, pruning, refusal, duplicate arrival and promotion.

## Budgets, caches and revalidation

- Trace pre-admission budget gating and post-validation cost charges for successful, rejected, unresolved, API, wallet, peer and revalidation attempts.
- Global/per-peer/local-source allowances must not bypass the intended CPU bound; define failure-cost charging when evaluation aborts early.
- Reset only at appropriate applied-block boundaries; equal-height reorgs and repeated notifier diffs must not create free validation loops.
- Disconnect/reconnect cleanup must bound peer-accounting memory and avoid turning cheap identity churn into unbounded global work.
- Invalidation keys based on canonical IDs must not let one malformed serialization poison a valid transaction with that ID.
- Unresolved raw-byte hashes, tip changes and parent arrivals must not suppress a transaction once its inputs become resolvable.
- TTL/LRU/spam-window boundary handling, capacity-zero behavior, clock inputs and eviction must be deterministic/testable.
- `TxDiff` transitions must remove confirmations, evict conflicts, adjust family weights, demote survivors and reset budgets in the intended order.
- Equal-height/different-ID tips, rollback/reapply, empty diffs, unavailable/pruned history and duplicate/stale diff delivery need distinct handling.
- Revalidation queue must be bounded, fair, deduplicated as promised and explicit about dropped entries.
- Epoch parameter or validation-setting changes must invalidate prior admission facts for active and staged entries before relay/mining reuse.
- Cleanup/recheck selection must rotate fairly within its cost ceiling; transient unresolved/state failures must not be cached as definitively invalid.
- `invalidate` and failed-block transaction propagation must remove the intended local family and emit correct revocation/observer events.

## Callers, observability and API/mining seams

- Submission result survives caller timeout/drop: accounting, insertion and observer events must describe the actual outcome once processing began.
- Admission and relay actions must not be lost or double-applied across API, peer, wallet and revalidation routes.
- Observer callbacks run inline under mutable ownership; inspect implementations for blocking, lock contention, panic and accidental reentrancy.
- Check-only/would-admit outcomes must not emit admitted events; confirmations, replacements and evictions must remain distinct and exactly attributed.
- Snapshots must be owned and coherent, and must not carry a reusable validation proof beyond its tip context.
- API with-pool overlays, fee stats and mining selection must interpret priorities, sizes, fees, outputs and revision consistently.
- This crate has no durable pool guarantee: verify node restart/reorg documentation does not promise retention the implementation lacks.
- State read/persist failure at tip-context/notifier seams cannot become a fake successful reconcile or silently stale validation context.

## Required evidence and meaningful verification

Start with `cargo test --locked -p ergo-mempool --lib` and `cargo test --locked -p ergo-mempool --test it`.
Compile diagnostics with `cargo test --locked -p ergo-mempool --features diagnostics --no-run`; identify `test-support` exposure independently.
With an isolated pinned Scala oracle, use `NODE_URL` and `cargo test --locked -p ergo-mempool --features diagnostics --test it m7_scala_oracle`; inspect whether diagnostics submit/mutate before running.
Do not copy stale instructions naming a nonexistent standalone `--test m7_scala_oracle` target.
Inspect ignored corpus/cost probes and absent retired vectors; list exact prerequisites and missing evidence.
Demand production-validator admission/rejection vectors, package arrival-order tests, same-height reorgs, activation/epoch transitions and atomic refusal tests.
Exercise all index invariants using generated operation sequences and adversarial wide/deep dependency graphs under small caps.
Use independent arithmetic/policy oracles for ordering/CPFP and capture intended Scala divergences explicitly.
Measure budget-bounded script work, staging retained allocations and cleanup latency; mock-validator success alone is insufficient consensus evidence.

## Crate-specific completion criteria

Report admission/rejection/side-effect taxonomy, pool/staging transition coverage and source-specific budget accounting under COMMON.
Provide evidence that each unsuccessful single/package commit preserves pool integrity and each real mutation produces coherent actions/revision.
List consensus parity and local policy parity separately, including documented bounded-walk/saturation differences.
Do not certify reference readiness if cached validation can survive the wrong tip, staged packages bypass cost charging, or rejected admission can corrupt incumbent state.
