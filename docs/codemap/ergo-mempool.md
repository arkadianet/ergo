# ergo-mempool

**Purpose:** Single-writer admission, weighted ordering, cost budgets, short-lived
staging, and reorg maintenance. Consensus validation is delegated to
`ergo-validation`; ordering, relay policy, and resource limits belong here.

**Workspace dependencies:** ergo-primitives, ergo-ser, ergo-validation, ergo-state.

## Start here

- `src/mempool.rs`: `Mempool`, its production drivers `process`, `check`,
  `on_tip_change`, `tick_revalidation`, `recheck_and_evict`, `recheck_ids`, and
  `invalidate`, plus read projections, peer cleanup, and epoch demotion.
- `src/admission/mod.rs`: the single-transaction decision and commit paths.
- `src/pool.rs`: `OrderedPool`, `Entry`, reverse indexes, family weights, and
  the retained frontier for bounded descendant eviction.
- `src/validator.rs`: `ErgoValidator`, the production validation adapter and
  miner-fee proposition matching.

## Modules

- `src/lib.rs` defines crate exports and `MempoolObserver`; the handle itself
  lives in `src/mempool.rs`. `src/telemetry.rs` emits journal events and callbacks.
- `src/admission/context.rs` defines `AdmissionCtx`, `TipContext`, `Validator`,
  `Validated`, and validation errors. `outcome.rs` defines admission/check
  outcomes, rejection reasons, and error classification; `revalidate.rs` shares
  pooled validation and cache/eviction classification. `mock.rs` is test support.
- `src/pool.rs` orders entries by weight descending, then transaction ID
  ascending. It maintains input/output and parent/child indexes, family credit
  and debit, transactional clones, and a candidate-visible revision counter.
- `src/weight.rs` contains `ByCost`, `BySize`, `ByMin`, `SCALE = 1024`, and
  `from_config`. Arithmetic widens and saturates instead of wrapping.
- `src/budget.rs` manages the shared remote budget, per-peer budget, and local
  reserve. Peer and public API traffic use the remote budget; wallet/operator
  traffic can use the reserve. Rollback-demoted transactions are exempt.
- `src/invalidation.rs` filters repeated inventory fetches by transaction ID.
  `src/unresolved.rs` briefly suppresses repeated unresolved raw bytes by hash.
  Both caches use insertion-order eviction and TTL; refresh owns one bounded
  node, lookups do not refresh order, and capacity zero disables retention.
- `src/overlay.rs` provides regular-input resolution from committed and pooled
  outputs. `CommittedOnly` restricts data-input resolution to committed boxes.
- `src/staging.rs` retains orphan structure and fully validated held facts under
  count/byte/per-peer/TTL/block limits. Holding emits no gossip. Promotion and
  package admission run through `src/mempool.rs`.
- `src/reorg.rs` removes confirmed transactions, evicts conflicting families,
  detaches confirmed parents, enqueues rollback-demoted bytes, and resets budgets.
  `src/revalidation.rs` owns the bounded demotion queue.
- `src/snapshot.rs` provides owned read snapshots. `src/types.rs` defines config,
  actions, events, sources, tip pointers, and state-diff bridges.

## Contracts

- The production node mutates one `Mempool` through its method surface.
  `pool()`/`pool_mut()` are gated by tests or `test-support`; the standalone
  public `OrderedPool` API still requires callers to maintain entry preconditions.
- Single-transaction `check` changes budgets/caches but does not mutate pool
  membership. `process` may additionally admit a package from held ancestors,
  so a single-transaction unresolved verdict can become a committed admission.
  Package success returns the child's admission and traces each member's source.
- Validation work is charged before later duplicate/conflict/capacity decisions.
  Each fresh package evaluation passes its original source budget first; temporary
  budget refusal preserves held ancestors. Demoted-source exemption is explicit.
- Replacement uses weight rather than only absolute fee. Package replacement
  additionally compares aggregate fee and weight against its measured conflict
  closure. Evicting admission changes are staged and adopted only on success.
- Confirming a parent keeps its children. Evicting a parent removes descendants
  under a node cap, retaining unfinished work in the committed pool. Maintenance
  ticks continue the frontier under the cleanup budget even between blocks;
  dependency cleanup revokes relay without blacklisting each descendant.
- Recheck failures are contextual. Hard rule failures and unresolved data inputs
  evict; transient unresolved spending inputs and internal `Other` errors do not.
  The invalidation cache filters inventory requests, while received bytes still
  undergo validation. A later tip or corrected proof can change the verdict.
- Regular-input overlays leave committed boxes visible for replacement checks;
  input-conflict detection is separate. Data inputs never see pooled outputs.
- Epoch demotion and rollback enqueue raw transactions for bounded re-admission;
  they do not insert unvalidated transactions directly. Node maintenance is
  gated on the applied and best-header tips being synchronized.

## Verification entry points

`cargo test --locked -p ergo-mempool` runs hermetic unit/integration coverage.
`src/mempool/{staging_tests,recheck_tests,invalidate_tests}.rs` covers package
outcomes, source budgets, recheck policy, and bounded cleanup. `tests/it` covers
lifecycle, observers, admission spans, retained ordering captures, and cost checks.

The live Scala diagnostic is explicitly ignored and needs a configured node:
`cargo test --locked -p ergo-mempool --features diagnostics --test it scala_pending_tx_oracle -- --ignored --nocapture`.
It requires real admissions and at least five common ordering entries; excluded
or unresolved input alone cannot establish a passing comparison. Hermetic
`oracle_coverage_rejects_all_excluded_and_empty_admission_results` checks this gate.

The historical corpus test is also ignored and its large inputs are absent from
git. Follow `test-vectors/mainnet/FIXTURES.md` before explicitly running
`cargo test --locked -p ergo-mempool --test it mempool_admits_mainnet_corpus_1761k -- --ignored`.
Compilation or skipped execution does not establish fresh Scala or corpus parity.
