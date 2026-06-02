# ergo-mempool

**Purpose:** Single-writer mempool for the Ergo node. Drives a 17-step
admission pipeline (parse → fee → structural/monetary/script via
`ergo-validation` → cost budget → insert) over a weight-ordered pool, with
anti-DoS cost budgets, invalidation/unresolved caches, a pool-aware UTXO
overlay, and reorg-driven demotion + revalidation. All consensus checks are
delegated to `ergo-validation`; this crate owns ordering, anti-DoS, and
relay/reorg policy, not transaction-acceptance rules.

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-validation, ergo-state
**Depended on by:** (see codemap index)
**Approx LOC:** ~5,250 (excl. tests; ~7,000 with tests)

## Start here
- `Mempool` (`src/lib.rs:325`) — the top-level handle that bundles every
  sub-component; its three driver methods `process` / `on_tip_change` /
  `tick_revalidation` are the whole public contract.
- `admission::check` + `admission::commit` (`src/admission.rs:397`, `:805`)
  — the heart of the crate: the decision-then-mutate split that the
  module doc calls the "no pool mutation until step 15" staging rule.
- `OrderedPool` (`src/pool.rs:141`) — weight-ordered pool plus the
  `by_input` / `by_output` / `children_of` indexes everything else reads.
- `types::MempoolConfig` + `types::MempoolAction` (`src/types.rs:216`, `:44`)
  — the config knobs and the action transcript the node event loop consumes.
- `Validator` trait (`src/admission.rs:131`) and its production impl
  `ErgoValidator` (`src/validator.rs:52`) — the seam between admission and
  `ergo-validation`.

## Modules
- `src/lib.rs` — the `Mempool` handle (fields + `new`/`process`/`check`/
  `on_tip_change`/`tick_revalidation`/`demote_all_for_revalidation`), the
  crate re-export surface, and all `tracing` event emission
  (`mempool_tx_admitted/_rejected/_evicted/_replaced`, tip-change and
  revalidation span events).
- `src/admission.rs` — the admission pipeline. `process` = `check` + `commit`.
  Holds `AdmissionCtx`/`TipContext` borrow bundles, the `Validator` trait,
  `Validated`/`PeekedTx`/`ValidationErr`, `AdmissionOutcome`/`CheckOutcome`/
  `RejectReason`, error→penalty `classify`, and `MockValidator` (test-support).
- `src/pool.rs` — `OrderedPool` and `Entry`. BTreeMap keyed by `WeightedKey`
  (weight DESC, tx_id ASC), reverse indexes, CPFP `children_of` graph,
  `remove_with_descendants`, `output_map`/`input_map` for overlays, and a
  monotonic `revision` counter the off-loop mining engine polls.
- `src/weight.rs` — `WeightFunction` trait + `ByCost` (default), `BySize`,
  `ByMin`; `SCALE = 1024`; `from_config` string parser.
- `src/budget.rs` — `CostBudgets`: global + per-peer cost caps with a
  pre-admission gate, post-charge verdict, per-block `reset`, and
  per-disconnect `forget_peer`.
- `src/invalidation.rs` — `InvalidationCache`: TTL + LRU of known-bad tx_ids
  with first-hit-vs-spam-window classification (`LookupResult`).
- `src/unresolved.rs` — `UnresolvedCache`: short-TTL cache keyed on raw-bytes
  hash for txs whose inputs don't resolve at tip (re-resolution suppressor).
- `src/overlay.rs` — `PoolUtxoOverlay` (committed UTXO + pool-created outputs,
  for regular inputs) and `CommittedOnly` (data-input resolution; never sees
  pool state).
- `src/reorg.rs` — free fns `on_tip_change` (confirm-remove → input-conflict
  evict → CPFP re-weight → demote-enqueue → budget reset) and
  `tick_revalidation` (drain queue back through `process`).
- `src/revalidation.rs` — `RevalidationQueue`: bounded FIFO of demoted tx
  bytes, capped at `max_depth`, drained per tick.
- `src/snapshot.rs` — `MempoolReadSnapshot`: owned, borrow-free clone of pool
  entries in priority order, for the mining-candidate generator.
- `src/types.rs` — shared types: `MempoolConfig`, `MempoolAction`,
  `ObservedEvent`, `TxSource`, `PenaltyKind`, `TipPointer`, `TxDiff`/
  `AppliedTx`/`DemotedTx`, `TxId`/`PeerId` aliases, and `From<ergo_state::diff>`
  bridges.

## Key types, traits & functions
- `Mempool` (struct) — top-level handle bundling pool/config/weight_fn/tip/
  budgets/caches/revalidation — `src/lib.rs:325`
- `Mempool::process` / `check` / `on_tip_change` / `tick_revalidation` (fns)
  — the four production drivers — `src/lib.rs:461`, `:521`, `:564`, `:607`
- `Mempool::revision` (fn) — monotonic pool-mutation counter the off-loop
  candidate engine polls for same-tip rebuilds — `src/lib.rs:379`
- `Mempool::pool_output_overlay` / `pool_input_overlay` (fns) — `BoxId→ErgoBox`
  and spent-`BoxId→TxId` maps for the `/utxo/withPool/*` + extra-index P5
  overlays — `src/lib.rs:407`, `:420`
- `Validator` (trait) — `peek_fee` (cheap id+fee) + `validate` (full) — `src/admission.rs:131`
- `ErgoValidator` (struct, impl `Validator`) — production adapter onto
  `ergo_validation::validate_transaction_parsed` — `src/validator.rs:52`
- `MAINNET_FEE_PROPOSITION_BYTES` (const) — canonical miner-fee ErgoTree;
  outputs matching it ARE the fee under ERG conservation — `src/validator.rs:38`
- `admission::check` (fn) — steps 0–14, decision-only, no pool mutation — `src/admission.rs:397`
- `admission::commit` (fn) — steps 15+17, applies the cleared candidate — `src/admission.rs:805`
- `AdmissionCtx` / `TipContext` (structs) — borrow bundles threaded through
  admission — `src/admission.rs:69`, `:39`
- `RejectReason` (enum) — full rejection taxonomy admission produces — `src/admission.rs:315`
- `OrderedPool` (struct) + `Entry` (struct) — the pool and its entry
  projection — `src/pool.rs:141`, `:22`
- `OrderedPool::remove_with_descendants` (fn) — bounded CPFP cascade eviction — `src/pool.rs:302`
- `WeightFunction` (trait), `ByCost`/`BySize`/`ByMin` (structs), `from_config`
  (fn) — `src/weight.rs:26`, `:36`/`:54`/`:73`, `:93`
- `CostBudgets` (struct) — anti-DoS cost accounting — `src/budget.rs:23`
- `InvalidationCache` / `UnresolvedCache` (structs) — `src/invalidation.rs:44`, `src/unresolved.rs:18`
- `RevalidationQueue` (struct) — `src/revalidation.rs:12`
- `PoolUtxoOverlay` / `CommittedOnly` (structs, impl `UtxoView`) — `src/overlay.rs:20`, `:49`
- `MempoolReadSnapshot` (struct) — borrow-free pool snapshot — `src/snapshot.rs:23`
- `reorg::on_tip_change` / `tick_revalidation` (fns) — `src/reorg.rs:40`, `:197`
- `MempoolConfig` (struct) + `Default` (defaults are production values) — `src/types.rs:216`, `:238`
- `MempoolAction` / `ObservedEvent` / `TxSource` (enums) — action transcript
  + observability + origin — `src/types.rs:44`, `:66`, `:21`
- `TxDiff` (struct) + `From<ergo_state::diff::TxDiff>` — the reorg input — `src/types.rs:149`, `:197`

## Invariants & contracts
- **Single writer.** Every pool mutation goes through `&mut OrderedPool`;
  production callers reach the pool only via `Mempool`'s method surface.
  Raw `pool()`/`pool_mut()` accessors are `#[cfg(test)]`/`test-support`-gated
  and `#[doc(hidden)]` so no production caller can bypass admission
  (`src/lib.rs:710`, `:725`).
- **Staged admission (no mutation before step 15).** `check` (steps 0–14) is
  decision-only and reads the pool; only `commit` (steps 15+17) inserts or
  evicts. This prevents a late capacity/budget reject from silently dropping
  valid pooled txs during double-spend resolution (`src/admission.rs:1`).
- **`check` and `process` agree.** Both produce the same `RejectReason` for
  the same input; `process` is `check` followed by `commit` on the
  `WouldAdmit` arm (`src/admission.rs:354`).
- **Anti-DoS state mutates even on `/check`.** `check` still charges cost
  budgets and populates the invalidation/unresolved caches, so `/check`
  cannot be a free oracle for unmetered script execution
  (`src/lib.rs:503`, `src/admission.rs:383`).
- **Index consistency.** `OrderedPool` keeps `ordered`/`by_tx_id`/`by_input`/
  `by_output`/`children_of`/`total_bytes` in lockstep on every insert/remove;
  `insert` is all-or-nothing on duplicate/output-collision; asserted by
  `check_invariants` (`src/pool.rs:237`, `:373`). At most one pool tx may
  spend any given box (`by_input` is `BoxId → TxId`).
- **Weight ordering is total and saturating.** `WeightedKey` sorts weight DESC
  then tx_id ASC (negated `i128` to survive `u64::MAX` negation); weight
  functions use `u128` intermediates and saturate to `u64::MAX`, never panic
  (`src/pool.rs:91`, `src/weight.rs`).
- **Double-spend replacement is weight-based, not raw RBF.** A conflicting
  candidate replaces the pooled conflict set only if its weight strictly
  exceeds the *average* weight of that set; otherwise it is the
  `DoubleSpendLoser` and is still charged cost (`src/admission.rs:698`).
- **Cost is charged on failure too.** Validation failures, double-spend
  losses, and `/check` all charge consumed cost to global + per-peer budgets;
  charges saturate (`src/admission.rs:576`, `src/budget.rs:66`).
- **Min-fee gate precedes script eval.** `peek_fee` (deserialize + sum
  fee-proposition outputs only) gates below-min-fee txs before any UTXO
  resolution or script execution, matching Scala `ErgoMemPool.process`
  ordering; `peek_fee` may only return `Deserialize` (`src/admission.rs:471`,
  `src/validator.rs:55`).
- **Data inputs never see pool state.** Regular inputs resolve through
  `PoolUtxoOverlay` (committed + pool-created); data inputs resolve through
  `CommittedOnly`, so a tx cannot observe an unconfirmed pool output via a
  data input (`src/overlay.rs`).
- **Overlay does not mask pool-spent committed boxes.** A committed box an
  existing pool tx already spends stays visible so a replacement candidate can
  resolve it; conflict detection is the separate `by_input` path
  (`src/overlay.rs:34`).
- **Reorg ordering is fixed.** `on_tip_change` snapshots confirmed-parent
  children before any index mutation, then: remove confirmed (no cascade) →
  evict input-conflicts (with CPFP cascade) → re-weight surviving descendants
  (lose CPFP boost) → enqueue demoted → reset budgets (`src/reorg.rs:1`).
- **Demoted txs never re-enter the pool directly.** Rolled-back txs go to the
  bounded `RevalidationQueue` and re-run full admission via
  `TxSource::DemotedFromBlock` on `tick_revalidation`; demoted source bypasses
  the IBD gate (`src/reorg.rs:197`, `src/admission.rs:407`,
  `src/revalidation.rs`).
- **Budgets reset every block.** `CostBudgets::reset` runs on every tip change
  and on `demote_all_for_revalidation` (`src/budget.rs:90`, `src/reorg.rs:188`,
  `src/lib.rs:699`).
- **Bounded family walks.** CPFP descendant eviction is capped at
  `cpfp_max_family_depth`; the revalidation queue is capped at
  `revalidation_max_depth` (oldest dropped on overflow rather than OOM)
  (`src/pool.rs:302`, `src/revalidation.rs:36`).
- **`peek_fee`/`validate` consistency.** For the same bytes both must return
  identical `(tx_id, fee)`; divergence is a validator bug, caught by
  `debug_assert` in `check` (`src/admission.rs:676`).
- **Fee-proposition drift guard.** `MAINNET_FEE_PROPOSITION_BYTES` is pinned
  against the Scala-derived fixture `test-vectors/mainnet/fee_proposition.hex`
  (`src/validator.rs:38`, drift test at `:285`).
