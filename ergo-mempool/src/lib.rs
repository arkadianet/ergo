//! Ergo mempool: a Rust-native, single-writer, action-transcript mempool.
//!
//! Sits on top of [`ergo_primitives`], [`ergo_ser`], [`ergo_validation`],
//! and [`ergo_state`]. Provides the [`Mempool`] handle that bundles the
//! pool, anti-DoS budgets, invalidation / unresolved caches, and the
//! revalidation queue, plus the action transcript emitted to the
//! caller (P2P / RPC) on every state transition.
//!
//! Module map:
//!
//! * [`pool`] — `OrderedPool` ordered by `WeightFunction`, with
//!   per-input and per-output indexes for overlay / conflict checks.
//! * [`admission`] — admission pipeline: parse → structural →
//!   monetary → script → cost budget → insert. Drives [`Validator`]
//!   under the store's active protocol parameters.
//! * [`weight`] — weight functions that order the pool
//!   (`ByCost` / `ByMin` / `BySize`).
//! * [`budget`] — global + per-peer cost budgets with eviction.
//! * [`invalidation`] / [`unresolved`] — TTL'd caches: known-bad
//!   tx ids and unresolved-input tx bodies pending parents.
//! * [`overlay`] — `PoolUtxoOverlay` for `/utxo/withPool/*` reads.
//! * [`reorg`] — on-tip-change + revalidation tick handlers.
//! * [`revalidation`] — bounded-size queue of demoted-then-pending
//!   tx bodies driven by `tick_revalidation`.
//! * [`validator`] — `ErgoValidator` adapter that wires the pool's
//!   admission steps onto `ergo_validation::tx::validate_transaction`.
//! * [`types`] — shared types: `MempoolConfig`, `MempoolAction`,
//!   `TxId`, `TipPointer`, `TxDiff`, `TxSource`, etc.

pub mod admission;
pub mod budget;
pub mod invalidation;
pub mod overlay;
pub mod pool;
pub mod reorg;
pub mod revalidation;
pub mod snapshot;
pub mod types;
pub mod unresolved;
pub mod validator;
pub mod weight;

pub use admission::{
    AdmissionOutcome, CheckOutcome, RejectReason, Validated, ValidationErr, Validator,
};
#[cfg(any(test, feature = "test-support"))]
pub use admission::{MockPlan, MockValidator};
pub use budget::{BudgetVerdict, CostBudgets};
pub use invalidation::{InvalidationCache, InvalidationReason, LookupResult};
pub use overlay::{CommittedOnly, PoolUtxoOverlay};
pub use pool::{Entry, OrderedPool, PoolError};
pub use reorg::{on_tip_change, tick_revalidation};
pub use revalidation::RevalidationQueue;
pub use snapshot::MempoolReadSnapshot;
// `TxDiffError` is the state-crate type at its source location. The
// re-export keeps `ergo_mempool::TxDiffError` resolving to one shared
// definition, matching the spec at `tx_diff_since -> Result<TxDiff,
// TxDiffError>` while removing the in-tree duplicate.
pub use ergo_state::diff::TxDiffError;
pub use types::{
    AppliedTx, DemotedTx, EvictionReason, MempoolAction, MempoolConfig, ObservedEvent, PeerId,
    PenaltyKind, TipPointer, TxDiff, TxId, TxSource,
};
pub use unresolved::UnresolvedCache;
pub use validator::ErgoValidator;
pub use weight::{ByCost, ByMin, BySize, WeightFunction, WeightInputs, SCALE};

use tracing::{debug, info};

/// Tag string emitted in the `source` journal-event field.
///
/// Centralized here so a future taxonomy change (e.g. splitting `Api`
/// into `ApiSubmit`/`ApiCheck`) only edits one place.
fn source_tag(source: &TxSource) -> &'static str {
    match source {
        TxSource::Api => "api",
        TxSource::Peer(_) => "peer",
        TxSource::Wallet => "local",
        TxSource::DemotedFromBlock => "revalidation",
    }
}

/// Extract a `tx_id` from any `Dropped*` action so an outcome-driven
/// rejection event can attribute the rejection when admission walked
/// far enough to compute it.
///
/// Used by `emit_tracing_for_admission` for the `mempool_tx_rejected`
/// path. Pre-peek_fee rejections (IBD, budget, size cap) do not push
/// a `Dropped*` action — those events fire with an empty `tx_id`
/// field, which is honest about how far admission got.
fn extract_dropped_tx_id(actions: &[MempoolAction]) -> Option<TxId> {
    actions.iter().find_map(|a| match a {
        MempoolAction::Observe { event } => match event {
            ObservedEvent::DroppedBelowMinFee { tx_id, .. } => Some(*tx_id),
            ObservedEvent::DroppedDuplicate { tx_id } => Some(*tx_id),
            ObservedEvent::DroppedKnownInvalid { tx_id } => Some(*tx_id),
            ObservedEvent::DroppedUnresolvedInput { tx_id } => Some(*tx_id),
            ObservedEvent::DroppedDoubleSpendLoser { tx_id } => Some(*tx_id),
            ObservedEvent::DroppedPoolFull { tx_id } => Some(*tx_id),
            ObservedEvent::DroppedBudgetExhausted { tx_id, .. } => Some(*tx_id),
            ObservedEvent::Admitted { .. }
            | ObservedEvent::DroppedIbdGated
            | ObservedEvent::Evicted { .. }
            | ObservedEvent::Replaced { .. } => None,
        },
        _ => None,
    })
}

/// Emit per-action tracing for `Evicted` and `Replaced` events.
///
/// Skipped for empty-tx_ids `Evicted` (internal no-op churn) and for
/// `Dropped*` events (those are folded into the outcome-driven
/// `mempool_tx_rejected` event instead, so a single rejection
/// generates exactly one log line).
fn emit_tracing_for_pool_actions(actions: &[MempoolAction]) {
    for a in actions {
        if let MempoolAction::Observe { event } = a {
            match event {
                ObservedEvent::Evicted { tx_ids, reason } if !tx_ids.is_empty() => {
                    info!(
                        event = "mempool_tx_evicted",
                        count = tx_ids.len(),
                        reason = ?reason,
                        "mempool eviction",
                    );
                }
                ObservedEvent::Replaced {
                    loser_id,
                    winner_id,
                    weight_loser,
                    weight_winner,
                } => {
                    info!(
                        event = "mempool_tx_replaced",
                        loser_id = %hex::encode(loser_id.as_bytes()),
                        winner_id = %hex::encode(winner_id.as_bytes()),
                        weight_loser,
                        weight_winner,
                        "mempool tx replaced",
                    );
                }
                _ => {}
            }
        }
    }
}

/// Emit `mempool_tx_admitted` / `mempool_tx_rejected` for an admission
/// outcome plus the per-action `mempool_tx_evicted` / `_replaced`
/// fan-out.
///
/// Level selection per the Phase 2A guidance:
/// - `TxSource::Api`: admit/reject at `info!` (operator action).
/// - All other sources (`Peer`, `DemotedFromBlock`): `debug!` to keep
///   per-peer traffic out of the default operator stream.
fn emit_tracing_for_admission(
    outcome: &AdmissionOutcome,
    actions: &[MempoolAction],
    source: &TxSource,
    pool_size: usize,
    pool_bytes: usize,
) {
    let src = source_tag(source);
    // User-initiated sources (`Api`, `Wallet`) log at `info!`;
    // per-peer churn (`Peer`, `DemotedFromBlock`) drops to `debug!`
    // to keep the default operator stream readable on busy networks.
    let is_api = matches!(source, TxSource::Api | TxSource::Wallet);

    match outcome {
        AdmissionOutcome::Admitted { tx_id, fee, size } => {
            // `weight` is carried only in the corresponding Admitted
            // ObservedEvent action — pull it out for the journal event.
            let weight = actions.iter().find_map(|a| match a {
                MempoolAction::Observe {
                    event:
                        ObservedEvent::Admitted {
                            weight, tx_id: aid, ..
                        },
                } if aid == tx_id => Some(*weight),
                _ => None,
            });
            let tx_id_hex = hex::encode(tx_id.as_bytes());
            if is_api {
                info!(
                    event = "mempool_tx_admitted",
                    tx_id = %tx_id_hex,
                    source = src,
                    fee = *fee,
                    size = *size,
                    weight = weight.unwrap_or(0),
                    pool_size,
                    pool_bytes,
                    "mempool tx admitted",
                );
            } else {
                debug!(
                    event = "mempool_tx_admitted",
                    tx_id = %tx_id_hex,
                    source = src,
                    fee = *fee,
                    size = *size,
                    weight = weight.unwrap_or(0),
                    pool_size,
                    pool_bytes,
                    "mempool tx admitted",
                );
            }
        }
        AdmissionOutcome::Rejected { reason } => {
            let tx_id_hex = extract_dropped_tx_id(actions)
                .map(|id| hex::encode(id.as_bytes()))
                .unwrap_or_default();
            if is_api {
                info!(
                    event = "mempool_tx_rejected",
                    tx_id = %tx_id_hex,
                    source = src,
                    reason = ?reason,
                    pool_size,
                    "mempool tx rejected",
                );
            } else {
                debug!(
                    event = "mempool_tx_rejected",
                    tx_id = %tx_id_hex,
                    source = src,
                    reason = ?reason,
                    pool_size,
                    "mempool tx rejected",
                );
            }
        }
    }

    emit_tracing_for_pool_actions(actions);
}

/// Symmetric `Mempool::check`-side variant. `CheckOutcome` never
/// admits (it carries `WouldAdmit` instead), so the success branch
/// emits the same `mempool_tx_admitted` event with a `would_admit =
/// true` discriminator so dashboards can distinguish a successful
/// `/transactions/check` from a successful `/transactions` submit.
fn emit_tracing_for_check(
    outcome: &CheckOutcome,
    actions: &[MempoolAction],
    source: &TxSource,
    pool_size: usize,
    pool_bytes: usize,
) {
    let src = source_tag(source);
    // User-initiated sources (`Api`, `Wallet`) log at `info!`;
    // per-peer churn (`Peer`, `DemotedFromBlock`) drops to `debug!`
    // to keep the default operator stream readable on busy networks.
    let is_api = matches!(source, TxSource::Api | TxSource::Wallet);

    match outcome {
        CheckOutcome::WouldAdmit {
            validated, weight, ..
        } => {
            let tx_id_hex = hex::encode(validated.tx_id.as_bytes());
            if is_api {
                info!(
                    event = "mempool_tx_admitted",
                    tx_id = %tx_id_hex,
                    source = src,
                    would_admit = true,
                    fee = validated.fee,
                    size = validated.size_bytes,
                    weight = *weight,
                    pool_size,
                    pool_bytes,
                    "mempool tx admitted (check-only)",
                );
            } else {
                debug!(
                    event = "mempool_tx_admitted",
                    tx_id = %tx_id_hex,
                    source = src,
                    would_admit = true,
                    fee = validated.fee,
                    size = validated.size_bytes,
                    weight = *weight,
                    pool_size,
                    pool_bytes,
                    "mempool tx admitted (check-only)",
                );
            }
        }
        CheckOutcome::Rejected { reason } => {
            let tx_id_hex = extract_dropped_tx_id(actions)
                .map(|id| hex::encode(id.as_bytes()))
                .unwrap_or_default();
            if is_api {
                info!(
                    event = "mempool_tx_rejected",
                    tx_id = %tx_id_hex,
                    source = src,
                    reason = ?reason,
                    would_admit = false,
                    pool_size,
                    "mempool tx rejected",
                );
            } else {
                debug!(
                    event = "mempool_tx_rejected",
                    tx_id = %tx_id_hex,
                    source = src,
                    reason = ?reason,
                    would_admit = false,
                    pool_size,
                    "mempool tx rejected",
                );
            }
        }
    }

    emit_tracing_for_pool_actions(actions);
}

/// Top-level mempool handle. Bundles all the sub-components so callers
/// don't thread six pieces through every call site. Production wiring
/// holds one `Mempool` on `NodeState` and drives it via the three
/// methods below (`process`, `on_tip_change`, `tick_revalidation`).
pub struct Mempool {
    pool: OrderedPool,
    config: MempoolConfig,
    weight_fn: Box<dyn WeightFunction>,
    tip: Option<TipPointer>,
    budgets: CostBudgets,
    invalidation: InvalidationCache,
    unresolved: UnresolvedCache,
    revalidation: RevalidationQueue,
}

impl Mempool {
    pub fn new(config: MempoolConfig, weight_fn: Box<dyn WeightFunction>) -> Self {
        let budgets = CostBudgets::new(config.global_cost_budget, config.per_peer_cost_budget);
        let invalidation = InvalidationCache::new(
            config.invalidation_cache_size,
            std::time::Duration::from_secs(config.invalidation_ttl_seconds),
            std::time::Duration::from_secs(60),
        );
        let unresolved = UnresolvedCache::new(
            config.unresolved_cache_size,
            std::time::Duration::from_secs(config.unresolved_cache_ttl_seconds),
        );
        let revalidation = RevalidationQueue::new(config.revalidation_max_depth);
        Self {
            pool: OrderedPool::with_capacity(config.max_pool_size),
            config,
            weight_fn,
            tip: None,
            budgets,
            invalidation,
            unresolved,
            revalidation,
        }
    }

    pub fn size(&self) -> usize {
        self.pool.len()
    }

    /// Total bytes occupied by pooled tx payloads. Mirrors
    /// `OrderedPool::total_bytes` for read-only operator surfaces.
    pub fn total_bytes(&self) -> usize {
        self.pool.total_bytes()
    }

    /// Monotonic candidate-visible pool revision (bumped on every pool
    /// mutation — admission, eviction, reorg removal, revalidation re-admit,
    /// and CPFP family-weight credits/debits — which route through
    /// `OrderedPool::insert`/`remove`/`rekey_weight`). The off-loop candidate
    /// engine compares this against the revision its last build reflected to
    /// decide whether a same-tip rebuild is due. A family-weight credit
    /// reweights ancestors *during* an admission (same tip), but that
    /// admission already advances the revision and warrants a rebuild, so the
    /// extra per-ancestor bumps coalesce into that one pending rebuild rather
    /// than triggering a spurious extra one.
    pub fn revision(&self) -> u64 {
        self.pool.revision()
    }

    /// Pooled transactions in relay priority order. This is the
    /// production read-only surface for operator snapshots; callers must
    /// not reach through the doc-hidden test pool accessor.
    pub fn iter_transactions(&self) -> impl Iterator<Item = &Entry> {
        self.pool.iter_prioritized()
    }

    pub fn contains(&self, tx_id: &TxId) -> bool {
        self.pool.contains(tx_id)
    }

    /// Canonical tx bytes for a pooled tx, or `None` if absent. Used
    /// by P2P to respond to a peer's `RequestModifier` for one of our
    /// pool entries.
    pub fn get_bytes(&self, tx_id: &TxId) -> Option<std::sync::Arc<[u8]>> {
        self.pool.get(tx_id).map(|e| e.bytes.clone())
    }

    /// `BoxId → ErgoBox` map over all pool-created outputs, for the
    /// `/utxo/withPool/*` overlay surface. Pool entries that don't
    /// carry materialized output boxes (e.g. in unit tests that seed
    /// the pool directly) contribute nothing. O(N) over pool size;
    /// the publisher calls this once per `sync_tick` and stores the
    /// result in the snapshot.
    pub fn pool_output_overlay(
        &self,
    ) -> std::collections::HashMap<ergo_primitives::digest::Digest32, ergo_ser::ergo_box::ErgoBox>
    {
        self.pool.output_map()
    }

    /// Spent committed-box id → pool tx that spends it, for the
    /// extra-index P5 overlay (`excludeMempoolSpent` filter and
    /// `spending_tx_id` surfacing on byErgoTree/byErgoTreeHash routes).
    /// O(N) clone over the pool's `by_input` index; the publisher
    /// calls this once per `sync_tick` and stores the result in the
    /// snapshot.
    pub fn pool_input_overlay(
        &self,
    ) -> std::collections::HashMap<ergo_primitives::digest::Digest32, TxId> {
        self.pool.input_map()
    }

    /// Is `tx_id` known to be invalid? Checked before requesting a tx
    /// a peer advertised via Inv so we don't re-fetch bytes we
    /// already rejected.
    pub fn is_invalidated(&self, tx_id: &TxId) -> bool {
        self.invalidation.contains(tx_id)
    }

    pub fn tip(&self) -> Option<&TipPointer> {
        self.tip.as_ref()
    }

    pub fn config(&self) -> &MempoolConfig {
        &self.config
    }

    pub fn revalidation_pending(&self) -> usize {
        self.revalidation.len()
    }

    /// Admit a raw transaction. Returns `(outcome, actions)`.
    ///
    /// `tx_id` on the span is `Empty` until parsing succeeds; `admission::check`
    /// records it via `Span::current().record(...)` once `peek_fee` returns
    /// the canonical id. Pre-parse rejects (size cap, IBD gate, budget) thus
    /// have an empty tx_id field — by design, since no parsed id exists.
    #[tracing::instrument(
        name = "admit",
        level = "debug",
        skip_all,
        fields(
            source = ?source,
            bytes = tx_bytes.len(),
            tx_id = tracing::field::Empty,
        ),
    )]
    pub fn process<V: Validator>(
        &mut self,
        tx_bytes: &[u8],
        source: TxSource,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
    ) -> (AdmissionOutcome, Vec<MempoolAction>) {
        if !self.config.enabled {
            let outcome = AdmissionOutcome::Rejected {
                reason: RejectReason::Disabled,
            };
            emit_tracing_for_admission(
                &outcome,
                &[],
                &source,
                self.pool.len(),
                self.pool.total_bytes(),
            );
            return (outcome, Vec::new());
        }
        let mut cx = admission::AdmissionCtx {
            tip_ctx,
            config: &self.config,
            pool: &mut self.pool,
            budgets: &mut self.budgets,
            invalidated: &mut self.invalidation,
            unresolved: &mut self.unresolved,
            weight_fn: &*self.weight_fn,
        };
        let (outcome, actions) =
            admission::process(tx_bytes, source.clone(), now, &mut cx, validator);
        emit_tracing_for_admission(
            &outcome,
            &actions,
            &source,
            self.pool.len(),
            self.pool.total_bytes(),
        );
        (outcome, actions)
    }

    /// Run admission steps 0-14 on `tx_bytes` *without committing*.
    ///
    /// Drives REST `/transactions/check[Bytes]`: tells the caller
    /// whether the tx would be admitted as of now, but never inserts
    /// or evicts. Anti-DoS state (cost budgets, invalidation cache,
    /// unresolved cache) is still updated, otherwise `/check` becomes
    /// a free oracle for unmetered script execution. Returns the same
    /// `RejectReason` set as `process`.
    #[tracing::instrument(
        name = "admit_check",
        level = "debug",
        skip_all,
        fields(
            source = ?source,
            bytes = tx_bytes.len(),
            tx_id = tracing::field::Empty,
        ),
    )]
    pub fn check<V: Validator>(
        &mut self,
        tx_bytes: &[u8],
        source: TxSource,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
    ) -> (CheckOutcome, Vec<MempoolAction>) {
        if !self.config.enabled {
            let outcome = CheckOutcome::Rejected {
                reason: RejectReason::Disabled,
            };
            emit_tracing_for_check(
                &outcome,
                &[],
                &source,
                self.pool.len(),
                self.pool.total_bytes(),
            );
            return (outcome, Vec::new());
        }
        let mut cx = admission::AdmissionCtx {
            tip_ctx,
            config: &self.config,
            pool: &mut self.pool,
            budgets: &mut self.budgets,
            invalidated: &mut self.invalidation,
            unresolved: &mut self.unresolved,
            weight_fn: &*self.weight_fn,
        };
        let (outcome, actions) = admission::check(tx_bytes, &source, now, &mut cx, validator);
        emit_tracing_for_check(
            &outcome,
            &actions,
            &source,
            self.pool.len(),
            self.pool.total_bytes(),
        );
        (outcome, actions)
    }

    /// Apply a state-change diff. Advances `tip` and returns emitted
    /// actions.
    pub fn on_tip_change(&mut self, diff: &TxDiff) -> Vec<MempoolAction> {
        let prev_tip = self.tip;
        let t0 = std::time::Instant::now();
        let (new_tip, actions) = reorg::on_tip_change(
            diff,
            &self.config,
            &mut self.pool,
            &mut self.budgets,
            &mut self.revalidation,
        );
        self.tip = Some(new_tip);

        // Per-action evictions log first so dashboards show the cause
        // before the summary.
        emit_tracing_for_pool_actions(&actions);
        let evicted_count: usize = actions
            .iter()
            .filter_map(|a| match a {
                MempoolAction::Observe {
                    event: ObservedEvent::Evicted { tx_ids, .. },
                } => Some(tx_ids.len()),
                _ => None,
            })
            .sum();
        let prev_height = prev_tip.map(|t| t.height).unwrap_or(0);
        info!(
            event = "mempool_tip_change_processed",
            prev_height,
            new_height = new_tip.height,
            applied = diff.applied.len(),
            demoted = diff.demoted.len(),
            evicted_count,
            pool_size = self.pool.len(),
            pool_bytes = self.pool.total_bytes(),
            revalidation_pending = self.revalidation.len(),
            duration_ms = t0.elapsed().as_millis() as u64,
            "mempool tip change processed",
        );
        actions
    }

    /// Drain up to `revalidation_per_tick` demoted txs through admission.
    pub fn tick_revalidation<V: Validator>(
        &mut self,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
    ) -> Vec<MempoolAction> {
        let pending_before = self.revalidation.len();
        // Quiet fast path: empty queue means the call is a no-op (per
        // reorg::tick_revalidation's contract). Skip the start/complete
        // pair so a tick that does nothing produces zero log lines.
        if pending_before == 0 {
            return Vec::new();
        }

        let t0 = std::time::Instant::now();
        info!(
            event = "mempool_revalidation_started",
            pending_before, "mempool revalidation started",
        );

        let mut cx = admission::AdmissionCtx {
            tip_ctx,
            config: &self.config,
            pool: &mut self.pool,
            budgets: &mut self.budgets,
            invalidated: &mut self.invalidation,
            unresolved: &mut self.unresolved,
            weight_fn: &*self.weight_fn,
        };
        let actions = reorg::tick_revalidation(now, &mut cx, &mut self.revalidation, validator);

        // Per-action evictions (rare during revalidation but possible
        // if a demoted tx wins a double-spend conflict against an
        // already-pooled one).
        emit_tracing_for_pool_actions(&actions);

        // Counts derived from the action stream: each successful
        // re-admission emits exactly one `BroadcastInv`.
        let admitted_count = actions
            .iter()
            .filter(|a| matches!(a, MempoolAction::BroadcastInv { .. }))
            .count();
        let pending_after = self.revalidation.len();
        let drained = pending_before.saturating_sub(pending_after);
        let rejected_count = drained.saturating_sub(admitted_count);
        info!(
            event = "mempool_revalidation_completed",
            drained,
            admitted_count,
            rejected_count,
            pending_before,
            pending_after,
            duration_ms = t0.elapsed().as_millis() as u64,
            "mempool revalidation completed",
        );
        actions
    }

    /// Peer disconnected — drop per-peer budget bookkeeping.
    pub fn on_peer_disconnected(&mut self, peer: &PeerId) {
        self.budgets.forget_peer(peer);
    }

    /// Demote every active tx into the revalidation queue. Used after
    /// a voted-params change at an epoch boundary (or post-reorg)
    /// invalidates prior admission decisions: txs admitted under the
    /// old `(active_params, validation_settings)` may no longer fit
    /// the new limits.
    ///
    /// Drains the active pool, clears cost budgets, and enqueues every
    /// tx with its preserved bytes so the next `tick_revalidation`
    /// re-runs admission against current params. Returns the number of
    /// oldest revalidation entries dropped (pathological case where
    /// the queue can't hold the entire pool).
    pub fn demote_all_for_revalidation(&mut self) -> usize {
        let demoted: Vec<DemotedTx> = self
            .pool
            .iter_prioritized()
            .map(|e| DemotedTx {
                tx_id: e.tx_id,
                bytes: e.bytes.clone(),
            })
            .collect();
        if demoted.is_empty() {
            return 0;
        }
        // Drain the pool. Collect ids first to avoid borrow issues.
        let ids: Vec<TxId> = demoted.iter().map(|d| d.tx_id).collect();
        for id in &ids {
            self.pool.remove(id);
        }
        // Reset cost budgets (mirrors reorg::on_tip_change line 188).
        self.budgets.reset();
        // Enqueue for re-admission.
        self.revalidation.push_batch(demoted)
    }

    /// Test-only: access the underlying pool for invariant checks.
    /// `#[doc(hidden)]` hides the symbol from rustdoc; the cfg-gate
    /// removes it from the production crate surface entirely so a
    /// future production caller can't accidentally bypass the
    /// method-level invariants (single-writer admission, anti-DoS
    /// budgeting) by reading raw pool state.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn pool(&self) -> &OrderedPool {
        &self.pool
    }

    /// Test-only: mutable pool access. Production code writes through
    /// the method surface above; this is for unit tests that seed
    /// state before exercising a specific transition. The cfg-gate
    /// matches the existing `MockValidator` pattern and forces
    /// non-test callers (e.g., future embedders or `ergo-node`
    /// imports) to either run with `cargo test` or opt into the
    /// `test-support` feature explicitly in `[dev-dependencies]` —
    /// closing the "any caller can skip the 17-step admission
    /// pipeline" hole.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn pool_mut(&mut self) -> &mut OrderedPool {
        &mut self.pool
    }

    pub fn weight_fn(&self) -> &dyn WeightFunction {
        &*self.weight_fn
    }
}
