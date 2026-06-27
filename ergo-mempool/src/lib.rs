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

    /// Proactive tip-revalidation (recheck-and-evict). Re-validates pooled txs
    /// against the new tip and EVICTS those no longer valid — the Scala
    /// `MempoolAuditor`/`CleanupWorker` end-result, reached via a superior
    /// full-pass Rust path (no 30s throttle). It re-uses the node's OWN
    /// admission validation (`admission::revalidate_pooled`) so the pool stays
    /// consistent with admission (no admit-then-evict flapping).
    ///
    /// Bounding: a full pass by default, bounded only by an anti-DoS per-pass
    /// COST BUDGET (`mempool_cleanup_cost_mult × LIVE params.max_block_cost`).
    /// The budget is checked BEFORE each tx and the actual consumed cost is
    /// charged after — on BOTH the pass and fail paths — so an all-expensive
    /// pool cannot over-run it. It is a soft budget: the tx in flight when the
    /// budget is reached still completes, so a single pass can exceed the budget
    /// by at most one in-flight tx's consumed validation cost (one tx's
    /// accounting, ≈ `max_tx_cost`; a cost-exceeded tx is charged its
    /// post-limit consumed figure, which can edge slightly past the per-tx cap).
    /// Remaining txs are deferred to later blocks, oldest `last_checked_at` first
    /// (tie-break `tx_id`), so the tail is covered within a bounded number of
    /// passes and cannot starve.
    ///
    /// Eviction policy: a tx is evicted ONLY when it is PROVABLY invalid at the
    /// new tip — a hard consensus failure (script/monetary/structural/cost),
    /// per `admission::is_hard_invalid`. A non-resolution failure
    /// (`UnresolvedInput`/`UnresolvedDataInput`) or a parse-class failure does
    /// NOT evict: an unresolved input can be a transient reorg-dependency (a
    /// demoted parent pending re-admission via the future revalidation-queue
    /// drain, §7), and a genuine confirmed double-spend is already evicted by
    /// `on_tip_change`'s input-conflict cascade — so such txs are left in place
    /// (rotation clock advanced) rather than dropped to the unresolved-bytes
    /// cache (a suppression filter, not a re-admit queue). Eviction goes through
    /// the family-weight debiting wrapper (PR #139) and routes the FAILED ROOT
    /// id through the shared `admission::record_failed_tx` classifier (here
    /// always the blacklist arm, since only hard-invalid failures reach it), so
    /// it stops being relayed. Cascade descendants are dependency-evicted only
    /// (never cached): a descendant beyond the `max_family_depth` cascade bound
    /// is left in the pool and caught on a later pass.
    ///
    /// `now` is injected and stamps all per-tx bookkeeping (the rotation clock),
    /// so the pass is deterministic and unit-testable; the only wall-clock read
    /// is a single monotonic `Instant::now()` for the completion-log
    /// `duration_ms` metric (as in `tick_revalidation`), which feeds no
    /// bookkeeping or control flow. Returns the emitted `RevokeBroadcast`/
    /// `Evicted` actions for the caller to route.
    pub fn recheck_and_evict<V: Validator>(
        &mut self,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
    ) -> Vec<MempoolAction> {
        let mut actions: Vec<MempoolAction> = Vec::new();
        if self.pool.is_empty() {
            return actions;
        }

        // Snapshot config-derived bounds before the mutating loop.
        let max_tx_cost = self.config.max_tx_cost;
        let max_family_depth = self.config.max_family_depth;

        // Misconfiguration guard: if `max_tx_cost` is set above the JitCost
        // bound the per-tx cap cannot be built, so EVERY revalidation would
        // return `CostExceeded` with zero consumed cost — the budget would
        // never trip and the WHOLE pool would be evicted + blacklisted. Refuse
        // to run rather than mass-evict on a bad config; admission already
        // surfaces the same misconfig per-tx.
        if ergo_primitives::cost::JitCost::from_block_cost(max_tx_cost).is_err() {
            debug!(
                max_tx_cost,
                "mempool recheck skipped: max_tx_cost exceeds the JitCost bound (misconfig)",
            );
            return actions;
        }
        let t0 = std::time::Instant::now();

        let bounds = crate::pool::FamilyBounds::new(
            self.config.max_family_depth,
            self.config.max_family_ops,
            self.config.max_family_update_ms,
        );
        // Anti-DoS per-pass budget = mult × LIVE max_block_cost (epoch-votable).
        let cost_cap: u128 = u128::from(self.config.mempool_cleanup_cost_mult)
            .saturating_mul(u128::from(tip_ctx.params.max_block_cost));

        // Build the pool-output overlay map ONCE (output_map is O(pool)); prune
        // it as evictions remove entries so it stays consistent within the pass.
        let mut pool_outputs = self.pool.output_map();

        // Visit oldest-checked first (tie-break tx id) so the per-pass cap
        // rotates coverage across blocks without starving the tail.
        let mut ids: Vec<(std::time::Instant, TxId)> = self
            .pool
            .iter_prioritized()
            .map(|e| (e.last_checked_at, e.tx_id))
            .collect();
        ids.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.as_bytes().cmp(b.1.as_bytes()))
        });

        let mut cost_acc: u128 = 0;
        let mut rechecked: usize = 0;
        let mut removed_for_actions: Vec<TxId> = Vec::new();

        for (_, id) in ids {
            if cost_acc >= cost_cap {
                break; // per-pass budget spent; remainder deferred to next block
            }
            let Some(bytes) = self.pool.get(&id).map(|e| e.bytes.clone()) else {
                continue; // already cascade-evicted earlier this pass
            };
            rechecked += 1;
            let (consumed, verdict) = admission::revalidate_pooled(
                &bytes,
                tip_ctx,
                &pool_outputs,
                max_tx_cost,
                validator,
            );
            // Charge actual consumed cost on BOTH pass and fail so an expensive
            // failing pool cannot over-run the cap.
            cost_acc = cost_acc.saturating_add(u128::from(consumed));
            match verdict {
                Ok(()) => {
                    // Still valid: keep it, refresh only the rotation clock.
                    // Deliberately NOT the cost/weight — re-pricing on a
                    // validity check would desync `Entry.cost` from the
                    // `ByCost` weight key (and feed stale weights to later #139
                    // debits). Priority is owned by admission.
                    self.pool.touch_rechecked(&id, now);
                }
                Err(ref err) if !admission::is_hard_invalid(err) => {
                    // Not PROVABLY invalid — a non-resolution failure
                    // (UnresolvedInput/DataInput) or a parse-class failure.
                    // Do NOT evict: an unresolved input can be a transient
                    // reorg-dependency (a demoted parent pending re-admission
                    // via the future revalidation-queue drain), and evicting it
                    // to the unresolved-bytes cache — a suppression filter, not
                    // a re-admit queue — would DROP a valid tx before its parent
                    // returns. A genuine confirmed double-spend is already
                    // evicted by `on_tip_change`'s input-conflict cascade. Leave
                    // the tx in place; only advance its rotation clock so the
                    // pass moves on. (Residual: a genuinely-orphaned tx lingers
                    // until its input is confirmed-spent or it is re-admitted —
                    // closed by the §7 queue-drain PR, which re-admits demoted
                    // parents before the recheck so the remainder can be safely
                    // evicted.)
                    self.pool.touch_rechecked(&id, now);
                }
                Err(err) => {
                    // Provably invalid at the new tip (script/monetary/
                    // structural/cost): evict it + its now-orphaned descendants
                    // (debiting ancestors per #139), and prune the pass overlay
                    // so a later tx can't resolve a gone output.
                    let removed =
                        self.pool
                            .remove_with_descendants_debiting(&id, max_family_depth, bounds);
                    for e in &removed {
                        for out in &e.outputs {
                            pool_outputs.remove(out);
                        }
                    }
                    // Route ONLY the failed root id through admission's shared
                    // classifier (here always the blacklist arm, since we only
                    // reach this branch for hard-invalid failures). Cascade
                    // descendants are dependency-evicted, never cached — they
                    // re-admit if later valid. Matches Scala's per-failed-id
                    // invalidate.
                    admission::record_failed_tx(
                        &mut self.invalidation,
                        &mut self.unresolved,
                        id,
                        &bytes,
                        &err,
                        now,
                    );
                    for e in removed {
                        removed_for_actions.push(e.tx_id);
                    }
                }
            }
        }

        let evicted = removed_for_actions.len();
        if !removed_for_actions.is_empty() {
            actions.push(MempoolAction::RevokeBroadcast {
                tx_ids: removed_for_actions.clone(),
            });
            actions.push(MempoolAction::Observe {
                event: ObservedEvent::Evicted {
                    tx_ids: removed_for_actions,
                    reason: EvictionReason::TipInvalid,
                },
            });
        }
        emit_tracing_for_pool_actions(&actions);
        info!(
            event = "mempool_recheck_completed",
            rechecked,
            evicted,
            pool_size = self.pool.len(),
            duration_ms = t0.elapsed().as_millis() as u64,
            "mempool tip recheck completed",
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

#[cfg(test)]
mod recheck_tests {
    //! Unit tests for `Mempool::recheck_and_evict` (proactive tip-revalidation).
    //!
    //! These pin the Scala `CleanupWorker`/`MempoolAuditor` *end-result*
    //! (the pool ends each block holding only currently-valid txs; invalid
    //! ones are evicted and stop being relayed), reached via the Rust full
    //! pass — a policy surface, so expected behavior is derived from the
    //! recheck semantics, not from mainnet bytes.

    use super::*;
    use crate::admission::{MockPlan, MockValidator, PeekedTx, Validated};
    use crate::pool::Entry;
    use ergo_primitives::cost::JitCost;
    use ergo_primitives::digest::{Digest32, ModifierId};
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::read_ergo_tree;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_validation::{ProtocolParams, TransactionContext, TxValidationCtx, UtxoView};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    // ----- helpers -----

    /// Committed UTXO view backed by an explicit box map (empty by default).
    struct FakeUtxo {
        boxes: HashMap<Digest32, ErgoBox>,
    }
    impl FakeUtxo {
        fn empty() -> Self {
            Self {
                boxes: HashMap::new(),
            }
        }
        fn with_box(mut self, id: Digest32, b: ErgoBox) -> Self {
            self.boxes.insert(id, b);
            self
        }
    }
    impl UtxoView for FakeUtxo {
        fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
            self.boxes.get(box_id).cloned()
        }
    }

    fn d(b: u8) -> Digest32 {
        Digest32::from_bytes([b; 32])
    }

    /// Canonical bytes for the seeded tx `b`. A `MockValidator` plan keyed
    /// on this exact slice matches the entry during the recheck.
    fn tx_bytes(b: u8) -> Vec<u8> {
        vec![b; 20]
    }

    /// Minimal ErgoBox (contents immaterial — only identity matters here).
    fn dummy_box(id_byte: u8) -> ErgoBox {
        let tree_bytes = vec![0x00u8, 0x01, 0x01];
        let mut r = VlqReader::new(&tree_bytes);
        let tree = read_ergo_tree(&mut r).expect("parse tree");
        let candidate =
            ErgoBoxCandidate::new(1_000_000, tree, 0, vec![], AdditionalRegisters::empty())
                .expect("candidate");
        ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes([id_byte; 32]),
            index: 0,
        }
    }

    fn dummy_tx_context(height: u32) -> TransactionContext {
        TransactionContext {
            height,
            miner_pubkey: [0u8; 33],
            pre_header_timestamp: 0,
            activated_script_version: 2,
            pre_header_version: 3,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        }
    }

    /// Owns the tip-context backing storage so a borrowed `TipContext` can
    /// be re-derived per call (mirrors the node's `OwnedTipContext`).
    struct TestTip {
        tx_context: TransactionContext,
        params: ProtocolParams,
    }
    impl TestTip {
        fn new() -> Self {
            Self::at_height(1000)
        }
        /// Tip context whose validation height (tip+1) is `height` — lets a
        /// test model a height-dependent tx going stale as the tip advances.
        fn at_height(height: u32) -> Self {
            Self {
                tx_context: dummy_tx_context(height),
                params: ProtocolParams::mainnet_default(),
            }
        }
        /// Override the per-pass cap denominator (`mult × max_block_cost`).
        fn with_max_block_cost(mut self, c: u64) -> Self {
            self.params.max_block_cost = c;
            self
        }
        fn view<'a>(&'a self, utxo: &'a dyn UtxoView) -> admission::TipContext<'a> {
            admission::TipContext {
                tip: TipPointer {
                    height: 1000,
                    header_id: d(0xFF),
                },
                best_header_height: 1000,
                best_full_block_height: 1000,
                utxo,
                tx_context: &self.tx_context,
                params: &self.params,
                last_headers: &[],
                reemission: None,
            }
        }
    }

    fn mempool_with(cfg: MempoolConfig) -> Mempool {
        Mempool::new(cfg, Box::new(ByCost))
    }

    /// Seed a standalone pool entry whose canonical bytes are `tx_bytes(b)`.
    fn seed(mp: &mut Mempool, b: u8, input: u8, output: u8, weight: u64, parents: Vec<TxId>) {
        let entry = Entry::new(
            d(b),
            Arc::from(tx_bytes(b).into_boxed_slice()),
            vec![d(input)],
            vec![d(output)],
            parents,
            1_000_000,
            weight,
            20,
            50_000,
            TxSource::Api,
        );
        mp.pool_mut().insert(entry).unwrap();
    }

    /// Force a deterministic `last_checked_at` on a seeded entry so the
    /// oldest-first visit order is reproducible (the real method injects
    /// `now`; tests inject the seed instants).
    fn set_checked(mp: &mut Mempool, b: u8, at: Instant) {
        mp.pool_mut().touch_rechecked(&d(b), at);
    }

    fn ok_plan(b: u8, charge: u64) -> (Vec<u8>, MockPlan) {
        (
            tx_bytes(b),
            MockPlan {
                result: Ok(Validated {
                    tx_id: d(b),
                    input_box_ids: vec![],
                    output_box_ids: vec![],
                    outputs: vec![],
                    fee: 1_000_000,
                    size_bytes: 20,
                    consumed_cost: charge,
                }),
                charge,
                peek_fee: None,
                peek_tx_id: None,
            },
        )
    }

    fn err_plan(b: u8, charge: u64) -> (Vec<u8>, MockPlan) {
        (
            tx_bytes(b),
            MockPlan {
                result: Err(ValidationErr::ScriptFailed),
                charge,
                peek_fee: None,
                peek_tx_id: None,
            },
        )
    }

    fn validator(plans: Vec<(Vec<u8>, MockPlan)>) -> MockValidator {
        let mut v = MockValidator::new();
        for (bytes, plan) in plans {
            v = v.plan(bytes, plan);
        }
        v
    }

    fn evicted_ids(actions: &[MempoolAction]) -> Vec<TxId> {
        actions
            .iter()
            .find_map(|a| match a {
                MempoolAction::Observe {
                    event:
                        ObservedEvent::Evicted {
                            tx_ids,
                            reason: EvictionReason::TipInvalid,
                        },
                } => Some(tx_ids.clone()),
                _ => None,
            })
            .unwrap_or_default()
    }

    // ----- happy path: still-valid txs are kept -----

    #[test]
    fn recheck_keeps_still_valid_tx_and_refreshes_last_checked() {
        let mut mp = mempool_with(MempoolConfig::default());
        seed(&mut mp, 1, 0x10, 0x11, 100, vec![]); // seeded cost=50_000, weight=100
        let base = Instant::now();
        set_checked(&mut mp, 1, base);

        let utxo = FakeUtxo::empty();
        let tip = TestTip::new();
        // Deliberately charge a DIFFERENT cost than the seeded 50_000 to prove
        // the recheck does not re-price the surviving entry.
        let v = validator(vec![ok_plan(1, 77_000)]);

        let now = base + Duration::from_secs(10);
        let actions = mp.recheck_and_evict(now, &tip.view(&utxo), &v);

        assert!(mp.contains(&d(1)), "valid tx must survive the recheck");
        assert!(
            actions.is_empty(),
            "no eviction actions for an all-valid pool"
        );
        assert!(
            !mp.is_invalidated(&d(1)),
            "valid tx must not be blacklisted"
        );
        let e = mp.pool().get(&d(1)).unwrap();
        assert_eq!(
            e.last_checked_at, now,
            "surviving tx has its last_checked_at refreshed to the pass clock"
        );
        assert_eq!(
            e.cost, 50_000,
            "recheck must NOT re-price cost (would desync the ByCost weight key)"
        );
        assert_eq!(
            e.weight, 100,
            "priority weight unchanged by a validity check"
        );
        mp.pool().check_invariants();
    }

    #[test]
    fn recheck_small_pool_full_pass_visits_every_tx() {
        // A pool well under the cost cap is rechecked completely in one pass.
        let mut mp = mempool_with(MempoolConfig::default());
        for b in 1..=4u8 {
            seed(&mut mp, b, 0x10 + b, 0x40 + b, 100, vec![]);
        }
        let utxo = FakeUtxo::empty();
        let tip = TestTip::new();
        let v = validator((1..=4u8).map(|b| ok_plan(b, 10_000)).collect());

        let actions = mp.recheck_and_evict(Instant::now(), &tip.view(&utxo), &v);

        assert_eq!(v.validate_call_count(), 4, "every tx visited in one pass");
        assert_eq!(mp.size(), 4, "all valid txs retained");
        assert!(actions.is_empty());
        mp.pool().check_invariants();
    }

    #[test]
    fn recheck_empty_pool_is_noop() {
        let mut mp = mempool_with(MempoolConfig::default());
        let utxo = FakeUtxo::empty();
        let tip = TestTip::new();
        let v = validator(vec![]);
        let actions = mp.recheck_and_evict(Instant::now(), &tip.view(&utxo), &v);
        assert!(actions.is_empty());
        assert_eq!(v.validate_call_count(), 0, "no validation on an empty pool");
    }

    // ----- error paths: tip-invalid txs are evicted -----

    #[test]
    fn recheck_evicts_stale_rent_recreate_claim_and_blacklists() {
        // A storage-rent recreate claim is valid ONLY at the block whose height
        // equals the box's creation height (creationHeight == currentHeight).
        // Model that height-dependence directly with a validator that passes
        // only when the validating height matches: the claim was valid at
        // H=999, but the tip has advanced so the recheck (validating at the
        // tip+1 height = 1000) sees it as invalid and must evict + blacklist it.
        const CLAIM_HEIGHT: u32 = 999;

        // Negative: tip advanced past the creation height -> evicted + blacklisted.
        let mut mp = mempool_with(MempoolConfig::default());
        seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
        let utxo = FakeUtxo::empty();
        let advanced_tip = TestTip::at_height(1000);
        let v = HeightGatedValidator {
            valid_at: CLAIM_HEIGHT,
            charge: 30_000,
        };
        let actions = mp.recheck_and_evict(Instant::now(), &advanced_tip.view(&utxo), &v);
        assert!(
            !mp.contains(&d(1)),
            "stale recreate claim evicted once the tip advanced past its creation height"
        );
        assert!(
            mp.is_invalidated(&d(1)),
            "evicted claim blacklisted so it is not re-relayed"
        );
        assert_eq!(evicted_ids(&actions), vec![d(1)]);
        mp.pool().check_invariants();

        // Positive control: validating AT the claim's creation height -> the
        // very same claim is still valid and survives. This is what makes the
        // negative case a height-transition test, not a generic failure.
        let mut mp_ok = mempool_with(MempoolConfig::default());
        seed(&mut mp_ok, 1, 0x10, 0x11, 100, vec![]);
        let utxo_ok = FakeUtxo::empty();
        let at_claim = TestTip::at_height(CLAIM_HEIGHT);
        let v_ok = HeightGatedValidator {
            valid_at: CLAIM_HEIGHT,
            charge: 30_000,
        };
        let actions_ok = mp_ok.recheck_and_evict(Instant::now(), &at_claim.view(&utxo_ok), &v_ok);
        assert!(
            mp_ok.contains(&d(1)),
            "claim valid at its own creation height survives the recheck"
        );
        assert!(actions_ok.is_empty());
        assert!(!mp_ok.is_invalidated(&d(1)));
    }

    #[test]
    fn recheck_evicts_generic_tip_invalid_tx() {
        // Same eviction for a non-rent tx — proves the pass is general,
        // not rent-specific.
        let mut mp = mempool_with(MempoolConfig::default());
        seed(&mut mp, 9, 0x10, 0x11, 100, vec![]);
        let utxo = FakeUtxo::empty();
        let tip = TestTip::new();
        let v = validator(vec![err_plan(9, 20_000)]);

        let actions = mp.recheck_and_evict(Instant::now(), &tip.view(&utxo), &v);

        assert!(!mp.contains(&d(9)));
        assert!(mp.is_invalidated(&d(9)));
        assert_eq!(evicted_ids(&actions), vec![d(9)]);
        mp.pool().check_invariants();
    }

    #[test]
    fn recheck_eviction_emits_revoke_before_evicted_event() {
        let mut mp = mempool_with(MempoolConfig::default());
        seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
        let utxo = FakeUtxo::empty();
        let tip = TestTip::new();
        let v = validator(vec![err_plan(1, 10_000)]);

        let actions = mp.recheck_and_evict(Instant::now(), &tip.view(&utxo), &v);

        let revoke_pos = actions.iter().position(
            |a| matches!(a, MempoolAction::RevokeBroadcast { tx_ids } if tx_ids.contains(&d(1))),
        );
        let evicted_pos = actions.iter().position(|a| {
            matches!(
                a,
                MempoolAction::Observe {
                    event: ObservedEvent::Evicted {
                        reason: EvictionReason::TipInvalid,
                        ..
                    }
                }
            )
        });
        assert!(
            matches!((revoke_pos, evicted_pos), (Some(r), Some(e)) if r < e),
            "RevokeBroadcast must precede Observe(Evicted::TipInvalid); \
             got revoke={revoke_pos:?} evicted={evicted_pos:?}"
        );
    }

    #[test]
    fn recheck_eviction_debits_ancestor_family_weight() {
        // P (weight carries a child boost) <- C. Evicting C must de-propagate
        // its weight from the surviving ancestor P (#139 debiting removal).
        let mut mp = mempool_with(MempoolConfig::default());
        seed(&mut mp, 1, 0x10, 0x11, 900, vec![]); // P (boosted)
        seed(&mut mp, 2, 0x11, 0x22, 100, vec![d(1)]); // C spends P's output 0x11
                                                       // Visit P first (valid), then C (invalid → evicted, debits P).
        let base = Instant::now();
        set_checked(&mut mp, 1, base);
        set_checked(&mut mp, 2, base + Duration::from_millis(1));

        let utxo = FakeUtxo::empty();
        let tip = TestTip::new();
        let v = validator(vec![ok_plan(1, 10_000), err_plan(2, 10_000)]);

        mp.recheck_and_evict(base + Duration::from_secs(10), &tip.view(&utxo), &v);

        assert!(mp.contains(&d(1)), "ancestor survives");
        assert!(!mp.contains(&d(2)), "tip-invalid child evicted");
        assert_eq!(
            mp.pool().get(&d(1)).unwrap().weight,
            800,
            "surviving ancestor debited by the evicted child's weight (900 - 100)"
        );
        mp.pool().check_invariants();
    }

    #[test]
    fn recheck_cascade_descendant_not_blacklisted() {
        // Evicting a tip-invalid parent cascades to its descendant, but only
        // the parent's id enters the invalidation cache — the descendant is
        // dependency-evicted and remains re-admittable if later valid.
        let mut mp = mempool_with(MempoolConfig::default());
        seed(&mut mp, 1, 0x10, 0x11, 200, vec![]); // parent (tip-invalid)
        seed(&mut mp, 2, 0x11, 0x22, 100, vec![d(1)]); // child of parent
        let base = Instant::now();
        set_checked(&mut mp, 1, base);
        set_checked(&mut mp, 2, base + Duration::from_millis(1));

        let utxo = FakeUtxo::empty();
        let tip = TestTip::new();
        // Only the parent has an Err plan; the child is never validated
        // (it is cascade-removed before its turn).
        let v = validator(vec![err_plan(1, 10_000), ok_plan(2, 10_000)]);

        let actions = mp.recheck_and_evict(base + Duration::from_secs(10), &tip.view(&utxo), &v);

        assert!(!mp.contains(&d(1)) && !mp.contains(&d(2)), "both removed");
        assert!(mp.is_invalidated(&d(1)), "failed parent is blacklisted");
        assert!(
            !mp.is_invalidated(&d(2)),
            "cascade descendant must NOT be blacklisted"
        );
        assert_eq!(v.validate_call_count(), 1, "child not separately validated");
        let mut evicted = evicted_ids(&actions);
        evicted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        assert_eq!(evicted, vec![d(1), d(2)], "both ids reported in the action");
        mp.pool().check_invariants();
    }

    // ----- anti-DoS cost cap + rotation -----

    #[test]
    fn recheck_cost_cap_caps_one_pass_and_defers_the_rest() {
        // cap = mult(1) × max_block_cost(100_000) = 100_000; each tx charges
        // 60_000, so the second visit pushes the accumulator to 120_000 and
        // the third tx is deferred.
        let cfg = MempoolConfig {
            mempool_cleanup_cost_mult: 1,
            ..MempoolConfig::default()
        };
        let mut mp = mempool_with(cfg);
        let base = Instant::now();
        for b in 1..=5u8 {
            seed(&mut mp, b, 0x10 + b, 0x40 + b, 100, vec![]);
            set_checked(&mut mp, b, base + Duration::from_millis(u64::from(b)));
        }
        let utxo = FakeUtxo::empty();
        let tip = TestTip::new().with_max_block_cost(100_000);
        let v = validator((1..=5u8).map(|b| ok_plan(b, 60_000)).collect());

        mp.recheck_and_evict(base + Duration::from_secs(10), &tip.view(&utxo), &v);

        assert_eq!(
            v.validate_call_count(),
            2,
            "cost cap binds the pass to two txs"
        );
        // The two oldest (d(1), d(2)) were visited; the rest were deferred.
        let now = base + Duration::from_secs(10);
        assert_eq!(mp.pool().get(&d(1)).unwrap().last_checked_at, now);
        assert_eq!(mp.pool().get(&d(2)).unwrap().last_checked_at, now);
        for b in 3..=5u8 {
            assert_eq!(
                mp.pool().get(&d(b)).unwrap().last_checked_at,
                base + Duration::from_millis(u64::from(b)),
                "deferred tx d({b}) untouched this pass"
            );
        }
    }

    #[test]
    fn recheck_failing_txs_consume_budget_and_defer_rest() {
        // Even failing txs charge their actual consumed cost, so the cap
        // cannot be over-run by an all-invalid pool.
        let cfg = MempoolConfig {
            mempool_cleanup_cost_mult: 1,
            ..MempoolConfig::default()
        };
        let mut mp = mempool_with(cfg);
        let base = Instant::now();
        for b in 1..=5u8 {
            seed(&mut mp, b, 0x10 + b, 0x40 + b, 100, vec![]);
            set_checked(&mut mp, b, base + Duration::from_millis(u64::from(b)));
        }
        let utxo = FakeUtxo::empty();
        let tip = TestTip::new().with_max_block_cost(100_000);
        let v = validator((1..=5u8).map(|b| err_plan(b, 60_000)).collect());

        let actions = mp.recheck_and_evict(base + Duration::from_secs(10), &tip.view(&utxo), &v);

        assert_eq!(v.validate_call_count(), 2, "cap binds even for failing txs");
        assert_eq!(mp.size(), 3, "only the two budgeted txs were evicted");
        let mut evicted = evicted_ids(&actions);
        evicted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        assert_eq!(evicted, vec![d(1), d(2)]);
        mp.pool().check_invariants();
    }

    #[test]
    fn recheck_eventual_coverage_deterministic_order_no_starvation() {
        // A pool exceeding the per-pass cap is fully covered across passes,
        // visited in (last_checked_at, tx_id) order; a tip-invalid tx that
        // is not the oldest is still reached and evicted within a bounded
        // number of passes (not starved).
        let cfg = MempoolConfig {
            mempool_cleanup_cost_mult: 1,
            ..MempoolConfig::default()
        };
        let mut mp = mempool_with(cfg);
        let base = Instant::now();
        for b in 1..=5u8 {
            seed(&mut mp, b, 0x10 + b, 0x40 + b, 100, vec![]);
            set_checked(&mut mp, b, base + Duration::from_millis(u64::from(b)));
        }
        let utxo = FakeUtxo::empty();
        let tip = TestTip::new().with_max_block_cost(100_000);
        // d(3) is tip-invalid; the rest are valid. Cap allows two per pass.
        let v = validator(
            (1..=5u8)
                .map(|b| {
                    if b == 3 {
                        err_plan(b, 60_000)
                    } else {
                        ok_plan(b, 60_000)
                    }
                })
                .collect(),
        );

        // Pass 1 visits the two oldest, d(1) and d(2).
        let now1 = base + Duration::from_secs(10);
        mp.recheck_and_evict(now1, &tip.view(&utxo), &v);
        assert_eq!(v.validate_call_count(), 2);
        assert!(mp.contains(&d(3)), "tip-invalid tx not yet reached");
        assert_eq!(mp.pool().get(&d(1)).unwrap().last_checked_at, now1);
        assert_eq!(mp.pool().get(&d(2)).unwrap().last_checked_at, now1);

        // Pass 2 visits the next-oldest pair d(3), d(4); d(3) is evicted.
        let now2 = now1 + Duration::from_secs(10);
        mp.recheck_and_evict(now2, &tip.view(&utxo), &v);
        assert!(
            !mp.contains(&d(3)),
            "tip-invalid tx evicted on a later pass"
        );
        assert!(mp.is_invalidated(&d(3)));
        assert_eq!(mp.pool().get(&d(4)).unwrap().last_checked_at, now2);

        // Pass 3 reaches the remaining least-recently-checked txs.
        let now3 = now2 + Duration::from_secs(10);
        mp.recheck_and_evict(now3, &tip.view(&utxo), &v);
        // Every surviving tx has now been visited at least once.
        for b in [1u8, 2, 4, 5] {
            assert!(
                mp.pool().get(&d(b)).unwrap().last_checked_at >= now1,
                "tx d({b}) covered within the bounded pass count"
            );
        }
        mp.pool().check_invariants();
    }

    // ----- view-content recording probe (overlay / pruning pins) -----

    /// Validator that, for the `probe_tx`, RECORDS whether `box_id` resolves in
    /// the regular input view and in the data-input view it was handed, then
    /// passes. An optional `hard_fail_tx` returns `ScriptFailed` so a test can
    /// evict that tx first and observe the downstream (pruned) overlay. This
    /// observes the exact views the recheck feeds the validator, without relying
    /// on the eviction policy.
    struct ViewRecordingProbe {
        hard_fail_tx: Option<Vec<u8>>,
        probe_tx: Vec<u8>,
        box_id: Digest32,
        saw_input: std::cell::Cell<Option<bool>>,
        saw_data: std::cell::Cell<Option<bool>>,
    }
    impl ViewRecordingProbe {
        fn new(probe_tx: Vec<u8>, box_id: Digest32, hard_fail_tx: Option<Vec<u8>>) -> Self {
            Self {
                hard_fail_tx,
                probe_tx,
                box_id,
                saw_input: std::cell::Cell::new(None),
                saw_data: std::cell::Cell::new(None),
            }
        }
    }
    impl Validator for ViewRecordingProbe {
        fn peek_fee(&self, _: &[u8]) -> Result<PeekedTx, ValidationErr> {
            Err(ValidationErr::Deserialize)
        }
        fn validate(
            &self,
            tx_bytes: &[u8],
            input_view: &dyn UtxoView,
            data_input_view: &dyn UtxoView,
            cx: &mut TxValidationCtx<'_>,
        ) -> Result<Validated, ValidationErr> {
            if let Ok(jc) = JitCost::from_block_cost(10_000) {
                let _ = cx.cost.add(jc);
            }
            if self.hard_fail_tx.as_deref() == Some(tx_bytes) {
                return Err(ValidationErr::ScriptFailed);
            }
            if tx_bytes == self.probe_tx.as_slice() {
                self.saw_input
                    .set(Some(input_view.get_box(&self.box_id).is_some()));
                self.saw_data
                    .set(Some(data_input_view.get_box(&self.box_id).is_some()));
            }
            Ok(Validated {
                tx_id: Digest32::from_bytes(
                    tx_bytes.first().map(|b| [*b; 32]).unwrap_or([0u8; 32]),
                ),
                input_box_ids: vec![],
                output_box_ids: vec![],
                outputs: vec![],
                fee: 1_000_000,
                size_bytes: 20,
                consumed_cost: 10_000,
            })
        }
    }

    #[test]
    fn recheck_data_input_uses_committed_only_view() {
        // [R1-6] P creates box 0xCC into the pool overlay; Q is rechecked. The
        // recheck feeds REGULAR inputs the PoolUtxoOverlay (which carries 0xCC)
        // but DATA inputs the CommittedOnly view (which does NOT) — admission
        // parity. Observe both views directly: the same box is visible to Q's
        // regular-input view and invisible to its data-input view.
        let mut mp = mempool_with(MempoolConfig::default());
        let p = Entry::new(
            d(1),
            Arc::from(tx_bytes(1).into_boxed_slice()),
            vec![d(0x10)],
            vec![d(0xCC)],
            vec![],
            1_000_000,
            100,
            20,
            50_000,
            TxSource::Api,
        )
        .with_output_boxes(vec![dummy_box(0xCC)]);
        mp.pool_mut().insert(p).unwrap();
        seed(&mut mp, 2, 0x20, 0x21, 100, vec![]); // Q

        // Sanity: 0xCC IS in the pool overlay (committed view is empty).
        assert!(
            mp.pool().output_map().contains_key(&d(0xCC)),
            "precondition: pool overlay carries the box"
        );

        let tip = TestTip::new();
        let empty = FakeUtxo::empty();
        let probe = ViewRecordingProbe::new(tx_bytes(2), d(0xCC), None);
        let actions = mp.recheck_and_evict(Instant::now(), &tip.view(&empty), &probe);

        assert_eq!(
            probe.saw_input.get(),
            Some(true),
            "regular inputs see the pool overlay (0xCC present)"
        );
        assert_eq!(
            probe.saw_data.get(),
            Some(false),
            "data inputs use the committed-only view (pool-created 0xCC invisible)"
        );
        assert!(actions.is_empty(), "both txs valid, nothing evicted");
        assert!(mp.contains(&d(1)) && mp.contains(&d(2)));

        // Contrapositive: when 0xCC is a COMMITTED box, the data-input view DOES
        // resolve it — the committed-only view isn't blind, it just excludes the
        // pool overlay.
        let mut mp2 = mempool_with(MempoolConfig::default());
        seed(&mut mp2, 2, 0x20, 0x21, 100, vec![]);
        let committed = FakeUtxo::empty().with_box(d(0xCC), dummy_box(0xCC));
        let probe2 = ViewRecordingProbe::new(tx_bytes(2), d(0xCC), None);
        mp2.recheck_and_evict(Instant::now(), &tip.view(&committed), &probe2);
        assert_eq!(
            probe2.saw_data.get(),
            Some(true),
            "data inputs resolve COMMITTED boxes (committed-only view is not pool-blind)"
        );
    }

    // ----- failure classification (shared with admission) -----

    /// Validator that fails every tx with a fixed `ValidationErr` (charging a
    /// fixed cost), so a test can pin how each error class is cached.
    struct AlwaysErr {
        err: ValidationErr,
    }
    impl Validator for AlwaysErr {
        fn peek_fee(&self, _: &[u8]) -> Result<PeekedTx, ValidationErr> {
            Err(ValidationErr::Deserialize)
        }
        fn validate(
            &self,
            _tx_bytes: &[u8],
            _input_view: &dyn UtxoView,
            _data_input_view: &dyn UtxoView,
            cx: &mut TxValidationCtx<'_>,
        ) -> Result<Validated, ValidationErr> {
            if let Ok(jc) = JitCost::from_block_cost(10_000) {
                let _ = cx.cost.add(jc);
            }
            Err(self.err.clone())
        }
    }

    #[test]
    fn recheck_unresolved_input_left_in_pool_not_evicted() {
        // An UnresolvedInput failure at recheck is NOT proof of invalidity: the
        // input may be a transient reorg-dependency (a demoted parent pending
        // re-admission). The tx must be LEFT in the pool — not evicted, not
        // cached — so it is not dropped before its parent returns; only its
        // rotation clock advances. (A genuine confirmed double-spend is handled
        // by on_tip_change's input-conflict cascade, not here.)
        let mut mp = mempool_with(MempoolConfig::default());
        seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
        let base = Instant::now();
        set_checked(&mut mp, 1, base);
        let utxo = FakeUtxo::empty();
        let tip = TestTip::new();
        let v = AlwaysErr {
            err: ValidationErr::UnresolvedInput,
        };

        let now = base + Duration::from_secs(10);
        let actions = mp.recheck_and_evict(now, &tip.view(&utxo), &v);

        assert!(
            mp.contains(&d(1)),
            "unresolved-input tx must be kept (could be a reorg-dependency)"
        );
        assert!(!mp.is_invalidated(&d(1)), "kept tx must not be blacklisted");
        assert!(actions.is_empty(), "no eviction action for a kept tx");
        assert_eq!(
            mp.pool().get(&d(1)).unwrap().last_checked_at,
            now,
            "rotation clock advances even when the tx is kept"
        );
        mp.pool().check_invariants();
    }

    #[test]
    fn recheck_hard_invalid_evicts_and_blacklists() {
        // A hard-invalid failure (script/monetary/...) is evicted AND
        // blacklisted so the Inv path stops re-fetching it.
        let mut mp = mempool_with(MempoolConfig::default());
        seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
        let utxo = FakeUtxo::empty();
        let tip = TestTip::new();
        let v = AlwaysErr {
            err: ValidationErr::MonetaryFailed,
        };

        mp.recheck_and_evict(Instant::now(), &tip.view(&utxo), &v);

        assert!(!mp.contains(&d(1)));
        assert!(
            mp.is_invalidated(&d(1)),
            "hard-invalid tx must be blacklisted"
        );
        mp.pool().check_invariants();
    }

    #[test]
    fn recheck_misconfigured_max_tx_cost_skips_pass_without_evicting() {
        // If `max_tx_cost` is set above the JitCost bound, the per-tx cap
        // cannot be built and every revalidation would return CostExceeded
        // with zero consumed cost — which, unguarded, would evict + blacklist
        // the WHOLE pool on a zero budget. The pass must instead refuse to run.
        let cfg = MempoolConfig {
            max_tx_cost: 1_000_000_000, // > JitCost bound (i32::MAX / 10)
            ..MempoolConfig::default()
        };
        let mut mp = mempool_with(cfg);
        seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
        let utxo = FakeUtxo::empty();
        let tip = TestTip::new();
        // Even a would-fail validator must not get the chance to evict.
        let v = AlwaysErr {
            err: ValidationErr::ScriptFailed,
        };

        let actions = mp.recheck_and_evict(Instant::now(), &tip.view(&utxo), &v);

        // The would-fail validator never gets to evict: no actions, the tx is
        // retained, and it is not blacklisted — the guard short-circuited the
        // whole pass before any revalidation.
        assert!(actions.is_empty(), "misconfigured pass emits no actions");
        assert!(mp.contains(&d(1)), "no eviction on a misconfigured cap");
        assert!(!mp.is_invalidated(&d(1)), "no blacklisting on a misconfig");
    }

    // ----- overlay pruning across evictions in one pass -----

    #[test]
    fn recheck_prunes_overlay_when_a_producing_tx_is_evicted() {
        // P creates box 0xCC into the pool overlay. C spends 0xCC as a REGULAR
        // input but is intentionally NOT recorded as P's child (parents=[]), so
        // P's eviction does not cascade to it; C is rechecked on its own. After
        // P is evicted (hard-invalid) the pass overlay is pruned, so when C is
        // rechecked next 0xCC is no longer visible to its input view — proving
        // the once-per-pass overlay is pruned in lockstep with evictions.
        let mut mp = mempool_with(MempoolConfig::default());
        let p = Entry::new(
            d(1),
            Arc::from(tx_bytes(1).into_boxed_slice()),
            vec![d(0x10)],
            vec![d(0xCC)],
            vec![],
            1_000_000,
            100,
            20,
            50_000,
            TxSource::Api,
        )
        .with_output_boxes(vec![dummy_box(0xCC)]);
        mp.pool_mut().insert(p).unwrap();
        // C spends 0xCC but declares no in-pool parent, so it is not a cascade
        // descendant of P — it is rechecked independently, after P.
        let c = Entry::new(
            d(2),
            Arc::from(tx_bytes(2).into_boxed_slice()),
            vec![d(0xCC)],
            vec![d(0x22)],
            vec![],
            1_000_000,
            100,
            20,
            50_000,
            TxSource::Api,
        );
        mp.pool_mut().insert(c).unwrap();
        // Visit P (d(1)) before C (d(2)).
        let base = Instant::now();
        set_checked(&mut mp, 1, base);
        set_checked(&mut mp, 2, base + Duration::from_millis(1));

        let utxo = FakeUtxo::empty();
        let tip = TestTip::new();
        // hard_fail P so it is evicted; record what C's input view sees afterward.
        let v = ViewRecordingProbe::new(tx_bytes(2), d(0xCC), Some(tx_bytes(1)));

        let actions = mp.recheck_and_evict(base + Duration::from_secs(10), &tip.view(&utxo), &v);

        assert!(!mp.contains(&d(1)), "producing tx P evicted (hard-invalid)");
        assert!(mp.is_invalidated(&d(1)), "P blacklisted");
        assert_eq!(
            v.saw_input.get(),
            Some(false),
            "after P's eviction, 0xCC is pruned from the pass overlay C is rechecked against"
        );
        // C itself fails no hard rule in this probe, so it survives; the point is
        // the overlay no longer resolves the evicted producer's output.
        assert_eq!(evicted_ids(&actions), vec![d(1)]);
        mp.pool().check_invariants();
    }

    // ----- deterministic rotation tie-break -----

    #[test]
    fn recheck_rotation_tie_breaks_on_tx_id() {
        // When last_checked_at ties, the visit order falls back to tx_id bytes
        // ascending, so the per-pass budget deterministically selects the
        // lowest tx_ids first (no reliance on map/iteration order).
        let cfg = MempoolConfig {
            mempool_cleanup_cost_mult: 1,
            ..MempoolConfig::default()
        };
        let mut mp = mempool_with(cfg);
        let base = Instant::now();
        for b in 1..=5u8 {
            seed(&mut mp, b, 0x10 + b, 0x40 + b, 100, vec![]);
            set_checked(&mut mp, b, base); // identical last_checked_at -> tie
        }
        let utxo = FakeUtxo::empty();
        let tip = TestTip::new().with_max_block_cost(100_000);
        let v = validator((1..=5u8).map(|b| ok_plan(b, 60_000)).collect());

        let now = base + Duration::from_secs(10);
        mp.recheck_and_evict(now, &tip.view(&utxo), &v);

        assert_eq!(v.validate_call_count(), 2, "budget binds to two txs");
        // Tie broken by tx_id: the lowest bytes (d(1), d(2)) are visited first.
        assert_eq!(mp.pool().get(&d(1)).unwrap().last_checked_at, now);
        assert_eq!(mp.pool().get(&d(2)).unwrap().last_checked_at, now);
        for b in 3..=5u8 {
            assert_eq!(
                mp.pool().get(&d(b)).unwrap().last_checked_at,
                base,
                "higher tx_id d({b}) deferred under the tie-break"
            );
        }
    }

    // ----- height-dependent validator (used by the recreate-claim test) -----

    /// Validator that passes a tx ONLY when the validation context height
    /// equals `valid_at` (charging `charge`), else returns `ScriptFailed`.
    /// Models a tx whose validity is bound to a specific block height (e.g. a
    /// storage-rent recreate claim with creationHeight == currentHeight).
    struct HeightGatedValidator {
        valid_at: u32,
        charge: u64,
    }
    impl Validator for HeightGatedValidator {
        fn peek_fee(&self, _: &[u8]) -> Result<PeekedTx, ValidationErr> {
            Err(ValidationErr::Deserialize)
        }
        fn validate(
            &self,
            tx_bytes: &[u8],
            _input_view: &dyn UtxoView,
            _data_input_view: &dyn UtxoView,
            cx: &mut TxValidationCtx<'_>,
        ) -> Result<Validated, ValidationErr> {
            if let Ok(jc) = JitCost::from_block_cost(self.charge) {
                let _ = cx.cost.add(jc);
            }
            if cx.ctx.height != self.valid_at {
                return Err(ValidationErr::ScriptFailed);
            }
            Ok(Validated {
                tx_id: Digest32::from_bytes(
                    tx_bytes.first().map(|b| [*b; 32]).unwrap_or([0u8; 32]),
                ),
                input_box_ids: vec![],
                output_box_ids: vec![],
                outputs: vec![],
                fee: 1_000_000,
                size_bytes: 20,
                consumed_cost: self.charge,
            })
        }
    }
}
