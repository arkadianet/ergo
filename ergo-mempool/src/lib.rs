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

use std::sync::Arc;

use ergo_primitives::digest::Digest32;
use tracing::{debug, info};

/// Sink for mempool admission/eviction telemetry — the tap the operator
/// WS/webhook surface (`ergo-api`'s realtime bus) hangs off of.
///
/// Defined here, not in `ergo-api`, so `ergo-mempool` never depends on
/// `ergo-api` types; the node/API layer implements this trait against
/// whatever it wants to feed (a `RealtimeBus`, a metrics counter, a test
/// spy) and hands `Mempool::set_observer` an `Arc<dyn MempoolObserver>`.
///
/// Calls happen inline on the admission hot path under `&mut Mempool` —
/// implementations must be cheap and non-blocking (no `.await`, no lock
/// contention with the WS fan-out). Fired from the same call sites as the
/// `mempool_tx_admitted` / `mempool_tx_evicted` / `mempool_tx_replaced`
/// tracing events, and ONLY for real state transitions: check-only
/// (`Mempool::check`) and would-admit outcomes never call this.
///
/// All callbacks describe **this node's pool under this node's policy /
/// tip** — not a network-wide mempool oracle.
pub trait MempoolObserver: Send + Sync {
    /// A tx was admitted to the pool.
    fn on_admitted(&self, tx_id: TxId, fee: u64, size_bytes: u32);
    /// A tx left the pool without confirming (policy eviction, tip-invalid,
    /// etc.). `reason` is `EvictionReason`'s `Debug` rendering — a short,
    /// stable tag. Never used for `EvictionReason::Confirmed` (see
    /// [`on_confirmed`]) or replacement losers (see [`on_replaced`]).
    fn on_evicted(&self, tx_id: TxId, reason: &str);
    /// A pooled tx was applied in our tip. Not a drop — confirmation.
    fn on_confirmed(&self, tx_id: TxId, height: u32, header_id: Digest32);
    /// Loser of a same-node replacement / weight fight. `winner_id` is the
    /// tx that stayed (or entered) the pool.
    fn on_replaced(&self, loser_id: TxId, winner_id: TxId);
}

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
///
/// `observer` is `None` for the check-only path (`Mempool::check` never
/// evicts, but the caller still passes `None` explicitly so this stays
/// correct even if that invariant ever changes) and `Some` for every real
/// pool mutation (admission-time eviction, reorg, revalidation, recheck).
///
/// `tip` is the tip *after* the mutation (used to turn
/// `EvictionReason::Confirmed` into [`MempoolObserver::on_confirmed`]).
fn emit_tracing_for_pool_actions(
    actions: &[MempoolAction],
    observer: Option<&dyn MempoolObserver>,
    tip: Option<TipPointer>,
) {
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
                    if let Some(obs) = observer {
                        match reason {
                            EvictionReason::Confirmed => {
                                // Confirmation is not a drop. Need tip
                                // context for height/header; without it
                                // skip the observer (still traced above).
                                if let Some(t) = tip {
                                    for tx_id in tx_ids {
                                        obs.on_confirmed(*tx_id, t.height, t.header_id);
                                    }
                                }
                            }
                            _ => {
                                let reason_str = format!("{reason:?}");
                                for tx_id in tx_ids {
                                    obs.on_evicted(*tx_id, &reason_str);
                                }
                            }
                        }
                    }
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
                    if let Some(obs) = observer {
                        obs.on_replaced(*loser_id, *winner_id);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Order demoted txs PARENT-BEFORE-CHILD for re-admission by `tick_revalidation`.
///
/// `snapshot` is `(tx_id, in_pool_parents, bytes)` for every demoted tx, in
/// priority (weight) order. `demote_all_for_revalidation` demotes the WHOLE
/// pool, so every parent edge points within the set. A child's inputs resolve
/// against its parent's pool output, so the drain must re-admit the parent
/// first; the raw weight order can place a high-fee child ahead of its low-fee
/// parent. Kahn's topological sort, sweeping in the input (priority) order so
/// independent txs keep their relative priority as a tie-break. The spend DAG is
/// acyclic; any entry left unemitted by an unexpected cycle is appended in input
/// order so nothing is dropped. O(N²) worst case (a deep chain), bounded by
/// `max_pool_size` and only run on the infrequent demote-all (epoch/reorg) path.
fn topological_demote_order(
    snapshot: Vec<(TxId, Vec<TxId>, std::sync::Arc<[u8]>)>,
) -> Vec<DemotedTx> {
    use std::collections::{HashMap, HashSet};
    let in_set: HashSet<TxId> = snapshot.iter().map(|(id, _, _)| *id).collect();
    // Remaining in-degree = count of in-set parents not yet emitted.
    let mut indeg: HashMap<TxId, usize> = HashMap::with_capacity(snapshot.len());
    let mut children: HashMap<TxId, Vec<TxId>> = HashMap::new();
    for (id, parents, _) in &snapshot {
        indeg.insert(*id, parents.iter().filter(|p| in_set.contains(p)).count());
        for p in parents {
            if in_set.contains(p) {
                children.entry(*p).or_default().push(*id);
            }
        }
    }
    let bytes_of: HashMap<TxId, std::sync::Arc<[u8]>> =
        snapshot.iter().map(|(id, _, b)| (*id, b.clone())).collect();
    let order: Vec<TxId> = snapshot.iter().map(|(id, _, _)| *id).collect();
    let mut emitted: HashSet<TxId> = HashSet::with_capacity(snapshot.len());
    let mut out: Vec<DemotedTx> = Vec::with_capacity(snapshot.len());
    loop {
        let mut progressed = false;
        for id in &order {
            if emitted.contains(id) || indeg.get(id).copied().unwrap_or(0) != 0 {
                continue;
            }
            emitted.insert(*id);
            out.push(DemotedTx {
                tx_id: *id,
                bytes: bytes_of[id].clone(),
            });
            progressed = true;
            if let Some(ch) = children.get(id) {
                for c in ch {
                    if let Some(d) = indeg.get_mut(c) {
                        *d = d.saturating_sub(1);
                    }
                }
            }
        }
        if !progressed {
            break;
        }
    }
    // Defensive: append any unemitted entries (only on an unexpected cycle) in
    // input order — never drop a demoted tx.
    if out.len() < order.len() {
        for id in &order {
            if !emitted.contains(id) {
                out.push(DemotedTx {
                    tx_id: *id,
                    bytes: bytes_of[id].clone(),
                });
            }
        }
    }
    out
}

/// Emit `mempool_tx_admitted` / `mempool_tx_rejected` for an admission
/// outcome plus the per-action `mempool_tx_evicted` / `_replaced`
/// fan-out.
///
/// Level selection:
/// - `TxSource::Api`: admit/reject at `info!` (operator action).
/// - All other sources (`Peer`, `DemotedFromBlock`): `debug!` to keep
///   per-peer traffic out of the default operator stream.
fn emit_tracing_for_admission(
    outcome: &AdmissionOutcome,
    actions: &[MempoolAction],
    source: &TxSource,
    pool_size: usize,
    pool_bytes: usize,
    observer: Option<&dyn MempoolObserver>,
    tip: Option<TipPointer>,
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
            if let Some(obs) = observer {
                obs.on_admitted(*tx_id, *fee, *size);
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

    emit_tracing_for_pool_actions(actions, observer, tip);
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

    // Check-only path: `Mempool::check` never admits or evicts, so the
    // observer is never fired here — `None`, not the live observer, even
    // though `actions` in practice carries no `Evicted`/`Replaced` events
    // for this outcome.
    emit_tracing_for_pool_actions(actions, None, None);
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
    /// Optional telemetry tap (see [`MempoolObserver`]). `None` by default —
    /// every existing caller and test keeps working unchanged; the node
    /// wires a `Some(_)` after boot once the realtime bus exists.
    observer: Option<Arc<dyn MempoolObserver>>,
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
            observer: None,
        }
    }

    /// Install (or clear, with `None`) the telemetry observer. Cheap — one
    /// `Option<Arc<_>>` swap, no allocation on the hot path this feeds.
    pub fn set_observer(&mut self, observer: Option<Arc<dyn MempoolObserver>>) {
        self.observer = observer;
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
                self.observer.as_deref(),
                self.tip,
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
            self.observer.as_deref(),
            self.tip,
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
        emit_tracing_for_pool_actions(&actions, self.observer.as_deref(), Some(new_tip));
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
        emit_tracing_for_pool_actions(&actions, self.observer.as_deref(), self.tip);

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
    /// (`UnresolvedInput`/`UnresolvedDataInput`), a parse-class failure, or the
    /// validator's catch-all `Other(_)` (an internal/contract error — resolved-
    /// inputs mismatch / internal-invariant violation — not a consensus verdict)
    /// does NOT evict: an unresolved input can be a transient reorg-dependency (a
    /// demoted parent pending re-admission via the revalidation-queue drain), a
    /// genuine confirmed double-spend is already evicted by
    /// `on_tip_change`'s input-conflict cascade, and an `Other(_)` is not safe
    /// proof to drop an already-accepted tx — so such txs are left in place
    /// (rotation clock advanced) rather than dropped to the unresolved-bytes
    /// cache (a suppression filter, not a re-admit queue). Eviction goes through
    /// the family-weight debiting wrapper and routes the FAILED ROOT
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
        // Ids that PASSED recheck this pass (verdict Ok — all inputs in place),
        // in visit (oldest-`last_checked_at` first) order. The re-broadcast
        // candidate set; filtered to those still pooled (not cascade-evicted by
        // a later tx) below.
        let mut passed_ids: Vec<TxId> = Vec::new();

        for (_, id) in ids {
            if cost_acc >= cost_cap {
                break; // per-pass budget spent; remainder deferred to next block
            }
            if !self.pool.contains(&id) {
                continue; // already cascade-evicted earlier this pass
            }
            rechecked += 1;
            cost_acc = cost_acc.saturating_add(u128::from(self.recheck_one(
                id,
                now,
                tip_ctx,
                validator,
                &mut pool_outputs,
                max_tx_cost,
                max_family_depth,
                bounds,
                &mut removed_for_actions,
                &mut passed_ids,
            )));
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

        // Re-broadcast half of Scala `MempoolAuditor.rebroadcastTransactions`:
        // after the eviction pass, re-advertise up to `rebroadcast_count`
        // SURVIVORS — txs that PASSED recheck this pass (verdict Ok, so all
        // inputs resolve: the exact `inputIds.forall(boxById(_).isDefined)`
        // precondition Scala re-broadcasts under) and are still pooled. Scala
        // selects `random(rebroadcastCount)`; we reuse the pass's
        // oldest-`last_checked_at` visit order, which is functionally equivalent
        // for load-spreading and is deterministic/testable: a cost-capped pass
        // refreshes only its rechecked survivors' clocks, so coverage rotates
        // across blocks. Excluded: evicted txs (revoked above), kept-but-failed
        // txs (unresolved/Other — inputs NOT in place), and the budget-deferred
        // tail (never rechecked this pass). Reuses the survivor set the loop
        // already established — no extra validation pass.
        let rebroadcast_count = self.config.rebroadcast_count;
        if rebroadcast_count > 0 {
            let mut rebroadcast = 0usize;
            for id in passed_ids {
                if rebroadcast >= rebroadcast_count {
                    break;
                }
                // A passed id can still be cascade-evicted by a LATER tx's
                // hard-invalid removal; only still-pooled survivors are relayed.
                if self.pool.contains(&id) {
                    actions.push(MempoolAction::BroadcastInv {
                        tx_id: id,
                        except: None,
                    });
                    rebroadcast += 1;
                }
            }
        }

        emit_tracing_for_pool_actions(&actions, self.observer.as_deref(), self.tip);
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

    /// Re-validate ONE pooled tx (`id`) against `tip_ctx` and apply the recheck
    /// eviction policy. The single shared per-id core of both the full-pool pass
    /// (`recheck_and_evict`) and the targeted suspect pass (`recheck_ids`), so
    /// the two have byte-identical validity/eviction/debit/cache semantics.
    ///
    /// * `Ok` (still valid) → keep; refresh only the rotation clock
    ///   (`touch_rechecked`) — deliberately NOT cost/weight, since re-pricing on
    ///   a validity check would desync `Entry.cost` from the `ByCost` weight key.
    /// * `Err` that is NOT `is_hard_invalid` (non-resolution / parse-class /
    ///   validator catch-all `Other(_)`) → keep, only advancing the rotation
    ///   clock. Such a failure is not proof of invalidity: an unresolved input
    ///   can be a transient reorg-dependency, dropping it to the unresolved-bytes
    ///   cache (a suppression filter, not a re-admit queue) would lose a valid
    ///   tx; a confirmed double-spend is already evicted by `on_tip_change`'s
    ///   input-conflict cascade; an `Other(_)` is an internal/contract error,
    ///   not a consensus verdict.
    /// * hard-invalid `Err` (script/monetary/structural/cost) → evict it + its
    ///   now-orphaned descendants (debiting the surviving ancestor's family
    ///   weight), prune the pass
    ///   overlay so a later tx can't resolve a gone output, and route ONLY the
    ///   failed root through the shared `record_failed_tx` classifier (here
    ///   always the blacklist arm). Cascade descendants are dependency-evicted,
    ///   never cached.
    ///
    /// `pool_outputs` is the once-per-pass overlay map, pruned in place on
    /// eviction. Removed tx ids are appended to `removed_for_actions`; ids that
    /// PASSED cleanly (verdict Ok — all inputs in place) are appended to
    /// `passed_ids` for the full pass's re-broadcast selection (a kept-but-FAILED
    /// non-hard-invalid tx is NOT recorded). Returns the validation cost the
    /// caller charges to its per-pass budget. A no-op returning 0 if `id` is no
    /// longer pooled (already cascade-evicted).
    #[allow(clippy::too_many_arguments)]
    fn recheck_one<V: Validator>(
        &mut self,
        id: TxId,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
        pool_outputs: &mut std::collections::HashMap<
            ergo_primitives::digest::Digest32,
            ergo_ser::ergo_box::ErgoBox,
        >,
        max_tx_cost: u64,
        max_family_depth: usize,
        bounds: crate::pool::FamilyBounds,
        removed_for_actions: &mut Vec<TxId>,
        passed_ids: &mut Vec<TxId>,
    ) -> u64 {
        let Some(bytes) = self.pool.get(&id).map(|e| e.bytes.clone()) else {
            return 0; // already gone (cascade-evicted, or a stale suspect id)
        };
        let (consumed, verdict) =
            admission::revalidate_pooled(&bytes, tip_ctx, pool_outputs, max_tx_cost, validator);
        match verdict {
            Ok(()) => {
                self.pool.touch_rechecked(&id, now);
                // Passed cleanly (all inputs in place) — a re-broadcast candidate.
                // A kept-but-FAILED tx (non-hard-invalid: unresolved / Other) is
                // deliberately NOT recorded: Scala only re-broadcasts txs whose
                // inputs all resolve, which a non-resolution failure violates.
                passed_ids.push(id);
            }
            Err(ref err) if !admission::is_hard_invalid(err) => {
                self.pool.touch_rechecked(&id, now);
            }
            Err(err) => {
                let removed =
                    self.pool
                        .remove_with_descendants_debiting(&id, max_family_depth, bounds);
                for e in &removed {
                    for out in &e.outputs {
                        pool_outputs.remove(out);
                    }
                }
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
        consumed
    }

    /// Targeted recheck of a SPECIFIC set of pooled tx ids — Component B's
    /// suspect feed from off-loop mining candidate assembly. The candidate
    /// builder skips a tx whose consensus re-validation fails against the build
    /// snapshot; those ids are forwarded here so a tx that has gone tip-invalid
    /// is evicted THIS block instead of waiting for the next full
    /// `recheck_and_evict` pass — purely a latency win, since the full pass would
    /// catch the same txs on the next tip change.
    ///
    /// Suspects are an ADVISORY hint computed against a possibly-stale build
    /// snapshot, so every id is RE-VALIDATED against the live `tip_ctx` here
    /// (via the shared [`Self::recheck_one`]): a suspect that is valid at the
    /// current tip is kept; only still-hard-invalid ones are evicted, with the
    /// exact eviction/debit/blacklist semantics of the full pass. Ids no longer
    /// pooled (confirmed/already-evicted) are skipped. Bounded by the same
    /// anti-DoS per-pass cost budget. The caller must gate on fully-synced (as
    /// the `recheck_and_evict` hook does) so a catching-up node doesn't act on a
    /// stale tip. Returns the emitted actions for the caller to route.
    pub fn recheck_ids<V: Validator>(
        &mut self,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
        ids: &[TxId],
    ) -> Vec<MempoolAction> {
        let mut actions: Vec<MempoolAction> = Vec::new();
        if ids.is_empty() || self.pool.is_empty() {
            return actions;
        }

        let max_tx_cost = self.config.max_tx_cost;
        let max_family_depth = self.config.max_family_depth;
        // Same misconfig guard as the full pass (see `recheck_and_evict`): a
        // max_tx_cost above the JitCost bound would make every revalidation a
        // zero-cost CostExceeded and mass-evict; refuse to run instead.
        if ergo_primitives::cost::JitCost::from_block_cost(max_tx_cost).is_err() {
            debug!(
                max_tx_cost,
                "mempool suspect recheck skipped: max_tx_cost exceeds the JitCost bound (misconfig)",
            );
            return actions;
        }
        let t0 = std::time::Instant::now();

        let bounds = crate::pool::FamilyBounds::new(
            self.config.max_family_depth,
            self.config.max_family_ops,
            self.config.max_family_update_ms,
        );
        let cost_cap: u128 = u128::from(self.config.mempool_cleanup_cost_mult)
            .saturating_mul(u128::from(tip_ctx.params.max_block_cost));
        let mut pool_outputs = self.pool.output_map();

        let mut cost_acc: u128 = 0;
        let mut rechecked: usize = 0;
        let mut removed_for_actions: Vec<TxId> = Vec::new();
        // The targeted suspect pass (Component B) is eviction-only; it does NOT
        // re-broadcast (that is the full `MempoolAuditor` pass's job), so the
        // passed-id set is collected and discarded.
        let mut passed_ids: Vec<TxId> = Vec::new();

        for id in ids {
            if cost_acc >= cost_cap {
                break; // per-pass budget spent; suspects re-surface on the next build
            }
            if !self.pool.contains(id) {
                continue; // suspect already confirmed / evicted / never pooled
            }
            rechecked += 1;
            cost_acc = cost_acc.saturating_add(u128::from(self.recheck_one(
                *id,
                now,
                tip_ctx,
                validator,
                &mut pool_outputs,
                max_tx_cost,
                max_family_depth,
                bounds,
                &mut removed_for_actions,
                &mut passed_ids,
            )));
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
        emit_tracing_for_pool_actions(&actions, self.observer.as_deref(), self.tip);
        info!(
            event = "mempool_suspect_recheck_completed",
            suspects = ids.len(),
            rechecked,
            evicted,
            pool_size = self.pool.len(),
            duration_ms = t0.elapsed().as_millis() as u64,
            "mempool suspect recheck completed",
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
        // Snapshot every active tx with its in-pool parent edges, in priority
        // order, then re-emit PARENT-BEFORE-CHILD. The drain
        // (`tick_revalidation`) re-admits in queue order and resolves a child's
        // inputs against its parent's now-pooled output, so the parent must be
        // re-admitted first; the raw weight order can place a high-fee child
        // ahead of its low-fee parent (which would then fail `UnresolvedInput`
        // and be dropped). See `topological_demote_order`.
        let snapshot: Vec<(TxId, Vec<TxId>, std::sync::Arc<[u8]>)> = self
            .pool
            .iter_prioritized()
            .map(|e| (e.tx_id, e.parents_in_pool.clone(), e.bytes.clone()))
            .collect();
        if snapshot.is_empty() {
            return 0;
        }
        let demoted = topological_demote_order(snapshot);
        // Drain the pool. Collect ids first to avoid borrow issues.
        let ids: Vec<TxId> = demoted.iter().map(|d| d.tx_id).collect();
        for id in &ids {
            self.pool.remove(id);
        }
        // Reset cost budgets (mirrors reorg::on_tip_change line 188).
        self.budgets.reset();
        // Enqueue for re-admission, parent-before-child.
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
#[path = "mempool/recheck_tests.rs"]
mod recheck_tests;
