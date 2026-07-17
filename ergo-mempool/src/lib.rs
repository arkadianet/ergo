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
mod mempool;
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
pub use mempool::Mempool;
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
pub(crate) fn emit_tracing_for_pool_actions(
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
pub(crate) fn topological_demote_order(
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
pub(crate) fn emit_tracing_for_admission(
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
pub(crate) fn emit_tracing_for_check(
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
