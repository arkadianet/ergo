//! Mempool telemetry glue: pure functions that translate an admission /
//! check / pool-mutation outcome plus its `MempoolAction` transcript into
//! `tracing` journal events and [`MempoolObserver`] callbacks.
//!
//! These carry no `Mempool` state — they operate solely over
//! `MempoolAction` / `ObservedEvent` / `AdmissionOutcome` / `CheckOutcome`
//! / `TxSource` — so they live outside `mempool.rs`. `Mempool`'s methods
//! call `emit_tracing_for_admission` / `emit_tracing_for_check` /
//! `emit_tracing_for_pool_actions` on every real state transition.

use tracing::{debug, info};

use crate::types::{EvictionReason, MempoolAction, ObservedEvent, TipPointer, TxId, TxSource};
use crate::{AdmissionOutcome, CheckOutcome, MempoolObserver};

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
