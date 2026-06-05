//! Peer + API transaction admission. Both paths fund through the same
//! `Mempool::process` / `Mempool::check` calls; the routing layer here
//! translates the resulting `MempoolAction`s into outer-loop `Action`s
//! (Inv broadcasts, peer penalties, observe events) and shapes
//! rejection reasons into the wire-level `SubmitError` payload the API
//! returns.

use std::time::Instant;

use ergo_api::types::{SubmitError, SubmitMode};
use ergo_mempool::types::{MempoolAction, TxSource};
use ergo_mempool::{AdmissionOutcome, CheckOutcome, ErgoValidator, RejectReason, ValidationErr};
use ergo_p2p::peer::{PeerId, Penalty};
use ergo_p2p::types::ModifierTypeId;
use ergo_sync::coordinator::Action;
use tracing::{debug, warn};

use super::tip_context::build_tip_context;
use super::{flush_actions, NodeState};

/// Route the actions a mempool admission produced into outer-loop
/// `Action`s. `BroadcastInv` becomes one `SendToPeer(Inv)` per
/// connected peer except the source; `Penalize` becomes
/// `Action::Penalize` for `peer_manager` consumption; `Observe` is
/// already traced at the source so it's a structural no-op here.
pub(super) fn route_mempool_actions(
    state: &mut NodeState,
    actions: Vec<MempoolAction>,
) -> Vec<Action> {
    let mut out = Vec::new();
    for action in actions {
        match action {
            MempoolAction::BroadcastInv { tx_id, except } => {
                // Single-id Inv per peer. The wire format supports
                // multi-id Invs, but per-tx batching can come later
                // once pool volume grows.
                let inv = ergo_p2p::types::InvData {
                    type_id: ModifierTypeId::Transaction.as_byte(),
                    ids: vec![*tx_id.as_bytes()],
                };
                let payload = match ergo_p2p::message::serialize_inv(&inv) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(error = %e, "mempool: failed to serialize tx Inv");
                        continue;
                    }
                };
                for peer in state.registry.peers.keys().copied().collect::<Vec<_>>() {
                    if Some(peer) == except {
                        continue;
                    }
                    out.push(Action::SendToPeer {
                        peer,
                        code: ergo_p2p::message::CODE_INV,
                        payload: payload.clone(),
                    });
                }
            }
            MempoolAction::RevokeBroadcast { tx_ids } => {
                // No wire-level revocation exists in the Ergo P2P
                // protocol — peers that already requested a revoked
                // tx will hit `get_bytes(...) == None` and receive
                // no response. Surface as a log for operators.
                if !tx_ids.is_empty() {
                    debug!(
                        removed = tx_ids.len(),
                        "mempool: tx(s) removed from pool; no further relay",
                    );
                }
            }
            MempoolAction::Penalize { peer, kind } => {
                let penalty = match kind {
                    ergo_mempool::types::PenaltyKind::Misbehavior => Penalty::Misbehavior,
                    ergo_mempool::types::PenaltyKind::Spam => Penalty::Spam,
                    ergo_mempool::types::PenaltyKind::NonDelivery => Penalty::NonDelivery,
                };
                out.push(Action::Penalize { peer, penalty });
            }
            MempoolAction::Observe { event: _ } => {
                // Per-event tracing (`mempool_tx_admitted` /
                // `mempool_tx_rejected` / `mempool_tx_evicted` /
                // `mempool_tx_replaced`) is emitted at the source by
                // `Mempool::{process, check, on_tip_change,
                // tick_revalidation}`. No-op here; the action stream
                // stays in place so future consumers (metrics,
                // dashboards) can still observe events structurally.
            }
        }
    }
    out
}

pub(super) fn admit_transaction(
    state: &mut NodeState,
    peer: PeerId,
    tx_bytes: &[u8],
    now: Instant,
) -> Vec<Action> {
    let owned = match build_tip_context(state) {
        Some(o) => o,
        // Too early in bootstrap to validate anything — mempool tick
        // will IBD-gate us anyway. Drop silently; peer gets no
        // penalty because this is our problem, not theirs.
        None => return Vec::new(),
    };
    let size = tx_bytes.len();
    let actions = {
        let tip_ctx = owned.as_mempool_ctx(
            state
                .store
                .as_utxo()
                .expect("utxo-only: mempool admission is gated off in digest mode"),
        );
        let (outcome, actions) = state.mempool.process(
            tx_bytes,
            TxSource::Peer(peer),
            now,
            &tip_ctx,
            &ErgoValidator,
        );
        match &outcome {
            AdmissionOutcome::Admitted { tx_id, fee, .. } => {
                debug!(
                    tx = %hex::encode(tx_id.as_bytes()),
                    peer = %peer,
                    fee = fee,
                    size = size,
                    outcome = "admitted",
                    "modifier received",
                );
            }
            AdmissionOutcome::Rejected { reason } => {
                debug!(
                    peer = %peer,
                    size = size,
                    outcome = "rejected",
                    reason = ?reason,
                    "modifier received",
                );
            }
        }
        actions
    };
    route_mempool_actions(state, actions)
}

/// Drive an API submission through the same admission pipeline peers
/// use. `Broadcast` mode runs `Mempool::process` (steps 0–14 then
/// commit then Inv); `CheckOnly` runs `Mempool::check` (steps 0–14,
/// no commit, no Inv). Both still mutate the anti-DoS bookkeeping.
///
/// Returns the hex-encoded tx_id on success; on rejection, returns
/// the wire-shaped `SubmitError`.
pub(super) fn admit_api_transaction(
    state: &mut NodeState,
    bytes: &[u8],
    mode: SubmitMode,
    now: Instant,
) -> Result<String, SubmitError> {
    // No admission pipeline without a mempool (digest mode, or mempool
    // disabled by config): reject as Disabled rather than failing deeper
    // with a misleading tip/context error. `Mempool::process`/`check`
    // already short-circuit to this reason when disabled; guarding here
    // keeps the digest backend off the `as_utxo()` path below entirely.
    if !state.mempool.config().enabled {
        return Err(reject_to_submit_error(RejectReason::Disabled));
    }
    let owned = match build_tip_context(state) {
        Some(o) => o,
        None => {
            return Err(reject_to_submit_error(RejectReason::TipUnready));
        }
    };
    let (tx_id, actions) =
        match mode {
            SubmitMode::Broadcast => {
                let (outcome, actions) =
                    {
                        let tip_ctx =
                            owned.as_mempool_ctx(state.store.as_utxo().expect(
                                "utxo-only: mempool admission is gated off in digest mode",
                            ));
                        state
                            .mempool
                            .process(bytes, TxSource::Api, now, &tip_ctx, &ErgoValidator)
                    };
                let tx_id = match outcome {
                    AdmissionOutcome::Admitted { tx_id, .. } => Ok(hex::encode(tx_id.as_bytes())),
                    AdmissionOutcome::Rejected { reason } => Err(reject_to_submit_error(reason)),
                };
                (tx_id, actions)
            }
            SubmitMode::CheckOnly => {
                let (outcome, actions) =
                    {
                        let tip_ctx =
                            owned.as_mempool_ctx(state.store.as_utxo().expect(
                                "utxo-only: mempool admission is gated off in digest mode",
                            ));
                        state
                            .mempool
                            .check(bytes, TxSource::Api, now, &tip_ctx, &ErgoValidator)
                    };
                let tx_id = match outcome {
                    CheckOutcome::WouldAdmit { validated, .. } => {
                        Ok(hex::encode(validated.tx_id.as_bytes()))
                    }
                    CheckOutcome::Rejected { reason } => Err(reject_to_submit_error(reason)),
                };
                (tx_id, actions)
            }
        };
    // Route admission's mempool actions into outer-loop Actions and FLUSH
    // them. A Broadcast submit emits a BroadcastInv, which becomes one
    // SendToPeer(Inv) per connected peer — flushing announces the tx so it
    // propagates across the network. The peer path flushes via its caller;
    // the API path returns a tx_id string, so it must flush here. Without
    // this the tx is admitted to the local pool but never advertised, so
    // peers never learn of it (and on a node not itself mining, it never
    // confirms). CheckOnly emits no commit-only actions, so this is a
    // no-op there.
    let to_broadcast = route_mempool_actions(state, actions);
    let inv_peers = to_broadcast
        .iter()
        .filter(|a| matches!(a, Action::SendToPeer { code, .. } if *code == ergo_p2p::message::CODE_INV))
        .count();
    if inv_peers > 0 {
        if let Ok(id) = &tx_id {
            // Make the announce step visible at INFO so an admitted-but-not-
            // propagated tx is diagnosable from the log (its absence after
            // `mempool_tx_admitted source=api` is the symptom).
            tracing::info!(tx_id = %id, peers = inv_peers, "api tx announced to peers");
        }
    }
    flush_actions(state, to_broadcast);
    tx_id
}

/// Shape a mempool rejection into the wire-level `SubmitError` payload
/// the operator API returns. `ValidationErr::Other(s)` short-circuits
/// because the message body already carries the explanation.
pub(super) fn reject_to_submit_error(reason: RejectReason) -> SubmitError {
    let (reason_str, detail) = match reason {
        RejectReason::Disabled => (
            "disabled",
            Some("mempool admission is disabled by config".to_string()),
        ),
        RejectReason::IbdGated => (
            "ibd_gated",
            Some("node is still syncing — header chain not yet near tip".to_string()),
        ),
        RejectReason::TipUnready => (
            "tip_unready",
            Some("tip context not yet built (cold headers)".to_string()),
        ),
        RejectReason::PeerBudgetExhausted => (
            "budget_exhausted",
            Some("per-peer cost budget exhausted".to_string()),
        ),
        RejectReason::GlobalBudgetExhausted => (
            "budget_exhausted",
            Some("global cost budget exhausted".to_string()),
        ),
        RejectReason::SizeLimit => ("size_limit", None),
        RejectReason::RecentlyUnresolved => ("recently_unresolved", None),
        RejectReason::Deserialize => ("deserialize", None),
        RejectReason::NonCanonical => ("non_canonical", None),
        RejectReason::KnownInvalid => ("known_invalid", None),
        RejectReason::Duplicate => ("duplicate", None),
        RejectReason::Structural => ("structural", None),
        RejectReason::BelowMinFee => ("below_min_fee", None),
        RejectReason::UnresolvedInput => ("unresolved_input", None),
        RejectReason::UnresolvedDataInput => ("unresolved_data_input", None),
        RejectReason::ValidationFailed { kind } => match kind {
            ValidationErr::Deserialize => ("deserialize", None),
            ValidationErr::NonCanonical => ("non_canonical", None),
            ValidationErr::Structural => ("structural", None),
            ValidationErr::UnresolvedInput => ("unresolved_input", None),
            ValidationErr::UnresolvedDataInput => ("unresolved_data_input", None),
            ValidationErr::ScriptFailed => ("script_failed", None),
            ValidationErr::MonetaryFailed => ("monetary_failed", None),
            ValidationErr::CostExceeded => ("cost_exceeded", None),
            ValidationErr::Other(s) => {
                return SubmitError {
                    reason: "validation_failed".to_string(),
                    detail: Some(s),
                }
            }
        },
        RejectReason::DoubleSpendLoser => (
            "double_spend_loser",
            Some("replacement weight too low".to_string()),
        ),
        RejectReason::PoolFull => ("pool_full", None),
        RejectReason::InsertCollision => (
            "insert_collision",
            Some("internal: investigate if seen".to_string()),
        ),
    };
    SubmitError {
        reason: reason_str.to_string(),
        detail,
    }
}
