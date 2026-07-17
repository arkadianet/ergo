//! Transaction-modifier delivery bookkeeping for [`SyncCoordinator`].
//!
//! The coordinator treats transactions as just another modifier type
//! for delivery tracking — it doesn't parse or validate them; the
//! node-side handler filters against the mempool before registering a
//! request here.

use std::time::Instant;

use ergo_p2p::delivery::DeliveryAction;
use ergo_p2p::message;
use ergo_p2p::peer::PeerId;
use ergo_p2p::types::{InvData, ModifierTypeId};
use tracing::warn;

use super::{Action, SyncCoordinator};

impl SyncCoordinator {
    /// Register a RequestModifier for `tx_ids` to `peer`. Returns the
    /// `(actions, requested_count)` pair: `actions` holds the `SendToPeer`
    /// with the serialized RequestModifier (or is empty if every id was
    /// already in-flight / failed or the per-peer cap blocks further
    /// requests, or serialization fails), and `requested_count` is the
    /// number of ids ACTUALLY registered + emitted in that RequestModifier.
    /// Callers use the count for observability; it never exceeds the number
    /// of `tx_ids` passed in and reflects the post-dedupe/cap reality, not
    /// the advertised set. The count is `0` exactly when `actions` is empty.
    pub fn request_transactions(
        &mut self,
        peer: PeerId,
        tx_ids: &[[u8; 32]],
        now: Instant,
    ) -> (Vec<Action>, usize) {
        let type_id = ModifierTypeId::Transaction.as_byte();
        let registered = self.delivery.request(peer, type_id, tx_ids, now);
        if registered.is_empty() {
            return (Vec::new(), 0);
        }
        let requested_count = registered.len();
        let request = InvData {
            type_id,
            ids: registered,
        };
        match message::serialize_inv(&request) {
            Ok(payload) => (
                vec![Action::SendToPeer {
                    peer,
                    code: message::CODE_REQUEST_MODIFIER,
                    payload,
                }],
                requested_count,
            ),
            Err(e) => {
                warn!(error = %e, "failed to serialize tx RequestModifier");
                (Vec::new(), 0)
            }
        }
    }

    /// Check delivery ownership when a tx arrives. Caller dispatches
    /// on the returned verdict:
    ///   Accept  → mark received + hand off to the mempool
    ///   Ignore  → duplicate delivery, drop silently
    ///   Reject  → unsolicited modifier, penalize sender
    pub fn on_transaction_received(&mut self, peer: PeerId, tx_id: &[u8; 32]) -> DeliveryAction {
        let action = self.delivery.on_received(tx_id, &peer);
        if let DeliveryAction::Accept = action {
            self.delivery.mark_received(tx_id);
        }
        action
    }
}
