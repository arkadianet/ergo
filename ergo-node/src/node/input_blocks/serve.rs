//! Serving side (spec 9.4): answer peers out of the processor's stores.
//!
//! `RequestModifier` for −123 / −122 / −121 and message 105 are answered
//! from what the processor already holds. An unknown id is logged and
//! ignored — **no penalty**, parity with Scala, because a peer can
//! legitimately ask for a block we pruned a moment ago.

use ergo_p2p::message;
use ergo_p2p::peer::PeerId;
use ergo_p2p::types::ModifierTypeId;
use ergo_sync::coordinator::Action;
use tracing::{debug, warn};

use super::super::NodeState;
use super::runtime::InputBlocksRuntime;

/// Answer a `RequestModifier` whose type is one of the input-block
/// family. Returns one reply frame per id we hold; an empty result means
/// we served nothing (and so the request is not progress).
pub(in crate::node) fn serve_request_modifier(
    state: &NodeState,
    peer: PeerId,
    type_id: u8,
    ids: &[[u8; 32]],
) -> Vec<Action> {
    let Some(rt) = state.input_blocks.as_ref() else {
        return Vec::new();
    };
    let Some(kind) = ModifierTypeId::from_byte(type_id) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for id in ids {
        match kind {
            ModifierTypeId::InputBlock => {
                push_announcement(rt, peer, id, &mut out);
            }
            ModifierTypeId::InputBlockTransactionIds => {
                push_weak_ids(rt, peer, id, &mut out);
            }
            ModifierTypeId::OrderingBlockAnnouncement => {
                push_ordering_announcement(rt, peer, id, &mut out);
            }
            _ => return Vec::new(),
        }
    }
    out
}

fn push_announcement(rt: &InputBlocksRuntime, peer: PeerId, id: &[u8; 32], out: &mut Vec<Action>) {
    let Some(ann) = rt.processor().announcement(id) else {
        debug!(block = %hex::encode(id), "input_blocks: asked for an announcement we do not hold");
        return;
    };
    match message::serialize_input_block(ann) {
        Ok(payload) => out.push(Action::SendToPeer {
            peer,
            code: message::CODE_INPUT_BLOCK,
            payload,
        }),
        Err(e) => warn!(error = %e, "input_blocks: announcement does not serialize"),
    }
}

fn push_weak_ids(rt: &InputBlocksRuntime, peer: PeerId, id: &[u8; 32], out: &mut Vec<Action>) {
    let Some(weak_ids) = rt.processor().weak_ids(id) else {
        debug!(block = %hex::encode(id), "input_blocks: asked for weak ids we do not hold");
        return;
    };
    out.push(Action::SendToPeer {
        peer,
        code: message::CODE_INPUT_BLOCK_TX_IDS,
        payload: message::serialize_input_block_tx_ids(&message::InputBlockTxIds {
            input_block_id: *id,
            weak_ids,
        }),
    });
}

fn push_ordering_announcement(
    rt: &InputBlocksRuntime,
    peer: PeerId,
    id: &[u8; 32],
    out: &mut Vec<Action>,
) {
    let Some(ann) = rt.processor().ordering_announcement(id) else {
        debug!(block = %hex::encode(id), "input_blocks: asked for an ordering announcement we do not hold");
        return;
    };
    match message::serialize_ordering_block_announcement_msg(ann) {
        Ok(payload) => out.push(Action::SendToPeer {
            peer,
            code: message::CODE_ORDERING_BLOCK_ANNOUNCEMENT,
            payload,
        }),
        Err(e) => warn!(error = %e, "input_blocks: ordering announcement does not serialize"),
    }
}

/// Answer message 105 (`RequestInputBlockTransactions`) with message 104,
/// carrying ONLY the bodies whose weak ids were asked for.
pub(in crate::node) fn serve_transactions(
    state: &NodeState,
    peer: PeerId,
    req: &message::InputBlockTxsRequest,
) -> Vec<Action> {
    let Some(rt) = state.input_blocks.as_ref() else {
        return Vec::new();
    };
    let bodies = rt
        .processor()
        .bodies_by_weak_ids(&req.input_block_id, &req.weak_ids)
        .unwrap_or_default();
    if bodies.is_empty() {
        debug!(
            block = %hex::encode(req.input_block_id),
            asked = req.weak_ids.len(),
            "input_blocks: asked for bodies we do not hold"
        );
        return Vec::new();
    }
    let data = message::InputBlockTxs {
        input_block_id: req.input_block_id,
        transactions: bodies.into_iter().map(|b| b.tx.clone()).collect(),
    };
    match message::serialize_input_block_txs(&data) {
        Ok(payload) => vec![Action::SendToPeer {
            peer,
            code: message::CODE_INPUT_BLOCK_TXS,
            payload,
        }],
        Err(e) => {
            warn!(error = %e, "input_blocks: transaction reply does not serialize");
            Vec::new()
        }
    }
}
