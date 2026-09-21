//! Inbound dispatch for the input-block message family (spec 9.1-9.2).
//!
//! Codes 100 / 102 / 104 / 106 carry data INTO the processor; 105 is a
//! request we serve. The cheap dispatch checks the spec assigns to this
//! layer are exactly two — "is the subsystem on" and "does the frame
//! decode" — because the height window (±2), the UTXO-mode gate and the
//! duplicate check all live in the processor (spec 9.2) and duplicating
//! them here would give the node two places to disagree with Scala.
//!
//! A frame that does not decode is peer misbehaviour, as on every other
//! request arm in `messaging::dispatch`.

use std::time::Instant;

use ergo_inputblocks::processor::{Body, Event};
use ergo_inputblocks::types::TxRef;
use ergo_p2p::handshake::Version;
use ergo_p2p::message;
use ergo_p2p::peer::{PeerId, Penalty};
use ergo_p2p::types::{InvData, ModifierTypeId};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::transaction::{transaction_id, write_transaction, Transaction};
use ergo_ser::weak_id::{weak_tx_id, witness_id};
use ergo_state::HeaderSectionStore;
use ergo_sync::coordinator::Action;
use tracing::{debug, warn};

use super::super::NodeState;
use super::ctx::build_ctx_data;
use super::effects::execute_effects;
use super::serve;

/// What dispatch produced: actions to flush, plus whether the frame
/// counted as protocol progress (spec 9.1: 100 and 106 always; 102, 104
/// and 105 only when they answer something).
pub(in crate::node) struct Dispatched {
    pub(in crate::node) actions: Vec<Action>,
    pub(in crate::node) progress: bool,
}

impl Dispatched {
    fn nothing() -> Self {
        Self {
            actions: Vec::new(),
            progress: false,
        }
    }
    fn penalize(peer: PeerId) -> Self {
        Self {
            actions: vec![Action::Penalize {
                peer,
                penalty: Penalty::Misbehavior,
            }],
            progress: false,
        }
    }
}

/// True when `code` belongs to the input-block message family.
pub(in crate::node) fn is_input_block_code(code: u8) -> bool {
    matches!(
        code,
        message::CODE_INPUT_BLOCK
            | message::CODE_INPUT_BLOCK_TX_IDS
            | message::CODE_INPUT_BLOCK_TXS
            | message::CODE_INPUT_BLOCK_TXS_REQUEST
            | message::CODE_ORDERING_BLOCK_ANNOUNCEMENT
    )
}

/// Handle one input-block frame. The caller has already established that
/// `state.input_blocks.is_some()`; with the subsystem off the frame falls
/// through to the unknown-opcode arm and is ignored, exactly like any
/// other code this node does not speak.
pub(in crate::node) fn handle(
    state: &mut NodeState,
    peer: PeerId,
    code: u8,
    payload: &[u8],
    now: Instant,
) -> Dispatched {
    match code {
        message::CODE_INPUT_BLOCK => match message::deserialize_input_block(payload) {
            Ok(ann) => {
                let Ok(id) = ann.id() else {
                    debug!(peer = %peer, "input_blocks: announcement header has no id");
                    return Dispatched::nothing();
                };
                let block_id = *id.as_bytes();
                let parent = *ann.header.parent_id.as_bytes();
                answered(state, &peer, &block_id);
                let actions = feed(state, peer, now, &[parent], |from, tick| {
                    Event::AnnouncementAccepted {
                        ann,
                        from,
                        now: tick,
                    }
                });
                // An announcement is always progress: it is chain
                // information we did not have, whether or not we asked.
                Dispatched {
                    actions,
                    progress: true,
                }
            }
            Err(e) => {
                warn!(peer = %peer, error = %e, "bad InputBlock announcement");
                Dispatched::penalize(peer)
            }
        },
        message::CODE_INPUT_BLOCK_TX_IDS => {
            match message::deserialize_input_block_tx_ids(payload) {
                Ok(d) => {
                    let progress = answered(state, &peer, &d.input_block_id);
                    let actions = feed(state, peer, now, &[], |from, tick| {
                        Event::TransactionIdsDelivered {
                            input_block_id: d.input_block_id,
                            weak_ids: d.weak_ids,
                            from,
                            now: tick,
                        }
                    });
                    Dispatched { actions, progress }
                }
                Err(e) => {
                    warn!(peer = %peer, error = %e, "bad InputBlockTransactionIds");
                    Dispatched::penalize(peer)
                }
            }
        }
        message::CODE_INPUT_BLOCK_TXS => match message::deserialize_input_block_txs(payload) {
            Ok(d) => {
                let progress = answered(state, &peer, &d.input_block_id);
                let bodies: Vec<Body> = d.transactions.into_iter().filter_map(body_of).collect();
                let actions = feed(state, peer, now, &[], |from, tick| {
                    Event::TransactionsDelivered {
                        input_block_id: d.input_block_id,
                        bodies,
                        from: Some(from),
                        now: tick,
                    }
                });
                Dispatched { actions, progress }
            }
            Err(e) => {
                warn!(peer = %peer, error = %e, "bad InputBlockTransactions");
                Dispatched::penalize(peer)
            }
        },
        message::CODE_INPUT_BLOCK_TXS_REQUEST => {
            match message::deserialize_input_block_txs_request(payload) {
                Ok(req) => {
                    let actions = serve::serve_transactions(state, peer, &req);
                    // Asking costs nothing; being served does. Same rule
                    // the generic `RequestModifier` arm applies.
                    let progress = !actions.is_empty();
                    Dispatched { actions, progress }
                }
                Err(e) => {
                    warn!(peer = %peer, error = %e, "bad RequestInputBlockTransactions");
                    Dispatched::penalize(peer)
                }
            }
        }
        message::CODE_ORDERING_BLOCK_ANNOUNCEMENT => {
            match message::deserialize_ordering_block_announcement_msg(payload) {
                Ok(ann) => {
                    let parent = *ann.header.parent_id.as_bytes();
                    // Acknowledge the −121 expectation this answers, so
                    // the request does not stay outstanding forever and
                    // `register_expectation`'s duplicate suppression
                    // does not refuse to ask anyone else for it.
                    answered(state, &peer, &ts_header_id(&ann.header));
                    let actions = feed(state, peer, now, &[parent], |from, tick| {
                        Event::OrderingAnnouncementAccepted {
                            ann,
                            from,
                            now: tick,
                        }
                    });
                    Dispatched {
                        actions,
                        progress: true,
                    }
                }
                Err(e) => {
                    warn!(peer = %peer, error = %e, "bad OrderingBlockAnnouncement");
                    Dispatched::penalize(peer)
                }
            }
        }
        _ => Dispatched::nothing(),
    }
}

/// Serve a `RequestModifier` carrying an input-block family type.
pub(in crate::node) fn serve_modifier_request(
    state: &NodeState,
    peer: PeerId,
    type_id: u8,
    ids: &[[u8; 32]],
) -> Vec<Action> {
    serve::serve_request_modifier(state, peer, type_id, ids)
}

/// An `Inv` advertising ordering-block announcements (type −121).
///
/// Parity with Scala's `Inv` path: ask for the ones whose header we do
/// not already have, and only from a peer that speaks the protocol. A
/// header we hold needs no announcement — the announcement exists to let
/// a peer rebuild a block it is missing.
pub(in crate::node) fn handle_ordering_inv(
    state: &mut NodeState,
    peer: PeerId,
    inv: &InvData,
    now: Instant,
) -> Vec<Action> {
    if state.input_blocks.is_none() {
        return Vec::new();
    }
    if inv.type_id != ModifierTypeId::OrderingBlockAnnouncement.as_byte() {
        return Vec::new();
    }
    if !peer_speaks_input_blocks(state, &peer) {
        debug!(peer = %peer, "input_blocks: ordering Inv from a peer below 6.5.0");
        return Vec::new();
    }
    let wanted: Vec<[u8; 32]> = inv
        .ids
        .iter()
        .copied()
        .filter(|id| !matches!(state.store.get_header(id), Ok(Some(_))))
        .collect();
    if wanted.is_empty() {
        return Vec::new();
    }
    super::super::tracked_request_modifier(
        state,
        peer,
        ModifierTypeId::OrderingBlockAnnouncement.as_byte(),
        &wanted,
        now,
    )
}

fn peer_speaks_input_blocks(state: &NodeState, peer: &PeerId) -> bool {
    state
        .peer_manager
        .get(peer)
        .and_then(|p| p.peer_spec.as_ref())
        .is_some_and(|spec| spec.version >= Version::SUBBLOCKS)
}

/// Release the delivery-tracker expectation this frame answers, and
/// report whether it answered one at all (spec 9.1's progress rule for
/// 102 / 104).
fn answered(state: &mut NodeState, peer: &PeerId, input_block_id: &[u8; 32]) -> bool {
    use ergo_p2p::delivery::DeliveryAction;
    let accept = state
        .coordinator
        .delivery()
        .on_received(input_block_id, peer)
        == DeliveryAction::Accept;
    if accept {
        state
            .coordinator
            .delivery_mut()
            .mark_received(input_block_id);
    }
    accept
}

/// Build the event, hand it to the processor, execute the effects.
fn feed(
    state: &mut NodeState,
    peer: PeerId,
    now: Instant,
    parent_ids: &[[u8; 32]],
    make: impl FnOnce(ergo_inputblocks::types::PeerTag, ergo_inputblocks::types::Tick) -> Event,
) -> Vec<Action> {
    let Some(mut rt) = state.input_blocks.take() else {
        return Vec::new();
    };
    let event = make(rt.tag(peer), rt.tick(now));
    let data = build_ctx_data(state, parent_ids);
    let effects = data.with(|ctx| rt.processor_mut().handle(event, ctx));
    drop(data);
    state.input_blocks = Some(rt);
    execute_effects(state, effects, now)
}

/// A header's modifier id. An ordering-block announcement is tracked by
/// its header id — that is the id a `RequestModifier` −121 carries.
fn ts_header_id(header: &ergo_ser::header::Header) -> [u8; 32] {
    ergo_ser::header::serialize_header(header)
        .map(|(_, id)| *id.as_bytes())
        .unwrap_or([0u8; 32])
}

/// A delivered transaction as a processor [`Body`]. `None` when the
/// transaction cannot be re-serialized or identified — the frame as a
/// whole still counts, the unusable body is simply dropped (the
/// processor's digest check then refuses the block).
fn body_of(tx: Transaction) -> Option<Body> {
    let mut w = VlqWriter::new();
    write_transaction(&mut w, &tx).ok()?;
    let bytes: std::sync::Arc<[u8]> = std::sync::Arc::from(w.result().into_boxed_slice());
    let tx_id = *transaction_id(&tx).ok()?.as_bytes();
    let wid = witness_id(&tx);
    Some(Body {
        tx_ref: TxRef {
            tx_id,
            witness_id: wid,
        },
        weak_id: weak_tx_id(&tx_id, &wid),
        bytes,
        tx,
    })
}
