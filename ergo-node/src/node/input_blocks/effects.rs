//! Effect executor: `ergo-inputblocks` effects → node actions, mempool
//! calls and pipeline handoffs (spec 7.2, 7.6, 9.1-9.2).
//!
//! | Effect | Node action |
//! |---|---|
//! | `RequestInputBlock` | `RequestModifier` (22) with `Inv` type −123 |
//! | `RequestTransactionIds` | `RequestModifier` (22) with `Inv` type −122 |
//! | `RequestTransactions` | `RequestInputBlockTransactions` (105) |
//! | `RequestOrderingHeader` | `RequestModifier` (22) with `Inv` type 101 |
//! | `RequestBlockTransactions` | `RequestModifier` (22) with `Inv` type 102, id = the stored header's `transactions_root` |
//! | `Validate` | run INLINE, feed `Event::ValidationResult` back, execute its effects |
//! | `ChainChanged` | restore rolled-back bodies, then apply; route the `MempoolAction`s |
//! | `RelayAnnouncement` | `InputBlock` (100) to every relay-eligible peer |
//! | `RelayOrderingInv` | `Inv` (55) type −121 to every relay-eligible peer |
//! | `Penalize` | `Action::Penalize { Misbehavior }` + `warn!` |
//! | `OrderingReconstruct` | Task 5 (counted + logged, no-op here) |
//! | `Dropped` | bump the per-reason counter, `debug!` |

use std::collections::VecDeque;
use std::time::Instant;

use ergo_inputblocks::processor::{Body, DropReason, Effect, Event};
use ergo_inputblocks::types::{InputBlockId, OrderingId, PeerTag};
use ergo_mempool::input_blocks::{RestoreBody, RestoreOutcome};
use ergo_p2p::handshake::{PeerFeature, Version};
use ergo_p2p::message;
use ergo_p2p::peer::{PeerId, Penalty};
use ergo_p2p::types::{InvData, ModifierTypeId};
use ergo_primitives::digest::Digest32;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_sync::coordinator::Action;
use tracing::{debug, warn};

use super::super::admission::route_mempool_actions;
use super::super::NodeState;
use super::ctx::build_ctx_data;
use super::runtime::InputBlocksRuntime;
use super::validate::{run_validation, ValidateJob};

/// Peers whose reported height may differ from ours by at most this much
/// and still be worth relaying an input block to (spec 9.2's ±2 window —
/// an input block is only actionable at `best_full_block_height + 1`).
const RELAY_HEIGHT_WINDOW: u32 = 2;

/// Translate `effects` into node actions, applying every mempool and
/// pipeline side effect on the way. A no-op returning no actions when the
/// runtime is absent (`[input_blocks] enabled = false`).
pub(in crate::node) fn execute_effects(
    state: &mut NodeState,
    effects: Vec<Effect>,
    now: Instant,
) -> Vec<Action> {
    // Take the runtime out of the state for the duration: the `Validate`
    // arm needs `&NodeState` (to read the store) AND `&mut Processor` at
    // the same time, and the `ChainChanged` arm needs `&mut NodeState`.
    let Some(mut rt) = state.input_blocks.take() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut queue: VecDeque<Effect> = effects.into();
    // `Validate` pushes the effects of the `ValidationResult` it feeds
    // back onto this queue. The processor keeps exactly one job in flight
    // (spec 7.4), so each round emits at most one further `Validate` and
    // the loop drains.
    while let Some(effect) = queue.pop_front() {
        execute_one(state, &mut rt, effect, now, &mut out, &mut queue);
    }
    state.input_blocks = Some(rt);
    out
}

fn execute_one(
    state: &mut NodeState,
    rt: &mut InputBlocksRuntime,
    effect: Effect,
    now: Instant,
    out: &mut Vec<Action>,
    queue: &mut VecDeque<Effect>,
) {
    match effect {
        Effect::RequestInputBlock { id, from } => {
            request_modifier(state, rt, from, ModifierTypeId::InputBlock, id, out);
        }
        Effect::RequestTransactionIds {
            input_block_id,
            from,
        } => {
            request_modifier(
                state,
                rt,
                from,
                ModifierTypeId::InputBlockTransactionIds,
                input_block_id,
                out,
            );
        }
        Effect::RequestTransactions {
            input_block_id,
            weak_ids,
            from,
        } => {
            let Some(peer) = resolve(rt, from, "RequestTransactions") else {
                return;
            };
            let payload =
                message::serialize_input_block_txs_request(&message::InputBlockTxsRequest {
                    input_block_id,
                    weak_ids,
                });
            out.push(Action::SendToPeer {
                peer,
                code: message::CODE_INPUT_BLOCK_TXS_REQUEST,
                payload,
            });
        }
        Effect::RequestOrderingHeader { header_id, from } => {
            request_modifier(state, rt, from, ModifierTypeId::Header, header_id, out);
        }
        Effect::RequestBlockTransactions { header_id, from } => {
            // The section's modifier id is the header's transactions root,
            // so the header must be stored before we can ask for its body.
            let Some(section_id) = transactions_section_id(state, &header_id) else {
                debug!(
                    header = %hex::encode(header_id),
                    "input_blocks: cannot request block transactions, header not stored"
                );
                return;
            };
            request_modifier(
                state,
                rt,
                from,
                ModifierTypeId::BlockTransactions,
                section_id,
                out,
            );
        }
        Effect::Validate {
            job,
            generation,
            input_block_id,
            txs,
            previous,
        } => {
            let job = ValidateJob {
                job,
                generation,
                input_block_id,
                txs,
                previous,
            };
            let outcome = run_validation(state, rt, &job);
            match &outcome {
                Ok(cost) => debug!(
                    block = %hex::encode(job.input_block_id),
                    cost, "input_blocks: validation passed"
                ),
                Err(reason) => debug!(
                    block = %hex::encode(job.input_block_id),
                    %reason, "input_blocks: validation failed"
                ),
            }
            let data = build_ctx_data(state, &[]);
            let follow_on = data.with(|ctx| {
                rt.processor_mut().handle(
                    Event::ValidationResult {
                        job: job.job,
                        generation: job.generation,
                        outcome,
                    },
                    ctx,
                )
            });
            queue.extend(follow_on);
        }
        Effect::ChainChanged {
            ordering_id,
            applied,
            rolled_back,
        } => {
            let applied_bodies = bodies_for(rt, &applied);
            let rolled_back_bodies = bodies_for(rt, &rolled_back);
            debug!(
                ordering = %hex::encode(ordering_id),
                applied = applied.len(),
                rolled_back = rolled_back.len(),
                "input_blocks: best input chain changed"
            );
            out.extend(apply_chain_change(
                state,
                rt,
                &applied_bodies,
                &rolled_back_bodies,
                now,
            ));
            // Task 7 publishes `/info.bestInputBlock` from
            // `rt.processor().best_input_block()` through the identity slot.
        }
        Effect::RelayAnnouncement { id } => {
            // The processor emits this ONLY for a block announced under
            // `PeerTag::LOCAL` (spec 9.2 item 7, Scala parity), so
            // `[input_blocks] relay_remote` cannot be honoured at this
            // layer — enabling remote relay is a processor-side change.
            let Some(ann) = rt.processor().announcement(&id) else {
                debug!(block = %hex::encode(id), "input_blocks: relay of an unknown announcement");
                return;
            };
            let payload = match message::serialize_input_block(ann) {
                Ok(p) => p,
                Err(e) => {
                    warn!(block = %hex::encode(id), error = %e, "input_blocks: announcement does not serialize");
                    return;
                }
            };
            for peer in relay_peers(state) {
                out.push(Action::SendToPeer {
                    peer,
                    code: message::CODE_INPUT_BLOCK,
                    payload: payload.clone(),
                });
            }
        }
        Effect::RelayOrderingInv { header_id } => {
            let inv = InvData {
                type_id: ModifierTypeId::OrderingBlockAnnouncement.as_byte(),
                ids: vec![header_id],
            };
            let payload = match message::serialize_inv(&inv) {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "input_blocks: ordering Inv does not serialize");
                    return;
                }
            };
            for peer in relay_peers(state) {
                out.push(Action::SendToPeer {
                    peer,
                    code: message::CODE_INV,
                    payload: payload.clone(),
                });
            }
        }
        Effect::Penalize { from, reason } => {
            let Some(peer) = resolve(rt, from, "Penalize") else {
                return;
            };
            warn!(%peer, reason, "input_blocks: penalizing peer for an invalid announcement");
            out.push(Action::Penalize {
                peer,
                penalty: Penalty::Misbehavior,
            });
        }
        Effect::OrderingReconstruct { plan } => {
            // Task 5 builds the `BlockTransactions` section from the plan
            // and hands it to the ordinary block pipeline (spec 9.3).
            debug!(
                ordering = %hex::encode(plan.header_id),
                "input_blocks: ordering reconstruction not wired yet (task 5)"
            );
        }
        Effect::Dropped { id, reason } => {
            rt.counters.bump(&reason);
            debug!(id = %hex::encode(id), ?reason, "input_blocks: dropped");
        }
    }
}

/// `RequestModifier` (code 22) for one id of one modifier type.
fn request_modifier(
    state: &NodeState,
    rt: &InputBlocksRuntime,
    from: PeerTag,
    type_id: ModifierTypeId,
    id: [u8; 32],
    out: &mut Vec<Action>,
) {
    let Some(peer) = resolve(rt, from, "RequestModifier") else {
        return;
    };
    if !state.registry.peers.contains_key(&peer) {
        debug!(%peer, "input_blocks: request dropped, peer is no longer connected");
        return;
    }
    let inv = InvData {
        type_id: type_id.as_byte(),
        ids: vec![id],
    };
    match message::serialize_inv(&inv) {
        Ok(payload) => out.push(Action::SendToPeer {
            peer,
            code: message::CODE_REQUEST_MODIFIER,
            payload,
        }),
        Err(e) => warn!(error = %e, "input_blocks: RequestModifier does not serialize"),
    }
}

fn resolve(rt: &InputBlocksRuntime, tag: PeerTag, what: &'static str) -> Option<PeerId> {
    match rt.peer(tag) {
        Some(p) => Some(p),
        None => {
            debug!(
                tag = tag.0,
                what, "input_blocks: effect names an unknown peer tag"
            );
            None
        }
    }
}

fn transactions_section_id(state: &NodeState, header_id: &OrderingId) -> Option<[u8; 32]> {
    let bytes = state.store.get_header(header_id).ok().flatten()?;
    let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
    let header = ergo_ser::header::read_header(&mut r).ok()?;
    Some(*header.transactions_root.as_bytes())
}

/// The bodies each named block holds, as far as the processor's cache
/// still has them. A block whose bodies were evicted contributes an empty
/// list rather than failing the whole chain change — the mempool half is
/// best-effort bookkeeping, not consensus.
fn bodies_for(rt: &InputBlocksRuntime, ids: &[InputBlockId]) -> Vec<(InputBlockId, Vec<Body>)> {
    ids.iter()
        .map(|id| {
            let bodies = rt
                .processor()
                .bodies(id)
                .map(|bs| bs.into_iter().cloned().collect())
                .unwrap_or_default();
            (*id, bodies)
        })
        .collect()
}

/// Spec 7.6 / §8: restore the rolled-back input blocks' bodies into the
/// mempool FIRST, then remove the applied ones — so a transaction present
/// in both ends up removed (parity with Scala's put-then-remove order).
pub(in crate::node) fn apply_chain_change(
    state: &mut NodeState,
    rt: &mut InputBlocksRuntime,
    applied: &[(InputBlockId, Vec<Body>)],
    rolled_back: &[(InputBlockId, Vec<Body>)],
    now: Instant,
) -> Vec<Action> {
    let mut mempool_actions = Vec::new();

    // ---- restore ----
    for (id, cached) in rolled_back {
        let retained = rt.retained.remove(id).unwrap_or_default();
        let mut bodies: Vec<RestoreBody> = Vec::with_capacity(retained.len() + cached.len());
        let mut seen: std::collections::HashSet<Digest32> = std::collections::HashSet::new();
        // Entries this node itself evicted carry their previously computed
        // validation cost; Scala's `put` reuses it rather than the fake cost.
        for entry in retained {
            if seen.insert(entry.tx_id) {
                bodies.push((entry.tx_id, entry.bytes.clone(), Some(entry.cost)));
            }
        }
        // Scala restores the rolled-back block's cached bodies whether or
        // not they were ever pooled, so the ones we never evicted are
        // restored too — with no retained cost.
        for body in cached {
            let tx_id = Digest32::from_bytes(body.tx_ref.tx_id);
            if seen.insert(tx_id) {
                bodies.push((tx_id, body.bytes.clone(), None));
            }
        }
        if bodies.is_empty() {
            continue;
        }
        for outcome in state.mempool.restore_input_block_txs(&bodies, now) {
            match outcome {
                RestoreOutcome::Restored(_) => {}
                other => debug!(
                    block = %hex::encode(id),
                    ?other,
                    "input_blocks: rolled-back body not restored"
                ),
            }
        }
    }

    // ---- apply ----
    for (id, bodies) in applied {
        if bodies.is_empty() {
            continue;
        }
        let txs: Vec<ergo_ser::transaction::Transaction> =
            bodies.iter().map(|b| b.tx.clone()).collect();
        match state.mempool.apply_input_block_txs(&txs) {
            Ok((removed, actions)) => {
                if !removed.is_empty() {
                    rt.retained.insert(*id, removed);
                }
                mempool_actions.extend(actions);
            }
            Err(e) => warn!(
                block = %hex::encode(id),
                error = ?e,
                "input_blocks: apply to the mempool failed, pool left untouched"
            ),
        }
    }

    route_mempool_actions(state, mempool_actions)
}

/// Peers worth relaying an input block / ordering announcement to:
/// protocol version ≥ 6.5.0, UTXO mode, and a reported height within
/// ±[`RELAY_HEIGHT_WINDOW`] of our best full block.
///
/// Both capability facts degrade OPEN: a peer that advertised no `Mode`
/// feature, and a peer whose height we have not learned (a V2 SyncInfo
/// peer with no overlap yet), are treated as eligible. Relaying to a peer
/// that cannot use the message costs one small frame; silently never
/// relaying because a fact is missing costs propagation.
fn relay_peers(state: &NodeState) -> Vec<PeerId> {
    let our_height = state.store.chain_state_meta().best_full_block_height;
    let snapshots = state.coordinator.peer_sync_snapshots();
    let mut peers: Vec<PeerId> = state
        .peer_manager
        .connected_peers()
        .filter(|p| state.registry.peers.contains_key(&p.addr))
        .filter(|p| match &p.peer_spec {
            Some(spec) => {
                spec.version >= Version::SUBBLOCKS
                    && spec.features.iter().all(|f| {
                        // Only a Mode feature that explicitly says "digest"
                        // disqualifies; an absent Mode feature does not.
                        !matches!(f, PeerFeature::Mode { state_type: 1, .. })
                    })
            }
            None => false,
        })
        .filter(
            |p| match snapshots.get(&p.addr).and_then(|s| s.peer_height) {
                Some(h) => h.abs_diff(our_height) <= RELAY_HEIGHT_WINDOW,
                None => true,
            },
        )
        .map(|p| p.addr)
        .collect();
    peers.sort();
    peers
}

/// Telemetry helper for the effect arms that only count. Kept so the
/// `DropReason` import stays honest if the arms above are refactored.
#[allow(dead_code)]
fn count_only(rt: &mut InputBlocksRuntime, reason: DropReason) {
    rt.counters.bump(&reason);
}
