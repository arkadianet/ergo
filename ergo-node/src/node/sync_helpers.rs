//! Anchor-aware SyncInfo dispatch, hedged RequestModifier fan-out, and
//! shared IBD auto-exit logic.
//!
//! Helpers shared by the action loop's sync paths:
//!
//! - `maybe_exit_ibd` — after a full block is applied, exit IBD durability
//!   mode once the full-block tip is within 10 of the header tip.
//! - `try_send_anchor_sync_info` — Step C+D crafted single-anchor V1
//!   SyncInfo for a peer, falling back to the standard tip-tail
//!   payload via the caller when the anchor path is not eligible.
//! - `hedge_request_modifiers` — duplicate `RequestModifier`
//!   actions to a few least-loaded hedge peers (registered as
//!   late-acceptable senders) so a slow primary can't stall a
//!   download window.

use ergo_p2p::message;
use ergo_p2p::peer::PeerId;
use ergo_state::{ChainStateRead, StateBackendKind};
use ergo_sync::coordinator::Action;
use std::time::Instant;
use tracing::info;

use super::{send_to_peer, NodeState};

/// Step C+D — try to send a crafted single-anchor SyncInfo to `peer`,
/// returning `true` if the anchor path was used. Falls through to
/// `false` (caller sends the standard `build_sync_info_payload`)
/// when the feature is disabled, the anchor map snapshot is
/// contended, or no eligible anchor is available above our tip.
///
/// Eligibility for the anchor path:
///   1. `enable_anchor_scheduler` flag is on,
///   2. `AnchorMap::try_verified_snapshot` returns `Some`,
///   3. `AnchorScheduler::assign_for_peer` returns `Some`.
///
/// **Step D change (vs the original v3 design doc):** the REST-
/// capability gate is dropped. The anchored SyncInfo is just a
/// crafted V1 message; Scala peers process it via
/// `compareV1`/`continuationIdsV1` regardless of whether THEY
/// advertise REST. REST is only needed for *building* the anchor
/// map (Step B), not for *consuming* it. Sending anchors to all
/// connected peers is the only way to hit the doc's "60 peers ×
/// 400 = 24,000 IDs in flight per round-trip" throughput ceiling
/// — restricting to 5-7 REST advertisers caps the gain at ~12% of
/// the design's potential.
///
/// On success, the V1 SyncInfo wire payload contains exactly one
/// header ID — the anchor — which Scala's `compareV1` /
/// `continuationIdsV1` interprets as a `Fork` request and answers
/// with up to `MaxInvObjects = 400` novel header IDs starting from
/// that anchor.
pub(super) fn try_send_anchor_sync_info(
    state: &mut NodeState,
    peer: &PeerId,
    now: Instant,
) -> bool {
    if !state.enable_anchor_scheduler {
        return false;
    }
    // **Bridge reservation**: a deterministic subset of the connected
    // peer set is held on the tip-tail SyncInfo path. This is
    // essential — an anchored peer responds with headers starting
    // AT the anchor (≥ our_tip + ANCHOR_INTERVAL above tip), so
    // without at least one bridge peer nobody ships the gap
    // `our_tip+1..our_tip+ANCHOR_INTERVAL-1` and the orphan buffer
    // accumulates parent-less headers indefinitely.
    //
    // Selection: rank every connected peer by a stable hash of its
    // socket address; the bottom `max(1, peer_count / 8)` peers by
    // hash are bridges. This guarantees AT LEAST ONE bridge peer
    // any time at least one peer is connected. A
    // `hash(peer) % 8 == 0` heuristic would deterministically yield
    // zero bridges with small or unlucky peer sets. Cost per call:
    // O(N log N) sort over ≤100 peers — negligible vs network IO.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let connected: Vec<PeerId> = state
        .peer_manager
        .connected_peers()
        .map(|p| p.addr)
        .collect();
    if connected.is_empty() {
        return false;
    }
    let bridges_needed = (connected.len() / 8).max(1);
    let mut hashed: Vec<(u64, PeerId)> = connected
        .iter()
        .map(|p| {
            let mut h = DefaultHasher::new();
            p.hash(&mut h);
            (h.finish(), *p)
        })
        .collect();
    hashed.sort_by_key(|(h, _)| *h);
    let is_bridge = hashed[..bridges_needed].iter().any(|(_, p)| p == peer);
    if is_bridge {
        return false;
    }
    let snapshot = match state.anchor_map.try_verified_snapshot() {
        Some(s) => s,
        None => return false,
    };
    let our_tip = state.store.chain_state_meta().best_header_height;
    let assignment = state
        .anchor_scheduler
        .assign_for_peer(*peer, our_tip, &snapshot, now);
    let (_h, anchor_id) = match assignment {
        Some(p) => p,
        None => return false,
    };
    // A single anchor id can never exceed the sync-info cap, so this
    // serialize is infallible in practice; on the unreachable error we
    // simply don't send (report "not sent") rather than emit a bad frame.
    match message::serialize_sync_info(&message::SyncInfo::V1 {
        header_ids: vec![anchor_id],
    }) {
        Ok(payload) => {
            send_to_peer(state, peer, message::CODE_SYNC_INFO, payload);
            true
        }
        Err(_) => false,
    }
}

/// Hedge `RequestModifier` dispatch. After `on_inv` registers
/// `primary` as the owner of the admitted IDs, duplicate the
/// `RequestModifier` action to `HEDGE_PEERS` additional peers chosen
/// by lowest in-flight count, and register them as hedge senders via
/// `delivery.register_hedge_peers`. Their responses will be accepted
/// via the `late_delivery_allowed` path; first valid delivery wins,
/// subsequent are `Ignore` (not `Spam`).
///
/// Resource cost: each hedge dispatch adds one `RequestModifier`
/// message + one `Modifier` response per hedge peer per ID set. With
/// HEDGE_PEERS=2 and ~400 IDs per Inv, that's 2× extra wire traffic
/// per Inv. Bounded by `MAX_IN_FLIGHT_PER_PEER` on the primary side
/// and natural socket back-pressure on hedge peers (their inflight
/// counts are NOT incremented for hedged registrations — acceptable
/// for the IBD case where hedge fanout is bursty, not sustained).
const HEDGE_PEERS: usize = 2;

pub(super) fn hedge_request_modifiers(
    state: &mut NodeState,
    actions: Vec<Action>,
    primary: PeerId,
) -> Vec<Action> {
    let mut out = Vec::with_capacity(actions.len() + actions.len() * HEDGE_PEERS);
    for action in actions {
        match &action {
            Action::SendToPeer {
                peer,
                code,
                payload,
            } if *code == message::CODE_REQUEST_MODIFIER && *peer == primary => {
                // Decode IDs from the RequestModifier payload (which is
                // an InvData wire form per Scala spec).
                if let Ok(inv) = ergo_p2p::message::deserialize_inv(payload) {
                    // Pick K hedge peers (least-loaded, excluding primary).
                    let hedge_peers = pick_hedge_peers(state, primary, HEDGE_PEERS);
                    if !hedge_peers.is_empty() {
                        // Register hedge peers as late-acceptable for
                        // these IDs so their responses Accept.
                        state
                            .coordinator
                            .delivery_mut()
                            .register_hedge_peers(&inv.ids, &hedge_peers);
                        // Emit a duplicate RequestModifier per hedge peer.
                        for hp in hedge_peers {
                            out.push(Action::SendToPeer {
                                peer: hp,
                                code: *code,
                                payload: payload.clone(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
        out.push(action);
    }
    out
}

/// Pick `n` peers from the connected set (excluding `exclude`) ranked
/// by lowest in-flight count. Less-loaded peers are likely faster to
/// respond, so the hedge race favours them.
fn pick_hedge_peers(state: &NodeState, exclude: PeerId, n: usize) -> Vec<PeerId> {
    let mut peers: Vec<(PeerId, usize)> = state
        .peer_manager
        .connected_peers()
        .map(|p| p.addr)
        .filter(|p| *p != exclude)
        .filter(|p| state.registry.peers.contains_key(p))
        .map(|p| (p, state.coordinator.delivery().inflight_count(&p)))
        .collect();
    peers.sort_by_key(|(_, cnt)| *cnt);
    peers.into_iter().take(n).map(|(p, _)| p).collect()
}

/// Exit IBD durability mode once the full-block tip is close to the header
/// tip.
///
/// IBD durability mode is a UTXO-arena flush-cadence knob; the digest
/// backend commits per-apply and has no IBD concept, so `as_utxo_mut()`
/// returns `None` and this becomes a no-op on digest stores while
/// `best_full_block_height` still advances normally.
///
/// The exit fires when all four hold:
///   - `fb` advanced from `fb_before` (a full block was actually applied),
///   - the arena is currently in IBD mode,
///   - `bh` is above genesis (`bh > 0`), and
///   - the gap `bh - fb` has dropped below 10 headers.
pub(super) fn maybe_exit_ibd(store: &mut StateBackendKind, fb_before: u32, fb: u32, bh: u32) {
    if let Some(u) = store.as_utxo_mut() {
        if fb > fb_before && u.ibd_mode() && bh > 0 && bh.saturating_sub(fb) < 10 {
            u.set_ibd_mode(false, 0);
            info!(gap = bh - fb, durability = "Immediate", "IBD complete",);
        }
    }
}
