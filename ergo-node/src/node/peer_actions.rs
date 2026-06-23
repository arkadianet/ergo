//! Outbound peer plumbing: dial scheduler, action flushing, penalty
//! application, disconnect cleanup, and the channel-level send. Every
//! function here mutates [`NodeState`] under the action loop's
//! single-writer guarantee.

use std::time::{Duration, Instant};

use ergo_p2p::message;
use ergo_p2p::peer::{PeerId, Penalty, PenaltyOutcome};
use ergo_sync::coordinator::Action;
use tracing::debug;

use crate::peer_loop;

use super::NodeState;

/// Upper bound on concurrent dial attempts per dial cycle. Keeps the
/// initial fill-up from bursting too many SYNs at once when a large
/// batch of learned addresses lands. Matches the per-tick concurrency
/// budget the Scala reference node uses for its 5s connection
/// scheduler.
const MAX_DIAL_ATTEMPTS_PER_CYCLE: usize = 24;

/// Once outbound deficit drops to or below this many slots, switch to
/// `DIAL_SLOW_PERIOD` between cycles. Above this threshold (cold start
/// / IBD) we dial on every 5s tick. Picked so that we stay aggressive
/// for the entire fill-up: at the default `target_outbound=75` we
/// don't throttle until we have at least 67 outbound peers.
const DIAL_FAST_THRESHOLD: usize = 8;

/// Period between dial cycles once deficit ≤ `DIAL_FAST_THRESHOLD`.
/// Matches the original 30s cadence — gentle to the network in steady
/// state, where churn is rare.
const DIAL_SLOW_PERIOD: Duration = Duration::from_secs(30);

/// Sync-S4: drive outbound connections up toward the PeerManager's
/// configured outbound target on each dial tick, rather than giving
/// up as soon as we have one peer. The base tick is 5s; the slow-mode
/// gate below throttles to one cycle per `DIAL_SLOW_PERIOD` once the
/// pool is nearly full.
pub(super) fn try_dial_peers(state: &mut NodeState) {
    let now = Instant::now();

    // Periodic gossip: ask one random non-degraded connected peer
    // for its peer list every GOSSIP_INTERVAL, regardless of
    // outbound deficit. Mirrors Scala `PeerSynchronizer` so topology
    // drift (dead peers, new peers) gets detected even when the
    // pool is at capacity. Runs BEFORE the `deficit == 0`
    // early-return because a healthy node never reaches the dial
    // logic below.
    if now.duration_since(state.last_gossip_at) >= ergo_p2p::peer_manager::GOSSIP_INTERVAL {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        if let Some(peer) = state.peer_manager.select_peer_for_gossip(now, seed) {
            if state.registry.peers.contains_key(&peer) {
                send_to_peer(state, &peer, message::CODE_GET_PEERS, Vec::new());
                debug!(peer = %peer, "periodic gossip GetPeers");
            }
        }
        state.last_gossip_at = now;
    }

    let deficit = state.peer_manager.outbound_deficit();
    if deficit == 0 {
        return;
    }
    // Steady-state throttle: when we're within DIAL_FAST_THRESHOLD
    // of the outbound target, only dial once per DIAL_SLOW_PERIOD.
    // The base 5s tick still fires; we just early-return from most
    // of them.
    if deficit <= DIAL_FAST_THRESHOLD && now.duration_since(state.last_dial_at) < DIAL_SLOW_PERIOD {
        return;
    }
    // Past the throttle gate: stamp now so the next slow-mode tick
    // measures from this attempt regardless of whether we end up
    // firing dials or fanning a GetPeers (both are valid "we did
    // work" paths).
    state.last_dial_at = now;
    // Overshoot the deficit slightly to absorb dials that fail
    // immediately, but cap at the per-cycle budget.
    let want = (deficit + 1).min(MAX_DIAL_ATTEMPTS_PER_CYCLE);
    let addrs = state.peer_manager.addresses_to_connect(now, want);
    if addrs.is_empty() {
        // Deficit > 0 but we have no candidate addresses. Ask an
        // existing peer for more via GetPeers; its response hits
        // the CODE_PEERS handler which populates known_addresses.
        let peers: Vec<_> = state
            .peer_manager
            .connected_peers()
            .map(|p| p.addr)
            .filter(|addr| state.registry.peers.contains_key(addr))
            .collect();
        for addr in &peers {
            send_to_peer(state, addr, message::CODE_GET_PEERS, Vec::new());
        }
        if !peers.is_empty() {
            debug!(
                deficit = deficit,
                fanned_to_peers = peers.len(),
                "dial tick: no known candidates, fanned GetPeers",
            );
        }
        return;
    }
    for addr in addrs {
        match state.peer_manager.register_outbound(addr, now) {
            Ok(()) => {
                debug!(peer = %addr, deficit = deficit, "attempting dial");
                tokio::spawn(peer_loop::dial_task(
                    addr,
                    state.magic,
                    state.our_handshake.clone(),
                    state.event_tx.clone(),
                ));
            }
            Err(e) => {
                debug!(peer = %addr, error = %e, "cannot register outbound dial");
            }
        }
    }
}

/// `POST /peers/connect` (Scala `ConnectTo`): one-shot dial of the
/// operator-supplied address with the standard dial idiom — and NOTHING
/// persisted up front. Scala writes no peer record before handshake
/// success and removes the peer on dial failure; here, success persists
/// via the normal handshake path and a failed dial leaves no residue
/// (no address-book entry, no redial schedule). Deliberately NOT
/// `add_known_address`: a Seed-origin entry would be retained and
/// re-dialed forever, turning a typo'd address into permanent dial
/// noise and the endpoint into a (key-gated) address-book poisoning
/// vector.
pub(super) fn connect_to_address(state: &mut NodeState, addr: std::net::SocketAddr) {
    let now = Instant::now();
    match state.peer_manager.register_outbound(addr, now) {
        Ok(()) => {
            debug!(peer = %addr, "operator /peers/connect dial");
            tokio::spawn(peer_loop::dial_task(
                addr,
                state.magic,
                state.our_handshake.clone(),
                state.event_tx.clone(),
            ));
        }
        Err(e) => {
            // Already connected / already dialing / at capacity — the
            // route already answered 200 (fire-and-forget, Scala parity).
            debug!(peer = %addr, error = %e, "operator dial not registered");
        }
    }
}

pub(super) fn flush_actions(state: &mut NodeState, actions: Vec<Action>) {
    let now = Instant::now();
    // Count RequestModifier messages AND their ID payloads
    // separately. Messages = how many SendToPeer(RequestModifier)
    // actions we're about to emit. IDs = how many sections we're
    // actually asking the peer for. Under bucketed multi-peer
    // (Sync-S1), messages ≫ what a single-peer caller would
    // expect, but IDs is still the real demand figure.
    let mut req_msg_count: u32 = 0;
    let mut req_id_count: u32 = 0;
    let mut batch_peer_set: std::collections::BTreeSet<std::net::SocketAddr> = Default::default();
    for action in &actions {
        if let Action::SendToPeer {
            peer,
            code,
            payload,
        } = action
        {
            if *code == message::CODE_REQUEST_MODIFIER {
                req_msg_count += 1;
                batch_peer_set.insert(*peer);
                if let Ok(inv) = message::deserialize_inv(payload) {
                    req_id_count += inv.ids.len() as u32;
                }
            }
        }
    }
    if req_msg_count > 0 {
        state.req_messages_total += req_msg_count as u64;
        state.req_ids_total += req_id_count as u64;
        let n_peers = batch_peer_set.len();
        if n_peers == 1 {
            let p = batch_peer_set.iter().next().unwrap();
            debug!(
                msgs = req_msg_count,
                ids = req_id_count,
                peer = %p,
                "GetData",
            );
        } else if n_peers > 1 {
            debug!(
                msgs = req_msg_count,
                ids = req_id_count,
                peers = n_peers,
                "GetData (multi-peer)",
            );
        }
    }
    for action in actions {
        match action {
            #[allow(clippy::collapsible_match)]
            Action::SendToPeer {
                peer,
                code,
                payload,
            } => {
                // Negative branch only — the failure path runs all
                // the recovery work; collapsing into a match guard
                // would require an explicit empty arm for the
                // success case.
                if !send_to_peer(state, &peer, code, payload) {
                    // Channel full → disconnect + flush recovery actions
                    let disc_actions = state.executor.on_peer_disconnected(
                        &peer,
                        &mut state.coordinator,
                        &state.peer_manager,
                        now,
                    );
                    state.peer_manager.disconnect(&peer);
                    cleanup_disconnected_peer(state, &peer);
                    flush_actions(state, disc_actions);
                }
            }
            Action::Penalize { peer, penalty } => {
                penalize_peer(state, peer, penalty, now);
            }
            Action::NoteDeliveryOutcome { peer, succeeded } => {
                state.peer_manager.note_delivery_outcome(&peer, succeeded);
            }
            _ => {} // ValidateHeader, PersistSection, AssembleBlock handled by executor
        }
    }
}

pub(super) fn penalize_peer(state: &mut NodeState, peer: PeerId, penalty: Penalty, now: Instant) {
    let outcome = state.peer_manager.penalize(&peer, penalty, now);
    let removed_from_manager = state.peer_manager.get(&peer).is_none();
    if outcome != PenaltyOutcome::Banned && !removed_from_manager {
        return;
    }

    // PeerManager removes banned peers immediately. Keep the
    // runtime registry and delivery tracker in lockstep or the node
    // keeps showing phantom peers and may leave their in-flight
    // requests stuck until a later timeout cycle.
    if !state.registry.peers.contains_key(&peer) {
        return;
    }
    let recovery_actions = state.executor.on_peer_disconnected(
        &peer,
        &mut state.coordinator,
        &state.peer_manager,
        now,
    );
    cleanup_disconnected_peer(state, &peer);
    flush_actions(state, recovery_actions);
}

pub(super) fn cleanup_disconnected_peer(state: &mut NodeState, peer: &PeerId) {
    state.registry.remove(peer);
    state.mempool.on_peer_disconnected(peer);
    state.throttle.forget_peer(peer);
    state.snapshot_bootstrap.on_peer_disconnect(peer);
    if let Some(ca) = state.chunk_assembly.as_mut() {
        let _freed = ca.drop_peer(peer);
        // Freed subtree IDs naturally re-enter `next_to_request`
        // on the next sync_tick; nothing further to do here.
    }
    // Step B: drop the peer's REST URL so the anchor builder stops
    // querying it. Best-effort — if the lock is poisoned we leak
    // one entry, capped by max_connections.
    if let Ok(mut g) = state.rest_peer_urls.write() {
        g.remove(peer);
    }
    // Step C: release any anchor claims this peer was holding so
    // the slots are immediately available to other peers (rather
    // than waiting out `ANCHOR_REASSIGN_TIMEOUT`).
    state.anchor_scheduler.forget_peer(*peer);
}

pub(super) fn send_to_peer(state: &NodeState, peer: &PeerId, code: u8, payload: Vec<u8>) -> bool {
    state.registry.try_send(peer, code, payload)
}
