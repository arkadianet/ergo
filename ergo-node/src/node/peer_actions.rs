//! Outbound peer plumbing: dial scheduler, action flushing, penalty
//! application, disconnect cleanup, and the channel-level send. Every
//! function here mutates [`NodeState`] under the action loop's
//! single-writer guarantee.

use std::time::{Duration, Instant};

use ergo_p2p::message;
use ergo_p2p::peer::{PeerId, Penalty, PenaltyOutcome};
use ergo_sync::coordinator::Action;
use tracing::{debug, warn};

use crate::peer_loop;

use super::NodeState;

/// Upper bound on concurrent dial attempts per dial cycle. Keeps the
/// initial fill-up from bursting too many SYNs at once when a large
/// batch of learned addresses lands. Sized a little above the Scala
/// reference node's per-tick budget so the larger outbound target
/// (`DEFAULT_TARGET_OUTBOUND = 96`) closes in a few 5s cycles without a
/// thundering herd.
const MAX_DIAL_ATTEMPTS_PER_CYCLE: usize = 32;

/// Upper bound on how many connected peers we fan a `GetPeers` request
/// to when the candidate pool is merely thin (non-empty but short of
/// this cycle's demand). A fully drained pool fans to every connected
/// peer instead — see [`getpeers_fanout`]. Kept small so a
/// well-connected node stays a polite gossip citizen.
const GOSSIP_FANOUT: usize = 3;

/// Once outbound deficit drops to or below this many slots, switch to
/// `DIAL_SLOW_PERIOD` between cycles. Above this threshold (cold start
/// / IBD) we dial on every 5s tick. Picked so that we stay aggressive
/// for the entire fill-up: at the default `target_outbound = 96` we
/// don't throttle until we have at least 88 outbound peers.
const DIAL_FAST_THRESHOLD: usize = 8;

/// Period between dial cycles once deficit ≤ `DIAL_FAST_THRESHOLD`.
/// Matches the original 30s cadence — gentle to the network in steady
/// state, where churn is rare.
const DIAL_SLOW_PERIOD: Duration = Duration::from_secs(30);

/// Minimum spacing between bootstrap-starved WARNs. A node whose every
/// known address is inside its dial-backoff window AND has no connected
/// peers has no discovery surface; without this gate the condition
/// would log once per 5s dial tick for as long as the drought lasts.
/// 5 minutes keeps a multi-hour starvation visible without spamming —
/// and the first occurrence always warns immediately.
const STARVE_WARN_INTERVAL: Duration = Duration::from_secs(300);

/// Whether this dial cycle may emit the bootstrap-starved WARN: first
/// sight always fires, repeats are suppressed until
/// [`STARVE_WARN_INTERVAL`] has elapsed since the previous one.
fn starve_warn_due(last_warn: Option<Instant>, now: Instant) -> bool {
    match last_warn {
        None => true,
        Some(t) => now.duration_since(t) >= STARVE_WARN_INTERVAL,
    }
}

/// Decide how many connected peers to fan a `GetPeers` request to this
/// dial cycle.
///
/// * `have` — dial candidates currently available.
/// * `want` — candidates this cycle would like (already capped at
///   `MAX_DIAL_ATTEMPTS_PER_CYCLE`).
/// * `connected` — eligible connected peers we could ask.
///
/// Returns:
/// * `0` when the pool is healthy (`have >= want`) — a node at capacity
///   never spams GetPeers (the periodic single-peer gossip still runs).
/// * `connected` when the pool is fully drained (`have == 0`) — the
///   dead-seed recovery case: ask everyone, we have nothing to lose.
/// * `min(connected, GOSSIP_FANOUT)` when the pool is thin — top it up
///   from a bounded set without spamming.
fn getpeers_fanout(have: usize, want: usize, connected: usize) -> usize {
    if have >= want {
        0
    } else if have == 0 {
        connected
    } else {
        connected.min(GOSSIP_FANOUT)
    }
}

/// Sync-S4: drive outbound connections up toward the PeerManager's
/// configured outbound target on each dial tick, rather than giving
/// up as soon as we have one peer. The base tick is 5s; the slow-mode
/// gate below throttles to one cycle per `DIAL_SLOW_PERIOD` once the
/// pool is nearly full.
pub(super) fn try_dial_peers(state: &mut NodeState) {
    try_dial_peers_at(state, Instant::now());
}

fn try_dial_peers_at(state: &mut NodeState, now: Instant) {
    // Periodic gossip: ask one random non-degraded connected peer
    // for its peer list every GOSSIP_INTERVAL, regardless of
    // outbound deficit. Mirrors Scala `PeerSynchronizer` so topology
    // drift (dead peers, new peers) gets detected even when the
    // pool is at capacity. Runs BEFORE the `deficit == 0`
    // early-return because a healthy node never reaches the dial
    // logic below.
    if now.duration_since(state.last_gossip_at) >= ergo_p2p::peer_manager::GOSSIP_INTERVAL {
        let seed = rand::RngCore::next_u64(&mut rand::rngs::OsRng);
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
    // Slightly overshoot normal demand to absorb immediate dial failures.
    let want = (deficit + 1).min(MAX_DIAL_ATTEMPTS_PER_CYCLE);
    let mut addrs = state.peer_manager.addresses_to_connect(now, want);
    let recovery = addrs.is_empty() && state.peer_manager.connected_count() == 0;
    // Recovery has its own cadence, independent of deficit and normal dials.
    // None fires immediately even when startup occurs in normal slow mode.
    if recovery {
        if state
            .last_recovery_dial_at
            .is_some_and(|last| now.duration_since(last) < DIAL_SLOW_PERIOD)
        {
            return;
        }
        addrs = state
            .peer_manager
            .addresses_for_recovery(now, want, state.recovery_dial_rotation);
        if !addrs.is_empty() {
            state.last_recovery_dial_at = Some(now);
            state.recovery_dial_rotation = state.recovery_dial_rotation.wrapping_add(1);
        }
    }
    // Steady-state throttle: when we're within DIAL_FAST_THRESHOLD
    // of the outbound target, only dial once per DIAL_SLOW_PERIOD.
    // The base 5s tick still fires; we just early-return from most
    // of them.
    if !recovery
        && deficit <= DIAL_FAST_THRESHOLD
        && now.duration_since(state.last_dial_at) < DIAL_SLOW_PERIOD
    {
        return;
    }
    // Past the throttle gate: stamp now so the next slow-mode tick
    // measures from this attempt regardless of whether we end up
    // firing dials or fanning a GetPeers (both are valid "we did
    // work" paths).
    state.last_dial_at = now;
    // Top up the candidate pool by asking connected peers for their peer
    // lists whenever ours is thin relative to this cycle's demand — not
    // only when it is fully drained. Firing on "thin" (not just "empty")
    // closes the large-deficit / few-candidates gap on cold start and
    // after churn; `getpeers_fanout` bounds how many peers we ask so a
    // node near capacity never spams GetPeers. A fully drained pool still
    // fans to everyone (the dead-seed recovery path that fixed a prod
    // incident where dead seeds pinned peer count at 3–4). Guarded on the
    // thin condition so a healthy pool skips the connected-peer scan and
    // allocation entirely.
    if addrs.len() < want {
        let gossip_targets: Vec<_> = state
            .peer_manager
            .connected_peers()
            .map(|p| p.addr)
            .filter(|addr| state.registry.peers.contains_key(addr))
            .collect();
        let fanout = getpeers_fanout(addrs.len(), want, gossip_targets.len());
        if fanout > 0 {
            // Rotate the start offset so we don't keep hitting the same
            // leading peers each cycle — spreads discovery load and pulls a
            // more diverse address set over time. `fanout <= len`, so the
            // wrapped window still yields distinct peers.
            let start =
                (rand::RngCore::next_u64(&mut rand::rngs::OsRng) as usize) % gossip_targets.len();
            for addr in gossip_targets.iter().cycle().skip(start).take(fanout) {
                send_to_peer(state, addr, message::CODE_GET_PEERS, Vec::new());
            }
            debug!(
                deficit = deficit,
                have = addrs.len(),
                want = want,
                fanned_to_peers = fanout,
                "dial tick: candidate pool thin, fanned GetPeers",
            );
        }
    }

    let mut recovery_attempts = 0;
    for addr in addrs {
        let registered = if recovery {
            state.peer_manager.register_recovery_outbound(addr, now)
        } else {
            state.peer_manager.register_outbound(addr, now)
        };
        match registered {
            Ok(()) => {
                if recovery {
                    recovery_attempts += 1;
                }
                debug!(peer = %addr, deficit = deficit, recovery, "attempting dial");
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
    if recovery && starve_warn_due(state.last_starve_warn_at, now) {
        state.last_starve_warn_at = Some(now);
        warn!(
            deficit,
            known_addresses = state.peer_manager.known_addresses_len(),
            recovery_dials = recovery_attempts,
            "peer bootstrap starved: no normal dial candidates and no connected peers; attempting recovery dials"
        );
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

pub(super) fn flush_actions(state: &mut NodeState, mut actions: Vec<Action>) {
    for id in state.executor.take_failed_transactions() {
        let evictions = state
            .mempool
            .invalidate(ergo_mempool::TxId::from_bytes(id), Instant::now());
        actions.extend(super::admission::route_mempool_actions(state, evictions));
    }
    actions.extend(super::block_relay::applied_block_announcements(state, None));
    let now = Instant::now();
    // Fold any first-deliverer observations the coordinator accumulated
    // during the just-completed execute batch into the bounded ring. The
    // coordinator records `(header_id, peer)` in `on_header_validated`
    // (the spot where both the header id and the delivering peer are
    // known); draining here — after every execute path — keeps the ring
    // current without scattering the drain across each `execute_all`
    // call site. The ring keeps only the FIRST deliverer per id and is
    // FIFO-bounded; pure observability, no sync/consensus effect. Cheap
    // when nothing accumulated (an empty-Vec swap).
    for (header_id, peer) in state.coordinator.take_first_deliverers() {
        state.first_deliverer_ring.record(header_id, peer, now);
    }
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
                if code == message::CODE_SYNC_INFO
                    && super::sync_helpers::popow_blocks_sync_info(state)
                {
                    continue;
                }
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
                } else if code == message::CODE_SYNC_INFO {
                    // Scala `lastSyncSentTime` parity, stamped on
                    // TRANSPORT DISPATCH success (registry accepted the
                    // frame). Not action construction, and not a claim
                    // of peer receipt — no acknowledgment exists at this
                    // layer. Serialization failures never construct an
                    // action; connection closure / full channel fail the
                    // dispatch above and leave the timestamp untouched so
                    // the next inbound SyncInfo retries the reply.
                    state.coordinator.sync_state_mut().mark_sync_sent(peer, now);
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
    if state.peer_manager.is_banned(&peer, now) {
        cleanup_banned_ip(state, peer.ip(), now);
        return;
    }
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

pub(super) fn cleanup_banned_ip(state: &mut NodeState, ip: std::net::IpAddr, now: Instant) {
    let peers: Vec<_> = state
        .registry
        .peers
        .keys()
        .filter(|peer| peer.ip() == ip)
        .copied()
        .collect();
    let mut actions = Vec::new();
    for peer in peers {
        actions.extend(state.executor.on_peer_disconnected(
            &peer,
            &mut state.coordinator,
            &state.peer_manager,
            now,
        ));
        cleanup_disconnected_peer(state, &peer);
    }
    flush_actions(state, actions);
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
    // Step B2: drop this peer's REST-url rejection-warn rows too, so a
    // churned address cannot accumulate stale entries in the bounded
    // warn set (logging-audit review follow-up).
    state.rest_url_reject_warned.retain_peer(peer);
    // Step C: release any anchor claims this peer was holding so
    // the slots are immediately available to other peers (rather
    // than waiting out `ANCHOR_REASSIGN_TIMEOUT`).
    state.anchor_scheduler.forget_peer(*peer);
}

pub(super) fn send_to_peer(state: &NodeState, peer: &PeerId, code: u8, payload: Vec<u8>) -> bool {
    state.registry.try_send(peer, code, payload)
}

#[cfg(test)]
mod tests {
    use super::{getpeers_fanout, starve_warn_due, GOSSIP_FANOUT, STARVE_WARN_INTERVAL};
    use std::time::{Duration, Instant};

    #[test]
    fn healthy_pool_asks_no_one() {
        // have >= want → never gossip when the pool already covers demand.
        assert_eq!(getpeers_fanout(32, 32, 100), 0);
        assert_eq!(getpeers_fanout(40, 32, 100), 0);
    }

    #[test]
    fn drained_pool_asks_everyone() {
        // have == 0 → dead-seed recovery: fan to every connected peer.
        assert_eq!(getpeers_fanout(0, 32, 5), 5);
        assert_eq!(getpeers_fanout(0, 32, 0), 0);
    }

    #[test]
    fn thin_pool_asks_bounded_set() {
        // 0 < have < want → cap the fan-out at GOSSIP_FANOUT...
        assert_eq!(getpeers_fanout(3, 32, 100), GOSSIP_FANOUT);
        // ...but never more peers than are actually connected.
        assert_eq!(getpeers_fanout(3, 32, 2), 2);
    }

    #[test]
    fn starve_warn_fires_on_first_sight_then_gates() {
        let now = Instant::now();
        // First starved cycle always warns...
        assert!(starve_warn_due(None, now));
        // ...repeats inside the interval are suppressed...
        let soon = now + Duration::from_secs(60);
        assert!(!starve_warn_due(Some(now), soon));
        // ...and the warn re-fires once the interval has elapsed.
        let later = now + STARVE_WARN_INTERVAL;
        assert!(starve_warn_due(Some(now), later));
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use ergo_p2p::address_book::AddressBook;
    use ergo_p2p::peer_manager::{PeerLimits, PeerManager, PeerOrigin};
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn starved_state(
        dir: &std::path::Path,
        target: usize,
    ) -> (NodeState, Arc<AddressBook>, Vec<SocketAddr>) {
        let mut state = crate::node::tests::make_state(&dir.join("state.redb"));
        state.peer_manager = PeerManager::new_with_limits(
            0,
            PeerLimits {
                target_outbound: target,
                ..PeerLimits::default()
            },
        );
        let book = Arc::new(AddressBook::open_at(&dir.join("peers.redb")).unwrap());
        state.peer_manager.set_address_book(book.clone());
        let now = Instant::now();
        let addrs: Vec<SocketAddr> = (1..=8)
            .map(|i| format!("127.{i}.0.1:1").parse().unwrap())
            .collect();
        for addr in &addrs {
            state
                .peer_manager
                .add_known_address(*addr, PeerOrigin::Seed);
            for _ in 0..5 {
                state.peer_manager.mark_dial_failed(addr, now);
            }
        }
        (state, book, addrs)
    }

    fn fail_batch(state: &mut NodeState, addrs: &[SocketAddr]) {
        let events = addrs
            .iter()
            .filter(|addr| state.peer_manager.get(addr).is_some())
            .map(|addr| crate::peer_loop::PeerEvent::ConnectFailed { addr: *addr })
            .collect();
        crate::node::events::handle_event_batch(state, events);
    }

    // Current-thread tests never yield: spawned dial tasks cannot run, so
    // these exercise the scheduler and event paths without network traffic.
    #[tokio::test(flavor = "current_thread")]
    async fn recovery_first_cycle_is_immediate_and_batch_is_four() {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, _, addrs) = starved_state(dir.path(), 8);
        let now = Instant::now();
        state.last_dial_at = now; // Inside the normal slow-mode cooldown.
        try_dial_peers_at(&mut state, now);
        assert_eq!(state.peer_manager.peer_count(), 4);
        assert_eq!(state.last_recovery_dial_at, Some(now));
        assert_eq!(state.last_starve_warn_at, Some(now));
        for addr in &addrs[..4] {
            assert!(state.peer_manager.get(addr).is_some());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recovery_batches_are_limited_to_once_per_thirty_seconds_and_rotate() {
        let dir = tempfile::tempdir().unwrap();
        // Large deficit normally dials every 5s; recovery still waits 30s.
        let (mut state, _, addrs) = starved_state(dir.path(), 96);
        let now = Instant::now();
        try_dial_peers_at(&mut state, now);
        assert_eq!(state.peer_manager.peer_count(), 4);
        fail_batch(&mut state, &addrs);
        for secs in [0, 5, 10, 20, 29] {
            try_dial_peers_at(&mut state, now + Duration::from_secs(secs));
            assert_eq!(state.peer_manager.peer_count(), 0, "early batch at {secs}s");
        }
        try_dial_peers_at(&mut state, now + DIAL_SLOW_PERIOD);
        assert_eq!(state.peer_manager.peer_count(), 4);
        assert!(
            state.peer_manager.get(&addrs[4]).is_some(),
            "ties must rotate"
        );
        assert!(state.peer_manager.get(&addrs[0]).is_none());
        assert_eq!(
            state.last_starve_warn_at,
            Some(now),
            "WARN stays rate limited"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recovery_is_disabled_with_a_connected_peer_even_without_registry_entry() {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, _, addrs) = starved_state(dir.path(), 96);
        let now = Instant::now();
        state.peer_manager.register_outbound(addrs[0], now).unwrap();
        state.peer_manager.mark_tcp_connected(&addrs[0]);
        state
            .peer_manager
            .complete_handshake(&addrs[0], state.our_handshake.peer_spec.clone(), None, now)
            .unwrap();
        try_dial_peers_at(&mut state, now);
        assert_eq!(state.peer_manager.peer_count(), 1);
        assert_eq!(state.last_recovery_dial_at, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recovery_is_disabled_with_a_normal_candidate_and_normal_failure_escalates() {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, book, _) = starved_state(dir.path(), 96);
        let normal: SocketAddr = "127.0.20.1:1".parse().unwrap();
        state
            .peer_manager
            .add_known_address(normal, PeerOrigin::Seed);
        try_dial_peers_at(&mut state, Instant::now());
        assert_eq!(state.peer_manager.peer_count(), 1);
        assert!(state.peer_manager.get(&normal).is_some());
        assert_eq!(state.last_recovery_dial_at, None);
        fail_batch(&mut state, &[normal]);
        let loaded = book.load_all(false).unwrap();
        assert_eq!(
            loaded
                .peers
                .iter()
                .find(|p| p.addr == normal)
                .unwrap()
                .consecutive_failures,
            1
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recovery_connect_failed_event_preserves_persisted_backoff() {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, book, addrs) = starved_state(dir.path(), 96);
        let before = book.load_all(false).unwrap();
        try_dial_peers_at(&mut state, Instant::now());
        assert_eq!(state.peer_manager.peer_count(), 4);
        fail_batch(&mut state, &addrs);
        assert_eq!(state.peer_manager.peer_count(), 0);
        let after = book.load_all(false).unwrap();
        for old in before.peers {
            let new = after.peers.iter().find(|p| p.addr == old.addr).unwrap();
            assert_eq!(new.consecutive_failures, old.consecutive_failures);
            assert_eq!(new.last_failure, old.last_failure);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recovery_timeout_preserves_backoff_instead_of_escalating() {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, book, _) = starved_state(dir.path(), 96);
        let now = Instant::now();
        try_dial_peers_at(&mut state, now);
        assert_eq!(state.peer_manager.peer_count(), 4);
        crate::node::sync_tick::handle_sync_tick_at(&mut state, now + Duration::from_secs(6));
        assert_eq!(state.peer_manager.peer_count(), 0);
        assert!(book
            .load_all(false)
            .unwrap()
            .peers
            .iter()
            .all(|p| p.consecutive_failures == 5));
    }
}
