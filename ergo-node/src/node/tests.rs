use super::sync_helpers::try_send_anchor_sync_info;
use super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use ergo_crypto::difficulty::DifficultyParams;
use ergo_mempool::types::MempoolConfig;
use ergo_mempool::{weight, Mempool};
use ergo_p2p::handshake::{Handshake, PeerSpec, Version};
use ergo_p2p::message;
use ergo_p2p::peer::{Penalty, SyncVersion};
use ergo_p2p::peer_manager::PeerManager;
use ergo_p2p::throttle::ThroughputLimiter;
use ergo_p2p::types::{InvData, ModifierTypeId};
use ergo_state::store::StateStore;
use ergo_state::HeaderSectionStore;
use ergo_sync::coordinator::{Action, SyncCoordinator};
use ergo_sync::executor::SyncExecutor;
use ergo_validation::ProtocolParams;
use tokio::sync::mpsc;

use crate::anchor_map::{self, RestPeers};
use crate::anchor_scheduler::AnchorScheduler;
use crate::notifier::MempoolNotifier;
use crate::peer_loop::PeerEvent;

use super::identity::build_api_identity;
use super::peer_actions::flush_actions;
use super::state::PeerRegistry;
use super::sync_tick::{handle_sync_tick, handle_sync_tick_at};

fn test_peer() -> SocketAddr {
    "127.0.0.1:9999".parse().unwrap()
}

fn mid(n: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[31] = n;
    id
}

pub(super) fn make_state(db_path: &Path) -> NodeState {
    let store = StateStore::open(db_path).unwrap();
    make_state_with_store(store)
}

/// Same as [`make_state`], but takes an already-configured `StateStore`
/// (e.g. one with genesis + a NiPoPoW proof already applied) rather than
/// opening a fresh one. Lets `sync_tick`'s own test module reuse its
/// `popow_sparse_store` fixture to drive a real `NodeState` through Mode 4
/// install-phase scenarios (`resolve_install_anchor` gaps) without
/// duplicating the whole `NodeState` construction.
pub(super) fn make_state_with_store(store: StateStore) -> NodeState {
    make_state_with_backend(
        ergo_state::StateBackendKind::Utxo(store),
        crate::config::StateType::Utxo,
        MempoolConfig::default(),
    )
}

/// Open a fresh Mode-5 digest-verifier backend on `db_path`, using the
/// same `DigestStateStore::open` call as `boot.rs`'s digest arm. A
/// digest `NodeState`'s `as_utxo()`/`as_utxo_mut()` both return `None`,
/// which is what the digest-mode survival fixes guard against.
///
/// Production force-disables the mempool for any digest mode (admission
/// needs UTXO box bytes — see `config::mempool_must_force_disable`), so
/// this pins `enabled = false` to match the real Mode-5 posture rather
/// than fabricating an impossible digest-with-live-mempool node.
pub(super) fn make_digest_state(db_path: &Path) -> NodeState {
    make_digest_state_with_mempool_config(db_path, false)
}

/// Same digest backend as [`make_digest_state`], parameterized on the
/// mempool's `enabled` flag. `mempool_enabled = true` is an
/// impossible-in-production combination (`config::mempool_must_force_disable`
/// prevents it at boot) — used ONLY to exercise `handle_mempool_tick`'s
/// post-boot degrade guard: it must log-and-skip rather than panic if
/// this invariant is ever violated.
pub(super) fn make_digest_state_with_mempool_config(
    db_path: &Path,
    mempool_enabled: bool,
) -> NodeState {
    let store = ergo_state::DigestStateStore::open(
        db_path,
        ergo_validation::scala_launch(),
        ergo_chain_spec::VotingParams {
            voting_length: 2,
            ..ergo_chain_spec::VotingParams::mainnet()
        },
        [0u8; 33], // EMPTY_AVL_DIGEST — a fresh digest store seeds from it
    )
    .unwrap();
    let mempool_cfg = MempoolConfig {
        enabled: mempool_enabled,
        ..MempoolConfig::default()
    };
    make_state_with_backend(
        ergo_state::StateBackendKind::Digest(store),
        crate::config::StateType::Digest,
        mempool_cfg,
    )
}

fn make_state_with_backend(
    backend: ergo_state::StateBackendKind,
    state_type: crate::config::StateType,
    mempool_cfg: MempoolConfig,
) -> NodeState {
    let coordinator = SyncCoordinator::new(0);
    let executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let peer_manager = PeerManager::new(0);
    let (event_tx, _rx) = mpsc::channel::<PeerEvent>(4);
    let mempool = Mempool::new(mempool_cfg, weight::from_config("cost").unwrap());
    NodeState {
        store: backend,
        shadow: None,
        last_reorg_enrichment: None,
        coordinator,
        executor,
        peer_manager,
        registry: PeerRegistry::new(),
        event_tx,
        event_byte_budget: crate::peer_loop::new_event_byte_budget(),
        magic: [0u8; 4],
        our_handshake: Handshake {
            time: 0,
            peer_spec: PeerSpec {
                agent_name: "test".into(),
                version: Version::CURRENT,
                node_name: "test".into(),
                declared_address: None,
                features: vec![],
            },
        },
        mempool,
        mempool_notifier: MempoolNotifier::new(),
        mempool_gate_broken: false,
        throttle: ThroughputLimiter::with_defaults(),
        last_seen_active_params: ergo_validation::scala_launch(),
        last_seen_validation_settings: ergo_validation::ErgoValidationSettings::empty(),
        snapshot_publisher: None,
        identity_inputs: crate::node::identity::IdentityInputs {
            state_type,
            verify_transactions: true,
            blocks_to_keep: -1,
            keep_versions: ergo_state::store::ROLLBACK_WINDOW,
            utxo_bootstrap: false,
            nipopow_bootstrap: false,
            mining_enabled: false,
            extra_index_enabled: false,
            declared_addr: None,
            bind_addr: None,
        },
        identity_slot: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
            ergo_api::types::ApiIdentity::default(),
        )),
        last_beat: Instant::now(),
        last_beat_emit: Instant::now(),
        last_beat_progress_emit: Instant::now(),
        last_beat_height: 0,
        last_beat_headers: 0,
        req_messages_total: 0,
        req_ids_total: 0,
        sections_received_total: 0,
        mempool_tx_requested_total: 0,
        mempool_peer_tx_admitted_total: 0,
        mempool_peer_tx_rejected_total: 0,
        last_beat_req_messages: 0,
        last_beat_req_ids: 0,
        last_beat_sections_received: 0,
        last_dial_at: Instant::now(),
        last_gossip_at: Instant::now(),
        last_starve_warn_at: None,
        indexer_handle: None,
        anchor_map: anchor_map::AnchorMap::new(),
        rest_peer_urls: std::sync::Arc::new(std::sync::RwLock::new(RestPeers::new())),
        rest_url_reject_warned: Default::default(),
        anchor_builder_cancel_tx: tokio::sync::watch::channel(false).0,
        anchor_scheduler: AnchorScheduler::new(),
        enable_anchor_scheduler: false,
        sync_interval: ergo_p2p::sync::DEFAULT_SYNC_INTERVAL,
        sync_interval_stable: ergo_p2p::sync::DEFAULT_SYNC_INTERVAL_STABLE,
        last_sync_broadcast: Instant::now(),
        anchor_tip_cursor: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
        snapshot_state: super::snapshot_state::SnapshotState::new(),
        snapshot_bootstrap: ergo_sync::snapshot_bootstrap::SnapshotBootstrap::new(),
        popow_bootstrap: None,
        utxo_bootstrap_enabled: false,
        chunk_assembly: None,
        reconstructed_tree: None,
        pending_manifest_bytes: None,
        bootstrap_started_unix_ms: None,
        bootstrap_was_active_this_session: false,
        installed_snapshot: None,
        snapshot_anchor_refusal_warned: false,
        wallet_hook: None,
        mining_enabled: false,
        mined_apply_failed_parent: None,
        api_publicly_bound: false,
        api_weight_function: ergo_api::types::ApiWeightFunction::Cost,
        recent_blocks_cache: None,
        network: ergo_ser::address::NetworkPrefix::Mainnet,
        first_deliverer_ring: crate::node::first_deliverer::FirstDelivererRing::new(),
        event_feed: crate::node::event_feed::EventFeedRing::new(),
        event_feed_prev: crate::node::event_feed::FeedPrev::default(),
        reorg_history: crate::node::reorg_history::ReorgHistory::new(),
        event_feed_projection: None,
        reorg_history_projection: None,
    }
}

fn req_modifier_payload(type_id: u8, ids: &[[u8; 32]]) -> Vec<u8> {
    message::serialize_inv(&InvData {
        type_id,
        ids: ids.to_vec(),
    })
    .unwrap()
}

fn assert_modifier_response(actions: &[Action], expected_type_id: u8, expected_ids: &[[u8; 32]]) {
    assert_eq!(actions.len(), 1, "expected 1 action, got {}", actions.len());
    let Action::SendToPeer { code, payload, .. } = &actions[0] else {
        panic!("expected SendToPeer, got {:?}", actions[0]);
    };
    assert_eq!(*code, message::CODE_MODIFIER);
    let modifiers = message::deserialize_modifiers(payload).unwrap();
    assert_eq!(modifiers.type_id, expected_type_id);
    let returned: Vec<[u8; 32]> = modifiers.modifiers.iter().map(|(id, _)| *id).collect();
    assert_eq!(returned.len(), expected_ids.len(), "wrong modifier count");
    for id in expected_ids {
        assert!(returned.contains(id), "missing id in response: {:?}", id);
    }
}

#[test]
fn penalty_ban_cleans_registry_peer() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();

    state.peer_manager.register_outbound(peer, now).unwrap();
    state.peer_manager.mark_tcp_connected(&peer);
    state
        .peer_manager
        .complete_handshake(&peer, state.our_handshake.peer_spec.clone(), None, now)
        .unwrap();
    let (tx, _rx) = crate::peer_loop::outbound::channel(1);
    state.registry.peers.insert(
        peer,
        PeerRuntime {
            sync_version: SyncVersion::V2,
            outbound_tx: tx,
        },
    );

    let mut t = now;
    for _ in 0..30 {
        t += ergo_p2p::peer::SAFE_INTERVAL;
        state.peer_manager.penalize(&peer, Penalty::Spam, t);
    }

    flush_actions(
        &mut state,
        vec![Action::Penalize {
            peer,
            penalty: Penalty::Spam,
        }],
    );

    assert_eq!(state.peer_manager.peer_count(), 0);
    assert!(!state.registry.peers.contains_key(&peer));
}

#[test]
fn request_header_mixed_present_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));

    let h1 = mid(1);
    let h2 = mid(2);
    let missing = mid(99);
    state.store.store_header(&h1, &[0xAA; 80]).unwrap();
    state.store.store_header(&h2, &[0xBB; 80]).unwrap();

    let payload = req_modifier_payload(ModifierTypeId::Header.as_byte(), &[h1, missing, h2]);
    let actions = handle_message(
        &mut state,
        test_peer(),
        message::CODE_REQUEST_MODIFIER,
        &payload,
        Instant::now(),
    );

    assert_modifier_response(&actions, ModifierTypeId::Header.as_byte(), &[h1, h2]);
}

#[test]
fn request_block_section_mixed_present_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));

    let s1 = mid(1);
    let s2 = mid(2);
    let missing = mid(99);
    state
        .store
        .as_utxo()
        .expect("utxo-only: block-section store test runs in UTXO mode")
        .store_block_section(&s1, &[0xCC; 200])
        .unwrap();
    state
        .store
        .as_utxo()
        .expect("utxo-only: block-section store test runs in UTXO mode")
        .store_block_section(&s2, &[0xDD; 200])
        .unwrap();

    let payload = req_modifier_payload(
        ModifierTypeId::BlockTransactions.as_byte(),
        &[s1, missing, s2],
    );
    let actions = handle_message(
        &mut state,
        test_peer(),
        message::CODE_REQUEST_MODIFIER,
        &payload,
        Instant::now(),
    );

    assert_modifier_response(
        &actions,
        ModifierTypeId::BlockTransactions.as_byte(),
        &[s1, s2],
    );
}

/// P2 observability: an inbound tx-typed `Inv` advertising ids we don't
/// already have must (a) bump `mempool_tx_requested_total` by the number of
/// `unknown` (not-pooled, not-invalidated) ids and (b) emit a
/// `RequestModifier` for them. The counter is the always-on aggregate
/// surfaced via `/metrics`; this pins the increment seam in
/// `handle_message`'s tx-Inv→request branch.
#[test]
fn tx_inv_increments_requested_counter_and_requests_unknown() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    assert_eq!(state.mempool_tx_requested_total, 0);

    let ids = [mid(1), mid(2), mid(3)];
    let payload = message::serialize_inv(&InvData {
        type_id: ModifierTypeId::Transaction.as_byte(),
        ids: ids.to_vec(),
    })
    .unwrap();

    let actions = handle_message(
        &mut state,
        test_peer(),
        message::CODE_INV,
        &payload,
        Instant::now(),
    );

    // All three ids are unknown (empty pool, nothing invalidated), so the
    // counter advances by 3 and a RequestModifier is emitted for them.
    assert_eq!(state.mempool_tx_requested_total, 3);
    assert_eq!(actions.len(), 1, "expected a RequestModifier action");
    let Action::SendToPeer { code, .. } = &actions[0] else {
        panic!("expected SendToPeer, got {:?}", actions[0]);
    };
    assert_eq!(*code, message::CODE_REQUEST_MODIFIER);
}

/// P2 (accuracy): re-advertising tx ids that are ALREADY in-flight must not
/// re-bump `mempool_tx_requested_total`. The coordinator dedupes the second
/// Inv's ids against in-flight delivery state and emits no RequestModifier,
/// so the counter — which is supposed to track ids ACTUALLY requested — must
/// stay put. Pins the fix where the increment uses the post-dedupe count
/// returned by `request_transactions`, not the advertised `unknown.len()`.
/// Fail-first against the old `unknown.len()` increment, which double-counted
/// the second Inv (counter would reach 6, not 3).
#[test]
fn tx_inv_does_not_recount_already_in_flight_ids() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    assert_eq!(state.mempool_tx_requested_total, 0);

    let ids = [mid(1), mid(2), mid(3)];
    let payload = message::serialize_inv(&InvData {
        type_id: ModifierTypeId::Transaction.as_byte(),
        ids: ids.to_vec(),
    })
    .unwrap();
    let now = Instant::now();

    // First Inv: all three ids are unknown and get registered + requested.
    let first = handle_message(&mut state, test_peer(), message::CODE_INV, &payload, now);
    assert_eq!(state.mempool_tx_requested_total, 3);
    assert_eq!(first.len(), 1, "first Inv emits a RequestModifier");

    // Second Inv (same ids, still in-flight from the first): the coordinator
    // dedupes them all away, so nothing new is requested. The counter must
    // NOT advance and no RequestModifier is emitted.
    let second = handle_message(&mut state, test_peer(), message::CODE_INV, &payload, now);
    assert_eq!(
        state.mempool_tx_requested_total, 3,
        "in-flight ids must not be re-counted as requested",
    );
    assert!(
        second.is_empty(),
        "no RequestModifier for already-in-flight ids",
    );
}

/// P2: with the mempool disabled the tx-Inv branch returns early before the
/// `unknown` filter, so a tx-typed `Inv` neither advances the request
/// counter nor emits a request. Pins that the counter is scoped to the
/// genuine request path, not bumped unconditionally on every tx Inv.
#[test]
fn tx_inv_does_not_count_when_mempool_disabled() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state_with_backend(
        ergo_state::StateBackendKind::Utxo(
            StateStore::open(&tmp.path().join("state.redb")).unwrap(),
        ),
        crate::config::StateType::Utxo,
        MempoolConfig {
            enabled: false,
            ..MempoolConfig::default()
        },
    );

    let payload = message::serialize_inv(&InvData {
        type_id: ModifierTypeId::Transaction.as_byte(),
        ids: vec![mid(1), mid(2)],
    })
    .unwrap();

    let actions = handle_message(
        &mut state,
        test_peer(),
        message::CODE_INV,
        &payload,
        Instant::now(),
    );

    assert_eq!(
        state.mempool_tx_requested_total, 0,
        "a disabled mempool must not advance the request counter",
    );
    assert!(actions.is_empty(), "disabled mempool serves no tx request");
}

/// P2: the peer-tx admit/reject counters live in `admit_transaction`,
/// AFTER its tip-context gate. On a cold tip (`build_tip_context == None`,
/// the default fixture state — no full block applied) the path drops the tx
/// silently and must NOT touch either counter: a tx the node can't even
/// evaluate is neither an admit nor a reject.
///
/// Driving a real `Admitted` / `Rejected` outcome through this seam needs a
/// populated `block_context_headers` (set only by the block-apply path) plus
/// valid/invalid tx bytes against live UTXO state, which a `make_state`
/// fixture can't synthesize. The increment itself is a single
/// `saturating_add(1)` on each branch of the same `match &outcome` that
/// already drives the per-tx `debug!` traces (admission.rs), and the
/// SnapshotParts→ApiStatus plumbing is covered by
/// `snapshot::build_snapshot_carries_mempool_tx_gossip_counters`. This test
/// pins the gate: the counters stay at the seam, behind the tip check.
#[test]
fn peer_admit_counters_untouched_on_cold_tip() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    assert_eq!(state.mempool_peer_tx_admitted_total, 0);
    assert_eq!(state.mempool_peer_tx_rejected_total, 0);

    // Garbage tx bytes; on a cold tip admit_transaction returns before it
    // ever reaches Mempool::process, so neither counter moves.
    let actions = super::admit_transaction(&mut state, test_peer(), &[0xDE, 0xAD], Instant::now());

    assert!(
        actions.is_empty(),
        "cold-tip admit drops silently with no actions",
    );
    assert_eq!(
        state.mempool_peer_tx_admitted_total, 0,
        "cold-tip drop is not an admit",
    );
    assert_eq!(
        state.mempool_peer_tx_rejected_total, 0,
        "cold-tip drop is not a reject",
    );
}

#[test]
fn request_all_missing_returns_no_action() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));

    let payload = req_modifier_payload(ModifierTypeId::Header.as_byte(), &[mid(1), mid(2)]);
    let actions = handle_message(
        &mut state,
        test_peer(),
        message::CODE_REQUEST_MODIFIER,
        &payload,
        Instant::now(),
    );

    assert!(actions.is_empty(), "expected no actions, got {:?}", actions);
}

#[test]
fn request_unknown_type_id_returns_no_action() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));

    // type_id=99 has no known ModifierTypeId mapping — return empty, not a peer penalize
    let payload = req_modifier_payload(99, &[mid(1)]);
    let actions = handle_message(
        &mut state,
        test_peer(),
        message::CODE_REQUEST_MODIFIER,
        &payload,
        Instant::now(),
    );

    assert!(actions.is_empty(), "expected no actions, got {:?}", actions);
}

#[test]
fn unknown_inv_type_is_rejected_before_request_registration() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let id = mid(1);
    let payload = message::serialize_inv(&InvData {
        type_id: 100,
        ids: vec![id],
    })
    .unwrap();

    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_INV,
        &payload,
        Instant::now(),
    );

    assert!(actions.iter().any(|action| matches!(
        action,
        Action::Penalize {
            peer: penalized_peer,
            penalty: Penalty::Misbehavior,
        } if *penalized_peer == peer
    )));
    assert_eq!(
        state.coordinator.delivery().status(&id),
        ergo_p2p::delivery::ModifierStatus::Unknown
    );
    assert!(!actions
        .iter()
        .any(|action| matches!(action, Action::SendToPeer { .. })));
}

#[test]
fn unknown_modifier_type_is_rejected_before_delivery_mutation() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let id = mid(2);
    let now = Instant::now();
    assert_eq!(
        state
            .coordinator
            .delivery_mut()
            .request(peer, 100, &[id], now),
        vec![id]
    );
    let payload = message::serialize_modifiers(&ergo_p2p::types::ModifiersData {
        type_id: 100,
        modifiers: vec![(id, vec![1, 2, 3])],
    })
    .unwrap();

    let actions = handle_message(&mut state, peer, message::CODE_MODIFIER, &payload, now);

    assert!(actions.iter().any(|action| matches!(
        action,
        Action::Penalize {
            peer: penalized_peer,
            penalty: Penalty::Misbehavior,
        } if *penalized_peer == peer
    )));
    assert_eq!(
        state.coordinator.delivery().status(&id),
        ergo_p2p::delivery::ModifierStatus::Requested
    );
    assert!(!actions
        .iter()
        .any(|action| matches!(action, Action::PersistSection { .. })));
}

// ----- idle-peer progress gating (#247 item 9) -----

/// Register a handshaked, registry-backed peer so `evict_timed_out` and
/// `send_to_peer` both see it. The returned receiver must be held for the
/// duration of the test, otherwise the outbound channel reads as closed.
#[must_use]
pub(super) fn connect_test_peer(
    state: &mut NodeState,
    peer: SocketAddr,
    now: Instant,
) -> crate::peer_loop::outbound::Receiver {
    state.peer_manager.register_outbound(peer, now).unwrap();
    state.peer_manager.mark_tcp_connected(&peer);
    state
        .peer_manager
        .complete_handshake(&peer, state.our_handshake.peer_spec.clone(), None, now)
        .unwrap();
    let (tx, rx) = crate::peer_loop::outbound::channel(64);
    state.registry.peers.insert(
        peer,
        PeerRuntime {
            sync_version: SyncVersion::V2,
            outbound_tx: tx,
        },
    );
    rx
}

/// Mirror the `PeerEvent::Message` path in `events.rs`: every valid frame
/// touches, and `handle_message` decides whether it also counts as
/// progress.
fn deliver_frame(state: &mut NodeState, peer: SocketAddr, code: u8, payload: &[u8], now: Instant) {
    state.peer_manager.touch(&peer, now);
    let _ = handle_message(state, peer, code, payload, now);
}

/// Addresses evicted by `evict_timed_out`, dropping the state each was in.
fn evicted_addrs(state: &mut NodeState, now: Instant) -> Vec<SocketAddr> {
    state
        .peer_manager
        .evict_timed_out(now)
        .into_iter()
        .map(|(addr, _)| addr)
        .collect()
}

/// A `PeerSpec` that does or does not name an address we could dial.
fn peers_payload(with_declared_address: bool) -> Vec<u8> {
    let spec = PeerSpec {
        agent_name: "ergoref".to_string(),
        version: Version::NIPOPOW,
        node_name: "gossiped".to_string(),
        declared_address: with_declared_address.then(|| ergo_p2p::handshake::DeclaredAddress {
            addr: vec![203, 0, 113, 7],
            port: 9030,
        }),
        features: Vec::new(),
    };
    message::serialize_peers(&[spec])
}

/// Trickle `payload` at `every` for longer than the inactivity window,
/// then report whether the peer survived. One state per call so the cases
/// stay independent.
fn survives_trickle(dir: &Path, name: &str, code: u8, payload: &[u8], every: Duration) -> bool {
    let mut state = make_state(&dir.join(name));
    let peer = test_peer();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);

    let deadline = now + ergo_p2p::peer::INACTIVE_TIMEOUT + Duration::from_secs(60);
    let mut t = now;
    while t < deadline {
        t += every;
        deliver_frame(&mut state, peer, code, payload, t);
    }
    evicted_addrs(&mut state, t).is_empty()
}

/// A peer that trickles nothing but bare `GetPeers` keeps its `last_seen`
/// fresh yet makes no progress, so it must lose its slot once the
/// inactivity window elapses. Pre-fix this peer was immortal.
#[test]
fn keepalive_only_peer_is_evicted_after_inactive_window() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);

    let mut t = now;
    let deadline = now + ergo_p2p::peer::INACTIVE_TIMEOUT + Duration::from_secs(60);
    while t < deadline {
        t += Duration::from_secs(60);
        deliver_frame(&mut state, peer, message::CODE_GET_PEERS, &[], t);
    }

    assert_eq!(
        evicted_addrs(&mut state, t),
        vec![peer],
        "keepalive-only peer must be evicted",
    );
    assert_eq!(state.peer_manager.peer_count(), 0);
}

/// The honest-peer premise the whole change rests on: a Scala neighbour
/// sends `SyncInfo` to every connected peer at least once a minute
/// (`ErgoSyncTracker.scala:144-148`, `SyncThreshold = 1.minute`), so that
/// cadence alone must hold a slot indefinitely. This also pins the
/// interaction with the 100 ms per-peer sync lock time, whose early
/// `return` sits just above the `note_progress` call.
#[test]
fn sync_info_at_scala_cadence_keeps_peer() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);

    let payload = message::serialize_sync_info(&message::SyncInfo::V1 {
        header_ids: vec![mid(1)],
    })
    .unwrap();

    let mut t = now;
    let deadline = now + ergo_p2p::peer::INACTIVE_TIMEOUT * 3;
    while t < deadline {
        t += Duration::from_secs(60);
        deliver_frame(&mut state, peer, message::CODE_SYNC_INFO, &payload, t);
        assert!(
            evicted_addrs(&mut state, t).is_empty(),
            "a peer syncing at Scala's cadence must never be evicted",
        );
    }
}

/// ...but an *empty* `SyncInfo` is a legal 4-byte frame carrying no chain
/// information, so it must not hold the slot.
#[test]
fn empty_sync_info_is_not_progress() {
    let tmp = tempfile::tempdir().unwrap();
    let payload = message::serialize_sync_info(&message::SyncInfo::V1 {
        header_ids: Vec::new(),
    })
    .unwrap();
    assert!(
        !survives_trickle(
            tmp.path(),
            "state.redb",
            message::CODE_SYNC_INFO,
            &payload,
            Duration::from_secs(60),
        ),
        "an empty SyncInfo must not refresh the idle timer",
    );
}

/// `Peers` counts only when it gossips something dialable: an empty list
/// is as cheap as a keepalive, and so is a spec with no declared address.
#[test]
fn peers_reply_counts_only_with_a_dialable_entry() {
    let tmp = tempfile::tempdir().unwrap();

    assert!(
        !survives_trickle(
            tmp.path(),
            "empty.redb",
            message::CODE_PEERS,
            &message::serialize_peers(&[]),
            Duration::from_secs(60),
        ),
        "an empty Peers reply must not refresh the idle timer",
    );
    assert!(
        !survives_trickle(
            tmp.path(),
            "undialable.redb",
            message::CODE_PEERS,
            &peers_payload(false),
            Duration::from_secs(60),
        ),
        "a Peers entry with no declared address is not progress",
    );
    assert!(
        survives_trickle(
            tmp.path(),
            "dialable.redb",
            message::CODE_PEERS,
            &peers_payload(true),
            Duration::from_secs(60),
        ),
        "a Peers entry we could dial is progress",
    );
}

/// A `RequestModifier` counts only when we actually served something.
/// Asking costs the peer nothing; being served is the work.
#[test]
fn request_modifier_counts_only_when_served() {
    let tmp = tempfile::tempdir().unwrap();

    // Unserved: the header id is unknown to us.
    assert!(
        !survives_trickle(
            tmp.path(),
            "unserved.redb",
            message::CODE_REQUEST_MODIFIER,
            &req_modifier_payload(ModifierTypeId::Header.as_byte(), &[mid(1)]),
            Duration::from_secs(60),
        ),
        "requests we serve nothing for must not refresh the idle timer",
    );

    // Served: same request, but the header is in the store.
    let mut state = make_state(&tmp.path().join("served.redb"));
    let header_id = mid(1);
    state
        .store
        .store_header(&header_id, &[0xAAu8; 80])
        .expect("seed header");
    let peer = test_peer();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);

    let payload = req_modifier_payload(ModifierTypeId::Header.as_byte(), &[header_id]);
    let mut t = now;
    let deadline = now + ergo_p2p::peer::INACTIVE_TIMEOUT + Duration::from_secs(60);
    while t < deadline {
        t += Duration::from_secs(60);
        deliver_frame(
            &mut state,
            peer,
            message::CODE_REQUEST_MODIFIER,
            &payload,
            t,
        );
    }
    assert!(
        evicted_addrs(&mut state, t).is_empty(),
        "a request we served is progress",
    );
}

/// The clock restarts from the last progress frame, and only then does the
/// full window have to elapse.
#[test]
fn progress_frame_inside_window_keeps_peer() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);

    let payload = message::serialize_sync_info(&message::SyncInfo::V1 {
        header_ids: vec![mid(1)],
    })
    .unwrap();
    let progress_at = now + Duration::from_secs(500);
    deliver_frame(
        &mut state,
        peer,
        message::CODE_SYNC_INFO,
        &payload,
        progress_at,
    );

    assert!(
        evicted_addrs(&mut state, progress_at + ergo_p2p::peer::INACTIVE_TIMEOUT).is_empty(),
        "peer must be kept for a full window after its last progress",
    );
    assert_eq!(
        evicted_addrs(
            &mut state,
            progress_at + ergo_p2p::peer::INACTIVE_TIMEOUT + Duration::from_secs(1),
        ),
        vec![peer],
        "and evicted once that window elapses with no further progress",
    );
}

/// A handshaked peer evicted for making no progress is NOT a dial
/// failure: the address answered, handshaked, and stayed reachable, so
/// counting it would bump `consecutive_failures` and push a perfectly
/// dialable address down the ranking. A pre-handshake timeout still is a
/// dial failure and must still take the backoff.
#[test]
fn no_progress_eviction_does_not_take_dial_backoff() {
    let tmp = tempfile::tempdir().unwrap();
    let peer = test_peer();

    // Handshaked, then silent for longer than the inactivity window.
    let mut state = make_state(&tmp.path().join("handshaked.redb"));
    state
        .peer_manager
        .add_known_address(peer, ergo_p2p::peer_manager::PeerOrigin::Seed);
    let base = Instant::now();
    let now = base + ergo_p2p::peer::INACTIVE_TIMEOUT + Duration::from_secs(100);
    state.peer_manager.register_outbound(peer, base).unwrap();
    state.peer_manager.mark_tcp_connected(&peer);
    state
        .peer_manager
        .complete_handshake(&peer, state.our_handshake.peer_spec.clone(), None, base)
        .unwrap();

    handle_sync_tick_at(&mut state, now);

    assert_eq!(
        state.peer_manager.peer_count(),
        0,
        "stalled handshaked peer should have been evicted",
    );
    assert!(
        state
            .peer_manager
            .addresses_to_connect(now, 10)
            .contains(&peer),
        "a no-progress eviction must leave the address immediately dialable",
    );

    // Same address, but it never got past `Connecting`.
    let mut state = make_state(&tmp.path().join("connecting.redb"));
    state
        .peer_manager
        .add_known_address(peer, ergo_p2p::peer_manager::PeerOrigin::Seed);
    let base = Instant::now();
    let now = base + ergo_p2p::peer::CONNECT_TIMEOUT + Duration::from_secs(10);
    state.peer_manager.register_outbound(peer, base).unwrap();

    handle_sync_tick_at(&mut state, now);

    assert_eq!(
        state.peer_manager.peer_count(),
        0,
        "stalled dial should have been evicted",
    );
    assert!(
        !state
            .peer_manager
            .addresses_to_connect(now, 10)
            .contains(&peer),
        "a pre-handshake timeout is a dial failure and must take the backoff",
    );
}

// ----- mode 2 part 2f-2: inbound SnapshotsInfo + disconnect cleanup -----

fn snapshots_info_payload(manifests: &[(i32, [u8; 32])]) -> Vec<u8> {
    message::serialize_snapshots_info(&ergo_p2p::types::SnapshotsInfo {
        available_manifests: manifests.to_vec(),
    })
    .unwrap()
}

fn synthetic_peer(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
}

#[test]
fn inbound_snapshots_info_below_quorum_keeps_bootstrap_querying() {
    use ergo_sync::snapshot_bootstrap::BootstrapState;
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let payload = snapshots_info_payload(&[(52_224, mid(0xAA))]);

    for p in 1..=2u16 {
        let actions = handle_message(
            &mut state,
            synthetic_peer(p),
            message::CODE_SNAPSHOTS_INFO,
            &payload,
            Instant::now(),
        );
        assert!(actions.is_empty(), "no outbound action on SnapshotsInfo");
    }

    assert_eq!(
        state.snapshot_bootstrap.state(),
        BootstrapState::Querying,
        "2 votes < default quorum of 3 must stay Querying",
    );
}

#[test]
fn inbound_snapshots_info_at_quorum_advances_bootstrap_to_selected() {
    use ergo_sync::snapshot_bootstrap::BootstrapState;
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let payload = snapshots_info_payload(&[(52_224, mid(0xAA))]);

    for p in 1..=3u16 {
        handle_message(
            &mut state,
            synthetic_peer(p),
            message::CODE_SNAPSHOTS_INFO,
            &payload,
            Instant::now(),
        );
    }

    assert_eq!(
        state.snapshot_bootstrap.state(),
        BootstrapState::Selected {
            height: 52_224,
            manifest_id: mid(0xAA),
        },
    );
}

#[test]
fn malformed_snapshots_info_emits_misbehavior_penalty() {
    // A SnapshotsInfo payload claiming N entries but truncated
    // mid-list must trip the deserializer and trigger a peer
    // penalty — keeps the reducer from being fed garbage.
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));

    // Claim 100 entries but provide only 1 byte. VlqReader will fail.
    // VLQ count = 100, then a single truncated body byte.
    let bad = vec![100u8, 0u8];

    let actions = handle_message(
        &mut state,
        test_peer(),
        message::CODE_SNAPSHOTS_INFO,
        &bad,
        Instant::now(),
    );
    assert!(
        actions.iter().any(
            |a| matches!(a, Action::Penalize { penalty, .. } if *penalty == Penalty::Misbehavior)
        ),
        "malformed payload must trigger Misbehavior penalty; got {actions:?}",
    );
}

#[test]
fn peer_disconnect_drops_snapshot_bootstrap_vote() {
    use ergo_sync::snapshot_bootstrap::BootstrapState;
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let payload = snapshots_info_payload(&[(52_224, mid(0xAA))]);

    for p in 1..=3u16 {
        handle_message(
            &mut state,
            synthetic_peer(p),
            message::CODE_SNAPSHOTS_INFO,
            &payload,
            Instant::now(),
        );
    }
    assert!(matches!(
        state.snapshot_bootstrap.state(),
        BootstrapState::Selected { .. },
    ));

    // Disconnect one of the three voting peers — selection must
    // revert to Querying since quorum drops from 3 to 2.
    super::cleanup_disconnected_peer(&mut state, &synthetic_peer(3));
    assert_eq!(
        state.snapshot_bootstrap.state(),
        BootstrapState::Querying,
        "disconnect of the 3rd voter must revoke quorum",
    );
}

#[test]
fn inbound_manifest_rejects_malformed_bytes_before_latch() {
    use ergo_sync::snapshot_bootstrap::BootstrapState;

    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let height = 52_224i32;
    let manifest_id = mid(0xAA);
    for port in 1..=3u16 {
        state
            .snapshot_bootstrap
            .on_snapshots_info(synthetic_peer(port), &[(height, manifest_id)]);
    }
    let peer = synthetic_peer(1);
    state
        .snapshot_bootstrap
        .mark_manifest_requested(peer, height, manifest_id, Instant::now());

    let payload = message::serialize_manifest(&[0, 1]).unwrap();
    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_MANIFEST,
        &payload,
        Instant::now(),
    );

    assert!(
        matches!(actions.as_slice(), [Action::Penalize { peer: offender, .. }] if *offender == peer)
    );
    assert!(!matches!(
        state.snapshot_bootstrap.state(),
        BootstrapState::ManifestVerified { .. }
    ));
    assert!(state.chunk_assembly.is_none());
    assert!(state.pending_manifest_bytes.is_none());
    assert!(state.reconstructed_tree.is_none());
    assert!(state.snapshot_bootstrap.should_query(&synthetic_peer(2)));
}

#[test]
fn inbound_manifest_rejects_duplicate_expected_ids_before_latch() {
    use ergo_state::avl::snapshot_codec::{SnapshotServer, KEY_SIZE, LABEL_SIZE};
    use ergo_state::avl::tree::AvlTree;
    use ergo_sync::snapshot_bootstrap::BootstrapState;

    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let mut tree = AvlTree::new();
    for i in 0..8u8 {
        tree.insert([i + 0x10; 32], vec![i]);
    }
    let server = SnapshotServer::build(&tree, 52_224, 1).unwrap();
    let manifest_id = *server.manifest_id.as_bytes();
    let mut manifest = server.manifest_bytes.clone();
    let left_label = 2 + 1 + 1 + KEY_SIZE;
    let right_label = left_label + LABEL_SIZE;
    let left = manifest[left_label..left_label + LABEL_SIZE].to_vec();
    manifest[right_label..right_label + LABEL_SIZE].copy_from_slice(&left);

    for port in 1..=3u16 {
        state
            .snapshot_bootstrap
            .on_snapshots_info(synthetic_peer(port), &[(52_224, manifest_id)]);
    }
    let peer = synthetic_peer(1);
    state
        .snapshot_bootstrap
        .mark_manifest_requested(peer, 52_224, manifest_id, Instant::now());
    let payload = message::serialize_manifest(&manifest).unwrap();
    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_MANIFEST,
        &payload,
        Instant::now(),
    );

    assert!(
        matches!(actions.as_slice(), [Action::Penalize { peer: offender, .. }] if *offender == peer)
    );
    assert!(!matches!(
        state.snapshot_bootstrap.state(),
        BootstrapState::ManifestVerified { .. }
    ));
}

#[test]
fn inbound_manifest_rejects_same_root_with_different_tree_height() {
    use ergo_primitives::digest::ADDigest;
    use ergo_state::avl::snapshot_codec::{SnapshotServer, MAINNET_MANIFEST_DEPTH};
    use ergo_state::avl::tree::AvlTree;
    use ergo_state::chain::HeaderMeta;
    use ergo_sync::snapshot_bootstrap::BootstrapState;

    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let snapshot_height = 5u32;
    let mut tree = AvlTree::new();
    tree.insert([0x10; 32], vec![0xAA]);
    let server = SnapshotServer::build(&tree, snapshot_height, MAINNET_MANIFEST_DEPTH).unwrap();
    let manifest_id = *server.manifest_id.as_bytes();
    let mut state_root_bytes = [0u8; 33];
    state_root_bytes[..32].copy_from_slice(&manifest_id);
    state_root_bytes[32] = server.manifest_bytes[0];
    let state_root = ADDigest::from_bytes(state_root_bytes);
    let (header_id, header_bytes) = synthetic_header_with_state_root(snapshot_height, state_root);

    {
        let store = state.store.as_utxo_mut().unwrap();
        store.store_header(&header_id, &header_bytes).unwrap();
        store
            .store_header_meta(
                &header_id,
                &HeaderMeta {
                    parent_id: [0u8; 32],
                    height: snapshot_height,
                    cumulative_score: vec![5],
                    pow_validity: 1,
                    timestamp: 1_700_000_005,
                },
            )
            .unwrap();
        store
            .test_force_set_best_header_unsafe(header_id, snapshot_height, vec![5])
            .unwrap();
        store
            .test_force_put_header_chain_index(snapshot_height, &header_id)
            .unwrap();
        store
            .test_force_put_headers_by_height(snapshot_height, &header_id)
            .unwrap();
    }

    for port in 1..=3u16 {
        state.snapshot_bootstrap.on_snapshots_info(
            synthetic_peer(port),
            &[(snapshot_height as i32, manifest_id)],
        );
    }
    let peer = synthetic_peer(1);
    state.snapshot_bootstrap.mark_manifest_requested(
        peer,
        snapshot_height as i32,
        manifest_id,
        Instant::now(),
    );
    let mut manifest = server.manifest_bytes.clone();
    manifest[0] = manifest[0].wrapping_add(1);
    let payload = message::serialize_manifest(&manifest).unwrap();

    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_MANIFEST,
        &payload,
        Instant::now(),
    );
    assert!(
        matches!(actions.as_slice(), [Action::Penalize { peer: offender, .. }] if *offender == peer)
    );
    assert!(!matches!(
        state.snapshot_bootstrap.state(),
        BootstrapState::ManifestVerified { .. }
    ));

    state
        .snapshot_bootstrap
        .on_snapshots_info(peer, &[(snapshot_height as i32, manifest_id)]);
    state.snapshot_bootstrap.mark_manifest_requested(
        peer,
        snapshot_height as i32,
        manifest_id,
        Instant::now(),
    );
    let valid_payload = message::serialize_manifest(&server.manifest_bytes).unwrap();
    handle_message(
        &mut state,
        peer,
        message::CODE_MANIFEST,
        &valid_payload,
        Instant::now(),
    );
    assert!(matches!(
        state.snapshot_bootstrap.state(),
        BootstrapState::ManifestVerified { .. }
    ));
}

// ----- mode 2 part 2i: install retry across a deferred checkpoint anchor -----

/// Round-trip an empty `AvlTree` through the manifest codec to get a real
/// (non-fabricated) `ReconstructedTree` — same shape `drive_chunk_download`
/// hands `install_reconstructed_snapshot`, just without the network/chunk
/// machinery.
fn empty_reconstructed_tree() -> ergo_state::avl::snapshot_codec::ReconstructedTree {
    use ergo_state::avl::snapshot_codec::{
        reconstruct_tree, serialize_manifest, MAINNET_MANIFEST_DEPTH,
    };
    use ergo_state::avl::tree::AvlTree;
    let tree = AvlTree::new();
    let manifest_bytes = serialize_manifest(&tree, MAINNET_MANIFEST_DEPTH).unwrap();
    reconstruct_tree(&manifest_bytes, &std::collections::HashMap::new()).unwrap()
}

/// A minimal synthetic header at `height` carrying `state_root`. Not
/// PoW-valid or otherwise consensus-checked — `install_reconstructed_snapshot`
/// only reads `(height, state_root)` off the persisted bytes via
/// `ergo_ser::header::read_header`, it never re-validates them.
pub(super) fn synthetic_header_with_state_root(
    height: u32,
    state_root: ergo_primitives::digest::ADDigest,
) -> ([u8; 32], Vec<u8>) {
    use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
    use ergo_primitives::group_element::{GroupElement, GROUP_ELEMENT_LENGTH};
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::header::{write_header, Header};

    let header = Header {
        version: 2,
        parent_id: ModifierId::from_bytes([0u8; 32]),
        ad_proofs_root: Digest32::ZERO,
        transactions_root: Digest32::ZERO,
        state_root,
        timestamp: 1_700_000_000 + height as u64,
        extension_root: Digest32::ZERO,
        n_bits: 0,
        height,
        votes: [0, 0, 0],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes([0u8; GROUP_ELEMENT_LENGTH]),
            nonce: [0u8; 8],
        },
    };
    let mut w = VlqWriter::new();
    write_header(&mut w, &header).expect("synthetic header fits wire bounds");
    let bytes = w.result();
    let id = *blake2b256(&bytes).as_bytes();
    (id, bytes)
}

/// CodeRabbit #313 (MAJOR, `sync_tick.rs:946`): `install_reconstructed_snapshot`
/// calls `state.reconstructed_tree.take()` up front. The anchor-not-observed
/// early return (checkpoint height not yet materialized on this node's
/// header chain — a `SparseGap`/store-corruption-shaped read from
/// `lookup_header_at_height`, same as a genuine PoPowSparse gap) dropped the
/// taken tree without putting it back, so a SECOND tick would silently
/// no-op forever: `state.reconstructed_tree` is `None` and can never be
/// rebuilt (`pending_manifest_bytes` was already consumed). Bootstrap would
/// be permanently stuck even after the anchor became observable. Fixed by
/// restoring `state.reconstructed_tree` before returning on that path (and
/// the `SparseGap`-defer path just above it).
#[test]
fn install_reconstructed_snapshot_retries_after_deferred_checkpoint_anchor_appears() {
    use ergo_state::chain::HeaderMeta;
    use ergo_sync::header_proc::HeaderCheckpoint;
    use ergo_sync::snapshot_bootstrap::BootstrapState;

    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));

    let snapshot_height: u32 = 5;
    let checkpoint_height: u32 = 3;
    let checkpoint_block_id = [0xEEu8; 32];

    // An (empty-tree) reconstructed snapshot, its root embedded as a real
    // header's `state_root` so the install-time trust re-check passes.
    let reconstructed = empty_reconstructed_tree();
    let manifest_id = *reconstructed.root_label.as_bytes();
    let mut root_digest = [0u8; 33];
    root_digest[..32].copy_from_slice(&manifest_id);
    root_digest[32] = reconstructed.tree_height;
    let state_root = ergo_primitives::digest::ADDigest::from_bytes(root_digest);

    let (h5_id, h5_bytes) = synthetic_header_with_state_root(snapshot_height, state_root);

    {
        let store = state.store.as_utxo_mut().unwrap();
        store.store_header(&h5_id, &h5_bytes).unwrap();
        store
            .store_header_meta(
                &h5_id,
                &HeaderMeta {
                    parent_id: [0u8; 32],
                    height: snapshot_height,
                    cumulative_score: vec![5],
                    pow_validity: 1,
                    timestamp: 1_700_000_005,
                },
            )
            .unwrap();
        store
            .test_force_set_best_header_unsafe(h5_id, snapshot_height, vec![5])
            .unwrap();
        store
            .test_force_put_header_chain_index(snapshot_height, &h5_id)
            .unwrap();
        store
            .test_force_put_headers_by_height(snapshot_height, &h5_id)
            .unwrap();
        // Deliberately leave `checkpoint_height` unindexed: the operator's
        // anchor has not been observed on this node's header chain yet.
    }

    state.executor.set_header_checkpoint(Some(HeaderCheckpoint {
        height: checkpoint_height,
        block_id: checkpoint_block_id,
    }));

    // Drive the snapshot_bootstrap reducer to `ManifestVerified` — the gate
    // `install_reconstructed_snapshot` checks — without the real quorum/
    // chunk-download machinery, which is irrelevant to this regression.
    for p in 1..=3u16 {
        state
            .snapshot_bootstrap
            .on_snapshots_info(synthetic_peer(p), &[(snapshot_height as i32, manifest_id)]);
    }
    assert!(matches!(
        state.snapshot_bootstrap.state(),
        BootstrapState::Selected { .. }
    ));
    state.snapshot_bootstrap.mark_manifest_requested(
        synthetic_peer(1),
        snapshot_height as i32,
        manifest_id,
        Instant::now(),
    );
    state
        .snapshot_bootstrap
        .accept_verified_manifest(Vec::new());
    assert!(matches!(
        state.snapshot_bootstrap.state(),
        BootstrapState::ManifestVerified { .. }
    ));

    state.reconstructed_tree = Some(reconstructed);

    // Tick 1: anchor not yet observed — install must defer, not drop the
    // reconstructed tree.
    handle_sync_tick(&mut state);
    assert!(
        state.reconstructed_tree.is_some(),
        "a deferred (not-yet-observed) checkpoint anchor must NOT drop the \
         reconstructed tree — the install must be retryable next tick",
    );
    assert_eq!(
        state
            .store
            .as_utxo()
            .unwrap()
            .chain_state()
            .best_full_block_height,
        0,
        "install must not have proceeded while the anchor is unobserved",
    );

    // The anchor becomes observed: the operator's pinned id materializes at
    // the checkpoint height on this node's header chain.
    state
        .store
        .as_utxo()
        .unwrap()
        .test_force_put_header_chain_index(checkpoint_height, &checkpoint_block_id)
        .unwrap();

    // Tick 2: anchor now observed and matches — install must succeed using
    // the SAME reconstructed tree kept from tick 1.
    handle_sync_tick(&mut state);
    assert!(
        state.reconstructed_tree.is_none(),
        "a successful install must consume the reconstructed tree",
    );
    assert_eq!(
        state.installed_snapshot,
        Some((snapshot_height, manifest_id)),
        "install must complete once the anchor is observed",
    );
    assert_eq!(
        state
            .store
            .as_utxo()
            .unwrap()
            .chain_state()
            .best_full_block_height,
        snapshot_height,
    );
}

// ----- span emission -----

#[test]
fn handle_message_emits_span_with_peer_and_code() {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::format::FmtSpan;
    use tracing_subscriber::fmt::MakeWriter;

    // Per-test capture buffer (CLOSE-event format dumps the span's
    // final field values, catching both entry-time and any late
    // recorded fields).
    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedBuf {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
    let buf_for_subscriber = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .with_ansi(false)
        .with_writer(buf_for_subscriber)
        .finish();

    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let payload = req_modifier_payload(99, &[mid(1)]);

    tracing::subscriber::with_default(subscriber, || {
        let _ = handle_message(
            &mut state,
            peer,
            message::CODE_REQUEST_MODIFIER,
            &payload,
            Instant::now(),
        );
    });

    let output = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
    assert!(
        output.contains("msg"),
        "missing msg span name in:\n{output}"
    );
    let peer_str = format!("peer={peer}");
    assert!(
        output.contains(&peer_str),
        "missing {peer_str} in:\n{output}"
    );
    let code_str = format!("code={}", message::CODE_REQUEST_MODIFIER);
    assert!(
        output.contains(&code_str),
        "missing {code_str} in:\n{output}"
    );
}

// ----- mode_label_for: future-mode arms -----

fn cfg_with_mode(
    state_type: crate::config::StateType,
    vt: bool,
    btk: i32,
) -> crate::config::NodeConfig {
    use crate::config::{LoggingConfig, LoggingFormat, Network, NodeConfig};
    use ergo_chain_spec::ChainSpec;
    use ergo_indexer::IndexerConfig;
    use ergo_mempool::types::MempoolConfig;
    use ergo_p2p::peer_manager::PeerLimits;
    use std::sync::Arc;
    // Mirror the loader's `mempool_force_off_for_mode` policy:
    // the helper produces configs that match what
    // `NodeConfig::load` would emit, so tests that exercise
    // accepted combos don't trip the runtime backstop on a
    // detail the loader would have force-disabled. Tests for
    // the rejection path override `mempool_config.enabled` to
    // `true` after the helper returns.
    let mut mempool_config = MempoolConfig::default();
    if !vt || state_type == crate::config::StateType::Digest {
        mempool_config.enabled = false;
    }
    NodeConfig {
        network: Network::Mainnet,
        shadow_config: Default::default(),
        chain_spec: Arc::new(ChainSpec::mainnet()),
        data_dir: std::env::temp_dir().join("ergo-mode-label-cfg"),
        known_peers: vec!["127.0.0.1:1".parse().unwrap()],
        allow_local: false,
        peer_limits: PeerLimits::default(),
        bind_addr: None,
        declared_addr: None,
        agent_name: "x".into(),
        node_name: "y".into(),
        blocks_to_keep: btk,
        keep_versions: ergo_state::store::ROLLBACK_WINDOW,
        state_type,
        verify_transactions: vt,
        utxo_bootstrap: false,
        nipopow_bootstrap: false,
        p2p_nipopows: 2,
        ibd_flush_interval: 0,
        download_window: 1,
        sync_interval: ergo_p2p::sync::DEFAULT_SYNC_INTERVAL,
        sync_interval_stable: ergo_p2p::sync::DEFAULT_SYNC_INTERVAL_STABLE,
        cache_bytes: None,
        script_validation_checkpoint: None,
        header_checkpoint: None,
        genesis_id: None,
        api_bind: None,
        api_key_hash: None,
        api_allowed_hosts: Vec::new(),
        api_local_reverse_proxy: false,
        allow_direct_block_submit: false,
        devnet_max_block_cost: None,
        mempool_config,
        mempool_sort_policy: "cost".into(),
        indexer_config: IndexerConfig::default(),
        enable_anchor_scheduler: false,
        logging: LoggingConfig {
            modules: Default::default(),
            default_level: "info".into(),
            format: LoggingFormat::Text,
            file: None,
        },
        mining_config: ergo_mining::MiningConfig::default(),
        voting_targets: std::collections::BTreeMap::new(),
        wallet_expose_private_keys: false,
    }
}

#[test]
fn mode_label_archive_default() {
    let cfg = cfg_with_mode(crate::config::StateType::Utxo, true, -1);
    assert_eq!(super::mode_label_for(&cfg), "archive · utxo");
}

/// Pin the default-mode tuple that both the handshake construction
/// at `run_inner()` and `ApiIdentity` source from `NodeConfig`. If
/// any of these defaults drift, the wire `Mode` peer-feature and
/// `/api/v1/identity` would silently disagree with downstream
/// expectations. This test makes the contract explicit so future
/// changes break loudly.
#[test]
fn default_mode_tuple_pinned_to_mode_1_archive() {
    let cfg = cfg_with_mode(crate::config::StateType::Utxo, true, -1);
    assert_eq!(cfg.state_type, crate::config::StateType::Utxo);
    assert_eq!(
        cfg.state_type.wire_byte(),
        0,
        "UTXO must serialize as byte 0"
    );
    assert!(cfg.verify_transactions);
    assert_eq!(cfg.blocks_to_keep, -1, "archive sentinel");
    assert_eq!(super::mode_label_for(&cfg), "archive · utxo");
}

#[test]
fn mode_label_pruned() {
    let cfg = cfg_with_mode(crate::config::StateType::Utxo, true, 1024);
    assert_eq!(super::mode_label_for(&cfg), "pruned · utxo · keep 1024");
}

#[test]
fn mode_label_utxo_bootstrapped() {
    // Hand-built config with the wire-only -2 sentinel directly
    // in blocks_to_keep — covers the theoretical case (label is
    // no longer "archive ..." since post-bootstrap nodes don't
    // hold pre-snapshot blocks).
    let cfg = cfg_with_mode(crate::config::StateType::Utxo, true, -2);
    assert_eq!(super::mode_label_for(&cfg), "utxo · utxo-bootstrapped");
}

#[test]
fn mode_label_utxo_bootstrap_flag_overrides_blocks_to_keep() {
    // Mode 2 derives the -2 sentinel from `utxo_bootstrap = true`
    // at runtime — operators don't set -2 in TOML. The label
    // should reflect that, not the literal config blocks_to_keep.
    let mut cfg = cfg_with_mode(crate::config::StateType::Utxo, true, -1);
    cfg.utxo_bootstrap = true;
    assert_eq!(super::mode_label_for(&cfg), "utxo · utxo-bootstrapped");
}

#[test]
fn mode_label_digest_verifier_strict() {
    let cfg = cfg_with_mode(crate::config::StateType::Digest, true, -1);
    assert_eq!(super::mode_label_for(&cfg), "digest-verifier");
}

#[test]
fn mode_label_headers_only_strict() {
    // Canonical Mode 6 combo per Scala application.conf:15:
    // verify_transactions=false requires blocks_to_keep == 0.
    let cfg = cfg_with_mode(crate::config::StateType::Digest, false, 0);
    assert_eq!(super::mode_label_for(&cfg), "headers-only · digest");
}

#[test]
fn mode_label_invalid_digest_verifier_with_pruning() {
    // (Digest, true, 1024) is not a Scala-supported mode; the
    // label must flag it rather than silently normalize to
    // "digest-verifier".
    let cfg = cfg_with_mode(crate::config::StateType::Digest, true, 1024);
    let label = super::mode_label_for(&cfg);
    assert!(label.starts_with("invalid mode"), "got: {label}");
}

#[test]
fn mode_label_invalid_headers_only_non_zero_btk() {
    // (Digest, false, anything but 0) is invalid per Scala
    // convention. Today this is reachable only by a future
    // refactor that lifts the activation gate without updating
    // the label; the strict match here keeps the misclassification
    // visible.
    for btk in &[-1i32, -2, 1024, 100] {
        let cfg = cfg_with_mode(crate::config::StateType::Digest, false, *btk);
        let label = super::mode_label_for(&cfg);
        assert!(
            label.starts_with("invalid mode"),
            "(Digest, false, {btk}) must be invalid; got: {label}",
        );
    }
}

// ----- build_api_identity -----

/// Helper: produce an archive-default `NodeConfig` plus an opt-in
/// hook to flip `utxo_bootstrap`. Reuses `cfg_with_mode` for the
/// (state_type, verify_transactions, blocks_to_keep) triple.
fn cfg_for_history_mode(
    state_type: crate::config::StateType,
    vt: bool,
    btk: i32,
    utxo_bootstrap: bool,
) -> crate::config::NodeConfig {
    let mut cfg = cfg_with_mode(state_type, vt, btk);
    cfg.utxo_bootstrap = utxo_bootstrap;
    cfg
}

/// Archive: `blocks_to_keep = -1` + `state_type = Utxo` +
/// `verify_transactions = true` + `utxo_bootstrap = false`. The default
/// runtime mode; this is the live path most nodes boot into.
#[test]
fn build_api_identity_archive_default() {
    use ergo_api::types::ApiHistoryMode;
    let cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, -1, false);
    let id = build_api_identity(&cfg, 1, crate::node::identity::BootstrapKind::None)
        .expect("archive must build");
    assert_eq!(id.history_mode, ApiHistoryMode::Archive);
    assert!(!id.utxo_bootstrap);
    assert_eq!(id.state_type, ergo_api::types::ApiStateType::Utxo);
    assert!(id.verify_transactions);
}

/// `utxo_bootstrap = true` on top of a Utxo/verify_tx/Archive base
/// produces `UtxoBootstrapped`. The canonical Mode 6 check ahead of
/// this branch doesn't match (state_type is Utxo, not Digest) so the
/// `utxo_bootstrap` arm fires.
#[test]
fn build_api_identity_utxo_bootstrap_on_legit_mode_2_base() {
    use ergo_api::types::ApiHistoryMode;
    let cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, -1, true);
    let id = build_api_identity(&cfg, 1, crate::node::identity::BootstrapKind::None)
        .expect("utxo_bootstrap must build");
    assert_eq!(id.history_mode, ApiHistoryMode::UtxoBootstrapped);
    assert!(id.utxo_bootstrap);
}

/// Conflicting combo: `utxo_bootstrap=true` on top of the canonical
/// Mode 6 triple (`Digest + !verify_tx + blocks_to_keep=0`) is a
/// contradictory mode (no UTXO state to bootstrap into). Both
/// `NodeConfig::load` and `validate_runtime_mode_support` refuse it;
/// `build_api_identity` is the projection backstop for callers that
/// bypass both gates. It must `Err` rather than silently normalize
/// the contradiction to `HeadersOnly`.
#[test]
fn build_api_identity_rejects_mode_6_plus_utxo_bootstrap() {
    let cfg = cfg_for_history_mode(crate::config::StateType::Digest, false, 0, true);
    let err = build_api_identity(&cfg, 1, crate::node::identity::BootstrapKind::None)
        .expect_err("contradictory Mode 6 + utxo_bootstrap must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("contradictory") || msg.contains("utxo_bootstrap"),
        "rejection must reference the contradiction: {msg}",
    );
}

/// Canonical Mode 6 combo (`Digest + !verify_tx + blocks_to_keep = 0`).
/// Live runtime path today per `is_canonical_mode_6` short-circuit.
#[test]
fn build_api_identity_canonical_mode_6_emits_headers_only() {
    use ergo_api::types::ApiHistoryMode;
    let cfg = cfg_for_history_mode(crate::config::StateType::Digest, false, 0, false);
    let id = build_api_identity(&cfg, 1, crate::node::identity::BootstrapKind::None)
        .expect("canonical Mode 6 must build");
    assert_eq!(id.history_mode, ApiHistoryMode::HeadersOnly);
}

/// `blocks_to_keep = N` for `N >= 1` produces `Pruned { suffix_len: N }`.
/// Forward-compat variant — runtime gate currently rejects this combo,
/// but the projection is ready when Mode 3 eviction lands.
#[test]
fn build_api_identity_pruned_n_emits_pruned_with_suffix_len() {
    use ergo_api::types::ApiHistoryMode;
    let cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, 1440, false);
    let id = build_api_identity(&cfg, 1, crate::node::identity::BootstrapKind::None)
        .expect("pruned config must build (projection only)");
    assert_eq!(id.history_mode, ApiHistoryMode::Pruned { suffix_len: 1440 },);
}

/// Unreachable partials — `blocks_to_keep = 0` without the rest of
/// the Mode 6 combo, or `blocks_to_keep < -1` — fail loudly rather
/// than emitting a misleading variant. Both `NodeConfig::load` and
/// `validate_runtime_mode_support` reject these in production; the
/// helper's `Err` path is a defense-in-depth tripwire for hand-built
/// configs that bypass both gates.
#[test]
fn build_api_identity_rejects_unreachable_combo() {
    // blocks_to_keep = 0 without the canonical Mode 6 triple
    let cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, 0, false);
    let err = build_api_identity(&cfg, 1, crate::node::identity::BootstrapKind::None)
        .expect_err("partial Mode 6 combo must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("unreachable") && msg.contains("history_mode"),
        "error must explain unreachable history_mode: {msg}",
    );

    // blocks_to_keep < -1
    let cfg2 = cfg_for_history_mode(crate::config::StateType::Utxo, true, -3, false);
    let err2 = build_api_identity(&cfg2, 1, crate::node::identity::BootstrapKind::None)
        .expect_err("blocks_to_keep < -1 must reject");
    assert!(
        err2.to_string().contains("unreachable"),
        "error must explain unreachable: {}",
        err2,
    );
}

/// On a sentinel-active archive boot whose store carries the
/// `BootstrapKind::Utxo` provenance marker, `/api/v1/identity`
/// reports the truthful effective state: `history_mode = Archive`
/// (config-driven, mirrors the wire-handshake field) AND
/// `utxo_bootstrap = true` (provenance), with the operator-
/// facing `mode` label resolving to `utxo-bootstrapped`.
#[test]
fn build_api_identity_sentinel_active_archive_utxo_bootstrap_label() {
    use ergo_api::types::ApiHistoryMode;
    let cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, -1, false);
    let id = build_api_identity(&cfg, 100_000, crate::node::identity::BootstrapKind::Utxo)
        .expect("sentinel-active archive must project");
    // `history_mode` is config-driven (Scala parity).
    assert_eq!(id.history_mode, ApiHistoryMode::Archive);
    // `utxo_bootstrap` is truthful effective state (provenance OR
    // config). With BootstrapKind::Utxo it must be true.
    assert!(id.utxo_bootstrap);
    assert!(!id.nipopow_bootstrap);
    assert!(
        id.mode.contains("utxo-bootstrapped"),
        "Utxo bootstrap_kind must label utxo-bootstrapped: {}",
        id.mode,
    );
}

/// `build_api_identity_from_inputs` must produce the same
/// projection as `build_api_identity` when fed equivalent
/// inputs. Guards the post-bootstrap refresh path against drift
/// from the boot-time path.
#[test]
fn build_api_identity_from_inputs_matches_build_api_identity() {
    use crate::node::identity::{build_api_identity_from_inputs, BootstrapKind, IdentityInputs};
    for (state_type, verify_tx, btk, utxo_boot, sentinel, kind) in [
        (
            crate::config::StateType::Utxo,
            true,
            -1i32,
            false,
            1u32,
            BootstrapKind::None,
        ),
        (
            crate::config::StateType::Utxo,
            true,
            -1,
            false,
            100_000,
            BootstrapKind::Utxo,
        ),
        (
            crate::config::StateType::Utxo,
            true,
            -1,
            false,
            100_000,
            BootstrapKind::Nipopow,
        ),
        (
            crate::config::StateType::Utxo,
            true,
            -1,
            false,
            100_000,
            BootstrapKind::Both,
        ),
        (
            crate::config::StateType::Utxo,
            true,
            -1,
            false,
            100_000,
            BootstrapKind::None,
        ),
        (
            crate::config::StateType::Utxo,
            true,
            1440,
            false,
            1_000,
            BootstrapKind::None,
        ),
        (
            crate::config::StateType::Utxo,
            true,
            1440,
            false,
            100_000,
            BootstrapKind::Utxo,
        ),
        (
            crate::config::StateType::Utxo,
            true,
            1440,
            false,
            100_000,
            BootstrapKind::Nipopow,
        ),
        (
            crate::config::StateType::Utxo,
            true,
            1440,
            false,
            100_000,
            BootstrapKind::Both,
        ),
        (
            crate::config::StateType::Utxo,
            true,
            -1,
            true,
            1,
            BootstrapKind::None,
        ),
        (
            crate::config::StateType::Digest,
            false,
            0,
            false,
            1,
            BootstrapKind::None,
        ),
    ] {
        let cfg = cfg_for_history_mode(state_type, verify_tx, btk, utxo_boot);
        let inputs = IdentityInputs::from_config(&cfg);
        let from_config = build_api_identity(&cfg, sentinel, kind).expect("build from config");
        let from_inputs =
            build_api_identity_from_inputs(&inputs, sentinel, kind).expect("build from inputs");
        let same_shape = from_config.mode == from_inputs.mode
            && from_config.state_type == from_inputs.state_type
            && from_config.verify_transactions == from_inputs.verify_transactions
            && from_config.history_mode == from_inputs.history_mode
            && from_config.utxo_bootstrap == from_inputs.utxo_bootstrap
            && from_config.nipopow_bootstrap == from_inputs.nipopow_bootstrap
            && from_config.mining == from_inputs.mining
            && from_config.extra_index_enabled == from_inputs.extra_index_enabled
            && from_config.declared_addr == from_inputs.declared_addr
            && from_config.bind_addr == from_inputs.bind_addr;
        assert!(
            same_shape,
            "drift between config and inputs paths for \
             (state_type={state_type:?}, verify_tx={verify_tx}, btk={btk}, \
             utxo_boot={utxo_boot}, sentinel={sentinel}, kind={kind:?})\n\
             from_config = {from_config:?}\nfrom_inputs = {from_inputs:?}",
        );
    }
}

/// A node booting against an `apply_popow_proof`-installed
/// store (`BootstrapKind::Nipopow`) MUST report
/// `nipopow_bootstrap = true` even when the config flag is
/// cleared, AND `utxo_bootstrap = false`.
#[test]
fn build_api_identity_nipopow_bootstrap_projects_truthfully() {
    use ergo_api::types::ApiHistoryMode;
    let cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, -1, false);
    let id = build_api_identity(&cfg, 100_000, crate::node::identity::BootstrapKind::Nipopow)
        .expect("nipopow-bootstrapped store must project");
    assert_eq!(id.history_mode, ApiHistoryMode::Archive);
    assert!(id.nipopow_bootstrap);
    assert!(!id.utxo_bootstrap);
    assert!(
        id.mode.contains("popow-bootstrapped"),
        "Nipopow bootstrap_kind must label popow-bootstrapped: {}",
        id.mode,
    );
}

/// When the persistent UTXO-bootstrap provenance marker is
/// absent (an archive node that later started pruning),
/// `BootstrapKind::None` is the truthful classification. The
/// label MUST resolve to `post-prune archive` so an operator
/// dashboard can distinguish that shape from a real Mode 2
/// install.
#[test]
fn build_api_identity_sentinel_active_archive_post_prune_label() {
    use ergo_api::types::ApiHistoryMode;
    let cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, -1, false);
    let id = build_api_identity(&cfg, 100_000, crate::node::identity::BootstrapKind::None)
        .expect("sentinel-active archive must project");
    assert_eq!(id.history_mode, ApiHistoryMode::Archive);
    assert!(!id.utxo_bootstrap);
    assert!(
        id.mode.contains("post-prune archive"),
        "None bootstrap_kind on sentinel-active archive must label post-prune archive: {}",
        id.mode,
    );
}

/// The `mining` flag on the projected identity tracks
/// `IdentityInputs::mining_enabled` (sourced from
/// `mining_config.enabled`) — a live mining node reports
/// `mining = true`, an idle one reports `false`.
#[test]
fn build_api_identity_mining_flag_tracks_mining_enabled() {
    use crate::node::identity::{build_api_identity_from_inputs, BootstrapKind};
    for mining_enabled in [true, false] {
        let mut inputs = inputs_for(crate::config::StateType::Utxo, true, -1, false, false);
        inputs.mining_enabled = mining_enabled;
        let id = build_api_identity_from_inputs(&inputs, 1, BootstrapKind::None)
            .expect("archive inputs must project");
        assert_eq!(
            id.mining, mining_enabled,
            "mining flag must mirror mining_enabled={mining_enabled}",
        );
    }
}

// ----- classify_node_mode (Phase 4a) -----

use super::identity::{classify_node_mode, NodeMode};

fn floor_keep() -> i32 {
    (ergo_state::store::ROLLBACK_WINDOW + ergo_state::store::SAFETY_MARGIN) as i32
}

fn inputs_for(
    state_type: crate::config::StateType,
    verify_transactions: bool,
    blocks_to_keep: i32,
    utxo_bootstrap: bool,
    nipopow_bootstrap: bool,
) -> crate::node::identity::IdentityInputs {
    crate::node::identity::IdentityInputs {
        state_type,
        verify_transactions,
        blocks_to_keep,
        keep_versions: ergo_state::store::ROLLBACK_WINDOW,
        utxo_bootstrap,
        nipopow_bootstrap,
        mining_enabled: false,
        extra_index_enabled: false,
        declared_addr: None,
        bind_addr: None,
    }
}

#[test]
fn classify_archive_default() {
    let i = inputs_for(crate::config::StateType::Utxo, true, -1, false, false);
    assert_eq!(classify_node_mode(&i), NodeMode::Archive);
}

#[test]
fn classify_utxo_bootstrap_with_archive_keep() {
    let i = inputs_for(crate::config::StateType::Utxo, true, -1, true, false);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::UtxoBootstrap {
            with_nipopow: false
        },
    );
}

#[test]
fn classify_utxo_bootstrap_with_nipopow_archive_keep() {
    let i = inputs_for(crate::config::StateType::Utxo, true, -1, true, true);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::UtxoBootstrap { with_nipopow: true },
    );
}

#[test]
fn classify_pruned_without_bootstrap() {
    let keep = floor_keep();
    let i = inputs_for(crate::config::StateType::Utxo, true, keep, false, false);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::Pruned { keep: keep as u32 },
    );
}

#[test]
fn classify_pruned_plus_utxo_bootstrap_is_mode_4() {
    let keep = floor_keep();
    let i = inputs_for(crate::config::StateType::Utxo, true, keep, true, false);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::PrunedBootstrap {
            keep: keep as u32,
            utxo: true,
            nipopow: false,
        },
    );
}

#[test]
fn classify_pruned_plus_nipopow_bootstrap_is_mode_4() {
    let keep = floor_keep();
    let i = inputs_for(crate::config::StateType::Utxo, true, keep, false, true);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::PrunedBootstrap {
            keep: keep as u32,
            utxo: false,
            nipopow: true,
        },
    );
}

#[test]
fn classify_pruned_plus_both_bootstraps_is_mode_4() {
    let keep = floor_keep();
    let i = inputs_for(crate::config::StateType::Utxo, true, keep, true, true);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::PrunedBootstrap {
            keep: keep as u32,
            utxo: true,
            nipopow: true,
        },
    );
}

#[test]
fn classify_headers_only() {
    let i = inputs_for(crate::config::StateType::Digest, false, 0, false, false);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::HeadersOnly {
            with_nipopow: false
        },
    );
}

#[test]
fn classify_digest_verifier_combo_is_digest_verifier() {
    let i = inputs_for(crate::config::StateType::Digest, true, -1, false, false);
    assert_eq!(classify_node_mode(&i), NodeMode::DigestVerifier);
}

#[test]
fn classify_headers_only_plus_nipopow_surfaces_in_variant() {
    // `Digest + verify=false + keep=0 + nipopow_bootstrap=true`
    // passes R3 (keep >= 0 satisfies the NiPoPoW consumer rule).
    // Scala accepts this combo (`ErgoSettingsReader.scala:191`),
    // so the classifier must too — but the bootstrap flag MUST
    // surface in the variant rather than being silently dropped.
    let i = inputs_for(crate::config::StateType::Digest, false, 0, false, true);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::HeadersOnly { with_nipopow: true },
    );
}

#[test]
fn classify_digest_verifier_plus_nipopow_invalid() {
    // R3 (config/load.rs:253) rejects nipopow_bootstrap without
    // utxo_bootstrap or blocks_to_keep >= 0. For the digest
    // verifier shape (keep = -1, no utxo_bootstrap), nipopow
    // therefore has no consumer and must classify as Invalid.
    let i = inputs_for(crate::config::StateType::Digest, true, -1, false, true);
    match classify_node_mode(&i) {
        NodeMode::Invalid { reason } => {
            assert!(
                reason.contains("nipopow_bootstrap"),
                "reason must name nipopow_bootstrap: {reason}",
            );
        }
        other => {
            panic!("digest verifier + nipopow without consumer must be Invalid, got {other:?}")
        }
    }
}

#[test]
fn classify_digest_plus_utxo_bootstrap_invalid() {
    let i = inputs_for(crate::config::StateType::Digest, true, -1, true, false);
    match classify_node_mode(&i) {
        NodeMode::Invalid { .. } => {}
        other => panic!("digest + utxo_bootstrap must be Invalid, got {other:?}"),
    }
}

#[test]
fn classify_utxo_no_verify_invalid() {
    let i = inputs_for(crate::config::StateType::Utxo, false, -1, false, false);
    match classify_node_mode(&i) {
        NodeMode::Invalid { .. } => {}
        other => panic!("utxo + !verify_tx must be Invalid, got {other:?}"),
    }
}

#[test]
fn classify_nipopow_archive_without_utxo_bootstrap_invalid() {
    // Mirrors the existing TOML-time rejection: NiPoPoW requires
    // either utxo_bootstrap or blocks_to_keep >= 0.
    let i = inputs_for(crate::config::StateType::Utxo, true, -1, false, true);
    match classify_node_mode(&i) {
        NodeMode::Invalid { .. } => {}
        other => panic!("nipopow archive without utxo_bootstrap must be Invalid, got {other:?}"),
    }
}

#[test]
fn classify_utxo_keep_zero_invalid() {
    let i = inputs_for(crate::config::StateType::Utxo, true, 0, false, false);
    match classify_node_mode(&i) {
        NodeMode::Invalid { .. } => {}
        other => panic!("utxo + keep=0 must be Invalid, got {other:?}"),
    }
}

#[test]
fn classify_keep_below_minus_one_invalid() {
    let i = inputs_for(crate::config::StateType::Utxo, true, -3, false, false);
    match classify_node_mode(&i) {
        NodeMode::Invalid { .. } => {}
        other => panic!("keep < -1 must be Invalid, got {other:?}"),
    }
}

#[test]
fn classify_sub_floor_keep_invalid() {
    // Positive blocks_to_keep below the rollback-window floor must
    // be classified as Invalid — same contract the TOML loader
    // enforces. Without this the classifier would tolerate
    // configurations the rest of the runtime refuses to boot.
    let i = inputs_for(
        crate::config::StateType::Utxo,
        true,
        floor_keep() - 1,
        false,
        false,
    );
    match classify_node_mode(&i) {
        NodeMode::Invalid { reason } => {
            assert!(
                reason.contains("rollback-window floor"),
                "reason must name the floor: {reason}",
            );
        }
        other => panic!("sub-floor keep must be Invalid, got {other:?}"),
    }
    // The lowest legal positive value (keep == 1) is also
    // sub-floor and must reject.
    let i = inputs_for(crate::config::StateType::Utxo, true, 1, false, false);
    match classify_node_mode(&i) {
        NodeMode::Invalid { .. } => {}
        other => panic!("keep == 1 must be Invalid, got {other:?}"),
    }
}

fn inputs_for_with_indexer(
    blocks_to_keep: i32,
    utxo_bootstrap: bool,
    extra_index_enabled: bool,
) -> crate::node::identity::IdentityInputs {
    let mut i = inputs_for(
        crate::config::StateType::Utxo,
        true,
        blocks_to_keep,
        utxo_bootstrap,
        false,
    );
    i.extra_index_enabled = extra_index_enabled;
    i
}

#[test]
fn classify_extra_index_plus_pruning_invalid() {
    // Indexer + pruning is rejected by the config loader because
    // extra-index needs the full archive. Classifier mirrors the
    // rejection.
    let i = inputs_for_with_indexer(floor_keep(), false, true);
    match classify_node_mode(&i) {
        NodeMode::Invalid { reason } => {
            assert!(
                reason.contains("extra-index"),
                "reason must name extra-index: {reason}",
            );
        }
        other => panic!("extra_index + pruning must be Invalid, got {other:?}"),
    }
}

#[test]
fn classify_extra_index_plus_utxo_bootstrap_invalid() {
    // Indexer + utxo_bootstrap is also rejected — the bootstrap
    // skips the chain below the snapshot, leaving nothing for
    // extra-index to index.
    let i = inputs_for_with_indexer(-1, true, true);
    match classify_node_mode(&i) {
        NodeMode::Invalid { reason } => {
            assert!(
                reason.contains("extra-index"),
                "reason must name extra-index: {reason}",
            );
        }
        other => panic!("extra_index + utxo_bootstrap must be Invalid, got {other:?}"),
    }
}

#[test]
fn classify_extra_index_with_archive_is_archive() {
    // The valid extra-index combo is the full-archive node: no
    // pruning, no bootstrap. Classify still returns Archive.
    let i = inputs_for_with_indexer(-1, false, true);
    assert_eq!(classify_node_mode(&i), NodeMode::Archive);
}

#[test]
fn classify_agrees_with_build_api_identity_on_canonical_combos() {
    // The classifier and the identity-projection paths must not
    // disagree on which combos are valid. For every row that
    // classify returns a non-Invalid mode, `build_api_identity`
    // must succeed; for every Invalid row, `build_api_identity`
    // is allowed to either succeed (with the resulting label
    // self-flagged as `invalid mode:`) or fail. The asymmetry is
    // intentional: build_api_identity has its own rejections at
    // a different layer; classify is the stricter projection.
    use crate::node::identity::{build_api_identity_from_inputs, BootstrapKind};
    let floor = floor_keep();
    let canonical: &[(crate::config::StateType, bool, i32, bool, bool)] = &[
        (crate::config::StateType::Utxo, true, -1, false, false),
        (crate::config::StateType::Utxo, true, -1, true, false),
        (crate::config::StateType::Utxo, true, -1, true, true),
        (crate::config::StateType::Utxo, true, floor, false, false),
        (crate::config::StateType::Utxo, true, floor, true, false),
        (crate::config::StateType::Utxo, true, floor, false, true),
        (crate::config::StateType::Utxo, true, floor, true, true),
        (crate::config::StateType::Digest, false, 0, false, false),
        (crate::config::StateType::Digest, true, -1, false, false),
    ];
    for &(st, vt, btk, ub, np) in canonical {
        let i = inputs_for(st, vt, btk, ub, np);
        let mode = classify_node_mode(&i);
        let id = build_api_identity_from_inputs(&i, 1, BootstrapKind::None);
        if matches!(mode, NodeMode::Invalid { .. }) {
            // Skip — classify rejected; identity is allowed to
            // disagree.
            continue;
        }
        assert!(
            id.is_ok(),
            "classify_node_mode returned {mode:?} but build_api_identity_from_inputs \
             failed for inputs (state_type={st:?}, vt={vt}, btk={btk}, ub={ub}, np={np}): \
             {:?}",
            id.err(),
        );
    }
}

/// Cross-product the plan calls out: `{utxo_bootstrap,
/// nipopow_bootstrap} × {-1, ≥ floor}`. Mode 4 must be reached on
/// the `(*, ≥ floor)` rows where at least one bootstrap flag is
/// set; archive / Mode 2 / Mode 3 cover the rest.
#[test]
fn classify_cross_product_utxo_nipopow_keep_minus_one_or_floor() {
    let floor = floor_keep();
    let cases: &[(bool, bool, i32, NodeMode)] = &[
        (false, false, -1, NodeMode::Archive),
        (
            true,
            false,
            -1,
            NodeMode::UtxoBootstrap {
                with_nipopow: false,
            },
        ),
        (
            true,
            true,
            -1,
            NodeMode::UtxoBootstrap { with_nipopow: true },
        ),
        (false, false, floor, NodeMode::Pruned { keep: floor as u32 }),
        (
            true,
            false,
            floor,
            NodeMode::PrunedBootstrap {
                keep: floor as u32,
                utxo: true,
                nipopow: false,
            },
        ),
        (
            false,
            true,
            floor,
            NodeMode::PrunedBootstrap {
                keep: floor as u32,
                utxo: false,
                nipopow: true,
            },
        ),
        (
            true,
            true,
            floor,
            NodeMode::PrunedBootstrap {
                keep: floor as u32,
                utxo: true,
                nipopow: true,
            },
        ),
    ];
    // (false, true, -1) is intentionally absent — the classifier
    // returns Invalid for it, covered separately.
    for &(utxo, popow, keep, ref expected) in cases {
        let i = inputs_for(crate::config::StateType::Utxo, true, keep, utxo, popow);
        let got = classify_node_mode(&i);
        assert_eq!(
            got, *expected,
            "cross-product row (utxo={utxo}, popow={popow}, keep={keep}): \
             expected {expected:?}, got {got:?}",
        );
    }
}

// ----- Phase 4c: Mode 4 label projection -----

/// Mode 4 via config flag — `utxo_bootstrap = true +
/// blocks_to_keep > 0` emits the mode-4 label with the
/// utxo-bootstrapped source AND the suffix length, not the Mode
/// 2 short-circuit. Wire-visible fields stay Scala-parity.
#[test]
fn build_api_identity_mode_4_utxo_via_config_emits_mode_4_label() {
    let mut cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, 1440, true);
    cfg.nipopow_bootstrap = false;
    let id = build_api_identity(&cfg, 1, crate::node::identity::BootstrapKind::None)
        .expect("Mode 4 config must project");
    assert!(
        id.mode.starts_with("mode-4 · utxo-bootstrapped"),
        "expected Mode 4 label, got {:?}",
        id.mode,
    );
    assert!(id.mode.ends_with("keep 1440"));
    assert!(id.utxo_bootstrap);
    assert!(!id.nipopow_bootstrap);
}

/// Mode 4 via NiPoPoW config flag.
#[test]
fn build_api_identity_mode_4_nipopow_via_config_emits_mode_4_label() {
    let mut cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, 1440, false);
    cfg.nipopow_bootstrap = true;
    let id = build_api_identity(&cfg, 1, crate::node::identity::BootstrapKind::None)
        .expect("Mode 4 + nipopow config must project");
    assert_eq!(
        id.mode, "mode-4 · popow-bootstrapped · keep 1440",
        "expected Mode 4 popow label, got {:?}",
        id.mode,
    );
    assert!(!id.utxo_bootstrap);
    assert!(id.nipopow_bootstrap);
}

/// Mode 4 with both config flags set — label MUST surface both
/// provenance sources.
#[test]
fn build_api_identity_mode_4_both_bootstrap_config_flags_emits_both_label() {
    let mut cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, 1440, true);
    cfg.nipopow_bootstrap = true;
    let id = build_api_identity(&cfg, 1, crate::node::identity::BootstrapKind::None)
        .expect("Mode 4 + both config flags must project");
    assert_eq!(
        id.mode, "mode-4 · utxo+popow-bootstrapped · keep 1440",
        "expected Mode 4 utxo+popow label, got {:?}",
        id.mode,
    );
    assert!(id.utxo_bootstrap);
    assert!(id.nipopow_bootstrap);
}

/// Mode 4 detected via runtime provenance — config-side flags
/// cleared but `BootstrapKind::Utxo` from the persistent marker
/// still drives the Mode 4 label.
#[test]
fn build_api_identity_mode_4_via_provenance_only_emits_mode_4_label() {
    let mut cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, 1440, false);
    cfg.nipopow_bootstrap = false;
    let id = build_api_identity(&cfg, 100_000, crate::node::identity::BootstrapKind::Utxo)
        .expect("Mode 4 via provenance must project");
    assert_eq!(
        id.mode, "mode-4 · utxo-bootstrapped · keep 1440",
        "expected Mode 4 label via provenance, got {:?}",
        id.mode,
    );
    assert!(id.utxo_bootstrap);
}

/// `BootstrapKind::Both` — both bootstrap mechanisms ran on a
/// pure Mode 4 store. The label MUST name both.
#[test]
fn build_api_identity_mode_4_both_provenance_emits_both_label() {
    let mut cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, 1440, false);
    cfg.nipopow_bootstrap = false;
    let id = build_api_identity(&cfg, 100_000, crate::node::identity::BootstrapKind::Both)
        .expect("Mode 4 Both provenance must project");
    assert_eq!(
        id.mode, "mode-4 · utxo+popow-bootstrapped · keep 1440",
        "Both provenance must surface both bootstrap sources",
    );
    assert!(id.utxo_bootstrap);
    assert!(id.nipopow_bootstrap);
}

/// Sentinel-active archive label refinement gains a Both arm
/// when an archive-config restart sees both provenance markers.
#[test]
fn build_api_identity_sentinel_active_archive_both_label_refines() {
    let cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, -1, false);
    let id = build_api_identity(&cfg, 100_000, crate::node::identity::BootstrapKind::Both)
        .expect("sentinel-active archive Both provenance must project");
    assert!(
        id.mode.contains("utxo+popow-bootstrapped"),
        "post-bootstrap archive label must surface both sources, got {:?}",
        id.mode,
    );
    // Effective flags reflect both detections.
    assert!(id.utxo_bootstrap);
    assert!(id.nipopow_bootstrap);
}

/// Mode 3 (pruned, no bootstrap, no provenance) keeps the
/// existing "pruned · utxo · keep N" label — Mode 4 label MUST
/// NOT swallow plain Mode 3 configs.
#[test]
fn build_api_identity_mode_3_pure_pruned_label_unchanged() {
    let mut cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, 1440, false);
    cfg.nipopow_bootstrap = false;
    let id = build_api_identity(&cfg, 1, crate::node::identity::BootstrapKind::None)
        .expect("Mode 3 must project");
    assert_eq!(id.mode, "pruned · utxo · keep 1440");
}

// ----- Phase 4b': classify_nipopow_resume truth table -----

use super::identity::{classify_nipopow_resume, NipopowResumeState};
use ergo_state::chain::HeaderAvailability;

fn sparse() -> HeaderAvailability {
    HeaderAvailability::PoPowSparse {
        dense_from_height: 1024,
        proof_suffix_height: 2048,
    }
}

#[test]
fn nipopow_resume_disabled_when_flag_off() {
    assert_eq!(
        classify_nipopow_resume(false, &HeaderAvailability::Dense, 0, 0),
        NipopowResumeState::Disabled,
    );
    // Even with non-default chain state, disabled wins when the
    // flag is off.
    assert_eq!(
        classify_nipopow_resume(false, &sparse(), 2048, 2048),
        NipopowResumeState::Disabled,
    );
}

#[test]
fn nipopow_resume_fresh_at_zero_state() {
    // Row 1 of the truth table.
    assert_eq!(
        classify_nipopow_resume(true, &HeaderAvailability::Dense, 0, 0),
        NipopowResumeState::Fresh,
    );
}

#[test]
fn nipopow_resume_partial_header_sync_when_headers_but_no_full_blocks() {
    // Row 2 — partial header progress, full-block state still 0.
    assert_eq!(
        classify_nipopow_resume(true, &HeaderAvailability::Dense, 500, 0),
        NipopowResumeState::PartialHeaderSync,
    );
}

#[test]
fn nipopow_resume_normal_store_when_full_block_applied() {
    // Row 3 — regression guard. A store with any applied full
    // block MUST NOT be classified as bootstrap-resumable.
    assert_eq!(
        classify_nipopow_resume(true, &HeaderAvailability::Dense, 500, 100),
        NipopowResumeState::NormalStore,
    );
    assert_eq!(
        classify_nipopow_resume(true, &HeaderAvailability::Dense, 500, 1),
        NipopowResumeState::NormalStore,
    );
}

#[test]
fn nipopow_resume_proof_committed_on_sparse_history() {
    // Row 4 — apply_popow_proof has committed; the dense suffix
    // is built out and any further bootstrap is a no-op.
    assert_eq!(
        classify_nipopow_resume(true, &sparse(), 2048, 0),
        NipopowResumeState::ProofCommitted,
    );
    // ProofCommitted also wins when a full block has applied
    // after the proof.
    assert_eq!(
        classify_nipopow_resume(true, &sparse(), 2048, 2048),
        NipopowResumeState::ProofCommitted,
    );
}

// ----- Phase 4b: should_engage_utxo_install -----

use super::identity::should_engage_utxo_install;

#[test]
fn utxo_install_engages_on_fresh_store_with_config_flag() {
    assert!(should_engage_utxo_install(true, 0, false));
}

#[test]
fn utxo_install_skips_when_config_flag_off() {
    // Operator never asked for a snapshot install.
    assert!(!should_engage_utxo_install(false, 0, false));
}

#[test]
fn utxo_install_skips_when_full_block_already_applied() {
    // Post-install restart: best_full_block_height > 0 means
    // the install happened (or normal forward sync ran).
    assert!(!should_engage_utxo_install(true, 100, false));
}

#[test]
fn utxo_install_skips_when_marker_armed() {
    // Phase 4b core invariant — repeat boot with the same
    // config skips the install path.
    assert!(!should_engage_utxo_install(true, 0, true));
}

#[test]
fn utxo_install_skips_when_both_marker_and_full_block_present() {
    // Healthy steady state after the install.
    assert!(!should_engage_utxo_install(true, 100, true));
}

// ----- validate_runtime_mode_support -----

use super::identity::validate_runtime_mode_support;

/// Mode 6 (headers-only) baseline — the canonical combo `Digest +
/// verify_tx=false + blocks_to_keep=0 + utxo_bootstrap=false`. Must
/// pass.
#[test]
fn validate_runtime_mode_canonical_mode_6_accepted() {
    let cfg = cfg_for_history_mode(crate::config::StateType::Digest, false, 0, false);
    validate_runtime_mode_support(&cfg).expect("canonical Mode 6 must pass");
}

/// Headers-only + `utxo_bootstrap=true` is a physically nonsensical
/// combo: there is no UTXO state to bootstrap into. The runtime gate
/// must reject so the boot path never wires snapshot orchestration
/// onto a digest data dir.
#[test]
fn validate_runtime_mode_rejects_mode_6_plus_utxo_bootstrap() {
    let cfg = cfg_for_history_mode(crate::config::StateType::Digest, false, 0, true);
    let err = validate_runtime_mode_support(&cfg).expect_err("Mode 6 + utxo_bootstrap must reject");
    let msg = err.to_string();
    // The error can surface via the verify_transactions arm (which now
    // mentions utxo_bootstrap=false in the canonical combo) or via the
    // dedicated `utxo_bootstrap` arm — either is acceptable as long as
    // the combo is refused.
    assert!(
        msg.contains("verify_transactions") || msg.contains("utxo_bootstrap"),
        "rejection must reference verify_transactions or utxo_bootstrap: {msg}",
    );
}

/// `utxo_bootstrap=true` with `state_type=digest` (without the rest
/// of the Mode 6 combo, so it doesn't hit the Mode 6 path) must be
/// rejected — snapshot bootstrap only makes sense for the UTXO
/// backend.
#[test]
fn validate_runtime_mode_rejects_utxo_bootstrap_on_digest() {
    let cfg = cfg_for_history_mode(crate::config::StateType::Digest, true, -1, true);
    let err =
        validate_runtime_mode_support(&cfg).expect_err("utxo_bootstrap on digest must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("state_type") || msg.contains("utxo_bootstrap"),
        "rejection must reference state_type or utxo_bootstrap: {msg}",
    );
}

/// Mode 2 baseline (Utxo + utxo_bootstrap=true + archive btk) must
/// still pass the runtime gate; the snapshot pipeline takes over
/// from there.
#[test]
fn validate_runtime_mode_mode_2_accepted() {
    let cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, -1, true);
    validate_runtime_mode_support(&cfg).expect("Mode 2 must pass");
}

/// Single-source-of-truth check: both gates delegate to
/// `is_canonical_mode_6_combo`, so they agree on every 4-tuple. This
/// test exercises the predicate directly across the interesting
/// corners.
#[test]
fn is_canonical_mode_6_combo_pins_the_contract() {
    use crate::config::{is_canonical_mode_6_combo, StateType};
    // Positive: canonical
    assert!(is_canonical_mode_6_combo(
        StateType::Digest,
        false,
        0,
        false
    ));
    // Negative: utxo_bootstrap flips the predicate
    assert!(!is_canonical_mode_6_combo(
        StateType::Digest,
        false,
        0,
        true
    ));
    // Negative: verify_transactions=true
    assert!(!is_canonical_mode_6_combo(
        StateType::Digest,
        true,
        0,
        false
    ));
    // Negative: state_type=utxo
    assert!(!is_canonical_mode_6_combo(StateType::Utxo, false, 0, false));
    // Negative: blocks_to_keep != 0
    assert!(!is_canonical_mode_6_combo(
        StateType::Digest,
        false,
        -1,
        false
    ));
}

#[test]
fn is_canonical_mode_5_combo_pins_the_contract() {
    use crate::config::{is_canonical_mode_5_combo, StateType};
    // Positive: the bare Mode 5 row (digest + verify + archive, no bootstrap).
    assert!(is_canonical_mode_5_combo(
        StateType::Digest,
        true,
        -1,
        false
    ));
    // Negative: verify_transactions=false is Mode 6, not Mode 5.
    assert!(!is_canonical_mode_5_combo(
        StateType::Digest,
        false,
        -1,
        false
    ));
    // Negative: state_type=utxo.
    assert!(!is_canonical_mode_5_combo(StateType::Utxo, true, -1, false));
    // Negative: pruning (blocks_to_keep >= 0) — digest mode is archive-only.
    assert!(!is_canonical_mode_5_combo(
        StateType::Digest,
        true,
        0,
        false
    ));
    assert!(!is_canonical_mode_5_combo(
        StateType::Digest,
        true,
        100,
        false
    ));
    // Negative: utxo_bootstrap has no box arena to install into.
    assert!(!is_canonical_mode_5_combo(
        StateType::Digest,
        true,
        -1,
        true
    ));
}

// ----- mining engine exhaustion -----

/// Wire the build worker + coordinator exactly as `boot` does, for tests that
/// drive `run_mining_engine` directly. Boot owns the worker thread and the
/// coordinator future owns only the request `Sender`; this mirrors that split
/// so the tests preserve the production lifecycle (and the log-capture
/// dispatcher snapshot — taken here on the test thread so the worker inherits
/// the test's thread-local subscriber). Returns the spawned coordinator task
/// and the worker `JoinHandle`; the test joins the worker after cancelling.
fn spawn_engine_with_worker(
    reader: ergo_state::reader::ChainStoreReader,
    handle: ergo_mining::handle::MiningHandle,
    indexer: Option<ergo_indexer::IndexerHandle>,
    intent_rx: tokio::sync::watch::Receiver<Option<ergo_mining::engine::BuildIntent>>,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
) -> (tokio::task::JoinHandle<()>, std::thread::JoinHandle<()>) {
    let (req_tx, req_rx) = std::sync::mpsc::channel::<super::mining_engine::BuildRequest>();
    let dispatch = tracing::dispatcher::get_default(|d| d.clone());
    let worker = {
        let worker_handle = handle.clone();
        std::thread::Builder::new()
            .name("mining-build-worker-test".to_string())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    // Base cache off: these tests exercise the topology /
                    // exhaustion path, not the cache itself.
                    super::mining_engine::run_build_worker(
                        reader,
                        worker_handle,
                        indexer,
                        false,
                        req_rx,
                    );
                });
            })
            .expect("spawn test mining build worker thread")
    };
    let engine = tokio::spawn(super::mining_engine::run_mining_engine(
        handle, req_tx, intent_rx, cancel_rx,
    ));
    (engine, worker)
}

/// Aborting the coordinator task (the production shutdown path: `shutdown()`
/// `abort()`s the engine after its bounded await, usually while it is parked at
/// an await point) must leave the build worker quiescent — it observes the
/// closed request channel and exits — so it can be joined, never detaching to
/// keep reading/publishing past shutdown.
///
/// This pins the ownership inversion directly: because the coordinator future
/// owns ONLY the `req_tx`, dropping it (on abort) closes the channel and the
/// worker's `recv()` errs. Pre-split the worker `JoinHandle` lived inside the
/// future and was dropped (detached) on abort, leaving the worker running. Here
/// the worker is idle (no intent ever sent), so after the abort the join must
/// complete promptly.
#[tokio::test]
async fn coordinator_abort_leaves_worker_joinable() {
    use ergo_crypto::difficulty::DifficultyParams;
    use ergo_mining::emission_rules::MonetarySettings;
    use ergo_mining::handle::MiningHandle;
    use ergo_mining::reemission::ReemissionSettings;
    use ergo_state::store::StateStore;
    use tokio::sync::watch;

    let tmp = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(tmp.path().join("s.redb").as_path()).unwrap();
    let mut box_id = [0u8; 32];
    box_id[31] = 1;
    store
        .initialize_genesis(&[(box_id, vec![0xAAu8; 32])])
        .unwrap();
    let reader = store.reader_handle();

    let handle = MiningHandle::new(
        [0x02u8; 33],
        MonetarySettings::mainnet(),
        Some(ReemissionSettings::mainnet()),
        DifficultyParams::mainnet(),
        ergo_validation::VotingSettings::mainnet(),
    );

    // No intent is ever sent, so the coordinator parks on the intent channel —
    // an abort point. The worker parks on `req_rx.recv()`.
    let (_intent_tx, intent_rx) = watch::channel(None);
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    let (engine, worker) = spawn_engine_with_worker(reader, handle, None, intent_rx, cancel_rx);

    // Let both park.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Simulate the shutdown abort: drop the coordinator future. This drops its
    // `req_tx`, so the worker's `recv()` errs and the worker exits.
    engine.abort();
    let _ = engine.await; // observe cancellation (JoinError::is_cancelled)

    // The worker must now exit and be joinable promptly. Join off-runtime under
    // a bound; a hang here is the regression (a detached, still-running worker).
    let joined = tokio::task::spawn_blocking(move || worker.join());
    tokio::time::timeout(std::time::Duration::from_secs(5), joined)
        .await
        .expect("worker must exit promptly after the coordinator future is dropped")
        .expect("join task must not fail")
        .expect("worker thread must not panic");
}

/// The engine task must survive `MAX_VIS_RETRIES` `TipNotVisible` returns and
/// then go back to waiting — not spin, not exit.
///
/// The intent carries an `expected_parent` / `expected_height` that can never
/// become commit-visible against a genesis-only store (committed height 0,
/// intent height 5). The test observes the exhaustion `warn!` event via log
/// capture (no fixed-sleep race), then proves the task survives exhaustion and
/// keeps running.
///
/// Capture mechanism: `tracing::subscriber::set_default` installs the
/// collecting subscriber as the thread-local default and returns a guard that
/// keeps it active until dropped. `#[tokio::test]` uses the current-thread
/// runtime, so all task polls (including the spawned engine) execute on this
/// thread and see the same thread-local default — every `warn!` emitted inside
/// the engine goes through the capture buffer.
#[tokio::test]
async fn engine_visibility_retry_exhaustion_warns_and_keeps_running() {
    use ergo_crypto::difficulty::DifficultyParams;
    use ergo_mempool::MempoolReadSnapshot;
    use ergo_mining::emission_rules::MonetarySettings;
    use ergo_mining::engine::{BuildIntent, BuildReason};
    use ergo_mining::handle::MiningHandle;
    use ergo_mining::reemission::ReemissionSettings;
    use ergo_state::store::StateStore;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use tokio::sync::watch;
    use tracing_subscriber::fmt::MakeWriter;

    // Shared capture buffer — same pattern as handle_message_emits_span_with_peer_and_code.
    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedBuf {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_target(false)
        .with_ansi(false)
        .with_writer(buf.clone())
        .finish();

    // `set_default` returns a guard that keeps the subscriber active as the
    // thread-local default until dropped. Because #[tokio::test] uses the
    // current-thread runtime, all task polls happen on this thread, so every
    // tracing event dispatched during the test (including from the spawned
    // engine task) routes to `buf`.
    let _guard = tracing::subscriber::set_default(subscriber);

    // A genesis-only store: committed tip is zeroed @ height 0.
    let tmp = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(tmp.path().join("s.redb").as_path()).unwrap();
    let mut box_id = [0u8; 32];
    box_id[31] = 1;
    store
        .initialize_genesis(&[(box_id, vec![0xAAu8; 32])])
        .unwrap();
    let reader = store.reader_handle();

    let handle = MiningHandle::new(
        [0x02u8; 33],
        MonetarySettings::mainnet(),
        Some(ReemissionSettings::mainnet()),
        DifficultyParams::mainnet(),
        ergo_validation::VotingSettings::mainnet(),
    );

    // Intent whose expected_parent / expected_height can never become
    // commit-visible: committed height is 0, intent expects height 5.
    let intent = BuildIntent {
        expected_parent: [0x42u8; 32],
        expected_height: 5,
        mempool: Arc::new(MempoolReadSnapshot::empty()),
        miner_pk: [0x02u8; 33],
        reason: BuildReason::Startup,
    };

    let (intent_tx, intent_rx) = watch::channel(Some(intent));
    let (cancel_tx, cancel_rx) = watch::channel(false);

    // Re-send the intent to advance the watch version from INITIAL (0) to 1.
    // `watch::channel` initialises both the sender state and the receiver at
    // the same version (0), so the engine's first `changed()` call would block
    // forever without this bump — the receiver only wakes on a version advance.
    intent_tx.send_if_modified(|_| true);

    let (engine, worker) = spawn_engine_with_worker(reader, handle, None, intent_rx, cancel_rx);

    // The target warn! message emitted after MAX_VIS_RETRIES exhaustion.
    const EXHAUSTION_MSG: &str =
        "mining engine: commit-visibility retries exhausted; awaiting next intent";

    // Poll every 50 ms until the exhaustion warn appears in the capture buffer.
    // Normal arrival: ~1 s (40 × 25 ms backoff). Timeout at 30 s only caps a
    // hung test.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let observed = loop {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let output = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
        if output.contains(EXHAUSTION_MSG) {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
    };
    assert!(
        observed,
        "timed out (30 s) waiting for exhaustion warn — \
         the engine never emitted '{EXHAUSTION_MSG}'",
    );

    // Exhaustion goes back to waiting, not exit or panic.
    assert!(
        !engine.is_finished(),
        "engine task must survive retry exhaustion and keep running",
    );

    // Cancel cleanly and join within a tight deadline.
    cancel_tx.send(true).unwrap();
    drop(intent_tx);
    tokio::time::timeout(std::time::Duration::from_millis(500), engine)
        .await
        .expect("engine task must exit promptly after cancel")
        .expect("engine task must not panic");
    // The test owns the worker thread now (as boot does in production). The
    // coordinator future dropped its request sender on exit, so the worker's
    // recv() has erred — join it so the thread doesn't leak past the test.
    worker.join().expect("worker thread must not panic");
}

/// Pins that a mid-retry parent switch grants the new tip a FULL
/// visibility-retry budget (the `budget_parent` reset in `run_mining_engine`).
///
/// ## Why the old test didn't pin anything
///
/// The previous version waited for A's exhaustion warn before sending B.  At
/// that point the inner retry loop had already `break`-ed and returned to the
/// outer loop, which re-declares `let mut attempts = 0` when B wakes it — so
/// the test passed even WITHOUT the `budget_parent` reset fix: the outer loop
/// always reset.  The bug only manifests when B is picked up by the INNER
/// loop's re-borrow while A's budget is partially spent (mid-`TipNotVisible`
/// retry), which is exactly what this test arms.
///
/// ## Timing design
///
/// Budget constants: `MAX_VIS_RETRIES = 40`, `VIS_BACKOFF = 25 ms` →
/// a fresh budget takes ≥ 40 × 25 ms = 1 000 ms of backoff before exhausting.
///
/// 1. Send A (parent `[0x42;32]`, h5) and arm the engine.
/// 2. Sleep 500 ms — A is mid-retry (≈ 20 of 40 retries burned).
///    If an exhaustion warn already appeared the scenario didn't arm (the
///    runner is pathologically slow or the clock ran fast); return early with
///    a note rather than failing — the sibling exhaustion test still covers
///    liveness, and a flaky-slow runner should not count as a test failure.
/// 3. Send B (parent `[0x43;32]`, h5) while A's inner loop is still running.
///    The engine's next `borrow_and_update` sees B; because B's parent differs
///    from A's, the `budget_parent` guard resets `attempts = 0`.  A's remaining
///    retries are abandoned (A's exhaustion warn never fires).
/// 4. Poll for the FIRST exhaustion warn (30 s cap).  Record `warn_at`.
/// 5. Assert:
///    - Exactly ONE exhaustion warn total (A's never fired; B's did once).
///    - `warn_at − b_sent ≥ 950 ms`: a full fresh budget of 40 × 25 ms = 1 000 ms
///      of backoff cannot exhaust in under 950 ms.  With the fix the warn
///      cannot arrive earlier; without the fix B inherits ≈ 20 burned retries
///      and the warn lands at ≈ 500 ms, failing the bound.
///      Lower-bound asserts are flake-safe: sleeps never finish early, so a
///      slow CI only pushes the time later, never below the bound.
///
/// ## Honest limitations
///
/// A pathologically slow runner that burned < 2 retries by the time B is sent
/// would mask a buggy inherited budget (the inherited count would still be < 2,
/// and the warn would still take ≈ 950 ms).  The 500 ms arm window and the
/// step-2 early-return guard make that scenario remote in practice.
#[tokio::test]
async fn visibility_retry_budget_resets_on_parent_change() {
    use ergo_crypto::difficulty::DifficultyParams;
    use ergo_mempool::MempoolReadSnapshot;
    use ergo_mining::emission_rules::MonetarySettings;
    use ergo_mining::engine::{BuildIntent, BuildReason};
    use ergo_mining::handle::MiningHandle;
    use ergo_mining::reemission::ReemissionSettings;
    use ergo_state::store::StateStore;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::sync::watch;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedBuf {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_target(false)
        .with_ansi(false)
        .with_writer(buf.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let tmp = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(tmp.path().join("s.redb").as_path()).unwrap();
    let mut box_id = [0u8; 32];
    box_id[31] = 1;
    store
        .initialize_genesis(&[(box_id, vec![0xAAu8; 32])])
        .unwrap();
    let reader = store.reader_handle();

    let handle = MiningHandle::new(
        [0x02u8; 33],
        MonetarySettings::mainnet(),
        Some(ReemissionSettings::mainnet()),
        DifficultyParams::mainnet(),
        ergo_validation::VotingSettings::mainnet(),
    );

    // Step 1 — Intent A: parent [0x42;32], height 5 — commit-visible never
    // (genesis store has height 0, intent expects height 5).
    let intent_a = BuildIntent {
        expected_parent: [0x42u8; 32],
        expected_height: 5,
        mempool: Arc::new(MempoolReadSnapshot::empty()),
        miner_pk: [0x02u8; 33],
        reason: BuildReason::Startup,
    };

    let (intent_tx, intent_rx) = watch::channel(Some(intent_a));
    let (cancel_tx, cancel_rx) = watch::channel(false);

    // Bump the watch version so the engine's first `changed()` fires
    // (watch::channel initialises sender and receiver at the same version,
    // so the engine would block on `changed()` without this bump).
    intent_tx.send_if_modified(|_| true);

    let _a_started = Instant::now();
    let (engine, worker) = spawn_engine_with_worker(reader, handle, None, intent_rx, cancel_rx);

    const EXHAUSTION_MSG: &str =
        "mining engine: commit-visibility retries exhausted; awaiting next intent";

    // Step 2 — Sleep 500 ms: A is mid-retry (≈ 20 of 40 retries burned).
    // After waking, check that NO exhaustion warn has appeared yet.
    // If one has — pathologically slow runner or unexpectedly fast clock —
    // the scenario didn't arm; return early rather than failing spuriously.
    tokio::time::sleep(Duration::from_millis(500)).await;
    {
        let output = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
        if output.contains(EXHAUSTION_MSG) {
            eprintln!(
                "visibility_retry_budget_resets_on_parent_change: \
                 scenario did not arm — A exhausted before B was sent \
                 (slow runner or fast clock); skipping timing assertion. \
                 The sibling exhaustion test still covers liveness."
            );
            cancel_tx.send(true).unwrap();
            drop(intent_tx);
            tokio::time::timeout(Duration::from_millis(500), engine)
                .await
                .expect("engine task must exit promptly after cancel")
                .expect("engine task must not panic");
            worker.join().expect("worker thread must not panic");
            return;
        }
    }

    // Step 3 — Send B mid-retry.  The engine's NEXT `borrow_and_update` sees B;
    // because B's parent differs from A's, the `budget_parent` guard resets
    // `attempts = 0`.  A's remaining retries are abandoned silently.
    let intent_b = BuildIntent {
        expected_parent: [0x43u8; 32],
        expected_height: 5,
        mempool: Arc::new(MempoolReadSnapshot::empty()),
        miner_pk: [0x02u8; 33],
        reason: BuildReason::Tip,
    };
    intent_tx.send(Some(intent_b)).unwrap();
    let b_sent = Instant::now();

    // Step 4 — Poll for the FIRST exhaustion warn (30 s cap).
    let deadline = Instant::now() + Duration::from_secs(30);
    let warn_observed = loop {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let output = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
        if output.contains(EXHAUSTION_MSG) {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
    };
    let warn_at = Instant::now();

    assert!(
        warn_observed,
        "timed out (30 s) waiting for exhaustion warn after intent-B was sent"
    );

    // Step 5a — Exactly ONE exhaustion warn total.
    // A's was never emitted (the supersession consumed its remaining budget);
    // B's fired exactly once.
    let output = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
    let warn_count = output.matches(EXHAUSTION_MSG).count();
    assert_eq!(
        warn_count, 1,
        "expected exactly one exhaustion warn (B's); A's should have been \
         abandoned when B superseded it mid-retry; got {warn_count}",
    );

    // Step 5b — Lower-bound timing: a full fresh budget of 40 × 25 ms = 1 000 ms
    // of backoff cannot exhaust in under 950 ms.  With the fix the warn cannot
    // arrive earlier; without the fix B inherits ≈ 20 burned retries and the
    // warn lands at ≈ 500 ms, failing this bound.  Lower-bound asserts are
    // flake-safe: sleeps never complete early, so a slow CI only pushes the
    // time further above the threshold.
    let elapsed = warn_at.duration_since(b_sent);
    assert!(
        elapsed >= Duration::from_millis(950),
        "exhaustion warn arrived only {elapsed:?} after B was sent; \
         a fresh 40-retry budget at 25 ms/retry requires ≥ 950 ms — \
         B appears to have inherited A's partially-spent retry counter",
    );

    // Task alive after the single exhaustion event.
    assert!(
        !engine.is_finished(),
        "engine task must survive exhaustion and keep running",
    );

    cancel_tx.send(true).unwrap();
    drop(intent_tx);
    tokio::time::timeout(Duration::from_millis(500), engine)
        .await
        .expect("engine task must exit promptly after cancel")
        .expect("engine task must not panic");
    worker.join().expect("worker thread must not panic");
}

// ----- digest-mode (Mode 5) survival: handshake / sync / API seams -----

/// The handshake arm's SyncInfo fallback builds the payload from
/// `&state.store` via the backend-agnostic `ChainView`, not the
/// UTXO-narrowed `as_utxo()`. On a digest backend the old `.expect()`
/// would have panicked; here it must produce a `CODE_SYNC_INFO` frame
/// whose bytes match calling `build_sync_info_payload` directly on the
/// same store (the seam is internal, so self-consistency is the bar).
#[test]
fn handshake_complete_digest_backend_sends_sync_info_without_panic() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_digest_state(&tmp.path().join("digest.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let sync_version = SyncVersion::V1;

    // Register the peer with an outbound channel we can drain, mirroring
    // the `state.registry.peers.insert` the handshake arm performs.
    let (tx, mut rx) = crate::peer_loop::outbound::channel(4);
    state.registry.peers.insert(
        peer,
        PeerRuntime {
            sync_version,
            outbound_tx: tx,
        },
    );

    // Expected bytes: `build_sync_info_payload` over the digest store
    // directly. This is the exact call the fixed handshake arm makes.
    let expected =
        ergo_sync::coordinator::build_sync_info_payload(sync_version, &state.store).unwrap();

    // Run the fixed seam: anchor scheduler is off in the fixture, so
    // `try_send_anchor_sync_info` returns false and the fallback path
    // (the one the fix touches) fires.
    assert!(
        !try_send_anchor_sync_info(&mut state, &peer, now),
        "anchor scheduler is disabled in the fixture; fallback must run",
    );
    let payload =
        ergo_sync::coordinator::build_sync_info_payload(sync_version, &state.store).unwrap();
    assert!(send_to_peer(
        &state,
        &peer,
        message::CODE_SYNC_INFO,
        payload
    ));

    let frame = rx.try_recv().expect("a SyncInfo frame must be queued");
    assert_eq!(frame.code, message::CODE_SYNC_INFO);
    assert_eq!(frame.payload, expected);
}

/// `request_missing_sections` takes `&dyn ChainView`; on a digest
/// backend `&state.store` routes to the digest header tables instead of
/// panicking through `as_utxo()`. With no eligible peers it returns no
/// actions — the point is that the call survives.
#[test]
fn request_missing_sections_digest_backend_no_panic() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_digest_state(&tmp.path().join("digest.redb"));
    let now = Instant::now();

    let actions = state.executor.request_missing_sections(
        &mut state.coordinator,
        &state.store,
        &state.peer_manager,
        now,
    );
    assert!(
        actions.is_empty(),
        "no peers registered, so no section requests: {actions:?}",
    );
}

/// `maybe_exit_ibd` is a no-op on a digest backend: `as_utxo_mut()` returns
/// `None`, so the function returns without touching anything. Calling it with
/// condition-satisfying values (fb advanced, gap < 10) must not panic.
#[test]
fn ibd_auto_exit_digest_backend_skips_utxo_branch() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_digest_state(&tmp.path().join("digest.redb"));
    // Confirm the guard's enabling condition: no UTXO arena on a digest store.
    assert!(
        state.store.as_utxo_mut().is_none(),
        "digest backend exposes no UTXO arena — maybe_exit_ibd must be a no-op",
    );
    // Calling with condition-satisfying values must be a silent no-op, not a panic.
    maybe_exit_ibd(&mut state.store, 0, 5, 7);
}

/// `maybe_exit_ibd` exits IBD mode on a UTXO backend when the full-block tip
/// advances within 10 of the header tip.
#[test]
fn ibd_auto_exit_utxo_backend_exits_ibd_when_near_tip() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("utxo.redb"));
    // Arm IBD mode (same call as boot.rs:664).
    state.store.as_utxo_mut().unwrap().set_ibd_mode(true, 50);
    assert!(
        state.store.as_utxo_mut().unwrap().ibd_mode(),
        "pre-condition: IBD armed"
    );

    // Condition-satisfying call: fb advanced (0→5), bh=7, gap=2 < 10.
    maybe_exit_ibd(&mut state.store, 0, 5, 7);
    assert!(
        !state.store.as_utxo_mut().unwrap().ibd_mode(),
        "IBD must have exited when gap < 10",
    );
}

/// `maybe_exit_ibd` leaves IBD mode unchanged when the gap is >= 10.
#[test]
fn ibd_auto_exit_utxo_backend_stays_ibd_when_gap_large() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("utxo.redb"));
    state.store.as_utxo_mut().unwrap().set_ibd_mode(true, 50);

    // Gap = bh - fb = 100 - 5 = 95, well above the threshold.
    maybe_exit_ibd(&mut state.store, 0, 5, 100);
    assert!(
        state.store.as_utxo_mut().unwrap().ibd_mode(),
        "IBD must stay armed when gap >= 10",
    );
}

/// API admission rejects with the `Disabled` wire shape when the mempool
/// is off — which a digest node always is (production force-disables it).
/// The guard short-circuits before `build_tip_context` / `as_utxo()`, so
/// both submit intents return `reason: "disabled"` instead of panicking
/// or surfacing a misleading `tip_unready` error.
#[test]
fn api_submit_without_mempool_rejects_disabled() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_digest_state(&tmp.path().join("digest.redb"));
    assert!(
        !state.mempool.config().enabled,
        "a digest fixture must have the mempool force-disabled",
    );
    let now = Instant::now();

    use ergo_api::types::SubmitMode;
    for mode in [SubmitMode::Broadcast, SubmitMode::CheckOnly] {
        let err = super::admission::admit_api_transaction(&mut state, &[0u8; 8], mode, now)
            .expect_err("mempool-off admission must reject");
        assert_eq!(err.reason, "disabled", "{mode:?} should reject as disabled");
    }
}

/// The memory sampler emits a row on a digest backend: the UTXO-arena
/// columns read 0 (via `as_utxo().map(...).unwrap_or(0)`) rather than
/// panicking through the old `.expect()`. Asserts a data row is appended
/// AND that every UTXO-only column in it is exactly "0", keyed by column
/// name off the CSV header so the check survives schema reordering.
#[test]
fn memory_sample_digest_backend_emits_zeroed_arena_row() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_digest_state(&tmp.path().join("digest.redb"));
    let csv_path = tmp.path().join("mem.csv");
    let mut file: Option<std::fs::File> = None;

    super::memory_sampler::sample_memory(&state, &csv_path, &mut file);

    assert!(file.is_some(), "sampler must open the CSV file");
    let contents = std::fs::read_to_string(&csv_path).unwrap();
    let mut lines = contents.lines();
    let header: Vec<&str> = lines.next().expect("header line").split(',').collect();
    let row: Vec<&str> = lines.next().expect("one data row").split(',').collect();
    assert_eq!(
        header.len(),
        row.len(),
        "data row column count must match the header",
    );

    // Every column sourced from the UTXO arena must read 0 on a digest
    // backend (these are the columns the fix routes through
    // `as_utxo().map(...).unwrap_or(0)`).
    for col in [
        "avl_cache_clean_bytes",
        "avl_cache_capacity_bytes",
        "avl_clean_len",
        "avl_dirty_len",
        "avl_read_count",
        "batch_headers_len",
        "batch_headers_bytes",
        "batch_meta_len",
        "redb_state_evictions",
    ] {
        let idx = header
            .iter()
            .position(|h| *h == col)
            .unwrap_or_else(|| panic!("column {col} missing from header"));
        assert_eq!(row[idx], "0", "digest backend must zero-fill {col}");
    }
}

// ---- SyncInfo stamp = transport DISPATCH success (PR #251 follow-up) ----

fn register_connected_peer(
    state: &mut NodeState,
    peer: ergo_p2p::peer::PeerId,
) -> crate::peer_loop::outbound::Receiver {
    let (tx, rx) = crate::peer_loop::outbound::channel(8);
    state.registry.peers.insert(
        peer,
        super::state::PeerRuntime {
            sync_version: SyncVersion::V2,
            outbound_tx: tx,
        },
    );
    rx
}

#[test]
fn sync_info_dispatch_success_stamps_last_sync_sent() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 9, 1)), 9030);
    let mut rx = register_connected_peer(&mut state, peer);

    assert!(
        state
            .coordinator
            .sync_state_mut()
            .not_synced_or_outdated(peer, Instant::now()),
        "peer starts not-synced (never dispatched to)"
    );

    flush_actions(
        &mut state,
        vec![Action::SendToPeer {
            peer,
            code: message::CODE_SYNC_INFO,
            payload: vec![0x01],
        }],
    );

    // The frame was accepted by the channel; drain it to prove dispatch.
    let frame = rx.try_recv().expect("SyncInfo frame must be queued");
    assert_eq!(frame.code, message::CODE_SYNC_INFO);
    assert!(
        !state
            .coordinator
            .sync_state_mut()
            .not_synced_or_outdated(peer, Instant::now()),
        "successful dispatch must stamp last_sync_sent"
    );
}

#[test]
fn sync_info_failed_dispatch_does_not_stamp_last_sync_sent() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    // Peer NOT registered in the registry ⇒ try_send fails (closed/absent).
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 9, 2)), 9030);

    flush_actions(
        &mut state,
        vec![Action::SendToPeer {
            peer,
            code: message::CODE_SYNC_INFO,
            payload: vec![0x01],
        }],
    );

    assert!(
        state
            .coordinator
            .sync_state_mut()
            .not_synced_or_outdated(peer, Instant::now()),
        "failed dispatch must leave the timestamp untouched"
    );
}

// ----- throughput throttle: solicited deliveries are never dropped -----

/// Fill `peer`'s byte window until the NEXT frame of any size exceeds it,
/// whatever the peer has already spent. Drives the limiter's own accounting
/// rather than a hand-computed constant, so it stays correct if the default
/// budget changes.
fn saturate_byte_window(state: &mut NodeState, peer: SocketAddr, now: Instant) {
    use ergo_p2p::throttle::LimiterVerdict;
    let mut chunk = 1_000_000u32;
    // Shrink the fill frame as the window nears full so the last of the budget
    // is actually spent rather than left as an unreachable remainder.
    while chunk > 0 {
        match state.throttle.check_and_record(peer, now, chunk) {
            LimiterVerdict::Ok => {}
            LimiterVerdict::ByteRateExceeded => chunk /= 2,
            LimiterVerdict::MessageRateExceeded => {
                panic!("window fill must not hit the message cap")
            }
        }
    }
    assert_eq!(
        state.throttle.check_and_record(peer, now, 1),
        LimiterVerdict::ByteRateExceeded,
        "the window must now be saturated",
    );
}

/// A canonical ADProofs section of roughly `payload_len` bytes, paired with the
/// modifier id it actually hashes to. ADProofs is the cheapest section to
/// synthesize (its content digest is just `blake2b256(proof_bytes)`), and using
/// real bytes keeps the throttle assertion honest: the frame must survive the
/// downstream `verify_section_modifier_id` check too, so a `Penalize` in the
/// result can only have come from the throttle.
fn canonical_ad_proofs_section(payload_len: usize) -> ([u8; 32], Vec<u8>) {
    use ergo_primitives::digest::{blake2b256, ModifierId};
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::modifier_id::{compute_section_id, TYPE_AD_PROOFS};

    let header_id = [0x42u8; 32];
    let proof_bytes = vec![0xAAu8; payload_len];
    let content_digest = *blake2b256(&proof_bytes).as_bytes();
    let section_id = compute_section_id(TYPE_AD_PROOFS, &header_id, &content_digest);
    let mut w = VlqWriter::new();
    ergo_ser::ad_proofs::write_ad_proofs(
        &mut w,
        &ergo_ser::ad_proofs::ADProofs {
            header_id: ModifierId::from_bytes(header_id),
            proof_bytes,
        },
    );
    (section_id, w.result())
}

/// The liveness property: a `Modifier` frame delivering something we requested
/// must not be dropped by the byte axis. Dropping it makes our own delivery
/// checker time the request out and charge the honest holder a `NonDelivery`
/// penalty for a drop we caused — self-inflicted eviction of the peer that was
/// serving us. Body catch-up from a single holder is exactly the traffic
/// pattern that saturates a 2 MB/s cap.
#[test]
fn byte_throttle_over_cap_modifier_frame_admitted_without_penalty() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let (section_id, section_bytes) = canonical_ad_proofs_section(4096);

    // Solicit it first, so the delivery below is one we actually asked this
    // peer for — the case the byte axis must never drop.
    let inv = message::serialize_inv(&InvData {
        type_id: ModifierTypeId::ADProofs.as_byte(),
        ids: vec![section_id],
    })
    .expect("serialize inv");
    let requested = handle_message(&mut state, peer, message::CODE_INV, &inv, now);
    assert!(
        requested.iter().any(|a| matches!(
            a,
            Action::SendToPeer { code, .. } if *code == message::CODE_REQUEST_MODIFIER
        )),
        "the section must actually be requested for this test to mean anything: {requested:?}",
    );

    saturate_byte_window(&mut state, peer, now);

    let payload = message::serialize_modifiers(&ergo_p2p::types::ModifiersData {
        type_id: ModifierTypeId::ADProofs.as_byte(),
        modifiers: vec![(section_id, section_bytes)],
    })
    .expect("serialize modifiers");
    let actions = handle_message(&mut state, peer, message::CODE_MODIFIER, &payload, now);

    assert!(
        !actions.iter().any(|a| matches!(a, Action::Penalize { .. })),
        "an over-cap delivery of a modifier we requested must not penalize the holder: \
         {actions:?}",
    );
}

/// The exemption is decided on the delivery tracker, not the opcode. A peer
/// re-sending a section we already received resolves to `DeliveryAction::Ignore`,
/// so it stays on the drop-and-penalize path — otherwise the byte cap would be
/// inoperative for `CODE_MODIFIER` and a peer could replay a legitimately
/// delivered 8 MB section at the message rate for free.
#[test]
fn byte_throttle_over_cap_replayed_modifier_frame_drops_and_penalizes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let (section_id, section_bytes) = canonical_ad_proofs_section(4096);

    // Request it, then deliver it once under the cap so it lands in the
    // tracker's received set.
    let inv = message::serialize_inv(&InvData {
        type_id: ModifierTypeId::ADProofs.as_byte(),
        ids: vec![section_id],
    })
    .expect("serialize inv");
    let _ = handle_message(&mut state, peer, message::CODE_INV, &inv, now);
    let payload = message::serialize_modifiers(&ergo_p2p::types::ModifiersData {
        type_id: ModifierTypeId::ADProofs.as_byte(),
        modifiers: vec![(section_id, section_bytes)],
    })
    .expect("serialize modifiers");
    let _ = handle_message(&mut state, peer, message::CODE_MODIFIER, &payload, now);
    assert_eq!(
        state.coordinator.delivery().status(&section_id),
        ergo_p2p::delivery::ModifierStatus::Received,
        "the first delivery must have been accepted for the replay to be a replay",
    );

    saturate_byte_window(&mut state, peer, now);
    let actions = handle_message(&mut state, peer, message::CODE_MODIFIER, &payload, now);

    assert!(
        actions.iter().any(|a| matches!(
            a,
            Action::Penalize {
                penalty: Penalty::Misbehavior,
                ..
            }
        )),
        "an over-cap replay of an already-received section must be dropped and penalized: \
         {actions:?}",
    );
}

/// Charge `peer`'s byte window up to `headroom` bytes short of the cap, so the
/// next frame larger than `headroom` is over-cap while a 1-byte probe still
/// fits. Lets a test tell "the exempt frame was charged" apart from "the
/// window was already full".
fn fill_byte_window_leaving(state: &mut NodeState, peer: SocketAddr, now: Instant, headroom: u64) {
    use ergo_p2p::throttle::LimiterVerdict;
    let mut remaining = state.throttle.limits().max_bytes_per_window - headroom;
    while remaining > 0 {
        let chunk = remaining.min(u32::MAX as u64) as u32;
        assert_eq!(
            state.throttle.check_and_record(peer, now, chunk),
            LimiterVerdict::Ok,
            "pre-fill must stay under the cap"
        );
        remaining -= chunk as u64;
    }
    assert_eq!(
        state.throttle.check_and_record(peer, now, 1),
        LimiterVerdict::Ok,
        "a 1-byte probe must still fit inside the headroom",
    );
}

/// The byte axis still charges the exempted frame, so a peer cannot mint free
/// bandwidth by sending only `Modifier` frames — its next non-exempt frame is
/// judged against the true window.
#[test]
fn byte_throttle_over_cap_modifier_frame_still_charged_to_the_window() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let budget = state.throttle.limits().max_bytes_per_window;
    let (section_id, section_bytes) = canonical_ad_proofs_section(4096);

    let inv = message::serialize_inv(&InvData {
        type_id: ModifierTypeId::ADProofs.as_byte(),
        ids: vec![section_id],
    })
    .expect("serialize inv");
    let _ = handle_message(&mut state, peer, message::CODE_INV, &inv, now);

    // Leave a sliver of headroom: the 4 KiB delivery below is over-cap (and so
    // takes the exempt path), but a 1-byte probe fits UNLESS that delivery was
    // charged. Fully saturating the window here would make the final
    // assertion pass even if the exempt frame were never recorded.
    fill_byte_window_leaving(&mut state, peer, now, 64);

    let payload = message::serialize_modifiers(&ergo_p2p::types::ModifiersData {
        type_id: ModifierTypeId::ADProofs.as_byte(),
        modifiers: vec![(section_id, section_bytes)],
    })
    .expect("serialize modifiers");
    let _ = handle_message(&mut state, peer, message::CODE_MODIFIER, &payload, now);

    assert_eq!(
        state.throttle.check_and_record(peer, now, 1),
        ergo_p2p::throttle::LimiterVerdict::ByteRateExceeded,
        "the exempted delivery must remain charged (budget {budget})",
    );
}

/// Contrast case: the exemption is narrow. Any other over-cap frame still
/// drops and still penalizes — the byte axis keeps its teeth for traffic we
/// did not ask for.
#[test]
fn byte_throttle_over_cap_non_modifier_frame_drops_and_penalizes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    saturate_byte_window(&mut state, peer, now);

    let payload = message::serialize_inv(&InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![mid(1)],
    })
    .expect("serialize inv");
    let actions = handle_message(&mut state, peer, message::CODE_INV, &payload, now);

    assert!(
        actions.iter().any(|a| matches!(
            a,
            Action::Penalize {
                penalty: Penalty::Misbehavior,
                ..
            }
        )),
        "an over-cap non-delivery frame must still be dropped and penalized: {actions:?}",
    );
}

#[test]
fn coalesced_over_throttle_header_is_penalized_without_validation() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);
    let rejected_id = mid(1);
    // A real header: admission checks that the bytes hash to the requested
    // id, and a header that then fails validation has its delivery rolled
    // back, so only a genuine header stays `Received`.
    let admitted_bytes = hex::decode(POPOW_GENESIS_HEX).unwrap();
    let admitted_id = *ergo_primitives::digest::blake2b256(&admitted_bytes).as_bytes();
    let rejected_payload = message::serialize_modifiers(&ergo_p2p::types::ModifiersData {
        type_id: ModifierTypeId::Header.as_byte(),
        modifiers: vec![(rejected_id, vec![0u8; 1024])],
    })
    .unwrap();
    let admitted_payload = message::serialize_modifiers(&ergo_p2p::types::ModifiersData {
        type_id: ModifierTypeId::Header.as_byte(),
        modifiers: vec![(admitted_id, admitted_bytes)],
    })
    .unwrap();
    let admitted_frame_bytes = (admitted_payload.len() + 9) as u64;
    fill_byte_window_leaving(&mut state, peer, now, admitted_frame_bytes + 2);
    assert_eq!(
        state.coordinator.delivery_mut().request(
            peer,
            ModifierTypeId::Header.as_byte(),
            &[admitted_id],
            now
        ),
        vec![admitted_id]
    );

    let rejected_event_payload =
        crate::peer_loop::MeteredPayload::for_test(rejected_payload, &state.event_byte_budget);
    let admitted_event_payload =
        crate::peer_loop::MeteredPayload::for_test(admitted_payload, &state.event_byte_budget);
    super::events::handle_event_batch(
        &mut state,
        vec![
            PeerEvent::Message {
                peer,
                code: message::CODE_MODIFIER,
                payload: rejected_event_payload,
            },
            PeerEvent::Message {
                peer,
                code: message::CODE_MODIFIER,
                payload: admitted_event_payload,
            },
        ],
    );

    assert_eq!(state.sections_received_total, 1);
    assert_eq!(
        state.coordinator.delivery().status(&rejected_id),
        ergo_p2p::delivery::ModifierStatus::Unknown
    );
    assert_eq!(
        state.coordinator.delivery().status(&admitted_id),
        ergo_p2p::delivery::ModifierStatus::Received
    );
    assert_eq!(state.peer_manager.get(&peer).unwrap().score.raw_score(), 10);
}

// ----- duplicate inbound drop (issue #293) -----

/// A `HandshakeComplete` for an address the registry already holds — a
/// late event from a previous dial, or an inbound connection from a
/// reused ephemeral port — leaves the existing runtime untouched and
/// drops the new connection. Replacing the runtime is not safe: both the
/// registry and `PeerEvent::Disconnected` are keyed by remote address
/// alone, so the old connection's teardown would then evict the peer we
/// had just swapped in. Scala drops the duplicate for the same reason
/// (`NetworkController.handleHandshake`, NetworkController.scala:417-424).
/// The branch now emits a `reason = "address_still_registered"` DEBUG
/// line so an operator can tell this drop from a network fault.
#[tokio::test]
async fn handshake_complete_for_registered_address_keeps_existing_runtime() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("dup.redb"));
    let peer = test_peer();

    // The incumbent runtime, whose channel must survive the duplicate.
    let (tx, mut rx) = crate::peer_loop::outbound::channel(4);
    state.registry.peers.insert(
        peer,
        PeerRuntime {
            sync_version: SyncVersion::V1,
            outbound_tx: tx,
        },
    );

    // A real socket for the duplicate connection: the drop must close it.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
    let client = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
    let server = accept.await.unwrap();
    let conn = Box::new(ergo_p2p::connection::Connection::new(server, state.magic));

    super::events::handle_event_batch(
        &mut state,
        vec![PeerEvent::HandshakeComplete {
            addr: peer,
            peer_spec: PeerSpec {
                agent_name: "dup".into(),
                version: Version::NIPOPOW,
                node_name: "dup".into(),
                declared_address: None,
                features: Vec::new(),
            },
            time: 0,
            conn,
        }],
    );

    assert_eq!(
        state.registry.peers.len(),
        1,
        "the duplicate must not add or replace a registry entry",
    );
    assert!(
        state
            .registry
            .try_send(&peer, message::CODE_SYNC_INFO, Vec::new()),
        "the incumbent runtime's channel must still be usable",
    );
    assert_eq!(
        rx.try_recv().expect("frame reaches the incumbent").code,
        message::CODE_SYNC_INFO,
    );
    assert!(
        state.peer_manager.get(&peer).is_none(),
        "the dropped duplicate must not complete a handshake",
    );
    drop(client);
}

// ----- NiPoPoW proof vs the header checkpoint (ingress) -----

/// Mainnet genesis header, hex, as served on the wire. The only real header
/// that passes validation on an empty store, so delivery tests use it as a
/// genuinely admitted header.
const POPOW_GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b";

/// Mainnet height-2 header, hex, as served on the wire. Same
/// vector the `ergo-sync` popow reducer tests use; duplicated here because
/// this test drives the node's real message dispatch rather than the reducer.
const POPOW_HEIGHT_2_HEX: &str = "01b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b828b0f6a0e6cb98ed4649c6e4cc00599ae78755324c79a8cec51e94ecca339d7a3a11a92de9c0ba1e95068f39bc1e08afa4ca23dff16de135fac64d0cf7dd1ab6291b70477f591ee8efb8a962d36ddbe3ac57591e39fe45ffb8c51c4939e41980387d9cfe9ba2d6b46bcba6f750f5be67d89679e921b78c277c5546a08cdb0955376fa0ea271e30601176502000000033c46c7fd7085638bf4bc902badb4e5a1942d3251d92d0eddd6fbe5d57e91553703df646d7f6138aede718a2a4f1a76d4125750e8ab496b7a8a25292d07e14cbadb0000000a03d0d0191b06164a2e86a170f0d8ac96cffa2e3312f2f5b0b1c3b1e082b9a0cd";

fn popow_proof_frame() -> Vec<u8> {
    use ergo_primitives::digest::ModifierId;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::{read_header, serialize_header, Header};
    use ergo_ser::popow_header::PoPowHeader;
    use ergo_ser::popow_proof::NipopowProof;

    let raw = std::fs::read_to_string(format!(
        "{}/../test-vectors/mainnet/headers_1_2000.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let values: Vec<serde_json::Value> = serde_json::from_str(&raw).unwrap();
    let headers: Vec<Header> = values
        .iter()
        .take(11)
        .map(|value| {
            let bytes = hex::decode(value["bytes"].as_str().unwrap()).unwrap();
            read_header(&mut VlqReader::new(&bytes)).unwrap()
        })
        .collect();
    assert_eq!(headers.len(), 11);

    let (_bytes, genesis_id) = serialize_header(&headers[0]).unwrap();
    let popow_hdr = |h: Header| -> PoPowHeader {
        if h.height == 1 {
            return PoPowHeader {
                header: h,
                interlinks: vec![],
                interlinks_proof: vec![0u8; 8],
            };
        }
        let links = vec![ModifierId::from_bytes(*genesis_id.as_bytes())];
        let fields = ergo_validation::popow::algos::pack_interlinks(&links);
        ergo_validation::popow::algos::build_popow_header(h, links, &fields).unwrap()
    };
    let proof = NipopowProof {
        m: ergo_p2p::types::P2P_NIPOPOW_PROOF_M as u32,
        k: ergo_p2p::types::P2P_NIPOPOW_PROOF_K as u32,
        prefix: vec![popow_hdr(headers[0].clone())],
        suffix_head: popow_hdr(headers[1].clone()),
        suffix_tail: headers[2..].to_vec(),
        continuous: true,
    };
    let body = ergo_ser::popow_proof::serialize_nipopow_proof(&proof).unwrap();
    message::serialize_nipopow_proof(&body).unwrap()
}

fn state_with_popow_bootstrap(state: &mut NodeState) {
    state.popow_bootstrap = Some(ergo_sync::popow_bootstrap::PopowBootstrap::new(
        2,
        None,
        DifficultyParams::mainnet(),
    ));
}

#[test]
fn popow_proof_wrong_profile_penalizes_peer_and_records_response() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    state_with_popow_bootstrap(&mut state);

    let valid_frame = popow_proof_frame();
    let body = message::deserialize_nipopow_proof(&valid_frame).unwrap();
    let mut proof = ergo_ser::popow_proof::deserialize_nipopow_proof(&body).unwrap();
    proof.m = 5;
    let body = ergo_ser::popow_proof::serialize_nipopow_proof(&proof).unwrap();
    let wrong_frame = message::serialize_nipopow_proof(&body).unwrap();
    let peer = test_peer();
    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_NIPOPOW_PROOF,
        &wrong_frame,
        Instant::now(),
    );

    assert!(
        matches!(
            actions.as_slice(),
            [Action::Penalize { peer: p, penalty: Penalty::Misbehavior }] if *p == peer
        ),
        "a first wrong-profile response must be rejected, not treated as a duplicate: {actions:?}"
    );
    let popow = state.popow_bootstrap.as_ref().unwrap();
    assert_eq!(popow.provider_count(), 1);
    assert_eq!(popow.proofs_processed(), 0);
    assert!(popow.best_proof().is_none());
    assert!(!popow.quorum_reached());

    // Both invalid and corrected retries from this provider are duplicates.
    for frame in [wrong_frame, valid_frame] {
        let actions = handle_message(
            &mut state,
            peer,
            message::CODE_NIPOPOW_PROOF,
            &frame,
            Instant::now(),
        );
        assert!(actions.is_empty(), "duplicate response: {actions:?}");
        let popow = state.popow_bootstrap.as_ref().unwrap();
        assert_eq!(popow.provider_count(), 1);
        assert_eq!(popow.proofs_processed(), 0);
    }
}

// ----- error paths -----

#[test]
fn popow_proof_difficulty_error_penalizes_and_logs_reason() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    state_with_popow_bootstrap(&mut state);
    let frame = popow_proof_frame();
    let body = message::deserialize_nipopow_proof(&frame).unwrap();
    let mut proof = ergo_ser::popow_proof::deserialize_nipopow_proof(&body).unwrap();
    proof.suffix_tail.last_mut().unwrap().n_bits ^= 1;
    let body = ergo_ser::popow_proof::serialize_nipopow_proof(&proof).unwrap();
    let frame = message::serialize_nipopow_proof(&body).unwrap();
    let log_path = tmp.path().join("difficulty.log");
    let log_file = std::fs::File::create(&log_path).unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || log_file.try_clone().unwrap())
        .finish();
    let peer = test_peer();
    let actions = tracing::subscriber::with_default(subscriber, || {
        handle_message(
            &mut state,
            peer,
            message::CODE_NIPOPOW_PROOF,
            &frame,
            Instant::now(),
        )
    });
    assert!(matches!(actions.as_slice(),
        [Action::Penalize { peer: p, penalty: Penalty::Misbehavior }] if *p == peer));
    let log = std::fs::read_to_string(log_path).unwrap();
    assert!(log.contains("bootstrap proof rejected"), "{log}");
    assert!(
        log.contains("consensus difficulty mismatch at height 11"),
        "{log}"
    );
    let popow = state.popow_bootstrap.as_ref().unwrap();
    assert_eq!(popow.provider_count(), 1);
    assert_eq!(popow.proofs_processed(), 0);
    assert!(popow.best_proof().is_none());
    let retry = handle_message(
        &mut state,
        peer,
        message::CODE_NIPOPOW_PROOF,
        &frame,
        Instant::now(),
    );
    assert!(retry.is_empty());
}

#[test]
fn popow_proof_violating_checkpoint_penalizes_peer_and_never_reaches_verifier() {
    // A forged proof carrying a different header at the operator's anchor
    // height must be rejected at INGRESS: penalise the sender, and leave the
    // reducer untouched so the forgery neither counts toward quorum nor wins
    // best-proof selection. Marking the bootstrap terminal here would let one
    // such proof disable NiPoPoW for the whole run.
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    state_with_popow_bootstrap(&mut state);
    state
        .executor
        .set_header_checkpoint(Some(ergo_sync::header_proc::HeaderCheckpoint {
            height: 2,
            block_id: [0x7fu8; 32],
        }));

    let peer = test_peer();
    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_NIPOPOW_PROOF,
        &popow_proof_frame(),
        Instant::now(),
    );

    assert!(
        actions.iter().any(|a| matches!(
            a,
            Action::Penalize {
                peer: p,
                penalty: Penalty::Misbehavior,
            } if *p == peer
        )),
        "a proof violating the checkpoint must penalise its sender: {actions:?}"
    );
    let popow = state.popow_bootstrap.as_ref().unwrap();
    assert_eq!(
        popow.proofs_processed(),
        0,
        "the forged proof must never reach the verifier"
    );
    assert!(
        popow.is_active(true),
        "one forged proof must not disable NiPoPoW bootstrap"
    );
    assert!(!popow.quorum_reached());
}

#[test]
fn popow_proof_matching_checkpoint_reaches_the_verifier() {
    // Control for the test above: with the anchor satisfied, the same proof
    // takes the normal path into the verifier and no penalty is emitted.
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::{read_header, serialize_header};

    let raw = hex::decode(POPOW_HEIGHT_2_HEX).unwrap();
    let h2 = read_header(&mut VlqReader::new(&raw)).unwrap();
    let (_bytes, h2_id) = serialize_header(&h2).unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    state_with_popow_bootstrap(&mut state);
    state
        .executor
        .set_header_checkpoint(Some(ergo_sync::header_proc::HeaderCheckpoint {
            height: 2,
            block_id: *h2_id.as_bytes(),
        }));

    let peer = test_peer();
    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_NIPOPOW_PROOF,
        &popow_proof_frame(),
        Instant::now(),
    );

    assert!(
        !actions.iter().any(|a| matches!(a, Action::Penalize { .. })),
        "a proof consistent with the checkpoint must not be penalised: {actions:?}"
    );
    assert_eq!(
        state.popow_bootstrap.as_ref().unwrap().provider_count(),
        1,
        "the proof must have reached the reducer"
    );
}

#[test]
fn ip_ban_cleans_all_ports_and_pending_handshakes_but_keeps_other_ips() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("bans.redb"));
    state.peer_manager = PeerManager::new_with_limits(
        0,
        ergo_p2p::peer_manager::PeerLimits {
            per_ip_limit: 4,
            per_subnet_limit: 8,
            ..Default::default()
        },
    );
    let now = Instant::now();
    let a: SocketAddr = "127.0.0.1:1001".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:1002".parse().unwrap();
    let pending: SocketAddr = "127.0.0.1:1003".parse().unwrap();
    let other: SocketAddr = "127.0.0.2:1001".parse().unwrap();
    let mut rx_a = connect_test_peer(&mut state, a, now);
    let mut rx_b = connect_test_peer(&mut state, b, now);
    let mut rx_other = connect_test_peer(&mut state, other, now);
    state.peer_manager.register_inbound(pending, now).unwrap();
    let mut t = now;
    for _ in 0..40 {
        t += ergo_p2p::peer::SAFE_INTERVAL;
        super::peer_actions::penalize_peer(&mut state, a, Penalty::Spam, t);
        if state.peer_manager.is_banned(&a, t) {
            break;
        }
    }
    assert!(state.peer_manager.is_banned(&b, t));
    assert!(state.peer_manager.get(&a).is_none());
    assert!(state.peer_manager.get(&b).is_none());
    assert!(state.peer_manager.get(&pending).is_none());
    assert!(rx_a.is_closed() && rx_b.is_closed());
    assert!(rx_a.try_recv().is_err() && rx_b.try_recv().is_err());
    assert!(state.peer_manager.get(&other).is_some());
    assert!(send_to_peer(&state, &other, 1, Vec::new()));
    assert_eq!(rx_other.try_recv().unwrap().code, 1);
    // Repeated cleanup with the original socket already absent is harmless.
    super::peer_actions::penalize_peer(&mut state, a, Penalty::Spam, t);
    assert!(state.registry.peers.contains_key(&other));
}

mod post_header_sync {
    use super::*;
    use ergo_p2p::delivery::ModifierStatus;
    use ergo_p2p::types::ModifiersData;
    use ergo_primitives::digest::blake2b256;
    use ergo_state::ChainStateRead;

    // ----- helpers -----

    fn deliver(state: &mut NodeState, peer: SocketAddr, payload: &[u8], coalesced: bool) {
        if coalesced {
            // Two frames exercise coalescing and per-peer deduplication.
            let events = (0..2)
                .map(|_| PeerEvent::Message {
                    peer,
                    code: message::CODE_MODIFIER,
                    payload: crate::peer_loop::MeteredPayload::for_test(
                        payload.to_vec(),
                        &state.event_byte_budget,
                    ),
                })
                .collect();
            super::super::events::handle_event_batch(state, events);
        } else {
            let actions =
                handle_message(state, peer, message::CODE_MODIFIER, payload, Instant::now());
            flush_actions(state, actions);
        }
    }

    fn assert_refresh(
        rx: &mut crate::peer_loop::outbound::Receiver,
        expected: usize,
        id: [u8; 32],
    ) {
        let mut syncs = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            if frame.code == message::CODE_SYNC_INFO {
                syncs.push(frame);
            }
        }
        assert_eq!(syncs.len(), expected);
        for frame in syncs {
            let message::SyncInfo::V2 { headers } =
                message::deserialize_sync_info(&frame.payload).unwrap()
            else {
                panic!("expected V2 SyncInfo");
            };
            assert_eq!(*blake2b256(&headers[0]).as_bytes(), id);
        }
    }

    fn scenario(coalesced: bool, requested: bool, already_applied: bool, duplicate: bool) {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let peer = test_peer();
        let now = Instant::now();
        let mut rx = connect_test_peer(&mut state, peer, now);
        let bytes = hex::decode(POPOW_GENESIS_HEX).unwrap();
        let id = *blake2b256(&bytes).as_bytes();
        if requested {
            let inv = message::serialize_inv(&InvData {
                type_id: ModifierTypeId::Header.as_byte(),
                ids: vec![id],
            })
            .unwrap();
            let actions = handle_message(&mut state, peer, message::CODE_INV, &inv, now);
            flush_actions(&mut state, actions);
            let frame = rx.try_recv().expect("header must be requested from P");
            assert_eq!(frame.code, message::CODE_REQUEST_MODIFIER);
            assert_eq!(
                message::deserialize_inv(&frame.payload).unwrap().ids,
                vec![id]
            );
        }
        if already_applied {
            let (_, actions) = state
                .executor
                .process_local_header(&mut state.store, &mut state.coordinator, &bytes, now)
                .unwrap();
            flush_actions(&mut state, actions);
            assert_eq!(state.store.chain_state_meta().best_header_height, 1);
            assert_eq!(
                state.coordinator.delivery().status(&id),
                ModifierStatus::Requested
            );
        }
        let payload = message::serialize_modifiers(&ModifiersData {
            type_id: ModifierTypeId::Header.as_byte(),
            modifiers: vec![(id, bytes)],
        })
        .unwrap();
        deliver(&mut state, peer, &payload, coalesced);
        assert_refresh(&mut rx, usize::from(requested), id);
        if requested {
            assert_eq!(state.store.chain_state_meta().best_header_height, 1);
            assert!(!state
                .coordinator
                .sync_state_mut()
                .not_synced_or_outdated(peer, Instant::now()));
        }
        if duplicate {
            assert_eq!(
                state.coordinator.delivery().status(&id),
                ModifierStatus::Received
            );
            deliver(&mut state, peer, &payload, coalesced);
            assert_refresh(&mut rx, 0, id);
        }
    }

    // ----- happy path -----

    #[test]
    fn modifier_requested_already_applied_sends_one_sync_info() {
        scenario(false, true, true, false);
    }

    #[test]
    fn coalesced_requested_already_applied_sends_one_sync_info() {
        scenario(true, true, true, false);
    }

    #[test]
    fn modifier_requested_advancing_sends_one_sync_info() {
        scenario(false, true, false, false);
    }

    #[test]
    fn coalesced_requested_advancing_sends_one_sync_info() {
        scenario(true, true, false, false);
    }

    // ----- error paths -----

    #[test]
    fn modifier_unrequested_sends_no_sync_info() {
        scenario(false, false, false, false);
    }

    #[test]
    fn coalesced_unrequested_sends_no_sync_info() {
        scenario(true, false, false, false);
    }

    #[test]
    fn modifier_duplicate_held_sends_no_sync_info() {
        scenario(false, true, false, true);
    }

    #[test]
    fn coalesced_duplicate_held_sends_no_sync_info() {
        scenario(true, true, false, true);
    }

    #[test]
    fn coalesced_requested_and_unsolicited_refreshes_only_requested_peer() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let peer = test_peer();
        let spammer = "127.0.0.2:9999".parse().unwrap();
        let now = Instant::now();
        let mut rx = connect_test_peer(&mut state, peer, now);
        let bytes = hex::decode(POPOW_GENESIS_HEX).unwrap();
        let id = *blake2b256(&bytes).as_bytes();
        let inv = message::serialize_inv(&InvData {
            type_id: ModifierTypeId::Header.as_byte(),
            ids: vec![id],
        })
        .unwrap();
        let actions = handle_message(&mut state, peer, message::CODE_INV, &inv, now);
        flush_actions(&mut state, actions);
        assert_eq!(rx.try_recv().unwrap().code, message::CODE_REQUEST_MODIFIER);
        let payload = message::serialize_modifiers(&ModifiersData {
            type_id: ModifierTypeId::Header.as_byte(),
            modifiers: vec![(id, bytes)],
        })
        .unwrap();
        // Connect after the Inv so this peer was not included in request hedging.
        let mut spam_rx = connect_test_peer(&mut state, spammer, now);
        assert_eq!(
            state.coordinator.delivery().on_received(&id, &spammer),
            ergo_p2p::delivery::DeliveryAction::RejectSpam
        );
        // Wrong peer goes first while P still owns the request (RejectSpam).
        let events = [spammer, peer]
            .into_iter()
            .map(|peer| PeerEvent::Message {
                peer,
                code: message::CODE_MODIFIER,
                payload: crate::peer_loop::MeteredPayload::for_test(
                    payload.clone(),
                    &state.event_byte_budget,
                ),
            })
            .collect();
        super::super::events::handle_event_batch(&mut state, events);
        assert_refresh(&mut rx, 1, id);
        assert_refresh(&mut spam_rx, 0, id);
    }

    #[test]
    fn modifier_requested_malformed_sends_no_sync_info() {
        for coalesced in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut state = make_state(&dir.path().join("state.redb"));
            let peer = test_peer();
            let now = Instant::now();
            let mut rx = connect_test_peer(&mut state, peer, now);
            let bytes = vec![0];
            let id = *blake2b256(&bytes).as_bytes();
            let inv = message::serialize_inv(&InvData {
                type_id: ModifierTypeId::Header.as_byte(),
                ids: vec![id],
            })
            .unwrap();
            let actions = handle_message(&mut state, peer, message::CODE_INV, &inv, now);
            flush_actions(&mut state, actions);
            assert_eq!(rx.try_recv().unwrap().code, message::CODE_REQUEST_MODIFIER);
            let payload = message::serialize_modifiers(&ModifiersData {
                type_id: ModifierTypeId::Header.as_byte(),
                modifiers: vec![(id, bytes)],
            })
            .unwrap();
            deliver(&mut state, peer, &payload, coalesced);
            assert_refresh(&mut rx, 0, id);
        }
    }
}

mod block_relay {
    use super::super::block_relay::Announcement;
    use super::*;
    use ergo_mining::candidate::Candidate;
    use ergo_mining::engine::{BestTip, BuildReason};
    use ergo_mining::handle::MiningHandle;
    use ergo_primitives::digest::{ADDigest, ModifierId};
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::header::{read_header, serialize_header};
    use ergo_ser::modifier_id::ExpectedSections;
    use ergo_state::ChainStateRead;

    // ----- helpers -----

    /// Inventories in queue order, each as (modifier type, ids).
    type Inventory = Vec<(u8, Vec<[u8; 32]>)>;

    /// Alters a candidate after the production builder made it.
    type Tamper = fn(&mut Candidate);

    /// Compressed secp256k1 point the mined fixtures pay and sign with.
    const MINER_PK: [u8; 33] = [0x02; 33];

    /// Difficulty one: the target is the group order, so the first nonce
    /// essentially always solves. It is the testnet genesis difficulty, which
    /// the synthetic height-one fixtures ([`solved_block`]) run under.
    const DIFFICULTY_ONE: u32 = 0x0101_0000;

    /// A block solved against a cached candidate, as a miner would submit it.
    struct SolvedBlock {
        candidate: Candidate,
        nonce: [u8; 8],
        id: [u8; 32],
        header_bytes: Vec<u8>,
        sections: ExpectedSections,
    }

    /// Solve a one-transaction block on `parent` whose header passes the real
    /// header pipeline under the testnet difficulty schedule. Its roots commit
    /// to its sections; `state_root` decides whether height one applies.
    fn solved_block(
        parent: [u8; 32],
        height: u32,
        timestamp: u64,
        state_root: ADDigest,
    ) -> SolvedBlock {
        use ergo_crypto::autolykos::common::{blake2b256, calc_n};
        use ergo_primitives::digest::Digest32;
        use ergo_primitives::group_element::GroupElement;
        use ergo_ser::autolykos::AutolykosSolution;
        use ergo_ser::header::{serialize_header_without_pow, Header};
        use ergo_validation::pre_header::{
            build_last_block_utxo_root, CandidatePreHeader, CandidateValidationContext,
        };

        let transactions = vec![ergo_ser::transaction::Transaction {
            inputs: vec![],
            data_inputs: vec![],
            output_candidates: vec![],
        }];
        let tx_id = *ergo_ser::transaction::transaction_id(&transactions[0])
            .unwrap()
            .as_bytes();
        let witness_id = blake2b256(&[])[1..].to_vec();
        let ad_proof_bytes = vec![1, 2, 3];
        let mut header = Header {
            version: 2,
            parent_id: ModifierId::from_bytes(parent),
            ad_proofs_root: Digest32::from_bytes(blake2b256(&ad_proof_bytes)),
            transactions_root: Digest32::from_bytes(ergo_crypto::merkle::transactions_root(
                &[&tx_id],
                Some(&[&witness_id]),
            )),
            state_root,
            timestamp,
            extension_root: Digest32::from_bytes(ergo_crypto::merkle::extension_root(&[])),
            n_bits: DIFFICULTY_ONE,
            height,
            votes: [0; 3],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from(MINER_PK),
                nonce: [0; 8],
            },
        };
        let candidate_header = header.clone();
        let msg = blake2b256(&serialize_header_without_pow(&header).unwrap());
        let target = ergo_crypto::difficulty::get_target(DIFFICULTY_ONE);
        let n = calc_n(header.version, height);
        let nonce = (0u64..)
            .map(u64::to_be_bytes)
            .find(|nonce| ergo_crypto::autolykos::v2::hit_for_v2(&msg, nonce, height, n) < target)
            .unwrap();
        header.solution = AutolykosSolution::V2 {
            pk: GroupElement::from(MINER_PK),
            nonce,
        };
        let (header_bytes, id) = serialize_header(&header).unwrap();
        let id = *id.as_bytes();
        let sections = ExpectedSections::from_header(
            &id,
            header.transactions_root.as_bytes(),
            header.extension_root.as_bytes(),
            header.ad_proofs_root.as_bytes(),
        );
        let candidate = Candidate {
            header: candidate_header,
            validation_ctx: CandidateValidationContext {
                pre_header: CandidatePreHeader {
                    version: 2,
                    parent_id: parent,
                    height,
                    timestamp,
                    n_bits: DIFFICULTY_ONE,
                    votes: [0; 3],
                    miner_pubkey: MINER_PK,
                },
                activated_script_version: 2,
                last_headers: Vec::new(),
                last_block_utxo_root: build_last_block_utxo_root(state_root),
            },
            transactions,
            ad_proof_bytes,
            extension_fields: Vec::new(),
            msg,
            target,
            parent_id: parent,
        };
        SolvedBlock {
            candidate,
            nonce,
            id,
            header_bytes,
            sections,
        }
    }

    /// A synced mining handle on the testnet schedule serving `block`'s
    /// candidate. [`genesis_state`] puts the executor on the same schedule.
    fn mining_handle(block: &SolvedBlock) -> MiningHandle {
        let spec = ergo_chain_spec::ChainSpec::testnet();
        let handle = MiningHandle::new(MINER_PK, spec.monetary, None, spec.difficulty, spec.voting)
            .with_network(spec.network);
        let parent = block.candidate.parent_id;
        handle.set_best_tip(BestTip {
            parent_id: parent,
            chain_seq: 1,
            synced: true,
        });
        let work = ergo_mining::work_message::WorkMessage {
            msg: block.candidate.msg,
            target: block.candidate.target.clone(),
            height: block.candidate.header.height,
            pk: MINER_PK,
        };
        assert!(handle
            .publish_if_current(
                block.candidate.clone(),
                work,
                &parent,
                || 0,
                BuildReason::Tip
            )
            .is_some());
        handle
    }

    /// Submit `nonce` through the real `POST /mining/solution` handler.
    fn submit_solution(
        state: &mut NodeState,
        handle: &MiningHandle,
        nonce: [u8; 8],
    ) -> Result<(), ergo_api::MiningApiError> {
        let (reply, mut rx) = tokio::sync::oneshot::channel();
        super::super::mining_dispatch::handle_mining_request(
            state,
            Some(handle),
            crate::mining_bridge::MiningRequest::SubmitSolution {
                solution: ergo_rest_json::mining::AutolykosSolutionJson {
                    pk: None,
                    w: None,
                    n: hex::encode(nonce),
                    d: None,
                },
                reply,
            },
        );
        rx.try_recv()
            .expect("the mining handler replies before returning")
    }

    /// Submit `block` through the real `POST /blocks` loop handler; true when
    /// the node answers 200.
    fn post_block(state: &mut NodeState, block: &SolvedBlock) -> bool {
        let header_id = ModifierId::from_bytes(block.id);
        let mut bt = VlqWriter::new();
        ergo_ser::block_transactions::write_block_transactions_with_version(
            &mut bt,
            &ergo_ser::block_transactions::BlockTransactions {
                header_id,
                transactions: block.candidate.transactions.clone(),
            },
            block.candidate.header.version,
        )
        .unwrap();
        let mut ext = VlqWriter::new();
        ergo_ser::extension::write_extension(
            &mut ext,
            &ergo_ser::extension::Extension {
                header_id,
                fields: vec![],
            },
        )
        .unwrap();
        let mut proofs = VlqWriter::new();
        ergo_ser::ad_proofs::write_ad_proofs(
            &mut proofs,
            &ergo_ser::ad_proofs::ADProofs {
                header_id,
                proof_bytes: block.candidate.ad_proof_bytes.clone(),
            },
        );
        let (reply, mut rx) = tokio::sync::oneshot::channel();
        super::super::events::handle_event_batch(
            state,
            vec![PeerEvent::LocalFullBlock {
                header_bytes: block.header_bytes.clone(),
                bt_bytes: bt.result(),
                ext_bytes: ext.result(),
                ad_proofs_bytes: Some(proofs.result()),
                reply,
            }],
        );
        rx.try_recv()
            .expect("the POST /blocks handler replies before returning")
            .is_ok()
    }

    /// A fresh UTXO state at the empty genesis, returning its state root. The
    /// executor runs the testnet difficulty schedule, as [`mining_handle`]
    /// does.
    fn genesis_state(dir: &Path) -> (NodeState, ADDigest) {
        let mut state = make_state(&dir.join("state.redb"));
        state.executor = SyncExecutor::new(
            ProtocolParams::mainnet_default(),
            ergo_chain_spec::ChainSpec::testnet().difficulty,
        );
        let store = state.store.as_utxo_mut().unwrap();
        store.initialize_genesis(&[]).unwrap();
        let root = store.root_digest();
        (state, root)
    }

    /// [`section_inventory`] for a synthetic solved block.
    fn full_inventory(block: &SolvedBlock) -> Inventory {
        section_inventory(block.id, &block.sections)
    }

    /// The Inv set a block announces when every section is servable: header
    /// first, then ADProofs, transactions and extension.
    fn section_inventory(id: [u8; 32], sections: &ExpectedSections) -> Inventory {
        vec![
            (101, vec![id]),
            (104, vec![sections.ad_proofs_id]),
            (102, vec![sections.transactions_id]),
            (108, vec![sections.extension_id]),
        ]
    }

    /// [`section_inventory`] for a header already in the store.
    fn stored_inventory(state: &NodeState, id: [u8; 32]) -> Inventory {
        let bytes = state.store.get_header(&id).unwrap().unwrap();
        let header = read_header(&mut VlqReader::new(&bytes)).unwrap();
        section_inventory(
            id,
            &ExpectedSections::from_header(
                &id,
                header.transactions_root.as_bytes(),
                header.extension_root.as_bytes(),
                header.ad_proofs_root.as_bytes(),
            ),
        )
    }

    /// Every announced id is served by the RequestModifier handler, and the
    /// served bytes pass the check a receiving peer runs before accepting
    /// them: the header hashes to its id, and each section re-hashes to the
    /// id its header's root commits to.
    fn assert_announced_ids_served(state: &mut NodeState, announced: &[(u8, Vec<[u8; 32]>)]) {
        for (kind, ids) in announced {
            let request = message::serialize_inv(&InvData {
                type_id: *kind,
                ids: ids.clone(),
            })
            .unwrap();
            let actions = handle_message(
                state,
                test_peer(),
                message::CODE_REQUEST_MODIFIER,
                &request,
                Instant::now(),
            );
            let [Action::SendToPeer { code, payload, .. }] = actions.as_slice() else {
                panic!("announced type {kind} id is not served: {actions:?}")
            };
            assert_eq!(*code, message::CODE_MODIFIER, "kind={kind}");
            let served = message::deserialize_modifiers(payload).unwrap();
            assert_eq!(served.type_id, *kind);
            let served_ids: Vec<_> = served.modifiers.iter().map(|(id, _)| *id).collect();
            assert_eq!(&served_ids, ids, "kind={kind}");
            for (id, bytes) in &served.modifiers {
                if *kind == 101 {
                    assert_eq!(
                        ergo_crypto::autolykos::common::blake2b256(bytes),
                        *id,
                        "served header bytes hash to the announced id"
                    );
                } else {
                    ergo_sync::coordinator::verify_section_modifier_id(*kind, id, bytes)
                        .unwrap_or_else(|e| panic!("served type {kind} fails the peer check: {e}"));
                }
            }
        }
    }

    /// A devnet UTXO node at the shared testnet genesis state, with the
    /// store, executor and mining handle on the devnet chain spec, as boot
    /// wires them.
    fn devnet_node(dir: &Path) -> (NodeState, MiningHandle) {
        let spec = ergo_chain_spec::ChainSpec::devnet();
        let mut store = StateStore::open_with_cache_launch_voting(
            &dir.join("state.redb"),
            StateStore::DEFAULT_CACHE_BYTES,
            ergo_validation::scala_launch_for_network(spec.network),
            spec.voting,
        )
        .unwrap();
        store.set_difficulty_params(spec.difficulty.clone());
        store
            .initialize_genesis(&crate::genesis::genesis_boxes_for(spec.network))
            .unwrap();
        let mut state = make_state_with_store(store);
        state.executor =
            SyncExecutor::new(ProtocolParams::mainnet_default(), spec.difficulty.clone());
        let handle = MiningHandle::new(
            MINER_PK,
            spec.monetary,
            spec.reemission,
            spec.difficulty,
            spec.voting,
        )
        .with_network(spec.network);
        (state, handle)
    }

    /// Point the handle at the applied tip as the action loop does once the
    /// mining latch is closed.
    fn sync_handle_to_tip(state: &NodeState, handle: &MiningHandle) -> ([u8; 32], u32) {
        let chain = state.store.chain_state_meta();
        handle.set_best_tip(BestTip {
            parent_id: chain.best_full_block_id,
            chain_seq: u64::from(chain.best_full_block_height) + 1,
            synced: true,
        });
        (chain.best_full_block_id, chain.best_full_block_height)
    }

    /// Build and publish the next candidate on the applied tip with the
    /// production engine, as the off-loop build worker does.
    fn publish_candidate(state: &NodeState, handle: &MiningHandle) {
        use ergo_mining::engine::{build_and_publish, BuildIntent, BuildOutcome};
        let (parent, height) = sync_handle_to_tip(state, handle);
        let intent = BuildIntent {
            expected_parent: parent,
            expected_height: height,
            mempool: std::sync::Arc::new(ergo_mempool::MempoolReadSnapshot::empty()),
            miner_pk: MINER_PK,
            reason: BuildReason::Tip,
        };
        let outcome = build_and_publish(
            &state.store.as_utxo().unwrap().reader_handle(),
            handle,
            &intent,
            ergo_mining::candidate::BuildMode::Full,
            None,
            wall_clock_ms,
            |_, _| Vec::new(),
            &mut None,
        )
        .unwrap();
        assert!(
            matches!(outcome, BuildOutcome::Published { .. }),
            "{outcome:?}"
        );
    }

    /// Build the next candidate with the production candidate builder, let
    /// `tamper` alter it, recommit its PoW message to the altered header,
    /// and publish it. Every header check still passes.
    fn publish_tampered_candidate(
        state: &NodeState,
        handle: &MiningHandle,
        tamper: impl FnOnce(&mut Candidate),
    ) {
        let spec = ergo_chain_spec::ChainSpec::devnet();
        let (mut candidate, mut work, _) = ergo_mining::candidate::generate_candidate(
            state.store.as_utxo().unwrap(),
            spec.network,
            ergo_mining::candidate::BuildMode::Full,
            ergo_mempool::MempoolReadSnapshot::empty(),
            &MINER_PK,
            &spec.monetary,
            spec.reemission.as_ref(),
            None,
            &spec.difficulty,
            &[],
            &std::collections::BTreeMap::new(),
            &spec.voting,
            &[],
            &mut Vec::new(),
        )
        .unwrap()
        .unwrap();
        tamper(&mut candidate);
        candidate.msg = ergo_crypto::autolykos::common::blake2b256(
            &ergo_ser::header::serialize_header_without_pow(&candidate.header).unwrap(),
        );
        work.msg = candidate.msg;
        let (parent, _) = sync_handle_to_tip(state, handle);
        assert!(handle
            .publish_if_current(candidate, work, &parent, wall_clock_ms, BuildReason::Tip)
            .is_some());
    }

    /// A solution to the newest published template.
    struct MinedSolution {
        nonce: [u8; 8],
        id: [u8; 32],
        header: ergo_ser::header::Header,
    }

    /// The `skip`-th nonce that solves the newest published template at the
    /// devnet's difficulty one, with the header it produces.
    fn solve(state: &NodeState, handle: &MiningHandle, skip: usize) -> MinedSolution {
        use ergo_crypto::autolykos::common::calc_n;
        let work = handle.cached_work_if_synced().unwrap();
        // Autolykos v2's N depends only on height for every version >= 2.
        let n = calc_n(2, work.height);
        let nonce = (0u64..)
            .map(u64::to_be_bytes)
            .filter(|nonce| {
                ergo_crypto::autolykos::v2::hit_for_v2(&work.msg, nonce, work.height, n)
                    < work.target
            })
            .nth(skip)
            .unwrap();
        let solution =
            ergo_mining::work_message::MinerSolution::from_hex(&hex::encode(nonce), None).unwrap();
        let ergo_mining::solution::SolutionOutcome::Accepted(block) = handle
            .verify_solution(&solution, state.store.as_utxo().unwrap())
            .unwrap()
        else {
            panic!("the newest template accepts its own solution")
        };
        let (_, id) = serialize_header(&block.header).unwrap();
        MinedSolution {
            nonce,
            id: *id.as_bytes(),
            header: block.header,
        }
    }

    /// Mine the next block with the production engine and apply it through
    /// the real mining handler; returns its id.
    fn mine_and_apply(state: &mut NodeState, handle: &MiningHandle) -> [u8; 32] {
        publish_candidate(state, handle);
        let mined = solve(state, handle, 0);
        let result = submit_solution(state, handle, mined.nonce);
        assert!(
            result.is_ok(),
            "{result:?}: {:?}",
            state.executor.last_block_apply_error()
        );
        assert_eq!(state.store.chain_state_meta().best_full_block_id, mined.id);
        mined.id
    }

    /// While armed on a thread, drains the peer's queued frames when the
    /// executor starts applying a block there (the `handle_assemble_block`
    /// span is created), so a test can tell inventories queued before apply
    /// from those queued after it.
    ///
    /// It is this test binary's process-wide default subscriber, installed
    /// once, not a scoped one: tracing caches a callsite's interest when the
    /// first thread reaches it, and while a scoped probe is the only live
    /// dispatcher, a thread without it caches `never` for every thread. The
    /// global dispatcher takes part in every interest computation, so the
    /// span is always created.
    struct ApplyEntryProbe;

    /// The probe armed on one thread: the queue it drains, and what it
    /// drained when apply started.
    struct ArmedProbe {
        queue: SharedQueue,
        before_apply: Option<Inventory>,
    }

    thread_local! {
        static ARMED_PROBE: std::cell::RefCell<Option<ArmedProbe>> =
            const { std::cell::RefCell::new(None) };
    }

    fn is_apply_entry(metadata: &tracing::Metadata<'_>) -> bool {
        metadata.is_span() && metadata.name() == "handle_assemble_block"
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for ApplyEntryProbe {
        fn register_callsite(
            &self,
            metadata: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            if is_apply_entry(metadata) {
                tracing::subscriber::Interest::always()
            } else {
                tracing::subscriber::Interest::never()
            }
        }

        fn enabled(
            &self,
            metadata: &tracing::Metadata<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) -> bool {
            is_apply_entry(metadata)
        }

        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if !is_apply_entry(attrs.metadata()) {
                return;
            }
            ARMED_PROBE.with(|armed| {
                if let Some(probe) = armed.borrow_mut().as_mut() {
                    if probe.before_apply.is_none() {
                        probe.before_apply = Some(drain(&probe.queue));
                    }
                }
            });
        }
    }

    /// Make [`ApplyEntryProbe`] the process-wide default subscriber.
    fn install_apply_entry_probe() {
        static INSTALLED: std::sync::Once = std::sync::Once::new();
        INSTALLED.call_once(|| {
            use tracing_subscriber::layer::SubscriberExt;
            tracing::subscriber::set_global_default(
                tracing_subscriber::registry().with(ApplyEntryProbe),
            )
            .expect("no other ergo-node lib test installs a global subscriber");
        });
        // A thread that registered the span's callsite while the probe was
        // being installed can have cached a stale interest; recompute it.
        tracing::callsite::rebuild_interest_cache();
    }

    /// A handshaked peer whose outbound queue the test and an
    /// [`ApplyEntryProbe`] share.
    type SharedQueue = std::sync::Arc<std::sync::Mutex<crate::peer_loop::outbound::Receiver>>;

    fn register_shared_peer(state: &mut NodeState) -> SharedQueue {
        std::sync::Arc::new(std::sync::Mutex::new(register_connected_peer(
            state,
            test_peer(),
        )))
    }

    fn drain(queue: &SharedQueue) -> Inventory {
        inventories(&mut queue.lock().unwrap())
    }

    /// What one probed submission queued for the peer.
    struct ProbedSubmission {
        result: Result<(), ergo_api::MiningApiError>,
        before_apply: Inventory,
        after_apply: Inventory,
    }

    /// Submit `nonce` through the real mining handler with an
    /// [`ApplyEntryProbe`] armed on the peer queue.
    fn submit_probing_apply(
        state: &mut NodeState,
        handle: &MiningHandle,
        nonce: [u8; 8],
        queue: &SharedQueue,
    ) -> ProbedSubmission {
        install_apply_entry_probe();
        ARMED_PROBE.with(|armed| {
            *armed.borrow_mut() = Some(ArmedProbe {
                queue: queue.clone(),
                before_apply: None,
            })
        });
        let result = submit_solution(state, handle, nonce);
        let probe = ARMED_PROBE
            .with(|armed| armed.borrow_mut().take())
            .expect("the probe stays armed until the submission returns");
        let Some(before_apply) = probe.before_apply else {
            panic!(
                "the handler never started apply: {result:?}: {:?}",
                state.executor.last_block_apply_error()
            )
        };
        ProbedSubmission {
            result,
            before_apply,
            after_apply: drain(queue),
        }
    }

    /// A solved header on `parent`, one height up, at difficulty one.
    fn solved_child(parent: &ergo_ser::header::Header, parent_id: [u8; 32]) -> Vec<u8> {
        use ergo_crypto::autolykos::common::{blake2b256, calc_n};
        let mut child = parent.clone();
        child.parent_id = ModifierId::from_bytes(parent_id);
        child.height = parent.height + 1;
        child.timestamp = parent.timestamp + 1;
        let msg = blake2b256(&ergo_ser::header::serialize_header_without_pow(&child).unwrap());
        let target = ergo_crypto::difficulty::get_target(child.n_bits);
        let n = calc_n(child.version, child.height);
        let nonce = (0u64..)
            .map(u64::to_be_bytes)
            .find(|nonce| {
                ergo_crypto::autolykos::v2::hit_for_v2(&msg, nonce, child.height, n) < target
            })
            .unwrap();
        child.solution = ergo_ser::autolykos::AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from(MINER_PK),
            nonce,
        };
        serialize_header(&child).unwrap().0
    }

    /// Store `header_bytes` through the executor's local header pipeline.
    fn process_header(state: &mut NodeState, header_bytes: &[u8]) {
        let (_, actions) = state
            .executor
            .process_local_header(
                &mut state.store,
                &mut state.coordinator,
                header_bytes,
                Instant::now(),
            )
            .unwrap();
        flush_actions(state, actions);
    }

    /// Replace the candidate's ADProofs with bytes that hash to its header
    /// root but are not the proof apply regenerates: a durable validation
    /// verdict (`AdProofsHashMismatch`) that passes every header check.
    fn replace_ad_proofs(candidate: &mut Candidate) {
        candidate.ad_proof_bytes = vec![1, 2, 3];
        candidate.header.ad_proofs_root = ergo_primitives::digest::Digest32::from_bytes(
            ergo_crypto::autolykos::common::blake2b256(&candidate.ad_proof_bytes),
        );
    }

    fn apply_failed(result: &Result<(), ergo_api::MiningApiError>) -> bool {
        matches!(result, Err(ergo_api::MiningApiError::Internal(reason)) if reason.starts_with("block apply failed"))
    }

    fn wall_clock_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    // Synthetic genesis isolates successful full-block application from PoW.
    // The executor still parses sections and checks the resulting state root.
    fn prepare_block(state: &mut NodeState, timestamp: u64) -> ([u8; 32], ExpectedSections) {
        let store = state.store.as_utxo_mut().unwrap();
        store.initialize_genesis(&[]).unwrap();
        let (_, bytes) = synthetic_header_with_state_root(1, store.root_digest());
        let mut header = read_header(&mut VlqReader::new(&bytes)).unwrap();
        header.timestamp = timestamp;
        let (bytes, id) = serialize_header(&header).unwrap();
        let id = *id.as_bytes();
        let sections = ExpectedSections::from_header(&id, &[0; 32], &[0; 32], &[0; 32]);
        store
            .store_validated_header(
                &id,
                &bytes,
                &ergo_state::chain::HeaderMeta {
                    parent_id: [0; 32],
                    height: 1,
                    cumulative_score: vec![1],
                    pow_validity: 1,
                    timestamp,
                },
                Some((1, vec![1])),
            )
            .unwrap();
        let mut writer = VlqWriter::new();
        ergo_ser::block_transactions::write_block_transactions(
            &mut writer,
            &ergo_ser::block_transactions::BlockTransactions {
                header_id: ModifierId::from_bytes(id),
                transactions: vec![ergo_ser::transaction::Transaction {
                    inputs: vec![],
                    data_inputs: vec![],
                    output_candidates: vec![],
                }],
            },
        )
        .unwrap();
        store
            .store_block_section_typed(&sections.transactions_id, &writer.result(), 102)
            .unwrap();
        let mut writer = VlqWriter::new();
        ergo_ser::extension::write_extension(
            &mut writer,
            &ergo_ser::extension::Extension {
                header_id: ModifierId::from_bytes(id),
                fields: vec![],
            },
        )
        .unwrap();
        store
            .store_block_section_typed(&sections.extension_id, &writer.result(), 108)
            .unwrap();
        (id, sections)
    }

    fn apply(state: &mut NodeState, id: [u8; 32]) -> Vec<Action> {
        let actions = state.executor.execute(
            Action::AssembleBlock { header_id: id },
            &mut state.store,
            &mut state.coordinator,
            Instant::now(),
            None,
        );
        assert_eq!(state.store.chain_state_meta().best_full_block_id, id);
        actions
    }

    fn inventories(rx: &mut crate::peer_loop::outbound::Receiver) -> Inventory {
        let mut result = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            assert_eq!(frame.code, message::CODE_INV);
            let inv = message::deserialize_inv(&frame.payload).unwrap();
            result.push((inv.type_id, inv.ids));
        }
        result
    }

    fn prepare_mainnet_catch_up(store: &mut ergo_state::store::StateStore) -> Vec<[u8; 32]> {
        use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
        use ergo_ser::extension::{write_extension, Extension, ExtensionField};
        use ergo_validation::popow::algos::{pack_interlinks, update_interlinks};
        store
            .initialize_genesis(&crate::genesis::mainnet_genesis_boxes())
            .unwrap();
        let headers: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../test-vectors/mainnet/headers_1_10.json"
        ))
        .unwrap();
        let txs: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../test-vectors/mainnet/transactions_1_10.json"
        ))
        .unwrap();
        let mut ids = Vec::new();
        let mut prev = None;
        let mut links = Vec::new();
        for height in 1..=10 {
            let row = &headers[height - 1];
            let bytes = hex::decode(row["bytes"].as_str().unwrap()).unwrap();
            let id: [u8; 32] = hex::decode(row["id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let header = read_header(&mut VlqReader::new(&bytes)).unwrap();
            if let Some(parent) = prev.as_ref() {
                links = update_interlinks(parent, &links).unwrap();
            }
            store
                .store_validated_header(
                    &id,
                    &bytes,
                    &ergo_state::chain::HeaderMeta {
                        parent_id: *header.parent_id.as_bytes(),
                        height: header.height,
                        cumulative_score: vec![height as u8],
                        pow_validity: 1,
                        timestamp: header.timestamp,
                    },
                    Some((height as u32, vec![height as u8])),
                )
                .unwrap();
            let tx_row = txs
                .iter()
                .find(|t| t["height"].as_u64() == Some(height as u64))
                .unwrap();
            let tx = ergo_ser::transaction::read_transaction(&mut VlqReader::new(
                &hex::decode(tx_row["bytes"].as_str().unwrap()).unwrap(),
            ))
            .unwrap();
            let sections = ExpectedSections::from_header(
                &id,
                header.transactions_root.as_bytes(),
                header.extension_root.as_bytes(),
                header.ad_proofs_root.as_bytes(),
            );
            let mut w = VlqWriter::new();
            write_block_transactions(
                &mut w,
                &BlockTransactions {
                    header_id: ModifierId::from_bytes(id),
                    transactions: vec![tx],
                },
            )
            .unwrap();
            store
                .store_block_section_typed(&sections.transactions_id, &w.result(), 102)
                .unwrap();
            let mut w = VlqWriter::new();
            write_extension(
                &mut w,
                &Extension {
                    header_id: ModifierId::from_bytes(id),
                    fields: pack_interlinks(&links)
                        .into_iter()
                        .map(|(key, value)| ExtensionField {
                            key: key.try_into().unwrap(),
                            value,
                        })
                        .collect(),
                },
            )
            .unwrap();
            store
                .store_block_section_typed(&sections.extension_id, &w.result(), 108)
                .unwrap();
            ids.push(id);
            prev = Some(header);
        }
        ids
    }

    // ----- happy path -----

    #[test]
    fn remote_block_fresh_announces_each_id_to_every_handshaked_peer() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let (id, sections) = prepare_block(&mut state, wall_clock_ms());
        let mut a = register_connected_peer(&mut state, "10.0.0.1:9001".parse().unwrap());
        let mut b = register_connected_peer(&mut state, "10.0.0.2:9001".parse().unwrap());
        state
            .peer_manager
            .register_inbound("10.0.0.3:9001".parse().unwrap(), Instant::now())
            .unwrap();
        let mut actions = apply(&mut state, id);
        actions.extend(super::super::block_relay::applied_block_announcements(
            &mut state, None,
        ));
        assert_eq!(
            actions
                .iter()
                .filter(|a| matches!(a, Action::SendToPeer { .. }))
                .count(),
            6
        );
        let peer_count = state.peer_manager.peer_count();
        flush_actions(&mut state, actions);
        assert_eq!(
            state.peer_manager.peer_count(),
            peer_count,
            "inbound-only peer must remain registered"
        );
        assert!(
            state
                .peer_manager
                .get(&"10.0.0.3:9001".parse().unwrap())
                .is_some(),
            "the inbound-only recipient must still be present after flush"
        );
        let expected = vec![
            (101, vec![id]),
            (102, vec![sections.transactions_id]),
            (108, vec![sections.extension_id]),
        ];
        assert_eq!(inventories(&mut a), expected);
        assert_eq!(inventories(&mut b), expected);
        flush_actions(&mut state, vec![]);
        assert!(inventories(&mut a).is_empty());
    }

    #[test]
    fn remote_block_below_tip_window_sends_no_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let (id, _) = prepare_block(&mut state, wall_clock_ms());
        let mut rx = register_connected_peer(&mut state, test_peer());
        let actions = apply(&mut state, id);
        state
            .store
            .as_utxo_mut()
            .unwrap()
            .test_force_set_best_header_unsafe([77; 32], 18, vec![18])
            .unwrap();
        flush_actions(&mut state, actions);
        assert!(
            inventories(&mut rx).is_empty(),
            "fresh block 17 below best header must not relay"
        );
    }

    #[test]
    fn relay_flush_pending_persist_failure_next_apply_still_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let (id, _) = prepare_block(&mut state, wall_clock_ms());
        let _rx = register_connected_peer(&mut state, test_peer());
        let actions = apply(&mut state, id);
        state
            .store
            .as_utxo_mut()
            .unwrap()
            .inject_pending_persist_failure_for_test(1);
        flush_actions(&mut state, actions);
        let store = state.store.as_utxo_mut().unwrap();
        let root = store.root_digest();
        let result = store.apply_block_unchecked_for_test(2, &[88; 32], &root, &[]);
        assert!(
            matches!(
                result,
                Err(ergo_state::store::StateError::PersistFailed { height: 1, .. })
            ),
            "next apply must see pending persist error, got {result:?}"
        );
    }

    #[test]
    fn remote_block_sequential_apply_announces_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let (id, _) = prepare_block(&mut state, wall_clock_ms());
        let mut rx = register_connected_peer(&mut state, test_peer());
        state.executor.try_apply_next_blocks(
            &mut state.store,
            &mut state.coordinator,
            Instant::now(),
            None,
        );
        assert_eq!(state.store.chain_state_meta().best_full_block_id, id);
        flush_actions(&mut state, vec![]);
        assert_eq!(inventories(&mut rx).len(), 3);
        let actions = apply(&mut state, id);
        flush_actions(&mut state, actions);
        assert!(inventories(&mut rx).is_empty());
    }

    #[test]
    fn mined_apply_failure_guard_any_applied_block_clears_it() {
        // The guard keys on the failed block's parent, so it matters again
        // only if the full tip returns to that parent; it is cleared once any
        // block applies, with no peer connected too.
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let (id, _) = prepare_block(&mut state, wall_clock_ms());
        state.mined_apply_failed_parent = Some([9; 32]);
        flush_actions(&mut state, vec![]);
        assert_eq!(
            state.mined_apply_failed_parent,
            Some([9; 32]),
            "no block applied yet"
        );
        let actions = apply(&mut state, id);
        flush_actions(&mut state, actions);
        assert_eq!(state.mined_apply_failed_parent, None, "the full tip moved");
    }

    #[test]
    fn locally_mined_first_block_applied_announces_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, root) = genesis_state(dir.path());
        let block = solved_block([0; 32], 1, wall_clock_ms(), root);
        let handle = mining_handle(&block);
        let mut rx = register_connected_peer(&mut state, test_peer());
        let result = submit_solution(&mut state, &handle, block.nonce);
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(state.store.chain_state_meta().best_full_block_id, block.id);
        // One Inv set: announcing again from the applied-block drain would
        // repeat it here, before the handler returns.
        assert_eq!(inventories(&mut rx), full_inventory(&block));
        flush_actions(&mut state, vec![]);
        assert!(
            inventories(&mut rx).is_empty(),
            "nothing is left for a later flush"
        );
    }

    #[test]
    fn locally_mined_block_non_genesis_apply_announces_once_before_apply() {
        // Height two runs the full non-genesis apply (height one goes through
        // the genesis apply): ADProofs regenerated and checked against the
        // header root, transaction and script validation, and the
        // regenerated proof re-stored. Both blocks come from the production
        // candidate engine over the devnet genesis state.
        let dir = tempfile::tempdir().unwrap();
        let (mut state, handle) = devnet_node(dir.path());
        mine_and_apply(&mut state, &handle);
        assert!(matches!(
            state.store.as_utxo().unwrap().ad_proofs_apply_policy(),
            ergo_state::store::AdProofsApplyPolicy::Regenerate
        ));
        let queue = register_shared_peer(&mut state);
        publish_candidate(&state, &handle);
        let mined = solve(&state, &handle, 0);
        let probed = submit_probing_apply(&mut state, &handle, mined.nonce, &queue);
        assert!(
            probed.result.is_ok(),
            "{:?}: {:?}",
            probed.result,
            state.executor.last_block_apply_error()
        );
        let chain = state.store.chain_state_meta();
        assert_eq!(
            (chain.best_full_block_id, chain.best_full_block_height),
            (mined.id, 2)
        );
        assert_eq!(
            probed.before_apply,
            stored_inventory(&state, mined.id),
            "the whole Inv set is queued before apply starts"
        );
        assert!(
            probed.after_apply.is_empty(),
            "apply must not announce it again: {:?}",
            probed.after_apply
        );
        flush_actions(&mut state, vec![]);
        assert!(
            drain(&queue).is_empty(),
            "nothing is left for a later flush"
        );
        // An archive UTXO node serves every section; the ADProofs served now
        // is the proof apply regenerated and re-stored.
        assert_announced_ids_served(&mut state, &probed.before_apply);
    }

    #[test]
    fn locally_mined_block_after_failed_sibling_announces_once_after_apply() {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, handle) = devnet_node(dir.path());
        let parent = mine_and_apply(&mut state, &handle);
        let queue = register_shared_peer(&mut state);
        publish_tampered_candidate(&state, &handle, replace_ad_proofs);
        let failed = solve(&state, &handle, 0);
        let result = submit_solution(&mut state, &handle, failed.nonce);
        assert!(apply_failed(&result), "{result:?}");
        assert_eq!(drain(&queue), stored_inventory(&state, failed.id));
        // A sound template on the same parent: its block applies and is
        // announced only then, exactly once.
        publish_candidate(&state, &handle);
        let mined = solve(&state, &handle, 0);
        assert_eq!(mined.header.parent_id.as_bytes(), &parent);
        let probed = submit_probing_apply(&mut state, &handle, mined.nonce, &queue);
        assert!(probed.result.is_ok(), "{:?}", probed.result);
        assert_eq!(state.store.chain_state_meta().best_full_block_id, mined.id);
        assert!(
            probed.before_apply.is_empty(),
            "not announced before apply on a parent whose announced child failed: {:?}",
            probed.before_apply
        );
        assert_eq!(probed.after_apply, stored_inventory(&state, mined.id));
        flush_actions(&mut state, vec![]);
        assert!(
            drain(&queue).is_empty(),
            "nothing is left for a later flush"
        );
        assert_announced_ids_served(&mut state, &probed.after_apply);
        // Pre-apply announcement resumes for the next block, on the new tip.
        // Its parent is never the guarded one, so this does not pin that the
        // guard clears; mined_apply_failure_guard_any_applied_block_clears_it
        // does.
        publish_candidate(&state, &handle);
        let next = solve(&state, &handle, 0);
        let probed = submit_probing_apply(&mut state, &handle, next.nonce, &queue);
        assert!(probed.result.is_ok(), "{:?}", probed.result);
        assert_eq!(probed.before_apply, stored_inventory(&state, next.id));
        assert!(probed.after_apply.is_empty(), "{:?}", probed.after_apply);
    }

    #[test]
    fn locally_mined_fork_block_joining_best_chain_later_announced_once() {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, handle) = devnet_node(dir.path());
        mine_and_apply(&mut state, &handle);
        publish_candidate(&state, &handle);
        let ours = solve(&state, &handle, 0);
        // An equal-score rival on the same parent reaches this node first.
        let rival = solve(&state, &handle, 1);
        process_header(&mut state, &serialize_header(&rival.header).unwrap().0);
        assert_eq!(state.store.chain_state_meta().best_header_id, rival.id);
        let mut rx = register_connected_peer(&mut state, test_peer());
        let result = submit_solution(&mut state, &handle, ours.nonce);
        // Only the best header is applied, so the handler reports the fork
        // as not applied.
        assert!(apply_failed(&result), "{result:?}");
        assert!(
            state.store.get_header(&ours.id).unwrap().is_some(),
            "the mined header is stored as a fork"
        );
        flush_actions(&mut state, vec![]);
        assert!(
            inventories(&mut rx).is_empty(),
            "a non-best mined block is not announced before apply"
        );
        // A child of ours makes our fork the best chain, and ours applies.
        process_header(&mut state, &solved_child(&ours.header, ours.id));
        state.executor.try_apply_next_blocks(
            &mut state.store,
            &mut state.coordinator,
            Instant::now(),
            None,
        );
        assert_eq!(state.store.chain_state_meta().best_full_block_id, ours.id);
        flush_actions(&mut state, vec![]);
        let announced = inventories(&mut rx);
        assert_eq!(
            announced,
            stored_inventory(&state, ours.id),
            "the applied-block relay announces it once it applies"
        );
        flush_actions(&mut state, vec![]);
        assert!(inventories(&mut rx).is_empty());
        assert_announced_ids_served(&mut state, &announced);
    }

    #[test]
    fn posted_block_applied_announces_after_apply() {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, root) = genesis_state(dir.path());
        let block = solved_block([0; 32], 1, wall_clock_ms(), root);
        let mut rx = register_connected_peer(&mut state, test_peer());
        assert!(post_block(&mut state, &block));
        assert_eq!(state.store.chain_state_meta().best_full_block_id, block.id);
        assert_eq!(inventories(&mut rx), full_inventory(&block));
        flush_actions(&mut state, vec![]);
        assert!(inventories(&mut rx).is_empty());
    }

    #[test]
    fn remote_blocks_real_catch_up_flush_announces_only_near_tip() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let ids = prepare_mainnet_catch_up(state.store.as_utxo_mut().unwrap());
        state.executor.try_apply_next_blocks(
            &mut state.store,
            &mut state.coordinator,
            Instant::now(),
            None,
        );
        assert_eq!(
            state.store.chain_state_meta().best_full_block_height,
            10,
            "all ten fixture blocks must actually apply: {:?}",
            state.executor.last_block_apply_error()
        );
        let applied = state.executor.take_applied_blocks();
        assert_eq!(
            applied, ids,
            "whole catch-up batch before a single relay flush"
        );
        let tip_bytes = state.store.get_header(&ids[9]).unwrap().unwrap();
        let now_ms = read_header(&mut VlqReader::new(&tip_bytes))
            .unwrap()
            .timestamp;
        // Deterministic historical wall time: all ten fixture blocks are fresh.
        for id in &ids {
            let bytes = state.store.get_header(id).unwrap().unwrap();
            assert!(
                now_ms - read_header(&mut VlqReader::new(&bytes)).unwrap().timestamp < 7_200_000
            );
        }
        state
            .store
            .as_utxo_mut()
            .unwrap()
            .test_force_set_best_header_unsafe([77; 32], 25, vec![25])
            .unwrap();
        let (tx, mut rx) =
            crate::peer_loop::outbound::channel(crate::peer_loop::outbound::MAX_MESSAGES);
        state.registry.peers.insert(
            test_peer(),
            super::super::state::PeerRuntime {
                sync_version: SyncVersion::V2,
                outbound_tx: tx,
            },
        );
        let actions = super::super::block_relay::remote_announcements(&state, applied, now_ms);
        flush_actions(&mut state, actions);
        let announced: Vec<_> = inventories(&mut rx)
            .into_iter()
            .filter(|(kind, _)| *kind == 101)
            .map(|(_, ids)| ids[0])
            .collect();
        assert_eq!(
            announced,
            ids[8..],
            "only heights 9 and 10 are within 16 of header tip 25"
        );
        assert!(state.executor.take_applied_blocks().is_empty());
    }

    #[test]
    fn remote_blocks_catch_up_only_tip_window_fits_queue() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let now = wall_clock_ms();
        let mut ids = Vec::new();
        // Simulate the drained feedback of a large catch-up batch. Executor
        // batch/reorg feedback itself is covered with real blocks in ergo-sync.
        for height in 1..=600 {
            let (_, bytes) = synthetic_header_with_state_root(
                height,
                ergo_primitives::digest::ADDigest::from_bytes([0; 33]),
            );
            let mut header = read_header(&mut VlqReader::new(&bytes)).unwrap();
            header.timestamp = now;
            let (bytes, id) = serialize_header(&header).unwrap();
            let id = *id.as_bytes();
            state.store.store_header(&id, &bytes).unwrap();
            let sections = ExpectedSections::from_header(&id, &[0; 32], &[0; 32], &[0; 32]);
            for (kind, section) in [
                (104, sections.ad_proofs_id),
                (102, sections.transactions_id),
                (108, sections.extension_id),
            ] {
                state
                    .store
                    .store_block_section_typed(&section, &[kind], kind)
                    .unwrap();
            }
            ids.push(id);
        }
        state
            .store
            .as_utxo_mut()
            .unwrap()
            .test_force_set_best_header_unsafe(ids[599], 600, vec![1])
            .unwrap();
        let (tx, mut rx) =
            crate::peer_loop::outbound::channel(crate::peer_loop::outbound::MAX_MESSAGES);
        state.registry.peers.insert(
            test_peer(),
            super::super::state::PeerRuntime {
                sync_version: SyncVersion::V2,
                outbound_tx: tx,
            },
        );
        let actions = super::super::block_relay::remote_announcements(&state, ids.clone(), now);
        assert_eq!(actions.len(), 17 * 4, "inclusive tip through tip-16");
        flush_actions(&mut state, actions);
        let announced = inventories(&mut rx);
        let headers: Vec<_> = announced
            .iter()
            .filter(|(kind, _)| *kind == 101)
            .map(|(_, ids)| ids[0])
            .collect();
        assert_eq!(headers, ids[583..], "only the last 17 heights may relay");
        let actions = super::super::block_relay::remote_announcements(
            &state,
            ids[584..].iter().copied(),
            now,
        );
        assert_eq!(actions.len(), 16 * 4);
        assert!(
            actions.len() < crate::peer_loop::outbound::MAX_MESSAGES / 16,
            "16-block burst must leave ample queue headroom"
        );
    }

    #[test]
    fn remote_block_freshness_boundary_matches_scala() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let timestamp = 10_000_000;
        let (id, _) = prepare_block(&mut state, timestamp);
        let _rx = register_connected_peer(&mut state, test_peer());
        assert_eq!(
            super::super::block_relay::block_announcements(&state, id, Announcement::Mined).len(),
            3
        );
        for (now, count) in [
            (0, 0),
            (timestamp - 1, 3),
            (timestamp + 7_199_999, 3),
            (timestamp + 7_200_000, 0),
        ] {
            let actions = super::super::block_relay::block_announcements(
                &state,
                id,
                Announcement::Remote {
                    now_ms: now,
                    best_header_height: 1,
                },
            );
            assert_eq!(actions.len(), count, "now={now}");
        }
    }

    #[test]
    fn served_sections_storage_modes_match_request_modifier_handler() {
        // Includes proof-retaining UTXO, proof-less UTXO, digest, and the
        // prune/bootstrap sentinel at/below the stored header's height.
        for digest in [false, true] {
            for proofs in [false, true] {
                for sentinel in [1, 10, 11] {
                    if digest && sentinel != 1 {
                        continue; // Digest has no configurable pruning window.
                    }
                    let dir = tempfile::tempdir().unwrap();
                    let mut state = if digest {
                        make_digest_state(&dir.path().join("state.redb"))
                    } else {
                        make_state(&dir.path().join("state.redb"))
                    };
                    let (id, bytes) = synthetic_header_with_state_root(
                        10,
                        ergo_primitives::digest::ADDigest::from_bytes([0; 33]),
                    );
                    state.store.store_header(&id, &bytes).unwrap();
                    let sections = ExpectedSections::from_header(&id, &[0; 32], &[0; 32], &[0; 32]);
                    let entries = [
                        (104, sections.ad_proofs_id),
                        (102, sections.transactions_id),
                        (108, sections.extension_id),
                    ];
                    for (kind, section_id) in entries {
                        if kind != 104 || proofs {
                            state
                                .store
                                .store_block_section_typed(&section_id, &[kind; 8], kind)
                                .unwrap();
                        }
                    }
                    let orphan = [99; 32];
                    state
                        .store
                        .store_block_section_typed(&orphan, &[102; 8], 102)
                        .unwrap();
                    if let Some(store) = state.store.as_utxo_mut() {
                        if sentinel > 1 {
                            store.set_blocks_to_keep(1000);
                        }
                        store.write_minimal_full_block_height(sentinel).unwrap();
                    }
                    let peer = test_peer();
                    let mut rx = register_connected_peer(&mut state, peer);
                    let actions = super::super::block_relay::block_announcements(
                        &state,
                        id,
                        Announcement::Mined,
                    );
                    flush_actions(&mut state, actions);
                    let advertised = inventories(&mut rx);
                    let expected: Vec<_> = std::iter::once((101, vec![id]))
                        .chain(
                            entries
                                .into_iter()
                                .filter(|(kind, _)| sentinel <= 10 && (*kind != 104 || proofs))
                                .map(|(kind, id)| (kind, vec![id])),
                        )
                        .collect();
                    assert_eq!(
                        advertised, expected,
                        "digest={digest} proofs={proofs} sentinel={sentinel}"
                    );
                    for (kind, section_id) in std::iter::once((101, id)).chain(entries) {
                        let request = message::serialize_inv(&InvData {
                            type_id: kind,
                            ids: vec![section_id],
                        })
                        .unwrap();
                        let actions = handle_message(
                            &mut state,
                            peer,
                            message::CODE_REQUEST_MODIFIER,
                            &request,
                            Instant::now(),
                        );
                        let advertised_id = advertised.contains(&(kind, vec![section_id]));
                        assert_eq!(
                            !actions.is_empty(),
                            advertised_id,
                            "digest={digest} proofs={proofs} sentinel={sentinel} kind={kind}"
                        );
                        for action in actions {
                            let Action::SendToPeer { code, payload, .. } = action else {
                                panic!("expected served modifier: digest={digest} proofs={proofs} sentinel={sentinel} kind={kind}")
                            };
                            assert_eq!(
                                code,
                                message::CODE_MODIFIER,
                                "digest={digest} proofs={proofs} sentinel={sentinel} kind={kind}"
                            );
                            let served = message::deserialize_modifiers(&payload).unwrap();
                            assert_eq!(
                                served.type_id, kind,
                                "digest={digest} proofs={proofs} sentinel={sentinel} kind={kind}"
                            );
                            assert_eq!(
                                served.modifiers.len(),
                                1,
                                "digest={digest} proofs={proofs} sentinel={sentinel} kind={kind}"
                            );
                            assert_eq!(
                                served.modifiers[0].0, section_id,
                                "digest={digest} proofs={proofs} sentinel={sentinel} kind={kind}"
                            );
                            let expected_bytes = if kind == 101 {
                                bytes.clone()
                            } else {
                                vec![kind; 8]
                            };
                            assert_eq!(
                                served.modifiers[0].1, expected_bytes,
                                "digest={digest} proofs={proofs} sentinel={sentinel} kind={kind}"
                            );
                        }
                    }
                    // A stored section without a header index fails closed when pruned.
                    let request = message::serialize_inv(&InvData {
                        type_id: 102,
                        ids: vec![orphan],
                    })
                    .unwrap();
                    let actions = handle_message(
                        &mut state,
                        peer,
                        message::CODE_REQUEST_MODIFIER,
                        &request,
                        Instant::now(),
                    );
                    assert_eq!(
                        actions.is_empty(),
                        sentinel > 1,
                        "digest={digest} proofs={proofs} sentinel={sentinel} orphan"
                    );
                    assert_eq!(
                        super::super::section_serving::servable_section(
                            &state.store,
                            &orphan,
                            sentinel
                        )
                        .is_none(),
                        sentinel > 1,
                        "digest={digest} proofs={proofs} sentinel={sentinel} orphan helper"
                    );
                }
            }
        }
    }

    #[test]
    fn served_sections_mixed_request_returns_only_retained_indexed_ids() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let mut ids = Vec::new();
        for height in [9, 10] {
            let (id, bytes) = synthetic_header_with_state_root(
                height,
                ergo_primitives::digest::ADDigest::from_bytes([0; 33]),
            );
            state.store.store_header(&id, &bytes).unwrap();
            ids.push(
                ExpectedSections::from_header(&id, &[0; 32], &[0; 32], &[0; 32]).transactions_id,
            );
        }
        ids.push([99; 32]); // stored, unindexed orphan
        for id in &ids {
            state
                .store
                .store_block_section_typed(id, &[42], 102)
                .unwrap();
        }
        let store = state.store.as_utxo_mut().unwrap();
        store.set_blocks_to_keep(1000);
        store.write_minimal_full_block_height(10).unwrap();
        let request = message::serialize_inv(&InvData {
            type_id: 102,
            ids: ids.clone(),
        })
        .unwrap();
        let actions = handle_message(
            &mut state,
            test_peer(),
            message::CODE_REQUEST_MODIFIER,
            &request,
            Instant::now(),
        );
        assert_eq!(actions.len(), 1);
        let Action::SendToPeer { code, payload, .. } = &actions[0] else {
            panic!("expected modifier response")
        };
        assert_eq!(*code, message::CODE_MODIFIER);
        assert_eq!(
            message::deserialize_modifiers(payload).unwrap().modifiers,
            vec![(ids[1], vec![42])]
        );
    }

    // ----- error paths -----

    #[test]
    fn locally_mined_block_pruned_utxo_node_fails_at_section_persist() {
        // Mining needs a UTXO backend (config rejects digest mining and the
        // handler requires the UTXO store), so besides archive UTXO the only
        // storage mode left is a serving window above height one: pruned, or
        // bootstrapped from a UTXO snapshot or NiPoPoW proof. This pins a
        // known step-2 ordering bug there, not servability: the mined
        // sections are persisted before their header creates the
        // SECTION_HEIGHT_INDEX rows, so the pruning guard refuses them and
        // the submission fails before anything is stored or announced.
        let dir = tempfile::tempdir().unwrap();
        let (mut state, handle) = devnet_node(dir.path());
        mine_and_apply(&mut state, &handle);
        let store = state.store.as_utxo_mut().unwrap();
        store.set_blocks_to_keep(1000);
        store.write_minimal_full_block_height(2).unwrap();
        let mut rx = register_connected_peer(&mut state, test_peer());
        publish_candidate(&state, &handle);
        let mined = solve(&state, &handle, 0);
        let result = submit_solution(&mut state, &handle, mined.nonce);
        assert!(
            matches!(
                &result,
                Err(ergo_api::MiningApiError::Internal(reason))
                    if reason.starts_with("persist:") && reason.contains("PrunedSection")
            ),
            "{result:?}"
        );
        assert!(state.store.get_header(&mined.id).unwrap().is_none());
        assert!(inventories(&mut rx).is_empty());
    }

    #[test]
    fn locally_mined_block_apply_failure_already_announced_once() {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, _) = genesis_state(dir.path());
        // Every header check passes; apply then rejects the state root.
        let block = solved_block([0; 32], 1, wall_clock_ms(), ADDigest::from_bytes([7; 33]));
        let handle = mining_handle(&block);
        let mut rx = register_connected_peer(&mut state, test_peer());
        let result = submit_solution(&mut state, &handle, block.nonce);
        assert!(
            apply_failed(&result),
            "apply failure is still reported to the miner: {result:?}"
        );
        assert_ne!(state.store.chain_state_meta().best_full_block_id, block.id);
        let announced = inventories(&mut rx);
        assert_eq!(
            announced,
            full_inventory(&block),
            "announced after header validation, before apply"
        );
        assert_announced_ids_served(&mut state, &announced);
        flush_actions(&mut state, vec![]);
        // The miner resubmitting the same solution stops at the known-header
        // check.
        let resubmitted = submit_solution(&mut state, &handle, block.nonce);
        assert!(
            matches!(
                &resubmitted,
                Err(ergo_api::MiningApiError::Internal(reason)) if reason.starts_with("process_header:")
            ),
            "{resubmitted:?}"
        );
        assert!(inventories(&mut rx).is_empty());
    }

    #[test]
    fn locally_mined_block_durable_apply_failure_stops_pre_apply_announcement() {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, handle) = devnet_node(dir.path());
        let parent = mine_and_apply(&mut state, &handle);
        let mut rx = register_connected_peer(&mut state, test_peer());
        publish_tampered_candidate(&state, &handle, replace_ad_proofs);
        let first = solve(&state, &handle, 0);
        let result = submit_solution(&mut state, &handle, first.nonce);
        assert!(apply_failed(&result), "{result:?}");
        assert!(
            state.executor.last_block_apply_error().is_some_and(
                |e| e.header_id == first.id && e.reason.starts_with("ADProofs hash mismatch")
            ),
            "{:?}",
            state.executor.last_block_apply_error()
        );
        let announced = inventories(&mut rx);
        assert_eq!(
            announced,
            stored_inventory(&state, first.id),
            "announced once, before apply"
        );
        assert_eq!(
            state
                .store
                .get_header_meta(&first.id)
                .unwrap()
                .unwrap()
                .pow_validity,
            3,
            "durably invalid"
        );
        let chain = state.store.chain_state_meta();
        assert_eq!(
            (chain.best_header_id, chain.best_full_block_id),
            (parent, parent),
            "best header re-anchored to the parent"
        );
        // Serving the invalidated block is deliberate. Scala refuses Invalid
        // ids (ErgoHistoryReader.modifierTypeAndBytesById, v6.0.6 23aabead8
        // :80-85); this node keeps serving what it announced, so peers can
        // judge the block themselves and no request for it ends in a
        // non-delivery timeout.
        assert_announced_ids_served(&mut state, &announced);
        // The template stays cached, so another nonce on it passes every
        // header check as a new best header and fails apply the same way.
        let second = solve(&state, &handle, 1);
        assert_ne!(second.id, first.id);
        let result = submit_solution(&mut state, &handle, second.nonce);
        assert!(apply_failed(&result), "{result:?}");
        assert_eq!(
            state
                .store
                .get_header_meta(&second.id)
                .unwrap()
                .unwrap()
                .pow_validity,
            3
        );
        assert_eq!(state.store.chain_state_meta().best_header_id, parent);
        flush_actions(&mut state, vec![]);
        assert!(
            inventories(&mut rx).is_empty(),
            "no pre-apply announcement on a parent whose announced child failed"
        );
    }

    #[test]
    fn failed_apply_invalidity_each_mark_reports_its_kind() {
        // The error log for an announced mined block that did not apply names
        // how apply left it.
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let (id, _) = prepare_block(&mut state, wall_clock_ms());
        let invalidity = |state: &NodeState| {
            super::super::mining_dispatch::failed_apply_invalidity(state, &id).0
        };
        assert_eq!(invalidity(&state), "none");
        state.store.mark_session_invalid(id);
        assert_eq!(invalidity(&state), "session");
        state.store.invalidate_validation_branch(id).unwrap();
        assert_eq!(invalidity(&state), "durable");
    }

    #[test]
    fn locally_mined_block_section_root_mismatch_sends_no_inventory() {
        // A header root the stored section bytes do not hash to. A receiving
        // peer recomputes the section id from the bytes, rejects a mismatch
        // and penalizes the sender, so nothing is announced; apply rejects
        // the block too. The last case roots the transactions over their ids
        // alone, the version-one formula, while the bytes carry the header's
        // later version marker: this node's section check accepts either
        // formula, but Scala derives the id from the marker.
        let tampers: [(&str, Tamper); 4] = [
            ("transactions", |c| {
                c.header.transactions_root =
                    ergo_primitives::digest::Digest32::from_bytes([0x55; 32])
            }),
            ("extension", |c| {
                c.header.extension_root = ergo_primitives::digest::Digest32::from_bytes([0x55; 32])
            }),
            ("ad_proofs", |c| {
                c.header.ad_proofs_root = ergo_primitives::digest::Digest32::from_bytes([0x55; 32])
            }),
            ("transactions_version_one_formula", |c| {
                assert!(c.header.version > 1, "{}", c.header.version);
                let tx_ids: Vec<_> = c
                    .transactions
                    .iter()
                    .map(|tx| {
                        *ergo_ser::transaction::transaction_id(tx)
                            .unwrap()
                            .as_bytes()
                    })
                    .collect();
                let tx_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();
                c.header.transactions_root = ergo_primitives::digest::Digest32::from_bytes(
                    ergo_crypto::merkle::transactions_root(&tx_refs, None),
                );
            }),
        ];
        for (root, tamper) in tampers {
            let dir = tempfile::tempdir().unwrap();
            let (mut state, handle) = devnet_node(dir.path());
            mine_and_apply(&mut state, &handle);
            let mut rx = register_connected_peer(&mut state, test_peer());
            publish_tampered_candidate(&state, &handle, tamper);
            let mined = solve(&state, &handle, 0);
            let result = submit_solution(&mut state, &handle, mined.nonce);
            assert!(apply_failed(&result), "{root}: {result:?}");
            assert_eq!(
                state
                    .store
                    .get_header_meta(&mined.id)
                    .unwrap()
                    .unwrap()
                    .pow_validity,
                3,
                "{root}: the header passed the pipeline and apply rejected the block"
            );
            flush_actions(&mut state, vec![]);
            assert!(inventories(&mut rx).is_empty(), "{root}");
        }
    }

    #[test]
    fn posted_block_apply_failure_sends_no_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, _) = genesis_state(dir.path());
        let block = solved_block([0; 32], 1, wall_clock_ms(), ADDigest::from_bytes([7; 33]));
        let mut rx = register_connected_peer(&mut state, test_peer());
        assert!(
            post_block(&mut state, &block),
            "the stored header answers 200"
        );
        assert_ne!(state.store.chain_state_meta().best_full_block_id, block.id);
        flush_actions(&mut state, vec![]);
        assert!(
            inventories(&mut rx).is_empty(),
            "POST /blocks announces only after a successful apply"
        );
    }

    #[test]
    fn served_sections_oversized_proof_is_not_announced() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let (id, sections) = prepare_block(&mut state, wall_clock_ms());
        state
            .store
            .store_block_section_typed(&sections.ad_proofs_id, &vec![0; 9 * 1024 * 1024], 104)
            .unwrap();
        let peer = test_peer();
        let mut rx = register_connected_peer(&mut state, peer);
        let actions =
            super::super::block_relay::block_announcements(&state, id, Announcement::Mined);
        flush_actions(&mut state, actions);
        assert_eq!(
            inventories(&mut rx),
            vec![
                (101, vec![id]),
                (102, vec![sections.transactions_id]),
                (108, vec![sections.extension_id]),
            ]
        );
        let request = message::serialize_inv(&InvData {
            type_id: 104,
            ids: vec![sections.ad_proofs_id],
        })
        .unwrap();
        let actions = handle_message(
            &mut state,
            peer,
            message::CODE_REQUEST_MODIFIER,
            &request,
            Instant::now(),
        );
        assert!(
            actions.is_empty(),
            "the serving encoder refuses this proof too"
        );
    }

    #[test]
    fn remote_block_unreadable_clock_drains_without_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let (id, _) = prepare_block(&mut state, wall_clock_ms());
        let _rx = register_connected_peer(&mut state, test_peer());
        apply(&mut state, id);
        let broken_clock = std::time::UNIX_EPOCH - Duration::from_secs(1);
        let actions = super::super::block_relay::applied_block_announcements_at(
            &mut state,
            None,
            broken_clock,
        );
        assert!(actions.is_empty(), "unreadable clock must fail closed");
        assert!(
            state.executor.take_applied_blocks().is_empty(),
            "bad clock must not accumulate feedback"
        );
    }

    #[test]
    fn remote_block_old_timestamp_sends_no_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let (id, _) = prepare_block(&mut state, wall_clock_ms() - 7_200_001);
        let mut rx = register_connected_peer(&mut state, test_peer());
        let actions = apply(&mut state, id);
        flush_actions(&mut state, actions);
        assert!(inventories(&mut rx).is_empty());
    }

    #[test]
    fn remote_block_unknown_header_sends_no_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let (id, _) = prepare_block(&mut state, wall_clock_ms());
        let _connected = register_connected_peer(&mut state, "10.0.0.8:9001".parse().unwrap());
        assert!(super::super::block_relay::block_announcements(
            &state,
            [99; 32],
            Announcement::Remote {
                now_ms: wall_clock_ms(),
                best_header_height: 1
            }
        )
        .is_empty());
        // Advertised id is not an applicable block: no success feedback.
        let mut rx = register_connected_peer(&mut state, test_peer());
        let actions = state.executor.execute(
            Action::AssembleBlock {
                header_id: [99; 32],
            },
            &mut state.store,
            &mut state.coordinator,
            Instant::now(),
            None,
        );
        assert_ne!(state.store.chain_state_meta().best_full_block_id, id);
        flush_actions(&mut state, actions);
        assert!(inventories(&mut rx).is_empty());
    }
}
