use super::sync_helpers::try_send_anchor_sync_info;
mod section_wire_policy;
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
use ergo_state::{ChainStateRead, HeaderSectionStore};
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
            mempool_enabled: true,
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
        last_recovery_dial_at: None,
        recovery_dial_rotation: 0,
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
        mining_enabled: false,
        mined_apply_failed_parent: None,
        private_mining: Default::default(),
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

// Keep the existing test namespace and filters while grouping bodies by behavior.
// These include files retain their original assertions and oracle provenance.
include!("tests/peer_messages.rs");
include!("tests/peer_liveness.rs");
include!("tests/snapshot_install.rs");
include!("tests/message_tracing.rs");
include!("tests/api_identity.rs");
include!("tests/mode_policy.rs");
include!("tests/mining_engine.rs");
include!("tests/digest_survival.rs");
include!("tests/transport_policy.rs");
include!("tests/popow_ingress.rs");
include!("tests/post_header_sync.rs");
include!("tests/block_relay.rs");
include!("tests/action_loop.rs");
