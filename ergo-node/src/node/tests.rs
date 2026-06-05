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
    let coordinator = SyncCoordinator::new(0);
    let executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let peer_manager = PeerManager::new(0);
    let (event_tx, _rx) = mpsc::channel::<PeerEvent>(4);
    let mempool = Mempool::new(
        MempoolConfig::default(),
        weight::from_config("cost").unwrap(),
    );
    NodeState {
        store: ergo_state::StateBackendKind::Utxo(store),
        coordinator,
        executor,
        peer_manager,
        registry: PeerRegistry::new(),
        event_tx,
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
        throttle: ThroughputLimiter::with_defaults(),
        last_seen_active_params: ergo_validation::scala_launch(),
        last_seen_validation_settings: ergo_validation::ErgoValidationSettings::empty(),
        snapshot_publisher: None,
        identity_inputs: crate::node::identity::IdentityInputs {
            state_type: crate::config::StateType::Utxo,
            verify_transactions: true,
            blocks_to_keep: -1,
            utxo_bootstrap: false,
            nipopow_bootstrap: false,
            extra_index_enabled: false,
            declared_addr: None,
            bind_addr: None,
        },
        identity_slot: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
            ergo_api::types::ApiIdentity::default(),
        )),
        last_beat: Instant::now(),
        last_beat_emit: Instant::now()
            .checked_sub(crate::node::heartbeat::HEARTBEAT_IDLE_INTERVAL)
            .unwrap_or_else(Instant::now),
        last_beat_height: 0,
        last_beat_headers: 0,
        req_messages_total: 0,
        req_ids_total: 0,
        sections_received_total: 0,
        last_beat_req_messages: 0,
        last_beat_req_ids: 0,
        last_beat_sections_received: 0,
        last_dial_at: Instant::now()
            .checked_sub(Duration::from_secs(60))
            .unwrap_or_else(Instant::now),
        last_gossip_at: Instant::now()
            .checked_sub(ergo_p2p::peer_manager::GOSSIP_INTERVAL)
            .unwrap_or_else(Instant::now),
        indexer_handle: None,
        anchor_map: anchor_map::AnchorMap::new(),
        rest_peer_urls: std::sync::Arc::new(std::sync::RwLock::new(RestPeers::new())),
        anchor_builder_cancel_tx: tokio::sync::watch::channel(false).0,
        anchor_scheduler: AnchorScheduler::new(),
        enable_anchor_scheduler: false,
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
        wallet_hook: None,
        api_weight_function: ergo_api::types::ApiWeightFunction::Cost,
        recent_blocks_cache: None,
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
    let (tx, _rx) = mpsc::channel(1);
    state.registry.peers.insert(
        peer,
        PeerRuntime {
            sync_version: SyncVersion::V2,
            outbound_tx: tx,
        },
    );

    // `checked_sub` rather than `-` because `Instant - Duration`
    // panics on monotonic-clock underflow. On a freshly-rebooted
    // CI host this test would flake otherwise; the floor at `now`
    // is harmless since the loop only walks forward from this
    // anchor.
    let mut t = now.checked_sub(Duration::from_secs(75 * 60)).unwrap_or(now);
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

// ----- mode 2 part 2f-2: inbound SnapshotsInfo + disconnect cleanup -----

fn snapshots_info_payload(manifests: &[(i32, [u8; 32])]) -> Vec<u8> {
    message::serialize_snapshots_info(&ergo_p2p::types::SnapshotsInfo {
        available_manifests: manifests.to_vec(),
    })
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
        chain_spec: Arc::new(ChainSpec::mainnet()),
        data_dir: std::env::temp_dir().join("ergo-mode-label-cfg"),
        known_peers: vec!["127.0.0.1:1".parse().unwrap()],
        peer_limits: PeerLimits::default(),
        bind_addr: None,
        declared_addr: None,
        agent_name: "x".into(),
        node_name: "y".into(),
        blocks_to_keep: btk,
        state_type,
        verify_transactions: vt,
        utxo_bootstrap: false,
        nipopow_bootstrap: false,
        p2p_nipopows: 2,
        ibd_flush_interval: 0,
        download_window: 1,
        cache_bytes: None,
        script_validation_checkpoint: None,
        genesis_id: None,
        api_bind: None,
        api_key_hash: None,
        mempool_config,
        mempool_sort_policy: "cost".into(),
        indexer_config: IndexerConfig::default(),
        enable_anchor_scheduler: false,
        logging: LoggingConfig {
            default_level: "info".into(),
            format: LoggingFormat::Text,
            file: None,
        },
        mining_config: ergo_mining::MiningConfig::default(),
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
        utxo_bootstrap,
        nipopow_bootstrap,
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

/// The engine task must survive `MAX_VIS_RETRIES` `TipNotVisible` returns and
/// then go back to waiting — not spin, not exit. The intent carries an
/// `expected_parent` / `expected_height` that can never become commit-visible
/// against a genesis-only store (committed height 0, intent height 5).
///
/// The 40 × 25 ms backoff sleeps run in real time (~1 s total); the test is
/// correct but slow by design. If the suite budget becomes a concern, enabling
/// the tokio `test-util` feature and using `start_paused = true` would collapse
/// the wait to zero elapsed real time.
#[tokio::test]
async fn engine_visibility_retry_exhaustion_warns_and_keeps_running() {
    use ergo_crypto::difficulty::DifficultyParams;
    use ergo_mempool::MempoolReadSnapshot;
    use ergo_mining::emission_rules::MonetarySettings;
    use ergo_mining::engine::{BuildIntent, BuildReason};
    use ergo_mining::handle::MiningHandle;
    use ergo_mining::reemission::ReemissionSettings;
    use ergo_state::store::StateStore;
    use std::sync::Arc;
    use tokio::sync::watch;

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
    );

    // Intent whose expected_parent / expected_height can never become
    // commit-visible: committed height is 0, intent expects height 5.
    let intent = BuildIntent {
        expected_parent: [0x42u8; 32],
        expected_height: 5,
        mempool: Arc::new(MempoolReadSnapshot::empty()),
        miner_pk: [0x02u8; 33],
        eligible_rent_boxes: Arc::new(Vec::new()),
        reason: BuildReason::Startup,
    };

    let (intent_tx, intent_rx) = watch::channel(Some(intent));
    let (cancel_tx, cancel_rx) = watch::channel(false);

    // Spawn the engine task.
    let engine = tokio::spawn(super::mining_engine::run_mining_engine(
        reader, handle, intent_rx, cancel_rx,
    ));

    // Give the task time to exhaust all retries: 40 × 25 ms = 1 000 ms.
    // Under paused time this returns immediately after tokio advances the
    // clock through all the sleep calls.
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;

    // The engine must still be alive (exhaustion goes back to waiting,
    // does not exit or panic).
    assert!(
        !engine.is_finished(),
        "engine task must survive retry exhaustion and keep running",
    );

    // Cancel cleanly and join within a tight deadline.
    cancel_tx.send(true).unwrap();
    // Drop the sender so the watch channel closes, letting the task notice.
    drop(intent_tx);
    tokio::time::timeout(std::time::Duration::from_millis(500), engine)
        .await
        .expect("engine task must exit promptly after cancel")
        .expect("engine task must not panic");
}
