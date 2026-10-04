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
        redb_cache_budgets: Default::default(),
        script_validation_checkpoint: None,
        header_checkpoint: None,
        genesis_id: None,
        api_bind: None,
        peer_details: Default::default(),
        api_key_hash: None,
        api_allowed_hosts: Vec::new(),
        api_local_reverse_proxy: false,
        api_script: Default::default(),
        api_scoped_keys: Vec::new(),
        api_limits: Default::default(),
        api_readiness: Default::default(),
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
