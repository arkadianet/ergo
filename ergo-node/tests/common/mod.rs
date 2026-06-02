//! Shared harness for `ergo-node` integration tests in `tests/`.
//!
//! Bypasses [`NodeConfig::load`] (which requires real seed peers and a
//! TOML file on disk) by fabricating a [`NodeConfig`] directly. Tests
//! get a fresh data dir, a kernel-assigned API port, and the API
//! submission surface enabled.
//!
//! The single unreachable loopback peer satisfies the non-empty
//! `known_peers` invariant without producing real network traffic — the
//! peer manager will dial 127.0.0.1:1, the kernel will refuse it
//! immediately, and the loop carries on.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use ergo_chain_spec::ChainSpec;
use ergo_indexer::IndexerConfig;
use ergo_mempool::MempoolConfig;
use ergo_node::config::{LoggingConfig, LoggingFormat, Network, NodeConfig};
use ergo_node::{run_inner, RunHandle};
use ergo_p2p::peer_manager::PeerLimits;

/// Build a NodeConfig pointing at `data_dir` with the API enabled on a
/// kernel-assigned loopback port and a single unreachable seed peer.
///
/// The cache is the store default; `ibd_flush_interval = 0` keeps every
/// commit durable so a crashed test never replays half a chain on the
/// next run.
pub fn make_test_config(data_dir: PathBuf) -> NodeConfig {
    let unreachable_peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let chain_spec = Arc::new(ChainSpec::mainnet());
    NodeConfig {
        network: Network::Mainnet,
        chain_spec: chain_spec.clone(),
        data_dir,
        known_peers: vec![unreachable_peer],
        peer_limits: PeerLimits::default(),
        bind_addr: None,
        declared_addr: None,
        agent_name: "ergo-node-test".into(),
        node_name: "test-node".into(),
        blocks_to_keep: -1,
        state_type: ergo_node::config::StateType::Utxo,
        verify_transactions: true,
        utxo_bootstrap: false,
        nipopow_bootstrap: false,
        p2p_nipopows: 2,
        ibd_flush_interval: 0,
        download_window: ergo_p2p::sync::DOWNLOAD_WINDOW,
        cache_bytes: None,
        script_validation_checkpoint: chain_spec.bootstrap.checkpoint,
        genesis_id: chain_spec.genesis.header_id,
        api_bind: Some("127.0.0.1:0".parse().unwrap()),
        // Scala-parity Blake2b256("hello") test oracle. The integration
        // harness does not exercise the auth gate but `api_bind = Some`
        // implies a configured hash per the load-time invariant; we
        // satisfy that here with the same oracle used by the unit tests.
        // Duplicated in `ergo-api/src/auth.rs::tests`,
        // `ergo-api/tests/auth.rs::SCALA_HELLO_HASH`, and
        // `ergo-node/src/config.rs::tests::TEST_DEFAULT_API_KEY_HASH`.
        // All four MUST stay in sync with the Scala reference
        // (`reference/ergo/src/main/resources/*.conf::apiKeyHash`).
        api_key_hash: Some(
            "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf".into(),
        ),
        mempool_config: MempoolConfig::default(),
        mempool_sort_policy: "cost".into(),
        indexer_config: IndexerConfig::default(),
        enable_anchor_scheduler: false, // matches NodeConfig::load default
        logging: LoggingConfig {
            default_level: "info".into(),
            format: LoggingFormat::Text,
            file: None,
        },
        mining_config: ergo_mining::MiningConfig::default(),
        wallet_expose_private_keys: false,
    }
}

/// Spawn a node from `config` and return its live handle. Panics on
/// startup error — tests that want to exercise the failure path should
/// call `run_inner` directly.
pub async fn spawn_node(config: NodeConfig) -> RunHandle {
    run_inner(config)
        .await
        .expect("test node should start cleanly with a valid config")
}
