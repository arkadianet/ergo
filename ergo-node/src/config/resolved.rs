//! Resolved configuration: the in-memory shapes the rest of the node
//! consumes once `NodeConfig::load` has translated the TOML + CLI
//! surface. Construction happens in [`super::load`]; this file only
//! holds the struct definitions and the `StateType` helpers that
//! belong to the resolved shape rather than the TOML / load surface.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use ergo_chain_spec::ChainSpec;
use ergo_indexer::IndexerConfig;
use ergo_mempool::MempoolConfig;

use super::Network;

// ---- StateType ----

/// Node state backend kind. Mirrors Scala `ergo.node.stateType` and
/// the `state_type` byte of the wire `Mode` peer-feature.
///
/// - `Utxo` (wire byte 0): full UTXO set kept on disk; the canonical
///   archive backend used by Modes 1, 2, 3.
/// - `Digest` (wire byte 1): AD-root + header-window only; the
///   backend Modes 5 (Digest Verifier) and 6 (Headers-only) use.
///
/// Only `Utxo` is honored by the runtime today — Mode 6 part 1 lands
/// the schema, gate, and wire advertisement; the `Digest` backend
/// itself is the part-2 follow-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateType {
    Utxo,
    Digest,
}

impl StateType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Utxo => "utxo",
            Self::Digest => "digest",
        }
    }

    /// `state_type` byte advertised in the `Mode` peer-feature.
    /// Matches Scala `ModePeerFeature` exactly.
    pub fn wire_byte(&self) -> u8 {
        match self {
            Self::Utxo => 0,
            Self::Digest => 1,
        }
    }
}

impl std::str::FromStr for StateType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "utxo" => Ok(StateType::Utxo),
            "digest" => Ok(StateType::Digest),
            other => Err(format!(
                "unknown state_type: {other:?}; expected \"utxo\" or \"digest\""
            )),
        }
    }
}

// ---- NodeConfig ----

#[derive(Debug)]
pub struct NodeConfig {
    pub network: Network,
    /// Shared chain specification. Constructed once via
    /// [`ChainSpec::for_network`] and cloned into long-lived services.
    /// The intent is for consumers to read narrow views
    /// (`&DifficultyParams`, `&VotingParams`, …) from this field;
    /// it currently sits alongside the existing per-field state and
    /// is mostly unused until that migration completes.
    pub chain_spec: Arc<ChainSpec>,
    pub data_dir: PathBuf,
    pub known_peers: Vec<SocketAddr>,
    pub peer_limits: ergo_p2p::peer_manager::PeerLimits,
    /// Address to bind our inbound TCP listener on. `None` → outbound
    /// only (no inbound listener spawned). When present, the node
    /// accepts inbound peers up to `peer_limits.max_inbound()`.
    pub bind_addr: Option<SocketAddr>,
    /// Address to advertise in the handshake / `Peers` gossip so other
    /// peers can find and dial us. `None` → handshake omits the
    /// declared address (anonymous, not gossipable). Independent of
    /// `bind_addr`: a NAT'd node may bind to its private LAN IP but
    /// declare a forwarded public IP.
    pub declared_addr: Option<SocketAddr>,
    pub agent_name: String,
    pub node_name: String,
    /// Pruning suffix length advertised in the `Mode` peer-feature.
    /// `-1` = full archive (default); `N >= 0` = Mode 3 pruned, retain
    /// at least `max(N, ROLLBACK_WINDOW)` blocks below tip. Mirrors
    /// Scala `ergo.node.blocksToKeep`.
    pub blocks_to_keep: i32,
    /// State backend kind. Default `Utxo`. `Digest` selects the
    /// AD-proof-driven backend (Modes 5/6 of the roadmap).
    pub state_type: StateType,
    /// When `false`, the node syncs headers only and skips
    /// block-section download and tx validation (Mode 6). Default
    /// `true`. R1 (per Scala `ErgoSettingsReader.consistentSettings`)
    /// requires `state_type = Digest` when this is `false`.
    pub verify_transactions: bool,
    /// Operator intent: when `true`, bootstrap the UTXO set from a
    /// snapshot instead of replaying the chain from genesis
    /// (Mode 2). Distinct from the runtime "snapshot applied" flag
    /// — this is what was asked for; the wire `-2` sentinel
    /// (`UTXOSetBootstrapped`) is set only after the actual
    /// snapshot apply completes (Mode 2 part 2). Default `false`.
    pub utxo_bootstrap: bool,
    /// Operator intent: when `true`, download a PoPoW proof at
    /// startup and bootstrap headers from it. Distinct from the
    /// runtime "proof applied" flag — the wire `nipopow = Some(1)`
    /// is set only after the proof has been validated and applied
    /// (nipopow part 2). Default `false`.
    pub nipopow_bootstrap: bool,
    /// Number of valid NiPoPoW proofs required for quorum before
    /// the apply path runs. Scala parity:
    /// `mainnet.conf::p2p_nipopows = 2`. Mirrored from
    /// `[node.nipopow] p2p_nipopows` TOML override.
    pub p2p_nipopows: u32,
    pub ibd_flush_interval: u32,
    /// Download window size in blocks (Sync-S3 default 384).
    pub download_window: usize,
    /// redb + AVL arena page cache, in bytes. None → use store default.
    pub cache_bytes: Option<usize>,
    /// Script-validation checkpoint: blocks at or below this height skip
    /// per-input ErgoScript evaluation. `None` → fully validate every block.
    /// `Some((h, id))` → skip below `h`, assert observed header_id at `h`
    /// matches `id` (mismatch = hard error).
    pub script_validation_checkpoint: Option<(u32, [u8; 32])>,
    /// Genesis header id (32 bytes) used for NiPoPoW R5 enforcement.
    /// `Some(id)` → verifier rejects proofs whose first header id
    /// does not match. `None` → open verification (development only).
    /// Resolved from `[chain] genesis_id` config override or the
    /// network's baked-in default; an explicit empty string in TOML
    /// disables the check.
    pub genesis_id: Option<[u8; 32]>,
    /// Operator HTTP API bind address. `None` disables the API server.
    /// Default: `127.0.0.1:9099`.
    pub api_bind: Option<SocketAddr>,
    /// `[api.security].api_key_hash` — lowercase Base16 (hex) of the
    /// Blake2b-256 of the operator's secret API key. Always required
    /// when the API is enabled (`api_bind = Some(_)`), mirroring the
    /// Scala node's `ErgoApp.scala:40-43`
    /// `require(apiKeyHash.isDefined, "API key hash must be set")`.
    /// Validated at load: 64 chars, lowercase hex only. Used by
    /// `ergo_api::auth::ApiSecurity` to gate `/wallet/*` and
    /// `/node/shutdown`.
    pub api_key_hash: Option<String>,
    /// Resolved mempool configuration. All fields populated from `[mempool]`
    /// section + CLI overrides. Defaults match `MempoolConfig::default()`.
    pub mempool_config: MempoolConfig,
    /// Mempool sort policy string: "cost" | "size" | "min". Validated at
    /// load time — `from_config(sort_policy)` will always succeed.
    pub mempool_sort_policy: String,
    /// Resolved indexer configuration. Defaults match
    /// `IndexerConfig::default()` (disabled, poll_idle 1000ms,
    /// db_filename "indexer.redb"). When `enabled = false` the node
    /// runtime skips both the polling task spawn and the
    /// `/blockchain/*` router mount.
    pub indexer_config: IndexerConfig,
    /// `[mining]` TOML section: external-miner subsystem. Defaults to
    /// disabled. CLI overrides: `--mining-enabled`,
    /// `--mining-public-key`. Validated at startup before the mining
    /// task is spawned so a misconfigured node refuses to start.
    pub mining_config: ergo_mining::MiningConfig,
    /// `[wallet] expose_private_keys`: when `true`, the
    /// `POST /wallet/getPrivateKey` route returns the derived secret
    /// scalar for an address. Default `false` — the route otherwise
    /// returns `403 Forbidden`. Threaded into the wallet writer task's
    /// `WriterConfig` at boot.
    pub wallet_expose_private_keys: bool,
    /// Step C — when `true`, the per-peer SyncInfo dispatch swaps
    /// our recent-header-tail `lastHeaderIds` for a single anchor ID
    /// drawn from the REST-built `AnchorMap` whenever the peer is
    /// REST-capable and an unassigned anchor above our tip is
    /// available. Default `false` — same opt-in surface as
    /// `[indexer] enabled`.
    pub enable_anchor_scheduler: bool,
    /// Resolved logging configuration. `default_level` always set;
    /// `file` is `Some(_)` only when `[logging.file]` is configured.
    pub logging: LoggingConfig,
}

/// Resolved tracing subscriber configuration. Built from
/// `[logging]` TOML at config-load time and consumed by
/// `crate::main` to wire the subscriber.
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Default RUST_LOG filter when the env var is unset.
    pub default_level: String,
    /// On-wire format. Validated at load time; main.rs branches on it.
    pub format: LoggingFormat,
    /// Optional rolling-file output. `None` = stderr only.
    pub file: Option<LoggingFileConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoggingFormat {
    /// Line-oriented human-readable output (the default).
    Text,
    /// One JSON object per event — the shape log aggregators expect
    /// (Loki, Datadog, Splunk, journald with `LogTarget=journal`).
    Json,
}

#[derive(Debug, Clone)]
pub struct LoggingFileConfig {
    /// Absolute directory for rotated log files.
    pub dir: PathBuf,
    /// File-name prefix.
    pub prefix: String,
    /// Rotation cadence: "minutely" | "hourly" | "daily" | "never".
    /// Validated at load time; main.rs maps it to
    /// `tracing_appender::rolling::Rotation`.
    pub rotation: String,
    /// Number of rotated files retained.
    pub max_files: usize,
}
