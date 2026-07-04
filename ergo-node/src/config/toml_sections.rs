//! `[section]` structs deserialized from `ergo-node.toml`. Held privately
//! inside `config::load`, then translated into [`super::NodeConfig`] +
//! its resolved sub-types. Defaults live next to the field that the
//! resolver fills from; reject-on-typo behaviour comes from the
//! per-section `#[serde(deny_unknown_fields)]` derives below.

// ---- TOML config ----

#[derive(serde::Deserialize, Default, Debug)]
#[serde(default)]
pub(super) struct TomlConfig {
    pub(super) network: Option<String>,
    pub(super) data_dir: Option<String>,
    pub(super) node: TomlNode,
    pub(super) peers: TomlPeers,
    pub(super) sync: TomlSync,
    pub(super) store: TomlStore,
    pub(super) chain: TomlChain,
    pub(super) api: TomlApi,
    pub(super) mempool: TomlMempool,
    pub(super) indexer: TomlIndexer,
    pub(super) logging: TomlLogging,
    pub(super) wallet: TomlWallet,
    #[serde(default)]
    pub(super) mining: ergo_mining::MiningConfig,
    pub(super) voting: TomlVoting,
}

/// `[voting]` TOML section: operator on-chain voting policy. Only a
/// `[voting.targets]` map of canonical camelCase parameter name → desired
/// numeric value. The candidate builder moves each parameter one step per
/// block toward its target (capped at `ParamVotesCount` = 2 votes per block).
///
/// Names are resolved to votable ids at load time via
/// `ergo_validation::voting::votable_param_id`; an unknown or non-votable name
/// (e.g. `blockVersion`, soft-fork) is a startup error. No soft-fork field —
/// soft-fork voting (the epoch-boundary proposed-update encoding) is deferred.
///
/// `deny_unknown_fields` so a mis-keyed `target` (singular) surfaces as a parse
/// error rather than silently no-opping.
#[derive(serde::Deserialize, Default, Debug)]
#[serde(default, deny_unknown_fields)]
pub(super) struct TomlVoting {
    /// Parameter-name → target-value map. Empty/absent ⇒ the node mines with
    /// neutral votes. Keys are validated against the votable set at load.
    pub(super) targets: std::collections::BTreeMap<String, i64>,
}

/// `[wallet]` TOML section: operator flags controlling sensitive
/// wallet-admin surface gating. All fields default to the safe
/// (disabled) value — an explicit `true` in TOML is the only way
/// to flip them on.
#[derive(serde::Deserialize, Default, Debug)]
#[serde(default, deny_unknown_fields)]
pub(super) struct TomlWallet {
    /// `[wallet] expose_private_keys`: when `true`, the
    /// `POST /wallet/getPrivateKey` route returns the derived secret
    /// scalar for an address; when `false`/absent the route returns
    /// `403 Forbidden`. Default `false`. Operators who set this
    /// `true` accept that an authenticated `api_key` request can
    /// extract per-address private material from the running node.
    pub(super) expose_private_keys: Option<bool>,
}

/// `[logging]` TOML section: tracing subscriber configuration.
///
/// Default: stderr only at warn level, env-filter via `RUST_LOG`.
/// When `[logging.file]` is set, events are tee'd to a rolling file
/// under `data_dir/logs` (or absolute `dir`). Compression is NOT
/// performed in-process — pair with `logrotate(8)` (Linux) or an
/// equivalent OS scheduler if compressed-on-rotate is required.
/// `tracing-appender`'s `max_files` performs retention by deletion.
///
/// `format` selects the on-wire layout: `"text"` (line-oriented, the
/// human-readable default) or `"json"` (one JSON object per line, the
/// shape log aggregators expect).
///
/// `deny_unknown_fields` so typos surface as a parse error.
#[derive(serde::Deserialize, Default, Debug)]
#[serde(default, deny_unknown_fields)]
pub(super) struct TomlLogging {
    /// Default RUST_LOG filter when the env var is unset. Default "info".
    /// `info` is the operator-facing level: lifecycle one-shots (network,
    /// data dir, peers, shutdown) and per-block apply summaries surface;
    /// `debug` and `trace` (per-tick / per-message hot loop) stay off
    /// unless explicitly asked for.
    pub(super) default_level: Option<String>,
    /// On-wire format: `"text"` | `"json"`. Default "text".
    pub(super) format: Option<String>,
    /// Optional file output. Absent = stderr only.
    pub(super) file: Option<TomlLoggingFile>,
}

#[derive(serde::Deserialize, Default, Debug)]
#[serde(default, deny_unknown_fields)]
pub(super) struct TomlLoggingFile {
    /// Directory for rotated log files. Relative paths resolve against
    /// data_dir. Default: `<data_dir>/logs`.
    pub(super) dir: Option<String>,
    /// File-name prefix. Rotation appends `.YYYY-MM-DD` (or hour /
    /// minute, depending on cadence). Default: "ergo-node".
    pub(super) prefix: Option<String>,
    /// Rotation cadence: "minutely" | "hourly" | "daily" | "never".
    /// Default: "daily".
    pub(super) rotation: Option<String>,
    /// Number of rotated files retained — older files deleted on
    /// rotate. Default: 14 (two weeks of daily rotation).
    pub(super) max_files: Option<usize>,
}

/// `[indexer]` TOML section: opt-in extra-index parity.
///
/// Disabled by default. When `enabled = true`, the indexer crate opens
/// its own redb file (`db_filename`) under the data dir, the polling
/// task spawns alongside the action loop, and the `/blockchain/*`
/// router mounts. When `enabled = false` (default) the
/// `/blockchain/*` paths return 404 — a deliberate divergence from
/// Scala's "always-mount, return 503" behavior.
///
/// `deny_unknown_fields` so typos don't silently no-op.
#[derive(serde::Deserialize, Default, Debug)]
#[serde(default, deny_unknown_fields)]
pub(super) struct TomlIndexer {
    pub(super) enabled: Option<bool>,
    pub(super) poll_idle_ms: Option<u64>,
    pub(super) db_filename: Option<String>,
}

/// `[api]` TOML section: operator HTTP API.
///
/// Bind address is loopback by enforcement: a non-loopback `bind`
/// requires `public_bind = true` plus a configured
/// `[api.security].api_key_hash`, and a loud warning is logged.
/// `/wallet/*` and `/node/shutdown` are wrapped with API-key
/// middleware whenever the API is enabled; every other route stays
/// unauthenticated.
#[derive(serde::Deserialize, Default, Debug)]
#[serde(default)]
pub(super) struct TomlApi {
    /// Bind address for the HTTP API. Default `127.0.0.1:9099`.
    pub(super) bind: Option<String>,
    /// Disable the API server entirely.
    pub(super) disabled: Option<bool>,
    /// Permit binding a non-loopback address. Default false. Setting
    /// this to true while exposing the port publicly requires
    /// `[api.security].api_key_hash`; auth gates `/wallet/*` and
    /// `/node/shutdown`.
    pub(super) public_bind: Option<bool>,
    /// `[api.security]` subsection. Optional in TOML but its
    /// `api_key_hash` field must be present when the API server is
    /// enabled — checked at load.
    pub(super) security: Option<TomlApiSecurity>,
}

/// `[api.security]` TOML subsection. Carries the operator's
/// `api_key_hash` used by `ergo_api::auth::ApiSecurity`.
#[derive(serde::Deserialize, Default, Debug)]
#[serde(default)]
pub(super) struct TomlApiSecurity {
    /// Lowercase Base16 (hex) of `Blake2b256(api_key_plaintext)`.
    /// 64 chars. Generate with e.g.
    /// `echo -n "<your-secret>" | b2sum -l 256 | cut -d' ' -f1`.
    pub(super) api_key_hash: Option<String>,
}

/// `[mempool]` TOML section: unconfirmed transaction pool configuration.
///
/// All fields are optional; omitted fields fall back to `MempoolConfig::default()`.
/// Set `disabled = true` to skip tx relay entirely (e.g. archival or sync-test runs).
///
/// Only operator-facing knobs are exposed here. Internal tuning parameters
/// (CPFP depths, budget caps, invalidation TTLs, revalidation rates) are
/// intentionally not surfaced — they are rarely changed and an incorrect
/// value could degrade performance without a clear error. Use source-level
/// defaults for those.
///
/// `#[serde(deny_unknown_fields)]` makes typos (e.g. `enabled = false`
/// instead of `disabled = true`) an explicit parse error rather than a
/// silent no-op.
#[derive(serde::Deserialize, Default, Debug)]
#[serde(default, deny_unknown_fields)]
pub(super) struct TomlMempool {
    pub(super) disabled: Option<bool>,
    /// Priority ordering: "cost" (default), "size", or "min".
    pub(super) sort_policy: Option<String>,
    pub(super) max_pool_size: Option<usize>,
    pub(super) max_pool_bytes: Option<usize>,
    pub(super) min_relay_fee_nano_erg: Option<u64>,
    pub(super) max_tx_size_bytes: Option<usize>,
    pub(super) max_tx_cost: Option<u64>,
    pub(super) ibd_gate_block_lag: Option<u32>,
    /// Count of surviving unconfirmed txs to re-advertise on each tip-change
    /// recheck (Scala `MempoolAuditor` `rebroadcastCount`, default 3). 0
    /// disables re-broadcast.
    pub(super) rebroadcast_count: Option<usize>,
}

#[derive(serde::Deserialize, Default, Debug)]
#[serde(default)]
pub(super) struct TomlChain {
    /// Override the network's default script-validation checkpoint
    /// height. Use 0 to disable.
    pub(super) script_validation_checkpoint_height: Option<u32>,
    /// Hex-encoded block_id pinned to `script_validation_checkpoint_height`.
    /// Defaults to the network's hardcoded value if only the height is
    /// overridden.
    pub(super) script_validation_checkpoint_block_id: Option<String>,
    /// Hex-encoded genesis header id (32 bytes). Required for NiPoPoW
    /// proof verification: the verifier rejects any proof whose first
    /// header's id does not match this value (R5 enforcement per
    /// Part 2 spec §11). If omitted, the network's baked-in default
    /// is used (mainnet / testnet hardcoded ids). Pass an empty
    /// string to disable genesis-id checking entirely — accepted
    /// **only** in development; production runs MUST keep the default.
    pub(super) genesis_id: Option<String>,
}

#[derive(serde::Deserialize, Default, Debug)]
#[serde(default)]
pub(super) struct TomlStore {
    /// redb + AVL arena page cache, in bytes. Override
    /// `StateStore::DEFAULT_CACHE_BYTES`.
    pub(super) cache_bytes: Option<usize>,
}

#[derive(serde::Deserialize, Default, Debug)]
#[serde(default, deny_unknown_fields)]
pub(super) struct TomlNode {
    pub(super) agent_name: Option<String>,
    pub(super) node_name: Option<String>,
    /// `[node] blocks_to_keep` — pruning suffix length (Mode 3 of the
    /// node mode-coverage roadmap). Mirrors Scala
    /// `ergo.node.blocksToKeep`. Accepts `-1` (full archive — default
    /// when omitted) or a non-negative `N`. Wire sentinel `-2`
    /// (UTXOSetBootstrapped) is not a valid configured value; that
    /// state is reached at runtime when a UTXO snapshot bootstrap
    /// completes (Mode 2, deferred).
    pub(super) blocks_to_keep: Option<i32>,
    /// `[node] state_type` — node state backend (Modes 5/6 of the
    /// roadmap). Mirrors Scala `ergo.node.stateType`. Default
    /// `"utxo"`. `"digest"` selects the AD-proof-driven backend
    /// (Mode 5 verifier, or Mode 6 headers-only when combined with
    /// `verify_transactions = false`).
    pub(super) state_type: Option<String>,
    /// `[node] verify_transactions` — when `false`, the node syncs
    /// headers only and skips block-section download and tx
    /// validation. Default `true`. Per Scala R1
    /// (ErgoSettingsReader.consistentSettings:175-176),
    /// `verify_transactions = false` requires `state_type = "digest"`.
    pub(super) verify_transactions: Option<bool>,
    /// `[node.utxo]` — UTXO snapshot bootstrap settings (Mode 2 of
    /// the roadmap). Mirrors Scala `ergo.node.utxo`. Nested as a
    /// table so the `utxo_bootstrap` key reads `[node.utxo]`
    /// `utxo_bootstrap = false` in TOML, matching Scala layout.
    #[serde(default)]
    pub(super) utxo: TomlNodeUtxo,
    /// `[node.nipopow]` — NiPoPoW bootstrap settings. Mirrors Scala
    /// `ergo.node.nipopow`. Part-1 schema only; the proof
    /// verification + p2p message surface are deferred.
    #[serde(default)]
    pub(super) nipopow: TomlNodeNipopow,
}

/// `[node.utxo]` — nested table for the UTXO snapshot bootstrap
/// settings. Mirrors Scala `ergo.node.utxo`. `deny_unknown_fields`
/// so typos surface as parse errors rather than silently falling
/// back to defaults.
#[derive(serde::Deserialize, Default, Debug)]
#[serde(default, deny_unknown_fields)]
pub(super) struct TomlNodeUtxo {
    /// `utxo_bootstrap` — when `true`, the node downloads the
    /// UTXO set snapshot at a fixed-cadence height (Mode 2) instead
    /// of replaying the chain from genesis. Default `false`.
    /// Operator intent flag: this is what the operator asked for.
    /// The wire `blocks_to_keep = -2` sentinel
    /// (`UTXOSetBootstrapped`) is set by the runtime *after* the
    /// snapshot has actually been applied, not from this config
    /// value directly.
    pub(super) utxo_bootstrap: Option<bool>,
}

/// `[node.nipopow]` — nested table for NiPoPoW bootstrap settings.
/// Mirrors Scala `ergo.node.nipopow`. `deny_unknown_fields` so typos
/// surface as parse errors.
#[derive(serde::Deserialize, Default, Debug)]
#[serde(default, deny_unknown_fields)]
pub(super) struct TomlNodeNipopow {
    /// `nipopow_bootstrap` — when `true`, the node downloads a
    /// PoPoW proof at startup and jumps to the suffix tip without
    /// full header sync. Operator intent flag. Default `false`.
    /// The wire `nipopow = Some(1)` is set after the proof has
    /// actually been validated and applied, not from this config
    /// value directly.
    pub(super) nipopow_bootstrap: Option<bool>,
    /// `p2p_nipopows` — number of valid NiPoPoW proofs required to
    /// reach quorum before the apply path runs. Scala parity:
    /// `mainnet.conf::p2p_nipopows = 2` (`NipopowSettings.scala:10`).
    /// Defaults to 2 when omitted.
    pub(super) p2p_nipopows: Option<u32>,
}

#[derive(serde::Deserialize, Default, Debug)]
#[serde(default)]
pub(super) struct TomlPeers {
    pub(super) known: Vec<String>,
    pub(super) max_connections: Option<usize>,
    pub(super) target_outbound: Option<usize>,
    /// Maximum inbound connections accepted. Decoupled from
    /// `target_outbound`, so a full outbound set never reduces inbound
    /// capacity. `0` = outbound-only. Defaults to `DEFAULT_MAX_INBOUND`
    /// (256) when omitted.
    pub(super) max_inbound: Option<usize>,
    pub(super) per_ip_limit: Option<usize>,
    pub(super) per_subnet_limit: Option<usize>,
    /// `0.0.0.0:9030` to listen on the default mainnet port. Empty
    /// string or absent → outbound-only (no inbound listener). Mirrors
    /// Scala `scorex.network.bindAddress` semantics.
    pub(super) bind_addr: Option<String>,
    /// Address advertised in our handshake / `Peers` gossip so other
    /// peers can dial us. Empty string or absent → handshake omits the
    /// declared address (we are not gossipped as reachable). Mirrors
    /// Scala `scorex.network.declaredAddress`.
    pub(super) declared_addr: Option<String>,
}

/// `[sync]` TOML section: tunables for the download pipeline.
///
/// The `inv_batch_size` knob from the original S3 scope was removed:
/// MAX_INV_OBJECTS is already 400 (the wire cap) and the coordinator
/// derives its per-bucket sizing from peer count — no runtime override
/// is exercised anywhere.
#[derive(serde::Deserialize, Default, Debug)]
#[serde(default)]
pub(super) struct TomlSync {
    /// Blocks ahead of validated tip to keep pending download. See
    /// [`ergo_p2p::sync::DOWNLOAD_WINDOW`] for the default.
    pub(super) download_window: Option<usize>,
    /// Step C feature flag — when `true`, the per-peer SyncInfo
    /// dispatch crafts a single-anchor `lastHeaderIds` from the
    /// REST-built anchor map for REST-capable peers (instead of our
    /// own recent header tail). Default `false` — operator opts in
    /// once the anchor map is observed to be healthy.
    pub(super) enable_anchor_scheduler: Option<bool>,
}
