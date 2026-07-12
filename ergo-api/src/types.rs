//! Wire-shaped DTOs for the operator API.
//!
//! Field types are stable primitives — no internal enum representations
//! or binary blobs leak through.
//!
//! ## Id encoding
//!
//! Every id- or root-shaped `String` field on this module's wire DTOs is
//! lowercase hex, byte-exact with the on-disk and on-chain bytes. No
//! `0x` prefix, no upper-case, no base64. Concretely:
//!
//! - 32 bytes / 64 hex chars — every id- and content-hash field on
//!   this surface (`header_id`, `parent_id`, `tx_id`, `box_id`,
//!   `token_id`, `manifest_id`). All are `Digest32` under the hood —
//!   see the shared aliases in `ergo-indexer-types::{TxId, HeaderId,
//!   BoxId, TokenId}` — the field name carries the semantic, not the
//!   type. `manifest_id` is the AVL chunk-tree root label of a
//!   snapshot bootstrap.
//! - 33 bytes / 66 hex chars — `state_root_avl`, the AVL+
//!   authenticated UTXO-tree root (`Digest32 || balance-byte`);
//!   matches the on-chain `Header.stateRoot`.
//!
//! Numeric fields on this surface (e.g. `ApiPeer.score`, heights,
//! timestamps, n_bits) are JSON numbers, not hex.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Static node identity. Cheap to compute; doesn't change after boot.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiInfo {
    pub agent_name: String,
    pub node_name: String,
    pub network: String,
    pub version: String,
    pub started_at_unix_ms: u64,
    pub uptime_seconds: u64,
    /// Target block interval for this network, in milliseconds.
    /// Mainnet = 120_000 (2 min). Testnet = 45_000 (45 s). Read from
    /// the chain spec's `DifficultyParams::desired_interval_ms` at
    /// boot so the operator dashboard can label "avg block time"
    /// against the *actual* network's target instead of hardcoding
    /// the mainnet value (which was wrong on testnet).
    #[serde(default = "default_block_interval_ms")]
    pub target_block_interval_ms: u64,
}

fn default_block_interval_ms() -> u64 {
    120_000
}

/// What kind of node this is, beyond the boot-time `ApiInfo` shape.
///
/// Captures the protocol-visible mode flags advertised on the P2P
/// handshake plus operator-config toggles (extra-index, API submission,
/// declared / bind addr). Set at boot from `NodeConfig` + the hardcoded
/// `Mode` peer-feature; doesn't change at runtime today.
///
/// `mining` mirrors the node's mining configuration (whether the
/// `/mining/*` work-serving routes are wired).
///
/// Backs `GET /api/v1/identity`; consumed by the operator dashboard's
/// identity strip. Rust-native — Scala's `/info` has no equivalent.
///
/// Field contract:
/// - `state_type`, `verify_transactions`, `history_mode`, `mining`,
///   `extra_index_enabled`, `declared_addr`, `bind_addr` are
///   config-intent: what `NodeConfig` asked for at boot. Scala parity
///   for the wire-visible fields lives here.
/// - `utxo_bootstrap` and `nipopow_bootstrap` are effective-state:
///   true when either the operator's config flag is set OR a
///   matching provenance marker on disk confirms the bootstrap
///   actually ran. An operator who cleared the bootstrap flag in
///   config after a successful install therefore still sees `true`
///   on the surface that survived the install. Refreshed by the
///   action loop on bootstrap transitions; live for the process
///   lifetime via `Arc<ArcSwap<ApiIdentity>>` in `api_bridge.rs`.
/// - `mode` is a compact human-readable label composed from both
///   classes, including the Mode 4 `"mode-4 · …"` variants.
///
/// To observe actual runtime progress (e.g. current chain height,
/// peer count), read `fullHeight` / `bestFullHeaderId` on adjacent
/// endpoints.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct ApiIdentity {
    /// Compact human-readable summary (e.g. "archive · utxo"). Derived
    /// from `state_type` + `history_mode` + `utxo_bootstrap` so the
    /// dashboard hero strip can render a single string.
    pub mode: String,
    /// Wire byte = 0 / 1 in the `Mode` peer-feature; mirrored here as
    /// a typed enum so consumers don't have to guess the string set.
    pub state_type: ApiStateType,
    pub verify_transactions: bool,
    /// How the operator configured chain-history retention. Tagged
    /// union — clients switch on `kind`. See [`ApiHistoryMode`].
    pub history_mode: ApiHistoryMode,
    pub utxo_bootstrap: bool,
    pub nipopow_bootstrap: bool,
    pub mining: bool,
    pub extra_index_enabled: bool,
    /// `[peers] declared_addr` from the TOML config — what we advertise
    /// to peers in the handshake. `None` = anonymous, not gossipable.
    pub declared_addr: Option<String>,
    /// `[peers] bind_addr` — local TCP listen address. `None` =
    /// outbound-only.
    pub bind_addr: Option<String>,
}

/// State-store backend kind, mirroring the protocol-visible `Mode`
/// peer-feature byte (`utxo` = 0, `digest` = 1).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiStateType {
    #[default]
    Utxo,
    Digest,
}

/// Chain-history retention policy as configured at boot. Tagged
/// union; clients switch on `kind`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApiHistoryMode {
    /// `blocks_to_keep = -1` and `utxo_bootstrap = false` and not the
    /// canonical Mode 6 combo. Full archive — the most common live
    /// runtime mode and the `Default` variant.
    #[default]
    Archive,
    /// `utxo_bootstrap = true`. Operator opted into the Mode 2 UTXO
    /// snapshot bootstrap path. The `kind` wires regardless of whether
    /// the snapshot has been applied — observe `fullHeight > 0` on
    /// `/info` or `/api/v1/tip` for that.
    UtxoBootstrapped,
    /// Canonical Mode 6 combo: `state_type = Digest`,
    /// `verify_transactions = false`, `blocks_to_keep = 0`. Boots
    /// successfully via the `is_canonical_mode_6` short-circuit in
    /// `validate_runtime_mode_support`.
    HeadersOnly,
    /// `blocks_to_keep = N` for `N >= 1`. Forward-compat with the
    /// Mode 3 eviction roadmap; currently rejected by the runtime
    /// gate.
    Pruned { suffix_len: u32 },
}

/// Single-call dashboard view: collapses sync + tip + peer count.
/// Polled at 1 Hz by the UI header strip.
///
/// Derives `Default` (like [`ApiIdentity`]) so test stubs can write
/// `ApiStatus { <overrides>, ..Default::default() }` and stop breaking
/// on every added field.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct ApiStatus {
    pub sync_state: SyncStateLabel,
    pub peer_count: u32,
    pub best_header_height: u32,
    pub best_full_block_height: u32,
    pub headers_ahead_of_full_blocks: u32,
    pub mempool_size: u32,
    pub snapshot_age_ms: u64,
    /// Mode 2 bootstrap progress. Populated while a UTXO snapshot
    /// bootstrap is in flight — i.e. operator config has
    /// `utxo_bootstrap = true` AND `best_full_block_height == 0`.
    /// Cleared (`None`) once the snapshot installs and the node
    /// transitions to normal block sync. Operators rendering the
    /// dashboard panel should treat `Some(_)` as "show the
    /// bootstrap card, hide the normal block-sync pipeline row".
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bootstrap: Option<ApiBootstrapStatus>,
    /// The most recent block this node REJECTED during apply — a consensus
    /// fork-from-network signal (the node refused a block its peers may have
    /// accepted). `None` when no rejection has occurred this session. A
    /// persistent `Some(_)` is an operator page.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_block_apply_error: Option<ApiBlockApplyError>,
    /// Monotonic count of block-apply rejections since node start (the
    /// `ergo_node_block_apply_errors_total` Prometheus counter source).
    /// Session-scoped — resets on restart, which `rate()` handles.
    #[serde(default)]
    pub block_apply_errors_total: u64,
    /// Terminal deep-fork wedge: the best-header chain forks below the
    /// state backend's rollback window, so this node can never reorg onto
    /// it and will not apply another block. A persistent `Some(_)` is an
    /// operator page — the only recovery is a resync (wipe the data dir
    /// and sync fresh). `None` in normal operation.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sync_wedged: Option<ApiSyncWedged>,
    /// Shadow-validation status (`[shadow]` — live cross-check against a
    /// Scala reference node). Present only when the mode is enabled.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub shadow: Option<ApiShadowStatus>,
    /// Monotonic count of unconfirmed-tx ids this node REQUESTED from peers
    /// in response to a tx-typed `Inv` (the
    /// `ergo_node_mempool_tx_requested_total` Prometheus counter source).
    /// Counts ids passed to the coordinator's `request_transactions`, i.e.
    /// the `unknown` (not-already-pooled / not-invalidated) advertised set.
    /// Session-scoped — resets on restart, which `rate()` handles.
    #[serde(default)]
    pub mempool_tx_requested_total: u64,
    /// Monotonic count of peer-sourced (`TxSource::Peer`) transactions
    /// ADMITTED to the mempool (the
    /// `ergo_node_mempool_peer_tx_admitted_total` Prometheus counter
    /// source). API/Wallet-sourced admissions are excluded. Session-scoped
    /// — resets on restart, which `rate()` handles.
    #[serde(default)]
    pub mempool_peer_tx_admitted_total: u64,
    /// Monotonic count of peer-sourced (`TxSource::Peer`) transactions
    /// REJECTED by admission (the
    /// `ergo_node_mempool_peer_tx_rejected_total` Prometheus counter
    /// source). API/Wallet-sourced rejections are excluded. Session-scoped
    /// — resets on restart, which `rate()` handles.
    #[serde(default)]
    pub mempool_peer_tx_rejected_total: u64,
    /// Session-total tip-replacement reorgs detected by the operator event
    /// differ (`ergo_node_reorg_total`).
    #[serde(default)]
    pub reorgs_total: u64,
    /// Depth of the most recent retained reorg, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reorg_depth: Option<u32>,
    /// Unix-ms of the most recent retained reorg, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reorg_unix_ms: Option<u64>,
    /// `1` while the action loop is inside full-block `process_block`
    /// (`ergo_node_apply_in_progress`). Live atomic — not snapshot-stale.
    #[serde(default)]
    pub apply_in_progress: bool,
    /// Wall-clock ms of the last finished apply attempt
    /// (`ergo_node_last_apply_duration_ms`).
    #[serde(default)]
    pub last_apply_duration_ms: u64,
    /// Height of the last *successful* full-block apply
    /// (`ergo_node_last_applied_height`). `0` until the first success.
    #[serde(default)]
    pub last_applied_height: u32,
    /// ms since the last finished apply attempt, if any
    /// (`ergo_node_last_apply_age_ms`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_apply_age_ms: Option<u64>,
}

/// A block this node rejected during apply, surfaced to operators. Distinct
/// from a benign data-wait (section not yet downloaded) or reorg — this is a
/// block the node refused on validation while its peers may have accepted it.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiBlockApplyError {
    /// Hex-encoded rejected header id.
    pub block_id: String,
    /// Height the rejected block claimed.
    pub height: u32,
    /// Operator-facing rejection reason (the `BlockProcessError` Display).
    pub reason: String,
    /// Milliseconds since the rejection was recorded (computed at read time).
    pub age_ms: u64,
}

/// Terminal deep-fork wedge, surfaced to operators. The best-header chain
/// (the heaviest chain the network is on) forks below this node's rollback
/// window: the undo data needed to reorg onto it was pruned, so block apply
/// is permanently stuck at `stuck_height` while headers keep advancing.
/// Matches the Scala reference node's `keepVersions` horizon — a Scala node
/// in the same position is equally unrecoverable. Only a resync recovers.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiSyncWedged {
    /// Hex-encoded id of the stuck full-block tip (on the abandoned branch).
    pub stuck_block_id: String,
    /// Height of the stuck full-block tip.
    pub stuck_height: u32,
    /// Lowest height the fork-point walk examined — the best-header chain
    /// still disagreed there, so the true fork is at or below it.
    pub fork_below_height: u32,
    /// The rollback window the fork depth exceeded.
    pub max_rollback_depth: u32,
    /// Milliseconds since the wedge was detected, computed when the snapshot
    /// is PUBLISHED (staleness bounded by `snapshot_age_ms`, ~1 s ticks) —
    /// not recomputed per read.
    pub age_ms: u64,
}

/// Shadow-validation status (`[shadow]`): the outcome of the live
/// cross-check against the configured Scala reference node. Sourced from
/// the watch task's shared state at snapshot publish; backs the
/// `ergo_node_shadow_*` Prometheus series and the `shadowDivergence`
/// operator event.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiShadowStatus {
    /// Reference answered on the most recent compare tick.
    pub reference_reachable: bool,
    /// Highest height a compare completed at (0 = none yet).
    pub last_compared_height: u32,
    /// Confirmed divergences since node start (monotonic).
    pub divergence_total: u64,
    /// The ACTIVE confirmed divergence, or `None` when the chains agree.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub diverged: Option<ApiShadowDivergence>,
}

/// One active shadow divergence: `header_mismatch` (this node and the
/// reference follow different canonical headers at `height`) or
/// `tip_stall` (the reference's full-block tip is advancing past ours).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiShadowDivergence {
    /// `header_mismatch | tip_stall`.
    pub kind: String,
    pub height: u32,
    /// Our canonical header id at `height` (empty for `tip_stall`).
    pub ours: String,
    /// The reference's canonical header id at `height` (empty for `tip_stall`).
    pub theirs: String,
}

/// Bootstrap progress for the Mode 2 (UTXO snapshot) consume side.
/// Surfaced to operators so the ~30–60 minute boot window doesn't
/// look like a stuck node (fullHeight=0, indexer=0%, etc.). Each
/// field maps directly to a dashboard cell or progress bar.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiBootstrapStatus {
    /// Current bootstrap phase. UI maps each variant to its human
    /// label and phase indicator.
    pub phase: ApiBootstrapPhase,
    /// Snapshot height as selected by the discovery quorum.
    /// `0` when still in `discovery` and no manifest has been picked.
    pub snapshot_height: u32,
    /// Hex-encoded manifest_id when known (post-discovery), else `None`.
    /// 32 bytes / 64 hex chars.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub manifest_id: Option<String>,
    /// Number of peers in the quorum that voted for the selected
    /// manifest. `0` during the `discovery` phase before quorum.
    pub voters: u32,
    /// Chunks received and committed to assembly. `0` until the
    /// `downloading_chunks` phase starts.
    pub chunks_received: u32,
    /// Total chunks expected per the verified manifest. `0` before
    /// `manifest_verified`.
    pub chunks_total: u32,
    /// `true` once the manifest's root label has been compared
    /// against the canonical header.state_root at `snapshot_height`
    /// and matched. False until the trust check fires.
    pub trust_check_passed: bool,
    /// Unix-ms timestamp when the bootstrap reducer first transitioned
    /// out of `Idle`. Lets the UI compute an "elapsed" clock without
    /// holding state of its own.
    pub started_unix_ms: u64,
    /// NiPoPoW bootstrap phase, when enabled. Absent when NiPoPoW
    /// bootstrap is disabled (legacy Mode 2-only flow) or hasn't
    /// started.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub popow_phase: Option<ApiPopowPhase>,
    /// Number of distinct peers that have responded with a NiPoPoW
    /// proof so far. `0` when popow_phase is absent or before any
    /// inbound proof.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub popow_providers: Option<u32>,
    /// Header-chain availability mode as reported by the store —
    /// `dense` for a full-node-sync history, `sparse` for a NiPoPoW-
    /// bootstrapped history. Absent when the store reports the
    /// default (Dense) and no NiPoPoW bootstrap is in progress.
    ///
    /// Distinct from [`ApiIdentity::history_mode`] — that field is the
    /// operator-configured chain-retention policy (archive / pruned /
    /// utxo-bootstrapped / headers-only), this field is the on-disk
    /// header-section shape (dense from genesis vs sparse with a
    /// NiPoPoW dense-suffix anchor).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub header_availability: Option<ApiHeaderAvailability>,
    /// In `HeaderAvailability::PoPowSparse` mode, the lowest height
    /// for which a `HEADER_CHAIN_INDEX` row exists locally. Heights
    /// below this are sparse-prefix witnesses (not chain-indexed).
    /// `None` when mode is Dense.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub popow_dense_from_height: Option<u32>,
}

/// UTXO snapshot bootstrap reducer phase, as surfaced on
/// [`ApiBootstrapStatus`]. UI maps each variant to a human label and
/// phase indicator.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiBootstrapPhase {
    /// Outbound peer-query fan-out; no manifest selected yet.
    Discovery,
    /// Manifest selected by quorum; download in flight.
    ManifestRequested,
    /// Manifest bytes verified against `header.state_root`; chunk
    /// download has not started yet.
    ManifestVerified,
    /// Chunk download in progress.
    DownloadingChunks,
    /// All chunks received; reconstructing the UTXO tree.
    Reconstructing,
    /// Tree reconstructed; install into the chain store in flight.
    Installing,
    /// Snapshot installed; catching up from snapshot height to tip.
    PostInstallCatchup,
}

/// NiPoPoW bootstrap reducer phase, as surfaced on
/// [`ApiBootstrapStatus::popow_phase`]. UI mirrors the UTXO bootstrap
/// progression but for the NiPoPoW chain-prefix path.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiPopowPhase {
    /// Outbound NiPoPoW proof requests in flight; quorum not yet met.
    Requesting,
    /// Quorum met; the dominant proof has been selected.
    QuorumMet,
    /// Proof applied to the chain state — `header_availability` is
    /// now `Sparse`.
    Applied,
    /// Bounded forward catch-up from the proof's anchor height in
    /// flight.
    Catchup,
}

/// Header-chain density reported by the chain store.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiHeaderAvailability {
    /// Full-node-sync header chain — every height has a row in
    /// `HEADER_CHAIN_INDEX`.
    Dense,
    /// NiPoPoW-bootstrapped history — heights below
    /// `popow_dense_from_height` are sparse-prefix witnesses, not
    /// chain-indexed.
    Sparse,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SyncStateLabel {
    /// No connected peers. The `Default` — matches the pre-first-publish
    /// snapshot (`SnapshotPublisher` empty state).
    #[default]
    Disconnected,
    /// Catching up — header chain not yet near tip, or block-application
    /// gap > tolerance.
    Syncing,
    /// Header chain synced, full-block tip within tolerance.
    AtTip,
    /// Connected but no progress within stall threshold.
    Stalled,
}

/// Tip pointers. During IBD `best_header` and `best_full_block` can
/// diverge by tens of thousands of blocks — they are reported separately
/// and the gap is precomputed for clients.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiTip {
    pub best_header: ApiHeaderRef,
    pub best_full_block: ApiFullBlockRef,
    pub headers_ahead_of_full_blocks: u32,
}

/// `GET /api/v1/votes` — what the node operator can vote on. Native operator
/// endpoint (no Scala equivalent; ungated like the other `/api/v1/*` reads).
/// The votable set + per-parameter bounds come from the same table the
/// consensus vote-recompute uses, so an operator (and the candidate-vote
/// selector) sees exactly which votes are legal.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiVotes {
    /// Current full-block height (votes are cast by the miner at the next height).
    pub block_height: u32,
    /// Active block-format version.
    pub block_version: u8,
    /// Height the current voting epoch's parameters took effect from.
    pub epoch_start_height: u32,
    /// The numeric parameters an operator can vote to change, with the bounds a
    /// vote must respect. Excludes blockVersion (soft-fork driven, not voted).
    pub votable_parameters: Vec<ApiVotableParam>,
    /// The operator's configured voting targets — the boot `[voting]` config
    /// plus any successful runtime `POST /api/v1/votes` edits (the live policy).
    /// Empty when no targets are configured.
    pub configured_votes: Vec<ApiConfiguredVote>,
}

/// A votable numeric protocol parameter and the inclusive `[min, max]` target
/// bounds. A vote moves the parameter at most one `step` per voting epoch toward
/// the target and only while it is inside the bound, so a target outside
/// `[min, max]` is rejected. Mirror of `ergo_validation::voting::ParamDescriptor`.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiVotableParam {
    pub id: u8,
    pub name: String,
    /// One-line operator-facing explanation of what the parameter governs and
    /// the implication of voting it higher. Sourced from
    /// `ergo_validation::voting::votable_param_description`.
    pub description: String,
    pub current: i32,
    pub step: i32,
    /// Inclusive lower target bound. The recompute gates at the bound (won't
    /// step a parameter further past it) rather than hard-clamping.
    pub min: i32,
    /// Inclusive upper target bound.
    pub max: i32,
}

/// An operator's configured vote target for one parameter.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiConfiguredVote {
    pub parameter_id: u8,
    pub name: String,
    /// Desired target value; the node votes up/down toward it.
    pub target: i64,
}

/// Request body for `POST /api/v1/votes` (auth-gated operator write). The
/// `votes` list is the FULL desired set and REPLACES the node's current voting
/// targets — an empty list clears all votes.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiSetVotesRequest {
    /// The operator's desired votes, one entry per parameter to target.
    pub votes: Vec<ApiVoteTarget>,
}

/// One desired vote in a `POST /api/v1/votes` request.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiVoteTarget {
    /// Votable parameter id (1..=8, or 9 = subblocksPerBlock). `blockVersion`
    /// (123) and soft-fork (120) are not operator-votable and are rejected.
    pub parameter_id: u8,
    /// Desired value; the node votes up/down one step per block toward it.
    pub target: i64,
}

/// Response for `GET /api/v1/votes/history` — the protocol-parameter change
/// timeline reconstructed from the node's stored per-epoch parameter rows.
/// Each entry is an epoch boundary at which one or more parameters actually
/// changed (boundaries with no change are omitted), so this reads as the
/// governance history: what the network's votes have changed, and when.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiVotesHistory {
    /// Voting epoch length in blocks (mainnet 1024, testnet 128). Parameter
    /// changes can only take effect at heights that are multiples of this.
    pub epoch_length: u32,
    /// Current full-block height, for context.
    pub current_height: u32,
    /// Epoch boundaries where at least one parameter changed, oldest first.
    pub changes: Vec<ApiVoteChangeEvent>,
}

/// One epoch boundary at which the active protocol parameters changed.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiVoteChangeEvent {
    /// Epoch-start height at which these new values took effect.
    pub height: u32,
    /// The parameters that changed at this boundary.
    pub params: Vec<ApiParamChange>,
}

/// A single parameter's change across one epoch boundary.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiParamChange {
    /// Parameter id (1..=8, 9 = subblocksPerBlock, or 123 = blockVersion).
    pub id: u8,
    /// Stable camelCase parameter name.
    pub name: String,
    /// One-line operator-facing explanation of the parameter.
    pub description: String,
    /// Value before this boundary. `null` when the parameter first became
    /// active here (e.g. `subblocksPerBlock` at its activation fork).
    pub from: Option<i64>,
    /// Value from this boundary onward.
    pub to: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiHeaderRef {
    pub height: u32,
    pub header_id: String,
    pub parent_id: String,
    pub timestamp_unix_ms: u64,
    /// Compact difficulty target (`nBits`) committed in this header.
    pub n_bits: u32,
    /// Network difficulty decoded from `n_bits`, as a decimal string —
    /// full precision, since difficulty exceeds `u64` at high mainnet
    /// difficulty. Hashrate is a client derivation (`difficulty /
    /// target_block_interval`), not a field here.
    pub difficulty: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiFullBlockRef {
    pub height: u32,
    pub header_id: String,
    pub parent_id: String,
    pub timestamp_unix_ms: u64,
    /// AVL+ authenticated UTXO-tree root digest committed in this full
    /// block's header — 33 bytes (`Digest32 || balance-byte`), hex-encoded
    /// (66 chars). Mirrors the on-chain `Header.stateRoot` field;
    /// distinct from the chain's cumulative-PoW score or any header hash.
    pub state_root_avl: String,
    /// Compact difficulty target (`nBits`) committed in this header.
    pub n_bits: u32,
    /// Network difficulty decoded from `n_bits`, as a decimal string.
    pub difficulty: String,
}

/// Sync pipeline state.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiSyncStatus {
    pub headers_chain_synced: bool,
    pub best_header_height: u32,
    pub best_full_block_height: u32,
    pub gap: u32,
    pub download_window: u32,
    pub pending_blocks: u32,
    pub recovery_done: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiPeer {
    pub addr: String,
    pub direction: ApiPeerDirection,
    pub state: ApiPeerState,
    pub score: i32,
    pub agent: Option<String>,
    pub node_name: Option<String>,
    pub version: Option<String>,
    pub sync_version: String,
    pub connected_seconds: u64,
    pub last_seen_seconds: u64,
    /// Cumulative post-handshake framed-message bytes received from this
    /// peer (per-frame header+checksum+payload), counted at the per-peer
    /// I/O task's transport boundary. Excludes the handshake exchange,
    /// which precedes that task. Read-only telemetry, never fed into peer
    /// scoring/throttle. `None` only on snapshots that predate the peer's
    /// connection.
    pub bytes_in: Option<u64>,
    /// Cumulative post-handshake framed-message bytes sent to this peer.
    /// Same accounting as [`Self::bytes_in`].
    pub bytes_out: Option<u64>,
    /// Peer's own best-block height as advertised in the most recent
    /// `SyncInfo` exchange. `None` until the sync layer plumbs it through.
    pub peer_height: Option<u32>,
    /// Peer's advertised REST API URL (the `RestApiUrl` handshake
    /// feature), verbatim as the peer sent it. `None` when the peer
    /// advertised none. Identity/observability only — not validated
    /// here beyond what the handshake parser already did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rest_api_url: Option<String>,
    /// Peer's declared public address (`ip:port`) from its `PeerSpec`,
    /// what it advertises as reachable. `None` when the peer declared no
    /// address (anonymous / not gossipable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_address: Option<String>,
}

/// Which side initiated the peer connection.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiPeerDirection {
    Inbound,
    Outbound,
}

/// Connection lifecycle state observed by the peer manager.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiPeerState {
    Connecting,
    Handshaking,
    Active,
    Degraded,
    Disconnected,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiMempoolSummary {
    pub size: u32,
    pub total_bytes: u64,
    pub capacity_count: u32,
    pub capacity_bytes: u64,
    pub revalidation_pending: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiMempoolTransactions {
    pub transactions: Vec<ApiMempoolTransaction>,
    /// Active priority-weight function for the running node — one of
    /// `"cost"`, `"size"`, `"min"`. Clients dividing `priority_weight`
    /// by 1024 and the matching denominator recover raw fee-per-resource.
    pub weight_function: ApiWeightFunction,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiMempoolTransaction {
    pub tx_id: String,
    pub fee_nano_erg: u64,
    pub fee_per_byte_nano_erg: u64,
    pub size_bytes: u32,
    /// Sigma-interpreter execution cost in block-budget units. Compare
    /// against the active epoch's `maxBlockCost`.
    pub validation_cost_units: u64,
    /// Mempool priority weight = `(fee × 1024) / denom`, where `denom`
    /// is set by `weight_function` on the envelope.
    pub priority_weight: u64,
    pub source: ApiTxSource,
    pub input_count: u32,
    pub output_count: u32,
    pub parents_in_pool: u32,
    pub first_seen_unix_ms: u64,
    pub first_seen_age_ms: u64,
    pub last_checked_age_ms: u64,
}

/// A single resolved input or output box for the tx-detail drawer.
/// `box_id`/`address`/`value`/`tokens` are all `Option` because an
/// unconfirmed tx's spent input may not resolve against the extra-index
/// or the pool-output overlay (dangling, or an indexer-lag miss). When a
/// box is unresolved the wire emits `null` for every projected field —
/// including `tokens` — so a consumer cannot mistake "unknown" for
/// "known to have no tokens" (`null` ≠ `[]`).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiIoBox {
    pub box_id: Option<String>,
    pub address: Option<String>,
    pub value: Option<u64>,
    pub tokens: Option<Vec<ApiAsset>>,
}

/// `{tokenId, amount}` asset entry on an [`ApiIoBox`].
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiAsset {
    pub token_id: String,
    pub amount: u64,
}

/// Inputs/outputs of a transaction resolved to addresses + values for the
/// UI detail drawer, backing `GET /api/v1/transactions/{tx_id}/detail`.
///
/// No `confirmed` flag: the endpoint resolves a tx found in either the
/// extra-index or the mempool, but the extra-index is not chain-state, so
/// during indexer lag a chain-confirmed tx could be indistinguishable
/// from a pooled one — rather than emit a label that can be wrong, the
/// caller relies on its own context (the page it opened the drawer from).
/// Fee is intentionally omitted: it's shown on the mempool row already,
/// and recomputing it from possibly-unresolved inputs would be unreliable.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiTxDetail {
    pub tx_id: String,
    pub inputs: Vec<ApiIoBox>,
    pub outputs: Vec<ApiIoBox>,
}

/// One recent full block for the dashboard cockpit's "recent blocks" list,
/// backing `GET /api/v1/blocks/recent` (newest-first). The list reflects the
/// committed full-block chain and may briefly trail `/api/v1/tip` during the
/// async-persist window (see the endpoint description). `size_bytes` sums the
/// on-disk section byte lengths — header + blockTransactions + extension,
/// plus adProofs when the node retains it (adProofs is optional in UTXO
/// mode). A block whose required sections are missing, or whose any section
/// read errors, is omitted from the list rather than reported with a
/// silently undercounted size.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiRecentBlock {
    pub height: u32,
    pub header_id: String,
    pub ts_unix_ms: u64,
    pub txs: u32,
    pub size_bytes: u64,
    /// Socket address (`ip:port`) of the FIRST peer that delivered this
    /// block's header to us — the peer whose `Modifier` carried the
    /// header bytes we accepted. A freshly-mined block is typically
    /// announced first by the miner/pool's node, so this attributes a
    /// block → peer (→ pool, with out-of-band peer↔pool knowledge).
    /// `None` when the deliverer is unknown: the block was synced before
    /// the bounded first-deliverer ring captured it, the entry has since
    /// been FIFO-evicted, or the block was applied locally (self-mined).
    /// Pure observability — never affects validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_by: Option<String>,
    /// Miner public key from the header's Autolykos solution (33-byte
    /// compressed secp256k1 point, hex) — present on both v1 and v2
    /// solutions. Identifies who mined the block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub miner_pk: Option<String>,
    /// P2PK base58 address derived from `miner_pk` with this node's
    /// network prefix — the conventional "miner" identity explorers
    /// show. `None` only if address encoding failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub miner_address: Option<String>,
}

/// Active mempool priority-weight function. Wire strings match
/// `ergo_mempool::WeightFunction::name()` exactly: `"cost"`, `"size"`,
/// `"min"`. Boot-time `TryFrom<&str>` rejects unknown names.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub enum ApiWeightFunction {
    #[default]
    #[serde(rename = "cost")]
    Cost,
    #[serde(rename = "size")]
    Size,
    #[serde(rename = "min")]
    Min,
}

/// Error returned by [`ApiWeightFunction::try_from`] for an unknown
/// weight-function name. The boot path propagates this as a hard
/// failure rather than silently falling back to a default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownWeightFunction(pub String);

impl std::fmt::Display for UnknownWeightFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown mempool weight function {:?}; expected one of \"cost\", \"size\", \"min\"",
            self.0
        )
    }
}

impl std::error::Error for UnknownWeightFunction {}

impl TryFrom<&str> for ApiWeightFunction {
    type Error = UnknownWeightFunction;
    fn try_from(name: &str) -> Result<Self, Self::Error> {
        match name {
            "cost" => Ok(Self::Cost),
            "size" => Ok(Self::Size),
            "min" => Ok(Self::Min),
            other => Err(UnknownWeightFunction(other.to_string())),
        }
    }
}

/// Where a mempool transaction entered our pool. Tagged union — clients
/// switch on `kind` and read `addr` only for `peer`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApiTxSource {
    Peer { addr: String },
    Api,
    Wallet,
    DemotedFromBlock,
}

/// Host-process metrics: memory, on-disk databases, free space on the
/// data-directory volume. `None` on any field means "could not
/// determine" — sysinfo refresh failure, permissions, missing file,
/// or platform gap. `Some(0)` means a legitimately zero measurement.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct ApiHost {
    /// Resident set size of the node process.
    pub rss_bytes: Option<u64>,
    /// Size of `state.redb` on disk.
    pub state_db_bytes: Option<u64>,
    /// Size of `indexer.redb`. `None` when the indexer is disabled or
    /// the file is missing.
    pub index_db_bytes: Option<u64>,
    /// Free bytes on the volume containing the data directory.
    pub disk_free_bytes: Option<u64>,
    /// Total bytes on that volume.
    pub disk_total_bytes: Option<u64>,
    /// CPU usage of the node process as a percent of one core.
    pub cpu_pct: Option<f32>,
    /// Receive bytes-per-second across all interfaces.
    pub net_in_bps: Option<u64>,
    /// Transmit bps.
    pub net_out_bps: Option<u64>,
    /// 1-minute load average.
    pub load_1m: Option<f32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiHealth {
    pub status: HealthStatus,
    pub behind: u32,
    pub last_progress_age_ms: u64,
    pub peer_count: u32,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Ok,
    Stalled,
    Disconnected,
    /// A block-apply rejection is outstanding — the node refused a block its
    /// peers may have accepted (a possible consensus fork from the network).
    /// /health maps this to HTTP 503 so operators page on it.
    Rejecting,
    /// Terminal deep-fork wedge — the best-header chain forks below the
    /// rollback window and this node can never reorg onto it (see
    /// [`ApiSyncWedged`]). /health maps this to HTTP 503; the only recovery
    /// is a resync.
    Wedged,
}

/// Hex-encode a 32-byte id without the `0x` prefix.
pub fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

/// Submission mode picks the commit boundary inside the shared admission
/// pipeline. `Broadcast` runs steps 0–14 and commits to the pool +
/// emits `BroadcastInv`. `CheckOnly` runs steps 0–14 and stops — no
/// pool mutation, no Inv. Both still mutate the anti-DoS bookkeeping
/// per mempool invariant #7.
///
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmitMode {
    Broadcast,
    CheckOnly,
}

/// Stable wire-shape for a submission rejection. Mirrors the keys of
/// `RejectReason` flattened to short snake_case strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitError {
    pub reason: String,
    pub detail: Option<String>,
}

/// 200 body for `POST /api/v1/mempool/{submit,check}`.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiSubmitResponse {
    pub tx_id: String,
}

/// 4xx/5xx body for the Scala-compat submit endpoints
/// (`POST /transactions`, `/transactions/bytes`, `/transactions/checkBytes`).
/// Shape matches Scala's `ApiError` (`{error, reason, detail}`) where
/// `error` is the HTTP status code repeated as an integer for
/// Scala-client parity. Kept on the compat surface only.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiSubmitError {
    pub error: u16,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// 4xx/5xx body for `POST /api/v1/mempool/{submit,check}`. Identical to
/// [`ApiSubmitError`] minus the `error` field — Rust-native clients have
/// the HTTP status from the response line, so duplicating it in the body
/// is just bytes on the wire.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiNativeSubmitError {
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl From<ApiSubmitError> for ApiNativeSubmitError {
    fn from(e: ApiSubmitError) -> Self {
        Self {
            reason: e.reason,
            detail: e.detail,
        }
    }
}

/// OpenAPI request-body schema for the raw transaction bytes accepted by
/// `POST /api/v1/mempool/{submit,check}`. The handlers take an opaque
/// `axum::body::Bytes` and forward it verbatim; this renders that body as
/// `application/octet-stream` binary (`type: string, format: binary`) in
/// the generated spec. Documentation only — never constructed at runtime.
#[derive(ToSchema)]
#[schema(value_type = String, format = Binary)]
pub struct RawTransactionBytes(pub Vec<u8>);

/// One sample in the difficulty time series returned by
/// `GET /api/v1/difficulty/history`: the network difficulty observed at a
/// block height, alongside that block's timestamp.
///
/// `difficulty` is the decoded decimal value as a string — at mainnet
/// scale it exceeds `u64`, so a JSON number would silently lose precision
/// in javascript consumers. `n_bits` is deliberately omitted: it is the
/// compact encoding of this same value, so it would be a lossy duplicate.
/// Consumers read `difficulty` directly.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiDifficultyPoint {
    pub height: u32,
    pub timestamp_unix_ms: u64,
    pub difficulty: String,
}

/// Ascending-by-height difficulty series for `GET
/// /api/v1/difficulty/history`. Oldest point first so a consumer can plot
/// it left-to-right without re-sorting.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiDifficultySeries {
    pub points: Vec<ApiDifficultyPoint>,
}

/// One miner's aggregate over the `minerStats` window.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiMinerStat {
    /// Miner public key (33-byte compressed point, hex) from the folded
    /// headers' Autolykos solutions.
    pub pk: String,
    /// P2PK address derived from `pk` with this node's network prefix.
    /// Absent only when the stored pk bytes fail address encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Blocks this miner produced within the window.
    pub count: u32,
    /// Height of this miner's most recent block in the window.
    pub last_height: u32,
}

/// Response of `GET /api/v1/mining/minerStats` — the network mining
/// landscape over the last `window` headers of the canonical chain.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiMinerStats {
    /// Best-header height at fold time (0 on an empty chain).
    pub tip_height: u32,
    /// Requested window after clamping to `[1, 16384]`.
    pub window: u32,
    /// Headers actually scanned — shorter than `window` near genesis.
    pub blocks: u32,
    /// Miners sorted by `count` descending, ties by `last_height`
    /// descending.
    pub miners: Vec<ApiMinerStat>,
}

/// One operator event for `GET /api/v1/events` — flat shape with optional
/// per-kind fields so the feed renders without a type registry. `kind` is
/// one of `blockApplied` / `reorg` / `peerConnected` / `peerDisconnected` /
/// `indexerStatus`. Reorg-only fields (`depth`, `dropped_header_ids`) are
/// best-effort from the node's 32-block committed tail; deeper orphan ids are
/// not fabricated.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiNodeEvent {
    /// Monotonic sequence number (gaps = ring eviction).
    pub seq: u64,
    pub unix_ms: u64,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropped_header_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txs: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Event-feed page for `GET /api/v1/events`: the retained tail (bounded by
/// the node-side ring) plus the newest sequence number for `?since=` polls.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiNodeEvents {
    pub latest_seq: u64,
    pub events: Vec<ApiNodeEvent>,
}

/// One retained reorg for `GET /api/v1/diagnostics/reorgs` — postmortem
/// ring (last 64 **or** 7 days), not the coarse glanceable event feed.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiReorgRecord {
    pub unix_ms: u64,
    pub height: u32,
    pub header_id: String,
    pub depth: u32,
    pub dropped_header_ids: Vec<String>,
    /// True when dropped ids hit the 32-block committed-tail cap.
    pub orphans_truncated: bool,
}

/// Envelope for the diagnostics reorg history.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiReorgHistory {
    /// Session-total reorgs detected (not reset by age/count prune).
    pub total: u64,
    pub cap: u32,
    pub max_age_ms: u64,
    /// Newest-first retained entries.
    pub reorgs: Vec<ApiReorgRecord>,
}

/// Self-repair sub-state of the extra-index for `GET /api/v1/indexer/status`.
/// Mirrors the durable `INDEXER_META` repair markers: `pending` = a
/// chain-free rebuild of the derived template/token segments is owed or in
/// progress; `nextGi` = the rebuild's phase-1 cursor (boxes re-derived so
/// far — progress % = nextGi / totals.boxes); `skipped` = undecodable boxes a
/// completed rebuild had to omit (the honest marker: non-zero with
/// `pending=false` means knowingly incomplete); `driftSkips` = cumulative
/// process-lifetime live-apply skips (diagnostic; resets on restart).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiIndexerRepair {
    pub pending: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_gi: Option<u64>,
    pub skipped: u64,
    pub drift_skips: u64,
}

/// Running index totals for `GET /api/v1/indexer/status`.
///
/// `boxes`/`txs` (and `repair.nextGi`) are `u64` JSON numbers. Mainnet is
/// at ~10^7–10^8 today; a JS consumer only loses precision past 2^53
/// (~9·10^15), which at ~50M boxes/year is comfortably >10^8 years away —
/// documented so the contract's limit is explicit rather than discovered.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiIndexerTotals {
    pub boxes: u64,
    pub txs: u64,
}

/// Operator-grade extra-index health for `GET /api/v1/indexer/status`.
/// Superset of `/blockchain/indexedHeight` (which stays pinned to its
/// Scala-parity shape): adds the self-repair markers and totals so the UI
/// can say "caught up but degraded" honestly. `status` carries the same
/// camelCase label set as indexedHeight (`syncing` / `caughtUp` /
/// `halted`); `haltReason` is the kebab-case reason when halted.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiIndexerStatus {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub halt_reason: Option<String>,
    pub indexed_height: u64,
    pub full_height: u32,
    pub repair: ApiIndexerRepair,
    pub totals: ApiIndexerTotals,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    /// `Peer` variant serializes as `{"kind":"peer","addr":"..."}`.
    /// `kind` is snake_case; `addr` is the only payload field.
    #[test]
    fn api_tx_source_peer_serializes_with_kind_and_addr() {
        let src = ApiTxSource::Peer {
            addr: "159.65.11.55:9030".to_string(),
        };
        let json = serde_json::to_value(&src).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "kind": "peer", "addr": "159.65.11.55:9030" }),
            "peer wire shape regression: got {json}",
        );
    }

    /// Unit variants serialize as bare `{"kind":"..."}` with no payload.
    /// snake_case rename covers the multi-word `DemotedFromBlock`.
    #[test]
    fn api_tx_source_unit_variants_serialize_kind_only() {
        let cases: &[(ApiTxSource, &str)] = &[
            (ApiTxSource::Api, "api"),
            (ApiTxSource::Wallet, "wallet"),
            (ApiTxSource::DemotedFromBlock, "demoted_from_block"),
        ];
        for (variant, kind) in cases {
            let json = serde_json::to_value(variant).unwrap();
            assert_eq!(
                json,
                serde_json::json!({ "kind": kind }),
                "{variant:?} wire shape regression: got {json}",
            );
        }
    }

    // ----- round-trips -----

    /// Every variant survives serialize → deserialize byte-for-byte.
    /// Pins that the tag-based discriminator can be both written and
    /// read with no asymmetry.
    #[test]
    fn api_tx_source_roundtrips_all_variants() {
        let cases = [
            ApiTxSource::Peer {
                addr: "127.0.0.1:9030".to_string(),
            },
            ApiTxSource::Api,
            ApiTxSource::Wallet,
            ApiTxSource::DemotedFromBlock,
        ];
        for original in cases {
            let json = serde_json::to_string(&original).unwrap();
            let decoded: ApiTxSource = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, original, "roundtrip failed for {original:?}");
        }
    }

    // ----- error paths -----

    /// An unknown `kind` value must fail deserialization rather than
    /// silently fall through to a default variant. Pins that we don't
    /// regress to an `#[serde(other)]` catch-all.
    #[test]
    fn api_tx_source_unknown_kind_rejects() {
        let bad = serde_json::json!({ "kind": "satellite" });
        let result: Result<ApiTxSource, _> = serde_json::from_value(bad);
        assert!(
            result.is_err(),
            "unknown kind must reject, got Ok({:?})",
            result.ok(),
        );
    }

    // ----- ApiWeightFunction: happy path -----

    /// Each variant serializes to the canonical mempool name —
    /// `Cost → "cost"`, `Size → "size"`, `Min → "min"`. Matches
    /// `ergo_mempool::WeightFunction::name()` exactly so no two
    /// strings claim to mean the same policy.
    #[test]
    fn api_weight_function_serializes_to_canonical_lowercase() {
        let cases = [
            (ApiWeightFunction::Cost, "cost"),
            (ApiWeightFunction::Size, "size"),
            (ApiWeightFunction::Min, "min"),
        ];
        for (variant, expected) in cases {
            let json = serde_json::to_value(variant).unwrap();
            assert_eq!(
                json,
                serde_json::Value::String(expected.to_string()),
                "{variant:?} must serialize as {expected:?}, got {json}",
            );
        }
    }

    // ----- ApiWeightFunction: round-trips -----

    #[test]
    fn api_weight_function_roundtrips_all_variants() {
        let cases = [
            ApiWeightFunction::Cost,
            ApiWeightFunction::Size,
            ApiWeightFunction::Min,
        ];
        for variant in cases {
            let json = serde_json::to_string(&variant).unwrap();
            let decoded: ApiWeightFunction = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, variant);
        }
    }

    // ----- ApiWeightFunction: TryFrom<&str> contract -----

    #[test]
    fn api_weight_function_try_from_accepts_canonical_names() {
        assert_eq!(
            ApiWeightFunction::try_from("cost").unwrap(),
            ApiWeightFunction::Cost,
        );
        assert_eq!(
            ApiWeightFunction::try_from("size").unwrap(),
            ApiWeightFunction::Size,
        );
        assert_eq!(
            ApiWeightFunction::try_from("min").unwrap(),
            ApiWeightFunction::Min,
        );
    }

    // ----- ApiWeightFunction: error paths -----

    /// Unknown names propagate as `UnknownWeightFunction(name)` —
    /// the boot path surfaces this as `NodeError` and refuses to
    /// start. No silent fallback, no `"unknown"` wire sentinel.
    #[test]
    fn api_weight_function_try_from_rejects_unknown() {
        let err = ApiWeightFunction::try_from("by_cost").unwrap_err();
        assert_eq!(err, UnknownWeightFunction("by_cost".to_string()));
        // Error message includes the bad name so the boot log is actionable.
        let msg = err.to_string();
        assert!(
            msg.contains("by_cost"),
            "error message must echo input: {msg}"
        );
        assert!(
            msg.contains("cost"),
            "error message must list canonical names: {msg}"
        );
    }

    /// Unit Default → `Cost`. `ApiMempoolTransactions::default()`
    /// downstream relies on this for empty-snapshot stubs that don't
    /// know the configured policy.
    #[test]
    fn api_weight_function_default_is_cost() {
        assert_eq!(ApiWeightFunction::default(), ApiWeightFunction::Cost);
    }

    // ----- ApiHistoryMode: happy path -----

    /// Unit variants emit bare `{"kind":"..."}` with no payload.
    /// snake_case rename covers `UtxoBootstrapped` and `HeadersOnly`.
    #[test]
    fn api_history_mode_unit_variants_serialize_kind_only() {
        let cases: &[(ApiHistoryMode, &str)] = &[
            (ApiHistoryMode::Archive, "archive"),
            (ApiHistoryMode::UtxoBootstrapped, "utxo_bootstrapped"),
            (ApiHistoryMode::HeadersOnly, "headers_only"),
        ];
        for (variant, kind) in cases {
            let json = serde_json::to_value(variant).unwrap();
            assert_eq!(
                json,
                serde_json::json!({ "kind": kind }),
                "{variant:?} wire shape regression: got {json}",
            );
        }
    }

    /// `Pruned { suffix_len }` carries the retention length on the
    /// same JSON object as the `kind` tag.
    #[test]
    fn api_history_mode_pruned_serializes_kind_and_suffix_len() {
        let variant = ApiHistoryMode::Pruned { suffix_len: 1440 };
        let json = serde_json::to_value(&variant).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "kind": "pruned", "suffix_len": 1440 }),
        );
    }

    // ----- ApiHistoryMode: round-trips -----

    #[test]
    fn api_history_mode_roundtrips_all_variants() {
        let cases = [
            ApiHistoryMode::Archive,
            ApiHistoryMode::UtxoBootstrapped,
            ApiHistoryMode::HeadersOnly,
            ApiHistoryMode::Pruned { suffix_len: 1440 },
        ];
        for original in cases {
            let json = serde_json::to_string(&original).unwrap();
            let decoded: ApiHistoryMode = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, original, "roundtrip failed for {original:?}");
        }
    }

    // ----- ApiHistoryMode: Default -----

    /// `ApiIdentity::default()` calls `ApiHistoryMode::default()` via
    /// the derive. The default is `Archive` — the most common live
    /// runtime mode — so absent-config stubs render a plausible wire
    /// shape rather than panicking on an uninhabited variant.
    #[test]
    fn api_history_mode_default_is_archive() {
        assert_eq!(ApiHistoryMode::default(), ApiHistoryMode::Archive);
    }

    // ----- ApiHistoryMode: error paths -----

    /// Unknown `kind` rejects rather than silently coercing.
    #[test]
    fn api_history_mode_unknown_kind_rejects() {
        let bad = serde_json::json!({ "kind": "ephemeral" });
        let result: Result<ApiHistoryMode, _> = serde_json::from_value(bad);
        assert!(
            result.is_err(),
            "unknown kind must reject, got Ok({:?})",
            result.ok(),
        );
    }

    // ----- ApiHeaderRef: difficulty fields round-trip -----

    /// `n_bits` (u32) and `difficulty` (decimal String) survive
    /// serialize → deserialize on the tip ref.
    #[test]
    fn api_header_ref_difficulty_fields_roundtrip() {
        let h = ApiHeaderRef {
            height: 5,
            header_id: "ab".to_string(),
            parent_id: "cd".to_string(),
            timestamp_unix_ms: 1,
            n_bits: 117_501_863,
            difficulty: "263500538576896".to_string(),
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: ApiHeaderRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back.n_bits, 117_501_863);
        assert_eq!(back.difficulty, "263500538576896");
    }

    #[test]
    fn api_native_submit_error_omits_redundant_http_status_field() {
        // Rust-native clients have the HTTP status from the response line
        // already; duplicating it in the body is just bytes on the wire.
        // Pin the absence so a future refactor cannot accidentally
        // reintroduce the `error` field on the native shape.
        let e = ApiNativeSubmitError {
            reason: "non_canonical".to_string(),
            detail: Some("amount mismatch".to_string()),
        };
        let v = serde_json::to_value(&e).unwrap();
        let obj = v.as_object().expect("object");
        assert!(
            !obj.contains_key("error"),
            "native shape must not duplicate the HTTP status code as `error`"
        );
        assert_eq!(
            obj.get("reason").and_then(|x| x.as_str()),
            Some("non_canonical"),
        );
        assert_eq!(
            obj.get("detail").and_then(|x| x.as_str()),
            Some("amount mismatch"),
        );
    }

    #[test]
    fn api_native_submit_error_omits_detail_when_none() {
        let v = serde_json::to_value(ApiNativeSubmitError {
            reason: "pool_full".to_string(),
            detail: None,
        })
        .unwrap();
        let obj = v.as_object().expect("object");
        assert!(
            !obj.contains_key("detail"),
            "absent detail must omit the key, not serialize as null"
        );
    }

    #[test]
    fn api_node_events_reorg_serializes_depth_and_dropped_header_ids() {
        let event = ApiNodeEvent {
            seq: 1,
            unix_ms: 1_700_000_000_000,
            kind: "reorg".to_string(),
            height: Some(100),
            header_id: Some("new-tip".to_string()),
            depth: Some(2),
            dropped_header_ids: Some(vec!["old-100".to_string(), "old-99".to_string()]),
            txs: None,
            size_bytes: None,
            addr: None,
            detail: None,
        };

        let v = serde_json::to_value(event).unwrap();

        assert_eq!(
            v,
            serde_json::json!({
                "seq": 1,
                "unixMs": 1_700_000_000_000u64,
                "kind": "reorg",
                "height": 100,
                "headerId": "new-tip",
                "depth": 2,
                "droppedHeaderIds": ["old-100", "old-99"],
            })
        );
    }

    #[test]
    fn api_node_events_non_reorg_omits_reorg_fields() {
        let event = ApiNodeEvent {
            seq: 1,
            unix_ms: 1_700_000_000_000,
            kind: "peerConnected".to_string(),
            height: None,
            header_id: None,
            depth: None,
            dropped_header_ids: None,
            txs: None,
            size_bytes: None,
            addr: Some("127.0.0.1:9030".to_string()),
            detail: None,
        };

        let v = serde_json::to_value(event).unwrap();
        let obj = v.as_object().expect("object");

        assert!(!obj.contains_key("depth"));
        assert!(!obj.contains_key("droppedHeaderIds"));
    }

    #[test]
    fn api_native_submit_error_projects_from_scala_compat_shape() {
        // The `From<ApiSubmitError>` impl drops `.error` and keeps
        // `reason` / `detail`. Pin field-by-field so a future expansion
        // of either type can't silently lose data.
        let compat = ApiSubmitError {
            error: 503,
            reason: "overloaded".to_string(),
            detail: Some("retry".to_string()),
        };
        let native: ApiNativeSubmitError = compat.into();
        assert_eq!(native.reason, "overloaded");
        assert_eq!(native.detail.as_deref(), Some("retry"));
    }

    #[test]
    fn api_mempool_transactions_envelope_does_not_emit_redundant_size() {
        // The envelope's pre-rename `size` field duplicated `transactions.len()`
        // exactly (the producer wrote `transactions.len() as u32`); dropping
        // it means clients read the array length directly. Pin the absence
        // so a future refactor cannot accidentally reintroduce the field.
        let v = serde_json::to_value(ApiMempoolTransactions {
            transactions: Vec::new(),
            weight_function: ApiWeightFunction::Cost,
        })
        .unwrap();
        let obj = v.as_object().expect("object");
        assert!(
            !obj.contains_key("size"),
            "the redundant size field must not appear on the wire"
        );
        assert!(
            obj.contains_key("transactions"),
            "transactions array must remain on the wire"
        );
        assert!(
            obj.contains_key("weight_function"),
            "weight_function tag must remain on the wire"
        );
    }

    #[test]
    fn api_full_block_ref_uses_state_root_avl_not_state_digest() {
        // Pin the renamed wire key: the AVL+ UTXO-root field is named
        // state_root_avl on the wire, and the old state_digest name must
        // not appear (clients reading the old key get a missing field
        // and surface it instead of silently consuming wrong bytes).
        let f = ApiFullBlockRef {
            height: 1,
            header_id: String::new(),
            parent_id: String::new(),
            timestamp_unix_ms: 0,
            state_root_avl: "0123abcd".to_string(),
            n_bits: 0,
            difficulty: "0".to_string(),
        };
        let v = serde_json::to_value(&f).unwrap();
        let obj = v.as_object().expect("object");
        assert_eq!(
            obj.get("state_root_avl"),
            Some(&serde_json::Value::String("0123abcd".into())),
            "AVL root must wire under the new state_root_avl key"
        );
        assert!(
            !obj.contains_key("state_digest"),
            "old state_digest key must not appear on the wire"
        );
    }

    /// `ApiFullBlockRef` gained the same fields — round-trip them too.
    #[test]
    fn api_full_block_ref_difficulty_fields_roundtrip() {
        let f = ApiFullBlockRef {
            height: 5,
            header_id: "ab".to_string(),
            parent_id: "cd".to_string(),
            timestamp_unix_ms: 1,
            state_root_avl: "ef".to_string(),
            n_bits: 117_501_863,
            difficulty: "263500538576896".to_string(),
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: ApiFullBlockRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back.n_bits, 117_501_863);
        assert_eq!(back.difficulty, "263500538576896");
    }

    // ----- ApiStateType: wire shape -----

    #[test]
    fn api_state_type_serializes_to_canonical_lowercase() {
        for (variant, expected) in [
            (ApiStateType::Utxo, "utxo"),
            (ApiStateType::Digest, "digest"),
        ] {
            let got = serde_json::to_value(variant).unwrap();
            assert_eq!(got, serde_json::Value::String(expected.into()));
        }
    }

    #[test]
    fn api_state_type_default_is_utxo() {
        assert_eq!(ApiStateType::default(), ApiStateType::Utxo);
    }

    #[test]
    fn api_state_type_roundtrips_and_rejects_unknown() {
        for v in [ApiStateType::Utxo, ApiStateType::Digest] {
            let s = serde_json::to_string(&v).unwrap();
            let back: ApiStateType = serde_json::from_str(&s).unwrap();
            assert_eq!(back, v);
        }
        let err = serde_json::from_value::<ApiStateType>(serde_json::json!("ledger"));
        assert!(err.is_err(), "unknown state_type variant must reject");
    }

    // ----- ApiPeerDirection: wire shape -----

    #[test]
    fn api_peer_direction_serializes_to_canonical_lowercase() {
        for (variant, expected) in [
            (ApiPeerDirection::Inbound, "inbound"),
            (ApiPeerDirection::Outbound, "outbound"),
        ] {
            let got = serde_json::to_value(variant).unwrap();
            assert_eq!(got, serde_json::Value::String(expected.into()));
        }
    }

    #[test]
    fn api_peer_direction_roundtrips_and_rejects_unknown() {
        for v in [ApiPeerDirection::Inbound, ApiPeerDirection::Outbound] {
            let s = serde_json::to_string(&v).unwrap();
            let back: ApiPeerDirection = serde_json::from_str(&s).unwrap();
            assert_eq!(back, v);
        }
        let err = serde_json::from_value::<ApiPeerDirection>(serde_json::json!("lateral"));
        assert!(err.is_err(), "unknown direction variant must reject");
    }

    // ----- ApiPeerState: wire shape -----

    #[test]
    fn api_peer_state_serializes_to_canonical_lowercase() {
        for (variant, expected) in [
            (ApiPeerState::Connecting, "connecting"),
            (ApiPeerState::Handshaking, "handshaking"),
            (ApiPeerState::Active, "active"),
            (ApiPeerState::Degraded, "degraded"),
            (ApiPeerState::Disconnected, "disconnected"),
        ] {
            let got = serde_json::to_value(variant).unwrap();
            assert_eq!(got, serde_json::Value::String(expected.into()));
        }
    }

    #[test]
    fn api_peer_state_roundtrips_and_rejects_unknown() {
        for v in [
            ApiPeerState::Connecting,
            ApiPeerState::Handshaking,
            ApiPeerState::Active,
            ApiPeerState::Degraded,
            ApiPeerState::Disconnected,
        ] {
            let s = serde_json::to_string(&v).unwrap();
            let back: ApiPeerState = serde_json::from_str(&s).unwrap();
            assert_eq!(back, v);
        }
        let err = serde_json::from_value::<ApiPeerState>(serde_json::json!("dormant"));
        assert!(err.is_err(), "unknown peer state variant must reject");
    }

    // ----- ApiBootstrapPhase: wire shape -----

    #[test]
    fn api_bootstrap_phase_serializes_to_canonical_lowercase() {
        for (variant, expected) in [
            (ApiBootstrapPhase::Discovery, "discovery"),
            (ApiBootstrapPhase::ManifestRequested, "manifest_requested"),
            (ApiBootstrapPhase::ManifestVerified, "manifest_verified"),
            (ApiBootstrapPhase::DownloadingChunks, "downloading_chunks"),
            (ApiBootstrapPhase::Reconstructing, "reconstructing"),
            (ApiBootstrapPhase::Installing, "installing"),
            (
                ApiBootstrapPhase::PostInstallCatchup,
                "post_install_catchup",
            ),
        ] {
            let got = serde_json::to_value(variant).unwrap();
            assert_eq!(got, serde_json::Value::String(expected.into()));
        }
    }

    #[test]
    fn api_bootstrap_phase_roundtrips_and_rejects_unknown() {
        for v in [
            ApiBootstrapPhase::Discovery,
            ApiBootstrapPhase::ManifestRequested,
            ApiBootstrapPhase::ManifestVerified,
            ApiBootstrapPhase::DownloadingChunks,
            ApiBootstrapPhase::Reconstructing,
            ApiBootstrapPhase::Installing,
            ApiBootstrapPhase::PostInstallCatchup,
        ] {
            let s = serde_json::to_string(&v).unwrap();
            let back: ApiBootstrapPhase = serde_json::from_str(&s).unwrap();
            assert_eq!(back, v);
        }
        let err = serde_json::from_value::<ApiBootstrapPhase>(serde_json::json!("paused"));
        assert!(err.is_err(), "unknown bootstrap phase must reject");
    }

    // ----- ApiPopowPhase: wire shape -----

    #[test]
    fn api_popow_phase_serializes_to_canonical_lowercase() {
        for (variant, expected) in [
            (ApiPopowPhase::Requesting, "requesting"),
            (ApiPopowPhase::QuorumMet, "quorum_met"),
            (ApiPopowPhase::Applied, "applied"),
            (ApiPopowPhase::Catchup, "catchup"),
        ] {
            let got = serde_json::to_value(variant).unwrap();
            assert_eq!(got, serde_json::Value::String(expected.into()));
        }
    }

    #[test]
    fn api_popow_phase_roundtrips_and_rejects_unknown() {
        for v in [
            ApiPopowPhase::Requesting,
            ApiPopowPhase::QuorumMet,
            ApiPopowPhase::Applied,
            ApiPopowPhase::Catchup,
        ] {
            let s = serde_json::to_string(&v).unwrap();
            let back: ApiPopowPhase = serde_json::from_str(&s).unwrap();
            assert_eq!(back, v);
        }
        let err = serde_json::from_value::<ApiPopowPhase>(serde_json::json!("aborted"));
        assert!(err.is_err(), "unknown popow phase must reject");
    }

    // ----- ApiHeaderAvailability: wire shape -----

    #[test]
    fn api_header_availability_serializes_to_canonical_lowercase() {
        for (variant, expected) in [
            (ApiHeaderAvailability::Dense, "dense"),
            (ApiHeaderAvailability::Sparse, "sparse"),
        ] {
            let got = serde_json::to_value(variant).unwrap();
            assert_eq!(got, serde_json::Value::String(expected.into()));
        }
    }

    #[test]
    fn api_header_availability_roundtrips_and_rejects_unknown() {
        for v in [ApiHeaderAvailability::Dense, ApiHeaderAvailability::Sparse] {
            let s = serde_json::to_string(&v).unwrap();
            let back: ApiHeaderAvailability = serde_json::from_str(&s).unwrap();
            assert_eq!(back, v);
        }
        let err = serde_json::from_value::<ApiHeaderAvailability>(serde_json::json!("partial"));
        assert!(
            err.is_err(),
            "unknown header availability variant must reject"
        );
    }

    fn bootstrap_status_with(
        phase: ApiBootstrapPhase,
        popow_phase: Option<ApiPopowPhase>,
        header_availability: Option<ApiHeaderAvailability>,
    ) -> ApiBootstrapStatus {
        ApiBootstrapStatus {
            phase,
            snapshot_height: 0,
            manifest_id: None,
            voters: 0,
            chunks_received: 0,
            chunks_total: 0,
            trust_check_passed: false,
            started_unix_ms: 0,
            popow_phase,
            popow_providers: None,
            header_availability,
            popow_dense_from_height: None,
        }
    }

    #[test]
    fn api_bootstrap_status_phase_serializes_to_each_canonical_literal() {
        for (variant, expected) in [
            (ApiBootstrapPhase::Discovery, "discovery"),
            (ApiBootstrapPhase::ManifestRequested, "manifest_requested"),
            (ApiBootstrapPhase::ManifestVerified, "manifest_verified"),
            (ApiBootstrapPhase::DownloadingChunks, "downloading_chunks"),
            (ApiBootstrapPhase::Reconstructing, "reconstructing"),
            (ApiBootstrapPhase::Installing, "installing"),
            (
                ApiBootstrapPhase::PostInstallCatchup,
                "post_install_catchup",
            ),
        ] {
            let v = serde_json::to_value(bootstrap_status_with(variant, None, None)).unwrap();
            assert_eq!(
                v["phase"],
                serde_json::Value::String(expected.into()),
                "phase wire literal must remain {expected}"
            );
        }
    }

    #[test]
    fn api_bootstrap_status_renames_history_mode_to_header_availability() {
        let v = serde_json::to_value(bootstrap_status_with(
            ApiBootstrapPhase::Discovery,
            None,
            Some(ApiHeaderAvailability::Sparse),
        ))
        .unwrap();
        let obj = v.as_object().expect("object");
        assert!(
            !obj.contains_key("history_mode"),
            "old key must not appear on the wire"
        );
        assert_eq!(
            obj.get("header_availability"),
            Some(&serde_json::Value::String("sparse".into())),
            "new key carries the value"
        );
    }

    #[test]
    fn api_bootstrap_status_omits_optional_fields_when_none() {
        let v = serde_json::to_value(bootstrap_status_with(
            ApiBootstrapPhase::Discovery,
            None,
            None,
        ))
        .unwrap();
        let obj = v.as_object().expect("object");
        for key in [
            "popow_phase",
            "header_availability",
            "popow_providers",
            "popow_dense_from_height",
            "manifest_id",
        ] {
            assert!(
                !obj.contains_key(key),
                "{key} must be omitted (not serialized as null) when None"
            );
        }
    }
}
