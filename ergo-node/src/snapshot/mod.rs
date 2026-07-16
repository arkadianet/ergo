//! Operator-API snapshot: a bounded, all-DTOs projection of node state.
//!
//! The publisher ([`publisher::SnapshotPublisher`]) rebuilds a
//! [`NodeSnapshot`] once per `sync_tick` (~3s) on the main loop and stores
//! it in an `ArcSwap` shared with the API task. Construction stays bounded:
//! bounded peer iteration, a mempool walk capped by
//! `MempoolConfig::max_pool_size`, and the two `get_header_meta` lookups
//! for the `/tip` DTO. The one non-trivial DB walk is the recent-blocks
//! tail (up to 32 full-block header + section reads); it is cached by the
//! full-block tip id and recomputed only when the tip advances, so a
//! steady-state tick pays a single id comparison. See
//! `node::snapshot_emit::recent_blocks::recent_blocks_for_tip`. Everything
//! else reads cached in-memory state.
//!
//! This struct holds the DTOs ([`NodeSnapshot`], [`SnapshotParts`]) and
//! their small support types; [`build`] assembles a `NodeSnapshot` from a
//! `SnapshotParts`, and [`publisher`] owns the per-tick publish + stall-clock
//! bookkeeping.

mod build;
mod publisher;

pub use publisher::SnapshotPublisher;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransactions,
    ApiPeer, ApiRecentBlock, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction, HealthStatus,
    SyncStateLabel,
};
use ergo_p2p::peer::PeerInfo;
use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;

/// Owned, serializable snapshot of the node's operator-visible state.
///
/// Each field is the exact DTO the matching handler returns; the bridge
/// just clones from here onto the response. The struct is `Send + Sync`
/// so it can be parked in `ArcSwap` and read concurrently by axum
/// handlers running on the tokio runtime.
pub struct NodeSnapshot {
    pub info: ApiInfo,
    pub status: ApiStatus,
    pub tip: ApiTip,
    pub sync: ApiSyncStatus,
    pub peers: Vec<ApiPeer>,
    pub mempool: ApiMempoolSummary,
    pub mempool_transactions: ApiMempoolTransactions,
    pub health: ApiHealth,
    /// Wall-clock instant the snapshot was built. Bridge subtracts from
    /// `Instant::now()` to compute `snapshot_age_ms` on each read.
    pub produced_at: Instant,
    /// Cumulative score at `best_header_id`, big-endian bytes. Empty if
    /// the chain hasn't progressed past genesis.
    pub best_header_score: Vec<u8>,
    /// Cumulative score at `best_full_block_id`, big-endian bytes. Empty
    /// before genesis is committed or during early IBD.
    pub best_full_block_score: Vec<u8>,
    /// Header id at height 0. Zero-bytes hex until genesis is committed.
    pub genesis_block_id: [u8; 32],
    /// Most recent peer-message arrival, Unix-ms. 0 if no peer has sent
    /// anything since boot (e.g., still handshaking).
    pub last_seen_message_unix_ms: u64,
    /// Most recent mempool change, Unix-ms. Approximated as the max
    /// `first_seen` across pool entries — close to Scala's value when the
    /// pool is fed by gossip, off by a tick when entries are demoted.
    pub last_mempool_update_unix_ms: u64,
    /// Active protocol parameters for the current full-block tip:
    /// the highest `voted_params` row with `key <= best_full_block.height`.
    /// Always populated post-`StateStore::open` (genesis row guarantees
    /// at least key 0 exists). Used by `/info.parameters`.
    pub active_params: ergo_validation::ActiveProtocolParameters,
    /// Pool-created output boxes indexed by `box_id`, supplying the
    /// overlay for `/utxo/withPool/*`. Cloned from `Mempool::pool_output_overlay`
    /// once per `sync_tick`. `Arc`-shared so concurrent reads on the
    /// API task pay no copy. Scala's `withMempool.boxById` is purely
    /// additive — pool outputs supplement committed UTXOs, never subtract,
    /// so callers consult the chain store first and fall back here.
    pub pool_outputs: Arc<HashMap<Digest32, ErgoBox>>,
    /// Spent committed-box id → pool tx that spends it. Cloned from
    /// `Mempool::pool_input_overlay` once per `sync_tick`. Drives the
    /// extra-index mempool overlay for `excludeMempoolSpent` (filter
    /// the box out) and surfaces a tentative `spending_tx_id` on
    /// byErgoTree / byErgoTreeHash routes when a confirmed UTXO has a
    /// pending pool spend.
    pub pool_inputs: Arc<HashMap<Digest32, Digest32>>,
    /// Pool full-transaction bytes, in `Mempool::iter_transactions`
    /// priority order (matches Scala's `MempoolReader.getAll`).
    /// Each entry is `(tx_id, serialized_tx_bytes)` — bytes are
    /// the canonical wire form preserved by mempool admission.
    /// `Arc`-shared so paged + by-id + batch handlers pay no copy
    /// per request. Drives the three mempool read endpoints
    /// (`/transactions/unconfirmed?offset=&limit=`,
    /// `/transactions/unconfirmed/byTransactionId/{id}`, and
    /// `POST /transactions/unconfirmed/byTransactionIds`).
    pub pool_full_txs: Arc<Vec<(Digest32, Arc<[u8]>)>>,
    /// Per-peer last-observed sync-info classification — Scala's
    /// `syncTracker.fullInfo` analogue. Snapshotted from
    /// `SyncCoordinator::peer_sync_snapshots()`. Drives
    /// `/peers/syncInfo`. `Arc`-shared so per-request reads pay no
    /// copy; map size is bounded by connected-peer count.
    pub peer_sync: Arc<std::collections::HashMap<std::net::SocketAddr, PeerSyncProjection>>,
    /// Delivery-tracker counters — Scala's `deliveryTracker.fullInfo`
    /// triple. Source: `DeliveryTracker::total_inflight()` /
    /// `received_count()` / `failed_count()`. Drives
    /// `/peers/trackInfo`.
    pub delivery_counts: DeliveryCounters,
    /// IPs currently in the peer manager's ban list whose ban
    /// hasn't expired yet. Source:
    /// `PeerManager::currently_banned_ips`. Drives
    /// `/peers/blacklisted` — the bridge formats each entry as
    /// `InetAddress.toString()`-shape (`/literal-ip`) so the wire
    /// output matches Scala's `ErgoPeersApiRoute.scala:98-102`.
    /// `Arc`-shared so per-request reads pay no copy.
    pub banned_ips: Arc<Vec<std::net::IpAddr>>,
    /// Bounded tail of the most-recent full blocks (newest-first),
    /// precomputed each tick. Serves `GET /api/v1/blocks/recent` as a pure
    /// snapshot clone — no live store read on the request path.
    pub recent_blocks: Arc<Vec<ApiRecentBlock>>,
    /// Operator event feed tail (bounded ring projection) + newest seq.
    pub events: Arc<ergo_api::types::ApiNodeEvents>,
    /// Postmortem reorg ring (64 / 7d) for diagnostics + metrics.
    pub reorgs: Arc<ergo_api::types::ApiReorgHistory>,
    /// Best network-known header height — `SyncState::best_known_header_height()`
    /// (our validated-header latch, initialized to the full-block tip and
    /// advanced by peer sync info). Matches Scala's `maxPeerHeight` notion
    /// (network best height), NOT a literal max over per-peer heights — the
    /// literal max is derivable from `peer_sync` if ever needed.
    pub max_peer_height: u32,
    /// Whether mining is configured on (the candidate engine + wiring exist).
    /// Feeds `/info.isMining` — Scala parity: Scala reports its configured
    /// mining flag here, not liveness of candidate generation.
    pub mining_enabled: bool,
    /// `(height, hex manifest id)` of the Mode-2 serve-side snapshot
    /// cache (at most one entry — the latest 52,224-boundary build).
    /// Mirrored from the action loop's `SnapshotState` each publish so
    /// REST `/utxo/getSnapshotsInfo` always agrees with the P2P
    /// `SnapshotsInfo` reply. Empty at boot (cache is in-memory only)
    /// and on digest backends.
    pub snapshot_manifests: Vec<(i32, String)>,
}

/// Public-facing projection of a per-peer SyncInfo observation.
/// Carried on `NodeSnapshot.peer_sync` so the API bridge produces
/// `/peers/syncInfo` entries without re-deriving anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSyncProjection {
    /// Stringified chain status: `"Equal"` / `"Younger"` / `"Older"`
    /// / `"Fork"` / `"Unknown"`. String form so the bridge passes it
    /// through without depending on `ergo-p2p::sync::PeerChainStatus`.
    pub status: &'static str,
    /// Peer's reported (V1) or inferred-from-overlap (V2) best
    /// height, or `None` when we have no overlap with our chain.
    pub peer_height: Option<u32>,
}

/// Aggregated delivery-tracker counters at snapshot time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeliveryCounters {
    pub requested: u32,
    pub received: u32,
    pub failed: u32,
}

/// Tip-keyed cache for the dashboard recent-blocks tail. The publisher
/// recomputes the tail only when the full-block tip id changes; on every
/// other `sync_tick` it hands back this cached `Arc` unchanged. See
/// `node::snapshot_emit::recent_blocks::recent_blocks_for_tip`.
pub(crate) struct RecentBlocksCache {
    /// Full-block tip id the cached tail was built from.
    pub(crate) tip_id: [u8; 32],
    /// Newest-first recent-blocks tail, shared with each snapshot built
    /// while the tip is unchanged.
    pub(crate) blocks: Arc<Vec<ApiRecentBlock>>,
}

impl NodeSnapshot {
    /// Initial empty snapshot for use before the first publish. Returns
    /// zero-valued DTOs that handlers can serve while the main loop has
    /// not produced its first real snapshot yet. `weight_function` is
    /// the configured mempool priority-weight policy — passing it here
    /// avoids defaulting to a value that misrepresents the node config.
    pub fn empty(info: ApiInfo, weight_function: ApiWeightFunction) -> Self {
        let header_ref = ApiHeaderRef {
            height: 0,
            header_id: String::new(),
            parent_id: String::new(),
            timestamp_unix_ms: 0,
            // Pre-sync "no tip" — deliberately zero (see build_snapshot for
            // the live value). decode_compact_bits(0) is "0".
            n_bits: 0,
            difficulty: "0".to_string(),
        };
        let full_ref = ApiFullBlockRef {
            height: 0,
            header_id: String::new(),
            parent_id: String::new(),
            timestamp_unix_ms: 0,
            state_root_avl: String::new(),
            n_bits: 0,
            difficulty: "0".to_string(),
        };
        Self {
            status: ApiStatus {
                bootstrap: None,
                sync_state: SyncStateLabel::Disconnected,
                peer_count: 0,
                best_header_height: 0,
                best_full_block_height: 0,
                headers_ahead_of_full_blocks: 0,
                mempool_size: 0,
                snapshot_age_ms: 0,
                last_block_apply_error: None,
                block_apply_errors_total: 0,
                sync_wedged: None,
                shadow: None,
                mempool_tx_requested_total: 0,
                mempool_peer_tx_admitted_total: 0,
                mempool_peer_tx_rejected_total: 0,
                reorgs_total: 0,
                last_reorg_depth: None,
                last_reorg_unix_ms: None,
                apply_in_progress: false,
                last_apply_duration_ms: 0,
                last_applied_height: 0,
                last_apply_age_ms: None,
            },
            tip: ApiTip {
                best_header: header_ref,
                best_full_block: full_ref,
                headers_ahead_of_full_blocks: 0,
            },
            sync: ApiSyncStatus {
                headers_chain_synced: false,
                best_header_height: 0,
                best_full_block_height: 0,
                gap: 0,
                download_window: 0,
                pending_blocks: 0,
                recovery_done: false,
            },
            peers: Vec::new(),
            mempool: ApiMempoolSummary {
                size: 0,
                total_bytes: 0,
                capacity_count: 0,
                capacity_bytes: 0,
                revalidation_pending: 0,
            },
            mempool_transactions: ApiMempoolTransactions {
                transactions: Vec::new(),
                weight_function,
            },
            health: ApiHealth {
                status: HealthStatus::Disconnected,
                behind: 0,
                last_progress_age_ms: 0,
                peer_count: 0,
            },
            info,
            produced_at: Instant::now(),
            best_header_score: Vec::new(),
            best_full_block_score: Vec::new(),
            genesis_block_id: [0u8; 32],
            last_seen_message_unix_ms: 0,
            last_mempool_update_unix_ms: 0,
            active_params: ergo_validation::scala_launch(),
            pool_outputs: Arc::new(HashMap::new()),
            pool_inputs: Arc::new(HashMap::new()),
            pool_full_txs: Arc::new(Vec::new()),
            peer_sync: Arc::new(HashMap::new()),
            delivery_counts: DeliveryCounters::default(),
            banned_ips: Arc::new(Vec::new()),
            recent_blocks: Arc::new(Vec::new()),
            events: Arc::new(ergo_api::types::ApiNodeEvents::default()),
            reorgs: Arc::new(ergo_api::types::ApiReorgHistory::default()),
            max_peer_height: 0,
            mining_enabled: false,
            snapshot_manifests: Vec::new(),
        }
    }
}

/// Shared snapshot handle. The publisher writes; the API bridge reads.
pub type SnapshotHandle = std::sync::Arc<ArcSwap<NodeSnapshot>>;

/// Inputs the publisher consumes to assemble a snapshot. Cheap to
/// construct on the main loop: every field is a copy of in-memory state,
/// a single DB-key lookup, or — for `recent_blocks` — an `Arc` clone of
/// the tip-cached recent-blocks tail (rebuilt only when the full-block
/// tip changes; see `node::snapshot_emit`).
pub struct SnapshotParts<'a> {
    pub now_unix_ms: u64,
    pub snapshot_built_at: Instant,
    pub best_header_height: u32,
    pub best_header_id: [u8; 32],
    pub best_header_parent_id: [u8; 32],
    pub best_header_timestamp_ms: u64,
    pub best_full_block_height: u32,
    pub best_full_block_id: [u8; 32],
    pub best_full_block_parent_id: [u8; 32],
    pub best_full_block_timestamp_ms: u64,
    /// Compact difficulty (`nBits`) of the best-header / best-full-block
    /// tips. `None` ⇒ the header read failed and the publisher carries the
    /// last-known value forward (never a synthetic 0). Set by
    /// `publish_snapshot`.
    pub best_header_n_bits: Option<u32>,
    pub best_full_block_n_bits: Option<u32>,
    pub state_digest: [u8; 33],
    pub headers_chain_synced: bool,
    pub download_window: u32,
    pub pending_blocks: u32,
    pub recovery_done: bool,
    pub peer_count: u32,
    pub mempool_size: u32,
    pub mempool_total_bytes: u64,
    pub mempool_capacity_count: u32,
    pub mempool_capacity_bytes: u64,
    pub mempool_revalidation_pending: u32,
    pub mempool_transactions: ApiMempoolTransactions,
    pub peers: &'a [&'a PeerInfo],
    /// Cumulative score at the best-header tip (BE bytes from `HeaderMeta`).
    pub best_header_score: Vec<u8>,
    /// Cumulative score at the best-full-block tip (BE bytes).
    pub best_full_block_score: Vec<u8>,
    /// Header id at height 0. Zeroed if not yet committed.
    pub genesis_block_id: [u8; 32],
    /// Most recent peer-message arrival, Unix-ms.
    pub last_seen_message_unix_ms: u64,
    /// Most recent mempool change, Unix-ms.
    pub last_mempool_update_unix_ms: u64,
    /// Active protocol parameters at `best_full_block_height`. Builder
    /// reads this once per `sync_tick` from the store.
    pub active_params: ergo_validation::ActiveProtocolParameters,
    /// Pool-created outputs (`box_id → ErgoBox`) snapshot from
    /// `Mempool::pool_output_overlay`. Wraps in `Arc` so the publisher
    /// can hand the same allocation to every snapshot read without
    /// per-call cloning.
    pub pool_outputs: Arc<HashMap<Digest32, ErgoBox>>,
    /// Spent committed-box id → pool tx that spends it, snapshot from
    /// `Mempool::pool_input_overlay`. `Arc`-shared like `pool_outputs`.
    /// Empty when the pool has no entries.
    pub pool_inputs: Arc<HashMap<Digest32, Digest32>>,
    /// Full pool-transaction bytes in priority order. Drives the
    /// unconfirmed full-tx endpoints.
    pub pool_full_txs: Arc<Vec<(Digest32, Arc<[u8]>)>>,
    /// Per-peer chain-state projection from
    /// `SyncCoordinator::peer_sync_snapshots()`. Drives
    /// `/peers/syncInfo`.
    pub peer_sync: Arc<std::collections::HashMap<std::net::SocketAddr, PeerSyncProjection>>,
    /// Delivery-tracker counters at snapshot time. Drives
    /// `/peers/trackInfo`.
    pub delivery_counts: DeliveryCounters,
    /// Currently-banned IPs at snapshot time, from
    /// `PeerManager::currently_banned_ips`. Drives
    /// `/peers/blacklisted`.
    pub banned_ips: Arc<Vec<std::net::IpAddr>>,
    /// Mode 2 bootstrap progress, `Some` only while the dashboard
    /// should show a bootstrap panel (utxo_bootstrap configured AND
    /// either pre-install or in the post-install catch-up window).
    /// Built in `node::snapshot_emit::bootstrap_panel::build_bootstrap_status`
    /// from the bootstrap reducer + chunk assembly. Cleared once the node
    /// is at tip so the panel auto-hides.
    pub bootstrap: Option<ergo_api::types::ApiBootstrapStatus>,
    /// Bounded tail of recent full blocks (newest-first), from the
    /// canonical full-block chain. `Arc`-shared with the publisher's
    /// per-tip cache so an unchanged full-block tip re-publishes the same
    /// allocation. Drives `GET /api/v1/blocks/recent`.
    pub recent_blocks: Arc<Vec<ApiRecentBlock>>,
    /// Operator event feed tail (bounded ring projection) + newest seq.
    pub events: Arc<ergo_api::types::ApiNodeEvents>,
    /// Postmortem reorg ring (64 / 7d).
    pub reorgs: Arc<ergo_api::types::ApiReorgHistory>,
    /// `SyncState::best_known_header_height()` — the network-best-height
    /// latch advanced by peer sync info. Feeds `/info.maxPeerHeight`.
    pub max_peer_height: u32,
    /// Whether the mining engine + wiring are configured on this node.
    /// Feeds `/info.isMining`.
    pub mining_enabled: bool,
    /// Mode-2 serve-cache manifests `(height, hex id)`; see
    /// `NodeSnapshot::snapshot_manifests`.
    pub snapshot_manifests: Vec<(i32, String)>,
    /// The most recent block-apply REJECTION projected to the API DTO
    /// (age computed at publish time from the executor's `Instant`), or `None`.
    /// Drives `ApiStatus.last_block_apply_error` and the
    /// `HealthStatus::Rejecting` overlay in `build_snapshot`.
    pub last_block_apply_error: Option<ergo_api::types::ApiBlockApplyError>,
    /// Monotonic block-apply rejection count, for the
    /// `ergo_node_block_apply_errors_total` Prometheus counter.
    pub block_apply_errors_total: u64,
    /// Terminal deep-fork wedge projected to the API DTO (age computed at
    /// publish time from the executor's `Instant`), or `None`. Drives
    /// `ApiStatus.sync_wedged` and the `HealthStatus::Wedged` overlay in
    /// `build_snapshot`.
    pub sync_wedged: Option<ergo_api::types::ApiSyncWedged>,
    /// Shadow-validation outcome (`[shadow]`), projected at publish.
    /// `None` when the mode is off. Drives `ApiStatus.shadow` and the
    /// `ergo_node_shadow_*` metrics.
    pub shadow: Option<ergo_api::types::ApiShadowStatus>,
    /// Monotonic count of unconfirmed-tx ids requested from peers, for
    /// the `ergo_node_mempool_tx_requested_total` Prometheus counter.
    pub mempool_tx_requested_total: u64,
    /// Monotonic count of peer-sourced txs admitted to the mempool, for
    /// the `ergo_node_mempool_peer_tx_admitted_total` Prometheus counter.
    pub mempool_peer_tx_admitted_total: u64,
    /// Monotonic count of peer-sourced txs rejected by admission, for
    /// the `ergo_node_mempool_peer_tx_rejected_total` Prometheus counter.
    pub mempool_peer_tx_rejected_total: u64,
}

/// Compute the canonical `now_unix_ms` for snapshot timestamps.
pub fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}
