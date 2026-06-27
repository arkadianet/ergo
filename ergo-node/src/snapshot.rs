//! Operator-API snapshot: a bounded, all-DTOs projection of node state.
//!
//! The publisher rebuilds a `NodeSnapshot` once per `sync_tick` (~3s) on
//! the main loop and stores it in an `ArcSwap` shared with the API task.
//! Construction stays bounded: bounded peer iteration, a mempool walk
//! capped by `MempoolConfig::max_pool_size`, and the two `get_header_meta`
//! lookups for the `/tip` DTO. The one non-trivial DB walk is the
//! recent-blocks tail (up to 32 full-block header + section reads); it is
//! cached by the full-block tip id and recomputed only when the tip
//! advances, so a steady-state tick pays a single id comparison. See
//! `node::snapshot_emit::recent_blocks_for_tip`. Everything else reads
//! cached in-memory state.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use ergo_api::types::{
    hex32, ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary,
    ApiMempoolTransactions, ApiPeer, ApiRecentBlock, ApiStatus, ApiSyncStatus, ApiTip,
    ApiWeightFunction, HealthStatus, SyncStateLabel,
};
use ergo_p2p::peer::{ConnectionState, Direction, PeerInfo};
use ergo_primitives::digest::Digest32;
use ergo_ser::difficulty::decode_compact_bits;
use ergo_ser::ergo_box::ErgoBox;

/// Time threshold for `/health`'s stall detection. If the best full
/// block height has not advanced within this window AND we are not at
/// tip, `/health` returns 503.
const STALL_THRESHOLD_SECS: u64 = 120;

/// Tolerance for declaring "at tip": full-block tip within this many
/// blocks of the best known header tip.
const AT_TIP_GAP: u32 = 2;

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
/// `node::snapshot_emit::recent_blocks_for_tip`.
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
                mempool_tx_requested_total: 0,
                mempool_peer_tx_admitted_total: 0,
                mempool_peer_tx_rejected_total: 0,
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
            max_peer_height: 0,
            mining_enabled: false,
            snapshot_manifests: Vec::new(),
        }
    }
}

/// Shared snapshot handle. The publisher writes; the API bridge reads.
pub type SnapshotHandle = std::sync::Arc<ArcSwap<NodeSnapshot>>;

/// Per-tick state the publisher keeps to derive deltas (stall detection)
/// across snapshots. Owned by the main loop alongside `NodeState`.
pub struct SnapshotPublisher {
    handle: SnapshotHandle,
    info: ApiInfo,
    started_at: Instant,
    /// Last time *either* the best-header height or the best-full-block
    /// height strictly advanced. Used as the stall clock during initial
    /// header-only sync (no full block has applied yet) — header advance
    /// must count as progress there, otherwise the node would flag
    /// itself stalled before block sync has even started.
    last_progress_at: Instant,
    /// Last time the best-full-block height strictly advanced. Once any
    /// block has applied (`last_full_block_height > 0`) this becomes the
    /// authoritative stall clock: header advances cannot mask a node
    /// that has stopped applying blocks while peers keep streaming
    /// fresh headers (the original `last_progress_at`-only behaviour
    /// failed to detect this).
    last_block_progress_at: Instant,
    last_header_height: u32,
    last_full_block_height: u32,
}

impl SnapshotPublisher {
    pub fn new(info: ApiInfo, started_at: Instant, weight_function: ApiWeightFunction) -> Self {
        let handle = std::sync::Arc::new(ArcSwap::from_pointee(NodeSnapshot::empty(
            info.clone(),
            weight_function,
        )));
        Self {
            handle,
            info,
            started_at,
            last_progress_at: started_at,
            last_block_progress_at: started_at,
            last_header_height: 0,
            last_full_block_height: 0,
        }
    }

    pub fn handle(&self) -> SnapshotHandle {
        self.handle.clone()
    }

    /// Refresh `info.uptime_seconds` and write a fresh snapshot built
    /// from the supplied projections.
    pub fn publish(&mut self, mut parts: SnapshotParts<'_>) {
        // Resolve n_bits on read failure (`*_n_bits == None`): carry the
        // last-known value forward, never a synthetic 0. If the tip is live
        // (height > 0) but there is no real prior to carry — the very first
        // publish on a non-empty chain hit a header-read fault — retain the
        // previous snapshot rather than publish a live tip with 0
        // difficulty (the fault was already logged in `read_tip_n_bits`).
        let (prior_header_n_bits, prior_full_n_bits) = {
            let prior = self.handle.load();
            (
                prior.tip.best_header.n_bits,
                prior.tip.best_full_block.n_bits,
            )
        };
        if parts.best_header_n_bits.is_none() {
            if parts.best_header_height > 0 && prior_header_n_bits == 0 {
                return;
            }
            parts.best_header_n_bits = Some(prior_header_n_bits);
        }
        if parts.best_full_block_n_bits.is_none() {
            if parts.best_full_block_height > 0 && prior_full_n_bits == 0 {
                return;
            }
            parts.best_full_block_n_bits = Some(prior_full_n_bits);
        }
        let now = Instant::now();
        let header_advanced = parts.best_header_height > self.last_header_height;
        let block_advanced = parts.best_full_block_height > self.last_full_block_height;
        if header_advanced || block_advanced {
            self.last_progress_at = now;
        }
        if block_advanced {
            self.last_block_progress_at = now;
        }
        if header_advanced {
            self.last_header_height = parts.best_header_height;
        }
        if block_advanced {
            self.last_full_block_height = parts.best_full_block_height;
        }
        // Once a block has applied, the authoritative stall signal is
        // block progress; header advances cannot reset it (the
        // header-only-resets-stall bug). Before the first block applies
        // the combined clock still wins so the initial header sync
        // doesn't flag itself stalled.
        let effective_progress_age_ms = if self.last_full_block_height > 0 {
            now.duration_since(self.last_block_progress_at).as_millis() as u64
        } else {
            now.duration_since(self.last_progress_at).as_millis() as u64
        };

        let mut info = self.info.clone();
        info.uptime_seconds = now.duration_since(self.started_at).as_secs();

        let snap = build_snapshot(parts, info, effective_progress_age_ms);
        self.handle.store(std::sync::Arc::new(snap));
    }
}

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
    /// Full pool-transaction bytes in priority order. Drives §10.4
    /// unconfirmed full-tx endpoints.
    pub pool_full_txs: Arc<Vec<(Digest32, Arc<[u8]>)>>,
    /// Per-peer chain-state projection from
    /// `SyncCoordinator::peer_sync_snapshots()`. Drives §10.6
    /// `/peers/syncInfo`.
    pub peer_sync: Arc<std::collections::HashMap<std::net::SocketAddr, PeerSyncProjection>>,
    /// Delivery-tracker counters at snapshot time. Drives §10.6
    /// `/peers/trackInfo`.
    pub delivery_counts: DeliveryCounters,
    /// Currently-banned IPs at snapshot time, from
    /// `PeerManager::currently_banned_ips`. Drives §10.6
    /// `/peers/blacklisted`.
    pub banned_ips: Arc<Vec<std::net::IpAddr>>,
    /// Mode 2 bootstrap progress, `Some` only while the dashboard
    /// should show a bootstrap panel (utxo_bootstrap configured AND
    /// either pre-install or in the post-install catch-up window).
    /// Built in `snapshot_emit.rs::publish_snapshot` from the
    /// bootstrap reducer + chunk assembly. Cleared once the node is
    /// at tip so the panel auto-hides.
    pub bootstrap: Option<ergo_api::types::ApiBootstrapStatus>,
    /// Bounded tail of recent full blocks (newest-first), from the
    /// canonical full-block chain. `Arc`-shared with the publisher's
    /// per-tip cache so an unchanged full-block tip re-publishes the same
    /// allocation. Drives `GET /api/v1/blocks/recent`.
    pub recent_blocks: Arc<Vec<ApiRecentBlock>>,
    /// `SyncState::best_known_header_height()` — the network-best-height
    /// latch advanced by peer sync info. Feeds `/info.maxPeerHeight`.
    pub max_peer_height: u32,
    /// Whether the mining engine + wiring are configured on this node.
    /// Feeds `/info.isMining`.
    pub mining_enabled: bool,
    /// Mode-2 serve-cache manifests `(height, hex id)`; see
    /// `NodeSnapshot::snapshot_manifests`.
    pub snapshot_manifests: Vec<(i32, String)>,
    /// OBS-1: the most recent block-apply REJECTION projected to the API DTO
    /// (age computed at publish time from the executor's `Instant`), or `None`.
    /// Drives `ApiStatus.last_block_apply_error` and the
    /// `HealthStatus::Rejecting` overlay in `build_snapshot`.
    pub last_block_apply_error: Option<ergo_api::types::ApiBlockApplyError>,
    /// OBS-1: monotonic block-apply rejection count, for the
    /// `ergo_node_block_apply_errors_total` Prometheus counter.
    pub block_apply_errors_total: u64,
    /// P2: monotonic count of unconfirmed-tx ids requested from peers, for
    /// the `ergo_node_mempool_tx_requested_total` Prometheus counter.
    pub mempool_tx_requested_total: u64,
    /// P2: monotonic count of peer-sourced txs admitted to the mempool, for
    /// the `ergo_node_mempool_peer_tx_admitted_total` Prometheus counter.
    pub mempool_peer_tx_admitted_total: u64,
    /// P2: monotonic count of peer-sourced txs rejected by admission, for
    /// the `ergo_node_mempool_peer_tx_rejected_total` Prometheus counter.
    pub mempool_peer_tx_rejected_total: u64,
}

fn build_snapshot(p: SnapshotParts<'_>, info: ApiInfo, last_progress_age_ms: u64) -> NodeSnapshot {
    let gap = p
        .best_header_height
        .saturating_sub(p.best_full_block_height);
    let sync_state = classify(
        p.peer_count,
        p.headers_chain_synced,
        gap,
        last_progress_age_ms,
    );

    // n_bits is resolved by the publisher (carry-forward on read failure),
    // so `unwrap_or(0)` here only hits the pre-first-publish path.
    let best_header_n_bits = p.best_header_n_bits.unwrap_or(0);
    let best_full_block_n_bits = p.best_full_block_n_bits.unwrap_or(0);
    let best_header = ApiHeaderRef {
        height: p.best_header_height,
        header_id: hex32(&p.best_header_id),
        parent_id: hex32(&p.best_header_parent_id),
        timestamp_unix_ms: p.best_header_timestamp_ms,
        n_bits: best_header_n_bits,
        difficulty: decode_compact_bits(best_header_n_bits).to_string(),
    };
    let best_full_block = ApiFullBlockRef {
        height: p.best_full_block_height,
        header_id: hex32(&p.best_full_block_id),
        parent_id: hex32(&p.best_full_block_parent_id),
        timestamp_unix_ms: p.best_full_block_timestamp_ms,
        state_root_avl: hex::encode(p.state_digest),
        n_bits: best_full_block_n_bits,
        difficulty: decode_compact_bits(best_full_block_n_bits).to_string(),
    };

    // OBS-1: an outstanding block-apply rejection overrides the sync-derived
    // health below (a node refusing blocks its peers accept is not healthy,
    // however it looks on the sync axis).
    let rejecting = p.last_block_apply_error.is_some();
    let status = ApiStatus {
        sync_state,
        peer_count: p.peer_count,
        best_header_height: p.best_header_height,
        best_full_block_height: p.best_full_block_height,
        headers_ahead_of_full_blocks: gap,
        mempool_size: p.mempool_size,
        snapshot_age_ms: 0,
        bootstrap: p.bootstrap.clone(),
        last_block_apply_error: p.last_block_apply_error.clone(),
        block_apply_errors_total: p.block_apply_errors_total,
        mempool_tx_requested_total: p.mempool_tx_requested_total,
        mempool_peer_tx_admitted_total: p.mempool_peer_tx_admitted_total,
        mempool_peer_tx_rejected_total: p.mempool_peer_tx_rejected_total,
    };

    let tip = ApiTip {
        best_header: best_header.clone(),
        best_full_block: best_full_block.clone(),
        headers_ahead_of_full_blocks: gap,
    };

    let sync = ApiSyncStatus {
        headers_chain_synced: p.headers_chain_synced,
        best_header_height: p.best_header_height,
        best_full_block_height: p.best_full_block_height,
        gap,
        download_window: p.download_window,
        pending_blocks: p.pending_blocks,
        recovery_done: p.recovery_done,
    };

    let peers = p
        .peers
        .iter()
        .map(|pi| project_peer(pi, p.snapshot_built_at, &p.peer_sync))
        .collect();

    let mempool = ApiMempoolSummary {
        size: p.mempool_size,
        total_bytes: p.mempool_total_bytes,
        capacity_count: p.mempool_capacity_count,
        capacity_bytes: p.mempool_capacity_bytes,
        revalidation_pending: p.mempool_revalidation_pending,
    };

    let health_status = if rejecting {
        HealthStatus::Rejecting
    } else {
        match sync_state {
            SyncStateLabel::Disconnected => HealthStatus::Disconnected,
            SyncStateLabel::Stalled => HealthStatus::Stalled,
            SyncStateLabel::Syncing | SyncStateLabel::AtTip => HealthStatus::Ok,
        }
    };
    let health = ApiHealth {
        status: health_status,
        behind: gap,
        last_progress_age_ms,
        peer_count: p.peer_count,
    };

    let _ = p.now_unix_ms;
    NodeSnapshot {
        info,
        status,
        tip,
        sync,
        peers,
        mempool,
        mempool_transactions: p.mempool_transactions,
        health,
        produced_at: p.snapshot_built_at,
        best_header_score: p.best_header_score,
        best_full_block_score: p.best_full_block_score,
        genesis_block_id: p.genesis_block_id,
        last_seen_message_unix_ms: p.last_seen_message_unix_ms,
        last_mempool_update_unix_ms: p.last_mempool_update_unix_ms,
        active_params: p.active_params,
        pool_outputs: p.pool_outputs,
        pool_inputs: p.pool_inputs,
        pool_full_txs: p.pool_full_txs,
        peer_sync: p.peer_sync,
        delivery_counts: p.delivery_counts,
        banned_ips: p.banned_ips,
        recent_blocks: p.recent_blocks,
        max_peer_height: p.max_peer_height,
        mining_enabled: p.mining_enabled,
        snapshot_manifests: p.snapshot_manifests,
    }
}

fn classify(
    peer_count: u32,
    headers_synced: bool,
    gap: u32,
    last_progress_age_ms: u64,
) -> SyncStateLabel {
    if peer_count == 0 {
        return SyncStateLabel::Disconnected;
    }
    let stalled = last_progress_age_ms / 1000 >= STALL_THRESHOLD_SECS && gap > AT_TIP_GAP;
    if stalled {
        return SyncStateLabel::Stalled;
    }
    if headers_synced && gap <= AT_TIP_GAP {
        SyncStateLabel::AtTip
    } else {
        SyncStateLabel::Syncing
    }
}

fn project_peer(
    pi: &PeerInfo,
    now: Instant,
    peer_sync: &std::collections::HashMap<std::net::SocketAddr, PeerSyncProjection>,
) -> ApiPeer {
    let addr = pi.addr.to_string();
    let direction = match pi.direction {
        Direction::Inbound => ergo_api::types::ApiPeerDirection::Inbound,
        Direction::Outbound => ergo_api::types::ApiPeerDirection::Outbound,
    };
    let state = match pi.state {
        ConnectionState::Connecting => ergo_api::types::ApiPeerState::Connecting,
        ConnectionState::Handshaking => ergo_api::types::ApiPeerState::Handshaking,
        ConnectionState::Active => ergo_api::types::ApiPeerState::Active,
        ConnectionState::Degraded => ergo_api::types::ApiPeerState::Degraded,
        ConnectionState::Disconnected => ergo_api::types::ApiPeerState::Disconnected,
    };
    let (agent, node_name, version) = match &pi.peer_spec {
        Some(spec) => (
            Some(spec.agent_name.clone()),
            Some(spec.node_name.clone()),
            Some(spec.version.to_string()),
        ),
        None => (None, None, None),
    };
    // Parsed-but-previously-dropped peer identity from the handshake
    // PeerSpec: the advertised REST URL feature and the declared public
    // address. Both are observability/identity only — never fed into sync
    // or scoring. Surfaced on the native peer DTO; the legacy
    // `/peers/connected` Scala-compat surface is intentionally left as-is.
    let (rest_api_url, declared_address) = match &pi.peer_spec {
        Some(spec) => (
            spec.features.iter().find_map(|f| match f {
                ergo_p2p::handshake::PeerFeature::RestApiUrl { url } => Some(url.clone()),
                _ => None,
            }),
            spec.declared_address.as_ref().map(format_declared_address),
        ),
        None => (None, None),
    };
    let connected_seconds = now.saturating_duration_since(pi.connected_at).as_secs();
    let last_seen_seconds = now.saturating_duration_since(pi.last_seen).as_secs();
    // peer_height comes from the per-peer sync-info projection
    // populated by SyncCoordinator::on_sync_info. V1 SyncInfo
    // carries the height directly; V2 SyncInfo infers it from the
    // newest peer-header that overlaps our best chain. `None` until
    // we've processed a SyncInfo from this peer.
    let peer_height = peer_sync.get(&pi.addr).and_then(|s| s.peer_height);
    ApiPeer {
        addr,
        direction,
        state,
        score: pi.score.raw_score(),
        agent,
        node_name,
        version,
        sync_version: format!("{:?}", pi.sync_version),
        connected_seconds,
        last_seen_seconds,
        // Cumulative post-handshake framed bytes, counted at the per-peer
        // I/O task's transport boundary (ergo-p2p PeerInfo shared counters).
        bytes_in: Some(pi.bytes_in()),
        bytes_out: Some(pi.bytes_out()),
        peer_height,
        rest_api_url,
        declared_address,
    }
}

/// Format a handshake-declared address (`addr` bytes + `port`) as an
/// `ip:port` string. Handles the two valid Ergo declared-address byte
/// widths — 4 (IPv4) and 16 (IPv6); any other width yields `None` rather
/// than a misparsed address. `Scala`'s declared address is an
/// `InetSocketAddress`; this renders the same `host:port` shape.
fn format_declared_address(d: &ergo_p2p::handshake::DeclaredAddress) -> String {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let ip: Option<std::net::IpAddr> = match d.addr.len() {
        4 => {
            let b: [u8; 4] = d.addr[..4].try_into().expect("len checked == 4");
            Some(std::net::IpAddr::V4(Ipv4Addr::from(b)))
        }
        16 => {
            let b: [u8; 16] = d.addr[..16].try_into().expect("len checked == 16");
            Some(std::net::IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    };
    match ip {
        Some(ip) => std::net::SocketAddr::new(ip, d.port as u16).to_string(),
        // Non-standard width: surface the raw shape rather than fabricate
        // an address, so an operator sees something is off.
        None => format!(
            "<malformed declared addr: {} bytes>:{}",
            d.addr.len(),
            d.port
        ),
    }
}

/// Compute the canonical `now_unix_ms` for snapshot timestamps.
pub fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    fn fake_info() -> ApiInfo {
        ApiInfo {
            agent_name: "test".into(),
            node_name: "test".into(),
            network: "mainnet".into(),
            version: "0.0.0".into(),
            started_at_unix_ms: 0,
            uptime_seconds: 0,
            target_block_interval_ms: 120_000,
        }
    }

    #[test]
    fn project_peer_surfaces_byte_counters() {
        use std::collections::HashMap;
        // The snapshot must surface exactly the counters the per-peer I/O
        // task increments: project_peer reads the same Arc-backed PeerInfo
        // whose byte_counters() handle we bump here.
        let pi = ergo_p2p::peer::PeerInfo::new_outbound(
            "127.0.0.1:9030".parse().unwrap(),
            std::time::Instant::now(),
        );
        let (cin, cout) = pi.byte_counters();
        cin.fetch_add(42, std::sync::atomic::Ordering::Relaxed);
        cout.fetch_add(7, std::sync::atomic::Ordering::Relaxed);

        let api = project_peer(&pi, std::time::Instant::now(), &HashMap::new());
        assert_eq!(api.bytes_in, Some(42));
        assert_eq!(api.bytes_out, Some(7));
    }

    /// `ApiPeer` surfaces the parsed-but-previously-dropped peer identity:
    /// the `RestApiUrl` handshake feature → `rest_api_url`, and the
    /// `PeerSpec.declared_address` → `declared_address` (`ip:port`). Both
    /// are `None` when the spec carries neither.
    #[test]
    fn project_peer_surfaces_rest_url_and_declared_address() {
        use ergo_p2p::handshake::{DeclaredAddress, PeerFeature, PeerSpec, Version};
        use std::collections::HashMap;

        let mut pi = ergo_p2p::peer::PeerInfo::new_outbound(
            "127.0.0.1:9030".parse().unwrap(),
            std::time::Instant::now(),
        );
        pi.peer_spec = Some(PeerSpec {
            agent_name: "ergoref".into(),
            version: Version {
                major: 5,
                minor: 0,
                patch: 0,
            },
            node_name: "node".into(),
            declared_address: Some(DeclaredAddress {
                addr: vec![203, 0, 113, 9],
                port: 9030,
            }),
            features: vec![PeerFeature::RestApiUrl {
                url: "http://203.0.113.9:9053".into(),
            }],
        });

        let api = project_peer(&pi, std::time::Instant::now(), &HashMap::new());
        assert_eq!(
            api.rest_api_url.as_deref(),
            Some("http://203.0.113.9:9053"),
            "RestApiUrl feature must surface on rest_api_url",
        );
        assert_eq!(
            api.declared_address.as_deref(),
            Some("203.0.113.9:9030"),
            "declared address must surface as ip:port",
        );
    }

    /// With no peer_spec (pre-handshake) both new identity fields are
    /// `None` — the absent case the additive serde-skip relies on.
    #[test]
    fn project_peer_identity_fields_none_without_spec() {
        use std::collections::HashMap;
        let pi = ergo_p2p::peer::PeerInfo::new_outbound(
            "127.0.0.1:9030".parse().unwrap(),
            std::time::Instant::now(),
        );
        let api = project_peer(&pi, std::time::Instant::now(), &HashMap::new());
        assert_eq!(api.rest_api_url, None);
        assert_eq!(api.declared_address, None);
    }

    fn make_parts<'a>(
        header_h: u32,
        full_h: u32,
        peers: &'a [&'a ergo_p2p::peer::PeerInfo],
    ) -> SnapshotParts<'a> {
        SnapshotParts {
            now_unix_ms: 0,
            snapshot_built_at: Instant::now(),
            best_header_height: header_h,
            best_header_id: [1u8; 32],
            best_header_parent_id: [2u8; 32],
            best_header_timestamp_ms: 1_700_000_000_000,
            best_full_block_height: full_h,
            best_full_block_id: [3u8; 32],
            best_full_block_parent_id: [4u8; 32],
            best_full_block_timestamp_ms: 1_700_000_000_000,
            // Captured Scala mainnet nBits (test-vectors scala_chainslice);
            // decodes to difficulty "263500538576896" — an external oracle.
            best_header_n_bits: Some(117_501_863),
            best_full_block_n_bits: Some(117_501_863),
            state_digest: [5u8; 33],
            headers_chain_synced: false,
            download_window: 384,
            pending_blocks: 0,
            recovery_done: false,
            peer_count: 1,
            mempool_size: 0,
            mempool_total_bytes: 0,
            mempool_capacity_count: 1000,
            mempool_capacity_bytes: 1024,
            mempool_revalidation_pending: 0,
            mempool_transactions: ApiMempoolTransactions {
                transactions: Vec::new(),
                weight_function: ApiWeightFunction::Cost,
            },
            peers,
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
            bootstrap: None,
            recent_blocks: Arc::new(Vec::new()),
            max_peer_height: 0,
            mining_enabled: false,
            snapshot_manifests: Vec::new(),
            last_block_apply_error: None,
            block_apply_errors_total: 0,
            mempool_tx_requested_total: 0,
            mempool_peer_tx_admitted_total: 0,
            mempool_peer_tx_rejected_total: 0,
        }
    }

    /// Wiring + oracle-parity: the tip surfaces the header's `n_bits` and
    /// the difficulty decoded from it. The `(n_bits, difficulty)` pair is
    /// captured from a Scala mainnet header (not self-derived), so this
    /// also pins `decode_compact_bits` against the reference value.
    #[test]
    fn tip_surfaces_n_bits_and_scala_difficulty() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        publisher.publish(make_parts(100, 100, &[]));
        let snap = publisher.handle().load_full();
        assert_eq!(snap.tip.best_header.n_bits, 117_501_863);
        assert_eq!(snap.tip.best_header.difficulty, "263500538576896");
        assert_eq!(snap.tip.best_full_block.n_bits, 117_501_863);
        assert_eq!(snap.tip.best_full_block.difficulty, "263500538576896");
    }

    /// A header-read failure (`n_bits == None`) carries the prior
    /// snapshot's difficulty forward — never a false-zero (a 0 fallback
    /// would flicker `/info difficulty` to 0 on a transient read fault).
    #[test]
    fn snapshot_carries_n_bits_forward_on_read_failure() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        publisher.publish(make_parts(100, 100, &[]));
        let mut parts = make_parts(101, 101, &[]);
        parts.best_header_n_bits = None;
        parts.best_full_block_n_bits = None;
        publisher.publish(parts);
        let snap = publisher.handle().load_full();
        assert_eq!(snap.tip.best_header.n_bits, 117_501_863);
        assert_eq!(snap.tip.best_header.difficulty, "263500538576896");
        assert_ne!(snap.tip.best_header.difficulty, "0");
    }

    /// First publish on a non-empty chain whose tip header is unreadable
    /// (`n_bits == None`, no real prior to carry): the publisher retains
    /// the empty pre-publish snapshot rather than emit a live tip with 0
    /// difficulty.
    #[test]
    fn first_publish_with_unreadable_n_bits_retains_empty_not_live_zero() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        let mut parts = make_parts(100, 100, &[]);
        parts.best_header_n_bits = None;
        parts.best_full_block_n_bits = None;
        publisher.publish(parts);
        let snap = publisher.handle().load_full();
        // Retained the empty snapshot — no live tip with a synthetic 0.
        assert_eq!(snap.tip.best_header.height, 0);
        assert_eq!(snap.tip.best_header.difficulty, "0");
    }

    /// The `/info` u64 difficulty narrowing: the captured Scala mainnet
    /// nBits decodes and fits u64 (oracle value, not self-derived).
    #[test]
    fn difficulty_u64_narrowing_for_scala_mainnet_n_bits() {
        assert_eq!(
            u64::try_from(decode_compact_bits(117_501_863)).unwrap_or(u64::MAX),
            263_500_538_576_896
        );
    }

    /// Difficulty above `u64::MAX` saturates rather than wrapping — the
    /// `/info` u64 is a Scala-surface cap; native `ApiTip` carries the
    /// full-precision String.
    #[test]
    fn difficulty_u64_narrowing_saturates_above_u64() {
        assert_eq!(
            u64::try_from(decode_compact_bits(0x20_ff_ff_ff)).unwrap_or(u64::MAX),
            u64::MAX
        );
    }

    /// During IBD, `best_header` runs far ahead of `best_full_block`.
    /// The DTO must surface both — collapsing them would lose the
    /// information operators rely on to see header-sync progress while
    /// blocks are still at genesis. Regresses the splitting that was
    /// the motivating reason for the `ApiTip` schema.
    #[test]
    fn tip_dto_splits_header_and_full_block_during_ibd() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        publisher.publish(make_parts(31_881, 0, &[]));
        let snap = publisher.handle().load_full();

        assert_eq!(snap.tip.best_header.height, 31_881);
        assert_eq!(snap.tip.best_full_block.height, 0);
        assert_eq!(snap.tip.headers_ahead_of_full_blocks, 31_881);
        assert_eq!(snap.status.headers_ahead_of_full_blocks, 31_881);
        assert_eq!(snap.sync.gap, 31_881);
        assert_eq!(snap.sync.best_header_height, 31_881);
        assert_eq!(snap.sync.best_full_block_height, 0);
    }

    /// Header-only progress must reset the stall clock *during initial
    /// header sync* (no full block has applied yet). Before the first
    /// block applies, headers running ahead is the only progress signal
    /// available, so flipping the node to `Stalled` would be wrong.
    #[test]
    fn header_only_progress_resets_stall_clock_pre_first_block() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);

        publisher.publish(make_parts(100, 0, &[]));
        let age0 = publisher.handle().load_full().health.last_progress_age_ms;
        assert!(age0 < 100, "first publish should be fresh, got {age0}ms");

        sleep(Duration::from_millis(80));
        publisher.publish(make_parts(200, 0, &[]));
        let age_after_header = publisher.handle().load_full().health.last_progress_age_ms;
        assert!(
            age_after_header < 50,
            "header-only advance must reset stall clock pre-first-block, got {age_after_header}ms",
        );

        sleep(Duration::from_millis(120));
        publisher.publish(make_parts(200, 0, &[]));
        let age_after_idle = publisher.handle().load_full().health.last_progress_age_ms;
        assert!(
            age_after_idle >= 100,
            "no advance must let stall clock grow, got {age_after_idle}ms",
        );
    }

    /// Once at least one block has applied, the stall clock tracks
    /// **block** progress only — header-only advance must NOT reset it.
    /// This was the silent-stall bug: a node stuck applying block N+1
    /// while peers kept streaming headers showed `sync_state=syncing`
    /// indefinitely, because every header tick reset the combined
    /// clock. Now the publisher uses `last_block_progress_at` as the
    /// authoritative clock once `last_full_block_height > 0`.
    #[test]
    fn header_only_progress_does_not_mask_block_stall_post_first_block() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);

        // First block applies — switches publisher to block-progress mode.
        publisher.publish(make_parts(100, 50, &[]));
        let age0 = publisher.handle().load_full().health.last_progress_age_ms;
        assert!(age0 < 100, "first publish should be fresh, got {age0}ms");

        // Headers advance, blocks stuck. The block clock must keep
        // running; header advance must NOT mask the stall.
        sleep(Duration::from_millis(80));
        publisher.publish(make_parts(200, 50, &[]));
        let age_after_header = publisher.handle().load_full().health.last_progress_age_ms;
        assert!(
            age_after_header >= 80,
            "header-only advance must not reset the block-stall clock, got {age_after_header}ms",
        );

        // Block finally advances — clock resets.
        publisher.publish(make_parts(200, 51, &[]));
        let age_after_block = publisher.handle().load_full().health.last_progress_age_ms;
        assert!(
            age_after_block < 50,
            "block advance must reset stall clock, got {age_after_block}ms",
        );
    }

    /// `active_params` must travel through `SnapshotParts → build_snapshot
    /// → NodeSnapshot` so the API bridge sees exactly what the publisher
    /// read from `voted_params`. A field added to one struct but not
    /// threaded would silently fall back to the test-default `scala_launch`
    /// here — this guard catches that.
    #[test]
    fn active_params_round_trips_through_snapshot() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        let mut parts = make_parts(1_024, 1_024, &[]);
        let mut p = ergo_validation::scala_launch();
        p.epoch_start_height = 1024;
        p.input_cost = 7777;
        p.subblocks_per_block = Some(30);
        parts.active_params = p.clone();

        publisher.publish(parts);
        let snap = publisher.handle().load_full();

        assert_eq!(snap.active_params, p);
    }

    /// `pool_inputs` must travel through `SnapshotParts → build_snapshot
    /// → NodeSnapshot` alongside `pool_outputs`. Same threading guard as
    /// `active_params_round_trips_through_snapshot`: if a P5 reader can't
    /// see a value the publisher set, the overlay would silently behave
    /// like `NoopMempoolView` even when the pool has entries.
    #[test]
    fn pool_inputs_round_trip_through_snapshot() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        let mut parts = make_parts(1, 1, &[]);

        let spent_box = Digest32::from_bytes([0xAA; 32]);
        let spending_tx = Digest32::from_bytes([0xBB; 32]);
        let mut inputs = HashMap::new();
        inputs.insert(spent_box, spending_tx);
        parts.pool_inputs = Arc::new(inputs);

        publisher.publish(parts);
        let snap = publisher.handle().load_full();

        assert_eq!(snap.pool_inputs.len(), 1);
        assert_eq!(snap.pool_inputs.get(&spent_box), Some(&spending_tx));
    }

    /// OBS-1: a block-apply rejection threads from `SnapshotParts` through
    /// `build_snapshot` onto `status.last_block_apply_error` + the counter, AND
    /// overrides health to `Rejecting` (a node refusing blocks is unhealthy
    /// however the sync axis looks). Absent ⇒ `None` and the normal
    /// sync-derived health, never `Rejecting`.
    #[test]
    fn build_snapshot_surfaces_block_apply_rejection_and_health() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        let mut parts = make_parts(500, 500, &[]);
        parts.last_block_apply_error = Some(ergo_api::types::ApiBlockApplyError {
            block_id: "ab".repeat(32),
            height: 1234,
            reason: "tx invalid".to_string(),
            age_ms: 42,
        });
        parts.block_apply_errors_total = 3;
        publisher.publish(parts);
        let snap = publisher.handle().load_full();
        let e = snap
            .status
            .last_block_apply_error
            .as_ref()
            .expect("rejection surfaced on status");
        assert_eq!(e.height, 1234);
        assert_eq!(e.reason, "tx invalid");
        assert_eq!(snap.status.block_apply_errors_total, 3);
        assert_eq!(snap.health.status, HealthStatus::Rejecting);

        // No rejection set above ⇒ the three new mempool-gossip counters
        // default to 0 on this publish path.
        assert_eq!(snap.status.mempool_tx_requested_total, 0);
        assert_eq!(snap.status.mempool_peer_tx_admitted_total, 0);
        assert_eq!(snap.status.mempool_peer_tx_rejected_total, 0);

        // No rejection: None on status, and health is NOT Rejecting.
        let mut publisher2 =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        publisher2.publish(make_parts(500, 500, &[]));
        let snap2 = publisher2.handle().load_full();
        assert!(snap2.status.last_block_apply_error.is_none());
        assert_ne!(snap2.health.status, HealthStatus::Rejecting);
    }

    /// P2: the three mempool-tx-gossip observability counters travel from
    /// `SnapshotParts` through `build_snapshot` onto `ApiStatus` (the
    /// `/metrics` source). Same threading guard as
    /// `build_snapshot_surfaces_block_apply_rejection_and_health`: a field
    /// added to one struct but not threaded would silently fall back to 0
    /// here, leaving the Prometheus counter stuck at zero.
    #[test]
    fn build_snapshot_carries_mempool_tx_gossip_counters() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        let mut parts = make_parts(500, 500, &[]);
        parts.mempool_tx_requested_total = 11;
        parts.mempool_peer_tx_admitted_total = 7;
        parts.mempool_peer_tx_rejected_total = 4;

        publisher.publish(parts);
        let snap = publisher.handle().load_full();

        assert_eq!(snap.status.mempool_tx_requested_total, 11);
        assert_eq!(snap.status.mempool_peer_tx_admitted_total, 7);
        assert_eq!(snap.status.mempool_peer_tx_rejected_total, 4);
    }

    /// `max_peer_height` and `mining_enabled` travel from `SnapshotParts`
    /// through `build_snapshot` to `NodeSnapshot`. A field added to one struct
    /// but not threaded would silently fall back to 0/false here.
    #[test]
    fn build_snapshot_carries_mining_enabled_and_max_peer_height() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        let mut parts = make_parts(500, 500, &[]);
        parts.max_peer_height = 1_000;
        parts.mining_enabled = true;

        publisher.publish(parts);
        let snap = publisher.handle().load_full();

        assert_eq!(snap.max_peer_height, 1_000);
        assert!(snap.mining_enabled);
    }

    /// Threading the configured weight function through `SnapshotPublisher::new`
    /// preserves it on the boot-empty snapshot — i.e. the constructor isn't
    /// hardcoded to `Cost`. A node booted with the `"size"` policy must emit
    /// `"size"` on the boot snapshot, not the default. Pins against accidental
    /// regression to a `Default::default()` shortcut on the publisher init
    /// path. (Post-publish snapshots carry whatever `SnapshotParts.mempool_transactions`
    /// the projection built — exercised indirectly via the `project_mempool_transactions`
    /// path in production, not here.)
    #[test]
    fn empty_snapshot_preserves_non_default_weight_function() {
        let publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Size);
        let snap = publisher.handle().load_full();
        assert_eq!(
            snap.mempool_transactions.weight_function,
            ApiWeightFunction::Size,
            "boot-empty snapshot must carry the threaded weight function",
        );
    }
}
