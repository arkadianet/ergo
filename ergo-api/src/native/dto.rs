use ergo_api_core::capability::{CapabilityDescriptor, CapabilityReason};
use ergo_api_core::chain::{ProtocolHistory, Stored};
use ergo_api_core::indexer::{IndexerStatus, IndexerStatusSnapshot};
use ergo_api_core::node::{
    ChainTip, Health, HealthStatus, NodeIdentity, NodeInfo, NodeSnapshot, NodeStatus, SyncState,
    SyncStatus,
};
use ergo_api_core::observability::{EventFeed, EventRecord, HostStatus, RecentBlockRecord};
use ergo_api_core::page::Page;
use ergo_api_core::transaction::{TransactionRecord, TransactionState};
use ergo_ser::address::NetworkPrefix;
use ergo_ser::header::Header;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NodeView {
    pub info: NodeInfoView,
    pub identity: NodeIdentityView,
    pub status: NodeStatusView,
    pub tip: ChainTipView,
    pub sync: SyncStatusView,
    pub health: HealthView,
    pub capabilities: Vec<CapabilityView>,
    pub revision: u64,
    pub produced_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NodeInfoView {
    pub agent_name: String,
    pub node_name: String,
    pub network: String,
    pub version: String,
    pub started_at_unix_ms: u64,
    pub uptime_seconds: u64,
    pub target_block_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NodeIdentityView {
    pub state_backend: String,
    pub verify_transactions: bool,
    pub history_mode: String,
    pub utxo_bootstrap: bool,
    pub nipopow_bootstrap: bool,
    pub mining_enabled: bool,
    pub indexer_enabled: bool,
    pub declared_address: Option<String>,
    pub bind_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NodeStatusView {
    pub sync_state: String,
    pub peer_count: u32,
    pub mempool_size: u32,
    pub headers_ahead_of_full_blocks: u32,
    pub snapshot_age_ms: u64,
    pub block_apply_errors_total: u64,
    pub storage_errors_total: u64,
    pub reorgs_total: u64,
    pub sync_wedged: bool,
    pub apply_wedged: bool,
    pub apply_in_progress: bool,
    pub shadow_diverged: bool,
    pub bootstrap_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HostStatusView {
    pub rss_bytes: Option<u64>,
    pub state_db_bytes: Option<u64>,
    pub index_db_bytes: Option<u64>,
    pub disk_free_bytes: Option<u64>,
    pub disk_total_bytes: Option<u64>,
    pub cpu_pct: Option<f32>,
    pub net_in_bps: Option<u64>,
    pub net_out_bps: Option<u64>,
    pub load_1m: Option<f32>,
}

pub type HostView = HostStatusView;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChainTipView {
    pub best_header: HeaderTipView,
    pub best_block: BlockTipView,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HeaderTipView {
    pub height: u32,
    pub id: Option<String>,
    pub parent_id: Option<String>,
    pub timestamp_unix_ms: u64,
    pub compact_bits: u32,
    pub difficulty: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockTipView {
    pub height: u32,
    pub id: Option<String>,
    pub parent_id: Option<String>,
    pub timestamp_unix_ms: u64,
    pub compact_bits: u32,
    pub difficulty: String,
    pub state_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HeaderView {
    pub id: String,
    pub parent_id: String,
    pub height: u32,
    pub timestamp_unix_ms: u64,
    pub state_root: String,
    pub transactions_root: String,
    pub extension_root: String,
    pub ad_proofs_root: String,
    pub compact_bits: u32,
    pub difficulty: String,
    pub version: u8,
    pub size_bytes: u64,
    pub canonical_bytes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PageView {
    pub next_cursor: Option<String>,
    pub has_more: bool,
    pub total: Option<u64>,
    pub as_of: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HeaderPage {
    pub items: Vec<HeaderView>,
    pub page: PageView,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NetworkPage {
    pub limit: u32,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NetworkPeerView {
    pub addr: String,
    pub direction: String,
    pub state: String,
    pub score: i32,
    pub agent: Option<String>,
    pub node_name: Option<String>,
    pub version: Option<String>,
    pub sync_version: String,
    pub connected_seconds: u64,
    pub last_seen_seconds: u64,
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
    pub peer_height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rest_api_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NetworkBlacklistedView {
    pub addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NetworkSyncInfoView {
    pub addr: String,
    pub peer_height: u32,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NetworkTrackInfoView {
    pub num_requested: u32,
    pub num_received: u32,
    pub num_failed: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NetworkPeerPage {
    pub items: Vec<NetworkPeerView>,
    pub page: NetworkPage,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NetworkBlacklistedPage {
    pub items: Vec<NetworkBlacklistedView>,
    pub page: NetworkPage,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NetworkSyncInfoPage {
    pub items: Vec<NetworkSyncInfoView>,
    pub page: NetworkPage,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DifficultyPointView {
    pub height: u32,
    pub timestamp_unix_ms: u64,
    pub difficulty: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DifficultySeriesView {
    pub points: Vec<DifficultyPointView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MinerStatView {
    pub pk: String,
    pub address: Option<String>,
    pub count: u32,
    pub last_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MinerStatsView {
    pub tip_height: u32,
    pub window: u32,
    pub blocks: u32,
    pub miners: Vec<MinerStatView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProtocolHistoryView {
    pub epoch_length: u32,
    pub current_height: u32,
    pub changes: Vec<ProtocolChangeView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProtocolChangeView {
    pub height: u32,
    pub params: Vec<ProtocolParamView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProtocolParamView {
    pub id: u8,
    pub name: String,
    pub description: String,
    pub from: Option<i64>,
    pub to: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IndexerRepairView {
    pub pending: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_gi: Option<u64>,
    pub skipped: u64,
    pub drift_skips: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IndexerTotalsView {
    pub boxes: u64,
    pub txs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IndexerStatusView {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub halt_reason: Option<String>,
    pub indexed_height: u64,
    pub full_height: u32,
    pub repair: IndexerRepairView,
    pub totals: IndexerTotalsView,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransactionView {
    pub tx_id: String,
    pub state: String,
    pub inclusion_height: Option<u32>,
    pub index_in_block: Option<u32>,
    pub size_bytes: u32,
    pub confirmations: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransactionStatusView {
    pub tx_id: String,
    pub state: String,
    pub inclusion_height: Option<u32>,
    pub index_in_block: Option<u32>,
    pub size_bytes: Option<u32>,
    pub confirmations: Option<u32>,
}

pub fn transaction_view(value: &TransactionRecord) -> TransactionView {
    TransactionView {
        tx_id: value.id.to_string(),
        state: match value.state {
            TransactionState::Confirmed => "confirmed",
            TransactionState::Pending => "pending",
        }
        .to_string(),
        inclusion_height: value.inclusion_height,
        index_in_block: value.index_in_block,
        size_bytes: value.size_bytes,
        confirmations: value.confirmations,
    }
}

pub fn transaction_status_view(
    tx_id: String,
    value: Option<&TransactionRecord>,
) -> TransactionStatusView {
    let Some(value) = value else {
        return TransactionStatusView {
            tx_id,
            state: "unknown".to_string(),
            inclusion_height: None,
            index_in_block: None,
            size_bytes: None,
            confirmations: None,
        };
    };
    TransactionStatusView {
        tx_id: value.id.to_string(),
        state: match value.state {
            TransactionState::Confirmed => "confirmed",
            TransactionState::Pending => "pending",
        }
        .to_string(),
        inclusion_height: value.inclusion_height,
        index_in_block: value.index_in_block,
        size_bytes: Some(value.size_bytes),
        confirmations: value.confirmations,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransactionAdmissionView {
    pub tx_id: String,
    pub disposition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransactionBody {
    pub bytes: String,
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EventView {
    pub seq: u64,
    pub unix_ms: u64,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped_header_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returned_tx_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returned_txs_total: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txs: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EventFeedView {
    pub latest_seq: u64,
    pub events: Vec<EventView>,
}

pub fn event_view(value: &EventRecord) -> EventView {
    EventView {
        seq: value.seq,
        unix_ms: value.unix_ms,
        kind: value.kind.clone(),
        height: value.height,
        header_id: value.header_id.clone(),
        depth: value.depth,
        dropped_header_ids: value.dropped_header_ids.clone(),
        returned_tx_ids: value.returned_tx_ids.clone(),
        returned_txs_total: value.returned_txs_total,
        delivered_by: value.delivered_by.clone(),
        txs: value.txs,
        size_bytes: value.size_bytes,
        addr: value.addr.clone(),
        detail: value.detail.clone(),
    }
}

pub fn event_feed_view(value: &EventFeed) -> EventFeedView {
    EventFeedView {
        latest_seq: value.latest_seq,
        events: value.events.iter().map(event_view).collect(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RecentBlockView {
    pub height: u32,
    pub header_id: String,
    pub ts_unix_ms: u64,
    pub txs: u32,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub miner_pk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub miner_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockSummaryView {
    pub id: String,
    pub parent_id: String,
    pub height: u32,
    pub timestamp_unix_ms: u64,
    pub state_root: String,
    pub transaction_count: u32,
    pub size_bytes: u64,
}

pub type BlockView = BlockSummaryView;

pub fn recent_block_view(value: &RecentBlockRecord) -> RecentBlockView {
    RecentBlockView {
        height: value.height,
        header_id: value.header_id.to_string(),
        ts_unix_ms: value.timestamp_unix_ms,
        txs: value.transaction_count,
        size_bytes: value.size_bytes,
        delivered_by: value.delivered_by.map(|value| value.to_string()),
        miner_pk: value.miner_public_key.map(hex::encode),
        miner_address: value.miner_address.clone(),
    }
}

pub fn block_summary_view(value: &ergo_api_core::chain::BlockSummary) -> BlockSummaryView {
    BlockSummaryView {
        id: value.id.to_string(),
        parent_id: value.parent_id.to_string(),
        height: value.height,
        timestamp_unix_ms: value.timestamp_unix_ms,
        state_root: value
            .state_root
            .map(|root| hex::encode(root.as_bytes()))
            .unwrap_or_default(),
        transaction_count: value.transaction_count,
        size_bytes: value.size_bytes,
    }
}

pub fn header_page(page: Page<Stored<Header>>) -> HeaderPage {
    let has_more = page.next_cursor.is_some();
    HeaderPage {
        items: page.items.iter().map(header_view).collect(),
        page: PageView {
            next_cursor: page.next_cursor.map(|cursor| cursor.as_str().to_string()),
            has_more,
            total: page.total,
            as_of: page.as_of.map(|revision| revision.0),
        },
    }
}

pub fn difficulty_series(mut headers: Vec<Stored<Header>>) -> DifficultySeriesView {
    headers.retain(|header| header.value.height > 0);
    headers.reverse();
    DifficultySeriesView {
        points: headers
            .into_iter()
            .map(|header| DifficultyPointView {
                height: header.value.height,
                timestamp_unix_ms: header.value.timestamp,
                difficulty: ergo_ser::difficulty::decode_compact_bits(header.value.n_bits)
                    .to_string(),
            })
            .collect(),
    }
}

pub fn miner_stats(
    mut headers: Vec<Stored<Header>>,
    window: u32,
    network: NetworkPrefix,
) -> MinerStatsView {
    headers.retain(|header| header.value.height > 0);
    headers.reverse();
    let blocks = headers.len() as u32;
    let tip_height = headers
        .last()
        .map(|header| header.value.height)
        .unwrap_or(0);
    let mut aggregates: std::collections::HashMap<String, (u32, u32)> =
        std::collections::HashMap::new();
    for header in &headers {
        let pk_bytes = header.value.solution.pk().as_bytes();
        let entry = aggregates.entry(hex::encode(pk_bytes)).or_insert((0, 0));
        entry.0 += 1;
        entry.1 = entry.1.max(header.value.height);
    }
    let mut miners = aggregates
        .into_iter()
        .map(|(pk, (count, last_height))| {
            let address = hex::decode(&pk)
                .ok()
                .and_then(|bytes| ergo_ser::address::encode_p2pk_from_pubkey(network, &bytes).ok());
            MinerStatView {
                pk,
                address,
                count,
                last_height,
            }
        })
        .collect::<Vec<_>>();
    miners.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| right.last_height.cmp(&left.last_height))
            .then_with(|| left.pk.cmp(&right.pk))
    });
    MinerStatsView {
        tip_height,
        window,
        blocks,
        miners,
    }
}

pub fn protocol_history_view(value: &ProtocolHistory) -> ProtocolHistoryView {
    ProtocolHistoryView {
        epoch_length: value.epoch_length,
        current_height: value.current_height,
        changes: value
            .changes
            .iter()
            .map(|change| ProtocolChangeView {
                height: change.height,
                params: change
                    .params
                    .iter()
                    .map(|param| ProtocolParamView {
                        id: param.id,
                        name: param.name.clone(),
                        description: param.description.clone(),
                        from: param.from,
                        to: param.to,
                    })
                    .collect(),
            })
            .collect(),
    }
}

pub fn header_view(value: &Stored<Header>) -> HeaderView {
    let header = &value.value;
    HeaderView {
        id: hex::encode(value.id.as_bytes()),
        parent_id: hex::encode(header.parent_id.as_bytes()),
        height: header.height,
        timestamp_unix_ms: header.timestamp,
        state_root: hex::encode(header.state_root.as_bytes()),
        transactions_root: hex::encode(header.transactions_root.as_bytes()),
        extension_root: hex::encode(header.extension_root.as_bytes()),
        ad_proofs_root: hex::encode(header.ad_proofs_root.as_bytes()),
        compact_bits: header.n_bits,
        difficulty: ergo_ser::difficulty::decode_compact_bits(header.n_bits).to_string(),
        version: header.version,
        size_bytes: value.bytes.len() as u64,
        canonical_bytes: hex::encode(&value.bytes),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SyncStatusView {
    pub state: String,
    pub headers_chain_synced: bool,
    pub header_height: u32,
    pub full_block_height: u32,
    pub gap: u32,
    pub download_window: u32,
    pub pending_blocks: u32,
    pub recovery_complete: bool,
    pub best_known_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HealthView {
    pub status: String,
    pub behind: u32,
    pub last_progress_age_ms: u64,
    pub peer_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CapabilityView {
    pub id: String,
    pub state: String,
    pub reason: Option<String>,
}

pub fn indexer_status_view(value: &IndexerStatusSnapshot, full_height: u32) -> IndexerStatusView {
    IndexerStatusView {
        status: match value.status {
            IndexerStatus::Syncing => "syncing",
            IndexerStatus::CaughtUp => "caughtUp",
            IndexerStatus::Halted => "halted",
        }
        .to_string(),
        halt_reason: value.halt_reason.clone(),
        indexed_height: value.indexed_height,
        full_height,
        repair: IndexerRepairView {
            pending: value.repair.pending,
            next_gi: value.repair.next_gi,
            skipped: value.repair.skipped,
            drift_skips: value.repair.drift_skips,
        },
        totals: IndexerTotalsView {
            boxes: value.totals.boxes,
            txs: value.totals.txs,
        },
    }
}

pub fn host_status_view(value: &HostStatus) -> HostStatusView {
    HostStatusView {
        rss_bytes: value.rss_bytes,
        state_db_bytes: value.state_db_bytes,
        index_db_bytes: value.index_db_bytes,
        disk_free_bytes: value.disk_free_bytes,
        disk_total_bytes: value.disk_total_bytes,
        cpu_pct: value.cpu_pct,
        net_in_bps: value.net_in_bps,
        net_out_bps: value.net_out_bps,
        load_1m: value.load_1m,
    }
}

pub fn node_view(snapshot: &NodeSnapshot) -> NodeView {
    NodeView {
        info: info_view(&snapshot.info),
        identity: identity_view(&snapshot.identity),
        status: status_view(&snapshot.status),
        tip: tip_view(&snapshot.tip),
        sync: sync_view(&snapshot.sync),
        health: health_view(&snapshot.health),
        capabilities: snapshot.capabilities.iter().map(capability_view).collect(),
        revision: snapshot.revision.0,
        produced_at_unix_ms: snapshot.produced_at_unix_ms,
    }
}

pub fn info_view(value: &NodeInfo) -> NodeInfoView {
    NodeInfoView {
        agent_name: value.agent_name.clone(),
        node_name: value.node_name.clone(),
        network: match value.network {
            ergo_api_core::node::NodeNetwork::Mainnet => "mainnet",
            ergo_api_core::node::NodeNetwork::Testnet => "testnet",
            ergo_api_core::node::NodeNetwork::Devnet => "devnet",
        }
        .to_string(),
        version: value.version.clone(),
        started_at_unix_ms: value.started_at_unix_ms,
        uptime_seconds: value.uptime_seconds,
        target_block_interval_ms: value.target_block_interval_ms,
    }
}

pub fn identity_view(value: &NodeIdentity) -> NodeIdentityView {
    NodeIdentityView {
        state_backend: match value.state_backend {
            ergo_api_core::node::StateBackend::Utxo => "utxo",
            ergo_api_core::node::StateBackend::Digest => "digest",
        }
        .to_string(),
        verify_transactions: value.verify_transactions,
        history_mode: match value.history_mode {
            ergo_api_core::node::HistoryMode::Archive => "archive",
            ergo_api_core::node::HistoryMode::UtxoBootstrapped => "utxo_bootstrapped",
            ergo_api_core::node::HistoryMode::HeadersOnly => "headers_only",
            ergo_api_core::node::HistoryMode::Pruned { .. } => "pruned",
        }
        .to_string(),
        utxo_bootstrap: value.utxo_bootstrap,
        nipopow_bootstrap: value.nipopow_bootstrap,
        mining_enabled: value.mining_enabled,
        indexer_enabled: value.indexer_enabled,
        declared_address: value.declared_address.map(|v| v.to_string()),
        bind_address: value.bind_address.map(|v| v.to_string()),
    }
}

pub fn status_view(value: &NodeStatus) -> NodeStatusView {
    NodeStatusView {
        sync_state: sync_state_name(value.sync).to_string(),
        peer_count: value.peer_count,
        mempool_size: value.mempool_size,
        headers_ahead_of_full_blocks: value.headers_ahead_of_full_blocks,
        snapshot_age_ms: value.snapshot_age_ms,
        block_apply_errors_total: value.block_apply_errors_total,
        storage_errors_total: value.storage_errors_total,
        reorgs_total: value.reorgs_total,
        sync_wedged: value.sync_wedged,
        apply_wedged: value.apply_wedged,
        apply_in_progress: value.apply_in_progress,
        shadow_diverged: value.shadow_diverged,
        bootstrap_active: value.bootstrap_active,
    }
}

pub fn tip_view(value: &ChainTip) -> ChainTipView {
    ChainTipView {
        best_header: header_tip_view(&value.best_header),
        best_block: BlockTipView {
            height: value.best_block.header.height,
            id: value.best_block.header.id.map(|id| id.to_string()),
            parent_id: value.best_block.header.parent_id.map(|id| id.to_string()),
            timestamp_unix_ms: value.best_block.header.timestamp_unix_ms,
            compact_bits: value.best_block.header.compact_bits,
            difficulty: value.best_block.header.difficulty.to_string(),
            state_root: value.best_block.state_root.map(hex::encode),
        },
    }
}

pub fn sync_view(value: &SyncStatus) -> SyncStatusView {
    SyncStatusView {
        state: sync_state_name(value.state).to_string(),
        headers_chain_synced: value.headers_chain_synced,
        header_height: value.header_height,
        full_block_height: value.full_block_height,
        gap: value.gap,
        download_window: value.download_window,
        pending_blocks: value.pending_blocks,
        recovery_complete: value.recovery_complete,
        best_known_height: value.best_known_height,
    }
}

pub fn health_view(value: &Health) -> HealthView {
    HealthView {
        status: health_status_name(value.status).to_string(),
        behind: value.behind,
        last_progress_age_ms: value.last_progress_age_ms,
        peer_count: value.peer_count,
    }
}

fn header_tip_view(value: &ergo_api_core::node::HeaderTip) -> HeaderTipView {
    HeaderTipView {
        height: value.height,
        id: value.id.map(|id| id.to_string()),
        parent_id: value.parent_id.map(|id| id.to_string()),
        timestamp_unix_ms: value.timestamp_unix_ms,
        compact_bits: value.compact_bits,
        difficulty: value.difficulty.to_string(),
    }
}

pub fn capability_view(value: &CapabilityDescriptor) -> CapabilityView {
    CapabilityView {
        id: value.id.as_str().to_string(),
        state: value.state.as_str().to_string(),
        reason: value.reason.as_ref().map(reason_name),
    }
}

fn reason_name(value: &CapabilityReason) -> String {
    match value {
        CapabilityReason::DisabledByConfig => "disabled_by_config".to_string(),
        CapabilityReason::UnsupportedState(_) => "unsupported_state".to_string(),
        CapabilityReason::StartupFailed(_) => "startup_failed".to_string(),
        CapabilityReason::TemporarilyUnavailable(_) => "temporarily_unavailable".to_string(),
    }
}

fn sync_state_name(value: SyncState) -> &'static str {
    match value {
        SyncState::Disconnected => "disconnected",
        SyncState::Syncing => "syncing",
        SyncState::AtTip => "at_tip",
        SyncState::Stalled => "stalled",
    }
}

fn health_status_name(value: HealthStatus) -> &'static str {
    match value {
        HealthStatus::Healthy => "healthy",
        HealthStatus::Syncing => "syncing",
        HealthStatus::Disconnected => "disconnected",
        HealthStatus::Stalled => "stalled",
        HealthStatus::Rejecting => "rejecting",
        HealthStatus::Wedged => "wedged",
    }
}
