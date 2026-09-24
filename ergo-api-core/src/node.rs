use std::net::SocketAddr;
use std::sync::Arc;

use num_bigint::BigUint;

use crate::capability::CapabilityDescriptor;
use crate::id::HeaderId;
use crate::page::SnapshotRevision;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeNetwork {
    Mainnet,
    Testnet,
    Devnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateBackend {
    Utxo,
    Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryMode {
    Archive,
    UtxoBootstrapped,
    HeadersOnly,
    Pruned { suffix_len: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    pub agent_name: String,
    pub node_name: String,
    pub network: NodeNetwork,
    pub version: String,
    pub started_at_unix_ms: u64,
    pub uptime_seconds: u64,
    pub target_block_interval_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    pub state_backend: StateBackend,
    pub verify_transactions: bool,
    pub history_mode: HistoryMode,
    pub utxo_bootstrap: bool,
    pub nipopow_bootstrap: bool,
    pub mining_enabled: bool,
    pub indexer_enabled: bool,
    pub declared_address: Option<SocketAddr>,
    pub bind_address: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    Disconnected,
    Syncing,
    AtTip,
    Stalled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderTip {
    pub height: u32,
    pub id: Option<HeaderId>,
    pub parent_id: Option<HeaderId>,
    pub timestamp_unix_ms: u64,
    pub compact_bits: u32,
    pub difficulty: BigUint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTip {
    pub header: HeaderTip,
    pub state_root: Option<[u8; 33]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTip {
    pub best_header: HeaderTip,
    pub best_block: BlockTip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    pub state: SyncState,
    pub headers_chain_synced: bool,
    pub header_height: u32,
    pub full_block_height: u32,
    pub gap: u32,
    pub download_window: u32,
    pub pending_blocks: u32,
    pub recovery_complete: bool,
    pub best_known_height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Syncing,
    Disconnected,
    Stalled,
    Rejecting,
    Wedged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    pub status: HealthStatus,
    pub behind: u32,
    pub last_progress_age_ms: u64,
    pub peer_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStatus {
    pub sync: SyncState,
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

#[derive(Debug, Clone, PartialEq)]
pub struct NodeSnapshot {
    pub revision: SnapshotRevision,
    pub produced_at_unix_ms: u64,
    pub info: NodeInfo,
    pub identity: NodeIdentity,
    pub status: NodeStatus,
    pub tip: ChainTip,
    pub sync: SyncStatus,
    pub health: Health,
    pub capabilities: Vec<CapabilityDescriptor>,
}

pub trait NodeSnapshotSource: Send + Sync + 'static {
    fn snapshot(&self) -> Arc<NodeSnapshot>;
}
