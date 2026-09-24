use std::str::FromStr;
use std::sync::Arc;

use ergo_api::types::{ApiHistoryMode, ApiIdentity, ApiStateType, HealthStatus, SyncStateLabel};
use ergo_api_core::capability::CapabilityDescriptor;
use ergo_api_core::id::HeaderId;
use ergo_api_core::node::{
    BlockTip, ChainTip, HeaderTip, Health, HealthStatus as CoreHealthStatus, HistoryMode,
    NodeIdentity, NodeInfo, NodeNetwork, NodeSnapshot, NodeSnapshotSource, NodeStatus,
    StateBackend, SyncState, SyncStatus,
};
use num_bigint::BigUint;

use super::SnapshotReadState;

fn network(value: &str) -> NodeNetwork {
    match value {
        "testnet" => NodeNetwork::Testnet,
        "devnet" => NodeNetwork::Devnet,
        _ => NodeNetwork::Mainnet,
    }
}

fn identity(value: &ApiIdentity) -> NodeIdentity {
    NodeIdentity {
        state_backend: match value.state_type {
            ApiStateType::Utxo => StateBackend::Utxo,
            ApiStateType::Digest => StateBackend::Digest,
        },
        verify_transactions: value.verify_transactions,
        history_mode: match value.history_mode {
            ApiHistoryMode::Archive => HistoryMode::Archive,
            ApiHistoryMode::UtxoBootstrapped => HistoryMode::UtxoBootstrapped,
            ApiHistoryMode::HeadersOnly => HistoryMode::HeadersOnly,
            ApiHistoryMode::Pruned { suffix_len } => HistoryMode::Pruned { suffix_len },
        },
        utxo_bootstrap: value.utxo_bootstrap,
        nipopow_bootstrap: value.nipopow_bootstrap,
        mining_enabled: value.mining,
        indexer_enabled: value.extra_index_enabled,
        declared_address: value.declared_addr.as_deref().and_then(|v| v.parse().ok()),
        bind_address: value.bind_addr.as_deref().and_then(|v| v.parse().ok()),
    }
}

fn header_tip(value: &ergo_api::types::ApiHeaderRef) -> HeaderTip {
    HeaderTip {
        height: value.height,
        id: HeaderId::from_str(&value.header_id).ok(),
        parent_id: HeaderId::from_str(&value.parent_id).ok(),
        timestamp_unix_ms: value.timestamp_unix_ms,
        compact_bits: value.n_bits,
        difficulty: BigUint::parse_bytes(value.difficulty.as_bytes(), 10).unwrap_or_default(),
    }
}

fn block_tip(value: &ergo_api::types::ApiFullBlockRef) -> BlockTip {
    BlockTip {
        header: header_tip(&ergo_api::types::ApiHeaderRef {
            height: value.height,
            header_id: value.header_id.clone(),
            parent_id: value.parent_id.clone(),
            timestamp_unix_ms: value.timestamp_unix_ms,
            n_bits: value.n_bits,
            difficulty: value.difficulty.clone(),
        }),
        state_root: hex::decode(&value.state_root_avl)
            .ok()
            .and_then(|bytes| bytes.try_into().ok()),
    }
}

fn sync_state(value: SyncStateLabel) -> SyncState {
    match value {
        SyncStateLabel::Disconnected => SyncState::Disconnected,
        SyncStateLabel::Syncing => SyncState::Syncing,
        SyncStateLabel::AtTip => SyncState::AtTip,
        SyncStateLabel::Stalled => SyncState::Stalled,
    }
}

fn health_status(value: HealthStatus) -> CoreHealthStatus {
    match value {
        HealthStatus::Ok => CoreHealthStatus::Healthy,
        HealthStatus::Stalled => CoreHealthStatus::Stalled,
        HealthStatus::Disconnected => CoreHealthStatus::Disconnected,
        HealthStatus::Rejecting => CoreHealthStatus::Rejecting,
        HealthStatus::Wedged => CoreHealthStatus::Wedged,
    }
}

impl SnapshotReadState {
    pub fn with_core_capabilities(mut self, capabilities: Vec<CapabilityDescriptor>) -> Self {
        self.core_capabilities = Arc::new(capabilities);
        self
    }
}

impl NodeSnapshotSource for SnapshotReadState {
    fn snapshot(&self) -> Arc<NodeSnapshot> {
        let snap = self.handle.load_full();
        let info = self.info_from_snapshot(&snap);
        let identity_value = (**self.identity.load()).clone();
        let status = self.status_from_snapshot(&snap);
        let sync = snap.sync.clone();
        let health = self.health_from_snapshot(&snap);
        let tip = ChainTip {
            best_header: header_tip(&snap.tip.best_header),
            best_block: block_tip(&snap.tip.best_full_block),
        };
        Arc::new(NodeSnapshot {
            revision: ergo_api_core::page::SnapshotRevision(snap.revision),
            produced_at_unix_ms: crate::snapshot::unix_now_ms()
                .saturating_sub(self.age_ms(snap.produced_at)),
            info: NodeInfo {
                agent_name: info.agent_name,
                node_name: info.node_name,
                network: network(&info.network),
                version: info.version,
                started_at_unix_ms: info.started_at_unix_ms,
                uptime_seconds: info.uptime_seconds,
                target_block_interval_ms: info.target_block_interval_ms,
            },
            identity: identity(&identity_value),
            status: NodeStatus {
                sync: sync_state(status.sync_state),
                peer_count: status.peer_count,
                mempool_size: status.mempool_size,
                headers_ahead_of_full_blocks: status.headers_ahead_of_full_blocks,
                snapshot_age_ms: status.snapshot_age_ms,
                block_apply_errors_total: status.block_apply_errors_total,
                storage_errors_total: status.storage_errors_state_total
                    + status.storage_errors_indexer_total
                    + status.storage_errors_peers_total,
                reorgs_total: status.reorgs_total,
                sync_wedged: status.sync_wedged.is_some(),
                apply_wedged: status.apply_wedged,
                apply_in_progress: status.apply_in_progress,
                shadow_diverged: status
                    .shadow
                    .as_ref()
                    .and_then(|shadow| shadow.diverged.as_ref())
                    .is_some(),
                bootstrap_active: status.bootstrap.is_some(),
            },
            tip,
            sync: SyncStatus {
                state: sync_state(status.sync_state),
                headers_chain_synced: sync.headers_chain_synced,
                header_height: sync.best_header_height,
                full_block_height: sync.best_full_block_height,
                gap: sync.gap,
                download_window: sync.download_window,
                pending_blocks: sync.pending_blocks,
                recovery_complete: sync.recovery_done,
                best_known_height: snap.max_peer_height,
            },
            health: Health {
                status: if status.sync_wedged.is_some() || status.apply_wedged {
                    CoreHealthStatus::Wedged
                } else if status.sync_state == SyncStateLabel::Syncing
                    && health.status == HealthStatus::Ok
                {
                    CoreHealthStatus::Syncing
                } else {
                    health_status(health.status)
                },
                behind: health.behind,
                last_progress_age_ms: health.last_progress_age_ms,
                peer_count: health.peer_count,
            },
            capabilities: self.core_capabilities.as_ref().clone(),
        })
    }
}
