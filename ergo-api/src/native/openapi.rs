use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Ergo Rust Node — Native API",
        version = "1.0.0",
        description = "Rust-native node, chain, and transaction resources."
    ),
    paths(
        super::node,
        super::node_info,
        super::node_status,
        super::node_sync,
        super::node_identity,
         super::node_tip,
         super::node_host,
         super::node_health,

        super::node_capabilities,
        super::node_events,
        super::indexer_status,
        super::chain_tip,
        super::chain_headers,
        super::chain_header,
         super::chain_block,
        super::recent_blocks,
         super::voting_history,
         super::difficulty_history,
        super::miner_stats,
        super::transaction_by_id,
         super::transaction_status,
         super::submit_transaction,
         super::network::peers,
         super::network::connected,
         super::network::blacklisted,
         super::network::sync_info,
         super::network::track_info,

    ),
    components(schemas(
        super::dto::NodeView,
        super::dto::NodeInfoView,
        super::dto::NodeStatusView,
        super::dto::SyncStatusView,
        super::dto::NodeIdentityView,
        super::dto::ChainTipView,
        super::dto::HeaderTipView,
         super::dto::BlockTipView,
         super::dto::HealthView,
         super::dto::HostStatusView,

        super::dto::CapabilityView,
         super::dto::IndexerStatusView,
         super::dto::IndexerRepairView,
         super::dto::IndexerTotalsView,
        super::dto::HeaderView,
        super::dto::HeaderPage,
        super::dto::PageView,
        super::dto::BlockSummaryView,
        super::dto::EventView,
        super::dto::EventFeedView,
        super::dto::RecentBlockView,
        super::dto::DifficultyPointView,
        super::dto::DifficultySeriesView,
         super::dto::MinerStatView,
         super::dto::MinerStatsView,
         super::dto::ProtocolHistoryView,
         super::dto::ProtocolChangeView,
         super::dto::ProtocolParamView,
         super::dto::TransactionBody,
        super::dto::TransactionView,
        super::dto::TransactionStatusView,
          super::dto::TransactionAdmissionView,
          super::dto::NetworkPage,
          super::dto::NetworkPeerView,
          super::dto::NetworkBlacklistedView,
          super::dto::NetworkSyncInfoView,
          super::dto::NetworkTrackInfoView,
          super::dto::NetworkPeerPage,
          super::dto::NetworkBlacklistedPage,
          super::dto::NetworkSyncInfoPage,
          super::error::ErrorEnvelope,
        super::error::ErrorBody,
    )),
    tags(
         (name = "node", description = "Node identity, status, sync, and health"),
         (name = "indexer", description = "Extra-index health and repair status"),
          (name = "chain", description = "Canonical chain headers, tips, and blocks"),
         (name = "voting", description = "Protocol-parameter governance history"),
           (name = "transactions", description = "Transaction validation and submission"),
           (name = "network", description = "Peer, blacklist, and synchronization reads"),

    )
)]
pub struct NativeApiOpenApi;

pub fn document() -> utoipa::openapi::OpenApi {
    NativeApiOpenApi::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_contains_native_node_chain_and_transaction_paths() {
        let document = document();
        let paths = &document.paths.paths;
        for path in [
            "/api/v1/node",
            "/api/v1/node/status",
            "/api/v1/node/host",
            "/api/v1/node/events",
            "/api/v1/indexer/status",
            "/api/v1/chain/headers",
            "/api/v1/chain/blocks/{header_id}",
            "/api/v1/chain/blocks/recent",
            "/api/v1/voting/history",
            "/api/v1/difficulty/history",
            "/api/v1/mining/minerStats",
            "/api/v1/transactions",
            "/api/v1/transactions/{tx_id}",
            "/api/v1/transactions/{tx_id}/status",
            "/api/v1/network/peers",
            "/api/v1/network/connected",
            "/api/v1/network/blacklisted",
            "/api/v1/network/sync-info",
            "/api/v1/network/track-info",
        ] {
            assert!(paths.contains_key(path), "missing {path}");
        }
        let value = serde_json::to_value(&document).unwrap();
        let peer_operation = &value["paths"]["/api/v1/network/peers"]["get"];
        let peer_limit = peer_operation["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|parameter| parameter["name"] == "limit")
            .unwrap();
        assert_eq!(peer_limit["schema"]["default"], 256);
        assert_eq!(peer_limit["schema"]["maximum"], 1024);
        let network_operation = &value["paths"]["/api/v1/network/blacklisted"]["get"];
        let network_limit = network_operation["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|parameter| parameter["name"] == "limit")
            .unwrap();
        assert_eq!(network_limit["schema"]["default"], 100);
        assert_eq!(network_limit["schema"]["maximum"], 500);
        let event_operation = &value["paths"]["/api/v1/node/events"]["get"];
        let since = event_operation["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|parameter| parameter["name"] == "since")
            .unwrap();
        assert_eq!(since["in"], "query");
        assert_eq!(since["schema"]["minimum"], 0);
        assert_eq!(
            event_operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/EventFeedView"
        );
        let operation = &value["paths"]["/api/v1/chain/blocks/recent"]["get"];
        let n = operation["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|parameter| parameter["name"] == "n")
            .unwrap();
        assert_eq!(n["in"], "query");
        assert_eq!(n["schema"]["minimum"], 1);
        assert_eq!(n["schema"]["maximum"], 32);
        assert_eq!(n["schema"]["default"], 10);
        assert_eq!(
            operation["responses"]["200"]["content"]["application/json"]["schema"]["items"]["$ref"],
            "#/components/schemas/RecentBlockView"
        );
        let schemas = &document.components.as_ref().unwrap().schemas;
        let event_properties = &value["components"]["schemas"]["EventView"]["properties"];
        assert!(event_properties.get("unixMs").is_some());
        assert!(event_properties.get("headerId").is_some());
        assert!(event_properties.get("sizeBytes").is_some());
        assert!(schemas.contains_key("IndexerStatusView"));
        assert!(schemas.contains_key("EventView"));
        assert!(schemas.contains_key("EventFeedView"));
        assert!(schemas.contains_key("RecentBlockView"));
        assert!(schemas.contains_key("IndexerRepairView"));
        assert!(schemas.contains_key("IndexerTotalsView"));
        assert!(schemas.contains_key("ProtocolHistoryView"));
        assert!(schemas.contains_key("ProtocolChangeView"));
        assert!(schemas.contains_key("ProtocolParamView"));
        assert!(schemas.contains_key("HostStatusView"));
        assert!(schemas.contains_key("NetworkPeerView"));
        assert!(schemas.contains_key("NetworkPeerPage"));
        assert!(schemas.contains_key("NetworkBlacklistedView"));
        assert!(schemas.contains_key("NetworkSyncInfoView"));
        assert!(schemas.contains_key("NetworkTrackInfoView"));
        let network_properties = &value["components"]["schemas"]["NetworkPeerView"]["properties"];
        for field in [
            "addr",
            "direction",
            "state",
            "score",
            "agent",
            "node_name",
            "version",
            "sync_version",
            "connected_seconds",
            "last_seen_seconds",
            "bytes_in",
            "bytes_out",
            "peer_height",
        ] {
            assert!(network_properties.get(field).is_some(), "missing {field}");
        }
        let host_properties = &value["components"]["schemas"]["HostStatusView"]["properties"];
        for field in [
            "rss_bytes",
            "state_db_bytes",
            "index_db_bytes",
            "disk_free_bytes",
            "disk_total_bytes",
            "cpu_pct",
            "net_in_bps",
            "net_out_bps",
            "load_1m",
        ] {
            assert!(host_properties.get(field).is_some(), "missing {field}");
        }
    }
}
