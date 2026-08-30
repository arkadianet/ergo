use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ergo_api::server::{router_with_mempool_and_wallet_and_security, ServerCtx};
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction, ApiMempoolTransactions, ApiPeer,
    ApiStatus, ApiSyncGauges, ApiSyncStatus, ApiTip,
};
use ergo_api::wallet::NoopWalletAdmin;
use ergo_api::NoopNodeAdmin;
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

/// Stub read view: `/metrics` reads only `info`, `status`,
/// `mempool_summary`, and `sync_gauges` (trait-default zeros).
struct MetricsReadState;

impl NodeReadState for MetricsReadState {
    fn info(&self) -> ApiInfo {
        ApiInfo {
            agent_name: "ergo-rust-test".to_owned(),
            node_name: "metrics-gauge-test".to_owned(),
            network: "mainnet".to_owned(),
            version: "test".to_owned(),
            started_at_unix_ms: 0,
            uptime_seconds: 0,
            target_block_interval_ms: 120_000,
        }
    }
    fn status(&self) -> ApiStatus {
        ApiStatus::default()
    }
    fn tip(&self) -> ApiTip {
        unreachable!()
    }
    fn sync(&self) -> ApiSyncStatus {
        unreachable!()
    }
    fn peers(&self) -> Vec<ApiPeer> {
        Vec::new()
    }
    fn mempool_summary(&self) -> ApiMempoolSummary {
        ApiMempoolSummary {
            size: 0,
            total_bytes: 0,
            capacity_count: 0,
            capacity_bytes: 0,
            revalidation_pending: 0,
        }
    }
    fn mempool_transactions(&self) -> ApiMempoolTransactions {
        unreachable!()
    }
    fn mempool_transaction(&self, _tx_id_hex: &str) -> Option<ApiMempoolTransaction> {
        None
    }
    fn health(&self) -> ApiHealth {
        unreachable!()
    }
}

fn app() -> axum::Router {
    let ctx = ServerCtx {
        read: Arc::new(MetricsReadState),
        compat: None,
        submit: None,
        indexer: None,
        mempool: Arc::new(ergo_api::NoopMempoolView::new()),
        network: NetworkPrefix::Mainnet,
        chain_params: None,
        mining: None,
        emission: None,
        emission_scripts: None,
        utxo_reads_supported: true,
    };
    router_with_mempool_and_wallet_and_security(
        ctx,
        Some(Arc::new(NoopNodeAdmin)),
        Arc::new(NoopWalletAdmin),
        None,
    )
}

#[tokio::test]
async fn metrics_renders_subsystem_gauge_series() {
    let resp = app()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    // Trait-default gauges are all zeros; the handler must still render
    // every series (a missing line is the regression this test pins).
    let zeros = ApiSyncGauges::default();
    assert_eq!(zeros.dl_late_acceptable, 0);

    for series in [
        "ergo_dl_inflight 0",
        "ergo_dl_peers_inflight 0",
        "ergo_dl_received 0",
        "ergo_dl_late_acceptable 0",
        "ergo_dl_recently_released 0",
        "ergo_orphan_groups 0",
        "ergo_orphan_headers 0",
        "ergo_bans 0",
        "ergo_known_addrs 0",
        "ergo_solutions_accepted_total 0",
        "ergo_solutions_invalid_pow_total 0",
        "ergo_solutions_stale_parent_total 0",
        "ergo_rss_kb 0",
        // Storage gauges render even when the probes are absent (stub
        // status): absence → 0, documented in each HELP line.
        "ergo_state_db_bytes 0",
        "ergo_index_db_bytes 0",
        "ergo_disk_free_bytes 0",
        "ergo_disk_total_bytes 0",
    ] {
        assert!(
            text.contains(series),
            "/metrics must render `{series}`\n--- body ---\n{text}"
        );
    }
}
