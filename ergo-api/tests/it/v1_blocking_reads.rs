//! Scheduling and capacity isolation for the product chain-reader routes.
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Request, StatusCode},
    response::Response,
    Router,
};
use ergo_api::{
    compat::NodeChainQuery,
    traits::{NodeReadState, NodeSubmit, NoopMempoolView},
    types::*,
    v1::{v1_router, BlockingReads, BlockingReadsConfig, V1State},
};
use ergo_rest_json::types::ScalaHeader;
use ergo_ser::address::NetworkPrefix;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tower::ServiceExt;

// ----- helpers -----
const HEIGHT: u32 = 1;
struct StubRead(bool);
impl NodeReadState for StubRead {
    fn info(&self) -> ApiInfo {
        ApiInfo {
            agent_name: String::new(),
            node_name: String::new(),
            network: String::new(),
            version: String::new(),
            started_at_unix_ms: 0,
            uptime_seconds: 0,
            target_block_interval_ms: 120_000,
        }
    }
    fn status(&self) -> ApiStatus {
        assert!(!self.0, "status must not be used to read tip heights");
        ApiStatus {
            best_header_height: HEIGHT,
            best_full_block_height: HEIGHT,
            ..Default::default()
        }
    }
    fn tip(&self) -> ApiTip {
        ApiTip {
            best_header: ApiHeaderRef {
                height: 0,
                header_id: String::new(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                n_bits: 0,
                difficulty: String::new(),
            },
            best_full_block: ApiFullBlockRef {
                height: 0,
                header_id: String::new(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                state_root_avl: String::new(),
                n_bits: 0,
                difficulty: String::new(),
            },
            headers_ahead_of_full_blocks: 0,
        }
    }
    fn sync(&self) -> ApiSyncStatus {
        ApiSyncStatus {
            headers_chain_synced: true,
            best_header_height: HEIGHT,
            best_full_block_height: HEIGHT,
            gap: 0,
            download_window: 0,
            pending_blocks: 0,
            recovery_done: true,
        }
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
        ApiMempoolTransactions {
            transactions: Vec::new(),
            weight_function: ApiWeightFunction::Cost,
        }
    }
    fn mempool_transaction(&self, _tx_id_hex: &str) -> Option<ApiMempoolTransaction> {
        None
    }
    fn health(&self) -> ApiHealth {
        ApiHealth {
            status: HealthStatus::Ok,
            behind: 0,
            last_progress_age_ms: 0,
            peer_count: 0,
        }
    }
}

#[derive(Default)]
struct Store {
    header_delay: Duration,
    scan_delay: Duration,
    entered: tokio::sync::Notify,
    release: Option<Arc<std::sync::Barrier>>,
    calls: AtomicUsize,
    scan_calls: AtomicUsize,
}
impl NodeChainQuery for Store {
    fn full_block_by_id(&self, _id: &str) -> Option<ergo_rest_json::types::ScalaFullBlock> {
        None
    }
    fn info(&self) -> ergo_api::compat::types::ScalaInfo {
        unreachable!()
    }
    fn header_by_id(&self, id: &str) -> Option<ScalaHeader> {
        assert_eq!(id, format!("{HEIGHT:064x}"));
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.header_delay);
        None
    }
    fn header_ids_at_height(&self, height: u32) -> Vec<String> {
        assert_eq!(height, HEIGHT);
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        if self.scan_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            if let Some(barrier) = &self.release {
                barrier.wait();
            }
            std::thread::sleep(self.scan_delay);
        }
        Vec::new()
    }
}
struct Submit;
#[async_trait::async_trait]
impl NodeSubmit for Submit {
    async fn submit_transaction_json(
        &self,
        _tx: ergo_rest_json::types::ScalaTransactionInput,
        _mode: SubmitMode,
    ) -> Result<String, SubmitError> {
        unreachable!()
    }
    async fn submit_transaction(
        &self,
        bytes: Vec<u8>,
        mode: SubmitMode,
    ) -> Result<String, SubmitError> {
        assert_eq!(bytes, vec![1, 2]);
        assert!(matches!(mode, SubmitMode::Broadcast));
        Ok(format!("{:064x}", 42))
    }
}
fn config() -> BlockingReadsConfig {
    BlockingReadsConfig {
        point_permits: 1,
        scan_permits: 1,
        queue_wait: Duration::from_millis(20),
        run_timeout: Duration::from_secs(2),
    }
}
fn app(store: Arc<Store>, cfg: BlockingReadsConfig, panic_status: bool) -> Router {
    let state = V1State {
        blocking: BlockingReads::new(cfg).unwrap(),
        read: Arc::new(StubRead(panic_status)),
        chain: Some(store),
        indexer: None,
        submit: Some(Arc::new(Submit)),
        tx_builder: None,
        mempool: Arc::new(NoopMempoolView::new()),
        mempool_depth: Arc::new(ergo_api::v1::MempoolDepthRing::new()),
        emission: None,
        realtime: None,
        network: NetworkPrefix::Mainnet,
    };
    v1_router(
        state,
        ergo_api::v1::Governor::new(Default::default()).unwrap(),
    )
}
async fn request(app: Router, uri: &str, body: Option<Body>) -> Response {
    let mut req = Request::builder()
        .method(if body.is_some() { "POST" } else { "GET" })
        .uri(uri)
        .header("content-type", "application/json")
        .body(body.unwrap_or_else(Body::empty))
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))));
    app.oneshot(req).await.unwrap()
}
async fn reason(response: Response, status: StatusCode, reason: &str) {
    assert_eq!(response.status(), status);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["reason"], reason);
}
fn header_path() -> String {
    format!("/api/v1/chain/headers/{HEIGHT:064x}")
}
const BLOCKS: &str = "/api/v1/chain/blocks?limit=1";

// ----- happy path -----
#[tokio::test]
async fn chain_header_by_id_slow_store_read_does_not_block_runtime() {
    let ticks = Arc::new(AtomicUsize::new(0));
    let counter = ticks.clone();
    let heartbeat = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    tokio::task::yield_now().await;
    let store = Arc::new(Store {
        header_delay: Duration::from_millis(300),
        ..Default::default()
    });
    let response = request(app(store, config(), false), &header_path(), None).await;
    heartbeat.abort();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        ticks.load(Ordering::SeqCst) >= 3,
        "heartbeat was blocked by the read"
    );
}
#[tokio::test]
async fn chain_blocks_list_reads_tip_without_calling_status() {
    assert_eq!(
        request(
            app(Arc::new(Store::default()), config(), true),
            BLOCKS,
            None
        )
        .await
        .status(),
        StatusCode::OK
    );
}
#[tokio::test]
async fn chain_blocks_by_ids_slow_body_does_not_hold_read_permit() {
    let router = app(Arc::new(Store::default()), config(), false);
    let (polled_tx, polled_rx) = tokio::sync::oneshot::channel();
    let mut polled_tx = Some(polled_tx);
    let body = Body::from_stream(futures_util::stream::poll_fn(move |_| {
        if let Some(tx) = polled_tx.take() {
            let _ = tx.send(());
        }
        std::task::Poll::<Option<Result<axum::body::Bytes, std::io::Error>>>::Pending
    }));
    let pending = tokio::spawn(request(
        router.clone(),
        "/api/v1/chain/blocks/by-ids",
        Some(body),
    ));
    polled_rx.await.unwrap();
    assert_eq!(request(router, BLOCKS, None).await.status(), StatusCode::OK);
    pending.abort();
}

// ----- error paths -----
#[tokio::test]
async fn chain_blocks_list_saturated_scan_lane_is_overloaded_503() {
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let store = Arc::new(Store {
        release: Some(barrier.clone()),
        ..Default::default()
    });
    let router = app(store.clone(), config(), false);
    let first = tokio::spawn(request(router.clone(), BLOCKS, None));
    store.entered.notified().await;
    let response = request(router, BLOCKS, None).await;
    // Release before asserting so failed assertions cannot strand a blocking task.
    tokio::task::spawn_blocking(move || barrier.wait())
        .await
        .unwrap();
    assert_eq!(response.headers().get("retry-after").unwrap(), "1");
    reason(response, StatusCode::SERVICE_UNAVAILABLE, "overloaded").await;
    assert_eq!(first.await.unwrap().status(), StatusCode::OK);
}
#[tokio::test]
async fn chain_blocks_list_timed_out_read_is_timeout_504_and_keeps_permit() {
    let store = Arc::new(Store {
        scan_delay: Duration::from_millis(200),
        ..Default::default()
    });
    let router = app(
        store,
        BlockingReadsConfig {
            run_timeout: Duration::from_millis(50),
            ..config()
        },
        false,
    );
    reason(
        request(router.clone(), BLOCKS, None).await,
        StatusCode::GATEWAY_TIMEOUT,
        "timeout",
    )
    .await;
    reason(
        request(router.clone(), BLOCKS, None).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "overloaded",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(220)).await;
    assert_eq!(request(router, BLOCKS, None).await.status(), StatusCode::OK);
}
async fn saturated_request(uri: &str, body: Option<Body>) -> Response {
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let store = Arc::new(Store {
        release: Some(barrier.clone()),
        ..Default::default()
    });
    let router = app(store.clone(), config(), false);
    let first = tokio::spawn(request(router.clone(), BLOCKS, None));
    store.entered.notified().await;
    let response = request(router, uri, body).await;
    tokio::task::spawn_blocking(move || barrier.wait())
        .await
        .unwrap();
    assert_eq!(first.await.unwrap().status(), StatusCode::OK);
    response
}
#[tokio::test]
async fn transactions_submit_not_blocked_by_saturated_read_pool() {
    assert_eq!(
        saturated_request("/api/v1/transactions/submit", Some(Body::from(vec![1, 2])))
            .await
            .status(),
        StatusCode::OK
    );
}
#[tokio::test]
async fn chain_header_by_id_not_blocked_by_saturated_scan_lane() {
    reason(
        saturated_request(&header_path(), None).await,
        StatusCode::NOT_FOUND,
        "header_not_found",
    )
    .await;
}
#[tokio::test]
async fn chain_header_by_id_malformed_id_takes_no_permit() {
    let store = Arc::new(Store {
        header_delay: Duration::from_millis(300),
        ..Default::default()
    });
    let router = app(store.clone(), config(), false);
    let first_router = router.clone();
    let first = tokio::spawn(async move { request(first_router, &header_path(), None).await });
    while store.calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    reason(
        request(router, "/api/v1/chain/headers/nope", None).await,
        StatusCode::BAD_REQUEST,
        "invalid_hex",
    )
    .await;
    assert_eq!(first.await.unwrap().status(), StatusCode::NOT_FOUND);
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
}
