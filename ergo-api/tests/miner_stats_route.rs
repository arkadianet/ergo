//! Behaviour of the native `GET /api/v1/mining/minerStats` route.
//!
//! Drives the real handler against a chain stub: proves the per-pk fold
//! (count + last height), the count-desc sort, the server-side P2PK
//! address derivation (live-verified vector), the window default/clamp,
//! and that the route is conditional on a wired chain reader — the same
//! contract as `/api/v1/difficulty/history`, whose test this mirrors.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ergo_api::compat::traits::NodeChainQuery;
use ergo_api::compat::types::{
    Parameters, ScalaFullBlock, ScalaHeader, ScalaInfo, ScalaPowSolutions,
};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiMinerStats, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip,
    ApiWeightFunction, HealthStatus, SyncStateLabel,
};
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

// Live-verified vector: 2Miners' mining pk → its P2PK address
// (cross-checked against /utils/rawToAddress on mainnet 2026-07-05).
const PK_2MINERS: &str = "0274e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891f";
const ADDR_2MINERS: &str = "9fQYeMEXvSfmL2iUfsDDJ88SVtuPuvTZiB5aR19nKeCKSACVmgx";

// ----- helpers -----

/// Read-state is never touched by this route, but `router` requires one.
struct StubReadState;

impl NodeReadState for StubReadState {
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
        ApiStatus {
            sync_state: SyncStateLabel::AtTip,
            peer_count: 0,
            best_header_height: 0,
            best_full_block_height: 0,
            headers_ahead_of_full_blocks: 0,
            mempool_size: 0,
            snapshot_age_ms: 0,
            bootstrap: None,
            last_block_apply_error: None,
            block_apply_errors_total: 0,
            mempool_tx_requested_total: 0,
            mempool_peer_tx_admitted_total: 0,
            mempool_peer_tx_rejected_total: 0,
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
            best_header_height: 0,
            best_full_block_height: 0,
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

/// Chain stub that returns a fixed header list and records the `count` the
/// handler asked for, so the default/clamp logic can be asserted directly.
struct StubChain {
    headers: Vec<ScalaHeader>,
    last_requested: AtomicU32,
}

impl StubChain {
    fn new(headers: Vec<ScalaHeader>) -> Self {
        Self {
            headers,
            last_requested: AtomicU32::new(0),
        }
    }
}

impl NodeChainQuery for StubChain {
    fn info(&self) -> ScalaInfo {
        empty_info()
    }
    fn header_ids_at_height(&self, _height: u32) -> Vec<String> {
        Vec::new()
    }
    fn full_block_by_id(&self, _header_id_hex: &str) -> Option<ScalaFullBlock> {
        None
    }
    fn last_headers(&self, count: u32) -> Vec<ScalaHeader> {
        self.last_requested.store(count, Ordering::SeqCst);
        self.headers.clone()
    }
}

fn header(height: u32, timestamp: u64, pk: &str) -> ScalaHeader {
    ScalaHeader {
        extension_id: String::new(),
        difficulty: "1".to_string(),
        votes: String::new(),
        timestamp,
        size: 0,
        unparsed_bytes: String::new(),
        state_root: String::new(),
        height,
        n_bits: 0,
        version: 0,
        id: String::new(),
        ad_proofs_root: String::new(),
        transactions_root: String::new(),
        extension_hash: String::new(),
        pow_solutions: ScalaPowSolutions {
            pk: pk.to_string(),
            w: String::new(),
            n: String::new(),
            d: serde_json::Value::from(0),
        },
        ad_proofs_id: String::new(),
        transactions_id: String::new(),
        parent_id: String::new(),
    }
}

fn empty_info() -> ScalaInfo {
    ScalaInfo {
        last_mempool_update_time: 0,
        current_time: 0,
        network: String::new(),
        name: String::new(),
        state_type: String::new(),
        difficulty: 0,
        best_full_header_id: String::new(),
        best_header_id: String::new(),
        peers_count: 0,
        unconfirmed_count: 0,
        app_version: String::new(),
        eip37_supported: false,
        state_root: String::new(),
        genesis_block_id: String::new(),
        rest_api_url: None,
        previous_full_header_id: String::new(),
        full_height: 0,
        headers_height: 0,
        state_version: String::new(),
        full_blocks_score: 0,
        max_peer_height: 0,
        launch_time: 0,
        is_explorer: false,
        last_seen_message_time: 0,
        eip27_supported: false,
        headers_score: 0,
        parameters: Parameters {
            output_cost: 0,
            token_access_cost: 0,
            max_block_cost: 0,
            height: 0,
            max_block_size: 0,
            data_input_cost: 0,
            block_version: 0,
            input_cost: 0,
            storage_fee_factor: 0,
            subblocks_per_block: 0,
            min_value_per_byte: 0,
        },
        is_mining: false,
    }
}

fn build_app(chain: Arc<dyn NodeChainQuery>) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    router(read, Some(chain), None, None, NetworkPrefix::Mainnet)
}

async fn get(app: axum::Router, path: &str) -> (StatusCode, Vec<u8>) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec();
    (status, bytes)
}

async fn request(headers: Vec<ScalaHeader>, query: &str) -> (ApiMinerStats, u32) {
    let stub = Arc::new(StubChain::new(headers));
    let app = build_app(stub.clone());
    let (status, bytes) = get(app, &format!("/api/v1/mining/minerStats{query}")).await;
    assert_eq!(status, StatusCode::OK, "minerStats must answer 200");
    let stats: ApiMinerStats =
        serde_json::from_slice(&bytes).expect("body deserialises as ApiMinerStats");
    (stats, stub.last_requested.load(Ordering::SeqCst))
}

// ----- happy path -----

#[tokio::test]
async fn miner_stats_folds_by_pk_sorts_by_count_and_derives_addresses() {
    // Heights 100..=104: 2Miners mines 3 (last 104), pkB mines 2 (last 103).
    let pk_b = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let headers = vec![
        header(100, 1_000, PK_2MINERS),
        header(101, 2_000, pk_b),
        header(102, 3_000, PK_2MINERS),
        header(103, 4_000, pk_b),
        header(104, 5_000, PK_2MINERS),
    ];
    let (stats, _) = request(headers, "").await;
    assert_eq!(stats.tip_height, 104);
    assert_eq!(stats.blocks, 5);
    assert_eq!(stats.miners.len(), 2);
    // Sorted by count desc.
    assert_eq!(stats.miners[0].pk, PK_2MINERS);
    assert_eq!(stats.miners[0].count, 3);
    assert_eq!(stats.miners[0].last_height, 104);
    // Live-verified derivation vector.
    assert_eq!(stats.miners[0].address.as_deref(), Some(ADDR_2MINERS));
    assert_eq!(stats.miners[1].count, 2);
    assert_eq!(stats.miners[1].last_height, 103);
}

#[tokio::test]
async fn miner_stats_bad_pk_hex_degrades_to_absent_address() {
    let (stats, _) = request(vec![header(10, 1_000, "zz-not-hex")], "").await;
    assert_eq!(stats.miners.len(), 1);
    assert!(
        stats.miners[0].address.is_none(),
        "bad pk folds but gets no address"
    );
}

#[tokio::test]
async fn miner_stats_window_defaults_and_clamps() {
    assert_eq!(
        request(Vec::new(), "").await.1,
        720,
        "default window is 720"
    );
    assert_eq!(request(Vec::new(), "?window=128").await.1, 128);
    assert_eq!(
        request(Vec::new(), "?window=0").await.1,
        1,
        "clamps up to 1"
    );
    assert_eq!(
        request(Vec::new(), "?window=99999").await.1,
        16_384,
        "clamps to ceiling"
    );
    assert_eq!(
        request(Vec::new(), "?window=junk").await.1,
        720,
        "non-numeric falls back"
    );
}

#[tokio::test]
async fn miner_stats_empty_chain_yields_empty_stats() {
    let (stats, _) = request(Vec::new(), "").await;
    assert_eq!(stats.tip_height, 0);
    assert_eq!(stats.blocks, 0);
    assert!(stats.miners.is_empty());
}

// ----- error paths -----

#[tokio::test]
async fn miner_stats_absent_without_chain_reader_404s() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let app = router(read, None, None, None, NetworkPrefix::Mainnet);
    let (status, _) = get(app, "/api/v1/mining/minerStats").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "route rides the chain reader"
    );
}
