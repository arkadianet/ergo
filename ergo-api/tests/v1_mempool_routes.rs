//! Route-level integration tests for the `mempool/*` v1 group (§3.8) — the
//! last read-gap group.
//!
//! Convention-lock: the `{items, page}` collection envelope, the keyset
//! `(priority_weight, tx_id)` cursor, flat-string `source`, string amounts, the
//! derived summary + O4 depth `history`, the `mempool_view_disabled` honest
//! reason when the filter bridge is absent, the fee-histogram band being
//! honestly `null`, and the O1 `submit/check` aliases behaving identically to
//! the canonical `transactions/{submit,check}` routes.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use ergo_api::compat::types::{ScalaFeeHistogramBin, ScalaInfo, ScalaMerkleProof};
use ergo_api::compat::NodeChainQuery;
use ergo_api::traits::{MempoolView, NodeReadState, NodeSubmit, NoopMempoolView, PoolTxDetail};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiTxSource,
    ApiWeightFunction, HealthStatus, SubmitError, SubmitMode, SyncStateLabel,
};
use ergo_api::v1::{v1_router, MempoolDepthRing, V1State};
use ergo_indexer_types::{BoxId, TxId};
use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::writer::VlqWriter;
use ergo_rest_json::types::{
    ScalaBlockSection, ScalaBlockTransactions, ScalaFullBlock, ScalaHeader, ScalaTransaction,
};
use ergo_ser::address::{encode_address_from_tree_bytes, NetworkPrefix};
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::token::Token;
use ergo_ser::transaction::{write_transaction, Transaction};
use std::collections::HashMap;
use tower::ServiceExt;

// ----- fixtures -----------------------------------------------------------

/// A valid ErgoTree (the fee proposition) — round-trips through address
/// encode/decode so `by-address` has a decodable input.
const TREE_HEX: &str = "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304";

fn id_a() -> String {
    "aa".repeat(32)
}
fn id_b() -> String {
    "bb".repeat(32)
}
fn id_c() -> String {
    "cc".repeat(32)
}

fn tx(
    id: String,
    weight: u64,
    fpb: u64,
    first_seen: u64,
    source: ApiTxSource,
) -> ApiMempoolTransaction {
    ApiMempoolTransaction {
        tx_id: id,
        fee_nano_erg: fpb * 100,
        fee_per_byte_nano_erg: fpb,
        size_bytes: 100,
        validation_cost_units: 42,
        priority_weight: weight,
        source,
        input_count: 1,
        output_count: 1,
        parents_in_pool: 0,
        first_seen_unix_ms: first_seen,
        first_seen_age_ms: 5,
        last_checked_age_ms: 1,
    }
}

/// Pool with three distinct-weight txs (A>B>C) covering three sources.
fn fixture_pool() -> Vec<ApiMempoolTransaction> {
    vec![
        tx(
            id_a(),
            300,
            30,
            1000,
            ApiTxSource::Peer {
                addr: "1.2.3.4:9030".into(),
            },
        ),
        tx(id_b(), 200, 20, 2000, ApiTxSource::Api),
        tx(id_c(), 100, 10, 3000, ApiTxSource::Wallet),
    ]
}

fn scala_tx(id: String) -> ScalaTransaction {
    ScalaTransaction {
        id,
        inputs: Vec::new(),
        data_inputs: Vec::new(),
        outputs: Vec::new(),
        size: 100,
    }
}

// ----- stubs --------------------------------------------------------------

struct StubRead;
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
        ApiStatus {
            sync_state: SyncStateLabel::AtTip,
            peer_count: 0,
            best_header_height: 5,
            best_full_block_height: 5,
            headers_ahead_of_full_blocks: 0,
            mempool_size: 3,
            snapshot_age_ms: 0,
            bootstrap: None,
            last_block_apply_error: None,
            block_apply_errors_total: 0,
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
            best_header_height: 5,
            best_full_block_height: 5,
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
            size: 3,
            total_bytes: 300,
            capacity_count: 1000,
            capacity_bytes: 1_000_000,
            revalidation_pending: 2,
        }
    }
    fn mempool_transactions(&self) -> ApiMempoolTransactions {
        ApiMempoolTransactions {
            transactions: fixture_pool(),
            weight_function: ApiWeightFunction::Cost,
        }
    }
    fn mempool_transaction(&self, tx_id_hex: &str) -> Option<ApiMempoolTransaction> {
        fixture_pool().into_iter().find(|t| t.tx_id == tx_id_hex)
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

/// Chain reader whose `by-*` hooks answer fixed matches; everything else is a
/// miss. `pool_txs_by_ergo_tree` → {A, C}; `by_box_id` → {B}; `by_token_id`
/// → {A}. The histogram returns two bins.
struct StubChain;
impl NodeChainQuery for StubChain {
    fn info(&self) -> ScalaInfo {
        unreachable!("chain.info() is not on the mempool read path")
    }
    fn header_ids_at_height(&self, _height: u32) -> Vec<String> {
        Vec::new()
    }
    fn full_block_by_id(&self, _id: &str) -> Option<ScalaFullBlock> {
        None
    }
    fn header_by_id(&self, _id: &str) -> Option<ScalaHeader> {
        None
    }
    fn block_transactions_by_id(&self, _id: &str) -> Option<ScalaBlockTransactions> {
        None
    }
    fn proof_for_tx(&self, _h: &str, _t: &str) -> Option<ScalaMerkleProof> {
        None
    }
    fn modifier_by_id(&self, _id: &str) -> Option<ScalaBlockSection> {
        None
    }
    fn pool_txs_by_ergo_tree(&self, _tree: &[u8]) -> Vec<ScalaTransaction> {
        vec![scala_tx(id_a()), scala_tx(id_c())]
    }
    fn pool_txs_by_box_id(&self, _box_id: &[u8; 32]) -> Vec<ScalaTransaction> {
        vec![scala_tx(id_b())]
    }
    fn pool_txs_by_token_id(&self, _token_id: &[u8; 32]) -> Vec<ScalaTransaction> {
        vec![scala_tx(id_a())]
    }
    fn pool_fee_histogram(&self, _bins: u32, _maxtime_ms: u64) -> Vec<ScalaFeeHistogramBin> {
        vec![
            ScalaFeeHistogramBin {
                n_txns: 2,
                total_fee: 4000,
            },
            ScalaFeeHistogramBin {
                n_txns: 1,
                total_fee: 1000,
            },
        ]
    }
}

struct StubSubmit {
    tx_id: String,
}
#[async_trait]
impl NodeSubmit for StubSubmit {
    async fn submit_transaction(&self, _b: Vec<u8>, _m: SubmitMode) -> Result<String, SubmitError> {
        Ok(self.tx_id.clone())
    }
    async fn submit_transaction_json(
        &self,
        _i: ergo_api::compat::types::ScalaTransactionInput,
        _m: SubmitMode,
    ) -> Result<String, SubmitError> {
        Err(SubmitError {
            reason: "internal_error".into(),
            detail: None,
        })
    }
}

// ----- harness ------------------------------------------------------------

fn app_full(
    chain: Option<Arc<dyn NodeChainQuery>>,
    submit: Option<Arc<dyn NodeSubmit>>,
    ring: Arc<MempoolDepthRing>,
) -> Router {
    let mempool: Arc<dyn MempoolView> = Arc::new(NoopMempoolView::new());
    let state = V1State {
        read: Arc::new(StubRead),
        chain,
        indexer: None,
        submit,
        tx_builder: None,
        mempool,
        mempool_depth: ring,
        emission: None,
        realtime: None,
        network: NetworkPrefix::Mainnet,
    };
    v1_router(
        state,
        ergo_api::v1::governor::Governor::new(Default::default()).expect("valid governor config"),
    )
}

fn app() -> Router {
    app_full(
        Some(Arc::new(StubChain)),
        None,
        Arc::new(MempoolDepthRing::new()),
    )
}

async fn get(app: Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

async fn post(app: Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header("content-type", "application/octet-stream")
                .body(Body::from(b"raw".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

fn ids(items: &serde_json::Value) -> Vec<String> {
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["tx_id"].as_str().unwrap().to_string())
        .collect()
}

// ----- summary -----

#[tokio::test]
async fn summary_has_utilization_weight_function_and_no_history_by_default() {
    let (status, body) = get(app(), "/api/v1/mempool/summary").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["size"].as_u64(), Some(3));
    assert_eq!(body["capacity_count"].as_u64(), Some(1000));
    assert_eq!(body["revalidation_pending"].as_u64(), Some(2));
    assert_eq!(body["weight_function"].as_str(), Some("cost"));
    // utilization = used/cap.
    assert_eq!(
        body["utilization"]["count_pct"].as_f64(),
        Some(3.0 / 1000.0)
    );
    assert_eq!(
        body["utilization"]["bytes_pct"].as_f64(),
        Some(300.0 / 1_000_000.0)
    );
    assert!(body.get("history").is_none(), "history omitted by default");
}

#[tokio::test]
async fn summary_history_exposes_the_o4_ring_oldest_first() {
    let ring = Arc::new(MempoolDepthRing::new());
    ring.push_observation(10, 1, 10, 1000, 1_000_000, 5, 0);
    ring.push_observation(20, 2, 20, 1000, 1_000_000, 6, 0);
    ring.push_observation(30, 3, 30, 1000, 1_000_000, 7, 0);
    let app = app_full(Some(Arc::new(StubChain)), None, ring);

    let (status, body) = get(app, "/api/v1/mempool/summary?history=2").await;
    assert_eq!(status, StatusCode::OK);
    let hist = body["history"].as_array().expect("history array");
    assert_eq!(hist.len(), 2, "trailing two samples");
    // oldest-first: the second-and-third pushes.
    assert_eq!(hist[0]["timestamp_unix_ms"].as_u64(), Some(20));
    assert_eq!(hist[1]["timestamp_unix_ms"].as_u64(), Some(30));
    assert!(hist[0]["timestamp_iso"].is_string());
    assert_eq!(
        hist[1]["min_fee_per_byte"].as_str(),
        Some("7"),
        "amount is a string"
    );
    assert_eq!(hist[1]["size"].as_u64(), Some(3));
}

// ----- transactions list -----

#[tokio::test]
async fn list_is_collection_of_mempool_tx_in_weight_order() {
    let (status, body) = get(app(), "/api/v1/mempool/transactions").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ids(&body["items"]), vec![id_a(), id_b(), id_c()]);
    assert_eq!(body["page"]["has_more"], serde_json::json!(false));
    assert!(body["page"]["next_cursor"].is_null());

    let a = &body["items"][0];
    assert_eq!(a["source"].as_str(), Some("peer"));
    assert_eq!(a["fee"].as_str(), Some("3000"));
    assert_eq!(a["fee_per_byte"].as_str(), Some("30"));
    assert_eq!(a["priority_weight"].as_str(), Some("300"));
    assert_eq!(a["validation_cost_units"].as_u64(), Some(42));
    assert!(a["first_seen_iso"].is_string());
}

#[tokio::test]
async fn list_order_first_seen_sorts_newest_first() {
    let (_s, body) = get(app(), "/api/v1/mempool/transactions?order=first_seen").await;
    // first_seen DESC: C(3000) > B(2000) > A(1000).
    assert_eq!(ids(&body["items"]), vec![id_c(), id_b(), id_a()]);
}

#[tokio::test]
async fn list_keyset_cursor_walks_without_gaps_or_dupes() {
    let (_s, p1) = get(app(), "/api/v1/mempool/transactions?limit=2").await;
    assert_eq!(ids(&p1["items"]), vec![id_a(), id_b()]);
    assert_eq!(p1["page"]["has_more"], serde_json::json!(true));
    let cursor = p1["page"]["next_cursor"].as_str().unwrap().to_string();

    let (_s, p2) = get(
        app(),
        &format!("/api/v1/mempool/transactions?limit=2&cursor={cursor}"),
    )
    .await;
    assert_eq!(ids(&p2["items"]), vec![id_c()]);
    assert_eq!(p2["page"]["has_more"], serde_json::json!(false));
    assert!(p2["page"]["next_cursor"].is_null());
}

#[tokio::test]
async fn list_rejects_bad_order_and_bad_cursor() {
    let (status, body) = get(app(), "/api/v1/mempool/transactions?order=nope").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["reason"].as_str(), Some("invalid_params"));

    let (status, body) = get(app(), "/api/v1/mempool/transactions?cursor=%21%21bad").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["reason"].as_str(), Some("invalid_cursor"));
}

// ----- transaction detail -----

#[tokio::test]
async fn detail_returns_row_plus_io_arrays() {
    let (status, body) = get(app(), &format!("/api/v1/mempool/transactions/{}", id_a())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tx_id"].as_str(), Some(id_a().as_str()));
    assert_eq!(body["source"].as_str(), Some("peer"));
    assert_eq!(body["priority_weight"].as_str(), Some("300"));
    // NoopMempoolView → no overlay → empty (but present) io arrays.
    assert_eq!(body["inputs"].as_array().map(|a| a.len()), Some(0));
    assert_eq!(body["outputs"].as_array().map(|a| a.len()), Some(0));
}

#[tokio::test]
async fn detail_absent_is_tx_not_found_and_bad_id_is_invalid_tx_id() {
    let (status, body) = get(
        app(),
        &format!("/api/v1/mempool/transactions/{}", "0".repeat(64)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["reason"].as_str(), Some("tx_not_found"));

    let (status, body) = get(app(), "/api/v1/mempool/transactions/xyz").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["reason"].as_str(), Some("invalid_tx_id"));
}

// ----- by-* -----

#[tokio::test]
async fn by_ergo_tree_filters_the_pool() {
    let (status, body) = get(app(), &format!("/api/v1/mempool/by-ergo-tree/{TREE_HEX}")).await;
    assert_eq!(status, StatusCode::OK);
    // Matches {A, C}, rendered in weight order.
    assert_eq!(ids(&body["items"]), vec![id_a(), id_c()]);
}

#[tokio::test]
async fn by_address_filters_the_pool() {
    let tree = hex::decode(TREE_HEX).unwrap();
    let addr = encode_address_from_tree_bytes(NetworkPrefix::Mainnet, &tree).unwrap();
    let (status, body) = get(app(), &format!("/api/v1/mempool/by-address/{addr}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ids(&body["items"]), vec![id_a(), id_c()]);
}

#[tokio::test]
async fn by_box_id_and_by_token_id_filter_the_pool() {
    let (_s, box_body) = get(
        app(),
        &format!("/api/v1/mempool/by-box-id/{}", "1".repeat(64)),
    )
    .await;
    assert_eq!(ids(&box_body["items"]), vec![id_b()]);

    let (_s, tok_body) = get(
        app(),
        &format!("/api/v1/mempool/by-token-id/{}", "2".repeat(64)),
    )
    .await;
    assert_eq!(ids(&tok_body["items"]), vec![id_a()]);
}

#[tokio::test]
async fn by_star_validates_inputs() {
    let (status, body) = get(app(), "/api/v1/mempool/by-box-id/xyz").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["reason"].as_str(), Some("invalid_box_id"));

    let (status, body) = get(app(), "/api/v1/mempool/by-token-id/xyz").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["reason"].as_str(), Some("invalid_token_id"));

    let (status, body) = get(app(), "/api/v1/mempool/by-ergo-tree/zz").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["reason"].as_str(), Some("invalid_ergo_tree"));

    let (status, body) = get(app(), "/api/v1/mempool/by-address/not-base58").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["reason"].as_str(), Some("invalid_address"));
}

#[tokio::test]
async fn by_star_is_mempool_view_disabled_without_chain_bridge() {
    let ring = Arc::new(MempoolDepthRing::new());
    let app = app_full(None, None, ring);
    let (status, body) = get(
        app,
        &format!("/api/v1/mempool/by-box-id/{}", "1".repeat(64)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body["error"]["reason"].as_str(),
        Some("mempool_view_disabled")
    );
}

// ----- fee-histogram -----

#[tokio::test]
async fn fee_histogram_indexes_bins_and_nulls_the_band() {
    let (status, body) = get(app(), "/api/v1/mempool/fee-histogram").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["weight_function"].as_str(), Some("cost"));
    let bins = body["bins"].as_array().unwrap();
    assert_eq!(bins.len(), 2);
    assert_eq!(bins[0]["index"].as_u64(), Some(0));
    assert_eq!(bins[0]["n_txns"].as_u64(), Some(2));
    assert_eq!(
        bins[0]["total_fee"].as_str(),
        Some("4000"),
        "amount is a string"
    );
    assert!(
        bins[0]["fee_per_byte_min"].is_null(),
        "band is honestly null"
    );
    assert!(bins[0]["fee_per_byte_max"].is_null());
    assert_eq!(bins[1]["index"].as_u64(), Some(1));
}

#[tokio::test]
async fn fee_histogram_is_mempool_view_disabled_without_chain_bridge() {
    let ring = Arc::new(MempoolDepthRing::new());
    let (status, body) = get(app_full(None, None, ring), "/api/v1/mempool/fee-histogram").await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body["error"]["reason"].as_str(),
        Some("mempool_view_disabled")
    );
}

// ----- O1 submit/check aliases -----

#[tokio::test]
async fn submit_and_check_aliases_match_the_canonical_routes() {
    let tx_id = "cd".repeat(32);
    let submit: Arc<dyn NodeSubmit> = Arc::new(StubSubmit {
        tx_id: tx_id.clone(),
    });

    for (alias, canonical) in [
        ("/api/v1/mempool/submit", "/api/v1/transactions/submit"),
        ("/api/v1/mempool/check", "/api/v1/transactions/check"),
    ] {
        let ring = Arc::new(MempoolDepthRing::new());
        let a = app_full(
            Some(Arc::new(StubChain)),
            Some(submit.clone()),
            ring.clone(),
        );
        let (sa, ba) = post(a, alias).await;
        let c = app_full(Some(Arc::new(StubChain)), Some(submit.clone()), ring);
        let (sc, bc) = post(c, canonical).await;
        assert_eq!(sa, StatusCode::OK);
        assert_eq!(sa, sc, "{alias} status must match {canonical}");
        assert_eq!(ba, bc, "{alias} body must match {canonical}");
        assert_eq!(ba["tx_id"].as_str(), Some(tx_id.as_str()));
    }
}

#[tokio::test]
async fn submit_alias_without_bridge_is_submit_disabled() {
    let ring = Arc::new(MempoolDepthRing::new());
    let (status, body) = post(
        app_full(Some(Arc::new(StubChain)), None, ring),
        "/api/v1/mempool/submit",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["reason"].as_str(), Some("submit_disabled"));
}

// ----- cursor/order fail-closed (CodeRabbit #171 finding 4) ----------------

#[tokio::test]
async fn cursor_from_one_order_is_rejected_when_replayed_against_another() {
    // A page-1 cursor issued under `weight` carries the order it was minted
    // for. Replaying it against a different `?order=` must fail closed with
    // `invalid_cursor` (not silently skip/dupe under the new sort).
    let (_s, p1) = get(app(), "/api/v1/mempool/transactions?limit=2&order=weight").await;
    let cursor = p1["page"]["next_cursor"].as_str().unwrap().to_string();

    let (status, body) = get(
        app(),
        &format!("/api/v1/mempool/transactions?limit=2&order=fee_per_byte&cursor={cursor}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["reason"].as_str(), Some("invalid_cursor"));

    // Same order replays cleanly.
    let (status, _b) = get(
        app(),
        &format!("/api/v1/mempool/transactions?limit=2&order=weight&cursor={cursor}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ----- populated tx-detail io resolution (CodeRabbit #171 finding 12) ------

/// `MempoolView` that hands back one pooled tx's wire bytes + its pool-output
/// overlay for a single `tx_id` (the tx-detail seam); every other accessor is
/// an empty pool.
struct StubMempool {
    tx_id: TxId,
    bytes: Arc<[u8]>,
    pool_outputs: Arc<HashMap<BoxId, ErgoBox>>,
}

impl MempoolView for StubMempool {
    fn is_spent_by_pool(&self, _box_id: &BoxId) -> bool {
        false
    }
    fn pool_spending_tx(&self, _box_id: &BoxId) -> Option<TxId> {
        None
    }
    fn pool_outputs(&self) -> Arc<HashMap<BoxId, ErgoBox>> {
        self.pool_outputs.clone()
    }
    fn pool_tx_detail(&self, tx_id: &TxId) -> Option<PoolTxDetail> {
        (tx_id == &self.tx_id).then(|| (self.bytes.clone(), self.pool_outputs.clone()))
    }
}

fn app_with_mempool(mempool: Arc<dyn MempoolView>) -> Router {
    let state = V1State {
        read: Arc::new(StubRead),
        chain: Some(Arc::new(StubChain)),
        indexer: None,
        submit: None,
        tx_builder: None,
        mempool,
        mempool_depth: Arc::new(MempoolDepthRing::new()),
        emission: None,
        realtime: None,
        network: NetworkPrefix::Mainnet,
    };
    v1_router(
        state,
        ergo_api::v1::governor::Governor::new(Default::default()).expect("valid governor config"),
    )
}

/// Minimal always-true (`SBoolean` const) script tree — encodes to a valid P2S
/// address so io projection yields a non-null address.
fn true_tree() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: true,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
        },
    }
}

fn candidate(value: u64, tokens: Vec<Token>) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(
        value,
        true_tree(),
        100,
        tokens,
        AdditionalRegisters::empty(),
    )
    .unwrap()
}

fn input(box_id_fill: u8) -> Input {
    Input {
        box_id: Digest32::from_bytes([box_id_fill; 32]),
        spending_proof: SpendingProof::new(vec![0xDE, 0xAD], ContextExtension::empty()).unwrap(),
    }
}

#[tokio::test]
async fn detail_with_populated_view_renders_real_io_boxes() {
    // Pooled tx id_a spends box 0xA1 (resolvable via the pool overlay) and
    // emits one output carrying a token. With a populated MempoolView the
    // detail must render real io_box inputs/outputs, not the Noop empty case.
    let token = Token {
        token_id: Digest32::from_bytes([0x07; 32]),
        amount: 42,
    };
    let tx = Transaction {
        inputs: vec![input(0xA1)],
        data_inputs: vec![],
        output_candidates: vec![candidate(5_000_000, vec![token])],
    };
    let mut w = VlqWriter::new();
    write_transaction(&mut w, &tx).unwrap();
    let bytes: Arc<[u8]> = Arc::from(w.result());

    let mut overlay: HashMap<BoxId, ErgoBox> = HashMap::new();
    overlay.insert(
        Digest32::from_bytes([0xA1; 32]),
        ErgoBox {
            candidate: candidate(3_000_000, vec![]),
            transaction_id: ModifierId::from_bytes([0xCC; 32]),
            index: 0,
        },
    );

    // id_a() is "aa"*32 → raw [0xAA; 32]; StubRead returns its pool row.
    let tx_id = TxId::from_bytes([0xAA; 32]);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempool {
        tx_id,
        bytes,
        pool_outputs: Arc::new(overlay),
    });

    let (status, body) = get(
        app_with_mempool(mempool),
        &format!("/api/v1/mempool/transactions/{}", id_a()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["tx_id"].as_str(), Some(id_a().as_str()));

    // Output resolves: string value + a non-null address + the token asset.
    let outs = body["outputs"].as_array().expect("outputs array");
    assert_eq!(outs.len(), 1);
    assert_eq!(outs[0]["value"].as_str(), Some("5000000"));
    assert!(outs[0]["address"].is_string(), "output address: {body}");
    let assets = outs[0]["assets"].as_array().expect("assets array");
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0]["amount"].as_str(), Some("42"));

    // Input A resolves via the pool overlay → real value + address.
    let ins = body["inputs"].as_array().expect("inputs array");
    assert_eq!(ins.len(), 1);
    assert_eq!(ins[0]["value"].as_str(), Some("3000000"));
    assert!(ins[0]["address"].is_string(), "input address: {body}");
}
