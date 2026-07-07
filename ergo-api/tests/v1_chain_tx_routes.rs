//! Route-level integration tests for the first v1 group: `chain/*` +
//! `transactions/*` reads (`dev-docs/v1-api-design.md` §3.5–§3.6).
//!
//! These are the convention-lock tests: they assert the exact snake_case field
//! names from the design's example responses, the `{items, page}` collection
//! envelope, the `{error:{reason,message,detail}}` error envelope with the
//! canonical `reason`, and the honest `*_unavailable` / `*_disabled` gating —
//! so every later group copies a verified template. Handlers are driven via
//! `oneshot` over stub reader traits + `v1_router`.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use ergo_api::compat::types::ScalaMerkleProof;
use ergo_api::compat::NodeChainQuery;
use ergo_api::traits::{MempoolView, NodeReadState, NodeSubmit, NoopMempoolView};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SubmitError, SubmitMode, SyncStateLabel,
};
use ergo_api::v1::{v1_router, V1State};
use ergo_indexer_types::IndexerQuery;
use ergo_rest_json::types::{
    ScalaAdProofs, ScalaBlockSection, ScalaBlockTransactions, ScalaDataInput, ScalaExtension,
    ScalaFullBlock, ScalaHeader, ScalaInput, ScalaOutput, ScalaPowSolutions, ScalaSpendingProof,
    ScalaTransaction,
};
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

// ----- fixtures -----------------------------------------------------------

const HEIGHT: u32 = 5;
/// Canonical fixture header id (64 lowercase hex).
fn block_id() -> String {
    format!("{HEIGHT:064x}")
}
fn tx_id() -> String {
    format!("{:064x}", 42u32)
}
/// A real 33-byte compressed pubkey so miner-address derivation succeeds.
const MINER_PK: &str = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";
/// A valid ErgoTree (the fee proposition) — parses for address derivation.
const TREE_HEX: &str = "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304";

fn scala_header() -> ScalaHeader {
    ScalaHeader {
        extension_id: format!("{:064x}", 0xe1u32),
        difficulty: "123456789".to_string(),
        votes: "000000".to_string(),
        timestamp: 1_600_000_000_123,
        size: 210,
        unparsed_bytes: String::new(),
        state_root: format!("{:064x}", 0x57u32),
        height: HEIGHT,
        n_bits: 83_886_080,
        version: 3,
        id: block_id(),
        ad_proofs_root: format!("{:064x}", 0xadu32),
        transactions_root: format!("{:064x}", 0x7au32),
        extension_hash: format!("{:064x}", 0xe4u32),
        pow_solutions: ScalaPowSolutions {
            pk: MINER_PK.to_string(),
            w: "03".to_string(),
            n: "0000000000000000".to_string(),
            d: serde_json::Value::from(0),
        },
        ad_proofs_id: format!("{:064x}", 0xa1u32),
        transactions_id: format!("{:064x}", 0x71u32),
        parent_id: format!("{:064x}", HEIGHT - 1),
    }
}

fn scala_output() -> ScalaOutput {
    ScalaOutput {
        box_id: format!("{:064x}", 0xb0u32),
        value: 1_000_000_000,
        ergo_tree: TREE_HEX.to_string(),
        assets: Vec::new(),
        creation_height: HEIGHT,
        additional_registers: Default::default(),
        transaction_id: tx_id(),
        index: 0,
    }
}

fn scala_tx() -> ScalaTransaction {
    ScalaTransaction {
        id: tx_id(),
        inputs: vec![ScalaInput {
            box_id: format!("{:064x}", 0xc0u32),
            spending_proof: ScalaSpendingProof {
                proof_bytes: "abcd".to_string(),
                extension: Default::default(),
            },
        }],
        data_inputs: vec![ScalaDataInput {
            box_id: format!("{:064x}", 0xd0u32),
        }],
        outputs: vec![scala_output()],
        size: 200,
    }
}

fn scala_full_block(with_ad_proofs: bool) -> ScalaFullBlock {
    ScalaFullBlock {
        header: scala_header(),
        block_transactions: ScalaBlockTransactions {
            header_id: block_id(),
            transactions: vec![scala_tx()],
            block_version: 3,
            size: 250,
        },
        extension: ScalaExtension {
            header_id: block_id(),
            digest: format!("{:064x}", 0xeeu32),
            fields: vec![["00".to_string(), "0142".to_string()]],
        },
        ad_proofs: with_ad_proofs.then(|| ScalaAdProofs {
            header_id: block_id(),
            proof_bytes: "ffff".to_string(),
            digest: format!("{:064x}", 0xaau32),
            size: 100,
        }),
        size: 8421,
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
            best_header_height: HEIGHT,
            best_full_block_height: HEIGHT,
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

/// Answers the fixture block/header/tx at `HEIGHT`; everything else is a miss.
struct StubChain {
    ad_proofs: bool,
    proof: bool,
}
impl NodeChainQuery for StubChain {
    fn info(&self) -> ergo_api::compat::types::ScalaInfo {
        unreachable!("chain.info() is not on the v1 read path")
    }
    fn header_ids_at_height(&self, height: u32) -> Vec<String> {
        if height == HEIGHT {
            vec![block_id()]
        } else {
            Vec::new()
        }
    }
    fn full_block_by_id(&self, header_id_hex: &str) -> Option<ScalaFullBlock> {
        (header_id_hex == block_id()).then(|| scala_full_block(self.ad_proofs))
    }
    fn header_by_id(&self, header_id_hex: &str) -> Option<ScalaHeader> {
        (header_id_hex == block_id()).then(scala_header)
    }
    fn block_transactions_by_id(&self, header_id_hex: &str) -> Option<ScalaBlockTransactions> {
        (header_id_hex == block_id()).then(|| scala_full_block(true).block_transactions)
    }
    fn proof_for_tx(&self, header_id_hex: &str, tx_id_hex: &str) -> Option<ScalaMerkleProof> {
        if self.proof && header_id_hex == block_id() && tx_id_hex == tx_id() {
            Some(ScalaMerkleProof {
                leaf_data: tx_id(),
                levels: vec![("11".to_string(), 0), ("22".to_string(), 1)],
            })
        } else {
            None
        }
    }
    fn modifier_by_id(&self, modifier_id_hex: &str) -> Option<ScalaBlockSection> {
        (modifier_id_hex == block_id()).then(|| ScalaBlockSection::Header(Box::new(scala_header())))
    }
}

struct StubSubmit {
    result: Result<String, SubmitError>,
}
#[async_trait]
impl NodeSubmit for StubSubmit {
    async fn submit_transaction(
        &self,
        _bytes: Vec<u8>,
        _mode: SubmitMode,
    ) -> Result<String, SubmitError> {
        match &self.result {
            Ok(s) => Ok(s.clone()),
            Err(e) => Err(SubmitError {
                reason: e.reason.clone(),
                detail: e.detail.clone(),
            }),
        }
    }
    async fn submit_transaction_json(
        &self,
        _input: ergo_api::compat::types::ScalaTransactionInput,
        _mode: SubmitMode,
    ) -> Result<String, SubmitError> {
        Err(SubmitError {
            reason: "internal_error".to_string(),
            detail: None,
        })
    }
}

// ----- harness ------------------------------------------------------------

struct Deps {
    chain: Option<Arc<dyn NodeChainQuery>>,
    indexer: Option<Arc<dyn IndexerQuery>>,
    submit: Option<Arc<dyn NodeSubmit>>,
}
impl Default for Deps {
    fn default() -> Self {
        Deps {
            chain: Some(Arc::new(StubChain {
                ad_proofs: true,
                proof: true,
            })),
            indexer: None,
            submit: None,
        }
    }
}

fn app(deps: Deps) -> Router {
    let mempool: Arc<dyn MempoolView> = Arc::new(NoopMempoolView::new());
    let state = V1State {
        read: Arc::new(StubRead),
        chain: deps.chain,
        indexer: deps.indexer,
        submit: deps.submit,
        mempool,
        mempool_depth: Arc::new(ergo_api::v1::MempoolDepthRing::new()),
        network: NetworkPrefix::Mainnet,
    };
    let governor =
        ergo_api::v1::governor::Governor::new(Default::default()).expect("valid governor config");
    v1_router(state, governor)
}

async fn send(
    app: Router,
    method: Method,
    uri: &str,
    body: Body,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        // `by-ids` uses a JSON-array body (the `Json` extractor requires the
        // content-type); the octet-stream `Bytes` submit/check extractor
        // ignores it, so setting it uniformly is harmless.
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(body)
        .unwrap();
    // Loopback peer → governor-exempt, so tests never flake on rate limits.
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

async fn get(deps: Deps, uri: &str) -> (StatusCode, serde_json::Value) {
    send(app(deps), Method::GET, uri, Body::empty()).await
}

fn reason(v: &serde_json::Value) -> &str {
    v["error"]["reason"].as_str().unwrap_or("<none>")
}

// ----- chain/blocks -------------------------------------------------------

#[tokio::test]
async fn block_by_id_returns_bare_object_with_glossary_field_names() {
    let (status, body) = get(
        Deps::default(),
        &format!("/api/v1/chain/blocks/{}", block_id()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for key in [
        "header_id",
        "height",
        "parent_id",
        "timestamp_unix_ms",
        "timestamp_iso",
        "version",
        "difficulty",
        "n_bits",
        "votes",
        "state_root",
        "ad_proofs_root",
        "transactions_root",
        "extension_id",
        "extension_hash",
        "size_bytes",
        "miner_pk",
        "miner_address",
        "transactions",
        "extension",
        "ad_proofs",
    ] {
        assert!(body.get(key).is_some(), "missing field {key}: {body}");
    }
    // No camelCase / Scala leakage.
    assert!(body.get("adProofsRoot").is_none());
    assert!(body.get("size").is_none());
    // Value discipline: difficulty is a string, size_bytes is the block size.
    assert_eq!(body["difficulty"], serde_json::json!("123456789"));
    assert_eq!(body["size_bytes"].as_u64(), Some(8421));
    assert_eq!(
        body["timestamp_iso"],
        serde_json::json!("2020-09-13T12:26:40.123Z")
    );
    assert!(body["miner_address"].is_string());
    // Embedded block tx: outputs are boxes with string value + assets.
    let out = &body["transactions"][0]["outputs"][0];
    assert_eq!(out["value"], serde_json::json!("1000000000"));
    assert!(out["box_id"].is_string());
    assert_eq!(out["confirmed"], serde_json::json!(true));
    // ad_proofs section present + renamed.
    assert!(body["ad_proofs"]["proof_bytes"].is_string());
}

#[tokio::test]
async fn block_by_id_unknown_is_block_not_found() {
    let (status, body) = get(
        Deps::default(),
        &format!("/api/v1/chain/blocks/{:064x}", 999u32),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(reason(&body), "block_not_found");
}

#[tokio::test]
async fn block_by_id_malformed_is_invalid_hex() {
    let (status, body) = get(Deps::default(), "/api/v1/chain/blocks/NOTHEX").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_hex");
}

#[tokio::test]
async fn chain_reads_without_chain_reader_are_unavailable() {
    let deps = Deps {
        chain: None,
        ..Deps::default()
    };
    let (status, body) = get(deps, "/api/v1/chain/blocks").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reason(&body), "chain_reader_unavailable");
}

#[tokio::test]
async fn list_blocks_returns_collection_envelope() {
    let (status, body) = get(Deps::default(), "/api/v1/chain/blocks").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["items"].is_array());
    let page = &body["page"];
    for key in ["limit", "next_cursor", "has_more"] {
        assert!(page.get(key).is_some(), "page missing {key}");
    }
    assert_eq!(page["limit"].as_u64(), Some(25)); // default cap
                                                  // Single fixture block at HEIGHT → one summary, no further page.
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert_eq!(page["has_more"], serde_json::json!(false));
    assert!(page["next_cursor"].is_null());
    let item = &body["items"][0];
    assert_eq!(item["height"].as_u64(), Some(HEIGHT as u64));
    assert_eq!(item["transaction_count"].as_u64(), Some(1));
    assert!(item.get("delivered_by").is_some()); // present, null
    assert!(item["delivered_by"].is_null());
}

#[tokio::test]
async fn list_blocks_bad_order_is_invalid_sort_direction() {
    let (status, body) = get(Deps::default(), "/api/v1/chain/blocks?order=sideways").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_sort_direction");
}

#[tokio::test]
async fn list_blocks_tampered_cursor_is_invalid_cursor() {
    let (status, body) = get(Deps::default(), "/api/v1/chain/blocks?cursor=!!!bad").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_cursor");
}

#[tokio::test]
async fn blocks_at_height_is_single_page_id_collection() {
    let (status, body) = get(
        Deps::default(),
        &format!("/api/v1/chain/blocks/at-height/{HEIGHT}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0], serde_json::json!(block_id()));
    assert_eq!(body["page"]["has_more"], serde_json::json!(false));
}

#[tokio::test]
async fn block_transactions_is_single_page_collection() {
    let (status, body) = get(
        Deps::default(),
        &format!("/api/v1/chain/blocks/{}/transactions", block_id()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["tx_id"], serde_json::json!(tx_id()));
    assert_eq!(body["page"]["has_more"], serde_json::json!(false));
}

#[tokio::test]
async fn blocks_by_ids_over_cap_is_too_many_ids() {
    let ids: Vec<String> = (0..201u32).map(|i| format!("{i:064x}")).collect();
    let (status, body) = send(
        app(Deps::default()),
        Method::POST,
        "/api/v1/chain/blocks/by-ids",
        Body::from(serde_json::to_vec(&ids).unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(reason(&body), "too_many_ids");
}

#[tokio::test]
async fn blocks_by_ids_returns_full_blocks_in_order() {
    let ids = vec![block_id()];
    let (status, body) = send(
        app(Deps::default()),
        Method::POST,
        "/api/v1/chain/blocks/by-ids",
        Body::from(serde_json::to_vec(&ids).unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["header_id"], serde_json::json!(block_id()));
    assert_eq!(body["page"]["has_more"], serde_json::json!(false));
}

// ----- chain/headers ------------------------------------------------------

#[tokio::test]
async fn list_headers_returns_header_objects() {
    let (status, body) = get(Deps::default(), "/api/v1/chain/headers").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["page"]["limit"].as_u64(), Some(100)); // header default
    let item = &body["items"][0];
    assert_eq!(item["header_id"], serde_json::json!(block_id()));
    assert!(item.get("transactions").is_none()); // header object, not full block
    assert!(item["size_bytes"].as_u64().is_some());
}

#[tokio::test]
async fn header_by_id_unknown_is_header_not_found() {
    let (status, body) = get(
        Deps::default(),
        &format!("/api/v1/chain/headers/{:064x}", 999u32),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(reason(&body), "header_not_found");
}

#[tokio::test]
async fn headers_at_height_returns_full_header_objects() {
    let (status, body) = get(
        Deps::default(),
        &format!("/api/v1/chain/headers/at-height/{HEIGHT}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["header_id"], serde_json::json!(block_id()));
}

// ----- chain/modifiers + proofs ------------------------------------------

#[tokio::test]
async fn modifier_by_id_carries_kind_discriminant() {
    let (status, body) = get(
        Deps::default(),
        &format!("/api/v1/chain/modifiers/{}", block_id()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["kind"], serde_json::json!("header"));
    assert_eq!(body["data"]["header_id"], serde_json::json!(block_id()));
}

#[tokio::test]
async fn block_ad_proofs_present() {
    let (status, body) = get(
        Deps::default(),
        &format!("/api/v1/chain/proofs/{}", block_id()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for key in ["header_id", "proof_bytes", "digest", "size_bytes"] {
        assert!(body.get(key).is_some(), "missing {key}");
    }
}

#[tokio::test]
async fn block_ad_proofs_pruned_is_ad_proofs_unavailable() {
    let deps = Deps {
        chain: Some(Arc::new(StubChain {
            ad_proofs: false,
            proof: true,
        })),
        ..Deps::default()
    };
    let (status, body) = get(deps, &format!("/api/v1/chain/proofs/{}", block_id())).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reason(&body), "ad_proofs_unavailable");
}

#[tokio::test]
async fn proof_for_tx_renders_left_right_sides() {
    let (status, body) = get(
        Deps::default(),
        &format!(
            "/api/v1/chain/proofs/{}/transactions/{}",
            block_id(),
            tx_id()
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tx_id"], serde_json::json!(tx_id()));
    assert_eq!(body["levels"][0]["side"], serde_json::json!("left"));
    assert_eq!(body["levels"][1]["side"], serde_json::json!("right"));
    assert_eq!(body["levels"][0]["sibling"], serde_json::json!("11"));
}

#[tokio::test]
async fn proof_for_tx_miss_is_tx_not_in_block() {
    let deps = Deps {
        chain: Some(Arc::new(StubChain {
            ad_proofs: true,
            proof: false,
        })),
        ..Deps::default()
    };
    let (status, body) = get(
        deps,
        &format!(
            "/api/v1/chain/proofs/{}/transactions/{}",
            block_id(),
            tx_id()
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(reason(&body), "tx_not_in_block");
}

// ----- transactions -------------------------------------------------------

#[tokio::test]
async fn tx_by_id_without_indexer_is_indexer_disabled() {
    let (status, body) = get(
        Deps::default(),
        &format!("/api/v1/transactions/{}", tx_id()),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reason(&body), "indexer_disabled");
}

#[tokio::test]
async fn tx_by_id_malformed_is_invalid_tx_id() {
    let (status, body) = get(Deps::default(), "/api/v1/transactions/NOTHEX").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_tx_id");
}

#[tokio::test]
async fn submit_without_bridge_is_submit_disabled() {
    let (status, body) = send(
        app(Deps::default()),
        Method::POST,
        "/api/v1/transactions/submit",
        Body::from(vec![1, 2, 3]),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reason(&body), "submit_disabled");
}

#[tokio::test]
async fn submit_ok_returns_tx_id() {
    let deps = Deps {
        submit: Some(Arc::new(StubSubmit {
            result: Ok("deadbeef".to_string()),
        })),
        ..Deps::default()
    };
    let (status, body) = send(
        app(deps),
        Method::POST,
        "/api/v1/transactions/submit",
        Body::from(vec![1, 2, 3]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tx_id"], serde_json::json!("deadbeef"));
}

#[tokio::test]
async fn submit_rejection_maps_to_v1_envelope() {
    let deps = Deps {
        submit: Some(Arc::new(StubSubmit {
            result: Err(SubmitError {
                reason: "double_spend".to_string(),
                detail: Some("input already spent".to_string()),
            }),
        })),
        ..Deps::default()
    };
    let (status, body) = send(
        app(deps),
        Method::POST,
        "/api/v1/transactions/check",
        Body::from(vec![9]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "double_spend");
    assert_eq!(
        body["error"]["detail"],
        serde_json::json!("input already spent")
    );
    assert!(body["error"]["message"].is_string());
}
