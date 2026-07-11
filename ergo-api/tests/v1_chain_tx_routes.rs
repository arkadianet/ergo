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
use ergo_api::traits::{
    BuiltChange, BuiltUnsigned, KeylessAsset, KeylessBuildRequest, MempoolView, NodeReadState,
    NodeSubmit, NodeTxBuilder, NoopMempoolView, SimulateConflict, SimulateOutcome, TxBuildError,
};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiTxSource,
    ApiWeightFunction, HealthStatus, SubmitError, SubmitMode, SyncStateLabel,
};
use ergo_api::v1::{v1_router, V1State};
use ergo_indexer_types::types::IndexedErgoTransaction;
use ergo_indexer_types::{
    BalanceDto, BoxId, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerQuery, IndexerStatus,
    Page, SortDir, TemplateHash, TokenId, TreeHash, TxId,
};
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
            reorgs_total: 0,
            last_reorg_depth: None,
            last_reorg_unix_ms: None,
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
    // Deterministic fee oracle for the `fee-estimate` tests: cheaper the longer
    // the wait, scaled by size (mirrors the real bucket monotonicity).
    fn pool_recommended_fee(&self, wait_time_minutes: u32, tx_size_bytes: u32) -> u64 {
        (10_000 / u64::from(wait_time_minutes.max(1))) * u64::from(tx_size_bytes)
    }
    // Fixed 2-block wait for the `status` eta tests (240s at a 120s interval).
    fn pool_expected_wait_time_ms(&self, _fee: u64, _tx_size_bytes: u32) -> u64 {
        240_000
    }
}

/// Headers dense at every height `1..=HEIGHT` (per-height synthetic ids), but
/// a body only at `HEIGHT` — models a node whose older block bodies are
/// pruned/missing while the header chain stays complete.
struct PrunedChain;
impl NodeChainQuery for PrunedChain {
    fn info(&self) -> ergo_api::compat::types::ScalaInfo {
        unreachable!("chain.info() is not on the v1 read path")
    }
    fn header_ids_at_height(&self, height: u32) -> Vec<String> {
        if height == HEIGHT {
            vec![block_id()]
        } else if (1..=HEIGHT).contains(&height) {
            vec![format!("{height:064x}")]
        } else {
            Vec::new()
        }
    }
    fn full_block_by_id(&self, header_id_hex: &str) -> Option<ScalaFullBlock> {
        (header_id_hex == block_id()).then(|| scala_full_block(true))
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
    read: Arc<dyn NodeReadState>,
    chain: Option<Arc<dyn NodeChainQuery>>,
    indexer: Option<Arc<dyn IndexerQuery>>,
    submit: Option<Arc<dyn NodeSubmit>>,
    tx_builder: Option<Arc<dyn NodeTxBuilder>>,
}
impl Default for Deps {
    fn default() -> Self {
        Deps {
            read: Arc::new(StubRead),
            chain: Some(Arc::new(StubChain {
                ad_proofs: true,
                proof: true,
            })),
            indexer: None,
            submit: None,
            tx_builder: None,
        }
    }
}

fn app(deps: Deps) -> Router {
    let mempool: Arc<dyn MempoolView> = Arc::new(NoopMempoolView::new());
    let state = V1State {
        read: deps.read,
        chain: deps.chain,
        indexer: deps.indexer,
        submit: deps.submit,
        tx_builder: deps.tx_builder,
        mempool,
        mempool_depth: Arc::new(ergo_api::v1::MempoolDepthRing::new()),
        emission: None,
        realtime: None,
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
async fn list_blocks_pruned_bodies_keep_paging_until_headers_end() {
    let pruned = || Deps {
        chain: Some(Arc::new(PrunedChain)),
        ..Deps::default()
    };
    // Page 1 (desc from tip=5, limit=2): heights [5,4]; only 5 has a body.
    // Pre-fix, the short page flipped has_more=false and ended the listing.
    let (status, body) = get(pruned(), "/api/v1/chain/blocks?limit=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert_eq!(body["page"]["has_more"], serde_json::json!(true));
    let cur = body["page"]["next_cursor"].as_str().unwrap().to_string();

    // Page 2: heights [3,2] — headers only; the page is empty but advances.
    let uri = format!("/api/v1/chain/blocks?limit=2&cursor={cur}");
    let (_, body) = get(pruned(), &uri).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    assert_eq!(body["page"]["has_more"], serde_json::json!(true));
    let cur = body["page"]["next_cursor"].as_str().unwrap().to_string();

    // Page 3: height [1], nothing beyond → the listing honestly ends.
    let uri = format!("/api/v1/chain/blocks?limit=2&cursor={cur}");
    let (_, body) = get(pruned(), &uri).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    assert_eq!(body["page"]["has_more"], serde_json::json!(false));
    assert!(body["page"]["next_cursor"].is_null());
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

// ===== tx-intelligence group (§3.6 Phase-2) ===============================
//
// build (stub keyless builder), simulate (stub non-mutating validate),
// fee-estimate (StubChain fee oracle), status (pooled / confirmed / unknown).

/// A valid mainnet P2PK address derived from the fixture pubkey — used as the
/// intent's required change address and an output recipient.
fn p2pk() -> String {
    ergo_ser::address::encode_p2pk_from_pubkey(
        NetworkPrefix::Mainnet,
        &hex::decode(MINER_PK).unwrap(),
    )
    .unwrap()
}

async fn post_json(
    deps: Deps,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    send(
        app(deps),
        Method::POST,
        uri,
        Body::from(serde_json::to_vec(&body).unwrap()),
    )
    .await
}

// ----- stub keyless builder -----------------------------------------------

struct StubBuilder {
    result: Result<BuiltUnsigned, TxBuildError>,
}
#[async_trait]
impl NodeTxBuilder for StubBuilder {
    async fn build_unsigned(
        &self,
        _request: KeylessBuildRequest,
    ) -> Result<BuiltUnsigned, TxBuildError> {
        self.result.clone()
    }
}

fn canned_built() -> BuiltUnsigned {
    BuiltUnsigned {
        unsigned_tx_bytes: vec![0xde, 0xad, 0xbe, 0xef],
        tx_id: tx_id(),
        input_box_ids: vec![format!("{:064x}", 1u32)],
        selected_value_nano_erg: 3_000_000_000,
        fee_nano_erg: 1_100_000,
        fee_source: "auto".to_string(),
        change: vec![BuiltChange {
            address: p2pk(),
            value_nano_erg: 1_899_000_000,
            assets: vec![KeylessAsset {
                token_id: format!("{:064x}", 9u32),
                amount: 5,
            }],
        }],
        size_bytes: 1240,
        estimated_cost_units: 84_213,
    }
}

/// A minimal well-formed send intent (box_ids inputs, one payment output).
fn send_intent() -> serde_json::Value {
    serde_json::json!({
        "inputs": { "type": "box_ids", "box_ids": [format!("{:064x}", 1u32)] },
        "outputs": [ { "type": "payment", "address": p2pk(), "value": "1000000000" } ],
        "change_address": p2pk(),
    })
}

// ----- stub non-mutating simulate -----------------------------------------

struct StubSimulate {
    outcome: Result<SimulateOutcome, SubmitError>,
}
#[async_trait]
impl NodeSubmit for StubSimulate {
    async fn submit_transaction(&self, _b: Vec<u8>, _m: SubmitMode) -> Result<String, SubmitError> {
        Err(SubmitError {
            reason: "internal_error".to_string(),
            detail: None,
        })
    }
    async fn submit_transaction_json(
        &self,
        _i: ergo_api::compat::types::ScalaTransactionInput,
        _m: SubmitMode,
    ) -> Result<String, SubmitError> {
        Err(SubmitError {
            reason: "internal_error".to_string(),
            detail: None,
        })
    }
    async fn simulate(&self, _b: Vec<u8>, _h: Option<u32>) -> Result<SimulateOutcome, SubmitError> {
        self.outcome.clone()
    }
}

fn canned_sim(valid: bool) -> SimulateOutcome {
    SimulateOutcome {
        tx_id: tx_id(),
        valid,
        cost_units: 84_213,
        max_block_cost: 8_000_000,
        size_bytes: 1240,
        fee_nano_erg: 1_100_000,
        min_fee_required_nano_erg: 1_088_000,
        fee_sufficient: valid,
        spends_unknown_inputs: false,
        conflicts: if valid {
            Vec::new()
        } else {
            vec![SimulateConflict {
                box_id: format!("{:064x}", 7u32),
                conflicting_tx_id: tx_id(),
            }]
        },
        warnings: Vec::new(),
    }
}

fn sim_body() -> serde_json::Value {
    serde_json::json!({ "tx": { "type": "bytes", "bytes": "00" } })
}

// ----- read stub that surfaces a pooled row -------------------------------

struct PoolRead {
    rows: Vec<ApiMempoolTransaction>,
}
impl NodeReadState for PoolRead {
    fn info(&self) -> ApiInfo {
        StubRead.info()
    }
    fn status(&self) -> ApiStatus {
        StubRead.status()
    }
    fn tip(&self) -> ApiTip {
        StubRead.tip()
    }
    fn sync(&self) -> ApiSyncStatus {
        StubRead.sync()
    }
    fn peers(&self) -> Vec<ApiPeer> {
        StubRead.peers()
    }
    fn mempool_summary(&self) -> ApiMempoolSummary {
        ApiMempoolSummary {
            size: self.rows.len() as u32,
            ..StubRead.mempool_summary()
        }
    }
    fn mempool_transactions(&self) -> ApiMempoolTransactions {
        ApiMempoolTransactions {
            transactions: self.rows.clone(),
            weight_function: ApiWeightFunction::Cost,
        }
    }
    fn mempool_transaction(&self, tx_id_hex: &str) -> Option<ApiMempoolTransaction> {
        self.rows.iter().find(|r| r.tx_id == tx_id_hex).cloned()
    }
    fn health(&self) -> ApiHealth {
        StubRead.health()
    }
}

fn pool_row(id: &str, weight: u64, fpb: u64, size: u32) -> ApiMempoolTransaction {
    ApiMempoolTransaction {
        tx_id: id.to_string(),
        fee_nano_erg: 1_100_000,
        fee_per_byte_nano_erg: fpb,
        size_bytes: size,
        validation_cost_units: 10,
        priority_weight: weight,
        source: ApiTxSource::Api,
        input_count: 1,
        output_count: 1,
        parents_in_pool: 0,
        first_seen_unix_ms: 1_600_000_000_000,
        first_seen_age_ms: 0,
        last_checked_age_ms: 0,
    }
}

// ----- minimal confirmed-tx indexer stub ----------------------------------

struct StubIndexer {
    tx: IndexedErgoTransaction,
}
impl IndexerQuery for StubIndexer {
    fn indexed_height(&self) -> u64 {
        self.tx.height.max(0) as u64
    }
    fn status(&self) -> IndexerStatus {
        IndexerStatus::CaughtUp
    }
    fn box_by_id(&self, _b: &BoxId) -> Option<IndexedBoxDto> {
        None
    }
    fn box_by_global_index(&self, _n: u64) -> Option<IndexedBoxDto> {
        None
    }
    fn boxes_by_global_range(&self, _l: u64, _h: u64) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn tx_by_id(&self, tx_id: &TxId) -> Option<IndexedTxDto> {
        (tx_id == &self.tx.id).then(|| self.tx.clone())
    }
    fn tx_by_global_index(&self, _n: u64) -> Option<IndexedTxDto> {
        None
    }
    fn txs_by_global_range(&self, _l: u64, _h: u64) -> Vec<IndexedTxDto> {
        Vec::new()
    }
    fn address_balance(&self, _t: &TreeHash) -> Option<BalanceDto> {
        None
    }
    fn address_txs_paged(&self, _t: &TreeHash, _p: Page, _d: SortDir) -> Vec<IndexedTxDto> {
        Vec::new()
    }
    fn address_boxes_paged(&self, _t: &TreeHash, _p: Page, _d: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_unspent_paged(&self, _t: &TreeHash, _p: Page, _d: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_total_txs(&self, _t: &TreeHash) -> u64 {
        0
    }
    fn address_total_boxes(&self, _t: &TreeHash) -> u64 {
        0
    }
    fn template_boxes_paged(&self, _t: &TemplateHash, _p: Page) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_unspent_paged(
        &self,
        _t: &TemplateHash,
        _p: Page,
        _d: SortDir,
    ) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_total_boxes(&self, _t: &TemplateHash) -> u64 {
        0
    }
    fn token_by_id(&self, _t: &TokenId) -> Option<IndexedTokenDto> {
        None
    }
    fn tokens_by_ids(&self, _ids: &[TokenId]) -> Vec<IndexedTokenDto> {
        Vec::new()
    }
    fn token_boxes_paged(&self, _t: &TokenId, _p: Page) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn token_unspent_paged(&self, _t: &TokenId, _p: Page, _d: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn token_total_boxes(&self, _t: &TokenId) -> u64 {
        0
    }
}

/// A confirmed tx at `HEIGHT` with empty IO (so the response never dereferences
/// a box). Its id is the all-`0x2a` digest → query with `"2a".repeat(32)`.
fn confirmed_tx_fixture() -> IndexedErgoTransaction {
    IndexedErgoTransaction {
        id: TxId::from_bytes([0x2a; 32]),
        index_in_block: 0,
        height: HEIGHT as i32,
        size: 256,
        global_index: 0,
        input_nums: Vec::new(),
        output_nums: Vec::new(),
        data_inputs: Vec::new(),
    }
}

// ----- build --------------------------------------------------------------

#[tokio::test]
async fn build_happy_path_returns_unsigned_tx_and_summary() {
    let deps = Deps {
        tx_builder: Some(Arc::new(StubBuilder {
            result: Ok(canned_built()),
        })),
        ..Deps::default()
    };
    let (status, body) = post_json(deps, "/api/v1/transactions/build", send_intent()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["unsigned_tx"]["type"], "bytes");
    assert_eq!(body["unsigned_tx"]["bytes"], "deadbeef");
    assert_eq!(body["tx_id"], tx_id());
    let sum = &body["summary"];
    assert_eq!(sum["selected_value"], "3000000000");
    assert_eq!(sum["fee"], "1100000");
    assert_eq!(sum["fee_source"], "auto");
    assert_eq!(sum["change"][0]["address"], p2pk());
    assert_eq!(sum["change"][0]["value"], "1899000000");
    assert_eq!(sum["change"][0]["assets"][0]["amount"], "5");
    assert_eq!(sum["size_bytes"], 1240);
    assert_eq!(sum["estimated_cost_units"], 84_213);
}

#[tokio::test]
async fn build_mint_output_is_unsupported_intent() {
    // Reaches the intent-shape gate before the builder — so no builder needed.
    let body = serde_json::json!({
        "inputs": { "type": "box_ids", "box_ids": [format!("{:064x}", 1u32)] },
        "outputs": [ { "type": "mint", "address": p2pk(), "amount": "1000" } ],
        "change_address": p2pk(),
    });
    let (status, body) = post_json(Deps::default(), "/api/v1/transactions/build", body).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(reason(&body), "unsupported_intent");
}

#[tokio::test]
async fn build_without_builder_is_route_unavailable() {
    // Default deps have no tx_builder wired — the honest deferral (G8/O7).
    let (status, body) =
        post_json(Deps::default(), "/api/v1/transactions/build", send_intent()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reason(&body), "route_unavailable");
}

#[tokio::test]
async fn build_invalid_change_address_is_invalid_address() {
    let body = serde_json::json!({
        "inputs": { "type": "box_ids", "box_ids": [format!("{:064x}", 1u32)] },
        "outputs": [ { "type": "payment", "address": p2pk(), "value": "1000000000" } ],
        "change_address": "not-an-address",
    });
    let (status, body) = post_json(Deps::default(), "/api/v1/transactions/build", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_address");
}

// ----- simulate -----------------------------------------------------------

#[tokio::test]
async fn simulate_accept_returns_valid_cost_report() {
    let deps = Deps {
        submit: Some(Arc::new(StubSimulate {
            outcome: Ok(canned_sim(true)),
        })),
        ..Deps::default()
    };
    let (status, body) = post_json(deps, "/api/v1/transactions/simulate", sim_body()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], true);
    assert_eq!(body["tx_id"], tx_id());
    assert_eq!(body["cost_units"], 84_213);
    assert_eq!(body["max_block_cost"], 8_000_000);
    assert_eq!(body["fee"], "1100000");
    assert_eq!(body["min_fee_required"], "1088000");
    assert_eq!(body["fee_sufficient"], true);
    assert_eq!(body["spends_unknown_inputs"], false);
    assert!(body["conflicts"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn simulate_reject_is_a_200_with_valid_false() {
    let deps = Deps {
        submit: Some(Arc::new(StubSimulate {
            outcome: Ok(canned_sim(false)),
        })),
        ..Deps::default()
    };
    let (status, body) = post_json(deps, "/api/v1/transactions/simulate", sim_body()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], false);
    assert_eq!(body["fee_sufficient"], false);
    assert_eq!(body["conflicts"][0]["box_id"], format!("{:064x}", 7u32));
    assert_eq!(body["conflicts"][0]["conflicting_tx_id"], tx_id());
}

#[tokio::test]
async fn simulate_without_submit_is_submit_disabled() {
    let (status, body) =
        post_json(Deps::default(), "/api/v1/transactions/simulate", sim_body()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reason(&body), "submit_disabled");
}

#[tokio::test]
async fn simulate_default_impl_is_route_unavailable() {
    // A submit bridge that does NOT override `simulate` falls through to the
    // trait default (route_disabled) → the honest 503 (G8 deferral).
    let deps = Deps {
        submit: Some(Arc::new(StubSubmit {
            result: Ok(tx_id()),
        })),
        ..Deps::default()
    };
    let (status, body) = post_json(deps, "/api/v1/transactions/simulate", sim_body()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reason(&body), "route_unavailable");
}

#[tokio::test]
async fn simulate_bad_hex_is_deserialize() {
    let deps = Deps {
        submit: Some(Arc::new(StubSimulate {
            outcome: Ok(canned_sim(true)),
        })),
        ..Deps::default()
    };
    let body = serde_json::json!({ "tx": { "type": "bytes", "bytes": "zz" } });
    let (status, body) = post_json(deps, "/api/v1/transactions/simulate", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "deserialize");
}

// ----- fee-estimate -------------------------------------------------------

#[tokio::test]
async fn fee_estimate_reports_string_tiers_and_floor() {
    let (status, body) = get(Deps::default(), "/api/v1/transactions/fee-estimate").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["target_blocks"], 3);
    assert_eq!(body["tx_size_bytes"], 200);
    // 3-block horizon: 6 min → (10000/6)*200 = 333200; fpb 333200/200 = 1666.
    assert_eq!(body["recommended_fee"], "333200");
    assert_eq!(body["fee_per_byte"], "1666");
    let tiers = body["tiers"].as_array().unwrap();
    assert_eq!(tiers.len(), 3);
    assert_eq!(tiers[0]["target_blocks"], 1);
    assert_eq!(tiers[1]["target_blocks"], 3);
    assert_eq!(tiers[2]["target_blocks"], 10);
    // Every fee field is a string (§1.1).
    assert!(tiers[0]["recommended_fee"].is_string());
    assert!(tiers[0]["fee_per_byte"].is_string());
    assert!(body["floor_fee_per_byte"].is_string());
    assert_eq!(body["pool_size"], 0);
}

#[tokio::test]
async fn fee_estimate_invalid_target_blocks_is_invalid_params() {
    let (status, body) = get(
        Deps::default(),
        "/api/v1/transactions/fee-estimate?target_blocks=2",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_params");
}

#[tokio::test]
async fn fee_estimate_without_chain_is_mempool_view_disabled() {
    let deps = Deps {
        chain: None,
        ..Deps::default()
    };
    let (status, body) = get(deps, "/api/v1/transactions/fee-estimate").await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reason(&body), "mempool_view_disabled");
}

// ----- status -------------------------------------------------------------

#[tokio::test]
async fn status_pending_reports_rank_and_eta() {
    let ours = tx_id();
    let rows = vec![
        pool_row(&ours, 100, 900, 200),
        pool_row(&format!("{:064x}", 200u32), 300, 1200, 150), // ahead of us
        pool_row(&format!("{:064x}", 3u32), 50, 400, 100),     // behind us
    ];
    let deps = Deps {
        read: Arc::new(PoolRead { rows }),
        ..Deps::default()
    };
    let (status, body) = get(deps, &format!("/api/v1/transactions/{ours}/status")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["state"], "pending");
    assert_eq!(body["tx_id"], ours);
    let pool = &body["pool"];
    assert_eq!(pool["rank"], 2);
    assert_eq!(pool["pool_size"], 3);
    assert_eq!(pool["ahead_of_you_bytes"], 150);
    assert_eq!(pool["fee"], "1100000");
    assert_eq!(pool["fee_per_byte"], "900");
    assert_eq!(pool["priority_weight"], "100");
    assert_eq!(pool["eta_ms"], 240_000);
    assert_eq!(pool["eta_blocks"], 2);
    assert!(body["first_seen_unix_ms"].is_u64());
    assert!(body["first_seen_iso"].is_string());
}

#[tokio::test]
async fn status_confirmed_reports_inclusion_height() {
    let deps = Deps {
        indexer: Some(Arc::new(StubIndexer {
            tx: confirmed_tx_fixture(),
        })),
        ..Deps::default()
    };
    let id = "2a".repeat(32);
    let (status, body) = get(deps, &format!("/api/v1/transactions/{id}/status")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["state"], "confirmed");
    assert_eq!(body["inclusion_height"], HEIGHT);
    assert_eq!(body["confirmations"], 0);
    assert!(body["header_id"].is_string());
}

#[tokio::test]
async fn status_unknown_id_is_a_200_unknown() {
    let id = format!("{:064x}", 999u32);
    let (status, body) = get(
        Deps::default(),
        &format!("/api/v1/transactions/{id}/status"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["state"], "unknown");
    assert_eq!(body["tx_id"], id);
}

#[tokio::test]
async fn status_malformed_id_is_invalid_tx_id() {
    let (status, body) = get(Deps::default(), "/api/v1/transactions/xyz/status").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_tx_id");
}
