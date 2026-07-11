//! `GET /blockchain/block/byHeaderId/{headerId}` and
//! `POST /blockchain/block/byHeaderIds` — the block-reassembly routes
//! (#21, #22).
//!
//! What this file pins:
//! - The status gate fronts both routes via the layered middleware:
//!   `Syncing` → 503 `indexer-syncing`, `Halted` → 503 `indexer-halted`.
//!   POST is gated before the JSON body is parsed.
//! - Path-param parsing on #21 mirrors the byTemplateHash / byTokenId
//!   path-matcher parity: bad hex → 404 `block not found`, not 400.
//! - Chain miss (`full_block_by_id` returns `None`) → 404 on #21, drop
//!   on #22 (Scala flatMap parity).
//! - Inner-tx miss (chain has block but indexer is missing one of its
//!   txs) → 404 on #21, drop on #22 — surfaces as "block not yet
//!   queryable in indexed form" rather than 500. Keeps the API
//!   contract honest during the indexer-lag window where chain has
//!   advanced past `indexed_height`.
//! - Wire shape: `{ header, blockTransactions, extension, adProofs,
//!   size }` with `blockTransactions = { headerId, transactions, size }`
//!   and per-tx `IndexedErgoTransactionResponse` rows.
//! - POST batch: malformed hex ids dropped at parse step (Scala
//!   flatMap parity), unknown ids dropped at lookup step, output
//!   preserves input order minus drops.
//!
//! Test wiring: gate / 404 cases reuse `IndexerHandle::syncing()` and
//! `IndexerHandle::halted()` (store-less). Happy-path cases use
//! `StubIndexer` + `StubChain` so we can inject a fixture full block
//! plus matching indexer txs without a real `IndexerStore` / chain redb.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use ergo_api::compat::traits::NodeChainQuery;
use ergo_api::compat::types::{
    Parameters, ScalaAdProofs, ScalaBlockTransactions, ScalaExtension, ScalaFullBlock, ScalaHeader,
    ScalaInfo, ScalaPowSolutions, ScalaTransaction,
};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_indexer::{
    BalanceDto, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerHaltReason, IndexerHandle,
    IndexerQuery, IndexerStatus, Page, SortDir,
};
use ergo_indexer_types::types::IndexedErgoTransaction;
use ergo_indexer_types::{BoxId, TemplateHash, TokenId, TreeHash, TxId};
use http_body_util::BodyExt;
use tower::ServiceExt;

const HEX_64_AA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HEX_64_BB: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HEX_64_CC: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const TX_HEX_AA: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const TX_HEX_BB: &str = "2222222222222222222222222222222222222222222222222222222222222222";

// ---------- gate: Syncing → 503 indexer-syncing -------------------------

#[tokio::test]
async fn block_by_header_id_503_indexer_syncing() {
    let app = build_app(syncing_handle(500), Some(empty_chain()));
    let (status, body) = json_get(app, &format!("/blockchain/block/byHeaderId/{HEX_64_AA}")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-syncing");
}

#[tokio::test]
async fn blocks_by_header_ids_503_indexer_syncing() {
    let app = build_app(syncing_handle(0), Some(empty_chain()));
    let body_json = serde_json::to_vec(&vec![HEX_64_AA]).unwrap();
    let (status, body) = json_post(app, "/blockchain/block/byHeaderIds", body_json).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-syncing");
}

// ---------- gate: Halted → 503 indexer-halted ---------------------------

#[tokio::test]
async fn block_by_header_id_503_indexer_halted() {
    let h = IndexerHandle::halted(IndexerHaltReason::DbCorruption);
    let app = build_app(h, Some(empty_chain()));
    let (status, body) = json_get(app, &format!("/blockchain/block/byHeaderId/{HEX_64_AA}")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-halted");
}

#[tokio::test]
async fn blocks_by_header_ids_503_indexer_halted_pre_body_parse() {
    // POST gate fires before Json extractor — even an empty body 503's
    // when the indexer is halted.
    let h = IndexerHandle::halted(IndexerHaltReason::UndoMissing);
    let app = build_app(h, Some(empty_chain()));
    let (status, body) = json_post(app, "/blockchain/block/byHeaderIds", b"".to_vec()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-halted");
}

// ---------- 404 bad hex -------------------------------------------------

#[tokio::test]
async fn block_by_header_id_404_on_short_hex() {
    let app = build_app(caught_up_handle(), Some(empty_chain()));
    let (status, body) = json_get(app, "/blockchain/block/byHeaderId/abcd").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "not-found");
    assert_eq!(body["detail"], "block not found");
}

#[tokio::test]
async fn block_by_header_id_404_on_non_hex() {
    let app = build_app(caught_up_handle(), Some(empty_chain()));
    let url = format!("/blockchain/block/byHeaderId/zz{}", &HEX_64_AA[2..]);
    let (status, _) = json_get(app, &url).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------- 404 chain miss ----------------------------------------------

#[tokio::test]
async fn block_by_header_id_404_when_chain_has_no_block() {
    // Valid hex, indexer caught up, but chain returns None for this id.
    let app = build_app(caught_up_handle(), Some(empty_chain()));
    let (status, body) = json_get(app, &format!("/blockchain/block/byHeaderId/{HEX_64_BB}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["detail"], "block not found");
}

// ---------- 200 happy path ----------------------------------------------

#[tokio::test]
async fn block_by_header_id_200_returns_indexed_full_block_shape() {
    let tx_a = fixture_tx(TX_HEX_AA, 700_000, 0, 100);
    let tx_b = fixture_tx(TX_HEX_BB, 700_000, 1, 200);
    let block = fixture_full_block(
        HEX_64_AA,
        700_000,
        vec![scala_tx(TX_HEX_AA, 100), scala_tx(TX_HEX_BB, 200)],
        true, // ad_proofs present
    );

    let chain = stub_chain(vec![(HEX_64_AA.to_string(), block)]);
    let indexer: Arc<dyn IndexerQuery> =
        Arc::new(StubIndexer::caught_up().with_tx(tx_a).with_tx(tx_b));
    let app = build_app_with_indexer(indexer, Some(chain));

    let (status, body) = json_get(app, &format!("/blockchain/block/byHeaderId/{HEX_64_AA}")).await;
    assert_eq!(status, StatusCode::OK);

    // Top-level shape — five keys per IndexedFullBlock schema.
    assert_eq!(body["header"]["id"], HEX_64_AA);
    assert_eq!(body["adProofs"]["headerId"], HEX_64_AA);
    assert_eq!(body["extension"]["headerId"], HEX_64_AA);
    assert!(body["size"].is_number());

    // blockTransactions wrapper.
    assert_eq!(body["blockTransactions"]["headerId"], HEX_64_AA);
    assert!(body["blockTransactions"]["size"].is_number());

    // Inner transactions are the indexed shape, in chain order.
    let txs = body["blockTransactions"]["transactions"]
        .as_array()
        .unwrap();
    assert_eq!(txs.len(), 2);
    assert_eq!(txs[0]["id"], TX_HEX_AA);
    assert_eq!(txs[1]["id"], TX_HEX_BB);
    assert_eq!(txs[0]["blockId"], HEX_64_AA);
    assert_eq!(txs[0]["inclusionHeight"], 700_000);
    assert!(txs[0]["timestamp"].is_number());
}

#[tokio::test]
async fn block_by_header_id_200_with_null_ad_proofs_for_pruned_block() {
    let tx_a = fixture_tx(TX_HEX_AA, 700_000, 0, 100);
    let block = fixture_full_block(
        HEX_64_AA,
        700_000,
        vec![scala_tx(TX_HEX_AA, 100)],
        false, // ad_proofs absent
    );
    let chain = stub_chain(vec![(HEX_64_AA.to_string(), block)]);
    let indexer: Arc<dyn IndexerQuery> = Arc::new(StubIndexer::caught_up().with_tx(tx_a));
    let app = build_app_with_indexer(indexer, Some(chain));

    let (status, body) = json_get(app, &format!("/blockchain/block/byHeaderId/{HEX_64_AA}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["adProofs"].is_null());
}

#[tokio::test]
async fn block_by_header_id_200_handles_empty_tx_list() {
    let block = fixture_full_block(HEX_64_AA, 700_000, Vec::new(), true);
    let chain = stub_chain(vec![(HEX_64_AA.to_string(), block)]);
    let indexer: Arc<dyn IndexerQuery> = Arc::new(StubIndexer::caught_up());
    let app = build_app_with_indexer(indexer, Some(chain));

    let (status, body) = json_get(app, &format!("/blockchain/block/byHeaderId/{HEX_64_AA}")).await;
    assert_eq!(status, StatusCode::OK);
    let txs = body["blockTransactions"]["transactions"]
        .as_array()
        .unwrap();
    assert!(txs.is_empty());
}

// ---------- 404 indexer missing inner tx --------------------------------

#[tokio::test]
async fn block_by_header_id_404_when_indexer_missing_tx() {
    // Chain has the block, but indexer doesn't have one of its txs —
    // surfaces to the client as a clean miss.
    let block = fixture_full_block(
        HEX_64_AA,
        700_000,
        vec![scala_tx(TX_HEX_AA, 100), scala_tx(TX_HEX_BB, 200)],
        true,
    );
    let chain = stub_chain(vec![(HEX_64_AA.to_string(), block)]);
    // Only seed one of the two txs.
    let indexer: Arc<dyn IndexerQuery> =
        Arc::new(StubIndexer::caught_up().with_tx(fixture_tx(TX_HEX_AA, 700_000, 0, 100)));
    let app = build_app_with_indexer(indexer, Some(chain));

    let (status, body) = json_get(app, &format!("/blockchain/block/byHeaderId/{HEX_64_AA}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["detail"], "block not found");
}

// ---------- POST byHeaderIds --------------------------------------------

#[tokio::test]
async fn blocks_by_header_ids_200_empty_array_on_empty_input() {
    let app = build_app(caught_up_handle(), Some(empty_chain()));
    let body_json = serde_json::to_vec::<Vec<String>>(&vec![]).unwrap();
    let (status, body) = json_post(app, "/blockchain/block/byHeaderIds", body_json).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn blocks_by_header_ids_200_drops_malformed_hex_ids() {
    let app = build_app(caught_up_handle(), Some(empty_chain()));
    let body_json = serde_json::to_vec(&vec!["not-hex", "tooshort", HEX_64_AA]).unwrap();
    let (status, body) = json_post(app, "/blockchain/block/byHeaderIds", body_json).await;
    assert_eq!(status, StatusCode::OK);
    // All three drop: two malformed at parse, one (valid hex) miss at chain.
    assert!(body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn blocks_by_header_ids_200_returns_known_blocks_in_input_order() {
    let tx_a = fixture_tx(TX_HEX_AA, 700_000, 0, 100);
    let tx_b = fixture_tx(TX_HEX_BB, 700_001, 0, 200);
    let block_a = fixture_full_block(HEX_64_AA, 700_000, vec![scala_tx(TX_HEX_AA, 100)], true);
    let block_b = fixture_full_block(HEX_64_BB, 700_001, vec![scala_tx(TX_HEX_BB, 200)], true);
    let chain = stub_chain(vec![
        (HEX_64_AA.to_string(), block_a),
        (HEX_64_BB.to_string(), block_b),
    ]);
    let indexer: Arc<dyn IndexerQuery> =
        Arc::new(StubIndexer::caught_up().with_tx(tx_a).with_tx(tx_b));
    let app = build_app_with_indexer(indexer, Some(chain));

    // Request order: BB, unknown, AA — output should drop the unknown
    // and preserve [BB, AA] in input order.
    let body_json = serde_json::to_vec(&vec![HEX_64_BB, HEX_64_CC, HEX_64_AA]).unwrap();
    let (status, body) = json_post(app, "/blockchain/block/byHeaderIds", body_json).await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["header"]["id"], HEX_64_BB);
    assert_eq!(arr[1]["header"]["id"], HEX_64_AA);
}

#[tokio::test]
async fn blocks_by_header_ids_200_drops_block_with_missing_indexer_tx() {
    // Chain has both blocks, but indexer is missing the tx for block A.
    // Response keeps only block B.
    let tx_b = fixture_tx(TX_HEX_BB, 700_001, 0, 200);
    let block_a = fixture_full_block(HEX_64_AA, 700_000, vec![scala_tx(TX_HEX_AA, 100)], true);
    let block_b = fixture_full_block(HEX_64_BB, 700_001, vec![scala_tx(TX_HEX_BB, 200)], true);
    let chain = stub_chain(vec![
        (HEX_64_AA.to_string(), block_a),
        (HEX_64_BB.to_string(), block_b),
    ]);
    let indexer: Arc<dyn IndexerQuery> = Arc::new(StubIndexer::caught_up().with_tx(tx_b));
    let app = build_app_with_indexer(indexer, Some(chain));

    let body_json = serde_json::to_vec(&vec![HEX_64_AA, HEX_64_BB]).unwrap();
    let (status, body) = json_post(app, "/blockchain/block/byHeaderIds", body_json).await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["header"]["id"], HEX_64_BB);
}

// ---------- helpers ------------------------------------------------------

fn syncing_handle(indexed_height: u64) -> IndexerHandle {
    IndexerHandle::syncing(indexed_height)
}

fn caught_up_handle() -> IndexerHandle {
    let h = IndexerHandle::syncing(700_000);
    h.set_status(IndexerStatus::CaughtUp);
    h
}

fn fixture_tx(id_hex: &str, height: i32, index_in_block: i32, size: i32) -> IndexedErgoTransaction {
    let mut id = [0u8; 32];
    hex::decode_to_slice(id_hex, &mut id).unwrap();
    IndexedErgoTransaction {
        id: TxId::from_bytes(id),
        index_in_block,
        height,
        size,
        global_index: index_in_block as i64,
        input_nums: Vec::new(),
        output_nums: Vec::new(),
        data_inputs: Vec::new(),
    }
}

fn scala_tx(id_hex: &str, size: u32) -> ScalaTransaction {
    ScalaTransaction {
        id: id_hex.to_string(),
        inputs: Vec::new(),
        data_inputs: Vec::new(),
        outputs: Vec::new(),
        size,
    }
}

fn fixture_full_block(
    header_id_hex: &str,
    height: u32,
    txs: Vec<ScalaTransaction>,
    with_ad_proofs: bool,
) -> ScalaFullBlock {
    let bt_size: u32 = txs.iter().map(|t| t.size).sum();
    ScalaFullBlock {
        header: fixture_header(header_id_hex, height, 1_700_000_000_000),
        block_transactions: ScalaBlockTransactions {
            header_id: header_id_hex.to_string(),
            transactions: txs,
            block_version: 3,
            size: bt_size,
        },
        extension: ScalaExtension {
            header_id: header_id_hex.to_string(),
            digest: String::new(),
            fields: Vec::new(),
        },
        ad_proofs: if with_ad_proofs {
            Some(ScalaAdProofs {
                header_id: header_id_hex.to_string(),
                proof_bytes: String::new(),
                digest: String::new(),
                size: 64,
            })
        } else {
            None
        },
        size: 1024 + bt_size,
    }
}

fn fixture_header(id_hex: &str, height: u32, timestamp_ms: u64) -> ScalaHeader {
    ScalaHeader {
        extension_id: String::new(),
        difficulty: "0".to_string(),
        votes: "000000".to_string(),
        timestamp: timestamp_ms,
        size: 220,
        unparsed_bytes: String::new(),
        state_root: String::new(),
        height,
        n_bits: 0,
        version: 3,
        id: id_hex.to_string(),
        ad_proofs_root: String::new(),
        transactions_root: String::new(),
        extension_hash: String::new(),
        pow_solutions: ScalaPowSolutions {
            pk: String::new(),
            w: String::new(),
            n: String::new(),
            d: serde_json::Value::Null,
        },
        ad_proofs_id: String::new(),
        transactions_id: String::new(),
        parent_id: String::new(),
    }
}

fn build_app(handle: IndexerHandle, chain: Option<Arc<dyn NodeChainQuery>>) -> axum::Router {
    let indexer: Arc<dyn IndexerQuery> = Arc::new(handle);
    build_app_with_indexer(indexer, chain)
}

fn build_app_with_indexer(
    indexer: Arc<dyn IndexerQuery>,
    chain: Option<Arc<dyn NodeChainQuery>>,
) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState {
        full_height: 700_000,
    });
    router(
        read,
        chain,
        None,
        Some(indexer),
        ergo_ser::address::NetworkPrefix::Mainnet,
    )
}

async fn json_get(app: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
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
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

async fn json_post(
    app: axum::Router,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

// ---------- stub IndexerQuery -------------------------------------------

struct StubIndexer {
    txs: HashMap<TxId, IndexedErgoTransaction>,
    status: IndexerStatus,
}

impl StubIndexer {
    fn caught_up() -> Self {
        Self {
            txs: HashMap::new(),
            status: IndexerStatus::CaughtUp,
        }
    }

    fn with_tx(mut self, tx: IndexedErgoTransaction) -> Self {
        self.txs.insert(tx.id, tx);
        self
    }
}

impl IndexerQuery for StubIndexer {
    fn indexed_height(&self) -> u64 {
        700_000
    }
    fn status(&self) -> IndexerStatus {
        self.status.clone()
    }

    fn box_by_id(&self, _box_id: &BoxId) -> Option<IndexedBoxDto> {
        None
    }
    fn box_by_global_index(&self, _n: u64) -> Option<IndexedBoxDto> {
        None
    }
    fn boxes_by_global_range(&self, _lo: u64, _hi: u64) -> Vec<IndexedBoxDto> {
        Vec::new()
    }

    fn tx_by_id(&self, tx_id: &TxId) -> Option<IndexedTxDto> {
        self.txs.get(tx_id).cloned()
    }
    fn tx_by_global_index(&self, _n: u64) -> Option<IndexedTxDto> {
        None
    }
    fn txs_by_global_range(&self, _lo: u64, _hi: u64) -> Vec<IndexedTxDto> {
        Vec::new()
    }

    fn address_balance(&self, _tree_hash: &TreeHash) -> Option<BalanceDto> {
        None
    }
    fn address_txs_paged(
        &self,
        _tree_hash: &TreeHash,
        _p: Page,
        _dir: SortDir,
    ) -> Vec<IndexedTxDto> {
        Vec::new()
    }
    fn address_boxes_paged(
        &self,
        _tree_hash: &TreeHash,
        _p: Page,
        _dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_unspent_paged(
        &self,
        _tree_hash: &TreeHash,
        _p: Page,
        _dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_total_txs(&self, _tree_hash: &TreeHash) -> u64 {
        0
    }
    fn address_total_boxes(&self, _tree_hash: &TreeHash) -> u64 {
        0
    }

    fn template_boxes_paged(&self, _template_hash: &TemplateHash, _p: Page) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_unspent_paged(
        &self,
        _template_hash: &TemplateHash,
        _p: Page,
        _dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_total_boxes(&self, _template_hash: &TemplateHash) -> u64 {
        0
    }

    fn token_by_id(&self, _token_id: &TokenId) -> Option<IndexedTokenDto> {
        None
    }
    fn tokens_by_ids(&self, _ids: &[TokenId]) -> Vec<IndexedTokenDto> {
        Vec::new()
    }
    fn token_boxes_paged(&self, _token_id: &TokenId, _p: Page) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn token_unspent_paged(
        &self,
        _token_id: &TokenId,
        _p: Page,
        _dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn token_total_boxes(&self, _token_id: &TokenId) -> u64 {
        0
    }
}

// ---------- stub NodeChainQuery -----------------------------------------

fn empty_chain() -> Arc<dyn NodeChainQuery> {
    Arc::new(StubChain {
        blocks: HashMap::new(),
    })
}

fn stub_chain(entries: Vec<(String, ScalaFullBlock)>) -> Arc<dyn NodeChainQuery> {
    Arc::new(StubChain {
        blocks: entries.into_iter().collect(),
    })
}

struct StubChain {
    blocks: HashMap<String, ScalaFullBlock>,
}

impl NodeChainQuery for StubChain {
    fn info(&self) -> ScalaInfo {
        empty_info()
    }

    fn header_ids_at_height(&self, height: u32) -> Vec<String> {
        self.blocks
            .iter()
            .filter(|(_, b)| b.header.height == height)
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn full_block_by_id(&self, header_id_hex: &str) -> Option<ScalaFullBlock> {
        self.blocks.get(header_id_hex).cloned()
    }

    fn header_by_id(&self, header_id_hex: &str) -> Option<ScalaHeader> {
        self.blocks.get(header_id_hex).map(|b| b.header.clone())
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

// ---------- stub NodeReadState ------------------------------------------

struct StubReadState {
    full_height: u32,
}

impl NodeReadState for StubReadState {
    fn info(&self) -> ApiInfo {
        ApiInfo {
            agent_name: "ergo-rust".into(),
            node_name: "stub".into(),
            network: "mainnet".into(),
            version: "0.1.0".into(),
            started_at_unix_ms: 0,
            uptime_seconds: 0,
            target_block_interval_ms: 120_000,
        }
    }
    fn status(&self) -> ApiStatus {
        ApiStatus {
            sync_state: SyncStateLabel::AtTip,
            peer_count: 0,
            best_header_height: self.full_height,
            best_full_block_height: self.full_height,
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
