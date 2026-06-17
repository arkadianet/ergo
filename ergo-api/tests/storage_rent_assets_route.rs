//! `/blockchain/storageRent/*` token-asset surfacing.
//!
//! Pins that each eligibility row carries an `assets` array byte-shape-
//! identical to `/blockchain/box/byId` (`[{ tokenId, amount }]`, `[]`
//! when the box holds no tokens), that the three routes share the
//! rendering, and that a row whose box record is missing (index desync)
//! fails the response with a 500 rather than emitting empty assets.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ergo_api::server::{router_with_mempool, ServerCtx};
use ergo_api::traits::{ChainParamsView, NodeReadState, NoopMempoolView};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_indexer_types::types::IndexedErgoBox;
use ergo_indexer_types::{
    BalanceDto, BoxId, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerQuery, IndexerStatus,
    Page, SortDir, StorageRentEligibleDto, TemplateHash, TokenId, TreeHash, TxId,
};
use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::opcode::{Body as TreeBody, Expr};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::token::Token;
use http_body_util::BodyExt;
use tower::ServiceExt;

// ----- helpers -----

/// A height comfortably above `StoragePeriod` (1_051_200) so the handlers
/// do not short-circuit to an empty page before consulting the indexer.
const QUERY_HEIGHT: u32 = 2_000_000;

fn size_delimited_tree() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: true,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
        } as TreeBody,
    }
}

/// Build an `IndexedErgoBox` carrying `tokens`, plus the matching
/// eligibility row that references it. `index` distinguishes box ids
/// (same tx id, different output index ⇒ different box id).
fn make_box_and_row(
    value: u64,
    index: u16,
    tokens: Vec<Token>,
) -> (IndexedErgoBox, StorageRentEligibleDto) {
    let candidate = ErgoBoxCandidate::new(
        value,
        size_delimited_tree(),
        1,
        tokens,
        AdditionalRegisters::empty(),
    )
    .unwrap();
    let ergo_box = ErgoBox {
        candidate,
        transaction_id: Digest32::from_bytes([0x22; 32]).into(),
        index,
    };
    let box_id = ergo_box.box_id().unwrap();
    let box_bytes_len = i32::try_from(serialize_ergo_box(&ergo_box).unwrap().len()).unwrap();
    let indexed = IndexedErgoBox {
        inclusion_height: 1,
        spending_tx_id: None,
        spending_height: None,
        spending_proof: None,
        box_data: ergo_box,
        global_index: index as i64,
    };
    let row = StorageRentEligibleDto {
        creation_height: 1,
        global_box_index: index as i64,
        box_id,
        box_value: value,
        box_bytes_len,
    };
    (indexed, row)
}

fn token(seed: u8, amount: u64) -> Token {
    Token {
        token_id: TokenId::from_bytes([seed; 32]),
        amount,
    }
}

async fn json_get(app: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
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

fn build_app(indexer: StubIndexer) -> axum::Router {
    build_app_with_params(
        indexer,
        Arc::new(StubChainParams) as Arc<dyn ChainParamsView>,
    )
}

fn build_app_with_params(
    indexer: StubIndexer,
    chain_params: Arc<dyn ChainParamsView>,
) -> axum::Router {
    let ctx = ServerCtx {
        read: Arc::new(StubReadState),
        compat: None,
        submit: None,
        indexer: Some(Arc::new(indexer) as Arc<dyn IndexerQuery>),
        mempool: Arc::new(NoopMempoolView::new()),
        network: ergo_ser::address::NetworkPrefix::Mainnet,
        chain_params: Some(chain_params),
        mining: None,
        emission: None,
        emission_scripts: None,
        utxo_reads_supported: true,
    };
    router_with_mempool(ctx, None)
}

// ----- happy path -----

#[tokio::test]
async fn eligible_box_with_tokens_lists_assets_matching_box() {
    let (boxed, row) = make_box_and_row(1_000_000, 0, vec![token(0x07, 4242)]);
    let indexer = StubIndexer::new(vec![(boxed, row)]);
    let app = build_app(indexer);

    let (status, body) = json_get(
        app,
        &format!("/blockchain/storageRent/eligibleAt/{QUERY_HEIGHT}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let assets = &body["items"][0]["assets"];
    assert_eq!(assets.as_array().unwrap().len(), 1);
    assert_eq!(assets[0]["tokenId"], "07".repeat(32));
    assert_eq!(assets[0]["amount"], 4242);
}

#[tokio::test]
async fn eligible_box_without_tokens_emits_empty_assets() {
    let (boxed, row) = make_box_and_row(1_000_000, 0, vec![]);
    let indexer = StubIndexer::new(vec![(boxed, row)]);
    let app = build_app(indexer);

    let (status, body) = json_get(
        app,
        &format!("/blockchain/storageRent/eligibleAt/{QUERY_HEIGHT}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["assets"], serde_json::json!([]));
}

#[tokio::test]
async fn matures_at_route_shares_asset_rendering() {
    let (boxed, row) = make_box_and_row(1_000_000, 0, vec![token(0x09, 7)]);
    let indexer = StubIndexer::new(vec![(boxed, row)]);
    let app = build_app(indexer);

    let (status, body) = json_get(
        app,
        &format!("/blockchain/storageRent/maturesAt/{QUERY_HEIGHT}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["assets"][0]["tokenId"], "09".repeat(32));
    assert_eq!(body["items"][0]["assets"][0]["amount"], 7);
}

#[tokio::test]
async fn matures_in_range_route_shares_asset_rendering() {
    let (boxed, row) = make_box_and_row(1_000_000, 0, vec![token(0x0b, 99)]);
    let indexer = StubIndexer::new(vec![(boxed, row)]);
    let app = build_app(indexer);

    let path = format!(
        "/blockchain/storageRent/maturesInRange?fromHeight={QUERY_HEIGHT}&toHeight={QUERY_HEIGHT}"
    );
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["assets"][0]["tokenId"], "0b".repeat(32));
    assert_eq!(body["items"][0]["assets"][0]["amount"], 99);
}

// ----- round-trips -----

#[tokio::test]
async fn eligible_box_preserves_token_order() {
    // Two distinct tokens; the response must keep the box's native token
    // order (matching /blockchain/box/byId's candidate.tokens iteration).
    let (boxed, row) = make_box_and_row(1_000_000, 0, vec![token(0x01, 10), token(0x02, 20)]);
    let indexer = StubIndexer::new(vec![(boxed, row)]);
    let app = build_app(indexer);

    let (status, body) = json_get(
        app,
        &format!("/blockchain/storageRent/eligibleAt/{QUERY_HEIGHT}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let assets = body["items"][0]["assets"].as_array().unwrap();
    assert_eq!(assets.len(), 2);
    assert_eq!(assets[0]["tokenId"], "01".repeat(32));
    assert_eq!(assets[0]["amount"], 10);
    assert_eq!(assets[1]["tokenId"], "02".repeat(32));
    assert_eq!(assets[1]["amount"], 20);
}

// ----- error paths -----

#[tokio::test]
async fn eligible_row_missing_box_record_errors() {
    // Row references a box id the box store does not hold → index desync.
    let (_orphan_box, row) = make_box_and_row(1_000_000, 0, vec![token(0x07, 1)]);
    let indexer = StubIndexer::with_rows_only(vec![row]);
    let app = build_app(indexer);

    let (status, _body) = json_get(
        app,
        &format!("/blockchain/storageRent/eligibleAt/{QUERY_HEIGHT}"),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

// ----- edge cases: H < StoragePeriod short-circuit -----

// All three storage-rent handlers must return an empty page for heights below
// `StoragePeriod` WITHOUT consulting `storage_fee_factor_for_validation_at` —
// that lookup reads the `H - 1` voted-params row and panics in debug at H == 0
// (no row exists below genesis). `PanicOnFactorParams` turns a missing
// short-circuit into a test panic instead of a silent regression.

#[tokio::test]
async fn eligible_at_height_zero_short_circuits_before_voted_param_lookup() {
    let app = build_app_with_params(StubIndexer::new(vec![]), Arc::new(PanicOnFactorParams));
    let (status, body) = json_get(app, "/blockchain/storageRent/eligibleAt/0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"], serde_json::json!([]));
    assert_eq!(body["total"], 0);
}

#[tokio::test]
async fn matures_at_height_zero_short_circuits_before_voted_param_lookup() {
    let app = build_app_with_params(StubIndexer::new(vec![]), Arc::new(PanicOnFactorParams));
    let (status, body) = json_get(app, "/blockchain/storageRent/maturesAt/0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"], serde_json::json!([]));
}

#[tokio::test]
async fn matures_in_range_to_height_zero_short_circuits_before_voted_param_lookup() {
    let app = build_app_with_params(StubIndexer::new(vec![]), Arc::new(PanicOnFactorParams));
    let (status, body) = json_get(
        app,
        "/blockchain/storageRent/maturesInRange?fromHeight=0&toHeight=0",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"], serde_json::json!([]));
}

// ---- stubs --------------------------------------------------------

struct StubChainParams;

impl ChainParamsView for StubChainParams {
    fn storage_fee_factor_for_validation_at(&self, _h: u32) -> Option<i32> {
        Some(1_250_000)
    }
    fn compute_storage_fee(&self, box_bytes_len: i32, storage_fee_factor: i32) -> i32 {
        // Consensus arithmetic: factor * bytes_len, wrapping i32 (see
        // ergo_validation::storage_rent::compute_storage_fee).
        storage_fee_factor.wrapping_mul(box_bytes_len)
    }
}

/// `ChainParamsView` that panics if its factor method is ever called. Used to
/// pin that the `H < StoragePeriod` short-circuit fires before the handler
/// reaches the `H - 1` voted-params lookup.
struct PanicOnFactorParams;

impl ChainParamsView for PanicOnFactorParams {
    fn storage_fee_factor_for_validation_at(&self, h: u32) -> Option<i32> {
        panic!(
            "storage_fee_factor_for_validation_at({h}) called: a storage-rent \
             handler reached the voted-param lookup for a height below \
             StoragePeriod instead of short-circuiting to an empty page"
        );
    }
    fn compute_storage_fee(&self, box_bytes_len: i32, storage_fee_factor: i32) -> i32 {
        storage_fee_factor.wrapping_mul(box_bytes_len)
    }
}

struct StubIndexer {
    rows: Vec<StorageRentEligibleDto>,
    boxes: HashMap<BoxId, IndexedErgoBox>,
}

impl StubIndexer {
    fn new(entries: Vec<(IndexedErgoBox, StorageRentEligibleDto)>) -> Self {
        let mut rows = Vec::new();
        let mut boxes = HashMap::new();
        for (b, row) in entries {
            boxes.insert(row.box_id, b);
            rows.push(row);
        }
        Self { rows, boxes }
    }
    fn with_rows_only(rows: Vec<StorageRentEligibleDto>) -> Self {
        Self {
            rows,
            boxes: HashMap::new(),
        }
    }
}

impl IndexerQuery for StubIndexer {
    fn indexed_height(&self) -> u64 {
        QUERY_HEIGHT as u64
    }
    fn status(&self) -> IndexerStatus {
        IndexerStatus::CaughtUp
    }

    fn box_by_id(&self, box_id: &BoxId) -> Option<IndexedBoxDto> {
        self.boxes.get(box_id).cloned()
    }
    fn box_by_global_index(&self, _: u64) -> Option<IndexedBoxDto> {
        None
    }
    fn boxes_by_global_range(&self, _: u64, _: u64) -> Vec<IndexedBoxDto> {
        Vec::new()
    }

    fn tx_by_id(&self, _: &TxId) -> Option<IndexedTxDto> {
        None
    }
    fn tx_by_global_index(&self, _: u64) -> Option<IndexedTxDto> {
        None
    }
    fn txs_by_global_range(&self, _: u64, _: u64) -> Vec<IndexedTxDto> {
        Vec::new()
    }

    fn address_balance(&self, _: &TreeHash) -> Option<BalanceDto> {
        None
    }
    fn address_txs_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedTxDto> {
        Vec::new()
    }
    fn address_boxes_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_unspent_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_total_txs(&self, _: &TreeHash) -> u64 {
        0
    }
    fn address_total_boxes(&self, _: &TreeHash) -> u64 {
        0
    }

    fn template_boxes_paged(&self, _: &TemplateHash, _: Page) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_unspent_paged(&self, _: &TemplateHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_total_boxes(&self, _: &TemplateHash) -> u64 {
        0
    }

    fn token_by_id(&self, _: &TokenId) -> Option<IndexedTokenDto> {
        None
    }
    fn tokens_by_ids(&self, _: &[TokenId]) -> Vec<IndexedTokenDto> {
        Vec::new()
    }
    fn token_boxes_paged(&self, _: &TokenId, _: Page) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn token_unspent_paged(&self, _: &TokenId, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn token_total_boxes(&self, _: &TokenId) -> u64 {
        0
    }

    // Storage-rent overrides: ignore cutoff/paging and return the fixture
    // rows; the test controls the data and asserts on the rendered output.
    fn storage_rent_eligible_paged(
        &self,
        _: u32,
        _: Page,
        _: SortDir,
    ) -> Vec<StorageRentEligibleDto> {
        self.rows.clone()
    }
    fn storage_rent_eligible_total(&self, _: u32) -> u64 {
        self.rows.len() as u64
    }
    fn storage_rent_in_creation_range(
        &self,
        _: u32,
        _: u32,
        _: Page,
        _: SortDir,
    ) -> Vec<StorageRentEligibleDto> {
        self.rows.clone()
    }
    fn storage_rent_total_in_creation_range(&self, _: u32, _: u32) -> u64 {
        self.rows.len() as u64
    }
}

struct StubReadState;

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
            best_header_height: QUERY_HEIGHT,
            best_full_block_height: QUERY_HEIGHT,
            headers_ahead_of_full_blocks: 0,
            mempool_size: 0,
            snapshot_age_ms: 0,
            bootstrap: None,
            last_block_apply_error: None,
            block_apply_errors_total: 0,
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
