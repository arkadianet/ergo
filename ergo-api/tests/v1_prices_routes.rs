use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Router;
use ergo_api::traits::{MempoolView, NodeReadState, NoopMempoolView};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_api::v1::{v1_router, V1State};
use ergo_indexer_types::{
    BalanceDto, BoxId, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerQuery,
    IndexerReadError, IndexerStatus, Page, SortDir, TemplateHash, TokenId, TreeHash, TxId,
};
use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::address::NetworkPrefix;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::{write_registers, AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaValue};
use ergo_ser::token::Token;
use serde_json::{json, Value};
use tower::ServiceExt;

const HEIGHT: u64 = 700_000;
const TOKEN_ID_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TEMPLATE_HASH_HEX: &str = "850f2d5b02b3e66612e5499953fe8dfe54b8c077a0bd85362b5c706ffebd2bae";

// ----- helpers -----

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
            best_header_height: HEIGHT as u32,
            best_full_block_height: HEIGHT as u32,
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
            best_header_height: HEIGHT as u32,
            best_full_block_height: HEIGHT as u32,
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

struct HeightScript {
    values: VecDeque<u64>,
    last: u64,
}

struct ScriptedPage {
    offset: u32,
    limit: u32,
    dir: SortDir,
    result: Result<Vec<IndexedBoxDto>, IndexerReadError>,
}

type ScriptedTokenRead = (TokenId, Result<Option<IndexedTokenDto>, IndexerReadError>);
type ScriptedBoxRead = (BoxId, Result<Option<IndexedBoxDto>, IndexerReadError>);

struct StubIndexer {
    status: IndexerStatus,
    heights: Mutex<HeightScript>,
    pages: Mutex<VecDeque<ScriptedPage>>,
    tokens: Mutex<VecDeque<ScriptedTokenRead>>,
    boxes: Mutex<VecDeque<ScriptedBoxRead>>,
}

impl StubIndexer {
    fn new(heights: impl IntoIterator<Item = u64>) -> Self {
        let values = heights.into_iter().collect::<VecDeque<_>>();
        let last = values.front().copied().unwrap_or(HEIGHT);
        Self {
            status: IndexerStatus::CaughtUp,
            heights: Mutex::new(HeightScript { values, last }),
            pages: Mutex::new(VecDeque::new()),
            tokens: Mutex::new(VecDeque::new()),
            boxes: Mutex::new(VecDeque::new()),
        }
    }

    fn with_pages(self, pages: Vec<ScriptedPage>) -> Self {
        *self.pages.lock().unwrap() = pages.into();
        self
    }

    fn with_token(
        self,
        token_id: TokenId,
        result: Result<Option<IndexedTokenDto>, IndexerReadError>,
    ) -> Self {
        self.tokens.lock().unwrap().push_back((token_id, result));
        self
    }

    fn with_box(
        self,
        box_id: BoxId,
        result: Result<Option<IndexedBoxDto>, IndexerReadError>,
    ) -> Self {
        self.boxes.lock().unwrap().push_back((box_id, result));
        self
    }
}

impl IndexerQuery for StubIndexer {
    fn indexed_height(&self) -> u64 {
        let mut script = self.heights.lock().unwrap();
        let height = script.values.pop_front().unwrap_or(script.last);
        script.last = height;
        height
    }

    fn status(&self) -> IndexerStatus {
        self.status.clone()
    }

    fn box_by_id(&self, _box_id: &BoxId) -> Option<IndexedBoxDto> {
        None
    }

    fn try_box_by_id(&self, box_id: &BoxId) -> Result<Option<IndexedBoxDto>, IndexerReadError> {
        let Some((expected_id, result)) = self.boxes.lock().unwrap().pop_front() else {
            return Ok(None);
        };
        assert_eq!(*box_id, expected_id);
        result
    }

    fn box_by_global_index(&self, _n: u64) -> Option<IndexedBoxDto> {
        None
    }

    fn boxes_by_global_range(&self, _lo: u64, _hi: u64) -> Vec<IndexedBoxDto> {
        Vec::new()
    }

    fn tx_by_id(&self, _tx_id: &TxId) -> Option<IndexedTxDto> {
        None
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

    fn try_template_unspent_paged(
        &self,
        template_hash: &TemplateHash,
        page: Page,
        dir: SortDir,
    ) -> Result<Vec<IndexedBoxDto>, IndexerReadError> {
        assert_eq!(hex::encode(template_hash.as_bytes()), TEMPLATE_HASH_HEX);
        let scripted = self
            .pages
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected template page read");
        assert_eq!(
            (page.offset, page.limit, dir),
            (scripted.offset, scripted.limit, scripted.dir)
        );
        scripted.result
    }

    fn template_total_boxes(&self, _template_hash: &TemplateHash) -> u64 {
        0
    }

    fn token_by_id(&self, _token_id: &TokenId) -> Option<IndexedTokenDto> {
        None
    }

    fn try_token_by_id(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<IndexedTokenDto>, IndexerReadError> {
        let Some((expected_id, result)) = self.tokens.lock().unwrap().pop_front() else {
            return Ok(None);
        };
        assert_eq!(*token_id, expected_id);
        result
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

fn fixture_tree_bytes() -> Vec<u8> {
    hex::decode(include_str!("fixtures/spectrum_n2t_v1_ergo_tree.hex").trim()).unwrap()
}

fn int_register(value: i32) -> RegisterValue {
    RegisterValue {
        tpe: SigmaType::SInt,
        value: SigmaValue::Int(value),
    }
}

fn bytes_register(value: &[u8]) -> RegisterValue {
    RegisterValue {
        tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        value: SigmaValue::Coll(CollValue::Bytes(value.to_vec())),
    }
}

fn token(seed: u8, amount: u64) -> Token {
    Token {
        token_id: TokenId::from_bytes([seed; 32]),
        amount,
    }
}

fn indexed_box(
    transaction_seed: u8,
    value: u64,
    tokens: Vec<Token>,
    registers: Vec<RegisterValue>,
) -> IndexedBoxDto {
    let tree_bytes = fixture_tree_bytes();
    let mut tree_reader = VlqReader::new(&tree_bytes);
    let ergo_tree = read_ergo_tree(&mut tree_reader).unwrap();
    assert!(tree_reader.is_empty());
    let additional_registers = AdditionalRegisters { registers };
    let mut register_writer = VlqWriter::new();
    write_registers(&mut register_writer, &additional_registers).unwrap();
    let candidate = ErgoBoxCandidate::from_trusted_raw_parts(
        value,
        ergo_tree,
        tree_bytes,
        HEIGHT as u32,
        tokens,
        additional_registers,
        register_writer.result(),
    );

    IndexedBoxDto {
        inclusion_height: HEIGHT as i32,
        spending_tx_id: None,
        spending_height: None,
        spending_proof: None,
        box_data: ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes([transaction_seed; 32]),
            index: 0,
        },
        global_index: i64::from(transaction_seed),
    }
}

fn pool_box() -> IndexedBoxDto {
    indexed_box(
        1,
        34_583_910,
        vec![token(1, 1), token(2, 1_000_000), token(0xaa, 1_000_000)],
        vec![int_register(997)],
    )
}

fn mint_box() -> IndexedBoxDto {
    indexed_box(
        9,
        1_000_000,
        Vec::new(),
        vec![int_register(0), int_register(0), bytes_register(b"6")],
    )
}

fn token_id() -> TokenId {
    TokenId::from_bytes([0xaa; 32])
}

fn short_page(result: Result<Vec<IndexedBoxDto>, IndexerReadError>) -> ScriptedPage {
    ScriptedPage {
        offset: 0,
        limit: 100,
        dir: SortDir::Asc,
        result,
    }
}

fn cap_pages(candidate: &IndexedBoxDto) -> Vec<ScriptedPage> {
    (0..50)
        .map(|page| ScriptedPage {
            offset: page * 100,
            limit: 100,
            dir: SortDir::Asc,
            result: Ok(vec![candidate.clone(); 100]),
        })
        .chain(std::iter::once(ScriptedPage {
            offset: 5_000,
            limit: 1,
            dir: SortDir::Asc,
            result: Ok(vec![candidate.clone()]),
        }))
        .collect()
}

fn app(indexer: Option<Arc<dyn IndexerQuery>>) -> Router {
    let mempool: Arc<dyn MempoolView> = Arc::new(NoopMempoolView::new());
    let state = V1State {
        read: Arc::new(StubRead),
        chain: None,
        indexer,
        submit: None,
        tx_builder: None,
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

async fn get(indexer: Option<Arc<dyn IndexerQuery>>, uri: &str) -> (StatusCode, Value) {
    let mut request = Request::builder().uri(uri).body(Body::empty()).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let response = app(indexer).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap();
    (status, body)
}

fn reason(body: &Value) -> &str {
    body["error"]["reason"].as_str().unwrap_or("<none>")
}

// ----- happy path -----

#[tokio::test]
async fn prices_no_liquidity_returns_200_unpriced() {
    let indexer = StubIndexer::new([HEIGHT, HEIGHT]).with_pages(vec![short_page(Ok(Vec::new()))]);

    let (status, body) = get(
        Some(Arc::new(indexer)),
        &format!("/api/v1/prices?token_id={TOKEN_ID_HEX}"),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["items"][0],
        json!({
            "token_id": TOKEN_ID_HEX,
            "priced": false,
            "reason": "no_liquidity"
        })
    );
}

#[tokio::test]
async fn prices_unknown_decimals_returns_200_decimals_unknown() {
    let indexer = StubIndexer::new([HEIGHT, HEIGHT])
        .with_pages(vec![short_page(Ok(vec![pool_box()]))])
        .with_token(token_id(), Ok(None));

    let (status, body) = get(
        Some(Arc::new(indexer)),
        &format!("/api/v1/prices?token_id={TOKEN_ID_HEX}"),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let item = &body["items"][0];
    assert_eq!(item["token_id"], TOKEN_ID_HEX);
    assert_eq!(item["priced"], false);
    assert_eq!(item["reason"], "decimals_unknown");
    assert!(item.get("price").is_none());
    assert!(item.get("source").is_none());
    assert!(item.get("warnings").is_none());
}

#[tokio::test]
async fn prices_valid_returns_reduced_raw_and_provenance() {
    let pool = pool_box();
    let pool_box_id = pool.box_data.box_id().unwrap();
    let mint = mint_box();
    let mint_box_id = mint.box_data.box_id().unwrap();
    let indexer = StubIndexer::new([HEIGHT, HEIGHT])
        .with_pages(vec![short_page(Ok(vec![pool]))])
        .with_token(
            token_id(),
            Ok(Some(IndexedTokenDto {
                token_id: token_id(),
                creating_box_id: mint_box_id,
                emission_amount: 1_000_000,
                name: String::new(),
                description: String::new(),
                decimals: 0,
            })),
        )
        .with_box(mint_box_id, Ok(Some(mint)));

    let (status, body) = get(
        Some(Arc::new(indexer)),
        &format!("/api/v1/prices?token_id={TOKEN_ID_HEX}"),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["quote"], "ERG");
    assert_eq!(body["height"], HEIGHT);
    assert!(body["timestamp"].as_str().unwrap().ends_with('Z'));
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    let item = &body["items"][0];
    assert_eq!(item["token_id"], TOKEN_ID_HEX);
    assert_eq!(item["priced"], true);
    assert!(item.get("reason").is_none());
    assert_eq!(item["price"]["display"], "0.02458391");
    assert_eq!(item["price"]["raw"]["numerator"], "2458391");
    assert_eq!(item["price"]["raw"]["denominator"], "100000000");
    assert_eq!(item["price"]["token_decimals"], 6);
    assert_eq!(item["source"]["protocol"], "spectrum");
    assert_eq!(item["source"]["pool_type"], "N2T");
    assert_eq!(
        item["source"]["pool_box_id"],
        hex::encode(pool_box_id.as_bytes())
    );
    assert_eq!(item["source"]["path"].as_array().unwrap().len(), 1);
    assert_eq!(
        item["source"]["path"][0]["pool_box_id"],
        item["source"]["pool_box_id"]
    );
    assert_eq!(item["source"]["path"][0]["pool_type"], "N2T");
    assert_eq!(item["warnings"], json!([]));
}

// ----- round-trips -----

// ----- error paths -----

#[tokio::test]
async fn prices_disabled_returns_409_indexer_disabled() {
    let (status, body) = get(None, &format!("/api/v1/prices?token_id={TOKEN_ID_HEX}")).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reason(&body), "indexer_disabled");
}

#[tokio::test]
async fn prices_malformed_id_returns_400_invalid_token_id() {
    let malformed_id = "AA".repeat(32);
    let (status, body) = get(
        Some(Arc::new(StubIndexer::new([HEIGHT]))),
        &format!("/api/v1/prices?token_id={malformed_id}"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_token_id");
}

#[tokio::test]
async fn prices_unsupported_quote_returns_400_unsupported_quote() {
    let (status, body) = get(
        Some(Arc::new(StubIndexer::new([HEIGHT]))),
        &format!("/api/v1/prices?token_id={TOKEN_ID_HEX}&quote=USD"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "unsupported_quote");
}

#[tokio::test]
async fn prices_read_error_returns_500_internal_error() {
    let indexer = StubIndexer::new([HEIGHT]).with_pages(vec![short_page(Err(
        IndexerReadError::new("template read failed"),
    ))]);

    let (status, body) = get(
        Some(Arc::new(indexer)),
        &format!("/api/v1/prices?token_id={TOKEN_ID_HEX}"),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(reason(&body), "internal_error");
}

#[tokio::test]
async fn prices_cap_returns_503_pricing_unavailable() {
    let candidate = pool_box();
    let indexer = StubIndexer::new([HEIGHT]).with_pages(cap_pages(&candidate));

    let (status, body) = get(
        Some(Arc::new(indexer)),
        &format!("/api/v1/prices?token_id={TOKEN_ID_HEX}"),
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reason(&body), "pricing_unavailable");
}

#[tokio::test]
async fn prices_unstable_returns_503_pricing_unavailable() {
    let indexer = StubIndexer::new([HEIGHT, HEIGHT + 1, HEIGHT + 2, HEIGHT + 3])
        .with_pages(vec![short_page(Ok(Vec::new())), short_page(Ok(Vec::new()))]);

    let (status, body) = get(
        Some(Arc::new(indexer)),
        &format!("/api/v1/prices?token_id={TOKEN_ID_HEX}"),
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reason(&body), "pricing_unavailable");
}

// ----- oracle parity -----
