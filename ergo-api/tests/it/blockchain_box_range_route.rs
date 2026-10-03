//! `GET|POST /blockchain/box/range` — extra-index row #9.
//!
//! Pinned behaviour:
//! - The status gate fires before the handler — `Syncing` / `Halted`
//!   short-circuits with the `503 indexer-{syncing,halted}` envelope.
//! - Paging contract: defaults `(offset=0, limit=5)`, `limit>16384`
//!   surfaces the `bad-request` envelope with the `"boxes"` noun (the
//!   route emits box-ids, not transactions).
//! - Wire shape: bare `[ModifierId]` array — global-range projection of
//!   `IndexedErgoBox.box_id()` only, no enrichment.
//! - Scala mounts no method directive (`*`); GET and POST go to the
//!   same dispatch and return identical bodies for identical queries.

use ergo_indexer_types::IndexerReadError;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ergo_api::compat::traits::NodeChainQuery;
use ergo_api::compat::types::{Parameters, ScalaFullBlock, ScalaInfo};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_indexer::{IndexerHaltReason, IndexerHandle};
use ergo_indexer_types::types::IndexedErgoBox;
use ergo_indexer_types::{
    BalanceDto, BoxId, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerQuery, IndexerStatus,
    Page, SortDir, TemplateHash, TokenId, TreeHash, TxId,
};
use ergo_primitives::digest::ModifierId;
use ergo_primitives::group_element::GroupElement;
use ergo_ser::address::NetworkPrefix;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use http_body_util::BodyExt;
use tower::ServiceExt;

// ---- 503 status-gate ------------------------------------------------------

#[tokio::test]
async fn range_503_indexer_syncing() {
    let app = build_app(Arc::new(StubIndexer::with_status(IndexerStatus::Syncing)));
    let (status, body) = json_get(app, "/blockchain/box/range").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-syncing");
}

#[tokio::test]
async fn range_503_indexer_halted() {
    let app = build_app(Arc::new(StubIndexer::with_status(IndexerStatus::Halted(
        IndexerHaltReason::DbCorruption,
    ))));
    let (status, body) = json_get(app, "/blockchain/box/range").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-halted");
}

// ---- 400 paging (boxes noun) ----------------------------------------------

#[tokio::test]
async fn range_400_on_limit_above_max() {
    let app = build_app(Arc::new(StubIndexer::caught_up(Vec::new())));
    let (status, body) = json_get(app, "/blockchain/box/range?limit=16385").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
    assert_eq!(body["detail"], "No more than 16384 boxes can be requested");
}

#[tokio::test]
async fn range_400_on_negative_offset() {
    let app = build_app(Arc::new(StubIndexer::caught_up(Vec::new())));
    let (status, body) = json_get(app, "/blockchain/box/range?offset=-1").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
}

#[tokio::test]
async fn range_rejects_offsets_outside_scala_int_domain() {
    for offset in [2147483648_i64, 4294967296, i64::MAX] {
        let app = build_app(Arc::new(StubIndexer::caught_up(Vec::new())));
        let (status, body) = json_get(
            app,
            &format!("/blockchain/box/range?offset={offset}&limit=1"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["reason"], "bad-request");
    }
    let app = build_app(Arc::new(StubIndexer::caught_up(Vec::new())));
    let (status, body) = json_get(app, "/blockchain/box/range?offset=2147483647&limit=0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!([]));
}

// ---- 200 dispatch + projection --------------------------------------------

#[tokio::test]
async fn range_200_returns_bare_id_array() {
    let boxes = vec![
        fixture_box([0x02; 33], 100, 1_000, 0),
        fixture_box([0x03; 33], 101, 2_000, 1),
        fixture_box([0x04; 33], 102, 3_000, 2),
    ];
    let expected_ids: Vec<String> = boxes
        .iter()
        .rev()
        .map(|b| hex::encode(b.box_data.box_id().expect("box_id").as_bytes()))
        .collect();
    let app = build_app(Arc::new(StubIndexer::caught_up(boxes)));
    let (status, body) = json_get(app, "/blockchain/box/range").await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("bare array response");
    assert_eq!(arr.len(), 3);
    for (i, id) in expected_ids.iter().enumerate() {
        assert_eq!(arr[i], serde_json::Value::String(id.clone()));
    }
}

#[tokio::test]
async fn range_200_post_get_parity() {
    let boxes = vec![
        fixture_box([0x02; 33], 100, 1_000, 0),
        fixture_box([0x03; 33], 101, 2_000, 1),
    ];
    let stub = Arc::new(StubIndexer::caught_up(boxes));
    let app_get = build_app(stub.clone());
    let app_post = build_app(stub);

    let (s_get, b_get) = json_get(app_get, "/blockchain/box/range?offset=0&limit=2").await;
    let (s_post, b_post) =
        json_post_empty(app_post, "/blockchain/box/range?offset=0&limit=2").await;

    assert_eq!(s_get, StatusCode::OK);
    assert_eq!(s_post, StatusCode::OK);
    assert_eq!(b_get, b_post);
}

// ---- mounted native query parity ------------------------------------------

#[tokio::test]
async fn native_ranges_apply_latest_window_to_persisted_global_counters() {
    use ergo_indexer::{apply_block, IndexerBlock, IndexerStore};
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::transaction::{transaction_id, Transaction};

    let temporary = tempfile::TempDir::new().unwrap();
    let (store, _) = IndexerStore::open(&temporary.path().join("indexer.redb")).unwrap();
    let handle = IndexerHandle::with_store(store, 0);
    let transactions: Vec<Transaction> = (0..2)
        .map(|i| Transaction {
            inputs: vec![Input {
                box_id: BoxId::from_bytes([i + 1; 32]),
                spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).unwrap(),
            }],
            data_inputs: Vec::new(),
            output_candidates: (0..=i)
                .map(|j| {
                    fixture_box(
                        [0x02; 33],
                        1,
                        1_000_000 + u64::from(i * 2 + j),
                        i64::from(i * 2 + j),
                    )
                    .box_data
                    .candidate
                })
                .collect(),
        })
        .collect();
    let store = handle.store().unwrap();
    let block = IndexerBlock {
        height: 1,
        header_id: BoxId::from_bytes([0x51; 32]),
        transactions: &transactions,
    };
    apply_block(&store, &store.read_meta().unwrap(), &block).unwrap();
    handle.set_status(IndexerStatus::CaughtUp);
    let expected_box = hex::encode(
        handle
            .box_by_global_index(1)
            .unwrap()
            .unwrap()
            .box_data
            .box_id()
            .unwrap()
            .as_bytes(),
    );
    let expected_tx = hex::encode(transaction_id(&transactions[0]).unwrap().as_bytes());
    let app = build_app(Arc::new(handle));
    let (status, body) = json_get(app.clone(), "/blockchain/box/range?offset=1&limit=1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!([expected_box]));
    let (status, body) =
        json_post_empty(app, "/blockchain/transaction/range?offset=1&limit=1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!([expected_tx]));
}

// ---- helpers --------------------------------------------------------------

fn p2pk_tree(pubkey: [u8; 33]) -> ErgoTree {
    // Fixture "pubkeys" are identity tags; normalize the SEC1 lead byte so
    // the tree parses under the wire prefix rule (0x00/0x02/0x03 only) the
    // JVM enforces at deserialize. Tail bytes keep the tags distinct.
    let mut pubkey = pubkey;
    pubkey[0] = match pubkey[0] {
        0x00 | 0x02 | 0x03 => pubkey[0],
        _ => 0x02,
    };
    ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        reserved_header_bits: 0,
        constants: Vec::new(),
        body: Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(pubkey))),
        },
    }
}

fn fixture_box(pubkey: [u8; 33], height: i32, value: u64, global_index: i64) -> IndexedErgoBox {
    let tree = p2pk_tree(pubkey);
    let candidate = ErgoBoxCandidate::new(
        value,
        tree,
        height as u32,
        Vec::new(),
        AdditionalRegisters::empty(),
    )
    .expect("ErgoBoxCandidate::new");
    let box_data = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes([(global_index as u8).wrapping_add(0xA0); 32]),
        index: global_index as u16,
    };
    IndexedErgoBox {
        inclusion_height: height,
        spending_tx_id: None,
        spending_height: None,
        spending_proof: None,
        box_data,
        global_index,
    }
}

fn build_app(indexer: Arc<dyn IndexerQuery>) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let compat: Arc<dyn NodeChainQuery> = Arc::new(StubCompat);
    router(
        read,
        Some(compat),
        None,
        Some(indexer),
        NetworkPrefix::Mainnet,
    )
}

async fn json_get(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    decode_response(resp).await
}

async fn json_post_empty(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    decode_response(resp).await
}

async fn decode_response(resp: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

// ---- StubIndexer ----------------------------------------------------------

struct StubIndexer {
    status: IndexerStatus,
    boxes: Vec<IndexedErgoBox>,
}

impl StubIndexer {
    fn with_status(status: IndexerStatus) -> Self {
        Self {
            status,
            boxes: Vec::new(),
        }
    }
    fn caught_up(boxes: Vec<IndexedErgoBox>) -> Self {
        Self {
            status: IndexerStatus::CaughtUp,
            boxes,
        }
    }
}

impl IndexerQuery for StubIndexer {
    fn indexed_height(&self) -> u64 {
        0
    }
    fn status(&self) -> IndexerStatus {
        self.status.clone()
    }

    fn box_by_id(&self, _: &BoxId) -> Result<Option<IndexedBoxDto>, IndexerReadError> {
        Ok(None)
    }
    fn box_by_global_index(&self, _: u64) -> Result<Option<IndexedBoxDto>, IndexerReadError> {
        Ok(None)
    }
    fn boxes_by_global_range(
        &self,
        lo: u64,
        hi: u64,
    ) -> Result<Vec<IndexedBoxDto>, IndexerReadError> {
        Ok({
            let lo = lo as usize;
            let hi = (hi as usize).min(self.boxes.len());
            if lo >= self.boxes.len() {
                Vec::new()
            } else {
                self.boxes[lo..hi].to_vec()
            }
        })
    }

    fn tx_by_id(&self, _: &TxId) -> Result<Option<IndexedTxDto>, IndexerReadError> {
        Ok(None)
    }
    fn tx_by_global_index(&self, _: u64) -> Result<Option<IndexedTxDto>, IndexerReadError> {
        Ok(None)
    }
    fn txs_by_global_range(&self, _: u64, _: u64) -> Result<Vec<IndexedTxDto>, IndexerReadError> {
        Ok(Vec::new())
    }

    fn boxes_latest_paged(&self, page: Page) -> Result<Vec<IndexedBoxDto>, IndexerReadError> {
        Ok(self
            .boxes
            .iter()
            .rev()
            .skip(page.offset as usize)
            .take(page.limit as usize)
            .cloned()
            .collect())
    }

    fn address_balance(&self, _: &TreeHash) -> Result<Option<BalanceDto>, IndexerReadError> {
        Ok(None)
    }
    fn address_txs_paged(
        &self,
        _: &TreeHash,
        _: Page,
        _: SortDir,
    ) -> Result<Vec<IndexedTxDto>, IndexerReadError> {
        Ok(Vec::new())
    }
    fn address_boxes_paged(
        &self,
        _: &TreeHash,
        _: Page,
        _: SortDir,
    ) -> Result<Vec<IndexedBoxDto>, IndexerReadError> {
        Ok(Vec::new())
    }
    fn address_unspent_paged(
        &self,
        _: &TreeHash,
        _: Page,
        _: SortDir,
    ) -> Result<Vec<IndexedBoxDto>, IndexerReadError> {
        Ok(Vec::new())
    }
    fn address_total_txs(&self, _: &TreeHash) -> Result<u64, IndexerReadError> {
        Ok(0)
    }
    fn address_total_boxes(&self, _: &TreeHash) -> Result<u64, IndexerReadError> {
        Ok(0)
    }

    fn template_boxes_paged(
        &self,
        _: &TemplateHash,
        _: Page,
    ) -> Result<Vec<IndexedBoxDto>, IndexerReadError> {
        Ok(Vec::new())
    }
    fn template_unspent_paged(
        &self,
        _: &TemplateHash,
        _: Page,
        _: SortDir,
    ) -> Result<Vec<IndexedBoxDto>, IndexerReadError> {
        Ok(Vec::new())
    }
    fn template_total_boxes(&self, _: &TemplateHash) -> Result<u64, IndexerReadError> {
        Ok(0)
    }

    fn token_by_id(&self, _: &TokenId) -> Result<Option<IndexedTokenDto>, IndexerReadError> {
        Ok(None)
    }
    fn tokens_by_ids(&self, _: &[TokenId]) -> Result<Vec<IndexedTokenDto>, IndexerReadError> {
        Ok(Vec::new())
    }
    fn token_boxes_paged(
        &self,
        _: &TokenId,
        _: Page,
    ) -> Result<Vec<IndexedBoxDto>, IndexerReadError> {
        Ok(Vec::new())
    }
    fn token_unspent_paged(
        &self,
        _: &TokenId,
        _: Page,
        _: SortDir,
    ) -> Result<Vec<IndexedBoxDto>, IndexerReadError> {
        Ok(Vec::new())
    }
    fn token_total_boxes(&self, _: &TokenId) -> Result<u64, IndexerReadError> {
        Ok(0)
    }
}

// ---- StubReadState / StubCompat (minimal) ---------------------------------

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
    fn mempool_transaction(&self, _: &str) -> Option<ApiMempoolTransaction> {
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

struct StubCompat;

impl NodeChainQuery for StubCompat {
    fn header_ids_at_height(&self, _: u32) -> Vec<String> {
        Vec::new()
    }
    fn full_block_by_id(&self, _: &str) -> Option<ScalaFullBlock> {
        None
    }
    fn info(&self) -> ScalaInfo {
        ScalaInfo {
            last_mempool_update_time: 0,
            current_time: 0,
            network: "mainnet".into(),
            name: "stub".into(),
            state_type: "utxo".into(),
            difficulty: 0,
            best_full_header_id: String::new(),
            best_header_id: String::new(),
            peers_count: 0,
            unconfirmed_count: 0,
            app_version: "0.1.0".into(),
            eip37_supported: true,
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
            eip27_supported: true,
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
}

#[allow(dead_code)]
fn _ensure_handle_use_compiles() {
    let _: ModifierId = ModifierId::from_bytes([0; 32]);
    let _ = IndexerHandle::syncing(0);
}
