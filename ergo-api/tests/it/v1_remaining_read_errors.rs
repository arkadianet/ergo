//! Failed store reads must not become successful empty or partial product responses.
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use ergo_api::{
    compat::{ChainReadError, NodeChainQuery},
    server::{router_with_mempool, ServerCtx},
    traits::{MempoolView, NodeReadState, PoolTxDetail},
    types::*,
};
use ergo_indexer_types::{
    query::{BalanceDto, IndexedBoxDto, IndexedTokenDto, IndexedTxDto},
    BoxId, IndexerQuery, IndexerReadError, IndexerStatus, Page, SortDir, TemplateHash, TokenId,
    TreeHash, TxId,
};
use ergo_rest_json::types::{
    ScalaBlockTransactions, ScalaHeader, ScalaPopowHeader, ScalaPowSolutions,
};
use ergo_ser::address::NetworkPrefix;
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceExt;

// ----- helpers -----
const HEIGHT: u32 = 3;
const PRIVATE: &str = "private store path and read failure";
fn id(h: u32) -> String {
    format!("{h:064x}")
}
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
            best_input_block_id: None,
        }
    }
    fn status(&self) -> ApiStatus {
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
    fn mempool_transaction(&self, tx_id_hex: &str) -> Option<ApiMempoolTransaction> {
        (tx_id_hex == hex::encode(pool_transaction().0.as_bytes())).then(|| ApiMempoolTransaction {
            tx_id: tx_id_hex.into(),
            fee_nano_erg: 0,
            fee_per_byte_nano_erg: 0,
            size_bytes: 100,
            validation_cost_units: 1,
            priority_weight: 1,
            source: ApiTxSource::Peer {
                addr: "127.0.0.1:9030".into(),
            },
            input_count: 1,
            output_count: 0,
            parents_in_pool: 0,
            first_seen_unix_ms: 0,
            first_seen_age_ms: 0,
            last_checked_age_ms: 0,
        })
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

fn scala_header(height: u32) -> ScalaHeader {
    ScalaHeader {
        extension_id: id(0xe1),
        difficulty: "1200000".to_string(),
        votes: "000000".to_string(),
        timestamp: 1_700_000_000_000 + u64::from(height) * 120_000,
        size: 200,
        unparsed_bytes: String::new(),
        state_root: id(0x57),
        height,
        n_bits: 83_886_080,
        version: 3,
        id: id(height),
        ad_proofs_root: id(0xad),
        transactions_root: id(0x77),
        extension_hash: id(0xe2),
        pow_solutions: ScalaPowSolutions {
            pk: "03".to_string() + &"01".repeat(32),
            w: "03".to_string() + &"00".repeat(32),
            n: "0000000000000000".to_string(),
            d: serde_json::json!(0),
        },
        ad_proofs_id: id(0xa1),
        transactions_id: id(0x77),
        parent_id: id(height.saturating_sub(1)),
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Range,
    Transactions,
    Votes,
    Interlinks,
    Miners,
    Corrupt,
}
struct Store(Failure);
impl Store {
    fn error(&self) -> ChainReadError {
        if matches!(self.0, Failure::Corrupt) {
            ChainReadError::Corrupt("bad row".into())
        } else {
            ChainReadError::Unavailable(PRIVATE.into())
        }
    }
}
impl NodeChainQuery for Store {
    fn info(&self) -> ergo_api::compat::types::ScalaInfo {
        unreachable!()
    }
    fn full_block_by_id(&self, _id: &str) -> Option<ergo_rest_json::types::ScalaFullBlock> {
        unreachable!()
    }
    fn header_ids_at_height(&self, height: u32) -> Vec<String> {
        (1..=HEIGHT)
            .contains(&height)
            .then(|| id(height))
            .into_iter()
            .collect()
    }
    fn votes_history(&self) -> ApiVotesHistory {
        ApiVotesHistory {
            epoch_length: 1024,
            current_height: HEIGHT,
            changes: vec![],
        }
    }
    fn try_votes_history(&self) -> Result<ApiVotesHistory, ChainReadError> {
        assert!(matches!(self.0, Failure::Votes | Failure::Corrupt));
        Err(self.error())
    }
    fn chain_slice(&self, from: u32, to: u32) -> Vec<ScalaHeader> {
        (from.saturating_add(1)..=to.min(HEIGHT))
            .filter(|h| *h != 2 || !matches!(self.0, Failure::Range | Failure::Corrupt))
            .map(scala_header)
            .collect()
    }
    fn try_chain_slice(&self, from: u32, to: u32) -> Result<Vec<ScalaHeader>, ChainReadError> {
        if from < 2 && to >= 2 && matches!(self.0, Failure::Range | Failure::Corrupt) {
            return Err(self.error());
        }
        Ok(self.chain_slice(from, to))
    }
    fn block_transactions_by_id(&self, header: &str) -> Option<ScalaBlockTransactions> {
        let height = (1..=HEIGHT).find(|h| id(*h) == header)?;
        if height == 2 {
            None
        } else {
            Some(ScalaBlockTransactions {
                header_id: header.into(),
                transactions: vec![],
                size: 0,
                block_version: 3,
            })
        }
    }
    fn try_block_transactions_by_id(
        &self,
        header: &str,
    ) -> Result<Option<ScalaBlockTransactions>, ChainReadError> {
        if header == id(2) && matches!(self.0, Failure::Transactions) {
            Err(self.error())
        } else {
            Ok(self.block_transactions_by_id(header))
        }
    }
    fn last_headers(&self, count: u32) -> Vec<ScalaHeader> {
        assert_eq!(count, 3);
        vec![]
    }
    fn try_last_headers(&self, count: u32) -> Result<Vec<ScalaHeader>, ChainReadError> {
        assert_eq!(count, 3);
        Err(self.error())
    }
    fn nipopow_header_at_height(&self, height: u32) -> Option<ScalaPopowHeader> {
        assert!((1..=HEIGHT).contains(&height));
        None
    }
    fn try_nipopow_header_at_height(
        &self,
        height: u32,
    ) -> Result<Option<ScalaPopowHeader>, ChainReadError> {
        assert!((1..=HEIGHT).contains(&height));
        Err(self.error())
    }
}
struct StubIndexer;
impl IndexerQuery for StubIndexer {
    fn indexed_height(&self) -> u64 {
        u64::from(HEIGHT)
    }
    fn status(&self) -> IndexerStatus {
        IndexerStatus::CaughtUp
    }
    fn box_by_id(&self, id: &BoxId) -> Option<IndexedBoxDto> {
        assert_eq!(hex::encode(id.as_bytes()), format!("{:064x}", 1));
        None
    }
    fn try_box_by_id(&self, id: &BoxId) -> Result<Option<IndexedBoxDto>, IndexerReadError> {
        assert_eq!(hex::encode(id.as_bytes()), format!("{:064x}", 1));
        Err(IndexerReadError::new(PRIVATE))
    }
    fn try_token_by_id(&self, tid: &TokenId) -> Result<Option<IndexedTokenDto>, IndexerReadError> {
        assert_eq!(hex::encode(tid.as_bytes()), id(1));
        Err(IndexerReadError::new(PRIVATE))
    }
    fn box_by_global_index(&self, _n: u64) -> Option<IndexedBoxDto> {
        unreachable!("unexpected indexer query")
    }
    fn boxes_by_global_range(&self, _l: u64, _h: u64) -> Vec<IndexedBoxDto> {
        unreachable!("unexpected indexer query")
    }
    fn tx_by_id(&self, tx_id: &TxId) -> Option<IndexedTxDto> {
        assert_eq!(*tx_id, pool_transaction().0);
        None
    }
    fn tx_by_global_index(&self, _n: u64) -> Option<IndexedTxDto> {
        unreachable!("unexpected indexer query")
    }
    fn txs_by_global_range(&self, _l: u64, _h: u64) -> Vec<IndexedTxDto> {
        unreachable!("unexpected indexer query")
    }
    fn address_balance(&self, _t: &TreeHash) -> Option<BalanceDto> {
        unreachable!("unexpected indexer query")
    }
    fn address_txs_paged(&self, _t: &TreeHash, _p: Page, _d: SortDir) -> Vec<IndexedTxDto> {
        unreachable!("unexpected indexer query")
    }
    fn address_boxes_paged(&self, _t: &TreeHash, _p: Page, _d: SortDir) -> Vec<IndexedBoxDto> {
        unreachable!("unexpected indexer query")
    }
    fn address_unspent_paged(&self, _t: &TreeHash, _p: Page, _d: SortDir) -> Vec<IndexedBoxDto> {
        unreachable!("unexpected indexer query")
    }
    fn address_total_txs(&self, _t: &TreeHash) -> u64 {
        unreachable!("unexpected indexer query")
    }
    fn address_total_boxes(&self, _t: &TreeHash) -> u64 {
        unreachable!("unexpected indexer query")
    }
    fn template_boxes_paged(&self, _t: &TemplateHash, _p: Page) -> Vec<IndexedBoxDto> {
        unreachable!("unexpected indexer query")
    }
    fn template_unspent_paged(&self, t: &TemplateHash, p: Page, d: SortDir) -> Vec<IndexedBoxDto> {
        assert_eq!(hex::encode(t.as_bytes()), id(1));
        assert_eq!((p.offset, p.limit, d), (0, 21, SortDir::Desc));
        vec![]
    }
    fn try_template_unspent_paged(
        &self,
        t: &TemplateHash,
        p: Page,
        d: SortDir,
    ) -> Result<Vec<IndexedBoxDto>, IndexerReadError> {
        self.template_unspent_paged(t, p, d);
        Err(IndexerReadError::new(PRIVATE))
    }
    fn template_total_boxes(&self, _t: &TemplateHash) -> u64 {
        unreachable!("unexpected indexer query")
    }
    fn token_by_id(&self, tid: &TokenId) -> Option<IndexedTokenDto> {
        assert_eq!(hex::encode(tid.as_bytes()), id(1));
        None
    }
    fn tokens_by_ids(&self, _ids: &[TokenId]) -> Vec<IndexedTokenDto> {
        unreachable!("unexpected indexer query")
    }
    fn token_boxes_paged(&self, id: &TokenId, page: Page) -> Vec<IndexedBoxDto> {
        assert_eq!(hex::encode(id.as_bytes()), format!("{:064x}", 1));
        assert_eq!((page.offset, page.limit), (0, 2));
        Vec::new()
    }
    fn token_unspent_paged(&self, id: &TokenId, page: Page, dir: SortDir) -> Vec<IndexedBoxDto> {
        assert_eq!(hex::encode(id.as_bytes()), format!("{:064x}", 1));
        assert_eq!((page.offset, page.limit), (0, 1000));
        assert_eq!(dir, SortDir::Asc);
        Vec::new()
    }
    fn token_total_boxes(&self, _t: &TokenId) -> u64 {
        unreachable!("unexpected indexer query")
    }
}

fn pool_transaction() -> (TxId, Arc<[u8]>) {
    use ergo_ser::{
        input::{ContextExtension, Input, SpendingProof},
        transaction::{transaction_id, write_transaction, Transaction},
    };
    let tx = Transaction {
        inputs: vec![Input {
            box_id: BoxId::from_bytes(hex::decode(id(1)).unwrap().try_into().unwrap()),
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![],
    };
    let mut writer = ergo_primitives::writer::VlqWriter::new();
    write_transaction(&mut writer, &tx).unwrap();
    (
        TxId::from_bytes(*transaction_id(&tx).unwrap().as_bytes()),
        Arc::from(writer.result()),
    )
}
struct Pool;
impl MempoolView for Pool {
    fn is_spent_by_pool(&self, id: &BoxId) -> bool {
        hex::encode(id.as_bytes()) == format!("{:064x}", 1)
    }
    fn pool_spending_tx(&self, id: &BoxId) -> Option<TxId> {
        self.is_spent_by_pool(id).then(|| pool_transaction().0)
    }
    fn pool_outputs(&self) -> Arc<std::collections::HashMap<BoxId, ergo_ser::ergo_box::ErgoBox>> {
        Arc::new(Default::default())
    }
    fn pool_tx_detail(&self, id: &TxId) -> Option<PoolTxDetail> {
        let (actual, bytes) = pool_transaction();
        (*id == actual).then(|| (bytes, self.pool_outputs()))
    }
}
struct Emission;
impl ergo_api::emission::EmissionSchedule for Emission {
    fn emission_info_at(&self, height: u32) -> ergo_api::emission::EmissionInfoJson {
        ergo_api::emission::EmissionInfoJson {
            height,
            miner_reward: 1,
            total_coins_issued: u64::from(height),
            total_remain_coins: u64::from(u32::MAX - height),
            reemitted: 0,
        }
    }
}
async fn get(failure: Failure, uri: &str) -> (StatusCode, serde_json::Value) {
    let app = router_with_mempool(
        ServerCtx {
            read: Arc::new(StubRead),
            compat: Some(Arc::new(Store(failure))),
            submit: None,
            indexer: Some(Arc::new(StubIndexer)),
            mempool: Arc::new(Pool),
            network: NetworkPrefix::Mainnet,
            chain_params: None,
            mining: None,
            emission: Some(Arc::new(Emission)),
            emission_scripts: None,
            utxo_reads_supported: true,
            local_reverse_proxy: false,
        },
        None,
    );
    let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}
async fn assert_error(failure: Failure, uri: &str, status: StatusCode, reason: &str) {
    let (actual, body) = get(failure, uri).await;
    assert_eq!(actual, status, "{uri}: {body}");
    assert_eq!(body["error"]["reason"], reason, "{body}");
    assert!(!body.to_string().contains(PRIVATE));
}

// ----- error paths -----
#[tokio::test]
async fn voting_history_store_read_failure_is_503_not_empty() {
    assert_error(
        Failure::Votes,
        "/api/v1/voting/history",
        StatusCode::SERVICE_UNAVAILABLE,
        "chain_reader_unavailable",
    )
    .await;
}
#[tokio::test]
async fn stats_difficulty_store_read_failure_is_503_not_gapped_series() {
    assert_error(
        Failure::Range,
        "/api/v1/stats/difficulty?from_height=0&to_height=3",
        StatusCode::SERVICE_UNAVAILABLE,
        "chain_reader_unavailable",
    )
    .await;
}
#[tokio::test]
async fn stats_fees_store_read_failure_is_503_not_gapped_series() {
    assert_error(
        Failure::Transactions,
        "/api/v1/stats/fees?from_height=0&to_height=3",
        StatusCode::SERVICE_UNAVAILABLE,
        "chain_reader_unavailable",
    )
    .await;
}
#[tokio::test]
async fn stats_supply_store_read_failure_is_503_not_null_timestamps() {
    assert_error(
        Failure::Range,
        "/api/v1/stats/supply?from_height=0&to_height=3",
        StatusCode::SERVICE_UNAVAILABLE,
        "chain_reader_unavailable",
    )
    .await;
}
#[tokio::test]
async fn light_headers_interlinks_store_read_failure_is_503_not_nipopow_unavailable() {
    assert_error(
        Failure::Interlinks,
        "/api/v1/light/headers-interlinks?from_height=1",
        StatusCode::SERVICE_UNAVAILABLE,
        "chain_reader_unavailable",
    )
    .await;
}
#[tokio::test]
async fn mining_miner_stats_store_read_failure_is_503_not_empty() {
    assert_error(
        Failure::Miners,
        "/api/v1/mining/miner-stats?window=3",
        StatusCode::SERVICE_UNAVAILABLE,
        "chain_reader_unavailable",
    )
    .await;
}
#[tokio::test]
async fn boxes_by_id_indexer_read_failure_is_error_not_404() {
    assert_error(
        Failure::Votes,
        "/api/v1/boxes/0000000000000000000000000000000000000000000000000000000000000001",
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
    )
    .await;
}
#[tokio::test]
async fn tokens_by_id_indexer_read_failure_is_error_not_404() {
    assert_error(
        Failure::Votes,
        "/api/v1/tokens/0000000000000000000000000000000000000000000000000000000000000001",
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
    )
    .await;
}
#[tokio::test]
async fn tokens_stats_indexer_read_failure_is_error_not_404() {
    assert_error(
        Failure::Votes,
        "/api/v1/tokens/0000000000000000000000000000000000000000000000000000000000000001/stats",
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
    )
    .await;
}
#[tokio::test]
async fn stats_holders_indexer_read_failure_is_error_not_404() {
    assert_error(Failure::Votes,"/api/v1/stats/holders?token_id=0000000000000000000000000000000000000000000000000000000000000001",StatusCode::INTERNAL_SERVER_ERROR,"internal_error").await;
}

#[tokio::test]
async fn remaining_chain_routes_corrupt_row_is_500() {
    for uri in [
        "/api/v1/voting/history",
        "/api/v1/stats/difficulty?from_height=0&to_height=3",
        "/api/v1/stats/fees?from_height=0&to_height=3",
        "/api/v1/stats/supply?from_height=0&to_height=3",
        "/api/v1/mining/miner-stats?window=3",
        "/api/v1/light/headers-interlinks?from_height=1",
    ] {
        assert_error(
            Failure::Corrupt,
            uri,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
        )
        .await;
    }
}

#[tokio::test]
async fn transactions_input_indexer_read_failure_is_error_not_unresolved() {
    assert_error(
        Failure::Votes,
        &format!(
            "/api/v1/transactions/{}",
            hex::encode(pool_transaction().0.as_bytes())
        ),
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
    )
    .await;
}
#[tokio::test]
async fn mempool_input_indexer_read_failure_is_error_not_unresolved() {
    assert_error(
        Failure::Votes,
        &format!(
            "/api/v1/mempool/transactions/{}",
            hex::encode(pool_transaction().0.as_bytes())
        ),
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
    )
    .await;
}

#[tokio::test]
async fn boxes_unspent_template_indexer_read_failure_is_error_not_empty() {
    assert_error(
        Failure::Votes,
        &format!("/api/v1/boxes/unspent/by-template/{}", id(1)),
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
    )
    .await;
}

// ----- oracle parity -----
#[tokio::test]
async fn legacy_votes_history_store_read_failure_stays_200_empty() {
    let (status, body) = get(Failure::Votes, "/api/v1/votes/history").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::json!({"epochLength":1024,"currentHeight":HEIGHT,"changes":[]})
    );
}
#[tokio::test]
async fn compat_chain_slice_store_read_failure_stays_best_effort() {
    let (status, body) = get(Failure::Range, "/blocks/chainSlice?fromHeight=0&toHeight=3").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::to_value(vec![scala_header(1), scala_header(3)]).unwrap()
    );
}
