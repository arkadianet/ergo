//! Shape parity for `GET /blocks/{headerId}/proofFor/{txId}`.
//!
//! Mirrors `BlocksApiRoute.scala:78-91, 155-157`. Wire shape per
//! `ApiCodecs.scala:48-60`:
//! ```json
//! { "leafData": "<hex>", "levels": [["<hex>", 0|1], ...] }
//! ```
//! Empty siblings (odd-paired) serialize as `""`.
//!
//! Crypto correctness lives in `ergo-crypto` unit tests; this file
//! pins the JSON wire format and 404 paths.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ergo_api::compat::traits::NodeChainQuery;
use ergo_api::compat::types::{Parameters, ScalaFullBlock, ScalaInfo, ScalaMerkleProof};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use tower::ServiceExt;

const FIXTURE_700K: &str = include_str!("fixtures/scala/blocks/700000.json");

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

const HEADER_ID_KNOWN: &str = "54dd49ffbb32d35d8d6c41f3b427c68ac3cec91f6718fb7a50ec0d18d36e982a";
const TX_ID_IN_BLOCK: &str = "1111111111111111111111111111111111111111111111111111111111111111";

struct StubCompat;

impl NodeChainQuery for StubCompat {
    fn info(&self) -> ScalaInfo {
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

    fn header_ids_at_height(&self, _height: u32) -> Vec<String> {
        Vec::new()
    }

    fn full_block_by_id(&self, _header_id_hex: &str) -> Option<ScalaFullBlock> {
        None
    }

    fn proof_for_tx(&self, header_id_hex: &str, tx_id_hex: &str) -> Option<ScalaMerkleProof> {
        if header_id_hex == HEADER_ID_KNOWN && tx_id_hex == TX_ID_IN_BLOCK {
            // A 2-leaf proof at index 0: leafData=tx_id, one level
            // with sibling=leaf_hash(other_tx), side=0.
            Some(ScalaMerkleProof {
                leaf_data: TX_ID_IN_BLOCK.to_string(),
                levels: vec![("aa".repeat(32), 0)],
            })
        } else {
            None
        }
    }
}

async fn json_get(app: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

fn build_app() -> axum::Router {
    // Validate fixture parses; not consumed by these tests directly.
    let _: ScalaFullBlock = serde_json::from_str(FIXTURE_700K).expect("fixture parses");
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let compat: Arc<dyn NodeChainQuery> = Arc::new(StubCompat);
    router(
        read,
        Some(compat),
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    )
}

#[tokio::test]
async fn known_proof_returns_scala_shape() {
    let path = format!("/blocks/{HEADER_ID_KNOWN}/proofFor/{TX_ID_IN_BLOCK}");
    let (status, body) = json_get(build_app(), &path).await;
    assert_eq!(status, StatusCode::OK);
    let leaf_data = body.get("leafData").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(leaf_data, TX_ID_IN_BLOCK);
    let levels = body.get("levels").and_then(|v| v.as_array()).unwrap();
    assert_eq!(levels.len(), 1);
    let level0 = levels[0].as_array().unwrap();
    assert_eq!(level0.len(), 2, "each level is [hex_sibling, side_byte]");
    assert!(level0[0].is_string(), "sibling is a hex string");
    assert!(level0[1].is_number(), "side is a numeric byte");
}

#[tokio::test]
async fn unknown_header_returns_404() {
    let unknown = "0".repeat(64);
    let path = format!("/blocks/{unknown}/proofFor/{TX_ID_IN_BLOCK}");
    let (status, _) = json_get(build_app(), &path).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tx_not_in_block_returns_404() {
    let other_tx = "f".repeat(64);
    let path = format!("/blocks/{HEADER_ID_KNOWN}/proofFor/{other_tx}");
    let (status, _) = json_get(build_app(), &path).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn empty_sibling_serializes_as_empty_string() {
    // Pin the wire shape for the single-leaf / odd-paired empty
    // sibling case. The DTO uses Vec<(String, u8)>; empty hex must
    // remain an empty string after JSON round-trip — matches Scala's
    // `Base16.encode([])` = "" per `ApiCodecs.scala:50`.
    let proof = ScalaMerkleProof {
        leaf_data: "ab".repeat(32),
        levels: vec![(String::new(), 0)],
    };
    let json = serde_json::to_value(&proof).unwrap();
    let levels = json.get("levels").unwrap().as_array().unwrap();
    let entry = levels[0].as_array().unwrap();
    assert_eq!(entry[0].as_str().unwrap(), "");
    assert_eq!(entry[1].as_u64().unwrap(), 0);
}
