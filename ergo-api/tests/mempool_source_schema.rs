//! `/api/v1/mempool/transactions[/{tx_id}]` `.source` wire-shape pins.
//!
//! `source` is a tagged union, not a flat string; these tests pin the
//! end-to-end wire emission so it can't silently regress.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiHost, ApiIdentity, ApiInfo, ApiMempoolSummary,
    ApiMempoolTransaction, ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip,
    ApiTxSource, ApiWeightFunction, HealthStatus, SyncStateLabel,
};
use tower::ServiceExt;

const PEER_TX_ID: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const API_TX_ID: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const WALLET_TX_ID: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const DEMOTED_TX_ID: &str = "4444444444444444444444444444444444444444444444444444444444444444";

struct StubReadState;

impl StubReadState {
    fn fixture_tx(tx_id: &str, source: ApiTxSource) -> ApiMempoolTransaction {
        ApiMempoolTransaction {
            tx_id: tx_id.to_string(),
            fee_nano_erg: 1_500_000,
            fee_per_byte_nano_erg: 2_205,
            size_bytes: 680,
            validation_cost_units: 17_390,
            priority_weight: 88_326,
            source,
            input_count: 2,
            output_count: 3,
            parents_in_pool: 0,
            first_seen_unix_ms: 0,
            first_seen_age_ms: 0,
            last_checked_age_ms: 0,
        }
    }

    fn fixture_pool() -> Vec<ApiMempoolTransaction> {
        vec![
            Self::fixture_tx(
                PEER_TX_ID,
                ApiTxSource::Peer {
                    addr: "159.65.11.55:9030".to_string(),
                },
            ),
            Self::fixture_tx(API_TX_ID, ApiTxSource::Api),
            Self::fixture_tx(WALLET_TX_ID, ApiTxSource::Wallet),
            Self::fixture_tx(DEMOTED_TX_ID, ApiTxSource::DemotedFromBlock),
        ]
    }
}

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
            size: 4,
            total_bytes: 4 * 680,
            capacity_count: 1000,
            capacity_bytes: 1 << 20,
            revalidation_pending: 0,
        }
    }
    fn mempool_transactions(&self) -> ApiMempoolTransactions {
        let transactions = Self::fixture_pool();
        ApiMempoolTransactions {
            transactions,
            weight_function: ApiWeightFunction::Cost,
        }
    }
    fn mempool_transaction(&self, tx_id_hex: &str) -> Option<ApiMempoolTransaction> {
        Self::fixture_pool()
            .into_iter()
            .find(|t| t.tx_id == tx_id_hex)
    }
    fn health(&self) -> ApiHealth {
        ApiHealth {
            status: HealthStatus::Ok,
            behind: 0,
            last_progress_age_ms: 0,
            peer_count: 0,
        }
    }
    fn identity(&self) -> ApiIdentity {
        ApiIdentity::default()
    }
    fn host(&self) -> ApiHost {
        ApiHost::default()
    }
}

fn build_app() -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    router(
        read,
        None,
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    )
}

async fn get_json(uri: &str) -> (StatusCode, serde_json::Value) {
    let app = build_app();
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("body is JSON");
    (status, value)
}

// ----- list route -----

/// Every entry in `/api/v1/mempool/transactions` carries a tagged
/// `source` object — never a flat string. Pins the wire shape
/// against silent regression to a string.
#[tokio::test]
async fn mempool_list_source_is_tagged_object_not_string() {
    let (status, body) = get_json("/api/v1/mempool/transactions").await;
    assert_eq!(status, StatusCode::OK);
    let txs = body
        .get("transactions")
        .and_then(|v| v.as_array())
        .expect("body.transactions must be an array");
    assert!(!txs.is_empty(), "fixture pool must be non-empty");
    for (i, tx) in txs.iter().enumerate() {
        let src = tx
            .get("source")
            .unwrap_or_else(|| panic!("tx[{i}] missing source field"));
        assert!(
            src.is_object(),
            "tx[{i}].source must be a JSON object (tagged union), got {src}",
        );
        assert!(
            src.get("kind").and_then(|k| k.as_str()).is_some(),
            "tx[{i}].source.kind must be a string, got {src}",
        );
    }
}

/// `peer` variant carries `kind` + `addr` and nothing else; the
/// canonical Scala-shape host:port string lands on `addr`.
#[tokio::test]
async fn mempool_list_peer_variant_carries_kind_and_addr() {
    let (_status, body) = get_json("/api/v1/mempool/transactions").await;
    let txs = body
        .get("transactions")
        .and_then(|v| v.as_array())
        .expect("transactions array");
    let peer_tx = txs
        .iter()
        .find(|t| t.get("tx_id").and_then(|v| v.as_str()) == Some(PEER_TX_ID))
        .expect("peer fixture must be present");
    let src = peer_tx.get("source").unwrap();
    assert_eq!(
        src,
        &serde_json::json!({ "kind": "peer", "addr": "159.65.11.55:9030" }),
        "peer variant wire shape regression: got {src}",
    );
}

/// `api` / `wallet` / `demoted_from_block` unit variants emit only
/// `{"kind": "..."}` — no `addr`, no extra keys.
#[tokio::test]
async fn mempool_list_unit_variants_emit_kind_only() {
    let (_status, body) = get_json("/api/v1/mempool/transactions").await;
    let txs = body
        .get("transactions")
        .and_then(|v| v.as_array())
        .expect("transactions array");

    let cases = [
        (API_TX_ID, "api"),
        (WALLET_TX_ID, "wallet"),
        (DEMOTED_TX_ID, "demoted_from_block"),
    ];
    for (tx_id, expected_kind) in cases {
        let tx = txs
            .iter()
            .find(|t| t.get("tx_id").and_then(|v| v.as_str()) == Some(tx_id))
            .unwrap_or_else(|| panic!("fixture {tx_id} must be present"));
        let src = tx.get("source").and_then(|v| v.as_object()).unwrap();
        assert_eq!(
            src.len(),
            1,
            "{expected_kind} variant must have exactly one key (kind), got {src:?}",
        );
        assert_eq!(
            src.get("kind").and_then(|v| v.as_str()),
            Some(expected_kind),
        );
        assert!(
            !src.contains_key("addr"),
            "{expected_kind} variant must NOT carry addr, got {src:?}",
        );
    }
}

// ----- by-id route -----

/// `/api/v1/mempool/transactions/{tx_id}` emits the same tagged
/// source object — not a flat string and not omitted.
#[tokio::test]
async fn mempool_by_id_emits_tagged_source() {
    let (status, body) = get_json(&format!("/api/v1/mempool/transactions/{PEER_TX_ID}")).await;
    assert_eq!(status, StatusCode::OK);
    let src = body.get("source").unwrap_or_else(|| {
        panic!("by-id response must carry .source, got {body}");
    });
    assert_eq!(
        src,
        &serde_json::json!({ "kind": "peer", "addr": "159.65.11.55:9030" }),
        "by-id peer variant wire shape regression: got {src}",
    );
}

// ----- envelope-level weight_function + per-tx metric fields -----

/// `/api/v1/mempool/transactions` envelope carries `weight_function`
/// as a top-level field so clients can interpret `priority_weight`
/// against the active policy without an out-of-band config read.
#[tokio::test]
async fn mempool_list_envelope_carries_weight_function() {
    let (_status, body) = get_json("/api/v1/mempool/transactions").await;
    let wf = body
        .get("weight_function")
        .and_then(|v| v.as_str())
        .expect("envelope must carry weight_function as a string");
    assert!(
        matches!(wf, "cost" | "size" | "min"),
        "weight_function must be one of cost|size|min, got {wf:?}",
    );
}

/// Each mempool tx emits the metric fields `validation_cost_units`
/// and `priority_weight` (units are explicit, not the bare
/// `cost` / `weight` they replace).
#[tokio::test]
async fn mempool_list_tx_carries_renamed_metric_fields() {
    let (_status, body) = get_json("/api/v1/mempool/transactions").await;
    let tx = body
        .get("transactions")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .expect("fixture pool is non-empty");
    let cost = tx
        .get("validation_cost_units")
        .and_then(|v| v.as_u64())
        .expect("validation_cost_units must be present as a number");
    let weight = tx
        .get("priority_weight")
        .and_then(|v| v.as_u64())
        .expect("priority_weight must be present as a number");
    assert_eq!(cost, 17_390, "fixture validation_cost_units");
    assert_eq!(weight, 88_326, "fixture priority_weight");
}

/// Legacy field names `cost` and `weight` MUST be absent on every tx
/// emission — clients that grep for them must see them gone, not
/// silently shadowed by both old + new keys. Tripwire against a
/// future merge accidentally re-introducing the old names.
#[tokio::test]
async fn mempool_list_legacy_cost_and_weight_keys_are_absent() {
    let (_status, body) = get_json("/api/v1/mempool/transactions").await;
    for (i, tx) in body
        .get("transactions")
        .and_then(|v| v.as_array())
        .expect("transactions array")
        .iter()
        .enumerate()
    {
        let obj = tx.as_object().unwrap();
        assert!(
            !obj.contains_key("cost"),
            "tx[{i}] must not carry legacy `cost` key, got keys = {:?}",
            obj.keys().collect::<Vec<_>>(),
        );
        assert!(
            !obj.contains_key("weight"),
            "tx[{i}] must not carry legacy `weight` key, got keys = {:?}",
            obj.keys().collect::<Vec<_>>(),
        );
    }
}
