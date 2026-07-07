//! `/api/v1/mempool/*` v1 wire-shape pins (§3.8).
//!
//! The v1 product routes reshape the old native mempool endpoints: the list is
//! a `{items, page}` cursor collection, per-tx `source` is a FLAT snake_case
//! string (`peer|api|wallet|demoted_from_block` — the real `ApiTxSource`
//! taxonomy, projected down from the tagged union), fee/weight amounts are
//! strings, and `weight_function` moves onto `/summary`. These tests pin those
//! shapes end-to-end so they can't silently regress.

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

// ----- list route (v1 collection envelope) -----

/// The list is a `{items, page}` collection — the old flat
/// `{transactions, weight_function}` object is retired.
#[tokio::test]
async fn mempool_list_is_v1_collection_envelope() {
    let (status, body) = get_json("/api/v1/mempool/transactions").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("items").and_then(|v| v.as_array()).is_some(),
        "list must be a {{items, page}} collection, got {body}",
    );
    assert!(body.get("page").is_some(), "collection must carry page");
    assert!(
        body.get("transactions").is_none(),
        "legacy `transactions` key must be gone",
    );
}

/// Per-tx `source` is a FLAT snake_case string projected from the real
/// `ApiTxSource` taxonomy — never the old tagged object.
#[tokio::test]
async fn mempool_list_source_is_flat_string() {
    let (_status, body) = get_json("/api/v1/mempool/transactions").await;
    let items = body["items"].as_array().expect("items array");
    let cases = [
        (PEER_TX_ID, "peer"),
        (API_TX_ID, "api"),
        (WALLET_TX_ID, "wallet"),
        (DEMOTED_TX_ID, "demoted_from_block"),
    ];
    for (tx_id, expected) in cases {
        let tx = items
            .iter()
            .find(|t| t.get("tx_id").and_then(|v| v.as_str()) == Some(tx_id))
            .unwrap_or_else(|| panic!("fixture {tx_id} must be present"));
        assert_eq!(
            tx.get("source").and_then(|v| v.as_str()),
            Some(expected),
            "source must be the flat string {expected:?}, got {}",
            tx["source"],
        );
    }
}

/// Fee/weight amounts are strings (§1.1); the raw-number `ApiMempoolTransaction`
/// field names are gone. `first_seen` follows the §1.2 flat `*_unix_ms`+`*_iso`
/// rule.
#[tokio::test]
async fn mempool_list_amounts_are_strings_and_legacy_keys_absent() {
    let (_status, body) = get_json("/api/v1/mempool/transactions").await;
    let tx = &body["items"].as_array().expect("items")[0];
    for k in ["fee", "fee_per_byte", "priority_weight"] {
        assert!(tx[k].is_string(), "{k} must be a string, got {}", tx[k]);
    }
    assert!(tx["validation_cost_units"].is_u64());
    assert!(tx["first_seen_unix_ms"].is_u64());
    assert!(tx["first_seen_iso"].is_string());
    let obj = tx.as_object().unwrap();
    for legacy in ["fee_nano_erg", "fee_per_byte_nano_erg", "cost", "weight"] {
        assert!(
            !obj.contains_key(legacy),
            "legacy key {legacy:?} must be gone, keys = {:?}",
            obj.keys().collect::<Vec<_>>(),
        );
    }
}

// ----- by-id route -----

/// `/api/v1/mempool/transactions/{tx_id}` emits the same flat-string source and
/// carries the resolved `io_box` arrays (empty under the no-op overlay here).
#[tokio::test]
async fn mempool_by_id_emits_flat_source_and_io() {
    let (status, body) = get_json(&format!("/api/v1/mempool/transactions/{PEER_TX_ID}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["source"].as_str(), Some("peer"), "got {body}");
    assert_eq!(body["tx_id"].as_str(), Some(PEER_TX_ID));
    assert!(body["inputs"].is_array(), "detail carries io_box inputs");
    assert!(body["outputs"].is_array(), "detail carries io_box outputs");
}

/// A malformed id is `400 invalid_tx_id`; a well-formed-but-absent id is
/// `404 tx_not_found` — both enveloped, never a bare status.
#[tokio::test]
async fn mempool_by_id_error_envelopes() {
    let (status, body) = get_json("/api/v1/mempool/transactions/not-hex").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["reason"].as_str(), Some("invalid_tx_id"));

    let absent = "0".repeat(64);
    let (status, body) = get_json(&format!("/api/v1/mempool/transactions/{absent}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["reason"].as_str(), Some("tx_not_found"));
}

// ----- summary route -----

/// `weight_function` moves onto `/summary`, alongside derived `utilization`.
#[tokio::test]
async fn mempool_summary_carries_weight_function_and_utilization() {
    let (status, body) = get_json("/api/v1/mempool/summary").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        matches!(
            body["weight_function"].as_str(),
            Some("cost" | "size" | "min")
        ),
        "summary must carry weight_function, got {body}",
    );
    assert!(body["utilization"]["count_pct"].is_number());
    assert!(body["utilization"]["bytes_pct"].is_number());
    assert_eq!(body["size"].as_u64(), Some(4), "fixture pool size");
    assert!(
        body.get("history").is_none(),
        "history omitted unless ?history= is requested",
    );
}
