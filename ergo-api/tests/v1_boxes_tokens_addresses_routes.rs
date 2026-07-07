//! Route-level integration tests for the second v1 group: `boxes/*` +
//! `tokens/*` + `addresses/*` reads (`dev-docs/v1-api-design.md` §3.7).
//!
//! Convention-lock tests: the honest `indexer_disabled` / `_syncing` /
//! `_halted` gating (v1 mounts unconditionally, never a bare 404 for a disabled
//! subsystem), the `{items, page}` collection envelope, the canonical typed
//! `invalid_*` reasons, the `addresses/{addr}/{boxes,unspent}` ≡
//! `boxes/{by-address,unspent/by-address}` dual mount (O10), and the honest
//! `state_unavailable` for the not-yet-indexable mint-order token list (G3).
//! Handlers are driven via `oneshot` over the store-less `IndexerHandle` (all
//! reads empty/None) so the envelope + gating are exercised in isolation.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use ergo_api::traits::{MempoolView, NodeReadState, NoopMempoolView};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_api::v1::{v1_router, V1State};
use ergo_indexer::{IndexerHaltReason, IndexerHandle, IndexerStatus};
use ergo_indexer_types::IndexerQuery;
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

const HEIGHT: u32 = 700_000;
const HEX_64: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// A real 33-byte compressed pubkey, for deriving a valid mainnet address.
const PK: &str = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";

fn mainnet_address() -> String {
    let pk = hex::decode(PK).unwrap();
    ergo_ser::address::encode_p2pk_from_pubkey(NetworkPrefix::Mainnet, &pk).unwrap()
}

// ----- indexer handles ----------------------------------------------------

fn caught_up() -> Arc<dyn IndexerQuery> {
    let h = IndexerHandle::syncing(HEIGHT as u64);
    h.set_status(IndexerStatus::CaughtUp);
    Arc::new(h)
}
fn syncing() -> Arc<dyn IndexerQuery> {
    Arc::new(IndexerHandle::syncing(HEIGHT as u64))
}
fn halted() -> Arc<dyn IndexerQuery> {
    Arc::new(IndexerHandle::halted(IndexerHaltReason::DbCorruption))
}

// ----- harness ------------------------------------------------------------

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
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(body)
        .unwrap();
    // Loopback → governor-exempt, so tests never flake on rate limits.
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

async fn get(indexer: Option<Arc<dyn IndexerQuery>>, uri: &str) -> (StatusCode, serde_json::Value) {
    send(app(indexer), Method::GET, uri, Body::empty()).await
}

fn reason(v: &serde_json::Value) -> &str {
    v["error"]["reason"].as_str().unwrap_or("<none>")
}

fn assert_page_envelope(body: &serde_json::Value) {
    assert!(body["items"].is_array(), "items must be an array: {body}");
    for key in ["limit", "next_cursor", "has_more"] {
        assert!(
            body["page"].get(key).is_some(),
            "page missing {key}: {body}"
        );
    }
}

// ----- gating -------------------------------------------------------------

#[tokio::test]
async fn boxes_without_indexer_are_indexer_disabled_not_bare_404() {
    let (status, body) = get(None, &format!("/api/v1/boxes/{HEX_64}")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reason(&body), "indexer_disabled");
}

#[tokio::test]
async fn boxes_while_syncing_is_indexer_syncing() {
    // The canonical `Reason` enum (G2 primitive) classes the subsystem-off
    // `indexer_syncing` as 409 CONFLICT, not 503 — the enum is the binding
    // contract (`ergo-api/src/v1/error.rs`), overriding the prose fragment.
    let (status, body) = get(Some(syncing()), &format!("/api/v1/boxes/{HEX_64}")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reason(&body), "indexer_syncing");
}

#[tokio::test]
async fn boxes_while_halted_is_indexer_halted() {
    let (status, body) = get(Some(halted()), &format!("/api/v1/boxes/{HEX_64}")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reason(&body), "indexer_halted");
}

// ----- boxes/{id} ---------------------------------------------------------

#[tokio::test]
async fn box_by_id_unknown_is_box_not_found() {
    let (status, body) = get(Some(caught_up()), &format!("/api/v1/boxes/{HEX_64}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(reason(&body), "box_not_found");
}

#[tokio::test]
async fn box_by_id_malformed_is_invalid_box_id() {
    let (status, body) = get(Some(caught_up()), "/api/v1/boxes/NOTHEX").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_box_id");
}

// ----- boxes/by-address (+ collection envelope + input validation) --------

#[tokio::test]
async fn boxes_by_address_empty_is_collection_envelope() {
    let (status, body) = get(
        Some(caught_up()),
        &format!("/api/v1/boxes/by-address/{}", mainnet_address()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_page_envelope(&body);
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    assert_eq!(body["page"]["has_more"], serde_json::json!(false));
    assert!(body["page"]["next_cursor"].is_null());
    assert_eq!(body["page"]["limit"].as_u64(), Some(20)); // group default
}

#[tokio::test]
async fn boxes_by_address_invalid_address_is_invalid_address() {
    let (status, body) = get(Some(caught_up()), "/api/v1/boxes/by-address/not-an-address").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_address");
}

#[tokio::test]
async fn boxes_by_address_bad_sort_is_invalid_sort_direction() {
    let (status, body) = get(
        Some(caught_up()),
        &format!(
            "/api/v1/boxes/by-address/{}?sort=sideways",
            mainnet_address()
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_sort_direction");
}

#[tokio::test]
async fn boxes_by_address_tampered_cursor_is_invalid_cursor() {
    let (status, body) = get(
        Some(caught_up()),
        &format!(
            "/api/v1/boxes/by-address/{}?cursor=!!!bad",
            mainnet_address()
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_cursor");
}

// ----- boxes/by-ergo-tree -------------------------------------------------

#[tokio::test]
async fn boxes_by_ergo_tree_bad_hex_is_invalid_ergo_tree() {
    let (status, body) = send(
        app(Some(caught_up())),
        Method::POST,
        "/api/v1/boxes/by-ergo-tree",
        Body::from(serde_json::json!({ "ergo_tree": "zzzz" }).to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_ergo_tree");
}

// ----- boxes/by-template + by-token empty-parity + range ------------------

#[tokio::test]
async fn boxes_by_template_unknown_is_empty_page_not_404() {
    let (status, body) = get(
        Some(caught_up()),
        &format!("/api/v1/boxes/by-template/{HEX_64}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_page_envelope(&body);
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn boxes_by_token_unknown_is_empty_page_not_404() {
    let (status, body) = get(
        Some(caught_up()),
        &format!("/api/v1/boxes/by-token/{HEX_64}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_page_envelope(&body);
}

#[tokio::test]
async fn box_range_is_id_collection_with_range_cap_limit() {
    let (status, body) = get(Some(caught_up()), "/api/v1/boxes/range").await;
    assert_eq!(status, StatusCode::OK);
    assert_page_envelope(&body);
    assert_eq!(body["page"]["limit"].as_u64(), Some(100)); // range default
}

// ----- tokens -------------------------------------------------------------

#[tokio::test]
async fn token_by_id_unknown_is_token_not_found() {
    let (status, body) = get(Some(caught_up()), &format!("/api/v1/tokens/{HEX_64}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(reason(&body), "token_not_found");
}

#[tokio::test]
async fn token_by_id_malformed_is_invalid_token_id() {
    let (status, body) = get(Some(caught_up()), "/api/v1/tokens/NOTHEX").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_token_id");
}

#[tokio::test]
async fn tokens_list_is_honest_state_unavailable_not_faked() {
    let (status, body) = get(Some(caught_up()), "/api/v1/tokens").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reason(&body), "state_unavailable");
}

#[tokio::test]
async fn token_holders_empty_is_collection_with_meta() {
    let (status, body) = get(
        Some(caught_up()),
        &format!("/api/v1/tokens/{HEX_64}/holders"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_page_envelope(&body);
    // Part D: the whole-result scalars live under `meta`, not as top-level siblings.
    for key in ["as_of_height", "scanned_boxes", "scan_capped"] {
        assert!(
            body["meta"].get(key).is_some(),
            "meta missing {key}: {body}"
        );
    }
    assert!(
        body.get("scanned_boxes").is_none(),
        "no ad-hoc top-level siblings"
    );
    assert_eq!(body["meta"]["scan_capped"], serde_json::json!(false));
}

#[tokio::test]
async fn token_stats_unknown_token_is_token_not_found() {
    let (status, body) = get(Some(caught_up()), &format!("/api/v1/tokens/{HEX_64}/stats")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(reason(&body), "token_not_found");
}

// ----- addresses ----------------------------------------------------------

#[tokio::test]
async fn address_balance_shape_uses_value_leaf_and_dual_scopes() {
    let (status, body) = get(
        Some(caught_up()),
        &format!("/api/v1/addresses/{}/balance", mainnet_address()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["address"], serde_json::json!(mainnet_address()));
    // nanoERG leaf is `value` (glossary C.2), a string; both scopes present.
    assert_eq!(body["confirmed"]["value"], serde_json::json!("0"));
    assert!(body["confirmed"]["assets"].is_array());
    assert!(body["unconfirmed"].get("value").is_some());
    assert!(body.get("nanoErgs").is_none());
}

#[tokio::test]
async fn address_transactions_is_collection_envelope() {
    let (status, body) = get(
        Some(caught_up()),
        &format!("/api/v1/addresses/{}/transactions", mainnet_address()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_page_envelope(&body);
}

#[tokio::test]
async fn addresses_boxes_is_dual_mount_of_boxes_by_address() {
    let addr = mainnet_address();
    let (s1, b1) = get(
        Some(caught_up()),
        &format!("/api/v1/boxes/by-address/{addr}"),
    )
    .await;
    let (s2, b2) = get(
        Some(caught_up()),
        &format!("/api/v1/addresses/{addr}/boxes"),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    // ONE handler, two mounts (O10) — byte-identical responses.
    assert_eq!(b1, b2);
}

#[tokio::test]
async fn addresses_unspent_is_dual_mount_of_boxes_unspent_by_address() {
    let addr = mainnet_address();
    let (s1, b1) = get(
        Some(caught_up()),
        &format!("/api/v1/boxes/unspent/by-address/{addr}"),
    )
    .await;
    let (s2, b2) = get(
        Some(caught_up()),
        &format!("/api/v1/addresses/{addr}/unspent"),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b1, b2);
}

// ----- semantic decode / protocol registry (§4.3) -------------------------

// SigmaUSD v2 identifying tokens (grounded vs mainnet token metadata).
const SIGUSD_BANK_NFT: &str = "7d672d1def471720ca5b1dd6a56b48a83db78f5510c2a48800a5e2588f43c9e5";

#[tokio::test]
async fn protocols_list_advertises_registry_capabilities() {
    let (status, body) = get(None, "/api/v1/protocols").await;
    assert_eq!(status, StatusCode::OK);
    assert_page_envelope(&body);
    // SigmaUSD is present and fully decodable.
    let sigusd = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["protocol_id"] == "sigmausd")
        .expect("sigmausd registered");
    assert_eq!(sigusd["decodable"], serde_json::json!(true));
    assert_eq!(sigusd["family"], "bank");
    // Stubs are advertised but honestly not decodable (no fabricated support).
    let spectrum = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["protocol_id"] == "spectrum")
        .expect("spectrum registered as a stub");
    assert_eq!(spectrum["decodable"], serde_json::json!(false));
    assert_eq!(spectrum["matcher_count"], serde_json::json!(0));
}

#[tokio::test]
async fn protocol_detail_exposes_matchers_for_client_precompute() {
    let (status, body) = get(None, "/api/v1/protocols/sigmausd").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["protocol_id"], "sigmausd");
    let matchers = body["matchers"].as_array().unwrap();
    assert!(matchers
        .iter()
        .any(|m| m["kind"] == "identifying_token" && m["key"] == SIGUSD_BANK_NFT));
}

#[tokio::test]
async fn protocol_detail_unknown_is_protocol_not_found() {
    let (status, body) = get(None, "/api/v1/protocols/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(reason(&body), "protocol_not_found");
}

#[tokio::test]
async fn boxes_decode_sigmausd_structured_box_populates_state() {
    // The route path (`POST /boxes/decode`) drives the same decode seam as
    // `boxes/{id}?decode=true`. Synthetic SigmaUSD bank body (verified token +
    // register layout; numbers chosen) → decoded contract state.
    let body = serde_json::json!({
        "ergo_tree": "0008cd02a7955281885bf0f0ca4a48678848c4a9d301d5cabd2d3428f77c2b1d9761b6e6",
        "value": "1402000000000000",
        "assets": [
            { "token_id": SIGUSD_BANK_NFT, "amount": "1" },
            { "token_id": "03faf2cb329f2e90d6d23b58d91bbb6c046aa143261cc21f52fbe2824bfcbf04", "amount": "9000000000" }
        ],
        // R4 = SLong(1200345), R5 = SLong(9930021) — real zig-zag VLQ encoding.
        "registers": { "R4": "05b2c39201", "R5": "05ca94bc09" }
    });
    let (status, resp) = send(
        app(None),
        Method::POST,
        "/api/v1/boxes/decode",
        Body::from(body.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "resp: {resp}");
    let contract = &resp["decoded"]["contract"];
    assert_eq!(contract["protocol_id"], "sigmausd");
    assert_eq!(contract["matched_by"], "identifying_token");
    assert_eq!(contract["state"]["reserve_nanoerg"], "1402000000000000");
    assert_eq!(contract["state"]["circulating_sigusd"], "1200345");
    assert_eq!(contract["state"]["oracle_derived_price_available"], false);
}

#[tokio::test]
async fn boxes_decode_unrecognized_box_is_honest_null_contract() {
    let body = serde_json::json!({
        "ergo_tree": "0008cd02a7955281885bf0f0ca4a48678848c4a9d301d5cabd2d3428f77c2b1d9761b6e6",
        "value": "1000000",
        "assets": [],
        "registers": {}
    });
    let (status, resp) = send(
        app(None),
        Method::POST,
        "/api/v1/boxes/decode",
        Body::from(body.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(resp["decoded"]["contract"].is_null());
    assert!(resp["decoded"]["registers"].is_object());
}

// ----- stub read state ----------------------------------------------------

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

// ----- extractor rejections stay in the v1 envelope (CodeRabbit #171 #2) ---

#[tokio::test]
async fn malformed_query_param_is_v1_invalid_params_envelope() {
    // `limit=abc` fails V1Query extraction; the failure must render the v1
    // envelope, not axum's default plain-text 400.
    let (status, body) = get(
        Some(caught_up()),
        &format!("/api/v1/boxes/by-token/{HEX_64}?limit=abc"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "invalid_params");
}

#[tokio::test]
async fn malformed_json_body_is_v1_bad_request_envelope() {
    // A body that isn't valid JSON fails V1Json extraction on the POST
    // by-ergo-tree route; the failure must render the v1 envelope.
    let (status, body) = send(
        app(Some(caught_up())),
        Method::POST,
        "/api/v1/boxes/by-ergo-tree",
        Body::from("{ not json"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), "bad_request");
}
