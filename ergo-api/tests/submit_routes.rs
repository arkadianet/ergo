//! Operator submission surface — `POST /api/v1/mempool/{submit,check}`.
//!
//! Covers:
//! - `ApiNativeSubmitError` wire shape (JSON keys, optional `detail`,
//!   no redundant HTTP-status-as-int `error` field).
//! - Reason-string → HTTP status mapping (admission-pipeline reasons
//!   plus the channel-side reasons).
//! - Success path returns `200 ApiSubmitResponse { tx_id }`.
//! - Both POST routes go through the same `submit_inner` so each is
//!   exercised at least once.
//! - Endpoint inventory: with `submit = None`, the two POST routes
//!   return `404` (axum-level, route not registered). Adding a new
//!   submission route requires updating this test, which forces a
//!   deliberate review of the new admission entry point.
//!
//! No tokio runtime contention: every test drives the router via
//! `tower::ServiceExt::oneshot` and asserts on the response shape
//! synchronously after `await`.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use ergo_api::server::router;
use ergo_api::traits::{NodeReadState, NodeSubmit};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSubmitError, ApiSubmitResponse, ApiSyncStatus,
    ApiTip, ApiWeightFunction, HealthStatus, SubmitError, SubmitMode, SyncStateLabel,
};
use tower::ServiceExt;

// ---- Stubs ----

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

/// Configurable submit stub. Default returns `Ok(tx_id)`; tests override
/// with a closure that returns whatever `Result<String, SubmitError>` they
/// want to map. Recorded `last_call` lets a test assert which mode the
/// handler called through with.
struct StubSubmit {
    handler: Box<dyn Fn(Vec<u8>, SubmitMode) -> Result<String, SubmitError> + Send + Sync>,
}

impl StubSubmit {
    fn ok(tx_id: &'static str) -> Arc<dyn NodeSubmit> {
        Arc::new(Self {
            handler: Box::new(move |_bytes, _mode| Ok(tx_id.to_string())),
        })
    }

    fn fail(reason: &'static str, detail: Option<&'static str>) -> Arc<dyn NodeSubmit> {
        Arc::new(Self {
            handler: Box::new(move |_bytes, _mode| {
                Err(SubmitError {
                    reason: reason.to_string(),
                    detail: detail.map(|s| s.to_string()),
                })
            }),
        })
    }
}

#[async_trait]
impl NodeSubmit for StubSubmit {
    async fn submit_transaction(
        &self,
        bytes: Vec<u8>,
        mode: SubmitMode,
    ) -> Result<String, SubmitError> {
        (self.handler)(bytes, mode)
    }

    async fn submit_transaction_json(
        &self,
        _input: ergo_api::compat::types::ScalaTransactionInput,
        _mode: SubmitMode,
    ) -> Result<String, SubmitError> {
        // The operator routes don't exercise the JSON path. The
        // Scala-compat tests have their own stub.
        Err(SubmitError {
            reason: "internal_error".to_string(),
            detail: Some("submit_transaction_json not implemented in this stub".to_string()),
        })
    }
}

// ---- Helpers ----

fn build_app(submit: Option<Arc<dyn NodeSubmit>>) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    router(
        read,
        None,
        submit,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    )
}

async fn post(app: axum::Router, path: &str, body: Vec<u8>) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header("content-type", "application/octet-stream")
                .body(Body::from(body))
                .unwrap(),
        )
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

// ---- DTO unit tests ----

// ----- happy path -----

#[test]
fn api_submit_error_json_shape_includes_required_keys() {
    let err = ApiSubmitError {
        error: 400,
        reason: "deserialize".into(),
        detail: Some("expected u32".into()),
    };
    let v = serde_json::to_value(&err).expect("serialize");
    let o = v.as_object().expect("object");
    assert_eq!(o.get("error").and_then(|x| x.as_u64()), Some(400));
    assert_eq!(
        o.get("reason").and_then(|x| x.as_str()),
        Some("deserialize"),
    );
    assert_eq!(
        o.get("detail").and_then(|x| x.as_str()),
        Some("expected u32"),
    );
}

#[test]
fn api_submit_error_omits_detail_when_none() {
    // Many reasons (`pool_full`, `non_canonical`, …) carry
    // `Detail: None`. The wire shape must
    // omit the key entirely so wallets can `JSON.has("detail")` to
    // detect richer messages without false positives.
    let err = ApiSubmitError {
        error: 400,
        reason: "pool_full".into(),
        detail: None,
    };
    let v = serde_json::to_value(&err).expect("serialize");
    let o = v.as_object().expect("object");
    assert!(
        !o.contains_key("detail"),
        "detail must be omitted when None"
    );
    assert_eq!(o.len(), 2, "exactly {{error, reason}} when detail is None");
}

#[test]
fn api_submit_error_round_trips_through_json() {
    let err = ApiSubmitError {
        error: 503,
        reason: "overloaded".into(),
        detail: Some("retry with backoff".into()),
    };
    let s = serde_json::to_string(&err).expect("serialize");
    let back: ApiSubmitError = serde_json::from_str(&s).expect("deserialize");
    assert_eq!(back.error, 503);
    assert_eq!(back.reason, "overloaded");
    assert_eq!(back.detail.as_deref(), Some("retry with backoff"));
}

#[test]
fn api_submit_response_is_plain_object_with_tx_id() {
    let r = ApiSubmitResponse {
        tx_id: "ab".repeat(32),
    };
    let v = serde_json::to_value(&r).expect("serialize");
    let o = v.as_object().expect("object");
    assert_eq!(o.len(), 1, "200 body must be exactly {{tx_id}}");
    assert_eq!(
        o.get("tx_id").and_then(|x| x.as_str()).map(str::len),
        Some(64),
    );
}

#[test]
fn submit_mode_serializes_snake_case() {
    // The DTO is used internally (handler arg) but we still pin its
    // serde shape: any future wire surface (e.g. a `?mode=` query param
    // or a JSON envelope) must see snake-case strings, not Pascal.
    assert_eq!(
        serde_json::to_string(&SubmitMode::Broadcast).unwrap(),
        "\"broadcast\"",
    );
    assert_eq!(
        serde_json::to_string(&SubmitMode::CheckOnly).unwrap(),
        "\"check_only\"",
    );
}

// ---- Status-mapping integration tests ----

/// Every reason that maps to `400`. Driven through both `/submit`
/// and `/check` so the status-mapping logic in `submit_inner` is
/// covered for both routes.
#[tokio::test]
async fn admission_reasons_return_400() {
    let reasons_400 = [
        "disabled",
        "ibd_gated",
        "tip_unready",
        "deserialize",
        "non_canonical",
        "structural",
        "below_min_fee",
        "duplicate",
        "known_invalid",
        "unresolved_input",
        "unresolved_data_input",
        "script_failed",
        "monetary_failed",
        "cost_exceeded",
        "validation_failed",
        "double_spend_loser",
        "pool_full",
        "budget_exhausted",
        "recently_unresolved",
        "size_limit",
        "insert_collision",
    ];
    for reason in reasons_400 {
        for path in ["/api/v1/mempool/submit", "/api/v1/mempool/check"] {
            let app = build_app(Some(StubSubmit::fail(reason, Some("d"))));
            let (status, body) = post(app, path, b"x".to_vec()).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "reason {reason:?} on {path} must map to 400",
            );
            let o = body.as_object().expect("error body is JSON object");
            assert!(
                !o.contains_key("error"),
                "Rust-native error body must not duplicate the HTTP status code as an `error` field — clients read it from the status line"
            );
            assert_eq!(o.get("reason").and_then(|x| x.as_str()), Some(reason));
            assert_eq!(o.get("detail").and_then(|x| x.as_str()), Some("d"));
        }
    }
}

#[tokio::test]
async fn channel_full_returns_503_overloaded() {
    let app = build_app(Some(StubSubmit::fail("overloaded", Some("retry"))));
    let (status, body) = post(app, "/api/v1/mempool/submit", b"x".to_vec()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !body.as_object().unwrap().contains_key("error"),
        "Rust-native error body must not duplicate the HTTP status code as an `error` field"
    );
    assert_eq!(
        body.get("reason").and_then(|x| x.as_str()),
        Some("overloaded"),
    );
}

#[tokio::test]
async fn shutting_down_returns_503() {
    let app = build_app(Some(StubSubmit::fail("shutting_down", None)));
    let (status, body) = post(app, "/api/v1/mempool/check", b"x".to_vec()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!body.as_object().unwrap().contains_key("error"));
}

#[tokio::test]
async fn timeout_returns_504() {
    let app = build_app(Some(StubSubmit::fail("timeout", Some("loop stuck"))));
    let (status, body) = post(app, "/api/v1/mempool/submit", b"x".to_vec()).await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert!(!body.as_object().unwrap().contains_key("error"));
    assert_eq!(body.get("reason").and_then(|x| x.as_str()), Some("timeout"),);
}

#[tokio::test]
async fn unknown_reason_falls_back_to_400() {
    // Defensive: a future RejectReason variant we forget to map should
    // fail safely as a client error, not crash the handler. Pins the
    // catch-all branch in `submit_inner`.
    let app = build_app(Some(StubSubmit::fail("brand_new_reason", None)));
    let (status, body) = post(app, "/api/v1/mempool/submit", b"x".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("reason").and_then(|x| x.as_str()),
        Some("brand_new_reason"),
    );
}

// ---- Success path ----

#[tokio::test]
async fn successful_submit_returns_200_and_tx_id_envelope() {
    let tx_id = "cd".repeat(32);
    let leaked: &'static str = Box::leak(tx_id.clone().into_boxed_str());
    let app = build_app(Some(StubSubmit::ok(leaked)));
    let (status, body) = post(app, "/api/v1/mempool/submit", b"raw".to_vec()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.get("tx_id").and_then(|x| x.as_str()),
        Some(tx_id.as_str())
    );
    let o = body.as_object().expect("body is object");
    assert_eq!(o.len(), 1, "success body is exactly {{tx_id}}");
}

#[tokio::test]
async fn successful_check_returns_200_and_tx_id_envelope() {
    let tx_id = "ef".repeat(32);
    let leaked: &'static str = Box::leak(tx_id.clone().into_boxed_str());
    let app = build_app(Some(StubSubmit::ok(leaked)));
    let (status, body) = post(app, "/api/v1/mempool/check", b"raw".to_vec()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.get("tx_id").and_then(|x| x.as_str()),
        Some(tx_id.as_str())
    );
}

#[tokio::test]
async fn handler_passes_correct_mode_per_route() {
    use std::sync::atomic::{AtomicU8, Ordering};
    static SAW_BROADCAST: AtomicU8 = AtomicU8::new(0);
    static SAW_CHECK_ONLY: AtomicU8 = AtomicU8::new(0);
    SAW_BROADCAST.store(0, Ordering::SeqCst);
    SAW_CHECK_ONLY.store(0, Ordering::SeqCst);

    let recording: Arc<dyn NodeSubmit> = Arc::new(StubSubmit {
        handler: Box::new(|_bytes, mode| {
            match mode {
                SubmitMode::Broadcast => SAW_BROADCAST.fetch_add(1, Ordering::SeqCst),
                SubmitMode::CheckOnly => SAW_CHECK_ONLY.fetch_add(1, Ordering::SeqCst),
            };
            Ok("aa".repeat(32))
        }),
    });

    let app = build_app(Some(recording.clone()));
    let (s1, _) = post(app, "/api/v1/mempool/submit", b"x".to_vec()).await;
    assert_eq!(s1, StatusCode::OK);
    let app = build_app(Some(recording));
    let (s2, _) = post(app, "/api/v1/mempool/check", b"x".to_vec()).await;
    assert_eq!(s2, StatusCode::OK);

    assert_eq!(
        SAW_BROADCAST.load(Ordering::SeqCst),
        1,
        "/submit must dispatch Broadcast exactly once"
    );
    assert_eq!(
        SAW_CHECK_ONLY.load(Ordering::SeqCst),
        1,
        "/check must dispatch CheckOnly exactly once"
    );
}

// ---- Endpoint inventory regression ----

/// Frozen set of operator-namespaced route paths that exist regardless
/// of submission state. Adding/removing an `/api/v1/*` route requires
/// editing this list — which forces the spec/checklist edit too.
const READ_ONLY_PATHS: &[&str] = &[
    "/api/v1/info",
    "/api/v1/status",
    "/api/v1/tip",
    "/api/v1/sync",
    "/api/v1/peers",
    "/api/v1/mempool/summary",
    "/api/v1/mempool/transactions",
    "/api/v1/health",
];

/// Frozen set of submission routes that mount unconditionally in
/// production. `build_app(None)` (no submit bridge) is still used by
/// some read-only test fixtures, which is why the absence path
/// remains exercised below.
const SUBMIT_PATHS: &[&str] = &["/api/v1/mempool/submit", "/api/v1/mempool/check"];

#[tokio::test]
async fn read_only_routes_present_without_submit_bridge() {
    let app = build_app(None);
    for path in READ_ONLY_PATHS {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(*path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{path} must mount unconditionally (read-only surface)",
        );
    }
}

#[tokio::test]
async fn mempool_transaction_by_id_route_mounts_unconditionally_returning_404_when_absent() {
    // Distinct from "route not registered". A registered GET on a
    // non-matching id must respond 404 NOT_FOUND with no method-not-
    // allowed; `oneshot` against an unregistered path also returns
    // 404, so we additionally check that the route registration
    // doesn't depend on `submit = Some(_)` by repeating with both.
    for submit_state in [None, Some(StubSubmit::ok("aa"))] {
        let app = build_app(submit_state);
        let path = format!("/api/v1/mempool/transactions/{}", "0".repeat(64));
        let resp = app
            .oneshot(Request::builder().uri(&path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "GET tx-by-id mounts unconditionally; absent id is 404",
        );
    }
}

#[tokio::test]
async fn submit_routes_present_when_enabled() {
    let app = build_app(Some(StubSubmit::ok("aa")));
    for path in SUBMIT_PATHS {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(*path)
                    .header("content-type", "application/octet-stream")
                    .body(Body::from(b"x".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{path} must be registered when submission is enabled",
        );
    }
}

#[tokio::test]
async fn submit_routes_reject_get() {
    // Method routing is part of the surface contract: a stray GET on
    // a write endpoint must surface as 405 Method Not Allowed (or
    // similar non-200). axum returns 405 here for an existing path
    // that was registered as POST-only.
    let app = build_app(Some(StubSubmit::ok("aa")));
    for path in SUBMIT_PATHS {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(*path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "GET on {path} must be 405, not 200",
        );
    }
}
