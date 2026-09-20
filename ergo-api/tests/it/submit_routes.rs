//! Operator submission surface.
//!
//! Two layers:
//! - DTO wire-shape unit tests for the frozen `ApiSubmitError` /
//!   `ApiSubmitResponse` types (still used by the Scala-compat submit path).
//! - Integration tests for `POST /api/v1/mempool/{submit,check}`, which are
//!   now Overlap-O1 **aliases** of the canonical `transactions/{submit,check}`
//!   v1 handlers: same handler, second mount. They therefore emit the v1 error
//!   envelope `{error:{reason,message,detail}}` (not the old flat native shape)
//!   and mount unconditionally, answering `409 submit_disabled` when no submit
//!   bridge is wired rather than a bare 404.
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

// ---- v1 alias integration tests ----
//
// `mempool/{submit,check}` are the SAME v1 handler as
// `transactions/{submit,check}`; these tests assert the alias mounts and
// emits the v1 envelope. The reason→status mapping itself is exhaustively
// covered by the canonical routes in `v1_chain_tx_routes.rs`.

fn v1_reason(v: &serde_json::Value) -> String {
    v["error"]["reason"]
        .as_str()
        .unwrap_or("<none>")
        .to_string()
}

#[tokio::test]
async fn mempool_submit_alias_returns_tx_id() {
    let tx_id = "cd".repeat(32);
    let leaked: &'static str = Box::leak(tx_id.clone().into_boxed_str());
    let app = build_app(Some(StubSubmit::ok(leaked)));
    let (status, body) = post(app, "/api/v1/mempool/submit", b"raw".to_vec()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.get("tx_id").and_then(|x| x.as_str()),
        Some(tx_id.as_str())
    );
    assert_eq!(
        body.as_object().map(|o| o.len()),
        Some(1),
        "body is {{tx_id}}"
    );
}

#[tokio::test]
async fn mempool_check_alias_returns_tx_id() {
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
async fn mempool_submit_rejection_is_v1_envelope() {
    let app = build_app(Some(StubSubmit::fail(
        "double_spend",
        Some("box already spent"),
    )));
    let (status, body) = post(app, "/api/v1/mempool/submit", b"x".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v1_reason(&body), "double_spend");
    assert_eq!(
        body["error"]["detail"],
        serde_json::json!("box already spent")
    );
    assert!(body["error"]["message"].is_string());
}

#[tokio::test]
async fn mempool_submit_overloaded_is_503() {
    let app = build_app(Some(StubSubmit::fail("overloaded", None)));
    let (status, body) = post(app, "/api/v1/mempool/submit", b"x".to_vec()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v1_reason(&body), "overloaded");
}

#[tokio::test]
async fn mempool_submit_without_bridge_is_submit_disabled_409() {
    // The v1 posture: the alias mounts unconditionally and answers the honest
    // `409 submit_disabled` reason, never a bare 404.
    let app = build_app(None);
    let (status, body) = post(app, "/api/v1/mempool/submit", b"x".to_vec()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(v1_reason(&body), "submit_disabled");
}

#[tokio::test]
async fn mempool_submit_and_check_dispatch_correct_mode() {
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
        "/submit → Broadcast"
    );
    assert_eq!(
        SAW_CHECK_ONLY.load(Ordering::SeqCst),
        1,
        "/check → CheckOnly"
    );
}

#[tokio::test]
async fn mempool_submit_and_check_reject_get() {
    let app = build_app(Some(StubSubmit::ok("aa")));
    for path in ["/api/v1/mempool/submit", "/api/v1/mempool/check"] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "GET on {path} must be 405, not 200",
        );
    }
}
