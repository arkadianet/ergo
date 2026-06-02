//! Scala-compat submission surface — `POST /transactions/bytes` and
//! the `checkBytes` / JSON twins.
//!
//! Covers:
//! - Success body is a bare JSON string (no envelope), per Scala's
//!   `ApiResponse(tx.id)` (`TransactionsApiRoute.scala:175`).
//! - Failure body is the `ApiSubmitError` shape matching Scala's
//!   `ApiError` (`{error, reason, detail?}`). Distinct from the
//!   Rust-native `ApiNativeSubmitError` used by `/api/v1/mempool/*`,
//!   which omits the redundant HTTP-status-as-int `error` field.
//! - `fromJsonOrPlain` body parsing: raw hex (no quotes) and
//!   JSON-quoted hex both decode to the same bytes.
//! - Bad hex returns `400 reason: "deserialize"` without ever calling
//!   the submit handler.
//! - Channel-side reasons (overloaded, shutting_down, timeout) still
//!   map to 503/504 even though Scala only emits 400 — our channel is
//!   real signal we don't have a way to hide.
//! - Route gating: `/transactions/bytes` requires both `compat = Some(_)`
//!   AND `submit = Some(_)`; either-only mounts a 404.
//!
//! No tokio runtime contention: every test drives the router via
//! `tower::ServiceExt::oneshot`.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use ergo_api::compat::types::{Parameters, ScalaFullBlock, ScalaInfo};
use ergo_api::compat::NodeChainQuery;
use ergo_api::server::router;
use ergo_api::traits::{NodeReadState, NodeSubmit};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SubmitError, SubmitMode, SyncStateLabel,
};
use tower::ServiceExt;

// ---- Stubs (minimal — only what the router needs for state) ----

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
    fn info(&self) -> ScalaInfo {
        // Minimal valid skeleton — submit-route tests don't exercise
        // /info, but the trait requires the method.
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
    fn header_ids_at_height(&self, _: u32) -> Vec<String> {
        Vec::new()
    }
    fn full_block_by_id(&self, _: &str) -> Option<ScalaFullBlock> {
        None
    }
}

type JsonHandler = Box<
    dyn Fn(
            ergo_api::compat::types::ScalaTransactionInput,
            SubmitMode,
        ) -> Result<String, SubmitError>
        + Send
        + Sync,
>;

struct StubSubmit {
    handler: Box<dyn Fn(Vec<u8>, SubmitMode) -> Result<String, SubmitError> + Send + Sync>,
    json_handler: JsonHandler,
}

impl StubSubmit {
    fn ok(tx_id: &'static str) -> Arc<dyn NodeSubmit> {
        Arc::new(Self {
            handler: Box::new(move |_, _| Ok(tx_id.to_string())),
            json_handler: default_json_handler(),
        })
    }
    fn fail(reason: &'static str, detail: Option<&'static str>) -> Arc<dyn NodeSubmit> {
        Arc::new(Self {
            handler: Box::new(move |_, _| {
                Err(SubmitError {
                    reason: reason.to_string(),
                    detail: detail.map(|s| s.to_string()),
                })
            }),
            json_handler: default_json_handler(),
        })
    }
    /// Echoes the bytes back as a hex tx_id. Used to assert the body
    /// the handler hands to the channel actually decoded as expected.
    fn echo() -> Arc<dyn NodeSubmit> {
        Arc::new(Self {
            handler: Box::new(|bytes, _| Ok(hex::encode(bytes))),
            json_handler: default_json_handler(),
        })
    }
    /// JSON-path success stub: returns a fixed `tx_id` and ignores the
    /// input. The route-level tests use this to confirm the handler
    /// invoked the bridge and shaped the success body correctly,
    /// independent of the bridge's decoding logic (which has its own
    /// unit tests in `ergo-node/src/api_bridge.rs`).
    fn json_ok(tx_id: &'static str) -> Arc<dyn NodeSubmit> {
        Arc::new(Self {
            handler: Box::new(|_, _| {
                Err(SubmitError {
                    reason: "internal_error".to_string(),
                    detail: Some("bytes path not exercised in this test".to_string()),
                })
            }),
            json_handler: Box::new(move |_, _| Ok(tx_id.to_string())),
        })
    }
    /// JSON-path failure stub: lets a test pin the error mapping
    /// (reason → status) for the JSON route, mirroring `fail()` for
    /// the bytes path.
    fn json_fail(reason: &'static str, detail: Option<&'static str>) -> Arc<dyn NodeSubmit> {
        Arc::new(Self {
            handler: Box::new(|_, _| {
                Err(SubmitError {
                    reason: "internal_error".to_string(),
                    detail: Some("bytes path not exercised in this test".to_string()),
                })
            }),
            json_handler: Box::new(move |_, _| {
                Err(SubmitError {
                    reason: reason.to_string(),
                    detail: detail.map(|s| s.to_string()),
                })
            }),
        })
    }
}

fn default_json_handler() -> JsonHandler {
    Box::new(|_, _| {
        Err(SubmitError {
            reason: "internal_error".to_string(),
            detail: Some("submit_transaction_json not implemented in this stub".to_string()),
        })
    })
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
        input: ergo_api::compat::types::ScalaTransactionInput,
        mode: SubmitMode,
    ) -> Result<String, SubmitError> {
        (self.json_handler)(input, mode)
    }
}

// ---- Helpers ----

fn build_app(
    compat: Option<Arc<dyn NodeChainQuery>>,
    submit: Option<Arc<dyn NodeSubmit>>,
) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    router(
        read,
        compat,
        submit,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    )
}

fn compat() -> Arc<dyn NodeChainQuery> {
    Arc::new(StubCompat)
}

async fn post_text(app: axum::Router, path: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, bytes.to_vec())
}

// ---- Success path ----

/// Plain hex body. Scala accepts unquoted hex via `fromJsonOrPlain`;
/// we mirror that. 200 body is the tx_id as a bare JSON string —
/// `Json("ab…")` serializes to `"ab…"`, exactly Scala's
/// `ApiResponse(tx.id)`.
#[tokio::test]
async fn plain_hex_body_returns_200_and_bare_json_string() {
    let tx_id: &'static str = Box::leak("aa".repeat(32).into_boxed_str());
    let app = build_app(Some(compat()), Some(StubSubmit::ok(tx_id)));
    let (status, body) = post_text(app, "/transactions/bytes", b"deadbeef".to_vec()).await;
    assert_eq!(status, StatusCode::OK);
    let s: String = serde_json::from_slice(&body).expect("body is a JSON string");
    assert_eq!(s, tx_id);
}

/// JSON-quoted hex body — what `node-ergo-cli` and curl-with-`Content-
/// Type: application/json` send. Scala's `fromJsonOrPlain` peels the
/// quotes; ours must too.
#[tokio::test]
async fn json_quoted_hex_body_decodes_to_same_bytes_as_plain() {
    let app = build_app(Some(compat()), Some(StubSubmit::echo()));
    let (s_plain, body_plain) = post_text(app, "/transactions/bytes", b"deadbeef".to_vec()).await;
    assert_eq!(s_plain, StatusCode::OK);
    let plain_id: String = serde_json::from_slice(&body_plain).unwrap();

    let app = build_app(Some(compat()), Some(StubSubmit::echo()));
    let (s_quoted, body_quoted) =
        post_text(app, "/transactions/bytes", b"\"deadbeef\"".to_vec()).await;
    assert_eq!(s_quoted, StatusCode::OK);
    let quoted_id: String = serde_json::from_slice(&body_quoted).unwrap();

    assert_eq!(
        plain_id, quoted_id,
        "plain vs JSON-quoted hex must decode identically"
    );
    assert_eq!(plain_id, "deadbeef");
}

/// Whitespace tolerance: Scala trims, we trim. A body of `"  ab cd  "`
/// (just leading/trailing whitespace, no internal whitespace) must
/// decode the same as `"abcd"` — handlers should be tolerant of
/// trailing newlines that some clients append.
#[tokio::test]
async fn body_whitespace_is_trimmed() {
    let app = build_app(Some(compat()), Some(StubSubmit::echo()));
    let (status, body) = post_text(app, "/transactions/bytes", b"  abcd  \n".to_vec()).await;
    assert_eq!(status, StatusCode::OK);
    let id: String = serde_json::from_slice(&body).unwrap();
    assert_eq!(id, "abcd");
}

// ---- Failure paths ----

/// Bad hex must surface as `400 reason: "deserialize"` *without*
/// ever invoking the channel — pinning the input-validation boundary
/// at the handler layer.
#[tokio::test]
async fn bad_hex_returns_400_deserialize_without_calling_submit() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static CALLED: AtomicBool = AtomicBool::new(false);
    CALLED.store(false, Ordering::SeqCst);

    let trap: Arc<dyn NodeSubmit> = Arc::new(StubSubmit {
        handler: Box::new(|_, _| {
            CALLED.store(true, Ordering::SeqCst);
            Ok(String::new())
        }),
        json_handler: default_json_handler(),
    });

    let app = build_app(Some(compat()), Some(trap));
    let (status, body) = post_text(app, "/transactions/bytes", b"xyz!".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let v: serde_json::Value = serde_json::from_slice(&body).expect("error body is JSON");
    assert_eq!(v.get("error").and_then(|x| x.as_u64()), Some(400));
    assert_eq!(
        v.get("reason").and_then(|x| x.as_str()),
        Some("deserialize")
    );
    assert!(
        v.get("detail").and_then(|x| x.as_str()).is_some(),
        "deserialize must include a detail explaining what failed",
    );

    assert!(
        !CALLED.load(Ordering::SeqCst),
        "submit handler must NOT be invoked when the body fails to decode",
    );
}

/// JSON-quoted but invalid hex inside the quotes — same bucket as
/// plain bad hex (deserialize, 400). Confirms the JSON-string parse
/// succeeded and the failure happened at hex_decode, not at JSON
/// parse — both go in the same bucket per spec.
#[tokio::test]
async fn json_quoted_bad_hex_returns_400_deserialize() {
    let app = build_app(Some(compat()), Some(StubSubmit::ok("aa")));
    let (status, body) = post_text(app, "/transactions/bytes", b"\"zzzz\"".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v.get("reason").and_then(|x| x.as_str()),
        Some("deserialize")
    );
}

/// Admission-pipeline rejections surface with the same `ApiSubmitError`
/// shape Scala uses for `ApiError`. Non-channel reasons map to 400.
#[tokio::test]
async fn admission_rejection_returns_400_with_api_error_shape() {
    let app = build_app(
        Some(compat()),
        Some(StubSubmit::fail(
            "unresolved_input",
            Some("box ab… not found"),
        )),
    );
    let (status, body) = post_text(app, "/transactions/bytes", b"ab".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v.get("error").and_then(|x| x.as_u64()), Some(400));
    assert_eq!(
        v.get("reason").and_then(|x| x.as_str()),
        Some("unresolved_input"),
    );
    assert_eq!(
        v.get("detail").and_then(|x| x.as_str()),
        Some("box ab… not found"),
    );
}

/// Channel-overload (`503`) and timeout (`504`) are non-Scala status
/// codes our spec emits because our channel-bounded design is real.
/// Wallets need to know the difference between "your tx is bad" and
/// "we're under load — try again".
#[tokio::test]
async fn channel_overload_returns_503() {
    let app = build_app(
        Some(compat()),
        Some(StubSubmit::fail("overloaded", Some("retry with backoff"))),
    );
    let (status, body) = post_text(app, "/transactions/bytes", b"ab".to_vec()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v.get("error").and_then(|x| x.as_u64()), Some(503));
    assert_eq!(v.get("reason").and_then(|x| x.as_str()), Some("overloaded"));
}

#[tokio::test]
async fn timeout_returns_504() {
    let app = build_app(
        Some(compat()),
        Some(StubSubmit::fail("timeout", Some("loop stuck"))),
    );
    let (status, body) = post_text(app, "/transactions/bytes", b"ab".to_vec()).await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v.get("reason").and_then(|x| x.as_str()), Some("timeout"));
}

// ---- Route gating ----

/// Frozen path list — adding a Scala-compat write route requires
/// editing this list, forcing a deliberate review of every new
/// admission entry point. The current set is the four submission
/// paths Scala exposes: hex bodies for `/transactions/bytes` +
/// `/transactions/checkBytes`, JSON bodies for `/transactions` +
/// `/transactions/check`.
const SCALA_SUBMIT_PATHS: &[&str] = &[
    "/transactions/bytes",
    "/transactions/checkBytes",
    "/transactions",
    "/transactions/check",
];

#[tokio::test]
async fn scala_submit_routes_present_when_both_compat_and_submit_enabled() {
    let app = build_app(Some(compat()), Some(StubSubmit::ok("aa")));
    for path in SCALA_SUBMIT_PATHS {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(*path)
                    .body(Body::from(b"ab".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{path} must be present when compat+submit are both enabled",
        );
    }
}

#[tokio::test]
async fn scala_submit_routes_404_when_compat_disabled() {
    // Submit is on, compat is off — operator routes work, but the
    // bare-path Scala-compat write surface must not (it lives in the
    // compat branch).
    let app = build_app(None, Some(StubSubmit::ok("aa")));
    for path in SCALA_SUBMIT_PATHS {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(*path)
                    .body(Body::from(b"ab".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{path} must NOT be registered when compat is disabled",
        );
    }
}

/// Track B: JSON-bodied `/transactions` and `/transactions/check`
/// are mounted. A clearly-malformed JSON body (`{}` is missing every
/// required top-level array) must surface as `400 reason:
/// "deserialize"` from the JSON-parse boundary, not 404. This pins
/// that the routes are present AND that the input-DTO refuses
/// missing required arrays.
#[tokio::test]
async fn json_transactions_routes_reject_empty_object_with_deserialize() {
    let app = build_app(Some(compat()), Some(StubSubmit::ok("aa")));
    for path in ["/transactions", "/transactions/check"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(b"{}".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{path} must be mounted and reject `{{}}` with 400, not 404",
        );
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v.get("reason").and_then(|x| x.as_str()),
            Some("deserialize"),
            "{path} missing-field rejection must bucket as `deserialize`",
        );
    }
}

/// Mode dispatch: `/transactions/bytes` must drive the admission
/// pipeline in `Broadcast` mode, `/transactions/checkBytes` in
/// `CheckOnly`. Same channel, same body shape — the only thing that
/// changes per route is the mode arg.
#[tokio::test]
async fn handler_passes_correct_mode_per_compat_route() {
    use std::sync::atomic::{AtomicU8, Ordering};
    static SAW_BROADCAST: AtomicU8 = AtomicU8::new(0);
    static SAW_CHECK_ONLY: AtomicU8 = AtomicU8::new(0);
    SAW_BROADCAST.store(0, Ordering::SeqCst);
    SAW_CHECK_ONLY.store(0, Ordering::SeqCst);

    let recording: Arc<dyn NodeSubmit> = Arc::new(StubSubmit {
        handler: Box::new(|_, mode| {
            match mode {
                SubmitMode::Broadcast => SAW_BROADCAST.fetch_add(1, Ordering::SeqCst),
                SubmitMode::CheckOnly => SAW_CHECK_ONLY.fetch_add(1, Ordering::SeqCst),
            };
            Ok("aa".repeat(32))
        }),
        json_handler: default_json_handler(),
    });

    let app = build_app(Some(compat()), Some(recording.clone()));
    let (s1, _) = post_text(app, "/transactions/bytes", b"ab".to_vec()).await;
    assert_eq!(s1, StatusCode::OK);
    let app = build_app(Some(compat()), Some(recording));
    let (s2, _) = post_text(app, "/transactions/checkBytes", b"ab".to_vec()).await;
    assert_eq!(s2, StatusCode::OK);

    assert_eq!(
        SAW_BROADCAST.load(Ordering::SeqCst),
        1,
        "/transactions/bytes must dispatch Broadcast exactly once",
    );
    assert_eq!(
        SAW_CHECK_ONLY.load(Ordering::SeqCst),
        1,
        "/transactions/checkBytes must dispatch CheckOnly exactly once",
    );
}

/// `/checkBytes` reuses the same body-decode + ApiSubmitError path as
/// `/bytes`. Pin that bad-hex on `/checkBytes` returns 400 deserialize
/// without ever invoking the channel — same boundary contract.
#[tokio::test]
async fn check_bytes_bad_hex_returns_400_deserialize() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static CALLED: AtomicBool = AtomicBool::new(false);
    CALLED.store(false, Ordering::SeqCst);

    let trap: Arc<dyn NodeSubmit> = Arc::new(StubSubmit {
        handler: Box::new(|_, _| {
            CALLED.store(true, Ordering::SeqCst);
            Ok(String::new())
        }),
        json_handler: default_json_handler(),
    });

    let app = build_app(Some(compat()), Some(trap));
    let (status, body) = post_text(app, "/transactions/checkBytes", b"!!!!".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v.get("reason").and_then(|x| x.as_str()),
        Some("deserialize")
    );
    assert!(
        !CALLED.load(Ordering::SeqCst),
        "submit handler must NOT be invoked when /checkBytes body fails to decode",
    );
}

#[tokio::test]
async fn check_bytes_admission_rejection_returns_400() {
    let app = build_app(
        Some(compat()),
        Some(StubSubmit::fail("script_failed", Some("input #0 failed"))),
    );
    let (status, body) = post_text(app, "/transactions/checkBytes", b"ab".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v.get("error").and_then(|x| x.as_u64()), Some(400));
    assert_eq!(
        v.get("reason").and_then(|x| x.as_str()),
        Some("script_failed"),
    );
    assert_eq!(
        v.get("detail").and_then(|x| x.as_str()),
        Some("input #0 failed"),
    );
}

#[tokio::test]
async fn scala_submit_route_rejects_get() {
    let app = build_app(Some(compat()), Some(StubSubmit::ok("aa")));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/transactions/bytes")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "GET on POST-only route must be 405",
    );
}

// ============================================================
// JSON route positive coverage
// ============================================================

/// Minimal valid JSON tx body (one input, no data inputs, one output).
/// Fields are syntactically well-formed; the bridge stub doesn't decode
/// in these tests, so the values can be placeholder bytes.
const MINIMAL_JSON_TX: &str = r#"{
    "inputs": [
        {
            "boxId": "0000000000000000000000000000000000000000000000000000000000000000",
            "spendingProof": {
                "proofBytes": "",
                "extension": {}
            }
        }
    ],
    "dataInputs": [],
    "outputs": [
        {
            "value": 1000000,
            "ergoTree": "0101",
            "assets": [],
            "creationHeight": 1,
            "additionalRegisters": {}
        }
    ]
}"#;

/// `/transactions` success body is a bare JSON string carrying the
/// tx_id from the bridge — no envelope. Mirrors the bytes path's
/// `Json("…")` shape, which matches Scala's `ApiResponse(tx.id)`.
#[tokio::test]
async fn json_submit_route_returns_bare_string_tx_id_on_success() {
    let tx_id: &'static str = Box::leak("ab".repeat(32).into_boxed_str());
    let app = build_app(Some(compat()), Some(StubSubmit::json_ok(tx_id)));
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/transactions")
                .header("content-type", "application/json")
                .body(Body::from(MINIMAL_JSON_TX))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let s: String = serde_json::from_slice(&body).expect("body must be a JSON string");
    assert_eq!(s, tx_id, "body must be tx_id from bridge, no envelope");
}

/// `/transactions/check` mirrors `/transactions`'s success shape —
/// bare JSON string, no envelope. Same bridge path, CheckOnly mode.
#[tokio::test]
async fn json_check_route_returns_bare_string_tx_id_on_success() {
    let app = build_app(Some(compat()), Some(StubSubmit::json_ok("cd00")));
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/transactions/check")
                .header("content-type", "application/json")
                .body(Body::from(MINIMAL_JSON_TX))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let s: String = serde_json::from_slice(&body).unwrap();
    assert_eq!(s, "cd00");
}

/// Mode dispatch parity with the bytes path: `/transactions` must hit
/// the bridge in `Broadcast`, `/transactions/check` in `CheckOnly`.
/// Pins that the JSON route pair doesn't accidentally collapse to a
/// single mode.
#[tokio::test]
async fn json_routes_dispatch_correct_mode_per_path() {
    use std::sync::atomic::{AtomicU8, Ordering};
    static SAW_BROADCAST: AtomicU8 = AtomicU8::new(0);
    static SAW_CHECK_ONLY: AtomicU8 = AtomicU8::new(0);
    SAW_BROADCAST.store(0, Ordering::SeqCst);
    SAW_CHECK_ONLY.store(0, Ordering::SeqCst);

    let recording: Arc<dyn NodeSubmit> = Arc::new(StubSubmit {
        handler: Box::new(|_, _| {
            Err(SubmitError {
                reason: "internal_error".to_string(),
                detail: Some("bytes path not exercised in this test".to_string()),
            })
        }),
        json_handler: Box::new(|_, mode| {
            match mode {
                SubmitMode::Broadcast => SAW_BROADCAST.fetch_add(1, Ordering::SeqCst),
                SubmitMode::CheckOnly => SAW_CHECK_ONLY.fetch_add(1, Ordering::SeqCst),
            };
            Ok("aa".repeat(32))
        }),
    });

    let app = build_app(Some(compat()), Some(recording.clone()));
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/transactions")
                .body(Body::from(MINIMAL_JSON_TX))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let app = build_app(Some(compat()), Some(recording));
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/transactions/check")
                .body(Body::from(MINIMAL_JSON_TX))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(
        SAW_BROADCAST.load(Ordering::SeqCst),
        1,
        "/transactions must dispatch Broadcast exactly once",
    );
    assert_eq!(
        SAW_CHECK_ONLY.load(Ordering::SeqCst),
        1,
        "/transactions/check must dispatch CheckOnly exactly once",
    );
}

/// Bridge errors flow through the same status mapping as the bytes
/// path: `non_canonical` (400), `overloaded` (503), `timeout` (504).
/// Pins that the JSON route reuses `map_submit_error` rather than a
/// parallel implementation that could drift.
///
/// Parameterised across both POST paths (`/transactions` and
/// `/transactions/check`) so error-status parity is verified for both,
/// not just the broadcast variant.
#[tokio::test]
async fn json_route_maps_bridge_errors_to_correct_status() {
    let cases: &[(&str, StatusCode)] = &[
        ("non_canonical", StatusCode::BAD_REQUEST),
        ("deserialize", StatusCode::BAD_REQUEST),
        ("script_failed", StatusCode::BAD_REQUEST),
        ("overloaded", StatusCode::SERVICE_UNAVAILABLE),
        ("shutting_down", StatusCode::SERVICE_UNAVAILABLE),
        ("timeout", StatusCode::GATEWAY_TIMEOUT),
    ];
    for path in &["/transactions", "/transactions/check"] {
        for (reason, expected_status) in cases {
            let app = build_app(
                Some(compat()),
                Some(StubSubmit::json_fail(reason, Some("test"))),
            );
            let resp = app
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(*path)
                        .body(Body::from(MINIMAL_JSON_TX))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                *expected_status,
                "{path} reason {reason} must map to {expected_status}"
            );
            let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                v.get("reason").and_then(|x| x.as_str()),
                Some(*reason),
                "{path} error body must echo reason {reason}"
            );
            assert_eq!(
                v.get("error").and_then(|x| x.as_u64()),
                Some(expected_status.as_u16() as u64),
                "{path} error code must match status"
            );
        }
    }
}

/// Unknown JSON fields at the route layer must not cause 400; the
/// bridge stub here returns `Ok` so a 400 would indicate `serde`
/// rejected the body. Complements the api_bridge unit test which
/// verifies the same against the canonical decoder.
///
/// Parameterised across both POST paths so Q3 tolerance is verified
/// for both broadcast and check-only.
#[tokio::test]
async fn json_route_tolerates_unknown_top_level_fields() {
    let polluted = r#"{
        "inputs": [{"boxId":"00", "spendingProof":{"proofBytes":"","extension":{}}}],
        "dataInputs": [],
        "outputs": [{"value":1,"ergoTree":"0101","assets":[],"creationHeight":1,"additionalRegisters":{}}],
        "id": "ignored",
        "size": 999,
        "myCustomFieldThatScalaNeverEmits": [1,2,3]
    }"#;
    for path in &["/transactions", "/transactions/check"] {
        let app = build_app(Some(compat()), Some(StubSubmit::json_ok("aa")));
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(*path)
                    .header("content-type", "application/json")
                    .body(Body::from(polluted))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{path}: unknown fields (including derived id/size) must be tolerated"
        );
    }
}

/// `null` for required arrays must reject at the route layer with
/// `400 reason: "deserialize"` — same bucket as malformed JSON. Pins
/// that the rejection happens at parse time, not after invoking the
/// bridge.
///
/// Parameterised across both POST paths so Q4 rejection is verified
/// for both broadcast and check-only.
#[tokio::test]
async fn json_route_rejects_null_required_arrays() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static CALLED: AtomicBool = AtomicBool::new(false);
    CALLED.store(false, Ordering::SeqCst);

    let trap: Arc<dyn NodeSubmit> = Arc::new(StubSubmit {
        handler: Box::new(|_, _| {
            Err(SubmitError {
                reason: "internal_error".to_string(),
                detail: None,
            })
        }),
        json_handler: Box::new(|_, _| {
            CALLED.store(true, Ordering::SeqCst);
            Ok("aa".to_string())
        }),
    });

    let cases: &[&str] = &[
        r#"{"inputs": null, "dataInputs": [], "outputs": []}"#,
        r#"{"inputs": [], "dataInputs": null, "outputs": []}"#,
        r#"{"inputs": [], "dataInputs": [], "outputs": null}"#,
    ];
    for path in &["/transactions", "/transactions/check"] {
        for body in cases {
            let app = build_app(Some(compat()), Some(trap.clone()));
            let resp = app
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(*path)
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "{path}: null array must reject with 400"
            );
            let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                v.get("reason").and_then(|x| x.as_str()),
                Some("deserialize"),
                "{path}: null array must bucket as deserialize"
            );
        }
    }
    assert!(
        !CALLED.load(Ordering::SeqCst),
        "bridge must NOT be called when JSON parse fails"
    );
}
