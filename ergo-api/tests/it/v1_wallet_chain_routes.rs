use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use ergo_api::auth::{ApiSecurity, API_KEY_HEADER};
use ergo_api::server::{router_with_mempool_and_wallet_and_wallet_moved, ServerCtx};
use ergo_api::traits::{NodeReadState, NoopMempoolView, WalletChain, WalletChainError};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_api::v1::auth::V1AuthConfig;
use ergo_api::v1::governor::{Governor, GovernorConfig};
use ergo_api::v1::{wallet_chain_router, WalletChainState};
use ergo_api::wallet::NoopWalletAdmin;
use ergo_ser::address::NetworkPrefix;
use ergo_wallet_protocol::chain as wire;
use serde_json::{json, Value};
use tower::ServiceExt;

const KEY: &[u8] = b"wallet-chain-test-key";

struct ProductionRead;

impl NodeReadState for ProductionRead {
    fn info(&self) -> ApiInfo {
        ApiInfo {
            agent_name: "test".to_string(),
            node_name: "test".to_string(),
            network: "mainnet".to_string(),
            version: "test".to_string(),
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

#[derive(Clone)]
enum Mode {
    Good,
    Stale,
    Pruned,
    PrunedError,
    Missing,
    Unsupported,
    RejectedInvalid,
    RejectedFee,
    Overloaded,
    ShuttingDown,
    Timeout,
    Internal,
}

struct FakeChain {
    mode: Mode,
    calls: Arc<Mutex<Vec<String>>>,
}

impl FakeChain {
    fn tip_fixture(&self) -> wire::ChainTip {
        wire::ChainTip::new(10, "a".repeat(64)).expect("valid tip")
    }

    fn snapshot_fixture(&self) -> wire::ChainSnapshot {
        wire::ChainSnapshot {
            tip: self.tip_fixture(),
            headers: vec![wire::ChainHeader {
                height: 10,
                header_id: "a".repeat(64),
                parent_id: "b".repeat(64),
                timestamp_unix_ms: 123,
            }],
            active_parameters: json!({"hardFork": 1}),
            reemission_inputs: vec![
                wire::ReemissionInput {
                    token_id: "c".repeat(64),
                    amount: "9007199254740993".to_string(),
                    box_ids: Some(vec!["d".repeat(64)]),
                },
                wire::ReemissionInput {
                    token_id: "e".repeat(64),
                    amount: "1".to_string(),
                    box_ids: None,
                },
            ],
            snapshot_id: "a".repeat(64),
        }
    }

    fn block(&self) -> wire::ChainBlock {
        wire::ChainBlock {
            block_id: "b".repeat(64),
            height: 11,
            parent_id: "a".repeat(64),
            transactions: vec![wire::ChainTransaction {
                tx_id: "e".repeat(64),
                inputs: vec![wire::ChainInput {
                    box_id: "f".repeat(64),
                    index: 0,
                }],
                outputs: vec![wire::ChainOutput {
                    box_id: "1".repeat(64),
                    index: 0,
                    bytes: "00ff".to_string(),
                }],
            }],
        }
    }

    fn record(&self, call: &str) {
        self.calls
            .lock()
            .expect("calls lock")
            .push(call.to_string());
    }
}

impl WalletChain for FakeChain {
    fn tip(&self) -> Result<wire::ChainTip, WalletChainError> {
        self.record("tip");
        match self.mode {
            Mode::Stale => Err(WalletChainError::stale_tip(
                wire::ChainTip::new(9, "0".repeat(64)).expect("valid expected tip"),
                self.tip_fixture(),
            )),
            Mode::Unsupported => Err(WalletChainError::Unsupported),
            _ => Ok(self.tip_fixture()),
        }
    }

    fn snapshot(&self) -> Result<wire::ChainSnapshot, WalletChainError> {
        self.record("snapshot");
        match self.mode {
            Mode::Unsupported => Err(WalletChainError::Unsupported),
            _ => Ok(self.snapshot_fixture()),
        }
    }

    fn blocks_since(
        &self,
        request: wire::BlocksSinceRequest,
    ) -> Result<wire::BlocksSinceResponse, WalletChainError> {
        self.record(&format!("blocks:{}:{}", request.height, request.limit));
        match self.mode {
            Mode::Stale => Err(WalletChainError::stale_tip(
                wire::ChainTip::new(request.height, request.id).expect("valid expected tip"),
                self.tip_fixture(),
            )),
            Mode::Pruned => Ok(wire::BlocksSinceResponse::Pruned(wire::PrunedBlocksSince {
                tip: self.tip_fixture(),
                minimum_height: 7,
            })),
            Mode::PrunedError => Err(WalletChainError::history_pruned(7)),
            Mode::Unsupported => Err(WalletChainError::Unsupported),
            _ => Ok(wire::BlocksSinceResponse::Forward(
                wire::ForwardBlocksSince {
                    tip: self.tip_fixture(),
                    blocks: vec![self.block()],
                },
            )),
        }
    }

    fn box_lookup(
        &self,
        request: wire::BoxLookupRequest,
    ) -> Result<wire::BoxLookupResponse, WalletChainError> {
        self.record(&format!(
            "box:{}:{}",
            request.box_id,
            request.tip.unwrap_or_default()
        ));
        match self.mode {
            Mode::Missing => Err(WalletChainError::BoxNotFound),
            Mode::Stale => Err(WalletChainError::stale_tip(
                wire::ChainTip::new(9, "0".repeat(64)).expect("valid expected tip"),
                self.tip_fixture(),
            )),
            Mode::Unsupported => Err(WalletChainError::Unsupported),
            _ => Ok(wire::BoxLookupResponse {
                tip: self.tip_fixture(),
                box_info: wire::ChainBox {
                    box_id: request.box_id,
                    bytes: "00ff".to_string(),
                    value: 123,
                    assets: vec![wire::ChainAsset {
                        token_id: "9".repeat(64),
                        amount: "17".to_string(),
                    }],
                    creation_tx_id: "8".repeat(64),
                    creation_output_index: 2,
                    creation_height: 9,
                },
            }),
        }
    }

    fn submit(
        &self,
        request: wire::SubmitRequest,
    ) -> Result<wire::SubmitResponse, WalletChainError> {
        self.record(&format!(
            "submit:{}:{}",
            request.transaction,
            request.snapshot_id.unwrap_or_default()
        ));
        match self.mode {
            Mode::Unsupported => Err(WalletChainError::Unsupported),
            Mode::Stale => Err(WalletChainError::stale_tip(
                wire::ChainTip::new(9, "0".repeat(64)).expect("valid expected tip"),
                self.tip_fixture(),
            )),
            Mode::RejectedInvalid => Ok(wire::SubmitResponse::Rejected {
                tip: self.tip_fixture(),
                reason: wire::SubmitError::Invalid,
                detail: Some("validation failed".to_string()),
            }),
            Mode::RejectedFee => Ok(wire::SubmitResponse::Rejected {
                tip: self.tip_fixture(),
                reason: wire::SubmitError::Fee,
                detail: Some("fee too low".to_string()),
            }),
            Mode::Overloaded => Err(WalletChainError::Overloaded(
                "submission channel full".to_string(),
            )),
            Mode::ShuttingDown => Err(WalletChainError::ShuttingDown(
                "main loop stopped".to_string(),
            )),
            Mode::Timeout => Err(WalletChainError::Timeout(
                "admission deadline elapsed".to_string(),
            )),
            Mode::Internal => Err(WalletChainError::Internal(
                "local state failure".to_string(),
            )),
            _ => Ok(wire::SubmitResponse::Accepted {
                tip: self.tip_fixture(),
                tx_id: "7".repeat(64),
            }),
        }
    }
}

fn security() -> Arc<ApiSecurity> {
    Arc::new(ApiSecurity::new(ApiSecurity::hash_key(KEY)).expect("valid security"))
}

fn governor() -> Arc<Governor> {
    Governor::new(GovernorConfig::default()).expect("valid governor")
}

fn app(chain: Option<Arc<dyn WalletChain>>) -> Router {
    let auth = V1AuthConfig::new(Some(security())).into_shared();
    wallet_chain_router(WalletChainState::new(chain), governor(), auth)
}

fn production_app(chain: Option<Arc<dyn WalletChain>>, wallet_moved: Option<&str>) -> Router {
    let ctx = ServerCtx {
        read: Arc::new(ProductionRead),
        compat: None,
        submit: None,
        wallet_chain: chain,
        indexer: None,
        mempool: Arc::new(NoopMempoolView::new()),
        network: NetworkPrefix::Mainnet,
        chain_params: None,
        mining: None,
        emission: None,
        emission_scripts: None,
        utxo_reads_supported: true,
    };
    router_with_mempool_and_wallet_and_wallet_moved(
        ctx,
        None,
        Arc::new(NoopWalletAdmin),
        Some(security()),
        wallet_moved,
    )
}

async fn send(
    app: Router,
    method: Method,
    uri: &str,
    body: Body,
    key: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(axum::http::header::CONTENT_TYPE, "application/json");
    if let Some(key) = key {
        request = request.header(API_KEY_HEADER, key);
    }
    let mut request = request.body(body).expect("request");
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            40000,
        ))));
    let response = app.oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn get(app: Router, uri: &str, key: Option<&str>) -> (StatusCode, Value) {
    send(app, Method::GET, uri, Body::empty(), key).await
}

fn fake(mode: Mode) -> (Arc<dyn WalletChain>, Arc<Mutex<Vec<String>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    (
        Arc::new(FakeChain {
            mode,
            calls: calls.clone(),
        }),
        calls,
    )
}

#[tokio::test]
async fn all_wallet_chain_routes_return_protocol_shapes() {
    let (chain, _) = fake(Mode::Good);
    let app = app(Some(chain));
    let key = std::str::from_utf8(KEY).expect("utf8 key");

    let (status, body) = get(app.clone(), "/api/v1/chain/tip", Some(key)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["height"], 10);
    assert_eq!(body["headerId"], "a".repeat(64));

    let (status, body) = get(app.clone(), "/api/v1/chain/snapshot", Some(key)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["snapshotId"], "a".repeat(64));
    assert_eq!(body["reemissionInputs"][0]["amount"], "9007199254740993");
    assert_eq!(body["reemissionInputs"][0]["boxIds"][0], "d".repeat(64));
    assert!(body["reemissionInputs"][1].get("boxIds").is_none());

    let (status, body) = get(
        app.clone(),
        &format!(
            "/api/v1/chain/blocks-since?height=10&id={}&limit=1",
            "a".repeat(64)
        ),
        Some(key),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["type"], "forward");
    assert_eq!(body["blocks"][0]["blockId"], "b".repeat(64));

    let (status, body) = get(
        app.clone(),
        &format!(
            "/api/v1/chain/boxes/{}?tip={}",
            "1".repeat(64),
            "a".repeat(64)
        ),
        Some(key),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["box"]["boxId"], "1".repeat(64));
    assert_eq!(body["box"]["value"], "123");
    assert_eq!(body["box"]["assets"][0]["amount"], "17");

    let (status, body) = send(
        app,
        Method::POST,
        "/api/v1/chain/transactions",
        Body::from(r#"{"transaction":"00ff"}"#),
        Some(key),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "accepted");
    assert_eq!(body["txId"], "7".repeat(64));
}

#[tokio::test]
async fn wallet_chain_routes_require_the_v1_api_key() {
    let (chain, _) = fake(Mode::Good);
    let app = app(Some(chain));
    let cases = [
        (Method::GET, "/api/v1/chain/tip", Body::empty()),
        (Method::GET, "/api/v1/chain/snapshot", Body::empty()),
        (
            Method::GET,
            &format!(
                "/api/v1/chain/blocks-since?height=0&id={}&limit=1",
                "0".repeat(64)
            ),
            Body::empty(),
        ),
        (
            Method::GET,
            &format!(
                "/api/v1/chain/boxes/{}?tip={}",
                "1".repeat(64),
                "a".repeat(64)
            ),
            Body::empty(),
        ),
        (
            Method::POST,
            "/api/v1/chain/transactions",
            Body::from(r#"{"transaction":"00"}"#),
        ),
    ];
    for (method, uri, body) in cases {
        let (status, value) = send(app.clone(), method.clone(), uri, body, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}: {value}");
        assert_eq!(value["error"]["reason"], "unauthorized");
        let (status, _) = send(app.clone(), method, uri, Body::empty(), Some("wrong")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
    }
}

#[tokio::test]
async fn semantic_chain_errors_map_to_v1_statuses() {
    let key = std::str::from_utf8(KEY).expect("utf8 key");
    let (chain, _) = fake(Mode::Stale);
    let (status, body) = get(app(Some(chain)), "/api/v1/chain/tip", Some(key)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["reason"], "stale_tip");

    let (chain, _) = fake(Mode::Pruned);
    let (status, body) = get(
        app(Some(chain)),
        &format!(
            "/api/v1/chain/blocks-since?height=1&id={}&limit=1",
            "a".repeat(64)
        ),
        Some(key),
    )
    .await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(body["type"], "pruned");
    assert_eq!(body["minimumHeight"], 7);

    let (chain, _) = fake(Mode::PrunedError);
    let (status, body) = get(
        app(Some(chain)),
        &format!(
            "/api/v1/chain/blocks-since?height=1&id={}&limit=1",
            "a".repeat(64)
        ),
        Some(key),
    )
    .await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(body["type"], "pruned");
    assert_eq!(body["minimumHeight"], 7);

    let (chain, _) = fake(Mode::Missing);
    let (status, body) = get(
        app(Some(chain)),
        &format!(
            "/api/v1/chain/boxes/{}?tip={}",
            "1".repeat(64),
            "a".repeat(64)
        ),
        Some(key),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["reason"], "box_not_found");

    let (chain, _) = fake(Mode::Unsupported);
    let (status, body) = get(app(Some(chain)), "/api/v1/chain/tip", Some(key)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["reason"], "route_unavailable");

    let (status, body) = get(app(None), "/api/v1/chain/snapshot", Some(key)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["reason"], "route_unavailable");
}

#[tokio::test]
async fn submit_failure_classes_map_to_protocol_statuses() {
    let key = std::str::from_utf8(KEY).expect("utf8 key");
    let cases = [
        (Mode::RejectedInvalid, StatusCode::BAD_REQUEST, "invalid"),
        (Mode::RejectedFee, StatusCode::BAD_REQUEST, "fee"),
        (Mode::Stale, StatusCode::CONFLICT, "stale_tip"),
        (
            Mode::Overloaded,
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
        ),
        (
            Mode::ShuttingDown,
            StatusCode::SERVICE_UNAVAILABLE,
            "shutting_down",
        ),
        (Mode::Timeout, StatusCode::GATEWAY_TIMEOUT, "timeout"),
        (
            Mode::Internal,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
        ),
    ];

    for (mode, expected_status, expected_reason) in cases {
        let (chain, _) = fake(mode);
        let (status, body) = send(
            app(Some(chain)),
            Method::POST,
            "/api/v1/chain/transactions",
            Body::from(r#"{"transaction":"00"}"#),
            Some(key),
        )
        .await;
        assert_eq!(status, expected_status, "{expected_reason}: {body}");
        if expected_status == StatusCode::BAD_REQUEST {
            assert_eq!(body["status"], "rejected");
            assert_eq!(body["reason"], expected_reason);
        } else {
            assert_eq!(body["error"]["reason"], expected_reason);
        }
    }
}

#[tokio::test]
async fn malformed_inputs_are_rejected_before_the_chain_call() {
    let (chain, calls) = fake(Mode::Good);
    let app = app(Some(chain));
    let key = std::str::from_utf8(KEY).expect("utf8 key");
    let cases = [
        (
            Method::GET,
            "/api/v1/chain/blocks-since?height=1",
            Body::empty(),
        ),
        (
            Method::GET,
            &format!("/api/v1/chain/blocks-since?height=1&id={}", "A".repeat(64)),
            Body::empty(),
        ),
        (
            Method::GET,
            &format!(
                "/api/v1/chain/blocks-since?height=1&id={}&limit=0",
                "a".repeat(64)
            ),
            Body::empty(),
        ),
        (
            Method::GET,
            &format!("/api/v1/chain/boxes/{}", "A".repeat(64)),
            Body::empty(),
        ),
        (
            Method::GET,
            &format!("/api/v1/chain/boxes/{}", "1".repeat(64)),
            Body::empty(),
        ),
        (
            Method::POST,
            "/api/v1/chain/transactions",
            Body::from(r#"{"transaction":"0G"}"#),
        ),
    ];
    for (method, uri, body) in cases {
        let (status, value) = send(app.clone(), method, uri, body, Some(key)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {value}");
        assert!(value["error"]["reason"].is_string(), "{uri}: {value}");
    }
    assert!(calls.lock().expect("calls lock").is_empty());
}

#[tokio::test]
async fn blocks_since_caps_large_limits_and_passes_the_cursor() {
    let (chain, calls) = fake(Mode::Good);
    let key = std::str::from_utf8(KEY).expect("utf8 key");
    let (status, _) = get(
        app(Some(chain)),
        &format!(
            "/api/v1/chain/blocks-since?height=7&id={}&limit=99999",
            "a".repeat(64)
        ),
        Some(key),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(calls.lock().expect("calls lock")[0], "blocks:7:1024");
}

/// A cursor id is 64 lowercase hex on every semantic mismatch, so shape
/// validation alone cannot catch it. Height `0` is the genesis sentinel and
/// must carry the all-zero id; a positive height must carry the real
/// committed header id. Both mismatches are client errors, so they must be
/// the `invalid_params` 400 envelope and must never reach the adapter (which
/// would surface them as a 500).
#[tokio::test]
async fn blocks_since_rejects_semantic_cursor_mismatches_before_the_chain_call() {
    let key = std::str::from_utf8(KEY).expect("utf8 key");
    let zero = wire::GENESIS_CURSOR_ID;
    let cases = [
        (
            "height 0 with the all-zero genesis id",
            format!("/api/v1/chain/blocks-since?height=0&id={zero}&limit=1"),
            StatusCode::OK,
            None,
            Some("forward"),
            Some("blocks:0:1"),
        ),
        (
            "height 0 with a real header id",
            format!("/api/v1/chain/blocks-since?height=0&id={}", "a".repeat(64)),
            StatusCode::BAD_REQUEST,
            Some("invalid_params"),
            None,
            None,
        ),
        (
            "positive height with the all-zero id",
            format!("/api/v1/chain/blocks-since?height=7&id={zero}&limit=1"),
            StatusCode::BAD_REQUEST,
            Some("invalid_params"),
            None,
            None,
        ),
        (
            "positive height with a real header id",
            format!(
                "/api/v1/chain/blocks-since?height=7&id={}&limit=1",
                "a".repeat(64)
            ),
            StatusCode::OK,
            None,
            Some("forward"),
            Some("blocks:7:1"),
        ),
    ];

    for (label, query, expected_status, expected_reason, expected_tag, expected_call) in cases {
        let (chain, calls) = fake(Mode::Good);
        let (status, body) = get(app(Some(chain)), &query, Some(key)).await;
        assert_eq!(status, expected_status, "{label}: {body}");
        match expected_reason {
            Some(reason) => {
                assert_eq!(body["error"]["reason"], reason, "{label}: {body}");
                assert!(body["error"]["message"].is_string(), "{label}: {body}");
                assert!(body["error"]["detail"].is_string(), "{label}: {body}");
            }
            None => {
                assert_eq!(
                    body["type"],
                    expected_tag.unwrap_or_default(),
                    "{label}: {body}"
                );
                assert_eq!(body["blocks"][0]["blockId"], "b".repeat(64), "{label}");
            }
        }
        let recorded = calls.lock().expect("calls lock").clone();
        match expected_call {
            Some(call) => assert_eq!(recorded, vec![call.to_string()], "{label}: {query}"),
            None => assert!(
                recorded.is_empty(),
                "{label}: must not reach the chain adapter, recorded {recorded:?}"
            ),
        }
    }
}

#[tokio::test]
async fn duplicate_submit_is_a_tagged_200() {
    struct DuplicateChain;
    impl WalletChain for DuplicateChain {
        fn tip(&self) -> Result<wire::ChainTip, WalletChainError> {
            Ok(wire::ChainTip::new(1, "1".repeat(64)).expect("valid tip"))
        }
        fn snapshot(&self) -> Result<wire::ChainSnapshot, WalletChainError> {
            Err(WalletChainError::Unsupported)
        }
        fn blocks_since(
            &self,
            _request: wire::BlocksSinceRequest,
        ) -> Result<wire::BlocksSinceResponse, WalletChainError> {
            Err(WalletChainError::Unsupported)
        }
        fn box_lookup(
            &self,
            _request: wire::BoxLookupRequest,
        ) -> Result<wire::BoxLookupResponse, WalletChainError> {
            Err(WalletChainError::Unsupported)
        }
        fn submit(
            &self,
            _request: wire::SubmitRequest,
        ) -> Result<wire::SubmitResponse, WalletChainError> {
            Ok(wire::SubmitResponse::Duplicate {
                tip: wire::ChainTip::new(1, "1".repeat(64)).expect("valid tip"),
                tx_id: "2".repeat(64),
            })
        }
    }
    let key = std::str::from_utf8(KEY).expect("utf8 key");
    let (status, body) = send(
        app(Some(Arc::new(DuplicateChain))),
        Method::POST,
        "/api/v1/chain/transactions",
        Body::from(r#"{"transaction":"00"}"#),
        Some(key),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "duplicate");
}

#[tokio::test]
async fn production_router_keeps_chain_routes_available_without_embedded_wallet() {
    let (chain, _) = fake(Mode::Good);
    let (status, body) = get(
        production_app(Some(chain), Some("http://127.0.0.1:19090")),
        "/api/v1/chain/tip",
        Some(std::str::from_utf8(KEY).expect("utf8 key")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["height"], 10);
}

#[tokio::test]
async fn production_router_returns_503_when_chain_port_is_absent() {
    let (status, body) = get(
        production_app(None, Some("http://127.0.0.1:19090")),
        "/api/v1/chain/tip",
        Some(std::str::from_utf8(KEY).expect("utf8 key")),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["reason"], "route_unavailable");
}
