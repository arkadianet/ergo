//! Scala-compat `POST /blocks` (sendMinedBlock) route tests.
//!
//! Covers the §12 step (f) wiring: the route is mounted in
//! `server::router` when both `compat = Some(_)` and `submit = Some(_)`
//! are passed, JSON parse failures map to `400 deserialize` without
//! ever calling the bridge, and the per-reason HTTP status mapping
//! follows `map_submit_error`'s extended vocabulary.
//!
//! The bridge's own JSON-decode + PoW-verify behaviour is exercised
//! at the boundary in `ergo-node/src/api_bridge.rs::tests` — this
//! file only proves the route mount + handler dispatch + status map.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use ergo_api::compat::types::{
    Parameters, ScalaAdProofs, ScalaBlockTransactions, ScalaExtension, ScalaFullBlock, ScalaHeader,
    ScalaInfo, ScalaPowSolutions, ScalaTransactionInput,
};
use ergo_api::compat::NodeChainQuery;
use ergo_api::server::router;
use ergo_api::traits::{NodeReadState, NodeSubmit};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSubmitError, ApiSyncStatus, ApiTip,
    ApiWeightFunction, HealthStatus, SubmitError, SubmitMode, SyncStateLabel,
};
use tower::ServiceExt;

// ----- helpers -----

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
            mempool_tx_requested_total: 0,
            mempool_peer_tx_admitted_total: 0,
            mempool_peer_tx_rejected_total: 0,
            reorgs_total: 0,
            last_reorg_depth: None,
            last_reorg_unix_ms: None,
            apply_in_progress: false,
            last_apply_duration_ms: 0,
            last_applied_height: 0,
            last_apply_age_ms: None,
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

type BlockHandler = Box<dyn Fn(ScalaFullBlock) -> Result<String, SubmitError> + Send + Sync>;

struct StubBlockSubmit {
    block_handler: BlockHandler,
}

impl StubBlockSubmit {
    fn ok(header_id: &'static str) -> Arc<dyn NodeSubmit> {
        Arc::new(Self {
            block_handler: Box::new(move |_| Ok(header_id.to_string())),
        })
    }
    fn fail(reason: &'static str, detail: Option<&'static str>) -> Arc<dyn NodeSubmit> {
        Arc::new(Self {
            block_handler: Box::new(move |_| {
                Err(SubmitError {
                    reason: reason.to_string(),
                    detail: detail.map(|s| s.to_string()),
                })
            }),
        })
    }
}

#[async_trait]
impl NodeSubmit for StubBlockSubmit {
    async fn submit_transaction(&self, _: Vec<u8>, _: SubmitMode) -> Result<String, SubmitError> {
        // Not exercised by the /blocks route tests.
        Err(SubmitError {
            reason: "internal_error".to_string(),
            detail: Some("submit_transaction not implemented in this stub".to_string()),
        })
    }
    async fn submit_transaction_json(
        &self,
        _: ScalaTransactionInput,
        _: SubmitMode,
    ) -> Result<String, SubmitError> {
        Err(SubmitError {
            reason: "internal_error".to_string(),
            detail: Some("submit_transaction_json not implemented in this stub".to_string()),
        })
    }
    async fn submit_full_block(&self, block: ScalaFullBlock) -> Result<String, SubmitError> {
        (self.block_handler)(block)
    }
}

// ----- stubs that inherit the trait default -----

struct StubDefaultSubmit;

#[async_trait]
impl NodeSubmit for StubDefaultSubmit {
    async fn submit_transaction(&self, _: Vec<u8>, _: SubmitMode) -> Result<String, SubmitError> {
        Err(SubmitError {
            reason: "internal_error".to_string(),
            detail: None,
        })
    }
    async fn submit_transaction_json(
        &self,
        _: ScalaTransactionInput,
        _: SubmitMode,
    ) -> Result<String, SubmitError> {
        Err(SubmitError {
            reason: "internal_error".to_string(),
            detail: None,
        })
    }
    // submit_full_block deliberately not overridden — falls through to
    // the trait default `route_disabled`.
}

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

/// Build a JSON body shaped like a Scala `ErgoFullBlock`. The
/// bridge would reject this for several reasons (PoW would fail,
/// section ids wouldn't match), but the route tests use a
/// `StubBlockSubmit` that bypasses the bridge entirely — so the
/// content needs only to deserialize cleanly via `serde_json`.
fn synthetic_block_json() -> Vec<u8> {
    let block = ScalaFullBlock {
        header: ScalaHeader {
            extension_id: String::new(),
            difficulty: "1".to_string(),
            votes: "000000".to_string(),
            timestamp: 0,
            size: 0,
            unparsed_bytes: String::new(),
            state_root: "00".repeat(33),
            height: 1,
            n_bits: 1,
            version: 2,
            id: String::new(),
            ad_proofs_root: "00".repeat(32),
            transactions_root: "00".repeat(32),
            extension_hash: "00".repeat(32),
            pow_solutions: ScalaPowSolutions {
                pk: "02".to_string() + &"00".repeat(32),
                w: "00".repeat(33),
                n: "00".repeat(8),
                d: serde_json::Value::Number(0u32.into()),
            },
            ad_proofs_id: String::new(),
            transactions_id: String::new(),
            parent_id: "00".repeat(32),
        },
        block_transactions: ScalaBlockTransactions {
            header_id: String::new(),
            transactions: vec![],
            block_version: 2,
            size: 0,
        },
        extension: ScalaExtension {
            header_id: String::new(),
            digest: "00".repeat(32),
            fields: vec![],
        },
        ad_proofs: Some(ScalaAdProofs {
            header_id: String::new(),
            proof_bytes: String::new(),
            digest: "00".repeat(32),
            size: 0,
        }),
        size: 0,
    };
    serde_json::to_vec(&block).unwrap()
}

async fn post(app: axum::Router, path: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
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

// ----- happy path -----

#[tokio::test]
async fn ok_returns_200_with_header_id_as_bare_json_string() {
    let id: &'static str = Box::leak("ab".repeat(32).into_boxed_str());
    let app = build_app(Some(compat()), Some(StubBlockSubmit::ok(id)));
    let (status, body) = post(app, "/blocks", synthetic_block_json()).await;
    assert_eq!(status, StatusCode::OK);
    let s: String = serde_json::from_slice(&body).expect("body is a JSON string");
    assert_eq!(s, id);
}

// ----- error paths -----

#[tokio::test]
async fn malformed_json_returns_400_deserialize_without_calling_bridge() {
    let app = build_app(
        Some(compat()),
        Some(StubBlockSubmit::ok("dead")), // would 200 if reached
    );
    let (status, body) = post(app, "/blocks", b"{not json".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let err: ApiSubmitError = serde_json::from_slice(&body).expect("error envelope");
    assert_eq!(err.reason, "deserialize");
    assert_eq!(err.error, 400);
}

#[tokio::test]
async fn trait_default_route_disabled_maps_to_503() {
    let app = build_app(
        Some(compat()),
        Some(Arc::new(StubDefaultSubmit) as Arc<dyn NodeSubmit>),
    );
    let (status, body) = post(app, "/blocks", synthetic_block_json()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let err: ApiSubmitError = serde_json::from_slice(&body).expect("error envelope");
    assert_eq!(err.reason, "route_disabled");
    assert_eq!(err.error, 503);
}

/// Table-driven sweep of every reason the bridge can return →
/// expected HTTP status. Pins `map_submit_error` for the full
/// extended vocabulary so a future tweak to the mapper that breaks
/// any of these surfaces here, not in a Scala-compat client running
/// against a deployed node.
#[tokio::test]
async fn submit_error_reason_to_status_mapping() {
    let cases: &[(&'static str, StatusCode)] = &[
        // Caller-input errors → 400
        ("deserialize", StatusCode::BAD_REQUEST),
        ("non_canonical", StatusCode::BAD_REQUEST),
        ("invalid_pow", StatusCode::BAD_REQUEST),
        ("header_rejected", StatusCode::BAD_REQUEST),
        // Channel-side back-pressure / shutdown → 503
        ("overloaded", StatusCode::SERVICE_UNAVAILABLE),
        ("shutting_down", StatusCode::SERVICE_UNAVAILABLE),
        ("route_disabled", StatusCode::SERVICE_UNAVAILABLE),
        // Per-submission deadline → 504
        ("timeout", StatusCode::GATEWAY_TIMEOUT),
        // Local DB / storage failure → 500
        ("internal_error", StatusCode::INTERNAL_SERVER_ERROR),
    ];
    for (reason, expected_status) in cases {
        let app = build_app(Some(compat()), Some(StubBlockSubmit::fail(reason, None)));
        let (status, body) = post(app, "/blocks", synthetic_block_json()).await;
        assert_eq!(
            status, *expected_status,
            "reason {reason:?} should map to {expected_status}",
        );
        let err: ApiSubmitError = serde_json::from_slice(&body).expect("error envelope");
        assert_eq!(err.reason, *reason);
        assert_eq!(err.error, expected_status.as_u16());
    }
}

// ----- route gating -----

#[tokio::test]
async fn route_404s_when_compat_disabled() {
    // No compat = scala router never builds, so /blocks isn't
    // mounted (the scala_writes router is only merged inside the
    // compat branch in server::router).
    let app = build_app(None, Some(StubBlockSubmit::ok("dead")));
    let (status, _) = post(app, "/blocks", synthetic_block_json()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
