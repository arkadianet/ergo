//! Mining-side REST routes for candidates, supplied transactions and solutions.
//!
//! The trait [`NodeMining`] is the seam: the node implements it against
//! `ergo_mining::handle::MiningHandle` + the main loop's mining-submit
//! channel; this crate consumes it through `Arc<dyn NodeMining>`. Routes
//! are async and run on the API tokio task.
//!
//! HTTP shape (matches Scala `MiningApiRoute`):
//! - `GET  /mining/candidate`        → `WorkMessage` JSON
//! - `POST /mining/candidateWithTxs` → work with transaction inclusion proofs
//! - `POST /mining/candidateWithTxsAndPk` → the same, with a per-request miner key
//! - `POST /mining/solution`         → empty body on 200, JSON error on 4xx
//! - `GET  /mining/rewardAddress`    → `{ rewardAddress: "9..." }`
//! - `GET  /mining/rewardPublicKey`  → `{ rewardPubkey: "02..." }`
//!
//! Every route defaults to the api_key gate. Explicit legacy compatibility
//! opens only the original candidate/solution/reward routes; transaction
//! injection always requires a configured key.

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ergo_rest_json::mining::{
    AutolykosSolutionJson, CandidateWithTxsAndPkRequest, RewardAddressResponse,
    RewardPublicKeyResponse, WorkMessageJson,
};
use ergo_rest_json::mining_inspection::{
    CandidateDetailsJson, MiningFreshnessJson, MiningHistoryJson,
};
use ergo_rest_json::types::ScalaTransactionInput;
use serde::{Deserialize, Serialize};

mod private;
pub use private::{PrivateTransactionEntry, PrivateTransactionOptions, PrivateTransactionRequest};

/// Availability of the operator's optional storage-rent self-claims.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RentSelfClaimState {
    #[default]
    Disabled,
    Active,
    PausedIndexerBehind {
        indexed_height: u64,
        chain_height: u32,
    },
}

/// Trait the node implements to surface its mining subsystem to the
/// API server. Each call crosses into the node's main loop and awaits
/// a oneshot reply, matching the existing [`crate::traits::NodeSubmit`]
/// shape.
#[async_trait]
pub trait NodeMining: Send + Sync {
    /// `GET /mining/candidate`. Returns the current work message, or
    /// `None` if no candidate could be generated (e.g., the node isn't
    /// synced to tip). The handler maps `None` to 503.
    ///
    /// `longpoll` is the `msg` (the job id) of the template the client
    /// currently holds. When `Some` and still equal to the current template's
    /// `msg`, the call blocks in the API task until a fresher template is
    /// published or a bounded timeout elapses, then returns whatever is current
    /// (getblocktemplate-style longpoll). `None` — or a value that no longer
    /// matches — returns the current template immediately.
    async fn candidate(
        &self,
        longpoll: Option<String>,
    ) -> Result<Option<WorkMessageJson>, MiningApiError>;

    /// Builds and retains a candidate with the supplied transactions, optionally
    /// using a per-request miner key. Transactions keep their request order and
    /// their spending-proof context extension order. Only admitted transactions
    /// receive inclusion proofs in the returned work message.
    async fn candidate_with_txs(
        &self,
        _txs: Vec<ScalaTransactionInput>,
        _miner_pk: Option<String>,
    ) -> Result<Option<WorkMessageJson>, MiningApiError> {
        Err(MiningApiError::Unavailable(
            "transaction candidate building not wired".into(),
        ))
    }

    /// Authenticated exact-template inspection. Both selectors are matched
    /// against the same retained template; no selector chooses current work.
    async fn candidate_details(
        &self,
        _msg: Option<String>,
        _template_seq: Option<u64>,
    ) -> Result<Option<CandidateDetailsJson>, MiningApiError> {
        Err(MiningApiError::Unavailable(
            "candidate inspection unsupported".into(),
        ))
    }

    /// Operator-only bounded template and local submission history.
    async fn mining_history(&self) -> Result<MiningHistoryJson, MiningApiError> {
        Err(MiningApiError::Unavailable(
            "mining history unsupported".into(),
        ))
    }

    /// Public freshness has no transaction or wallet content.
    async fn mining_freshness(&self) -> Result<MiningFreshnessJson, MiningApiError> {
        Ok(MiningFreshnessJson::default())
    }

    /// Last availability observed by the serial mining worker; contains no
    /// transaction or wallet contents.
    async fn rent_self_claim_state(&self) -> RentSelfClaimState {
        RentSelfClaimState::Disabled
    }

    /// Validated runtime block selection policy. A JSON seam preserves the
    /// API crate's independence from the concrete mining implementation.
    async fn block_policy(&self) -> Result<serde_json::Value, MiningApiError> {
        Err(MiningApiError::Unavailable(
            "block policy unsupported".into(),
        ))
    }
    async fn set_block_policy(
        &self,
        _policy: serde_json::Value,
    ) -> Result<serde_json::Value, MiningApiError> {
        Err(MiningApiError::Unavailable(
            "block policy unsupported".into(),
        ))
    }

    /// `POST /mining/solution`. Returns `Ok(())` on accepted-by-executor.
    async fn submit_solution(&self, solution: AutolykosSolutionJson) -> Result<(), MiningApiError>;

    /// `GET /mining/rewardAddress`. The base58 P2S over the canonical
    /// reward output script using the miner's pubkey. Fallible: a
    /// wallet-resolved reward key is `Unavailable` (503) until the wallet is
    /// initialized, and `Internal` (500) if wallet tracking is inconsistent —
    /// never a stale or fabricated address.
    async fn reward_address(&self) -> Result<String, MiningApiError>;

    /// List private transactions, available only through authenticated routes.
    async fn private_transactions(&self) -> Result<Vec<PrivateTransactionEntry>, MiningApiError> {
        Err(MiningApiError::Unavailable(
            "private mining queue is unavailable".into(),
        ))
    }

    /// Validate and durably retain signed bytes for this miner alone.
    async fn submit_private_transaction(
        &self,
        _bytes: Vec<u8>,
        _options: PrivateTransactionOptions,
    ) -> Result<PrivateTransactionEntry, MiningApiError> {
        Err(MiningApiError::Unavailable(
            "private mining queue is unavailable".into(),
        ))
    }

    /// Withdraw pending work before releasing its reserved wallet inputs.
    async fn cancel_private_transaction(
        &self,
        _tx_id: String,
    ) -> Result<PrivateTransactionEntry, MiningApiError> {
        Err(MiningApiError::Unavailable(
            "private mining queue is unavailable".into(),
        ))
    }

    /// `GET /mining/rewardPublicKey`. Hex-encoded 33-byte compressed
    /// secp256k1 miner pubkey. Same fallibility as [`Self::reward_address`].
    async fn reward_pubkey(&self) -> Result<String, MiningApiError>;
}

/// Categorized errors the REST layer maps to HTTP status codes.
#[derive(Debug, Clone, thiserror::Error)]
pub enum MiningApiError {
    /// Posted nonce doesn't satisfy the cached candidate's target.
    #[error("invalid pow")]
    InvalidPow,
    /// The solved candidate is no longer current: its parent_id no longer
    /// equals the live best-full block id, or the node withdrew it after a
    /// block mined on its parent failed to apply. 400 `stale_candidate`.
    #[error("stale candidate (best-full flipped or candidate withdrawn)")]
    StaleParent,
    /// Mining subsystem disabled or node not synced. 503.
    #[error("mining not available: {0}")]
    Unavailable(String),
    /// Malformed input or internal error. 400 for the former, 500 for
    /// the latter — we collapse to 400 since a malformed solution is
    /// the only realistic shape.
    #[error("{0}")]
    BadRequest(String),
    /// API key required but missing or wrong. 401.
    #[error("api key required")]
    Unauthorized,
    /// Main loop did not reply within the request deadline. 504.
    #[error("timeout: {0}")]
    Timeout(String),
    /// Internal failure. 500.
    #[error("internal: {0}")]
    Internal(String),
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    error: u16,
    detail: String,
    reason: &'static str,
}

impl IntoResponse for MiningApiError {
    fn into_response(self) -> Response {
        let (status, reason): (StatusCode, &'static str) = match &self {
            MiningApiError::InvalidPow => (StatusCode::BAD_REQUEST, "invalid_pow"),
            MiningApiError::StaleParent => (StatusCode::BAD_REQUEST, "stale_candidate"),
            MiningApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            MiningApiError::Unavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            MiningApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            MiningApiError::Timeout(_) => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
            MiningApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        let body = ApiErrorBody {
            error: status.as_u16(),
            detail: self.to_string(),
            reason,
        };
        (status, Json(body)).into_response()
    }
}

/// Query string for `GET /mining/candidate`. `longpoll` carries the `msg`
/// (job id) of the template the client currently holds; see
/// [`NodeMining::candidate`] for the blocking semantics.
#[derive(Debug, Default, Deserialize)]
struct CandidateQuery {
    longpoll: Option<String>,
}

async fn candidate_handler(
    State(m): State<Arc<dyn NodeMining>>,
    Query(q): Query<CandidateQuery>,
) -> Result<Json<WorkMessageJson>, MiningApiError> {
    match m.candidate(q.longpoll).await? {
        Some(w) => Ok(Json(w)),
        None => Err(MiningApiError::Unavailable(
            "no candidate (not synced or generation race)".into(),
        )),
    }
}

/// Bound authenticated candidate requests before they cross into the node loop.
pub const MAX_CANDIDATE_TRANSACTIONS: usize = 1024;
pub const MAX_CANDIDATE_REQUEST_BYTES: usize = 2 * 1024 * 1024;

pub(crate) fn decode_candidate_transactions(
    body: &[u8],
) -> Result<Vec<ScalaTransactionInput>, MiningApiError> {
    check_candidate_body_size(body)?;
    let txs: Vec<ScalaTransactionInput> = serde_json::from_slice(body)
        .map_err(|e| MiningApiError::BadRequest(format!("invalid transaction array: {e}")))?;
    validate_candidate_request(&txs, None)?;
    Ok(txs)
}

pub(crate) fn decode_candidate_with_pk(
    body: &[u8],
) -> Result<CandidateWithTxsAndPkRequest, MiningApiError> {
    check_candidate_body_size(body)?;
    let request: CandidateWithTxsAndPkRequest = serde_json::from_slice(body)
        .map_err(|e| MiningApiError::BadRequest(format!("invalid candidate request: {e}")))?;
    validate_candidate_request(&request.txs, Some(&request.pk))?;
    Ok(request)
}

fn check_candidate_body_size(body: &[u8]) -> Result<(), MiningApiError> {
    if body.len() > MAX_CANDIDATE_REQUEST_BYTES {
        return Err(MiningApiError::BadRequest(format!(
            "candidate request exceeds {MAX_CANDIDATE_REQUEST_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_candidate_request(
    txs: &[ScalaTransactionInput],
    miner_pk: Option<&str>,
) -> Result<(), MiningApiError> {
    if txs.len() > MAX_CANDIDATE_TRANSACTIONS {
        return Err(MiningApiError::BadRequest(format!(
            "candidate request exceeds {MAX_CANDIDATE_TRANSACTIONS} transactions"
        )));
    }
    if let Some(pk) = miner_pk {
        if pk.len() != 66 {
            return Err(MiningApiError::BadRequest(
                "pk must be a compressed secp256k1 public key".into(),
            ));
        }
        let bytes = hex::decode(pk)
            .map_err(|_| MiningApiError::BadRequest("pk must be hexadecimal".into()))?;
        if bytes.len() != 33 || !matches!(bytes[0], 2 | 3) {
            return Err(MiningApiError::BadRequest(
                "pk must be a compressed secp256k1 public key".into(),
            ));
        }
        k256::PublicKey::from_sec1_bytes(&bytes)
            .map_err(|_| MiningApiError::BadRequest("pk is not a secp256k1 curve point".into()))?;
    }
    Ok(())
}

async fn candidate_with_txs_handler(
    State(m): State<Arc<dyn NodeMining>>,
    body: Result<axum::body::Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Json<WorkMessageJson>, MiningApiError> {
    let body = body.map_err(|e| MiningApiError::BadRequest(e.to_string()))?;
    let txs = decode_candidate_transactions(&body)?;
    candidate_response(m.candidate_with_txs(txs, None).await?)
}

async fn candidate_with_txs_and_pk_handler(
    State(m): State<Arc<dyn NodeMining>>,
    body: Result<axum::body::Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Json<WorkMessageJson>, MiningApiError> {
    let body = body.map_err(|e| MiningApiError::BadRequest(e.to_string()))?;
    let request = decode_candidate_with_pk(&body)?;
    candidate_response(m.candidate_with_txs(request.txs, Some(request.pk)).await?)
}

fn candidate_response(
    work: Option<WorkMessageJson>,
) -> Result<Json<WorkMessageJson>, MiningApiError> {
    work.map(Json).ok_or_else(|| {
        MiningApiError::Unavailable("no candidate (not synced or generation race)".into())
    })
}

async fn solution_handler(
    State(m): State<Arc<dyn NodeMining>>,
    Json(body): Json<AutolykosSolutionJson>,
) -> Result<StatusCode, MiningApiError> {
    m.submit_solution(body).await?;
    Ok(StatusCode::OK)
}

async fn reward_address_handler(
    State(m): State<Arc<dyn NodeMining>>,
) -> Result<Json<RewardAddressResponse>, MiningApiError> {
    Ok(Json(RewardAddressResponse {
        reward_address: m.reward_address().await?,
    }))
}

async fn reward_pubkey_handler(
    State(m): State<Arc<dyn NodeMining>>,
) -> Result<Json<RewardPublicKeyResponse>, MiningApiError> {
    Ok(Json(RewardPublicKeyResponse {
        reward_pubkey: m.reward_pubkey().await?,
    }))
}

/// Build the `/mining/*` sub-router. The integrator merges this into
/// the main router via `.merge(mining_router(handle))` when mining is
/// enabled.
pub fn mining_router(mining: Arc<dyn NodeMining>) -> Router {
    legacy_mining_router(mining.clone()).merge(transaction_mining_router(mining))
}

pub(crate) fn legacy_mining_router(mining: Arc<dyn NodeMining>) -> Router {
    Router::new()
        .route("/mining/candidate", get(candidate_handler))
        .route("/mining/solution", post(solution_handler))
        .route("/mining/rewardAddress", get(reward_address_handler))
        .route("/mining/rewardPublicKey", get(reward_pubkey_handler))
        .with_state(mining)
}

pub(crate) fn transaction_mining_router(mining: Arc<dyn NodeMining>) -> Router {
    Router::new()
        .route("/mining/candidateWithTxs", post(candidate_with_txs_handler))
        .route(
            "/mining/candidateWithTxsAndPk",
            post(candidate_with_txs_and_pk_handler),
        )
        .with_state(mining)
}

/// No-op `NodeMining` used by test harnesses + fixtures that mount the
/// router without a real mining subsystem. Every call reports
/// "unavailable" / empty.
#[derive(Debug, Default, Clone)]
pub struct NoopNodeMining;

#[async_trait]
impl NodeMining for NoopNodeMining {
    async fn candidate(
        &self,
        _longpoll: Option<String>,
    ) -> Result<Option<WorkMessageJson>, MiningApiError> {
        Err(MiningApiError::Unavailable("mining disabled".into()))
    }
    async fn submit_solution(&self, _: AutolykosSolutionJson) -> Result<(), MiningApiError> {
        Err(MiningApiError::Unavailable("mining disabled".into()))
    }
    async fn reward_address(&self) -> Result<String, MiningApiError> {
        Err(MiningApiError::Unavailable("mining disabled".into()))
    }
    async fn reward_pubkey(&self) -> Result<String, MiningApiError> {
        Err(MiningApiError::Unavailable("mining disabled".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn noop_mining_is_object_safe_via_arc_dyn() {
        let _: Arc<dyn NodeMining> = Arc::new(NoopNodeMining);
    }

    #[test]
    fn mining_router_builds() {
        let _r = mining_router(Arc::new(NoopNodeMining));
    }

    // ----- reward-key transport mapping -----

    /// Stub whose reward getters return a fixed `Result`, to assert the
    /// rewardAddress/rewardPublicKey HTTP status mapping for the three
    /// reward-key states (Ready→200, Pending→503, Corrupt→500).
    struct RewardStub(fn() -> Result<String, MiningApiError>);

    #[async_trait]
    impl NodeMining for RewardStub {
        async fn candidate(
            &self,
            _longpoll: Option<String>,
        ) -> Result<Option<WorkMessageJson>, MiningApiError> {
            Err(MiningApiError::Unavailable("n/a".into()))
        }
        async fn submit_solution(&self, _: AutolykosSolutionJson) -> Result<(), MiningApiError> {
            Err(MiningApiError::Unavailable("n/a".into()))
        }
        async fn reward_address(&self) -> Result<String, MiningApiError> {
            (self.0)()
        }
        async fn reward_pubkey(&self) -> Result<String, MiningApiError> {
            (self.0)()
        }
    }

    async fn reward_status(src: fn() -> Result<String, MiningApiError>, uri: &str) -> StatusCode {
        use tower::ServiceExt;
        let app = mining_router(Arc::new(RewardStub(src)));
        let req = axum::http::Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap();
        app.oneshot(req).await.unwrap().status()
    }

    // ----- longpoll plumbing -----

    /// Records the `longpoll` value the handler passed through, so the query
    /// extractor can be asserted end-to-end, and returns a fixed candidate.
    struct LongpollSpy {
        seen: std::sync::Mutex<Option<Option<String>>>,
    }

    fn fixed_work() -> WorkMessageJson {
        // Built via the wire form so this test doesn't pull `num_bigint` in
        // just to populate `b`; the value is inert for the longpoll plumbing.
        serde_json::from_value(serde_json::json!({
            "msg": "ab".repeat(32),
            "b": "1",
            "h": 1,
            "pk": "02".repeat(33),
            "template_seq": 1,
            "clean_jobs": true,
        }))
        .expect("valid WorkMessageJson")
    }

    #[async_trait]
    impl NodeMining for LongpollSpy {
        async fn candidate(
            &self,
            longpoll: Option<String>,
        ) -> Result<Option<WorkMessageJson>, MiningApiError> {
            *self.seen.lock().unwrap() = Some(longpoll);
            Ok(Some(fixed_work()))
        }
        async fn submit_solution(&self, _: AutolykosSolutionJson) -> Result<(), MiningApiError> {
            Err(MiningApiError::Unavailable("n/a".into()))
        }
        async fn reward_address(&self) -> Result<String, MiningApiError> {
            Err(MiningApiError::Unavailable("n/a".into()))
        }
        async fn reward_pubkey(&self) -> Result<String, MiningApiError> {
            Err(MiningApiError::Unavailable("n/a".into()))
        }
    }

    async fn candidate_longpoll_seen(uri: &str) -> Option<String> {
        use tower::ServiceExt;
        let spy = Arc::new(LongpollSpy {
            seen: std::sync::Mutex::new(None),
        });
        let app = mining_router(spy.clone());
        let req = axum::http::Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap();
        let status = app.oneshot(req).await.unwrap().status();
        assert_eq!(status, StatusCode::OK);
        let seen = spy.seen.lock().unwrap().clone();
        seen.expect("handler ran")
    }

    #[tokio::test]
    async fn candidate_query_threads_longpoll_param_through_to_the_trait() {
        // No query → None.
        assert_eq!(candidate_longpoll_seen("/mining/candidate").await, None);
        // `?longpoll=<hex>` → Some(<hex>), forwarded verbatim to the trait so
        // the bridge can compare it against the served template's msg.
        assert_eq!(
            candidate_longpoll_seen(&format!("/mining/candidate?longpoll={}", "ab".repeat(32)))
                .await,
            Some("ab".repeat(32)),
        );
    }

    #[tokio::test]
    async fn reward_endpoints_map_ready_pending_corrupt_to_200_503_500() {
        // Ready → 200
        assert_eq!(
            reward_status(|| Ok("9hAddr".into()), "/mining/rewardAddress").await,
            StatusCode::OK
        );
        // Pending (wallet not initialized) → 503
        assert_eq!(
            reward_status(
                || Err(MiningApiError::Unavailable("reward key pending".into())),
                "/mining/rewardPublicKey"
            )
            .await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        // Corrupt (wallet tracking inconsistent) → 500
        assert_eq!(
            reward_status(
                || Err(MiningApiError::Internal("reward key corrupt".into())),
                "/mining/rewardAddress"
            )
            .await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    // ----- candidate request transport and bounds -----

    const GENERATOR_PK: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    type CandidateObservation = (Vec<ScalaTransactionInput>, Option<String>);

    struct CandidateSpy {
        seen: std::sync::Mutex<Option<CandidateObservation>>,
    }

    #[async_trait]
    impl NodeMining for CandidateSpy {
        async fn candidate(
            &self,
            _: Option<String>,
        ) -> Result<Option<WorkMessageJson>, MiningApiError> {
            Ok(Some(fixed_work()))
        }
        async fn candidate_with_txs(
            &self,
            txs: Vec<ScalaTransactionInput>,
            pk: Option<String>,
        ) -> Result<Option<WorkMessageJson>, MiningApiError> {
            *self.seen.lock().unwrap() = Some((txs, pk));
            Ok(Some(fixed_work()))
        }
        async fn submit_solution(&self, _: AutolykosSolutionJson) -> Result<(), MiningApiError> {
            Ok(())
        }
        async fn reward_address(&self) -> Result<String, MiningApiError> {
            Ok(String::new())
        }
        async fn reward_pubkey(&self) -> Result<String, MiningApiError> {
            Ok(GENERATOR_PK.into())
        }
    }

    fn ordered_tx(id_byte: &str) -> String {
        format!(
            r#"{{"inputs":[{{"boxId":"{}","spendingProof":{{"proofBytes":"","extension":{{"5":"0400","3":"0400","8":"0400"}}}}}}],"dataInputs":[],"outputs":[]}}"#,
            id_byte.repeat(32)
        )
    }

    #[tokio::test]
    async fn candidate_posts_preserve_transaction_and_context_extension_order() {
        use tower::ServiceExt;
        for with_pk in [false, true] {
            let spy = Arc::new(CandidateSpy {
                seen: std::sync::Mutex::new(None),
            });
            let txs = format!("[{},{}]", ordered_tx("bb"), ordered_tx("aa"));
            let (path, body) = if with_pk {
                (
                    "/mining/candidateWithTxsAndPk",
                    format!(r#"{{"txs":{txs},"pk":"{GENERATOR_PK}"}}"#),
                )
            } else {
                ("/mining/candidateWithTxs", txs)
            };
            let request = axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap();
            let response = mining_router(spy.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let seen = spy.seen.lock().unwrap();
            let (txs, pk) = seen.as_ref().unwrap();
            assert_eq!(
                txs.iter()
                    .map(|tx| tx.inputs[0].box_id.as_str())
                    .collect::<Vec<_>>(),
                vec!["bb".repeat(32), "aa".repeat(32)]
            );
            assert_eq!(
                txs[0].inputs[0]
                    .spending_proof
                    .extension
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                ["5", "3", "8"]
            );
            assert_eq!(pk.as_deref(), with_pk.then_some(GENERATOR_PK));
        }
    }

    #[test]
    fn candidate_requests_reject_malformed_keys_and_excessive_work() {
        for pk in [
            "",
            "aa",
            &"00".repeat(33),
            &format!("02{}", "ff".repeat(32)),
        ] {
            let body = format!(r#"{{"txs":[],"pk":"{pk}"}}"#);
            assert!(matches!(
                decode_candidate_with_pk(body.as_bytes()),
                Err(MiningApiError::BadRequest(_))
            ));
        }
        let tx = ordered_tx("aa");
        let excessive = format!(
            "[{}]",
            vec![tx.as_str(); MAX_CANDIDATE_TRANSACTIONS + 1].join(",")
        );
        assert!(matches!(
            decode_candidate_transactions(excessive.as_bytes()),
            Err(MiningApiError::BadRequest(_))
        ));
        assert!(matches!(
            decode_candidate_transactions(&vec![b' '; MAX_CANDIDATE_REQUEST_BYTES + 1]),
            Err(MiningApiError::BadRequest(_))
        ));
        assert!(matches!(
            decode_candidate_transactions(b"{}"),
            Err(MiningApiError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn oversized_candidate_body_returns_json_error_without_calling_node() {
        use tower::ServiceExt;
        let spy = Arc::new(CandidateSpy {
            seen: std::sync::Mutex::new(None),
        });
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/mining/candidateWithTxs")
            .body(axum::body::Body::from(vec![
                b' ';
                MAX_CANDIDATE_REQUEST_BYTES + 1
            ]))
            .unwrap();
        let response = mining_router(spy.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(error["reason"], "bad_request");
        assert!(spy.seen.lock().unwrap().is_none());
    }
}
