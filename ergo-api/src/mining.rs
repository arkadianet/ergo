//! Mining-side REST routes: `/mining/{candidate,solution,rewardAddress,rewardPublicKey}`.
//!
//! The trait [`NodeMining`] is the seam: the node implements it against
//! `ergo_mining::handle::MiningHandle` + the main loop's mining-submit
//! channel; this crate consumes it through `Arc<dyn NodeMining>`. Routes
//! are async and run on the API tokio task.
//!
//! HTTP shape (matches Scala `MiningApiRoute`):
//! - `GET  /mining/candidate`        → `WorkMessage` JSON
//! - `POST /mining/solution`         → empty body on 200, JSON error on 4xx
//! - `GET  /mining/rewardAddress`    → `{ rewardAddress: "9..." }`
//! - `GET  /mining/rewardPublicKey`  → `{ rewardPubkey: "02..." }`
//!
//! API-key middleware on `/mining/solution` is the integrator's
//! responsibility — this module just wires the route handlers.

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ergo_rest_json::mining::{
    AutolykosSolutionJson, RewardAddressResponse, RewardPublicKeyResponse, WorkMessageJson,
};
use serde::{Deserialize, Serialize};

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

    /// `POST /mining/solution`. Returns `Ok(())` on accepted-by-executor.
    async fn submit_solution(&self, solution: AutolykosSolutionJson) -> Result<(), MiningApiError>;

    /// `GET /mining/rewardAddress`. The base58 P2S over the canonical
    /// reward output script using the miner's pubkey. Fallible: a
    /// wallet-resolved reward key is `Unavailable` (503) until the wallet is
    /// initialized, and `Internal` (500) if wallet tracking is inconsistent —
    /// never a stale or fabricated address.
    async fn reward_address(&self) -> Result<String, MiningApiError>;

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
    /// Cached candidate's parent_id no longer equals the live best-full
    /// block id. 400 "stale candidate (best-full flipped)".
    #[error("stale candidate (best-full flipped)")]
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
    Router::new()
        .route("/mining/candidate", get(candidate_handler))
        .route("/mining/solution", post(solution_handler))
        .route("/mining/rewardAddress", get(reward_address_handler))
        .route("/mining/rewardPublicKey", get(reward_pubkey_handler))
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
}
