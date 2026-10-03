//! Authenticated miner block policy. Reads and edits share the node's actual
//! assembly preferences; writes retire work built with the prior policy.

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::Value;

use super::OperatorState;
use crate::v1::error::Reason;

#[utoipa::path(
    get, path = "/api/v1/mining/policy", tag = "mining",
    responses((status = 200, description = "Active durable block assembly policy", body = Value)),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn get(State(state): State<OperatorState>) -> Response {
    let mining = match state.mining() {
        Ok(mining) => mining,
        Err(error) => return *error,
    };
    match mining.block_policy().await {
        Ok(policy) => Json(policy).into_response(),
        Err(error) => super::mining::map_mining_error(error, Reason::CandidateUnavailable),
    }
}

#[utoipa::path(
    put, path = "/api/v1/mining/policy", tag = "mining",
    request_body = Value,
    responses(
        (status = 200, description = "Saved policy; previously offered templates retired", body = Value),
        (status = 400, description = "Malformed or contradictory policy"),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn set(State(state): State<OperatorState>, Json(policy): Json<Value>) -> Response {
    let mining = match state.mining() {
        Ok(mining) => mining,
        Err(error) => return *error,
    };
    match mining.set_block_policy(policy).await {
        Ok(policy) => Json(policy).into_response(),
        Err(error) => super::mining::map_mining_error(error, Reason::CandidateUnavailable),
    }
}
