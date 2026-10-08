//! Owner-only private mining queue. Never mounted on public submission routes.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use super::OperatorState;
use crate::mining::PrivateTransactionRequest;

#[utoipa::path(get, path = "/api/v1/mining/private-transactions",
    operation_id = "v1_mining_private_transactions_get", tag = "mining",
    responses((status = 200, description = "Owner-only private queue")), security(("ApiKeyAuth" = [])))]
pub(crate) async fn list(State(s): State<OperatorState>) -> Response {
    let m = match s.private_queue() {
        Ok(m) => m,
        Err(e) => return *e,
    };
    match m.private_transactions().await {
        Ok(items) => (
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(json!({"items":items})),
        )
            .into_response(),
        Err(e) => {
            super::mining::map_mining_error(e, crate::v1::error::Reason::CandidateUnavailable)
        }
    }
}

#[utoipa::path(post, path = "/api/v1/mining/private-transactions",
    operation_id = "v1_mining_private_transactions_post", tag = "mining",
    request_body = PrivateTransactionRequest,
    responses((status = 200, description = "Durably queued without relay", body = crate::mining::PrivateTransactionEntry)), security(("ApiKeyAuth" = [])))]
pub(crate) async fn submit(
    State(s): State<OperatorState>,
    Json(req): Json<PrivateTransactionRequest>,
) -> Response {
    let m = match s.mining() {
        Ok(m) => m,
        Err(e) => return *e,
    };
    let bytes = match hex::decode(&req.signed_transaction_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            return super::mining::map_mining_error(
                crate::mining::MiningApiError::BadRequest(
                    "signed_transaction_hex must be hexadecimal".into(),
                ),
                crate::v1::error::Reason::CandidateUnavailable,
            )
        }
    };
    match m.submit_private_transaction(bytes, req.options).await {
        Ok(entry) => (
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(entry),
        )
            .into_response(),
        Err(e) => {
            super::mining::map_mining_error(e, crate::v1::error::Reason::CandidateUnavailable)
        }
    }
}

#[utoipa::path(post, path = "/api/v1/mining/private-transactions/{tx_id}/cancel",
    operation_id = "v1_mining_private_transaction_cancel_post", tag = "mining",
    params(("tx_id" = String, Path, description = "Private transaction id")),
    responses((status = 200, description = "Transaction withdrawn and inputs released", body = crate::mining::PrivateTransactionEntry)), security(("ApiKeyAuth" = [])))]
pub(crate) async fn cancel(State(s): State<OperatorState>, Path(tx_id): Path<String>) -> Response {
    let m = match s.private_queue() {
        Ok(m) => m,
        Err(e) => return *e,
    };
    if !hex::decode(&tx_id).is_ok_and(|id| id.len() == 32) {
        return super::mining::map_mining_error(
            crate::mining::MiningApiError::BadRequest(
                "tx_id must be 32 bytes of hexadecimal".into(),
            ),
            crate::v1::error::Reason::CandidateUnavailable,
        );
    }
    match m.cancel_private_transaction(tx_id).await {
        Ok(entry) => (
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(entry),
        )
            .into_response(),
        Err(e) => {
            super::mining::map_mining_error(e, crate::v1::error::Reason::CandidateUnavailable)
        }
    }
}
