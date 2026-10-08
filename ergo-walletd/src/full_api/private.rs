//! Explicit private-mining controls used by the wallet UI. These use the same
//! bounded submission capability as wallet delivery; they do not proxy paths.
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use ergo_wallet_protocol::mining::{PrivateTransactionEntry, PrivateTransactionOptions};
use ergo_wallet_protocol::native::dto::{SendTxRequest, TxDelivery, TxRepr};
use ergo_wallet_service::engine::TxSubmitError;

use super::facade::WalletApi;
use super::native::error::{map_err, native_err, NativeErr};
use super::native::StrictJson;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportRequest {
    signed_transaction_hex: String,
    #[serde(default)]
    options: PrivateTransactionOptions,
}

pub(super) fn router(admin: Arc<WalletApi>) -> Router {
    Router::new()
        .route(
            "/api/v1/mining/private-transactions",
            get(list).post(import),
        )
        .route("/api/v1/mining/private-transactions/:tx_id", get(status))
        .route(
            "/api/v1/mining/private-transactions/:tx_id/cancel",
            post(cancel),
        )
        .with_state(admin)
}

fn submit_error(error: TxSubmitError) -> NativeErr {
    let (status, reason) = match error.reason.as_str() {
        "private_mining_unavailable" => (
            StatusCode::SERVICE_UNAVAILABLE,
            "private_mining_unavailable",
        ),
        "stale_chain_tip" => (StatusCode::CONFLICT, "stale_chain_tip"),
        "timeout" => (StatusCode::GATEWAY_TIMEOUT, "node_rpc_timeout"),
        "overloaded" => (StatusCode::TOO_MANY_REQUESTS, "overloaded"),
        "shutting_down" => (StatusCode::SERVICE_UNAVAILABLE, "shutting_down"),
        "unauthorized"
        | "node_rpc_failed"
        | "invalid_node_response"
        | "node_rpc_worker_failed"
        | "invalid_node_transaction_id" => (StatusCode::SERVICE_UNAVAILABLE, "node_rpc_failed"),
        _ => (StatusCode::BAD_REQUEST, error.reason.as_str()),
    };
    native_err(status, reason, None)
}

fn validate_id(tx_id: String) -> Result<String, NativeErr> {
    if tx_id.len() != 64 || !tx_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(native_err(StatusCode::BAD_REQUEST, "bad_request", None));
    }
    Ok(tx_id.to_ascii_lowercase())
}

async fn list(State(admin): State<Arc<WalletApi>>) -> Result<Json<serde_json::Value>, NativeErr> {
    let submitter = admin.host.submitter();
    let entries = admin
        .host
        .call_spending_async(move |_| {
            Box::pin(async move { Ok(submitter.private_transactions().await) })
        })
        .await
        .map_err(map_err)?
        .map_err(submit_error)?;
    Ok(Json(serde_json::json!({"items":entries})))
}

async fn status(
    State(admin): State<Arc<WalletApi>>,
    Path(tx_id): Path<String>,
) -> Result<Json<PrivateTransactionEntry>, NativeErr> {
    let tx_id = validate_id(tx_id)?;
    let submitter = admin.host.submitter();
    let entry = admin
        .host
        .call_spending_async(move |_| {
            Box::pin(async move { Ok(submitter.private_transaction_status(tx_id).await) })
        })
        .await
        .map_err(map_err)?
        .map_err(submit_error)?;
    entry
        .map(Json)
        .ok_or_else(|| native_err(StatusCode::NOT_FOUND, "tx_not_found", None))
}

async fn import(
    State(admin): State<Arc<WalletApi>>,
    StrictJson(request): StrictJson<ImportRequest>,
) -> Result<Json<PrivateTransactionEntry>, NativeErr> {
    let response = admin
        .send_transaction(SendTxRequest::Signed {
            signed_transaction: TxRepr::Bytes {
                bytes: request.signed_transaction_hex,
            },
            delivery: TxDelivery::MinePrivate,
            private_options: Some(request.options),
        })
        .await
        .map_err(map_err)?;
    let submitter = admin.host.submitter();
    let entry = admin
        .host
        .call_spending_async(move |_| {
            Box::pin(async move { Ok(submitter.private_transaction_status(response.tx_id).await) })
        })
        .await
        .map_err(map_err)?
        .map_err(submit_error)?;
    entry.map(Json).ok_or_else(|| {
        native_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "private_status_unavailable",
            None,
        )
    })
}

async fn cancel(
    State(admin): State<Arc<WalletApi>>,
    Path(tx_id): Path<String>,
) -> Result<Json<PrivateTransactionEntry>, NativeErr> {
    let tx_id = validate_id(tx_id)?;
    let submitter = admin.host.submitter();
    let entry = admin
        .host
        .call_spending_async(move |_| {
            Box::pin(async move {
                if let Err(error) = submitter.cancel_private_transaction(tx_id.clone()).await {
                    return Ok(Err(error));
                }
                Ok(submitter.private_transaction_status(tx_id).await)
            })
        })
        .await
        .map_err(map_err)?
        .map_err(submit_error)?;
    entry
        .map(Json)
        .ok_or_else(|| native_err(StatusCode::NOT_FOUND, "tx_not_found", None))
}
