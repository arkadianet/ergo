use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub use ergo_wallet_protocol::scala::sending::*;

use super::lifecycle::map_err;
use super::types::TxIdResponse;
use super::WalletAdmin;

pub(crate) async fn payment_send(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(requests): Json<Vec<PaymentRequestDto>>,
) -> Result<Json<TxIdResponse>, (StatusCode, Json<serde_json::Value>)> {
    let tx_id = admin.payment_send(requests).await.map_err(map_err)?;
    Ok(Json(TxIdResponse { tx_id }))
}

pub(crate) async fn transaction_generate(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(req): Json<TransactionGenerateRequest>,
) -> Result<Json<TransactionGenerateResponse>, (StatusCode, Json<serde_json::Value>)> {
    let resp = admin.transaction_generate(req).await.map_err(map_err)?;
    Ok(Json(resp))
}

pub(crate) async fn transaction_generate_unsigned(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(req): Json<TransactionGenerateUnsignedRequest>,
) -> Result<Json<TransactionGenerateUnsignedResponse>, (StatusCode, Json<serde_json::Value>)> {
    let resp = admin
        .transaction_generate_unsigned(req)
        .await
        .map_err(map_err)?;
    Ok(Json(resp))
}

pub(crate) async fn transaction_sign(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(req): Json<TransactionSignRequest>,
) -> Result<Json<TransactionSignResponse>, (StatusCode, Json<serde_json::Value>)> {
    let resp = admin.transaction_sign(req).await.map_err(map_err)?;
    Ok(Json(resp))
}

pub(crate) async fn transaction_send(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(req): Json<TransactionSendRequest>,
) -> Result<Json<TxIdResponse>, (StatusCode, Json<serde_json::Value>)> {
    let tx_id = admin.transaction_send(req).await.map_err(map_err)?;
    Ok(Json(TxIdResponse { tx_id }))
}

pub(crate) async fn boxes_collect(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(req): Json<BoxesCollectRequest>,
) -> Result<Json<BoxesCollectResponse>, (StatusCode, Json<serde_json::Value>)> {
    let resp = admin.boxes_collect(req).await.map_err(map_err)?;
    Ok(Json(resp))
}
