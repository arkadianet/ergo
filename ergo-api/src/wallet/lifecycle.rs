use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub(crate) use ergo_wallet_protocol::scala::lifecycle::{
    CheckBody, CheckResponse, InitBody, InitResponse, RestoreBody, UnlockBody,
};

use super::types;
use super::WalletAdmin;

pub(crate) fn map_err(e: super::WalletAdminError) -> (StatusCode, Json<serde_json::Value>) {
    let mapped = ergo_wallet_protocol::WalletErrorSurface::Scala.map(&e);
    let status = StatusCode::from_u16(mapped.status).expect("protocol wallet status is valid");
    if status.is_server_error() {
        tracing::error!(reason = mapped.reason, detail = %e, "wallet request failed");
    } else {
        tracing::debug!(reason = mapped.reason, detail = %e, "wallet request rejected");
    }
    let body = serde_json::json!({ "reason": mapped.reason, "detail": e.to_string() });
    (status, Json(body))
}

pub(crate) async fn status(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<Json<types::WalletStatus>, (StatusCode, Json<serde_json::Value>)> {
    let s = admin.status().await.map_err(map_err)?;
    Ok(Json(s))
}

pub(crate) async fn init(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<InitBody>,
) -> Result<Json<InitResponse>, (StatusCode, Json<serde_json::Value>)> {
    let mnemonic = admin
        .init(body.pass, body.mnemonic_pass, body.strength)
        .await
        .map_err(map_err)?;
    Ok(Json(InitResponse { mnemonic }))
}

pub(crate) async fn restore(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<RestoreBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    admin
        .restore(
            body.mnemonic,
            body.mnemonic_pass,
            body.pass,
            body.use_pre_1627_key_derivation,
        )
        .await
        .map_err(map_err)?;
    Ok(StatusCode::OK)
}

pub(crate) async fn unlock(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<UnlockBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    admin.unlock(body.pass).await.map_err(map_err)?;
    Ok(StatusCode::OK)
}

pub(crate) async fn lock(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    admin.lock().await.map_err(map_err)?;
    Ok(StatusCode::OK)
}

pub(crate) async fn check(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<CheckBody>,
) -> Result<Json<CheckResponse>, (StatusCode, Json<serde_json::Value>)> {
    let matched = admin
        .check(body.mnemonic, body.mnemonic_pass)
        .await
        .map_err(map_err)?;
    Ok(Json(CheckResponse { matched }))
}
