use std::sync::Arc;

use super::super::native::StrictJson;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub use ergo_wallet_protocol::scala::admin_advanced::*;

use super::super::facade::WalletApi;

pub(crate) async fn derive_key(
    State(admin): State<Arc<WalletApi>>,
    StrictJson(body): StrictJson<DeriveKeyRequest>,
) -> Result<Json<DeriveKeyResponse>, (StatusCode, Json<serde_json::Value>)> {
    use super::lifecycle::map_err;
    let resp = admin.derive_key(body).await.map_err(map_err)?;
    Ok(Json(resp))
}

pub(crate) async fn derive_next_key(
    State(admin): State<Arc<WalletApi>>,
) -> Result<Json<DeriveNextKeyResponse>, (StatusCode, Json<serde_json::Value>)> {
    use super::lifecycle::map_err;
    let resp = admin.derive_next_key().await.map_err(map_err)?;
    Ok(Json(resp))
}

pub(crate) async fn get_private_key(
    State(admin): State<Arc<WalletApi>>,
    StrictJson(body): StrictJson<GetPrivateKeyRequest>,
) -> Result<Json<GetPrivateKeyResponse>, (StatusCode, Json<serde_json::Value>)> {
    use super::lifecycle::map_err;
    let resp = admin.get_private_key(body).await.map_err(map_err)?;
    Ok(Json(resp))
}
