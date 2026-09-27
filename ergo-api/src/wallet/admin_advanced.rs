use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub use ergo_wallet_protocol::scala::admin_advanced::*;

use super::WalletAdmin;

pub(crate) async fn derive_key(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<DeriveKeyRequest>,
) -> Result<Json<DeriveKeyResponse>, (StatusCode, Json<serde_json::Value>)> {
    use super::lifecycle::map_err;
    let resp = admin.derive_key(body).await.map_err(map_err)?;
    Ok(Json(resp))
}

pub(crate) async fn derive_next_key(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<Json<DeriveNextKeyResponse>, (StatusCode, Json<serde_json::Value>)> {
    use super::lifecycle::map_err;
    let resp = admin.derive_next_key().await.map_err(map_err)?;
    Ok(Json(resp))
}

pub(crate) async fn get_private_key(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<GetPrivateKeyRequest>,
) -> Result<Json<GetPrivateKeyResponse>, (StatusCode, Json<serde_json::Value>)> {
    use super::lifecycle::map_err;
    let resp = admin.get_private_key(body).await.map_err(map_err)?;
    Ok(Json(resp))
}
