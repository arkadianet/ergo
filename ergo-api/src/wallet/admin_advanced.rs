//! Advanced HD-key REST handlers.
//!
//! Routes (mounted in `wallet/mod.rs`):
//! - `POST /wallet/deriveKey`     — derive a pubkey at a caller-supplied BIP32 path.
//! - `GET  /wallet/deriveNextKey` — derive the next sequential key at the EIP-3 base path.
//! - `POST /wallet/getPrivateKey` — expose the private scalar for an address (operator-flag gated).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use super::WalletAdmin;

// ----- DTOs -----

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveKeyRequest {
    /// BIP32 path string, e.g. `m/44'/429'/0'/0/5`.
    pub derivation_path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveKeyResponse {
    /// Base58-encoded P2PK address for the derived pubkey.
    pub address: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveNextKeyResponse {
    /// BIP32 path of the newly-derived key.
    pub derivation_path: String,
    /// Base58-encoded P2PK address for the derived pubkey.
    pub address: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPrivateKeyRequest {
    /// Base58-encoded P2PK address whose scalar to return.
    pub address: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPrivateKeyResponse {
    /// Hex-encoded 32-byte secp256k1 scalar. Exposed only when
    /// `wallet.expose_private_keys = true` in the node config.
    pub w: String,
}

// ----- handlers -----

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
