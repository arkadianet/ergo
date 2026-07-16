//! Cache-only mutation endpoints — rescan + updateChangeAddress.
//!
//! Neither route requires an unlocked wallet per ErgoWalletActor.scala:
//! 340,410. Both are always-served, matching every other `/wallet/*` route
//! (see `crate::wallet` module docs).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use super::lifecycle::map_err;
use super::WalletAdmin;

/// Per spec §6 + §8.1: rescan body is `{ "fromHeight": u32 }`.
/// Optional; defaults to 0 (full from-genesis replay). Handler
/// returns 200 immediately; the rebuild runs in the background via
/// the writer task.
#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub(super) struct RescanBody {
    from_height: u32,
}

pub(super) async fn rescan(
    State(admin): State<Arc<dyn WalletAdmin>>,
    body: Option<Json<RescanBody>>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let from_height = body.map(|Json(b)| b.from_height).unwrap_or(0);
    admin.rescan(from_height).await.map_err(map_err)?;
    Ok(StatusCode::OK)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UpdateChangeAddressBody {
    address: String,
}

pub(super) async fn update_change_address(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<UpdateChangeAddressBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    admin
        .update_change_address(body.address)
        .await
        .map_err(map_err)?;
    Ok(StatusCode::OK)
}
