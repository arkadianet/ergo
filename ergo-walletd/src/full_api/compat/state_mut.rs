//! Cache-only mutation endpoints — rescan + updateChangeAddress.
//!
//! Rescan needs no unlocked wallet per ErgoWalletActor.scala:340 and is
//! always served. updateChangeAddress requires an unlocked wallet and a
//! signing-owned address (ErgoWalletActor.scala:410); it answers
//! `wallet_locked` when the wallet is locked.

use std::sync::Arc;

use super::super::native::StrictJson;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use super::super::facade::WalletApi;
use super::lifecycle::map_err;

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
    State(admin): State<Arc<WalletApi>>,
    StrictJson(body): StrictJson<RescanBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let from_height = body.from_height;
    admin.rescan(from_height).await.map_err(map_err)?;
    Ok(StatusCode::OK)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UpdateChangeAddressBody {
    address: String,
}

pub(super) async fn update_change_address(
    State(admin): State<Arc<WalletApi>>,
    StrictJson(body): StrictJson<UpdateChangeAddressBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    admin
        .update_change_address(body.address)
        .await
        .map_err(map_err)?;
    Ok(StatusCode::OK)
}
