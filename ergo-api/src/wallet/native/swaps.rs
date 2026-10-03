//! Authenticated wallet-approved bounded private direct swaps.

use super::{dto, error, no_store, NativeErr, NoStoreJson, StrictJson};
use crate::wallet::WalletAdmin;
use axum::extract::{Path, State};
use std::sync::Arc;

#[utoipa::path(
    get, path = "/api/v1/wallet/mining-swaps", tag = "wallet",
    responses((status = 200, description = "Bounded private swap intents", body = dto::MiningSwaps)),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn list(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<NoStoreJson<dto::MiningSwaps>, NativeErr> {
    Ok(no_store(
        admin.mining_swaps().await.map_err(error::map_err)?,
    ))
}
#[utoipa::path(
    post, path = "/api/v1/wallet/mining-swaps/preview", tag = "wallet",
    request_body = dto::MiningSwapRequest,
    responses((status = 200, description = "Frozen canonical pool quote and unsigned transaction", body = dto::MiningSwapPreview)),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn preview(
    State(admin): State<Arc<dyn WalletAdmin>>,
    StrictJson(request): StrictJson<dto::MiningSwapRequest>,
) -> Result<NoStoreJson<dto::MiningSwapPreview>, NativeErr> {
    Ok(no_store(
        admin
            .preview_mining_swap(request)
            .await
            .map_err(error::map_err)?,
    ))
}
#[utoipa::path(
    post, path = "/api/v1/wallet/mining-swaps", tag = "wallet",
    request_body = dto::MiningSwapRequest,
    responses(
        (status = 200, description = "Approved bounded swap intent", body = dto::MiningSwap),
        (status = 400, description = "Invalid pool, owned funding or price bounds", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn create(
    State(admin): State<Arc<dyn WalletAdmin>>,
    StrictJson(request): StrictJson<dto::MiningSwapRequest>,
) -> Result<NoStoreJson<dto::MiningSwap>, NativeErr> {
    Ok(no_store(
        admin
            .create_mining_swap(request)
            .await
            .map_err(error::map_err)?,
    ))
}
#[utoipa::path(
    post, path = "/api/v1/wallet/mining-swaps/{swap_id}/cancel", tag = "wallet",
    params(("swap_id" = String, Path, description = "Durable decimal intent ID")),
    responses((status = 200, description = "Cancelled intent and retired private templates, or already mined status", body = dto::MiningSwap)),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn cancel(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Path(swap_id): Path<String>,
) -> Result<NoStoreJson<dto::MiningSwap>, NativeErr> {
    Ok(no_store(
        admin
            .cancel_mining_swap(swap_id)
            .await
            .map_err(error::map_err)?,
    ))
}
