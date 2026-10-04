//! Owner-only finite wallet maintenance jobs.

use std::sync::Arc;

use axum::extract::{Path, State};

use super::{dto, error, no_store, NativeErr, NoStoreJson, StrictJson};
use crate::wallet::WalletAdmin;

#[utoipa::path(
    get, path = "/api/v1/wallet/mining-jobs", tag = "wallet",
    responses((status = 200, description = "Private wallet maintenance jobs", body = dto::WalletJobs)),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn list(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<NoStoreJson<dto::WalletJobs>, NativeErr> {
    Ok(no_store(admin.mining_jobs().await.map_err(error::map_err)?))
}

#[utoipa::path(
    post, path = "/api/v1/wallet/mining-jobs", tag = "wallet",
    request_body = dto::WalletJobRequest,
    responses(
        (status = 200, description = "One approved, finite private maintenance job", body = dto::WalletJob),
        (status = 400, description = "Invalid schedule, operation or pinned inputs, or a transaction consensus or the size limit would reject", body = error::NativeWalletError),
        (status = 404, description = "A pinned input is not an unspent wallet box", body = error::NativeWalletError),
        (status = 409, description = "The wallet is locked or its scan is invalidated", body = error::NativeWalletError),
        (status = 422, description = "The pinned inputs cannot fund or sign the operation", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn create(
    State(admin): State<Arc<dyn WalletAdmin>>,
    StrictJson(request): StrictJson<dto::WalletJobRequest>,
) -> Result<NoStoreJson<dto::WalletJob>, NativeErr> {
    Ok(no_store(
        admin
            .create_mining_job(request)
            .await
            .map_err(error::map_err)?,
    ))
}

#[utoipa::path(
    post, path = "/api/v1/wallet/mining-jobs/{job_id}/cancel", tag = "wallet",
    params(("job_id" = String, Path, description = "Durable decimal job ID")),
    responses((status = 200, description = "Cancelled job. Queued private work is withdrawn; a signed transaction stays valid until one of its inputs is spent", body = dto::WalletJob)),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn cancel(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Path(job_id): Path<String>,
) -> Result<NoStoreJson<dto::WalletJob>, NativeErr> {
    Ok(no_store(
        admin
            .cancel_mining_job(job_id)
            .await
            .map_err(error::map_err)?,
    ))
}
