//! Owner-only finite wallet maintenance jobs.

use std::sync::Arc;

use axum::extract::{Path, State};

use super::super::facade::WalletApi;
use super::{dto, error, no_store, NativeErr, NoStoreJson, StrictJson};

pub(crate) async fn list(
    State(admin): State<Arc<WalletApi>>,
) -> Result<NoStoreJson<dto::WalletJobs>, NativeErr> {
    Ok(no_store(admin.mining_jobs().await.map_err(error::map_err)?))
}

pub(crate) async fn create(
    State(admin): State<Arc<WalletApi>>,
    StrictJson(request): StrictJson<dto::WalletJobRequest>,
) -> Result<NoStoreJson<dto::WalletJob>, NativeErr> {
    Ok(no_store(
        admin
            .create_mining_job(request)
            .await
            .map_err(error::map_err)?,
    ))
}

pub(crate) async fn cancel(
    State(admin): State<Arc<WalletApi>>,
    Path(job_id): Path<String>,
) -> Result<NoStoreJson<dto::WalletJob>, NativeErr> {
    Ok(no_store(
        admin
            .cancel_mining_job(job_id)
            .await
            .map_err(error::map_err)?,
    ))
}
