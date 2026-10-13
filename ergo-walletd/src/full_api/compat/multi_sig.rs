use std::sync::Arc;

use super::super::native::StrictJson;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub use ergo_wallet_protocol::scala::multi_sig::*;

use super::super::facade::WalletApi;
use super::lifecycle::map_err;

pub(crate) async fn generate_commitments(
    State(admin): State<Arc<WalletApi>>,
    StrictJson(body): StrictJson<GenerateCommitmentsRequest>,
) -> Result<Json<GenerateCommitmentsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let resp = admin.generate_commitments(body).await.map_err(map_err)?;
    Ok(Json(resp))
}

pub(crate) async fn extract_hints(
    State(admin): State<Arc<WalletApi>>,
    StrictJson(body): StrictJson<HintExtractionRequest>,
) -> Result<Json<HintExtractionResponse>, (StatusCode, Json<serde_json::Value>)> {
    let resp = admin.extract_hints(body).await.map_err(map_err)?;
    Ok(Json(resp))
}
