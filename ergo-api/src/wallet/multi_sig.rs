use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub use ergo_wallet_protocol::scala::multi_sig::*;

use super::lifecycle::map_err;
use super::WalletAdmin;

pub(crate) async fn generate_commitments(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<GenerateCommitmentsRequest>,
) -> Result<Json<GenerateCommitmentsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let resp = admin.generate_commitments(body).await.map_err(map_err)?;
    Ok(Json(resp))
}

pub(crate) async fn extract_hints(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<HintExtractionRequest>,
) -> Result<Json<HintExtractionResponse>, (StatusCode, Json<serde_json::Value>)> {
    let resp = admin.extract_hints(body).await.map_err(map_err)?;
    Ok(Json(resp))
}
