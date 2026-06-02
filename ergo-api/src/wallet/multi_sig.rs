//! Multi-sig REST handlers for `/wallet/generateCommitments` and
//! `/wallet/extractHints`.
//!
//! Each handler is a thin forwarding wrapper to `WalletAdmin`; the
//! writer-task implementation owns the real commitment-generation +
//! hint-extraction logic.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use super::lifecycle::map_err;
use super::sending::{ExternalSecretDto, TxHintsBagDto};
use super::WalletAdmin;

// ---- request / response DTOs ----

/// `POST /wallet/generateCommitments` request.
///
/// Mirrors Scala `WalletApiRoute.generateCommitmentsR`:
/// unsigned tx + optional secrets + optional input/data-input box id overrides.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateCommitmentsRequest {
    /// Hex-encoded serialised unsigned transaction bytes.
    pub unsigned_tx: String,
    /// Optional external secrets used to generate commitments for
    /// propositions not covered by the wallet's own keys.
    #[serde(default)]
    pub external_secrets: Option<Vec<ExternalSecretDto>>,
    /// Explicit input box ids (hex) to include. `None` means "use all inputs
    /// in the unsigned tx".
    #[serde(default)]
    pub inputs: Option<Vec<String>>,
    /// Data-input box ids (hex). `None` means "use all data inputs in the tx".
    #[serde(default)]
    pub data_inputs: Option<Vec<String>>,
}

/// `POST /wallet/generateCommitments` response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateCommitmentsResponse {
    pub hints: TxHintsBagDto,
}

/// `POST /wallet/extractHints` request.
///
/// Mirrors Scala `WalletApiRoute.extractHintsR`:
/// a signed tx + the propositions categorised as "real" (known secret)
/// or "simulated" (OR-branch the caller can't prove).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HintExtractionRequest {
    /// Hex-encoded serialised signed transaction bytes.
    pub tx: String,
    /// ErgoTree hex strings (or address strings) of propositions for which
    /// the caller proved knowledge of a secret (real branches).
    pub real: Vec<String>,
    /// ErgoTree hex strings of simulated (OR-branch, no secret) propositions.
    pub simulated: Vec<String>,
    /// Explicit input box ids (hex) to include.
    #[serde(default)]
    pub inputs: Option<Vec<String>>,
    /// Data-input box ids (hex) to include.
    #[serde(default)]
    pub data_inputs: Option<Vec<String>>,
}

/// `POST /wallet/extractHints` response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HintExtractionResponse {
    pub hints: TxHintsBagDto,
}

// ---- handlers ----

/// `POST /wallet/generateCommitments`
///
/// Generates sigma-protocol commitments for the given unsigned transaction.
/// Returns an `OwnCommitment` bag (secret part) together with the matching
/// `RealCommitment` bag (public part to share with co-signers).
///
/// Forwards to `WalletAdmin::generate_commitments`; the writer-task
/// implementation owns the real commitment-generation logic.
pub(crate) async fn generate_commitments(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<GenerateCommitmentsRequest>,
) -> Result<Json<GenerateCommitmentsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let resp = admin.generate_commitments(body).await.map_err(map_err)?;
    Ok(Json(resp))
}

/// `POST /wallet/extractHints`
///
/// Extracts hints from a signed transaction for the given real / simulated
/// proposition sets. Returns a `RealCommitment + RealSecretProof` bag for the
/// real set and `SimulatedCommitment + SimulatedSecretProof` for the simulated
/// set.
///
/// Forwards to `WalletAdmin::extract_hints`; the writer-task implementation
/// owns the real hint-extraction logic.
pub(crate) async fn extract_hints(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<HintExtractionRequest>,
) -> Result<Json<HintExtractionResponse>, (StatusCode, Json<serde_json::Value>)> {
    let resp = admin.extract_hints(body).await.map_err(map_err)?;
    Ok(Json(resp))
}
