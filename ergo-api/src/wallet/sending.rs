//! Send-REST handlers + typed DTOs.
//!
//! 5 handlers: payment/send, transaction/generate, transaction/generateUnsigned,
//! transaction/sign, transaction/send. All forward to `WalletAdmin`; the
//! writer-task implementation owns the real send logic.
//!
//! Also declares `BoxesCollectRequest` / `BoxesCollectResponse` (needed by the
//! `WalletAdmin` trait alongside the box-selection handler).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use super::lifecycle::map_err;
use super::types::TxIdResponse;
use super::WalletAdmin;

// ---- wire DTOs ----

/// A single token amount carried in a payment request or response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetDto {
    pub token_id: String,
    pub amount: u64,
}

/// One payment target: address + nanoERG value + optional tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequestDto {
    pub address: String,
    pub value: u64,
    #[serde(default)]
    pub assets: Vec<AssetDto>,
}

/// Hex-encoded bytes of a signed transaction (binary via hex wire shape).
/// The current wire shape is binary-via-hex; Scala-style nested JSON may be
/// added later.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedTxDto {
    /// Hex-encoded serialised transaction bytes.
    pub bytes: String,
}

/// Hex-encoded bytes of an unsigned transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedTxDto {
    /// Hex-encoded serialised unsigned transaction bytes.
    pub bytes: String,
}

/// Wire enum for an externally supplied secret. Distinct from
/// `ergo_wallet::proving::external::ProverExternalSecret` (internal type
/// carrying decoded `k256::Scalar`s). This type carries hex strings and
/// is deserialized from JSON; the writer task decodes hex → scalar on use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExternalSecretDto {
    /// Discrete log secret: `dlog` is a big-endian hex scalar.
    Dlog { dlog: String },
    /// Diffie-Hellman tuple: four compressed SEC1 group element points +
    /// the scalar secret.
    DhTuple {
        g: String,
        h: String,
        u: String,
        v: String,
        x: String,
    },
}

/// Wire shape for a transaction hint bag.
///
/// Mirrors Scala `TransactionHintsBag(secretHints, publicHints)`. The map key
/// is the input index serialised as a decimal string (Scala JSON shape).
/// Secret hints carry `OwnCommitment`; public hints carry everything else
/// (`RealCommitment`, `SimulatedCommitment`, `RealSecretProof`,
/// `SimulatedSecretProof`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TxHintsBagDto {
    /// Per-input secret hints keyed by input index (decimal string).
    #[serde(default)]
    pub secret_hints: std::collections::BTreeMap<String, Vec<HintDto>>,
    /// Per-input public hints keyed by input index (decimal string).
    #[serde(default)]
    pub public_hints: std::collections::BTreeMap<String, Vec<HintDto>>,
}

/// A single sigma-protocol hint.
///
/// The `hint` field acts as the serde tag and uses the canonical Scala/sigma-rust
/// names: `cmtReal`, `cmtSimulated`, `cmtWithSecret`, `proofReal`, `proofSimulated`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "hint", rename_all = "camelCase")]
pub enum HintDto {
    /// Real commitment — public; shared with co-signers.
    /// Scala: `RealCommitment`.
    #[serde(rename = "cmtReal")]
    RealCommitment {
        image: SigmaBooleanJson,
        commitment: FirstProverMessageJson,
        position: String,
    },
    /// Simulated commitment — for OR-branches the prover can't prove.
    /// Scala: `SimulatedCommitment`.
    #[serde(rename = "cmtSimulated")]
    SimulatedCommitment {
        image: SigmaBooleanJson,
        commitment: FirstProverMessageJson,
        /// Fiat-Shamir challenge (24 bytes, hex-encoded).
        challenge: String,
        position: String,
    },
    /// Own commitment — private; contains the secret randomness scalar.
    /// Scala: `OwnCommitment` / `cmtWithSecret`.
    #[serde(rename = "cmtWithSecret")]
    OwnCommitment {
        image: SigmaBooleanJson,
        /// Secret randomness scalar `r` (32 bytes, hex-encoded).
        /// Must never be logged or returned to untrusted callers.
        secret: String,
        commitment: FirstProverMessageJson,
        position: String,
    },
    /// Real secret proof — challenge + response for a leaf the prover knows.
    /// Scala: `RealSecretProof`.
    #[serde(rename = "proofReal")]
    RealSecretProof {
        image: SigmaBooleanJson,
        /// Fiat-Shamir challenge (24 bytes, hex-encoded).
        challenge: String,
        /// Schnorr/DHT response scalar (32 bytes, hex-encoded).
        response: String,
        position: String,
    },
    /// Simulated proof — for OR-branches the prover simulates.
    /// Scala: `SimulatedSecretProof`.
    #[serde(rename = "proofSimulated")]
    SimulatedSecretProof {
        image: SigmaBooleanJson,
        /// Fiat-Shamir challenge (24 bytes, hex-encoded).
        challenge: String,
        /// Simulated response scalar (32 bytes, hex-encoded).
        response: String,
        position: String,
    },
}

/// First-prover message: the public commitment broadcast at the start of a
/// sigma protocol round. The `op` field tags the variant.
///
/// Scala: `FirstProverMessage` hierarchy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum FirstProverMessageJson {
    /// Schnorr commitment `A = g^r` (SEC1-compressed, hex-encoded).
    #[serde(rename = "dlogA")]
    Dlog {
        /// `g^r` — 33-byte compressed point, hex-encoded.
        a: String,
    },
    /// DH-tuple commitment `(A, B) = (g^r, h^r)` — two compressed points.
    #[serde(rename = "dhtABab")]
    DhTuple {
        /// `g^r` — 33-byte compressed point, hex-encoded.
        a: String,
        /// `h^r` — 33-byte compressed point, hex-encoded.
        b: String,
    },
}

/// Opaque JSON representation of a `SigmaBoolean` proposition.
///
/// The inner value is kept as a `serde_json::Value` so the API layer
/// can forward it without needing to parse the full sigma-boolean tree.
/// Callers supply the Scala-compatible JSON object verbatim; typed
/// conversion helpers may be added later.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigmaBooleanJson {
    #[serde(flatten)]
    pub inner: serde_json::Value,
}

/// Serialise a `NodePosition` to its hyphen-joined wire string.
///
/// Example: `NodePosition { positions: [1, 0, 2] }` → `"1-0-2"`.
/// The root-level crypto-tree prefix `[1]` serialises as `"1"` (no hyphen).
pub fn node_position_to_str(positions: &[u32]) -> String {
    positions
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// Parse a hyphen-joined position string back into a `Vec<u32>`.
///
/// Returns `Err` if any segment is not a valid `u32`.
pub fn node_position_from_str(s: &str) -> Result<Vec<u32>, String> {
    s.split('-')
        .map(|seg| {
            seg.parse::<u32>()
                .map_err(|_| format!("invalid position segment: {seg:?}"))
        })
        .collect()
}

// ---- request/response DTOs ----

/// `POST /wallet/transaction/generate` — build + sign, no submit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionGenerateRequest {
    pub requests: Vec<PaymentRequestDto>,
    /// Override box selection with explicit box IDs (hex).
    pub inputs: Option<Vec<String>>,
    /// Data-input box IDs (hex).
    pub data_inputs: Option<Vec<String>>,
    /// Explicit fee in nanoERG (uses MinFee when omitted).
    pub fee: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionGenerateResponse {
    pub transaction: SignedTxDto,
}

/// `POST /wallet/transaction/generateUnsigned` — build only, no sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionGenerateUnsignedRequest {
    pub requests: Vec<PaymentRequestDto>,
    pub inputs: Option<Vec<String>>,
    pub data_inputs: Option<Vec<String>>,
    pub fee: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionGenerateUnsignedResponse {
    pub unsigned_tx: UnsignedTxDto,
}

/// `POST /wallet/transaction/sign` — sign an already-built unsigned tx.
/// Works even when wallet is locked if `external_secrets` cover all inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSignRequest {
    pub unsigned_tx: UnsignedTxDto,
    pub external_secrets: Option<Vec<ExternalSecretDto>>,
    pub hints: Option<TxHintsBagDto>,
    pub inputs: Option<Vec<String>>,
    pub data_inputs: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSignResponse {
    pub transaction: SignedTxDto,
}

/// `POST /wallet/transaction/send` — build + sign + submit.
/// Mirrors `TransactionGenerateRequest` per Scala's `sendTransactionR`
/// (RequestsHolder path: build + sign + verify + submit with explicit
/// input/dataInput overrides).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSendRequest {
    pub requests: Vec<PaymentRequestDto>,
    pub inputs: Option<Vec<String>>,
    pub data_inputs: Option<Vec<String>>,
    pub fee: Option<u64>,
}

// ---- boxes/collect DTOs (needed by WalletAdmin trait before boxes_collect.rs) ----

/// `POST /wallet/boxes/collect` request: target value + optional token targets.
/// Used by `WalletAdmin::boxes_collect` which calls the box selector without
/// submitting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoxesCollectRequest {
    /// Target nanoERG amount to collect.
    pub target_assets: Vec<AssetDto>,
    pub target_balance: u64,
}

/// Response to `POST /wallet/boxes/collect`: selected boxes + change boxes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoxesCollectResponse {
    pub boxes: Vec<String>,
    pub change_boxes: Vec<String>,
}

// ---- handlers ----

/// `POST /wallet/payment/send`
///
/// Build + sign + verify + submit using the wallet's automatic box selection.
/// No explicit input overrides (use `/wallet/transaction/send` for that).
/// Returns the submitted transaction ID on success.
pub(crate) async fn payment_send(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(requests): Json<Vec<PaymentRequestDto>>,
) -> Result<Json<TxIdResponse>, (StatusCode, Json<serde_json::Value>)> {
    let tx_id = admin.payment_send(requests).await.map_err(map_err)?;
    Ok(Json(TxIdResponse { tx_id }))
}

/// `POST /wallet/transaction/generate`
///
/// Build + sign, no submit. Returns the signed transaction bytes (hex).
pub(crate) async fn transaction_generate(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(req): Json<TransactionGenerateRequest>,
) -> Result<Json<TransactionGenerateResponse>, (StatusCode, Json<serde_json::Value>)> {
    let resp = admin.transaction_generate(req).await.map_err(map_err)?;
    Ok(Json(resp))
}

/// `POST /wallet/transaction/generateUnsigned`
///
/// Build only (no signing). Returns the unsigned transaction bytes (hex).
pub(crate) async fn transaction_generate_unsigned(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(req): Json<TransactionGenerateUnsignedRequest>,
) -> Result<Json<TransactionGenerateUnsignedResponse>, (StatusCode, Json<serde_json::Value>)> {
    let resp = admin
        .transaction_generate_unsigned(req)
        .await
        .map_err(map_err)?;
    Ok(Json(resp))
}

/// `POST /wallet/transaction/sign`
///
/// Sign a caller-supplied unsigned transaction. Accepts external secrets so
/// this route works even when the wallet is locked (lock-matrix path).
pub(crate) async fn transaction_sign(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(req): Json<TransactionSignRequest>,
) -> Result<Json<TransactionSignResponse>, (StatusCode, Json<serde_json::Value>)> {
    let resp = admin.transaction_sign(req).await.map_err(map_err)?;
    Ok(Json(resp))
}

/// `POST /wallet/transaction/send`
///
/// Build + sign + verify + submit with explicit input/dataInput overrides.
/// Mirrors Scala's `sendTransactionR` (RequestsHolder path). Returns the
/// submitted transaction ID on success.
pub(crate) async fn transaction_send(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(req): Json<TransactionSendRequest>,
) -> Result<Json<TxIdResponse>, (StatusCode, Json<serde_json::Value>)> {
    let tx_id = admin.transaction_send(req).await.map_err(map_err)?;
    Ok(Json(TxIdResponse { tx_id }))
}

/// `POST /wallet/boxes/collect`
///
/// Run box selection without submitting. Returns selected + change boxes.
/// Forwards to `WalletAdmin::boxes_collect`.
pub(crate) async fn boxes_collect(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(req): Json<BoxesCollectRequest>,
) -> Result<Json<BoxesCollectResponse>, (StatusCode, Json<serde_json::Value>)> {
    let resp = admin.boxes_collect(req).await.map_err(map_err)?;
    Ok(Json(resp))
}
