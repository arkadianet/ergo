//! Lifecycle endpoints for `/wallet/*` — unconditionally mounted, unlike
//! routes gated on node configuration.
//!
//! Routes: status, init, restore, unlock, lock, check.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use super::types;
use super::WalletAdmin;

/// Map `WalletAdminError` to an HTTP response.
///
/// `pub(crate)` so `reads` and `state_mut` can reuse this mapping
/// without duplicating the status-code table.
pub(crate) fn map_err(e: super::WalletAdminError) -> (StatusCode, Json<serde_json::Value>) {
    use super::WalletAdminError as E;
    let (status, reason) = match &e {
        // Spec §8.1: wallet_uninitialized → 400 (NOT 409). The
        // request is well-formed; the server's wallet just hasn't
        // been initialized yet.
        E::Uninitialized => (StatusCode::BAD_REQUEST, "wallet_uninitialized"),
        E::Locked => (StatusCode::BAD_REQUEST, "wallet_locked"),
        E::InvalidMnemonic => (StatusCode::BAD_REQUEST, "invalid_mnemonic"),
        E::WrongPassword => (StatusCode::UNAUTHORIZED, "wrong_password"),
        E::RestorePruningUnsupported => (
            StatusCode::BAD_REQUEST,
            "wallet_restore_pruning_unsupported",
        ),
        E::ChangeAddressUntracked => (StatusCode::BAD_REQUEST, "change_address_untracked"),
        E::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
        E::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        E::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
        // Native-only typed variants: never constructed on the Scala-compat path
        // (the compat bridge commands produce only the variants above). Handled
        // here solely to keep this match exhaustive — the native surface maps
        // them via its own `map_err`. Natural status codes are used so the
        // response is still sensible if one ever reaches this table.
        E::WalletExists => (StatusCode::BAD_REQUEST, "wallet_exists"),
        E::DerivationPathExists => (StatusCode::BAD_REQUEST, "derivation_path_exists"),
        E::AddressNotTracked => (StatusCode::NOT_FOUND, "address_not_found"),
        E::RescanUnavailable(_) => (StatusCode::CONFLICT, "rescan_unavailable"),
        E::SensitiveOpDisabled => (StatusCode::FORBIDDEN, "sensitive_op_disabled"),
        E::AcknowledgementRequired => (StatusCode::BAD_REQUEST, "acknowledgement_required"),
        E::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        E::BoxNotFound => (StatusCode::NOT_FOUND, "box_not_found"),
        E::UnsupportedScript => (StatusCode::UNPROCESSABLE_ENTITY, "unsupported_script"),
        E::MissingSecret => (StatusCode::UNPROCESSABLE_ENTITY, "missing_secret"),
        E::UnsupportedIntent => (StatusCode::UNPROCESSABLE_ENTITY, "unsupported_intent"),
        E::ReemissionObligationUnmet(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "reemission_obligation_unmet",
        ),
        E::InsufficientFunds(_) => (StatusCode::UNPROCESSABLE_ENTITY, "insufficient_funds"),
        E::ReemissionSpendNotAllowed(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "reemission_spend_not_allowed",
        ),
        E::TokenBurnNotAllowed(_) => (StatusCode::UNPROCESSABLE_ENTITY, "token_burn_not_allowed"),
        E::TxNotFound => (StatusCode::NOT_FOUND, "tx_not_found"),
    };
    // Log at the HTTP boundary so a failure is diagnosable from the node log
    // alone — the cause otherwise lived only in the response body. Server
    // faults (5xx) log at error; client-correctable conditions (4xx) at debug
    // since they are expected and would otherwise be noise. The `detail`
    // carries the full WalletAdminError Display (the variant constructors are
    // responsible for never embedding secret material).
    if status.is_server_error() {
        tracing::error!(reason, detail = %e, "wallet request failed");
    } else {
        tracing::debug!(reason, detail = %e, "wallet request rejected");
    }
    let body = serde_json::json!({ "reason": reason, "detail": e.to_string() });
    (status, Json(body))
}

pub(crate) async fn status(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<Json<types::WalletStatus>, (StatusCode, Json<serde_json::Value>)> {
    let s = admin.status().await.map_err(map_err)?;
    Ok(Json(s))
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InitBody {
    pub pass: String,
    #[serde(default)]
    pub mnemonic_pass: String,
    #[serde(default = "default_strength")]
    pub strength: u8,
}

fn default_strength() -> u8 {
    24
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InitResponse {
    pub mnemonic: String,
}

pub(crate) async fn init(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<InitBody>,
) -> Result<Json<InitResponse>, (StatusCode, Json<serde_json::Value>)> {
    let mnemonic = admin
        .init(body.pass, body.mnemonic_pass, body.strength)
        .await
        .map_err(map_err)?;
    Ok(Json(InitResponse { mnemonic }))
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RestoreBody {
    pub mnemonic: String,
    #[serde(default)]
    pub mnemonic_pass: String,
    pub pass: String,
    /// Tier-1 spec §5.1 invariant: omitted field defaults to `true`
    /// (the LEGACY-COMPATIBLE choice). `#[serde(default)]` would
    /// default to `false` — that would silently break pre-EIP-3 wallet
    /// restoration from older clients that don't send the field.
    #[serde(default = "default_use_pre_1627_true")]
    pub use_pre_1627_key_derivation: bool,
}

fn default_use_pre_1627_true() -> bool {
    true
}

pub(crate) async fn restore(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<RestoreBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    admin
        .restore(
            body.mnemonic,
            body.mnemonic_pass,
            body.pass,
            body.use_pre_1627_key_derivation,
        )
        .await
        .map_err(map_err)?;
    Ok(StatusCode::OK)
}

#[derive(serde::Deserialize)]
pub(crate) struct UnlockBody {
    pub pass: String,
}

pub(crate) async fn unlock(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<UnlockBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    admin.unlock(body.pass).await.map_err(map_err)?;
    Ok(StatusCode::OK)
}

pub(crate) async fn lock(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    admin.lock().await.map_err(map_err)?;
    Ok(StatusCode::OK)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CheckBody {
    pub mnemonic: String,
    #[serde(default)]
    pub mnemonic_pass: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CheckResponse {
    pub matched: bool,
}

pub(crate) async fn check(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<CheckBody>,
) -> Result<Json<CheckResponse>, (StatusCode, Json<serde_json::Value>)> {
    let matched = admin
        .check(body.mnemonic, body.mnemonic_pass)
        .await
        .map_err(map_err)?;
    // Scala parity: locked wallet → matched = false (NOT an error).
    // The admin.check impl returns Ok(false) in that case.
    Ok(Json(CheckResponse { matched }))
}

#[cfg(test)]
mod tests {
    use super::super::WalletAdminError as E;
    use super::*;

    // ----- error mapping -----

    #[test]
    fn bad_request_maps_to_400_with_detail() {
        // A user-correctable failure (e.g. a tx that fails structural
        // validation — dust output below min box value) must surface as a
        // 400 `bad_request`, not the opaque 500 `internal`. The detail string
        // is preserved for diagnosis.
        let (status, body) = map_err(E::BadRequest(
            "transaction rejected: output 0 value 10 below minimum 360".into(),
        ));
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.0["reason"], "bad_request");
        assert!(
            body.0["detail"].as_str().unwrap().contains("below minimum"),
            "detail must carry the structural-validation reason"
        );
    }

    #[test]
    fn internal_still_maps_to_500() {
        // Contrast guard: genuine server faults stay 500 `internal`.
        let (status, body) = map_err(E::Internal("writer task gone".into()));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.0["reason"], "internal");
    }
}
