use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub(crate) use ergo_wallet_protocol::scala::lifecycle::{
    CheckBody, CheckResponse, InitBody, InitResponse, RestoreBody, UnlockBody,
};

use super::types;
use super::WalletAdmin;

pub(crate) fn map_err(e: super::WalletAdminError) -> (StatusCode, Json<serde_json::Value>) {
    use super::WalletAdminError as E;
    let (status, reason) = match &e {
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
        E::StaleChainTip(_) => (StatusCode::CONFLICT, "stale_chain_tip"),
        E::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        E::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
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

pub(crate) async fn check(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<CheckBody>,
) -> Result<Json<CheckResponse>, (StatusCode, Json<serde_json::Value>)> {
    let matched = admin
        .check(body.mnemonic, body.mnemonic_pass)
        .await
        .map_err(map_err)?;
    Ok(Json(CheckResponse { matched }))
}
