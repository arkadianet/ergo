//! Native `/api/v1/wallet/*` error envelope + mapping.
//!
//! One envelope `{reason, detail?}` (no numeric `error` — the HTTP status line
//! carries it), mirroring the native submit error shape. This is a SEPARATE
//! table from the Scala-compat [`crate::wallet::lifecycle::map_err`]: the two
//! surfaces map the same [`WalletAdminError`] differently (Scala maps `Locked`
//! → 400; native → 409). The native table must **not** be applied on the sign
//! path (that path never produces `Locked`).

use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::wallet::WalletAdminError;

/// The native wallet error body. `detail` is omitted (not `null`) when absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NativeWalletError {
    /// A closed snake_case reason set (e.g. `"locked"`, `"box_not_found"`).
    pub reason: String,
    /// Optional human-readable detail; never carries secret material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A typed `(status, body)` pair the native handlers return on the error arm.
pub(crate) type NativeErr = (StatusCode, Json<NativeWalletError>);

/// Build a native error response directly (for handler-level conditions that
/// are not a [`WalletAdminError`], e.g. a `box_not_found` from an `Option::None`).
pub(crate) fn native_err(status: StatusCode, reason: &str, detail: Option<String>) -> NativeErr {
    if status.is_server_error() {
        tracing::error!(reason, ?detail, "native wallet request failed");
    } else {
        tracing::debug!(reason, ?detail, "native wallet request rejected");
    }
    (
        status,
        Json(NativeWalletError {
            reason: reason.to_string(),
            detail,
        }),
    )
}

/// Map a [`WalletAdminError`] to the native `(status, {reason, detail?})`.
/// Distinct from the Scala-compat table; see the module docs.
pub(crate) fn map_err(e: WalletAdminError) -> NativeErr {
    use WalletAdminError as E;
    // `409` = state precondition; `422` = well-formed but unsatisfiable; `404`
    // = named resource absent; `403` = config-flag gate.
    let (status, reason) = match &e {
        E::Uninitialized => (StatusCode::CONFLICT, "wallet_uninitialized"),
        E::Locked => (StatusCode::CONFLICT, "wallet_locked"),
        E::InvalidMnemonic => (StatusCode::BAD_REQUEST, "invalid_mnemonic"),
        E::WrongPassword => (StatusCode::UNAUTHORIZED, "wrong_password"),
        E::RestorePruningUnsupported => (StatusCode::CONFLICT, "pruning_unsupported"),
        E::ChangeAddressUntracked => (StatusCode::UNPROCESSABLE_ENTITY, "change_address_untracked"),
        E::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
        E::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        // Legacy compat-only `Forbidden` (getPrivateKey) maps to the same
        // sensitive-disabled reason as the native `SensitiveOpDisabled`.
        E::Forbidden(_) => (StatusCode::FORBIDDEN, "sensitive_op_disabled"),
        E::WalletExists => (StatusCode::CONFLICT, "wallet_exists"),
        E::DerivationPathExists => (StatusCode::CONFLICT, "derivation_path_exists"),
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
    // Carry the variant's own message as `detail` only for the variants that
    // embed a bounded, non-secret string; never expand the others (avoids
    // leaking storage internals through a generic Display).
    let detail = match &e {
        E::BadRequest(d)
        | E::Internal(d)
        | E::Forbidden(d)
        | E::RescanUnavailable(d)
        | E::ReemissionObligationUnmet(d)
        | E::InsufficientFunds(d)
        | E::ReemissionSpendNotAllowed(d)
        | E::TokenBurnNotAllowed(d) => Some(d.clone()),
        _ => None,
    };
    native_err(status, reason, detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::WalletAdminError as E;

    // ----- error paths -----

    fn mapped(e: E) -> (StatusCode, NativeWalletError) {
        let (s, Json(b)) = map_err(e);
        (s, b)
    }

    #[test]
    fn locked_maps_to_409_not_400() {
        // The native divergence from the Scala-compat table (which maps Locked→400).
        let (s, b) = mapped(E::Locked);
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(b.reason, "wallet_locked");
    }

    #[test]
    fn uninitialized_maps_to_409() {
        let (s, b) = mapped(E::Uninitialized);
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(b.reason, "wallet_uninitialized");
    }

    #[test]
    fn missing_secret_maps_to_422() {
        let (s, b) = mapped(E::MissingSecret);
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(b.reason, "missing_secret");
    }

    #[test]
    fn box_not_found_maps_to_404() {
        let (s, b) = mapped(E::BoxNotFound);
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(b.reason, "box_not_found");
    }

    #[test]
    fn reemission_obligation_unmet_maps_to_422() {
        let (s, b) = mapped(E::ReemissionObligationUnmet("burn unmet".to_string()));
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(b.reason, "reemission_obligation_unmet");
        assert_eq!(b.detail.as_deref(), Some("burn unmet"));
    }

    #[test]
    fn internal_carries_bounded_detail() {
        let (s, b) = mapped(E::Internal("redb txn".to_string()));
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(b.reason, "internal");
        assert_eq!(b.detail.as_deref(), Some("redb txn"));
    }

    #[test]
    fn detail_omitted_when_absent() {
        // `detail` is skipped (not null) when there is none.
        let body = serde_json::to_value(NativeWalletError {
            reason: "box_not_found".to_string(),
            detail: None,
        })
        .unwrap();
        assert!(body.get("detail").is_none());
        assert_eq!(body["reason"], "box_not_found");
    }
}
