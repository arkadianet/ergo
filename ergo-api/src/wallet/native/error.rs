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

pub use ergo_wallet_protocol::native::error::NativeWalletError;

use crate::wallet::WalletAdminError;

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
    let mapped = ergo_wallet_protocol::WalletErrorSurface::NativeV1.map(&e);
    let status = StatusCode::from_u16(mapped.status).expect("protocol wallet status is valid");
    native_err(status, mapped.reason, mapped.detail)
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
    fn stale_chain_tip_maps_to_conflict() {
        let (s, b) = mapped(E::StaleChainTip("tip moved".to_string()));
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(b.reason, "stale_chain_tip");
        assert_eq!(b.detail.as_deref(), Some("tip moved"));
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
