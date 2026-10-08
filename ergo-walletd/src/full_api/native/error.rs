//! Native `/api/v1/wallet/*` error envelope + mapping.
//!
//! One envelope `{reason, detail?}` (no numeric `error` — the HTTP status line
//! carries it), mirroring the native submit error shape. This is a SEPARATE
//! table from the Scala-compat `crate::wallet::lifecycle::map_err`: the two
//! surfaces map the same [`WalletAdminError`] differently (Scala maps `Locked`
//! → 400; native → 409). The native table must **not** be applied on the sign
//! path (that path never produces `Locked`).

use axum::http::StatusCode;
use axum::Json;

pub use ergo_wallet_protocol::native::error::NativeWalletError;

use ergo_wallet_protocol::WalletAdminError;

/// A typed `(status, body)` pair the native handlers return on the error arm.
pub(crate) type NativeErr = (StatusCode, Json<NativeWalletError>);

/// Build a native error response directly (for handler-level conditions that
/// are not a [`WalletAdminError`], e.g. a `box_not_found` from an `Option::None`).
pub(crate) fn native_err(status: StatusCode, reason: &str, detail: Option<String>) -> NativeErr {
    let detail = if status.is_server_error() {
        None
    } else {
        detail
    };
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
