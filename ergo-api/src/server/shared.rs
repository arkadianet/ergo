//! Submission plumbing shared between the native operator handlers and
//! the Scala-compat write routes: the channel-hop submit wrapper and
//! the frozen `SubmitError` -> HTTP status mapping.

use std::sync::Arc;

use axum::http::StatusCode;

use crate::traits::NodeSubmit;
use crate::types::{ApiSubmitError, SubmitError, SubmitMode};

/// Channel-hop wrapper that lifts a `SubmitError` into `(StatusCode,
/// ApiSubmitError)`. Shared between operator routes (JSON envelope on
/// success) and Scala-compat routes (plain-string body on success).
pub(crate) async fn submit_via_node(
    submit: Arc<dyn NodeSubmit>,
    bytes: Vec<u8>,
    mode: SubmitMode,
) -> Result<String, (StatusCode, ApiSubmitError)> {
    submit
        .submit_transaction(bytes, mode)
        .await
        .map_err(map_submit_error)
}

/// Status mapping for `SubmitError`:
/// - `overloaded` / `shutting_down` / `route_disabled` → 503
///   (channel-side or feature-disabled failures; client may retry
///   or check operator config)
/// - `timeout` → 504 (per-submission deadline elapsed)
/// - `internal_error` → 500 (local DB / storage failure during
///   admission — caller did nothing wrong; node-side issue)
/// - everything else from the admission pipeline → 400 (bad
///   submitter input: `deserialize`, `non_canonical`, `invalid_pow`,
///   `header_rejected`, etc.)
pub(crate) fn map_submit_error(err: SubmitError) -> (StatusCode, ApiSubmitError) {
    let SubmitError { reason, detail } = err;
    let status = match reason.as_str() {
        "overloaded" | "shutting_down" | "route_disabled" => StatusCode::SERVICE_UNAVAILABLE,
        "timeout" => StatusCode::GATEWAY_TIMEOUT,
        "internal_error" => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        ApiSubmitError {
            error: status.as_u16(),
            reason,
            detail,
        },
    )
}
