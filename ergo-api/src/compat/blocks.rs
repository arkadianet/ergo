//! Scala-compat block submission handler (§12 sendMinedBlock).
//!
//! Mounts at `POST /blocks` — the Scala equivalent of `BlocksApiRoute`'s
//! `sendMinedBlock` endpoint. Accepts a full block as a JSON body in
//! the Scala `ErgoFullBlock` wire shape (the same shape `GET /blocks/:id`
//! reads back, modulo the `Option<AdProofs>` for digest-mode chains).
//!
//! On success returns the header_id as a plain JSON string. Status
//! mirrors Scala's `ApiResponse.OK` (200), but Scala emits an empty
//! 200 body while we emit a JSON header_id string — a Rust extension
//! over Scala parity. Status-and-reason parity holds; body-shape
//! parity is tracked separately. On failure returns `ApiSubmitError`
//! (`{error, reason, detail}`) — same envelope the `/transactions`
//! routes use, with a wider reason vocabulary documented at
//! `NodeSubmit::submit_full_block`.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::compat::types::ScalaFullBlock;
use crate::server::map_submit_error;
use crate::traits::NodeSubmit;
use crate::types::ApiSubmitError;

/// `POST /blocks` — accepts an externally-mined block as a Scala
/// `ErgoFullBlock` JSON DTO, runs PoW verify locally (in the bridge
/// task — invalid-PoW submissions never wake the action loop), and
/// dispatches the four section bodies into the apply pipeline.
///
/// Idempotent: re-submitting an already-applied block returns 200
/// with the same header_id.
///
/// Status mapping (delegated to `map_submit_error` for the common
/// vocabulary, plus the block-specific reasons documented at
/// `NodeSubmit::submit_full_block`):
/// - `deserialize` / `non_canonical` / `invalid_pow` /
///   `header_rejected` → 400
/// - `overloaded` / `shutting_down` / `route_disabled` → 503
/// - `timeout` → 504
/// - `internal_error` → 500
pub async fn submit_handler(State(submit): State<Arc<dyn NodeSubmit>>, body: Bytes) -> Response {
    let block: ScalaFullBlock = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiSubmitError {
                    error: StatusCode::BAD_REQUEST.as_u16(),
                    reason: "deserialize".to_string(),
                    detail: Some(format!("invalid JSON body: {e}")),
                }),
            )
                .into_response();
        }
    };

    match submit.submit_full_block(block).await {
        // Bare JSON string of the header_id. Scala's `ApiResponse.OK`
        // returns an empty 200 body; we emit a JSON string here as a
        // Rust extension. Status parity holds; body-shape parity
        // tracked separately.
        Ok(header_id) => (StatusCode::OK, Json(header_id)).into_response(),
        Err(err) => {
            let (status, body) = map_submit_error(err);
            (status, Json(body)).into_response()
        }
    }
}
