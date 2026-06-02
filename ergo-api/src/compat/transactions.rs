//! Scala-compat submission handlers.
//!
//! Mounts at the bare paths Scala's `TransactionsApiRoute.scala`
//! exposes: `POST /transactions/bytes` + `/transactions/checkBytes`
//! (hex bodies) and `POST /transactions` + `/transactions/check`
//! (JSON bodies). Bodies are bound to [`crate::traits::NodeSubmit`]
//! state; the routes are only registered when both `compat` and
//! `submit` were passed to [`crate::serve`].

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::compat::types::ScalaTransactionInput;
use crate::server::{map_submit_error, submit_via_node};
use crate::traits::NodeSubmit;
use crate::types::{ApiSubmitError, SubmitMode};

/// `POST /transactions/bytes` — accepts the transaction wire bytes
/// either as raw `application/octet-stream` or as a JSON-quoted hex
/// string (`"0a1b…"`), matching Scala's `fromJsonOrPlain`. On success
/// returns the tx_id as a plain JSON string (no envelope), matching
/// Scala's `ApiResponse(tx.id)` Circe emission. On failure returns
/// `ApiSubmitError` (`{error,reason,detail}`) matching Scala's
/// `ApiError` shape.
pub async fn submit_bytes_handler(
    State(submit): State<Arc<dyn NodeSubmit>>,
    body: Bytes,
) -> Response {
    bytes_handler_inner(submit, body, SubmitMode::Broadcast).await
}

/// `POST /transactions/checkBytes` — same body shape as
/// `/transactions/bytes` but runs the admission pipeline in
/// `CheckOnly` mode: no commit, no `BroadcastInv`. Anti-DoS
/// bookkeeping still mutates per mempool invariant #7.
pub async fn check_bytes_handler(
    State(submit): State<Arc<dyn NodeSubmit>>,
    body: Bytes,
) -> Response {
    bytes_handler_inner(submit, body, SubmitMode::CheckOnly).await
}

async fn bytes_handler_inner(
    submit: Arc<dyn NodeSubmit>,
    body: Bytes,
    mode: SubmitMode,
) -> Response {
    let bytes = match decode_bytes_body(&body) {
        Ok(b) => b,
        Err(reason) => {
            // Hex-decode failures are surfaced as `deserialize` — the
            // same bucket the admission pipeline uses for malformed
            // wire bytes.
            return (
                StatusCode::BAD_REQUEST,
                Json(crate::types::ApiSubmitError {
                    error: StatusCode::BAD_REQUEST.as_u16(),
                    reason: "deserialize".to_string(),
                    detail: Some(reason),
                }),
            )
                .into_response();
        }
    };

    match submit_via_node(submit, bytes, mode).await {
        // Scala returns the tx_id as a plain JSON string (just the
        // quoted hex), no envelope. Json("…") serializes a String as
        // `"…"` which is exactly what Scala's `ApiResponse(tx.id)`
        // emits via Circe.
        Ok(tx_id) => (StatusCode::OK, Json(tx_id)).into_response(),
        Err((status, err)) => (status, Json(err)).into_response(),
    }
}

/// Scala accepts either raw hex (no quotes) or a JSON-quoted string,
/// via `fromJsonOrPlain`. We mirror that: if the body parses as a
/// JSON string, use its contents; otherwise treat the whole body as
/// the hex string verbatim. Either way the result must hex-decode.
fn decode_bytes_body(body: &[u8]) -> Result<Vec<u8>, String> {
    let trimmed = trim_ascii_whitespace(body);
    let hex_str = if trimmed.first() == Some(&b'"') && trimmed.last() == Some(&b'"') {
        // JSON-quoted string. Use serde_json so escape sequences
        // (\\, \") are honored — matches Scala's Json.parse path.
        match serde_json::from_slice::<String>(trimmed) {
            Ok(s) => s,
            Err(e) => return Err(format!("invalid JSON-quoted body: {e}")),
        }
    } else {
        // Plain hex. Reject non-UTF8 — Scala does the same via String.
        match std::str::from_utf8(trimmed) {
            Ok(s) => s.to_string(),
            Err(e) => return Err(format!("body is not valid UTF-8 hex: {e}")),
        }
    };
    hex::decode(hex_str.trim()).map_err(|e| format!("hex decode failed: {e}"))
}

fn trim_ascii_whitespace(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map(|p| p + 1)
        .unwrap_or(start);
    &b[start..end]
}

/// `POST /transactions` — accepts the transaction as a JSON body in
/// the Scala wire shape (see `ScalaTransactionInput`). On success
/// returns the tx_id as a plain JSON string (no envelope), identical
/// to the bytes path. The node bridge decodes the JSON DTO into
/// canonical wire bytes via `ergo-rest-json::decode_scala_transaction`
/// and runs the same admission pipeline as `/transactions/bytes`.
pub async fn submit_handler(State(submit): State<Arc<dyn NodeSubmit>>, body: Bytes) -> Response {
    json_handler_inner(submit, body, SubmitMode::Broadcast).await
}

/// `POST /transactions/check` — JSON-body sibling of
/// `/transactions/checkBytes`. Same body shape as `/transactions`,
/// admission runs in `CheckOnly` mode (no commit, no `BroadcastInv`).
pub async fn check_handler(State(submit): State<Arc<dyn NodeSubmit>>, body: Bytes) -> Response {
    json_handler_inner(submit, body, SubmitMode::CheckOnly).await
}

async fn json_handler_inner(
    submit: Arc<dyn NodeSubmit>,
    body: Bytes,
    mode: SubmitMode,
) -> Response {
    let input: ScalaTransactionInput = match serde_json::from_slice(&body) {
        Ok(i) => i,
        Err(e) => {
            // JSON parse / shape failures bucket as `deserialize` —
            // the same bucket the bytes path uses for malformed wire
            // bytes. The bridge also emits `deserialize` for byte-shape
            // decode failures it discovers downstream.
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

    match submit.submit_transaction_json(input, mode).await {
        // Mirrors the bytes path: bare JSON string, no envelope.
        // Matches Scala's `ApiResponse(tx.id)` exactly.
        Ok(tx_id) => (StatusCode::OK, Json(tx_id)).into_response(),
        Err(err) => {
            let (status, body) = map_submit_error(err);
            (status, Json(body)).into_response()
        }
    }
}
