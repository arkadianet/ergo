use super::super::*;

/// `POST /node/shutdown` — trigger graceful shutdown (localhost only).
#[utoipa::path(
    post,
    path = "/node/shutdown",
    tag = "node",
    responses(
        (status = 200, description = "Shutdown initiated", body = Object)
    )
)]
pub(crate) async fn node_shutdown_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    if let Some(ref tx) = state.shutdown_tx {
        let _ = tx.send(true);
    }
    Ok(Json(serde_json::json!({ "status": "shutting_down" })))
}
