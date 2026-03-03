use super::super::*;

/// `GET /utxo/byId/{boxId}` -- look up a confirmed UTXO by box ID.
#[utoipa::path(
    get,
    path = "/utxo/byId/{boxId}",
    tag = "utxo",
    params(
        ("boxId" = String, Path, description = "Box ID (hex)")
    ),
    responses(
        (status = 200, description = "UTXO box data", body = Object),
        (status = 501, description = "Not yet implemented"),
        (status = 503, description = "Not available in digest mode")
    )
)]
pub(crate) async fn utxo_by_id_handler(
    State(state): State<ApiState>,
    Path(_box_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_utxo_state(&state.state_type)?;
    // UTXO tree lookup not yet wired
    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": 501,
            "reason": "UTXO state read not yet implemented"
        })),
    ))
}

/// `GET /utxo/byIdBinary/{boxId}` -- look up a confirmed UTXO (binary) by box ID.
#[utoipa::path(
    get,
    path = "/utxo/byIdBinary/{boxId}",
    tag = "utxo",
    params(
        ("boxId" = String, Path, description = "Box ID (hex)")
    ),
    responses(
        (status = 200, description = "UTXO box binary data", body = Object),
        (status = 501, description = "Not yet implemented"),
        (status = 503, description = "Not available in digest mode")
    )
)]
pub(crate) async fn utxo_by_id_binary_handler(
    State(state): State<ApiState>,
    Path(_box_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_utxo_state(&state.state_type)?;
    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": 501,
            "reason": "UTXO state read not yet implemented"
        })),
    ))
}

/// `GET /utxo/withPool/byId/{boxId}` -- UTXO lookup + mempool overlay.
#[utoipa::path(
    get,
    path = "/utxo/withPool/byId/{boxId}",
    tag = "utxo",
    params(
        ("boxId" = String, Path, description = "Box ID (hex)")
    ),
    responses(
        (status = 200, description = "UTXO box data (confirmed or unconfirmed)", body = Object),
        (status = 400, description = "Invalid box ID")
    )
)]
pub(crate) async fn utxo_with_pool_by_id_handler(
    State(state): State<ApiState>,
    Path(box_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let box_id_bytes = hex::decode(&box_id_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": 400, "reason": "invalid hex"})),
        )
    })?;
    if box_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": 400, "reason": "box ID must be 32 bytes"})),
        ));
    }
    let box_id = BoxId(box_id_bytes.try_into().unwrap());

    // Check mempool for unconfirmed outputs
    let mp = state.mempool.read().unwrap();
    if let Some(output_ref) = mp.find_output_by_box_id(&box_id) {
        let candidate = output_ref.candidate;
        return Ok(Json(serde_json::json!({
            "boxId": box_id_hex,
            "value": candidate.value,
            "ergoTree": hex::encode(&candidate.ergo_tree_bytes),
            "creationHeight": candidate.creation_height,
            "assets": candidate.tokens.iter().map(|(tid, amt)| {
                serde_json::json!({"tokenId": hex::encode(tid.0), "amount": amt})
            }).collect::<Vec<_>>(),
            "confirmed": false
        })));
    }
    drop(mp);

    // For confirmed lookup, need UTXO state
    require_utxo_state(&state.state_type)?;
    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": 501,
            "reason": "UTXO state read not yet implemented"
        })),
    ))
}

/// `POST /utxo/withPool/byIds` -- batch lookup across UTXO set + mempool.
#[utoipa::path(
    post,
    path = "/utxo/withPool/byIds",
    tag = "utxo",
    request_body = Vec<String>,
    responses(
        (status = 200, description = "UTXO boxes found", body = Vec<Object>)
    )
)]
pub(crate) async fn utxo_with_pool_by_ids_handler(
    State(state): State<ApiState>,
    Json(ids): Json<Vec<String>>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<serde_json::Value>)> {
    let mut results = Vec::new();
    let mp = state.mempool.read().unwrap();
    for id_hex in &ids {
        if let Ok(bytes) = hex::decode(id_hex) {
            if bytes.len() == 32 {
                let box_id = BoxId(bytes.try_into().unwrap());
                if let Some(output_ref) = mp.find_output_by_box_id(&box_id) {
                    let c = output_ref.candidate;
                    results.push(serde_json::json!({
                        "boxId": id_hex,
                        "value": c.value,
                        "ergoTree": hex::encode(&c.ergo_tree_bytes),
                        "creationHeight": c.creation_height,
                        "assets": c.tokens.iter().map(|(tid, amt)| {
                            serde_json::json!({"tokenId": hex::encode(tid.0), "amount": amt})
                        }).collect::<Vec<_>>(),
                        "confirmed": false
                    }));
                }
            }
        }
    }
    drop(mp);
    Ok(Json(results))
}

/// `GET /utxo/withPool/byIdBinary/{boxId}` -- binary UTXO + mempool overlay.
#[utoipa::path(
    get,
    path = "/utxo/withPool/byIdBinary/{boxId}",
    tag = "utxo",
    params(
        ("boxId" = String, Path, description = "Box ID (hex)")
    ),
    responses(
        (status = 200, description = "UTXO binary data", body = Object),
        (status = 501, description = "Not yet implemented"),
        (status = 503, description = "Not available in digest mode")
    )
)]
pub(crate) async fn utxo_with_pool_by_id_binary_handler(
    State(state): State<ApiState>,
    Path(_box_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_utxo_state(&state.state_type)?;
    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": 501,
            "reason": "UTXO binary state read not yet implemented"
        })),
    ))
}

/// `GET /utxo/genesis` -- genesis boxes (consensus constants).
#[utoipa::path(
    get,
    path = "/utxo/genesis",
    tag = "utxo",
    responses(
        (status = 200, description = "Genesis boxes", body = Vec<Object>)
    )
)]
pub(crate) async fn utxo_genesis_handler(
    State(_state): State<ApiState>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<serde_json::Value>)> {
    // Genesis boxes are consensus constants -- return empty for now
    Ok(Json(Vec::new()))
}

/// `GET /utxo/getSnapshotsInfo` -- return metadata about available UTXO snapshots.
#[utoipa::path(
    get,
    path = "/utxo/getSnapshotsInfo",
    tag = "utxo",
    responses(
        (status = 200, description = "UTXO snapshot metadata", body = Vec<Object>),
        (status = 503, description = "Not available in digest mode")
    )
)]
pub(crate) async fn utxo_snapshots_info_handler(
    State(state): State<ApiState>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<ApiError>)> {
    if state.state_type != "utxo" {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "UTXO snapshots info not available in digest mode",
        ));
    }

    if let Some(ref sdb) = state.snapshots_db {
        match sdb.get_info() {
            Ok(info) => {
                let manifests: Vec<serde_json::Value> = info
                    .manifests
                    .iter()
                    .map(|(height, manifest_id)| {
                        serde_json::json!({
                            "height": height,
                            "manifestId": hex::encode(manifest_id),
                        })
                    })
                    .collect();
                Ok(Json(manifests))
            }
            Err(e) => Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to read snapshots info: {e}"),
            )),
        }
    } else {
        // No snapshots DB configured — return empty list
        Ok(Json(Vec::new()))
    }
}

/// `POST /utxo/getBoxesBinaryProof` -- return a batch Merkle proof for a set of box IDs.
///
/// Accepts a JSON array of box ID hex strings. Sends a proof request to the event
/// loop which holds the live UTXO AVL+ tree, awaits the response, and returns the
/// hex-encoded serialized AD proof bytes.
#[utoipa::path(
    post,
    path = "/utxo/getBoxesBinaryProof",
    tag = "utxo",
    request_body = Vec<String>,
    responses(
        (status = 200, description = "Hex-encoded AD proof bytes", body = Object),
        (status = 400, description = "Invalid box ID"),
        (status = 503, description = "Not available in digest mode")
    )
)]
pub(crate) async fn utxo_boxes_binary_proof_handler(
    State(state): State<ApiState>,
    Json(box_ids): Json<Vec<String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    if state.state_type != "utxo" {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "UTXO binary proofs not available in digest mode",
        ));
    }

    // Validate and parse the input box IDs.
    let mut parsed_ids = Vec::with_capacity(box_ids.len());
    for id_hex in &box_ids {
        let bytes = hex::decode(id_hex).map_err(|_| {
            api_error(
                StatusCode::BAD_REQUEST,
                &format!("Invalid hex encoding in box ID: {}", id_hex),
            )
        })?;
        if bytes.len() != 32 {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                &format!("Box ID must be 32 bytes, got {}: {}", bytes.len(), id_hex),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        parsed_ids.push(arr);
    }

    // Send a proof request to the event loop via the oneshot channel pattern.
    let sender = state.utxo_proof.as_ref().ok_or_else(|| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "UTXO proof channel not available",
        )
    })?;

    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    let request = crate::event_loop::UtxoProofRequest {
        box_ids: parsed_ids,
        response_tx: resp_tx,
    };

    sender.try_send(request).map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Event loop busy, proof request channel full",
        )
    })?;

    // Await the response with a timeout.
    match tokio::time::timeout(std::time::Duration::from_secs(10), resp_rx).await {
        Ok(Ok(Ok(proof_bytes))) => Ok(Json(serde_json::json!(hex::encode(proof_bytes)))),
        Ok(Ok(Err(e))) => Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Proof generation failed: {e}"),
        )),
        Ok(Err(_)) => Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Event loop dropped proof response",
        )),
        Err(_) => Err(api_error(
            StatusCode::GATEWAY_TIMEOUT,
            "Proof generation timed out",
        )),
    }
}
