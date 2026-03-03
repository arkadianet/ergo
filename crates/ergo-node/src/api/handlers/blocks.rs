use super::super::*;

#[utoipa::path(
    get,
    path = "/blocks/{header_id}",
    tag = "blocks",
    params(
        ("header_id" = String, Path, description = "Block header ID (hex)")
    ),
    responses(
        (status = 200, description = "Full block data", body = BlockResponse),
        (status = 404, description = "Block not found")
    )
)]
pub(crate) async fn get_block_handler(
    State(state): State<ApiState>,
    Path(header_id_hex): Path<String>,
) -> Result<Json<BlockResponse>, (StatusCode, Json<ApiError>)> {
    let id = parse_modifier_id(&header_id_hex)?;

    let header = state
        .history
        .load_header(&id)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load header"))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Block not found"))?;

    let resp = build_block_response(&state, &header, &header_id_hex);

    Ok(Json(resp))
}

#[utoipa::path(
    get,
    path = "/blocks/at/{height}",
    tag = "blocks",
    params(
        ("height" = u32, Path, description = "Block height")
    ),
    responses(
        (status = 200, description = "Header IDs at height", body = Vec<String>)
    )
)]
pub(crate) async fn get_blocks_at_height_handler(
    State(state): State<ApiState>,
    Path(height): Path<u32>,
) -> Json<Vec<String>> {
    let ids = state
        .history
        .header_ids_at_height(height)
        .unwrap_or_default();
    Json(ids.iter().map(|id| hex::encode(id.0)).collect())
}

/// `GET /blocks?offset=0&limit=50` — paginated header IDs, newest first.
#[utoipa::path(
    get,
    path = "/blocks",
    tag = "blocks",
    params(
        ("offset" = Option<u32>, Query, description = "Offset"),
        ("limit" = Option<u32>, Query, description = "Limit (max 100)")
    ),
    responses(
        (status = 200, description = "Paginated header IDs (newest first)", body = Vec<String>)
    )
)]
pub(crate) async fn get_paginated_blocks_handler(
    State(state): State<ApiState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<ApiError>)> {
    let best_height = state.history.best_header_height().map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to read best header height",
        )
    })?;

    if best_height == 0 {
        // No headers stored yet — check if there really is a best header.
        if state
            .history
            .best_header_id()
            .map_err(|_| {
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to read best header ID",
                )
            })?
            .is_none()
        {
            return Ok(Json(Vec::new()));
        }
    }

    let limit = params.limit.min(100) as usize;
    let offset = params.offset as usize;

    // Jump directly to start_height to avoid O(chain_height) scan.
    let start_height = (best_height as i64) - (offset as i64);
    if start_height < 0 {
        return Ok(Json(Vec::new()));
    }

    let mut result: Vec<String> = Vec::new();
    let mut height = start_height;
    while height >= 0 && result.len() < limit {
        let ids = state
            .history
            .header_ids_at_height(height as u32)
            .map_err(|_| {
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to read header IDs at height",
                )
            })?;
        for id in &ids {
            result.push(hex::encode(id.0));
        }
        height -= 1;
    }

    Ok(Json(result))
}

/// `GET /blocks/lastHeaders/{n}` — last N full headers, newest first.
#[utoipa::path(
    get,
    path = "/blocks/lastHeaders/{n}",
    tag = "blocks",
    params(
        ("n" = usize, Path, description = "Number of headers (max 2048)")
    ),
    responses(
        (status = 200, description = "Last N headers", body = Vec<HeaderResponse>)
    )
)]
pub(crate) async fn get_last_headers_handler(
    State(state): State<ApiState>,
    Path(n): Path<usize>,
) -> Result<Json<Vec<HeaderResponse>>, (StatusCode, Json<ApiError>)> {
    let n = n.min(2048);
    let headers = state
        .history
        .last_n_headers(n)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load headers"))?;

    let responses: Vec<HeaderResponse> = headers.iter().map(header_to_response).collect();
    Ok(Json(responses))
}

/// `GET /blocks/chainSlice?fromHeight=0&toHeight=100` — headers between heights.
#[utoipa::path(
    get,
    path = "/blocks/chainSlice",
    tag = "blocks",
    params(
        ("fromHeight" = Option<u32>, Query, description = "Start height"),
        ("toHeight" = Option<u32>, Query, description = "End height")
    ),
    responses(
        (status = 200, description = "Headers in height range", body = Vec<HeaderResponse>),
        (status = 400, description = "Invalid range")
    )
)]
pub(crate) async fn get_chain_slice_handler(
    State(state): State<ApiState>,
    Query(params): Query<ChainSliceParams>,
) -> Result<Json<Vec<HeaderResponse>>, (StatusCode, Json<ApiError>)> {
    let from = params.from_height;
    let to = params.to_height;

    if to < from {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "toHeight must be >= fromHeight",
        ));
    }

    // Cap the range to prevent excessive queries.
    let capped_to = to.min(from.saturating_add(2048));

    let mut responses = Vec::new();
    for height in from..=capped_to {
        let ids = state.history.header_ids_at_height(height).map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read header IDs at height",
            )
        })?;
        for id in &ids {
            let header = state.history.load_header(id).map_err(|_| {
                api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load header")
            })?;
            if let Some(header) = header {
                responses.push(header_to_response_with_id(&header, &hex::encode(id.0)));
            }
        }
    }
    Ok(Json(responses))
}

/// `GET /blocks/{id}/header` — header only.
#[utoipa::path(
    get,
    path = "/blocks/{header_id}/header",
    tag = "blocks",
    params(
        ("header_id" = String, Path, description = "Block header ID (hex)")
    ),
    responses(
        (status = 200, description = "Block header", body = HeaderResponse),
        (status = 404, description = "Header not found")
    )
)]
pub(crate) async fn get_header_only_handler(
    State(state): State<ApiState>,
    Path(header_id_hex): Path<String>,
) -> Result<Json<HeaderResponse>, (StatusCode, Json<ApiError>)> {
    let id = parse_modifier_id(&header_id_hex)?;
    let header = state
        .history
        .load_header(&id)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load header"))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Header not found"))?;

    Ok(Json(header_to_response_with_id(&header, &header_id_hex)))
}

/// `GET /blocks/{id}/transactions` — block transactions as hex.
#[utoipa::path(
    get,
    path = "/blocks/{header_id}/transactions",
    tag = "blocks",
    params(
        ("header_id" = String, Path, description = "Block header ID (hex)")
    ),
    responses(
        (status = 200, description = "Block transactions (hex-encoded)", body = String),
        (status = 404, description = "Block transactions not found")
    )
)]
pub(crate) async fn get_block_transactions_handler(
    State(state): State<ApiState>,
    Path(header_id_hex): Path<String>,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    let id = parse_modifier_id(&header_id_hex)?;
    let data = state
        .history
        .get_modifier(102, &id)
        .map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to load block transactions",
            )
        })?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Block transactions not found"))?;

    Ok(Json(hex::encode(data)))
}

/// `POST /blocks/headerIds` — batch full blocks by header IDs.
#[utoipa::path(
    post,
    path = "/blocks/headerIds",
    tag = "blocks",
    request_body = Vec<String>,
    responses(
        (status = 200, description = "Full blocks for given header IDs", body = Vec<BlockResponse>),
        (status = 400, description = "Too many IDs")
    )
)]
pub(crate) async fn post_header_ids_handler(
    State(state): State<ApiState>,
    Json(ids): Json<Vec<String>>,
) -> Result<Json<Vec<BlockResponse>>, (StatusCode, Json<ApiError>)> {
    if ids.len() > 100 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Too many IDs; maximum is 100",
        ));
    }
    let mut blocks = Vec::new();
    for id_hex in &ids {
        let id = parse_modifier_id(id_hex)?;
        if let Ok(Some(header)) = state.history.load_header(&id) {
            blocks.push(build_block_response(&state, &header, id_hex));
        }
    }
    Ok(Json(blocks))
}

/// `GET /blocks/modifier/{id}` — any block section by ID.
#[utoipa::path(
    get,
    path = "/blocks/modifier/{modifier_id}",
    tag = "blocks",
    params(
        ("modifier_id" = String, Path, description = "Modifier ID (hex)")
    ),
    responses(
        (status = 200, description = "Modifier data", body = ModifierResponse),
        (status = 404, description = "Modifier not found")
    )
)]
pub(crate) async fn get_modifier_handler(
    State(state): State<ApiState>,
    Path(modifier_id_hex): Path<String>,
) -> Result<Json<ModifierResponse>, (StatusCode, Json<ApiError>)> {
    let id = parse_modifier_id(&modifier_id_hex)?;

    // Try each known modifier type: header=101, block_transactions=102,
    // ad_proofs=104, extension=108.
    for type_id in [101u8, 102, 104, 108] {
        if let Ok(Some(data)) = state.history.get_modifier(type_id, &id) {
            return Ok(Json(ModifierResponse {
                type_id,
                bytes: hex::encode(data),
            }));
        }
    }

    Err(api_error(StatusCode::NOT_FOUND, "Modifier not found"))
}

/// `POST /blocks` -- submit a full block for validation and inclusion.
///
/// Accepts a JSON body representing a full block. The body must contain a `header`
/// field with hex-encoded serialized header bytes, plus optional `blockTransactions`,
/// `extension`, and `adProofs` fields (also hex-encoded bytes). Validates the header's
/// proof-of-work, then fire-and-forget sends each section to the event loop for full
/// validation and application (matching Scala's pattern).
#[utoipa::path(
    post,
    path = "/blocks",
    tag = "blocks",
    request_body = Object,
    responses(
        (status = 200, description = "Block accepted", body = Object),
        (status = 400, description = "Invalid block")
    )
)]
pub(crate) async fn post_block_handler(
    State(state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    // Extract the header bytes (hex-encoded serialized header).
    let header_hex = body.get("header").and_then(|v| v.as_str()).ok_or_else(|| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Missing 'header' field (hex string)",
        )
    })?;

    let header_bytes = hex::decode(header_hex)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding in header"))?;

    // Parse the header to validate PoW.
    let header = ergo_wire::header_ser::parse_header(&header_bytes).map_err(|e| {
        api_error(
            StatusCode::BAD_REQUEST,
            &format!("Failed to parse header: {e}"),
        )
    })?;

    // Validate proof-of-work (lightweight pre-check, matching Scala's `powScheme.validate`).
    ergo_consensus::autolykos::validate_pow(&header)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &format!("Invalid PoW: {e}")))?;

    // Compute the header ID from the serialized bytes.
    let header_id = compute_header_id(&header_bytes);
    let header_id_hex = hex::encode(header_id.0);

    // Build the list of modifiers to send to the event loop.
    // type_id 101 = Header, 102 = BlockTransactions, 108 = Extension, 104 = ADProofs
    let mut modifiers = Vec::new();
    modifiers.push((101u8, header_id, header_bytes));

    // Optional body sections: blockTransactions, extension, adProofs
    if let Some(bt_hex) = body.get("blockTransactions").and_then(|v| v.as_str()) {
        let bt_bytes = hex::decode(bt_hex)
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex in blockTransactions"))?;
        modifiers.push((102u8, header_id, bt_bytes));
    }

    if let Some(ext_hex) = body.get("extension").and_then(|v| v.as_str()) {
        let ext_bytes = hex::decode(ext_hex)
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex in extension"))?;
        modifiers.push((108u8, header_id, ext_bytes));
    }

    if let Some(ap_hex) = body.get("adProofs").and_then(|v| v.as_str()) {
        let ap_bytes = hex::decode(ap_hex)
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex in adProofs"))?;
        modifiers.push((104u8, header_id, ap_bytes));
    }

    // Fire-and-forget: send to the event loop.
    let sender = state.block_submit.as_ref().ok_or_else(|| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Block submit channel not available",
        )
    })?;

    let submission = crate::event_loop::BlockSubmission { modifiers };
    sender.try_send(submission).map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Event loop busy, block submit channel full",
        )
    })?;

    // Return OK immediately with the header ID (Scala pattern: fire-and-forget).
    Ok(Json(serde_json::json!({ "headerId": header_id_hex })))
}

/// `GET /blocks/{header_id}/proofFor/{tx_id}` — Merkle inclusion proof for a tx in a block.
#[utoipa::path(
    get,
    path = "/blocks/{header_id}/proofFor/{tx_id}",
    tag = "blocks",
    params(
        ("header_id" = String, Path, description = "Block header ID (hex)"),
        ("tx_id" = String, Path, description = "Transaction ID (hex)")
    ),
    responses(
        (status = 200, description = "Merkle inclusion proof", body = MerkleProofResponse),
        (status = 404, description = "Transaction not found in block")
    )
)]
pub(crate) async fn merkle_proof_handler(
    State(state): State<ApiState>,
    Path((header_id_hex, tx_id_hex)): Path<(String, String)>,
) -> Result<Json<MerkleProofResponse>, (StatusCode, Json<ApiError>)> {
    let header_id = parse_modifier_id(&header_id_hex)?;

    let target_tx_id = hex::decode(&tx_id_hex)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding for tx ID"))?;
    if target_tx_id.len() != 32 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Transaction ID must be 32 bytes (64 hex chars)",
        ));
    }

    let block_txs = state
        .history
        .load_block_transactions(&header_id)
        .map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to load block transactions",
            )
        })?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Block transactions not found"))?;

    // Compute tx IDs: blake2b256 of each serialized transaction.
    use blake2::digest::{Update, VariableOutput};
    let tx_ids: Vec<[u8; 32]> = block_txs
        .tx_bytes
        .iter()
        .map(|tx_bytes| {
            let mut hasher = blake2::Blake2bVar::new(32).expect("valid");
            hasher.update(tx_bytes);
            let mut hash = [0u8; 32];
            hasher.finalize_variable(&mut hash).expect("valid");
            hash
        })
        .collect();

    let leaf_index = tx_ids
        .iter()
        .position(|id| id[..] == target_tx_id[..])
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Transaction not found in block"))?;

    let tx_id_slices: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();
    let proof_steps =
        ergo_consensus::merkle::merkle_proof(&tx_id_slices, leaf_index).ok_or_else(|| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to compute Merkle proof",
            )
        })?;

    // Format levels: each is hex(side_byte ++ 32-byte sibling hash).
    let levels: Vec<String> = proof_steps
        .iter()
        .map(|step| {
            let side_byte = match step.side {
                ergo_consensus::merkle::MerkleSide::Left => 0x00u8,
                ergo_consensus::merkle::MerkleSide::Right => 0x01u8,
            };
            let mut entry = Vec::with_capacity(33);
            entry.push(side_byte);
            entry.extend_from_slice(&step.hash);
            hex::encode(entry)
        })
        .collect();

    Ok(Json(MerkleProofResponse {
        leaf: tx_id_hex,
        levels,
    }))
}
