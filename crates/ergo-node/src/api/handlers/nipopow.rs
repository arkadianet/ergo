use super::super::*;

/// `GET /nipopow/popowHeaderById/{id}` — PoPow header by header ID.
#[utoipa::path(
    get,
    path = "/nipopow/popowHeaderById/{id}",
    tag = "nipopow",
    params(
        ("id" = String, Path, description = "Header ID (hex)")
    ),
    responses(
        (status = 200, description = "PoPow header with interlinks", body = PoPowHeaderResponse),
        (status = 404, description = "Header not found")
    )
)]
pub(crate) async fn popow_header_by_id_handler(
    State(state): State<ApiState>,
    Path(header_id_hex): Path<String>,
) -> Result<Json<PoPowHeaderResponse>, (StatusCode, Json<ApiError>)> {
    let id = parse_modifier_id(&header_id_hex)?;
    let header = state
        .history
        .load_header(&id)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load header"))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Header not found"))?;
    let ext = state
        .history
        .load_extension(&id)
        .map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to load extension",
            )
        })?
        .unwrap_or(ergo_types::extension::Extension {
            header_id: id,
            fields: Vec::new(),
        });
    let popow = ergo_network::nipopow::popow_header_for(header, &ext);
    Ok(Json(popow_header_to_response(&popow)))
}

/// `GET /nipopow/popowHeaderByHeight/{h}` — PoPow header by block height.
#[utoipa::path(
    get,
    path = "/nipopow/popowHeaderByHeight/{h}",
    tag = "nipopow",
    params(
        ("h" = u32, Path, description = "Block height")
    ),
    responses(
        (status = 200, description = "PoPow header with interlinks", body = PoPowHeaderResponse),
        (status = 404, description = "Header not found at height")
    )
)]
pub(crate) async fn popow_header_by_height_handler(
    State(state): State<ApiState>,
    Path(height): Path<u32>,
) -> Result<Json<PoPowHeaderResponse>, (StatusCode, Json<ApiError>)> {
    let ids = state.history.header_ids_at_height(height).map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to read header IDs at height",
        )
    })?;
    let id = ids
        .first()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "No header found at height"))?;
    let header = state
        .history
        .load_header(id)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load header"))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Header not found"))?;
    let ext = state
        .history
        .load_extension(id)
        .map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to load extension",
            )
        })?
        .unwrap_or(ergo_types::extension::Extension {
            header_id: *id,
            fields: Vec::new(),
        });
    let popow = ergo_network::nipopow::popow_header_for(header, &ext);
    Ok(Json(popow_header_to_response(&popow)))
}

/// `GET /nipopow/proof/{m}/{k}` — NiPoPoW proof from the tip of the chain.
#[utoipa::path(
    get,
    path = "/nipopow/proof/{m}/{k}",
    tag = "nipopow",
    params(
        ("m" = u32, Path, description = "Security parameter m"),
        ("k" = u32, Path, description = "Suffix length k")
    ),
    responses(
        (status = 200, description = "NiPoPoW proof from chain tip", body = NipopowProofResponse),
        (status = 400, description = "Invalid parameters"),
        (status = 404, description = "Failed to generate proof")
    )
)]
pub(crate) async fn nipopow_proof_handler(
    State(state): State<ApiState>,
    Path((m, k)): Path<(u32, u32)>,
) -> Result<Json<NipopowProofResponse>, (StatusCode, Json<ApiError>)> {
    if m == 0 || k == 0 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Parameters m and k must be > 0",
        ));
    }
    let proof = ergo_network::nipopow::prove(&state.history, m, k, None)
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "Failed to generate NiPoPoW proof"))?;
    Ok(Json(proof_to_response(&proof)))
}

/// `GET /nipopow/proof/{m}/{k}/{id}` — NiPoPoW proof anchored at a specific header.
#[utoipa::path(
    get,
    path = "/nipopow/proof/{m}/{k}/{id}",
    tag = "nipopow",
    params(
        ("m" = u32, Path, description = "Security parameter m"),
        ("k" = u32, Path, description = "Suffix length k"),
        ("id" = String, Path, description = "Anchor header ID (hex)")
    ),
    responses(
        (status = 200, description = "NiPoPoW proof at specific header", body = NipopowProofResponse),
        (status = 400, description = "Invalid parameters"),
        (status = 404, description = "Failed to generate proof")
    )
)]
pub(crate) async fn nipopow_proof_at_handler(
    State(state): State<ApiState>,
    Path((m, k, header_id_hex)): Path<(u32, u32, String)>,
) -> Result<Json<NipopowProofResponse>, (StatusCode, Json<ApiError>)> {
    if m == 0 || k == 0 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Parameters m and k must be > 0",
        ));
    }
    let id = parse_modifier_id(&header_id_hex)?;
    let proof = ergo_network::nipopow::prove(&state.history, m, k, Some(id))
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "Failed to generate NiPoPoW proof"))?;
    Ok(Json(proof_to_response(&proof)))
}
