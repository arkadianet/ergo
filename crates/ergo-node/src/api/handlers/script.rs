use super::super::*;

/// `GET /script/addressToTree/{addr}` — convert address to hex ErgoTree.
#[utoipa::path(
    get,
    path = "/script/addressToTree/{addr}",
    tag = "script",
    params(
        ("addr" = String, Path, description = "Ergo address")
    ),
    responses(
        (status = 200, description = "ErgoTree hex", body = Object),
        (status = 400, description = "Invalid address")
    )
)]
pub(crate) async fn script_address_to_tree_handler(
    State(state): State<ApiState>,
    Path(addr): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tree_bytes = address_to_ergo_tree(&addr, &state.network)?;
    Ok(Json(serde_json::json!({
        "tree": hex::encode(&tree_bytes)
    })))
}

/// `GET /script/addressToBytes/{addr}` — convert address to hex sigma ByteArrayConstant.
#[utoipa::path(
    get,
    path = "/script/addressToBytes/{addr}",
    tag = "script",
    params(
        ("addr" = String, Path, description = "Ergo address")
    ),
    responses(
        (status = 200, description = "Sigma ByteArrayConstant hex", body = Object),
        (status = 400, description = "Invalid address")
    )
)]
pub(crate) async fn script_address_to_bytes_handler(
    State(state): State<ApiState>,
    Path(addr): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tree_bytes = address_to_ergo_tree(&addr, &state.network)?;
    let constant_bytes = encode_byte_array_constant(&tree_bytes);
    Ok(Json(serde_json::json!({
        "bytes": hex::encode(&constant_bytes)
    })))
}

/// `POST /script/p2sAddress` — compile ErgoScript source to a P2S address.
#[utoipa::path(
    post,
    path = "/script/p2sAddress",
    tag = "script",
    request_body = ScriptCompileRequest,
    responses(
        (status = 200, description = "P2S address", body = ScriptCompileResponse),
        (status = 400, description = "Compilation error")
    )
)]
pub(crate) async fn script_p2s_address_handler(
    State(state): State<ApiState>,
    Json(req): Json<ScriptCompileRequest>,
) -> Result<Json<ScriptCompileResponse>, (StatusCode, String)> {
    let tree_bytes = compile_script_to_tree_bytes(&req.source)?;
    let network_prefix = network_prefix_from_str(&state.network);
    let addr = address::encode_address(network_prefix, address::AddressType::P2S, &tree_bytes);
    Ok(Json(ScriptCompileResponse { address: addr }))
}

/// `POST /script/p2shAddress` — compile ErgoScript source to a P2SH address.
#[utoipa::path(
    post,
    path = "/script/p2shAddress",
    tag = "script",
    request_body = ScriptCompileRequest,
    responses(
        (status = 200, description = "P2SH address", body = ScriptCompileResponse),
        (status = 400, description = "Compilation error")
    )
)]
pub(crate) async fn script_p2sh_address_handler(
    State(state): State<ApiState>,
    Json(req): Json<ScriptCompileRequest>,
) -> Result<Json<ScriptCompileResponse>, (StatusCode, String)> {
    let tree_bytes = compile_script_to_tree_bytes(&req.source)?;
    let hash = blake2b256(&tree_bytes);
    let network_prefix = network_prefix_from_str(&state.network);
    let addr = address::encode_address(network_prefix, address::AddressType::P2SH, &hash[..24]);
    Ok(Json(ScriptCompileResponse { address: addr }))
}

/// `POST /script/compile` — compile ErgoScript source to ErgoTree hex and P2S address.
#[utoipa::path(
    post,
    path = "/script/compile",
    tag = "script",
    request_body = ScriptCompileRequest,
    responses(
        (status = 200, description = "Compiled ErgoTree and address", body = ScriptFullCompileResponse),
        (status = 400, description = "Compilation error")
    )
)]
pub(crate) async fn script_compile_handler(
    State(state): State<ApiState>,
    Json(req): Json<ScriptCompileRequest>,
) -> Result<Json<ScriptFullCompileResponse>, (StatusCode, String)> {
    let tree_bytes = compile_script_to_tree_bytes(&req.source)?;
    let network_prefix = network_prefix_from_str(&state.network);
    let addr = address::encode_address(network_prefix, address::AddressType::P2S, &tree_bytes);
    Ok(Json(ScriptFullCompileResponse {
        ergo_tree: hex::encode(&tree_bytes),
        address: addr,
    }))
}

/// `POST /script/executeWithContext` -- compile and evaluate an ErgoScript with a given context.
///
/// Accepts a JSON body with a `script` field (ErgoScript source code).
/// Compiles the script and returns the resulting ErgoTree hex.
/// Full execution with a transaction context is not yet supported.
#[utoipa::path(
    post,
    path = "/script/executeWithContext",
    tag = "script",
    request_body = Object,
    responses(
        (status = 200, description = "Script execution result", body = Object),
        (status = 400, description = "Invalid script")
    )
)]
pub(crate) async fn script_execute_with_context_handler(
    State(_state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let script = body
        .get("script")
        .and_then(|s| s.as_str())
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "Missing 'script' field"))?;

    // Compile the script to an ErgoTree
    let tree_bytes =
        compile_script_to_tree_bytes(script).map_err(|(status, msg)| api_error(status, &msg))?;

    // Full script execution with a transaction context (inputs, data inputs,
    // self box, etc.) requires sigma-rust's Prover infrastructure and is
    // significantly more complex than compilation alone.
    // For now, return the compiled ErgoTree as hex and indicate that
    // full evaluation is not yet supported.
    Ok(Json(serde_json::json!({
        "compiledErgoTree": hex::encode(&tree_bytes),
        "note": "Full script evaluation with context is not yet supported. Only compilation is performed."
    })))
}
