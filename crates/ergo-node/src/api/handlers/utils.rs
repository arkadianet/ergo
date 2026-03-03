use super::super::*;

/// `GET /utils/address/{addr}` — validate an Ergo address.
#[utoipa::path(
    get,
    path = "/utils/address/{addr}",
    tag = "utils",
    params(
        ("addr" = String, Path, description = "Ergo address to validate")
    ),
    responses(
        (status = 200, description = "Address validation result", body = AddressValidationResponse)
    )
)]
pub(crate) async fn validate_address_handler(
    Path(addr): Path<String>,
) -> Json<AddressValidationResponse> {
    match address::validate_address(&addr) {
        Ok(_) => Json(AddressValidationResponse {
            address: addr,
            is_valid: true,
            error: None,
        }),
        Err(e) => Json(AddressValidationResponse {
            address: addr,
            is_valid: false,
            error: Some(e.to_string()),
        }),
    }
}

/// `POST /utils/address` — validate an Ergo address (body is a JSON string).
#[utoipa::path(
    post,
    path = "/utils/address",
    tag = "utils",
    request_body = String,
    responses(
        (status = 200, description = "Address validation result", body = AddressValidationResponse)
    )
)]
pub(crate) async fn validate_address_post_handler(
    Json(addr): Json<String>,
) -> Json<AddressValidationResponse> {
    match address::validate_address(&addr) {
        Ok(_) => Json(AddressValidationResponse {
            address: addr,
            is_valid: true,
            error: None,
        }),
        Err(e) => Json(AddressValidationResponse {
            address: addr,
            is_valid: false,
            error: Some(e.to_string()),
        }),
    }
}

/// `GET /utils/rawToAddress/{pubkey_hex}` — create a P2PK address from a hex public key.
#[utoipa::path(
    get,
    path = "/utils/rawToAddress/{pubkey_hex}",
    tag = "utils",
    params(
        ("pubkey_hex" = String, Path, description = "Hex-encoded public key")
    ),
    responses(
        (status = 200, description = "P2PK address", body = String),
        (status = 400, description = "Invalid public key")
    )
)]
pub(crate) async fn raw_to_address_handler(
    State(state): State<ApiState>,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    let prefix = network_prefix(&state.network);
    let addr = address::raw_to_address(&pubkey_hex, prefix)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid public key hex"))?;
    Ok(Json(addr))
}

/// `GET /utils/addressToRaw/{addr}` — decode an address and return hex content bytes.
#[utoipa::path(
    get,
    path = "/utils/addressToRaw/{addr}",
    tag = "utils",
    params(
        ("addr" = String, Path, description = "Ergo address")
    ),
    responses(
        (status = 200, description = "Hex content bytes", body = String),
        (status = 400, description = "Invalid address")
    )
)]
pub(crate) async fn address_to_raw_handler(
    Path(addr): Path<String>,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    let raw = address::address_to_raw(&addr)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid address"))?;
    Ok(Json(raw))
}

/// `GET /utils/ergoTreeToAddress/{ergo_tree_hex}` — derive an address from an ErgoTree.
#[utoipa::path(
    get,
    path = "/utils/ergoTreeToAddress/{ergo_tree_hex}",
    tag = "utils",
    params(
        ("ergo_tree_hex" = String, Path, description = "Hex-encoded ErgoTree")
    ),
    responses(
        (status = 200, description = "Ergo address", body = String),
        (status = 400, description = "Invalid ErgoTree")
    )
)]
pub(crate) async fn ergo_tree_to_address_handler(
    State(state): State<ApiState>,
    Path(ergo_tree_hex): Path<String>,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    ergo_tree_to_address_impl(&ergo_tree_hex, &state)
}

/// `POST /utils/ergoTreeToAddress` — derive an address from an ErgoTree hex in the request body.
#[utoipa::path(
    post,
    path = "/utils/ergoTreeToAddress",
    tag = "utils",
    request_body = String,
    responses(
        (status = 200, description = "Ergo address", body = String),
        (status = 400, description = "Invalid ErgoTree")
    )
)]
pub(crate) async fn ergo_tree_to_address_post_handler(
    State(state): State<ApiState>,
    body: String,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    let hex_str = body.trim().trim_matches('"');
    ergo_tree_to_address_impl(hex_str, &state)
}

/// `GET /utils/seed` — random 32-byte hex string.
#[utoipa::path(
    get,
    path = "/utils/seed",
    tag = "utils",
    responses(
        (status = 200, description = "Random 32-byte hex string", body = String)
    )
)]
pub(crate) async fn seed_handler() -> Json<String> {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    Json(hex::encode(buf))
}

/// `GET /utils/seed/{length}` — random N-byte hex string (max 256).
#[utoipa::path(
    get,
    path = "/utils/seed/{length}",
    tag = "utils",
    params(
        ("length" = usize, Path, description = "Seed length in bytes (max 256)")
    ),
    responses(
        (status = 200, description = "Random hex string", body = String),
        (status = 400, description = "Length exceeds maximum")
    )
)]
pub(crate) async fn seed_with_length_handler(
    Path(length): Path<usize>,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    use rand::RngCore;
    if length > 256 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Length must be at most 256",
        ));
    }
    let mut buf = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut buf);
    Ok(Json(hex::encode(buf)))
}

/// `POST /utils/hash/blake2b` — blake2b-256 hash of input JSON string.
#[utoipa::path(
    post,
    path = "/utils/hash/blake2b",
    tag = "utils",
    request_body = String,
    responses(
        (status = 200, description = "Blake2b-256 hash", body = Object)
    )
)]
pub(crate) async fn blake2b_hash_handler(Json(input): Json<String>) -> Json<serde_json::Value> {
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = blake2::Blake2bVar::new(32).expect("valid output size");
    hasher.update(input.as_bytes());
    let mut hash = [0u8; 32];
    hasher
        .finalize_variable(&mut hash)
        .expect("valid output size");
    Json(serde_json::json!({ "hash": hex::encode(hash) }))
}
