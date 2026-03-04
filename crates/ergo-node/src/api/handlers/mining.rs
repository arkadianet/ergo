use super::super::*;

/// GET /mining/candidate — return the current mining candidate (work message).
#[utoipa::path(
    get,
    path = "/mining/candidate",
    tag = "mining",
    responses(
        (status = 200, description = "Current mining candidate", body = MiningCandidateResponse),
        (status = 503, description = "Mining not enabled")
    )
)]
pub(crate) async fn mining_candidate_handler(
    State(state): State<ApiState>,
) -> Result<Json<MiningCandidateResponse>, (StatusCode, Json<ApiError>)> {
    let gen_lock = state
        .candidate_generator
        .as_ref()
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "Mining is not enabled"))?;

    let gen = gen_lock
        .read()
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("lock poisoned: {e}")))?;

    let (_candidate, header_template) = gen
        .current()
        .ok_or_else(|| api_error(StatusCode::SERVICE_UNAVAILABLE, "No mining candidate available yet"))?;

    // Recompute msg and target from header template.
    let msg = ergo_consensus::autolykos::msg_by_header(header_template);
    let b_big = ergo_consensus::autolykos::get_b(header_template.n_bits);
    let b = biguint_to_u64_saturating(&b_big);

    Ok(Json(MiningCandidateResponse {
        msg: hex::encode(msg),
        b,
        h: header_template.height,
        pk: hex::encode(gen.miner_pk),
    }))
}

/// POST /mining/candidateWithTxs — return the current mining candidate including transactions.
///
/// Accepts a JSON body (which is currently ignored) and returns the work message
/// fields plus the full list of transactions in the candidate block.
#[utoipa::path(
    post,
    path = "/mining/candidateWithTxs",
    tag = "mining",
    request_body = Object,
    responses(
        (status = 200, description = "Mining candidate with transactions", body = CandidateWithTxsResponse),
        (status = 503, description = "Mining not enabled")
    )
)]
pub(crate) async fn mining_candidate_with_txs_handler(
    State(state): State<ApiState>,
    _body: String,
) -> Result<Json<CandidateWithTxsResponse>, (StatusCode, Json<ApiError>)> {
    let gen_lock = state
        .candidate_generator
        .as_ref()
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "Mining is not enabled"))?;

    let gen = gen_lock
        .read()
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("lock poisoned: {e}")))?;

    let (candidate, header_template) = gen
        .current()
        .ok_or_else(|| api_error(StatusCode::SERVICE_UNAVAILABLE, "No mining candidate available yet"))?;

    // Recompute msg and target from header template.
    let msg = ergo_consensus::autolykos::msg_by_header(header_template);
    let b_big = ergo_consensus::autolykos::get_b(header_template.n_bits);
    let b = biguint_to_u64_saturating(&b_big);

    // Serialize candidate transactions.
    let transactions: Vec<TransactionResponse> = candidate
        .transactions
        .iter()
        .map(|tx| {
            let size = serialize_transaction(tx).len();
            ergo_tx_to_response(tx, size)
        })
        .collect();

    Ok(Json(CandidateWithTxsResponse {
        msg: hex::encode(msg),
        b,
        h: header_template.height,
        pk: hex::encode(gen.miner_pk),
        transactions,
    }))
}

/// POST /mining/solution — submit a mining solution from an external miner.
#[utoipa::path(
    post,
    path = "/mining/solution",
    tag = "mining",
    request_body = MiningSolution,
    responses(
        (status = 200, description = "Solution accepted", body = Object),
        (status = 400, description = "Invalid solution"),
        (status = 503, description = "Mining not enabled")
    )
)]
pub(crate) async fn mining_solution_handler(
    State(state): State<ApiState>,
    Json(solution): Json<MiningSolution>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    // Validate nonce format.
    if solution.nonce_bytes().is_none() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid nonce: expected 8 bytes hex-encoded (16 hex chars)",
        ));
    }

    let tx = state
        .mining_solution_tx
        .as_ref()
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "Mining is not enabled"))?;

    tx.send(solution).await.map_err(|_| {
        api_error(StatusCode::INTERNAL_SERVER_ERROR, "solution channel closed")
    })?;

    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// GET /mining/rewardAddress — return the configured mining reward address.
#[utoipa::path(
    get,
    path = "/mining/rewardAddress",
    tag = "mining",
    responses(
        (status = 200, description = "Mining reward address", body = RewardAddressResponse),
        (status = 503, description = "No mining key configured")
    )
)]
pub(crate) async fn mining_reward_address_handler(
    State(state): State<ApiState>,
) -> Result<Json<RewardAddressResponse>, (StatusCode, Json<ApiError>)> {
    if state.mining_pub_key_hex.is_empty() {
        return Err(api_error(StatusCode::BAD_REQUEST, "Mining is not enabled"));
    }
    Ok(Json(RewardAddressResponse {
        reward_address: state.mining_pub_key_hex.clone(),
    }))
}

/// GET /mining/rewardPublicKey — return the configured miner public key.
#[utoipa::path(
    get,
    path = "/mining/rewardPublicKey",
    tag = "mining",
    responses(
        (status = 200, description = "Mining reward public key", body = RewardPublicKeyResponse),
        (status = 503, description = "No mining key configured")
    )
)]
pub(crate) async fn mining_reward_pubkey_handler(
    State(state): State<ApiState>,
) -> Result<Json<RewardPublicKeyResponse>, (StatusCode, Json<ApiError>)> {
    if state.mining_pub_key_hex.is_empty() {
        return Err(api_error(StatusCode::BAD_REQUEST, "Mining is not enabled"));
    }
    Ok(Json(RewardPublicKeyResponse {
        reward_pub_key: state.mining_pub_key_hex.clone(),
    }))
}
