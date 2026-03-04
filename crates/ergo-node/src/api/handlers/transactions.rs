use super::super::*;

/// `POST /transactions` -- accept a Scala-compatible JSON transaction, validate, and submit.
#[utoipa::path(
    post,
    path = "/transactions",
    tag = "transactions",
    request_body = Object,
    responses(
        (status = 200, description = "Transaction ID", body = String),
        (status = 400, description = "Invalid transaction")
    )
)]
pub(crate) async fn submit_transaction_handler(
    State(state): State<ApiState>,
    Json(json_tx): Json<TxJsonTransaction>,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    let tx =
        convert_json_tx_to_ergo_tx(&json_tx).map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;

    let bytes = serialize_transaction(&tx);

    validate_tx_stateless(&tx, &ValidationSettings::initial()).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Stateless transaction validation failed",
        )
    })?;

    ergo_network::mempool::validate_for_pool(
        bytes.len(),
        &state.blacklisted_transactions,
        state.max_transaction_size,
        &tx.tx_id,
    )
    .map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Transaction rejected by mempool policy",
        )
    })?;

    let tx_id = tx.tx_id;

    // Insert into mempool (scoped to drop the lock guard before any .await).
    {
        let mut mp = state.mempool.write().unwrap();
        mp.put_with_size(tx, bytes.len()).map_err(|_| {
            api_error(
                StatusCode::BAD_REQUEST,
                "Failed to insert transaction into mempool",
            )
        })?;
    }

    // Signal event loop to broadcast and wait for confirmation.
    if let Some(sender) = state.tx_submit.clone() {
        await_tx_submission(sender, tx_id.0).await?;
    }

    // Return plain JSON string tx_id (matching Scala format)
    Ok(Json(hex::encode(tx_id.0)))
}

/// Wait for the event loop to confirm a transaction submission via oneshot channel.
pub(crate) async fn await_tx_submission(
    sender: tokio::sync::mpsc::Sender<TxSubmission>,
    tx_id: [u8; 32],
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    let submission = TxSubmission {
        tx_id,
        response: resp_tx,
    };
    sender
        .try_send(submission)
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "event loop busy"))?;
    match tokio::time::timeout(std::time::Duration::from_secs(5), resp_rx).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(e))) => Err(api_error(StatusCode::BAD_REQUEST, &e)),
        Ok(Err(_)) => Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "event loop dropped response",
        )),
        Err(_) => Err(api_error(StatusCode::GATEWAY_TIMEOUT, "event loop timeout")),
    }
}

#[utoipa::path(
    get,
    path = "/transactions/unconfirmed",
    tag = "transactions",
    params(
        ("offset" = Option<usize>, Query, description = "Offset"),
        ("limit" = Option<usize>, Query, description = "Limit (max 100)")
    ),
    responses(
        (status = 200, description = "Unconfirmed transactions", body = Vec<TransactionResponse>)
    )
)]
pub(crate) async fn get_unconfirmed_handler(
    State(state): State<ApiState>,
    Query(params): Query<UnconfirmedPaginationParams>,
) -> Json<Vec<TransactionResponse>> {
    let mp = state.mempool.read().unwrap();
    let limit = params.limit.min(100);
    let txs: Vec<TransactionResponse> = mp
        .get_all_with_size()
        .into_iter()
        .skip(params.offset)
        .take(limit)
        .map(|(tx, size)| ergo_tx_to_response(tx, size))
        .collect();
    Json(txs)
}

#[utoipa::path(
    get,
    path = "/transactions/unconfirmed/size",
    tag = "transactions",
    responses(
        (status = 200, description = "Mempool size", body = MempoolSizeResponse)
    )
)]
pub(crate) async fn get_unconfirmed_size_handler(
    State(state): State<ApiState>,
) -> Json<MempoolSizeResponse> {
    let mp = state.mempool.read().unwrap();
    Json(MempoolSizeResponse { size: mp.size() })
}

#[utoipa::path(
    get,
    path = "/transactions/unconfirmed/{tx_id}",
    tag = "transactions",
    params(
        ("tx_id" = String, Path, description = "Transaction ID (hex)")
    ),
    responses(
        (status = 200, description = "Unconfirmed transaction", body = TransactionResponse),
        (status = 404, description = "Transaction not found")
    )
)]
pub(crate) async fn get_unconfirmed_by_id_handler(
    State(state): State<ApiState>,
    Path(tx_id_hex): Path<String>,
) -> Result<Json<TransactionResponse>, (StatusCode, Json<ApiError>)> {
    let id_bytes = hex::decode(&tx_id_hex)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding"))?;
    if id_bytes.len() != 32 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Transaction ID must be 32 bytes (64 hex chars)",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&id_bytes);
    let tx_id = TxId(arr);

    let mp = state.mempool.read().unwrap();
    let (tx, size) = mp
        .get_with_size(&tx_id)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Transaction not found in mempool"))?;

    Ok(Json(ergo_tx_to_response(tx, size)))
}

/// `POST /transactions/check` -- validate a JSON transaction without broadcasting.
#[utoipa::path(
    post,
    path = "/transactions/check",
    tag = "transactions",
    request_body = Object,
    responses(
        (status = 200, description = "Transaction ID (valid)", body = String),
        (status = 400, description = "Invalid transaction")
    )
)]
pub(crate) async fn check_transaction_handler(
    State(state): State<ApiState>,
    Json(json_tx): Json<TxJsonTransaction>,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    let tx =
        convert_json_tx_to_ergo_tx(&json_tx).map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;

    let bytes = serialize_transaction(&tx);

    validate_tx_stateless(&tx, &ValidationSettings::initial()).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Stateless transaction validation failed",
        )
    })?;
    ergo_network::mempool::validate_for_pool(
        bytes.len(),
        &state.blacklisted_transactions,
        state.max_transaction_size,
        &tx.tx_id,
    )
    .map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Transaction rejected by mempool policy",
        )
    })?;

    // Return plain JSON string tx_id (matching Scala format)
    Ok(Json(hex::encode(tx.tx_id.0)))
}

#[utoipa::path(
    post,
    path = "/transactions/bytes",
    tag = "transactions",
    request_body = String,
    responses(
        (status = 200, description = "Transaction submitted", body = TxSubmitResponse),
        (status = 400, description = "Invalid transaction bytes")
    )
)]
/// `POST /transactions/bytes` — submit a transaction as hex-encoded serialized bytes.
pub(crate) async fn submit_transaction_bytes_handler(
    State(state): State<ApiState>,
    Json(hex_str): Json<String>,
) -> Result<Json<TxSubmitResponse>, (StatusCode, Json<ApiError>)> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding"))?;
    let tx = parse_transaction(&bytes)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Failed to parse transaction"))?;
    validate_tx_stateless(&tx, &ValidationSettings::initial()).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Stateless transaction validation failed",
        )
    })?;

    ergo_network::mempool::validate_for_pool(
        bytes.len(),
        &state.blacklisted_transactions,
        state.max_transaction_size,
        &tx.tx_id,
    )
    .map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Transaction rejected by mempool policy",
        )
    })?;

    let tx_id = tx.tx_id;

    // Insert into mempool (scoped to drop the lock guard before any .await).
    {
        let mut mp = state.mempool.write().unwrap();
        mp.put_with_size(tx, bytes.len()).map_err(|_| {
            api_error(
                StatusCode::BAD_REQUEST,
                "Failed to insert transaction into mempool",
            )
        })?;
    }

    if let Some(sender) = state.tx_submit.clone() {
        await_tx_submission(sender, tx_id.0).await?;
    }

    Ok(Json(TxSubmitResponse {
        tx_id: hex::encode(tx_id.0),
    }))
}

#[utoipa::path(
    post,
    path = "/transactions/checkBytes",
    tag = "transactions",
    request_body = String,
    responses(
        (status = 200, description = "Transaction valid", body = TxSubmitResponse),
        (status = 400, description = "Invalid transaction bytes")
    )
)]
/// `POST /transactions/checkBytes` — validate hex-encoded tx bytes without broadcasting.
pub(crate) async fn check_transaction_bytes_handler(
    State(state): State<ApiState>,
    Json(hex_str): Json<String>,
) -> Result<Json<TxSubmitResponse>, (StatusCode, Json<ApiError>)> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding"))?;
    let tx = parse_transaction(&bytes)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Failed to parse transaction"))?;
    validate_tx_stateless(&tx, &ValidationSettings::initial()).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Stateless transaction validation failed",
        )
    })?;
    ergo_network::mempool::validate_for_pool(
        bytes.len(),
        &state.blacklisted_transactions,
        state.max_transaction_size,
        &tx.tx_id,
    )
    .map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Transaction rejected by mempool policy",
        )
    })?;
    Ok(Json(TxSubmitResponse {
        tx_id: hex::encode(tx.tx_id.0),
    }))
}

/// `GET /transactions/poolHistogram?bins=10&maxtime=60000`
#[utoipa::path(
    get,
    path = "/transactions/poolHistogram",
    tag = "transactions",
    params(
        ("bins" = Option<usize>, Query, description = "Number of bins (default 10)"),
        ("maxtime" = Option<u64>, Query, description = "Max time in milliseconds (default 60000)")
    ),
    responses(
        (status = 200, description = "Pool histogram", body = Vec<HistogramBinResponse>)
    )
)]
pub(crate) async fn pool_histogram_handler(
    State(state): State<ApiState>,
    Query(params): Query<HistogramParams>,
) -> Json<Vec<HistogramBinResponse>> {
    let mp = state.mempool.read().unwrap();
    let bins = params.bins.clamp(1, 100);
    let histogram = mp.pool_histogram(bins, params.maxtime);
    Json(
        histogram
            .into_iter()
            .map(|bin| HistogramBinResponse {
                n_txns: bin.n_txns,
                total_fee: bin.total_fee,
            })
            .collect(),
    )
}

/// `GET /transactions/getFee?waitTime=1000`
#[utoipa::path(
    get,
    path = "/transactions/getFee",
    tag = "transactions",
    params(
        ("waitTime" = Option<u64>, Query, description = "Expected wait time in ms")
    ),
    responses(
        (status = 200, description = "Fee estimate in nanoErg", body = u64)
    )
)]
pub(crate) async fn get_fee_handler(
    State(state): State<ApiState>,
    Query(_params): Query<FeeEstimateParams>,
) -> Json<u64> {
    let mp = state.mempool.read().unwrap();
    // Simple heuristic: base fee scaled by mempool occupancy
    let min_fee: u64 = 1_000_000; // 0.001 ERG minimum
    let pool_size = mp.size() as u64;
    let fee = min_fee + pool_size * 100_000; // increase by 0.0001 ERG per pooled tx
    Json(fee)
}

/// `GET /transactions/waitTime?fee=1000000`
#[utoipa::path(
    get,
    path = "/transactions/waitTime",
    tag = "transactions",
    params(
        ("fee" = Option<u64>, Query, description = "Transaction fee in nanoErg")
    ),
    responses(
        (status = 200, description = "Wait time estimate in milliseconds", body = u64)
    )
)]
pub(crate) async fn wait_time_handler(
    State(state): State<ApiState>,
    Query(params): Query<WaitTimeParams>,
) -> Json<u64> {
    let mp = state.mempool.read().unwrap();
    // Simple heuristic: if fee >= min, expected wait is short
    let min_fee: u64 = 1_000_000;
    let wait = if params.fee >= min_fee {
        let excess = params.fee.saturating_sub(min_fee);
        // Higher fee = shorter wait. Base 60s, reduced by fee premium
        let reduction = excess / 100_000; // each 0.0001 ERG reduces wait by 1s
        60_000u64.saturating_sub(reduction * 1000)
    } else {
        // Below minimum fee, long wait proportional to mempool size
        60_000 + mp.size() as u64 * 10_000
    };
    Json(wait)
}

#[utoipa::path(
    head,
    path = "/transactions/unconfirmed/{tx_id}",
    tag = "transactions",
    params(
        ("tx_id" = String, Path, description = "Transaction ID (hex)")
    ),
    responses(
        (status = 200, description = "Transaction in mempool"),
        (status = 404, description = "Transaction not found")
    )
)]
/// `HEAD /transactions/unconfirmed/{tx_id}` — check if tx is in mempool (200/404, no body).
pub(crate) async fn head_unconfirmed_handler(
    State(state): State<ApiState>,
    Path(tx_id_hex): Path<String>,
) -> StatusCode {
    let Ok(id_bytes) = hex::decode(&tx_id_hex) else {
        return StatusCode::BAD_REQUEST;
    };
    if id_bytes.len() != 32 {
        return StatusCode::BAD_REQUEST;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&id_bytes);
    let tx_id = TxId(arr);

    let mp = state.mempool.read().unwrap();
    if mp.contains(&tx_id) {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

#[utoipa::path(
    get,
    path = "/transactions/unconfirmed/transactionIds",
    tag = "transactions",
    responses(
        (status = 200, description = "All unconfirmed transaction IDs", body = Vec<String>)
    )
)]
/// `GET /transactions/unconfirmed/transactionIds` — all unconfirmed tx IDs.
pub(crate) async fn get_unconfirmed_tx_ids_handler(
    State(state): State<ApiState>,
) -> Json<Vec<String>> {
    let mp = state.mempool.read().unwrap();
    let ids: Vec<String> = mp
        .get_all_tx_ids()
        .iter()
        .map(|id| hex::encode(id.0))
        .collect();
    Json(ids)
}

#[utoipa::path(
    post,
    path = "/transactions/unconfirmed/byTransactionIds",
    tag = "transactions",
    request_body = Vec<String>,
    responses(
        (status = 200, description = "Transaction IDs present in mempool", body = Vec<String>),
        (status = 400, description = "Too many IDs")
    )
)]
/// `POST /transactions/unconfirmed/byTransactionIds` — filter IDs by mempool presence.
pub(crate) async fn post_by_transaction_ids_handler(
    State(state): State<ApiState>,
    Json(ids): Json<Vec<String>>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<ApiError>)> {
    if ids.len() > 100 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Too many IDs; maximum is 100",
        ));
    }
    let mp = state.mempool.read().unwrap();
    let mut present = Vec::new();
    for id_hex in &ids {
        let Ok(id_bytes) = hex::decode(id_hex) else {
            continue;
        };
        if id_bytes.len() != 32 {
            continue;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&id_bytes);
        let tx_id = TxId(arr);
        if mp.contains(&tx_id) {
            present.push(id_hex.clone());
        }
    }
    Ok(Json(present))
}

/// `GET /transactions/unconfirmed/outputs/byBoxId/{id}` — find unconfirmed output by box ID.
/// `GET /transactions/unconfirmed/inputs/byBoxId/{id}` -- find which mempool tx spends a box.
#[utoipa::path(
    get,
    path = "/transactions/unconfirmed/inputs/byBoxId/{id}",
    tag = "transactions",
    params(
        ("id" = String, Path, description = "Box ID (hex)")
    ),
    responses(
        (status = 200, description = "Spending input info", body = SpendingInputResponse),
        (status = 404, description = "No spending input found")
    )
)]
pub(crate) async fn get_unconfirmed_inputs_by_box_id_handler(
    State(state): State<ApiState>,
    Path(box_id_hex): Path<String>,
) -> Result<Json<SpendingInputResponse>, (StatusCode, Json<ApiError>)> {
    let id_bytes = hex::decode(&box_id_hex)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding"))?;
    if id_bytes.len() != 32 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Box ID must be 32 bytes (64 hex chars)",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&id_bytes);
    let box_id = BoxId(arr);

    let mp = state.mempool.read().unwrap();
    let (tx_id, input) = mp
        .find_spending_input(&box_id)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "No spending input found for box ID"))?;

    Ok(Json(SpendingInputResponse {
        box_id: box_id_hex,
        spending_tx_id: hex::encode(tx_id.0),
        proof_bytes: hex::encode(&input.proof_bytes),
    }))
}

#[utoipa::path(
    get,
    path = "/transactions/unconfirmed/outputs/byBoxId/{id}",
    tag = "transactions",
    params(
        ("id" = String, Path, description = "Box ID (hex)")
    ),
    responses(
        (status = 200, description = "Unconfirmed output", body = UnconfirmedOutputResponse),
        (status = 404, description = "Output not found")
    )
)]
pub(crate) async fn get_unconfirmed_output_by_box_id_handler(
    State(state): State<ApiState>,
    Path(box_id_hex): Path<String>,
) -> Result<Json<UnconfirmedOutputResponse>, (StatusCode, Json<ApiError>)> {
    let id_bytes = hex::decode(&box_id_hex)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding"))?;
    if id_bytes.len() != 32 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Box ID must be 32 bytes (64 hex chars)",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&id_bytes);
    let box_id = BoxId(arr);

    let mp = state.mempool.read().unwrap();
    let output_ref = mp
        .find_output_by_box_id(&box_id)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Output not found for box ID"))?;

    Ok(Json(UnconfirmedOutputResponse {
        box_id: box_id_hex,
        tx_id: hex::encode(output_ref.tx_id.0),
        index: output_ref.index,
        value: output_ref.candidate.value,
        creation_height: output_ref.candidate.creation_height,
        token_count: output_ref.candidate.tokens.len(),
    }))
}

#[utoipa::path(
    get,
    path = "/transactions/unconfirmed/outputs/byTokenId/{id}",
    tag = "transactions",
    params(
        ("id" = String, Path, description = "Token ID (hex)")
    ),
    responses(
        (status = 200, description = "Unconfirmed outputs with token", body = Vec<UnconfirmedOutputResponse>)
    )
)]
/// `GET /transactions/unconfirmed/outputs/byTokenId/{id}` — find unconfirmed outputs by token ID.
pub(crate) async fn get_unconfirmed_outputs_by_token_id_handler(
    State(state): State<ApiState>,
    Path(token_id_hex): Path<String>,
) -> Result<Json<Vec<UnconfirmedOutputResponse>>, (StatusCode, Json<ApiError>)> {
    let id_bytes = hex::decode(&token_id_hex)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding"))?;
    if id_bytes.len() != 32 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Token ID must be 32 bytes (64 hex chars)",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&id_bytes);
    let token_id = BoxId(arr);

    let mp = state.mempool.read().unwrap();
    let results = mp.find_outputs_by_token_id(&token_id);

    let responses: Vec<UnconfirmedOutputResponse> = results
        .iter()
        .map(|output_ref| {
            let box_id = compute_box_id(&output_ref.tx_id, output_ref.index);
            UnconfirmedOutputResponse {
                box_id: hex::encode(box_id.0),
                tx_id: hex::encode(output_ref.tx_id.0),
                index: output_ref.index,
                value: output_ref.candidate.value,
                creation_height: output_ref.candidate.creation_height,
                token_count: output_ref.candidate.tokens.len(),
            }
        })
        .collect();

    Ok(Json(responses))
}

#[utoipa::path(
    post,
    path = "/transactions/unconfirmed/byErgoTree",
    tag = "transactions",
    request_body = String,
    responses(
        (status = 200, description = "Unconfirmed transactions by ErgoTree", body = Vec<TransactionResponse>)
    )
)]
/// `POST /transactions/unconfirmed/byErgoTree` — find unconfirmed txs by ErgoTree hex.
pub(crate) async fn post_unconfirmed_by_ergo_tree_handler(
    State(state): State<ApiState>,
    body: String,
) -> Result<Json<Vec<TransactionResponse>>, (StatusCode, Json<ApiError>)> {
    let hex_str = body.trim().trim_matches('"');
    let tree_bytes = hex::decode(hex_str)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid hex ErgoTree"))?;
    let tree_hash = blake2b256(&tree_bytes);
    let pool = state.mempool.read().unwrap();
    let txs = pool.find_txs_by_tree_hash(&tree_hash);
    let result: Vec<TransactionResponse> =
        txs.iter().map(|tx| ergo_tx_to_response(tx, 0)).collect();
    Ok(Json(result))
}

#[utoipa::path(
    post,
    path = "/transactions/unconfirmed/outputs/byErgoTree",
    tag = "transactions",
    request_body = String,
    responses(
        (status = 200, description = "Unconfirmed outputs by ErgoTree", body = Vec<UnconfirmedOutputResponse>)
    )
)]
/// `POST /transactions/unconfirmed/outputs/byErgoTree` — find unconfirmed outputs by ErgoTree hex.
pub(crate) async fn post_unconfirmed_outputs_by_ergo_tree_handler(
    State(state): State<ApiState>,
    body: String,
) -> Result<Json<Vec<UnconfirmedOutputResponse>>, (StatusCode, Json<ApiError>)> {
    let hex_str = body.trim().trim_matches('"');
    let tree_bytes = hex::decode(hex_str)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid hex ErgoTree"))?;
    let tree_hash = blake2b256(&tree_bytes);
    let pool = state.mempool.read().unwrap();
    let outputs = pool.find_outputs_by_tree_hash(&tree_hash);
    let result: Vec<UnconfirmedOutputResponse> = outputs
        .iter()
        .map(|o| {
            let box_id = compute_box_id(&o.tx_id, o.index);
            UnconfirmedOutputResponse {
                box_id: hex::encode(box_id.0),
                tx_id: hex::encode(o.tx_id.0),
                index: o.index,
                value: o.candidate.value,
                creation_height: o.candidate.creation_height,
                token_count: o.candidate.tokens.len(),
            }
        })
        .collect();
    Ok(Json(result))
}

#[utoipa::path(
    post,
    path = "/transactions/unconfirmed/outputs/byRegisters",
    tag = "transactions",
    request_body = Object,
    responses(
        (status = 200, description = "Unconfirmed outputs matching registers", body = Vec<UnconfirmedOutputResponse>)
    )
)]
/// `POST /transactions/unconfirmed/outputs/byRegisters` — find unconfirmed outputs by register values.
pub(crate) async fn post_unconfirmed_outputs_by_registers_handler(
    State(state): State<ApiState>,
    Json(body): Json<std::collections::HashMap<String, String>>,
) -> Result<Json<Vec<UnconfirmedOutputResponse>>, (StatusCode, Json<ApiError>)> {
    let mut filter: Vec<(u8, Vec<u8>)> = Vec::new();
    for (key, hex_val) in &body {
        let reg_idx = key
            .strip_prefix('R')
            .and_then(|s| s.parse::<u8>().ok())
            .ok_or_else(|| {
                api_error(
                    StatusCode::BAD_REQUEST,
                    &format!("invalid register key: {key}"),
                )
            })?;
        let val = hex::decode(hex_val)
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, &format!("invalid hex for {key}")))?;
        filter.push((reg_idx, val));
    }
    let pool = state.mempool.read().unwrap();
    let outputs = pool.find_outputs_by_registers(&filter);
    let result: Vec<UnconfirmedOutputResponse> = outputs
        .iter()
        .map(|o| {
            let box_id = compute_box_id(&o.tx_id, o.index);
            UnconfirmedOutputResponse {
                box_id: hex::encode(box_id.0),
                tx_id: hex::encode(o.tx_id.0),
                index: o.index,
                value: o.candidate.value,
                creation_height: o.candidate.creation_height,
                token_count: o.candidate.tokens.len(),
            }
        })
        .collect();
    Ok(Json(result))
}
