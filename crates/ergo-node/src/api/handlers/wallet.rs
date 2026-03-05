#[allow(unused_imports)]
use super::super::*;

/// `GET /wallet/status` — get wallet lifecycle status.
#[cfg(feature = "wallet")]
#[utoipa::path(
    get,
    path = "/wallet/status",
    tag = "wallet",
    responses(
        (status = 200, description = "Wallet status", body = Object)
    )
)]
pub(crate) async fn wallet_status_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<WalletStatusResponse>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let status = w.status();
    Ok(Json(WalletStatusResponse {
        is_initialized: status.initialized,
        is_unlocked: status.unlocked,
        change_address: status.change_address,
        wallet_height: status.wallet_height,
        error: status.error,
    }))
}

/// `POST /wallet/init` — create a new wallet (generates mnemonic).
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/init",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Initialize wallet", body = Object)
    )
)]
pub(crate) async fn wallet_init_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletInitRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    let mnemonic = w
        .init(&body.pass)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "mnemonic": mnemonic })))
}

/// `POST /wallet/restore` — restore wallet from an existing mnemonic.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/restore",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Restore wallet from mnemonic", body = Object)
    )
)]
pub(crate) async fn wallet_restore_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletRestoreRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    w.restore(&body.pass, &body.mnemonic, &body.mnemonic_pass)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({})))
}

/// `POST /wallet/unlock` — unlock the wallet with a password.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/unlock",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Unlock wallet", body = Object)
    )
)]
pub(crate) async fn wallet_unlock_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletUnlockRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    w.unlock(&body.pass)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({})))
}

/// `GET /wallet/lock` — lock the wallet (clear keys from memory).
#[cfg(feature = "wallet")]
#[utoipa::path(
    get,
    path = "/wallet/lock",
    tag = "wallet",
    responses(
        (status = 200, description = "Lock wallet", body = Object)
    )
)]
pub(crate) async fn wallet_lock_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    w.lock();
    Ok(Json(serde_json::json!({})))
}

/// `GET /wallet/addresses` — list all derived wallet addresses.
#[cfg(feature = "wallet")]
#[utoipa::path(
    get,
    path = "/wallet/addresses",
    tag = "wallet",
    responses(
        (status = 200, description = "Wallet addresses", body = Object)
    )
)]
pub(crate) async fn wallet_addresses_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let addresses = w
        .addresses()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(addresses))
}

/// `POST /wallet/deriveKey` — derive a key at a specific BIP-32 path.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/deriveKey",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Derive key", body = Object)
    )
)]
pub(crate) async fn wallet_derive_key_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletDeriveKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    let address = w
        .derive_key(&body.derivation_path)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "address": address })))
}

/// `GET /wallet/deriveNextKey` — derive the next key (auto-increment index).
#[cfg(feature = "wallet")]
#[utoipa::path(
    get,
    path = "/wallet/deriveNextKey",
    tag = "wallet",
    responses(
        (status = 200, description = "Derive next key", body = Object)
    )
)]
pub(crate) async fn wallet_derive_next_key_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    let (derivation_path, address) = w
        .derive_next_key()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({
        "derivationPath": derivation_path,
        "address": address,
    })))
}

/// `GET /wallet/balances` — get on-chain wallet balance.
#[cfg(feature = "wallet")]
#[utoipa::path(
    get,
    path = "/wallet/balances",
    tag = "wallet",
    responses(
        (status = 200, description = "Wallet balances", body = Object)
    )
)]
pub(crate) async fn wallet_balances_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<WalletBalanceResponse>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let digest = w
        .balances()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let tokens: std::collections::HashMap<String, u64> = digest
        .token_balances
        .iter()
        .map(|(tid, amt)| (hex::encode(tid), *amt))
        .collect();
    Ok(Json(WalletBalanceResponse {
        height: digest.height,
        balance: digest.erg_balance,
        tokens,
    }))
}

/// `GET /wallet/balances/withUnconfirmed` — get balance including unconfirmed.
///
/// Currently returns the same result as `/wallet/balances` since mempool
/// integration is deferred.
#[cfg(feature = "wallet")]
#[utoipa::path(
    get,
    path = "/wallet/balances/withUnconfirmed",
    tag = "wallet",
    responses(
        (status = 200, description = "Wallet balances with unconfirmed", body = Object)
    )
)]
pub(crate) async fn wallet_balances_with_unconfirmed_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<WalletBalanceResponse>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let digest = w
        .balances()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let tokens: std::collections::HashMap<String, u64> = digest
        .token_balances
        .iter()
        .map(|(tid, amt)| (hex::encode(tid), *amt))
        .collect();
    Ok(Json(WalletBalanceResponse {
        height: digest.height,
        balance: digest.erg_balance,
        tokens,
    }))
}

/// `POST /wallet/updateChangeAddress` — update the wallet's change address.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/updateChangeAddress",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Update change address", body = Object)
    )
)]
pub(crate) async fn wallet_update_change_address_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletUpdateChangeAddressRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    w.update_change_address(&body.address)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({})))
}

/// `GET /wallet/boxes/unspent` — list unspent wallet boxes with optional filters.
#[cfg(feature = "wallet")]
#[utoipa::path(
    get,
    path = "/wallet/boxes/unspent",
    tag = "wallet",
    responses(
        (status = 200, description = "Wallet unspent boxes", body = Object)
    )
)]
pub(crate) async fn wallet_unspent_boxes_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Query(params): Query<WalletBoxQueryParams>,
) -> Result<Json<Vec<WalletBoxWithMetaResponse>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let boxes = w
        .unspent_boxes()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let current_height = state.shared.read().await.full_height;
    let min_conf = params.min_confirmations.unwrap_or(0);
    let max_conf = params.max_confirmations.unwrap_or(-1);
    let min_h = params.min_inclusion_height.unwrap_or(0);
    let max_h = params.max_inclusion_height.unwrap_or(u32::MAX);

    let result: Vec<WalletBoxWithMetaResponse> = boxes
        .iter()
        .filter(|b| {
            let confirmations = if current_height >= b.inclusion_height as u64 {
                (current_height - b.inclusion_height as u64) as i32
            } else {
                0
            };
            let conf_ok = confirmations >= min_conf && (max_conf < 0 || confirmations <= max_conf);
            let height_ok = b.inclusion_height >= min_h && b.inclusion_height <= max_h;
            conf_ok && height_ok
        })
        .map(|b| tracked_box_to_meta_response(b, current_height))
        .collect();

    Ok(Json(result))
}

/// `GET /wallet/boxes` — list all wallet boxes (spent + unspent) with optional filters.
#[cfg(feature = "wallet")]
#[utoipa::path(
    get,
    path = "/wallet/boxes",
    tag = "wallet",
    responses(
        (status = 200, description = "All wallet boxes", body = Object)
    )
)]
pub(crate) async fn wallet_boxes_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Query(params): Query<WalletBoxQueryParams>,
) -> Result<Json<Vec<WalletBoxWithMetaResponse>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let boxes = w
        .all_boxes()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let current_height = state.shared.read().await.full_height;
    let min_conf = params.min_confirmations.unwrap_or(0);
    let max_conf = params.max_confirmations.unwrap_or(-1);
    let min_h = params.min_inclusion_height.unwrap_or(0);
    let max_h = params.max_inclusion_height.unwrap_or(u32::MAX);

    let result: Vec<WalletBoxWithMetaResponse> = boxes
        .iter()
        .filter(|b| {
            let confirmations = if current_height >= b.inclusion_height as u64 {
                (current_height - b.inclusion_height as u64) as i32
            } else {
                0
            };
            let conf_ok = confirmations >= min_conf && (max_conf < 0 || confirmations <= max_conf);
            let height_ok = b.inclusion_height >= min_h && b.inclusion_height <= max_h;
            conf_ok && height_ok
        })
        .map(|b| tracked_box_to_meta_response(b, current_height))
        .collect();

    Ok(Json(result))
}

/// `POST /wallet/boxes/collect` — collect boxes matching a target balance.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/boxes/collect",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Collect boxes for target balance", body = Object)
    )
)]
pub(crate) async fn wallet_collect_boxes_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletCollectBoxesRequest>,
) -> Result<Json<Vec<WalletBoxResponse>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let unspent = w
        .unspent_boxes()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let target_tokens: Vec<(String, u64)> = body.target_assets.into_iter().collect();

    let collected =
        ergo_wallet::tx_ops::collect_boxes(&unspent, body.target_balance, &target_tokens)
            .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let result: Vec<WalletBoxResponse> = collected.iter().map(tracked_box_to_response).collect();
    Ok(Json(result))
}

/// `GET /wallet/transactions` — list wallet transactions with optional filters.
#[cfg(feature = "wallet")]
#[utoipa::path(
    get,
    path = "/wallet/transactions",
    tag = "wallet",
    responses(
        (status = 200, description = "Wallet transactions", body = Object)
    )
)]
pub(crate) async fn wallet_transactions_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Query(params): Query<WalletTransactionQueryParams>,
) -> Result<Json<Vec<WalletTransactionResponse>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;

    let min_h = params.min_inclusion_height.unwrap_or(0);
    let max_h = params.max_inclusion_height.unwrap_or(u32::MAX);

    let txs = w
        .get_transactions(min_h, max_h)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let current_height = state.shared.read().await.full_height;
    let min_conf = params.min_confirmations.unwrap_or(0);
    let max_conf = params.max_confirmations.unwrap_or(-1);

    let result: Vec<WalletTransactionResponse> = txs
        .iter()
        .filter(|tx| {
            let confirmations = if current_height >= tx.inclusion_height as u64 {
                (current_height - tx.inclusion_height as u64) as i32
            } else {
                0
            };
            confirmations >= min_conf && (max_conf < 0 || confirmations <= max_conf)
        })
        .map(|tx| {
            let num_confirmations = if current_height >= tx.inclusion_height as u64 {
                (current_height - tx.inclusion_height as u64) as u32
            } else {
                0
            };
            WalletTransactionResponse {
                id: hex::encode(tx.tx_id),
                inclusion_height: tx.inclusion_height,
                num_confirmations,
            }
        })
        .collect();

    Ok(Json(result))
}

/// `GET /wallet/transactionById/{txId}` — get a wallet transaction by its ID.
#[cfg(feature = "wallet")]
#[utoipa::path(
    get,
    path = "/wallet/transactionById/{txId}",
    tag = "wallet",
    params(
        ("txId" = String, Path, description = "txId")
    ),
    responses(
        (status = 200, description = "Get wallet transaction by ID", body = Object)
    )
)]
pub(crate) async fn wallet_transaction_by_id_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Path(tx_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;

    let tx_id_bytes: [u8; 32] = hex::decode(&tx_id_hex)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid hex txId"))?
        .try_into()
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "txId must be 32 bytes"))?;

    match w.get_transaction_by_id(&tx_id_bytes) {
        Ok(Some(tx)) => {
            let current_height = state.shared.read().await.full_height;
            let num_confirmations = if current_height >= tx.inclusion_height as u64 {
                (current_height - tx.inclusion_height as u64) as u32
            } else {
                0
            };
            Ok(Json(serde_json::json!({
                "id": hex::encode(tx.tx_id),
                "inclusionHeight": tx.inclusion_height,
                "numConfirmations": num_confirmations,
            })))
        }
        Ok(None) => Err(api_error(StatusCode::NOT_FOUND, "transaction not found")),
        Err(e) => Err(api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

/// `POST /wallet/check` — check if a mnemonic matches the wallet's stored seed.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/check",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Check seed phrase", body = Object)
    )
)]
pub(crate) async fn wallet_check_seed_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<WalletCheckSeedRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;

    match w.check_seed(&req.pass, &req.mnemonic) {
        Ok(matched) => Ok(Json(serde_json::json!({ "matched": matched }))),
        Err(e) => Err(api_error(StatusCode::BAD_REQUEST, &e.to_string())),
    }
}

/// `POST /wallet/rescan` — rescan the wallet from a given height.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/rescan",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Rescan wallet", body = Object)
    )
)]
pub(crate) async fn wallet_rescan_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<WalletRescanRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;

    w.rescan(req.from_height)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

/// Build an unsigned transaction, sign it, and return the signed bytes.
///
/// Shared logic for `wallet_tx_generate_handler`, `wallet_payment_send_handler`,
/// and `wallet_tx_send_handler`.
#[cfg(feature = "wallet")]
pub(crate) async fn build_and_sign_tx(
    state: &ApiState,
    payment_requests: &[ergo_wallet::tx_ops::PaymentRequest],
    fee: u64,
) -> Result<(Vec<u8>, [u8; 32]), (StatusCode, Json<ApiError>)> {
    let wallet = require_wallet(state)?;
    let w = wallet.read().await;

    let change_address = w
        .change_address()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let unspent = w
        .unspent_boxes()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let keys = w
        .keys()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let num_addresses = w
        .addresses()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?
        .len() as u32;

    let current_height = state.shared.read().await.full_height as u32;

    let (unsigned_tx, _input_ids) = ergo_wallet::tx_ops::build_unsigned_tx(
        payment_requests,
        fee,
        &change_address,
        &unspent,
        current_height,
    )
    .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    // Build sigma state context from current blockchain state.
    let sigma_ctx = {
        let shared = state.shared.read().await;
        build_sigma_state_context(&state.history, &shared)?
    };

    // Derive key indices 0..num_addresses for signing.
    let key_indices: Vec<u32> = (0..num_addresses.max(1)).collect();

    // Filter unspent boxes to only those matching the unsigned tx input IDs.
    let input_box_ids: std::collections::HashSet<[u8; 32]> = unsigned_tx
        .inputs
        .as_vec()
        .iter()
        .map(|inp| {
            let id_bytes: &[u8] = inp.box_id.as_ref();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(id_bytes);
            arr
        })
        .collect();
    let input_boxes: Vec<ergo_wallet::tracked_box::TrackedBox> = unspent
        .into_iter()
        .filter(|b| input_box_ids.contains(&b.box_id))
        .collect();

    let signed_bytes = ergo_wallet::tx_ops::sign_transaction(
        unsigned_tx,
        keys,
        &key_indices,
        &input_boxes,
        &[],
        &sigma_ctx,
    )
    .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    // Compute tx_id from the signed bytes.
    let signed_tx = parse_transaction(&signed_bytes)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    let tx_id = signed_tx.tx_id.0;

    Ok((signed_bytes, tx_id))
}

/// Insert a signed transaction into the mempool and submit to the event loop.
#[cfg(feature = "wallet")]
pub(crate) async fn submit_signed_tx(
    state: &ApiState,
    signed_bytes: &[u8],
    tx_id: [u8; 32],
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let tx = parse_transaction(signed_bytes)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    {
        let mut mp = state.mempool.write().unwrap();
        mp.put_with_size(tx, signed_bytes.len())
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, "failed to insert into mempool"))?;
    }

    if let Some(sender) = state.tx_submit.clone() {
        await_tx_submission(sender, tx_id).await?;
    }

    Ok(())
}

/// `POST /wallet/payment/send` — build, sign, and broadcast a payment transaction.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/payment/send",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Send payment", body = Object)
    )
)]
pub(crate) async fn wallet_payment_send_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<Vec<WalletPaymentRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let _wallet = require_wallet(&state)?;

    let payment_requests = convert_payment_requests(&body);
    let (signed_bytes, tx_id) = build_and_sign_tx(&state, &payment_requests, default_fee()).await?;

    submit_signed_tx(&state, &signed_bytes, tx_id).await?;

    Ok(Json(serde_json::json!({
        "txId": hex::encode(tx_id),
    })))
}

/// `POST /wallet/transaction/generate` — generate a signed transaction (returned,
/// not broadcast).
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/transaction/generate",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Generate signed transaction", body = Object)
    )
)]
pub(crate) async fn wallet_tx_generate_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletGenerateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let _wallet = require_wallet(&state)?;

    let payment_requests = convert_payment_requests(&body.requests);
    let (signed_bytes, _tx_id) = build_and_sign_tx(&state, &payment_requests, body.fee).await?;

    Ok(Json(serde_json::json!({
        "bytes": hex::encode(&signed_bytes),
    })))
}

/// `POST /wallet/transaction/generateUnsigned` — build an unsigned transaction.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/transaction/generateUnsigned",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Generate unsigned transaction", body = Object)
    )
)]
pub(crate) async fn wallet_tx_generate_unsigned_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletGenerateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;

    // Require unlocked wallet for change address and box selection.
    let change_address = w
        .change_address()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let unspent = w
        .unspent_boxes()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let current_height = state.shared.read().await.full_height as u32;

    // Convert WalletPaymentRequests to tx_ops::PaymentRequest.
    let payment_requests: Vec<ergo_wallet::tx_ops::PaymentRequest> = body
        .requests
        .iter()
        .map(|r| ergo_wallet::tx_ops::PaymentRequest {
            address: r.address.clone(),
            value: r.value,
            tokens: r
                .assets
                .iter()
                .map(|a| (a.token_id.clone(), a.amount))
                .collect(),
        })
        .collect();

    let (unsigned_tx, input_ids) = ergo_wallet::tx_ops::build_unsigned_tx(
        &payment_requests,
        body.fee,
        &change_address,
        &unspent,
        current_height,
    )
    .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let tx_bytes = ergo_wallet::tx_ops::serialize_unsigned_tx(&unsigned_tx)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let input_id_strs: Vec<String> = input_ids.iter().map(hex::encode).collect();

    Ok(Json(serde_json::json!({
        "bytes": hex::encode(&tx_bytes),
        "inputIds": input_id_strs,
    })))
}

/// `POST /wallet/transaction/sign` — sign an existing unsigned transaction.
///
/// Expects `WalletSignRequest` with a `tx` field containing hex-encoded
/// unsigned transaction bytes. Signs using wallet keys and returns the
/// signed transaction bytes.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/transaction/sign",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Sign transaction", body = Object)
    )
)]
pub(crate) async fn wallet_tx_sign_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletSignRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;

    // Parse the hex-encoded unsigned transaction bytes.
    //
    // The "bytes to sign" format is a Transaction with empty proofs.
    // We parse it as a Transaction, then reconstruct the UnsignedTransaction.
    use ergo_lib::ergotree_ir::serialization::SigmaSerializable;

    let tx_bytes = hex::decode(body.tx.trim())
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &format!("invalid hex: {e}")))?;

    let signed_format = ergo_lib::chain::transaction::Transaction::sigma_parse_bytes(&tx_bytes)
        .map_err(|e| {
            api_error(
                StatusCode::BAD_REQUEST,
                &format!("failed to parse tx bytes: {e}"),
            )
        })?;

    let unsigned_inputs: Vec<ergo_lib::chain::transaction::UnsignedInput> = signed_format
        .inputs
        .as_vec()
        .iter()
        .map(|inp| {
            ergo_lib::chain::transaction::UnsignedInput::new(
                inp.box_id,
                inp.spending_proof.extension.clone(),
            )
        })
        .collect();

    let data_inputs: Vec<ergo_lib::chain::transaction::DataInput> = signed_format
        .data_inputs
        .map(|di| di.as_vec().clone())
        .unwrap_or_default();

    let output_candidates: Vec<ergo_lib::ergotree_ir::chain::ergo_box::ErgoBoxCandidate> =
        signed_format.output_candidates.as_vec().clone();

    let unsigned_tx = ergo_lib::chain::transaction::unsigned::UnsignedTransaction::new_from_vec(
        unsigned_inputs,
        data_inputs,
        output_candidates,
    )
    .map_err(|e| {
        api_error(
            StatusCode::BAD_REQUEST,
            &format!("failed to build unsigned tx: {e}"),
        )
    })?;

    let keys = w
        .keys()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let unspent = w
        .unspent_boxes()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let num_addresses = w
        .addresses()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?
        .len() as u32;

    // Build sigma state context.
    let sigma_ctx = {
        let shared = state.shared.read().await;
        build_sigma_state_context(&state.history, &shared)?
    };

    // Derive key indices 0..num_addresses for signing.
    let key_indices: Vec<u32> = (0..num_addresses.max(1)).collect();

    // Filter unspent boxes to those matching the unsigned tx input IDs.
    let input_box_ids: std::collections::HashSet<[u8; 32]> = unsigned_tx
        .inputs
        .as_vec()
        .iter()
        .map(|inp| {
            let id_bytes: &[u8] = inp.box_id.as_ref();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(id_bytes);
            arr
        })
        .collect();
    let input_boxes: Vec<ergo_wallet::tracked_box::TrackedBox> = unspent
        .into_iter()
        .filter(|b| input_box_ids.contains(&b.box_id))
        .collect();

    let signed_bytes = ergo_wallet::tx_ops::sign_transaction(
        unsigned_tx,
        keys,
        &key_indices,
        &input_boxes,
        &[],
        &sigma_ctx,
    )
    .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    Ok(Json(serde_json::json!({
        "bytes": hex::encode(&signed_bytes),
    })))
}

/// `POST /wallet/transaction/send` — generate, sign, and broadcast a transaction.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/transaction/send",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Send signed transaction", body = Object)
    )
)]
pub(crate) async fn wallet_tx_send_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletGenerateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let _wallet = require_wallet(&state)?;

    let payment_requests = convert_payment_requests(&body.requests);
    let (signed_bytes, tx_id) = build_and_sign_tx(&state, &payment_requests, body.fee).await?;

    submit_signed_tx(&state, &signed_bytes, tx_id).await?;

    Ok(Json(serde_json::json!({
        "txId": hex::encode(tx_id),
    })))
}

/// `POST /wallet/getPrivateKey` -- return the hex-encoded secret key for a wallet address.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/getPrivateKey",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Get private key for address", body = Object)
    )
)]
pub(crate) async fn wallet_get_private_key_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletGetPrivateKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let secret_hex = w
        .get_private_key(&body.address)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!(secret_hex)))
}

/// `POST /wallet/generateCommitments` -- generate signing commitments for multi-party signing.
///
/// This is an advanced EIP-11 feature that requires `TransactionHintsBag` and related types
/// from ergo-lib. These types are not publicly exposed in ergo-lib 0.28, so this endpoint
/// returns 501 Not Implemented.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/generateCommitments",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Generate commitments", body = Object)
    )
)]
pub(crate) async fn wallet_generate_commitments_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(_body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let _wallet = require_wallet(&state)?;
    Err(api_error(
        StatusCode::NOT_IMPLEMENTED,
        "generateCommitments is not yet implemented (requires TransactionHintsBag from ergo-lib)",
    ))
}

/// `POST /wallet/extractHints` -- extract signing hints from a signed transaction.
///
/// This is an advanced EIP-11 feature that requires `TransactionHintsBag` and hint extraction
/// APIs from ergo-lib. These types are not publicly exposed in ergo-lib 0.28, so this endpoint
/// returns 501 Not Implemented.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/wallet/extractHints",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Extract hints from transaction", body = Object)
    )
)]
pub(crate) async fn wallet_extract_hints_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(_body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let _wallet = require_wallet(&state)?;
    Err(api_error(
        StatusCode::NOT_IMPLEMENTED,
        "extractHints is not yet implemented (requires TransactionHintsBag from ergo-lib)",
    ))
}

/// `GET /wallet/transactionsByScanId/{scanId}` -- get wallet transactions for a scan.
#[cfg(feature = "wallet")]
#[utoipa::path(
    get,
    path = "/wallet/transactionsByScanId/{scanId}",
    tag = "wallet",
    params(
        ("scanId" = String, Path, description = "scanId")
    ),
    responses(
        (status = 200, description = "Get transactions by scan ID", body = Object)
    )
)]
pub(crate) async fn wallet_txs_by_scan_id_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Path(scan_id): Path<u16>,
) -> Result<Json<Vec<WalletTransactionResponse>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let txs = w
        .get_txs_by_scan_id(scan_id)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let current_height = state.shared.read().await.full_height;
    let response: Vec<WalletTransactionResponse> = txs
        .iter()
        .map(|tx| {
            let num_confirmations = if current_height >= tx.inclusion_height as u64 {
                (current_height - tx.inclusion_height as u64) as u32
            } else {
                0
            };
            WalletTransactionResponse {
                id: hex::encode(tx.tx_id),
                inclusion_height: tx.inclusion_height,
                num_confirmations,
            }
        })
        .collect();
    Ok(Json(response))
}

/// `POST /scan/register` — register a new user-defined scan.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/scan/register",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Register new scan", body = Object)
    )
)]
pub(crate) async fn scan_register_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<ScanRegisterRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    let scan_id = w
        .register_scan(
            body.scan_name,
            body.tracking_rule,
            body.wallet_interaction,
            body.remove_offchain,
        )
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "scanId": scan_id })))
}

/// `POST /scan/deregister` — deregister a user-defined scan.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/scan/deregister",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Deregister scan", body = Object)
    )
)]
pub(crate) async fn scan_deregister_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<ScanDeregisterRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    w.deregister_scan(body.scan_id)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "scanId": body.scan_id })))
}

/// `GET /scan/listAll` — list all registered scans.
#[cfg(feature = "wallet")]
#[utoipa::path(
    get,
    path = "/scan/listAll",
    tag = "wallet",
    responses(
        (status = 200, description = "List all scans", body = Object)
    )
)]
pub(crate) async fn scan_list_all_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let scans = w
        .list_scans()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let json_scans: Vec<serde_json::Value> = scans
        .iter()
        .map(|s| serde_json::to_value(s).unwrap_or_default())
        .collect();
    Ok(Json(serde_json::json!(json_scans)))
}

/// `GET /scan/unspentBoxes/{scanId}` — get unspent boxes for a scan.
#[cfg(feature = "wallet")]
#[utoipa::path(
    get,
    path = "/scan/unspentBoxes/{scanId}",
    tag = "wallet",
    params(
        ("scanId" = String, Path, description = "scanId")
    ),
    responses(
        (status = 200, description = "Unspent boxes for scan", body = Object)
    )
)]
pub(crate) async fn scan_unspent_boxes_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Path(scan_id): Path<u16>,
) -> Result<Json<Vec<WalletBoxResponse>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let boxes = w
        .unspent_boxes_for_scan(scan_id)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let response: Vec<WalletBoxResponse> = boxes.iter().map(tracked_box_to_response).collect();
    Ok(Json(response))
}

/// `GET /scan/spentBoxes/{scanId}` — get spent boxes for a scan.
#[cfg(feature = "wallet")]
#[utoipa::path(
    get,
    path = "/scan/spentBoxes/{scanId}",
    tag = "wallet",
    params(
        ("scanId" = String, Path, description = "scanId")
    ),
    responses(
        (status = 200, description = "Spent boxes for scan", body = Object)
    )
)]
pub(crate) async fn scan_spent_boxes_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Path(scan_id): Path<u16>,
) -> Result<Json<Vec<WalletBoxResponse>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let boxes = w
        .spent_boxes_for_scan(scan_id)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let response: Vec<WalletBoxResponse> = boxes.iter().map(tracked_box_to_response).collect();
    Ok(Json(response))
}

/// `POST /scan/stopTracking` — stop tracking a box for a scan.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/scan/stopTracking",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Stop tracking box", body = Object)
    )
)]
pub(crate) async fn scan_stop_tracking_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<ScanStopTrackingRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    let box_id = hex_to_32bytes(&body.box_id).map_err(|(code, msg)| api_error(code, &msg))?;
    w.stop_tracking(body.scan_id, &box_id)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({
        "scanId": body.scan_id,
        "boxId": body.box_id,
    })))
}

/// `POST /scan/addBox` — add a box to one or more scans.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/scan/addBox",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Add box to scan", body = Object)
    )
)]
pub(crate) async fn scan_add_box_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<ScanAddBoxRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    let box_id = hex_to_32bytes(&body.box_id).map_err(|(code, msg)| api_error(code, &msg))?;
    let ergo_tree_bytes = hex::decode(&body.ergo_tree)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex in ergoTree"))?;
    let tracked_box = ergo_wallet::tracked_box::TrackedBox {
        box_id,
        ergo_tree_bytes,
        value: body.value,
        tokens: vec![],
        creation_height: body.creation_height,
        inclusion_height: body.inclusion_height,
        tx_id: [0u8; 32],
        output_index: 0,
        serialized_box: vec![],
        additional_registers: vec![],
        spent: false,
        spending_tx_id: None,
        spending_height: None,
        scan_ids: body.scan_ids.clone(),
    };
    w.add_box_to_scans(tracked_box, &body.scan_ids)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({
        "boxId": body.box_id,
        "scanIds": body.scan_ids,
    })))
}

/// `POST /scan/p2sRule` — register a scan with an ErgoTree-equals predicate
/// derived from a P2S/P2PK address.
#[cfg(feature = "wallet")]
#[utoipa::path(
    post,
    path = "/scan/p2sRule",
    tag = "wallet",
    request_body = Object,
    responses(
        (status = 200, description = "Create P2S tracking rule", body = Object)
    )
)]
pub(crate) async fn scan_p2s_rule_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<ScanP2sRuleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let tree_bytes = address_to_ergo_tree(&body.address, &state.network)
        .map_err(|(code, msg)| api_error(code, &msg))?;
    let predicate = ergo_wallet::scan_types::ScanningPredicate::Equals {
        register: "R1".to_owned(),
        value: hex::encode(&tree_bytes),
    };
    let mut w = wallet.write().await;
    let scan_id = w
        .register_scan(
            body.scan_name,
            predicate,
            ergo_wallet::scan_types::ScanWalletInteraction::Off,
            false,
        )
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "scanId": scan_id })))
}
