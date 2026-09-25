#![allow(clippy::result_large_err)]

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use ergo_ser::address::NetworkPrefix;
use ergo_wallet::address::pubkey_to_p2pk_address;
use ergo_wallet_service::{RescanState, WalletService, WalletTransaction};
use serde_json::{json, Value};

#[derive(Clone)]
pub struct ApiState {
    pub service: Arc<WalletService>,
}

pub fn router(service: Arc<WalletService>) -> Router {
    let state = ApiState { service };
    Router::new()
        .route("/status", get(status))
        .route("/balance", get(balance))
        .route("/balances", get(balance))
        .route("/boxes", get(boxes))
        .route("/boxes/:id", get(box_by_id))
        .route("/transactions", get(transactions))
        .route("/transactions/:id", get(transaction_by_id))
        .route("/scans", get(scans))
        .route("/scan/listAll", get(scans))
        .route("/addresses", get(addresses))
        .route("/api/v1/wallet/status", get(status))
        .route("/api/v1/wallet/balance", get(balance))
        .route("/api/v1/wallet/balances", get(balance))
        .route("/api/v1/wallet/boxes", get(boxes))
        .route("/api/v1/wallet/boxes/:id", get(box_by_id))
        .route("/api/v1/wallet/transactions", get(transactions))
        .route("/api/v1/wallet/transactions/:id", get(transaction_by_id))
        .route("/api/v1/wallet/addresses", get(addresses))
        .route("/api/v1/scans", get(scans))
        .route("/api/v1/scan/listAll", get(scans))
        .with_state(state)
}

async fn status(State(state): State<ApiState>) -> Result<Json<Value>, ApiError> {
    let service_for_tip = state.service.clone();
    let service = state.service;
    let local = tokio::task::spawn_blocking(move || {
        let read = service.store().read()?;
        let cursor = read.scan_cursor()?;
        let state = read.rescan_state()?;
        let invalidated = read.scan_invalidated()?;
        Ok::<_, ergo_wallet_service::WalletServiceError>((cursor, state, invalidated))
    })
    .await
    .map_err(|_| ApiError::internal("status task failed".to_string()))??;
    let tip = tokio::task::spawn_blocking(move || {
        service_for_tip
            .chain()
            .committed_tip()
            .ok()
            .map(|tip| tip_json(&tip))
    })
    .await
    .ok()
    .flatten();
    let rescan_state = match local.1 {
        RescanState::Idle => "idle".to_string(),
        RescanState::Running { .. } => "running".to_string(),
        RescanState::Failed { .. } => "failed".to_string(),
    };
    Ok(Json(json!({
        "walletHeight": local.0.map(|cursor| cursor.height).unwrap_or(0),
        "tip": tip,
        "rescanState": rescan_state,
        "scanInvalidated": local.2,
    })))
}

async fn balance(State(state): State<ApiState>) -> Result<Json<Value>, ApiError> {
    let service = state.service;
    let value = tokio::task::spawn_blocking(move || service.confirmed_balance())
        .await
        .map_err(|_| ApiError::internal("balance task failed".to_string()))??;
    Ok(Json(balance_json(&value)))
}

async fn boxes(State(state): State<ApiState>) -> Result<Json<Value>, ApiError> {
    let service = state.service;
    let values = tokio::task::spawn_blocking(move || service.confirmed_boxes())
        .await
        .map_err(|_| ApiError::internal("boxes task failed".to_string()))??;
    Ok(Json(json!(values
        .into_iter()
        .map(|value| box_json(&value))
        .collect::<Vec<_>>())))
}

async fn box_by_id(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = decode_id(&id)?;
    let service = state.service;
    let value = tokio::task::spawn_blocking(move || service.box_by_id(&id))
        .await
        .map_err(|_| ApiError::internal("box task failed".to_string()))??;
    value
        .map(|value| Json(box_json(&value)).into_response())
        .ok_or(ApiError::not_found("box not found"))
}

async fn transactions(State(state): State<ApiState>) -> Result<Json<Value>, ApiError> {
    let service = state.service;
    let values = tokio::task::spawn_blocking(move || service.transactions())
        .await
        .map_err(|_| ApiError::internal("transactions task failed".to_string()))??;
    Ok(Json(json!(values
        .into_iter()
        .map(|value| transaction_json(&value))
        .collect::<Vec<_>>())))
}

async fn transaction_by_id(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = decode_id(&id)?;
    let service = state.service;
    let value = tokio::task::spawn_blocking(move || service.transaction_by_id(&id))
        .await
        .map_err(|_| ApiError::internal("transaction task failed".to_string()))??;
    value
        .map(|value| Json(transaction_json(&value)).into_response())
        .ok_or(ApiError::not_found("transaction not found"))
}

async fn scans(State(state): State<ApiState>) -> Result<Json<Value>, ApiError> {
    let service = state.service;
    let values = tokio::task::spawn_blocking(move || {
        let read = service.store().read()?;
        read.scan_registry()
    })
    .await
    .map_err(|_| ApiError::internal("scan task failed".to_string()))??;
    let mut result = Vec::with_capacity(values.scans.len());
    for scan in values.scans {
        let value: Value = serde_json::from_slice(&scan.json)
            .map_err(|_| ApiError::internal("stored scan is invalid".to_string()))?;
        result.push(json!({"id": scan.id, "scan": value}));
    }
    Ok(Json(json!(result)))
}

async fn addresses(State(state): State<ApiState>) -> Result<Json<Value>, ApiError> {
    let service = state.service;
    let values = tokio::task::spawn_blocking(move || {
        let read = service.store().read()?;
        read.tracked_addresses_with_meta()
    })
    .await
    .map_err(|_| ApiError::internal("address task failed".to_string()))??;
    let mut result = Vec::with_capacity(values.len());
    for item in values {
        let address = pubkey_to_p2pk_address(&item.pubkey, NetworkPrefix::Mainnet)
            .map_err(|_| ApiError::internal("stored public key is invalid".to_string()))?;
        result.push(json!({
            "index": item.path_idx,
            "path": item.derivation_path,
            "publicKey": hex::encode(item.pubkey),
            "address": address,
            "label": item.label,
            "addedAtHeight": item.added_at_height,
        }));
    }
    Ok(Json(json!(result)))
}

fn decode_id(value: &str) -> Result<[u8; 32], ApiError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad_request("id must be lowercase 32-byte hex"));
    }
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ApiError::bad_request("id must be lowercase 32-byte hex"))
}

fn tip_json(value: &ergo_wallet_service::CommittedTip) -> Value {
    json!({
        "height": value.height,
        "headerId": hex::encode(value.header_id),
    })
}

fn balance_json(value: &ergo_wallet_service::Balance) -> Value {
    json!({
        "confirmedNanoErgs": value.confirmed_nano_ergs,
        "immatureNanoErgs": value.immature_nano_ergs,
        "tokens": value.tokens.iter().map(|(id, amount)| json!({
            "tokenId": hex::encode(id),
            "amount": amount.to_string(),
        })).collect::<Vec<_>>(),
    })
}

fn box_json(value: &ergo_wallet_service::WalletBox) -> Value {
    json!({
        "boxId": hex::encode(value.box_id),
        "creationTxId": hex::encode(value.creation_tx_id),
        "creationOutputIndex": value.creation_output_index,
        "creationHeight": value.creation_height,
        "value": value.value.to_string(),
        "assets": value.assets.iter().map(|(id, amount)| json!({
            "tokenId": hex::encode(id),
            "amount": amount.to_string(),
        })).collect::<Vec<_>>(),
        "status": format!("{:?}", value.status),
        "provenance": format!("{:?}", value.provenance),
    })
}

fn transaction_json(value: &WalletTransaction) -> Value {
    json!({
        "txId": hex::encode(value.tx_id),
        "blockHeight": value.block_height,
        "blockId": hex::encode(value.block_id),
        "walletOutputs": value.wallet_outputs.iter().map(hex::encode).collect::<Vec<_>>(),
        "walletInputs": value.wallet_inputs.iter().map(hex::encode).collect::<Vec<_>>(),
    })
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl From<ergo_wallet_service::WalletServiceError> for ApiError {
    fn from(error: ergo_wallet_service::WalletServiceError) -> Self {
        Self::internal(error.to_string())
    }
}

impl From<ergo_wallet_service::WalletStoreError> for ApiError {
    fn from(error: ergo_wallet_service::WalletStoreError) -> Self {
        Self::internal(error.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.message}))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_wallet_service::{ChainClient, RedbWalletStore, WalletService};
    use tower::ServiceExt;

    struct NoChain;
    impl ChainClient for NoChain {
        fn committed_tip(
            &self,
        ) -> Result<ergo_wallet_service::CommittedTip, ergo_wallet_service::ChainClientError>
        {
            Err(ergo_wallet_service::ChainClientError::Unsupported)
        }
        fn snapshot(
            &self,
        ) -> Result<ergo_wallet_service::ChainSnapshot, ergo_wallet_service::ChainClientError>
        {
            Err(ergo_wallet_service::ChainClientError::Unsupported)
        }
        fn blocks_since(
            &self,
            _: ergo_wallet_service::BlocksSinceRequest,
        ) -> Result<ergo_wallet_service::BlocksSinceResponse, ergo_wallet_service::ChainClientError>
        {
            Err(ergo_wallet_service::ChainClientError::Unsupported)
        }
        fn lookup_utxo(
            &self,
            _: [u8; 32],
            _: ergo_wallet_service::CommittedTip,
        ) -> Result<ergo_wallet_service::UtxoLookup, ergo_wallet_service::ChainClientError>
        {
            Err(ergo_wallet_service::ChainClientError::Unsupported)
        }
        fn submit(
            &self,
            _: ergo_wallet_service::SubmitRequest,
        ) -> Result<ergo_wallet_service::SubmitResponse, ergo_wallet_service::ChainClientError>
        {
            Err(ergo_wallet_service::ChainClientError::Unsupported)
        }
    }

    #[tokio::test]
    async fn exposes_only_read_routes() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
        let service = Arc::new(WalletService::new(store, Arc::new(NoChain)));
        let app = router(service);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/wallet/balance")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        for route in [
            "/unlock",
            "/init",
            "/restore",
            "/send",
            "/sign",
            "/multisig",
            "/ws",
        ] {
            let response = router(Arc::new(WalletService::new(
                Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap()),
                Arc::new(NoChain),
            )))
            .oneshot(
                axum::http::Request::builder()
                    .uri(route)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }
}
