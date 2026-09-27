#![allow(clippy::result_large_err)]

use std::sync::Arc;
use std::time::Duration;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use ergo_wallet::address::pubkey_to_p2pk_address;
use ergo_wallet_protocol::chain::{ChainCursor as WireCursor, ChainTip as WireTip};
use ergo_wallet_protocol::native::dto::{
    AddressPage, BoxPage, BoxProvenanceDto, BoxStatusDto, NanoErgBreakdownDto, RescanStateDto,
    SyncStateDto, TxPage, WalletAddressDto, WalletAssetDto, WalletBalanceDto, WalletBoxSummary,
    WalletTransactionSummary, WatchOnlyWalletStatusDto,
};
use ergo_wallet_protocol::scala::scan::ScanDto;
use ergo_wallet_service::{
    Balance, BoxProvenance, BoxStatus, RescanState, WalletBox, WalletService, WalletTransaction,
};
use serde::Deserialize;

use crate::config::Network;
use crate::tip::CachedNodeTip;

/// Everything a local read route needs. The daemon is read-only, so this is
/// the complete surface: the wallet service, the network that decides address
/// rendering, and the cached node tip so a read never blocks on a chain probe.
#[derive(Clone)]
pub struct ApiContext {
    pub service: Arc<WalletService>,
    /// Network identity from config. Every base58 address this API returns is
    /// rendered with this network's prefix.
    pub network: Network,
    /// Last tip observed by the sync loop, with a capped probe as fallback.
    pub tip: Arc<CachedNodeTip>,
    /// How long a cached tip stays fresh before a read probes the node.
    pub tip_max_age: Duration,
}

impl ApiContext {
    /// Default freshness window for a cached tip: two sync intervals, so a
    /// healthy sync loop never makes a read probe, and a stalled one is
    /// detected within a couple of cycles.
    pub fn default_tip_max_age(sync_interval: Duration) -> Duration {
        sync_interval.saturating_mul(2).max(Duration::from_secs(30))
    }
}

#[derive(Clone)]
pub struct ApiState {
    context: ApiContext,
}

pub const READ_ROUTE_INVENTORY: &[&str] = &[
    "/status",
    "/balance",
    "/balances",
    "/boxes",
    "/boxes/:id",
    "/transactions",
    "/transactions/:id",
    "/scans",
    "/scan/listAll",
    "/addresses",
    "/api/v1/wallet/status",
    "/api/v1/wallet/balance",
    "/api/v1/wallet/balances",
    "/api/v1/wallet/boxes",
    "/api/v1/wallet/boxes/:id",
    "/api/v1/wallet/transactions",
    "/api/v1/wallet/transactions/:id",
    "/api/v1/wallet/addresses",
    "/api/v1/scans",
    "/api/v1/scan/listAll",
];

pub fn router(context: ApiContext) -> Router {
    let state = ApiState { context };
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

/// Status projection: the durable scan cursor, the node tip the sync loop last
/// observed, and the `lag` / `sync` state derived from them.
///
/// **Derived, not embedded.** `lag` and `sync` are computed here from the two
/// identities, `nodeTip` is served from a cache that may be up to two sync
/// intervals stale, and `rescan` is the daemon's own durable sync state. None of
/// it is a value the node serves, so it is not expected to match an embedded
/// wallet's `/wallet/status` field for field; see
/// `docs/codemap/ergo-walletd.md` "Known deviations" §2.
async fn status(State(state): State<ApiState>) -> Result<Json<WatchOnlyWalletStatusDto>, ApiError> {
    let context = state.context;
    let local_service = context.service.clone();
    let local = tokio::task::spawn_blocking(move || {
        let read = local_service.store().read()?;
        Ok::<_, ergo_wallet_service::WalletStoreError>((
            read.scan_cursor()?,
            read.rescan_state()?,
            read.scan_invalidated()?,
        ))
    })
    .await
    .map_err(|_| ApiError::internal("status task failed".to_string()))??;
    // Served from the sync loop's last observation; only a stale or missing
    // cache pays for a probe, and that probe is bounded (see `tip::CachedNodeTip`).
    let tip = {
        let tip = context.tip.clone();
        let max_age = context.tip_max_age;
        tokio::task::spawn_blocking(move || tip.tip_within(max_age, crate::tip::PROBE_TIMEOUT))
            .await
            .ok()
            .flatten()
    };
    let cursor = local.0.map(|cursor| WireCursor {
        height: cursor.height,
        header_id: cursor
            .header_id
            .map(hex::encode)
            .unwrap_or_else(|| ergo_wallet_protocol::chain::GENESIS_CURSOR_ID.to_string()),
    });
    let node_tip = tip.as_ref().map(|tip| WireTip {
        height: tip.height,
        header_id: hex::encode(tip.header_id),
    });
    let cursor_height = local.0.map(|cursor| cursor.height).unwrap_or(0);
    let lag = tip
        .as_ref()
        .map(|tip| tip.height.saturating_sub(cursor_height))
        .unwrap_or(0);
    let rescan = rescan_dto(&local.1);
    let sync = if matches!(local.1, RescanState::Failed { .. }) {
        SyncStateDto::Failed
    } else if tip.is_none() {
        SyncStateDto::Unavailable {
            detail: "node tip is unavailable".to_string(),
        }
    } else if local.2 {
        SyncStateDto::Rebuilding
    } else if matches!(local.1, RescanState::Running { .. }) {
        SyncStateDto::Syncing
    } else if lag == 0 {
        SyncStateDto::AtTip
    } else {
        SyncStateDto::CatchingUp
    };
    Ok(Json(WatchOnlyWalletStatusDto {
        scan_cursor: cursor,
        node_tip,
        lag,
        scan_invalidated: local.2,
        rescan,
        sync,
    }))
}

async fn balance(State(state): State<ApiState>) -> Result<Json<WalletBalanceDto>, ApiError> {
    let service = state.context.service;
    let value = tokio::task::spawn_blocking(move || {
        let balance = service.confirmed_balance()?;
        let height = service
            .store()
            .read()?
            .scan_cursor()?
            .map(|cursor| cursor.height)
            .unwrap_or(0);
        Ok::<_, ergo_wallet_service::WalletServiceError>((balance, height))
    })
    .await
    .map_err(|_| ApiError::internal("balance task failed".to_string()))??;
    Ok(Json(balance_dto(&value.0, value.1)))
}

async fn boxes(
    State(state): State<ApiState>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Json<BoxPage>, ApiError> {
    let (offset, limit) = page_bounds(query)?;
    let service = state.context.service;
    let (mut values, as_of) = tokio::task::spawn_blocking(move || {
        let values = service.confirmed_boxes()?;
        let as_of = service
            .store()
            .read()?
            .scan_cursor()?
            .map(|cursor| cursor.height)
            .unwrap_or(0);
        Ok::<_, ergo_wallet_service::WalletServiceError>((values, as_of))
    })
    .await
    .map_err(|_| ApiError::internal("boxes task failed".to_string()))??;
    values.sort_by(|left, right| {
        right
            .creation_height
            .cmp(&left.creation_height)
            .then_with(|| right.box_id.cmp(&left.box_id))
    });
    let total = values.len() as u32;
    let items = values
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(|value| box_dto(&value))
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(BoxPage {
        items,
        total,
        as_of,
    }))
}

async fn box_by_id(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = decode_id(&id)?;
    let service = state.context.service;
    let value = tokio::task::spawn_blocking(move || service.confirmed_box_by_id(&id))
        .await
        .map_err(|_| ApiError::internal("box task failed".to_string()))??;
    match value {
        Some(value) => Ok(Json(box_dto(&value)?).into_response()),
        None => Err(ApiError::not_found("box_not_found")),
    }
}

async fn transactions(
    State(state): State<ApiState>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Json<TxPage>, ApiError> {
    let (offset, limit) = page_bounds(query)?;
    let service = state.context.service;
    let (mut values, as_of) = tokio::task::spawn_blocking(move || {
        let values = service.transactions()?;
        let as_of = service
            .store()
            .read()?
            .scan_cursor()?
            .map(|cursor| cursor.height)
            .unwrap_or(0);
        Ok::<_, ergo_wallet_service::WalletServiceError>((values, as_of))
    })
    .await
    .map_err(|_| ApiError::internal("transactions task failed".to_string()))??;
    values.sort_by(|left, right| {
        right
            .block_height
            .cmp(&left.block_height)
            .then_with(|| right.tx_id.cmp(&left.tx_id))
    });
    let total = values.len() as u32;
    let items = values
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(|value| transaction_dto(&value))
        .collect();
    Ok(Json(TxPage {
        items,
        total,
        as_of,
    }))
}

async fn transaction_by_id(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = decode_id(&id)?;
    let service = state.context.service;
    let value = tokio::task::spawn_blocking(move || service.transaction_by_id(&id))
        .await
        .map_err(|_| ApiError::internal("transaction task failed".to_string()))??;
    value
        .map(|value| Json(transaction_dto(&value)).into_response())
        .ok_or(ApiError::not_found("tx_not_found"))
}

async fn scans(State(state): State<ApiState>) -> Result<Json<Vec<ScanDto>>, ApiError> {
    let service = state.context.service;
    let values = tokio::task::spawn_blocking(move || service.store().read()?.scan_registry())
        .await
        .map_err(|_| ApiError::internal("scan task failed".to_string()))??;
    values
        .scans
        .into_iter()
        .map(|scan| {
            serde_json::from_slice::<ScanDto>(&scan.json)
                .map_err(|_| ApiError::internal("stored scan is invalid".to_string()))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

async fn addresses(
    State(state): State<ApiState>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Json<AddressPage>, ApiError> {
    let (offset, limit) = page_bounds(query)?;
    let service = state.context.service;
    let network = state.context.network;
    let (mut values, as_of) = tokio::task::spawn_blocking(move || {
        let values = service.store().read()?.tracked_addresses_with_meta()?;
        let as_of = service
            .store()
            .read()?
            .scan_cursor()?
            .map(|cursor| cursor.height)
            .unwrap_or(0);
        Ok::<_, ergo_wallet_service::WalletStoreError>((values, as_of))
    })
    .await
    .map_err(|_| ApiError::internal("address task failed".to_string()))??;
    values.sort_by_key(|value| value.path_idx);
    let total = values.len() as u32;
    let items = values
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(|value| {
            // Rendered for the configured network, never baked into storage.
            let address = pubkey_to_p2pk_address(&value.pubkey, network.prefix())
                .map_err(|_| ApiError::internal("stored public key is invalid".to_string()))?;
            Ok(WalletAddressDto {
                address,
                derivation_path: format_derivation_path(&value.derivation_path),
                index: value.path_idx,
                label: (!value.label.is_empty()).then_some(value.label),
                added_at_height: value.added_at_height,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(AddressPage {
        items,
        total,
        as_of,
    }))
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageQuery {
    #[serde(default)]
    offset: u32,
    #[serde(default = "default_page_limit")]
    limit: u32,
}

fn default_page_limit() -> u32 {
    50
}

fn page_bounds(query: Result<Query<PageQuery>, QueryRejection>) -> Result<(u32, u32), ApiError> {
    let Query(query) = query.map_err(|error| ApiError::bad_request(error.to_string()))?;
    if query.limit == 0 || query.limit > 16_384 {
        return Err(ApiError::bad_request("limit must be between 1 and 16384"));
    }
    Ok((query.offset, query.limit))
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

fn rescan_dto(state: &RescanState) -> RescanStateDto {
    match state {
        RescanState::Idle => RescanStateDto::Idle,
        RescanState::Running { from_height } => RescanStateDto::Running {
            from_height: *from_height,
        },
        RescanState::Failed { height, reason } => RescanStateDto::Failed {
            height: *height,
            reason: reason.clone(),
        },
    }
}

/// Project the wallet's confirmed balance into the wire DTO.
///
/// **This is a projection, not a re-serve of the embedded wallet's values.**
/// `available` is deliberately the same number as `confirmed` (there is no
/// reservation concept on this read path), `reserved` and `immature` are literal
/// zeros rather than independently-sourced quantities, and `unconfirmed` /
/// `reemission` are `null` because the daemon has neither. `height` is the
/// wallet's durable scan cursor, not the node tip, so a lagging wallet reports
/// an older height than the chain has. A caller diffing this against an embedded
/// wallet's `/wallet/balance` is comparing two different projections, not two
/// views of one value; see `docs/codemap/ergo-walletd.md` "Known deviations" §2.
fn balance_dto(value: &Balance, height: u32) -> WalletBalanceDto {
    WalletBalanceDto {
        height,
        nano_erg: NanoErgBreakdownDto {
            confirmed: value.confirmed_nano_ergs.to_string(),
            available: value.confirmed_nano_ergs.to_string(),
            reserved: "0".to_string(),
            immature: "0".to_string(),
        },
        assets: value
            .tokens
            .iter()
            .map(|(token_id, amount)| WalletAssetDto {
                token_id: hex::encode(token_id),
                amount: amount.to_string(),
            })
            .collect(),
        reemission: None,
        unconfirmed: None,
    }
}

fn box_dto(value: &WalletBox) -> Result<WalletBoxSummary, ApiError> {
    Ok(WalletBoxSummary {
        box_id: hex::encode(value.box_id),
        value: value.value.to_string(),
        assets: value
            .assets
            .iter()
            .map(|(token_id, amount)| WalletAssetDto {
                token_id: hex::encode(token_id),
                amount: amount.to_string(),
            })
            .collect(),
        creation_tx_id: hex::encode(value.creation_tx_id),
        creation_output_index: value.creation_output_index,
        creation_height: value.creation_height,
        status: match value.status {
            BoxStatus::Confirmed => BoxStatusDto::Confirmed,
            BoxStatus::Immature { matures_at } => BoxStatusDto::Immature {
                matures_at_height: matures_at,
            },
            BoxStatus::Spent {
                spent_in_tx,
                spent_at,
            } => BoxStatusDto::Spent {
                tx_id: hex::encode(spent_in_tx),
                height: spent_at,
            },
        },
        provenance: match value.provenance {
            BoxProvenance::Owned => BoxProvenanceDto::Owned,
            BoxProvenance::MinerReward => BoxProvenanceDto::MinerReward,
            BoxProvenance::Custom { scan_id } => BoxProvenanceDto::Custom {
                scan_id: u16::try_from(scan_id).map_err(|_| {
                    ApiError::internal("stored custom scan id is out of range".to_string())
                })?,
            },
        },
    })
}

fn transaction_dto(value: &WalletTransaction) -> WalletTransactionSummary {
    WalletTransactionSummary {
        tx_id: hex::encode(value.tx_id),
        block_id: hex::encode(value.block_id),
        block_height: value.block_height,
        wallet_input_box_ids: value
            .wallet_inputs
            .iter()
            .copied()
            .map(hex::encode)
            .collect(),
        wallet_output_box_ids: value
            .wallet_outputs
            .iter()
            .copied()
            .map(hex::encode)
            .collect(),
    }
}

fn format_derivation_path(path: &[u32]) -> String {
    let mut result = String::from("m");
    for component in path {
        result.push('/');
        if *component & 0x8000_0000 != 0 {
            result.push_str(&(*component & 0x7fff_ffff).to_string());
            result.push('\'');
        } else {
            result.push_str(&component.to_string());
        }
    }
    result
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    reason: &'static str,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            reason: "bad_request",
            message: message.into(),
        }
    }

    fn not_found(reason: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            reason,
            message: "the requested wallet record is not available".to_string(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            reason: "internal_error",
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
        (
            self.status,
            Json(ergo_wallet_protocol::native::error::NativeWalletError {
                reason: self.reason.to_string(),
                detail: Some(self.message),
            }),
        )
            .into_response()
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

    const KEY: &str = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";

    fn context(dir: &tempfile::TempDir, network: Network) -> ApiContext {
        let store =
            Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
        let chain: Arc<dyn ChainClient> = Arc::new(NoChain);
        let tip = Arc::new(CachedNodeTip::new(chain.clone()));
        ApiContext {
            service: Arc::new(WalletService::new(store, chain)),
            network,
            tip,
            tip_max_age: ApiContext::default_tip_max_age(Duration::from_secs(15)),
        }
    }

    fn app(dir: &tempfile::TempDir) -> Router {
        router(context(dir, Network::Mainnet))
    }

    fn app_with_network(dir: &tempfile::TempDir, network: Network) -> Router {
        router(context(dir, network))
    }

    fn tracked(dir: &tempfile::TempDir, network: Network) {
        let entries = crate::descriptor::parse_text(
            &format!(r#"keys=[{{path="m/44'/429'/0'/0/0",public_key="{KEY}"}}]"#),
            network,
        )
        .unwrap();
        let store = RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap();
        crate::descriptor::import(&store, &entries).unwrap();
    }

    async fn address_of(app: Router) -> String {
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/wallet/addresses")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        value["items"][0]["address"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn addresses_are_rendered_for_the_configured_network() {
        let mainnet_dir = tempfile::tempdir().unwrap();
        tracked(&mainnet_dir, Network::Mainnet);
        let mainnet = address_of(app_with_network(&mainnet_dir, Network::Mainnet)).await;

        let testnet_dir = tempfile::tempdir().unwrap();
        tracked(&testnet_dir, Network::Testnet);
        let testnet = address_of(app_with_network(&testnet_dir, Network::Testnet)).await;

        assert_ne!(mainnet, testnet, "network must change address rendering");
        assert!(testnet.starts_with('3'), "testnet P2PK: {testnet}");
        assert!(mainnet.starts_with('9'), "mainnet P2PK: {mainnet}");
        // The same descriptor, rendered on the wrong network, is a different
        // address: the store keeps pubkeys, so only the prefix changes.
        let wrong = address_of(app_with_network(&testnet_dir, Network::Mainnet)).await;
        assert_eq!(wrong, mainnet);
    }

    #[tokio::test]
    async fn read_routes_are_confirmed_only_and_use_protocol_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let response = app(&dir)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/wallet/balance")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(value["nanoErg"].is_object());
        assert!(value["nanoErg"]["confirmed"].is_string());
        let response = app(&dir)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/wallet/boxes/not-an-id")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    async fn status_of(context: ApiContext) -> serde_json::Value {
        let response = router(context)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/wallet/status")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    /// `/status` must not probe the node on every read: it serves the tip the
    /// sync loop last observed. `NoChain` cannot answer a tip probe at all, so
    /// a reported tip can only have come from the cache.
    #[tokio::test]
    async fn status_serves_the_cached_tip_and_degrades_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let context = context(&dir, Network::Mainnet);
        assert!(context.tip.cached().is_none());
        let value = status_of(context.clone()).await;
        assert!(value["nodeTip"].is_null(), "no cache and no probe: {value}");
        assert_eq!(value["sync"]["type"], "unavailable");

        context
            .tip
            .record(ergo_wallet_service::CommittedTip::new(12, [12; 32]));
        for _ in 0..3 {
            let value = status_of(context.clone()).await;
            assert_eq!(value["nodeTip"]["height"], 12, "{value}");
            assert_eq!(
                hex::decode(value["nodeTip"]["headerId"].as_str().unwrap()).unwrap(),
                vec![12u8; 32]
            );
        }
        // A zero freshness window forces the capped probe path, which fails
        // against NoChain and degrades to "unavailable" instead of blocking.
        let mut stale = context.clone();
        stale.tip_max_age = Duration::ZERO;
        let value = status_of(stale).await;
        assert!(value["nodeTip"].is_null(), "{value}");
        assert_eq!(value["sync"]["type"], "unavailable");
    }

    #[tokio::test]
    async fn mutating_and_secret_routes_are_absent() {
        let dir = tempfile::tempdir().unwrap();
        for route in [
            "/unlock",
            "/init",
            "/restore",
            "/send",
            "/sign",
            "/private-key",
            "/multisig",
            "/ws",
            "/api/v1/wallet/unlock",
            "/api/v1/wallet/init",
            "/api/v1/wallet/restore",
            "/api/v1/wallet/send",
            "/api/v1/wallet/sign",
            "/api/v1/wallet/ws",
        ] {
            let response = app(&dir)
                .oneshot(
                    axum::http::Request::builder()
                        .uri(route)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{route}");
        }
    }
}
