#![allow(clippy::result_large_err)]

pub(crate) mod dto;
pub mod error;
pub(crate) mod network;
pub mod openapi;
pub mod runtime;

use std::str::FromStr;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::{
    rejection::{BytesRejection, FailedToBufferBody, JsonRejection, QueryRejection},
    DefaultBodyLimit, Path, Query, Request, State,
};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use ergo_api_core::chain::{ChainArchive, HeaderQuery, SortOrder, MAX_RECENT_HEADERS};
use ergo_api_core::id::{HeaderId, TxId};
use ergo_api_core::indexer::{IndexerStatusSnapshot, IndexerStatusSource};
pub use ergo_api_core::network::{
    NetworkSnapshot, PeerChainStatus, PeerDirection, PeerSnapshotSource, PeerState,
};
use ergo_api_core::node::NodeSnapshotSource;
use ergo_api_core::observability::{
    EventSource, HostStatus, HostStatusSource, RecentBlockSource, DEFAULT_RECENT_BLOCK_COUNT,
    MAX_RECENT_BLOCK_COUNT,
};
use ergo_api_core::page::{Cursor, PageRequest};
use ergo_api_core::transaction::{
    AdmissionDisposition, SubmissionMode, TransactionError, TransactionReader, TransactionSubmitter,
};
use ergo_ser::address::NetworkPrefix;
use serde::{Deserialize, Deserializer};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use utoipa::IntoParams;

pub use dto::{
    BlockSummaryView, BlockView, CapabilityView, ChainTipView, DifficultyPointView,
    DifficultySeriesView, EventFeedView, EventView, HeaderPage, HeaderView, HealthView,
    HostStatusView, HostView, IndexerRepairView, IndexerStatusView, IndexerTotalsView,
    MinerStatView, MinerStatsView, NetworkBlacklistedPage, NetworkBlacklistedView, NetworkPage,
    NetworkPeerPage, NetworkPeerView, NetworkSyncInfoPage, NetworkSyncInfoView,
    NetworkTrackInfoView, NodeIdentityView, NodeInfoView, NodeStatusView, NodeView,
    ProtocolChangeView, ProtocolHistoryView, ProtocolParamView, RecentBlockView, SyncStatusView,
    TransactionStatusView,
};
pub use network::router as network_router;
pub use runtime::{
    NativeRuntime, RuntimeConfig, RuntimeConfigError, MAX_COMPUTE_CONCURRENCY, MAX_PAGE_SIZE,
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};

pub struct NativeState {
    pub snapshot: Arc<dyn NodeSnapshotSource>,
    pub chain: Option<Arc<dyn ChainArchive>>,
    pub transactions: Option<Arc<dyn TransactionSubmitter>>,
    pub transaction_reader: Option<Arc<dyn TransactionReader>>,
    pub indexer: Option<Arc<dyn IndexerStatusSource>>,
    pub peers: Option<Arc<dyn PeerSnapshotSource>>,
    pub recent_blocks: Option<Arc<dyn RecentBlockSource>>,
    pub events: Option<Arc<dyn EventSource>>,
    pub host: Option<Arc<dyn HostStatusSource>>,
    network: NetworkPrefix,
    config: RuntimeConfig,
    compute_gate: Arc<Semaphore>,
}

impl Clone for NativeState {
    fn clone(&self) -> Self {
        Self {
            snapshot: self.snapshot.clone(),
            chain: self.chain.clone(),
            transactions: self.transactions.clone(),
            transaction_reader: self.transaction_reader.clone(),
            indexer: self.indexer.clone(),
            peers: self.peers.clone(),
            recent_blocks: self.recent_blocks.clone(),
            events: self.events.clone(),
            host: self.host.clone(),
            network: self.network,
            config: self.config.clone(),
            compute_gate: self.compute_gate.clone(),
        }
    }
}

impl NativeState {
    pub fn new(snapshot: Arc<dyn NodeSnapshotSource>) -> Self {
        let config = RuntimeConfig::default();
        Self {
            snapshot,
            chain: None,
            transactions: None,
            transaction_reader: None,
            indexer: None,
            peers: None,
            recent_blocks: None,
            events: None,
            host: None,
            network: NetworkPrefix::Mainnet,
            compute_gate: Arc::new(Semaphore::new(config.compute_concurrency)),
            config,
        }
    }

    pub fn with_chain(mut self, chain: Arc<dyn ChainArchive>) -> Self {
        self.chain = Some(chain);
        self
    }

    pub fn with_network(mut self, network: NetworkPrefix) -> Self {
        self.network = network;
        self
    }

    pub fn with_transactions(mut self, transactions: Arc<dyn TransactionSubmitter>) -> Self {
        self.transactions = Some(transactions);
        self
    }

    pub fn with_transaction_reader(
        mut self,
        transaction_reader: Arc<dyn TransactionReader>,
    ) -> Self {
        self.transaction_reader = Some(transaction_reader);
        self
    }

    pub fn with_indexer(mut self, indexer: Arc<dyn IndexerStatusSource>) -> Self {
        self.indexer = Some(indexer);
        self
    }

    pub fn with_peers(mut self, peers: Arc<dyn PeerSnapshotSource>) -> Self {
        self.peers = Some(peers);
        self
    }

    pub fn with_peer_source(self, peers: Arc<dyn PeerSnapshotSource>) -> Self {
        self.with_peers(peers)
    }

    pub fn with_peer_snapshot_source(self, peers: Arc<dyn PeerSnapshotSource>) -> Self {
        self.with_peers(peers)
    }

    pub fn with_network_source(self, peers: Arc<dyn PeerSnapshotSource>) -> Self {
        self.with_peers(peers)
    }

    pub fn with_recent_blocks(mut self, recent_blocks: Arc<dyn RecentBlockSource>) -> Self {
        self.recent_blocks = Some(recent_blocks);
        self
    }

    pub fn with_events(mut self, events: Arc<dyn EventSource>) -> Self {
        self.events = Some(events);
        self
    }

    pub fn with_event_source(self, events: Arc<dyn EventSource>) -> Self {
        self.with_events(events)
    }

    pub fn with_host(mut self, host: Arc<dyn HostStatusSource>) -> Self {
        self.host = Some(host);
        self
    }

    pub fn with_host_source(self, host: Arc<dyn HostStatusSource>) -> Self {
        self.with_host(host)
    }

    pub(crate) fn with_runtime_config(mut self, config: RuntimeConfig) -> Self {
        self.compute_gate = Arc::new(Semaphore::new(config.compute_concurrency));
        self.config = config;
        self
    }

    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }
}

async fn acquire_compute(state: &NativeState) -> Result<OwnedSemaphorePermit, Response> {
    state
        .compute_gate
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| {
            error::unavailable(
                "compute_unavailable",
                "the native compute runtime is shutting down",
            )
        })
}

async fn enforce_response_limit(
    State(limit): State<usize>,
    request: Request,
    next: Next,
) -> Response {
    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    match to_bytes(body, limit).await {
        Ok(bytes) => Response::from_parts(parts, Body::from(bytes)),
        Err(_) => error::response(ergo_api_core::error::ServiceError::payload_too_large(
            "response_too_large",
            "response exceeds the configured limit",
        )),
    }
}

#[allow(clippy::result_large_err)]
async fn run_chain<T, F>(state: &NativeState, operation: F) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(Arc<dyn ChainArchive>) -> ergo_api_core::error::ServiceResult<T> + Send + 'static,
{
    let Some(chain) = state.chain.clone() else {
        return Err(error::unavailable(
            "chain_unavailable",
            "chain reads are not wired on this node",
        ));
    };
    let permit =
        match tokio::time::timeout(state.config.request_timeout, acquire_compute(state)).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(response)) => return Err(response),
            Err(_) => {
                return Err(error::response(ergo_api_core::error::ServiceError::new(
                    ergo_api_core::error::ErrorKind::Timeout,
                    "chain_read_timeout",
                    "timed out waiting for chain compute capacity",
                )));
            }
        };
    let operation = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation(chain)
    });
    match operation.await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error::response(error)),
        Err(error) => Err(error::response(
            ergo_api_core::error::ServiceError::internal(
                "chain_task_failed",
                format!("chain read task failed: {error}"),
            ),
        )),
    }
}

async fn run_indexer(state: &NativeState) -> Result<(IndexerStatusSnapshot, u32), Response> {
    let Some(indexer) = state.indexer.clone() else {
        return Err(error::unavailable(
            "indexer_unavailable",
            "indexer status is not wired on this node",
        ));
    };
    let snapshot_source = state.snapshot.clone();
    let permit =
        match tokio::time::timeout(state.config.request_timeout, acquire_compute(state)).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(response)) => return Err(response),
            Err(_) => {
                return Err(error::response(ergo_api_core::error::ServiceError::new(
                    ergo_api_core::error::ErrorKind::Timeout,
                    "indexer_read_timeout",
                    "timed out waiting for indexer compute capacity",
                )));
            }
        };
    let operation = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let indexer = indexer.snapshot();
        let full_height = snapshot_source.snapshot().sync.full_block_height;
        (indexer, full_height)
    });
    match tokio::time::timeout(state.config.request_timeout, operation).await {
        Ok(Ok(snapshot)) => Ok(snapshot),
        Ok(Err(error)) => Err(error::response(
            ergo_api_core::error::ServiceError::internal(
                "indexer_task_failed",
                format!("indexer status task failed: {error}"),
            ),
        )),
        Err(_) => Err(error::response(ergo_api_core::error::ServiceError::new(
            ergo_api_core::error::ErrorKind::Timeout,
            "indexer_read_timeout",
            "indexer status read timed out",
        ))),
    }
}

async fn run_host(state: &NativeState) -> Result<HostStatus, Response> {
    let Some(source) = state.host.clone() else {
        return Err(error::unavailable(
            "host_unavailable",
            "host metrics are not wired on this node",
        ));
    };
    let permit =
        match tokio::time::timeout(state.config.request_timeout, acquire_compute(state)).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(response)) => return Err(response),
            Err(_) => {
                return Err(error::response(ergo_api_core::error::ServiceError::new(
                    ergo_api_core::error::ErrorKind::Timeout,
                    "host_read_timeout",
                    "timed out waiting for host compute capacity",
                )));
            }
        };
    let operation = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        source.host_status()
    });
    match tokio::time::timeout(state.config.request_timeout, operation).await {
        Ok(Ok(status)) => Ok(status),
        Ok(Err(error)) => Err(error::response(
            ergo_api_core::error::ServiceError::internal(
                "host_task_failed",
                format!("host metrics task failed: {error}"),
            ),
        )),
        Err(_) => Err(error::response(ergo_api_core::error::ServiceError::new(
            ergo_api_core::error::ErrorKind::Timeout,
            "host_read_timeout",
            "host metrics read timed out",
        ))),
    }
}

async fn transaction_compute_gate(
    State(state): State<NativeState>,
    request: Request,
    next: Next,
) -> Response {
    let permit =
        match tokio::time::timeout(state.config.request_timeout, acquire_compute(&state)).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(response)) => return response,
            Err(_) => {
                return error::response(ergo_api_core::error::ServiceError::new(
                    ergo_api_core::error::ErrorKind::Timeout,
                    "submission_capacity_timeout",
                    "timed out waiting for submission capacity",
                ));
            }
        };
    let _permit = permit;
    next.run(request).await
}

pub fn node_router(state: NativeState) -> Router {
    let response_limit = state.config.max_response_bytes;
    let router = Router::new()
        .route("/api/v1/node", get(node))
        .route("/api/v1/node/info", get(node_info))
        .route("/api/v1/node/status", get(node_status))
        .route("/api/v1/node/sync", get(node_sync))
        .route("/api/v1/node/identity", get(node_identity))
        .route("/api/v1/node/health", get(node_health))
        .route("/api/v1/node/tip", get(node_tip))
        .route("/api/v1/node/capabilities", get(node_capabilities));
    let router = if state.events.is_some() {
        router.route("/api/v1/node/events", get(node_events))
    } else {
        router
    };
    let router = if state.host.is_some() {
        router.route("/api/v1/node/host", get(node_host))
    } else {
        router
    };
    router
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            response_limit,
            enforce_response_limit,
        ))
}

pub fn chain_router(state: NativeState) -> Router {
    let response_limit = state.config.max_response_bytes;
    let router = Router::new()
        .route("/api/v1/chain/headers", get(chain_headers))
        .route("/api/v1/chain/headers/:header_id", get(chain_header))
        .route("/api/v1/chain/blocks/:header_id", get(chain_block))
        .route("/api/v1/voting/history", get(voting_history))
        .route("/api/v1/difficulty/history", get(difficulty_history))
        .route("/api/v1/mining/minerStats", get(miner_stats));
    let recent = if state.recent_blocks.is_some() {
        get(recent_blocks)
    } else {
        get(recent_blocks_unwired)
    };
    router
        .route("/api/v1/chain/blocks/recent", recent)
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            response_limit,
            enforce_response_limit,
        ))
}

pub fn transaction_router(state: NativeState) -> Router {
    let request_limit = state.config.max_request_bytes;
    let response_limit = state.config.max_response_bytes;
    Router::new()
        .route(
            "/api/v1/transactions",
            axum::routing::post(submit_transaction),
        )
        .route("/api/v1/transactions/:tx_id", get(transaction_by_id))
        .route(
            "/api/v1/transactions/:tx_id/status",
            get(transaction_status),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            transaction_compute_gate,
        ))
        .layer(DefaultBodyLimit::max(request_limit))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            response_limit,
            enforce_response_limit,
        ))
}

pub fn indexer_router(state: NativeState) -> Router {
    if state.indexer.is_none() {
        return Router::new().with_state(state);
    }
    let response_limit = state.config.max_response_bytes;
    Router::new()
        .route("/api/v1/indexer/status", get(indexer_status))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            response_limit,
            enforce_response_limit,
        ))
}

pub fn tip_router(state: NativeState) -> Router {
    let response_limit = state.config.max_response_bytes;
    Router::new()
        .route("/api/v1/chain/tip", get(chain_tip))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            response_limit,
            enforce_response_limit,
        ))
}

pub fn discovery_router(state: NativeState) -> Router {
    let response_limit = state.config.max_response_bytes;
    Router::new()
        .route("/api/v1/node/capabilities", get(node_capabilities))
        .route("/api/v1/chain/tip", get(chain_tip))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            response_limit,
            enforce_response_limit,
        ))
}

pub fn router(state: NativeState) -> Router {
    node_router(state.clone())
        .merge(chain_router(state.clone()))
        .merge(tip_router(state.clone()))
        .merge(transaction_router(state.clone()))
        .merge(indexer_router(state.clone()))
        .merge(network_router(state))
}

#[utoipa::path(
    get,
    path = "/api/v1/node",
    tag = "node",
    responses((status = 200, body = NodeView), (status = 503, body = error::ErrorEnvelope))
)]
pub(crate) async fn node(State(state): State<NativeState>) -> Json<NodeView> {
    Json(dto::node_view(&state.snapshot.snapshot()))
}

#[utoipa::path(
    get,
    path = "/api/v1/node/info",
    tag = "node",
    responses((status = 200, body = NodeInfoView), (status = 503, body = error::ErrorEnvelope))
)]
pub(crate) async fn node_info(State(state): State<NativeState>) -> Json<NodeInfoView> {
    Json(dto::info_view(&state.snapshot.snapshot().info))
}

#[utoipa::path(
    get,
    path = "/api/v1/node/status",
    tag = "node",
    responses((status = 200, body = NodeStatusView), (status = 503, body = error::ErrorEnvelope))
)]
pub(crate) async fn node_status(State(state): State<NativeState>) -> Json<NodeStatusView> {
    Json(dto::status_view(&state.snapshot.snapshot().status))
}

#[utoipa::path(
    get,
    path = "/api/v1/node/sync",
    tag = "node",
    responses((status = 200, body = SyncStatusView), (status = 503, body = error::ErrorEnvelope))
)]
pub(crate) async fn node_sync(State(state): State<NativeState>) -> Json<SyncStatusView> {
    Json(dto::sync_view(&state.snapshot.snapshot().sync))
}

#[utoipa::path(
    get,
    path = "/api/v1/node/identity",
    tag = "node",
    responses((status = 200, body = NodeIdentityView), (status = 503, body = error::ErrorEnvelope))
)]
pub(crate) async fn node_identity(State(state): State<NativeState>) -> Json<NodeIdentityView> {
    Json(dto::identity_view(&state.snapshot.snapshot().identity))
}

#[utoipa::path(
    get,
    path = "/api/v1/node/tip",
    tag = "node",
    responses((status = 200, body = ChainTipView), (status = 503, body = error::ErrorEnvelope))
)]
pub(crate) async fn node_tip(State(state): State<NativeState>) -> Json<ChainTipView> {
    Json(dto::tip_view(&state.snapshot.snapshot().tip))
}

#[utoipa::path(
    get,
    path = "/api/v1/node/host",
    tag = "node",
    responses((status = 200, body = HostStatusView), (status = 503, body = error::ErrorEnvelope))
)]
pub(crate) async fn node_host(State(state): State<NativeState>) -> Response {
    match run_host(&state).await {
        Ok(status) => Json(dto::host_status_view(&status)).into_response(),
        Err(response) => response,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/node/health",
    tag = "health",
    responses((status = 200, body = HealthView), (status = 503, body = HealthView))
)]
pub(crate) async fn node_health(State(state): State<NativeState>) -> Response {
    let health = state.snapshot.snapshot().health.clone();
    let view = dto::health_view(&health);
    let status = match health.status {
        ergo_api_core::node::HealthStatus::Healthy | ergo_api_core::node::HealthStatus::Syncing => {
            StatusCode::OK
        }
        ergo_api_core::node::HealthStatus::Disconnected
        | ergo_api_core::node::HealthStatus::Stalled
        | ergo_api_core::node::HealthStatus::Rejecting
        | ergo_api_core::node::HealthStatus::Wedged => StatusCode::SERVICE_UNAVAILABLE,
    };
    (status, Json(view)).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/node/capabilities",
    tag = "node",
    responses((status = 200, body = Vec<CapabilityView>), (status = 503, body = error::ErrorEnvelope))
)]
pub(crate) async fn node_capabilities(
    State(state): State<NativeState>,
) -> Json<Vec<CapabilityView>> {
    Json(
        state
            .snapshot
            .snapshot()
            .capabilities
            .iter()
            .map(dto::capability_view)
            .collect(),
    )
}

fn deserialize_event_since<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(value.and_then(|value| value.parse().ok()))
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct EventsQueryDto {
    #[serde(default, deserialize_with = "deserialize_event_since")]
    #[param(minimum = 0)]
    since: Option<u64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/node/events",
    tag = "node",
    params(EventsQueryDto),
    responses(
        (status = 200, body = EventFeedView, content_type = "application/json"),
        (status = 503, body = error::ErrorEnvelope)
    )
)]
pub(crate) async fn node_events(
    State(state): State<NativeState>,
    query: Result<Query<EventsQueryDto>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(value) => value,
        Err(error) => {
            return error::response(ergo_api_core::error::ServiceError::validation(
                "invalid_params",
                format!("query parameters are malformed: {error}"),
            ));
        }
    };
    let Some(source) = state.events.as_ref() else {
        return error::unavailable(
            "events_unavailable",
            "event feed reads are not wired on this node",
        );
    };
    let feed = source.events().since(query.since.unwrap_or(0));
    Json(dto::event_feed_view(&feed)).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/indexer/status",
    tag = "node",
    responses(
        (status = 200, body = IndexerStatusView),
        (status = 503, body = error::ErrorEnvelope),
        (status = 504, body = error::ErrorEnvelope)
    )
)]
pub(crate) async fn indexer_status(State(state): State<NativeState>) -> Response {
    let (snapshot, full_height) = match run_indexer(&state).await {
        Ok(snapshot) => snapshot,
        Err(response) => return response,
    };
    Json(dto::indexer_status_view(&snapshot, full_height)).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/chain/tip",
    tag = "chain",
    responses((status = 200, body = ChainTipView), (status = 503, body = error::ErrorEnvelope))
)]
pub(crate) async fn chain_tip(State(state): State<NativeState>) -> Json<ChainTipView> {
    Json(dto::tip_view(&state.snapshot.snapshot().tip))
}

#[derive(Debug, Default, Deserialize, IntoParams)]
pub(crate) struct DifficultyQueryDto {
    blocks: Option<u32>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
pub(crate) struct MinerStatsQueryDto {
    window: Option<u32>,
}

#[utoipa::path(
    get,
    path = "/api/v1/voting/history",
    tag = "voting",
    responses(
        (status = 200, body = ProtocolHistoryView),
        (status = 503, body = error::ErrorEnvelope),
        (status = 504, body = error::ErrorEnvelope)
    )
)]
pub(crate) async fn voting_history(State(state): State<NativeState>) -> Response {
    match run_chain(&state, |chain| chain.protocol_history()).await {
        Ok(history) => Json(dto::protocol_history_view(&history)).into_response(),
        Err(response) => response,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/difficulty/history",
    tag = "chain",
    params(("blocks" = Option<u32>, Query, description = "Most-recent blocks to return")),
    responses((status = 200, body = DifficultySeriesView), (status = 503, body = error::ErrorEnvelope))
)]
pub(crate) async fn difficulty_history(
    State(state): State<NativeState>,
    query: Result<Query<DifficultyQueryDto>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(value) => value,
        Err(error) => {
            return error::response(ergo_api_core::error::ServiceError::validation(
                "invalid_params",
                format!("query parameters are malformed: {error}"),
            ));
        }
    };
    let blocks = query.blocks.unwrap_or(720).clamp(2, MAX_RECENT_HEADERS);
    let result = run_chain(&state, move |chain| chain.recent_headers(blocks)).await;
    match result {
        Ok(headers) => Json(dto::difficulty_series(headers)).into_response(),
        Err(response) => response,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/mining/minerStats",
    tag = "chain",
    params(("window" = Option<u32>, Query, description = "Most-recent headers to fold")),
    responses((status = 200, body = MinerStatsView), (status = 503, body = error::ErrorEnvelope))
)]
pub(crate) async fn miner_stats(
    State(state): State<NativeState>,
    query: Result<Query<MinerStatsQueryDto>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(value) => value,
        Err(error) => {
            return error::response(ergo_api_core::error::ServiceError::validation(
                "invalid_params",
                format!("query parameters are malformed: {error}"),
            ));
        }
    };
    let window = query.window.unwrap_or(720).clamp(1, MAX_RECENT_HEADERS);
    let network = state.network;
    let result = run_chain(&state, move |chain| chain.recent_headers(window)).await;
    match result {
        Ok(headers) => Json(dto::miner_stats(headers, window, network)).into_response(),
        Err(response) => response,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/transactions/{tx_id}",
    tag = "transactions",
    responses(
        (status = 200, body = dto::TransactionView),
        (status = 400, body = error::ErrorEnvelope),
        (status = 404, body = error::ErrorEnvelope),
        (status = 503, body = error::ErrorEnvelope)
    )
)]
pub(crate) async fn transaction_by_id(
    State(state): State<NativeState>,
    Path(tx_id): Path<String>,
) -> Response {
    let Some(reader) = state.transaction_reader.as_ref() else {
        return error::unavailable(
            "transaction_reads_unavailable",
            "transaction reads are not wired on this node",
        );
    };
    let id = match TxId::from_str(&tx_id) {
        Ok(value) => value,
        Err(_) => {
            return error::response(ergo_api_core::error::ServiceError::validation(
                "invalid_transaction_id",
                "transaction id must be a 32-byte hexadecimal identifier",
            ));
        }
    };
    match reader.get(id).await {
        Ok(Some(transaction)) => Json(dto::transaction_view(&transaction)).into_response(),
        Ok(None) => error::response(ergo_api_core::error::ServiceError::not_found(
            "transaction_not_found",
            "transaction was not found",
        )),
        Err(error) => error::response(error),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/transactions/{tx_id}/status",
    tag = "transactions",
    responses(
        (status = 200, body = TransactionStatusView),
        (status = 400, body = error::ErrorEnvelope),
        (status = 503, body = error::ErrorEnvelope)
    )
)]
pub(crate) async fn transaction_status(
    State(state): State<NativeState>,
    Path(tx_id): Path<String>,
) -> Response {
    let Some(reader) = state.transaction_reader.as_ref() else {
        return error::unavailable(
            "transaction_reads_unavailable",
            "transaction reads are not wired on this node",
        );
    };
    let id = match TxId::from_str(&tx_id) {
        Ok(value) => value,
        Err(_) => {
            return error::response(ergo_api_core::error::ServiceError::validation(
                "invalid_transaction_id",
                "transaction id must be a 32-byte hexadecimal identifier",
            ));
        }
    };
    match reader.get(id).await {
        Ok(transaction) => Json(dto::transaction_status_view(
            id.to_string(),
            transaction.as_ref(),
        ))
        .into_response(),
        Err(error) => error::response(error),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/transactions",
    tag = "transactions",
    request_body = dto::TransactionBody,
    responses(
        (status = 200, body = dto::TransactionAdmissionView),
        (status = 400, body = error::ErrorEnvelope),
        (status = 413, body = error::ErrorEnvelope),
        (status = 503, body = error::ErrorEnvelope),
        (status = 504, body = error::ErrorEnvelope)
    )
)]
pub(crate) async fn submit_transaction(
    State(state): State<NativeState>,
    body: Result<Json<dto::TransactionBody>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(value) => value,
        Err(error) => {
            let service_error = if matches!(
                error,
                JsonRejection::BytesRejection(BytesRejection::FailedToBufferBody(
                    FailedToBufferBody::LengthLimitError(_)
                ))
            ) {
                ergo_api_core::error::ServiceError::payload_too_large(
                    "request_too_large",
                    "request body exceeds the configured limit",
                )
            } else {
                ergo_api_core::error::ServiceError::validation(
                    "invalid_body",
                    format!("request body is malformed: {error}"),
                )
            };
            return error::response(service_error);
        }
    };
    let Some(transactions) = state.transactions.as_ref() else {
        return error::unavailable(
            "transaction_submission_unavailable",
            "transaction submission is not wired on this node",
        );
    };
    let max_decoded_bytes = state.config.max_request_bytes / 2;
    let bytes = match hex::decode(body.bytes.trim()) {
        Ok(value) if value.len() <= max_decoded_bytes => value,
        Ok(_) => {
            return error::response(ergo_api_core::error::ServiceError::payload_too_large(
                "transaction_too_large",
                format!("transaction bytes exceed the {max_decoded_bytes} byte limit"),
            ));
        }
        Err(error) => {
            return error::response(ergo_api_core::error::ServiceError::validation(
                "invalid_transaction_hex",
                format!("transaction bytes are not hexadecimal: {error}"),
            ));
        }
    };
    let mode = match body.mode.as_deref() {
        None | Some("broadcast") => SubmissionMode::Broadcast,
        Some("validate") | Some("check") => SubmissionMode::Validate,
        Some(_) => {
            return error::response(ergo_api_core::error::ServiceError::validation(
                "invalid_submission_mode",
                "mode must be broadcast or validate",
            ));
        }
    };
    let result = tokio::time::timeout(
        state.config.request_timeout,
        transactions.submit(ergo_api_core::transaction::TransactionSubmission::new(
            Arc::from(bytes.into_boxed_slice()),
            mode,
        )),
    )
    .await;
    match result {
        Ok(Ok(result)) => Json(dto::TransactionAdmissionView {
            tx_id: result.tx_id.to_string(),
            disposition: match result.disposition {
                AdmissionDisposition::Admitted => "admitted",
                AdmissionDisposition::WouldAdmit => "would_admit",
                AdmissionDisposition::AlreadyKnown => "already_known",
            }
            .to_string(),
        })
        .into_response(),
        Ok(Err(error)) => error::response(map_transaction_error(error)),
        Err(_) => error::response(ergo_api_core::error::ServiceError::new(
            ergo_api_core::error::ErrorKind::Timeout,
            "submission_timeout",
            "transaction submission timed out",
        )),
    }
}

fn map_transaction_error(error: TransactionError) -> ergo_api_core::error::ServiceError {
    use ergo_api_core::error::{ErrorKind, ServiceError};
    use ergo_api_core::transaction::TransactionRejection;
    match error {
        TransactionError::Rejected(rejection) => match rejection {
            TransactionRejection::Duplicate
            | TransactionRejection::DoubleSpend
            | TransactionRejection::DoubleSpendReplacement
            | TransactionRejection::Stale => ServiceError::new(
                ErrorKind::Conflict,
                "transaction_conflict",
                rejection.to_string(),
            ),
            TransactionRejection::IbdGated | TransactionRejection::TipUnready => {
                ServiceError::unavailable("transaction_tip_unready", rejection.to_string())
            }
            TransactionRejection::GlobalBudget
            | TransactionRejection::PeerBudget
            | TransactionRejection::PoolFull => {
                ServiceError::overloaded("transaction_admission_busy", rejection.to_string())
            }
            TransactionRejection::InvalidEncoding
            | TransactionRejection::NonCanonical
            | TransactionRejection::KnownInvalid
            | TransactionRejection::Structural
            | TransactionRejection::SizeLimit
            | TransactionRejection::FeeTooLow
            | TransactionRejection::CostLimit
            | TransactionRejection::UnresolvedInput
            | TransactionRejection::UnresolvedDataInput
            | TransactionRejection::ScriptValidation
            | TransactionRejection::MonetaryInvariant
            | TransactionRejection::ReemissionPolicy
            | TransactionRejection::ValidationFailed
            | TransactionRejection::InsertionCollision => {
                ServiceError::validation("transaction_rejected", rejection.to_string())
            }
        },
        TransactionError::Disabled => {
            ServiceError::unavailable("submission_disabled", "transaction submission is disabled")
        }
        TransactionError::Unavailable => ServiceError::unavailable(
            "submission_unavailable",
            "transaction submission is temporarily unavailable",
        ),
        TransactionError::Overloaded => ServiceError::overloaded(
            "submission_overloaded",
            "transaction submission is overloaded",
        ),
        TransactionError::ShuttingDown => {
            ServiceError::unavailable("shutting_down", "node is shutting down")
        }
        TransactionError::TimedOut => ServiceError::new(
            ErrorKind::Timeout,
            "submission_timeout",
            "transaction submission timed out",
        ),
        TransactionError::Internal(failure) => {
            ServiceError::internal("submission_failed", "transaction submission failed")
                .with_failure(failure)
        }
    }
}

async fn recent_blocks_unwired() -> StatusCode {
    StatusCode::NOT_FOUND
}

fn deserialize_recent_block_count<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(value.and_then(|value| value.parse().ok()))
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct RecentBlocksQueryDto {
    #[serde(default, deserialize_with = "deserialize_recent_block_count")]
    #[param(minimum = 1, maximum = 32, default = 10)]
    n: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/chain/blocks/recent",
    tag = "chain",
    description = "Returns at most 32 committed full blocks, newest first. The n parameter defaults to 10, clamps numeric values to [1, 32], and uses 10 for non-numeric values.",
    params(RecentBlocksQueryDto),
    responses(
        (status = 200, body = Vec<RecentBlockView>, content_type = "application/json"),
        (status = 400, body = error::ErrorEnvelope),
        (status = 503, body = error::ErrorEnvelope)
    )
)]
pub(crate) async fn recent_blocks(
    State(state): State<NativeState>,
    query: Result<Query<RecentBlocksQueryDto>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(value) => value,
        Err(error) => {
            return error::response(ergo_api_core::error::ServiceError::validation(
                "invalid_params",
                format!("query parameters are malformed: {error}"),
            ));
        }
    };
    let count = query
        .n
        .map(|value| value.clamp(1, i64::from(MAX_RECENT_BLOCK_COUNT)) as u32)
        .unwrap_or(DEFAULT_RECENT_BLOCK_COUNT);
    let Some(source) = state.recent_blocks.clone() else {
        return error::unavailable(
            "recent_blocks_unavailable",
            "recent block reads are not wired on this node",
        );
    };
    let blocks = source
        .recent_blocks(count)
        .into_iter()
        .take(count as usize)
        .map(|block| dto::recent_block_view(&block))
        .collect::<Vec<_>>();
    Json(blocks).into_response()
}

#[derive(Debug, Default, Deserialize, IntoParams)]
pub(crate) struct HeaderQueryDto {
    limit: Option<u32>,
    cursor: Option<String>,
    from_height: Option<u32>,
    to_height: Option<u32>,
    order: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/chain/headers",
    tag = "chain",
    params(
        ("limit" = Option<u32>, Query, description = "Maximum headers to return"),
        ("cursor" = Option<String>, Query, description = "Opaque next-page cursor"),
        ("from_height" = Option<u32>, Query, description = "First canonical height"),
        ("to_height" = Option<u32>, Query, description = "Last canonical height"),
        ("order" = Option<String>, Query, description = "asc or desc")
    ),
    responses((status = 200, body = dto::HeaderPage), (status = 400, body = error::ErrorEnvelope), (status = 503, body = error::ErrorEnvelope))
)]
pub(crate) async fn chain_headers(
    State(state): State<NativeState>,
    query: Result<Query<HeaderQueryDto>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(value) => value,
        Err(error) => {
            return error::response(ergo_api_core::error::ServiceError::validation(
                "invalid_params",
                format!("query parameters are malformed: {error}"),
            ));
        }
    };
    let cursor = match query.cursor {
        Some(value) => match Cursor::new(value) {
            Ok(value) => Some(value),
            Err(_) => {
                return error::response(ergo_api_core::error::ServiceError::validation(
                    "invalid_cursor",
                    "pagination cursor is malformed",
                ));
            }
        },
        None => None,
    };
    let default_limit = state.config.default_page_size;
    let max_limit = state.config.max_page_size;
    let requested_limit = query.limit.unwrap_or(default_limit);
    if requested_limit == 0 {
        return error::response(ergo_api_core::error::ServiceError::validation(
            "invalid_limit",
            "limit must be greater than zero",
        ));
    }
    let page = match PageRequest::new(requested_limit.min(max_limit), cursor) {
        Ok(value) => value,
        Err(_) => {
            return error::response(ergo_api_core::error::ServiceError::validation(
                "invalid_limit",
                "limit must be greater than zero",
            ));
        }
    };
    let order = match query.order.as_deref() {
        None | Some("asc") | Some("ascending") => SortOrder::Ascending,
        Some("desc") | Some("descending") => SortOrder::Descending,
        Some(_) => {
            return error::response(ergo_api_core::error::ServiceError::validation(
                "invalid_sort_order",
                "sort order must be asc or desc",
            ));
        }
    };
    let result = run_chain(&state, move |chain| {
        chain.headers(
            HeaderQuery {
                from_height: query.from_height,
                to_height: query.to_height,
                order,
            },
            page,
        )
    })
    .await;
    match result {
        Ok(page) => Json(dto::header_page(page)).into_response(),
        Err(response) => response,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/chain/headers/{header_id}",
    tag = "chain",
    responses((status = 200, body = dto::HeaderView), (status = 400, body = error::ErrorEnvelope), (status = 404, body = error::ErrorEnvelope), (status = 503, body = error::ErrorEnvelope))
)]
pub(crate) async fn chain_header(
    State(state): State<NativeState>,
    Path(header_id): Path<String>,
) -> Response {
    let id = match HeaderId::from_str(&header_id) {
        Ok(value) => value,
        Err(_) => {
            return error::response(ergo_api_core::error::ServiceError::validation(
                "invalid_header_id",
                "header id must be a 32-byte hexadecimal identifier",
            ));
        }
    };
    match run_chain(&state, move |chain| chain.header_by_id(id)).await {
        Ok(Some(header)) => Json(dto::header_view(&header)).into_response(),
        Ok(None) => error::response(ergo_api_core::error::ServiceError::not_found(
            "header_not_found",
            "header was not found",
        )),
        Err(response) => response,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/chain/blocks/{header_id}",
    tag = "chain",
    responses((status = 200, body = dto::BlockSummaryView), (status = 400, body = error::ErrorEnvelope), (status = 404, body = error::ErrorEnvelope), (status = 503, body = error::ErrorEnvelope))
)]
pub(crate) async fn chain_block(
    State(state): State<NativeState>,
    Path(header_id): Path<String>,
) -> Response {
    let id = match HeaderId::from_str(&header_id) {
        Ok(value) => value,
        Err(_) => {
            return error::response(ergo_api_core::error::ServiceError::validation(
                "invalid_header_id",
                "header id must be a 32-byte hexadecimal identifier",
            ));
        }
    };
    match run_chain(&state, move |chain| chain.block_summary_by_id(id)).await {
        Ok(Some(block)) => Json(dto::block_summary_view(&block)).into_response(),
        Ok(None) => error::response(ergo_api_core::error::ServiceError::not_found(
            "block_not_found",
            "block was not found or its transaction section is unavailable",
        )),
        Err(response) => response,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use ergo_api_core::capability::CapabilityDescriptor;
    use ergo_api_core::chain::{BlockSummary, HeaderQuery, ProtocolHistory, Stored};
    use ergo_api_core::id::{HeaderId, ModifierId};
    use ergo_api_core::indexer::{
        IndexerRepair, IndexerStatus, IndexerStatusSnapshot, IndexerStatusSource, IndexerTotals,
    };
    use ergo_primitives::digest::{ADDigest, Digest32};
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::header::Header;

    use ergo_api_core::node::{
        BlockTip, ChainTip, HeaderTip, Health, HealthStatus, HistoryMode, NodeIdentity, NodeInfo,
        NodeNetwork, NodeSnapshot, NodeStatus, StateBackend, SyncState, SyncStatus,
    };
    use ergo_api_core::observability::{HostStatus, HostStatusSource, RecentBlockRecord};

    use ergo_api_core::page::{Page, PageRequest};
    use http_body_util::BodyExt;
    use num_bigint::BigUint;
    use tower::ServiceExt;

    use super::*;

    struct FixedSnapshot(Arc<NodeSnapshot>);

    impl NodeSnapshotSource for FixedSnapshot {
        fn snapshot(&self) -> Arc<NodeSnapshot> {
            self.0.clone()
        }
    }

    struct FixedIndexer(IndexerStatusSnapshot);

    impl IndexerStatusSource for FixedIndexer {
        fn snapshot(&self) -> IndexerStatusSnapshot {
            self.0.clone()
        }
    }

    struct FixedHost(HostStatus);

    impl HostStatusSource for FixedHost {
        fn host_status(&self) -> HostStatus {
            self.0.clone()
        }
    }

    struct FixedRecent {
        blocks: Vec<RecentBlockRecord>,
        requested: Arc<AtomicU32>,
    }

    impl RecentBlockSource for FixedRecent {
        fn recent_blocks(&self, count: u32) -> Vec<RecentBlockRecord> {
            self.requested.store(count, Ordering::SeqCst);
            self.blocks.clone()
        }
    }

    struct SummaryChain;

    impl ChainArchive for SummaryChain {
        fn header_ids_at_height(
            &self,
            _height: u32,
        ) -> ergo_api_core::error::ServiceResult<Vec<HeaderId>> {
            Ok(Vec::new())
        }

        fn header_ids(
            &self,
            _query: HeaderQuery,
            _page: PageRequest,
        ) -> ergo_api_core::error::ServiceResult<Page<HeaderId>> {
            Ok(Page::new(Vec::new(), None, None, None))
        }

        fn headers(
            &self,
            _query: HeaderQuery,
            _page: PageRequest,
        ) -> ergo_api_core::error::ServiceResult<Page<Stored<Header>>> {
            Ok(Page::new(Vec::new(), None, None, None))
        }

        fn header_by_id(
            &self,
            _id: HeaderId,
        ) -> ergo_api_core::error::ServiceResult<Option<Stored<ergo_ser::header::Header>>> {
            Ok(None)
        }

        fn block_transactions_by_id(
            &self,
            _id: HeaderId,
        ) -> ergo_api_core::error::ServiceResult<
            Option<Stored<ergo_ser::block_transactions::BlockTransactions>>,
        > {
            Ok(None)
        }

        fn full_block_by_id(
            &self,
            _id: HeaderId,
        ) -> ergo_api_core::error::ServiceResult<Option<ergo_api_core::chain::FullBlock>> {
            panic!("summary route must not decode a full block")
        }

        fn block_summary_by_id(
            &self,
            id: HeaderId,
        ) -> ergo_api_core::error::ServiceResult<Option<BlockSummary>> {
            Ok(Some(BlockSummary {
                id,
                parent_id: HeaderId::from_bytes([2; 32]),
                height: 1,
                timestamp_unix_ms: 2,
                state_root: Some(ergo_primitives::digest::ADDigest::from_bytes([3; 33])),
                transaction_count: 4,
                size_bytes: 5,
            }))
        }

        fn full_blocks_by_ids(
            &self,
            _ids: &[HeaderId],
        ) -> ergo_api_core::error::ServiceResult<Page<ergo_api_core::chain::FullBlock>> {
            Ok(Page::new(Vec::new(), None, None, None))
        }
    }

    struct AnalyticsChain {
        headers: Vec<Stored<Header>>,
        last_limit: AtomicU32,
        protocol_history: ProtocolHistory,
        protocol_history_error: Option<ergo_api_core::error::ServiceError>,
    }

    struct StatusReader;

    #[async_trait::async_trait]
    impl TransactionReader for StatusReader {
        async fn get(
            &self,
            id: TxId,
        ) -> ergo_api_core::error::ServiceResult<
            Option<ergo_api_core::transaction::TransactionRecord>,
        > {
            Ok(Some(ergo_api_core::transaction::TransactionRecord {
                id,
                state: ergo_api_core::transaction::TransactionState::Confirmed,
                inclusion_height: Some(12),
                index_in_block: Some(3),
                size_bytes: 321,
                confirmations: Some(4),
            }))
        }
    }

    impl AnalyticsChain {
        fn new(headers: Vec<Stored<Header>>) -> Self {
            Self {
                headers,
                last_limit: AtomicU32::new(0),
                protocol_history: ProtocolHistory::default(),
                protocol_history_error: None,
            }
        }
    }

    impl ChainArchive for AnalyticsChain {
        fn header_ids_at_height(
            &self,
            height: u32,
        ) -> ergo_api_core::error::ServiceResult<Vec<HeaderId>> {
            Ok(self
                .headers
                .iter()
                .filter(|header| header.value.height == height)
                .map(|header| HeaderId::from_bytes(*header.id.as_bytes()))
                .collect())
        }

        fn header_ids(
            &self,
            _query: HeaderQuery,
            page: PageRequest,
        ) -> ergo_api_core::error::ServiceResult<Page<HeaderId>> {
            let items = self
                .headers
                .iter()
                .take(page.limit() as usize)
                .map(|header| HeaderId::from_bytes(*header.id.as_bytes()))
                .collect();
            Ok(Page::new(items, None, None, None))
        }

        fn headers(
            &self,
            _query: HeaderQuery,
            page: PageRequest,
        ) -> ergo_api_core::error::ServiceResult<Page<Stored<Header>>> {
            self.last_limit.store(page.limit(), Ordering::SeqCst);
            let offset = page
                .cursor()
                .and_then(|cursor| cursor.as_str().strip_prefix("offset:"))
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0)
                .min(self.headers.len());
            let end = offset
                .saturating_add(page.limit() as usize)
                .min(self.headers.len());
            let items = self.headers[offset..end].to_vec();
            let next_cursor = if end < self.headers.len() {
                Some(Cursor::new(format!("offset:{end}")).map_err(|_| {
                    ergo_api_core::error::ServiceError::internal(
                        "test_cursor",
                        "failed to encode test cursor",
                    )
                })?)
            } else {
                None
            };
            Ok(Page::new(items, next_cursor, None, None))
        }

        fn protocol_history(&self) -> ergo_api_core::error::ServiceResult<ProtocolHistory> {
            self.protocol_history_error
                .clone()
                .map_or_else(|| Ok(self.protocol_history.clone()), Err)
        }

        fn header_by_id(
            &self,
            id: HeaderId,
        ) -> ergo_api_core::error::ServiceResult<Option<Stored<Header>>> {
            Ok(self
                .headers
                .iter()
                .find(|header| header.id.as_bytes() == id.as_bytes())
                .cloned())
        }

        fn block_transactions_by_id(
            &self,
            _id: HeaderId,
        ) -> ergo_api_core::error::ServiceResult<
            Option<Stored<ergo_ser::block_transactions::BlockTransactions>>,
        > {
            Ok(None)
        }

        fn full_block_by_id(
            &self,
            _id: HeaderId,
        ) -> ergo_api_core::error::ServiceResult<Option<ergo_api_core::chain::FullBlock>> {
            Ok(None)
        }

        fn block_summary_by_id(
            &self,
            _id: HeaderId,
        ) -> ergo_api_core::error::ServiceResult<Option<BlockSummary>> {
            Ok(None)
        }

        fn full_blocks_by_ids(
            &self,
            _ids: &[HeaderId],
        ) -> ergo_api_core::error::ServiceResult<Page<ergo_api_core::chain::FullBlock>> {
            Ok(Page::new(Vec::new(), None, None, None))
        }
    }

    fn stored_header(height: u32, timestamp: u64, pk: [u8; 33]) -> Stored<Header> {
        let header = Header {
            version: 2,
            parent_id: ModifierId::from_bytes([height.saturating_sub(1) as u8; 32]),
            ad_proofs_root: Digest32::from_bytes([1; 32]),
            transactions_root: Digest32::from_bytes([2; 32]),
            state_root: ADDigest::from_bytes([3; 33]),
            timestamp,
            extension_root: Digest32::from_bytes([4; 32]),
            n_bits: 0x1a01_7660,
            height,
            votes: [0; 3],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes(pk),
                nonce: [0; 8],
            },
        };
        Stored::new(
            ModifierId::from_bytes([height as u8; 32]),
            Arc::from(Vec::<u8>::new()),
            header,
        )
    }

    fn recent_fixture() -> (NativeState, Arc<AtomicU32>) {
        let requested = Arc::new(AtomicU32::new(0));
        let blocks = (1..=40)
            .rev()
            .map(|height| RecentBlockRecord {
                height,
                header_id: HeaderId::from_bytes([height as u8; 32]),
                timestamp_unix_ms: 1_700_000_000_000 + height as u64,
                transaction_count: height,
                size_bytes: 1_000 + height as u64,
                delivered_by: (height == 40).then(|| "203.0.113.7:9030".parse().unwrap()),
                miner_public_key: (height == 40).then_some([2; 33]),
                miner_address: (height == 40).then(|| "miner-address".to_string()),
            })
            .collect();
        let source = Arc::new(FixedRecent {
            blocks,
            requested: requested.clone(),
        });
        (fixture().with_recent_blocks(source), requested)
    }

    fn fixture() -> NativeState {
        let id = HeaderId::from_bytes([7; 32]);
        let tip = ChainTip {
            best_header: HeaderTip {
                height: 10,
                id: Some(id),
                parent_id: Some(HeaderId::from_bytes([6; 32])),
                timestamp_unix_ms: 100,
                compact_bits: 1,
                difficulty: BigUint::from(2u32),
            },
            best_block: BlockTip {
                header: HeaderTip {
                    height: 9,
                    id: Some(id),
                    parent_id: Some(HeaderId::from_bytes([5; 32])),
                    timestamp_unix_ms: 90,
                    compact_bits: 1,
                    difficulty: BigUint::from(2u32),
                },
                state_root: Some([3; 33]),
            },
        };
        NativeState {
            chain: None,
            transactions: None,
            transaction_reader: None,
            indexer: None,
            peers: None,
            recent_blocks: None,
            events: None,
            host: None,
            network: NetworkPrefix::Mainnet,

            config: RuntimeConfig::default(),
            compute_gate: Arc::new(Semaphore::new(2)),
            snapshot: Arc::new(FixedSnapshot(Arc::new(NodeSnapshot {
                revision: ergo_api_core::page::SnapshotRevision(4),
                produced_at_unix_ms: 200,
                info: NodeInfo {
                    agent_name: "ergo".into(),
                    node_name: "node".into(),
                    network: NodeNetwork::Devnet,
                    version: "test".into(),
                    started_at_unix_ms: 1,
                    uptime_seconds: 2,
                    target_block_interval_ms: 3,
                },
                identity: NodeIdentity {
                    state_backend: StateBackend::Utxo,
                    verify_transactions: true,
                    history_mode: HistoryMode::Archive,
                    utxo_bootstrap: false,
                    nipopow_bootstrap: false,
                    mining_enabled: false,
                    indexer_enabled: false,
                    declared_address: None,
                    bind_address: None,
                },
                status: NodeStatus {
                    sync: SyncState::AtTip,
                    peer_count: 1,
                    mempool_size: 2,
                    headers_ahead_of_full_blocks: 1,
                    snapshot_age_ms: 0,
                    block_apply_errors_total: 0,
                    storage_errors_total: 0,
                    reorgs_total: 0,
                    sync_wedged: false,
                    apply_wedged: false,
                    apply_in_progress: false,
                    shadow_diverged: false,
                    bootstrap_active: false,
                },
                tip,
                sync: SyncStatus {
                    state: SyncState::AtTip,
                    headers_chain_synced: true,
                    header_height: 10,
                    full_block_height: 9,
                    gap: 1,
                    download_window: 8,
                    pending_blocks: 0,
                    recovery_complete: true,
                    best_known_height: 10,
                },
                health: Health {
                    status: HealthStatus::Healthy,
                    behind: 1,
                    last_progress_age_ms: 0,
                    peer_count: 1,
                },
                capabilities: vec![CapabilityDescriptor::available(
                    ergo_api_core::capability::CapabilityId::Node,
                )],
            }))),
        }
    }

    #[tokio::test]
    async fn unhealthy_node_health_uses_service_unavailable() {
        let base = fixture();
        let mut snapshot = (*base.snapshot.snapshot()).clone();
        snapshot.health.status = HealthStatus::Stalled;
        let state = NativeState {
            snapshot: Arc::new(FixedSnapshot(Arc::new(snapshot))),
            ..base
        };
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/node/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 503);
    }

    #[tokio::test]
    async fn oversized_native_response_uses_payload_too_large() {
        let mut state = fixture();
        state.config.max_response_bytes = 8;
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/node")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 413);
    }

    #[tokio::test]
    async fn recent_blocks_route_preserves_wire_shape_and_newest_first_order() {
        let (state, _) = recent_fixture();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/chain/blocks/recent?n=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let blocks = value.as_array().unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0]["height"], 40);
        assert_eq!(blocks[0]["header_id"], hex::encode([40; 32]));
        assert_eq!(blocks[0]["ts_unix_ms"], 1_700_000_000_040u64);
        assert_eq!(blocks[0]["txs"], 40);
        assert_eq!(blocks[0]["size_bytes"], 1_040);
        assert_eq!(blocks[0]["delivered_by"], "203.0.113.7:9030");
        assert_eq!(blocks[0]["miner_pk"], hex::encode([2; 33]));
        assert_eq!(blocks[0]["miner_address"], "miner-address");
        assert_eq!(blocks[1]["height"], 39);
        assert!(blocks[1].get("delivered_by").is_none());
        assert!(blocks[1].get("miner_pk").is_none());
        assert!(blocks[1].get("miner_address").is_none());
    }

    #[tokio::test]
    async fn recent_blocks_route_uses_legacy_default_and_bounds() {
        let (state, requested) = recent_fixture();
        let app = router(state);
        for (query, expected) in [
            ("", 10),
            ("?n=1", 1),
            ("?n=0", 1),
            ("?n=-1", 1),
            ("?n=999", 32),
            ("?n=abc", 10),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/chain/blocks/recent{query}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), 200, "{query}");
            assert_eq!(requested.load(Ordering::SeqCst), expected, "{query}");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                value.as_array().unwrap().len(),
                expected as usize,
                "{query}"
            );
        }
    }

    #[tokio::test]
    async fn recent_blocks_route_is_unmounted_without_a_source() {
        let response = router(fixture())
            .oneshot(
                Request::builder()
                    .uri("/api/v1/chain/blocks/recent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }

    #[tokio::test]
    async fn recent_blocks_route_obeys_response_body_limit() {
        let (mut state, _) = recent_fixture();
        state.config.max_response_bytes = 8;
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/chain/blocks/recent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 413);
    }

    #[tokio::test]
    async fn oversized_transaction_body_uses_payload_too_large() {
        let mut state = fixture();
        state.config.max_request_bytes = 8;
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/transactions")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"bytes":"0000"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 413);
    }

    #[tokio::test]
    async fn block_route_uses_summary_chain_port() {
        let state = fixture().with_chain(Arc::new(SummaryChain));
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/chain/blocks/0000000000000000000000000000000000000000000000000000000000000001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["transaction_count"], 4);
    }

    #[tokio::test]
    async fn analytics_routes_use_typed_chain_history() {
        let miner_a: [u8; 33] =
            hex::decode("0274e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891f")
                .unwrap()
                .try_into()
                .unwrap();
        let miner_b: [u8; 33] =
            hex::decode("02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap()
                .try_into()
                .unwrap();
        let chain = Arc::new(AnalyticsChain::new(vec![
            stored_header(3, 3_000, miner_b),
            stored_header(2, 2_000, miner_a),
            stored_header(1, 1_000, miner_a),
        ]));
        let app = router(fixture().with_chain(chain.clone()));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/difficulty/history?blocks=3")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["points"][0]["height"], 1);
        assert_eq!(value["points"][2]["height"], 3);
        assert!(value["points"][0]["difficulty"].is_string());
        assert!(value["points"][0].get("n_bits").is_none());
        assert_eq!(chain.last_limit.load(Ordering::SeqCst), 3);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/mining/minerStats?window=3")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["tip_height"], 3);
        assert_eq!(value["window"], 3);
        assert_eq!(value["blocks"], 3);
        assert_eq!(value["miners"][0]["count"], 2);
        assert_eq!(value["miners"][0]["last_height"], 2);
        assert_eq!(
            value["miners"][0]["address"],
            "9fQYeMEXvSfmL2iUfsDDJ88SVtuPuvTZiB5aR19nKeCKSACVmgx"
        );
    }

    #[test]
    fn recent_headers_pages_past_the_single_page_limit() {
        let pk = [2; 33];
        let headers = (1..=1_001)
            .map(|height| stored_header(height, height as u64, pk))
            .collect();
        let chain = AnalyticsChain::new(headers);
        let result = chain.recent_headers(1_001).unwrap();
        assert_eq!(result.len(), 1_001);
        assert_eq!(chain.last_limit.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn voting_history_route_uses_core_protocol_history() {
        let mut chain = AnalyticsChain::new(Vec::new());
        chain.protocol_history = ProtocolHistory {
            epoch_length: 17,
            current_height: 42,
            changes: vec![ergo_api_core::chain::ProtocolChangeEvent {
                height: 17,
                params: vec![ergo_api_core::chain::ProtocolParamChange {
                    id: 9,
                    name: "subblocksPerBlock".to_string(),
                    description: "active".to_string(),
                    from: None,
                    to: 4,
                }],
            }],
        };
        let response = router(fixture().with_chain(Arc::new(chain)))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/voting/history")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["epoch_length"], 17);
        assert_eq!(value["current_height"], 42);
        assert_eq!(value["changes"][0]["height"], 17);
        assert!(value["changes"][0]["params"][0]["from"].is_null());
    }

    #[tokio::test]
    async fn voting_history_route_propagates_chain_failure() {
        let mut chain = AnalyticsChain::new(Vec::new());
        chain.protocol_history_error = Some(ergo_api_core::error::ServiceError::unavailable(
            "protocol_history_failed",
            "protocol history failed",
        ));
        let response = router(fixture().with_chain(Arc::new(chain)))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/voting/history")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 503);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "protocol_history_failed");
    }

    #[tokio::test]
    async fn transaction_status_route_uses_the_native_reader_contract() {
        let app = router(fixture().with_transaction_reader(Arc::new(StatusReader)));
        let tx_id = "00".repeat(32);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/transactions/{tx_id}/status"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["tx_id"], tx_id);
        assert_eq!(value["state"], "confirmed");
        assert_eq!(value["inclusion_height"], 12);
        assert_eq!(value["index_in_block"], 3);
        assert_eq!(value["confirmations"], 4);
    }

    #[tokio::test]
    async fn indexer_status_route_preserves_wire_shape() {
        let source = IndexerStatusSnapshot {
            status: IndexerStatus::CaughtUp,
            halt_reason: None,
            indexed_height: 42,
            repair: IndexerRepair {
                pending: true,
                next_gi: Some(7),
                skipped: 3,
                drift_skips: 5,
            },
            totals: IndexerTotals { boxes: 11, txs: 13 },
        };
        let response = router(fixture().with_indexer(Arc::new(FixedIndexer(source))))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/indexer/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "status": "caughtUp",
                "indexedHeight": 42,
                "fullHeight": 9,
                "repair": {
                    "pending": true,
                    "nextGi": 7,
                    "skipped": 3,
                    "driftSkips": 5
                },
                "totals": {"boxes": 11, "txs": 13}
            })
        );
    }

    #[tokio::test]
    async fn indexer_status_route_keeps_syncing_and_halted_at_ok() {
        for (status, halt_reason, expected_status, expected_reason) in [
            (IndexerStatus::Syncing, None, "syncing", None),
            (
                IndexerStatus::Halted,
                Some("db-corruption".to_string()),
                "halted",
                Some("db-corruption"),
            ),
        ] {
            let source = IndexerStatusSnapshot {
                status,
                halt_reason,
                indexed_height: 0,
                repair: IndexerRepair {
                    pending: false,
                    next_gi: None,
                    skipped: 0,
                    drift_skips: 0,
                },
                totals: IndexerTotals { boxes: 0, txs: 0 },
            };
            let response = router(fixture().with_indexer(Arc::new(FixedIndexer(source))))
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/indexer/status")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["status"], expected_status);
            if let Some(expected_reason) = expected_reason {
                assert_eq!(value["haltReason"], expected_reason);
            } else {
                assert!(value.get("haltReason").is_none());
            }
        }
    }

    #[tokio::test]
    async fn indexer_status_route_is_unmounted_without_a_source() {
        let response = router(fixture())
            .oneshot(
                Request::builder()
                    .uri("/api/v1/indexer/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }

    #[tokio::test]
    async fn host_route_preserves_optional_null_wire_shape() {
        let state = fixture().with_host(Arc::new(FixedHost(HostStatus {
            rss_bytes: Some(42),
            state_db_bytes: Some(0),
            index_db_bytes: None,
            disk_free_bytes: Some(1024),
            disk_total_bytes: Some(2048),
            cpu_pct: Some(1.5),
            net_in_bps: Some(3),
            net_out_bps: None,
            load_1m: Some(0.25),
        })));
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/node/host")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["rss_bytes"], 42);
        assert_eq!(value["state_db_bytes"], 0);
        assert!(value["index_db_bytes"].is_null());
        assert_eq!(value["disk_free_bytes"], 1024);
        assert_eq!(value["disk_total_bytes"], 2048);
        assert_eq!(value["cpu_pct"], 1.5);
        assert_eq!(value["net_in_bps"], 3);
        assert!(value["net_out_bps"].is_null());
        assert_eq!(value["load_1m"], 0.25);
        for field in [
            "rss_bytes",
            "state_db_bytes",
            "index_db_bytes",
            "disk_free_bytes",
            "disk_total_bytes",
            "cpu_pct",
            "net_in_bps",
            "net_out_bps",
            "load_1m",
        ] {
            assert!(value.get(field).is_some(), "missing {field}");
        }
    }

    #[tokio::test]
    async fn host_route_is_unmounted_without_a_source() {
        let response = router(fixture())
            .oneshot(
                Request::builder()
                    .uri("/api/v1/node/host")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }

    #[tokio::test]
    async fn host_route_obeys_runtime_response_bound() {
        let mut state = fixture().with_host(Arc::new(FixedHost(HostStatus::default())));
        state.config.max_response_bytes = 8;
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/node/host")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 413);
    }

    #[tokio::test]
    async fn native_runtime_preserves_the_wired_host_source() {
        let runtime = NativeRuntime::build(
            fixture().with_host(Arc::new(FixedHost(HostStatus {
                rss_bytes: Some(7),
                ..HostStatus::default()
            }))),
            RuntimeConfig::default(),
        )
        .unwrap();
        let response = runtime
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/node/host")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["rss_bytes"],
            7
        );
    }

    #[tokio::test]
    async fn node_routes_return_native_views() {
        let app = router(fixture());
        for path in [
            "/api/v1/node",
            "/api/v1/node/info",
            "/api/v1/node/status",
            "/api/v1/node/sync",
            "/api/v1/node/identity",
            "/api/v1/node/health",
            "/api/v1/node/tip",
            "/api/v1/node/capabilities",
            "/api/v1/chain/tip",
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), 200, "{path}");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert!(!body.is_empty(), "{path}");
        }
    }
}
