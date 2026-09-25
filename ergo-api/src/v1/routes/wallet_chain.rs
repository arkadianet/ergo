use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ergo_wallet_protocol::chain as wire;
use serde::Deserialize;
use utoipa::ToSchema;

use super::extract::{V1Json, V1Query};
use crate::traits::{WalletChain, WalletChainError};
use crate::v1::auth::{require_tier, Tier, V1AuthConfig};
use crate::v1::error::{v1_error, Reason, V1Error};
use crate::v1::governor::{governor_mw, Governor, RouteClass};

pub const DEFAULT_BLOCKS_SINCE_LIMIT: u32 = 100;
pub const MAX_BLOCKS_SINCE_LIMIT: u32 = 1024;
pub const MAX_BLOCKS_PER_RESPONSE: u32 = MAX_BLOCKS_SINCE_LIMIT;
pub const MAX_BLOCKS_PER_REQUEST: u32 = MAX_BLOCKS_PER_RESPONSE;

#[derive(Clone, Default)]
pub struct WalletChainState {
    pub chain: Option<Arc<dyn WalletChain>>,
}

impl WalletChainState {
    pub fn new(chain: Option<Arc<dyn WalletChain>>) -> Self {
        Self { chain }
    }

    pub fn with_chain(chain: Arc<dyn WalletChain>) -> Self {
        Self { chain: Some(chain) }
    }

    fn chain(&self) -> Result<&Arc<dyn WalletChain>, Box<Response>> {
        self.chain.as_ref().ok_or_else(|| {
            Box::new(v1_error(
                Reason::RouteUnavailable,
                "the wallet chain API is not wired on this node",
                "configure a committed chain adapter before using this endpoint",
            ))
        })
    }
}

pub type V1ChainState = WalletChainState;

#[derive(Debug, Deserialize)]
pub struct BlocksSinceQuery {
    height: Option<u32>,
    id: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct BoxQuery {
    tip: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitBody {
    #[serde(alias = "bytes", alias = "transactionBytes", alias = "txBytes")]
    transaction: Option<String>,
    #[serde(
        rename = "snapshotId",
        alias = "snapshot_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    snapshot_id: Option<String>,
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletChainTip {
    pub height: u32,
    pub header_id: String,
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletChainHeader {
    pub height: u32,
    pub header_id: String,
    pub parent_id: String,
    pub timestamp_unix_ms: u64,
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletChainReemissionInput {
    pub token_id: String,
    pub amount: String,
    pub box_ids: Option<Vec<String>>,
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletChainSnapshot {
    pub tip: WalletChainTip,
    pub headers: Vec<WalletChainHeader>,
    pub active_parameters: serde_json::Value,
    pub reemission_inputs: Vec<WalletChainReemissionInput>,
    pub snapshot_id: String,
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletChainAsset {
    pub token_id: String,
    pub amount: String,
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletChainBox {
    pub box_id: String,
    pub bytes: String,
    pub value: String,
    pub assets: Vec<WalletChainAsset>,
    pub creation_tx_id: String,
    pub creation_output_index: u16,
    pub creation_height: u32,
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletChainInput {
    pub box_id: String,
    pub index: u16,
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletChainOutput {
    pub box_id: String,
    pub index: u16,
    pub bytes: String,
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletChainTransaction {
    pub tx_id: String,
    pub inputs: Vec<WalletChainInput>,
    pub outputs: Vec<WalletChainOutput>,
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletChainBlock {
    pub block_id: String,
    pub height: u32,
    pub parent_id: String,
    pub transactions: Vec<WalletChainTransaction>,
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletChainCursor {
    pub height: u32,
    pub header_id: String,
}

#[derive(Debug, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WalletChainBlocksSinceResponse {
    Forward {
        tip: WalletChainTip,
        blocks: Vec<WalletChainBlock>,
    },
    Ancestor {
        tip: WalletChainTip,
        ancestor: WalletChainCursor,
    },
    Pruned {
        tip: WalletChainTip,
        #[schema(rename = "minimumHeight")]
        minimum_height: u32,
    },
}

#[derive(Debug, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WalletChainPrunedBlocksSinceResponse {
    Pruned {
        tip: WalletChainTip,
        #[schema(rename = "minimumHeight")]
        minimum_height: u32,
    },
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletChainBoxLookupResponse {
    pub tip: WalletChainTip,
    #[serde(rename = "box")]
    pub box_info: WalletChainBox,
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletChainSubmitRequest {
    pub transaction: String,
    pub snapshot_id: Option<String>,
}

#[derive(Debug, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum WalletChainSubmitReason {
    Duplicate,
    Invalid,
    Fee,
}

#[derive(Debug, ToSchema)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum WalletChainSubmitResponse {
    Accepted {
        tip: WalletChainTip,
        #[schema(rename = "txId")]
        tx_id: String,
    },
    Duplicate {
        tip: WalletChainTip,
        #[schema(rename = "txId")]
        tx_id: String,
    },
    Rejected {
        tip: WalletChainTip,
        reason: WalletChainSubmitReason,
        detail: Option<String>,
    },
}

#[derive(ToSchema)]
#[serde(untagged)]
pub enum WalletChainSubmitBadRequest {
    Error(V1Error),
    Rejected(WalletChainSubmitResponse),
}

fn invalid_params(message: impl Into<String>, detail: impl Into<String>) -> Response {
    v1_error(Reason::InvalidParams, message, detail)
}

fn invalid_hex(field: &str) -> Response {
    v1_error(
        Reason::InvalidHex,
        format!("{field} must be a 64-character lowercase hex string"),
        "supply an unprefixed lowercase hexadecimal identifier",
    )
}

fn invalid_box_id() -> Response {
    v1_error(
        Reason::InvalidBoxId,
        "box id must be a 64-character lowercase hex string",
        "supply an unprefixed lowercase hexadecimal box id",
    )
}

fn validate_id(value: &str, field: &str) -> Result<(), Box<Response>> {
    wire::validate_id32(value, field).map_err(|_| Box::new(invalid_hex(field)))
}

/// Cursor *identity* — the semantic half of the cursor contract that
/// [`wire::validate_id32`] cannot see, because a cursor id is a well-formed
/// 64-hex string on every wire that is semantically wrong.
///
/// Height `0` is the genesis sentinel: the only header id the chain can have
/// there is the all-zero [`wire::GENESIS_CURSOR_ID`]. Any positive height
/// must name the real committed header, so the all-zero id is meaningless
/// there. Both mismatches are client bugs, so they are answered with the
/// `invalid_params` 400 envelope here — before `WalletChain` is called — rather
/// than being reported by the adapter as a chain failure (a 500).
fn validate_cursor_identity(height: u32, id: &str) -> Result<(), Box<Response>> {
    let is_genesis_id = id == wire::GENESIS_CURSOR_ID;
    if height == 0 {
        if is_genesis_id {
            return Ok(());
        }
        return Err(Box::new(invalid_params(
            "height 0 requires the genesis cursor id",
            format!(
                "supply the all-zero genesis cursor id {}, or the real height with its header id",
                wire::GENESIS_CURSOR_ID
            ),
        )));
    }
    if is_genesis_id {
        return Err(Box::new(invalid_params(
            "a positive cursor height requires a non-zero header id",
            "supply the committed header id at this height, or height=0 with the all-zero genesis cursor id",
        )));
    }
    Ok(())
}

fn validate_box_id(value: &str) -> Result<(), Box<Response>> {
    wire::validate_id32(value, "box_id").map_err(|_| Box::new(invalid_box_id()))
}

async fn run_chain<T, F>(chain: Arc<dyn WalletChain>, operation: F) -> Result<T, WalletChainError>
where
    T: Send + 'static,
    F: FnOnce(&dyn WalletChain) -> Result<T, WalletChainError> + Send + 'static,
{
    tokio::task::spawn_blocking(move || operation(chain.as_ref()))
        .await
        .map_err(|error| WalletChainError::Internal(format!("wallet chain task failed: {error}")))?
}

fn map_chain_error(error: WalletChainError) -> Response {
    match error {
        WalletChainError::Unsupported => v1_error(
            Reason::RouteUnavailable,
            "the wallet chain operation is not supported by this node",
            "configure a committed chain adapter before using this endpoint",
        ),
        WalletChainError::Overloaded(detail) => {
            v1_error(Reason::Overloaded, "the node is overloaded", detail)
        }
        WalletChainError::ShuttingDown(detail) => {
            v1_error(Reason::ShuttingDown, "the node is shutting down", detail)
        }
        WalletChainError::Timeout(detail) => v1_error(
            Reason::Timeout,
            "the node did not complete transaction admission in time",
            detail,
        ),
        WalletChainError::StaleTip { expected, actual } => v1_error(
            Reason::StaleTip,
            "the committed chain tip changed; retry from the new tip",
            format!(
                "expected height {} / {}, actual height {} / {}",
                expected.height, expected.header_id, actual.height, actual.header_id
            ),
        ),
        WalletChainError::HistoryPruned { minimum_height } => v1_error(
            Reason::HistoryPruned,
            "the requested chain history is no longer retained",
            format!("minimum available height: {minimum_height}"),
        ),
        WalletChainError::BoxNotFound => v1_error(
            Reason::BoxNotFound,
            "the requested box is not in the committed UTXO set",
            "the box may be spent or unknown to this node",
        ),
        WalletChainError::Invalid(detail) => v1_error(
            Reason::InvalidParams,
            "the chain request is invalid",
            detail,
        ),
        WalletChainError::Failure(detail) | WalletChainError::Internal(detail) => v1_error(
            Reason::InternalError,
            "the wallet chain operation failed",
            detail,
        ),
    }
}

fn render_blocks_since(response: wire::BlocksSinceResponse) -> Response {
    match response {
        wire::BlocksSinceResponse::Pruned(_) => (StatusCode::GONE, Json(response)).into_response(),
        wire::BlocksSinceResponse::Forward(_) | wire::BlocksSinceResponse::Ancestor(_) => {
            Json(response).into_response()
        }
    }
}

fn render_submit(response: wire::SubmitResponse) -> Response {
    match response {
        wire::SubmitResponse::Accepted { .. } | wire::SubmitResponse::Duplicate { .. } => {
            Json(response).into_response()
        }
        wire::SubmitResponse::Rejected { .. } => {
            (StatusCode::BAD_REQUEST, Json(response)).into_response()
        }
    }
}

#[utoipa::path(
    get, path = "/api/v1/chain/tip", tag = "chain", operation_id = "wallet_chain_tip",
    responses(
        (status = 200, description = "Committed full-block tip", body = WalletChainTip),
        (status = 503, description = "Wallet chain adapter unavailable", body = V1Error),
        (status = 500, description = "Wallet chain adapter failure", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn tip(State(state): State<WalletChainState>) -> Response {
    let chain = match state.chain() {
        Ok(chain) => chain.clone(),
        Err(response) => return *response,
    };
    match run_chain(chain, |chain| chain.committed_tip()).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => map_chain_error(error),
    }
}

#[utoipa::path(
    get, path = "/api/v1/chain/snapshot", tag = "chain", operation_id = "wallet_chain_snapshot",
    responses(
        (status = 200, description = "Committed signing snapshot", body = WalletChainSnapshot),
        (status = 503, description = "Wallet chain adapter unavailable", body = V1Error),
        (status = 500, description = "Wallet chain adapter failure", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn snapshot(State(state): State<WalletChainState>) -> Response {
    let chain = match state.chain() {
        Ok(chain) => chain.clone(),
        Err(response) => return *response,
    };
    match run_chain(chain, |chain| chain.chain_snapshot()).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => map_chain_error(error),
    }
}

#[utoipa::path(
    get, path = "/api/v1/chain/boxes/{id}", tag = "chain", operation_id = "wallet_chain_box_lookup",
    params(("id" = String, Path, description = "64-character lowercase hex box id")),
    params(("tip" = String, Query, description = "64-character lowercase hex committed tip id")),
    responses(
        (status = 200, description = "Committed box", body = WalletChainBoxLookupResponse),
        (status = 400, description = "Malformed box id or missing tip", body = V1Error),
        (status = 404, description = "Box is not unspent", body = V1Error),
        (status = 409, description = "Committed tip changed", body = V1Error),
        (status = 503, description = "Wallet chain adapter unavailable", body = V1Error),
        (status = 500, description = "Wallet chain adapter failure", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn box_lookup(
    State(state): State<WalletChainState>,
    Path(id): Path<String>,
    V1Query(query): V1Query<BoxQuery>,
) -> Response {
    if let Err(response) = validate_box_id(&id) {
        return *response;
    }
    let Some(tip) = query.tip else {
        return invalid_params(
            "tip is required",
            "supply the committed tip as a lowercase 64-hex query id",
        );
    };
    if let Err(response) = validate_id(&tip, "tip") {
        return *response;
    }
    let chain = match state.chain() {
        Ok(chain) => chain.clone(),
        Err(response) => return *response,
    };
    let request = wire::BoxLookupRequest {
        box_id: id,
        tip: Some(tip),
        height: None,
    };
    match run_chain(chain, move |chain| chain.lookup_box(request)).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => map_chain_error(error),
    }
}

#[utoipa::path(
    get, path = "/api/v1/chain/blocks-since", tag = "chain", operation_id = "wallet_chain_blocks_since",
    params(
        ("height" = u32, Query, description = "Committed cursor height (0 is the genesis cursor)"),
        ("id" = String, Query, description = "64-character lowercase hex cursor header id (all-zero exactly at height 0)"),
        ("limit" = Option<u32>, Query, minimum = 1, maximum = 1024,
            description = "Maximum blocks to return (default 100, cap 1024)"),
    ),
    responses(
        (status = 200, description = "Forward or ancestor result", body = WalletChainBlocksSinceResponse),
        (status = 400, description = "Malformed cursor, cursor/height identity mismatch, or invalid limit", body = V1Error),
        (status = 409, description = "Committed tip changed", body = V1Error),
        (status = 410, description = "Requested history is pruned", body = WalletChainPrunedBlocksSinceResponse),
        (status = 503, description = "Wallet chain adapter unavailable", body = V1Error),
        (status = 500, description = "Wallet chain adapter failure", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn blocks_since(
    State(state): State<WalletChainState>,
    V1Query(query): V1Query<BlocksSinceQuery>,
) -> Response {
    let Some(height) = query.height else {
        return invalid_params("height is required", "supply the cursor height");
    };
    let Some(id) = query.id else {
        return invalid_params("id is required", "supply the cursor header id");
    };
    if let Err(response) = validate_id(&id, "id") {
        return *response;
    }
    if let Err(response) = validate_cursor_identity(height, &id) {
        return *response;
    }
    let limit = match query.limit {
        None => DEFAULT_BLOCKS_SINCE_LIMIT,
        Some(0) => {
            return invalid_params("limit must be greater than zero", "supply a positive limit")
        }
        Some(limit) => limit.min(MAX_BLOCKS_PER_RESPONSE),
    };
    let chain = match state.chain() {
        Ok(chain) => chain.clone(),
        Err(response) => return *response,
    };
    let tip_chain = chain.clone();
    let request = wire::BlocksSinceRequest { height, id, limit };
    match run_chain(chain, move |chain| chain.blocks_since(request)).await {
        Ok(response) => render_blocks_since(response),
        Err(WalletChainError::HistoryPruned { minimum_height }) => {
            match run_chain(tip_chain, |chain| chain.committed_tip()).await {
                Ok(tip) => render_blocks_since(wire::BlocksSinceResponse::Pruned(
                    wire::PrunedBlocksSince {
                        tip,
                        minimum_height,
                    },
                )),
                Err(error) => map_chain_error(error),
            }
        }
        Err(error) => map_chain_error(error),
    }
}

#[utoipa::path(
    post, path = "/api/v1/chain/transactions", tag = "chain", operation_id = "wallet_chain_submit",
    request_body = WalletChainSubmitRequest,
    responses(
        (status = 200, description = "Accepted or duplicate transaction", body = WalletChainSubmitResponse),
        (status = 400, description = "Malformed request (V1Error) or typed transaction rejection", body = WalletChainSubmitBadRequest),
        (status = 409, description = "Snapshot tip changed", body = V1Error),
        (status = 503, description = "Wallet chain adapter unavailable", body = V1Error),
        (status = 504, description = "Node transaction admission timed out", body = V1Error),
        (status = 500, description = "Wallet chain adapter failure", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn submit(
    State(state): State<WalletChainState>,
    V1Json(body): V1Json<SubmitBody>,
) -> Response {
    let Some(transaction) = body.transaction else {
        return invalid_params(
            "transaction is required",
            "supply lowercase hexadecimal bytes",
        );
    };
    if transaction.is_empty() {
        return v1_error(
            Reason::InvalidHex,
            "transaction bytes must be non-empty lowercase hex",
            "supply an even-length lowercase hexadecimal string",
        );
    }
    if let Err(error) = wire::validate_hex_bytes(&transaction, "transaction") {
        return v1_error(
            Reason::InvalidHex,
            "transaction bytes must be lowercase hexadecimal",
            error,
        );
    }
    if let Some(snapshot_id) = body.snapshot_id.as_deref() {
        if let Err(error) = wire::validate_snapshot_id(snapshot_id) {
            return invalid_params("snapshotId is invalid", error);
        }
    }
    let chain = match state.chain() {
        Ok(chain) => chain.clone(),
        Err(response) => return *response,
    };
    let request = wire::SubmitRequest {
        transaction,
        snapshot_id: body.snapshot_id,
    };
    match run_chain(chain, move |chain| chain.submit_transaction(request)).await {
        Ok(response) => render_submit(response),
        Err(error) => map_chain_error(error),
    }
}

pub fn wallet_chain_router(
    state: WalletChainState,
    governor: Arc<Governor>,
    auth: Arc<V1AuthConfig>,
) -> Router {
    let reads: Router<WalletChainState> = Router::new()
        .route("/api/v1/chain/tip", get(tip))
        .route("/api/v1/chain/snapshot", get(snapshot))
        .route("/api/v1/chain/boxes/:id", get(box_lookup))
        .route("/api/v1/chain/blocks-since", get(blocks_since))
        .route_layer(axum::middleware::from_fn_with_state(
            governor.state(RouteClass::HeavyRead),
            governor_mw,
        ));
    let writes: Router<WalletChainState> = Router::new()
        .route("/api/v1/chain/transactions", post(submit))
        .route_layer(axum::middleware::from_fn_with_state(
            governor.state(RouteClass::Compute),
            governor_mw,
        ));
    reads
        .merge(writes)
        .route_layer(axum::middleware::from_fn_with_state(
            auth.state(Tier::Operator),
            require_tier,
        ))
        .with_state(state)
}
