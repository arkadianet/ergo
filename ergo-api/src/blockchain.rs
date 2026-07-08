//! `/blockchain/*` surface — the Scala-compat extra-index router.
//!
//! Wire shape:
//! - `/blockchain/indexedHeight` → `200 {indexedHeight, fullHeight,
//!   status, haltReason?}`. Always 200 regardless of indexer status —
//!   the response body conveys the status so operators can poll this
//!   endpoint to observe sync progress without hitting a 503. Bypasses
//!   the status gate.
//! - `/blockchain/box/{byId,byIndex}/...` and
//!   `/blockchain/transaction/{byId,byIndex}/...` are gated. When the
//!   indexer is `Syncing` or `Halted`, the gate short-circuits before
//!   the handler runs and emits the pinned error envelope.
//! - On a hit, the box / tx handler renders the canonical wire shape
//!   from the persisted `IndexedErgoBox` / `IndexedErgoTransaction`
//!   record plus address / numConfirmations / blockId / timestamp
//!   enrichment per the openapi schema.
//!
//! Status / halt encoding on the wire:
//! - `status ∈ {"syncing", "caughtUp", "halted"}` (camelCase per Scala).
//! - `haltReason` is the kebab-case form of `IndexerHaltReason`
//!   (e.g. `"db-corruption"`, `"undo-missing"`). The same kebab form is
//!   spliced into the `503 indexer-halted` `detail` string.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use ergo_indexer_types::{IndexerHaltReason, IndexerQuery, IndexerStatus, Page, SortDir};
use ergo_ser::address::NetworkPrefix;
use serde::Serialize;

use crate::compat::traits::NodeChainQuery;
use crate::traits::{ChainParamsView, MempoolView, NodeReadState};

mod balance;
mod blocks;
mod boxes;
mod byaddress;
mod byergotree;
mod bytemplate;
mod range;
mod storage_rent;
mod tokens;
mod transactions;
mod unspent_byaddress;
use balance::{address_to_tree_hash, invalid_address};
pub use balance::{
    balance_for_address_handler, balance_post_handler, BalanceInfoEntry, BalanceResponse,
    TokenAmountEntry,
};
pub use blocks::{
    block_by_header_id_handler, blocks_by_header_ids_handler, IndexedBlockTransactionsResponse,
    IndexedFullBlockResponse,
};
pub(crate) use boxes::build_indexed_box_response;
pub use boxes::{
    box_by_id_handler, box_by_index_handler, AssetEntry, IndexedErgoBoxResponse, SpendingProofEntry,
};
pub use byaddress::{
    boxes_by_address_get_handler, boxes_by_address_post_handler, txs_by_address_get_handler,
    txs_by_address_post_handler,
};
pub use byergotree::{boxes_by_ergo_tree_post_handler, boxes_unspent_by_ergo_tree_post_handler};
pub use bytemplate::{boxes_by_template_hash_handler, boxes_unspent_by_template_hash_handler};
pub use range::{
    box_range_get_handler, box_range_post_handler, transaction_range_get_handler,
    transaction_range_post_handler,
};
pub use storage_rent::{
    storage_rent_eligible_handler, storage_rent_matures_at_handler,
    storage_rent_matures_in_range_handler, StorageRentEligibleEntry, StorageRentEligibleResponse,
    StorageRentMaturesInRangeQuery,
};
pub use tokens::{
    boxes_by_token_id_handler, boxes_unspent_by_token_id_handler, token_by_id_handler,
    tokens_by_ids_handler, IndexedTokenResponse,
};
pub(crate) use transactions::build_indexed_tx_response;
pub use transactions::{
    tx_by_id_handler, tx_by_index_handler, tx_detail_handler, DataInputEntry,
    IndexedErgoTransactionResponse,
};
use unspent_byaddress::pool_unspent_for_tree;
pub use unspent_byaddress::{
    boxes_unspent_by_address_get_handler, boxes_unspent_by_address_post_handler,
    UnspentByAddressQuery,
};

/// Combined router state for `/blockchain/*` handlers. Holds the chain
/// reader (for `fullHeight`, etc.), the indexer reader (for indexed
/// records and status), the network prefix used by the address encoder,
/// and an optional `chain` reader used by the tx handlers for
/// `blockId` / `timestamp` enrichment. `chain` is `Option`-typed because
/// the indexer surface can mount without the compat surface (the
/// status-gate middleware predicates `/blockchain/*` on `indexer`
/// presence alone), but the tx
/// `byId` / `byIndex` routes require the chain reader to fulfill their
/// openapi contract — they are mounted only when both are present.
#[derive(Clone)]
pub struct BlockchainState {
    pub read: Arc<dyn NodeReadState>,
    pub indexer: Arc<dyn IndexerQuery>,
    pub network: NetworkPrefix,
    pub chain: Option<Arc<dyn NodeChainQuery>>,
    /// Snapshot-read mempool overlay used by the unconfirmed surface on
    /// `/blockchain/balance`, `/blockchain/box/unspent/*`, and friends.
    /// Defaults to [`crate::traits::NoopMempoolView`] when the router is
    /// built via the no-overlay [`crate::server::router`] entry point;
    /// production hands the snapshot-backed implementation through
    /// [`crate::server::router_with_mempool`] /
    /// [`crate::server::serve_on_with_mempool`].
    pub mempool: Arc<dyn MempoolView>,
    /// Voted-protocol-parameter view used by the storage-rent
    /// eligibility endpoint to compute `rentOwed` etc. with
    /// consensus-correct math. `None` ⇒ the storage-rent route is not
    /// mounted; every other `/blockchain/*` route is unaffected.
    pub chain_params: Option<Arc<dyn ChainParamsView>>,
}

// ---------------------------------------------------------------------------
// /blockchain/indexedHeight
// ---------------------------------------------------------------------------

/// JSON wire shape for `GET /blockchain/indexedHeight`. Mirrors the
/// Scala route's `{indexedHeight, fullHeight}` body and adds the
/// observable indexer status fields.
#[derive(Debug, Serialize)]
pub struct IndexedHeightResponse {
    #[serde(rename = "indexedHeight")]
    pub indexed_height: u64,
    #[serde(rename = "fullHeight")]
    pub full_height: u32,
    pub status: IndexerStatusLabel,
    #[serde(rename = "haltReason", skip_serializing_if = "Option::is_none")]
    pub halt_reason: Option<&'static str>,
}

/// Wire-string variant of `IndexerStatus` for the indexedHeight body.
/// Encoded as camelCase to match the Scala wire convention (`caughtUp`).
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IndexerStatusLabel {
    Syncing,
    CaughtUp,
    Halted,
}

impl IndexerStatusLabel {
    fn from_status(status: &IndexerStatus) -> Self {
        match status {
            IndexerStatus::Syncing => Self::Syncing,
            IndexerStatus::CaughtUp => Self::CaughtUp,
            IndexerStatus::Halted(_) => Self::Halted,
        }
    }
}

/// `GET /blockchain/indexedHeight`. Always 200; never gated.
pub async fn indexed_height_handler(State(state): State<BlockchainState>) -> Response {
    let status = state.indexer.status();
    let halt_reason = match &status {
        IndexerStatus::Halted(reason) => Some(reason.as_kebab_case()),
        _ => None,
    };
    let body = IndexedHeightResponse {
        indexed_height: state.indexer.indexed_height(),
        full_height: state.read.status().best_full_block_height,
        status: IndexerStatusLabel::from_status(&status),
        halt_reason,
    };
    Json(body).into_response()
}

// ---------------------------------------------------------------------------
// /api/v1/indexer/status — operator health surface
// ---------------------------------------------------------------------------

/// `GET /api/v1/indexer/status`. Always 200; never gated (like
/// `indexedHeight`, this must keep answering while the index is syncing,
/// repairing, or halted — that is exactly when the operator needs it).
/// `/blockchain/indexedHeight` stays pinned to its Scala-parity shape;
/// the self-repair markers and totals live here instead.
///
/// Mounted only when an indexer handle is plumbed — on indexer-less wiring
/// the route 404s, which the UI reads as "extra-index disabled".
#[utoipa::path(
    get,
    path = "/api/v1/indexer/status",
    tag = "node",
    responses(
        (status = 200,
         description = "Extra-index health: sync status, self-repair markers \
(rebuild pending / progress cursor / honestly-skipped boxes), and running totals. \
Conditional: mounted only when the node is wired with an extra-index; 404 means \
the index is disabled.",
         body = crate::types::ApiIndexerStatus, content_type = "application/json"),
    ),
)]
pub async fn indexer_status_handler(State(state): State<BlockchainState>) -> Response {
    let status = state.indexer.status();
    let halt_reason = match &status {
        IndexerStatus::Halted(reason) => Some(reason.as_kebab_case().to_string()),
        _ => None,
    };
    let health = state.indexer.health();
    let body = crate::types::ApiIndexerStatus {
        status: match &status {
            IndexerStatus::Syncing => "syncing".to_string(),
            IndexerStatus::CaughtUp => "caughtUp".to_string(),
            IndexerStatus::Halted(_) => "halted".to_string(),
        },
        halt_reason,
        indexed_height: state.indexer.indexed_height(),
        full_height: state.read.status().best_full_block_height,
        repair: crate::types::ApiIndexerRepair {
            pending: health.repair_pending,
            next_gi: health.repair_next_gi,
            skipped: health.repair_skipped,
            drift_skips: health.drift_skips,
        },
        totals: crate::types::ApiIndexerTotals {
            boxes: health.global_boxes,
            txs: health.global_txs,
        },
    };
    Json(body).into_response()
}

// ---------------------------------------------------------------------------
// Status gate middleware
// ---------------------------------------------------------------------------

/// Pinned error envelope.
///
/// Field order is `error`, `reason`, `detail` to match Scala's
/// `ErrorResponse.asJson` emission. Every route the gate fronts uses
/// this exact body — clients can match on `reason` to distinguish
/// `indexer-syncing` from `indexer-halted` without parsing `detail`.
#[derive(Debug, Serialize)]
pub(super) struct ErrorEnvelope {
    pub(super) error: u16,
    pub(super) reason: &'static str,
    pub(super) detail: String,
}

/// `enforce_status_gate` — axum middleware that fronts every gated
/// `/blockchain/*` route. Reads `indexer.status()` and short-circuits
/// to a `503 indexer-syncing` or `503 indexer-halted` envelope before
/// invoking the inner handler unless the status is `CaughtUp`.
///
/// `/blockchain/indexedHeight` is mounted on a separate router that
/// does not carry this layer — see [`router`] in `server.rs`.
pub async fn enforce_status_gate(
    State(state): State<BlockchainState>,
    req: Request,
    next: Next,
) -> Response {
    match state.indexer.status() {
        IndexerStatus::CaughtUp => next.run(req).await,
        IndexerStatus::Syncing => syncing_envelope(&state),
        IndexerStatus::Halted(reason) => halted_envelope(reason),
    }
}

fn syncing_envelope(state: &BlockchainState) -> Response {
    let n = state.indexer.indexed_height();
    let m = state.read.status().best_full_block_height;
    let body = ErrorEnvelope {
        error: 503,
        reason: "indexer-syncing",
        detail: format!("indexer at height {n}, target {m}"),
    };
    (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
}

fn halted_envelope(reason: IndexerHaltReason) -> Response {
    let body = ErrorEnvelope {
        error: 503,
        reason: "indexer-halted",
        detail: format!("indexer halted: {}", reason.as_kebab_case()),
    };
    (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
}

/// Decode an unprefixed lowercase 64-char hex modifier id. Anything
/// else returns `None`; the handler converts that to 404 to match
/// Scala's `Option`-driven not-found pattern (parse failure is
/// indistinguishable from "no such id" on the wire).
pub(super) fn parse_modifier_id(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

// ---------------------------------------------------------------------------
// Error envelopes — local 404 / 500 helpers
// ---------------------------------------------------------------------------

pub(super) fn not_found(detail: &str) -> Response {
    let body = ErrorEnvelope {
        error: 404,
        reason: "not-found",
        detail: detail.to_string(),
    };
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
    )
        .into_response()
}

pub(super) fn internal_error(detail: &str) -> Response {
    let body = ErrorEnvelope {
        error: 500,
        reason: "internal-error",
        detail: detail.to_string(),
    };
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
    )
        .into_response()
}
// ---------------------------------------------------------------------------
// /blockchain/{transaction,box}/byAddress (POST + GET twin)
// ---------------------------------------------------------------------------

/// Per-route paging cap (`BlockchainApiRoute.scala:41`). Scala enforces
/// this at every byAddress / byTokenId / byTemplate call site; we mirror
/// the literal value so router-walk parity tests can pin the
/// 16384/16385 boundary.
const MAX_ITEMS: i64 = 16384;

/// Scala `paging` directive: `(offset: Int = 0, limit: Int = 5)`. Parsed
/// from `?offset=&limit=` on every paged route. Both fields are
/// `Option<i64>` so missing values fall through to the Scala defaults
/// rather than parse-failing.
#[derive(Debug, Default, serde::Deserialize)]
pub struct PagedQuery {
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(default)]
    pub limit: Option<i64>,
}

/// JSON wire shape `{items: [..], total: <int>}` shared by routes #6/7
/// (transactions) and #9/10 (boxes). `total` is the address-wide count
/// returned by `address_total_*`, not the per-page item count — matches
/// `IndexedErgoAddressSerializer.scala`'s `txCount`/`boxCount` fields.
#[derive(Debug, Serialize)]
pub struct ItemsTotalResponse<T: Serialize> {
    pub items: Vec<T>,
    pub total: i64,
}

/// Validate the paged query and lower it to the trait `Page`. Mirrors
/// `compat::handlers::header_ids_paged_handler` behavior:
///   * missing → Scala defaults (`offset=0, limit=5`),
///   * negative → 400 `bad-request` "offset is negative" / "limit is
///     negative",
///   * `limit > 16384` → 400 `bad-request` "No more than 16384 {noun}
///     can be requested" (verbatim Scala error string).
///
/// Boxed `Err` is the clippy-friendly form: `axum::Response` is ~128 B
/// so a bare `Result<Page, Response>` trips `result_large_err`. Boxing
/// keeps the happy-path return small without changing call-site shape
/// beyond a `*` deref on the err branch.
pub(super) fn resolve_page(q: PagedQuery, noun: &str) -> Result<Page, Box<Response>> {
    let offset = q.offset.unwrap_or(0);
    let limit = q.limit.unwrap_or(5);
    if offset < 0 {
        return Err(Box::new(bad_request("offset is negative")));
    }
    if limit < 0 {
        return Err(Box::new(bad_request("limit is negative")));
    }
    if limit > MAX_ITEMS {
        return Err(Box::new(bad_request(&format!(
            "No more than {MAX_ITEMS} {noun} can be requested"
        ))));
    }
    Ok(Page {
        offset: offset as u32,
        limit: limit as u32,
    })
}

fn bad_request(detail: &str) -> Response {
    let body = ErrorEnvelope {
        error: 400,
        reason: "bad-request",
        detail: detail.to_string(),
    };
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
    )
        .into_response()
}

/// Scala literal for the `sortDirection` parse failure
/// (`BlockchainApiRoute.scala`). Quoted exactly for parity.
const SORT_DIRECTION_INVALID_DETAIL: &str =
    "Invalid parameter for sort direction, valid values are 'ASC' and 'DESC'";

/// Case-insensitive `asc`/`desc` parser; default `desc` per Scala
/// (`BlockchainApiRoute.scala:50, 52, 57`). Returns the pinned 400
/// envelope on any other input. Boxed for the same `result_large_err`
/// reason as `resolve_page`.
pub(super) fn parse_sort_direction(s: Option<&str>) -> Result<SortDir, Box<Response>> {
    match s {
        None => Ok(SortDir::Desc),
        Some(v) => match v.to_ascii_lowercase().as_str() {
            "asc" => Ok(SortDir::Asc),
            "desc" => Ok(SortDir::Desc),
            _ => Err(Box::new(bad_request(SORT_DIRECTION_INVALID_DETAIL))),
        },
    }
}
