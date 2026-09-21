//! Matrix (input blocks) Scala-compat REST surface (Plan 2, task 7):
//! `/blocks/bestInputBlock`, `/blocks/bestInputChain`,
//! `/blocks/{id}/inputBlockTransactions`,
//! `/blocks/{id}/inputBlockTransactionIds`.
//!
//! Response shapes are copied verbatim from the pinned Scala
//! `BlocksApiRoute.scala` (`getBestInputBlockR` / `getBestInputBlocksChainR`
//! / `getInputBlockTransactionsR` / `getInputBlockTransactionIdsR`):
//! `bestOrdering` / `bestInputBlock` default to `""` (Scala's
//! `Option.getOrElse("")`, NOT `null`), and the two id-keyed routes 404
//! when the id names no input block this node holds a record of
//! (`Option[Seq[..]]` in Scala).
//!
//! NOTE: Scala's `ErgoStatsCollector` also adds a `bestInputBlock` key to
//! `/info` (`Option[ModifierId]`, encoded `null` for `None` via circe's
//! default `Option` codec — unlike this module's `""` default). This
//! bridge does NOT add that field to `ScalaInfo`: the mainnet-captured
//! oracle fixture this crate pins `/info`'s key set against
//! (`ergo-api/tests/fixtures/scala/info.json`, `scala_parity.rs`) does
//! not carry that key, i.e. the currently pinned Scala reference predates
//! it. Adding the key would pass compilation while diverging from the
//! actual oracle. See the Task 7 report for the full reasoning.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::compat::types::ScalaTransaction;
use crate::traits::NodeReadState;

/// Matrix (input blocks) read-side snapshot backing the four routes in
/// this module. Refreshed by the node on every non-empty processor
/// effect batch (announcement / delivery / ordering apply / reorg — see
/// `input_blocks::effects::refresh_read_slot`) — NOT on the general
/// per-tick `NodeSnapshot` cadence, since input blocks can arrive and be
/// superseded between ticks. See `ergo-node/src/api_bridge.rs`'s
/// `InputBlocksSlot`.
#[derive(Clone, Debug, Default)]
pub struct ApiInputBlocks {
    /// Hex id of the tip of [`Self::best_chain`]. `None` when no input
    /// block currently leads under the best ordering block.
    pub best_input_block_id: Option<String>,
    /// Best input-block chain under the best ordering block, tip first
    /// (Scala `bestInputBlocksChain()`).
    pub best_chain: Vec<String>,
    /// Per-input-block transaction bodies the node currently holds,
    /// keyed by lowercase hex input-block id. An id absent from this map
    /// means the node has no record of it — the id-keyed routes 404.
    pub blocks: HashMap<String, Vec<ScalaTransaction>>,
}

/// `GET /blocks/bestInputBlock` — ids of the best ordering and input
/// blocks. `bestOrdering` is the best-HEADER id (Scala `bestHeaderOpt`,
/// not merely the best full block) since in the Matrix design ordering
/// blocks ARE headers; `bestInputBlock` is the tip of the best input
/// chain under it. Both default to `""` when absent.
pub async fn best_input_block_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    let best_ordering = read.tip().best_header.header_id;
    let best_input_block = read
        .input_blocks()
        .and_then(|ib| ib.best_input_block_id)
        .unwrap_or_default();
    Json(serde_json::json!({
        "bestOrdering": best_ordering,
        "bestInputBlock": best_input_block,
    }))
    .into_response()
}

/// `GET /blocks/bestInputChain` — the best ordering block id plus the
/// best input-blocks chain under it, tip first.
pub async fn best_input_chain_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    let best_ordering = read.tip().best_header.header_id;
    let best_chain = read
        .input_blocks()
        .map(|ib| ib.best_chain)
        .unwrap_or_default();
    Json(serde_json::json!({
        "bestOrdering": best_ordering,
        "bestInputBlocks": best_chain,
    }))
    .into_response()
}

/// `GET /blocks/{id}/inputBlockTransactions` — the transactions of one
/// input block. 404 when the node has no record of `id`.
pub async fn input_block_transactions_handler(
    State(read): State<Arc<dyn NodeReadState>>,
    Path(id): Path<String>,
) -> Response {
    match resolve_block(&read, &id) {
        Some(txs) => Json(txs).into_response(),
        None => input_block_not_found(),
    }
}

/// `GET /blocks/{id}/inputBlockTransactionIds` — the transaction ids of
/// one input block. 404 when the node has no record of `id`.
pub async fn input_block_transaction_ids_handler(
    State(read): State<Arc<dyn NodeReadState>>,
    Path(id): Path<String>,
) -> Response {
    match resolve_block(&read, &id) {
        Some(txs) => Json(txs.into_iter().map(|t| t.id).collect::<Vec<_>>()).into_response(),
        None => input_block_not_found(),
    }
}

fn resolve_block(read: &Arc<dyn NodeReadState>, id: &str) -> Option<Vec<ScalaTransaction>> {
    read.input_blocks()
        .and_then(|ib| ib.blocks.get(&id.to_ascii_lowercase()).cloned())
}

fn input_block_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": 404,
            "reason": "not-found",
            "detail": "input block not found"
        })),
    )
        .into_response()
}
