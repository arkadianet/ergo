//! Block reassembly routes (#21, #22).
//!
//! GET  /blockchain/block/byHeaderId/{headerId} — single IndexedFullBlock or 404.
//! POST /blockchain/block/byHeaderIds           — bare [IndexedFullBlock]; misses dropped.
//!
//! Reassembles `IndexedFullBlock` from chain-side block sections (header,
//! blockTransactions, extension, adProofs) joined with per-tx
//! `IndexedErgoTransaction` rows from the indexer. Chain reads come through
//! `NodeChainQuery::full_block_by_id`, which already produces a parsed
//! `ScalaFullBlock`; we replace its bare-tx list with the indexed-tx list
//! keyed by `tx_id`.
//!
//! `ScalaHeader`, `ScalaExtension`, and `ScalaAdProofs` already serialize
//! to the openapi `BlockHeader`, `Extension`, `BlockADProofs` shapes — they
//! are reused as-is. Only the inner block-transactions wrapper is rebuilt
//! with `IndexedErgoTransactionResponse`.
//!
//! The status gate fronts both routes via the layered middleware. Bad
//! hex on the path param surfaces as 404 (Akka path-matcher parity); on
//! the POST batch, malformed ids are silently dropped (Scala flatMap
//! parity), as are header-misses and reassembly failures.

use crate::compat::types::{ScalaAdProofs, ScalaExtension, ScalaFullBlock, ScalaHeader};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_indexer_types::TxId;
use serde::Serialize;

use super::{
    build_indexed_tx_response, internal_error, not_found, parse_modifier_id, BlockchainState,
    IndexedErgoTransactionResponse,
};

#[derive(Debug, Serialize)]
pub struct IndexedFullBlockResponse {
    pub header: ScalaHeader,
    #[serde(rename = "blockTransactions")]
    pub block_transactions: IndexedBlockTransactionsResponse,
    pub extension: ScalaExtension,
    #[serde(rename = "adProofs")]
    pub ad_proofs: Option<ScalaAdProofs>,
    pub size: u32,
}

#[derive(Debug, Serialize)]
pub struct IndexedBlockTransactionsResponse {
    #[serde(rename = "headerId")]
    pub header_id: String,
    pub transactions: Vec<IndexedErgoTransactionResponse>,
    pub size: u32,
}

pub async fn block_by_header_id_handler(
    State(state): State<BlockchainState>,
    Path(header_id_hex): Path<String>,
) -> Response {
    if parse_modifier_id(&header_id_hex).is_none() {
        return not_found("block not found");
    }
    let chain = match state.chain.as_ref() {
        Some(c) => c,
        None => {
            return internal_error("chain reader missing; block routes require chain plumbing");
        }
    };
    let scala_block = match chain.full_block_by_id(&header_id_hex) {
        Some(b) => b,
        None => return not_found("block not found"),
    };
    match build_indexed_full_block_response(&state, scala_block) {
        Ok(Some(resp)) => Json(resp).into_response(),
        // Reassembly failure (indexer lag or data inconsistency) presents
        // to the client as a clean miss — same observable shape as Scala
        // when `IndexedBlock.fromOption` returns None.
        Ok(None) => not_found("block not found"),
        Err(error) => internal_error(&error),
    }
}

/// `POST /blockchain/block/byHeaderIds`. Repeated ids are answered once;
/// the distinct-id cap and the response-size budget come from
/// [`crate::batch_ids::BlockBatchLimits`] and both refusals are a 400.
/// Blocks are assembled and serialized one at a time, so an oversized
/// request stops at the block that crosses the budget.
pub async fn blocks_by_header_ids_handler(
    State(state): State<BlockchainState>,
    limits: Option<axum::Extension<crate::batch_ids::BlockBatchLimits>>,
    Json(ids): Json<Vec<String>>,
) -> Response {
    let limits = crate::batch_ids::BlockBatchLimits::from_extension(limits);
    let chain = match state.chain.as_ref() {
        Some(c) => c,
        None => {
            return internal_error("chain reader missing; block routes require chain plumbing");
        }
    };
    let ids = match crate::batch_ids::dedupe_and_cap(ids, limits.max_blocks) {
        Ok(ids) => ids,
        Err(detail) => return super::bad_request(&detail),
    };
    let too_large = || {
        super::bad_request(&crate::batch_ids::response_too_large(
            limits.max_response_bytes,
        ))
    };
    let mut out = crate::batch_ids::BudgetedJsonArray::new(limits.max_response_bytes);
    for id in &ids {
        if parse_modifier_id(id).is_none() {
            continue;
        }
        let Some(scala_block) = chain.full_block_by_id(id) else {
            continue;
        };
        match build_indexed_full_block_response(&state, scala_block) {
            Ok(Some(resp)) => {
                if out.push(&resp).is_err() {
                    return too_large();
                }
            }
            Ok(None) => {}
            Err(error) => return internal_error(&error),
        }
    }
    match out.finish() {
        Ok(bytes) => crate::batch_ids::json_bytes_response(bytes),
        Err(_) => too_large(),
    }
}

fn build_indexed_full_block_response(
    state: &BlockchainState,
    scala_block: ScalaFullBlock,
) -> Result<Option<IndexedFullBlockResponse>, String> {
    let ScalaFullBlock {
        header,
        block_transactions,
        extension,
        ad_proofs,
        size,
    } = scala_block;

    let header_id_hex = block_transactions.header_id.clone();
    let bt_size = block_transactions.size;

    let mut indexed_txs: Vec<IndexedErgoTransactionResponse> =
        Vec::with_capacity(block_transactions.transactions.len());
    for stx in &block_transactions.transactions {
        let Some(tx_id_bytes) = parse_modifier_id(&stx.id) else {
            return Ok(None);
        };
        let tx_id = TxId::from_bytes(tx_id_bytes);
        let Some(indexed_tx) = state
            .indexer
            .tx_by_id(&tx_id)
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let resp = match build_indexed_tx_response(state, &indexed_tx) {
            Ok(r) => r,
            Err(detail) => {
                tracing::warn!(%detail, "block reassembly: failed to build indexed tx response");
                return Err(detail);
            }
        };
        indexed_txs.push(resp);
    }

    Ok(Some(IndexedFullBlockResponse {
        header,
        block_transactions: IndexedBlockTransactionsResponse {
            header_id: header_id_hex,
            transactions: indexed_txs,
            size: bt_size,
        },
        extension,
        ad_proofs,
        size,
    }))
}
