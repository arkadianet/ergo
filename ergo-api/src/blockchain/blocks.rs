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
        Some(resp) => Json(resp).into_response(),
        // Reassembly failure (indexer lag or data inconsistency) presents
        // to the client as a clean miss — same observable shape as Scala
        // when `IndexedBlock.fromOption` returns None.
        None => not_found("block not found"),
    }
}

pub async fn blocks_by_header_ids_handler(
    State(state): State<BlockchainState>,
    Json(ids): Json<Vec<String>>,
) -> Response {
    let chain = match state.chain.as_ref() {
        Some(c) => c,
        None => {
            return internal_error("chain reader missing; block routes require chain plumbing");
        }
    };
    let mut out: Vec<IndexedFullBlockResponse> = Vec::with_capacity(ids.len());
    for id in &ids {
        if parse_modifier_id(id).is_none() {
            continue;
        }
        let Some(scala_block) = chain.full_block_by_id(id) else {
            continue;
        };
        if let Some(resp) = build_indexed_full_block_response(&state, scala_block) {
            out.push(resp);
        }
    }
    Json(out).into_response()
}

fn build_indexed_full_block_response(
    state: &BlockchainState,
    scala_block: ScalaFullBlock,
) -> Option<IndexedFullBlockResponse> {
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
        let tx_id_bytes = parse_modifier_id(&stx.id)?;
        let tx_id = TxId::from_bytes(tx_id_bytes);
        let indexed_tx = state.indexer.tx_by_id(&tx_id)?;
        let resp = match build_indexed_tx_response(state, &indexed_tx) {
            Ok(r) => r,
            Err(detail) => {
                tracing::warn!(%detail, "block reassembly: failed to build indexed tx response");
                return None;
            }
        };
        indexed_txs.push(resp);
    }

    Some(IndexedFullBlockResponse {
        header,
        block_transactions: IndexedBlockTransactionsResponse {
            header_id: header_id_hex,
            transactions: indexed_txs,
            size: bt_size,
        },
        extension,
        ad_proofs,
        size,
    })
}
