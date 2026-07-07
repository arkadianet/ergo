//! `/blockchain/transaction/{byId,byIndex}` (#3, #4) plus the shared
//! `IndexedErgoTransaction → JSON` rendering pipeline.
//!
//! All `Option` fields on `IndexedErgoTransactionResponse` model the
//! construction pipeline, not on-wire absence: every field is `required`
//! per `openapi.yaml`, so build failures surface as 500 rather than
//! emitting a sparsely populated DTO.

use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_indexer_types::types::IndexedErgoTransaction;
use ergo_indexer_types::{BoxId, TxId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::address::{encode_address, NetworkPrefix};
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::transaction::read_transaction;
use serde::Serialize;

use super::{
    build_indexed_box_response, internal_error, not_found, parse_modifier_id, BlockchainState,
    IndexedErgoBoxResponse,
};
use crate::types::{ApiAsset, ApiIoBox, ApiTxDetail};

/// JSON wire shape for `IndexedErgoTransaction` per `openapi.yaml`. All
/// fields are `required` per the schema, so none of the `Option` fields
/// here represent absence on the wire — they're modeling the construction
/// pipeline (fail-fast when chain enrichment can't resolve).
#[derive(Debug, Serialize)]
pub struct IndexedErgoTransactionResponse {
    pub id: String,
    pub inputs: Vec<IndexedErgoBoxResponse>,
    #[serde(rename = "dataInputs")]
    pub data_inputs: Vec<DataInputEntry>,
    pub outputs: Vec<IndexedErgoBoxResponse>,
    #[serde(rename = "inclusionHeight")]
    pub inclusion_height: i32,
    #[serde(rename = "numConfirmations")]
    pub num_confirmations: i32,
    #[serde(rename = "blockId")]
    pub block_id: String,
    pub timestamp: u64,
    pub index: i32,
    #[serde(rename = "globalIndex")]
    pub global_index: i64,
    pub size: i32,
}

#[derive(Debug, Serialize)]
pub struct DataInputEntry {
    #[serde(rename = "boxId")]
    pub box_id: String,
}

/// `GET /blockchain/transaction/byId/{tx_id}`. 404 on miss.
pub async fn tx_by_id_handler(
    State(state): State<BlockchainState>,
    Path(tx_id_hex): Path<String>,
) -> Response {
    let Some(raw) = parse_modifier_id(&tx_id_hex) else {
        return not_found("transaction not found");
    };
    let tx_id: TxId = TxId::from_bytes(raw);
    match state.indexer.tx_by_id(&tx_id) {
        Some(tx) => render_indexed_tx(&state, &tx),
        None => not_found("transaction not found"),
    }
}

/// `GET /blockchain/transaction/byIndex/{n}`. 404 on miss / negative `n`.
pub async fn tx_by_index_handler(
    State(state): State<BlockchainState>,
    Path(n): Path<i64>,
) -> Response {
    if n < 0 {
        return not_found("transaction not found");
    }
    match state.indexer.tx_by_global_index(n as u64) {
        Some(tx) => render_indexed_tx(&state, &tx),
        None => not_found("transaction not found"),
    }
}

fn render_indexed_tx(state: &BlockchainState, tx: &IndexedErgoTransaction) -> Response {
    match build_indexed_tx_response(state, tx) {
        Ok(resp) => Json(resp).into_response(),
        Err(detail) => internal_error(&detail),
    }
}

pub(crate) fn build_indexed_tx_response(
    state: &BlockchainState,
    tx: &IndexedErgoTransaction,
) -> Result<IndexedErgoTransactionResponse, String> {
    // `chain` is required to enrich `blockId` / `timestamp`. The tx
    // routes mount only when chain is plumbed; reaching the handler with
    // `None` here would mean the router was misconfigured — surface as
    // 500 internal-error rather than silently emit an empty blockId.
    let chain = state
        .chain
        .as_ref()
        .ok_or_else(|| "chain reader missing; tx routes require chain plumbing".to_string())?;

    let inputs = tx
        .input_nums
        .iter()
        .map(|n| dereference_box(state, *n, "input"))
        .collect::<Result<Vec<_>, _>>()?;
    let outputs = tx
        .output_nums
        .iter()
        .map(|n| dereference_box(state, *n, "output"))
        .collect::<Result<Vec<_>, _>>()?;
    let data_inputs = tx
        .data_inputs
        .iter()
        .map(|id| DataInputEntry {
            box_id: hex::encode(id.as_bytes()),
        })
        .collect();

    let height = tx.height;
    if height < 0 {
        return Err(format!("tx height is negative: {height}"));
    }
    let height_u32 = height as u32;
    let header_ids = chain.header_ids_at_height(height_u32);
    let block_id = header_ids
        .into_iter()
        .next()
        .ok_or_else(|| format!("no canonical header at indexed tx height {height_u32}"))?;
    let header = chain.header_by_id(&block_id).ok_or_else(|| {
        format!("header {block_id} missing despite indexed tx at height {height_u32}")
    })?;

    // Confirmation count: `best - inclusion`, matching Scala
    // `IndexedErgoTransaction.scala:62`
    // (`_numConfirmations = history.fullBlockHeight - height`).
    // Note this is *not* the conventional Bitcoin-style
    // `tip - inclusion + 1` — Scala counts blocks ABOVE the tx's
    // block, not the inclusion block itself. Floored at 0 if the
    // chain tip has temporarily slipped below the indexed height
    // (e.g. a deep reorg in flight); the mirror is monotonic in
    // steady state.
    let best = state.read.status().best_full_block_height as i64;
    let raw_confirmations = best - height as i64;
    let num_confirmations = raw_confirmations.max(0).min(i32::MAX as i64) as i32;

    Ok(IndexedErgoTransactionResponse {
        id: hex::encode(tx.id.as_bytes()),
        inputs,
        data_inputs,
        outputs,
        inclusion_height: height,
        num_confirmations,
        block_id,
        timestamp: header.timestamp,
        index: tx.index_in_block,
        global_index: tx.global_index,
        size: tx.size,
    })
}

/// Dereference a box global index back to its full `IndexedErgoBox`
/// record and project it to the wire DTO. Missing rows are a consistency
/// failure (apply writes box rows + tx rows in the same redb txn), so we
/// surface them as 500 rather than silently producing partial output.
fn dereference_box(
    state: &BlockchainState,
    global_index: i64,
    role: &str,
) -> Result<IndexedErgoBoxResponse, String> {
    if global_index < 0 {
        return Err(format!(
            "tx references negative {role} global index {global_index}"
        ));
    }
    let b = state
        .indexer
        .box_by_global_index(global_index as u64)
        .ok_or_else(|| {
            format!("tx references missing {role} box at global index {global_index}")
        })?;
    build_indexed_box_response(state.network, &b)
}

// ---------------------------------------------------------------------------
// /api/v1/transactions/{tx_id}/detail — resolved inputs/outputs for the UI
// ---------------------------------------------------------------------------

/// `GET /api/v1/transactions/{tx_id}/detail`. Returns each input/output
/// resolved to `{address, value, tokens}` for the UI detail drawer.
/// A confirmed (extra-indexed) tx wins over an unconfirmed pool tx of the
/// same id (turnover can briefly leave a tx in both). 404 when neither
/// surface has it. Mounted ungated so the unconfirmed drawer works while
/// the indexer is still syncing.
pub async fn tx_detail_handler(
    State(state): State<BlockchainState>,
    Path(tx_id_hex): Path<String>,
) -> Response {
    let Some(raw) = parse_modifier_id(&tx_id_hex) else {
        return not_found("transaction not found");
    };
    let tx_id = TxId::from_bytes(raw);

    if let Some(tx) = state.indexer.tx_by_id(&tx_id) {
        return match build_tx_detail_confirmed(&state, &tx) {
            Ok(d) => Json(d).into_response(),
            Err(detail) => internal_error(&detail),
        };
    }
    if let Some((bytes, pool_outputs)) = state.mempool.pool_tx_detail(&tx_id) {
        return match build_tx_detail_unconfirmed(&state, &tx_id_hex, &bytes, &pool_outputs) {
            Ok(d) => Json(d).into_response(),
            Err(detail) => internal_error(&detail),
        };
    }
    not_found("transaction not found")
}

/// Map a fully-resolved confirmed box projection to the drawer DTO.
fn io_from_indexed(b: IndexedErgoBoxResponse) -> ApiIoBox {
    ApiIoBox {
        box_id: Some(b.box_id),
        address: Some(b.address),
        value: Some(b.value),
        tokens: Some(
            b.assets
                .into_iter()
                .map(|a| ApiAsset {
                    token_id: a.token_id,
                    amount: a.amount,
                })
                .collect(),
        ),
    }
}

/// Confirmed path: reuse the extra-index tx renderer so input/output box
/// projection (and its address/value/token resolution) never drifts from
/// `/blockchain/transaction/byId`.
fn build_tx_detail_confirmed(
    state: &BlockchainState,
    tx: &IndexedErgoTransaction,
) -> Result<ApiTxDetail, String> {
    let resp = build_indexed_tx_response(state, tx)?;
    Ok(ApiTxDetail {
        tx_id: resp.id,
        inputs: resp.inputs.into_iter().map(io_from_indexed).collect(),
        outputs: resp.outputs.into_iter().map(io_from_indexed).collect(),
    })
}

/// Project an output candidate (or a resolved source box) to the drawer
/// DTO. Uses the shared `encode_address` — no serializer fork.
fn io_from_candidate(
    network: NetworkPrefix,
    box_id: Option<String>,
    c: &ErgoBoxCandidate,
) -> ApiIoBox {
    ApiIoBox {
        box_id,
        address: Some(encode_address(network, c.ergo_tree(), c.ergo_tree_bytes())),
        value: Some(c.value),
        tokens: Some(
            c.tokens
                .iter()
                .map(|t| ApiAsset {
                    token_id: hex::encode(t.token_id.as_bytes()),
                    amount: t.amount,
                })
                .collect(),
        ),
    }
}

/// Unconfirmed path: parse the pooled tx bytes and resolve each spent
/// input against the confirmed UTXO set first, then the (same-snapshot)
/// pool-output overlay. Inputs that resolve to neither emit `null`
/// address/value rather than a fabricated figure. Outputs always resolve
/// (the candidate carries value + ergoTree + tokens).
fn build_tx_detail_unconfirmed(
    state: &BlockchainState,
    tx_id_hex: &str,
    bytes: &[u8],
    pool_outputs: &HashMap<BoxId, ErgoBox>,
) -> Result<ApiTxDetail, String> {
    let mut r = VlqReader::new(bytes);
    let tx = read_transaction(&mut r).map_err(|e| format!("pool tx parse: {e}"))?;

    let outputs = tx
        .output_candidates
        .iter()
        .map(|c| io_from_candidate(state.network, None, c))
        .collect();

    let inputs = tx
        .inputs
        .iter()
        .map(|input| {
            let box_id_hex = hex::encode(input.box_id.as_bytes());
            if let Some(b) = state.indexer.box_by_id(&input.box_id) {
                io_from_candidate(state.network, Some(box_id_hex), &b.box_data.candidate)
            } else if let Some(eb) = pool_outputs.get(&input.box_id) {
                io_from_candidate(state.network, Some(box_id_hex), &eb.candidate)
            } else {
                // Unresolved: emit null for every projected field —
                // including tokens — so "unknown" can't read as
                // "known to have none".
                ApiIoBox {
                    box_id: Some(box_id_hex),
                    address: None,
                    value: None,
                    tokens: None,
                }
            }
        })
        .collect();

    Ok(ApiTxDetail {
        tx_id: tx_id_hex.to_string(),
        inputs,
        outputs,
    })
}
