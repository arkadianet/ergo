//! `/blockchain/box/{byId,byIndex}` (#1, #2) plus the shared
//! `IndexedErgoBox → JSON` rendering used by every box-emitting route in
//! the `/blockchain/*` surface.
//!
//! `IndexedErgoBoxResponse` inlines all `ErgoTransactionOutput` fields so
//! the on-wire object is flat (Scala uses an `allOf` composition; serde
//! does not flatten nested structs across `allOf` without
//! `#[serde(flatten)]`, so we project the inherited fields directly).

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_indexer_types::types::IndexedErgoBox;
use ergo_indexer_types::BoxId;
use ergo_ser::address::{encode_address, NetworkPrefix};
use ergo_ser::input::{split_context_extension_bytes, SpendingProof};
use ergo_ser::register::split_register_bytes;
use serde::Serialize;

use super::{internal_error, not_found, parse_modifier_id, BlockchainState};

/// JSON wire shape for `IndexedErgoBox` per `openapi.yaml`. Inlines all
/// `ErgoTransactionOutput` fields so the on-wire object is flat (Scala
/// uses an `allOf` composition; serde does not flatten nested structs
/// across `allOf` without `#[serde(flatten)]`, so we project the
/// inherited fields directly).
#[derive(Debug, Serialize)]
pub struct IndexedErgoBoxResponse {
    #[serde(rename = "boxId")]
    pub box_id: String,
    pub value: u64,
    #[serde(rename = "ergoTree")]
    pub ergo_tree: String,
    pub assets: Vec<AssetEntry>,
    #[serde(rename = "creationHeight")]
    pub creation_height: u32,
    #[serde(rename = "additionalRegisters")]
    pub additional_registers: BTreeMap<String, String>,
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    pub index: u16,
    pub address: String,
    /// Required + nullable per openapi: emit JSON `null` when absent.
    #[serde(rename = "spentTransactionId")]
    pub spent_transaction_id: Option<String>,
    // `spendingHeight` is intentionally NOT emitted. The OpenAPI
    // schema at `web/openapi.yaml:353` (the `IndexedErgoBox`
    // schema; line 242 is the unrelated `WalletBox` schema) lists
    // the field as required + nullable, but Scala 6.0.3RC1 omits
    // it entirely from `/blockchain/box/byId` responses even for
    // spent boxes (verified 2026-05-19 via API parity probe on
    // mainnet h=1788718 and testnet h=352776 — zero records
    // carried the field). Scala's wire behaviour is the practical
    // compatibility target; re-introducing the field would break
    // byte-equal parity for every box-emitting route (#9–#16 in
    // the spec inventory) and for nested input/output boxes inside
    // `/blockchain/transaction/*`.
    #[serde(rename = "inclusionHeight")]
    pub inclusion_height: i32,
    /// Optional in openapi (not required) but nullable. Emit JSON `null`
    /// when absent so the wire shape is stable for clients that match on
    /// the field's presence to detect spending.
    #[serde(rename = "spendingProof")]
    pub spending_proof: Option<SpendingProofEntry>,
    #[serde(rename = "globalIndex")]
    pub global_index: i64,
}

#[derive(Debug, Serialize)]
pub struct AssetEntry {
    #[serde(rename = "tokenId")]
    pub token_id: String,
    pub amount: u64,
}

/// `SpendingProof` wire shape — same as `compat::types::ScalaSpendingProof`
/// but kept local so `/blockchain/*` doesn't pull in the compat surface.
#[derive(Debug, Serialize)]
pub struct SpendingProofEntry {
    #[serde(rename = "proofBytes")]
    pub proof_bytes: String,
    pub extension: BTreeMap<String, String>,
}

/// `GET /blockchain/box/byId/{box_id}`. 404 on miss with the standard
/// `not_found` envelope (matches `compat::handlers::not_found`).
pub async fn box_by_id_handler(
    State(state): State<BlockchainState>,
    Path(box_id_hex): Path<String>,
) -> Response {
    let Some(raw) = parse_modifier_id(&box_id_hex) else {
        return not_found("box not found");
    };
    let box_id: BoxId = BoxId::from_bytes(raw);
    match state.indexer.box_by_id(&box_id) {
        Some(b) => render_indexed_box(state.network, &b),
        None => not_found("box not found"),
    }
}

/// `GET /blockchain/box/byIndex/{n}`. `n` is the global index assigned
/// at apply time. 404 on miss.
pub async fn box_by_index_handler(
    State(state): State<BlockchainState>,
    Path(n): Path<i64>,
) -> Response {
    if n < 0 {
        return not_found("box not found");
    }
    match state.indexer.box_by_global_index(n as u64) {
        Some(b) => render_indexed_box(state.network, &b),
        None => not_found("box not found"),
    }
}

fn render_indexed_box(network: NetworkPrefix, b: &IndexedErgoBox) -> Response {
    match build_indexed_box_response(network, b) {
        Ok(resp) => Json(resp).into_response(),
        Err(detail) => internal_error(&detail),
    }
}

pub(super) fn build_indexed_box_response(
    network: NetworkPrefix,
    b: &IndexedErgoBox,
) -> Result<IndexedErgoBoxResponse, String> {
    let candidate = &b.box_data.candidate;
    let assets = candidate
        .tokens
        .iter()
        .map(|t| AssetEntry {
            token_id: hex::encode(t.token_id.as_bytes()),
            amount: t.amount,
        })
        .collect();
    let registers = encode_registers(candidate.register_bytes())?;
    let address = encode_address(network, candidate.ergo_tree(), candidate.ergo_tree_bytes());
    let spending_proof = b
        .spending_proof
        .as_ref()
        .map(encode_spending_proof)
        .transpose()?;

    // Recompute the box id from the canonical box bytes — the indexer
    // record stores the parsed `ErgoBox` but not its precomputed id, so
    // both byId and byIndex paths derive it here.
    let box_id = b.box_data.box_id().map_err(|e| format!("box_id: {e}"))?;

    Ok(IndexedErgoBoxResponse {
        box_id: hex::encode(box_id.as_bytes()),
        value: candidate.value,
        ergo_tree: hex::encode(candidate.ergo_tree_bytes()),
        assets,
        creation_height: candidate.creation_height,
        additional_registers: registers,
        transaction_id: hex::encode(b.box_data.transaction_id.as_bytes()),
        index: b.box_data.index,
        address,
        spent_transaction_id: b
            .spending_tx_id
            .as_ref()
            .map(|id| hex::encode(id.as_bytes())),
        inclusion_height: b.inclusion_height,
        spending_proof,
        global_index: b.global_index,
    })
}

const REGISTER_NAMES: [&str; 6] = ["R4", "R5", "R6", "R7", "R8", "R9"];

/// Slice register-bytes into per-register hex chunks. Mirrors
/// `ergo-node/src/api_bridge.rs::encode_output`'s register-encoding
/// invariant — the parser preserves wire-form bytes verbatim, and we
/// emit them without re-serialization.
fn encode_registers(register_bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let slices =
        split_register_bytes(register_bytes).map_err(|e| format!("register split: {e}"))?;
    Ok(slices
        .into_iter()
        .enumerate()
        .map(|(i, bytes)| (REGISTER_NAMES[i].to_string(), hex::encode(bytes)))
        .collect())
}

fn encode_spending_proof(proof: &SpendingProof) -> Result<SpendingProofEntry, String> {
    let entries = split_context_extension_bytes(proof.extension_bytes())
        .map_err(|e| format!("spending-proof extension split: {e}"))?;
    let extension: BTreeMap<String, String> = entries
        .into_iter()
        .map(|(k, v)| (k.to_string(), hex::encode(v)))
        .collect();
    Ok(SpendingProofEntry {
        proof_bytes: hex::encode(&proof.proof),
        extension,
    })
}
