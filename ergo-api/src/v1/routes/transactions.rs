//! `transactions/*` reads + submit/check. `GET /transactions/{tx_id}` unifies
//! the confirmed (extra-index) and unconfirmed (mempool overlay) views behind
//! one shape; `POST /transactions/{submit,check}` are the canonical submit
//! paths (`mempool/{submit,check}` stays a documented alias, added by the
//! mempool group). The tx-intelligence members (build / simulate /
//! fee-estimate / status) are a separate group and are not here.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;

use ergo_indexer_types::{IndexerQuery, IndexerStatus, TxId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::address::encode_address;
use ergo_ser::address::NetworkPrefix;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::register::split_register_bytes;
use ergo_ser::transaction::{read_transaction, transaction_id};
use serde_json::json;

use super::dto::{confirmations, unix_ms_to_iso, V1Asset, V1Box, V1Tx};
use super::{parse_id32, V1State};
use crate::blockchain::{
    build_indexed_box_response, build_indexed_tx_response, IndexedErgoBoxResponse,
};
use crate::types::{RawTransactionBytes, SubmitError, SubmitMode};
use crate::v1::error::{v1_error, Reason, V1Error};

/// Fee-proposition ErgoTree, canonical wire hex. Oracle-pinned against
/// `test-vectors/mainnet/fee_proposition.hex` (the same fixture the mempool
/// validator derives its constant from) by [`tests::fee_proposition_hex_matches_oracle`];
/// duplicated here as a hex string rather than taking an `ergo-mempool`
/// dependency into the API crate.
pub(super) const FEE_PROPOSITION_ERGO_TREE_HEX: &str = "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304";

const REGISTER_NAMES: [&str; 6] = ["R4", "R5", "R6", "R7", "R8", "R9"];

fn invalid_tx_id() -> Response {
    v1_error(
        Reason::InvalidTxId,
        "tx_id is not a 64-character lowercase hex string",
        "supply an unprefixed lowercase hex transaction id",
    )
}

// ----- GET /transactions/{tx_id} -----------------------------------------

/// `GET /api/v1/transactions/{tx_id}` — one transaction, confirmed (indexer)
/// first then the mempool overlay. The single source of truth for "is this
/// on-chain yet" (`confirmed`).
#[utoipa::path(
    get, path = "/api/v1/transactions/{tx_id}", tag = "transactions",
    params(("tx_id" = String, Path, description = "64-char lowercase hex transaction id")),
    responses(
        (status = 200, description = "Transaction (confirmed or pooled)", body = V1Tx),
        (status = 400, description = "Malformed tx id", body = V1Error),
        (status = 404, description = "Unknown, confirmed or pooled", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 500, description = "Failed to assemble the transaction response", body = V1Error),
        (status = 503, description = "Extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn tx_by_id(State(state): State<V1State>, Path(tx_id_hex): Path<String>) -> Response {
    let Some(raw) = parse_id32(&tx_id_hex) else {
        return invalid_tx_id();
    };
    let tx_id = TxId::from_bytes(raw);

    let Some(indexer) = state.indexer.clone() else {
        return v1_error(
            Reason::IndexerDisabled,
            "transaction reads require the extra index",
            "start the node with [indexer] enabled = true",
        );
    };
    match indexer.status() {
        IndexerStatus::CaughtUp => {}
        IndexerStatus::Syncing => {
            return v1_error(
                Reason::IndexerSyncing,
                "the extra index is still syncing",
                "retry once GET /api/v1/indexer/status reports caught up",
            )
        }
        IndexerStatus::Halted(reason) => {
            return v1_error(
                Reason::IndexerHalted,
                "the extra index is halted",
                format!("halt reason: {reason:?}"),
            )
        }
    }

    // Confirmed path: extra-index wins over a same-id pool entry.
    if let Some(itx) = indexer.tx_by_id(&tx_id) {
        let bstate = state.blockchain_state(&indexer);
        return match build_indexed_tx_response(&bstate, &itx) {
            Ok(resp) => {
                let best = state.read.status().best_full_block_height;
                Json(confirmed_tx(resp, best)).into_response()
            }
            Err(detail) => v1_error(
                Reason::InternalError,
                "failed to assemble the confirmed transaction",
                detail,
            ),
        };
    }

    // Unconfirmed path: coherent single-snapshot pool read.
    if let Some((bytes, pool_outputs)) = state.mempool.pool_tx_detail(&tx_id) {
        return match unconfirmed_tx(&state, indexer.as_ref(), &tx_id_hex, &bytes, &pool_outputs) {
            Ok(tx) => Json(tx).into_response(),
            Err(detail) => v1_error(
                Reason::InternalError,
                "failed to assemble the unconfirmed transaction",
                detail,
            ),
        };
    }

    v1_error(
        Reason::TxNotFound,
        "no transaction with that id, confirmed or pooled",
        "the id is well-formed but unknown to this node",
    )
}

/// Sum output values paying the fee proposition. Output-side only, so it is
/// computable even when some inputs are unresolved.
pub(super) fn fee_from_hex_values<S: AsRef<str>>(outputs: impl Iterator<Item = (S, u64)>) -> u64 {
    outputs
        .filter(|(tree, _)| tree.as_ref() == FEE_PROPOSITION_ERGO_TREE_HEX)
        .map(|(_, v)| v)
        .sum()
}

fn v1box_from_indexed(b: IndexedErgoBoxResponse, best_full_block_height: u32) -> V1Box {
    let inclusion = b.inclusion_height;
    V1Box {
        box_id: b.box_id,
        value: Some(b.value.to_string()),
        ergo_tree: Some(b.ergo_tree),
        address: Some(b.address),
        assets: Some(
            b.assets
                .into_iter()
                .map(|a| V1Asset {
                    token_id: a.token_id,
                    amount: a.amount.to_string(),
                })
                .collect(),
        ),
        registers: Some(b.additional_registers),
        creation_height: Some(b.creation_height),
        tx_id: Some(b.transaction_id),
        output_index: Some(b.index),
        spent_by: b.spent_transaction_id,
        confirmed: true,
        inclusion_height: Some(inclusion),
        confirmations: Some(confirmations(best_full_block_height, inclusion)),
        global_index: Some(b.global_index),
        spending_proof: None,
        decoded: None,
    }
}

fn confirmed_tx(
    resp: crate::blockchain::IndexedErgoTransactionResponse,
    best_full_block_height: u32,
) -> V1Tx {
    let fee = fee_from_hex_values(resp.outputs.iter().map(|o| (o.ergo_tree.as_str(), o.value)));
    let inclusion = resp.inclusion_height;
    let timestamp = resp.timestamp;
    V1Tx {
        tx_id: resp.id,
        confirmed: true,
        inclusion_height: Some(inclusion),
        confirmations: Some(i64::from(resp.num_confirmations)),
        header_id: Some(resp.block_id),
        timestamp_unix_ms: Some(timestamp),
        timestamp_iso: Some(unix_ms_to_iso(timestamp)),
        index_in_block: Some(resp.index),
        global_index: Some(resp.global_index),
        size_bytes: resp.size.max(0) as u32,
        fee: fee.to_string(),
        inputs: resp
            .inputs
            .into_iter()
            .map(|b| v1box_from_indexed(b, best_full_block_height))
            .collect(),
        data_inputs: resp.data_inputs.into_iter().map(|d| d.box_id).collect(),
        outputs: resp
            .outputs
            .into_iter()
            .map(|b| v1box_from_indexed(b, best_full_block_height))
            .collect(),
    }
}

/// Project a resolved `ErgoBox` (a confirmed UTXO, or a pool-parent output)
/// into the v1 box shape. `confirmed` distinguishes the two provenances.
fn v1box_from_ergo_box(
    network: NetworkPrefix,
    b: &ErgoBox,
    confirmed: bool,
) -> Result<V1Box, String> {
    let c = &b.candidate;
    let box_id = b.box_id().map_err(|e| format!("box_id: {e}"))?;
    let registers = split_register_bytes(c.register_bytes())
        .map_err(|e| format!("register split: {e}"))?
        .into_iter()
        .enumerate()
        .map(|(i, bytes)| (REGISTER_NAMES[i].to_string(), hex::encode(bytes)))
        .collect();
    Ok(V1Box {
        box_id: hex::encode(box_id.as_bytes()),
        value: Some(c.value.to_string()),
        ergo_tree: Some(hex::encode(c.ergo_tree_bytes())),
        address: Some(encode_address(network, c.ergo_tree(), c.ergo_tree_bytes())),
        assets: Some(
            c.tokens
                .iter()
                .map(|t| V1Asset {
                    token_id: hex::encode(t.token_id.as_bytes()),
                    amount: t.amount.to_string(),
                })
                .collect(),
        ),
        registers: Some(registers),
        creation_height: Some(c.creation_height),
        tx_id: Some(hex::encode(b.transaction_id.as_bytes())),
        output_index: Some(b.index),
        spent_by: None,
        confirmed,
        inclusion_height: None,
        confirmations: None,
        global_index: None,
        spending_proof: None,
        decoded: None,
    })
}

/// An unresolved input of an unconfirmed tx: only its `box_id` is known — the
/// rest is honest `null`, never fabricated (§1.1).
fn v1box_unresolved(box_id_hex: String) -> V1Box {
    V1Box {
        box_id: box_id_hex,
        value: None,
        ergo_tree: None,
        address: None,
        assets: None,
        registers: None,
        creation_height: None,
        tx_id: None,
        output_index: None,
        spent_by: None,
        confirmed: false,
        inclusion_height: None,
        confirmations: None,
        global_index: None,
        spending_proof: None,
        decoded: None,
    }
}

fn unconfirmed_tx(
    state: &V1State,
    indexer: &dyn IndexerQuery,
    tx_id_hex: &str,
    bytes: &[u8],
    pool_outputs: &HashMap<ergo_indexer_types::BoxId, ErgoBox>,
) -> Result<V1Tx, String> {
    let mut r = VlqReader::new(bytes);
    let tx = read_transaction(&mut r).map_err(|e| format!("pool tx parse: {e}"))?;
    let network = state.network;
    let self_tx_id = transaction_id(&tx).map_err(|e| format!("tx_id: {e}"))?;

    let fee = fee_from_hex_values(
        tx.output_candidates
            .iter()
            .map(|c| (hex::encode(c.ergo_tree_bytes()), c.value)),
    );

    let outputs = tx
        .output_candidates
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let eb = ErgoBox {
                candidate: <ErgoBoxCandidate as Clone>::clone(c),
                transaction_id: self_tx_id,
                index: i as u16,
            };
            v1box_from_ergo_box(network, &eb, false)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let inputs = tx
        .inputs
        .iter()
        .map(|input| {
            let box_id_hex = hex::encode(input.box_id.as_bytes());
            if let Some(b) = indexer.box_by_id(&input.box_id) {
                let resp = build_indexed_box_response(network, &b)?;
                Ok(v1box_from_indexed(
                    resp,
                    state.read.status().best_full_block_height,
                ))
            } else if let Some(eb) = pool_outputs.get(&input.box_id) {
                v1box_from_ergo_box(network, eb, false)
            } else {
                Ok(v1box_unresolved(box_id_hex))
            }
        })
        .collect::<Result<Vec<_>, String>>()?;

    let data_inputs = tx
        .data_inputs
        .iter()
        .map(|d| hex::encode(d.box_id.as_bytes()))
        .collect();

    Ok(V1Tx {
        tx_id: tx_id_hex.to_string(),
        confirmed: false,
        inclusion_height: None,
        confirmations: None,
        header_id: None,
        timestamp_unix_ms: None,
        timestamp_iso: None,
        index_in_block: None,
        global_index: None,
        size_bytes: bytes.len() as u32,
        fee: fee.to_string(),
        inputs,
        data_inputs,
        outputs,
    })
}

// ----- POST /transactions/{submit,check} ---------------------------------

/// `POST /api/v1/transactions/submit` — broadcast raw tx bytes into the pool.
/// Also mounted at `POST /api/v1/mempool/submit` (Overlap O1 — same handler,
/// documented alias, not a second implementation).
#[utoipa::path(
    post, path = "/api/v1/transactions/submit", tag = "transactions",
    request_body = RawTransactionBytes,
    responses(
        (status = 200, description = "Admitted — `{ tx_id }`", body = serde_json::Value),
        (status = 400, description = "Rejected by admission (deserialize/non_canonical/double_spend/...)", body = V1Error),
        (status = 409, description = "Submission not wired on this node", body = V1Error),
        (status = 503, description = "Node overloaded or shutting down", body = V1Error),
        (status = 504, description = "Admission timed out", body = V1Error),
    ),
)]
pub async fn submit(State(state): State<V1State>, body: Bytes) -> Response {
    submit_inner(state, body, SubmitMode::Broadcast).await
}

/// `POST /api/v1/transactions/check` — validate raw tx bytes without
/// broadcasting. Also mounted at `POST /api/v1/mempool/check` (Overlap O1).
#[utoipa::path(
    post, path = "/api/v1/transactions/check", tag = "transactions",
    request_body = RawTransactionBytes,
    responses(
        (status = 200, description = "Would be admitted — `{ tx_id }`", body = serde_json::Value),
        (status = 400, description = "Would be rejected by admission", body = V1Error),
        (status = 409, description = "Submission not wired on this node", body = V1Error),
        (status = 503, description = "Node overloaded or shutting down", body = V1Error),
        (status = 504, description = "Admission timed out", body = V1Error),
    ),
)]
pub async fn check(State(state): State<V1State>, body: Bytes) -> Response {
    submit_inner(state, body, SubmitMode::CheckOnly).await
}

async fn submit_inner(state: V1State, body: Bytes, mode: SubmitMode) -> Response {
    let Some(submit) = state.submit.clone() else {
        return v1_error(
            Reason::SubmitDisabled,
            "transaction submission is not wired on this node",
            "the submit channel is unavailable in this configuration",
        );
    };
    match submit.submit_transaction(body.to_vec(), mode).await {
        Ok(tx_id) => (axum::http::StatusCode::OK, Json(json!({ "tx_id": tx_id }))).into_response(),
        Err(SubmitError { reason, detail }) => v1_error(
            submit_reason(&reason),
            "transaction rejected by admission",
            detail.unwrap_or_default(),
        ),
    }
}

/// Map the frozen admission-pipeline `reason` verbs (`server::map_submit_error`)
/// onto the canonical v1 [`Reason`] enum; the HTTP status follows from the
/// reason so it agrees with the compat mapping (503 for the transient trio,
/// 504 for timeout, 500 for internal, 400 otherwise).
pub(crate) fn submit_reason(reason: &str) -> Reason {
    match reason {
        "deserialize" => Reason::Deserialize,
        "non_canonical" => Reason::NonCanonical,
        "double_spend" => Reason::DoubleSpend,
        "insufficient_fee" => Reason::InsufficientFee,
        "too_big" => Reason::TooBig,
        "invalid" => Reason::Invalid,
        "insufficient_funds" => Reason::InsufficientFunds,
        "no_inputs_found" => Reason::NoInputsFound,
        "dust_change" => Reason::DustChange,
        "stale_candidate" => Reason::StaleCandidate,
        "forced_tx_exceeds_budget" => Reason::ForcedTxExceedsBudget,
        "insufficient_signatures" => Reason::InsufficientSignatures,
        "script_error" => Reason::ScriptError,
        "unresolved_input" => Reason::UnresolvedInput,
        "cost_limit" => Reason::CostLimit,
        "too_deep" => Reason::TooDeep,
        "invalid_pow" => Reason::InvalidPow,
        "overloaded" => Reason::Overloaded,
        "shutting_down" => Reason::ShuttingDown,
        "route_disabled" => Reason::RouteUnavailable,
        "timeout" => Reason::Timeout,
        "internal_error" => Reason::InternalError,
        // Unknown reason from a future admission verb: fail closed as a 400.
        _ => Reason::BadRequest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- oracle parity -----

    #[test]
    fn fee_proposition_hex_matches_oracle() {
        let fixture = std::fs::read_to_string("../test-vectors/mainnet/fee_proposition.hex")
            .expect("test-vectors/mainnet/fee_proposition.hex present");
        assert_eq!(FEE_PROPOSITION_ERGO_TREE_HEX, fixture.trim());
    }

    // ----- happy path -----

    #[test]
    fn submit_reason_maps_transient_trio_and_defaults() {
        assert_eq!(submit_reason("overloaded"), Reason::Overloaded);
        assert_eq!(submit_reason("timeout"), Reason::Timeout);
        assert_eq!(submit_reason("internal_error"), Reason::InternalError);
        assert_eq!(submit_reason("deserialize"), Reason::Deserialize);
        // A future/unknown verb fails closed as a 400.
        assert_eq!(submit_reason("brand_new_verb"), Reason::BadRequest);
    }

    #[test]
    fn parse_id32_accepts_lowercase_rejects_uppercase_and_bad_len() {
        let lower = "a".repeat(64);
        assert!(
            parse_id32(&lower).is_some(),
            "canonical lowercase id decodes"
        );
        // Uppercase / mixed case decode to identical bytes but are non-canonical
        // — rejected, aligned with `valid_modifier_id` used by the chain routes.
        assert!(parse_id32(&"A".repeat(64)).is_none(), "uppercase rejected");
        assert!(
            parse_id32(&format!("{}{}", "a".repeat(63), "B")).is_none(),
            "mixed case rejected"
        );
        // Length + non-hex still rejected.
        assert!(parse_id32(&"a".repeat(63)).is_none(), "too short");
        assert!(parse_id32(&"a".repeat(65)).is_none(), "too long");
        assert!(parse_id32(&"g".repeat(64)).is_none(), "non-hex");
    }

    #[test]
    fn fee_sums_only_fee_proposition_outputs() {
        let other = "0008cd02aaaa";
        let sum = fee_from_hex_values(
            [
                (FEE_PROPOSITION_ERGO_TREE_HEX, 1_100_000u64),
                (other, 9_000_000),
                (FEE_PROPOSITION_ERGO_TREE_HEX, 100),
            ]
            .into_iter(),
        );
        assert_eq!(sum, 1_100_100);
    }
}
