//! `GET /api/v1/transactions/{tx_id}/status` — transaction lifecycle
//! (confirmed / pending / unknown) with the ranking-in-mempool pass
//! that computes rank / ahead-bytes / fee-competitiveness / ETA.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

use ergo_indexer_types::{IndexerStatus, TxId};

use super::super::dto::unix_ms_to_iso;
use super::super::V1State;
use super::invalid_tx_id;
use crate::v1::error::{v1_error, Reason, V1Error};

// ==========================================================================
//  GET /transactions/{tx_id}/status
// ==========================================================================

#[derive(Debug, Serialize, ToSchema)]
struct PoolStatus {
    priority_weight: String,
    fee: String,
    fee_per_byte: String,
    rank: u32,
    pool_size: u32,
    ahead_of_you_bytes: u64,
    fee_competitiveness_pct: f64,
    /// OMITTED when the node has no pool wait-time oracle wired (same
    /// absent-field convention as this response's other optionals) — a
    /// missing estimate must not read as "next block".
    #[serde(skip_serializing_if = "Option::is_none")]
    eta_blocks: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eta_ms: Option<u64>,
    parents_in_pool: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct StatusResponse {
    tx_id: String,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pool: Option<PoolStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_seen_unix_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_seen_iso: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inclusion_height: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmations: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    header_id: Option<String>,
}

/// `GET /api/v1/transactions/{tx_id}/status` — lifecycle + ETA. Confirmed
/// (extra-index) wins over pooled; a well-formed unknown id is a 200
/// `state:"unknown"` (a legitimate polled answer), only a malformed id is a 400.
#[utoipa::path(
    get, path = "/api/v1/transactions/{tx_id}/status", tag = "transactions",
    params(("tx_id" = String, Path, description = "64-char lowercase hex transaction id")),
    responses(
        (status = 200, description = "Lifecycle status: confirmed / pending / unknown", body = StatusResponse),
        (status = 400, description = "Malformed tx id", body = V1Error),
        (status = 500, description = "Failed to assemble the confirmed transaction status", body = V1Error),
    ),
)]
pub async fn status(State(state): State<V1State>, Path(tx_id_hex): Path<String>) -> Response {
    let Some(raw) = super::super::parse_id32(&tx_id_hex) else {
        return invalid_tx_id();
    };
    let tx_id = TxId::from_bytes(raw);

    // Confirmed path (extra index, when caught up).
    if let Some(indexer) = state.indexer.as_ref() {
        if matches!(indexer.status(), IndexerStatus::CaughtUp) {
            if let Some(itx) = indexer.tx_by_id(&tx_id) {
                let bstate = state.blockchain_state(indexer);
                return match crate::blockchain::build_indexed_tx_response(&bstate, &itx) {
                    Ok(resp) => Json(StatusResponse {
                        tx_id: resp.id,
                        state: "confirmed",
                        pool: None,
                        first_seen_unix_ms: None,
                        first_seen_iso: None,
                        inclusion_height: Some(resp.inclusion_height),
                        confirmations: Some(i64::from(resp.num_confirmations)),
                        header_id: Some(resp.block_id),
                    })
                    .into_response(),
                    Err(detail) => v1_error(
                        Reason::InternalError,
                        "failed to assemble the confirmed transaction status",
                        detail,
                    ),
                };
            }
        }
    }

    // Pooled path.
    if let Some(row) = state.read.mempool_transaction(&tx_id_hex) {
        return Json(pooled_status(&state, row)).into_response();
    }

    // Unknown: a legitimate lifecycle answer, not an error.
    Json(StatusResponse {
        tx_id: tx_id_hex,
        state: "unknown",
        pool: None,
        first_seen_unix_ms: None,
        first_seen_iso: None,
        inclusion_height: None,
        confirmations: None,
        header_id: None,
    })
    .into_response()
}

fn pooled_status(state: &V1State, row: crate::types::ApiMempoolTransaction) -> StatusResponse {
    let rows = state.read.mempool_transactions().transactions;
    let pool_size = rows.len() as u32;

    // Rank in the mining order (priority-weight DESC, tx_id ASC tiebreak) and
    // the total size of everything strictly ahead. One ordered pass.
    let mut ahead_bytes: u64 = 0;
    let mut rank: u32 = 1;
    let mut max_fpb: u64 = row.fee_per_byte_nano_erg;
    for other in &rows {
        max_fpb = max_fpb.max(other.fee_per_byte_nano_erg);
        if other.tx_id == row.tx_id {
            continue;
        }
        let ahead = other.priority_weight > row.priority_weight
            || (other.priority_weight == row.priority_weight && other.tx_id < row.tx_id);
        if ahead {
            rank += 1;
            ahead_bytes += u64::from(other.size_bytes);
        }
    }

    let competitiveness = if max_fpb == 0 {
        1.0
    } else {
        row.fee_per_byte_nano_erg as f64 / max_fpb as f64
    };

    let interval_ms = state.read.info().target_block_interval_ms.max(1);
    // No wait-time oracle (chain reader unwired) → an honest null, never a
    // fabricated one-block estimate.
    let eta_ms = state
        .chain
        .as_ref()
        .map(|c| c.pool_expected_wait_time_ms(row.fee_nano_erg, row.size_bytes));
    let eta_blocks =
        eta_ms.map(|ms| (ms.div_ceil(interval_ms)).max(1).min(u64::from(u32::MAX)) as u32);

    StatusResponse {
        tx_id: row.tx_id.clone(),
        state: "pending",
        pool: Some(PoolStatus {
            priority_weight: row.priority_weight.to_string(),
            fee: row.fee_nano_erg.to_string(),
            fee_per_byte: row.fee_per_byte_nano_erg.to_string(),
            rank,
            pool_size,
            ahead_of_you_bytes: ahead_bytes,
            fee_competitiveness_pct: competitiveness,
            eta_blocks,
            eta_ms,
            parents_in_pool: row.parents_in_pool,
        }),
        first_seen_unix_ms: Some(row.first_seen_unix_ms),
        first_seen_iso: Some(unix_ms_to_iso(row.first_seen_unix_ms)),
        inclusion_height: None,
        confirmations: None,
        header_id: None,
    }
}
