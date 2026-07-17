//! `GET /api/v1/transactions/fee-estimate` — mempool-derived fee tiers
//! backed by the chain reader's pool fee oracle.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::super::extract::V1Query;
use super::super::V1State;
use super::{DEFAULT_TX_SIZE_BYTES, FEE_TIERS, FLOOR_HORIZON_MINUTES};
use crate::v1::error::{v1_error, Reason, V1Error};

// ==========================================================================
//  GET /transactions/fee-estimate
// ==========================================================================

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct FeeEstimateQuery {
    #[serde(default)]
    target_blocks: Option<u32>,
    #[serde(default)]
    tx_size_bytes: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
struct FeeTier {
    target_blocks: u32,
    fee_per_byte: String,
    recommended_fee: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct FeeEstimateResponse {
    target_blocks: u32,
    tx_size_bytes: u32,
    recommended_fee: String,
    fee_per_byte: String,
    tiers: Vec<FeeTier>,
    pool_size: u32,
    floor_fee_per_byte: String,
}

/// `GET /api/v1/transactions/fee-estimate?target_blocks=1|3|10&tx_size_bytes=` —
/// mempool-derived fee tiers (nanoERG-per-byte as strings). Backed by the chain
/// reader's `pool_recommended_fee`; honest `mempool_view_disabled` if unwired.
#[utoipa::path(
    get, path = "/api/v1/transactions/fee-estimate", tag = "transactions",
    params(
        ("target_blocks" = Option<u32>, Query, description = "1, 3 (default), or 10"),
        ("tx_size_bytes" = Option<u32>, Query, description = "Assumed tx size in bytes (default 200)"),
    ),
    responses(
        (status = 200, description = "Fee tiers for the requested + standard horizons", body = FeeEstimateResponse),
        (status = 400, description = "Invalid target_blocks/tx_size_bytes", body = V1Error),
        (status = 409, description = "Fee estimation not wired on this node", body = V1Error),
    ),
)]
pub async fn fee_estimate(
    State(state): State<V1State>,
    V1Query(q): V1Query<FeeEstimateQuery>,
) -> Response {
    let target_blocks = q.target_blocks.unwrap_or(3);
    if !FEE_TIERS.contains(&target_blocks) {
        return v1_error(
            Reason::InvalidParams,
            "target_blocks must be 1, 3, or 10",
            "pick one of the supported fee horizons",
        );
    }
    let size = q.tx_size_bytes.unwrap_or(DEFAULT_TX_SIZE_BYTES);
    if size == 0 {
        return v1_error(
            Reason::InvalidParams,
            "tx_size_bytes must be a positive byte count",
            "omit tx_size_bytes to use the nominal default",
        );
    }

    let Some(chain) = state.chain.as_ref() else {
        return v1_error(
            Reason::MempoolViewDisabled,
            "fee estimation requires the chain-reader mempool bridge",
            "this node was wired without the pool fee oracle",
        );
    };

    let interval_ms = state.read.info().target_block_interval_ms.max(1);
    let per_byte = |fee: u64| (fee / u64::from(size)).to_string();

    let tiers: Vec<FeeTier> = FEE_TIERS
        .iter()
        .map(|&tb| {
            let minutes = tier_minutes(tb, interval_ms);
            let fee = chain.pool_recommended_fee(minutes, size);
            FeeTier {
                target_blocks: tb,
                fee_per_byte: per_byte(fee),
                recommended_fee: fee.to_string(),
            }
        })
        .collect();

    let selected = tiers
        .iter()
        .find(|t| t.target_blocks == target_blocks)
        .expect("target_blocks is one of FEE_TIERS");
    let floor_fee = chain.pool_recommended_fee(FLOOR_HORIZON_MINUTES, size);

    Json(FeeEstimateResponse {
        target_blocks,
        tx_size_bytes: size,
        recommended_fee: selected.recommended_fee.clone(),
        fee_per_byte: selected.fee_per_byte.clone(),
        pool_size: state.read.mempool_summary().size,
        floor_fee_per_byte: per_byte(floor_fee),
        tiers,
    })
    .into_response()
}

/// Wait-time (minutes) for a `target_blocks` horizon, at least 1 minute.
fn tier_minutes(target_blocks: u32, interval_ms: u64) -> u32 {
    let ms = u64::from(target_blocks) * interval_ms;
    let minutes = ms.div_ceil(60_000);
    minutes.max(1).min(u64::from(u32::MAX)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_minutes_rounds_up_and_floors_at_one() {
        // 120s block interval → 1/3/10-block horizons.
        assert_eq!(tier_minutes(1, 120_000), 2);
        assert_eq!(tier_minutes(3, 120_000), 6);
        assert_eq!(tier_minutes(10, 120_000), 20);
        // Sub-minute horizons floor at 1 minute.
        assert_eq!(tier_minutes(1, 1_000), 1);
    }
}
