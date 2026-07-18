//! v1 mempool DTOs (`mempool_tx` row, summary, depth series, fee
//! histogram) and the `mempool_tx_from_api` projection.

use serde::Serialize;
use utoipa::ToSchema;

use super::boxes::V1Asset;
use super::common::unix_ms_to_iso;
use crate::types::{ApiMempoolTransaction, ApiTxSource, ApiWeightFunction};

// ----- mempool -----------------------------------------------------

/// The v1 `mempool_tx` row — the glossary-renamed,
/// string-amount projection of [`ApiMempoolTransaction`] (`types.rs`). Fees and
/// the priority weight become strings; `first_seen` follows the flat
/// `*_unix_ms` + `*_iso` timestamp rule rather than a nested object.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1MempoolTx {
    pub tx_id: String,
    pub fee: String,
    pub fee_per_byte: String,
    pub size_bytes: u32,
    pub validation_cost_units: u64,
    pub priority_weight: String,
    /// Where the tx entered our pool: `peer | api | wallet | demoted_from_block`
    /// (the real [`ApiTxSource`] taxonomy, not a `propagated|local|reemission|
    /// rebroadcast` classification, which does not match the implemented enum).
    pub source: String,
    pub input_count: u32,
    pub output_count: u32,
    pub parents_in_pool: u32,
    pub first_seen_unix_ms: u64,
    pub first_seen_iso: String,
    pub first_seen_age_ms: u64,
    pub last_checked_age_ms: u64,
}

/// Real [`ApiTxSource`] → stable snake_case wire string.
pub(crate) fn mempool_source_str(source: &ApiTxSource) -> &'static str {
    match source {
        ApiTxSource::Peer { .. } => "peer",
        ApiTxSource::Api => "api",
        ApiTxSource::Wallet => "wallet",
        ApiTxSource::DemotedFromBlock => "demoted_from_block",
    }
}

/// Project a snapshot [`ApiMempoolTransaction`] into the v1 `mempool_tx` row.
pub(crate) fn mempool_tx_from_api(t: &ApiMempoolTransaction) -> V1MempoolTx {
    V1MempoolTx {
        tx_id: t.tx_id.clone(),
        fee: t.fee_nano_erg.to_string(),
        fee_per_byte: t.fee_per_byte_nano_erg.to_string(),
        size_bytes: t.size_bytes,
        validation_cost_units: t.validation_cost_units,
        priority_weight: t.priority_weight.to_string(),
        source: mempool_source_str(&t.source).to_string(),
        input_count: t.input_count,
        output_count: t.output_count,
        parents_in_pool: t.parents_in_pool,
        first_seen_unix_ms: t.first_seen_unix_ms,
        first_seen_iso: unix_ms_to_iso(t.first_seen_unix_ms),
        first_seen_age_ms: t.first_seen_age_ms,
        last_checked_age_ms: t.last_checked_age_ms,
    }
}

/// A resolved input/output of a pooled tx (`io_box`). Every field is
/// nullable: a spent input may not resolve against the extra index or the
/// pool-output overlay, and `null` ≠ `[]` (an unresolved box is not a box with
/// no assets) per the honesty rule of never fabricating data.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1IoBox {
    pub box_id: Option<String>,
    pub address: Option<String>,
    pub value: Option<String>,
    pub assets: Option<Vec<V1Asset>>,
}

/// The v1 `mempool/transactions/{tx_id}` bare object: the `mempool_tx`
/// row (flattened) plus its resolved `io_box` inputs/outputs.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1MempoolTxDetail {
    #[serde(flatten)]
    pub tx: V1MempoolTx,
    pub inputs: Vec<V1IoBox>,
    pub data_inputs: Vec<String>,
    pub outputs: Vec<V1IoBox>,
}

/// Derived pool-utilization fractions on [`V1MempoolSummary`] (0.0 when the
/// matching capacity is unset — never a divide-by-zero).
#[derive(Debug, Serialize, ToSchema)]
pub struct V1MempoolUtilization {
    pub count_pct: f64,
    pub bytes_pct: f64,
}

/// The v1 `mempool/summary` bare object: capacity counters + derived
/// `utilization` + active `weight_function`, plus the OPTIONAL depth
/// `history` (present only when `?history=<n>` is requested).
#[derive(Debug, Serialize, ToSchema)]
pub struct V1MempoolSummary {
    pub size: u32,
    pub total_bytes: u64,
    pub capacity_count: u32,
    pub capacity_bytes: u64,
    pub utilization: V1MempoolUtilization,
    pub revalidation_pending: u32,
    pub weight_function: ApiWeightFunction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<V1MempoolDepthPoint>>,
}

/// One point of the mempool-depth series (`stats/mempool-depth` point shape).
/// The wire projection of a [`crate::v1::mempool_depth::MempoolDepthSample`];
/// the future `stats/mempool-depth` endpoint reuses this SAME type over the SAME
/// ring.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1MempoolDepthPoint {
    pub timestamp_unix_ms: u64,
    pub timestamp_iso: String,
    pub size: u32,
    pub total_bytes: u64,
    pub capacity_count: u32,
    pub capacity_bytes: u64,
    pub min_fee_per_byte: String,
    pub revalidation_pending: u32,
}

impl V1MempoolDepthPoint {
    pub(crate) fn from_sample(s: &crate::v1::mempool_depth::MempoolDepthSample) -> Self {
        V1MempoolDepthPoint {
            timestamp_unix_ms: s.unix_ms,
            timestamp_iso: unix_ms_to_iso(s.unix_ms),
            size: s.size,
            total_bytes: s.total_bytes,
            capacity_count: s.capacity_count,
            capacity_bytes: s.capacity_bytes,
            min_fee_per_byte: s.min_fee_per_byte.to_string(),
            revalidation_pending: s.revalidation_pending,
        }
    }
}

/// One bin of the v1 `mempool/fee-histogram`. `total_fee` is
/// a string amount. `fee_per_byte_min`/`_max` are the ASSUMED-new band:
/// the frozen `pool_fee_histogram` hook is a WAIT-TIME histogram carrying only
/// `{n_txns, total_fee}` per bin, so the band is honestly `null` until a
/// fee-keyed histogram hook exists (design correction — see the group report).
#[derive(Debug, Serialize, ToSchema)]
pub struct V1FeeHistogramBin {
    pub index: u32,
    pub n_txns: u32,
    pub total_fee: String,
    pub fee_per_byte_min: Option<String>,
    pub fee_per_byte_max: Option<String>,
}

/// The v1 `mempool/fee-histogram` bare object: active `weight_function`,
/// the `max_wait_ms` horizon the bins span, and the per-bin counts.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1FeeHistogram {
    pub weight_function: ApiWeightFunction,
    pub max_wait_ms: u64,
    pub bins: Vec<V1FeeHistogramBin>,
}
