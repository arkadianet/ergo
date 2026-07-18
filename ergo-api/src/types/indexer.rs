//! Extra-index (indexer) health DTOs for `GET /api/v1/indexer/status`.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Self-repair sub-state of the extra-index for `GET /api/v1/indexer/status`.
/// Mirrors the durable `INDEXER_META` repair markers: `pending` = a
/// chain-free rebuild of the derived template/token segments is owed or in
/// progress; `nextGi` = the rebuild's phase-1 cursor (boxes re-derived so
/// far — progress % = nextGi / totals.boxes); `skipped` = undecodable boxes a
/// completed rebuild had to omit (the honest marker: non-zero with
/// `pending=false` means knowingly incomplete); `driftSkips` = cumulative
/// process-lifetime live-apply skips (diagnostic; resets on restart).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiIndexerRepair {
    pub pending: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_gi: Option<u64>,
    pub skipped: u64,
    pub drift_skips: u64,
}

/// Running index totals for `GET /api/v1/indexer/status`.
///
/// `boxes`/`txs` (and `repair.nextGi`) are `u64` JSON numbers. Mainnet is
/// at ~10^7–10^8 today; a JS consumer only loses precision past 2^53
/// (~9·10^15), which at ~50M boxes/year is comfortably >10^8 years away —
/// documented so the contract's limit is explicit rather than discovered.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiIndexerTotals {
    pub boxes: u64,
    pub txs: u64,
}

/// Operator-grade extra-index health for `GET /api/v1/indexer/status`.
/// Superset of `/blockchain/indexedHeight` (which stays pinned to its
/// Scala-parity shape): adds the self-repair markers and totals so the UI
/// can say "caught up but degraded" honestly. `status` carries the same
/// camelCase label set as indexedHeight (`syncing` / `caughtUp` /
/// `halted`); `haltReason` is the kebab-case reason when halted.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiIndexerStatus {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub halt_reason: Option<String>,
    pub indexed_height: u64,
    pub full_height: u32,
    pub repair: ApiIndexerRepair,
    pub totals: ApiIndexerTotals,
}
