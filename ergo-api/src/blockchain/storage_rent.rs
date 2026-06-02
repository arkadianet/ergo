//! `GET /blockchain/storageRent/eligibleAt/{height}` — Rust-node-exclusive
//! storage-rent eligibility endpoint. Returns the paged list of unspent
//! boxes whose `creationHeight ≤ height - StoragePeriod`, with rent
//! computation derived from the voted `storageFeeFactor` governing
//! block-`height` validation.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use ergo_indexer_types::{IndexerQuery, Page, SortDir, StorageRentEligibleDto};
use serde::{Deserialize, Serialize};

use super::{internal_error, AssetEntry, BlockchainState};
use crate::traits::ChainParamsView;

/// Ergo `StoragePeriod` — boxes are eligible for storage-rent collection
/// once they have lived at least this many blocks since their stamped
/// `creationHeight`. Constant; one snapshot per ~4 years on mainnet.
pub(crate) const STORAGE_PERIOD: u32 = 1_051_200;

/// Per-route paging cap. Mirrors the Scala `MaxItems` default for the
/// blockchain surface.
const MAX_LIMIT: u32 = 16_384;
const DEFAULT_LIMIT: u32 = 100;

#[derive(Debug, Deserialize)]
pub struct StorageRentEligibleQuery {
    #[serde(default)]
    pub offset: Option<u32>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default, rename = "sortDirection")]
    pub sort_direction: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StorageRentEligibleResponse {
    pub items: Vec<StorageRentEligibleEntry>,
    pub total: u64,
}

#[derive(Debug, Serialize)]
pub struct StorageRentEligibleEntry {
    #[serde(rename = "boxId")]
    pub box_id: String,
    #[serde(rename = "boxValue")]
    pub box_value: u64,
    /// Tokens the box holds, byte-shape-identical to `/blockchain/box/byId`'s
    /// `assets`. Empty when the box carries none. Sourced by a read-time
    /// lookup of the box record — the storage-rent index stores no token
    /// data — so a missing box record fails the response (see `build_items`).
    pub assets: Vec<AssetEntry>,
    #[serde(rename = "boxBytesLen")]
    pub box_bytes_len: i32,
    #[serde(rename = "creationHeight")]
    pub creation_height: u32,
    #[serde(rename = "globalBoxIndex")]
    pub global_box_index: i64,
    /// Raw consensus value: `storage_fee_factor.wrapping_mul(box_bytes_len)`.
    /// Negative when the i32 product wraps — see `consensusFeeOverflow`.
    #[serde(rename = "storageFeeI32")]
    pub storage_fee_i32: i32,
    /// Un-wrapped i64 product `factor * bytes_len`. The fee that
    /// SHOULD govern the box if i32 didn't wrap. Always equals
    /// `storageFeeI32 as i64` when no overflow; differs (positive)
    /// otherwise.
    #[serde(rename = "mathematicalStorageFee")]
    pub mathematical_storage_fee: i64,
    /// True when the i32 multiplication overflowed (i.e.
    /// `mathematicalStorageFee > i32::MAX`). The defining symptom of
    /// the consensus overflow bug.
    #[serde(rename = "consensusFeeOverflow")]
    pub consensus_fee_overflow: bool,
    /// Consensus-truthful storageFeeNotCovered flag. NOT a signal of
    /// "miner takes whole box" by itself — combine with
    /// `consensusFeeOverflow` via `expectedConsensusBranch` for
    /// branch identity.
    #[serde(rename = "storageFeeNotCovered")]
    pub storage_fee_not_covered: bool,
    /// Which branch of the consensus rule actually fires. The
    /// `overflowInverted` value flags a box that mathematically
    /// belongs in `wholeBoxTake` but the i32 wrap forced into the
    /// recreate branch — these are the boxes that never get collected.
    #[serde(rename = "expectedConsensusBranch")]
    pub expected_consensus_branch: ExpectedConsensusBranch,
    /// True when a rational party will ever attempt to collect this
    /// box. False on `overflowInverted` (collection requires gifting
    /// `|wrapped fee|` ERG to the box's original owner with no
    /// recoupment — no one does this). The right boolean filter for
    /// "boxes worth showing as actually collectable."
    #[serde(rename = "practicallyCollectable")]
    pub practically_collectable: bool,
    /// Expected miner net take if the box is collected at all. Equals
    /// `boxValue` on `wholeBoxTake`, `storageFeeI32 as i64` on
    /// `recreateWithFee`, and `0` on `overflowInverted` (no collection
    /// will happen).
    #[serde(rename = "rentOwed")]
    pub rent_owed: i64,
    /// Minimum value the recreated output must carry. `0` on
    /// `wholeBoxTake`; `boxValue − storageFee` on the other two
    /// branches (the overflow case requires a value greater than the
    /// box's own — that's why the box is uncollectable in practice).
    #[serde(rename = "minRecreatedOutputValue")]
    pub min_recreated_output_value: i64,
}

/// Which branch of the storage-rent consensus rule fires on this
/// box. The `overflowInverted` case is the i32-multiplication bug:
/// boxes that should consensus-rule-evaluate to `wholeBoxTake` but
/// whose `factor × bytes_len` wraps negative get forced into the
/// `recreateWithFee` arithmetic, requiring the rent-collecting
/// transaction to top up the box at the original owner's address —
/// no rational party does this, so these boxes never get collected.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ExpectedConsensusBranch {
    /// Consensus rule's `storageFeeNotCovered` branch fires correctly:
    /// `mathematical_fee >= box.value`. Miner takes the whole box;
    /// no recreate. Always profitable; will be collected.
    WholeBoxTake,
    /// `0 < mathematical_fee < box.value`. Miner takes the fee,
    /// recreates the rest at `box.value − fee`. Profitable for the
    /// miner; collected when economically attractive.
    RecreateWithFee,
    /// i32 overflow: `mathematical_fee > i32::MAX`, wraps to a
    /// negative i32. Forces the recreate branch with a recreated
    /// output value of `box.value + |wrapped_fee|`, which the miner
    /// must fund themselves (the funded ERG goes into the recreated
    /// box at the owner's ergoTree, not back to the miner). Effectively
    /// uncollectable in practice.
    OverflowInverted,
}

/// `GET /blockchain/storageRent/eligibleAt/{height}?offset=&limit=&sortDirection=`
///
/// `height = 0` (and any `height` below `StoragePeriod`) trivially
/// returns `{items: [], total: 0}` — no box can be StoragePeriod-old
/// at genesis. For `height ≥ StoragePeriod`, the cutoff is
/// `height - StoragePeriod` and the indexer scans
/// `unspent_by_creation_height` for matching rows.
pub async fn storage_rent_eligible_handler(
    State(state): State<BlockchainState>,
    Path(height): Path<u32>,
    Query(q): Query<StorageRentEligibleQuery>,
) -> Response {
    // Mount-time guard: chain_params is the wiring contract for
    // route presence. If we somehow land here without it, fall back
    // to a 503 rather than panicking.
    let chain_params: Arc<dyn ChainParamsView> = match state.chain_params.clone() {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": 503,
                    "reason": "chain-params-unavailable",
                    "detail": "node was not configured with the voted-parameter view",
                })),
            )
                .into_response();
        }
    };

    // Trivial-empty short-circuit for heights where no box can yet
    // qualify. Also dodges the `H - 1` lookup at H = 0.
    if height < STORAGE_PERIOD {
        return Json(StorageRentEligibleResponse {
            items: Vec::new(),
            total: 0,
        })
        .into_response();
    }
    let height_cutoff = height - STORAGE_PERIOD;

    // Block H is validated under H-1's voted parameters. Handler
    // short-circuits H == 0 above, so the subtraction is safe.
    let factor = match chain_params.storage_fee_factor_for_validation_at(height) {
        Some(f) => f,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": 503,
                    "reason": "voted-params-unavailable",
                    "detail": format!("no voted-params row at-or-before height {}", height - 1),
                })),
            )
                .into_response();
        }
    };

    let dir = match q.sort_direction.as_deref().unwrap_or("desc") {
        "asc" => SortDir::Asc,
        "desc" => SortDir::Desc,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": 400,
                    "reason": "bad-sort-direction",
                    "detail": format!("sortDirection must be 'asc' or 'desc'; got {other:?}"),
                })),
            )
                .into_response();
        }
    };
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let page = Page {
        offset: q.offset.unwrap_or(0),
        limit,
    };

    let rows = state
        .indexer
        .storage_rent_eligible_paged(height_cutoff, page, dir);
    let total = state.indexer.storage_rent_eligible_total(height_cutoff);

    let items = match build_items(rows, factor, &*chain_params, &*state.indexer) {
        Ok(items) => items,
        Err(detail) => return internal_error(&detail),
    };

    Json(StorageRentEligibleResponse { items, total }).into_response()
}

/// Forward-looking single-height slice. Returns currently-unspent
/// boxes that mature at exactly `height` — i.e. those whose
/// `creation_height = height − StoragePeriod`. Empty for `height <
/// StoragePeriod` (no box can yet mature at heights below the period).
pub async fn storage_rent_matures_at_handler(
    State(state): State<BlockchainState>,
    Path(height): Path<u32>,
    Query(q): Query<StorageRentEligibleQuery>,
) -> Response {
    let chain_params = match state.chain_params.clone() {
        Some(p) => p,
        None => return chain_params_unavailable(),
    };
    if height < STORAGE_PERIOD {
        return Json(StorageRentEligibleResponse {
            items: Vec::new(),
            total: 0,
        })
        .into_response();
    }
    let cutoff = height - STORAGE_PERIOD;
    let factor = match chain_params.storage_fee_factor_for_validation_at(height) {
        Some(f) => f,
        None => return voted_params_unavailable(height),
    };
    let dir = match parse_sort_dir(q.sort_direction.as_deref()) {
        Ok(d) => d,
        Err(resp) => return *resp,
    };
    let page = Page {
        offset: q.offset.unwrap_or(0),
        limit: q.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT),
    };
    let rows = state
        .indexer
        .storage_rent_in_creation_range(cutoff, cutoff, page, dir);
    let total = state
        .indexer
        .storage_rent_total_in_creation_range(cutoff, cutoff);
    let items = match build_items(rows, factor, &*chain_params, &*state.indexer) {
        Ok(items) => items,
        Err(detail) => return internal_error(&detail),
    };
    Json(StorageRentEligibleResponse { items, total }).into_response()
}

#[derive(Debug, Deserialize)]
pub struct StorageRentMaturesInRangeQuery {
    #[serde(rename = "fromHeight")]
    pub from_height: u32,
    #[serde(rename = "toHeight")]
    pub to_height: u32,
    #[serde(default)]
    pub offset: Option<u32>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default, rename = "sortDirection")]
    pub sort_direction: Option<String>,
}

/// Forward-looking range slice. Returns currently-unspent boxes
/// whose `creation_height ∈ [fromHeight − StoragePeriod, toHeight − StoragePeriod]`.
/// Empty when `fromHeight > toHeight` or when the range falls below
/// the StoragePeriod entirely.
pub async fn storage_rent_matures_in_range_handler(
    State(state): State<BlockchainState>,
    Query(q): Query<StorageRentMaturesInRangeQuery>,
) -> Response {
    let chain_params = match state.chain_params.clone() {
        Some(p) => p,
        None => return chain_params_unavailable(),
    };
    if q.from_height > q.to_height {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": 400,
                "reason": "bad-range",
                "detail": format!("fromHeight ({}) > toHeight ({})", q.from_height, q.to_height),
            })),
        )
            .into_response();
    }
    // Use `to_height` as the parameter source (most recent voted-params
    // governing the upper edge of the range). Since `storageFeeFactor`
    // is constant within an epoch and rent collection economics depend
    // on the factor at the consuming block's height, surfacing
    // computations against to_height's factor is the closest single-
    // value approximation. Range queries that span an epoch boundary
    // are rare in practice — voted-param changes come every 1024 blocks.
    if q.to_height < STORAGE_PERIOD {
        return Json(StorageRentEligibleResponse {
            items: Vec::new(),
            total: 0,
        })
        .into_response();
    }
    let lo_cutoff = q.from_height.saturating_sub(STORAGE_PERIOD);
    let hi_cutoff = q.to_height - STORAGE_PERIOD;
    let factor = match chain_params.storage_fee_factor_for_validation_at(q.to_height) {
        Some(f) => f,
        None => return voted_params_unavailable(q.to_height),
    };
    let dir = match parse_sort_dir(q.sort_direction.as_deref()) {
        Ok(d) => d,
        Err(resp) => return *resp,
    };
    let page = Page {
        offset: q.offset.unwrap_or(0),
        limit: q.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT),
    };
    let rows = state
        .indexer
        .storage_rent_in_creation_range(lo_cutoff, hi_cutoff, page, dir);
    let total = state
        .indexer
        .storage_rent_total_in_creation_range(lo_cutoff, hi_cutoff);
    let items = match build_items(rows, factor, &*chain_params, &*state.indexer) {
        Ok(items) => items,
        Err(detail) => return internal_error(&detail),
    };
    Json(StorageRentEligibleResponse { items, total }).into_response()
}

fn chain_params_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": 503,
            "reason": "chain-params-unavailable",
            "detail": "node was not configured with the voted-parameter view",
        })),
    )
        .into_response()
}

fn voted_params_unavailable(height: u32) -> Response {
    let prev = height.saturating_sub(1);
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": 503,
            "reason": "voted-params-unavailable",
            "detail": format!("no voted-params row at-or-before height {prev}"),
        })),
    )
        .into_response()
}

fn parse_sort_dir(raw: Option<&str>) -> Result<SortDir, Box<Response>> {
    match raw.unwrap_or("desc") {
        "asc" => Ok(SortDir::Asc),
        "desc" => Ok(SortDir::Desc),
        other => Err(Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": 400,
                    "reason": "bad-sort-direction",
                    "detail": format!("sortDirection must be 'asc' or 'desc'; got {other:?}"),
                })),
            )
                .into_response(),
        )),
    }
}

/// Render each eligible row, attaching the box's tokens via a read-time
/// lookup of the box record (the storage-rent index carries no token
/// data). The eligibility scan and these per-row lookups run on separate
/// read snapshots, so a row can momentarily reference a box the box store
/// no longer returns. Rather than silently emit empty assets for it, the
/// whole response fails with a 500 — a missing box means either the rent
/// index and `INDEXED_BOX` genuinely disagree (index desync), a
/// rollback/prune landed between the scan and the lookup, or the backend
/// read errored (`box_by_id` collapses read failures to `None`). All three
/// are "stop, don't serve half-truths" conditions; this mirrors
/// `remove_unspent`'s refusal to treat a missing key as a no-op.
fn build_items(
    rows: Vec<StorageRentEligibleDto>,
    factor: i32,
    chain_params: &dyn ChainParamsView,
    indexer: &dyn IndexerQuery,
) -> Result<Vec<StorageRentEligibleEntry>, String> {
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(b) = indexer.box_by_id(&row.box_id) else {
            return Err(format!(
                "storage-rent box {} unavailable: listed eligible but absent from the box \
                 store (index desync, concurrent rollback/prune, or backend read error)",
                hex::encode(row.box_id.as_bytes()),
            ));
        };
        let assets = b
            .box_data
            .candidate
            .tokens
            .iter()
            .map(|t| AssetEntry {
                token_id: hex::encode(t.token_id.as_bytes()),
                amount: t.amount,
            })
            .collect();
        items.push(build_entry(row, factor, chain_params, assets));
    }
    Ok(items)
}

fn build_entry(
    row: StorageRentEligibleDto,
    factor: i32,
    chain_params: &dyn ChainParamsView,
    assets: Vec<AssetEntry>,
) -> StorageRentEligibleEntry {
    let storage_fee_i32 = chain_params.compute_storage_fee(row.box_bytes_len, factor);
    // Un-wrapped product. Both inputs widen to i64 before multiplication —
    // i64::MAX is far past anything that can come from a real box, so this
    // never overflows for sane inputs.
    let mathematical_storage_fee: i64 = (factor as i64) * (row.box_bytes_len as i64);
    let consensus_fee_overflow = mathematical_storage_fee > i32::MAX as i64;

    let value_i64 = row.box_value as i64;
    let fee_i64 = storage_fee_i32 as i64;
    let storage_fee_not_covered = value_i64 - fee_i64 <= 0;

    // Branch identification combines the consensus-truthful flag with
    // the overflow detector. The overflow case is the consensus rule's
    // recreate branch firing on a box that mathematically belongs in
    // wholeBoxTake — that's why no one collects them.
    let expected_consensus_branch = if consensus_fee_overflow {
        ExpectedConsensusBranch::OverflowInverted
    } else if storage_fee_not_covered {
        ExpectedConsensusBranch::WholeBoxTake
    } else {
        ExpectedConsensusBranch::RecreateWithFee
    };
    let practically_collectable = !matches!(
        expected_consensus_branch,
        ExpectedConsensusBranch::OverflowInverted
    );

    let (rent_owed, min_recreated_output_value) = match expected_consensus_branch {
        ExpectedConsensusBranch::WholeBoxTake => (value_i64, 0),
        ExpectedConsensusBranch::RecreateWithFee => (fee_i64, value_i64 - fee_i64),
        // No collection will happen; rentOwed = 0 reflects "no rent
        // will ever be paid by anyone for this box." minRecreatedOutputValue
        // is still surfaced as the consensus-required floor for
        // educational purposes — it's the value that WOULD be required
        // if anyone tried to construct the recreate transaction.
        ExpectedConsensusBranch::OverflowInverted => (0, value_i64 - fee_i64),
    };

    StorageRentEligibleEntry {
        box_id: hex::encode(row.box_id.as_bytes()),
        box_value: row.box_value,
        assets,
        box_bytes_len: row.box_bytes_len,
        creation_height: row.creation_height,
        global_box_index: row.global_box_index,
        storage_fee_i32,
        mathematical_storage_fee,
        consensus_fee_overflow,
        storage_fee_not_covered,
        expected_consensus_branch,
        practically_collectable,
        rent_owed,
        min_recreated_output_value,
    }
}
