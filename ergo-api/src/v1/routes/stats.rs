//! `stats/*` — chain time-series analytics (`v1-api-design.md` §3.14).
//!
//! Every series is collection-enveloped (`{items, page}` (+ `meta`)), ascending
//! oldest-first so a consumer appends. A shared query grammar
//! (`from_height`/`to_height`/`limit`/`cursor`/`resolution`) is parsed once by
//! [`resolve_window`]; the height-keyed cursor is genuinely stable under a
//! growing chain.
//!
//! Reuse, not reinvention:
//! * `supply` / `emission-schedule` fold the per-height
//!   [`EmissionSchedule`](crate::emission::EmissionSchedule) view (pure math).
//! * `difficulty` reuses the same `last_headers`/`chain_slice` header fold the
//!   legacy `difficulty/history` handler does, now enveloped + ranged (O8).
//! * `fees` reuses the fee-proposition sum helper from [`super::transactions`].
//! * `mempool-depth` consumes the SAME O4 sample ring the mempool group built
//!   ([`V1State::mempool_depth`]) — one ring, two surfaces.
//! * `holders` reuses the ONE O3 holder-aggregation scan from
//!   [`super::tokens`] (`scan_token_holders`), adding concentration metrics.
//!
//! Where the data genuinely isn't wired (no emission view, indexer off), the
//! handler answers the honest `*_unavailable` / `*_disabled` reason (§1.4)
//! rather than fabricate a series.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use super::dto::{unix_ms_to_iso, CollectionMeta, V1MempoolDepthPoint};
use super::extract::V1Query;
use super::tokens::scan_token_holders;
use super::transactions::fee_from_hex_values;
use super::{parse_id32, V1State};
use crate::v1::cursor::{clamp_limit, decode_opt_cursor, encode_cursor, Page};
use crate::v1::error::{v1_error, Reason};
use ergo_indexer_types::TokenId;

/// Default points per series (~1 day at a 120 s block interval).
const SERIES_DEFAULT_LIMIT: u32 = 720;
/// Max points per series (the existing convention, `server.rs:1628,1666`).
const SERIES_MAX_LIMIT: u32 = 16_384;
/// Hard bound on the contiguous height span a single request may fold, so a
/// coarse `resolution` can never make one request read the whole chain.
const MAX_SPAN: u32 = 16_384;

/// Tighter point cap for `fees` — the one series whose per-point cost is a
/// full-block-transactions read, not a header fold.
const FEES_MAX_LIMIT: u32 = 1_024;

/// Holder distribution list caps (mirror `tokens/{id}/holders`).
const HOLDERS_DEFAULT_LIMIT: u32 = 100;
const HOLDERS_MAX_LIMIT: u32 = 1_000;

// ----- shared window + cursor ---------------------------------------------

/// Height-keyed opaque cursor: the next height to emit (ascending). Stable
/// under a growing chain (never an offset).
#[derive(Debug, Serialize, Deserialize)]
struct SeriesCursor {
    next_height: u32,
}

/// The shared `stats/*` query (all series except `emission-schedule`).
#[derive(Debug, Default, Deserialize)]
pub struct SeriesQuery {
    #[serde(default)]
    from_height: Option<u32>,
    #[serde(default)]
    to_height: Option<u32>,
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    resolution: Option<String>,
}

/// A resolved walk: the exact heights to emit + paging state.
struct Window {
    heights: Vec<u32>,
    /// Height that resumes the next page, when `has_more`.
    next_height: Option<u32>,
    limit: u32,
}

/// Map a `resolution` bucket to a height stride, derived from the network's
/// target block interval. `block` = every block; `hour`/`day` sample every
/// N-th real block (each emitted point stays a real header — a downsample, not
/// a fabrication). Unknown values are a `400 invalid_params`.
fn resolution_stride(raw: Option<&str>, interval_ms: u64) -> Result<u32, Box<Response>> {
    let per = |ms: u64| -> u32 {
        let iv = interval_ms.max(1);
        ms.div_ceil(iv).max(1) as u32
    };
    match raw {
        None | Some("block") => Ok(1),
        Some("hour") => Ok(per(3_600_000)),
        Some("day") => Ok(per(86_400_000)),
        Some(other) => Err(Box::new(v1_error(
            Reason::InvalidParams,
            "resolution must be block, hour, or day",
            format!("unknown resolution `{other}`"),
        ))),
    }
}

/// Resolve the shared window: parse cursor/from/to/limit/resolution into the
/// concrete ascending list of heights to emit (each ≤ `tip`, span ≤
/// [`MAX_SPAN`]), plus the resume height.
fn resolve_window(
    q: &SeriesQuery,
    tip: u32,
    interval_ms: u64,
    default_limit: u32,
    max_limit: u32,
) -> Result<Window, Box<Response>> {
    let limit = clamp_limit(q.limit, default_limit, max_limit);
    let stride = resolution_stride(q.resolution.as_deref(), interval_ms)?;
    let end_height = q.to_height.unwrap_or(tip).min(tip);

    // Cursor supersedes from_height; else from_height; else a tip-anchored
    // default window ending at `end_height`.
    let start = match decode_opt_cursor::<SeriesCursor>(q.cursor.as_deref())? {
        Some(c) => c.next_height,
        None => match q.from_height {
            Some(h) => h.max(1),
            None => {
                let span = (limit.saturating_sub(1)).saturating_mul(stride);
                end_height.saturating_sub(span).max(1)
            }
        },
    };

    let mut heights = Vec::new();
    let mut h = start;
    while (heights.len() as u32) < limit && h <= end_height && h.saturating_sub(start) < MAX_SPAN {
        heights.push(h);
        h = h.saturating_add(stride);
    }
    let next_height = match heights.last() {
        Some(&last) => {
            let nxt = last.saturating_add(stride);
            (nxt <= end_height).then_some(nxt)
        }
        None => None,
    };
    Ok(Window {
        heights,
        next_height,
        limit,
    })
}

/// Build the `{items, page}` envelope from a resolved window.
fn series_response<T: Serialize>(items: Vec<T>, w: &Window) -> Response {
    let next_cursor = w
        .next_height
        .map(|next_height| encode_cursor(&SeriesCursor { next_height }));
    Json(SeriesPage {
        items,
        page: Page {
            limit: w.limit,
            next_cursor: next_cursor.clone(),
            has_more: next_cursor.is_some(),
        },
    })
    .into_response()
}

#[derive(Debug, Serialize)]
struct SeriesPage<T> {
    items: Vec<T>,
    page: Page,
}

// ----- stats/supply (B1) --------------------------------------------------

/// One realized-supply point.
#[derive(Debug, Serialize)]
pub struct SupplyPoint {
    pub height: u32,
    pub timestamp_unix_ms: Option<u64>,
    pub timestamp_iso: Option<String>,
    pub emitted: String,
    pub remaining: String,
    pub block_reward: String,
}

/// `GET /api/v1/stats/supply` — realized circulating + remaining ERG over
/// height (the emission curve). Emission is pure arithmetic; timestamps come
/// from the header fold.
pub async fn supply(State(state): State<V1State>, V1Query(q): V1Query<SeriesQuery>) -> Response {
    let emission = match state.emission() {
        Ok(e) => e,
        Err(e) => return *e,
    };
    let interval_ms = state.read.info().target_block_interval_ms;
    let tip = state.read.sync().best_full_block_height;
    let window = match resolve_window(&q, tip, interval_ms, SERIES_DEFAULT_LIMIT, SERIES_MAX_LIMIT)
    {
        Ok(w) => w,
        Err(e) => return *e,
    };
    // Timestamps for the emitted heights (best-effort — supply math never
    // needs them, so an absent chain reader just yields null timestamps).
    let ts = timestamps_for(
        &state,
        window.heights.first().copied(),
        window.heights.last().copied(),
    );
    let items: Vec<SupplyPoint> = window
        .heights
        .iter()
        .map(|&h| {
            let info = emission.emission_info_at(h);
            let t = ts.as_ref().and_then(|m| m.get(&h).copied());
            SupplyPoint {
                height: h,
                timestamp_unix_ms: t,
                timestamp_iso: t.map(unix_ms_to_iso),
                emitted: info.total_coins_issued.to_string(),
                remaining: info.total_remain_coins.to_string(),
                block_reward: info.miner_reward.to_string(),
            }
        })
        .collect();
    series_response(items, &window)
}

/// Best-effort `height -> timestamp` map over `[from, to]` via `chain_slice`.
/// `None` when there is no chain reader (supply degrades to null timestamps
/// rather than fail — the emission math stands on its own).
fn timestamps_for(
    state: &V1State,
    from: Option<u32>,
    to: Option<u32>,
) -> Option<std::collections::HashMap<u32, u64>> {
    let (from, to) = (from?, to?);
    let chain = state.chain.as_ref()?;
    Some(
        chain
            .chain_slice(from, to)
            .into_iter()
            .map(|h| (h.height, h.timestamp))
            .collect(),
    )
}

// ----- stats/emission-schedule (B2) ---------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct EmissionScheduleQuery {
    #[serde(default)]
    from_height: Option<u32>,
    #[serde(default)]
    to_height: Option<u32>,
    #[serde(default)]
    step: Option<u32>,
    #[serde(default)]
    limit: Option<u32>,
    /// Round-trips the handler's own `next_cursor` (supersedes `from_height`,
    /// same rule as the other series endpoints).
    #[serde(default)]
    cursor: Option<String>,
}

/// `GET /api/v1/stats/emission-schedule` — the projected forward curve
/// (heights may exceed the tip). Pure schedule math, no chain read, so no
/// timestamps.
pub async fn emission_schedule(
    State(state): State<V1State>,
    V1Query(q): V1Query<EmissionScheduleQuery>,
) -> Response {
    let emission = match state.emission() {
        Ok(e) => e,
        Err(e) => return *e,
    };
    let limit = clamp_limit(q.limit, SERIES_DEFAULT_LIMIT, SERIES_MAX_LIMIT);
    let step = q.step.unwrap_or(1).max(1);
    // Cursor supersedes from_height (same rule as `resolve_window`).
    let cursor = match decode_opt_cursor::<SeriesCursor>(q.cursor.as_deref()) {
        Ok(c) => c,
        Err(boxed) => return *boxed,
    };
    let from = cursor.map(|c| c.next_height).or(q.from_height).unwrap_or(0);
    let Some(to) = q.to_height else {
        return v1_error(
            Reason::InvalidParams,
            "to_height is required",
            "supply ?from_height=&to_height= (to_height may exceed the tip)",
        );
    };
    if to < from {
        return v1_error(
            Reason::InvalidRange,
            "to_height must be >= from_height",
            "the projected window is empty",
        );
    }
    let mut items: Vec<SupplyPoint> = Vec::new();
    let mut h = from;
    let mut exhausted = false;
    while (items.len() as u32) < limit && h <= to {
        let info = emission.emission_info_at(h);
        items.push(SupplyPoint {
            height: h,
            timestamp_unix_ms: None,
            timestamp_iso: None,
            emitted: info.total_coins_issued.to_string(),
            remaining: info.total_remain_coins.to_string(),
            block_reward: info.miner_reward.to_string(),
        });
        let next = h.saturating_add(step);
        if next == h {
            // Saturated at u32::MAX — the walk cannot advance; without this
            // break the same height repeats and the cursor never terminates.
            exhausted = true;
            break;
        }
        h = next;
    }
    let next_height = (!exhausted && h <= to).then_some(h);
    let next_cursor = next_height.map(|next_height| encode_cursor(&SeriesCursor { next_height }));
    Json(SeriesPage {
        items,
        page: Page {
            limit,
            next_cursor: next_cursor.clone(),
            has_more: next_cursor.is_some(),
        },
    })
    .into_response()
}

// ----- stats/difficulty (B3, O8 canonical) --------------------------------

#[derive(Debug, Serialize)]
pub struct DifficultyPoint {
    pub height: u32,
    pub timestamp_unix_ms: u64,
    pub timestamp_iso: String,
    pub n_bits: u64,
    pub difficulty: String,
    pub hashrate: String,
}

/// `GET /api/v1/stats/difficulty` — per-block difficulty series (O8 canonical
/// home; supersedes the legacy bare-array `difficulty/history`). `hashrate` is
/// a server derivation (`difficulty / target_block_interval_s`).
pub async fn difficulty(
    State(state): State<V1State>,
    V1Query(q): V1Query<SeriesQuery>,
) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let interval_ms = state.read.info().target_block_interval_ms;
    let interval_s = (interval_ms / 1000).max(1) as u128;
    let tip = state.read.sync().best_full_block_height;
    let window = match resolve_window(&q, tip, interval_ms, SERIES_DEFAULT_LIMIT, SERIES_MAX_LIMIT)
    {
        Ok(w) => w,
        Err(e) => return *e,
    };
    let (Some(&first), Some(&last)) = (window.heights.first(), window.heights.last()) else {
        return series_response(Vec::<DifficultyPoint>::new(), &window);
    };
    let by_height: std::collections::HashMap<u32, _> = chain
        .chain_slice(first, last)
        .into_iter()
        .map(|h| (h.height, h))
        .collect();
    let items: Vec<DifficultyPoint> = window
        .heights
        .iter()
        .filter_map(|h| by_height.get(h))
        .map(|h| {
            let hashrate = h
                .difficulty
                .parse::<u128>()
                .map(|d| (d / interval_s).to_string())
                .unwrap_or_else(|_| "0".to_string());
            DifficultyPoint {
                height: h.height,
                timestamp_unix_ms: h.timestamp,
                timestamp_iso: unix_ms_to_iso(h.timestamp),
                n_bits: h.n_bits,
                difficulty: h.difficulty.clone(),
                hashrate,
            }
        })
        .collect();
    series_response(items, &window)
}

// ----- stats/fees (B4) ----------------------------------------------------

#[derive(Debug, Serialize)]
pub struct FeesPoint {
    pub height: u32,
    pub timestamp_unix_ms: u64,
    pub timestamp_iso: String,
    pub tx_count: u32,
    pub total_fee: String,
    pub fee_per_byte_p10: String,
    pub fee_per_byte_median: String,
    pub fee_per_byte_p90: String,
    pub min_fee: String,
}

/// `GET /api/v1/stats/fees` — per-block fee statistics from confirmed blocks.
/// Fees are summed output-side over the fee-proposition outputs (the same
/// honest, input-free approach as `transactions/{id}`), so no input resolution
/// is needed. The per-point cost is a full-block read, so the cap is tighter.
pub async fn fees(State(state): State<V1State>, V1Query(q): V1Query<SeriesQuery>) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let interval_ms = state.read.info().target_block_interval_ms;
    let tip = state.read.sync().best_full_block_height;
    let window = match resolve_window(&q, tip, interval_ms, SERIES_DEFAULT_LIMIT, FEES_MAX_LIMIT) {
        Ok(w) => w,
        Err(e) => return *e,
    };
    let (Some(&first), Some(&last)) = (window.heights.first(), window.heights.last()) else {
        return series_response(Vec::<FeesPoint>::new(), &window);
    };
    let headers: std::collections::HashMap<u32, (String, u64)> = chain
        .chain_slice(first, last)
        .into_iter()
        .map(|h| (h.height, (h.id, h.timestamp)))
        .collect();
    let items: Vec<FeesPoint> = window
        .heights
        .iter()
        .filter_map(|h| headers.get(h).map(|hdr| (*h, hdr)))
        .filter_map(|(height, (header_id, timestamp))| {
            let bt = chain.block_transactions_by_id(header_id)?;
            let mut per_byte: Vec<u64> = Vec::with_capacity(bt.transactions.len());
            let mut total_fee: u128 = 0;
            for tx in &bt.transactions {
                let fee =
                    fee_from_hex_values(tx.outputs.iter().map(|o| (o.ergo_tree.as_str(), o.value)));
                if fee == 0 {
                    continue;
                }
                total_fee = total_fee.saturating_add(u128::from(fee));
                let size = u64::from(tx.size.max(1));
                per_byte.push(fee / size);
            }
            per_byte.sort_unstable();
            Some(FeesPoint {
                height,
                timestamp_unix_ms: *timestamp,
                timestamp_iso: unix_ms_to_iso(*timestamp),
                tx_count: bt.transactions.len() as u32,
                total_fee: total_fee.to_string(),
                fee_per_byte_p10: percentile(&per_byte, 10).to_string(),
                fee_per_byte_median: percentile(&per_byte, 50).to_string(),
                fee_per_byte_p90: percentile(&per_byte, 90).to_string(),
                min_fee: per_byte.first().copied().unwrap_or(0).to_string(),
            })
        })
        .collect();
    series_response(items, &window)
}

/// Nearest-rank percentile of a pre-sorted slice (`0` on empty).
fn percentile(sorted: &[u64], p: u32) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((u64::from(p) * (sorted.len() as u64)).div_ceil(100)).max(1) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

// ----- stats/mempool-depth (B5, O4 ring) ----------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct DepthQuery {
    #[serde(default)]
    limit: Option<u32>,
}

/// `GET /api/v1/stats/mempool-depth` — the congestion chart. Consumes the SAME
/// O4 sample ring the mempool group built (Overlap O4). When the ring has not
/// yet recorded a sample, one live point is synthesized from the current
/// summary so the series is never empty on a fresh node.
pub async fn mempool_depth(
    State(state): State<V1State>,
    V1Query(q): V1Query<DepthQuery>,
) -> Response {
    let limit = clamp_limit(
        q.limit,
        SERIES_DEFAULT_LIMIT,
        crate::v1::mempool_depth::DEPTH_RING_CAP as u32,
    );
    let samples = state.mempool_depth.recent(limit as usize);
    let items: Vec<V1MempoolDepthPoint> = if samples.is_empty() {
        // Fresh node: one current point from the live summary (min-fee folded
        // from the pooled txs, exactly as the ring feeder does).
        let s = state.read.mempool_summary();
        let min_fee_per_byte = state
            .read
            .mempool_transactions()
            .transactions
            .iter()
            .map(|t| t.fee_per_byte_nano_erg)
            .min()
            .unwrap_or(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        vec![V1MempoolDepthPoint {
            timestamp_unix_ms: now,
            timestamp_iso: unix_ms_to_iso(now),
            size: s.size,
            total_bytes: s.total_bytes,
            capacity_count: s.capacity_count,
            capacity_bytes: s.capacity_bytes,
            min_fee_per_byte: min_fee_per_byte.to_string(),
            revalidation_pending: s.revalidation_pending,
        }]
    } else {
        samples
            .iter()
            .map(V1MempoolDepthPoint::from_sample)
            .collect()
    };
    // The ring is a bounded tail with no stable seek key yet — a single page.
    Json(SeriesPage {
        items,
        page: Page {
            limit,
            next_cursor: None,
            has_more: false,
        },
    })
    .into_response()
}

// ----- stats/holders (B6, O3 scan) ----------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct HoldersQuery {
    #[serde(default)]
    token_id: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    include_metrics: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct HolderRow {
    pub address: String,
    pub amount: String,
    pub share_pct: String,
}

#[derive(Debug, Serialize)]
pub struct HolderMetrics {
    pub holder_count: u64,
    pub top10_share_pct: String,
    pub gini: String,
    pub total_amount: String,
    /// Honest flag: the bounded O3 scan hit its cap, so the ranking/metrics are
    /// approximate (never silently partial).
    pub scan_capped: bool,
}

/// `GET /api/v1/stats/holders` — token-holder distribution + concentration
/// metrics. **Overlap O3:** reuses the ONE bounded holder-aggregation scan from
/// `tokens/{id}/holders` (`scan_token_holders`); this surface adds `share_pct`
/// per holder and the `gini` / `top10_share_pct` concentration metrics.
pub async fn holders(State(state): State<V1State>, V1Query(q): V1Query<HoldersQuery>) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let Some(token_hex) = q.token_id else {
        return v1_error(
            Reason::InvalidParams,
            "token_id is required",
            "supply ?token_id=<hex>",
        );
    };
    let Some(raw) = parse_id32(&token_hex) else {
        return v1_error(
            Reason::InvalidTokenId,
            "token_id is not a 64-character hex string",
            "supply an unprefixed hex token id",
        );
    };
    let tid = TokenId::from_bytes(raw);
    if idx.token_by_id(&tid).is_none() {
        return v1_error(
            Reason::TokenNotFound,
            "no token with that id",
            "the id is well-formed but unknown to this node",
        );
    }
    let start = match super::offset_from_cursor(q.cursor.as_deref()) {
        Ok(o) => o,
        Err(e) => return *e,
    };
    let limit = clamp_limit(q.limit, HOLDERS_DEFAULT_LIMIT, HOLDERS_MAX_LIMIT);
    let include_metrics = q.include_metrics.unwrap_or(true);

    let scan = scan_token_holders(idx.as_ref(), &tid, state.network);
    let total = scan.circulating.max(1);
    let mut items: Vec<HolderRow> = scan
        .holders
        .iter()
        .skip(start as usize)
        .take(limit as usize + 1)
        .map(|(address, amount)| HolderRow {
            address: address.clone(),
            amount: amount.to_string(),
            share_pct: pct(*amount, total),
        })
        .collect();
    let has_more = items.len() as u32 > limit;
    if has_more {
        items.truncate(limit as usize);
    }
    let next_cursor = has_more.then(|| {
        encode_cursor(&super::OffsetCursor {
            off: start.saturating_add(limit),
        })
    });

    let metrics = if include_metrics {
        let top10: u128 = scan.holders.iter().take(10).map(|(_, a)| *a).sum();
        HolderMetrics {
            holder_count: scan.holders.len() as u64,
            top10_share_pct: pct(top10, total),
            gini: gini(&scan.holders),
            total_amount: scan.circulating.to_string(),
            scan_capped: scan.capped,
        }
    } else {
        HolderMetrics {
            holder_count: scan.holders.len() as u64,
            top10_share_pct: "0".to_string(),
            gini: "0".to_string(),
            total_amount: scan.circulating.to_string(),
            scan_capped: scan.capped,
        }
    };

    Json(CollectionMeta {
        items,
        page: Page {
            limit,
            next_cursor,
            has_more,
        },
        meta: metrics,
    })
    .into_response()
}

/// `amount / total` as a 1-decimal percentage string.
fn pct(amount: u128, total: u128) -> String {
    if total == 0 {
        return "0.0".to_string();
    }
    // tenths of a percent = amount * 1000 / total
    let tenths = amount.saturating_mul(1000) / total;
    format!("{}.{}", tenths / 10, tenths % 10)
}

/// Gini coefficient over holder amounts (already sorted descending). `0` for
/// fewer than two holders or zero total. Rendered to 2 decimals.
fn gini(holders: &[(String, u128)]) -> String {
    let n = holders.len();
    if n < 2 {
        return "0".to_string();
    }
    let total: u128 = holders.iter().map(|(_, a)| *a).sum();
    if total == 0 {
        return "0".to_string();
    }
    // G = ( Σ_i (2i - n - 1) x_i ) / ( n Σ x_i ), i ascending rank 1..n.
    // holders are descending, so ascending rank i = n - pos.
    let mut weighted: i128 = 0;
    for (pos, (_, a)) in holders.iter().enumerate() {
        let rank = (n - pos) as i128; // 1..=n ascending
        let coeff = 2 * rank - n as i128 - 1;
        weighted += coeff * (*a as i128);
    }
    let denom = (n as i128) * (total as i128);
    if denom == 0 {
        return "0".to_string();
    }
    // hundredths of the ratio
    let hundredths = (weighted.abs().saturating_mul(100)) / denom;
    format!("0.{:02}", hundredths.min(99))
}
