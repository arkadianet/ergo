//! `GET /blockchain/box/nonP2pk` — Rust-node-exclusive forward scan over
//! the global box index that returns every box whose ErgoTree is not a
//! P2PK proposition (contracts: P2S trees, including P2PK-shaped trees
//! with segregated constants, which also encode as P2S addresses).
//!
//! The scan walks global indexes `[fromIndex, fromIndex + scanLimit)` and
//! stops early once `limit` matches are collected. `nextIndex` is where the
//! next call should resume; `null` means the scan reached the end of the
//! index. Reads run in chunks, each in its own indexer snapshot. Global
//! indexes are append-only outside rollbacks, so a resumed scan only misses
//! or repeats boxes when a reorg rewrites the tail it already passed.

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_ser::address::is_p2pk;
use serde::{Deserialize, Serialize};

use super::IndexedErgoBoxResponse;
use super::{bad_request, build_indexed_box_response, internal_error, BlockchainState};

const DEFAULT_LIMIT: u32 = 100;
const MAX_LIMIT: u32 = 16_384;
const DEFAULT_SCAN_LIMIT: u32 = 65_536;
const MAX_SCAN_LIMIT: u32 = 262_144;
/// Boxes read per indexer snapshot.
const CHUNK: u64 = 4_096;

#[derive(Debug, Deserialize)]
pub struct NonP2pkQuery {
    #[serde(default, rename = "fromIndex")]
    pub from_index: Option<u64>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default, rename = "scanLimit")]
    pub scan_limit: Option<u32>,
    #[serde(default, rename = "unspentOnly")]
    pub unspent_only: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct NonP2pkResponse {
    pub items: Vec<IndexedErgoBoxResponse>,
    /// Global index to pass as `fromIndex` on the next call; `null` once
    /// the scan has reached the end of the index.
    #[serde(rename = "nextIndex")]
    pub next_index: Option<u64>,
    /// Number of boxes examined by this call.
    pub scanned: u64,
}

pub async fn boxes_non_p2pk_handler(
    State(state): State<BlockchainState>,
    Query(q): Query<NonP2pkQuery>,
) -> Response {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAX_LIMIT {
        return bad_request(&format!("limit must be in 1..={MAX_LIMIT}"));
    }
    let scan_limit = q.scan_limit.unwrap_or(DEFAULT_SCAN_LIMIT);
    if scan_limit == 0 || scan_limit > MAX_SCAN_LIMIT {
        return bad_request(&format!("scanLimit must be in 1..={MAX_SCAN_LIMIT}"));
    }
    let from = q.from_index.unwrap_or(0);
    let unspent_only = q.unspent_only.unwrap_or(false);

    // A full scan reads up to `scanLimit` box records; keep it off the
    // async workers.
    let joined = tokio::task::spawn_blocking(move || {
        scan(
            &state,
            from,
            limit as usize,
            u64::from(scan_limit),
            unspent_only,
        )
    })
    .await;
    match joined {
        Ok(Ok(resp)) => Json(resp).into_response(),
        Ok(Err(detail)) => internal_error(&detail),
        Err(error) => internal_error(&format!("scan task failed: {error}")),
    }
}

fn scan(
    state: &BlockchainState,
    from: u64,
    limit: usize,
    scan_limit: u64,
    unspent_only: bool,
) -> Result<NonP2pkResponse, String> {
    let end = from.saturating_add(scan_limit);
    let mut items = Vec::new();
    let mut lo = from;
    while lo < end {
        let hi = lo.saturating_add(CHUNK).min(end);
        let boxes = state
            .indexer
            .boxes_by_global_range(lo, hi)
            .map_err(|e| format!("indexer read failed: {e}"))?;
        let exhausted = (boxes.len() as u64) < hi - lo;
        for (offset, b) in boxes.iter().enumerate() {
            let candidate = &b.box_data.candidate;
            if is_p2pk(candidate.ergo_tree()) || (unspent_only && b.spending_tx_id.is_some()) {
                continue;
            }
            items.push(build_indexed_box_response(state.network, b)?);
            if items.len() == limit {
                let next = lo + offset as u64 + 1;
                return Ok(NonP2pkResponse {
                    items,
                    next_index: Some(next),
                    scanned: next - from,
                });
            }
        }
        if exhausted {
            return Ok(NonP2pkResponse {
                items,
                next_index: None,
                scanned: lo + boxes.len() as u64 - from,
            });
        }
        lo = hi;
    }
    Ok(NonP2pkResponse {
        items,
        next_index: Some(end),
        scanned: end - from,
    })
}
