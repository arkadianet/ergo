//! `tokens/*` reads (`v1-api-design.md` §3.7) — by-id, list, holders, stats.
//!
//! `by-id` is a cheap point lookup. `holders`/`stats` share ONE bounded
//! full-scan (coherence overlap O3) — walk the token's unspent boxes up to a
//! hard cap, aggregate per address, and surface `scan_capped` honestly rather
//! than return a silently-partial ranking. The mint-order `list` needs an
//! enumeration index that does not exist yet (design G3), so it answers an
//! honest `state_unavailable` instead of faking data.

use utoipa::ToSchema;
use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_indexer_types::{IndexerQuery, Page as IdxPage, SortDir, TokenId};
use ergo_ser::address::{encode_address, NetworkPrefix};
use serde::Deserialize;

use super::dto::{
    token_from_dto, CollectionMeta, HoldersMeta, V1Token, V1TokenHolder, V1TokenStats,
};
use super::extract::V1Query;
use super::{offset_from_cursor, parse_id32, OffsetCursor, V1State};
use crate::v1::cursor::{clamp_limit, encode_cursor, Page};
use crate::v1::error::{v1_error, Reason, V1Error};

/// Hard cap on UNSPENT boxes walked per holder/stats scan (§2.2). When the
/// scan stops here with more unspent boxes pending, the ranking is
/// `scan_capped` (approximate) — never silently partial.
const HOLDER_SCAN_CAP: u32 = 50_000;
/// Per-batch page size for the bounded scan.
const SCAN_BATCH: u32 = 1_000;
const HOLDERS_DEFAULT_LIMIT: u32 = 50;
const HOLDERS_MAX_LIMIT: u32 = 500;

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct HoldersQuery {
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    cursor: Option<String>,
}

fn invalid_token_id() -> Response {
    v1_error(
        Reason::InvalidTokenId,
        "token_id is not a 64-character lowercase hex string",
        "supply an unprefixed hex token id",
    )
}

fn token_not_found() -> Response {
    v1_error(
        Reason::TokenNotFound,
        "no token with that id",
        "the id is well-formed but unknown to this node",
    )
}

// ----- tokens/{token_id} (cheap) ------------------------------------------

/// `GET /api/v1/tokens/{token_id}` — bare token object. `404` on miss.
#[utoipa::path(
    get, path = "/api/v1/tokens/{token_id}", tag = "tokens",
    params(("token_id" = String, Path, description = "64-char lowercase hex token id")),
    responses(
        (status = 200, description = "The token", body = V1Token),
        (status = 400, description = "Malformed token id", body = V1Error),
        (status = 404, description = "No token with that id", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 503, description = "Extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn token_by_id(State(state): State<V1State>, Path(token_hex): Path<String>) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let Some(raw) = parse_id32(&token_hex) else {
        return invalid_token_id();
    };
    let tid = TokenId::from_bytes(raw);
    match idx.token_by_id(&tid) {
        Some(t) => Json(token_from_dto(&t)).into_response(),
        None => token_not_found(),
    }
}

// ----- tokens (list) — Phase-2 honest gap ---------------------------------

/// `GET /api/v1/tokens` — mint-order list. Phase-2 (design G3): `INDEXED_TOKEN`
/// is hash-keyed with no mint-sequence enumeration index, so there is no honest
/// way to enumerate every token in mint order today. Answers `503
/// state_unavailable` (never fabricated data) once the index is confirmed
/// present-but-disabled by the gate.
#[utoipa::path(
    get, path = "/api/v1/tokens", tag = "tokens",
    responses(
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 503, description = "Mint-order enumeration not available on this node (design gap), or extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn tokens_list(State(state): State<V1State>) -> Response {
    // Gate first so a disabled index reads `indexer_disabled`, not the
    // capability gap.
    if let Err(e) = state.indexer() {
        return *e;
    }
    v1_error(
        Reason::StateUnavailable,
        "token mint-order enumeration is not available on this node",
        "listing every minted token needs a mint-sequence index (design G3) \
         that is not built; query a known token by id instead",
    )
}

// ----- tokens/{token_id}/holders + stats (bounded scan, O3) ---------------

/// Result of the bounded per-token unspent-box scan shared by holders + stats.
pub(super) struct HolderScan {
    /// Aggregated `(address, amount)` pairs, sorted descending by amount then
    /// address (a stable tiebreak so the cursor page is deterministic).
    pub(super) holders: Vec<(String, u128)>,
    pub(super) scanned: u64,
    pub(super) capped: bool,
    pub(super) circulating: u128,
}

pub(super) fn scan_token_holders(
    idx: &dyn IndexerQuery,
    token_id: &TokenId,
    network: NetworkPrefix,
) -> HolderScan {
    let mut capped = false;
    let mut acc: HashMap<String, u128> = HashMap::new();
    let mut circulating: u128 = 0;
    let mut scanned: u64 = 0;
    let mut offset: u32 = 0;
    loop {
        let scanned_u32 = scanned as u32;
        if scanned_u32 >= HOLDER_SCAN_CAP {
            // At the cap: probe ONE extra row before declaring the ranking
            // approximate — an unspent set of exactly HOLDER_SCAN_CAP rows is
            // a complete scan, not a truncated one.
            let probe =
                idx.token_unspent_paged(token_id, IdxPage { offset, limit: 1 }, SortDir::Asc);
            capped = !probe.is_empty();
            break;
        }
        let want = SCAN_BATCH.min(HOLDER_SCAN_CAP - scanned_u32);
        let rows = idx.token_unspent_paged(
            token_id,
            IdxPage {
                offset,
                limit: want,
            },
            SortDir::Asc,
        );
        if rows.is_empty() {
            break;
        }
        let got = rows.len() as u32;
        for b in &rows {
            let cand = &b.box_data.candidate;
            let amount: u128 = cand
                .tokens
                .iter()
                .filter(|t| &t.token_id == token_id)
                .map(|t| u128::from(t.amount))
                .sum();
            scanned += 1;
            if amount == 0 {
                continue;
            }
            circulating = circulating.saturating_add(amount);
            let addr = encode_address(network, cand.ergo_tree(), cand.ergo_tree_bytes());
            let entry = acc.entry(addr).or_insert(0);
            *entry = entry.saturating_add(amount);
        }
        offset = offset.saturating_add(got);
        if got < want {
            break;
        }
    }
    let mut holders: Vec<(String, u128)> = acc.into_iter().collect();
    holders.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    HolderScan {
        holders,
        scanned,
        capped,
        circulating,
    }
}

/// `GET /api/v1/tokens/{token_id}/holders` — `{items, page, meta}` (Part D).
#[utoipa::path(
    get, path = "/api/v1/tokens/{token_id}/holders", tag = "tokens",
    params(
        ("token_id" = String, Path, description = "64-char lowercase hex token id"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, cap 500)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
    ),
    responses(
        (status = 200, description = "Holder ranking + scan meta (scan_capped honesty flag)", body = CollectionMeta<V1TokenHolder, HoldersMeta>),
        (status = 400, description = "Malformed token id/cursor", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 503, description = "Extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn token_holders(
    State(state): State<V1State>,
    Path(token_hex): Path<String>,
    V1Query(q): V1Query<HoldersQuery>,
) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let Some(raw) = parse_id32(&token_hex) else {
        return invalid_token_id();
    };
    let tid = TokenId::from_bytes(raw);
    let start = match offset_from_cursor(q.cursor.as_deref()) {
        Ok(o) => o,
        Err(e) => return *e,
    };
    let limit = clamp_limit(q.limit, HOLDERS_DEFAULT_LIMIT, HOLDERS_MAX_LIMIT);

    let scan = scan_token_holders(idx.as_ref(), &tid, state.network);
    let mut items: Vec<V1TokenHolder> = scan
        .holders
        .iter()
        .skip(start as usize)
        .take(limit as usize + 1)
        .map(|(address, amount)| V1TokenHolder {
            address: address.clone(),
            amount: amount.to_string(),
        })
        .collect();
    let has_more = items.len() as u32 > limit;
    if has_more {
        items.truncate(limit as usize);
    }
    let next_cursor = has_more.then(|| {
        encode_cursor(&OffsetCursor {
            off: start.saturating_add(limit),
        })
    });
    let page = Page {
        limit,
        next_cursor,
        has_more,
    };
    let meta = HoldersMeta {
        as_of_height: idx.indexed_height(),
        scanned_boxes: scan.scanned,
        scan_capped: scan.capped,
    };
    Json(CollectionMeta { items, page, meta }).into_response()
}

/// `GET /api/v1/tokens/{token_id}/stats` — bare object; shares the holders
/// scan. `404 token_not_found` when the mint record is unknown.
#[utoipa::path(
    get, path = "/api/v1/tokens/{token_id}/stats", tag = "tokens",
    params(("token_id" = String, Path, description = "64-char lowercase hex token id")),
    responses(
        (status = 200, description = "Token stats (holder_count/circulating_supply inherit scan_capped honesty)", body = V1TokenStats),
        (status = 400, description = "Malformed token id", body = V1Error),
        (status = 404, description = "No token with that id", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 503, description = "Extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn token_stats(State(state): State<V1State>, Path(token_hex): Path<String>) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let Some(raw) = parse_id32(&token_hex) else {
        return invalid_token_id();
    };
    let tid = TokenId::from_bytes(raw);
    let Some(token) = idx.token_by_id(&tid) else {
        return token_not_found();
    };
    let scan = scan_token_holders(idx.as_ref(), &tid, state.network);
    let stats = V1TokenStats {
        token_id: hex::encode(tid.as_bytes()),
        emission_amount: token.emission_amount.to_string(),
        circulating_supply: scan.circulating.to_string(),
        holder_count: scan.holders.len() as u64,
        box_count: idx.token_total_boxes(&tid),
        scan_capped: scan.capped,
    };
    Json(stats).into_response()
}
