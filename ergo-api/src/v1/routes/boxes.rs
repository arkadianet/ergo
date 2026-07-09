//! `boxes/*` reads (`v1-api-design.md` §3.7) — by-id, by-address, by-ergo-tree,
//! by-template, by-token, their unspent variants, and the global-index range.
//!
//! This group OWNS the canonical box shape: every response converges on the ONE
//! [`V1Box`](super::dto::V1Box) the transactions group defined (coherence Part
//! B / coordination flag #2). Handlers adapt the existing indexer readers
//! (`address_boxes_paged`, `token_unspent_paged`, …) and pool overlays
//! (`pool_unspent_for_*`) into the v1 envelope + cursor, gating every read on
//! the extra index (`indexer_disabled` / `_syncing` / `_halted`).

use utoipa::ToSchema;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_indexer_types::types::IndexedErgoBox;
use ergo_indexer_types::{BoxId, Page as IdxPage, SortDir, TemplateHash, TokenId, TreeHash};
use ergo_ser::ergo_tree::tree_hash_from_bytes;
use serde::{Deserialize, Serialize};

use super::dto::{v1box_from_indexed_box, Collection, V1Box};
use super::extract::{V1Json, V1Query};
use super::{offset_from_cursor, offset_page, parse_id32, parse_sort, GiCursor, V1State};
use crate::blockchain::{
    address_to_tree_hash, pool_unspent_for_template, pool_unspent_for_token, pool_unspent_for_tree,
};
use crate::v1::cursor::{clamp_limit, decode_opt_cursor, encode_cursor, Page};
use crate::v1::error::{v1_error, Reason, V1Error};

/// Default page size and hard cap for this group (§2.2 — a deliberate
/// tightening vs the compat `MAX_ITEMS = 16384`).
const DEFAULT_LIMIT: u32 = 20;
const MAX_LIMIT: u32 = 500;
/// `boxes/range` returns bare ids, so its per-item payload is far lighter — a
/// looser cap is justified (§2.2).
const RANGE_DEFAULT_LIMIT: u32 = 100;
const RANGE_MAX_LIMIT: u32 = 2000;

// ----- query payloads -----------------------------------------------------

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct SingleBoxQuery {
    #[serde(default)]
    decode: Option<bool>,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct BoxListQuery {
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    sort: Option<String>,
    #[serde(default)]
    decode: Option<bool>,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct UnspentQuery {
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    sort: Option<String>,
    #[serde(default)]
    decode: Option<bool>,
    #[serde(default)]
    include_unconfirmed: Option<bool>,
    #[serde(default)]
    exclude_mempool_spent: Option<bool>,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct RangeQuery {
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    cursor: Option<String>,
}

/// POST body for the by-ergo-tree routes (a tree is too long for a path
/// segment — Scala made the same call).
#[derive(Debug, Deserialize, ToSchema)]
pub struct ErgoTreeBody {
    ergo_tree: String,
}

// ----- error helpers ------------------------------------------------------

fn invalid_box_id() -> Response {
    v1_error(
        Reason::InvalidBoxId,
        "box_id is not a 64-character lowercase hex string",
        "supply an unprefixed hex box id",
    )
}

fn invalid_token_id() -> Response {
    v1_error(
        Reason::InvalidTokenId,
        "token_id is not a 64-character lowercase hex string",
        "supply an unprefixed hex token id",
    )
}

fn invalid_template_hash() -> Response {
    v1_error(
        Reason::InvalidHex,
        "template_hash is not a 64-character lowercase hex string",
        "supply the blake2b256 template hash as unprefixed hex",
    )
}

fn invalid_ergo_tree(detail: impl Into<String>) -> Response {
    v1_error(
        Reason::InvalidErgoTree,
        "ergo_tree is not valid hex or not a parseable tree",
        detail,
    )
}

fn invalid_address(detail: &str) -> Response {
    v1_error(
        Reason::InvalidAddress,
        "address is not valid base58 for this network",
        detail.to_string(),
    )
}

fn box_not_found() -> Response {
    v1_error(
        Reason::BoxNotFound,
        "no box with that id",
        "the id is well-formed but unknown to this node",
    )
}

fn assemble_failed(detail: String) -> Response {
    v1_error(
        Reason::InternalError,
        "failed to assemble the box response",
        detail,
    )
}

/// Hash a hex-encoded ErgoTree to its canonical `tree_hash` (the indexer key),
/// mapping both hex-decode and parse failures to `400 invalid_ergo_tree`.
fn decode_ergo_tree(hex_str: &str) -> Result<TreeHash, Box<Response>> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| Box::new(invalid_ergo_tree(format!("hex decode: {e}"))))?;
    match tree_hash_from_bytes(&bytes) {
        Ok(h) => Ok(TreeHash::from_bytes(h)),
        Err(e) => Err(Box::new(invalid_ergo_tree(e.to_string()))),
    }
}

// ----- shared render paths ------------------------------------------------

/// Project a fetched page of indexer boxes into the canonical [`V1Box`] shape,
/// reading the tip once for the confirmation math.
fn project_boxes(
    state: &V1State,
    rows: Vec<IndexedErgoBox>,
    decode: bool,
) -> Result<Vec<V1Box>, String> {
    let best = state.read.status().best_full_block_height;
    rows.iter()
        .map(|b| v1box_from_indexed_box(state.network, b, best, decode))
        .collect()
}

/// A cursor-paginated box collection over an offset-aliased reader
/// (`by-address`, `by-ergo-tree`, `by-template`, `by-token`).
fn render_box_page(
    state: &V1State,
    limit: Option<u32>,
    cursor: Option<&str>,
    sort: Option<&str>,
    decode: bool,
    fetch: impl FnOnce(IdxPage, SortDir) -> Vec<IndexedErgoBox>,
) -> Response {
    let dir = match parse_sort(sort) {
        Ok(d) => d,
        Err(e) => return *e,
    };
    let start = match offset_from_cursor(cursor) {
        Ok(o) => o,
        Err(e) => return *e,
    };
    let limit = clamp_limit(limit, DEFAULT_LIMIT, MAX_LIMIT);
    let rows = fetch(
        IdxPage {
            offset: start,
            limit: limit + 1,
        },
        dir,
    );
    match project_boxes(state, rows, decode) {
        Ok(items) => {
            let (items, page) = offset_page(items, start, limit);
            Json(Collection { items, page }).into_response()
        }
        Err(d) => assemble_failed(d),
    }
}

/// Two-axis resume cursor for the unspent listings with the pool overlay:
/// `c` = the confirmed reader offset, `p` = overlay (pool) rows already
/// emitted. BOTH must advance or a page the overlay alone fills would repeat
/// forever (the overlay livelock); `p` indexes the volatile pool snapshot —
/// the same documented offset-alias drift the overlay always carried (§1.5).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct UnspentCursor {
    c: u32,
    p: u32,
}

/// Reject `sort=asc` on the listings whose reader has ONE fixed (DESC-keyed)
/// order — accepting it and answering desc data would silently mislabel the
/// result. `desc`/absent passes; malformed values keep the shared
/// `invalid_sort_direction` answer.
fn reject_asc_fixed_order(sort: Option<&str>) -> Result<(), Box<Response>> {
    match parse_sort(sort)? {
        SortDir::Desc => Ok(()),
        SortDir::Asc => Err(Box::new(v1_error(
            Reason::InvalidParams,
            "this listing only supports sort=desc",
            "the by-template / by-token box index is stored newest-first; `asc` is not available",
        ))),
    }
}

/// Overfetch confirmed unspent boxes until `limit + 1` rows SURVIVE the `keep`
/// filter (or the reader is exhausted). Each survivor is returned WITH the
/// reader offset just past it, so the caller can mint the resume cursor from
/// the last survivor it actually emits — not from rows that were fetched but
/// truncated away (e.g. by the unconfirmed overlay re-capping the merged
/// page). Filtering after a single overfetch would let `exclude_mempool_spent`
/// underfill the window and mis-compute `has_more`; looping fills the page.
fn confirmed_survivors<T>(
    start: u32,
    limit: u32,
    dir: SortDir,
    fetch: impl Fn(IdxPage, SortDir) -> Vec<T>,
    keep: impl Fn(&T) -> bool,
) -> Vec<(T, u32)> {
    let target = limit as usize + 1;
    let mut survivors: Vec<(T, u32)> = Vec::with_capacity(target);
    let mut read_off = start;
    loop {
        let batch = fetch(
            IdxPage {
                offset: read_off,
                limit: target as u32,
            },
            dir,
        );
        let batch_len = batch.len() as u32;
        if batch_len == 0 {
            break;
        }
        for (i, b) in batch.into_iter().enumerate() {
            if keep(&b) {
                let off_after = read_off.saturating_add(i as u32).saturating_add(1);
                survivors.push((b, off_after));
                if survivors.len() >= target {
                    return survivors;
                }
            }
        }
        read_off = read_off.saturating_add(batch_len);
        if batch_len < target as u32 {
            break; // reader exhausted
        }
    }
    survivors
}

/// The unspent variants: confirmed page (overfetched to fill past
/// `exclude_mempool_spent` drops) + the optional pool-output overlay, merged in
/// the Scala order, then **re-capped to `limit`** (v1 fixes the compat quirk
/// where `include_unconfirmed=true` could exceed `limit`). The two-axis
/// [`UnspentCursor`] advances the confirmed window AND the overlay window by
/// exactly the rows the page emitted — no repeats when the overlay fills a
/// page, no confirmed skips when it pushes rows out; the overlay axis is an
/// offset into the volatile pool snapshot (documented drift, §1.5).
fn render_unspent_page(
    state: &V1State,
    q: &UnspentQuery,
    fetch_confirmed: impl Fn(IdxPage, SortDir) -> Vec<IndexedErgoBox>,
    pool: impl FnOnce(bool) -> Vec<IndexedErgoBox>,
) -> Response {
    let dir = match parse_sort(q.sort.as_deref()) {
        Ok(d) => d,
        Err(e) => return *e,
    };
    let (c_start, p_start) = match decode_opt_cursor::<UnspentCursor>(q.cursor.as_deref()) {
        Ok(Some(cur)) => (cur.c, cur.p),
        Ok(None) => (0, 0),
        Err(e) => return *e,
    };
    let limit = clamp_limit(q.limit, DEFAULT_LIMIT, MAX_LIMIT);
    let limit_us = limit as usize;
    let include_unconfirmed = q.include_unconfirmed.unwrap_or(false);
    let exclude_spent = q.exclude_mempool_spent.unwrap_or(false);

    let confirmed = confirmed_survivors(c_start, limit, dir, fetch_confirmed, |b| {
        match b.box_data.box_id() {
            // Short-circuits when `exclude_spent` is false: every row is kept
            // and `is_spent_by_pool` is never consulted.
            Ok(id) => !exclude_spent || !state.mempool.is_spent_by_pool(&id),
            // Keep an un-canonicalizable row so the downstream projection
            // surfaces the same 500 rather than silently dropping it.
            Err(_) => true,
        }
    });
    // The overlay resumes past the `p` rows earlier pages already emitted, so
    // an overlay bigger than one page pages THROUGH rather than repeating.
    let pool_rows: Vec<IndexedErgoBox> = if include_unconfirmed {
        pool(exclude_spent)
            .into_iter()
            .skip(p_start as usize)
            .collect()
    } else {
        Vec::new()
    };

    // How many of each side the re-capped page actually emits — the cursor
    // advances EXACTLY past those rows on both axes (no skips, no repeats).
    let total = pool_rows.len() + confirmed.len();
    let has_more = total > limit_us;
    let emitted_total = total.min(limit_us);
    let (pool_emitted, confirmed_emitted) = match dir {
        // Scala parity: DESC → unconfirmed first; ASC → confirmed first.
        SortDir::Desc => {
            let pe = pool_rows.len().min(limit_us);
            (pe, emitted_total - pe)
        }
        SortDir::Asc => {
            let ce = confirmed.len().min(limit_us);
            (emitted_total - ce, ce)
        }
    };
    let next_c = confirmed_emitted
        .checked_sub(1)
        .and_then(|i| confirmed.get(i))
        .map(|(_, off_after)| *off_after)
        .unwrap_or(c_start);
    let next_p = p_start.saturating_add(pool_emitted as u32);

    let confirmed_rows = confirmed.into_iter().map(|(b, _)| b);
    let mut merged: Vec<IndexedErgoBox> = match dir {
        SortDir::Desc => pool_rows.into_iter().chain(confirmed_rows).collect(),
        SortDir::Asc => confirmed_rows.chain(pool_rows).collect(),
    };
    merged.truncate(limit_us);
    match project_boxes(state, merged, q.decode.unwrap_or(false)) {
        Ok(items) => {
            let next_cursor = has_more.then(|| {
                encode_cursor(&UnspentCursor {
                    c: next_c,
                    p: next_p,
                })
            });
            let page = Page {
                limit,
                has_more: next_cursor.is_some(),
                next_cursor,
            };
            Json(Collection { items, page }).into_response()
        }
        Err(d) => assemble_failed(d),
    }
}

// ----- boxes/{box_id} (cheap) ---------------------------------------------

/// `GET /api/v1/boxes/{box_id}` — a single box. `404 box_not_found` on miss (a
/// real absent resource, not a disabled subsystem).
#[utoipa::path(
    get, path = "/api/v1/boxes/{box_id}", tag = "boxes",
    params(
        ("box_id" = String, Path, description = "64-char lowercase hex box id"),
        ("decode" = Option<bool>, Query, description = "Semantic-decode the box contract"),
    ),
    responses(
        (status = 200, description = "The box", body = V1Box),
        (status = 400, description = "Malformed box id", body = V1Error),
        (status = 404, description = "No box with that id", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 503, description = "Extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn box_by_id(
    State(state): State<V1State>,
    Path(box_id_hex): Path<String>,
    V1Query(q): V1Query<SingleBoxQuery>,
) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let Some(raw) = parse_id32(&box_id_hex) else {
        return invalid_box_id();
    };
    let box_id = BoxId::from_bytes(raw);
    match idx.box_by_id(&box_id) {
        Some(b) => {
            let best = state.read.status().best_full_block_height;
            match v1box_from_indexed_box(state.network, &b, best, q.decode.unwrap_or(false)) {
                Ok(v) => Json(v).into_response(),
                Err(d) => assemble_failed(d),
            }
        }
        None => box_not_found(),
    }
}

// ----- boxes/by-address (+ unspent), dual-mounted at addresses/* ----------

/// `GET /api/v1/boxes/by-address/{address}` (also mounted at
/// `addresses/{address}/boxes`) — full history (spent + unspent). v1 drops the
/// Scala `.reverse` DESC-page quirk: strict requested-sort order.
#[utoipa::path(
    get, path = "/api/v1/boxes/by-address/{address}", tag = "boxes",
    params(
        ("address" = String, Path, description = "Base58 address"),
        ("limit" = Option<u32>, Query, description = "Page size (default 20, cap 500)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
        ("sort" = Option<String>, Query, description = "`desc` (default) or `asc`"),
        ("decode" = Option<bool>, Query, description = "Semantic-decode each box's contract"),
    ),
    responses(
        (status = 200, description = "Boxes at this address (full history)", body = Collection<V1Box>),
        (status = 400, description = "Invalid address/sort/cursor", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 503, description = "Extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn boxes_by_address(
    State(state): State<V1State>,
    Path(address): Path<String>,
    V1Query(q): V1Query<BoxListQuery>,
) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let tree_hash = match address_to_tree_hash(&address, state.network) {
        Ok(h) => h,
        Err(e) => return invalid_address(&e),
    };
    render_box_page(
        &state,
        q.limit,
        q.cursor.as_deref(),
        q.sort.as_deref(),
        q.decode.unwrap_or(false),
        |page, dir| idx.address_boxes_paged(&tree_hash, page, dir),
    )
}

/// `GET /api/v1/boxes/unspent/by-address/{address}` (also mounted at
/// `addresses/{address}/unspent`).
#[utoipa::path(
    get, path = "/api/v1/boxes/unspent/by-address/{address}", tag = "boxes",
    params(
        ("address" = String, Path, description = "Base58 address"),
        ("limit" = Option<u32>, Query, description = "Page size (default 20, cap 500)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
        ("sort" = Option<String>, Query, description = "`desc` (default) or `asc`"),
        ("decode" = Option<bool>, Query, description = "Semantic-decode each box's contract"),
        ("include_unconfirmed" = Option<bool>, Query, description = "Merge in unspent mempool outputs"),
        ("exclude_mempool_spent" = Option<bool>, Query, description = "Drop confirmed boxes already spent in the mempool"),
    ),
    responses(
        (status = 200, description = "Unspent boxes at this address", body = Collection<V1Box>),
        (status = 400, description = "Invalid address/sort/cursor", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 503, description = "Extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn boxes_unspent_by_address(
    State(state): State<V1State>,
    Path(address): Path<String>,
    V1Query(q): V1Query<UnspentQuery>,
) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let tree_hash = match address_to_tree_hash(&address, state.network) {
        Ok(h) => h,
        Err(e) => return invalid_address(&e),
    };
    render_unspent_page(
        &state,
        &q,
        |page, dir| idx.address_unspent_paged(&tree_hash, page, dir),
        |excl| pool_unspent_for_tree(state.mempool.as_ref(), &tree_hash, excl),
    )
}

// ----- boxes/by-ergo-tree (+ unspent) -------------------------------------

/// `POST /api/v1/boxes/by-ergo-tree` — body `{ "ergo_tree": "<hex>" }`.
#[utoipa::path(
    post, path = "/api/v1/boxes/by-ergo-tree", tag = "boxes",
    params(
        ("limit" = Option<u32>, Query, description = "Page size (default 20, cap 500)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
        ("sort" = Option<String>, Query, description = "`desc` (default) or `asc`"),
        ("decode" = Option<bool>, Query, description = "Semantic-decode each box's contract"),
    ),
    request_body = ErgoTreeBody,
    responses(
        (status = 200, description = "Boxes for this ErgoTree (full history)", body = Collection<V1Box>),
        (status = 400, description = "Invalid ergo_tree/sort/cursor", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 503, description = "Extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn boxes_by_ergo_tree(
    State(state): State<V1State>,
    V1Query(q): V1Query<BoxListQuery>,
    V1Json(body): V1Json<ErgoTreeBody>,
) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let tree_hash = match decode_ergo_tree(&body.ergo_tree) {
        Ok(h) => h,
        Err(e) => return *e,
    };
    render_box_page(
        &state,
        q.limit,
        q.cursor.as_deref(),
        q.sort.as_deref(),
        q.decode.unwrap_or(false),
        |page, dir| idx.address_boxes_paged(&tree_hash, page, dir),
    )
}

/// `POST /api/v1/boxes/unspent/by-ergo-tree`.
#[utoipa::path(
    post, path = "/api/v1/boxes/unspent/by-ergo-tree", tag = "boxes",
    params(
        ("limit" = Option<u32>, Query, description = "Page size (default 20, cap 500)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
        ("sort" = Option<String>, Query, description = "`desc` (default) or `asc`"),
        ("decode" = Option<bool>, Query, description = "Semantic-decode each box's contract"),
        ("include_unconfirmed" = Option<bool>, Query, description = "Merge in unspent mempool outputs"),
        ("exclude_mempool_spent" = Option<bool>, Query, description = "Drop confirmed boxes already spent in the mempool"),
    ),
    request_body = ErgoTreeBody,
    responses(
        (status = 200, description = "Unspent boxes for this ErgoTree", body = Collection<V1Box>),
        (status = 400, description = "Invalid ergo_tree/sort/cursor", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 503, description = "Extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn boxes_unspent_by_ergo_tree(
    State(state): State<V1State>,
    V1Query(q): V1Query<UnspentQuery>,
    V1Json(body): V1Json<ErgoTreeBody>,
) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let tree_hash = match decode_ergo_tree(&body.ergo_tree) {
        Ok(h) => h,
        Err(e) => return *e,
    };
    render_unspent_page(
        &state,
        &q,
        |page, dir| idx.address_unspent_paged(&tree_hash, page, dir),
        |excl| pool_unspent_for_tree(state.mempool.as_ref(), &tree_hash, excl),
    )
}

// ----- boxes/by-template (+ unspent) --------------------------------------

/// `GET /api/v1/boxes/by-template/{template_hash}`. Unknown template → `200`
/// empty page (Scala parity), never 404.
#[utoipa::path(
    get, path = "/api/v1/boxes/by-template/{template_hash}", tag = "boxes",
    params(
        ("template_hash" = String, Path, description = "64-char lowercase hex blake2b256 template hash"),
        ("limit" = Option<u32>, Query, description = "Page size (default 20, cap 500)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
        ("sort" = Option<String>, Query, description = "Only `desc` (fixed reader order) is supported"),
        ("decode" = Option<bool>, Query, description = "Semantic-decode each box's contract"),
    ),
    responses(
        (status = 200, description = "Boxes matching this template (empty page if unknown)", body = Collection<V1Box>),
        (status = 400, description = "Invalid template_hash/cursor, or sort=asc (unsupported)", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 503, description = "Extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn boxes_by_template(
    State(state): State<V1State>,
    Path(hash_hex): Path<String>,
    V1Query(q): V1Query<BoxListQuery>,
) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let Some(raw) = parse_id32(&hash_hex) else {
        return invalid_template_hash();
    };
    let th = TemplateHash::from_bytes(raw);
    // `template_boxes_paged` has ONE fixed (DESC-keyed) order — an honest 400
    // for `sort=asc` rather than silently answering desc data labeled asc.
    if let Err(e) = reject_asc_fixed_order(q.sort.as_deref()) {
        return *e;
    }
    render_box_page(
        &state,
        q.limit,
        q.cursor.as_deref(),
        q.sort.as_deref(),
        q.decode.unwrap_or(false),
        |page, _dir| idx.template_boxes_paged(&th, page),
    )
}

/// `GET /api/v1/boxes/unspent/by-template/{template_hash}`.
#[utoipa::path(
    get, path = "/api/v1/boxes/unspent/by-template/{template_hash}", tag = "boxes",
    params(
        ("template_hash" = String, Path, description = "64-char lowercase hex blake2b256 template hash"),
        ("limit" = Option<u32>, Query, description = "Page size (default 20, cap 500)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
        ("sort" = Option<String>, Query, description = "`desc` (default) or `asc`"),
        ("decode" = Option<bool>, Query, description = "Semantic-decode each box's contract"),
        ("include_unconfirmed" = Option<bool>, Query, description = "Merge in unspent mempool outputs"),
        ("exclude_mempool_spent" = Option<bool>, Query, description = "Drop confirmed boxes already spent in the mempool"),
    ),
    responses(
        (status = 200, description = "Unspent boxes matching this template (empty page if unknown)", body = Collection<V1Box>),
        (status = 400, description = "Invalid template_hash/sort/cursor", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 503, description = "Extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn boxes_unspent_by_template(
    State(state): State<V1State>,
    Path(hash_hex): Path<String>,
    V1Query(q): V1Query<UnspentQuery>,
) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let Some(raw) = parse_id32(&hash_hex) else {
        return invalid_template_hash();
    };
    let th = TemplateHash::from_bytes(raw);
    render_unspent_page(
        &state,
        &q,
        |page, dir| idx.template_unspent_paged(&th, page, dir),
        |excl| pool_unspent_for_template(state.mempool.as_ref(), &th, excl),
    )
}

// ----- boxes/by-token (+ unspent) -----------------------------------------

/// `GET /api/v1/boxes/by-token/{token_id}`. Unknown token → `200` empty page.
#[utoipa::path(
    get, path = "/api/v1/boxes/by-token/{token_id}", tag = "boxes",
    params(
        ("token_id" = String, Path, description = "64-char lowercase hex token id"),
        ("limit" = Option<u32>, Query, description = "Page size (default 20, cap 500)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
        ("sort" = Option<String>, Query, description = "Only `desc` (fixed reader order) is supported"),
        ("decode" = Option<bool>, Query, description = "Semantic-decode each box's contract"),
    ),
    responses(
        (status = 200, description = "Boxes carrying this token (empty page if unknown)", body = Collection<V1Box>),
        (status = 400, description = "Invalid token_id/cursor, or sort=asc (unsupported)", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 503, description = "Extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn boxes_by_token(
    State(state): State<V1State>,
    Path(token_hex): Path<String>,
    V1Query(q): V1Query<BoxListQuery>,
) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let Some(raw) = parse_id32(&token_hex) else {
        return invalid_token_id();
    };
    let tid = TokenId::from_bytes(raw);
    // Same fixed-order contract as `boxes_by_template`.
    if let Err(e) = reject_asc_fixed_order(q.sort.as_deref()) {
        return *e;
    }
    render_box_page(
        &state,
        q.limit,
        q.cursor.as_deref(),
        q.sort.as_deref(),
        q.decode.unwrap_or(false),
        |page, _dir| idx.token_boxes_paged(&tid, page),
    )
}

/// `GET /api/v1/boxes/unspent/by-token/{token_id}`.
#[utoipa::path(
    get, path = "/api/v1/boxes/unspent/by-token/{token_id}", tag = "boxes",
    params(
        ("token_id" = String, Path, description = "64-char lowercase hex token id"),
        ("limit" = Option<u32>, Query, description = "Page size (default 20, cap 500)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
        ("sort" = Option<String>, Query, description = "`desc` (default) or `asc`"),
        ("decode" = Option<bool>, Query, description = "Semantic-decode each box's contract"),
        ("include_unconfirmed" = Option<bool>, Query, description = "Merge in unspent mempool outputs"),
        ("exclude_mempool_spent" = Option<bool>, Query, description = "Drop confirmed boxes already spent in the mempool"),
    ),
    responses(
        (status = 200, description = "Unspent boxes carrying this token (empty page if unknown)", body = Collection<V1Box>),
        (status = 400, description = "Invalid token_id/sort/cursor", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 503, description = "Extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn boxes_unspent_by_token(
    State(state): State<V1State>,
    Path(token_hex): Path<String>,
    V1Query(q): V1Query<UnspentQuery>,
) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let Some(raw) = parse_id32(&token_hex) else {
        return invalid_token_id();
    };
    let tid = TokenId::from_bytes(raw);
    render_unspent_page(
        &state,
        &q,
        |page, dir| idx.token_unspent_paged(&tid, page, dir),
        |excl| pool_unspent_for_token(state.mempool.as_ref(), &tid, excl),
    )
}

// ----- boxes/range --------------------------------------------------------

/// `GET /api/v1/boxes/range` — bare box-id list over a global-index range.
/// Cursor `{gi}` is genuinely stable (append-only global index).
#[utoipa::path(
    get, path = "/api/v1/boxes/range", tag = "boxes",
    params(
        ("limit" = Option<u32>, Query, description = "Page size (default 100, cap 2000)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
    ),
    responses(
        (status = 200, description = "Box ids in global-index order", body = Collection<String>),
        (status = 400, description = "Invalid cursor", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 503, description = "Extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn box_range(State(state): State<V1State>, V1Query(q): V1Query<RangeQuery>) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let start_gi = match decode_opt_cursor::<GiCursor>(q.cursor.as_deref()) {
        Ok(c) => c.map(|c| c.gi).unwrap_or(0),
        Err(e) => return *e,
    };
    let limit = clamp_limit(q.limit, RANGE_DEFAULT_LIMIT, RANGE_MAX_LIMIT);
    let lo = start_gi;
    let hi = lo.saturating_add(u64::from(limit) + 1);
    let boxes = idx.boxes_by_global_range(lo, hi);
    let rows: Result<Vec<(String, u64)>, String> = boxes
        .iter()
        .map(|b| {
            b.box_data
                .box_id()
                .map(|id| (hex::encode(id.as_bytes()), b.global_index as u64))
                .map_err(|e| format!("box_id derivation failed: {e}"))
        })
        .collect();
    let rows = match rows {
        Ok(r) => r,
        Err(d) => return assemble_failed(d),
    };
    let (rows, page) = Page::from_overfetch(rows, limit, |row| GiCursor { gi: row.1 + 1 });
    let items: Vec<String> = rows.into_iter().map(|(id, _)| id).collect();
    Json(Collection { items, page }).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    /// A `fetch` closure over a fixed backing slice `0..n`, honoring the page
    /// window (ASC only — enough to exercise the overfetch loop).
    fn windowed_reader(n: u32) -> impl Fn(IdxPage, SortDir) -> Vec<u32> {
        move |page: IdxPage, _dir: SortDir| {
            (page.offset..n)
                .take(page.limit as usize)
                .collect::<Vec<u32>>()
        }
    }

    // ----- happy path -----

    fn rows_of(survivors: &[(u32, u32)]) -> Vec<u32> {
        survivors.iter().map(|(v, _)| *v).collect()
    }

    #[test]
    fn confirmed_survivors_no_filter_reads_one_overfetch_window() {
        // limit=3, no filter: exactly limit+1 survivors, each carrying the
        // reader offset just past it.
        let rows = confirmed_survivors(0, 3, SortDir::Asc, windowed_reader(100), |_| true);
        assert_eq!(rows_of(&rows), vec![0, 1, 2, 3]);
        // The limit-th (3rd) survivor sat at reader offset 2 → resumes at 3.
        assert_eq!(rows[2].1, 3);
    }

    #[test]
    fn confirmed_survivors_start_offset_advances_by_limit() {
        let rows = confirmed_survivors(10, 2, SortDir::Asc, windowed_reader(100), |_| true);
        assert_eq!(rows_of(&rows), vec![10, 11, 12]);
        assert_eq!(rows[1].1, 12);
    }

    // ----- error paths / underfill regression -----

    #[test]
    fn confirmed_survivors_filter_overfetches_until_page_fills() {
        // Keep only evens (simulating exclude_mempool_spent dropping half). A
        // single limit+1 fetch would underfill; the loop keeps reading until
        // limit+1 survivors exist, each with the offset PAST the rows read to
        // reach it (no dupes, no underfill).
        let keep_even = |v: &u32| v.is_multiple_of(2);
        let rows = confirmed_survivors(0, 3, SortDir::Asc, windowed_reader(100), keep_even);
        // limit+1 = 4 survivors: 0,2,4,6.
        assert_eq!(rows_of(&rows), vec![0, 2, 4, 6]);
        // 3rd survivor (value 4) sat at reader offset 4 → resumes at offset 5.
        assert_eq!(rows[2].1, 5);
        // If the overlay pushes a row out and only 2 survivors are emitted,
        // the cursor from the 2nd survivor resumes at offset 3 (after value 2)
        // — the row-loss regression the per-survivor offsets exist to prevent.
        assert_eq!(rows[1].1, 3);
    }

    #[test]
    fn confirmed_survivors_exhaustion_yields_short_page() {
        // Only 3 evens in 0..5 — short of limit+1; every survivor still
        // carries its own resume offset.
        let keep_even = |v: &u32| v.is_multiple_of(2);
        let rows = confirmed_survivors(0, 10, SortDir::Asc, windowed_reader(5), keep_even);
        assert_eq!(rows_of(&rows), vec![0, 2, 4]);
        assert_eq!(rows[2].1, 5);
    }
}
