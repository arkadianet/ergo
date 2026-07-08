//! `boxes/*` reads (`v1-api-design.md` §3.7) — by-id, by-address, by-ergo-tree,
//! by-template, by-token, their unspent variants, and the global-index range.
//!
//! This group OWNS the canonical box shape: every response converges on the ONE
//! [`V1Box`](super::dto::V1Box) the transactions group defined (coherence Part
//! B / coordination flag #2). Handlers adapt the existing indexer readers
//! (`address_boxes_paged`, `token_unspent_paged`, …) and pool overlays
//! (`pool_unspent_for_*`) into the v1 envelope + cursor, gating every read on
//! the extra index (`indexer_disabled` / `_syncing` / `_halted`).

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_indexer_types::types::IndexedErgoBox;
use ergo_indexer_types::{BoxId, Page as IdxPage, SortDir, TemplateHash, TokenId, TreeHash};
use ergo_ser::ergo_tree::tree_hash_from_bytes;
use serde::Deserialize;

use super::dto::{v1box_from_indexed_box, Collection, V1Box};
use super::{
    offset_from_cursor, offset_page, offset_page_explicit, parse_id32, parse_sort, GiCursor,
    V1State,
};
use crate::blockchain::{
    address_to_tree_hash, pool_unspent_for_template, pool_unspent_for_token, pool_unspent_for_tree,
};
use crate::v1::cursor::{clamp_limit, decode_opt_cursor, Page};
use crate::v1::error::{v1_error, Reason};

/// Default page size and hard cap for this group (§2.2 — a deliberate
/// tightening vs the compat `MAX_ITEMS = 16384`).
const DEFAULT_LIMIT: u32 = 20;
const MAX_LIMIT: u32 = 500;
/// `boxes/range` returns bare ids, so its per-item payload is far lighter — a
/// looser cap is justified (§2.2).
const RANGE_DEFAULT_LIMIT: u32 = 100;
const RANGE_MAX_LIMIT: u32 = 2000;

// ----- query payloads -----------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct SingleBoxQuery {
    #[serde(default)]
    decode: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
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

#[derive(Debug, Default, Deserialize)]
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

#[derive(Debug, Default, Deserialize)]
pub struct RangeQuery {
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    cursor: Option<String>,
}

/// POST body for the by-ergo-tree routes (a tree is too long for a path
/// segment — Scala made the same call).
#[derive(Debug, Deserialize)]
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

/// The unspent variants: confirmed page (overfetched) + the optional
/// pool-output overlay, merged in the Scala order, then **re-capped to
/// `limit`** (v1 fixes the compat quirk where `include_unconfirmed=true` could
/// exceed `limit`). The offset cursor advances the confirmed window; the
/// overlay is an offset-alias drift documented at the codec (§1.5).
fn render_unspent_page(
    state: &V1State,
    q: &UnspentQuery,
    fetch_confirmed: impl FnOnce(IdxPage, SortDir) -> Vec<IndexedErgoBox>,
    pool: impl FnOnce(bool) -> Vec<IndexedErgoBox>,
) -> Response {
    let dir = match parse_sort(q.sort.as_deref()) {
        Ok(d) => d,
        Err(e) => return *e,
    };
    let start = match offset_from_cursor(q.cursor.as_deref()) {
        Ok(o) => o,
        Err(e) => return *e,
    };
    let limit = clamp_limit(q.limit, DEFAULT_LIMIT, MAX_LIMIT);
    let include_unconfirmed = q.include_unconfirmed.unwrap_or(false);
    let exclude_spent = q.exclude_mempool_spent.unwrap_or(false);

    let mut confirmed = fetch_confirmed(
        IdxPage {
            offset: start,
            limit: limit + 1,
        },
        dir,
    );
    // The offset cursor advances the CONFIRMED window, so the next-page signal
    // is the confirmed overfetch — captured BEFORE `exclude_spent` (a pool-spent
    // view overlay) can drop the (limit+1)th sentinel row and fool the pager into
    // reporting no next page (CodeRabbit #170). Drop the sentinel now the signal
    // is recorded; the display page was capped to `limit` regardless.
    let more_confirmed = confirmed.len() as u64 > u64::from(limit);
    confirmed.truncate(limit as usize);
    if exclude_spent {
        confirmed.retain(|b| match b.box_data.box_id() {
            Ok(id) => !state.mempool.is_spent_by_pool(&id),
            // Keep an un-canonicalizable row so the downstream projection
            // surfaces the same 500 rather than silently dropping it.
            Err(_) => true,
        });
    }
    let unconfirmed = if include_unconfirmed {
        pool(exclude_spent)
    } else {
        Vec::new()
    };
    // Scala parity: DESC → unconfirmed first; ASC → confirmed first.
    let merged: Vec<IndexedErgoBox> = match dir {
        SortDir::Desc => unconfirmed.into_iter().chain(confirmed).collect(),
        SortDir::Asc => confirmed.into_iter().chain(unconfirmed).collect(),
    };
    match project_boxes(state, merged, q.decode.unwrap_or(false)) {
        Ok(items) => {
            let (items, page) = offset_page_explicit(items, start, limit, more_confirmed);
            Json(Collection { items, page }).into_response()
        }
        Err(d) => assemble_failed(d),
    }
}

// ----- boxes/{box_id} (cheap) ---------------------------------------------

/// `GET /api/v1/boxes/{box_id}` — a single box. `404 box_not_found` on miss (a
/// real absent resource, not a disabled subsystem).
pub async fn box_by_id(
    State(state): State<V1State>,
    Path(box_id_hex): Path<String>,
    Query(q): Query<SingleBoxQuery>,
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
pub async fn boxes_by_address(
    State(state): State<V1State>,
    Path(address): Path<String>,
    Query(q): Query<BoxListQuery>,
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
pub async fn boxes_unspent_by_address(
    State(state): State<V1State>,
    Path(address): Path<String>,
    Query(q): Query<UnspentQuery>,
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
pub async fn boxes_by_ergo_tree(
    State(state): State<V1State>,
    Query(q): Query<BoxListQuery>,
    Json(body): Json<ErgoTreeBody>,
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
pub async fn boxes_unspent_by_ergo_tree(
    State(state): State<V1State>,
    Query(q): Query<UnspentQuery>,
    Json(body): Json<ErgoTreeBody>,
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
pub async fn boxes_by_template(
    State(state): State<V1State>,
    Path(hash_hex): Path<String>,
    Query(q): Query<BoxListQuery>,
) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let Some(raw) = parse_id32(&hash_hex) else {
        return invalid_template_hash();
    };
    let th = TemplateHash::from_bytes(raw);
    // `template_boxes_paged` has no sort side; `sort` is still validated for a
    // uniform error surface, then the DESC-keyed reader window is used.
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
pub async fn boxes_unspent_by_template(
    State(state): State<V1State>,
    Path(hash_hex): Path<String>,
    Query(q): Query<UnspentQuery>,
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
pub async fn boxes_by_token(
    State(state): State<V1State>,
    Path(token_hex): Path<String>,
    Query(q): Query<BoxListQuery>,
) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let Some(raw) = parse_id32(&token_hex) else {
        return invalid_token_id();
    };
    let tid = TokenId::from_bytes(raw);
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
pub async fn boxes_unspent_by_token(
    State(state): State<V1State>,
    Path(token_hex): Path<String>,
    Query(q): Query<UnspentQuery>,
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
pub async fn box_range(State(state): State<V1State>, Query(q): Query<RangeQuery>) -> Response {
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
