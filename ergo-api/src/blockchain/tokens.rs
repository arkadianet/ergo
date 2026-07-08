//! Token routes (#17, #18, #19, #20).
//!
//! All four routes key on a 64-char hex token id (32 bytes). The token-id
//! path matchers mirror Scala's `path(modifierId)` directive — bad hex
//! (length ≠ 64 or non-hex chars) surfaces as 404 via the Akka default
//! rejection.
//!
//! Wire shapes:
//!   #17 byId           → `IndexedToken` object on hit, 404 on miss
//!   #18 tokens (POST)  → bare `[IndexedToken]` array; misses dropped
//!                        (Scala flatMap semantics)
//!   #19 byTokenId      → `{items, total}` envelope (paged box list)
//!   #20 unspent/byTokenId → bare `[IndexedErgoBox]` array (paged unspent)
//!
//! Empty-fallback parity for the box list routes (#19/#20): unknown token
//! ids hit the empty-segment path in `token_*_paged` and return 200 with
//! the empty envelope / array — Scala's `IndexedToken.boxes` slicing
//! yields zero entries when the parent record is missing rather than
//! 404'ing the request.

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_indexer_types::types::IndexedErgoBox;
use ergo_indexer_types::{IndexedTokenDto, SortDir, TokenId};
use serde::Serialize;

use crate::traits::MempoolView;

use super::{
    build_indexed_box_response, internal_error, not_found, parse_modifier_id, parse_sort_direction,
    resolve_page, BlockchainState, ItemsTotalResponse, PagedQuery, UnspentByAddressQuery,
};

/// JSON wire shape for `GET /blockchain/token/byId/{tokenId}` and the
/// elements of `POST /blockchain/tokens`. Mirrors the openapi
/// `IndexedToken` schema (`openapi.yaml:378-412`):
/// ```json
/// {
///   "id": "<hex tokenId>",
///   "boxId": "<hex creatingBoxId>",
///   "emissionAmount": <int64>,
///   "name": "<utf8>",
///   "description": "<utf8>",
///   "decimals": <int32>
/// }
/// ```
/// All six fields are required JSON properties — no nullables. Defaults
/// for missing R4/R5/R6 registers (`""`, `""`, `0`) come from the
/// indexer-side projection in `IndexerHandle::token_by_id`.
#[derive(Debug, Serialize)]
pub struct IndexedTokenResponse {
    pub id: String,
    #[serde(rename = "boxId")]
    pub box_id: String,
    #[serde(rename = "emissionAmount")]
    pub emission_amount: i64,
    pub name: String,
    pub description: String,
    pub decimals: i32,
}

fn build_indexed_token_response(t: &IndexedTokenDto) -> IndexedTokenResponse {
    IndexedTokenResponse {
        id: hex::encode(t.token_id.as_bytes()),
        box_id: hex::encode(t.creating_box_id.as_bytes()),
        emission_amount: t.emission_amount,
        name: t.name.clone(),
        description: t.description.clone(),
        decimals: t.decimals,
    }
}

/// `GET /blockchain/token/byId/{tokenId}`. 404 on miss.
pub async fn token_by_id_handler(
    State(state): State<BlockchainState>,
    Path(token_id_hex): Path<String>,
) -> Response {
    let token_id = match parse_modifier_id(&token_id_hex) {
        Some(raw) => TokenId::from_bytes(raw),
        None => return not_found("token not found"),
    };
    match state.indexer.token_by_id(&token_id) {
        Some(t) => Json(build_indexed_token_response(&t)).into_response(),
        None => not_found("token not found"),
    }
}

/// `POST /blockchain/tokens`. Body is a bare JSON array of hex token-id
/// strings; response is a bare JSON array of `IndexedToken` objects.
/// Misses (unknown ids, malformed hex) are silently dropped per Scala's
/// `flatMap` semantics. The empty-input case returns
/// `200 []`.
pub async fn tokens_by_ids_handler(
    State(state): State<BlockchainState>,
    Json(ids_hex): Json<Vec<String>>,
) -> Response {
    let ids: Vec<TokenId> = ids_hex
        .iter()
        .filter_map(|s| parse_modifier_id(s).map(TokenId::from_bytes))
        .collect();
    let tokens = state.indexer.tokens_by_ids(&ids);
    let items: Vec<IndexedTokenResponse> =
        tokens.iter().map(build_indexed_token_response).collect();
    Json(items).into_response()
}

/// `GET /blockchain/box/byTokenId/{tokenId}`. Paged, returns
/// `{items, total}`. Bad-hex path param surfaces as 404 (Scala
/// `path(modifierId)` parity). Unknown tokens return the empty envelope
/// (Scala `IndexedToken.boxes` slicing fallback).
pub async fn boxes_by_token_id_handler(
    State(state): State<BlockchainState>,
    Path(token_id_hex): Path<String>,
    Query(q): Query<PagedQuery>,
) -> Response {
    let token_id = match parse_modifier_id(&token_id_hex) {
        Some(raw) => TokenId::from_bytes(raw),
        None => return not_found("token not found"),
    };
    let page = match resolve_page(q, "boxes") {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let boxes = state.indexer.token_boxes_paged(&token_id, page);
    let total = state.indexer.token_total_boxes(&token_id) as i64;
    let items = match boxes
        .iter()
        .map(|b| build_indexed_box_response(state.network, b))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(detail) => return internal_error(&detail),
    };
    Json(ItemsTotalResponse { items, total }).into_response()
}

/// `GET /blockchain/box/unspent/byTokenId/{tokenId}`. Paged, supports
/// `sortDirection` + the mempool overlay flags. Wire shape is a bare
/// `[IndexedErgoBox]` array per the openapi schema. Validation order mirrors
/// `unspent_byAddress`: path → paging → sortDirection → read + overlay.
/// The overlay is strictly orthogonal — flags don't gate, they alter
/// behavior.
pub async fn boxes_unspent_by_token_id_handler(
    State(state): State<BlockchainState>,
    Path(token_id_hex): Path<String>,
    Query(q): Query<UnspentByAddressQuery>,
) -> Response {
    let token_id = match parse_modifier_id(&token_id_hex) {
        Some(raw) => TokenId::from_bytes(raw),
        None => return not_found("token not found"),
    };
    render_unspent_by_token_id(&state, &token_id, q)
}

/// Shared overlay-aware renderer for `unspent/byTokenId`. Mirrors
/// `render_unspent_by_template_hash` in shape and
/// merge order; the only difference is the keying function — pool
/// outputs are matched by membership in the box's `tokens` vector
/// (`box.candidate.tokens.iter().any(|t| t.token_id == queried_id)`).
/// Same `[inherited]` paging quirk applies.
fn render_unspent_by_token_id(
    state: &BlockchainState,
    token_id: &TokenId,
    q: UnspentByAddressQuery,
) -> Response {
    let page = match resolve_page(
        PagedQuery {
            offset: q.offset,
            limit: q.limit,
        },
        "boxes",
    ) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let dir = match parse_sort_direction(q.sort_direction.as_deref()) {
        Ok(d) => d,
        Err(resp) => return *resp,
    };
    let include_unconfirmed = q.include_unconfirmed.unwrap_or(false);
    let exclude_mempool_spent = q.exclude_mempool_spent.unwrap_or(false);
    let mut confirmed = state.indexer.token_unspent_paged(token_id, page, dir);
    if exclude_mempool_spent {
        confirmed.retain(|b| match b.box_data.box_id() {
            Ok(id) => !state.mempool.is_spent_by_pool(&id),
            Err(_) => true,
        });
    }
    let unconfirmed = if include_unconfirmed {
        pool_unspent_for_token(state.mempool.as_ref(), token_id, exclude_mempool_spent)
    } else {
        Vec::new()
    };
    let merged: Vec<IndexedErgoBox> = match dir {
        SortDir::Desc => unconfirmed.into_iter().chain(confirmed).collect(),
        SortDir::Asc => confirmed.into_iter().chain(unconfirmed).collect(),
    };
    match merged
        .iter()
        .map(|b| build_indexed_box_response(state.network, b))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(items) => Json(items).into_response(),
        Err(detail) => internal_error(&detail),
    }
}

/// Build the unconfirmed pool-output extension for `unspent/byTokenId`.
/// Pool outputs are matched by token-id membership in
/// `box.candidate.tokens` and emitted with the same
/// `IndexedErgoBox(0, None, None, None, _, 0)` sentinel as
/// `pool_unspent_for_tree`. A pool box with multiple tokens may be
/// returned by multiple distinct token-id queries (each token surfaces
/// the box once).
pub(crate) fn pool_unspent_for_token(
    mempool: &dyn MempoolView,
    token_id: &TokenId,
    exclude_spent: bool,
) -> Vec<IndexedErgoBox> {
    let outputs = mempool.pool_outputs();
    if outputs.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<IndexedErgoBox> = Vec::new();
    for (box_id, ergo_box) in outputs.iter() {
        if exclude_spent && mempool.is_spent_by_pool(box_id) {
            continue;
        }
        if !ergo_box
            .candidate
            .tokens
            .iter()
            .any(|t| &t.token_id == token_id)
        {
            continue;
        }
        out.push(IndexedErgoBox {
            inclusion_height: 0,
            spending_tx_id: None,
            spending_height: None,
            spending_proof: None,
            box_data: ergo_box.clone(),
            global_index: 0,
        });
    }
    out
}
