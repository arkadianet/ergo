//! `chain/*` reads — blocks, headers, modifiers, proofs. Every route is T0
//! and rides the live-store
//! [`NodeChainQuery`](crate::compat::NodeChainQuery) trait; none needs the
//! indexer or the compiler. Handlers project the frozen Scala-compat DTOs into
//! the glossary-named v1 shapes in [`super::dto`] and answer the honest
//! `chain_reader_unavailable` reason when the node has no chain reader.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::dto::{
    block_from_scala, block_summary_from_scala, block_tx_from_scala, header_from_scala,
    modifier_from_scala, Collection, MerkleSide, V1Block, V1BlockAdProofs, V1BlockSummary,
    V1BlockTx, V1Header, V1MerkleLevel, V1MerkleProof, V1Modifier,
};
use super::extract::{V1Json, V1Query};
use super::{
    candidate_heights, invalid_hex, parse_height, parse_order, valid_modifier_id, HeightCursor,
    ListQuery, V1State,
};
use crate::compat::ChainReadError;
use crate::v1::blocking::ReadLane;
use crate::v1::cursor::{clamp_limit, decode_opt_cursor, encode_cursor, Page};
use crate::v1::error::V1Error;
use crate::v1::error::{v1_error, Reason};

/// The node HAS the block but could not turn it into a response. Distinct
/// from [`block_not_found`]: a 404 asserts the node does not have the block,
/// which sends a chain-walking client looking for a hole that is not there.
fn block_unserialisable(detail: String) -> Response {
    v1_error(
        Reason::InternalError,
        "the block is stored but could not be serialised",
        detail,
    )
}

fn chain_read_failed(error: ChainReadError) -> Response {
    match error {
        ChainReadError::Unavailable(_) => v1_error(
            Reason::ChainReaderUnavailable,
            "the chain store could not be read",
            "retry the request shortly",
        ),
        ChainReadError::Corrupt(detail) => block_unserialisable(detail),
    }
}

fn block_not_found() -> Response {
    v1_error(
        Reason::BlockNotFound,
        "no block with that header id",
        "the id is well-formed but unknown to this node",
    )
}

fn header_not_found() -> Response {
    v1_error(
        Reason::HeaderNotFound,
        "no header with that id",
        "the id is well-formed but unknown to this node",
    )
}

/// Page assembly for the height-walk lists: `has_more`/`next_cursor` derive
/// from the height window scanned, NOT the collected row count — a height
/// whose row is missing (e.g. a pruned block body) must yield a short page
/// that keeps advancing, never a false end-of-listing. The overfetched
/// (limit+1)-th height is probed with `has_header`: headers are dense on a
/// synced chain, so header presence there is exactly "another candidate row
/// exists". Returns the window length (how many leading heights to render)
/// plus the finished `Page`. A failed probe fails the whole page.
fn height_window_page(
    heights: &[u32],
    limit: u32,
    has_header: impl Fn(u32) -> Result<bool, ChainReadError>,
) -> Result<(usize, Page), ChainReadError> {
    let window_len = heights.len().min(limit as usize);
    let mut has_next = false;
    for &height in &heights[window_len..] {
        has_next |= has_header(height)?;
    }
    let next_cursor = has_next
        .then(|| {
            heights[..window_len]
                .last()
                .map(|&h| encode_cursor(&HeightCursor { h }))
        })
        .flatten();
    let has_more = next_cursor.is_some();
    Ok((
        window_len,
        Page {
            limit,
            next_cursor,
            has_more,
        },
    ))
}

// ----- chain/blocks -------------------------------------------------------

/// `GET /api/v1/chain/blocks` — cursor-paginated full-history block summaries
/// (default 25, cap 200), newest-first by default.
#[utoipa::path(
    get, path = "/api/v1/chain/blocks", tag = "chain",
    params(
        ("order" = Option<String>, Query, description = "`desc` (default) or `asc`"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
        ("limit" = Option<u32>, Query, description = "Page size (default 25, cap 200)"),
    ),
    responses(
        (status = 200, description = "Block summaries", body = Collection<V1BlockSummary>),
        (status = 400, description = "Invalid order/cursor/limit", body = V1Error),
        (status = 500, description = "Stored chain record could not be serialised; internal_error on read failure", body = V1Error),
        (status = 503, description = "Chain reader unavailable; overloaded (Retry-After: 1) or shutting_down", body = V1Error),
        (status = 504, description = "Read timed out (timeout)", body = V1Error),
    ),
)]
pub async fn list_blocks(State(state): State<V1State>, V1Query(q): V1Query<ListQuery>) -> Response {
    let chain = match state.chain() {
        Ok(c) => c.clone(),
        Err(e) => return *e,
    };
    let order = match parse_order(q.order.as_deref()) {
        Ok(o) => o,
        Err(e) => return *e,
    };
    let cursor: Option<HeightCursor> = match decode_opt_cursor(q.cursor.as_deref()) {
        Ok(c) => c,
        Err(boxed) => return *boxed,
    };
    let limit = clamp_limit(q.limit, 25, 200);
    state
        .blocking
        .clone()
        .run(ReadLane::Scan, move || {
            let tip = state.read.sync().best_full_block_height;

            let heights = candidate_heights(cursor.map(|c| c.h), order, tip, limit + 1);
            let (window_len, page) = match height_window_page(&heights, limit, |h| {
                chain.try_header_ids_at_height(h).map(|ids| !ids.is_empty())
            }) {
                Ok(page) => page,
                Err(error) => return chain_read_failed(error),
            };
            let mut items = Vec::new();
            for &h in &heights[..window_len] {
                let ids = match chain.try_header_ids_at_height(h) {
                    Ok(ids) => ids,
                    Err(error) => return chain_read_failed(error),
                };
                if let Some(id) = ids.first() {
                    match chain.try_full_block_by_id(id) {
                        Ok(Some(fb)) => items.push(block_summary_from_scala(state.network, &fb)),
                        Ok(None) => {}
                        Err(error) => return chain_read_failed(error),
                    }
                }
            }
            Json(Collection { items, page }).into_response()
        })
        .await
}

/// `GET /api/v1/chain/blocks/{header_id}` — single full block.
#[utoipa::path(
    get, path = "/api/v1/chain/blocks/{header_id}", tag = "chain",
    params(("header_id" = String, Path, description = "64-char lowercase hex header id")),
    responses(
        (status = 200, description = "Full block", body = V1Block),
        (status = 400, description = "Malformed header id", body = V1Error),
        (status = 404, description = "No block with that header id", body = V1Error),
        (status = 500, description = "Block is stored but could not be serialised; internal_error on read failure", body = V1Error),
        (status = 503, description = "Chain reader unavailable; overloaded (Retry-After: 1) or shutting_down", body = V1Error),
        (status = 504, description = "Read timed out (timeout)", body = V1Error),
    ),
)]
pub async fn block_by_id(State(state): State<V1State>, Path(id): Path<String>) -> Response {
    let chain = match state.chain() {
        Ok(c) => c.clone(),
        Err(e) => return *e,
    };
    if !valid_modifier_id(&id) {
        return invalid_hex();
    }
    state
        .blocking
        .clone()
        .run(ReadLane::Point, move || {
            let tip = state.read.sync().best_full_block_height;
            match chain.try_full_block_by_id(&id) {
                Ok(Some(fb)) => Json(block_from_scala(state.network, &fb, tip)).into_response(),
                Ok(None) => block_not_found(),
                Err(error) => chain_read_failed(error),
            }
        })
        .await
}

/// `GET /api/v1/chain/blocks/{header_id}/transactions` — the block's tx
/// section (single-page collection; a block never spans pages).
#[utoipa::path(
    get, path = "/api/v1/chain/blocks/{header_id}/transactions", tag = "chain",
    params(("header_id" = String, Path, description = "64-char lowercase hex header id")),
    responses(
        (status = 200, description = "Block transactions (single page)", body = Collection<V1BlockTx>),
        (status = 400, description = "Malformed header id", body = V1Error),
        (status = 404, description = "No block with that header id", body = V1Error),
        (status = 500, description = "Block is stored but could not be serialised; internal_error on read failure", body = V1Error),
        (status = 503, description = "Chain reader unavailable; overloaded (Retry-After: 1) or shutting_down", body = V1Error),
        (status = 504, description = "Read timed out (timeout)", body = V1Error),
    ),
)]
pub async fn block_transactions(State(state): State<V1State>, Path(id): Path<String>) -> Response {
    let chain = match state.chain() {
        Ok(c) => c.clone(),
        Err(e) => return *e,
    };
    if !valid_modifier_id(&id) {
        return invalid_hex();
    }
    state
        .blocking
        .clone()
        .run(ReadLane::Point, move || {
            match chain.try_block_transactions_by_id(&id) {
                Ok(Some(bt)) => {
                    let tip = state.read.sync().best_full_block_height;
                    let height = match chain.try_header_by_id(&id) {
                        Ok(header) => header.map(|h| h.height),
                        Err(error) => return chain_read_failed(error),
                    };
                    let items = bt
                        .transactions
                        .iter()
                        .map(|tx| block_tx_from_scala(state.network, tx, height, tip))
                        .collect();
                    Json(Collection::single_page(items)).into_response()
                }
                Ok(None) => block_not_found(),
                Err(error) => chain_read_failed(error),
            }
        })
        .await
}

/// `GET /api/v1/chain/blocks/at-height/{height}` — header ids at a height
/// (canonical chain only; single-page collection).
#[utoipa::path(
    get, path = "/api/v1/chain/blocks/at-height/{height}", tag = "chain",
    params(("height" = u32, Path, description = "Block height")),
    responses(
        (status = 200, description = "Header ids at height (single page)", body = Collection<String>),
        (status = 400, description = "Height is not a non-negative integer", body = V1Error),
        (status = 500, description = "Stored chain record could not be serialised; internal_error on read failure", body = V1Error),
        (status = 503, description = "Chain reader unavailable; overloaded (Retry-After: 1) or shutting_down", body = V1Error),
        (status = 504, description = "Read timed out (timeout)", body = V1Error),
    ),
)]
pub async fn blocks_at_height(
    State(state): State<V1State>,
    Path(height): Path<String>,
) -> Response {
    let chain = match state.chain() {
        Ok(c) => c.clone(),
        Err(e) => return *e,
    };
    let height = match parse_height(&height) {
        Ok(h) => h,
        Err(e) => return *e,
    };
    state
        .blocking
        .clone()
        .run(ReadLane::Point, move || {
            let ids = match chain.try_header_ids_at_height(height) {
                Ok(ids) => ids,
                Err(error) => return chain_read_failed(error),
            };
            Json(Collection::single_page(ids)).into_response()
        })
        .await
}

/// `POST /api/v1/chain/blocks/by-ids` — bulk full-block fetch; request order
/// preserved, misses silently dropped, array capped at 200.
#[utoipa::path(
    post, path = "/api/v1/chain/blocks/by-ids", tag = "chain",
    request_body(content = Vec<String>, description = "Header ids to fetch, at most 200"),
    responses(
        (status = 200, description = "Full blocks found (single page, misses dropped)", body = Collection<V1Block>),
        (status = 400, description = "Malformed id or more than 200 ids", body = V1Error),
        (status = 500, description = "Stored chain record could not be serialised; internal_error on read failure", body = V1Error),
        (status = 503, description = "Chain reader unavailable; overloaded (Retry-After: 1) or shutting_down", body = V1Error),
        (status = 504, description = "Read timed out (timeout)", body = V1Error),
    ),
)]
pub async fn blocks_by_ids(
    State(state): State<V1State>,
    V1Json(ids): V1Json<Vec<String>>,
) -> Response {
    let chain = match state.chain() {
        Ok(c) => c.clone(),
        Err(e) => return *e,
    };
    if ids.len() > 200 {
        return v1_error(
            Reason::TooManyIds,
            "at most 200 header ids per request",
            "split the request into batches of 200 or fewer",
        );
    }
    if ids.iter().any(|id| !valid_modifier_id(id)) {
        return invalid_hex();
    }
    state
        .blocking
        .clone()
        .run(ReadLane::Scan, move || {
            let tip = state.read.sync().best_full_block_height;
            let mut items = Vec::new();
            for id in &ids {
                match chain.try_full_block_by_id(id) {
                    Ok(Some(fb)) => items.push(block_from_scala(state.network, &fb, tip)),
                    Ok(None) => {}
                    Err(error) => return chain_read_failed(error),
                }
            }
            Json(Collection::single_page(items)).into_response()
        })
        .await
}

// ----- chain/headers ------------------------------------------------------

/// `GET /api/v1/chain/headers` — cursor-paginated header objects (default
/// 100, cap 1000), newest-first by default.
#[utoipa::path(
    get, path = "/api/v1/chain/headers", tag = "chain",
    params(
        ("order" = Option<String>, Query, description = "`desc` (default) or `asc`"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
        ("limit" = Option<u32>, Query, description = "Page size (default 100, cap 1000)"),
    ),
    responses(
        (status = 200, description = "Header objects", body = Collection<V1Header>),
        (status = 400, description = "Invalid order/cursor/limit", body = V1Error),
        (status = 500, description = "Stored chain record could not be serialised; internal_error on read failure", body = V1Error),
        (status = 503, description = "Chain reader unavailable; overloaded (Retry-After: 1) or shutting_down", body = V1Error),
        (status = 504, description = "Read timed out (timeout)", body = V1Error),
    ),
)]
pub async fn list_headers(
    State(state): State<V1State>,
    V1Query(q): V1Query<ListQuery>,
) -> Response {
    let chain = match state.chain() {
        Ok(c) => c.clone(),
        Err(e) => return *e,
    };
    let order = match parse_order(q.order.as_deref()) {
        Ok(o) => o,
        Err(e) => return *e,
    };
    let cursor: Option<HeightCursor> = match decode_opt_cursor(q.cursor.as_deref()) {
        Ok(c) => c,
        Err(boxed) => return *boxed,
    };
    let limit = clamp_limit(q.limit, 100, 1000);
    state
        .blocking
        .clone()
        .run(ReadLane::Scan, move || {
            let tip = state.read.sync().best_header_height;

            let heights = candidate_heights(cursor.map(|c| c.h), order, tip, limit + 1);
            let (window_len, page) = match height_window_page(&heights, limit, |h| {
                chain.try_header_ids_at_height(h).map(|ids| !ids.is_empty())
            }) {
                Ok(page) => page,
                Err(error) => return chain_read_failed(error),
            };
            let mut items = Vec::new();
            for &h in &heights[..window_len] {
                let ids = match chain.try_header_ids_at_height(h) {
                    Ok(ids) => ids,
                    Err(error) => return chain_read_failed(error),
                };
                if let Some(id) = ids.first() {
                    match chain.try_header_by_id(id) {
                        Ok(Some(header)) => items.push(header_from_scala(state.network, &header)),
                        Ok(None) => {}
                        Err(error) => return chain_read_failed(error),
                    }
                }
            }
            Json(Collection { items, page }).into_response()
        })
        .await
}

/// `GET /api/v1/chain/headers/{header_id}` — single header object.
#[utoipa::path(
    get, path = "/api/v1/chain/headers/{header_id}", tag = "chain",
    params(("header_id" = String, Path, description = "64-char lowercase hex header id")),
    responses(
        (status = 200, description = "Header object", body = V1Header),
        (status = 400, description = "Malformed header id", body = V1Error),
        (status = 404, description = "No header with that id", body = V1Error),
        (status = 500, description = "Stored chain record could not be serialised; internal_error on read failure", body = V1Error),
        (status = 503, description = "Chain reader unavailable; overloaded (Retry-After: 1) or shutting_down", body = V1Error),
        (status = 504, description = "Read timed out (timeout)", body = V1Error),
    ),
)]
pub async fn header_by_id(State(state): State<V1State>, Path(id): Path<String>) -> Response {
    let chain = match state.chain() {
        Ok(c) => c.clone(),
        Err(e) => return *e,
    };
    if !valid_modifier_id(&id) {
        return invalid_hex();
    }
    state
        .blocking
        .clone()
        .run(ReadLane::Point, move || match chain.try_header_by_id(&id) {
            Ok(Some(h)) => Json(header_from_scala(state.network, &h)).into_response(),
            Ok(None) => header_not_found(),
            Err(error) => chain_read_failed(error),
        })
        .await
}

/// `GET /api/v1/chain/headers/at-height/{height}` — full header objects at a
/// height (single-page collection).
#[utoipa::path(
    get, path = "/api/v1/chain/headers/at-height/{height}", tag = "chain",
    params(("height" = u32, Path, description = "Block height")),
    responses(
        (status = 200, description = "Header objects at height (single page)", body = Collection<V1Header>),
        (status = 400, description = "Height is not a non-negative integer", body = V1Error),
        (status = 500, description = "Stored chain record could not be serialised; internal_error on read failure", body = V1Error),
        (status = 503, description = "Chain reader unavailable; overloaded (Retry-After: 1) or shutting_down", body = V1Error),
        (status = 504, description = "Read timed out (timeout)", body = V1Error),
    ),
)]
pub async fn headers_at_height(
    State(state): State<V1State>,
    Path(height): Path<String>,
) -> Response {
    let chain = match state.chain() {
        Ok(c) => c.clone(),
        Err(e) => return *e,
    };
    let height = match parse_height(&height) {
        Ok(h) => h,
        Err(e) => return *e,
    };
    state
        .blocking
        .clone()
        .run(ReadLane::Point, move || {
            let ids = match chain.try_header_ids_at_height(height) {
                Ok(ids) => ids,
                Err(error) => return chain_read_failed(error),
            };
            let mut items = Vec::new();
            for id in &ids {
                match chain.try_header_by_id(id) {
                    Ok(Some(header)) => items.push(header_from_scala(state.network, &header)),
                    Ok(None) => {}
                    Err(error) => return chain_read_failed(error),
                }
            }
            Json(Collection::single_page(items)).into_response()
        })
        .await
}

// ----- chain/modifiers + proofs ------------------------------------------

/// `GET /api/v1/chain/modifiers/{modifier_id}` — generic-by-id lookup across
/// headers + the three non-header block sections, tagged with an explicit
/// `kind` discriminant.
#[utoipa::path(
    get, path = "/api/v1/chain/modifiers/{modifier_id}", tag = "chain",
    params(("modifier_id" = String, Path, description = "64-char lowercase hex modifier id")),
    responses(
        (status = 200, description = "The modifier, tagged by kind", body = V1Modifier),
        (status = 400, description = "Malformed modifier id", body = V1Error),
        (status = 404, description = "No modifier with that id (block_not_found)", body = V1Error),
        (status = 500, description = "Stored chain record could not be serialised; internal_error on read failure", body = V1Error),
        (status = 503, description = "Chain reader unavailable; overloaded (Retry-After: 1) or shutting_down", body = V1Error),
        (status = 504, description = "Read timed out (timeout)", body = V1Error),
    ),
)]
pub async fn modifier_by_id(State(state): State<V1State>, Path(id): Path<String>) -> Response {
    let chain = match state.chain() {
        Ok(c) => c.clone(),
        Err(e) => return *e,
    };
    if !valid_modifier_id(&id) {
        return invalid_hex();
    }
    state
        .blocking
        .clone()
        .run(ReadLane::Point, move || {
            let tip = state.read.sync().best_full_block_height;
            match chain.try_modifier_by_id(&id) {
                Ok(Some(section)) => {
                    Json(modifier_from_scala(state.network, &section, tip)).into_response()
                }
                // No `modifier_not_found` in the canonical enum; a missing block-graph
                // object answers `block_not_found`.
                Ok(None) => block_not_found(),
                Err(error) => chain_read_failed(error),
            }
        })
        .await
}

/// `GET /api/v1/chain/proofs/{header_id}` — the block's AD-proofs section.
/// Distinguishes "block unknown" (`block_not_found`) from "block known, proof
/// section absent / pruned" (`ad_proofs_unavailable`).
#[utoipa::path(
    get, path = "/api/v1/chain/proofs/{header_id}", tag = "chain",
    params(("header_id" = String, Path, description = "64-char lowercase hex header id")),
    responses(
        (status = 200, description = "AD-proofs section", body = V1BlockAdProofs),
        (status = 400, description = "Malformed header id", body = V1Error),
        (status = 404, description = "No block with that header id", body = V1Error),
        (status = 500, description = "Block is stored but could not be serialised; internal_error on read failure", body = V1Error),
        (status = 503, description = "AD-proofs pruned in UTXO/non-archival mode, or chain reader unavailable; overloaded (Retry-After: 1) or shutting_down", body = V1Error),
        (status = 504, description = "Read timed out (timeout)", body = V1Error),
    ),
)]
pub async fn block_ad_proofs(State(state): State<V1State>, Path(id): Path<String>) -> Response {
    let chain = match state.chain() {
        Ok(c) => c.clone(),
        Err(e) => return *e,
    };
    if !valid_modifier_id(&id) {
        return invalid_hex();
    }
    state
        .blocking
        .clone()
        .run(ReadLane::Point, move || {
            match chain.try_full_block_by_id(&id) {
                Ok(Some(fb)) => match fb.ad_proofs {
                    Some(p) => Json(V1BlockAdProofs {
                        header_id: id,
                        proof_bytes: p.proof_bytes,
                        digest: p.digest,
                        size_bytes: p.size,
                    })
                    .into_response(),
                    None => v1_error(
                        Reason::AdProofsUnavailable,
                        "the block exists but its AD-proofs section is not retained",
                        "AD-proofs are pruned in UTXO / non-archival mode",
                    ),
                },
                Ok(None) => block_not_found(),
                Err(error) => chain_read_failed(error),
            }
        })
        .await
}

/// `GET /api/v1/chain/proofs/{header_id}/transactions/{tx_id}` — Merkle
/// membership proof; side byte `0/1` rendered as `"left"/"right"`.
#[utoipa::path(
    get, path = "/api/v1/chain/proofs/{header_id}/transactions/{tx_id}", tag = "chain",
    params(
        ("header_id" = String, Path, description = "64-char lowercase hex header id"),
        ("tx_id" = String, Path, description = "64-char lowercase hex transaction id"),
    ),
    responses(
        (status = 200, description = "Merkle membership proof", body = V1MerkleProof),
        (status = 400, description = "Malformed header or tx id", body = V1Error),
        (status = 404, description = "No block, or tx not in that block", body = V1Error),
        (status = 500, description = "Stored chain record could not be serialised; internal_error on read failure", body = V1Error),
        (status = 503, description = "Chain reader unavailable; overloaded (Retry-After: 1) or shutting_down", body = V1Error),
        (status = 504, description = "Read timed out (timeout)", body = V1Error),
    ),
)]
pub async fn proof_for_tx(
    State(state): State<V1State>,
    Path((header_id, tx_id)): Path<(String, String)>,
) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    merkle_membership_proof(&state.blocking, chain.clone(), header_id, tx_id).await
}

/// Shared Merkle membership-proof core (Overlap O2): the ONE implementation
/// behind both `chain/proofs/{header_id}/transactions/{tx_id}` (path params,
/// [`proof_for_tx`]) and `light/membership-proof` (query params,
/// [`super::light::membership_proof`]). Identical proof semantics — wraps
/// [`NodeChainQuery::try_proof_for_tx`](crate::compat::NodeChainQuery::try_proof_for_tx),
/// validating both ids and mapping the `None` return (header unknown OR tx not
/// in that block) to the honest `tx_not_in_block` 404.
pub(super) async fn merkle_membership_proof(
    blocking: &crate::v1::BlockingReads,
    chain: std::sync::Arc<dyn crate::compat::NodeChainQuery>,
    header_id: String,
    tx_id: String,
) -> Response {
    if !valid_modifier_id(&header_id) {
        return invalid_hex();
    }
    if !valid_modifier_id(&tx_id) {
        return v1_error(
            Reason::InvalidTxId,
            "tx_id is not a 64-character lowercase hex string",
            "supply an unprefixed lowercase hex transaction id",
        );
    }
    blocking
        .run(ReadLane::Point, move || {
            match chain.try_proof_for_tx(&header_id, &tx_id) {
                Ok(Some(mp)) => {
                    let levels = mp
                        .levels
                        .into_iter()
                        .map(|(sibling, side)| V1MerkleLevel {
                            sibling,
                            side: if side == 0 {
                                MerkleSide::Left
                            } else {
                                MerkleSide::Right
                            },
                        })
                        .collect();
                    Json(V1MerkleProof {
                        tx_id: tx_id.to_string(),
                        levels,
                    })
                    .into_response()
                }
                Err(error) => chain_read_failed(error),
                // Header unknown OR tx not in that block — a real 404.
                Ok(None) => v1_error(
                    Reason::TxNotInBlock,
                    "no membership proof: unknown block or tx not in it",
                    "verify the header id and that the tx is included in that block",
                ),
            }
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::cursor::decode_cursor;

    // ----- happy path -----

    #[test]
    fn height_window_page_full_window_pages_from_height_math() {
        let heights = [10, 9, 8, 7];
        let (window_len, page) = height_window_page(&heights, 3, |_| Ok(true)).unwrap();
        assert_eq!(window_len, 3);
        assert!(page.has_more);
        let cur: HeightCursor = decode_cursor(page.next_cursor.as_deref().unwrap()).unwrap();
        assert_eq!(cur.h, 8, "cursor is the last SCANNED height");
    }

    #[test]
    fn height_window_page_short_supply_ends_listing() {
        // Fewer candidate heights than the limit — nothing beyond the window.
        let heights = [3, 2, 1];
        let (window_len, page) = height_window_page(&heights, 25, |_| Ok(true)).unwrap();
        assert_eq!(window_len, 3);
        assert!(!page.has_more);
        assert!(page.next_cursor.is_none());
    }

    // ----- error paths -----

    #[test]
    fn height_window_page_missing_row_in_window_still_advances() {
        // A pruned body inside the window must not end the listing: the page
        // math never looks at the collected row count, only the height domain.
        let heights = [10, 9, 8, 7];
        let (window_len, page) = height_window_page(&heights, 3, |h| Ok(h != 9)).unwrap();
        assert_eq!(window_len, 3);
        assert!(page.has_more, "a header exists beyond the window");
        let cur: HeightCursor = decode_cursor(page.next_cursor.as_deref().unwrap()).unwrap();
        assert_eq!(cur.h, 8);
    }

    #[test]
    fn height_window_page_headerless_probe_ends_listing() {
        // The overfetched height has no header (nothing was ever there) —
        // the listing honestly ends.
        let heights = [10, 9, 8, 7];
        let (_, page) = height_window_page(&heights, 3, |h| Ok(h != 7)).unwrap();
        assert!(!page.has_more);
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn height_window_page_empty_heights_is_empty_last_page() {
        let (window_len, page) = height_window_page(&[], 25, |_| Ok(true)).unwrap();
        assert_eq!(window_len, 0);
        assert!(!page.has_more);
        assert!(page.next_cursor.is_none());
    }
}
