//! `chain/*` reads (`v1-api-design.md` §3.5) — blocks, headers, modifiers,
//! proofs. Every route is T0 Phase-1 and rides the live-store
//! [`NodeChainQuery`](crate::compat::NodeChainQuery) trait; none needs the
//! indexer or the compiler. Handlers project the frozen Scala-compat DTOs into
//! the glossary-named v1 shapes in [`super::dto`] and answer the honest
//! `chain_reader_unavailable` reason when the node has no chain reader.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::dto::{
    block_from_scala, block_summary_from_scala, block_tx_from_scala, header_from_scala,
    modifier_from_scala, Collection, MerkleSide, V1BlockAdProofs, V1MerkleLevel, V1MerkleProof,
};
use super::extract::{V1Json, V1Query};
use super::{
    candidate_heights, invalid_hex, parse_height, parse_order, valid_modifier_id, HeightCursor,
    ListQuery, V1State,
};
use crate::v1::cursor::{clamp_limit, decode_opt_cursor, Page};
use crate::v1::error::{v1_error, Reason};

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

// ----- chain/blocks -------------------------------------------------------

/// `GET /api/v1/chain/blocks` — cursor-paginated full-history block summaries
/// (default 25, cap 200), newest-first by default.
pub async fn list_blocks(State(state): State<V1State>, V1Query(q): V1Query<ListQuery>) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
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
    let tip = state.read.status().best_full_block_height;

    let mut items = Vec::new();
    for h in candidate_heights(cursor.map(|c| c.h), order, tip, limit + 1) {
        if let Some(id) = chain.header_ids_at_height(h).into_iter().next() {
            if let Some(fb) = chain.full_block_by_id(&id) {
                items.push(block_summary_from_scala(state.network, &fb));
            }
        }
    }
    let (items, page) = Page::from_overfetch(items, limit, |s| HeightCursor { h: s.base.height });
    Json(Collection { items, page }).into_response()
}

/// `GET /api/v1/chain/blocks/{header_id}` — single full block.
pub async fn block_by_id(State(state): State<V1State>, Path(id): Path<String>) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    if !valid_modifier_id(&id) {
        return invalid_hex();
    }
    let tip = state.read.status().best_full_block_height;
    match chain.full_block_by_id(&id) {
        Some(fb) => Json(block_from_scala(state.network, &fb, tip)).into_response(),
        None => block_not_found(),
    }
}

/// `GET /api/v1/chain/blocks/{header_id}/transactions` — the block's tx
/// section (single-page collection; a block never spans pages).
pub async fn block_transactions(State(state): State<V1State>, Path(id): Path<String>) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    if !valid_modifier_id(&id) {
        return invalid_hex();
    }
    match chain.block_transactions_by_id(&id) {
        Some(bt) => {
            let tip = state.read.status().best_full_block_height;
            let height = chain.header_by_id(&id).map(|h| h.height);
            let items = bt
                .transactions
                .iter()
                .map(|tx| block_tx_from_scala(state.network, tx, height, tip))
                .collect();
            Json(Collection::single_page(items)).into_response()
        }
        None => block_not_found(),
    }
}

/// `GET /api/v1/chain/blocks/at-height/{height}` — header ids at a height
/// (canonical chain only; single-page collection).
pub async fn blocks_at_height(
    State(state): State<V1State>,
    Path(height): Path<String>,
) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let height = match parse_height(&height) {
        Ok(h) => h,
        Err(e) => return *e,
    };
    let ids = chain.header_ids_at_height(height);
    Json(Collection::single_page(ids)).into_response()
}

/// `POST /api/v1/chain/blocks/by-ids` — bulk full-block fetch; request order
/// preserved, misses silently dropped, array capped at 200.
pub async fn blocks_by_ids(
    State(state): State<V1State>,
    V1Json(ids): V1Json<Vec<String>>,
) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
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
    let tip = state.read.status().best_full_block_height;
    let items = chain
        .full_blocks_by_header_ids(&ids)
        .iter()
        .map(|fb| block_from_scala(state.network, fb, tip))
        .collect();
    Json(Collection::single_page(items)).into_response()
}

// ----- chain/headers ------------------------------------------------------

/// `GET /api/v1/chain/headers` — cursor-paginated header objects (default
/// 100, cap 1000), newest-first by default.
pub async fn list_headers(
    State(state): State<V1State>,
    V1Query(q): V1Query<ListQuery>,
) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
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
    let tip = state.read.status().best_header_height;

    let mut items = Vec::new();
    for h in candidate_heights(cursor.map(|c| c.h), order, tip, limit + 1) {
        if let Some(id) = chain.header_ids_at_height(h).into_iter().next() {
            if let Some(hdr) = chain.header_by_id(&id) {
                items.push(header_from_scala(state.network, &hdr));
            }
        }
    }
    let (items, page) = Page::from_overfetch(items, limit, |h| HeightCursor { h: h.base.height });
    Json(Collection { items, page }).into_response()
}

/// `GET /api/v1/chain/headers/{header_id}` — single header object.
pub async fn header_by_id(State(state): State<V1State>, Path(id): Path<String>) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    if !valid_modifier_id(&id) {
        return invalid_hex();
    }
    match chain.header_by_id(&id) {
        Some(h) => Json(header_from_scala(state.network, &h)).into_response(),
        None => header_not_found(),
    }
}

/// `GET /api/v1/chain/headers/at-height/{height}` — full header objects at a
/// height (single-page collection).
pub async fn headers_at_height(
    State(state): State<V1State>,
    Path(height): Path<String>,
) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let height = match parse_height(&height) {
        Ok(h) => h,
        Err(e) => return *e,
    };
    let items = chain
        .header_ids_at_height(height)
        .into_iter()
        .filter_map(|id| chain.header_by_id(&id))
        .map(|h| header_from_scala(state.network, &h))
        .collect();
    Json(Collection::single_page(items)).into_response()
}

// ----- chain/modifiers + proofs ------------------------------------------

/// `GET /api/v1/chain/modifiers/{modifier_id}` — generic-by-id lookup across
/// headers + the three non-header block sections, tagged with an explicit
/// `kind` discriminant.
pub async fn modifier_by_id(State(state): State<V1State>, Path(id): Path<String>) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    if !valid_modifier_id(&id) {
        return invalid_hex();
    }
    let tip = state.read.status().best_full_block_height;
    match chain.modifier_by_id(&id) {
        Some(section) => Json(modifier_from_scala(state.network, &section, tip)).into_response(),
        // No `modifier_not_found` in the canonical enum; a missing block-graph
        // object answers `block_not_found`.
        None => block_not_found(),
    }
}

/// `GET /api/v1/chain/proofs/{header_id}` — the block's AD-proofs section.
/// Distinguishes "block unknown" (`block_not_found`) from "block known, proof
/// section absent / pruned" (`ad_proofs_unavailable`).
pub async fn block_ad_proofs(State(state): State<V1State>, Path(id): Path<String>) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    if !valid_modifier_id(&id) {
        return invalid_hex();
    }
    match chain.full_block_by_id(&id) {
        Some(fb) => match fb.ad_proofs {
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
        None => block_not_found(),
    }
}

/// `GET /api/v1/chain/proofs/{header_id}/transactions/{tx_id}` — Merkle
/// membership proof; side byte `0/1` rendered as `"left"/"right"`.
pub async fn proof_for_tx(
    State(state): State<V1State>,
    Path((header_id, tx_id)): Path<(String, String)>,
) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
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
    match chain.proof_for_tx(&header_id, &tx_id) {
        Some(mp) => {
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
            Json(V1MerkleProof { tx_id, levels }).into_response()
        }
        // Header unknown OR tx not in that block — a real 404.
        None => v1_error(
            Reason::TxNotInBlock,
            "no membership proof: unknown block or tx not in it",
            "verify the header id and that the tx is included in that block",
        ),
    }
}
