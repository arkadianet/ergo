//! `/blockchain/box/byErgoTree` (#24) and `/blockchain/box/unspent/byErgoTree` (#25).
//!
//! Both routes accept a hex-encoded ErgoTree as a JSON-string body. The
//! hex is decoded, the parsed tree is re-serialized to canonical bytes,
//! hashed (blake2b256), and the resulting tree_hash is dispatched into
//! the same address-keyed reader methods used by /box/byAddress and
//! /box/unspent/byAddress (extra-index parity doc lines 1553-1554).
//!
//! Wire shape:
//!   #24 byErgoTree          → {items, total} envelope (mirrors #9/#10)
//!   #25 unspent/byErgoTree  → bare [IndexedErgoBox] array (mirrors #11/#12)

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_indexer_types::types::IndexedErgoBox;
use ergo_indexer_types::{SortDir, TreeHash};
use ergo_ser::ergo_tree::{tree_hash_from_bytes, TreeHashError};

use super::{
    build_indexed_box_response, internal_error, parse_sort_direction, pool_unspent_for_tree,
    resolve_page, BlockchainState, ErrorEnvelope, ItemsTotalResponse, PagedQuery,
    UnspentByAddressQuery,
};

/// `POST /blockchain/box/byErgoTree`. Body is a JSON-string holding the
/// hex-encoded ergotree. Dispatches into `address_boxes_paged` after
/// hashing the canonical tree bytes.
pub async fn boxes_by_ergo_tree_post_handler(
    State(state): State<BlockchainState>,
    Query(q): Query<PagedQuery>,
    Json(tree_hex): Json<String>,
) -> Response {
    let page = match resolve_page(q, "boxes") {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let tree_hash = match decode_tree_hash(&tree_hex) {
        Ok(h) => h,
        Err(resp) => return *resp,
    };
    let boxes = state
        .indexer
        .address_boxes_paged(&tree_hash, page, SortDir::Desc);
    let total = state.indexer.address_total_boxes(&tree_hash) as i64;
    let items = match boxes
        .iter()
        .map(|b| build_indexed_box_response(state.network, b))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(detail) => return internal_error(&detail),
    };
    // Scala parity: `BlockchainApiRoute::getBoxesByErgoTree` fetches
    // the page in DESC order then `.reverse`s the resulting Seq
    // before responding, mirroring `getBoxesByAddress`. Same
    // semantics: page CONTENTS are the newest N for this tree, but
    // displayed oldest-first within the page.
    let items: Vec<_> = items.into_iter().rev().collect();
    Json(ItemsTotalResponse { items, total }).into_response()
}

/// `POST /blockchain/box/unspent/byErgoTree`. Same dispatch as #24 but
/// reads `address_unspent_paged`, supports `sortDirection` + the mempool
/// overlay flags, and emits a bare array per the openapi schema.
pub async fn boxes_unspent_by_ergo_tree_post_handler(
    State(state): State<BlockchainState>,
    Query(q): Query<UnspentByAddressQuery>,
    Json(tree_hex): Json<String>,
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
    let tree_hash = match decode_tree_hash(&tree_hex) {
        Ok(h) => h,
        Err(resp) => return *resp,
    };
    // The byErgoTree route dispatches into the same address-keyed reader
    // and pool-output filter (`pool_unspent_for_tree`) that
    // `render_unspent_by_address` uses — Scala wires this hash-then-
    // dispatch path explicitly (`BlockchainApiRoute.scala` byErgoTree
    // case), so the P5 overlay semantics are byte-identical to slice 4.
    let mut confirmed = state.indexer.address_unspent_paged(&tree_hash, page, dir);
    if exclude_mempool_spent {
        confirmed.retain(|b| match b.box_data.box_id() {
            Ok(id) => !state.mempool.is_spent_by_pool(&id),
            Err(_) => true,
        });
    }
    let unconfirmed = if include_unconfirmed {
        pool_unspent_for_tree(state.mempool.as_ref(), &tree_hash, exclude_mempool_spent)
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

/// Hex-decode the ErgoTree body and dispatch through the canonical
/// blake2b256 step that the indexer uses to key its address records.
/// Surfacing hex-decode and parse failures separately would let callers
/// distinguish them — Scala emits a generic 400 for either, so we
/// flatten both into the `invalid-ergo-tree` envelope.
pub(super) fn decode_tree_hash(tree_hex: &str) -> Result<TreeHash, Box<Response>> {
    let bytes = hex::decode(tree_hex.trim())
        .map_err(|e| Box::new(invalid_ergo_tree(&format!("hex decode: {e}"))))?;
    match tree_hash_from_bytes(&bytes) {
        Ok(h) => Ok(TreeHash::from_bytes(h)),
        Err(e @ TreeHashError::Parse(_) | e @ TreeHashError::Write(_)) => {
            Err(Box::new(invalid_ergo_tree(&e.to_string())))
        }
    }
}

pub(super) fn invalid_ergo_tree(detail: &str) -> Response {
    let body = ErrorEnvelope {
        error: 400,
        reason: "invalid-ergo-tree",
        detail: detail.to_string(),
    };
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
    )
        .into_response()
}
