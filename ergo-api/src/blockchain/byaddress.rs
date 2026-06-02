//! `/blockchain/{transaction,box}/byAddress` (POST + GET twin) — routes
//! #6, #7 (transactions) and #9, #10 (boxes).
//!
//! All four routes pair a base58 address with a paged query and emit the
//! `{items, total}` envelope. Validation order mirrors the Scala
//! directive chain: paging → address parse → indexer read.

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_indexer_types::SortDir;

use super::{
    address_to_tree_hash, build_indexed_box_response, build_indexed_tx_response, internal_error,
    invalid_address, resolve_page, BlockchainState, ItemsTotalResponse, PagedQuery,
};

/// `POST /blockchain/transaction/byAddress`. Body is a bare JSON-string
/// address; query-string carries `offset` / `limit`.
pub async fn txs_by_address_post_handler(
    State(state): State<BlockchainState>,
    Query(q): Query<PagedQuery>,
    Json(address): Json<String>,
) -> Response {
    render_txs_by_address(&state, &address, q)
}

/// `GET /blockchain/transaction/byAddress/{address}`. GET twin of #6.
pub async fn txs_by_address_get_handler(
    State(state): State<BlockchainState>,
    Path(address): Path<String>,
    Query(q): Query<PagedQuery>,
) -> Response {
    render_txs_by_address(&state, &address, q)
}

/// `POST /blockchain/box/byAddress`. Body + query mirror the tx variant.
pub async fn boxes_by_address_post_handler(
    State(state): State<BlockchainState>,
    Query(q): Query<PagedQuery>,
    Json(address): Json<String>,
) -> Response {
    render_boxes_by_address(&state, &address, q)
}

/// `GET /blockchain/box/byAddress/{address}`. GET twin of #9.
pub async fn boxes_by_address_get_handler(
    State(state): State<BlockchainState>,
    Path(address): Path<String>,
    Query(q): Query<PagedQuery>,
) -> Response {
    render_boxes_by_address(&state, &address, q)
}

fn render_txs_by_address(state: &BlockchainState, address: &str, q: PagedQuery) -> Response {
    let page = match resolve_page(q, "transactions") {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let tree_hash = match address_to_tree_hash(address, state.network) {
        Ok(h) => h,
        Err(e) => return invalid_address(&e),
    };
    let txs = state
        .indexer
        .address_txs_paged(&tree_hash, page, SortDir::Desc);
    let total = state.indexer.address_total_txs(&tree_hash) as i64;
    let items = match txs
        .iter()
        .map(|tx| build_indexed_tx_response(state, tx))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(detail) => return internal_error(&detail),
    };
    Json(ItemsTotalResponse { items, total }).into_response()
}

fn render_boxes_by_address(state: &BlockchainState, address: &str, q: PagedQuery) -> Response {
    let page = match resolve_page(q, "boxes") {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let tree_hash = match address_to_tree_hash(address, state.network) {
        Ok(h) => h,
        Err(e) => return invalid_address(&e),
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
    // Scala parity: `BlockchainApiRoute.scala::getBoxesByAddress`
    // fetches the page in DESC order then calls `.reverse` on the
    // resulting Seq before responding, so the returned page is the
    // newest-N boxes displayed oldest-first within the page. The
    // page CONTENTS match a DESC fetch (we're not switching to ASC
    // pagination — that would move the page window to the oldest
    // boxes globally); only the per-page item order is reversed.
    // `/transaction/byAddress` does NOT do this reverse in Scala
    // and is already byte-equal, so it stays untouched.
    let items: Vec<_> = items.into_iter().rev().collect();
    Json(ItemsTotalResponse { items, total }).into_response()
}
