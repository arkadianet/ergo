//! `/blockchain/transaction/range` (#8) and `/blockchain/box/range` (#9).
//!
//! Scala mounts no method directive on either route — both GET and POST
//! land on the same handler. Body (if any on POST) is ignored; only the
//! paged query matters. Wire shape is a bare `[ModifierId]` array of
//! tx-ids / box-ids, global-index range view (not the full
//! `IndexedErgoTransaction` / `IndexedErgoBox` objects).
//!
//! Both ranges are `[lo, hi)` upper-exclusive, matching Scala's
//! `getTxRange(offset, limit)` and `getBoxRange` slicing semantics.
//! Box ids are derived from `box_data.box_id()` rather than a stored
//! field (the indexer keys boxes by id, but doesn't keep a separate
//! id field on `IndexedErgoBox`). A computation failure there surfaces
//! as 500, consistent with the `box/byId` failure-mode shape.

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::{internal_error, resolve_page, BlockchainState, PagedQuery};

/// Common renderer for both GET and POST forms of #8. Resolves the page,
/// queries the indexer, and projects to hex tx-ids.
fn render_transaction_range(state: &BlockchainState, q: PagedQuery) -> Response {
    let page = match resolve_page(q, "transactions") {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let lo = page.offset as u64;
    let hi = lo.saturating_add(page.limit as u64);
    let txs = state.indexer.txs_by_global_range(lo, hi);
    let ids: Vec<String> = txs.iter().map(|tx| hex::encode(tx.id.as_bytes())).collect();
    Json(ids).into_response()
}

pub async fn transaction_range_get_handler(
    State(state): State<BlockchainState>,
    Query(q): Query<PagedQuery>,
) -> Response {
    render_transaction_range(&state, q)
}

pub async fn transaction_range_post_handler(
    State(state): State<BlockchainState>,
    Query(q): Query<PagedQuery>,
) -> Response {
    render_transaction_range(&state, q)
}

fn render_box_range(state: &BlockchainState, q: PagedQuery) -> Response {
    let page = match resolve_page(q, "boxes") {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let lo = page.offset as u64;
    let hi = lo.saturating_add(page.limit as u64);
    let boxes = state.indexer.boxes_by_global_range(lo, hi);
    let ids: Result<Vec<String>, String> = boxes
        .iter()
        .map(|b| {
            b.box_data
                .box_id()
                .map(|id| hex::encode(id.as_bytes()))
                .map_err(|e| format!("box_id derivation failed: {e}"))
        })
        .collect();
    match ids {
        Ok(items) => Json(items).into_response(),
        Err(detail) => internal_error(&detail),
    }
}

pub async fn box_range_get_handler(
    State(state): State<BlockchainState>,
    Query(q): Query<PagedQuery>,
) -> Response {
    render_box_range(&state, q)
}

pub async fn box_range_post_handler(
    State(state): State<BlockchainState>,
    Query(q): Query<PagedQuery>,
) -> Response {
    render_box_range(&state, q)
}
