//! `/blockchain/box/byTemplateHash` (#15) and `/blockchain/box/unspent/byTemplateHash` (#16).
//!
//! Both routes take a 64-char hex template hash as a path parameter.
//! The hash is the blake2b256 of an ErgoTree's `template` segment
//! evaluated under `VersionContext.withVersions(3, 3)`. We do NOT
//! re-derive it here — callers pass the already-hashed key, matching
//! Scala's `path(modifierId)` directive.
//!
//! Wire shape:
//!   #15 byTemplateHash          → {items, total} envelope (mirrors #9/#10)
//!   #16 unspent/byTemplateHash  → bare [IndexedErgoBox] array (mirrors #11/#12)
//!
//! Empty-fallback parity (`BlockchainApiRoute.scala:304-307, 323-325`):
//! unknown template hash returns 200 with the empty envelope, NOT 404 —
//! Scala falls back to `IndexedContractTemplate(hash)` and the downstream
//! slice yields zero entries.

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_indexer_types::types::IndexedErgoBox;
use ergo_indexer_types::{SortDir, TemplateHash};
use ergo_ser::ergo_tree::template_hash_from_bytes;

use crate::traits::MempoolView;

use super::{
    build_indexed_box_response, internal_error, not_found, parse_modifier_id, parse_sort_direction,
    resolve_page, BlockchainState, ItemsTotalResponse, PagedQuery, UnspentByAddressQuery,
};

/// `GET /blockchain/box/byTemplateHash/{templateHash}`. Paged, returns
/// `{items, total}`. Bad-hex path param surfaces as 404 to mirror Scala's
/// `path(modifierId)` rejection (Akka default rejection handler emits
/// `NotFound` on path-matcher failure).
pub async fn boxes_by_template_hash_handler(
    State(state): State<BlockchainState>,
    Path(hash_hex): Path<String>,
    Query(q): Query<PagedQuery>,
) -> Response {
    let template_hash = match parse_modifier_id(&hash_hex) {
        Some(raw) => TemplateHash::from_bytes(raw),
        None => return not_found("template hash not found"),
    };
    let page = match resolve_page(q, "boxes") {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let boxes = state.indexer.template_boxes_paged(&template_hash, page);
    let total = state.indexer.template_total_boxes(&template_hash) as i64;
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

/// `GET /blockchain/box/unspent/byTemplateHash/{templateHash}`. Paged,
/// supports `sortDirection` + the mempool overlay flags. Wire shape is
/// a bare `[IndexedErgoBox]` array per the openapi schema. Validation
/// order mirrors `unspent_byAddress`: path → paging → sortDirection →
/// read + overlay. The overlay is strictly orthogonal — flags don't
/// gate, they alter behavior.
pub async fn boxes_unspent_by_template_hash_handler(
    State(state): State<BlockchainState>,
    Path(hash_hex): Path<String>,
    Query(q): Query<UnspentByAddressQuery>,
) -> Response {
    let template_hash = match parse_modifier_id(&hash_hex) {
        Some(raw) => TemplateHash::from_bytes(raw),
        None => return not_found("template hash not found"),
    };
    render_unspent_by_template_hash(&state, &template_hash, q)
}

/// Shared overlay-aware renderer for `unspent/byTemplateHash`. Mirrors
/// `render_unspent_by_address` in shape and
/// merge order; the only difference is the keying function — pool
/// outputs are matched by `template_hash_from_bytes(tree_bytes)` instead
/// of `tree_hash_from_bytes(tree_bytes)`. Same `[inherited]` paging
/// quirk: confirmed slicing happens at the indexer before the
/// unconfirmed merge, so `includeUnconfirmed=true` responses can exceed
/// `limit` by `|pool_outputs|`.
fn render_unspent_by_template_hash(
    state: &BlockchainState,
    template_hash: &TemplateHash,
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
    let mut confirmed = state
        .indexer
        .template_unspent_paged(template_hash, page, dir);
    if exclude_mempool_spent {
        // Mirror `Segment.scala:265` — `spentBoxesIdsInMempool` filter is
        // route-wide, applied to confirmed and unconfirmed slices alike.
        confirmed.retain(|b| match b.box_data.box_id() {
            Ok(id) => !state.mempool.is_spent_by_pool(&id),
            Err(_) => true,
        });
    }
    let unconfirmed = if include_unconfirmed {
        pool_unspent_for_template(state.mempool.as_ref(), template_hash, exclude_mempool_spent)
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

/// Build the unconfirmed pool-output extension for
/// `unspent/byTemplateHash`. Pool outputs are matched by
/// `template_hash_from_bytes(tree_bytes)` and emitted with the same
/// `IndexedErgoBox(0, None, None, None, _, 0)` sentinel as
/// `pool_unspent_for_tree`.
///
/// Soft-fork-wrapped trees (`TemplateHashError::Unparseable`) are
/// skipped — Scala's `IndexedContractTemplate` only records template
/// hashes for parseable trees, so a wrapped pool output can never match
/// any queried template anyway.
fn pool_unspent_for_template(
    mempool: &dyn MempoolView,
    template_hash: &TemplateHash,
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
        let computed = match template_hash_from_bytes(ergo_box.candidate.ergo_tree_bytes()) {
            Ok(h) => TemplateHash::from_bytes(h),
            Err(err) => {
                tracing::warn!(error = ?err, "unspent/byTemplateHash: skipping pool output with unparseable template hash (snapshot/admission canonicalization drift?)");
                continue;
            }
        };
        if computed != *template_hash {
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
