//! `/blockchain/box/unspent/byAddress` (POST + GET twin) — routes #11, #12.
//!
//! Both routes pair a base58 address with a paged + sortDirection query
//! and a pair of mempool-overlay flags, then emit a bare
//! `[IndexedErgoBox]` array (NOT `{items, total}`) per the openapi
//! schema. Validation order mirrors the Scala directive chain: paging →
//! sortDirection → address parse → indexer read + mempool overlay merge.

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_indexer_types::types::IndexedErgoBox;
use ergo_indexer_types::{SortDir, TreeHash};
use ergo_ser::ergo_tree::tree_hash_from_bytes;
use serde::Deserialize;

use crate::traits::MempoolView;

use super::{
    address_to_tree_hash, build_indexed_box_response, internal_error, invalid_address,
    parse_sort_direction, resolve_page, BlockchainState, PagedQuery,
};

/// Query payload for routes #11/#12: paged + sortDirection + the two
/// pre-P5-stubbed mempool flags. Field names use serde rename to match
/// Scala's camelCase param spelling.
#[derive(Debug, Default, Deserialize)]
pub struct UnspentByAddressQuery {
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default, rename = "sortDirection")]
    pub sort_direction: Option<String>,
    #[serde(default, rename = "includeUnconfirmed")]
    pub include_unconfirmed: Option<bool>,
    #[serde(default, rename = "excludeMempoolSpent")]
    pub exclude_mempool_spent: Option<bool>,
}

/// `POST /blockchain/box/unspent/byAddress`. Body is a bare JSON-string
/// address; query carries paging + sortDirection + the two pre-P5
/// mempool flags.
pub async fn boxes_unspent_by_address_post_handler(
    State(state): State<BlockchainState>,
    Query(q): Query<UnspentByAddressQuery>,
    Json(address): Json<String>,
) -> Response {
    render_unspent_by_address(&state, &address, q)
}

/// `GET /blockchain/box/unspent/byAddress/{address}`. GET twin of #11.
pub async fn boxes_unspent_by_address_get_handler(
    State(state): State<BlockchainState>,
    Path(address): Path<String>,
    Query(q): Query<UnspentByAddressQuery>,
) -> Response {
    render_unspent_by_address(&state, &address, q)
}

/// Shared render path so the POST and GET twins emit byte-identical
/// responses for the same effective request. Validation order mirrors
/// the Scala directive chain: paging → sortDirection → address parse,
/// then the read + mempool overlay.
fn render_unspent_by_address(
    state: &BlockchainState,
    address: &str,
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
    let tree_hash = match address_to_tree_hash(address, state.network) {
        Ok(h) => h,
        Err(e) => return invalid_address(&e),
    };
    let mut confirmed = state.indexer.address_unspent_paged(&tree_hash, page, dir);
    if exclude_mempool_spent {
        // `Segment.scala:265` filters confirmed unspent by
        // `spentBoxesIdsInMempool`. The same filter set is reused for
        // the unconfirmed extension below — flag is route-wide, not
        // per-slice.
        confirmed.retain(|b| match b.box_data.box_id() {
            Ok(id) => !state.mempool.is_spent_by_pool(&id),
            // box_id failure means the indexer record can't be
            // canonicalized; the row would also fail downstream
            // `build_indexed_box_response`. Keep it so the existing
            // 500 envelope fires rather than silently dropping.
            Err(_) => true,
        });
    }
    let unconfirmed = if include_unconfirmed {
        pool_unspent_for_tree(state.mempool.as_ref(), &tree_hash, exclude_mempool_spent)
    } else {
        Vec::new()
    };
    // `Segment.scala:269-272`:
    //   DESC -> unconfirmedBoxes ++ confirmedBoxes  (unconfirmed first)
    //   ASC  -> confirmedBoxes ++ unconfirmedBoxes  (confirmed first)
    // Confirmed slicing already happened at the indexer above; the
    // unconfirmed extension is *not* re-paged, so the response can
    // exceed `limit` by `|pool_outputs|` — `[inherited]` Scala quirk.
    let merged: Vec<IndexedErgoBox> = match dir {
        SortDir::Desc => unconfirmed.into_iter().chain(confirmed).collect(),
        SortDir::Asc => confirmed.into_iter().chain(unconfirmed).collect(),
    };
    // Wire shape is a bare JSON array (NOT `{items, total}`) — Scala emits
    // `[IndexedErgoBox]` for unspent/* routes per the openapi schema.
    match merged
        .iter()
        .map(|b| build_indexed_box_response(state.network, b))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(items) => Json(items).into_response(),
        Err(detail) => internal_error(&detail),
    }
}

/// Build the unconfirmed pool-output extension for `unspent/byAddress`.
///
/// Each pool output whose canonical `tree_hash` matches the queried
/// address is emitted as `IndexedErgoBox(0, None, None, None, _, 0)` —
/// the `inclusionHeight = 0` sentinel is the unique discriminator from
/// confirmed boxes (heights start at 1). When `exclude_spent=true` we
/// also drop pool outputs already consumed by another pool tx (chained
/// pool spend) so the unconfirmed slice respects the same mempool-spent
/// filter as the confirmed slice (`Segment.scala:268`).
///
/// Iteration order is HashMap-natural and not deterministic across
/// snapshot rebuilds; this matches Scala's `mempool.getAll` order being
/// `pool.orderedTransactions.values` (insertion order, also unstable
/// across re-orgs / replacements). Tests assert membership, not order.
pub(super) fn pool_unspent_for_tree(
    mempool: &dyn MempoolView,
    tree_hash: &TreeHash,
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
        let computed = match tree_hash_from_bytes(ergo_box.candidate.ergo_tree_bytes()) {
            Ok(h) => TreeHash::from_bytes(h),
            // Same justification as `unconfirmed_balance_for_tree`: a
            // canonicalization failure here means the snapshot
            // publisher / admission canonicalizer drifted; skip the
            // box rather than poisoning the whole response.
            Err(err) => {
                tracing::warn!(error = ?err, "unspent/byAddress: skipping pool output with unparseable ergo_tree (snapshot/admission canonicalization drift?)");
                continue;
            }
        };
        if computed != *tree_hash {
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
