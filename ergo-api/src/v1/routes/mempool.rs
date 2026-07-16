//! `mempool/*` reads.
//!
//! Summary (+ derived utilization, active weight-function, and the depth
//! `history`), the cursor-paginated pool listing, the four `by-*` filtered
//! views, single pooled-tx detail with resolved `io_box`, and the fee
//! histogram. `mempool/{submit,check}` are NOT here: per Overlap O1 they are
//! documented aliases of the canonical `transactions/{submit,check}` handlers,
//! dual-mounted at the mempool path in [`super::v1_router`] — one handler, two
//! mounts, no duplicated logic.
//!
//! Rich rows come from [`crate::traits::NodeReadState::mempool_transactions`]
//! (the pre-projected snapshot list). The `by-*` views take the CONFIRMED
//! filtering hooks on [`crate::compat::NodeChainQuery`]
//! (`pool_txs_by_ergo_tree` / `_box_id` / `_token_id`) to learn *which* pooled
//! txs match, then re-hydrate each match from the rich list so every collection
//! shares the ONE `mempool_tx` shape and the keyset `(priority_weight, tx_id)`
//! cursor.

use std::collections::HashSet;
use utoipa::ToSchema;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use ergo_indexer_types::{BoxId, TxId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::address::{decode_address_to_tree_bytes, encode_address, NetworkPrefix};
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::transaction::{read_transaction, transaction_id};

use super::dto::{
    mempool_tx_from_api, Collection, V1Asset, V1FeeHistogram, V1FeeHistogramBin, V1IoBox,
    V1MempoolDepthPoint, V1MempoolSummary, V1MempoolTx, V1MempoolTxDetail, V1MempoolUtilization,
};
use super::extract::V1Query;
use super::{parse_id32, V1State};
use crate::blockchain::build_indexed_box_response;
use crate::compat::NodeChainQuery;
use crate::types::ApiMempoolTransaction;
use crate::v1::cursor::{clamp_limit, decode_opt_cursor, encode_cursor, Page};
use crate::v1::error::{v1_error, Reason, V1Error};

// ----- caps (§2.2) --------------------------------------------------------

/// `mempool/transactions` default page + hard cap.
const LIST_DEFAULT_LIMIT: u32 = 50;
const LIST_MAX_LIMIT: u32 = 200;
/// `by-*` views are tighter (server-side filtering work per §2.2).
const BY_DEFAULT_LIMIT: u32 = 50;
const BY_MAX_LIMIT: u32 = 100;
/// `fee-histogram` bins.
const HIST_DEFAULT_BINS: u32 = 12;
const HIST_MAX_BINS: u32 = 64;
/// Depth `history` samples returnable through `mempool/summary`.
const HISTORY_MAX: u32 = crate::v1::mempool_depth::DEPTH_RING_CAP as u32;

// ----- shared: ordering + keyset cursor -----------------------------------

/// Sort key for the pool collections (`?order=`), all descending — the mining
/// order for `weight`, newest-first for `first_seen`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Order {
    Weight,
    FeePerByte,
    FirstSeen,
}

fn parse_order(raw: Option<&str>) -> Result<Order, Box<Response>> {
    match raw {
        None | Some("weight") => Ok(Order::Weight),
        Some("fee_per_byte") => Ok(Order::FeePerByte),
        Some("first_seen") => Ok(Order::FirstSeen),
        Some(_) => Err(Box::new(v1_error(
            Reason::InvalidParams,
            "order must be `weight`, `fee_per_byte`, or `first_seen`",
            "omit `order` for the default priority-weight (mining) order",
        ))),
    }
}

/// The u64 sort value for a row under the active order.
fn order_key(t: &ApiMempoolTransaction, order: Order) -> u64 {
    match order {
        Order::Weight => t.priority_weight,
        Order::FeePerByte => t.fee_per_byte_nano_erg,
        Order::FirstSeen => t.first_seen_unix_ms,
    }
}

/// Keyset cursor payload: `(order, scope, key, tx_id)` of the last row served,
/// where `key` is the active order's sort value, `order` pins which `?order=`
/// the cursor was issued under, and `scope` pins which collection/filter
/// minted it. Opaque to clients (§1.5); the field names mirror the design's
/// `{w, t}` mempool-keyset example (`o`/`s` added so a cursor replayed against
/// a different order or a different view fails closed instead of mid-stream
/// seeking it).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct MempoolCursor {
    o: u8,
    s: String,
    w: u64,
    t: String,
}

/// Stable wire tag for an [`Order`], embedded in the cursor so a replay against
/// a different `?order=` is rejected (`invalid_cursor`) instead of mis-seeking.
fn order_tag(order: Order) -> u8 {
    match order {
        Order::Weight => 0,
        Order::FeePerByte => 1,
        Order::FirstSeen => 2,
    }
}

/// Short collection-scope tag (route family + filter key, hashed) baked into
/// the cursor so a cursor minted by one view cannot be replayed against
/// another (`invalid_cursor`), including the same `by-*` route with a
/// different filter value.
fn scope_tag(kind: &str, key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(kind.as_bytes());
    h.update([0u8]);
    h.update(key.as_bytes());
    hex::encode(&h.finalize()[..8])
}

/// Order rows into the stable total order (`key` DESC, then `tx_id` ASC), then
/// keyset-paginate them from `cursor` with an overfetch-by-one page, and render
/// the `mempool_tx` collection. `rows` is the full candidate set (already
/// filtered for the `by-*` views); the pool is bounded, so the in-memory sort
/// is cheap and the resulting cursor is genuinely stable under a moving pool.
fn render_mempool_page(
    mut rows: Vec<ApiMempoolTransaction>,
    order: Order,
    limit: u32,
    cursor: Option<&str>,
    scope: String,
) -> Response {
    let after = match decode_opt_cursor::<MempoolCursor>(cursor) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if let Some(cur) = after.as_ref() {
        if cur.o != order_tag(order) {
            return v1_error(
                Reason::InvalidCursor,
                "pagination cursor was issued for a different order",
                "restart from the first page (drop `cursor`) when changing `order`",
            );
        }
        if cur.s != scope {
            return v1_error(
                Reason::InvalidCursor,
                "pagination cursor was issued for a different mempool view",
                "restart from the first page (drop `cursor`) when changing route or filter",
            );
        }
    }

    rows.sort_by(|a, b| {
        order_key(b, order)
            .cmp(&order_key(a, order))
            .then_with(|| a.tx_id.cmp(&b.tx_id))
    });

    if let Some(cur) = after.as_ref() {
        rows.retain(|t| {
            let k = order_key(t, order);
            k < cur.w || (k == cur.w && t.tx_id > cur.t)
        });
    }

    let has_more = rows.len() as u64 > u64::from(limit);
    rows.truncate(limit as usize);
    let next_cursor = has_more.then(|| rows.last()).flatten().map(|last| {
        encode_cursor(&MempoolCursor {
            o: order_tag(order),
            s: scope.clone(),
            w: order_key(last, order),
            t: last.tx_id.clone(),
        })
    });
    let has_more = next_cursor.is_some();

    let items: Vec<V1MempoolTx> = rows.iter().map(mempool_tx_from_api).collect();
    Json(Collection {
        items,
        page: Page {
            limit,
            next_cursor,
            has_more,
        },
    })
    .into_response()
}

/// Filter the rich pool list down to the `matched` tx ids (learned from a
/// `by-*` hook), preserving nothing but membership — ordering + pagination are
/// applied by [`render_mempool_page`]. A tx present in the hook result but
/// absent from the rich snapshot (a rare cross-read race) is simply dropped.
fn rehydrate(
    all: Vec<ApiMempoolTransaction>,
    matched: &HashSet<String>,
) -> Vec<ApiMempoolTransaction> {
    all.into_iter()
        .filter(|t| matched.contains(&t.tx_id))
        .collect()
}

// ----- error helpers ------------------------------------------------------

fn mempool_view_disabled() -> Response {
    v1_error(
        Reason::MempoolViewDisabled,
        "mempool filtering is not wired on this node",
        "these views require the chain-reader mempool bridge",
    )
}

fn invalid_tx_id() -> Response {
    v1_error(
        Reason::InvalidTxId,
        "tx_id is not a 64-character lowercase hex string",
        "supply an unprefixed lowercase hex transaction id",
    )
}

/// The chain-reader bridge (carries the `by-*` filter hooks), or the honest
/// `409 mempool_view_disabled`. The error is boxed to keep the `Ok` path small
/// (repo convention — a rendered [`Response`] is large).
fn chain(state: &V1State) -> Result<&std::sync::Arc<dyn NodeChainQuery>, Box<Response>> {
    state
        .chain
        .as_ref()
        .ok_or_else(|| Box::new(mempool_view_disabled()))
}

// ----- GET /mempool/summary -----------------------------------------------

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct SummaryQuery {
    /// Number of trailing O4 depth samples to include as `history`
    /// (oldest-first). Absent/`0` ⇒ the field is omitted.
    #[serde(default)]
    history: Option<u32>,
}

/// `GET /api/v1/mempool/summary` — pool depth + capacity + derived utilization
/// + active weight-function, plus the optional O4 depth history.
#[utoipa::path(
    get, path = "/api/v1/mempool/summary", tag = "mempool",
    params(("history" = Option<u32>, Query, description = "Trailing depth samples to include (oldest-first); omitted/0 = field omitted")),
    responses(
        (status = 200, description = "Pool summary + derived utilization", body = V1MempoolSummary),
    ),
)]
pub async fn summary(State(state): State<V1State>, V1Query(q): V1Query<SummaryQuery>) -> Response {
    let s = state.read.mempool_summary();
    let count_pct = ratio(u64::from(s.size), u64::from(s.capacity_count));
    let bytes_pct = ratio(s.total_bytes, s.capacity_bytes);

    let history = match q.history {
        None | Some(0) => None,
        Some(n) => {
            let n = n.min(HISTORY_MAX) as usize;
            Some(
                state
                    .mempool_depth
                    .recent(n)
                    .iter()
                    .map(V1MempoolDepthPoint::from_sample)
                    .collect(),
            )
        }
    };

    Json(V1MempoolSummary {
        size: s.size,
        total_bytes: s.total_bytes,
        capacity_count: s.capacity_count,
        capacity_bytes: s.capacity_bytes,
        utilization: V1MempoolUtilization {
            count_pct,
            bytes_pct,
        },
        revalidation_pending: s.revalidation_pending,
        weight_function: state.read.mempool_weight_function(),
        history,
    })
    .into_response()
}

/// `used / cap` as a fraction in `[0, 1]`, or `0.0` when `cap == 0`.
fn ratio(used: u64, cap: u64) -> f64 {
    if cap == 0 {
        0.0
    } else {
        used as f64 / cap as f64
    }
}

// ----- GET /mempool/transactions ------------------------------------------

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct ListQuery {
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    order: Option<String>,
}

/// `GET /api/v1/mempool/transactions` — cursor-paginated pool listing,
/// priority-weight descending by default (mining order).
#[utoipa::path(
    get, path = "/api/v1/mempool/transactions", tag = "mempool",
    params(
        ("order" = Option<String>, Query, description = "`weight` (default), `fee_per_byte`, or `first_seen`"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, cap 200)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
    ),
    responses(
        (status = 200, description = "Pooled transactions", body = Collection<V1MempoolTx>),
        (status = 400, description = "Invalid order/cursor", body = V1Error),
    ),
)]
pub async fn transactions(
    State(state): State<V1State>,
    V1Query(q): V1Query<ListQuery>,
) -> Response {
    let order = match parse_order(q.order.as_deref()) {
        Ok(o) => o,
        Err(e) => return *e,
    };
    let limit = clamp_limit(q.limit, LIST_DEFAULT_LIMIT, LIST_MAX_LIMIT);
    let rows = state.read.mempool_transactions().transactions;
    render_mempool_page(
        rows,
        order,
        limit,
        q.cursor.as_deref(),
        scope_tag("transactions", ""),
    )
}

// ----- GET /mempool/transactions/{tx_id} ----------------------------------

/// `GET /api/v1/mempool/transactions/{tx_id}` — one pooled tx: the `mempool_tx`
/// row plus resolved `io_box` inputs/outputs (best-effort, from the extra index
/// + the pool-output overlay). `404 tx_not_found` when not pooled.
#[utoipa::path(
    get, path = "/api/v1/mempool/transactions/{tx_id}", tag = "mempool",
    params(("tx_id" = String, Path, description = "64-char lowercase hex transaction id")),
    responses(
        (status = 200, description = "Pooled tx + resolved io_box inputs/outputs", body = V1MempoolTxDetail),
        (status = 400, description = "Malformed tx id", body = V1Error),
        (status = 404, description = "Not in this node's mempool", body = V1Error),
    ),
)]
pub async fn transaction_by_id(
    State(state): State<V1State>,
    Path(tx_id_hex): Path<String>,
) -> Response {
    let Some(raw) = parse_id32(&tx_id_hex) else {
        return invalid_tx_id();
    };
    let Some(row) = state.read.mempool_transaction(&tx_id_hex) else {
        return v1_error(
            Reason::TxNotFound,
            "no pooled transaction with that id",
            "the id is well-formed but not in this node's mempool",
        );
    };
    let tx = mempool_tx_from_api(&row);

    // io resolution rides the coherent single-snapshot pool read; when the
    // overlay is a no-op view the row still returns with empty io.
    let (inputs, data_inputs, outputs) = match state.mempool.pool_tx_detail(&TxId::from_bytes(raw))
    {
        Some((bytes, pool_outputs)) => match resolve_io(&state, &bytes, &pool_outputs) {
            Ok(io) => io,
            Err(detail) => {
                return v1_error(
                    Reason::InternalError,
                    "failed to resolve the pooled transaction io",
                    detail,
                )
            }
        },
        None => (Vec::new(), Vec::new(), Vec::new()),
    };

    Json(V1MempoolTxDetail {
        tx,
        inputs,
        data_inputs,
        outputs,
    })
    .into_response()
}

type ResolvedIo = (Vec<V1IoBox>, Vec<String>, Vec<V1IoBox>);

/// Resolve a pooled tx's inputs/outputs into `io_box`es from its canonical wire
/// bytes + the same-snapshot pool-output overlay. Outputs come straight from
/// the tx's own candidates; inputs resolve against the extra index first, then
/// the pool overlay, then fall back to an id-only unresolved box (`null`
/// address/value/assets — never fabricated).
fn resolve_io(
    state: &V1State,
    bytes: &[u8],
    pool_outputs: &std::collections::HashMap<BoxId, ErgoBox>,
) -> Result<ResolvedIo, String> {
    let mut r = VlqReader::new(bytes);
    let tx = read_transaction(&mut r).map_err(|e| format!("pool tx parse: {e}"))?;
    let net = state.network;
    let self_tx_id = transaction_id(&tx).map_err(|e| format!("tx_id: {e}"))?;

    let outputs = tx
        .output_candidates
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let eb = ErgoBox {
                candidate: <ErgoBoxCandidate as Clone>::clone(c),
                transaction_id: self_tx_id,
                index: i as u16,
            };
            io_box_from_ergo_box(net, &eb)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let inputs = tx
        .inputs
        .iter()
        .map(|input| {
            if let Some(idx) = state.indexer.as_ref() {
                if let Some(b) = idx.box_by_id(&input.box_id) {
                    let resp = build_indexed_box_response(net, &b)?;
                    return Ok(V1IoBox {
                        box_id: Some(resp.box_id),
                        address: Some(resp.address),
                        value: Some(resp.value.to_string()),
                        assets: Some(
                            resp.assets
                                .into_iter()
                                .map(|a| V1Asset {
                                    token_id: a.token_id,
                                    amount: a.amount.to_string(),
                                })
                                .collect(),
                        ),
                    });
                }
            }
            if let Some(eb) = pool_outputs.get(&input.box_id) {
                return io_box_from_ergo_box(net, eb);
            }
            Ok(V1IoBox {
                box_id: Some(hex::encode(input.box_id.as_bytes())),
                address: None,
                value: None,
                assets: None,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let data_inputs = tx
        .data_inputs
        .iter()
        .map(|d| hex::encode(d.box_id.as_bytes()))
        .collect();

    Ok((inputs, data_inputs, outputs))
}

fn io_box_from_ergo_box(net: NetworkPrefix, b: &ErgoBox) -> Result<V1IoBox, String> {
    let c = &b.candidate;
    let box_id = b.box_id().map_err(|e| format!("box_id: {e}"))?;
    Ok(V1IoBox {
        box_id: Some(hex::encode(box_id.as_bytes())),
        address: Some(encode_address(net, c.ergo_tree(), c.ergo_tree_bytes())),
        value: Some(c.value.to_string()),
        assets: Some(
            c.tokens
                .iter()
                .map(|t| V1Asset {
                    token_id: hex::encode(t.token_id.as_bytes()),
                    amount: t.amount.to_string(),
                })
                .collect(),
        ),
    })
}

// ----- GET /mempool/by-* --------------------------------------------------

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct ByQuery {
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    cursor: Option<String>,
}

/// Shared tail for the `by-*` views: filter the rich list to `matched`, then
/// render the keyset page in priority-weight order. `scope` is the minting
/// view's [`scope_tag`] (route family + filter value).
fn render_by(state: &V1State, matched: HashSet<String>, q: &ByQuery, scope: String) -> Response {
    let limit = clamp_limit(q.limit, BY_DEFAULT_LIMIT, BY_MAX_LIMIT);
    let all = state.read.mempool_transactions().transactions;
    let rows = rehydrate(all, &matched);
    render_mempool_page(rows, Order::Weight, limit, q.cursor.as_deref(), scope)
}

fn matched_ids(txs: Vec<ergo_rest_json::types::ScalaTransaction>) -> HashSet<String> {
    txs.into_iter().map(|t| t.id).collect()
}

/// `GET /api/v1/mempool/by-address/{address}` — pooled txs paying a P2PK/P2S
/// address (output side). The address decodes to its ergo_tree; P2S addresses
/// map through the same ergo_tree path.
#[utoipa::path(
    get, path = "/api/v1/mempool/by-address/{address}", tag = "mempool",
    params(
        ("address" = String, Path, description = "Base58 address"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, cap 100)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
    ),
    responses(
        (status = 200, description = "Pooled txs paying this address", body = Collection<V1MempoolTx>),
        (status = 400, description = "Invalid address/cursor", body = V1Error),
        (status = 409, description = "Mempool filtering not wired on this node", body = V1Error),
    ),
)]
pub async fn by_address(
    State(state): State<V1State>,
    Path(address): Path<String>,
    V1Query(q): V1Query<ByQuery>,
) -> Response {
    let chain = match chain(&state) {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let tree_bytes = match decode_address_to_tree_bytes(&address, state.network) {
        Ok(b) => b,
        Err(e) => {
            return v1_error(
                Reason::InvalidAddress,
                "address is not valid base58 for this network",
                e.to_string(),
            )
        }
    };
    let matched = matched_ids(chain.pool_txs_by_ergo_tree(&tree_bytes));
    render_by(&state, matched, &q, scope_tag("by-address", &address))
}

/// `GET /api/v1/mempool/by-ergo-tree/{ergo_tree}` — pooled txs paying the given
/// ergo_tree (output side). The tree is unprefixed wire hex.
#[utoipa::path(
    get, path = "/api/v1/mempool/by-ergo-tree/{ergo_tree}", tag = "mempool",
    params(
        ("ergo_tree" = String, Path, description = "Unprefixed hex ErgoTree"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, cap 100)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
    ),
    responses(
        (status = 200, description = "Pooled txs paying this ErgoTree", body = Collection<V1MempoolTx>),
        (status = 400, description = "Invalid ergo_tree/cursor", body = V1Error),
        (status = 409, description = "Mempool filtering not wired on this node", body = V1Error),
    ),
)]
pub async fn by_ergo_tree(
    State(state): State<V1State>,
    Path(ergo_tree): Path<String>,
    V1Query(q): V1Query<ByQuery>,
) -> Response {
    let chain = match chain(&state) {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let tree_bytes = match hex::decode(ergo_tree.trim()) {
        Ok(b) => b,
        Err(e) => {
            return v1_error(
                Reason::InvalidErgoTree,
                "ergo_tree is not valid hex",
                format!("hex decode: {e}"),
            )
        }
    };
    let matched = matched_ids(chain.pool_txs_by_ergo_tree(&tree_bytes));
    render_by(
        &state,
        matched,
        &q,
        scope_tag("by-ergo-tree", ergo_tree.trim()),
    )
}

/// `GET /api/v1/mempool/by-box-id/{box_id}` — pooled tx(s) that SPEND the given
/// box (input side): the pending-spend / double-spend question (0..n rows).
#[utoipa::path(
    get, path = "/api/v1/mempool/by-box-id/{box_id}", tag = "mempool",
    params(
        ("box_id" = String, Path, description = "64-char lowercase hex box id"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, cap 100)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
    ),
    responses(
        (status = 200, description = "Pooled txs spending this box (0..n — double-spend candidates)", body = Collection<V1MempoolTx>),
        (status = 400, description = "Invalid box_id/cursor", body = V1Error),
        (status = 409, description = "Mempool filtering not wired on this node", body = V1Error),
    ),
)]
pub async fn by_box_id(
    State(state): State<V1State>,
    Path(box_id): Path<String>,
    V1Query(q): V1Query<ByQuery>,
) -> Response {
    let chain = match chain(&state) {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let Some(raw) = parse_id32(&box_id) else {
        return v1_error(
            Reason::InvalidBoxId,
            "box_id is not a 64-character lowercase hex string",
            "supply an unprefixed lowercase hex box id",
        );
    };
    let matched = matched_ids(chain.pool_txs_by_box_id(&raw));
    render_by(&state, matched, &q, scope_tag("by-box-id", &box_id))
}

/// `GET /api/v1/mempool/by-token-id/{token_id}` — pooled txs that reference the
/// given token id (output side).
#[utoipa::path(
    get, path = "/api/v1/mempool/by-token-id/{token_id}", tag = "mempool",
    params(
        ("token_id" = String, Path, description = "64-char lowercase hex token id"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, cap 100)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
    ),
    responses(
        (status = 200, description = "Pooled txs referencing this token", body = Collection<V1MempoolTx>),
        (status = 400, description = "Invalid token_id/cursor", body = V1Error),
        (status = 409, description = "Mempool filtering not wired on this node", body = V1Error),
    ),
)]
pub async fn by_token_id(
    State(state): State<V1State>,
    Path(token_id): Path<String>,
    V1Query(q): V1Query<ByQuery>,
) -> Response {
    let chain = match chain(&state) {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let Some(raw) = parse_id32(&token_id) else {
        return v1_error(
            Reason::InvalidTokenId,
            "token_id is not a 64-character lowercase hex string",
            "supply an unprefixed lowercase hex token id",
        );
    };
    let matched = matched_ids(chain.pool_txs_by_token_id(&raw));
    render_by(&state, matched, &q, scope_tag("by-token-id", &token_id))
}

// ----- GET /mempool/fee-histogram -----------------------------------------

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct HistogramQuery {
    #[serde(default)]
    bins: Option<u32>,
    /// Wait-time horizon the bins span. `0` (default) = the whole pool.
    #[serde(default)]
    max_wait_ms: Option<u64>,
}

/// `GET /api/v1/mempool/fee-histogram` — the pool's wait-time histogram
/// (`{index, n_txns, total_fee}` per bin). The `fee_per_byte_min/max` band is
/// honestly `null`: the frozen hook is wait-time-keyed and carries no per-bin
/// fee-per-byte bounds (design correction — see the group report).
#[utoipa::path(
    get, path = "/api/v1/mempool/fee-histogram", tag = "mempool",
    params(
        ("bins" = Option<u32>, Query, description = "Number of bins (default 12, cap 64)"),
        ("max_wait_ms" = Option<u64>, Query, description = "Wait-time horizon the bins span; 0 (default) = whole pool"),
    ),
    responses(
        (status = 200, description = "Wait-time fee histogram", body = V1FeeHistogram),
        (status = 409, description = "Mempool filtering not wired on this node", body = V1Error),
    ),
)]
pub async fn fee_histogram(
    State(state): State<V1State>,
    V1Query(q): V1Query<HistogramQuery>,
) -> Response {
    let chain = match chain(&state) {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let bins = clamp_limit(q.bins, HIST_DEFAULT_BINS, HIST_MAX_BINS);
    let max_wait_ms = q.max_wait_ms.unwrap_or(0);
    let raw = chain.pool_fee_histogram(bins, max_wait_ms);
    let bins_out = raw
        .into_iter()
        .enumerate()
        .map(|(i, b)| V1FeeHistogramBin {
            index: i as u32,
            n_txns: b.n_txns,
            total_fee: b.total_fee.to_string(),
            fee_per_byte_min: None,
            fee_per_byte_max: None,
        })
        .collect();
    Json(V1FeeHistogram {
        weight_function: state.read.mempool_weight_function(),
        max_wait_ms,
        bins: bins_out,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn tx(id: &str, weight: u64, fpb: u64, first_seen: u64) -> ApiMempoolTransaction {
        ApiMempoolTransaction {
            tx_id: id.to_string(),
            fee_nano_erg: 1000,
            fee_per_byte_nano_erg: fpb,
            size_bytes: 100,
            validation_cost_units: 10,
            priority_weight: weight,
            source: crate::types::ApiTxSource::Api,
            input_count: 1,
            output_count: 1,
            parents_in_pool: 0,
            first_seen_unix_ms: first_seen,
            first_seen_age_ms: 0,
            last_checked_age_ms: 0,
        }
    }

    fn ids(resp_rows: &[ApiMempoolTransaction]) -> Vec<String> {
        resp_rows.iter().map(|t| t.tx_id.clone()).collect()
    }

    // ----- happy path -----

    #[test]
    fn parse_order_maps_variants_and_rejects_unknown() {
        assert_eq!(parse_order(None).unwrap(), Order::Weight);
        assert_eq!(parse_order(Some("weight")).unwrap(), Order::Weight);
        assert_eq!(
            parse_order(Some("fee_per_byte")).unwrap(),
            Order::FeePerByte
        );
        assert_eq!(parse_order(Some("first_seen")).unwrap(), Order::FirstSeen);
        assert!(parse_order(Some("bogus")).is_err());
    }

    #[test]
    fn ratio_guards_zero_capacity() {
        assert_eq!(ratio(5, 0), 0.0);
        assert_eq!(ratio(1, 4), 0.25);
    }

    #[test]
    fn rehydrate_keeps_only_matched_ids() {
        let all = vec![tx("aa", 3, 3, 3), tx("bb", 2, 2, 2), tx("cc", 1, 1, 1)];
        let matched: HashSet<String> = ["aa".to_string(), "cc".to_string()].into_iter().collect();
        let kept = rehydrate(all, &matched);
        assert_eq!(ids(&kept), vec!["aa".to_string(), "cc".to_string()]);
    }

    // ----- ordering / keyset -----

    #[test]
    fn order_key_selects_the_active_field() {
        let t = tx("aa", 100, 50, 9);
        assert_eq!(order_key(&t, Order::Weight), 100);
        assert_eq!(order_key(&t, Order::FeePerByte), 50);
        assert_eq!(order_key(&t, Order::FirstSeen), 9);
    }
}
