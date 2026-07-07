//! `/api/v1/*` route groups mounted on the G2 shared primitives.
//!
//! This module mounts every native read group — `chain/*`, `transactions/*`,
//! `boxes/*`, `tokens/*`, `addresses/*`, and `mempool/*` (`v1-api-design.md`
//! §3.5–§3.8). Everything here consumes the G2 primitives (`error` envelope +
//! [`Reason`], `cursor` page builder, `governor`, `auth` tiers) rather than
//! inventing parallel mechanisms; later groups copy this shape.
//!
//! Mounting: [`v1_router`] returns a state-erased `Router` the server merges
//! under `/api/v1`. Every route in this group is **T0 (public)** — bounded by
//! the [`governor`](crate::v1::governor), not by auth — so it carries the
//! governor layer (route-class `HeavyRead`) but no tier gate.

pub mod dto;

mod addresses;
mod boxes;
mod chain;
mod decode;
pub(crate) mod extract;
mod mempool;
mod tokens;
pub(crate) mod transactions;
mod tx_intel;

use std::sync::Arc;

use axum::{
    response::Response,
    routing::{get, post},
    Router,
};
use ergo_indexer_types::{IndexerQuery, IndexerStatus};
use ergo_ser::address::NetworkPrefix;
use serde::{Deserialize, Serialize};

use crate::compat::NodeChainQuery;
use crate::traits::{MempoolView, NodeReadState, NodeSubmit, NodeTxBuilder};
use crate::v1::cursor::{decode_opt_cursor, encode_cursor, Page as CursorPage};
use crate::v1::error::{v1_error, Reason};
use crate::v1::governor::{governor_mw, Governor, RouteClass};

/// Shared state for the `chain/*` + `transactions/*` route group.
///
/// Every dependency is `Option` where the subsystem may be off, so a handler
/// can answer the honest `*_unavailable` / `*_disabled` reason (§1.4) instead
/// of a bare 404 — v1 mounts unconditionally and gates *inside* the handler.
#[derive(Clone)]
pub struct V1State {
    /// Snapshot reader (tip heights for cursor walks + confirmation math).
    pub read: Arc<dyn NodeReadState>,
    /// Live-store chain reader — the hook for every `chain/*` route.
    pub chain: Option<Arc<dyn NodeChainQuery>>,
    /// Extra-index reader — the confirmed side of `transactions/{tx_id}`.
    pub indexer: Option<Arc<dyn IndexerQuery>>,
    /// Submit bridge — `transactions/{submit,check}` + the non-mutating
    /// `transactions/simulate` (G8; `NodeSubmit::simulate`).
    pub submit: Option<Arc<dyn NodeSubmit>>,
    /// Keyless transaction builder — backs `POST /transactions/build`
    /// (`v1-api-design.md` §4.2 O7). `None` until the extracted keyless core is
    /// wired; the endpoint then answers the honest `route_unavailable` rather
    /// than fabricating a coin selection.
    pub tx_builder: Option<Arc<dyn NodeTxBuilder>>,
    /// Mempool overlay — the unconfirmed side of `transactions/{tx_id}`.
    pub mempool: Arc<dyn MempoolView>,
    /// Shared O4 mempool-depth sample ring — the source for
    /// `mempool/summary?history=` and (future) `stats/mempool-depth`.
    pub mempool_depth: Arc<crate::v1::mempool_depth::MempoolDepthRing>,
    /// Real-time subscriptions (`WS /api/v1/ws`) — the shared `RealtimeBus` +
    /// connection limiter. `None` ⇒ the WS route answers `realtime_disabled`
    /// (never a bare 404), per the subsystem-off rule (§4.1).
    pub realtime: Option<crate::v1::realtime::RealtimeHandle>,
    /// Address-encoding network prefix.
    pub network: NetworkPrefix,
}

impl V1State {
    /// The live chain reader, or the honest `503 chain_reader_unavailable`
    /// (§1.4) when the node was wired without one. The error is boxed to keep
    /// the `Ok` path small (repo convention — a rendered [`Response`] is large).
    fn chain(&self) -> Result<&Arc<dyn NodeChainQuery>, Box<Response>> {
        self.chain.as_ref().ok_or_else(|| {
            Box::new(v1_error(
                Reason::ChainReaderUnavailable,
                "the chain reader is not wired on this node",
                "chain reads require the live-store NodeChainQuery bridge",
            ))
        })
    }

    /// The extra-index reader, gated to `CaughtUp` per the §3.7 mounting rule:
    /// `None` → `409 indexer_disabled`, `Syncing` → `503 indexer_syncing`,
    /// `Halted` → `503 indexer_halted`. v1 mounts unconditionally and answers
    /// the honest reason instead of the compat bare-404 when the index is off.
    fn indexer(&self) -> Result<&Arc<dyn IndexerQuery>, Box<Response>> {
        let idx = self.indexer.as_ref().ok_or_else(|| {
            Box::new(v1_error(
                Reason::IndexerDisabled,
                "box/token/address queries require the extra index",
                "start the node with [indexer] enabled = true",
            ))
        })?;
        match idx.status() {
            IndexerStatus::CaughtUp => Ok(idx),
            IndexerStatus::Syncing => Err(Box::new(v1_error(
                Reason::IndexerSyncing,
                "the extra index is still syncing",
                "retry once GET /api/v1/indexer/status reports caught up",
            ))),
            IndexerStatus::Halted(reason) => Err(Box::new(v1_error(
                Reason::IndexerHalted,
                "the extra index is halted",
                format!("halt reason: {reason:?}"),
            ))),
        }
    }

    /// A `blockchain::BlockchainState` view over the same deps — lets the
    /// `addresses/{address}/transactions` handler reuse the shared
    /// `build_indexed_tx_response` builder (so confirmation math never drifts).
    fn blockchain_state(&self, idx: &Arc<dyn IndexerQuery>) -> crate::blockchain::BlockchainState {
        crate::blockchain::BlockchainState {
            read: self.read.clone(),
            indexer: idx.clone(),
            network: self.network,
            chain: self.chain.clone(),
            mempool: self.mempool.clone(),
            chain_params: None,
        }
    }
}

/// Sort direction for cursor-paginated chain lists (`?order=desc|asc`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Order {
    Desc,
    Asc,
}

/// Height-keyed opaque cursor payload (`{"h": <height>}`) for the chain
/// list endpoints. Opaque to clients; the field is an implementation detail
/// (§1.5).
#[derive(Debug, Serialize, Deserialize)]
struct HeightCursor {
    h: u32,
}

/// Common `?limit=&cursor=&order=` query for the chain list endpoints.
#[derive(Debug, Deserialize)]
struct ListQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    order: Option<String>,
}

/// A modifier / header / tx id on the wire is an unprefixed 64-char LOWERCASE
/// hex string — v1 is canonical-strict per the design doc (§ WS
/// `invalid_selector`: "must be 64 lowercase hex chars"; §1.4 lowercase
/// convention), stricter than the compat surfaces by design. Reject anything
/// else (wrong length, non-hex, or uppercase) *before* hitting the store so a
/// malformed id is a `400 invalid_*` (§1.4 rule 2), not a `404`.
fn valid_modifier_id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn invalid_hex() -> Response {
    v1_error(
        Reason::InvalidHex,
        "id is not a 64-character lowercase hex string",
        "supply an unprefixed lowercase hex modifier id",
    )
}

fn parse_order(raw: Option<&str>) -> Result<Order, Box<Response>> {
    match raw {
        None | Some("desc") => Ok(Order::Desc),
        Some("asc") => Ok(Order::Asc),
        Some(_) => Err(Box::new(v1_error(
            Reason::InvalidSortDirection,
            "order must be `desc` or `asc`",
            "omit `order` for the default newest-first (desc)",
        ))),
    }
}

fn parse_height(raw: &str) -> Result<u32, Box<Response>> {
    raw.parse::<u32>().map_err(|_| {
        Box::new(v1_error(
            Reason::InvalidParams,
            "height must be a non-negative integer",
            "supply the block height as a decimal number",
        ))
    })
}

/// Descending or ascending candidate heights for a cursor page: at most `n`
/// heights (the caller passes `limit + 1` for overfetch-by-one), clamped to
/// `[1, tip]`.
fn candidate_heights(cursor_h: Option<u32>, order: Order, tip: u32, n: u32) -> Vec<u32> {
    let n = n as usize;
    let mut v = Vec::with_capacity(n);
    match order {
        Order::Desc => {
            let start = cursor_h
                .map(|c| c.saturating_sub(1))
                .unwrap_or(tip)
                .min(tip);
            let mut h = start;
            while v.len() < n && h >= 1 {
                v.push(h);
                h -= 1;
            }
        }
        Order::Asc => {
            let mut h = cursor_h.map(|c| c.saturating_add(1)).unwrap_or(1).max(1);
            while v.len() < n && h <= tip {
                v.push(h);
                h += 1;
            }
        }
    }
    v
}

// ----- shared box/token/address helpers -----------------------------------

/// Offset-alias opaque cursor for the indexed collections (§0.2 / §1.5). A thin
/// shim over the offset-based `IndexerQuery`; opaque to clients so a Phase-2
/// stable-seek key can replace it without a wire break.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct OffsetCursor {
    pub off: u32,
}

/// Global-index cursor for `boxes/range` — genuinely stable/monotonic
/// (append-only global index), not an offset alias.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct GiCursor {
    pub gi: u64,
}

/// Parse an unprefixed 64-char hex id to its 32 raw bytes. `None` (wrong
/// length or non-hex) lets a handler answer the typed `invalid_*` reason before
/// touching the store.
pub(super) fn parse_id32(s: &str) -> Option<[u8; 32]> {
    // Canonical ids are 64-char LOWERCASE hex. Reuse `valid_modifier_id` so the
    // shared box/token id parsing rejects uppercase/mixed-case consistently with
    // the tx routes (CodeRabbit #170) — `hex::decode` alone accepts uppercase
    // (identical bytes), leaving `/boxes/*` and `/tokens/*` misaligned.
    if !valid_modifier_id(s) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

/// `?sort=asc|desc` (default `desc`). A malformed value is
/// `400 invalid_sort_direction` (§1.4).
pub(super) fn parse_sort(raw: Option<&str>) -> Result<ergo_indexer_types::SortDir, Box<Response>> {
    use ergo_indexer_types::SortDir;
    match raw {
        None | Some("desc") => Ok(SortDir::Desc),
        Some("asc") => Ok(SortDir::Asc),
        Some(_) => Err(Box::new(v1_error(
            Reason::InvalidSortDirection,
            "sort must be `desc` or `asc`",
            "omit `sort` for the default newest-first (desc)",
        ))),
    }
}

/// Decode the opaque offset cursor to its start offset (`0` for the first
/// page); tamper answers `400 invalid_cursor`.
pub(super) fn offset_from_cursor(cursor: Option<&str>) -> Result<u32, Box<Response>> {
    Ok(decode_opt_cursor::<OffsetCursor>(cursor)?
        .map(|c| c.off)
        .unwrap_or(0))
}

/// Build the `page` object for an offset-aliased collection from an
/// overfetched-by-one item list: trim the sentinel, set `has_more`, and mint
/// the next offset cursor (`start + limit`).
pub(super) fn offset_page<T>(items: Vec<T>, start: u32, limit: u32) -> (Vec<T>, CursorPage) {
    offset_page_at(items, limit, start.saturating_add(limit))
}

/// Like [`offset_page`] but with an explicit next-page offset. Used where the
/// window consumed a *variable* number of reader rows (e.g. an
/// `exclude_mempool_spent` overfetch that loops until `limit + 1` survivors), so
/// the cursor must resume past the rows actually read, not the naive
/// `start + limit`.
pub(super) fn offset_page_at<T>(
    mut items: Vec<T>,
    limit: u32,
    next_off: u32,
) -> (Vec<T>, CursorPage) {
    let has_more = items.len() as u64 > u64::from(limit);
    if has_more {
        items.truncate(limit as usize);
    }
    let next_cursor = has_more.then(|| encode_cursor(&OffsetCursor { off: next_off }));
    (
        items,
        CursorPage {
            limit,
            next_cursor,
            has_more,
        },
    )
}

/// Build the native `/api/v1/*` product-API router: the `chain/*` +
/// `transactions/*` reads group, the `boxes/*` + `tokens/*` + `addresses/*`
/// reads group, AND the `mempool/*` group (summary, listing, `by-*` filters,
/// single-tx detail, fee histogram, and the O1 `submit/check` aliases), all
/// consuming the G2 shared primitives (error envelope, cursor page builder,
/// per-IP governor) and state-erased for merging under `/api/v1`.
///
/// Route classes (§2.2): the single by-id lookups (`boxes/{id}`, `tokens/{id}`)
/// sit at `CheapRead`; every paginated / scan / range surface (and the whole
/// chain+tx group) sits at `HeavyRead`. The shared [`Governor`] is one per node
/// so all classes draw on the same per-IP budget. No tier gate: T0 is bounded
/// by the governor, not by auth.
pub fn v1_router(state: V1State, governor: Arc<Governor>) -> Router {
    // Cheap point reads — a single by-id lookup.
    let cheap: Router<V1State> = Router::new()
        .route("/api/v1/boxes/:box_id", get(boxes::box_by_id))
        .route("/api/v1/tokens/:token_id", get(tokens::token_by_id))
        // ----- mempool/* light point reads -----
        .route("/api/v1/mempool/summary", get(mempool::summary))
        .route(
            "/api/v1/mempool/transactions/:tx_id",
            get(mempool::transaction_by_id),
        )
        .route("/api/v1/mempool/fee-histogram", get(mempool::fee_histogram))
        // ----- protocols/* registry discovery (static, indexer-free) -----
        .route("/api/v1/protocols", get(decode::list_protocols))
        .route(
            "/api/v1/protocols/:protocol_id",
            get(decode::protocol_by_id),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            governor.state(RouteClass::CheapRead),
            governor_mw,
        ));

    // Heavy reads — full-block payloads, paginated / scan / range surfaces.
    let heavy: Router<V1State> = Router::new()
        // ----- chain/blocks -----
        .route("/api/v1/chain/blocks", get(chain::list_blocks))
        .route("/api/v1/chain/blocks/by-ids", post(chain::blocks_by_ids))
        .route(
            "/api/v1/chain/blocks/at-height/:height",
            get(chain::blocks_at_height),
        )
        .route("/api/v1/chain/blocks/:header_id", get(chain::block_by_id))
        .route(
            "/api/v1/chain/blocks/:header_id/transactions",
            get(chain::block_transactions),
        )
        // ----- chain/headers -----
        .route("/api/v1/chain/headers", get(chain::list_headers))
        .route(
            "/api/v1/chain/headers/at-height/:height",
            get(chain::headers_at_height),
        )
        .route("/api/v1/chain/headers/:header_id", get(chain::header_by_id))
        // ----- chain/modifiers + proofs -----
        .route(
            "/api/v1/chain/modifiers/:modifier_id",
            get(chain::modifier_by_id),
        )
        .route(
            "/api/v1/chain/proofs/:header_id",
            get(chain::block_ad_proofs),
        )
        .route(
            "/api/v1/chain/proofs/:header_id/transactions/:tx_id",
            get(chain::proof_for_tx),
        )
        // ----- transactions reads + submit -----
        .route("/api/v1/transactions/:tx_id", get(transactions::tx_by_id))
        .route("/api/v1/transactions/submit", post(transactions::submit))
        .route("/api/v1/transactions/check", post(transactions::check))
        // ----- transactions/* intelligence reads (§3.6 Phase-2) -----
        .route(
            "/api/v1/transactions/fee-estimate",
            get(tx_intel::fee_estimate),
        )
        .route("/api/v1/transactions/:tx_id/status", get(tx_intel::status))
        // ----- mempool/* lists + O1 submit/check aliases -----
        .route("/api/v1/mempool/transactions", get(mempool::transactions))
        .route(
            "/api/v1/mempool/by-address/:address",
            get(mempool::by_address),
        )
        .route(
            "/api/v1/mempool/by-ergo-tree/:ergo_tree",
            get(mempool::by_ergo_tree),
        )
        .route("/api/v1/mempool/by-box-id/:box_id", get(mempool::by_box_id))
        .route(
            "/api/v1/mempool/by-token-id/:token_id",
            get(mempool::by_token_id),
        )
        // O1: aliases of the canonical transactions/{submit,check} — SAME
        // handler, second mount (no duplicated logic).
        .route("/api/v1/mempool/submit", post(transactions::submit))
        .route("/api/v1/mempool/check", post(transactions::check))
        // ----- boxes/* -----
        .route("/api/v1/boxes/range", get(boxes::box_range))
        // Off-chain semantic decode (stateless) + the singleton state one-shot.
        .route("/api/v1/boxes/decode", post(decode::decode_off_chain_box))
        .route(
            "/api/v1/protocols/:protocol_id/state",
            get(decode::protocol_state),
        )
        .route(
            "/api/v1/boxes/by-address/:address",
            get(boxes::boxes_by_address),
        )
        .route(
            "/api/v1/boxes/unspent/by-address/:address",
            get(boxes::boxes_unspent_by_address),
        )
        .route(
            "/api/v1/boxes/by-ergo-tree",
            post(boxes::boxes_by_ergo_tree),
        )
        .route(
            "/api/v1/boxes/unspent/by-ergo-tree",
            post(boxes::boxes_unspent_by_ergo_tree),
        )
        .route(
            "/api/v1/boxes/by-template/:template_hash",
            get(boxes::boxes_by_template),
        )
        .route(
            "/api/v1/boxes/unspent/by-template/:template_hash",
            get(boxes::boxes_unspent_by_template),
        )
        .route(
            "/api/v1/boxes/by-token/:token_id",
            get(boxes::boxes_by_token),
        )
        .route(
            "/api/v1/boxes/unspent/by-token/:token_id",
            get(boxes::boxes_unspent_by_token),
        )
        // ----- tokens/* -----
        .route("/api/v1/tokens", get(tokens::tokens_list))
        .route(
            "/api/v1/tokens/:token_id/holders",
            get(tokens::token_holders),
        )
        .route("/api/v1/tokens/:token_id/stats", get(tokens::token_stats))
        // ----- addresses/* (O9; boxes/unspent are dual mounts of boxes::*) -----
        .route(
            "/api/v1/addresses/:address/balance",
            get(addresses::balance),
        )
        .route(
            "/api/v1/addresses/:address/transactions",
            get(addresses::transactions),
        )
        .route(
            "/api/v1/addresses/:address/boxes",
            get(boxes::boxes_by_address),
        )
        .route(
            "/api/v1/addresses/:address/unspent",
            get(boxes::boxes_unspent_by_address),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            governor.state(RouteClass::HeavyRead),
            governor_mw,
        ));

    // Compute — attacker-influenced coin selection / validation (§2.2). The
    // heavier `tx_intent` build + the non-mutating simulate sit here so the
    // load-bearing bound is the cost governor's `Compute` weight, not auth.
    let compute: Router<V1State> = Router::new()
        .route("/api/v1/transactions/build", post(tx_intel::build))
        .route("/api/v1/transactions/simulate", post(tx_intel::simulate))
        .route_layer(axum::middleware::from_fn_with_state(
            governor.state(RouteClass::Compute),
            governor_mw,
        ));

    // Real-time subscriptions (§3.16 / §4.1). The WS upgrade is a long-lived
    // socket, not a per-request read, so it is NOT fronted by the token-bucket
    // governor route-class; its cost is bounded by the connection limiter
    // (per-IP / global caps, checked pre-upgrade) and the per-socket control-op
    // rate limit + bounded send queue inside the handler.
    let realtime: Router<V1State> =
        Router::new().route("/api/v1/ws", get(crate::v1::realtime::ws_handler));

    heavy
        .merge(cheap)
        .merge(compute)
        .merge(realtime)
        .with_state(state)
}
