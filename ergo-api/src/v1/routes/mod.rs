//! `/api/v1/*` route groups mounted on the G2 shared primitives.
//!
//! This is the FIRST route-group module — the `chain/*` + `transactions/*`
//! reads that close the highest-priority self-sufficiency gap (`v1-api-design.md`
//! §3.5–§3.6). Everything here consumes the G2 primitives (`error` envelope +
//! [`Reason`], `cursor` page builder, `governor`, `auth` tiers) rather than
//! inventing parallel mechanisms; later groups copy this shape.
//!
//! Mounting: [`v1_router`] returns a state-erased `Router` the server merges
//! under `/api/v1`. Every route in this group is **T0 (public)** — bounded by
//! the [`governor`](crate::v1::governor), not by auth — so it carries the
//! governor layer (route-class `HeavyRead`) but no tier gate.

pub mod dto;

mod chain;
mod transactions;

use std::sync::Arc;

use axum::{
    response::Response,
    routing::{get, post},
    Router,
};
use ergo_indexer_types::IndexerQuery;
use ergo_ser::address::NetworkPrefix;
use serde::{Deserialize, Serialize};

use crate::compat::NodeChainQuery;
use crate::traits::{MempoolView, NodeReadState, NodeSubmit};
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
    /// Submit bridge — `transactions/{submit,check}`.
    pub submit: Option<Arc<dyn NodeSubmit>>,
    /// Mempool overlay — the unconfirmed side of `transactions/{tx_id}`.
    pub mempool: Arc<dyn MempoolView>,
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

/// A modifier / header / tx id on the wire is an unprefixed lowercase 64-char
/// hex string. Reject anything else *before* hitting the store so a malformed
/// id is a `400 invalid_*` (§1.4 rule 2), not a `404`.
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

/// Build the `chain/*` + `transactions/*` reads router, governor-bounded and
/// state-erased for merging under `/api/v1` in the server.
///
/// All routes are **T0**: the shared [`Governor`] (one per node, so later
/// groups share the same per-IP budget) fronts them at route-class
/// `HeavyRead` — full-block payloads and paginated walks are the heavier read
/// surface (§2.2). No tier gate: T0 is bounded by the governor, not by auth.
pub fn v1_router(state: V1State, governor: Arc<Governor>) -> Router {
    let router: Router<V1State> = Router::new()
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
        .route("/api/v1/transactions/check", post(transactions::check));

    router
        .route_layer(axum::middleware::from_fn_with_state(
            governor.state(RouteClass::HeavyRead),
            governor_mw,
        ))
        .with_state(state)
}
