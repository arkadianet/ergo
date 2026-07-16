//! `POST /api/v1/batch` — bounded read-only multiplexer over the v1 read
//! surface. One round trip, many v1 reads: each sub-request is dispatched,
//! in-process, to the SAME `routes::*` handlers every standalone v1 endpoint
//! uses — never HTTP-to-itself (that would be a self-inflicted DoS
//! amplifier). Batch answers `200` for any structurally valid, in-cap
//! request even when individual items fail (partial-failure semantics) —
//! only a malformed/empty/oversize request short-circuits before any item
//! runs.
//!
//! **Closed allow-list, not a proxy.** Batch allow-lists concrete
//! `(method, path template)` pairs — `chain/*`, `boxes/*`, `tokens/*`,
//! `addresses/*`, `mempool/*`, `transactions/*` (reads), `stats/*`,
//! `diagnostics`, `light/*`, and `protocols/*` — and dispatches through a
//! SECOND, restricted `Router<V1State>` wired to the exact same handler
//! functions (never a re-implementation). This is the same dual-mount idiom
//! already used in this crate for `mempool/{submit,check}` aliasing
//! `transactions::{submit,check}`, and `light/membership-proof` aliasing the
//! `chain/proofs` core — a second mount of an existing handler, not a second
//! implementation.
//!
//! A `(method, path)` not on [`allowed_routes`]'s table is REJECTED before
//! any dispatch — `forbidden_target`, never proxied, never a bare 404. The
//! submit-domain routes (`transactions/{submit,check}` — `check` also
//! mutates mempool bookkeeping, not a pure read), the keyless builder
//! (`transactions/build`), the compute-class `transactions/simulate`, and
//! the whole `script/*` playground are deliberately absent from the table:
//! batch is read-only by hard invariant, not by convention.
//!
//! **Cost.** Every allowed entry inherits the SAME [`RouteClass`] (cheap /
//! heavy) the standalone route's own governor layer already charges — batch
//! does not invent a second weight vocabulary, it reuses the one that
//! shipped. The whole batch call is charged ONCE, up front, for the SUM of
//! its dispatchable members' weights against the SAME per-IP [`Governor`]
//! bucket every other T0 surface draws from; a rejected (not-allow-listed)
//! item costs nothing, since it never reaches a handler.
//! The restricted dispatch router itself carries no per-route governor
//! layer — that would double-charge every dispatched item.
//!
//! **Mixed tiers (deferred, not forgotten).** Every entry on today's table is
//! T0 — no v1 T1 read group (wallet/mining/scan) has landed on this stacked
//! branch yet. A per-item-auth design (batch itself stays ungated, a T1/T2
//! `kind` is checked per item) has an obvious extension point here (an
//! `AllowedRoute::tier` field + the shared `crate::v1::auth` check before
//! dispatch) but is not built until a T1 v1 route actually exists to gate —
//! building it now would be untested, unreachable machinery.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use utoipa::ToSchema;

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{header::CONTENT_TYPE, HeaderValue, Method, Request, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tower::ServiceExt;

use super::{
    addresses, boxes, chain, decode, diagnostics, light, mempool, stats, tokens, transactions,
    tx_intel, V1State,
};
use crate::v1::client_ip;
use crate::v1::error::{v1_error, Reason, V1Error};
use crate::v1::governor::{Governor, RouteClass};

/// Hard cap on sub-requests per batch call.
/// ASSUMED policy constant — not yet an operator-config knob, same as every
/// other T0 bound at launch.
pub const MAX_BATCH_ITEMS: usize = 32;

/// Hard cap on the SUMMED [`RouteClass`] weight of one batch call's
/// dispatchable members, independent of the governor's own per-IP burst —
/// a structural request-shape bound, not a rate limit. A rejected (not
/// allow-listed) item contributes zero.
pub const MAX_BATCH_WEIGHT: f64 = 200.0;

/// Byte cap applied when buffering EITHER the inbound batch request body or a
/// single sub-response body before re-embedding it (defends batch's own
/// memory against a pathological body in either direction; every
/// allow-listed handler's real replies are far below this in practice).
const MAX_BUFFERED_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Shared "no resolvable peer" bucket key (mirrors [`super::super::governor`]).
const UNKNOWN_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

// ----- wire types -----------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct BatchRequest {
    requests: Vec<BatchItemRequest>,
}

#[derive(Debug, Deserialize, ToSchema)]
struct BatchItemRequest {
    #[serde(default)]
    id: Option<String>,
    method: String,
    path: String,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    body: Option<Value>,
}

#[derive(Debug, Serialize, ToSchema)]
struct BatchItemResult {
    id: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

impl BatchItemResult {
    fn ok(id: String, data: Value) -> Self {
        BatchItemResult {
            id,
            status: "ok",
            data: Some(data),
            error: None,
        }
    }

    /// Build an item-slot error from the canonical [`Reason`] triple — the
    /// exact `{reason, message, detail}` shape a standalone endpoint's
    /// [`v1_error`] would have rendered, just nested under `error` inside
    /// the item instead of at the top level.
    fn error(
        id: String,
        reason: Reason,
        message: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        let inner = V1Error::new(reason, message, detail).error;
        let err_json = serde_json::to_value(inner).expect("V1ErrorInner always serializes");
        BatchItemResult {
            id,
            status: "error",
            data: None,
            error: Some(err_json),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct BatchResponse {
    items: Vec<BatchItemResult>,
}

// ----- the closed allow-list -------------------------------------------------

/// One allow-listed `(method, path template)` pair and the [`RouteClass`] it
/// bills against — the classification half of the allow-list. `template`
/// segments prefixed `:` are wildcards (axum's own path-param syntax reused
/// verbatim so the table reads identically to [`super::v1_router`]'s route
/// list).
#[derive(Clone)]
struct AllowedRoute {
    method: Method,
    template: &'static str,
    class: RouteClass,
}

/// `template` segments matched against a concrete request `path`: a `:`-led
/// template segment matches any non-empty path segment, everything else must
/// match literally. Pure string logic, no route-table dependency — this is
/// what lets batch answer `forbidden_target` for an unlisted path WITHOUT
/// ever handing it to the dispatch router (a 404 from that router would mean
/// "matched something, arrived, resource missing", the wrong signal for "not
/// on the allow-list at all").
fn template_matches(template: &str, path: &str) -> bool {
    let mut t = template.split('/');
    let mut p = path.split('/');
    loop {
        match (t.next(), p.next()) {
            (Some(ts), Some(ps)) => {
                if ts.starts_with(':') {
                    // A wildcard binds a real segment — never the empty
                    // segment a trailing slash produces.
                    if ps.is_empty() {
                        return false;
                    }
                } else if ts != ps {
                    return false;
                }
            }
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// Literal-segment count — the specificity key for [`classify`]. Two
/// templates matching the same path have the same segment count, so the one
/// with more literals (fewer wildcards) is strictly more specific.
fn specificity(template: &str) -> usize {
    template.split('/').filter(|s| !s.starts_with(':')).count()
}

/// The [`RouteClass`] of the MOST-SPECIFIC allow-list entry matching
/// `(method, path)`, or `None` when nothing matches — the single point where
/// "may this batch item ever be dispatched" is decided. Most-specific (not
/// first-match) mirrors axum's own literal-beats-wildcard routing, so the
/// class charged is the class of the handler that actually runs (e.g.
/// `/boxes/range` must not be charged as `/boxes/:box_id`).
fn classify(table: &[AllowedRoute], method: &Method, path: &str) -> Option<RouteClass> {
    table
        .iter()
        .filter(|r| r.method == *method && template_matches(r.template, path))
        .max_by_key(|r| specificity(r.template))
        .map(|r| r.class)
}

/// Registers one allow-listed route on BOTH the restricted dispatch
/// [`Router`] and the classification table in a single call, so the two can
/// never drift apart (the risk a hand-duplicated second list would carry).
macro_rules! route {
    ($router:expr, $table:expr, GET, $path:expr, $class:expr, $handler:expr) => {{
        $table.push(AllowedRoute {
            method: Method::GET,
            template: $path,
            class: $class,
        });
        $router = $router.route($path, get($handler));
    }};
    ($router:expr, $table:expr, POST, $path:expr, $class:expr, $handler:expr) => {{
        $table.push(AllowedRoute {
            method: Method::POST,
            template: $path,
            class: $class,
        });
        $router = $router.route($path, post($handler));
    }};
}

/// Build the restricted dispatch router + its parallel classification table.
/// Every route here is a SECOND mount of a handler already wired in
/// [`super::v1_router`] — copied verbatim, minus the submit-domain / build /
/// simulate / WS / script / webhooks surfaces this module's docs enumerate.
fn allowed_routes() -> (Router<V1State>, Vec<AllowedRoute>) {
    use RouteClass::{CheapRead, HeavyRead};

    let mut table: Vec<AllowedRoute> = Vec::new();
    let mut router: Router<V1State> = Router::new();

    // ----- cheap point reads / discovery -----
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/:box_id",
        CheapRead,
        boxes::box_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/tokens/:token_id",
        CheapRead,
        tokens::token_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/summary",
        CheapRead,
        mempool::summary
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/transactions/:tx_id",
        CheapRead,
        mempool::transaction_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/fee-histogram",
        CheapRead,
        mempool::fee_histogram
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/protocols",
        CheapRead,
        decode::list_protocols
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/protocols/:protocol_id",
        CheapRead,
        decode::protocol_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/light/status",
        CheapRead,
        light::status
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/diagnostics",
        CheapRead,
        diagnostics::composite
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/diagnostics/chain-position",
        CheapRead,
        diagnostics::chain_position
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/diagnostics/fork-risk",
        CheapRead,
        diagnostics::fork_risk
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/diagnostics/tip-health",
        CheapRead,
        diagnostics::tip_health
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/diagnostics/peer-quality",
        CheapRead,
        diagnostics::peer_quality
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/diagnostics/candidate-build",
        CheapRead,
        diagnostics::candidate_build
    );

    // ----- chain/* -----
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/blocks",
        HeavyRead,
        chain::list_blocks
    );
    route!(
        router,
        table,
        POST,
        "/api/v1/chain/blocks/by-ids",
        HeavyRead,
        chain::blocks_by_ids
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/blocks/at-height/:height",
        HeavyRead,
        chain::blocks_at_height
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/blocks/:header_id",
        HeavyRead,
        chain::block_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/blocks/:header_id/transactions",
        HeavyRead,
        chain::block_transactions
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/headers",
        HeavyRead,
        chain::list_headers
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/headers/at-height/:height",
        HeavyRead,
        chain::headers_at_height
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/headers/:header_id",
        HeavyRead,
        chain::header_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/modifiers/:modifier_id",
        HeavyRead,
        chain::modifier_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/proofs/:header_id",
        HeavyRead,
        chain::block_ad_proofs
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/chain/proofs/:header_id/transactions/:tx_id",
        HeavyRead,
        chain::proof_for_tx
    );

    // ----- transactions/* reads (submit/check/build/simulate excluded) -----
    route!(
        router,
        table,
        GET,
        "/api/v1/transactions/:tx_id",
        HeavyRead,
        transactions::tx_by_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/transactions/fee-estimate",
        HeavyRead,
        tx_intel::fee_estimate
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/transactions/:tx_id/status",
        HeavyRead,
        tx_intel::status
    );

    // ----- mempool/* lists -----
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/transactions",
        HeavyRead,
        mempool::transactions
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/by-address/:address",
        HeavyRead,
        mempool::by_address
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/by-ergo-tree/:ergo_tree",
        HeavyRead,
        mempool::by_ergo_tree
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/by-box-id/:box_id",
        HeavyRead,
        mempool::by_box_id
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/mempool/by-token-id/:token_id",
        HeavyRead,
        mempool::by_token_id
    );

    // ----- boxes/* -----
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/range",
        HeavyRead,
        boxes::box_range
    );
    route!(
        router,
        table,
        POST,
        "/api/v1/boxes/decode",
        HeavyRead,
        decode::decode_off_chain_box
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/protocols/:protocol_id/state",
        HeavyRead,
        decode::protocol_state
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/by-address/:address",
        HeavyRead,
        boxes::boxes_by_address
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/unspent/by-address/:address",
        HeavyRead,
        boxes::boxes_unspent_by_address
    );
    route!(
        router,
        table,
        POST,
        "/api/v1/boxes/by-ergo-tree",
        HeavyRead,
        boxes::boxes_by_ergo_tree
    );
    route!(
        router,
        table,
        POST,
        "/api/v1/boxes/unspent/by-ergo-tree",
        HeavyRead,
        boxes::boxes_unspent_by_ergo_tree
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/by-template/:template_hash",
        HeavyRead,
        boxes::boxes_by_template
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/unspent/by-template/:template_hash",
        HeavyRead,
        boxes::boxes_unspent_by_template
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/by-token/:token_id",
        HeavyRead,
        boxes::boxes_by_token
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/boxes/unspent/by-token/:token_id",
        HeavyRead,
        boxes::boxes_unspent_by_token
    );

    // ----- tokens/* -----
    route!(
        router,
        table,
        GET,
        "/api/v1/tokens",
        HeavyRead,
        tokens::tokens_list
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/tokens/:token_id/holders",
        HeavyRead,
        tokens::token_holders
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/tokens/:token_id/stats",
        HeavyRead,
        tokens::token_stats
    );

    // ----- addresses/* -----
    route!(
        router,
        table,
        GET,
        "/api/v1/addresses/:address/balance",
        HeavyRead,
        addresses::balance
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/addresses/:address/transactions",
        HeavyRead,
        addresses::transactions
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/addresses/:address/boxes",
        HeavyRead,
        boxes::boxes_by_address
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/addresses/:address/unspent",
        HeavyRead,
        boxes::boxes_unspent_by_address
    );

    // ----- light/* -----
    route!(
        router,
        table,
        GET,
        "/api/v1/light/bootstrap-proof",
        HeavyRead,
        light::bootstrap_proof
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/light/headers-interlinks",
        HeavyRead,
        light::headers_interlinks
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/light/membership-proof",
        HeavyRead,
        light::membership_proof
    );

    // ----- stats/* -----
    route!(
        router,
        table,
        GET,
        "/api/v1/stats/supply",
        HeavyRead,
        stats::supply
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/stats/emission-schedule",
        HeavyRead,
        stats::emission_schedule
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/stats/difficulty",
        HeavyRead,
        stats::difficulty
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/stats/fees",
        HeavyRead,
        stats::fees
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/stats/mempool-depth",
        HeavyRead,
        stats::mempool_depth
    );
    route!(
        router,
        table,
        GET,
        "/api/v1/stats/holders",
        HeavyRead,
        stats::holders
    );

    (router, table)
}

// ----- handler ---------------------------------------------------------------

/// State for the mounted `/api/v1/batch` route: the restricted dispatch
/// router (already state-bound — see [`batch_router`]), the parallel
/// classification table, and the shared node-wide [`Governor`] batch draws
/// its one upfront charge from.
#[derive(Clone)]
pub(crate) struct BatchState {
    dispatch: Router,
    table: Arc<[AllowedRoute]>,
    governor: Arc<Governor>,
}

fn parse_method(raw: &str) -> Option<Method> {
    match raw.to_ascii_uppercase().as_str() {
        "GET" => Some(Method::GET),
        "POST" => Some(Method::POST),
        _ => None,
    }
}

/// Dispatch one already-classified item through the restricted router and
/// translate its response into a [`BatchItemResult`]. `data` is exactly the
/// standalone endpoint's own JSON body — no re-serialization, no parallel
/// vocabulary.
async fn dispatch_one(dispatch: &Router, id: String, item: BatchItemRequest) -> BatchItemResult {
    // Classification (the caller) already proved `item.method` parses.
    let method = parse_method(&item.method).expect("classified items have a valid method");

    let mut uri_string = item.path.clone();
    if let Some(q) = item.query.as_deref().filter(|q| !q.is_empty()) {
        uri_string.push('?');
        uri_string.push_str(q);
    }
    let uri: Uri = match uri_string.parse() {
        Ok(u) => u,
        Err(e) => {
            return BatchItemResult::error(
                id,
                Reason::BadRequest,
                "sub-request path/query is not a valid URI",
                e.to_string(),
            )
        }
    };

    let body_bytes = match &item.body {
        Some(v) => serde_json::to_vec(v).unwrap_or_default(),
        None => Vec::new(),
    };
    let mut builder = Request::builder().method(method).uri(uri);
    if !body_bytes.is_empty() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    let request = match builder.body(Body::from(body_bytes)) {
        Ok(r) => r,
        Err(e) => {
            return BatchItemResult::error(
                id,
                Reason::BadRequest,
                "failed to build the sub-request",
                e.to_string(),
            )
        }
    };

    // `Router<()>`'s `Service::Error` is `Infallible` — the router itself
    // never fails to produce SOME response, malformed sub-request or not.
    let response = match dispatch.clone().oneshot(request).await {
        Ok(r) => r,
        Err(never) => match never {},
    };
    let status = response.status();
    let bytes = match to_bytes(response.into_body(), MAX_BUFFERED_BODY_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            return BatchItemResult::error(
                id,
                Reason::InternalError,
                "failed to read the sub-response body",
                e.to_string(),
            )
        }
    };
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    if status.is_success() {
        BatchItemResult::ok(id, value)
    } else if let Some(err) = value.get("error").cloned() {
        // Already the v1 `{reason,message,detail}` triple every allow-listed
        // handler emits — re-embed verbatim under the item, don't reshape it.
        BatchItemResult {
            id,
            status: "error",
            data: None,
            error: Some(err),
        }
    } else {
        // Defensive only: every allow-listed handler renders through
        // `v1_error`, so this arm should be unreachable in practice.
        BatchItemResult::error(
            id,
            Reason::InternalError,
            "sub-request failed without a v1 error envelope",
            format!("status {status}"),
        )
    }
}

/// `POST /api/v1/batch` handler. Reads `api_key`-free (T0) — every entry on
/// today's allow-list is T0 (see module docs on mixed-tier deferral).
#[utoipa::path(
    post, path = "/api/v1/batch", tag = "batch",
    request_body = BatchRequest,
    responses(
        (status = 200, description = "Per-item results (partial-failure semantics — a structurally valid batch is always 200)", body = BatchResponse),
        (status = 400, description = "Malformed/empty batch, or a target not on the allow-list (forbidden_target)", body = V1Error),
        (status = 413, description = "Too many items, or summed weight/body size exceeds the batch cap", body = V1Error),
        (status = 429, description = "Rate limit exceeded for this client", body = V1Error),
    ),
)]
pub(crate) async fn batch_handler(State(state): State<BatchState>, req: Request<Body>) -> Response {
    let ip = client_ip(&req).unwrap_or(UNKNOWN_IP);
    let exempt = state.governor.exempt_loopback(&req);

    let (_parts, body) = req.into_parts();
    let bytes = match to_bytes(body, MAX_BUFFERED_BODY_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            return v1_error(
                Reason::BadRequest,
                "failed to read the request body",
                e.to_string(),
            )
        }
    };
    let batch_req: BatchRequest = match serde_json::from_slice(&bytes) {
        Ok(b) => b,
        Err(e) => {
            return v1_error(
                Reason::BadRequest,
                "request body is not a valid batch request",
                e.to_string(),
            )
        }
    };

    if batch_req.requests.is_empty() {
        return v1_error(
            Reason::EmptyBatch,
            "a batch must contain at least one request",
            "requests: []",
        );
    }
    if batch_req.requests.len() > MAX_BATCH_ITEMS {
        return v1_error(
            Reason::BatchTooLarge,
            "batch exceeds the per-request item cap",
            format!(
                "requests: {} (max {MAX_BATCH_ITEMS})",
                batch_req.requests.len()
            ),
        );
    }

    // Classify every item up front — never dispatch an unclassified path —
    // and sum the weight of only the dispatchable members (a rejected item
    // never reaches a handler, so it costs nothing).
    let classes: Vec<Option<RouteClass>> = batch_req
        .requests
        .iter()
        .map(|item| parse_method(&item.method).and_then(|m| classify(&state.table, &m, &item.path)))
        .collect();
    let total_weight: f64 = classes
        .iter()
        .filter_map(|c| c.map(|c| state.governor.class_weight(c)))
        .sum();
    if total_weight > MAX_BATCH_WEIGHT {
        return v1_error(
            Reason::BatchTooLarge,
            "batch exceeds the per-request cost cap",
            format!("cost: {total_weight} (max {MAX_BATCH_WEIGHT})"),
        );
    }

    if !exempt && total_weight > 0.0 {
        if let Err(retry_after_secs) = state.governor.try_charge(ip, total_weight) {
            let mut resp = v1_error(
                Reason::RateLimited,
                "per-IP rate/cost limit exceeded",
                format!("retry after ~{retry_after_secs}s"),
            );
            if let Ok(val) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                resp.headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, val);
            }
            return resp;
        }
    }

    let mut items = Vec::with_capacity(batch_req.requests.len());
    for (idx, (item, class)) in batch_req.requests.into_iter().zip(classes).enumerate() {
        let id = item.id.clone().unwrap_or_else(|| idx.to_string());
        let result = match class {
            Some(_) => dispatch_one(&state.dispatch, id, item).await,
            None => BatchItemResult::error(
                id,
                Reason::ForbiddenTarget,
                "method/path is not an allowed batch target",
                format!("{} {}", item.method, item.path),
            ),
        };
        items.push(result);
    }

    Json(BatchResponse { items }).into_response()
}

/// Mount `/api/v1/batch`. `governor` is the
/// SAME shared per-node [`Governor`] every other T0 group draws its budget
/// from — batch is one more class of spender on the one bucket, not a
/// second rate limiter.
pub fn batch_router(state: V1State, governor: Arc<Governor>) -> Router {
    let (inner, table) = allowed_routes();
    let dispatch: Router = inner.with_state(state);
    let batch_state = BatchState {
        dispatch,
        table: Arc::from(table),
        governor,
    };
    Router::new()
        .route("/api/v1/batch", post(batch_handler))
        .with_state(batch_state)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn route(method: Method, template: &'static str, class: RouteClass) -> AllowedRoute {
        AllowedRoute {
            method,
            template,
            class,
        }
    }

    // ----- happy path -----

    #[test]
    fn template_matches_literal_and_wildcard_segments() {
        assert!(template_matches(
            "/api/v1/boxes/:box_id",
            "/api/v1/boxes/abcd"
        ));
        assert!(template_matches(
            "/api/v1/chain/blocks/:header_id/transactions",
            "/api/v1/chain/blocks/deadbeef/transactions"
        ));
    }

    #[test]
    fn classify_finds_the_matching_entry() {
        let table = vec![
            route(Method::GET, "/api/v1/boxes/:box_id", RouteClass::CheapRead),
            route(
                Method::POST,
                "/api/v1/boxes/by-ergo-tree",
                RouteClass::HeavyRead,
            ),
        ];
        assert_eq!(
            classify(&table, &Method::GET, "/api/v1/boxes/6a2d"),
            Some(RouteClass::CheapRead)
        );
        assert_eq!(
            classify(&table, &Method::POST, "/api/v1/boxes/by-ergo-tree"),
            Some(RouteClass::HeavyRead)
        );
    }

    #[test]
    fn classify_prefers_the_most_specific_template() {
        // Table order must not matter: the wildcard entry precedes the
        // literal, yet the literal (more specific) wins — mirroring axum's
        // literal-beats-wildcard dispatch, so `/boxes/range` is charged as
        // itself, never as `/boxes/:box_id`.
        let table = vec![
            route(Method::GET, "/api/v1/boxes/:box_id", RouteClass::CheapRead),
            route(Method::GET, "/api/v1/boxes/range", RouteClass::HeavyRead),
        ];
        assert_eq!(
            classify(&table, &Method::GET, "/api/v1/boxes/range"),
            Some(RouteClass::HeavyRead)
        );
        assert_eq!(
            classify(&table, &Method::GET, "/api/v1/boxes/6a2d"),
            Some(RouteClass::CheapRead)
        );
    }

    // ----- error paths -----

    #[test]
    fn template_matches_rejects_empty_wildcard_segment() {
        // A trailing slash must not satisfy a wildcard.
        assert!(!template_matches("/api/v1/boxes/:box_id", "/api/v1/boxes/"));
    }

    #[test]
    fn template_matches_rejects_wrong_segment_count() {
        assert!(!template_matches("/api/v1/boxes/:box_id", "/api/v1/boxes"));
        assert!(!template_matches(
            "/api/v1/boxes/:box_id",
            "/api/v1/boxes/abcd/extra"
        ));
    }

    #[test]
    fn template_matches_rejects_literal_mismatch() {
        assert!(!template_matches(
            "/api/v1/boxes/by-address/:address",
            "/api/v1/boxes/by-token/9f"
        ));
    }

    #[test]
    fn classify_returns_none_for_wrong_method() {
        let table = vec![route(
            Method::GET,
            "/api/v1/boxes/:box_id",
            RouteClass::CheapRead,
        )];
        assert_eq!(classify(&table, &Method::POST, "/api/v1/boxes/6a2d"), None);
    }

    #[test]
    fn classify_returns_none_for_unlisted_path() {
        let table = vec![route(
            Method::GET,
            "/api/v1/boxes/:box_id",
            RouteClass::CheapRead,
        )];
        assert_eq!(
            classify(&table, &Method::POST, "/api/v1/transactions/submit"),
            None
        );
    }

    #[test]
    fn parse_method_accepts_get_and_post_only() {
        assert_eq!(parse_method("get"), Some(Method::GET));
        assert_eq!(parse_method("POST"), Some(Method::POST));
        assert_eq!(parse_method("DELETE"), None);
        assert_eq!(parse_method("PATCH"), None);
    }

    #[test]
    fn allowed_routes_table_excludes_mutating_submit_domain() {
        let (_router, table) = allowed_routes();
        let has = |m: Method, p: &str| table.iter().any(|r| r.method == m && r.template == p);
        assert!(!has(Method::POST, "/api/v1/transactions/submit"));
        assert!(!has(Method::POST, "/api/v1/transactions/check"));
        assert!(!has(Method::POST, "/api/v1/transactions/build"));
        assert!(!has(Method::POST, "/api/v1/transactions/simulate"));
        assert!(!has(Method::POST, "/api/v1/mempool/submit"));
        assert!(!has(Method::POST, "/api/v1/mempool/check"));
        // Sanity: the table is non-trivially populated (a real read surface).
        assert!(table.len() > 40);
    }
}
