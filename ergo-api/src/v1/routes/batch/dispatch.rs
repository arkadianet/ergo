//! Batch dispatch: the allow-list classification primitives
//! (`AllowedRoute`, `template_matches`, `classify`), the in-process
//! sub-request dispatcher, the `POST /api/v1/batch` handler, and the
//! router constructor. The route manifest itself lives in
//! [`super::allowlist`].

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{header::CONTENT_TYPE, HeaderValue, Method, Request, Uri},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde_json::Value;
use tower::ServiceExt;

use super::allowlist::allowed_routes;
use super::{
    BatchItemRequest, BatchItemResult, BatchRequest, BatchResponse, MAX_BATCH_ITEMS,
    MAX_BATCH_WEIGHT,
};
use crate::v1::client_ip;
use crate::v1::error::{v1_error, Reason, V1Error};
use crate::v1::governor::{Governor, RouteClass};
use crate::v1::routes::V1State;

/// Byte cap applied when buffering EITHER the inbound batch request body or a
/// single sub-response body before re-embedding it (defends batch's own
/// memory against a pathological body in either direction; every
/// allow-listed handler's real replies are far below this in practice).
const MAX_BUFFERED_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Shared "no resolvable peer" bucket key (mirrors [`super::super::governor`]).
const UNKNOWN_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

// ----- the closed allow-list -------------------------------------------------

/// One allow-listed `(method, path template)` pair and the [`RouteClass`] it
/// bills against — the classification half of the allow-list. `template`
/// segments prefixed `:` are wildcards (axum's own path-param syntax reused
/// verbatim so the table reads identically to [`super::v1_router`]'s route
/// list).
#[derive(Clone)]
pub(super) struct AllowedRoute {
    pub(super) method: Method,
    pub(super) template: &'static str,
    pub(super) class: RouteClass,
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
}
