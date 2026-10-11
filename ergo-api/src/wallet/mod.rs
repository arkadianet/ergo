//! The node hosts no wallet. Its former wallet, scan, account and PSBT routes
//! stay mounted only to point clients at `ergo-walletd`: every method on every
//! path under those prefixes answers `410 Gone` with reason `wallet_moved` and
//! the configured daemon address.
//!
//! Authentication still comes first, as it did while the routes were served,
//! so an unauthenticated caller learns nothing about the wallet's location:
//!
//! - Scala-compatible `/wallet/*`, `/scan/*` and native `/api/v1/wallet/*`
//!   check the operator API key ([`crate::auth`]) and answer
//!   `{"reason": "wallet_moved", "address": …}`.
//! - Native `/api/v1/scan/*`, `/api/v1/accounts/*` and
//!   `/api/v1/transactions-psbt/*` check the v1 operator tier and answer the
//!   v1 error envelope. The two watch-only reads that were public
//!   (`GET /api/v1/accounts/watch` and `GET /api/v1/accounts/watch/{id}/unspent`)
//!   answer without a key, as they always did.
//!
//! All mounts are explicit catch-all routes guarded with `route_layer`, never
//! a router-wide `layer` or fallback, so they cannot gate unrelated paths.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{MatchedPath, State};
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::{Json, Router};

use crate::v1::auth::{require_tier, Tier, V1AuthConfig, V1AuthState};
use crate::v1::error::{v1_error, Reason};

/// Every Scala-compatible path the wallet owned.
const COMPAT_PATHS: &[&str] = &["/wallet", "/wallet/*rest", "/scan", "/scan/*rest"];

/// Every native `/api/v1/wallet` path.
const NATIVE_WALLET_PATHS: &[&str] = &["/api/v1/wallet", "/api/v1/wallet/*rest"];

/// Every native v1 scan, account and PSBT path.
const PRODUCT_PATHS: &[&str] = &[
    "/api/v1/scan",
    "/api/v1/scan/*rest",
    "/api/v1/accounts",
    "/api/v1/accounts/*rest",
    "/api/v1/transactions-psbt",
    "/api/v1/transactions-psbt/*rest",
];

#[derive(Clone)]
struct MovedGuard {
    daemon_address: Option<Arc<str>>,
    security: Option<Arc<crate::auth::ApiSecurity>>,
}

/// Drop the catch-all's route template, so credential scopes resolve against
/// the request's own path (`/wallet/getPrivateKey` stays admin-only).
fn forget_route_template(req: &mut Request<Body>) {
    req.extensions_mut().remove::<MatchedPath>();
}

async fn moved_after_api_key(
    State(guard): State<MovedGuard>,
    mut req: Request<Body>,
    _next: Next,
) -> Response {
    forget_route_template(&mut req);
    let Some(security) = &guard.security else {
        return crate::auth::reject_unconfigured();
    };
    if !crate::auth::request_is_authorized(security, &req) {
        return crate::auth::reject_invalid();
    }
    wallet_moved_response(guard.daemon_address.as_deref())
}

/// The watch-only reads the accounts surface served without a key.
fn is_public_watch_read(method: &Method, path: &str) -> bool {
    method == Method::GET
        && (path == "/api/v1/accounts/watch"
            || path
                .strip_prefix("/api/v1/accounts/watch/")
                .and_then(|rest| rest.strip_suffix("/unspent"))
                .is_some_and(|id| !id.is_empty() && !id.contains('/')))
}

async fn product_auth(
    State(auth): State<V1AuthState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    if is_public_watch_read(req.method(), req.uri().path()) {
        return next.run(req).await;
    }
    forget_route_template(&mut req);
    require_tier(State(auth), req, next).await
}

async fn moved_v1(State(daemon_address): State<Option<Arc<str>>>) -> Response {
    v1_error(
        Reason::WalletMoved,
        "the wallet is owned by an external daemon",
        daemon_address.as_deref().unwrap_or_default(),
    )
}

/// The `410 wallet_moved` body of the Scala-compatible and native wallet
/// paths. `address` is `[wallet] daemon_address`; it is omitted when the
/// embedder configured none.
pub(crate) fn wallet_moved_response(address: Option<&str>) -> Response {
    let mut body = serde_json::json!({ "reason": "wallet_moved" });
    if let Some(address) = address {
        body["address"] = serde_json::Value::from(address);
    }
    (StatusCode::GONE, Json(body)).into_response()
}

fn catch_all(paths: &[&'static str]) -> Router {
    paths.iter().fold(Router::new(), |router, path| {
        router.route(path, any(crate::auth::unknown_gated_subpath))
    })
}

/// The Scala-compatible `/wallet/*` and `/scan/*` paths.
pub fn compat_router(
    daemon_address: Option<&str>,
    security: Option<Arc<crate::auth::ApiSecurity>>,
) -> Router {
    catch_all(COMPAT_PATHS).route_layer(axum::middleware::from_fn_with_state(
        MovedGuard {
            daemon_address: daemon_address.map(Arc::from),
            security,
        },
        moved_after_api_key,
    ))
}

/// The native `/api/v1/wallet/*` paths.
pub fn native_router(
    daemon_address: Option<&str>,
    security: Option<Arc<crate::auth::ApiSecurity>>,
) -> Router {
    catch_all(NATIVE_WALLET_PATHS).route_layer(axum::middleware::from_fn_with_state(
        MovedGuard {
            daemon_address: daemon_address.map(Arc::from),
            security,
        },
        moved_after_api_key,
    ))
}

/// The native v1 `/api/v1/scan/*`, `/api/v1/accounts/*` and
/// `/api/v1/transactions-psbt/*` paths.
pub fn product_router(daemon_address: Option<&str>, auth: Arc<V1AuthConfig>) -> Router {
    let state: Option<Arc<str>> = daemon_address.map(Arc::from);
    PRODUCT_PATHS
        .iter()
        .fold(Router::new(), |router, path| {
            router.route(path, any(moved_v1))
        })
        .with_state(state)
        .route_layer(axum::middleware::from_fn_with_state(
            auth.state(Tier::Operator),
            product_auth,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_two_watch_reads_are_public() {
        for (method, path, public) in [
            (Method::GET, "/api/v1/accounts/watch", true),
            (Method::GET, "/api/v1/accounts/watch/7/unspent", true),
            (Method::POST, "/api/v1/accounts/watch", false),
            (Method::DELETE, "/api/v1/accounts/watch/7", false),
            (Method::GET, "/api/v1/accounts/watch//unspent", false),
            (Method::GET, "/api/v1/accounts/watch/7/8/unspent", false),
            (Method::GET, "/api/v1/accounts", false),
            (Method::GET, "/api/v1/scan/scans", false),
        ] {
            assert_eq!(
                is_public_watch_read(&method, path),
                public,
                "{method} {path}"
            );
        }
    }
}
