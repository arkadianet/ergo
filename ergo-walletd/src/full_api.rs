//! Complete native and Scala-compatible adapters over the hosted wallet engine.
//! Static UI assets are public; every API operation uses the independent local
//! credential. The default watch-only adapter remains separate.
use crate::{api::ApiContext, config::ApiKey, host::WalletHost};
use axum::{extract::DefaultBodyLimit, middleware, Router};
use std::sync::Arc;
mod accounts;
mod compat;
mod cursor;
mod facade;
mod native;
mod private;
pub mod ui;

/// Bound transactions and scan-box payloads independently of small seed bodies.
pub const MAX_WALLET_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Authenticated non-GET requests are wallet operations: they reset the idle
/// lock. Reads do not, so a polling client cannot keep the wallet unlocked.
async fn note_operation(
    axum::extract::State(host): axum::extract::State<WalletHost>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    if !matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    ) {
        host.note_activity();
    }
    next.run(request).await
}

pub fn seed_router(context: ApiContext, host: WalletHost, key: ApiKey) -> Router {
    let admin = Arc::new(facade::WalletApi {
        host: host.clone(),
        reads: context.clone(),
    });
    let api = crate::api::short_router(context)
        .layer(middleware::from_fn(
            crate::lifecycle_api::sanitize_read_errors,
        ))
        .merge(crate::lifecycle_api::status_router(host.clone()))
        .merge(native::router(admin.clone()))
        .merge(compat::router(admin.clone()))
        .merge(private::router(admin.clone()))
        .merge(accounts::router(admin))
        .layer(DefaultBodyLimit::max(MAX_WALLET_BODY_BYTES))
        .layer(middleware::from_fn_with_state(host.clone(), note_operation))
        .layer(middleware::from_fn_with_state(
            key,
            crate::lifecycle_api::authenticate,
        ));
    api.merge(ui::router())
}
