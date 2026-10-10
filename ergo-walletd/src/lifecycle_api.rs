//! Independent local seed lifecycle status and the shared API credential gate.
use crate::api::ApiContext;
use crate::config::ApiKey;
use crate::host::WalletHost;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use ergo_wallet_protocol::native::dto::LifecycleStatusDto;
use ergo_wallet_protocol::native::error::NativeWalletError;
use ergo_wallet_protocol::{WalletAdminError, WalletErrorSurface};

pub const MAX_LIFECYCLE_BODY_BYTES: usize = 16 * 1024;
pub const LIFECYCLE_ROUTE_INVENTORY: &[(&str, &str)] = &[
    ("GET", "/api/v1/wallet/lifecycle/status"),
    ("POST", "/api/v1/wallet/init"),
    ("POST", "/api/v1/wallet/restore"),
    ("POST", "/api/v1/wallet/unlock"),
    ("POST", "/api/v1/wallet/lock"),
    ("POST", "/api/v1/wallet/mnemonic/verify"),
    ("POST", "/api/v1/wallet/addresses"),
    ("GET", "/api/v1/wallet/change-address"),
    ("PUT", "/api/v1/wallet/change-address"),
];

pub fn seed_router(context: ApiContext, host: WalletHost, local_api_key: ApiKey) -> Router {
    crate::full_api::seed_router(context, host, local_api_key)
}
pub(crate) fn status_router(host: WalletHost) -> Router {
    Router::new()
        .route("/api/v1/wallet/lifecycle/status", get(status))
        .with_state(host)
}
pub(crate) async fn authenticate(
    State(key): State<ApiKey>,
    request: Request,
    next: Next,
) -> Response {
    let mut values = request.headers().get_all("api_key").iter();
    let authorized = values.next().is_some_and(|value| {
        values.next().is_none() && bool::from(key.ct_eq_bytes(value.as_bytes()))
    });
    let mut response = if authorized {
        next.run(request).await
    } else {
        native_error(StatusCode::UNAUTHORIZED, "unauthorized", None).into_response()
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The retained short read adapter predates the seed engine and includes
/// internal diagnostics in its errors. Sanitize that subrouter only so the
/// native/Scala/collection engine adapters retain their own error envelopes.
pub(crate) async fn sanitize_read_errors(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    if response.status() == StatusCode::INTERNAL_SERVER_ERROR {
        native_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", None).into_response()
    } else {
        response
    }
}

type NativeError = (StatusCode, Json<NativeWalletError>);

fn native_error(status: StatusCode, reason: &str, detail: Option<String>) -> NativeError {
    (
        status,
        Json(NativeWalletError {
            reason: reason.to_owned(),
            detail,
        }),
    )
}

fn map_error(error: WalletAdminError) -> NativeError {
    let mut mapped = WalletErrorSurface::NativeV1.map(&error);
    if mapped.status >= 500 {
        mapped.detail = None;
    }
    native_error(
        StatusCode::from_u16(mapped.status).expect("wallet protocol status is valid"),
        mapped.reason,
        mapped.detail,
    )
}

async fn status(State(host): State<WalletHost>) -> Result<Json<LifecycleStatusDto>, NativeError> {
    let status = host.status().await.map_err(map_error)?;
    Ok(Json(LifecycleStatusDto {
        initialized: status.is_initialized,
        locked: !status.is_unlocked,
    }))
}
