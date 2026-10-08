//! Authenticated local seed lifecycle. Mounted only by the opt-in seed host;
//! the default watch-only router remains a separate, secret-free surface.

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ergo_wallet_protocol::native::dto::{
    ChangeAddressDto, DerivationMode, DeriveKeyRequest, DerivedAddress, InitRequest, InitResponse,
    LifecycleStatusDto, MnemonicVerifyRequest, MnemonicVerifyResult, RestoreRequest,
    SetChangeAddressRequest, UnlockRequest,
};
use ergo_wallet_protocol::native::error::NativeWalletError;
use ergo_wallet_protocol::{WalletAdminError, WalletErrorSurface};
use subtle::ConstantTimeEq;

use crate::api::ApiContext;
use crate::config::ApiKey;
use crate::host::WalletHost;

/// Seed and password requests are small. The cap applies after authentication
/// and keeps unauthorized callers from making the daemon parse a secret body.
pub const MAX_LIFECYCLE_BODY_BYTES: usize = 16 * 1024;

/// Additional seed-mode routes. Existing read routes are authenticated too.
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

#[derive(Clone)]
struct LifecycleContext {
    host: WalletHost,
    reads: ApiContext,
}

/// Mount the local seed API around the existing confirmed-chain reads.
///
/// The independently loaded daemon credential protects every route, on Unix
/// sockets as well as loopback TCP. It is never forwarded to the node.
pub fn seed_router(context: ApiContext, host: WalletHost, local_api_key: ApiKey) -> Router {
    let lifecycle = Router::new()
        .route("/api/v1/wallet/lifecycle/status", get(status))
        .route("/api/v1/wallet/init", post(init))
        .route("/api/v1/wallet/restore", post(restore))
        .route("/api/v1/wallet/unlock", post(unlock))
        .route("/api/v1/wallet/lock", post(lock))
        .route("/api/v1/wallet/mnemonic/verify", post(mnemonic_verify))
        .route("/api/v1/wallet/addresses", post(derive_address))
        .route(
            "/api/v1/wallet/change-address",
            get(change_address).put(set_change_address),
        )
        .with_state(LifecycleContext {
            host,
            reads: context.clone(),
        });
    crate::api::router(context)
        .merge(lifecycle)
        .layer(DefaultBodyLimit::max(MAX_LIFECYCLE_BODY_BYTES))
        // This is the outer layer: authenticate before a handler reads its body.
        .layer(middleware::from_fn_with_state(local_api_key, authenticate))
}

async fn authenticate(State(key): State<ApiKey>, request: Request, next: Next) -> Response {
    let mut values = request.headers().get_all("api_key").iter();
    let authorized = values.next().is_some_and(|value| {
        values.next().is_none() && bool::from(value.as_bytes().ct_eq(key.expose()))
    });
    let mut response = if authorized {
        let response = next.run(request).await;
        // Read handlers retain their watch-mode errors. Seed mode never sends
        // internal storage or task failure details across its local API.
        if response.status() == StatusCode::INTERNAL_SERVER_ERROR {
            native_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", None).into_response()
        } else {
            response
        }
    } else {
        native_error(StatusCode::UNAUTHORIZED, "unauthorized", None).into_response()
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
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
    if matches!(error, WalletAdminError::Internal(_)) {
        mapped.detail = None;
    }
    native_error(
        StatusCode::from_u16(mapped.status).expect("wallet protocol status is valid"),
        mapped.reason,
        mapped.detail,
    )
}

fn strict_body<T>(body: Result<Json<T>, JsonRejection>) -> Result<T, NativeError> {
    body.map(|Json(value)| value).map_err(|error| {
        let status = if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        };
        // A serde diagnostic can include input fields. Never echo it for a
        // seed/password request; the protocol DTO provides the strict schema.
        native_error(status, "bad_request", Some("invalid request body".into()))
    })
}

async fn status(
    State(context): State<LifecycleContext>,
) -> Result<Json<LifecycleStatusDto>, NativeError> {
    let status = context.host.status().await.map_err(map_error)?;
    Ok(Json(LifecycleStatusDto {
        initialized: status.is_initialized,
        locked: !status.is_unlocked,
    }))
}

async fn init(
    State(context): State<LifecycleContext>,
    body: Result<Json<InitRequest>, JsonRejection>,
) -> Result<Json<InitResponse>, NativeError> {
    let request = strict_body(body)?;
    let strength = match request.strength {
        12 | 15 | 18 | 21 | 24 => request.strength as u8,
        _ => {
            return Err(native_error(
                StatusCode::BAD_REQUEST,
                "bad_request",
                Some("strength must be 12, 15, 18, 21 or 24".into()),
            ))
        }
    };
    let mnemonic = context
        .host
        .init(request.pass, request.mnemonic_pass, strength)
        .await
        .map_err(map_error)?;
    Ok(Json(InitResponse { mnemonic }))
}

async fn restore(
    State(context): State<LifecycleContext>,
    body: Result<Json<RestoreRequest>, JsonRejection>,
) -> Result<StatusCode, NativeError> {
    let request = strict_body(body)?;
    context
        .host
        .restore(
            request.mnemonic,
            request.mnemonic_pass,
            request.pass,
            matches!(request.derivation, DerivationMode::LegacyPre1627),
        )
        .await
        .map_err(map_error)?;
    Ok(StatusCode::OK)
}

async fn unlock(
    State(context): State<LifecycleContext>,
    body: Result<Json<UnlockRequest>, JsonRejection>,
) -> Result<StatusCode, NativeError> {
    let request = strict_body(body)?;
    context.host.unlock(request.pass).await.map_err(map_error)?;
    Ok(StatusCode::OK)
}

async fn lock(State(context): State<LifecycleContext>) -> Result<StatusCode, NativeError> {
    context.host.lock().await.map_err(map_error)?;
    Ok(StatusCode::OK)
}

async fn mnemonic_verify(
    State(context): State<LifecycleContext>,
    body: Result<Json<MnemonicVerifyRequest>, JsonRejection>,
) -> Result<Json<MnemonicVerifyResult>, NativeError> {
    let request = strict_body(body)?;
    let matched = context
        .host
        .check(request.mnemonic, request.mnemonic_pass)
        .await
        .map_err(map_error)?;
    Ok(Json(MnemonicVerifyResult { matched }))
}

fn index_from_path(path: &str) -> Option<u32> {
    path.rsplit('/').next()?.trim_end_matches('\'').parse().ok()
}

async fn derive_address(
    State(context): State<LifecycleContext>,
    body: Result<Json<DeriveKeyRequest>, JsonRejection>,
) -> Result<Json<DerivedAddress>, NativeError> {
    let derived = match strict_body(body)? {
        DeriveKeyRequest::Next => {
            let derived = context.host.derive_next_key().await.map_err(map_error)?;
            let index = index_from_path(&derived.derivation_path).ok_or_else(|| {
                map_error(WalletAdminError::Internal(
                    "derived path has no address index".into(),
                ))
            })?;
            DerivedAddress {
                address: derived.address,
                derivation_path: derived.derivation_path,
                index,
            }
        }
        DeriveKeyRequest::Path { derivation_path } => {
            let index = index_from_path(&derivation_path).ok_or_else(|| {
                native_error(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    Some("derivation path has no numeric address index".into()),
                )
            })?;
            let derived = context
                .host
                .derive_key(
                    ergo_wallet_protocol::scala::admin_advanced::DeriveKeyRequest {
                        derivation_path: derivation_path.clone(),
                    },
                )
                .await
                .map_err(map_error)?;
            DerivedAddress {
                address: derived.address,
                derivation_path,
                index,
            }
        }
    };
    Ok(Json(derived))
}

async fn change_address(
    State(context): State<LifecycleContext>,
) -> Result<Json<ChangeAddressDto>, NativeError> {
    let service = context.reads.service;
    let network = context.reads.network;
    let address = tokio::task::spawn_blocking(move || {
        let read = service
            .store()
            .read()
            .map_err(|error| WalletAdminError::Internal(error.to_string()))?;
        let key = read
            .change_address_pubkey()
            .map_err(|error| WalletAdminError::Internal(error.to_string()))?;
        key.map(|key| ergo_wallet::address::pubkey_to_p2pk_address(&key, network.prefix()))
            .transpose()
            .map_err(|error| WalletAdminError::Internal(error.to_string()))
    })
    .await
    .map_err(|_| {
        map_error(WalletAdminError::Internal(
            "change-address task failed".into(),
        ))
    })?
    .map_err(map_error)?;
    Ok(Json(ChangeAddressDto { address }))
}

async fn set_change_address(
    State(context): State<LifecycleContext>,
    body: Result<Json<SetChangeAddressRequest>, JsonRejection>,
) -> Result<StatusCode, NativeError> {
    let request = strict_body(body)?;
    context
        .host
        .update_change_address(request.address)
        .await
        .map_err(map_error)?;
    Ok(StatusCode::OK)
}
