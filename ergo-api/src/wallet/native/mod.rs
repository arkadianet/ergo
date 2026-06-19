//! Native `/api/v1/wallet/*` surface — a second adapter over [`WalletAdmin`],
//! distinct from the Scala-compat `/wallet/*` handlers. Factual-only DTOs
//! (decimal-string amounts, tagged unions), the native `{reason, detail?}`
//! error envelope, and an EIP-27-aware balance. See
//! `dev-docs/native-wallet-v1-design.md`.

use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

use super::WalletAdmin;
use error::NativeErr;

pub mod dto;
pub mod error;

/// Unwrap a `Query<T>` extraction, mapping Axum's rejection (unknown query key
/// via `deny_unknown_fields`, malformed value) to the native `{reason, detail?}`
/// envelope instead of Axum's default plain-text 400 (codex). Handlers take
/// `Result<Query<T>, QueryRejection>` and pass it here.
fn query<T>(q: Result<Query<T>, QueryRejection>) -> Result<T, NativeErr> {
    match q {
        Ok(Query(v)) => Ok(v),
        Err(e) => Err(error::native_err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            Some(e.to_string()),
        )),
    }
}

/// Native pagination: `?offset=&limit=`, default `limit` 50, cap 16384, both
/// `u32`. Unknown query keys → `bad_request` (deny_unknown_fields). Deliberately
/// distinct from `blockchain::resolve_page` (default 5, numeric envelope).
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WalletPagedQuery {
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    50
}

/// Maximum page size; a larger `limit` is a `bad_request`.
const PAGE_LIMIT_CAP: u32 = 16384;

impl WalletPagedQuery {
    /// Validate the page window. `limit` must be `1..=16384`; any `offset` is
    /// valid (`u32` can't be negative). Returns `(offset, limit)`.
    fn resolve(&self) -> Result<(u32, u32), NativeErr> {
        if self.limit == 0 || self.limit > PAGE_LIMIT_CAP {
            return Err(error::native_err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                Some(format!("limit must be 1..={PAGE_LIMIT_CAP}")),
            ));
        }
        Ok((self.offset, self.limit))
    }
}

/// Validate a 64-char hex path id (box/tx id), returning it lowercased. A
/// malformed id is a `bad_request` (never a misleading 404).
fn validate_hex32(s: &str) -> Result<String, NativeErr> {
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(error::native_err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            Some("expected a 64-character hex id".to_string()),
        ))
    }
}

/// Query for `GET /api/v1/wallet/balance`. Strict: an unknown query key is a
/// `bad_request` (deny_unknown_fields).
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BalanceQuery {
    /// Add the labeled single-hop mempool delta to the response.
    #[serde(default)]
    pub include_unconfirmed: bool,
}

/// `GET /api/v1/wallet/balance` — the EIP-27-aware nanoErg breakdown
/// (`confirmed`/`available`/`reserved`/`immature`), confirmed token balances,
/// the re-emission reserve detail, and (only with `?includeUnconfirmed=true`)
/// the labeled mempool delta. All amounts are decimal strings; the body is
/// computed from one wallet read snapshot (`height` = its scan height).
#[utoipa::path(
    get,
    path = "/api/v1/wallet/balance",
    tag = "wallet",
    params(
        ("includeUnconfirmed" = Option<bool>, Query,
         description = "Include the labeled single-hop mempool delta")
    ),
    responses(
        (status = 200, description = "Wallet balance breakdown", body = dto::WalletBalanceDto),
        (status = 400, description = "Bad query", body = error::NativeWalletError),
        (status = 403, description = "Missing/invalid api key (route-layer gate)", body = error::NativeWalletError),
        (status = 409, description = "Wallet uninitialized", body = error::NativeWalletError),
        (status = 500, description = "Internal error", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn balance(
    State(admin): State<Arc<dyn WalletAdmin>>,
    q: Result<Query<BalanceQuery>, QueryRejection>,
) -> Result<Json<dto::WalletBalanceDto>, NativeErr> {
    let q = query(q)?;
    let b = admin
        .native_balance(q.include_unconfirmed)
        .await
        .map_err(error::map_err)?;
    Ok(Json(b))
}

/// `GET /api/v1/wallet/status` — wallet state snapshot.
#[utoipa::path(
    get, path = "/api/v1/wallet/status", tag = "wallet",
    responses(
        (status = 200, description = "Wallet status", body = dto::WalletStatusDto),
        (status = 403, description = "Missing/invalid api key (route-layer gate)", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn status(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<Json<dto::WalletStatusDto>, NativeErr> {
    Ok(Json(admin.native_status().await.map_err(error::map_err)?))
}

/// `GET /api/v1/wallet/addresses` — paged tracked addresses + derivation metadata.
#[utoipa::path(
    get, path = "/api/v1/wallet/addresses", tag = "wallet",
    params(
        ("offset" = Option<u32>, Query, description = "Page offset (default 0)"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, cap 16384)"),
    ),
    responses(
        (status = 200, description = "Paged tracked addresses", body = dto::AddressPage),
        (status = 400, description = "Bad page window", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn addresses(
    State(admin): State<Arc<dyn WalletAdmin>>,
    q: Result<Query<WalletPagedQuery>, QueryRejection>,
) -> Result<Json<dto::AddressPage>, NativeErr> {
    let (offset, limit) = query(q)?.resolve()?;
    Ok(Json(
        admin
            .native_addresses(offset, limit)
            .await
            .map_err(error::map_err)?,
    ))
}

/// `GET /api/v1/wallet/boxes` — paged wallet boxes (newest creation first).
#[utoipa::path(
    get, path = "/api/v1/wallet/boxes", tag = "wallet",
    params(
        ("offset" = Option<u32>, Query, description = "Page offset (default 0)"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, cap 16384)"),
    ),
    responses(
        (status = 200, description = "Paged wallet boxes", body = dto::BoxPage),
        (status = 400, description = "Bad page window", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn boxes(
    State(admin): State<Arc<dyn WalletAdmin>>,
    q: Result<Query<WalletPagedQuery>, QueryRejection>,
) -> Result<Json<dto::BoxPage>, NativeErr> {
    let (offset, limit) = query(q)?.resolve()?;
    Ok(Json(
        admin
            .native_boxes(offset, limit)
            .await
            .map_err(error::map_err)?,
    ))
}

/// `GET /api/v1/wallet/boxes/{boxId}` — a single wallet box summary.
#[utoipa::path(
    get, path = "/api/v1/wallet/boxes/{boxId}", tag = "wallet",
    params(("boxId" = String, Path, description = "32-byte box id (hex)")),
    responses(
        (status = 200, description = "Wallet box summary", body = dto::WalletBoxSummary),
        (status = 400, description = "Malformed box id", body = error::NativeWalletError),
        (status = 404, description = "Box not tracked", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn box_by_id(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Path(box_id): Path<String>,
) -> Result<Json<dto::WalletBoxSummary>, NativeErr> {
    let id = validate_hex32(&box_id)?;
    match admin.native_box_by_id(id).await.map_err(error::map_err)? {
        Some(b) => Ok(Json(b)),
        None => Err(error::native_err(
            StatusCode::NOT_FOUND,
            "box_not_found",
            None,
        )),
    }
}

/// `GET /api/v1/wallet/transactions` — paged wallet transactions (newest first).
#[utoipa::path(
    get, path = "/api/v1/wallet/transactions", tag = "wallet",
    params(
        ("offset" = Option<u32>, Query, description = "Page offset (default 0)"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, cap 16384)"),
    ),
    responses(
        (status = 200, description = "Paged wallet transactions", body = dto::TxPage),
        (status = 400, description = "Bad page window", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn transactions(
    State(admin): State<Arc<dyn WalletAdmin>>,
    q: Result<Query<WalletPagedQuery>, QueryRejection>,
) -> Result<Json<dto::TxPage>, NativeErr> {
    let (offset, limit) = query(q)?.resolve()?;
    Ok(Json(
        admin
            .native_transactions(offset, limit)
            .await
            .map_err(error::map_err)?,
    ))
}

/// `GET /api/v1/wallet/transactions/{txId}` — a single wallet transaction summary.
#[utoipa::path(
    get, path = "/api/v1/wallet/transactions/{txId}", tag = "wallet",
    params(("txId" = String, Path, description = "32-byte transaction id (hex)")),
    responses(
        (status = 200, description = "Wallet transaction summary", body = dto::WalletTransactionSummary),
        (status = 400, description = "Malformed transaction id", body = error::NativeWalletError),
        (status = 404, description = "Transaction not found", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn transaction_by_id(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Path(tx_id): Path<String>,
) -> Result<Json<dto::WalletTransactionSummary>, NativeErr> {
    let id = validate_hex32(&tx_id)?;
    match admin
        .native_transaction_by_id(id)
        .await
        .map_err(error::map_err)?
    {
        Some(t) => Ok(Json(t)),
        None => Err(error::native_err(
            StatusCode::NOT_FOUND,
            "tx_not_found",
            None,
        )),
    }
}

/// Build the native `/api/v1/wallet/*` router. Mirrors
/// [`crate::wallet::router_with_security`]: the whole subtree is api-key gated
/// via `route_layer` (never `layer` — see that fn's note on the `/emission/at`
/// regression), and the explicit `/api/v1/wallet` + `/api/v1/wallet/*rest`
/// catch-alls give whole-prefix gating without `403`-masking-`404`. Merged
/// alongside the Scala-compat wallet router in `server.rs`.
pub fn router_with_security(
    admin: Arc<dyn WalletAdmin>,
    security: Option<Arc<crate::auth::ApiSecurity>>,
) -> axum::Router {
    use axum::routing::{any, get};
    let r = axum::Router::new()
        .route("/api/v1/wallet/status", get(status))
        .route("/api/v1/wallet/balance", get(balance))
        .route("/api/v1/wallet/addresses", get(addresses))
        .route("/api/v1/wallet/boxes", get(boxes))
        .route("/api/v1/wallet/boxes/:box_id", get(box_by_id))
        .route("/api/v1/wallet/transactions", get(transactions))
        .route("/api/v1/wallet/transactions/:tx_id", get(transaction_by_id))
        .route("/api/v1/wallet", any(crate::auth::unknown_gated_subpath))
        .route(
            "/api/v1/wallet/*rest",
            any(crate::auth::unknown_gated_subpath),
        )
        .with_state(admin);
    match security {
        Some(sec) => r.route_layer(axum::middleware::from_fn_with_state(
            sec,
            crate::auth::require_api_key,
        )),
        None => r,
    }
}
