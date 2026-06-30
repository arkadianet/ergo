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

/// Strict-JSON body extractor for native POST/PUT routes. Deserializes the body
/// via serde with the DTO's `#[serde(deny_unknown_fields)]`, mapping ANY failure
/// (malformed JSON, unknown field, type error) to the native
/// `{reason:"bad_request", detail}` envelope — never Axum's default plain-text
/// 400. The centralized strict extractor the design mandates for the write surface.
pub(crate) struct StrictJson<T>(pub T);

#[async_trait::async_trait]
impl<T, S> axum::extract::FromRequest<S> for StrictJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = NativeErr;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = axum::body::Bytes::from_request(req, state)
            .await
            .map_err(|e| {
                error::native_err(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    Some(format!("could not read body: {e}")),
                )
            })?;
        // An empty body is treated as `{}` so endpoints whose fields are all
        // optional (e.g. rescan) accept a bodyless POST; required fields still error.
        let slice: &[u8] = if bytes.is_empty() { b"{}" } else { &bytes };
        let value = serde_json::from_slice::<T>(slice).map_err(|e| {
            error::native_err(StatusCode::BAD_REQUEST, "bad_request", Some(e.to_string()))
        })?;
        Ok(StrictJson(value))
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

/// A JSON response carrying `Cache-Control: no-store` — for secret-bearing
/// responses (the SPA security-header middleware does not cover `/api/*`).
type NoStoreJson<T> = (
    [(axum::http::HeaderName, axum::http::HeaderValue); 1],
    Json<T>,
);

fn no_store<T>(body: T) -> NoStoreJson<T> {
    (
        [(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        )],
        Json(body),
    )
}

/// `POST /api/v1/wallet/unlock` — load the in-memory master key.
#[utoipa::path(
    post, path = "/api/v1/wallet/unlock", tag = "wallet",
    request_body = dto::UnlockRequest,
    responses(
        (status = 200, description = "Unlocked"),
        (status = 400, description = "Malformed body", body = error::NativeWalletError),
        (status = 401, description = "Wrong password", body = error::NativeWalletError),
        (status = 409, description = "Wallet uninitialized", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn unlock(
    State(admin): State<Arc<dyn WalletAdmin>>,
    StrictJson(req): StrictJson<dto::UnlockRequest>,
) -> Result<StatusCode, NativeErr> {
    admin.unlock(req.pass).await.map_err(error::map_err)?;
    Ok(StatusCode::OK)
}

/// `POST /api/v1/wallet/lock` — drop the in-memory master key (idempotent).
#[utoipa::path(
    post, path = "/api/v1/wallet/lock", tag = "wallet",
    responses(
        (status = 200, description = "Locked"),
        (status = 403, description = "Missing/invalid api key (route-layer gate)", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn lock(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<StatusCode, NativeErr> {
    admin.lock().await.map_err(error::map_err)?;
    Ok(StatusCode::OK)
}

/// `POST /api/v1/wallet/mnemonic/verify` — compare a candidate mnemonic against
/// the persisted seed. `matched=false` is a factual answer, not an error.
#[utoipa::path(
    post, path = "/api/v1/wallet/mnemonic/verify", tag = "wallet",
    request_body = dto::MnemonicVerifyRequest,
    responses(
        (status = 200, description = "Verification result", body = dto::MnemonicVerifyResult),
        (status = 400, description = "Malformed body", body = error::NativeWalletError),
        (status = 409, description = "Wallet uninitialized", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn mnemonic_verify(
    State(admin): State<Arc<dyn WalletAdmin>>,
    StrictJson(req): StrictJson<dto::MnemonicVerifyRequest>,
) -> Result<NoStoreJson<dto::MnemonicVerifyResult>, NativeErr> {
    // `check` returns `false` on an uninitialized wallet; the native contract is
    // `409 wallet_uninitialized` (a bare `matched:false` would be misleading).
    if !admin
        .native_status()
        .await
        .map_err(error::map_err)?
        .initialized
    {
        return Err(error::native_err(
            StatusCode::CONFLICT,
            "wallet_uninitialized",
            None,
        ));
    }
    let matched = admin
        .check(req.mnemonic, req.mnemonic_pass)
        .await
        .map_err(error::map_err)?;
    Ok(no_store(dto::MnemonicVerifyResult { matched }))
}

/// `POST /api/v1/wallet/init` — create a new encrypted wallet; returns the
/// generated mnemonic ONCE (no-store).
#[utoipa::path(
    post, path = "/api/v1/wallet/init", tag = "wallet",
    request_body = dto::InitRequest,
    responses(
        (status = 200, description = "Wallet created; mnemonic returned once", body = dto::InitResponse),
        (status = 400, description = "Malformed body / invalid strength", body = error::NativeWalletError),
        (status = 409, description = "Wallet already exists", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn init(
    State(admin): State<Arc<dyn WalletAdmin>>,
    StrictJson(req): StrictJson<dto::InitRequest>,
) -> Result<NoStoreJson<dto::InitResponse>, NativeErr> {
    let strength = match req.strength {
        12 | 15 | 18 | 21 | 24 => req.strength as u8,
        other => {
            return Err(error::native_err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                Some(format!(
                    "strength must be one of 12/15/18/21/24, got {other}"
                )),
            ))
        }
    };
    let mnemonic = admin
        .init(req.pass, req.mnemonic_pass, strength)
        .await
        .map_err(error::map_err)?;
    Ok(no_store(dto::InitResponse { mnemonic }))
}

/// `POST /api/v1/wallet/restore` — restore from a recovery phrase with an
/// explicit derivation mode.
#[utoipa::path(
    post, path = "/api/v1/wallet/restore", tag = "wallet",
    request_body = dto::RestoreRequest,
    responses(
        (status = 200, description = "Wallet restored"),
        (status = 400, description = "Malformed body", body = error::NativeWalletError),
        (status = 409, description = "Wallet exists / restore unsupported on a pruned node", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn restore(
    State(admin): State<Arc<dyn WalletAdmin>>,
    StrictJson(req): StrictJson<dto::RestoreRequest>,
) -> Result<StatusCode, NativeErr> {
    let use_pre_1627 = matches!(req.derivation, dto::DerivationMode::LegacyPre1627);
    admin
        .restore(req.mnemonic, req.mnemonic_pass, req.pass, use_pre_1627)
        .await
        .map_err(error::map_err)?;
    Ok(StatusCode::OK)
}

/// Address index = the last derivation-path component (e.g. `5` in
/// `m/44'/429'/0'/0/5`; hardened markers stripped). `None` when the path has no
/// numeric trailing component (e.g. the bare root `m/`), so callers can reject a
/// path that can't yield a meaningful address index rather than report a
/// misleading `0`.
fn index_from_path(path: &str) -> Option<u32> {
    path.rsplit('/')
        .next()
        .map(|s| s.trim_end_matches('\''))
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<u32>().ok())
}

/// `POST /api/v1/wallet/addresses` — derive a new key (next sequential, or at an
/// explicit path) and register it as a tracked address. Needs unlock.
#[utoipa::path(
    post, path = "/api/v1/wallet/addresses", tag = "wallet",
    request_body = dto::DeriveKeyRequest,
    responses(
        (status = 200, description = "Derived address", body = dto::DerivedAddress),
        (status = 400, description = "Malformed body", body = error::NativeWalletError),
        (status = 409, description = "Wallet locked", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn derive_address(
    State(admin): State<Arc<dyn WalletAdmin>>,
    StrictJson(req): StrictJson<dto::DeriveKeyRequest>,
) -> Result<Json<dto::DerivedAddress>, NativeErr> {
    let derived = match req {
        dto::DeriveKeyRequest::Next => {
            let r = admin.derive_next_key().await.map_err(error::map_err)?;
            // The bridge builds a canonical `m/44'/429'/0'/0/N` path, so its last
            // component is always a numeric index; a miss here is an internal bug.
            let index = index_from_path(&r.derivation_path).ok_or_else(|| {
                error::native_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    Some("derived path has no address index".to_string()),
                )
            })?;
            dto::DerivedAddress {
                index,
                address: r.address,
                derivation_path: r.derivation_path,
            }
        }
        dto::DeriveKeyRequest::Path { derivation_path } => {
            // Reject a caller path with no meaningful trailing index BEFORE
            // deriving (a bare `m/` would otherwise report a misleading index 0).
            let index = index_from_path(&derivation_path).ok_or_else(|| {
                error::native_err(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    Some("derivation path has no numeric address index".to_string()),
                )
            })?;
            let r = admin
                .derive_key(crate::wallet::admin_advanced::DeriveKeyRequest {
                    derivation_path: derivation_path.clone(),
                })
                .await
                .map_err(error::map_err)?;
            dto::DerivedAddress {
                index,
                address: r.address,
                derivation_path,
            }
        }
    };
    Ok(Json(derived))
}

/// `GET /api/v1/wallet/change-address` — current change address, or `null`.
#[utoipa::path(
    get, path = "/api/v1/wallet/change-address", tag = "wallet",
    responses(
        (status = 200, description = "Change address (or null)", body = dto::ChangeAddressDto),
        (status = 403, description = "Missing/invalid api key (route-layer gate)", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn change_address_get(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<Json<dto::ChangeAddressDto>, NativeErr> {
    let status = admin.native_status().await.map_err(error::map_err)?;
    Ok(Json(dto::ChangeAddressDto {
        address: status.change_address,
    }))
}

/// `PUT /api/v1/wallet/change-address` — set the change address. The address
/// must be a tracked P2PK for this network (not unlock-gated).
#[utoipa::path(
    put, path = "/api/v1/wallet/change-address", tag = "wallet",
    request_body = dto::SetChangeAddressRequest,
    responses(
        (status = 200, description = "Change address set"),
        (status = 400, description = "Malformed body", body = error::NativeWalletError),
        (status = 422, description = "Address is not a tracked P2PK", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn change_address_put(
    State(admin): State<Arc<dyn WalletAdmin>>,
    StrictJson(req): StrictJson<dto::SetChangeAddressRequest>,
) -> Result<StatusCode, NativeErr> {
    admin
        .update_change_address(req.address)
        .await
        .map_err(error::map_err)?;
    Ok(StatusCode::OK)
}

/// `POST /api/v1/wallet/rescan` — trigger a wallet rescan (full rebuild when
/// `fromHeight` is 0). `rescan_unavailable(409)` on a backend that cannot replay.
#[utoipa::path(
    post, path = "/api/v1/wallet/rescan", tag = "wallet",
    // Optional body: the strict extractor treats an empty body as `{}` (a bodyless
    // POST does a full rebuild), so the OpenAPI contract must not mark it required.
    request_body = Option<dto::RescanRequest>,
    responses(
        (status = 200, description = "Rescan started"),
        (status = 400, description = "Malformed body", body = error::NativeWalletError),
        (status = 409, description = "Rescan unavailable / already in progress", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn rescan(
    State(admin): State<Arc<dyn WalletAdmin>>,
    StrictJson(req): StrictJson<dto::RescanRequest>,
) -> Result<StatusCode, NativeErr> {
    admin
        .rescan(req.from_height)
        .await
        .map_err(error::map_err)?;
    Ok(StatusCode::OK)
}

/// `POST /api/v1/wallet/boxes/select` — burn-aware box-selection dry-run. Returns
/// the real selected inputs, computed change, and the exact EIP-27 re-emission
/// burn. Requires an unlocked wallet (design §2).
#[utoipa::path(
    post, path = "/api/v1/wallet/boxes/select", tag = "wallet",
    request_body = dto::BoxSelectRequest,
    responses(
        (status = 200, description = "Selection plan", body = dto::BoxSelectResponse),
        (status = 400, description = "Malformed body", body = error::NativeWalletError),
        (status = 403, description = "Missing/invalid api key (route-layer gate)", body = error::NativeWalletError),
        (status = 404, description = "A requested box id is not a wallet box", body = error::NativeWalletError),
        (status = 409, description = "Wallet locked/uninitialized", body = error::NativeWalletError),
        (status = 422, description = "insufficient_funds / reemission_spend_not_allowed / change_address_untracked / unsupported_intent", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn select_boxes(
    State(admin): State<Arc<dyn WalletAdmin>>,
    StrictJson(req): StrictJson<dto::BoxSelectRequest>,
) -> Result<Json<dto::BoxSelectResponse>, NativeErr> {
    let resp = admin.select_boxes(req).await.map_err(error::map_err)?;
    Ok(Json(resp))
}

/// `POST /api/v1/wallet/transactions/build` — build a burn-aware unsigned tx from
/// an intent. Returns the unsigned tx plus the selected inputs, change outputs,
/// fee, and re-emission burn. Requires an unlocked wallet (design §2).
#[utoipa::path(
    post, path = "/api/v1/wallet/transactions/build", tag = "wallet",
    request_body = dto::TxIntent,
    responses(
        (status = 200, description = "Built unsigned transaction + plan", body = dto::BuildTxResponse),
        (status = 400, description = "Malformed body / no outputs", body = error::NativeWalletError),
        (status = 403, description = "Missing/invalid api key (route-layer gate)", body = error::NativeWalletError),
        (status = 409, description = "Wallet locked/uninitialized", body = error::NativeWalletError),
        (status = 422, description = "insufficient_funds / reemission_spend_not_allowed / change_address_untracked / unsupported_intent", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn build_transaction(
    State(admin): State<Arc<dyn WalletAdmin>>,
    StrictJson(req): StrictJson<dto::TxIntent>,
) -> Result<Json<dto::BuildTxResponse>, NativeErr> {
    let resp = admin.build_transaction(req).await.map_err(error::map_err)?;
    Ok(Json(resp))
}

/// `POST /api/v1/wallet/transactions/sign` — sign a caller-supplied unsigned tx.
/// Conditional unlock: succeeds while locked when `externalSecrets` cover all
/// inputs, else `missing_secret(422)` (never `wallet_locked`). Response is
/// `Cache-Control: no-store` (it carries signed material).
#[utoipa::path(
    post, path = "/api/v1/wallet/transactions/sign", tag = "wallet",
    request_body = dto::SignTxRequest,
    responses(
        (status = 200, description = "Signed transaction + txId", body = dto::SignTxResponse),
        (status = 400, description = "Malformed body / tx bytes", body = error::NativeWalletError),
        (status = 403, description = "Missing/invalid api key (route-layer gate)", body = error::NativeWalletError),
        (status = 422, description = "missing_secret / reemission_obligation_unmet / unsupported_script", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn sign_transaction(
    State(admin): State<Arc<dyn WalletAdmin>>,
    StrictJson(req): StrictJson<dto::SignTxRequest>,
) -> Result<NoStoreJson<dto::SignTxResponse>, NativeErr> {
    let resp = admin.sign_transaction(req).await.map_err(error::map_err)?;
    Ok(no_store(resp))
}

/// `POST /api/v1/wallet/transactions/send` — build+sign+submit an intent (needs
/// unlock) or submit a caller-supplied signed tx (no unlock). txId-first
/// idempotency: an already-known tx returns `accepted:true` without re-submitting,
/// and a duplicate submit is an idempotent accept. `Cache-Control: no-store`.
#[utoipa::path(
    post, path = "/api/v1/wallet/transactions/send", tag = "wallet",
    request_body = dto::SendTxRequest,
    responses(
        (status = 200, description = "Accepted (fresh or idempotent)", body = dto::SendTxResponse),
        (status = 400, description = "Malformed body / submit rejected", body = error::NativeWalletError),
        (status = 403, description = "Missing/invalid api key (route-layer gate)", body = error::NativeWalletError),
        (status = 409, description = "Wallet locked (intent send)", body = error::NativeWalletError),
        (status = 422, description = "insufficient_funds / reemission_* / missing_secret / unsupported_intent", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn send_transaction(
    State(admin): State<Arc<dyn WalletAdmin>>,
    StrictJson(req): StrictJson<dto::SendTxRequest>,
) -> Result<NoStoreJson<dto::SendTxResponse>, NativeErr> {
    let resp = admin.send_transaction(req).await.map_err(error::map_err)?;
    Ok(no_store(resp))
}

/// `POST /api/v1/wallet/rewards/retrieve` — sweep all matured miner-reward boxes
/// into one P2PK output (the wallet change address, or `destination`), in one
/// EIP-27-correct tx: the re-emission token is burned and its ERG routed to
/// pay-to-reemission, other tokens are carried through. `dryRun` returns the
/// breakdown without signing/submitting. `Cache-Control: no-store`.
#[utoipa::path(
    post, path = "/api/v1/wallet/rewards/retrieve", tag = "wallet",
    request_body = dto::RetrieveRewardsRequest,
    responses(
        (status = 200, description = "Preview (dryRun) or submitted sweep", body = dto::RetrieveRewardsResultDto),
        (status = 400, description = "Malformed body / no matured rewards / too many token types", body = error::NativeWalletError),
        (status = 403, description = "Missing/invalid api key (route-layer gate)", body = error::NativeWalletError),
        (status = 409, description = "Wallet locked (execute) / wallet uninitialized", body = error::NativeWalletError),
        (status = 422, description = "insufficient_funds / change_address_untracked", body = error::NativeWalletError),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub(crate) async fn retrieve_rewards(
    State(admin): State<Arc<dyn WalletAdmin>>,
    StrictJson(req): StrictJson<dto::RetrieveRewardsRequest>,
) -> Result<NoStoreJson<dto::RetrieveRewardsResultDto>, NativeErr> {
    let resp = admin.retrieve_rewards(req).await.map_err(error::map_err)?;
    Ok(no_store(resp))
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
    use axum::routing::{any, get, post};
    let r = axum::Router::new()
        .route("/api/v1/wallet/status", get(status))
        .route("/api/v1/wallet/balance", get(balance))
        .route(
            "/api/v1/wallet/addresses",
            get(addresses).post(derive_address),
        )
        .route(
            "/api/v1/wallet/change-address",
            get(change_address_get).put(change_address_put),
        )
        .route("/api/v1/wallet/boxes", get(boxes))
        .route("/api/v1/wallet/boxes/select", post(select_boxes))
        .route("/api/v1/wallet/boxes/:box_id", get(box_by_id))
        .route("/api/v1/wallet/transactions", get(transactions))
        .route("/api/v1/wallet/transactions/build", post(build_transaction))
        .route("/api/v1/wallet/transactions/sign", post(sign_transaction))
        .route("/api/v1/wallet/transactions/send", post(send_transaction))
        .route("/api/v1/wallet/rewards/retrieve", post(retrieve_rewards))
        .route("/api/v1/wallet/transactions/:tx_id", get(transaction_by_id))
        // --- lifecycle (POST) ---
        .route("/api/v1/wallet/init", post(init))
        .route("/api/v1/wallet/restore", post(restore))
        .route("/api/v1/wallet/unlock", post(unlock))
        .route("/api/v1/wallet/lock", post(lock))
        .route("/api/v1/wallet/mnemonic/verify", post(mnemonic_verify))
        .route("/api/v1/wallet/rescan", post(rescan))
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
