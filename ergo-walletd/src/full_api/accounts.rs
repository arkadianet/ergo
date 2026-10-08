//! Native scan/account adapters using the same hosted scan registry.
use super::{
    cursor::{clamp_limit, decode_opt_cursor, encode_cursor, Page},
    facade::WalletApi,
    native::{CollectionJson, CollectionQuery},
};
use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use ergo_ser::address::{decode_address_to_tree_bytes, NetworkPrefix};
use ergo_wallet_protocol::{scala::admin_advanced::GetPrivateKeyRequest, WalletAdminError};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
mod scan;
#[derive(Clone)]
pub(super) struct AccountsState {
    pub admin: Arc<WalletApi>,
    pub network: NetworkPrefix,
}
pub(super) fn router(admin: Arc<WalletApi>) -> Router {
    let state = AccountsState {
        network: admin.reads.network.prefix(),
        admin,
    };
    Router::new()
        // These capabilities are also unavailable in the embedded wallet.
        // Retain its explicit error surface when clients follow wallet_moved.
        .route(
            "/api/v1/accounts",
            get(accounts_unavailable).post(accounts_unavailable),
        )
        .route(
            "/api/v1/accounts/:account_id",
            get(accounts_unavailable)
                .patch(accounts_unavailable)
                .delete(accounts_unavailable),
        )
        .route(
            "/api/v1/accounts/:account_id/balance",
            get(accounts_unavailable),
        )
        .route(
            "/api/v1/accounts/:account_id/addresses",
            get(accounts_unavailable).post(accounts_unavailable),
        )
        .route("/api/v1/transactions-psbt", post(psbt_unavailable))
        .route("/api/v1/transactions-psbt/:psbt_id", get(psbt_unavailable))
        .route(
            "/api/v1/transactions-psbt/:psbt_id/contributions",
            post(psbt_unavailable),
        )
        .route(
            "/api/v1/transactions-psbt/:psbt_id/finalize",
            post(psbt_unavailable),
        )
        .route("/api/v1/scan/scans", get(scan::list).post(scan::register))
        .route(
            "/api/v1/scan/scans/:scan_id",
            get(scan::get_one).delete(scan::deregister),
        )
        .route("/api/v1/scan/scans/:scan_id/unspent", get(scan::unspent))
        .route(
            "/api/v1/scan/scans/:scan_id/transactions",
            get(scan::transactions),
        )
        .route("/api/v1/scan/scans/:scan_id/boxes", post(scan::attach_box))
        .route(
            "/api/v1/scan/scans/:scan_id/boxes/:box_id",
            delete(scan::detach_box),
        )
        .route(
            "/api/v1/accounts/watch",
            get(watch_list).post(watch_register),
        )
        .route("/api/v1/accounts/watch/:scan_id", delete(watch_delete))
        .route(
            "/api/v1/accounts/watch/:scan_id/unspent",
            get(scan::watch_unspent),
        )
        .route(
            "/api/v1/accounts/private-key",
            post(private_key).layer(axum::extract::DefaultBodyLimit::max(
                crate::lifecycle_api::MAX_LIFECYCLE_BODY_BYTES,
            )),
        )
        .with_state(state)
}
async fn accounts_unavailable() -> Response {
    v1_error(
        Reason::RouteUnavailable,
        "the named-accounts subsystem is unavailable",
        String::new(),
    )
}
async fn psbt_unavailable() -> Response {
    v1_error(
        Reason::RouteUnavailable,
        "the PSBT-session subsystem is unavailable",
        String::new(),
    )
}

#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Reason {
    AcknowledgementRequired,
    AddressNotWatched,
    BadRequest,
    BoxNotFound,
    ChangeAddressUntracked,
    InsufficientFunds,
    InternalError,
    Invalid,
    InvalidAddress,
    InvalidCursor,
    InvalidParams,
    MissingSecret,
    NodeUnavailable,
    RateLimited,
    RouteUnavailable,
    ScanNotFound,
    SensitiveOpDisabled,
    ShuttingDown,
    StaleCandidate,
    StateUnavailable,
    TxNotFound,
    UnsupportedIntent,
    WalletUninitialized,
    WrongPassword,
}
impl Reason {
    fn http_status(self) -> axum::http::StatusCode {
        match self {
            Self::AcknowledgementRequired => {
                axum::http::StatusCode::from_u16(409).expect("valid status")
            }
            Self::AddressNotWatched => axum::http::StatusCode::from_u16(404).expect("valid status"),
            Self::BadRequest => axum::http::StatusCode::from_u16(400).expect("valid status"),
            Self::BoxNotFound => axum::http::StatusCode::from_u16(404).expect("valid status"),
            Self::ChangeAddressUntracked => {
                axum::http::StatusCode::from_u16(409).expect("valid status")
            }
            Self::InsufficientFunds => axum::http::StatusCode::from_u16(400).expect("valid status"),
            Self::InternalError => axum::http::StatusCode::from_u16(500).expect("valid status"),
            Self::Invalid => axum::http::StatusCode::from_u16(400).expect("valid status"),
            Self::InvalidAddress => axum::http::StatusCode::from_u16(400).expect("valid status"),
            Self::InvalidCursor => axum::http::StatusCode::from_u16(400).expect("valid status"),
            Self::InvalidParams => axum::http::StatusCode::BAD_REQUEST,
            Self::NodeUnavailable => axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Self::MissingSecret => axum::http::StatusCode::from_u16(409).expect("valid status"),
            Self::RateLimited => axum::http::StatusCode::from_u16(429).expect("valid status"),
            Self::RouteUnavailable => axum::http::StatusCode::from_u16(503).expect("valid status"),
            Self::ScanNotFound => axum::http::StatusCode::from_u16(404).expect("valid status"),
            Self::SensitiveOpDisabled => {
                axum::http::StatusCode::from_u16(409).expect("valid status")
            }
            Self::ShuttingDown => axum::http::StatusCode::from_u16(503).expect("valid status"),
            Self::StaleCandidate => axum::http::StatusCode::from_u16(400).expect("valid status"),
            Self::StateUnavailable => axum::http::StatusCode::from_u16(503).expect("valid status"),
            Self::TxNotFound => axum::http::StatusCode::from_u16(404).expect("valid status"),
            Self::UnsupportedIntent => axum::http::StatusCode::from_u16(422).expect("valid status"),
            Self::WalletUninitialized => {
                axum::http::StatusCode::from_u16(409).expect("valid status")
            }
            Self::WrongPassword => axum::http::StatusCode::from_u16(401).expect("valid status"),
        }
    }
}
pub(super) fn v1_error(
    reason: Reason,
    message: impl Into<String>,
    detail: impl Into<String>,
) -> Response {
    let status = reason.http_status();
    let detail = if status.is_server_error() {
        String::new()
    } else {
        detail.into()
    };
    (
        status,
        Json(json!({ "error": { "reason":reason, "message":message.into(), "detail":detail } })),
    )
        .into_response()
}
/// Map a [`WalletAdminError`] onto the canonical v1 [`Reason`] envelope.
/// Exhaustive — a new trait variant must choose its v1 reason explicitly,
/// never fall through.
///
/// The v1 `Reason` enum was not extended with wallet-execution reasons, so a
/// few variants map to the closest existing reason (documented inline); the
/// human `detail` disambiguates. `Internal` never leaks its message.
pub(super) fn map_wallet_err(e: WalletAdminError) -> Response {
    use WalletAdminError as E;
    let (reason, message, detail): (Reason, &str, String) = match e {
        E::NodeUnavailable(_) => (
            Reason::NodeUnavailable,
            "the node is unavailable",
            String::new(),
        ),
        E::ShuttingDown => (
            Reason::ShuttingDown,
            "the wallet is shutting down",
            String::new(),
        ),
        E::Uninitialized => (
            Reason::WalletUninitialized,
            "the wallet is not initialized",
            "initialize or restore a wallet first".into(),
        ),
        // No dedicated `wallet_locked` reason exists in the v1 set; a locked
        // wallet cannot supply a secret, so it maps to `missing_secret` (409)
        // with an actionable detail.
        E::Locked => (
            Reason::MissingSecret,
            "the wallet is locked",
            "unlock the wallet before this operation".into(),
        ),
        E::InvalidMnemonic => (
            Reason::BadRequest,
            "the mnemonic is invalid",
            "check the recovery phrase words and order".into(),
        ),
        E::WrongPassword => (
            Reason::WrongPassword,
            "the wallet password is incorrect",
            String::new(),
        ),
        E::RestorePruningUnsupported => (
            Reason::RouteUnavailable,
            "restore is not available on a pruned node",
            "run against an unpruned node to restore".into(),
        ),
        E::ChangeAddressUntracked => (
            Reason::ChangeAddressUntracked,
            "the change address is not a tracked wallet key",
            String::new(),
        ),
        E::BadRequest(d) => (Reason::BadRequest, "the request is invalid", d),
        E::StaleChainTip(d) => (
            Reason::StaleCandidate,
            "the committed chain tip changed; retry",
            d,
        ),
        E::Internal(_) => (
            Reason::InternalError,
            "the wallet operation failed",
            String::new(),
        ),
        E::Forbidden(_) | E::SensitiveOpDisabled => (
            Reason::SensitiveOpDisabled,
            "this sensitive operation is disabled by node config",
            "set [wallet] expose_private_keys = true to enable it".into(),
        ),
        // No `wallet_exists` / `derivation_path_exists` reason in the v1 set;
        // both are client-correctable conflicts → bad_request with detail.
        E::WalletExists => (
            Reason::BadRequest,
            "a wallet already exists",
            "a node holds at most one wallet; lock/restore instead".into(),
        ),
        E::DerivationPathExists => (
            Reason::BadRequest,
            "that derivation path is already tracked",
            "the key at this path is already registered".into(),
        ),
        E::AddressNotTracked => (
            Reason::BadRequest,
            "the address is not tracked by this wallet",
            "derive or import the address before using it".into(),
        ),
        E::ScanInvalidated => (
            Reason::StateUnavailable,
            "wallet scan invalidated",
            E::ScanInvalidated.to_string(),
        ),
        E::RescanUnavailable(d) => (
            Reason::RouteUnavailable,
            "rescan is not available on this backend",
            d,
        ),
        E::AcknowledgementRequired => (
            Reason::AcknowledgementRequired,
            "this operation requires an explicit acknowledgement",
            "resend with acknowledge = true".into(),
        ),
        E::RateLimited => (
            Reason::RateLimited,
            "too many sensitive operations",
            "retry after the rate window".into(),
        ),
        E::BoxNotFound => (Reason::BoxNotFound, "the box was not found", String::new()),
        E::UnsupportedScript => (
            Reason::UnsupportedIntent,
            "the input script is not supported for this operation",
            String::new(),
        ),
        E::MissingSecret => (
            Reason::MissingSecret,
            "a required prover secret is missing",
            "supply an external secret covering every input".into(),
        ),
        E::UnsupportedIntent => (
            Reason::UnsupportedIntent,
            "the intent is well-formed but not yet supported",
            String::new(),
        ),
        E::ReemissionObligationUnmet(d) => (
            Reason::Invalid,
            "the transaction violates the EIP-27 re-emission rule",
            d,
        ),
        E::InsufficientFunds(d) => (
            Reason::InsufficientFunds,
            "the wallet cannot cover the requested target",
            d,
        ),
        E::ReemissionSpendNotAllowed(d) => (
            Reason::BadRequest,
            "a reward box would be spent but allow_reemission_spend is false",
            d,
        ),
        E::TokenBurnNotAllowed(d) => (
            Reason::BadRequest,
            "a token surplus would be burned but allow_token_burn is false",
            d,
        ),
        E::TxNotFound => (
            Reason::TxNotFound,
            "the transaction was not found",
            String::new(),
        ),
    };
    v1_error(reason, message, detail)
}

/// `POST /api/v1/accounts/watch` request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WatchRequest {
    address: String,
    #[serde(default)]
    label: Option<String>,
}

/// `?limit=&cursor=` for the watch list.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct WatchListQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ScanIdCursor {
    after: u16,
}

/// `POST /api/v1/accounts/watch` — register a watch-only address as an
/// `equals(R1, <script>)` scan (`scan_p2s_rule`), tracked but never spendable.
/// T1. Reuses the scan primitive; no second tracking mechanism.
pub(crate) async fn watch_register(
    State(state): State<AccountsState>,
    body: CollectionJson<WatchRequest>,
) -> Response {
    let CollectionJson(body) = body;
    if let Err(_e) = decode_address_to_tree_bytes(&body.address, state.network) {
        return v1_error(
            Reason::InvalidAddress,
            "the address is not valid base58 for this network",
            String::new(),
        );
    }
    match state.admin.scan_p2s_rule(body.address.clone()).await {
        Ok(scan_id) => Json(json!({
            "address": body.address,
            "scan_id": scan_id,
            // The scan registry has no label column; the label is echoed but
            // not persisted (a durable watch registry is Phase-2).
            "label": body.label,
        }))
        .into_response(),
        Err(e) => map_wallet_err(e),
    }
}

/// `GET /api/v1/accounts/watch?limit=&cursor=` — watch-only scans (the
/// `wallet_interaction = "off"` marker), ascending by `scan_id`. T0.
///
/// The scan registry stores no watch label / originating address, so those are
/// `null` here (Phase-2 durable watch registry); `tracking_rule` is the opaque
/// predicate the scan was registered with.
pub(crate) async fn watch_list(
    State(state): State<AccountsState>,
    q: CollectionQuery<WatchListQuery>,
) -> Response {
    let CollectionQuery(q) = q;
    let limit = clamp_limit(q.limit, 50, 500);
    let after = match decode_opt_cursor::<ScanIdCursor>(q.cursor.as_deref()) {
        Ok(c) => c.map(|c| c.after),
        Err(e) => return *e,
    };
    let scans = match state.admin.list_scans().await {
        Ok(s) => s,
        Err(e) => return map_wallet_err(e),
    };
    let mut rows: Vec<serde_json::Value> = scans
        .into_iter()
        .filter(|s| s.wallet_interaction.eq_ignore_ascii_case("off"))
        .filter(|s| after.is_none_or(|a| s.scan_id > a))
        .take(limit as usize + 1)
        .map(|s| {
            json!({
                "scan_id": s.scan_id,
                "address": serde_json::Value::Null,
                "label": serde_json::Value::Null,
                "tracking_rule": s.tracking_rule,
                "wallet_interaction": s.wallet_interaction,
            })
        })
        .collect();
    let has_more = rows.len() as u64 > u64::from(limit);
    if has_more {
        rows.truncate(limit as usize);
    }
    let next_cursor = has_more
        .then(|| {
            rows.last()
                .and_then(|v| v.get("scan_id").and_then(serde_json::Value::as_u64))
                .map(|id| encode_cursor(&ScanIdCursor { after: id as u16 }))
        })
        .flatten();
    let has_more = next_cursor.is_some();
    Json(json!({
        "items": rows,
        "page": Page { limit, next_cursor, has_more },
    }))
    .into_response()
}

/// `DELETE /api/v1/accounts/watch/{scan_id}` — deregister a watch-only scan. T1.
pub(crate) async fn watch_delete(
    State(state): State<AccountsState>,
    Path(scan_id): Path<u16>,
) -> Response {
    let scans = match state.admin.list_scans().await {
        Ok(scans) => scans,
        Err(error) => return map_wallet_err(error),
    };
    if !scans
        .iter()
        .any(|scan| scan.scan_id == scan_id && scan.wallet_interaction.eq_ignore_ascii_case("off"))
    {
        return v1_error(
            Reason::AddressNotWatched,
            "no watch-only scan with that id",
            String::new(),
        );
    }
    match state.admin.deregister_scan(scan_id).await {
        Ok(()) => Json(json!({ "scan_id": scan_id })).into_response(),
        Err(WalletAdminError::BadRequest(_)) => v1_error(
            Reason::AddressNotWatched,
            "no watch-only scan with that id",
            format!("scan {scan_id} is not registered"),
        ),
        Err(e) => map_wallet_err(e),
    }
}

// ==========================================================================
//  T2 — private-key export (BACKED via get_private_key)
// ==========================================================================

/// `POST /api/v1/accounts/private-key` request. T2 (admin + loopback-preferred).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateKeyRequest {
    address: String,
    #[serde(default)]
    acknowledge: bool,
}

/// `POST /api/v1/accounts/private-key` — export the raw secp256k1 scalar for a
/// tracked address (the spec's `wallet/keys/derive-at-path`, relocated to a
/// collision-free T2 mount). Requires `acknowledge = true` AND
/// `[wallet] expose_private_keys = true`. `Cache-Control: no-store`.
///
/// The T2 gate (admin api-key + loopback-preferred) is enforced by the
/// route_layer BEFORE this handler runs — a secret scalar is unreachable at
/// T0/T1 and, under hard-deny, from any non-loopback caller.
pub(crate) async fn private_key(
    State(state): State<AccountsState>,
    body: CollectionJson<PrivateKeyRequest>,
) -> Response {
    let CollectionJson(body) = body;
    if !body.acknowledge {
        return v1_error(
            Reason::AcknowledgementRequired,
            "exporting a private key requires an explicit acknowledgement",
            "resend with acknowledge = true",
        );
    }
    if let Err(_e) = decode_address_to_tree_bytes(&body.address, state.network) {
        return v1_error(
            Reason::InvalidAddress,
            "the address is not valid base58 for this network",
            String::new(),
        );
    }
    match state
        .admin
        .get_private_key(GetPrivateKeyRequest {
            address: body.address,
        })
        .await
    {
        Ok(resp) => (
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(json!({ "private_key": resp.w })),
        )
            .into_response(),
        Err(e) => map_wallet_err(e),
    }
}
