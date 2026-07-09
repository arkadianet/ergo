//! `/api/v1/scan/*` + `/api/v1/accounts/*` — the native scan registry, the
//! account-abstraction subsystem (named accounts, watch-only addresses,
//! PSBT-like partial signing), and the T2 private-key export
//! (`v1-api-design.md` §3.10–§3.11).
//!
//! **Mount seam / collision note.** The pre-existing native `/api/v1/wallet/*`
//! surface owns that whole prefix (including a `*rest` catch-all), exactly as
//! the frozen compat mount owns `node/shutdown`. A sibling router adding new
//! `/api/v1/wallet/*` paths would make `axum::Router::merge` panic on the
//! overlapping catch-all, so this group mounts ONLY prefixes it fully owns —
//! `/api/v1/scan/*` and `/api/v1/accounts/*` — and hosts the T2 secret export
//! under `/api/v1/accounts/private-key` rather than the spec's
//! `/api/v1/wallet/keys/derive-at-path` (see the report's design-corrections).
//!
//! **Tiers.**
//! * **T0** (governor-bounded, no auth): watch-only reads (`accounts/watch` list
//!   + `accounts/watch/{scan_id}/unspent`) — a watch address is public info.
//! * **T1** (operator api-key): all `scan/*`, watch register/delete, and the
//!   named-account + PSBT surfaces (which answer `route_unavailable` until the
//!   accounts subsystem is built — honest seam, never a fabricated balance).
//! * **T2** (admin api-key + loopback-preferred): `accounts/private-key`
//!   (exports the raw secret scalar). Gated by the fail-closed
//!   [`require_tier`](crate::v1::auth::require_tier) at `Tier::Admin` — a secret
//!   export is unreachable at T0/T1 and, under `admin_hard_deny_nonloopback`,
//!   from any non-loopback caller.
//!
//! Every backed endpoint reuses the existing [`WalletAdmin`](crate::wallet::WalletAdmin)
//! machinery (scan trait methods, `scan_p2s_rule`, `get_private_key`); nothing
//! here reimplements scan matching or key derivation.

mod scan;

use utoipa::ToSchema;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use ergo_ser::address::{decode_address_to_tree_bytes, NetworkPrefix};

use crate::v1::auth::{require_tier, Tier, V1AuthConfig};
use crate::v1::cursor::{clamp_limit, decode_opt_cursor, encode_cursor, Page};
use crate::v1::error::{v1_error, Reason, V1Error};
use crate::v1::governor::{governor_mw, Governor, RouteClass};
use crate::v1::routes::extract::{V1Json, V1Query};
use crate::wallet::admin_advanced::GetPrivateKeyRequest;
use crate::wallet::{WalletAdmin, WalletAdminError};

/// Shared state for the scan/accounts group: the wallet-admin bridge (the scan
/// and key machinery) plus the address-encoding network prefix (watch-only and
/// secret-export address validation).
#[derive(Clone)]
pub struct AccountsState {
    /// The wallet admin bridge — every backed endpoint projects off this.
    pub admin: Arc<dyn WalletAdmin>,
    /// Address-encoding network prefix (mainnet/testnet).
    pub network: NetworkPrefix,
}

/// Map a [`WalletAdminError`] onto the canonical v1 [`Reason`] envelope
/// (`v1-api-design.md` §1.4). Exhaustive — a new trait variant must choose its
/// v1 reason explicitly, never fall through.
///
/// The v1 `Reason` enum was not extended with wallet-execution reasons, so a
/// few variants map to the closest existing reason (documented inline); the
/// human `detail` disambiguates. `Internal` never leaks its message.
pub(super) fn map_wallet_err(e: WalletAdminError) -> Response {
    use WalletAdminError as E;
    let (reason, message, detail): (Reason, &str, String) = match e {
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

/// A boxed `route_unavailable` seam for a net-new capability with no node
/// backing yet (`v1-api-design.md` §1.4). Honest: never a fabricated success.
fn seam(what: &str, detail: &str) -> Response {
    v1_error(
        Reason::RouteUnavailable,
        format!("the {what} subsystem is not wired on this node"),
        detail.to_string(),
    )
}

// ==========================================================================
//  Watch-only addresses (BACKED via the scan registry)
// ==========================================================================

/// `POST /api/v1/accounts/watch` request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct WatchRequest {
    address: String,
    #[serde(default)]
    label: Option<String>,
}

/// `?limit=&cursor=` for the watch list.
#[derive(Debug, Default, Deserialize, ToSchema)]
struct WatchListQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, ToSchema)]
struct ScanIdCursor {
    after: u16,
}

/// `POST /api/v1/accounts/watch` — register a watch-only address as an
/// `equals(R1, <script>)` scan (`scan_p2s_rule`), tracked but never spendable.
/// T1. Reuses the scan primitive; no second tracking mechanism.
#[utoipa::path(
    post, path = "/api/v1/accounts/watch", tag = "accounts",
    request_body = WatchRequest,
    responses(
        (status = 200, description = "Registered — `{ address, scan_id, label }`", body = serde_json::Value),
        (status = 400, description = "Invalid address", body = V1Error),
        (status = 409, description = "Wallet uninitialized or locked", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
async fn watch_register(
    State(state): State<AccountsState>,
    body: V1Json<WatchRequest>,
) -> Response {
    let V1Json(body) = body;
    if let Err(e) = decode_address_to_tree_bytes(&body.address, state.network) {
        return v1_error(
            Reason::InvalidAddress,
            "the address is not valid base58 for this network",
            e.to_string(),
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
#[utoipa::path(
    get, path = "/api/v1/accounts/watch", tag = "accounts",
    params(
        ("limit" = Option<u32>, Query, description = "Page size (default 50, cap 500)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
    ),
    responses(
        (status = 200, description = "Watch-only scans — `{ items, page }` (address/label always null; Phase-2 durable registry)", body = serde_json::Value),
        (status = 400, description = "Invalid cursor", body = V1Error),
        (status = 409, description = "Wallet uninitialized or locked", body = V1Error),
    ),
)]
async fn watch_list(State(state): State<AccountsState>, q: V1Query<WatchListQuery>) -> Response {
    let V1Query(q) = q;
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
#[utoipa::path(
    delete, path = "/api/v1/accounts/watch/{scan_id}", tag = "accounts",
    params(("scan_id" = u16, Path, description = "Registered watch-only scan id")),
    responses(
        (status = 200, description = "Deregistered — `{ scan_id }`", body = serde_json::Value),
        (status = 404, description = "No watch-only scan with that id", body = V1Error),
        (status = 409, description = "Wallet uninitialized or locked", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
async fn watch_delete(State(state): State<AccountsState>, Path(scan_id): Path<u16>) -> Response {
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
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct PrivateKeyRequest {
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
#[utoipa::path(
    post, path = "/api/v1/accounts/private-key", tag = "accounts",
    request_body = PrivateKeyRequest,
    responses(
        (status = 200, description = "Raw secp256k1 scalar — `{ private_key }` (Cache-Control: no-store)", body = serde_json::Value),
        (status = 400, description = "Invalid address", body = V1Error),
        (status = 409, description = "Missing acknowledgement, wallet uninitialized/locked, or sensitive-op disabled by config", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
async fn private_key(
    State(state): State<AccountsState>,
    body: V1Json<PrivateKeyRequest>,
) -> Response {
    let V1Json(body) = body;
    if !body.acknowledge {
        return v1_error(
            Reason::AcknowledgementRequired,
            "exporting a private key requires an explicit acknowledgement",
            "resend with acknowledge = true",
        );
    }
    if let Err(e) = decode_address_to_tree_bytes(&body.address, state.network) {
        return v1_error(
            Reason::InvalidAddress,
            "the address is not valid base58 for this network",
            e.to_string(),
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

// ==========================================================================
//  Named accounts + PSBT (honest seams — no node backing yet)
// ==========================================================================

/// Any named-account route (`v1-api-design.md` §3.11). Net-new subsystem with
/// no `account_id` model in the wallet layer today → honest `route_unavailable`.
/// Representative mount for the whole named-accounts family — every method on
/// `/api/v1/accounts`, `/api/v1/accounts/{account_id}`,
/// `/api/v1/accounts/{account_id}/balance`, and
/// `/api/v1/accounts/{account_id}/addresses` shares this SAME handler and
/// answers identically.
#[utoipa::path(
    get, path = "/api/v1/accounts", tag = "accounts",
    responses(
        (status = 503, description = "Named-accounts subsystem not wired on this node (same answer on every named-accounts route/method)", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
async fn accounts_seam() -> Response {
    seam(
        "named-accounts",
        "accounts are a label over a BIP-44 derivation subtree; the durable \
         account registry is not built yet (v1-api-design.md §3.11)",
    )
}

/// Any PSBT-session route (`v1-api-design.md` §3.11). The commitment/hint math
/// exists (`generate_commitments`/`extract_hints`) but the durable session +
/// threshold state + a hints-bag sign variant do not → honest
/// `route_unavailable`, never a faked partial signature. Representative mount
/// for the whole PSBT family — every method on `/api/v1/transactions-psbt`,
/// `/api/v1/transactions-psbt/{psbt_id}`,
/// `/api/v1/transactions-psbt/{psbt_id}/contributions`, and
/// `/api/v1/transactions-psbt/{psbt_id}/finalize` shares this SAME handler and
/// answers identically.
#[utoipa::path(
    post, path = "/api/v1/transactions-psbt", tag = "accounts",
    responses(
        (status = 503, description = "PSBT-session subsystem not wired on this node (same answer on every psbt route/method)", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
async fn psbt_seam() -> Response {
    seam(
        "psbt-session",
        "PSBT-like partial signing needs a durable session store and a \
         hints-bag sign variant that are not wired yet (v1-api-design.md §3.11)",
    )
}

// ==========================================================================
//  Router
// ==========================================================================

/// Build the scan/accounts router. Three tier layers over one [`AccountsState`],
/// mirroring [`crate::v1::operator_router`]:
/// T0 (governor `CheapRead`) for watch reads, T1 (`require_tier(Operator)`) for
/// scan + watch writes + the account/PSBT seams, T2 (`require_tier(Admin)`) for
/// the private-key export. State-erased for merging under `/api/v1`.
pub fn accounts_router(
    state: AccountsState,
    governor: Arc<Governor>,
    auth: Arc<V1AuthConfig>,
) -> Router {
    // ----- T0: watch-only reads (public info, governor-bounded) -----
    let t0: Router<AccountsState> = Router::new()
        .route("/api/v1/accounts/watch", get(watch_list))
        .route(
            "/api/v1/accounts/watch/:scan_id/unspent",
            // Watch-only-scoped: a wallet-interacting scan is `scan_not_found`
            // on this PUBLIC mount (the unscoped read stays on the T1 mount).
            get(scan::watch_unspent),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            governor.state(RouteClass::CheapRead),
            governor_mw,
        ));

    // ----- T1: operator (api_key) -----
    let t1: Router<AccountsState> = Router::new()
        // scan/*
        .route("/api/v1/scan/scans", post(scan::register).get(scan::list))
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
        // watch-only writes
        .route("/api/v1/accounts/watch", post(watch_register))
        .route("/api/v1/accounts/watch/:scan_id", delete(watch_delete))
        // named accounts (seam)
        .route("/api/v1/accounts", get(accounts_seam).post(accounts_seam))
        .route(
            "/api/v1/accounts/:account_id",
            get(accounts_seam)
                .patch(accounts_seam)
                .delete(accounts_seam),
        )
        .route("/api/v1/accounts/:account_id/balance", get(accounts_seam))
        .route(
            "/api/v1/accounts/:account_id/addresses",
            get(accounts_seam).post(accounts_seam),
        )
        // PSBT (seam)
        .route("/api/v1/transactions-psbt", post(psbt_seam))
        .route("/api/v1/transactions-psbt/:psbt_id", get(psbt_seam))
        .route(
            "/api/v1/transactions-psbt/:psbt_id/contributions",
            post(psbt_seam),
        )
        .route(
            "/api/v1/transactions-psbt/:psbt_id/finalize",
            post(psbt_seam),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            auth.state(Tier::Operator),
            require_tier,
        ));

    // ----- T2: admin (api_key + loopback-preferred) — secret export -----
    let t2: Router<AccountsState> = Router::new()
        .route("/api/v1/accounts/private-key", post(private_key))
        .route_layer(axum::middleware::from_fn_with_state(
            auth.state(Tier::Admin),
            require_tier,
        ));

    t0.merge(t1).merge(t2).with_state(state)
}
