//! `/api/v1/scan/*` — the native scan-registry surface. All **T1**
//! (operator api-key). Every route reuses the existing
//! [`WalletAdmin`](crate::wallet::WalletAdmin) scan machinery
//! (`register_scan`/`list_scans`/`deregister_scan`/`scan_unspent_boxes`/
//! `scan_add_box`/`scan_stop_tracking`/`transactions_by_scan_id`) — this is
//! route + DTO adaptation to the v1 envelope, never a reimplementation of scan
//! matching.
//!
//! Case/envelope adaptation over the frozen Scala-compat `/scan/*` shapes:
//! camelCase → snake_case, the `{items, page}` cursor envelope, and the nested
//! `{error:{reason,…}}` family. The compat `/scan/*` router is untouched.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use super::{map_wallet_err, AccountsState};
use crate::v1::cursor::{clamp_limit, decode_opt_cursor, encode_cursor, Page};
use crate::v1::error::{v1_error, Reason, V1Error};
use crate::v1::routes::dto::Collection;
use crate::v1::routes::extract::{V1Json, V1Query};
use crate::wallet::scan::{ScanBoxFilter, ScanDto, ScanRequestDto};
use crate::wallet::types;

/// Default page size for the scan collections.
const SCAN_DEFAULT_LIMIT: u32 = 50;
/// Page cap for the scan box collections: ONE BELOW the `ScanBoxFilter`
/// validator's hard 1..=2500 bound, so the overfetch-by-one probe
/// (`limit + 1`) always fits it — at 2500 the probe itself was rejected,
/// turning a valid `?limit=2500` into a 400. A larger `?limit` clamps here
/// (same clamp semantics as every other v1 collection).
const SCAN_BOX_MAX_LIMIT: u32 = 2499;
/// Cap for the scan-list / scan-transactions collections.
const SCAN_LIST_MAX_LIMIT: u32 = 500;

// ----- wire DTOs ----------------------------------------------------------

/// `POST /api/v1/scan/scans` request — register a scan. `tracking_rule` stays an
/// opaque JSON value for Phase-1 (`ergo-api` deliberately does not depend on the
/// `ScanningPredicate` schema); a typed tagged union is Phase-2.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanRegisterRequest {
    name: String,
    tracking_rule: serde_json::Value,
    #[serde(default)]
    wallet_interaction: Option<String>,
    #[serde(default)]
    remove_offchain: Option<bool>,
}

/// A registered scan, snake_case.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ScanView {
    scan_id: u16,
    name: String,
    tracking_rule: serde_json::Value,
    wallet_interaction: String,
    remove_offchain: bool,
}

impl From<ScanDto> for ScanView {
    fn from(s: ScanDto) -> Self {
        ScanView {
            scan_id: s.scan_id,
            name: s.scan_name,
            tracking_rule: s.tracking_rule,
            wallet_interaction: s.wallet_interaction,
            remove_offchain: s.remove_offchain,
        }
    }
}

/// A box tracked by a scan (unspent surface). `spent_by` is always `null` here
/// (the `/unspent` endpoint) — carried only for shape parity with a future
/// `/spent` surface. `value` is a decimal string.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ScanBoxView {
    box_id: String,
    value: String,
    inclusion_height: Option<u32>,
    confirmations: Option<i64>,
    spent_by: Option<String>,
    bytes: String,
}

/// `?limit=&cursor=` for the scan-list / scan-transactions collections.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct ListQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

/// `?limit=&cursor=&min_confirmations=&…` for `/unspent`. The confirmation /
/// inclusion-height bounds are ported verbatim from `ScanBoxFilter`.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct ScanBoxQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    min_confirmations: Option<i32>,
    max_confirmations: Option<i32>,
    min_inclusion_height: Option<i32>,
    max_inclusion_height: Option<i32>,
}

/// `POST /api/v1/scan/scans/{scan_id}/boxes` request — attach a box (opaque
/// `ErgoBox` JSON parsed in `ergo-node`).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachBoxRequest {
    #[serde(rename = "box")]
    box_json: serde_json::Value,
}

/// Cursor for the scan list — ascending `scan_id`, resume after the last seen.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct ScanIdCursor {
    after: u16,
}

/// Opaque offset cursor for the box / transaction collections, whose underlying
/// trait calls are offset/limit paged. Opaque so a keyset seek can replace it
/// without a wire break.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct OffsetCursor {
    off: u32,
}

// ----- handlers -----------------------------------------------------------

/// `POST /api/v1/scan/scans` — register a scan, returning its allocated id.
#[utoipa::path(
    post, path = "/api/v1/scan/scans", tag = "scan",
    request_body = ScanRegisterRequest,
    responses(
        (status = 201, description = "Registered — `{ scan_id }`", body = serde_json::Value),
        (status = 400, description = "Invalid tracking_rule/wallet_interaction", body = V1Error),
        (status = 409, description = "Wallet uninitialized or locked", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub async fn register(
    State(state): State<AccountsState>,
    body: V1Json<ScanRegisterRequest>,
) -> Response {
    let V1Json(body) = body;
    let req = ScanRequestDto {
        scan_name: body.name,
        tracking_rule: body.tracking_rule,
        wallet_interaction: body.wallet_interaction,
        remove_offchain: body.remove_offchain,
    };
    match state.admin.register_scan(req).await {
        Ok(scan_id) => (
            axum::http::StatusCode::CREATED,
            Json(json!({ "scan_id": scan_id })),
        )
            .into_response(),
        Err(e) => map_wallet_err(e),
    }
}

/// `GET /api/v1/scan/scans?limit=&cursor=` — every registered scan, ascending
/// by `scan_id`, cursor-paginated on that natural key.
#[utoipa::path(
    get, path = "/api/v1/scan/scans", tag = "scan",
    params(
        ("limit" = Option<u32>, Query, description = "Page size (default 50, cap 500)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
    ),
    responses(
        (status = 200, description = "Registered scans — `{ items, page }`", body = serde_json::Value),
        (status = 400, description = "Invalid cursor", body = V1Error),
        (status = 409, description = "Wallet uninitialized or locked", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub async fn list(State(state): State<AccountsState>, q: V1Query<ListQuery>) -> Response {
    let V1Query(q) = q;
    let limit = clamp_limit(q.limit, SCAN_DEFAULT_LIMIT, SCAN_LIST_MAX_LIMIT);
    let after = match decode_opt_cursor::<ScanIdCursor>(q.cursor.as_deref()) {
        Ok(c) => c.map(|c| c.after),
        Err(e) => return *e,
    };
    let scans = match state.admin.list_scans().await {
        Ok(s) => s,
        Err(e) => return map_wallet_err(e),
    };
    // `list_scans` is already ascending by id; seek past the cursor then
    // overfetch-by-one for `has_more`.
    let mut rows: Vec<ScanView> = scans
        .into_iter()
        .filter(|s| after.is_none_or(|a| s.scan_id > a))
        .take(limit as usize + 1)
        .map(ScanView::from)
        .collect();
    let (items, page) = Page::from_overfetch(std::mem::take(&mut rows), limit, |v| ScanIdCursor {
        after: v.scan_id,
    });
    Json(json!({ "items": items, "page": page })).into_response()
}

/// `GET /api/v1/scan/scans/{scan_id}` — a single scan (filters `list_scans`).
/// A missing id is `404 scan_not_found` (a GET must 404 on absence, never the
/// compat 400).
#[utoipa::path(
    get, path = "/api/v1/scan/scans/{scan_id}", tag = "scan",
    params(("scan_id" = u16, Path, description = "Registered scan id")),
    responses(
        (status = 200, description = "The scan", body = ScanView),
        (status = 404, description = "No scan with that id", body = V1Error),
        (status = 409, description = "Wallet uninitialized or locked", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub async fn get_one(State(state): State<AccountsState>, Path(scan_id): Path<u16>) -> Response {
    let scans = match state.admin.list_scans().await {
        Ok(s) => s,
        Err(e) => return map_wallet_err(e),
    };
    match scans.into_iter().find(|s| s.scan_id == scan_id) {
        Some(s) => Json(ScanView::from(s)).into_response(),
        None => scan_not_found(scan_id),
    }
}

/// `DELETE /api/v1/scan/scans/{scan_id}` — deregister a scan. The trait treats a
/// missing id as `bad_request`; this surface maps that to `404 scan_not_found`
/// so a DELETE of an absent scan reads as "gone", not "malformed".
#[utoipa::path(
    delete, path = "/api/v1/scan/scans/{scan_id}", tag = "scan",
    params(("scan_id" = u16, Path, description = "Registered scan id")),
    responses(
        (status = 200, description = "Deregistered — `{ scan_id }`", body = serde_json::Value),
        (status = 404, description = "No scan with that id", body = V1Error),
        (status = 409, description = "Wallet uninitialized or locked", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub async fn deregister(State(state): State<AccountsState>, Path(scan_id): Path<u16>) -> Response {
    match state.admin.deregister_scan(scan_id).await {
        Ok(()) => Json(json!({ "scan_id": scan_id })).into_response(),
        // The trait's missing-id error is `BadRequest`; re-map to 404 here.
        Err(crate::wallet::WalletAdminError::BadRequest(_)) => scan_not_found(scan_id),
        Err(e) => map_wallet_err(e),
    }
}

/// `GET /api/v1/accounts/watch/{scan_id}/unspent` — the T0 (public) mount of
/// the unspent read, scoped to WATCH-ONLY scans exactly like `watch_list`
/// (`wallet_interaction = "off"`): a wallet-interacting operator scan answers
/// `scan_not_found` here, so the public route can never read it — only the T1
/// api-key mount (`scan/scans/{id}/unspent`) can.
#[utoipa::path(
    get, path = "/api/v1/accounts/watch/{scan_id}/unspent", tag = "scan",
    params(
        ("scan_id" = u16, Path, description = "Registered WATCH-ONLY scan id"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, cap 2499)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
        ("min_confirmations" = Option<i32>, Query, description = "Minimum confirmations"),
        ("max_confirmations" = Option<i32>, Query, description = "Maximum confirmations (-1 = unbounded)"),
        ("min_inclusion_height" = Option<i32>, Query, description = "Minimum inclusion height"),
        ("max_inclusion_height" = Option<i32>, Query, description = "Maximum inclusion height (-1 = unbounded)"),
    ),
    responses(
        (status = 200, description = "Unspent boxes tracked by this watch-only scan", body = Collection<ScanBoxView>),
        (status = 400, description = "Invalid filter bounds/cursor", body = V1Error),
        (status = 404, description = "No watch-only scan with that id", body = V1Error),
        (status = 409, description = "Wallet uninitialized or locked", body = V1Error),
    ),
)]
pub async fn watch_unspent(
    State(state): State<AccountsState>,
    Path(scan_id): Path<u16>,
    q: V1Query<ScanBoxQuery>,
) -> Response {
    let scans = match state.admin.list_scans().await {
        Ok(s) => s,
        Err(e) => return map_wallet_err(e),
    };
    let is_watch_only = scans
        .iter()
        .any(|s| s.scan_id == scan_id && s.wallet_interaction.eq_ignore_ascii_case("off"));
    if !is_watch_only {
        return scan_not_found(scan_id);
    }
    unspent(State(state), Path(scan_id), q).await
}

/// `GET /api/v1/scan/scans/{scan_id}/unspent` — unspent boxes tracked by a scan.
#[utoipa::path(
    get, path = "/api/v1/scan/scans/{scan_id}/unspent", tag = "scan",
    params(
        ("scan_id" = u16, Path, description = "Registered scan id"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, cap 2499)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
        ("min_confirmations" = Option<i32>, Query, description = "Minimum confirmations"),
        ("max_confirmations" = Option<i32>, Query, description = "Maximum confirmations (-1 = unbounded)"),
        ("min_inclusion_height" = Option<i32>, Query, description = "Minimum inclusion height"),
        ("max_inclusion_height" = Option<i32>, Query, description = "Maximum inclusion height (-1 = unbounded)"),
    ),
    responses(
        (status = 200, description = "Unspent boxes tracked by this scan", body = Collection<ScanBoxView>),
        (status = 400, description = "Invalid filter bounds/cursor", body = V1Error),
        (status = 409, description = "Wallet uninitialized or locked", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub async fn unspent(
    State(state): State<AccountsState>,
    Path(scan_id): Path<u16>,
    q: V1Query<ScanBoxQuery>,
) -> Response {
    let V1Query(q) = q;
    let limit = clamp_limit(q.limit, SCAN_DEFAULT_LIMIT, SCAN_BOX_MAX_LIMIT);
    let off = match decode_opt_cursor::<OffsetCursor>(q.cursor.as_deref()) {
        Ok(c) => c.map(|c| c.off).unwrap_or(0),
        Err(e) => return *e,
    };
    // Overfetch-by-one via the offset/limit trait call.
    let filter = ScanBoxFilter {
        min_confirmations: q.min_confirmations.unwrap_or(0),
        max_confirmations: q.max_confirmations.unwrap_or(-1),
        min_inclusion_height: q.min_inclusion_height.unwrap_or(0),
        max_inclusion_height: q.max_inclusion_height.unwrap_or(-1),
        limit: (limit as i32).saturating_add(1),
        offset: off as i32,
    };
    if let Err(e) = filter.validate() {
        return map_wallet_err(e);
    }
    let boxes = match state.admin.scan_unspent_boxes(scan_id, filter).await {
        Ok(b) => b,
        Err(e) => return map_wallet_err(e),
    };
    let views: Vec<ScanBoxView> = boxes
        .into_iter()
        .map(|b| ScanBoxView {
            box_id: b.box_id,
            value: b.value.to_string(),
            inclusion_height: b.inclusion_height,
            confirmations: b.confirmations_num,
            spent_by: None,
            bytes: b.bytes,
        })
        .collect();
    offset_page(views, limit, off)
}

/// `GET /api/v1/scan/scans/{scan_id}/transactions` — wallet transactions tagged
/// with this scan id. An unknown/deregistered id is an empty page, not 404
/// (trait contract). Item = the wallet tx summary + `scan_ids`.
#[utoipa::path(
    get, path = "/api/v1/scan/scans/{scan_id}/transactions", tag = "scan",
    params(
        ("scan_id" = u16, Path, description = "Registered scan id (unknown/deregistered id → empty page)"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, cap 500)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
    ),
    responses(
        (status = 200, description = "Wallet transactions tagged with this scan id — `{ items, page }`", body = serde_json::Value),
        (status = 400, description = "Invalid cursor", body = V1Error),
        (status = 409, description = "Wallet uninitialized or locked", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub async fn transactions(
    State(state): State<AccountsState>,
    Path(scan_id): Path<u16>,
    q: V1Query<ListQuery>,
) -> Response {
    let V1Query(q) = q;
    let limit = clamp_limit(q.limit, SCAN_DEFAULT_LIMIT, SCAN_LIST_MAX_LIMIT);
    let off = match decode_opt_cursor::<OffsetCursor>(q.cursor.as_deref()) {
        Ok(c) => c.map(|c| c.off).unwrap_or(0),
        Err(e) => return *e,
    };
    let page_in = types::Page {
        offset: off,
        limit: limit.saturating_add(1),
    };
    let txs = match state
        .admin
        .transactions_by_scan_id(u32::from(scan_id), page_in)
        .await
    {
        Ok(p) => p,
        Err(e) => return map_wallet_err(e),
    };
    let views: Vec<serde_json::Value> = txs
        .items
        .into_iter()
        .map(|t| {
            json!({
                "tx_id": t.tx_id,
                "header_id": t.block_id,
                "inclusion_height": t.block_height,
                "wallet_input_box_ids": t.wallet_inputs,
                "wallet_output_box_ids": t.wallet_outputs,
                "scan_ids": t.scan_ids,
            })
        })
        .collect();
    offset_page(views, limit, off)
}

/// `POST /api/v1/scan/scans/{scan_id}/boxes` — manually attach a box.
#[utoipa::path(
    post, path = "/api/v1/scan/scans/{scan_id}/boxes", tag = "scan",
    params(("scan_id" = u16, Path, description = "Registered scan id")),
    request_body = AttachBoxRequest,
    responses(
        (status = 200, description = "Attached — `{ box_id }`", body = serde_json::Value),
        (status = 400, description = "Malformed box JSON", body = V1Error),
        (status = 409, description = "Wallet uninitialized or locked", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub async fn attach_box(
    State(state): State<AccountsState>,
    Path(scan_id): Path<u16>,
    body: V1Json<AttachBoxRequest>,
) -> Response {
    let V1Json(body) = body;
    match state.admin.scan_add_box(vec![scan_id], body.box_json).await {
        Ok(box_id) => Json(json!({ "box_id": box_id })).into_response(),
        Err(e) => map_wallet_err(e),
    }
}

/// `DELETE /api/v1/scan/scans/{scan_id}/boxes/{box_id}` — stop tracking a box
/// (200, idempotent-friendly).
#[utoipa::path(
    delete, path = "/api/v1/scan/scans/{scan_id}/boxes/{box_id}", tag = "scan",
    params(
        ("scan_id" = u16, Path, description = "Registered scan id"),
        ("box_id" = String, Path, description = "64-char lowercase hex box id"),
    ),
    responses(
        (status = 200, description = "Untracked (idempotent) — `{ scan_id, box_id }`", body = serde_json::Value),
        (status = 409, description = "Wallet uninitialized or locked", body = V1Error),
    ),
    security(("ApiKeyAuth" = [])),
)]
pub async fn detach_box(
    State(state): State<AccountsState>,
    Path((scan_id, box_id)): Path<(u16, String)>,
) -> Response {
    match state
        .admin
        .scan_stop_tracking(scan_id, box_id.clone())
        .await
    {
        Ok(()) => Json(json!({ "scan_id": scan_id, "box_id": box_id })).into_response(),
        Err(e) => map_wallet_err(e),
    }
}

// ----- helpers ------------------------------------------------------------

fn scan_not_found(scan_id: u16) -> Response {
    v1_error(
        Reason::ScanNotFound,
        "no scan is registered with that id",
        format!("scan {scan_id} is not registered"),
    )
}

/// Build a `{items, page}` envelope from an overfetched offset window.
fn offset_page<T: Serialize>(mut items: Vec<T>, limit: u32, off: u32) -> Response {
    let has_more = items.len() as u64 > u64::from(limit);
    if has_more {
        items.truncate(limit as usize);
    }
    let next_cursor = has_more.then(|| {
        encode_cursor(&OffsetCursor {
            off: off.saturating_add(limit),
        })
    });
    Json(json!({
        "items": items,
        "page": Page { limit, next_cursor, has_more },
    }))
    .into_response()
}
