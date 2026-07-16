//! Read endpoints for `/wallet/*` — unconditionally mounted, unlike routes
//! gated on node configuration.
//!
//! Routes: balances, addresses, boxes, boxes/unspent, transactions,
//! transactionById, transactionsByScanId/{id}.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

use super::lifecycle::map_err;
use super::types;
use super::WalletAdmin;

#[derive(serde::Deserialize, Default)]
pub struct PageQuery {
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    50
}

#[derive(serde::Deserialize)]
pub struct TxIdQuery {
    pub id: String,
}

pub(crate) async fn balances(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<Json<types::WalletBalances>, (StatusCode, Json<serde_json::Value>)> {
    let b = admin.balances().await.map_err(map_err)?;
    Ok(Json(b))
}

/// `GET /wallet/balances/withUnconfirmed` — confirmed balance with the
/// mempool overlay folded in (same wire shape as `balances`). Mirrors
/// Scala `WalletApiRoute` `balancesWithUnconfirmed`.
pub(crate) async fn balances_with_unconfirmed(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<Json<types::WalletBalances>, (StatusCode, Json<serde_json::Value>)> {
    let b = admin.balances_with_unconfirmed().await.map_err(map_err)?;
    Ok(Json(b))
}

pub(crate) async fn addresses(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<Json<types::WalletAddressList>, (StatusCode, Json<serde_json::Value>)> {
    let a = admin.addresses().await.map_err(map_err)?;
    Ok(Json(a))
}

pub(crate) async fn boxes(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Query(page): Query<PageQuery>,
) -> Result<Json<types::WalletBoxesPage>, (StatusCode, Json<serde_json::Value>)> {
    let r = admin
        .boxes(types::Page {
            offset: page.offset,
            limit: page.limit,
        })
        .await
        .map_err(map_err)?;
    Ok(Json(r))
}

pub(crate) async fn boxes_unspent(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Query(page): Query<PageQuery>,
) -> Result<Json<types::WalletBoxesPage>, (StatusCode, Json<serde_json::Value>)> {
    let r = admin
        .boxes_unspent(types::Page {
            offset: page.offset,
            limit: page.limit,
        })
        .await
        .map_err(map_err)?;
    Ok(Json(r))
}

pub(crate) async fn transactions(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Query(page): Query<PageQuery>,
) -> Result<Json<types::WalletTransactionsPage>, (StatusCode, Json<serde_json::Value>)> {
    let r = admin
        .transactions(types::Page {
            offset: page.offset,
            limit: page.limit,
        })
        .await
        .map_err(map_err)?;
    Ok(Json(r))
}

pub(crate) async fn transaction_by_id(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Query(q): Query<TxIdQuery>,
) -> Result<Json<types::WalletTransactionEntry>, (StatusCode, Json<serde_json::Value>)> {
    let entry = admin.transaction_by_id(q.id).await.map_err(map_err)?;
    match entry {
        Some(t) => Ok(Json(t)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "reason": "tx_not_found" })),
        )),
    }
}

/// `GET /wallet/transactionsByScanId/{scanId}` — transactions associated with
/// a scan. Scan 10 (payments) is the wallet's own listing; user scans serve
/// the rows tagged at block apply. Unknown / deregistered scans return an
/// empty page (Scala's filter-by-membership likewise yields `[]`, despite the
/// 404 its swagger declares).
pub(crate) async fn transactions_by_scan_id(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Path(scan_id): Path<u32>,
    Query(page): Query<PageQuery>,
) -> Result<Json<types::WalletTransactionsPage>, (StatusCode, Json<serde_json::Value>)> {
    let r = admin
        .transactions_by_scan_id(
            scan_id,
            types::Page {
                offset: page.offset,
                limit: page.limit,
            },
        )
        .await
        .map_err(map_err)?;
    Ok(Json(r))
}
