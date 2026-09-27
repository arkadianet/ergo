use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

pub use ergo_wallet_protocol::scala::query::{PageQuery, TxIdQuery};

use super::lifecycle::map_err;
use super::types;
use super::WalletAdmin;

pub(crate) async fn balances(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<Json<types::WalletBalances>, (StatusCode, Json<serde_json::Value>)> {
    let b = admin.balances().await.map_err(map_err)?;
    Ok(Json(b))
}

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
        Some(e) => Ok(Json(e)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "reason": "tx_not_found" })),
        )),
    }
}

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
