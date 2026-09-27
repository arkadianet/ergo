use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

pub use ergo_wallet_protocol::scala::scan::*;

use super::lifecycle::map_err;
use super::WalletAdmin;

pub(crate) async fn register(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(request): Json<ScanRequestDto>,
) -> Result<Json<ScanIdJson>, (StatusCode, Json<serde_json::Value>)> {
    let scan_id = admin.register_scan(request).await.map_err(map_err)?;
    Ok(Json(ScanIdJson { scan_id }))
}

pub(crate) async fn deregister(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<ScanIdJson>,
) -> Result<Json<ScanIdJson>, (StatusCode, Json<serde_json::Value>)> {
    admin.deregister_scan(body.scan_id).await.map_err(map_err)?;
    Ok(Json(ScanIdJson {
        scan_id: body.scan_id,
    }))
}

pub(crate) async fn list_all(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<Json<Vec<ScanDto>>, (StatusCode, Json<serde_json::Value>)> {
    let scans = admin.list_scans().await.map_err(map_err)?;
    Ok(Json(scans))
}

pub(crate) async fn stop_tracking(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<ScanIdBoxIdDto>,
) -> Result<Json<ScanIdBoxIdDto>, (StatusCode, Json<serde_json::Value>)> {
    admin
        .scan_stop_tracking(body.scan_id, body.box_id.clone())
        .await
        .map_err(map_err)?;
    Ok(Json(body))
}

pub(crate) async fn add_box(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<AddBoxRequestDto>,
) -> Result<Json<String>, (StatusCode, Json<serde_json::Value>)> {
    let box_id = admin
        .scan_add_box(body.scan_ids, body.box_json)
        .await
        .map_err(map_err)?;
    Ok(Json(box_id))
}

pub(crate) async fn p2s_rule(
    State(admin): State<Arc<dyn WalletAdmin>>,
    body: String,
) -> Result<Json<ScanIdJson>, (StatusCode, Json<serde_json::Value>)> {
    let p2s = serde_json::from_str::<String>(&body).unwrap_or_else(|_| body.trim().to_string());
    let scan_id = admin.scan_p2s_rule(p2s).await.map_err(map_err)?;
    Ok(Json(ScanIdJson { scan_id }))
}

pub(crate) async fn unspent_boxes(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Path(scan_id): Path<u16>,
    Query(filter): Query<ScanBoxFilter>,
) -> Result<Json<Vec<ScanBoxEntry>>, (StatusCode, Json<serde_json::Value>)> {
    filter.validate().map_err(map_err)?;
    let boxes = admin
        .scan_unspent_boxes(scan_id, filter)
        .await
        .map_err(map_err)?;
    Ok(Json(boxes))
}

pub(crate) async fn spent_boxes(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Path(scan_id): Path<u16>,
    Query(filter): Query<ScanBoxFilter>,
) -> Result<Json<Vec<ScanBoxEntry>>, (StatusCode, Json<serde_json::Value>)> {
    filter.validate().map_err(map_err)?;
    let boxes = admin
        .scan_spent_boxes(scan_id, filter)
        .await
        .map_err(map_err)?;
    Ok(Json(boxes))
}
