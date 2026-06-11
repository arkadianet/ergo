//! Scan-registry endpoints (`/scan/register`, `/scan/deregister`,
//! `/scan/listAll`) — the registration layer of Scala's `ScanApiRoute`.
//!
//! Auth-gated (mounted under the same `require_api_key` route-layer as the
//! `/wallet/*` routes). `ergo-api` deliberately does not depend on
//! `ergo-wallet` (which would pull in redb/ergo-state), so the `trackingRule`
//! predicate is carried opaquely as a JSON value here; `ergo-node` parses and
//! validates it against `ergo_wallet::scan::ScanningPredicate` when it handles
//! the command. These handlers adapt the DTOs to HTTP and map
//! `WalletAdminError` to status codes via [`super::lifecycle::map_err`].

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

use super::lifecycle::map_err;
use super::WalletAdmin;

/// `POST /scan/register` request body (Scala `ScanRequest`). `scanName` and
/// `trackingRule` are required; `walletInteraction` (`off`/`shared`/`forced`)
/// and `removeOffchain` are optional and take their Scala defaults (`shared`,
/// `true`) — resolved in `ergo-node` when the predicate is parsed.
#[derive(serde::Deserialize, serde::Serialize)]
pub struct ScanRequestDto {
    #[serde(rename = "scanName")]
    pub scan_name: String,
    /// The tracking predicate, carried opaquely (validated in `ergo-node`).
    #[serde(rename = "trackingRule")]
    pub tracking_rule: serde_json::Value,
    #[serde(rename = "walletInteraction", default)]
    pub wallet_interaction: Option<String>,
    #[serde(rename = "removeOffchain", default)]
    pub remove_offchain: Option<bool>,
}

/// A registered scan (Scala `Scan`) — the `/scan/listAll` element.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct ScanDto {
    #[serde(rename = "scanId")]
    pub scan_id: u16,
    #[serde(rename = "scanName")]
    pub scan_name: String,
    #[serde(rename = "trackingRule")]
    pub tracking_rule: serde_json::Value,
    #[serde(rename = "walletInteraction")]
    pub wallet_interaction: String,
    #[serde(rename = "removeOffchain")]
    pub remove_offchain: bool,
}

/// The `{ "scanId": <int> }` wire object (Scala `ScanId`) — the `register`
/// response and the `deregister` request + response.
#[derive(serde::Deserialize, serde::Serialize)]
pub struct ScanIdJson {
    #[serde(rename = "scanId")]
    pub scan_id: u16,
}

/// `POST /scan/register` — register a scan, returning its allocated id.
pub(crate) async fn register(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(request): Json<ScanRequestDto>,
) -> Result<Json<ScanIdJson>, (StatusCode, Json<serde_json::Value>)> {
    let scan_id = admin.register_scan(request).await.map_err(map_err)?;
    Ok(Json(ScanIdJson { scan_id }))
}

/// `POST /scan/deregister` — remove a scan registration (storage + wallet
/// vars). A missing id is a 400 (Scala parity), echoed back as the removed id
/// on success. (Per-box untracking is the separate `/scan/stopTracking`
/// endpoint, a later slice.)
pub(crate) async fn deregister(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<ScanIdJson>,
) -> Result<Json<ScanIdJson>, (StatusCode, Json<serde_json::Value>)> {
    admin.deregister_scan(body.scan_id).await.map_err(map_err)?;
    Ok(Json(ScanIdJson {
        scan_id: body.scan_id,
    }))
}

/// `GET /scan/listAll` — every registered scan, ascending by id.
pub(crate) async fn list_all(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<Json<Vec<ScanDto>>, (StatusCode, Json<serde_json::Value>)> {
    let scans = admin.list_scans().await.map_err(map_err)?;
    Ok(Json(scans))
}

/// A box tracked by a scan — the `/scan/unspentBoxes` / `/scan/spentBoxes`
/// element. Minimal (like `WalletBoxEntry`) plus `bytes`, the full serialized
/// `ErgoBox` hex, so clients can decode the ergo tree / registers / assets.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanBoxEntry {
    pub box_id: String,
    pub value: u64,
    pub inclusion_height: u32,
    /// Confirmations at read time (`tip_height - inclusion_height`).
    pub confirmations_num: i64,
    pub spent: bool,
    /// Full serialized `ErgoBox`, hex.
    pub bytes: String,
}

/// Filters for the scan box endpoints. Defaults match the Scala swagger:
/// `minConfirmations=0`, `maxConfirmations=-1` (unlimited), `minInclusionHeight=0`,
/// `maxInclusionHeight=-1` (unlimited), `limit=500`, `offset=0`. A `-1` max means
/// "no upper bound".
#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanBoxFilter {
    #[serde(default)]
    pub min_confirmations: i32,
    #[serde(default = "neg_one")]
    pub max_confirmations: i32,
    #[serde(default)]
    pub min_inclusion_height: i32,
    #[serde(default = "neg_one")]
    pub max_inclusion_height: i32,
    #[serde(default = "default_limit")]
    pub limit: i32,
    #[serde(default)]
    pub offset: i32,
}

fn neg_one() -> i32 {
    -1
}
fn default_limit() -> i32 {
    500
}

/// `GET /scan/unspentBoxes/{scanId}` — unspent boxes tracked by the scan.
pub(crate) async fn unspent_boxes(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Path(scan_id): Path<u16>,
    Query(filter): Query<ScanBoxFilter>,
) -> Result<Json<Vec<ScanBoxEntry>>, (StatusCode, Json<serde_json::Value>)> {
    let boxes = admin
        .scan_unspent_boxes(scan_id, filter)
        .await
        .map_err(map_err)?;
    Ok(Json(boxes))
}

/// `GET /scan/spentBoxes/{scanId}` — spent boxes tracked by the scan.
pub(crate) async fn spent_boxes(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Path(scan_id): Path<u16>,
    Query(filter): Query<ScanBoxFilter>,
) -> Result<Json<Vec<ScanBoxEntry>>, (StatusCode, Json<serde_json::Value>)> {
    let boxes = admin
        .scan_spent_boxes(scan_id, filter)
        .await
        .map_err(map_err)?;
    Ok(Json(boxes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_request_dto_parses_with_optionals_absent() {
        let json =
            r#"{"scanName":"Assets","trackingRule":{"predicate":"containsAsset","assetId":"ab"}}"#;
        let dto: ScanRequestDto = serde_json::from_str(json).unwrap();
        assert_eq!(dto.scan_name, "Assets");
        assert_eq!(dto.wallet_interaction, None);
        assert_eq!(dto.remove_offchain, None);
        assert_eq!(dto.tracking_rule["predicate"], "containsAsset");
    }

    #[test]
    fn scan_dto_uses_scala_wire_field_names() {
        let dto = ScanDto {
            scan_id: 11,
            scan_name: "Assets".to_string(),
            tracking_rule: serde_json::json!({"predicate": "containsAsset"}),
            wallet_interaction: "shared".to_string(),
            remove_offchain: true,
        };
        let s = serde_json::to_string(&dto).unwrap();
        assert!(s.contains(r#""scanId":11"#));
        assert!(s.contains(r#""scanName":"Assets""#));
        assert!(s.contains(r#""walletInteraction":"shared""#));
        assert!(s.contains(r#""removeOffchain":true"#));
        assert!(s.contains(r#""trackingRule":"#));
    }

    #[test]
    fn scan_id_json_is_scan_id_object() {
        assert_eq!(
            serde_json::to_string(&ScanIdJson { scan_id: 11 }).unwrap(),
            r#"{"scanId":11}"#
        );
        let parsed: ScanIdJson = serde_json::from_str(r#"{"scanId":42}"#).unwrap();
        assert_eq!(parsed.scan_id, 42);
    }
}
