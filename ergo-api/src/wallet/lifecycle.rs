use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub(crate) use ergo_wallet_protocol::scala::lifecycle::{
    CheckBody, CheckResponse, InitBody, InitResponse, RestoreBody, UnlockBody,
};

use super::types;
use super::WalletAdmin;

pub(crate) fn map_err(e: super::WalletAdminError) -> (StatusCode, Json<serde_json::Value>) {
    let mapped = ergo_wallet_protocol::WalletErrorSurface::Scala.map(&e);
    let status = StatusCode::from_u16(mapped.status).expect("protocol wallet status is valid");
    if status.is_server_error() {
        tracing::error!(reason = mapped.reason, detail = %e, "wallet request failed");
    } else {
        tracing::debug!(reason = mapped.reason, detail = %e, "wallet request rejected");
    }
    let body = serde_json::json!({ "reason": mapped.reason, "detail": e.to_string() });
    (status, Json(body))
}

pub(crate) async fn status(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<Json<types::WalletStatus>, (StatusCode, Json<serde_json::Value>)> {
    let s = admin.status().await.map_err(map_err)?;
    Ok(Json(s))
}

pub(crate) async fn init(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<InitBody>,
) -> Result<Json<InitResponse>, (StatusCode, Json<serde_json::Value>)> {
    let mnemonic = admin
        .init(body.pass, body.mnemonic_pass, body.strength)
        .await
        .map_err(map_err)?;
    Ok(Json(InitResponse { mnemonic }))
}

pub(crate) async fn restore(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<RestoreBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    admin
        .restore(
            body.mnemonic,
            body.mnemonic_pass,
            body.pass,
            body.use_pre_1627_key_derivation,
        )
        .await
        .map_err(map_err)?;
    Ok(StatusCode::OK)
}

pub(crate) async fn unlock(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<UnlockBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    admin.unlock(body.pass).await.map_err(map_err)?;
    Ok(StatusCode::OK)
}

pub(crate) async fn lock(
    State(admin): State<Arc<dyn WalletAdmin>>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    admin.lock().await.map_err(map_err)?;
    Ok(StatusCode::OK)
}

pub(crate) async fn check(
    State(admin): State<Arc<dyn WalletAdmin>>,
    Json(body): Json<CheckBody>,
) -> Result<Json<CheckResponse>, (StatusCode, Json<serde_json::Value>)> {
    let matched = admin
        .check(body.mnemonic, body.mnemonic_pass)
        .await
        .map_err(map_err)?;
    Ok(Json(CheckResponse { matched }))
}

#[cfg(test)]
mod tests {
    use super::super::WalletAdminError as E;
    use super::*;

    // ----- error mapping -----

    #[test]
    fn bad_request_maps_to_400_with_detail() {
        // A user-correctable failure (e.g. a tx that fails structural
        // validation — dust output below min box value) must surface as a
        // 400 `bad_request`, not the opaque 500 `internal`. The detail string
        // is preserved for diagnosis.
        let (status, body) = map_err(E::BadRequest(
            "transaction rejected: output 0 value 10 below minimum 360".into(),
        ));
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.0["reason"], "bad_request");
        assert!(
            body.0["detail"].as_str().unwrap().contains("below minimum"),
            "detail must carry the structural-validation reason"
        );
    }

    #[test]
    fn internal_still_maps_to_500() {
        // Contrast guard: genuine server faults stay 500 `internal`.
        let (status, body) = map_err(E::Internal("writer task gone".into()));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.0["reason"], "internal");
    }

    #[test]
    fn wallet_scan_invalidated_maps_to_conflict_with_recovery_detail() {
        let (status, axum::Json(body)) = map_err(crate::wallet::WalletAdminError::ScanInvalidated);
        assert_eq!(status, StatusCode::CONFLICT);
        let body = serde_json::to_value(body).unwrap();
        assert_eq!(body["reason"], "scan_invalidated");
        assert!(body["detail"].as_str().unwrap().contains("fromHeight=0"));
    }

    #[test]
    fn rescan_preflight_unavailable_maps_to_conflict() {
        let (status, _) = map_err(crate::wallet::WalletAdminError::RescanUnavailable(
            "chain block-read history is unavailable before height 1".to_string(),
        ));
        assert_eq!(status, StatusCode::CONFLICT);
    }
}
