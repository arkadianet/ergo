//! End-to-end routing tests for the scan-registry endpoints
//! (`/scan/register`, `/scan/deregister`, `/scan/listAll`).
//!
//! Drives the real handlers through `wallet::router_with_security` with a
//! stateful in-memory mock, proving the routes are mounted + wired and that the
//! `register -> listAll -> deregister` flow and the deregister-not-found -> 400
//! mapping behave per Scala. The persistence + predicate-validation logic is
//! covered separately by the `ergo-node` command tests; this exercises the HTTP
//! adaptation layer.

use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use ergo_api::wallet::scan::{ScanDto, ScanRequestDto};
use ergo_api::wallet::sending::{
    BoxesCollectRequest, BoxesCollectResponse, PaymentRequestDto, TransactionGenerateRequest,
    TransactionGenerateResponse, TransactionGenerateUnsignedRequest,
    TransactionGenerateUnsignedResponse, TransactionSendRequest, TransactionSignRequest,
    TransactionSignResponse,
};
use ergo_api::wallet::types::*;
use ergo_api::wallet::{WalletAdmin, WalletAdminError};
use tower::ServiceExt;

/// A stateful in-memory scan registry, mirroring the Scala allocation: ids from
/// 11, monotonic, never reused; deregister of a missing id is a 400. Every
/// non-scan trait method is `unimplemented!()` — the scan routes never touch
/// them.
#[derive(Default)]
struct ScanAdmin {
    scans: Mutex<Vec<ScanDto>>,
    last_used: Mutex<u16>,
}

#[async_trait::async_trait]
impl WalletAdmin for ScanAdmin {
    async fn register_scan(&self, request: ScanRequestDto) -> Result<u16, WalletAdminError> {
        let mut last = self.last_used.lock().unwrap();
        let id = (*last).max(10) + 1;
        *last = id;
        self.scans.lock().unwrap().push(ScanDto {
            scan_id: id,
            scan_name: request.scan_name,
            tracking_rule: request.tracking_rule,
            wallet_interaction: request
                .wallet_interaction
                .unwrap_or_else(|| "shared".to_string()),
            remove_offchain: request.remove_offchain.unwrap_or(true),
        });
        Ok(id)
    }

    async fn deregister_scan(&self, scan_id: u16) -> Result<(), WalletAdminError> {
        let mut scans = self.scans.lock().unwrap();
        let before = scans.len();
        scans.retain(|s| s.scan_id != scan_id);
        if scans.len() < before {
            Ok(())
        } else {
            Err(WalletAdminError::BadRequest(format!("no scan {scan_id}")))
        }
    }

    async fn list_scans(&self) -> Result<Vec<ScanDto>, WalletAdminError> {
        Ok(self.scans.lock().unwrap().clone())
    }

    // ----- unused by the scan routes -----
    async fn status(&self) -> Result<WalletStatus, WalletAdminError> {
        unimplemented!()
    }
    async fn init(&self, _: String, _: String, _: u8) -> Result<String, WalletAdminError> {
        unimplemented!()
    }
    async fn restore(
        &self,
        _: String,
        _: String,
        _: String,
        _: bool,
    ) -> Result<(), WalletAdminError> {
        unimplemented!()
    }
    async fn unlock(&self, _: String) -> Result<(), WalletAdminError> {
        unimplemented!()
    }
    async fn lock(&self) -> Result<(), WalletAdminError> {
        unimplemented!()
    }
    async fn check(&self, _: String, _: String) -> Result<bool, WalletAdminError> {
        unimplemented!()
    }
    async fn rescan(&self, _: u32) -> Result<(), WalletAdminError> {
        unimplemented!()
    }
    async fn update_change_address(&self, _: String) -> Result<(), WalletAdminError> {
        unimplemented!()
    }
    async fn balances(&self) -> Result<WalletBalances, WalletAdminError> {
        unimplemented!()
    }
    async fn balances_with_unconfirmed(&self) -> Result<WalletBalances, WalletAdminError> {
        unimplemented!()
    }
    async fn addresses(&self) -> Result<WalletAddressList, WalletAdminError> {
        unimplemented!()
    }
    async fn boxes(&self, _: Page) -> Result<WalletBoxesPage, WalletAdminError> {
        unimplemented!()
    }
    async fn boxes_unspent(&self, _: Page) -> Result<WalletBoxesPage, WalletAdminError> {
        unimplemented!()
    }
    async fn transactions(&self, _: Page) -> Result<WalletTransactionsPage, WalletAdminError> {
        unimplemented!()
    }
    async fn transaction_by_id(
        &self,
        _: String,
    ) -> Result<Option<WalletTransactionEntry>, WalletAdminError> {
        unimplemented!()
    }
    async fn transactions_by_scan_id(
        &self,
        _: u32,
        _: Page,
    ) -> Result<WalletTransactionsPage, WalletAdminError> {
        unimplemented!()
    }
    async fn payment_send(&self, _: Vec<PaymentRequestDto>) -> Result<String, WalletAdminError> {
        unimplemented!()
    }
    async fn transaction_generate(
        &self,
        _: TransactionGenerateRequest,
    ) -> Result<TransactionGenerateResponse, WalletAdminError> {
        unimplemented!()
    }
    async fn transaction_generate_unsigned(
        &self,
        _: TransactionGenerateUnsignedRequest,
    ) -> Result<TransactionGenerateUnsignedResponse, WalletAdminError> {
        unimplemented!()
    }
    async fn transaction_sign(
        &self,
        _: TransactionSignRequest,
    ) -> Result<TransactionSignResponse, WalletAdminError> {
        unimplemented!()
    }
    async fn transaction_send(
        &self,
        _: TransactionSendRequest,
    ) -> Result<String, WalletAdminError> {
        unimplemented!()
    }
    async fn boxes_collect(
        &self,
        _: BoxesCollectRequest,
    ) -> Result<BoxesCollectResponse, WalletAdminError> {
        unimplemented!()
    }
    async fn generate_commitments(
        &self,
        _: ergo_api::wallet::multi_sig::GenerateCommitmentsRequest,
    ) -> Result<ergo_api::wallet::multi_sig::GenerateCommitmentsResponse, WalletAdminError> {
        unimplemented!()
    }
    async fn extract_hints(
        &self,
        _: ergo_api::wallet::multi_sig::HintExtractionRequest,
    ) -> Result<ergo_api::wallet::multi_sig::HintExtractionResponse, WalletAdminError> {
        unimplemented!()
    }
    async fn derive_key(
        &self,
        _: ergo_api::wallet::admin_advanced::DeriveKeyRequest,
    ) -> Result<ergo_api::wallet::admin_advanced::DeriveKeyResponse, WalletAdminError> {
        unimplemented!()
    }
    async fn derive_next_key(
        &self,
    ) -> Result<ergo_api::wallet::admin_advanced::DeriveNextKeyResponse, WalletAdminError> {
        unimplemented!()
    }
    async fn get_private_key(
        &self,
        _: ergo_api::wallet::admin_advanced::GetPrivateKeyRequest,
    ) -> Result<ergo_api::wallet::admin_advanced::GetPrivateKeyResponse, WalletAdminError> {
        unimplemented!()
    }
}

fn app() -> axum::Router {
    let admin: Arc<dyn WalletAdmin> = Arc::new(ScanAdmin::default());
    ergo_api::wallet::router_with_security(admin, None)
}

fn app_with(admin: Arc<dyn WalletAdmin>) -> axum::Router {
    ergo_api::wallet::router_with_security(admin, None)
}

async fn json(
    router: axum::Router,
    method: Method,
    uri: &str,
    body: &'static [u8],
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

const RULE: &[u8] =
    b"{\"scanName\":\"Assets\",\"trackingRule\":{\"predicate\":\"containsAsset\",\"assetId\":\"1111111111111111111111111111111111111111111111111111111111111111\"}}";

#[tokio::test]
async fn register_returns_scan_id_then_list_all_shows_it() {
    let admin: Arc<dyn WalletAdmin> = Arc::new(ScanAdmin::default());
    let router = app_with(admin.clone());

    let (status, body) = json(router, Method::POST, "/scan/register", RULE).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["scanId"], 11, "first user scan id is 11");

    let (status, body) = json(app_with(admin), Method::GET, "/scan/listAll", b"").await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("listAll is an array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["scanId"], 11);
    assert_eq!(arr[0]["scanName"], "Assets");
    assert_eq!(arr[0]["walletInteraction"], "shared");
    assert_eq!(arr[0]["removeOffchain"], true);
    assert_eq!(arr[0]["trackingRule"]["predicate"], "containsAsset");
}

#[tokio::test]
async fn deregister_removes_the_scan_and_echoes_id() {
    let admin: Arc<dyn WalletAdmin> = Arc::new(ScanAdmin::default());
    let _ = json(
        app_with(admin.clone()),
        Method::POST,
        "/scan/register",
        RULE,
    )
    .await;

    let (status, body) = json(
        app_with(admin.clone()),
        Method::POST,
        "/scan/deregister",
        b"{\"scanId\":11}",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["scanId"], 11, "deregister echoes the removed id");

    let (_, body) = json(app_with(admin), Method::GET, "/scan/listAll", b"").await;
    assert!(
        body.as_array().unwrap().is_empty(),
        "scan is gone after deregister"
    );
}

#[tokio::test]
async fn deregister_unknown_id_is_bad_request() {
    let (status, body) = json(app(), Method::POST, "/scan/deregister", b"{\"scanId\":999}").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "deregister of a missing scan is 400 (Scala parity), not 404"
    );
    assert_eq!(body["reason"], "bad_request");
}

#[tokio::test]
async fn list_all_is_empty_on_a_fresh_registry() {
    let (status, body) = json(app(), Method::GET, "/scan/listAll", b"").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().unwrap().is_empty());
}
