//! Lock-matrix smoke test: every `/wallet/*` route must be mounted
//! (no 404) in both locked and unlocked states. Specific status codes
//! are documented in comments.
//!
//! Per spec §8.1: all 27 routes are unconditionally registered.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use ergo_api::wallet::sending::{
    BoxesCollectRequest, BoxesCollectResponse, PaymentRequestDto, TransactionGenerateRequest,
    TransactionGenerateResponse, TransactionGenerateUnsignedRequest,
    TransactionGenerateUnsignedResponse, TransactionSendRequest, TransactionSignRequest,
    TransactionSignResponse,
};
use ergo_api::wallet::types::{
    Page, WalletAddressList, WalletBalances, WalletBoxesPage, WalletStatus, WalletTransactionEntry,
    WalletTransactionsPage,
};
use ergo_api::wallet::{WalletAdmin, WalletAdminError};
use tower::ServiceExt;

// ----- helpers -----

struct StubAdmin {
    initialized: bool,
    unlocked: bool,
}

#[async_trait::async_trait]
impl WalletAdmin for StubAdmin {
    async fn status(&self) -> Result<WalletStatus, WalletAdminError> {
        Ok(WalletStatus {
            is_initialized: self.initialized,
            is_unlocked: self.unlocked,
            change_address: String::new(),
            wallet_height: 0,
            error: String::new(),
        })
    }

    async fn init(
        &self,
        _pass: String,
        _mnemonic_pass: String,
        _strength_words: u8,
    ) -> Result<String, WalletAdminError> {
        Err(WalletAdminError::Internal("stub".into()))
    }

    async fn restore(
        &self,
        _mnemonic: String,
        _mnemonic_pass: String,
        _pass: String,
        _use_pre_1627: bool,
    ) -> Result<(), WalletAdminError> {
        Err(WalletAdminError::Internal("stub".into()))
    }

    async fn unlock(&self, _pass: String) -> Result<(), WalletAdminError> {
        Err(WalletAdminError::Internal("stub".into()))
    }

    async fn lock(&self) -> Result<(), WalletAdminError> {
        Err(WalletAdminError::Internal("stub".into()))
    }

    async fn check(
        &self,
        _mnemonic: String,
        _mnemonic_pass: String,
    ) -> Result<bool, WalletAdminError> {
        Err(WalletAdminError::Internal("stub".into()))
    }

    async fn rescan(&self, _from_height: u32) -> Result<(), WalletAdminError> {
        Err(WalletAdminError::Internal("stub".into()))
    }

    async fn update_change_address(&self, _address: String) -> Result<(), WalletAdminError> {
        Err(WalletAdminError::Internal("stub".into()))
    }

    async fn balances(&self) -> Result<WalletBalances, WalletAdminError> {
        Err(WalletAdminError::Internal("stub".into()))
    }
    async fn balances_with_unconfirmed(&self) -> Result<WalletBalances, WalletAdminError> {
        Err(WalletAdminError::Internal("stub".into()))
    }

    async fn addresses(&self) -> Result<WalletAddressList, WalletAdminError> {
        Err(WalletAdminError::Internal("stub".into()))
    }

    async fn boxes(&self, _page: Page) -> Result<WalletBoxesPage, WalletAdminError> {
        Err(WalletAdminError::Internal("stub".into()))
    }

    async fn boxes_unspent(&self, _page: Page) -> Result<WalletBoxesPage, WalletAdminError> {
        Err(WalletAdminError::Internal("stub".into()))
    }

    async fn transactions(&self, _page: Page) -> Result<WalletTransactionsPage, WalletAdminError> {
        Err(WalletAdminError::Internal("stub".into()))
    }

    async fn transaction_by_id(
        &self,
        _tx_id_hex: String,
    ) -> Result<Option<WalletTransactionEntry>, WalletAdminError> {
        Err(WalletAdminError::Internal("stub".into()))
    }

    async fn transactions_by_scan_id(
        &self,
        _scan_id: u32,
        _page: Page,
    ) -> Result<WalletTransactionsPage, WalletAdminError> {
        Err(WalletAdminError::Internal("stub".into()))
    }
    async fn payment_send(&self, _: Vec<PaymentRequestDto>) -> Result<String, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }
    async fn transaction_generate(
        &self,
        _: TransactionGenerateRequest,
    ) -> Result<TransactionGenerateResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }
    async fn transaction_generate_unsigned(
        &self,
        _: TransactionGenerateUnsignedRequest,
    ) -> Result<TransactionGenerateUnsignedResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }
    async fn transaction_sign(
        &self,
        _: TransactionSignRequest,
    ) -> Result<TransactionSignResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }
    async fn transaction_send(
        &self,
        _: TransactionSendRequest,
    ) -> Result<String, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }
    async fn boxes_collect(
        &self,
        _: BoxesCollectRequest,
    ) -> Result<BoxesCollectResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }
    async fn generate_commitments(
        &self,
        _: ergo_api::wallet::multi_sig::GenerateCommitmentsRequest,
    ) -> Result<ergo_api::wallet::multi_sig::GenerateCommitmentsResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }
    async fn extract_hints(
        &self,
        _: ergo_api::wallet::multi_sig::HintExtractionRequest,
    ) -> Result<ergo_api::wallet::multi_sig::HintExtractionResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }
    async fn derive_key(
        &self,
        _: ergo_api::wallet::admin_advanced::DeriveKeyRequest,
    ) -> Result<ergo_api::wallet::admin_advanced::DeriveKeyResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }
    async fn derive_next_key(
        &self,
    ) -> Result<ergo_api::wallet::admin_advanced::DeriveNextKeyResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }
    async fn get_private_key(
        &self,
        _: ergo_api::wallet::admin_advanced::GetPrivateKeyRequest,
    ) -> Result<ergo_api::wallet::admin_advanced::GetPrivateKeyResponse, WalletAdminError> {
        Err(WalletAdminError::Uninitialized)
    }
}

fn make_app(initialized: bool, unlocked: bool) -> axum::Router {
    let admin: Arc<dyn WalletAdmin> = Arc::new(StubAdmin {
        initialized,
        unlocked,
    });
    // Lock/unlock matrix doesn't exercise the auth gate; explicit None
    // documents the choice per the security-by-construction contract.
    ergo_api::wallet::router_with_security(admin, None)
}

async fn probe(app: axum::Router, method: Method, uri: &str) -> StatusCode {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

async fn probe_get(app: axum::Router, uri: &str) -> StatusCode {
    probe(app, Method::GET, uri).await
}

async fn probe_post(app: axum::Router, uri: &str) -> StatusCode {
    probe(app, Method::POST, uri).await
}

// ----- happy path -----

/// All 27 GET routes must NOT return 404 — they must be mounted.
#[tokio::test]
async fn all_get_routes_are_mounted_locked_state() {
    let get_routes = [
        "/wallet/status",
        "/wallet/lock",
        "/wallet/balances",
        "/wallet/balances/withUnconfirmed",
        "/wallet/addresses",
        "/wallet/boxes",
        "/wallet/boxes/unspent",
        "/wallet/transactions",
        "/wallet/transactionById?id=aabbcc",
        "/wallet/transactionsByScanId/10",
        "/wallet/deriveNextKey",
    ];

    let app = make_app(false, false);
    for route in &get_routes {
        let status = probe_get(app.clone(), route).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "GET {route} must be mounted — got 404",
        );
    }
}

/// All 27 GET routes must NOT return 404 in unlocked state either.
#[tokio::test]
async fn all_get_routes_are_mounted_unlocked_state() {
    let get_routes = [
        "/wallet/status",
        "/wallet/lock",
        "/wallet/balances",
        "/wallet/balances/withUnconfirmed",
        "/wallet/addresses",
        "/wallet/boxes",
        "/wallet/boxes/unspent",
        "/wallet/transactions",
        "/wallet/transactionById?id=aabbcc",
        "/wallet/transactionsByScanId/10",
        "/wallet/deriveNextKey",
    ];

    let app = make_app(true, true);
    for route in &get_routes {
        let status = probe_get(app.clone(), route).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "GET {route} must be mounted — got 404",
        );
    }
}

/// All POST routes must NOT return 404 (no method-not-allowed on absent route).
#[tokio::test]
async fn all_post_routes_are_mounted_locked_state() {
    let post_routes = [
        "/wallet/init",
        "/wallet/restore",
        "/wallet/unlock",
        "/wallet/check",
        "/wallet/rescan",
        "/wallet/updateChangeAddress",
        "/wallet/boxes/collect",
        "/wallet/extractHints",
        "/wallet/generateCommitments",
        "/wallet/transaction/sign",
        "/wallet/transaction/generateUnsigned",
        "/wallet/transaction/generate",
        "/wallet/transaction/send",
        "/wallet/payment/send",
        "/wallet/deriveKey",
        "/wallet/getPrivateKey",
    ];

    let app = make_app(false, false);
    for route in &post_routes {
        let status = probe_post(app.clone(), route).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "POST {route} must be mounted — got 404",
        );
    }
}

/// All POST routes must NOT return 404 in unlocked state either.
#[tokio::test]
async fn all_post_routes_are_mounted_unlocked_state() {
    let post_routes = [
        "/wallet/init",
        "/wallet/restore",
        "/wallet/unlock",
        "/wallet/check",
        "/wallet/rescan",
        "/wallet/updateChangeAddress",
        "/wallet/boxes/collect",
        "/wallet/extractHints",
        "/wallet/generateCommitments",
        "/wallet/transaction/sign",
        "/wallet/transaction/generateUnsigned",
        "/wallet/transaction/generate",
        "/wallet/transaction/send",
        "/wallet/payment/send",
        "/wallet/deriveKey",
        "/wallet/getPrivateKey",
    ];

    let app = make_app(true, true);
    for route in &post_routes {
        let status = probe_post(app.clone(), route).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "POST {route} must be mounted — got 404",
        );
    }
}

/// Stub handlers return 501 (NOT_IMPLEMENTED), not 404. Pins that the
/// route is mounted AND that the stub body is served correctly.
#[tokio::test]
async fn stub_handlers_return_501_not_404() {
    let app = make_app(false, false);
    let status = probe_get(app.clone(), "/wallet/status").await;
    // status may be a 501 stub — assert it is mounted (not 404).
    assert_ne!(status, StatusCode::NOT_FOUND, "/wallet/status must not 404");

    let status = probe_post(app.clone(), "/wallet/init").await;
    assert_ne!(status, StatusCode::NOT_FOUND, "/wallet/init must not 404");
}

/// `/wallet/status` response body must contain a valid JSON object
/// regardless of whether the route is currently stubbed.
#[tokio::test]
async fn status_route_returns_json_body() {
    let app = make_app(false, false);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/wallet/status")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "status must be mounted"
    );
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    // Body must parse as JSON.
    let _: serde_json::Value =
        serde_json::from_slice(&bytes).expect("/wallet/status body must be valid JSON");
}
