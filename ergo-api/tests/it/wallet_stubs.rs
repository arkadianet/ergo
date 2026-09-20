//! Stub-endpoint smoke tests. Each verifies the 501 + reason wire
//! shape — clients consuming our API rely on this shape to surface a
//! clear "this feature is coming later" message.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use ergo_api::wallet::sending::{
    BoxesCollectRequest, BoxesCollectResponse, PaymentRequestDto, TransactionGenerateRequest,
    TransactionGenerateResponse, TransactionGenerateUnsignedRequest,
    TransactionGenerateUnsignedResponse, TransactionSendRequest, TransactionSignRequest,
    TransactionSignResponse,
};
use ergo_api::wallet::types::*;
use ergo_api::wallet::{WalletAdmin, WalletAdminError};
use tower::ServiceExt;

// ----- helpers -----

struct MinimalAdmin;

#[async_trait::async_trait]
impl WalletAdmin for MinimalAdmin {
    // All stubbed routes don't actually call admin methods, so we
    // return unimplemented!() for every trait fn — stubs short-circuit
    // before reaching the admin.
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
        // Live handler reaches this; Uninitialized → 400 (not 501).
        Err(WalletAdminError::Uninitialized)
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

fn app() -> axum::Router {
    let admin: Arc<dyn WalletAdmin> = Arc::new(MinimalAdmin);
    ergo_api::wallet::router_with_security(admin, None)
}

/// Assert that a route is a live handler (returns 400 wallet_uninitialized
/// rather than 501), proving it's mounted and wired through the WalletAdmin trait.
/// `raw_body` is the JSON bytes to send (use `b"{}"` for object bodies, `b"[]"` for arrays).
async fn assert_live_handler_mounted(uri: &str, raw_body: &'static [u8]) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(raw_body))
        .unwrap();
    let resp = app().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "uri={uri} — live handler must return 400 wallet_uninitialized (not 501)"
    );
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body["reason"], "wallet_uninitialized",
        "uri={uri} — live route reason must be wallet_uninitialized"
    );
}

// ----- live handlers (return 400 wallet_uninitialized — mounted + wired) -----

#[tokio::test]
async fn balances_with_unconfirmed_handler_mounted() {
    // GET with no body — MinimalAdmin returns Uninitialized → 400, proving
    // the route is the real overlay handler (not the old 501 stub).
    let req = Request::builder()
        .method(Method::GET)
        .uri("/wallet/balances/withUnconfirmed")
        .body(Body::empty())
        .unwrap();
    let resp = app().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "withUnconfirmed must be a live handler (400 wallet_uninitialized), not 501",
    );
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["reason"], "wallet_uninitialized");
}

// ----- multi-sig live handlers (return 400 wallet_uninitialized — mounted + wired) -----

#[tokio::test]
async fn generate_commitments_stub() {
    // Sends a valid body so the handler reaches WalletAdmin::generate_commitments
    // which returns Uninitialized → 400.
    assert_live_handler_mounted(
        "/wallet/generateCommitments",
        b"{\"unsignedTx\":\"deadbeef\"}",
    )
    .await;
}

#[tokio::test]
async fn extract_hints_stub() {
    assert_live_handler_mounted(
        "/wallet/extractHints",
        b"{\"tx\":\"deadbeef\",\"real\":[],\"simulated\":[]}",
    )
    .await;
}

// ----- send live handlers (return 400 wallet_uninitialized — mounted + wired) -----

#[tokio::test]
async fn boxes_collect_handler_mounted() {
    assert_live_handler_mounted(
        "/wallet/boxes/collect",
        b"{\"targetBalance\":0,\"targetAssets\":[]}",
    )
    .await;
}

#[tokio::test]
async fn transaction_sign_handler_mounted() {
    assert_live_handler_mounted(
        "/wallet/transaction/sign",
        b"{\"unsignedTx\":{\"bytes\":\"\"}}",
    )
    .await;
}

#[tokio::test]
async fn transaction_generate_unsigned_handler_mounted() {
    assert_live_handler_mounted("/wallet/transaction/generateUnsigned", b"{\"requests\":[]}").await;
}

#[tokio::test]
async fn transaction_generate_handler_mounted() {
    assert_live_handler_mounted("/wallet/transaction/generate", b"{\"requests\":[]}").await;
}

#[tokio::test]
async fn transaction_send_handler_mounted() {
    assert_live_handler_mounted("/wallet/transaction/send", b"{\"requests\":[]}").await;
}

#[tokio::test]
async fn payment_send_handler_mounted() {
    // payment/send body is Vec<PaymentRequestDto> — a JSON array.
    assert_live_handler_mounted("/wallet/payment/send", b"[]").await;
}

// ----- advanced HD-key live handlers -----

#[tokio::test]
async fn derive_key_stub() {
    assert_live_handler_mounted(
        "/wallet/deriveKey",
        b"{\"derivationPath\":\"m/44'/429'/0'/0/5\"}",
    )
    .await;
}

#[tokio::test]
async fn derive_next_key_stub() {
    // GET with no body — MinimalAdmin returns Uninitialized → 400.
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/wallet/deriveNextKey")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "deriveNextKey — live handler must return 400 wallet_uninitialized"
    );
}

#[tokio::test]
async fn get_private_key_stub() {
    assert_live_handler_mounted(
        "/wallet/getPrivateKey",
        b"{\"address\":\"9fHBQFSmiCeMC39PZ25QAGhqiGJF3PqgKDYFGaM5GRc2Gs3MGKD\"}",
    )
    .await;
}
