//! /wallet/rescan + /wallet/updateChangeAddress smoke tests.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use ergo_api::wallet::sending::{
    BoxesCollectRequest, BoxesCollectResponse, PaymentRequestDto, TransactionGenerateRequest,
    TransactionGenerateResponse, TransactionGenerateUnsignedRequest,
    TransactionGenerateUnsignedResponse, TransactionSendRequest, TransactionSignRequest,
    TransactionSignResponse,
};
use ergo_api::wallet::{WalletAdmin, WalletAdminError};
use tower::ServiceExt;

// ----- helpers -----

struct StubAdmin;

#[async_trait::async_trait]
impl WalletAdmin for StubAdmin {
    async fn rescan(&self, _: u32) -> Result<(), WalletAdminError> {
        Ok(())
    }
    async fn update_change_address(&self, _: String) -> Result<(), WalletAdminError> {
        Err(WalletAdminError::ChangeAddressUntracked)
    }
    async fn status(&self) -> Result<ergo_api::wallet::types::WalletStatus, WalletAdminError> {
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
    async fn balances(&self) -> Result<ergo_api::wallet::types::WalletBalances, WalletAdminError> {
        unimplemented!()
    }
    async fn balances_with_unconfirmed(
        &self,
    ) -> Result<ergo_api::wallet::types::WalletBalances, WalletAdminError> {
        unimplemented!()
    }
    async fn addresses(
        &self,
    ) -> Result<ergo_api::wallet::types::WalletAddressList, WalletAdminError> {
        unimplemented!()
    }
    async fn boxes(
        &self,
        _: ergo_api::wallet::types::Page,
    ) -> Result<ergo_api::wallet::types::WalletBoxesPage, WalletAdminError> {
        unimplemented!()
    }
    async fn boxes_unspent(
        &self,
        _: ergo_api::wallet::types::Page,
    ) -> Result<ergo_api::wallet::types::WalletBoxesPage, WalletAdminError> {
        unimplemented!()
    }
    async fn transactions(
        &self,
        _: ergo_api::wallet::types::Page,
    ) -> Result<ergo_api::wallet::types::WalletTransactionsPage, WalletAdminError> {
        unimplemented!()
    }
    async fn transaction_by_id(
        &self,
        _: String,
    ) -> Result<Option<ergo_api::wallet::types::WalletTransactionEntry>, WalletAdminError> {
        unimplemented!()
    }
    async fn transactions_by_scan_id(
        &self,
        _: u32,
        _: ergo_api::wallet::types::Page,
    ) -> Result<ergo_api::wallet::types::WalletTransactionsPage, WalletAdminError> {
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

// ----- happy path -----

#[tokio::test]
async fn rescan_returns_200() {
    let admin: Arc<dyn WalletAdmin> = Arc::new(StubAdmin);
    let app = ergo_api::wallet::router_with_security(admin, None);
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/wallet/rescan")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ----- error paths -----

#[tokio::test]
async fn update_change_address_with_untracked_returns_400_with_reason() {
    let admin: Arc<dyn WalletAdmin> = Arc::new(StubAdmin);
    let app = ergo_api::wallet::router_with_security(admin, None);
    let body =
        serde_json::json!({ "address": "9eYMpbGgBf42bCcnB2nG3wQdqPzpCCw5eB1YaWUUen9uCaW3wwm" });
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/wallet/updateChangeAddress")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["reason"], "change_address_untracked");
}
