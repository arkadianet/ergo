//! `/wallet` read endpoint integration tests.
//!
//! Each route gets one test asserting 200 OK with the expected JSON shape.
//! The `transaction_by_id` test asserts 404 (admin returns None).
//! The `transactionsByScanId` tests assert 200 for id=10 and that user scan
//! ids forward to the admin (empty page for unknown scans, not 404).

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

struct StubAdmin;

#[async_trait::async_trait]
impl WalletAdmin for StubAdmin {
    async fn balances(&self) -> Result<WalletBalances, WalletAdminError> {
        Ok(WalletBalances {
            height: 1000,
            balance: 67_500_000_000,
            assets: vec![TokenBalance {
                token_id: "deadbeef".repeat(8),
                amount: 42,
            }],
        })
    }
    async fn balances_with_unconfirmed(&self) -> Result<WalletBalances, WalletAdminError> {
        self.balances().await
    }
    async fn addresses(&self) -> Result<WalletAddressList, WalletAdminError> {
        Ok(WalletAddressList(vec![
            "9hAymcGaRfTX7bMADNdfWfk7CKzi2ZpvRBCmtEf6d92n8E26Ax7".to_string(),
        ]))
    }
    async fn boxes(&self, _: Page) -> Result<WalletBoxesPage, WalletAdminError> {
        Ok(WalletBoxesPage {
            total: 1,
            items: vec![WalletBoxEntry {
                box_id: "ab".repeat(32),
                value: 1_000_000_000,
                creation_height: 100,
                status: "Confirmed".to_string(),
                provenance: "Owned".to_string(),
            }],
        })
    }
    async fn boxes_unspent(&self, p: Page) -> Result<WalletBoxesPage, WalletAdminError> {
        self.boxes(p).await
    }
    async fn transactions(&self, _: Page) -> Result<WalletTransactionsPage, WalletAdminError> {
        Ok(WalletTransactionsPage {
            total: 1,
            items: vec![WalletTransactionEntry {
                tx_id: "cd".repeat(32),
                block_height: 100,
                block_id: "ef".repeat(32),
                wallet_outputs: vec!["ab".repeat(32)],
                wallet_inputs: vec![],
                scan_ids: vec![],
            }],
        })
    }
    async fn transaction_by_id(
        &self,
        _: String,
    ) -> Result<Option<WalletTransactionEntry>, WalletAdminError> {
        Ok(None) // simulate "not found" — handler returns 404
    }
    async fn transactions_by_scan_id(
        &self,
        _: u32,
        _: Page,
    ) -> Result<WalletTransactionsPage, WalletAdminError> {
        Ok(WalletTransactionsPage::default())
    }
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
    let admin: Arc<dyn WalletAdmin> = Arc::new(StubAdmin);
    ergo_api::wallet::router_with_security(admin, None) // read smoke test; auth gate not exercised
}

// ----- happy path -----

#[tokio::test]
async fn balances_returns_camelcase_shape() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/wallet/balances")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["height"], 1000);
    assert_eq!(body["balance"], 67_500_000_000u64);
    let asset0 = &body["assets"][0];
    assert!(asset0.get("tokenId").is_some(), "tokenId must be camelCase");
    assert_eq!(asset0["amount"], 42);
}

#[tokio::test]
async fn addresses_returns_array() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/wallet/addresses")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(body.is_array());
    assert_eq!(
        body[0],
        "9hAymcGaRfTX7bMADNdfWfk7CKzi2ZpvRBCmtEf6d92n8E26Ax7"
    );
}

#[tokio::test]
async fn boxes_returns_paginated_shape() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/wallet/boxes?offset=0&limit=50")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["status"], "Confirmed");
}

#[tokio::test]
async fn boxes_unspent_returns_200() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/wallet/boxes/unspent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn transactions_returns_paginated_shape() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/wallet/transactions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["total"], 1);
    assert!(body["items"].is_array());
}

#[tokio::test]
async fn transaction_by_id_not_found_returns_404() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/wallet/transactionById?id=deadbeef")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["reason"], "tx_not_found");
}

#[tokio::test]
async fn transactions_by_scan_id_with_payments_id_returns_200() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/wallet/transactionsByScanId/10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn transactions_by_scan_id_forwards_user_scan_ids() {
    // User scan ids are no longer 404-gated at the HTTP edge: they forward to
    // the admin (which serves scan-tx rows; unknown/deregistered scans yield
    // an empty page, matching Scala's filter-by-membership `[]`).
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/wallet/transactionsByScanId/99")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["total"], 0);
    assert!(body["items"].as_array().unwrap().is_empty());
}
