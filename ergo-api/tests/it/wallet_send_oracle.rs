//! Handler-level tests for the send-wallet REST surface.
//!
//! ## Tests in this file (HTTP-layer only — no prover, no chain state)
//!
//! - **`payment_send_handler_round_trip`** — `POST /wallet/payment/send`
//!   deserialises `Vec<PaymentRequestDto>`, forwards to `WalletAdmin::payment_send`,
//!   returns `{"txId":"..."}` (Scala camelCase wire shape).
//!
//! - **`payment_send_handler_multi_request`** — multi-target batch forwarded
//!   without truncation.
//!
//! - **`payment_send_locked_wallet_returns_400`** — `WalletAdminError::Locked`
//!   maps to HTTP 400 with `reason="wallet_locked"`.
//!
//! ## Full e2e
//!
//! The full sign + verify round-trip lives in
//! `ergo-node/tests/wallet_send_e2e.rs` where `ergo-wallet::proving::*` and
//! `ergo-sigma::*` are all in scope without a crate-cycle constraint.

use std::sync::{Arc, Mutex};

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

/// Captures the `payment_send` call payload for test assertions.
struct CapturingAdmin {
    captured_requests: Mutex<Option<Vec<PaymentRequestDto>>>,
    fake_tx_id: String,
}

impl CapturingAdmin {
    fn new(fake_tx_id: &str) -> Self {
        Self {
            captured_requests: Mutex::new(None),
            fake_tx_id: fake_tx_id.to_string(),
        }
    }

    fn captured(&self) -> Option<Vec<PaymentRequestDto>> {
        self.captured_requests.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl WalletAdmin for CapturingAdmin {
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
    async fn payment_send(
        &self,
        requests: Vec<PaymentRequestDto>,
    ) -> Result<String, WalletAdminError> {
        *self.captured_requests.lock().unwrap() = Some(requests);
        Ok(self.fake_tx_id.clone())
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

// ----- happy path -----

/// Exercises the full HTTP-handler → WalletAdmin::payment_send path.
///
/// The CapturingAdmin captures the inbound PaymentRequestDto slice and returns a
/// known fake tx_id.  Validates that:
/// - the handler parses Vec<PaymentRequestDto> from JSON
/// - the WalletAdmin::payment_send receives exactly the submitted slice
/// - the 200 response body serialises as `{"txId":"<id>"}` (Scala camelCase)
/// - address / value / assets are faithfully forwarded (no silent truncation)
///
/// This test does NOT exercise the prover, signing context, or UTXO lookup —
/// those are exercised by the production `self_verify_signed_tx` gate and by
/// `ergo-node/tests/wallet_send_e2e.rs`.
#[tokio::test]
async fn payment_send_handler_round_trip() {
    let fake_tx_id = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    let admin = Arc::new(CapturingAdmin::new(fake_tx_id));
    let app = ergo_api::wallet::router_with_security(admin.clone(), None);

    let body_json = serde_json::json!([
        {
            "address": "9eYMpbGgBf42bCcnB2nG3wQdqPzpCCw5eB1YaWUUen9uCaW3wwm",
            "value": 100_000_000u64,
            "assets": []
        }
    ]);

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/wallet/payment/send")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "payment_send with capturing admin must return 200"
    );

    let resp_bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let resp_value: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();

    // Scala camelCase wire shape: { "txId": "..." }
    assert_eq!(
        resp_value["txId"].as_str().unwrap(),
        fake_tx_id,
        "response txId must match what WalletAdmin::payment_send returned"
    );

    // Verify the admin received exactly the request we sent.
    let captured = admin
        .captured()
        .expect("payment_send must have been called");
    assert_eq!(captured.len(), 1, "one payment request");
    assert_eq!(captured[0].value, 100_000_000, "value forwarded correctly");
    assert!(
        captured[0].assets.is_empty(),
        "empty assets forwarded correctly"
    );
}

/// Multi-request batch: two payment targets in one call.
///
/// Validates that the handler forwards all requests without truncating the slice.
#[tokio::test]
async fn payment_send_handler_multi_request() {
    let fake_tx_id = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let admin = Arc::new(CapturingAdmin::new(fake_tx_id));
    let app = ergo_api::wallet::router_with_security(admin.clone(), None);

    let body_json = serde_json::json!([
        {
            "address": "9eYMpbGgBf42bCcnB2nG3wQdqPzpCCw5eB1YaWUUen9uCaW3wwm",
            "value": 50_000_000u64,
            "assets": []
        },
        {
            "address": "9f4QF8AD1nQ3nJahQVkMj8hFSVVzVom77b52JU7EW71Zexg6N8v",
            "value": 200_000_000u64,
            "assets": [
                { "tokenId": "0000000000000000000000000000000000000000000000000000000000000001", "amount": 100 }
            ]
        }
    ]);

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/wallet/payment/send")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let captured = admin
        .captured()
        .expect("payment_send must have been called");
    assert_eq!(captured.len(), 2, "both payment requests must be forwarded");
    assert_eq!(captured[0].value, 50_000_000);
    assert_eq!(captured[1].value, 200_000_000);
    assert_eq!(captured[1].assets.len(), 1, "token asset forwarded");
    assert_eq!(captured[1].assets[0].amount, 100);
}

/// WalletAdminError::Locked from payment_send maps to 400 with reason="wallet_locked".
///
/// Validates the error-mapping path in the handler (via lifecycle::map_err) for
/// the Locked case — the most important send error: the wallet must be unlocked
/// to sign. Scala parity: the reference node uses 400 for all wallet-state
/// errors; 403 is not part of the wire protocol.
#[tokio::test]
async fn payment_send_locked_wallet_returns_400() {
    struct LockedAdmin;
    #[async_trait::async_trait]
    impl WalletAdmin for LockedAdmin {
        async fn payment_send(
            &self,
            _: Vec<PaymentRequestDto>,
        ) -> Result<String, WalletAdminError> {
            Err(WalletAdminError::Locked)
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
        ) -> Result<ergo_api::wallet::multi_sig::GenerateCommitmentsResponse, WalletAdminError>
        {
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
        ) -> Result<ergo_api::wallet::admin_advanced::DeriveNextKeyResponse, WalletAdminError>
        {
            unimplemented!()
        }
        async fn get_private_key(
            &self,
            _: ergo_api::wallet::admin_advanced::GetPrivateKeyRequest,
        ) -> Result<ergo_api::wallet::admin_advanced::GetPrivateKeyResponse, WalletAdminError>
        {
            unimplemented!()
        }
    }

    let admin: Arc<dyn WalletAdmin> = Arc::new(LockedAdmin);
    let app = ergo_api::wallet::router_with_security(admin, None);

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/wallet/payment/send")
                .header("content-type", "application/json")
                .body(Body::from(b"[]".as_ref()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Scala parity: Locked returns 400 BAD_REQUEST with reason=wallet_locked
    // (same as other wallet-state errors; 403 is not used by the Scala node).
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Locked wallet must return 400"
    );
    let resp_bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let resp_value: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    assert_eq!(
        resp_value["reason"].as_str().unwrap(),
        "wallet_locked",
        "Locked must serialize as reason=wallet_locked"
    );
}
