//! `/wallet/status`, `/wallet/restore` smoke tests + lock-aware behavior.

use std::sync::Arc;
use std::sync::Mutex;

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

struct StubAdmin {
    initialized: bool,
    unlocked: bool,
    height: u32,
}

#[async_trait::async_trait]
impl WalletAdmin for StubAdmin {
    async fn status(&self) -> Result<WalletStatus, WalletAdminError> {
        Ok(WalletStatus {
            is_initialized: self.initialized,
            is_unlocked: self.unlocked,
            change_address: String::new(),
            wallet_height: self.height,
            error: String::new(),
        })
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

fn app(initialized: bool, unlocked: bool, height: u32) -> axum::Router {
    let admin: Arc<dyn WalletAdmin> = Arc::new(StubAdmin {
        initialized,
        unlocked,
        height,
    });
    ergo_api::wallet::router_with_security(admin, None)
}

// ----- happy path -----

#[tokio::test]
async fn status_returns_zero_state_for_uninitialized_wallet() {
    let resp = app(false, false, 0)
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/wallet/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["isInitialized"], false);
    assert_eq!(body["isUnlocked"], false);
    assert_eq!(body["changeAddress"], "");
    assert_eq!(body["walletHeight"], 0);
}

#[tokio::test]
async fn status_returns_camelcase_fields_per_scala_parity() {
    let resp = app(true, true, 12345)
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/wallet/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // Scala parity: every field MUST be camelCase, not snake_case.
    assert!(
        body.get("is_initialized").is_none(),
        "snake_case is_initialized must not be present"
    );
    assert!(body.get("isInitialized").is_some());
    assert_eq!(body["walletHeight"], 12345);
}

// ----- oracle parity -----

/// Tier-1 spec §5.1: legacy clients that don't send
/// `usePre1627KeyDerivation` must be treated as pre-1627 (true).
/// The admin trait receives `use_pre_1627 = true`; verified here via
/// a CapturingAdmin that records the value it was called with.
#[tokio::test]
async fn restore_omits_use_pre_1627_field_defaults_to_true() {
    struct CapturingAdmin {
        captured: Mutex<Option<bool>>,
    }

    #[async_trait::async_trait]
    impl WalletAdmin for CapturingAdmin {
        async fn restore(
            &self,
            _: String,
            _: String,
            _: String,
            use_pre_1627: bool,
        ) -> Result<(), WalletAdminError> {
            *self.captured.lock().unwrap() = Some(use_pre_1627);
            Ok(())
        }
        async fn status(&self) -> Result<WalletStatus, WalletAdminError> {
            unimplemented!()
        }
        async fn init(&self, _: String, _: String, _: u8) -> Result<String, WalletAdminError> {
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
            _: Vec<PaymentRequestDto>,
        ) -> Result<String, WalletAdminError> {
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
        ) -> Result<ergo_api::wallet::multi_sig::GenerateCommitmentsResponse, WalletAdminError>
        {
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
        ) -> Result<ergo_api::wallet::admin_advanced::DeriveNextKeyResponse, WalletAdminError>
        {
            Err(WalletAdminError::Uninitialized)
        }
        async fn get_private_key(
            &self,
            _: ergo_api::wallet::admin_advanced::GetPrivateKeyRequest,
        ) -> Result<ergo_api::wallet::admin_advanced::GetPrivateKeyResponse, WalletAdminError>
        {
            Err(WalletAdminError::Uninitialized)
        }
    }

    let admin = Arc::new(CapturingAdmin {
        captured: Mutex::new(None),
    });
    let admin_arc: Arc<dyn WalletAdmin> = admin.clone();
    let app = ergo_api::wallet::router_with_security(admin_arc, None);

    // POST /wallet/restore WITHOUT usePre1627KeyDerivation field.
    let body = serde_json::json!({
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "pass": "test-pw",
        // Deliberately omit usePre1627KeyDerivation.
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/wallet/restore")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let captured = *admin.captured.lock().unwrap();
    assert_eq!(
        captured,
        Some(true),
        "omitted usePre1627KeyDerivation must default to true per spec §5.1",
    );
}
