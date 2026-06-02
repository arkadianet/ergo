//! Request-level contract for the wallet-UI init/restore → unlock flow.
//!
//! The wallet UI's init and restore flows do not leave the wallet
//! unlocked on their own: `/wallet/init` returns only a mnemonic and
//! `/wallet/restore` returns only `200`, so `wallet.js` must follow each
//! with an explicit `/wallet/unlock` carrying the passphrase the operator
//! just chose. This test pins that contract at the HTTP layer: it replays
//! the exact JSON sequence `wallet.js` emits against a recording
//! `WalletAdmin` and asserts the resulting trait-call order and arguments.
//!
//! Rust integration tests have no DOM, so the in-memory "mnemonic /
//! passphrase cleared from the JS carrier after use" claims are not
//! asserted here — they move to the manual smoke checklist in the plan.
//! What is mechanically checkable — call order, same-passphrase linkage,
//! the `usePre1627KeyDerivation` checkbox polarity, and that a failed
//! unlock fires no further state mutation — is pinned below.

use std::sync::{Arc, Mutex};

use axum::body::Body;
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

/// One recorded state-mutating call, in arrival order.
#[derive(Debug, Clone, PartialEq)]
enum Call {
    Init {
        pass: String,
        mnemonic_pass: String,
        strength: u8,
    },
    Restore {
        mnemonic: String,
        mnemonic_pass: String,
        pass: String,
        use_pre_1627: bool,
    },
    Unlock {
        pass: String,
    },
}

/// Records the init/restore/unlock calls the router makes, in order.
/// `unlock_fails` flips `unlock` to the `wrong_password` (401) path so
/// the failure-stops-the-sequence case is exercisable.
struct RecordingAdmin {
    calls: Mutex<Vec<Call>>,
    unlock_fails: bool,
}

impl RecordingAdmin {
    fn new(unlock_fails: bool) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            unlock_fails,
        })
    }
    fn log(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl WalletAdmin for RecordingAdmin {
    async fn init(
        &self,
        pass: String,
        mnemonic_pass: String,
        strength: u8,
    ) -> Result<String, WalletAdminError> {
        self.calls.lock().unwrap().push(Call::Init {
            pass,
            mnemonic_pass,
            strength,
        });
        // Shape mirrors a real init response; contents are irrelevant here.
        Ok(
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
                .to_string(),
        )
    }
    async fn restore(
        &self,
        mnemonic: String,
        mnemonic_pass: String,
        pass: String,
        use_pre_1627: bool,
    ) -> Result<(), WalletAdminError> {
        self.calls.lock().unwrap().push(Call::Restore {
            mnemonic,
            mnemonic_pass,
            pass,
            use_pre_1627,
        });
        Ok(())
    }
    async fn unlock(&self, pass: String) -> Result<(), WalletAdminError> {
        self.calls.lock().unwrap().push(Call::Unlock { pass });
        if self.unlock_fails {
            Err(WalletAdminError::WrongPassword)
        } else {
            Ok(())
        }
    }

    // --- everything else is irrelevant to this flow ---
    async fn status(&self) -> Result<WalletStatus, WalletAdminError> {
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

fn app(admin: Arc<RecordingAdmin>) -> axum::Router {
    let admin: Arc<dyn WalletAdmin> = admin;
    ergo_api::wallet::router_with_security(admin, None)
}

/// POST a JSON body to `path`, returning the status. Each call clones the
/// router (cheap) so the shared admin Arc accumulates across requests.
async fn post(router: &axum::Router, path: &str, body: serde_json::Value) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// ----- two-step ordering -----

#[tokio::test]
async fn init_is_followed_by_unlock_with_the_same_pass() {
    let admin = RecordingAdmin::new(false);
    let router = app(admin.clone());

    assert_eq!(
        post(
            &router,
            "/wallet/init",
            serde_json::json!({ "pass": "pw1", "mnemonicPass": "", "strength": 24 })
        )
        .await,
        StatusCode::OK,
    );
    assert_eq!(
        post(
            &router,
            "/wallet/unlock",
            serde_json::json!({ "pass": "pw1" })
        )
        .await,
        StatusCode::OK,
    );

    assert_eq!(
        admin.log(),
        vec![
            Call::Init {
                pass: "pw1".into(),
                mnemonic_pass: "".into(),
                strength: 24
            },
            Call::Unlock { pass: "pw1".into() },
        ],
    );
}

#[tokio::test]
async fn restore_is_followed_by_unlock_with_the_same_pass() {
    let admin = RecordingAdmin::new(false);
    let router = app(admin.clone());

    assert_eq!(
        post(&router, "/wallet/restore", serde_json::json!({
            "mnemonic": PHRASE, "mnemonicPass": "", "pass": "pw2", "usePre1627KeyDerivation": true,
        })).await,
        StatusCode::OK,
    );
    assert_eq!(
        post(
            &router,
            "/wallet/unlock",
            serde_json::json!({ "pass": "pw2" })
        )
        .await,
        StatusCode::OK,
    );

    assert_eq!(
        admin.log(),
        vec![
            Call::Restore {
                mnemonic: PHRASE.into(),
                mnemonic_pass: "".into(),
                pass: "pw2".into(),
                use_pre_1627: true
            },
            Call::Unlock { pass: "pw2".into() },
        ],
    );
}

// ----- unlock failure -----

#[tokio::test]
async fn failed_unlock_after_init_fires_no_further_state_mutation() {
    let admin = RecordingAdmin::new(true); // unlock → 401
    let router = app(admin.clone());

    assert_eq!(
        post(
            &router,
            "/wallet/init",
            serde_json::json!({ "pass": "pw3", "mnemonicPass": "", "strength": 15 })
        )
        .await,
        StatusCode::OK,
    );
    assert_eq!(
        post(
            &router,
            "/wallet/unlock",
            serde_json::json!({ "pass": "pw3" })
        )
        .await,
        StatusCode::UNAUTHORIZED,
    );

    // The flow stops at the failed unlock: exactly [init, unlock], no third
    // state-mutating call. (wallet.js surfaces the error and hands off to
    // the status view rather than auto-retrying.)
    let log = admin.log();
    assert_eq!(
        log,
        vec![
            Call::Init {
                pass: "pw3".into(),
                mnemonic_pass: "".into(),
                strength: 15
            },
            Call::Unlock { pass: "pw3".into() },
        ],
    );
    assert_eq!(log.len(), 2, "no state mutation may follow a failed unlock");
}

// ----- checkbox polarity -----

#[tokio::test]
async fn restore_checkbox_unticked_sends_use_pre_1627_true() {
    // Default state: the "use modern EIP-3 derivation" box is unticked, so
    // wallet.js sends usePre1627KeyDerivation = true (legacy / CLI default).
    let admin = RecordingAdmin::new(false);
    let router = app(admin.clone());

    assert_eq!(
        post(&router, "/wallet/restore", serde_json::json!({
            "mnemonic": PHRASE, "mnemonicPass": "", "pass": "pw", "usePre1627KeyDerivation": true,
        })).await,
        StatusCode::OK,
    );

    match &admin.log()[0] {
        Call::Restore { use_pre_1627, .. } => assert!(*use_pre_1627, "unticked → true"),
        other => panic!("expected a restore call, got {other:?}"),
    }
}

#[tokio::test]
async fn restore_checkbox_ticked_sends_use_pre_1627_false() {
    // Ticked: modern EIP-3 derivation → usePre1627KeyDerivation = false.
    let admin = RecordingAdmin::new(false);
    let router = app(admin.clone());

    assert_eq!(
        post(&router, "/wallet/restore", serde_json::json!({
            "mnemonic": PHRASE, "mnemonicPass": "", "pass": "pw", "usePre1627KeyDerivation": false,
        })).await,
        StatusCode::OK,
    );

    match &admin.log()[0] {
        Call::Restore { use_pre_1627, .. } => assert!(!*use_pre_1627, "ticked → false"),
        other => panic!("expected a restore call, got {other:?}"),
    }
}
