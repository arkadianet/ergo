//! `POST /script/p2sAddress` + `POST /script/p2shAddress` — the two
//! compile-requiring members of Scala's `ScriptApiRoute` (M6).
//!
//! End-to-end routing/extractor coverage on top of `crate::script`'s own
//! `build_env` unit tests: drives the real handlers through axum routing
//! with the `(NetworkPrefix, Arc<dyn WalletAdmin>)` tuple state, so the
//! `Json`/`State` extractors, the wallet-address-to-env plumbing, and the
//! compile-error->400 mapping are exercised, not just the pure pieces.
//!
//! No live Scala node needed: expected addresses are derived by calling
//! `ergo_compiler::compile` directly (itself extensively oracle-verified
//! elsewhere, M1-M5) and asserting the ROUTE agrees — this pins the route's
//! OWN plumbing (DTO parsing, env construction from wallet addresses,
//! response shape), which is what's new here.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use axum::routing::post;
use axum::Router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction, ApiMempoolTransactions, ApiPeer,
    ApiStatus, ApiSyncStatus, ApiTip,
};
use ergo_api::wallet::sending::{
    BoxesCollectRequest, BoxesCollectResponse, PaymentRequestDto, TransactionGenerateRequest,
    TransactionGenerateResponse, TransactionGenerateUnsignedRequest,
    TransactionGenerateUnsignedResponse, TransactionSendRequest, TransactionSignRequest,
    TransactionSignResponse,
};
use ergo_api::wallet::types::*;
use ergo_api::wallet::{WalletAdmin, WalletAdminError};
use ergo_compiler::{EnvValue, NetworkPrefix, ScriptEnv};
use ergo_ser::address::decode_p2pk_address;
use tower::ServiceExt;

// ----- helpers -----

/// A real mainnet P2PK address (same vector `ergo-api/tests/
/// script_address_routes.rs` and `crate::script`'s own unit tests use).
const ADDR: &str = "9gZyL9m7J9eJv7h6gvxurbD986nWkw44NmHBgMkcxGezesPiETp";

/// Minimal `WalletAdmin` stub: only `addresses()` is reachable from these
/// two routes, so every other method is `unimplemented!()` — mirrors
/// `ergo-api/tests/wallet_stubs.rs`'s `MinimalAdmin` pattern.
struct StubAdmin {
    addrs: Vec<String>,
    /// When set, `addresses()` fails with `WalletAdminError::Locked` — drives
    /// the route's `wallet_error_response` not-ready branch (400, not 500).
    fail_locked: bool,
}

#[async_trait::async_trait]
impl WalletAdmin for StubAdmin {
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
        if self.fail_locked {
            return Err(WalletAdminError::Locked);
        }
        Ok(WalletAddressList(self.addrs.clone()))
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

fn app(addrs: Vec<String>) -> Router {
    let admin: Arc<dyn WalletAdmin> = Arc::new(StubAdmin {
        addrs,
        fail_locked: false,
    });
    Router::new()
        .route(
            "/script/p2sAddress",
            post(ergo_api::script::p2s_address_handler),
        )
        .route(
            "/script/p2shAddress",
            post(ergo_api::script::p2sh_address_handler),
        )
        .with_state((NetworkPrefix::Mainnet, admin))
}

async fn post_json(router: Router, uri: &str, body: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// `NodeReadState` stub whose methods panic if reached -- the real-router
/// wiring test below never touches the read surface (the two `/script/*`
/// compile routes need only `NetworkPrefix` + `WalletAdmin`), so a call here
/// would mean a routing regression.
struct UnusedReadState;

impl NodeReadState for UnusedReadState {
    fn info(&self) -> ApiInfo {
        unreachable!()
    }
    fn status(&self) -> ApiStatus {
        unreachable!()
    }
    fn tip(&self) -> ApiTip {
        unreachable!()
    }
    fn sync(&self) -> ApiSyncStatus {
        unreachable!()
    }
    fn peers(&self) -> Vec<ApiPeer> {
        unreachable!()
    }
    fn mempool_summary(&self) -> ApiMempoolSummary {
        unreachable!()
    }
    fn mempool_transactions(&self) -> ApiMempoolTransactions {
        unreachable!()
    }
    fn mempool_transaction(&self, _tx_id_hex: &str) -> Option<ApiMempoolTransaction> {
        unreachable!()
    }
    fn health(&self) -> ApiHealth {
        unreachable!()
    }
}

// ----- happy path -----

#[tokio::test]
async fn p2s_address_route_matches_direct_compile() {
    let source = "sigmaProp(HEIGHT > 100)";
    let expected = ergo_compiler::compile(&ScriptEnv::new(), source, 0, NetworkPrefix::Mainnet)
        .expect("compiles");

    let body = serde_json::json!({ "source": source, "treeVersion": 0 }).to_string();
    let (status, json) = post_json(app(vec![]), "/script/p2sAddress", &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["address"], expected.p2s_address);
}

#[tokio::test]
async fn p2sh_address_route_matches_direct_compile() {
    let source = "sigmaProp(HEIGHT > 100)";
    let expected = ergo_compiler::compile(&ScriptEnv::new(), source, 0, NetworkPrefix::Mainnet)
        .expect("compiles");

    let body = serde_json::json!({ "source": source, "treeVersion": 0 }).to_string();
    let (status, json) = post_json(app(vec![]), "/script/p2shAddress", &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["address"], expected.p2sh_address);
}

#[tokio::test]
async fn p2s_address_route_injects_wallet_pubkey_env() {
    // Scala keysToEnv parity: a script referencing `myPubKey_0` compiles
    // against the FIRST tracked wallet address, exactly as if that address's
    // decoded pubkey had been lifted via `EnvValue::ProveDlog` directly —
    // proves the route's wallet-address-to-env wiring actually runs, not
    // just documents the intent.
    let pk = decode_p2pk_address(ADDR, NetworkPrefix::Mainnet).expect("decode");
    let mut env = ScriptEnv::new();
    env.insert("myPubKey_0", EnvValue::ProveDlog(pk));
    let expected =
        ergo_compiler::compile(&env, "myPubKey_0", 0, NetworkPrefix::Mainnet).expect("compiles");

    let body = serde_json::json!({ "source": "myPubKey_0", "treeVersion": 0 }).to_string();
    let (status, json) = post_json(app(vec![ADDR.to_string()]), "/script/p2sAddress", &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["address"], expected.p2s_address);
}

#[tokio::test]
async fn p2s_address_route_empty_wallet_still_compiles_keyless_script() {
    // Decision 4 (M6 report): an empty tracked-address list yields an empty
    // env, not an error — a script that doesn't reference `myPubKey_N` still
    // compiles (Scala's `keysToEnv` has no wallet-state precondition either).
    let body =
        serde_json::json!({ "source": "sigmaProp(HEIGHT > 100)", "treeVersion": 0 }).to_string();
    let (status, _json) = post_json(app(vec![]), "/script/p2sAddress", &body).await;
    assert_eq!(status, StatusCode::OK);
}

// ----- error paths -----

#[tokio::test]
async fn p2s_address_route_keyless_reference_on_empty_wallet_is_bad_request() {
    // Scala parity (recon §3): an EMPTY env means `myPubKey_0` fails to
    // resolve at bind/emit -- a 400, exactly like any other compile failure,
    // not a 500.
    let body = serde_json::json!({ "source": "myPubKey_0", "treeVersion": 0 }).to_string();
    let (status, json) = post_json(app(vec![]), "/script/p2sAddress", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], 400);
    assert_eq!(json["reason"], "bad-request");
}

#[tokio::test]
async fn p2s_address_route_invalid_source_is_bad_request() {
    let body = serde_json::json!({ "source": "{{{ not ergoscript", "treeVersion": 0 }).to_string();
    let (status, json) = post_json(app(vec![]), "/script/p2sAddress", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], 400);
    assert_eq!(json["reason"], "bad-request");
    assert!(json["detail"].as_str().is_some());
}

#[tokio::test]
async fn p2sh_address_route_invalid_source_is_bad_request() {
    let body = serde_json::json!({ "source": "{{{ not ergoscript", "treeVersion": 0 }).to_string();
    let (status, json) = post_json(app(vec![]), "/script/p2shAddress", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["reason"], "bad-request");
}

#[tokio::test]
async fn p2s_address_route_locked_wallet_maps_to_400_not_500() {
    // Drives the `wallet_error_response` not-ready branch through the route
    // layer: a Locked wallet is a well-formed request against a wallet that
    // isn't ready (400 + the standard bad-request envelope), never a 500.
    let admin: Arc<dyn WalletAdmin> = Arc::new(StubAdmin {
        addrs: vec![],
        fail_locked: true,
    });
    let router = Router::new()
        .route(
            "/script/p2sAddress",
            post(ergo_api::script::p2s_address_handler),
        )
        .with_state((NetworkPrefix::Mainnet, admin));
    let body = serde_json::json!({ "source": "sigmaProp(true)", "treeVersion": 0 }).to_string();
    let (status, json) = post_json(router, "/script/p2sAddress", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["reason"], "bad-request");
    assert!(json["detail"]
        .as_str()
        .is_some_and(|d| d.contains("wallet not ready")));
}

#[tokio::test]
async fn p2s_address_route_boolean_root_compiles_via_bool_to_sigmaprop() {
    // ScriptApiRoute.scala:60-65 root dispatch: a bare Boolean root wraps via
    // BoolToSigmaProp -- exercised end-to-end through the route (not just
    // `tree::compile`'s own unit tests).
    let body = serde_json::json!({ "source": "HEIGHT > 100", "treeVersion": 0 }).to_string();
    let (status, json) = post_json(app(vec![]), "/script/p2sAddress", &body).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["address"].as_str().is_some());
}

// ----- real merged-router wiring (not the hand-built `app()` above) -----

#[tokio::test]
async fn p2s_address_route_is_reachable_and_public_on_the_real_merged_router() {
    // Drives `ergo_api::server::router_with_wallet` -- the SAME builder
    // `router_with_mempool_and_wallet_and_security` delegates through, with
    // `security = None` -- proving the `server.rs` merge (the new
    // `script_routes` tuple-state sub-router beside `utils_routes`) actually
    // wires `/script/p2sAddress` into the assembled router, not just the
    // hand-built single-purpose router `app()` exercises above. Also proves
    // the route is PUBLIC (no api_key required, unlike `/wallet/*`) --
    // Scala's `ScriptApiRoute` carries no `withAuth` (decision 1).
    let admin: Arc<dyn WalletAdmin> = Arc::new(StubAdmin {
        addrs: vec![],
        fail_locked: false,
    });
    let router = ergo_api::server::router_with_wallet(
        Arc::new(UnusedReadState),
        None,
        None,
        None,
        NetworkPrefix::Mainnet,
        true,
        admin,
    );
    let body =
        serde_json::json!({ "source": "sigmaProp(HEIGHT > 100)", "treeVersion": 0 }).to_string();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/script/p2sAddress")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "route must be reachable, unauthenticated, on the real assembled router"
    );
}
