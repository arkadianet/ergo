//! Every privileged mount must reject before dispatch when no key is configured.
use super::compat_submit_routes::{StubCompat, StubReadState};
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use ergo_api::{
    auth::{ApiSecurity, API_KEY_HEADER},
    mining::{MiningApiError, NodeMining},
    server::{router_with_mempool_and_wallet_and_security, ServerCtx},
    traits::{NodeAdmin, NodeSubmit, NoopMempoolView, VotingControlError},
    types::{SubmitError, SubmitMode},
    wallet::{admin_advanced, multi_sig, sending, types, WalletAdmin, WalletAdminError},
};
use ergo_rest_json::mining::{AutolykosSolutionJson, WorkMessageJson};
use ergo_ser::address::NetworkPrefix;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tower::ServiceExt;

// ----- helpers -----

// Scala src/main/resources/mainnet.conf: scorex.restApi.apiKeyHash.
const SCALA_HELLO_HASH: &str = "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf";
const GUIDANCE: &str =
    "API key not configured: set [api.security] api_key_hash (see docs/configuration.md)";

#[derive(Default)]
struct Dispatch(AtomicUsize);
impl Dispatch {
    fn record(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn calls(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}
impl NodeAdmin for Dispatch {
    fn request_shutdown(&self) {
        self.record();
    }
    fn connect_to_peer(&self, _: std::net::SocketAddr) {
        self.record();
    }
    fn set_voting_targets(&self, _: Vec<(u8, i64)>) -> Result<(), VotingControlError> {
        self.record();
        Ok(())
    }
}
#[async_trait]
impl NodeMining for Dispatch {
    async fn candidate(
        &self,
        _: Option<String>,
    ) -> Result<Option<WorkMessageJson>, MiningApiError> {
        self.record();
        Ok(None)
    }
    async fn submit_solution(&self, _: AutolykosSolutionJson) -> Result<(), MiningApiError> {
        self.record();
        Ok(())
    }
    async fn reward_address(&self) -> Result<String, MiningApiError> {
        self.record();
        Ok("reward-address".into())
    }
    async fn reward_pubkey(&self) -> Result<String, MiningApiError> {
        self.record();
        Ok("reward-pubkey".into())
    }
}
#[async_trait]
impl NodeSubmit for Dispatch {
    async fn submit_transaction(&self, _: Vec<u8>, _: SubmitMode) -> Result<String, SubmitError> {
        self.record();
        Ok("accepted".into())
    }
    async fn submit_transaction_json(
        &self,
        _: ergo_api::compat::types::ScalaTransactionInput,
        _: SubmitMode,
    ) -> Result<String, SubmitError> {
        self.record();
        Ok("accepted".into())
    }
}
#[async_trait]
impl WalletAdmin for Dispatch {
    async fn status(&self) -> Result<types::WalletStatus, WalletAdminError> {
        self.record();
        Ok(types::WalletStatus::default())
    }

    async fn init(
        &self,
        _pass: String,
        _mnemonic_pass: String,
        _strength_words: u8,
    ) -> Result<String, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn restore(
        &self,
        _mnemonic: String,
        _mnemonic_pass: String,
        _pass: String,
        _use_pre_1627: bool,
    ) -> Result<(), WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn unlock(&self, _pass: String) -> Result<(), WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn lock(&self) -> Result<(), WalletAdminError> {
        self.record();
        Ok(())
    }

    async fn check(
        &self,
        _mnemonic: String,
        _mnemonic_pass: String,
    ) -> Result<bool, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn rescan(&self, _from_height: u32) -> Result<(), WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn update_change_address(&self, _address: String) -> Result<(), WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn balances(&self) -> Result<types::WalletBalances, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn balances_with_unconfirmed(&self) -> Result<types::WalletBalances, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn addresses(&self) -> Result<types::WalletAddressList, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn boxes(&self, _page: types::Page) -> Result<types::WalletBoxesPage, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn boxes_unspent(
        &self,
        _page: types::Page,
    ) -> Result<types::WalletBoxesPage, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn transactions(
        &self,
        _page: types::Page,
    ) -> Result<types::WalletTransactionsPage, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn transaction_by_id(
        &self,
        _tx_id_hex: String,
    ) -> Result<Option<types::WalletTransactionEntry>, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn transactions_by_scan_id(
        &self,
        _scan_id: u32,
        _page: types::Page,
    ) -> Result<types::WalletTransactionsPage, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn payment_send(
        &self,
        _requests: Vec<sending::PaymentRequestDto>,
    ) -> Result<String, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn transaction_generate(
        &self,
        _request: sending::TransactionGenerateRequest,
    ) -> Result<sending::TransactionGenerateResponse, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn transaction_generate_unsigned(
        &self,
        _request: sending::TransactionGenerateUnsignedRequest,
    ) -> Result<sending::TransactionGenerateUnsignedResponse, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn transaction_sign(
        &self,
        _request: sending::TransactionSignRequest,
    ) -> Result<sending::TransactionSignResponse, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn transaction_send(
        &self,
        _request: sending::TransactionSendRequest,
    ) -> Result<String, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn boxes_collect(
        &self,
        _request: sending::BoxesCollectRequest,
    ) -> Result<sending::BoxesCollectResponse, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn generate_commitments(
        &self,
        _request: multi_sig::GenerateCommitmentsRequest,
    ) -> Result<multi_sig::GenerateCommitmentsResponse, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn extract_hints(
        &self,
        _request: multi_sig::HintExtractionRequest,
    ) -> Result<multi_sig::HintExtractionResponse, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn derive_key(
        &self,
        _request: admin_advanced::DeriveKeyRequest,
    ) -> Result<admin_advanced::DeriveKeyResponse, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn derive_next_key(
        &self,
    ) -> Result<admin_advanced::DeriveNextKeyResponse, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }

    async fn get_private_key(
        &self,
        _request: admin_advanced::GetPrivateKeyRequest,
    ) -> Result<admin_advanced::GetPrivateKeyResponse, WalletAdminError> {
        unreachable!("unexpected wallet dispatch")
    }
    async fn deregister_scan(&self, _: u16) -> Result<(), WalletAdminError> {
        self.record();
        Ok(())
    }
}
fn app(configured: bool, dispatch: Arc<Dispatch>) -> axum::Router {
    let ctx = ServerCtx {
        read: Arc::new(StubReadState),
        compat: Some(Arc::new(StubCompat)),
        submit: Some(dispatch.clone()),
        indexer: None,
        mempool: Arc::new(NoopMempoolView::new()),
        network: NetworkPrefix::Mainnet,
        chain_params: None,
        mining: Some(dispatch.clone()),
        emission: None,
        emission_scripts: None,
        utxo_reads_supported: true,
        local_reverse_proxy: false,
    };
    router_with_mempool_and_wallet_and_security(
        ctx,
        Some(dispatch.clone()),
        dispatch,
        configured.then(|| Arc::new(ApiSecurity::new(SCALA_HELLO_HASH.into()).unwrap())),
    )
}

const ROUTES: &[(&str, &str, &str, StatusCode)] = &[
    ("POST", "/node/shutdown", "", StatusCode::ACCEPTED),
    (
        "POST",
        "/peers/connect",
        "\"127.0.0.1:9030\"",
        StatusCode::OK,
    ),
    ("POST", "/api/v1/node/shutdown", "", StatusCode::ACCEPTED),
    (
        "POST",
        "/api/v1/votes",
        r#"{"votes":[]}"#,
        StatusCode::NO_CONTENT,
    ),
    ("GET", "/wallet/status", "", StatusCode::OK),
    ("GET", "/wallet/lock", "", StatusCode::OK),
    (
        "POST",
        "/scan/deregister",
        r#"{"scanId":11}"#,
        StatusCode::OK,
    ),
    ("POST", "/api/v1/wallet/lock", "", StatusCode::OK),
    (
        "GET",
        "/mining/candidate",
        "",
        StatusCode::SERVICE_UNAVAILABLE,
    ),
    (
        "POST",
        "/mining/solution",
        r#"{"n":"0001020304050607"}"#,
        StatusCode::OK,
    ),
    ("GET", "/mining/rewardAddress", "", StatusCode::OK),
    ("GET", "/mining/rewardPublicKey", "", StatusCode::OK),
];

fn request(method: &str, path: &str, body: &str, key: Option<&str>) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(key) = key {
        req = req.header(API_KEY_HEADER, key);
    }
    req.body(Body::from(body.to_owned())).unwrap()
}

// ----- happy path -----

#[tokio::test]
async fn privileged_mounts_configured_valid_key_dispatch_once() {
    for &(method, path, body, expected) in ROUTES {
        let dispatch = Arc::new(Dispatch::default());
        let resp = app(true, dispatch.clone())
            .oneshot(request(method, path, body, Some("hello")))
            .await
            .unwrap();
        assert_eq!(resp.status(), expected, "{method} {path}");
        assert_eq!(dispatch.calls(), 1, "{method} {path}");
    }
}

#[tokio::test]
async fn public_routes_unconfigured_remain_available() {
    let dispatch = Arc::new(Dispatch::default());
    let app = app(false, dispatch.clone());
    for path in ["/", "/info", "/api/v1/votes", "/swagger", "/swagger/native"] {
        let resp = app
            .clone()
            .oneshot(request("GET", path, "", None))
            .await
            .unwrap();
        assert!(
            resp.status().is_success() || resp.status().is_redirection(),
            "{path}: {}",
            resp.status()
        );
    }
    let resp = app
        .oneshot(request("POST", "/transactions/bytes", r#""00""#, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        dispatch.calls(),
        1,
        "public transaction reaches submission boundary"
    );
}

// ----- error paths -----

#[tokio::test]
async fn privileged_mounts_unconfigured_deny_without_dispatch() {
    for &(method, path, body, _) in ROUTES {
        for key in [None, Some("hello"), Some("wrong")] {
            let dispatch = Arc::new(Dispatch::default());
            let resp = app(false, dispatch.clone())
                .oneshot(request(method, path, body, key))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{method} {path}");
            let bytes = to_bytes(resp.into_body(), 16384).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                json,
                serde_json::json!({
                    "error": 403, "reason": "api-key-not-configured", "detail": GUIDANCE,
                }),
                "{method} {path}"
            );
            assert_eq!(dispatch.calls(), 0, "{method} {path} must not dispatch");
        }
    }
}

#[tokio::test]
async fn privileged_mounts_configured_wrong_or_missing_key_deny_without_dispatch() {
    for &(method, path, body, _) in ROUTES {
        for key in [None, Some("wrong")] {
            let dispatch = Arc::new(Dispatch::default());
            let resp = app(true, dispatch.clone())
                .oneshot(request(method, path, body, key))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{method} {path}");
            let bytes = to_bytes(resp.into_body(), 16384).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                json,
                serde_json::json!({
                    "error": 403, "reason": "invalid.api-key", "detail": null,
                }),
                "{method} {path}"
            );
            assert_eq!(dispatch.calls(), 0, "{method} {path} must not dispatch");
        }
    }
}

#[tokio::test]
async fn privileged_prefixes_unconfigured_keep_catchalls_closed() {
    let dispatch = Arc::new(Dispatch::default());
    let app = app(false, dispatch.clone());
    for path in [
        "/node/unknown",
        "/wallet/unknown",
        "/scan/unknown",
        "/api/v1/wallet/unknown",
    ] {
        let resp = app
            .clone()
            .oneshot(request("GET", path, "", None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
        let body = to_bytes(resp.into_body(), 16384).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("api-key-not-configured"));
    }
    let resp = app
        .oneshot(request("GET", "/unknown", "", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(dispatch.calls(), 0);
}
