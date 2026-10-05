//! Auth-gate regression for the Scala-compat `/mining/*` routes.
//!
//! `POST /mining/solution` injects a PoW solution into the block pipeline,
//! the candidate longpoll holds an API task, and the reward routes leak
//! the miner payout identity — operator surface that used to be mounted
//! with no gate. All four routes now sit behind the same
//! api_key middleware as `/node/shutdown`. An absent verifier denies access.
//!
//! Pinned on the *real* merged router (`router_with_mempool_and_wallet_and_security`
//! with `mining = Some(NoopNodeMining)`, `security = Some(hello)`):
//! - without key → 403 from the gate (never a handler verdict)
//! - with key → the Noop handler's own 503 "unavailable" verdict, proving
//!   the request got through the gate to the route

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ergo_api::auth::{ApiSecurity, API_KEY_HEADER};
use ergo_api::server::{router_with_mempool_and_wallet_and_security, ServerCtx};
use ergo_api::traits::{NodeReadState, NoopMempoolView};
use ergo_api::types::{
    ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction, ApiMempoolTransactions, ApiPeer,
    ApiStatus, ApiSyncStatus, ApiTip,
};
use ergo_api::wallet::NoopWalletAdmin;
use ergo_api::NoopNodeMining;
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

// ----- helpers -----

const PLAINTEXT_KEY: &str = "hello";
const SCALA_HELLO_HASH: &str = "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf";

/// `NodeReadState` stub whose methods panic if reached: every route this
/// test exercises lives in the mining family.
struct UnusedReadState;

impl NodeReadState for UnusedReadState {
    fn info(&self) -> ApiInfo {
        unreachable!("mining auth test never hits the read surface")
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

fn app() -> axum::Router {
    app_with_legacy(false)
}

fn app_with_legacy(allow: bool) -> axum::Router {
    app_with_mining_and_security(
        Arc::new(NoopNodeMining),
        Arc::new(
            ApiSecurity::new(SCALA_HELLO_HASH.to_string())
                .unwrap()
                .with_unauthenticated_legacy_mining(allow),
        ),
    )
}

fn app_with_mining_and_security(
    mining: Arc<dyn ergo_api::mining::NodeMining>,
    security: Arc<ApiSecurity>,
) -> axum::Router {
    let ctx = ServerCtx {
        read: Arc::new(UnusedReadState),
        compat: None,
        submit: None,
        indexer: None,
        mempool: Arc::new(NoopMempoolView::new()),
        network: NetworkPrefix::Mainnet,
        chain_params: None,
        mining: Some(mining),
        emission: None,
        emission_scripts: None,
        utxo_reads_supported: true,
        local_reverse_proxy: false,
        services: Arc::new(ergo_api::ApiServices::new()),
        script_config: Default::default(),
    };
    router_with_mempool_and_wallet_and_security(
        ctx,
        None,
        Arc::new(NoopWalletAdmin),
        Some(security),
    )
}

fn get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

fn post(path: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

fn post_json(path: &str, json: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(json.to_owned()))
        .unwrap()
}

fn with_key(mut req: Request<Body>) -> Request<Body> {
    req.headers_mut()
        .insert(API_KEY_HEADER, PLAINTEXT_KEY.parse().unwrap());
    req
}

// ----- the gate -----

#[tokio::test]
async fn mining_candidate_403_without_key_503_with_key() {
    // Without key: the gate answers 403 before any handler runs.
    let resp = app().oneshot(get("/mining/candidate")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // With key: the request reaches the Noop handler, which reports the
    // mining subsystem unavailable (503) — proving the gate opened.
    let resp = app()
        .oneshot(with_key(get("/mining/candidate")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn mining_solution_gated_403_then_503_with_key() {
    // The mutating route: solution submission must never answer without
    // the key. (An empty body would be a 4xx decode error at the handler;
    // a 403 here can only come from the gate.)
    let resp = app().oneshot(post("/mining/solution")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // With the key and a well-formed solution body, the request reaches
    // the NoopNodeMining handler, which reports the mining subsystem
    // unavailable (503) — proving the gate opened for the mutating route
    // too, not just the reads.
    let resp = app()
        .oneshot(with_key(post_json(
            "/mining/solution",
            r#"{"n":"0001020304050607"}"#,
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn mining_reward_address_gated_but_reachable_with_key() {
    let resp = app().oneshot(get("/mining/rewardAddress")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app()
        .oneshot(with_key(get("/mining/rewardAddress")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn mining_reward_pubkey_gated() {
    let resp = app().oneshot(get("/mining/rewardPublicKey")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app()
        .oneshot(with_key(get("/mining/rewardPublicKey")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn transaction_candidates_always_require_key_and_reach_handler_with_key() {
    const PK: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    for allow in [false, true] {
        for (path, body) in [
            ("/mining/candidateWithTxs", "[]".to_owned()),
            (
                "/mining/candidateWithTxsAndPk",
                format!(r#"{{"txs":[],"pk":"{PK}"}}"#),
            ),
        ] {
            let resp = app_with_legacy(allow)
                .oneshot(post_json(path, &body))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            let resp = app_with_legacy(allow)
                .oneshot(with_key(post_json(path, &body)))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    }
}

#[tokio::test]
async fn legacy_mining_openapi_preserves_numbers_and_only_changes_legacy_security() {
    let flag_off = app_with_legacy(false);
    let flag_on = app_with_legacy(true);
    for endpoint in ["/api-docs/openapi.yaml", "/api-docs/openapi-scala.yaml"] {
        let mut documents = Vec::new();
        for router in [&flag_off, &flag_on] {
            let response = router.clone().oneshot(get(endpoint)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let yaml = std::str::from_utf8(&bytes).unwrap();
            assert!(
                !yaml.contains("serde_json::private"),
                "{endpoint} must preserve YAML numbers"
            );
            documents.push(serde_norway::from_str::<serde_norway::Value>(yaml).unwrap());
        }
        let mut enabled = documents.pop().unwrap();
        let baseline = documents.pop().unwrap();
        for (path, method) in [
            ("/mining/candidate", "get"),
            ("/mining/solution", "post"),
            ("/mining/rewardAddress", "get"),
            ("/mining/rewardPublicKey", "get"),
        ] {
            let security = &baseline["paths"][path][method]["security"];
            assert!(!security.as_sequence().unwrap().is_empty());
            assert_eq!(
                enabled["paths"][path][method]["security"],
                serde_norway::Value::Sequence(Vec::new()),
                "{endpoint}: {method} {path} must allow legacy mining"
            );
            enabled["paths"][path][method]["security"] = security.clone();
        }
        for path in ["/mining/candidateWithTxs", "/mining/candidateWithTxsAndPk"] {
            let security = &enabled["paths"][path]["post"]["security"];
            assert!(!security.as_sequence().unwrap().is_empty());
            assert_eq!(security, &baseline["paths"][path]["post"]["security"]);
        }
        assert_eq!(
            enabled, baseline,
            "{endpoint} must change only the four legacy security fields"
        );
    }
}

#[tokio::test]
async fn legacy_opt_in_opens_existing_routes_and_updates_served_docs() {
    for request in [
        get("/mining/candidate"),
        get("/mining/rewardAddress"),
        get("/mining/rewardPublicKey"),
        post_json("/mining/solution", r#"{"n":"0001020304050607"}"#),
    ] {
        let resp = app_with_legacy(true).oneshot(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    for allow in [false, true] {
        let resp = app_with_legacy(allow)
            .oneshot(get("/api-docs/openapi-scala.yaml"))
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let document: serde_json::Value = serde_norway::from_slice(&bytes).unwrap();
        let legacy = &document["paths"]["/mining/solution"]["post"]["security"];
        assert_eq!(legacy.as_array().unwrap().is_empty(), allow);
        assert!(
            !document["paths"]["/mining/candidateWithTxsAndPk"]["post"]["security"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn mining_candidate_inventory_and_history_require_operator_key() {
    for path in [
        "/api/v1/mining/candidate-details",
        "/api/v1/mining/history",
        "/api/v1/mining/policy",
    ] {
        assert_eq!(
            app().oneshot(get(path)).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "{path} must not expose private candidate content"
        );
        assert_eq!(
            app().oneshot(with_key(get(path))).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{path} must reach the authenticated handler"
        );
    }
}

#[tokio::test]
async fn mining_policy_mutation_requires_operator_key() {
    let request = || {
        axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/mining/policy")
            .header("content-type", "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap()
    };
    assert_eq!(
        app().oneshot(request()).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app().oneshot(with_key(request())).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn private_queue_routes_require_owner_key_before_parsing_signed_bytes() {
    let requests = [
        get("/api/v1/mining/private-transactions"),
        post_json("/api/v1/mining/private-transactions", r#"{"signed_transaction_hex":"00","options":{}}"#),
        post("/api/v1/mining/private-transactions/0000000000000000000000000000000000000000000000000000000000000000/cancel"),
    ];
    for req in requests {
        let response = app().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = app()
        .oneshot(with_key(get("/api/v1/mining/private-transactions")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn private_wallet_options_require_explicit_private_delivery() {
    use ergo_api::wallet::native::dto::{SendTxRequest, TxDelivery};
    let value = serde_json::json!({"type":"signed", "signedTransaction":{"type":"bytes", "bytes":"00"}, "privateOptions":{"expires_at_height":100}});
    assert!(serde_json::from_value::<SendTxRequest>(value.clone()).is_err());
    let mut private = value;
    private["delivery"] = serde_json::json!("mine_private");
    let request: SendTxRequest = serde_json::from_value(private).unwrap();
    assert!(matches!(
        request,
        SendTxRequest::Signed {
            delivery: TxDelivery::MinePrivate,
            ..
        }
    ));
}

#[tokio::test]
async fn legacy_opt_in_keeps_native_mining_operator_routes_authenticated() {
    for allow in [false, true] {
        let mut requests: Vec<_> = [
            "/api/v1/mining/candidate-details",
            "/api/v1/mining/history",
            "/api/v1/mining/policy",
            "/api/v1/mining/private-transactions",
        ]
        .into_iter()
        .map(get)
        .collect();
        requests.extend([
            post_json("/api/v1/mining/candidate-with-txs", "[]"),
            post_json("/api/v1/mining/private-transactions", r#"{"signed_transaction_hex":"00","options":{}}"#),
            post("/api/v1/mining/private-transactions/0000000000000000000000000000000000000000000000000000000000000000/cancel"),
            axum::http::Request::builder().method("PUT").uri("/api/v1/mining/policy")
                .header("content-type", "application/json").body(axum::body::Body::from("{}")).unwrap(),
        ]);
        for request in requests {
            let path = request.uri().to_string();
            assert_eq!(
                app_with_legacy(allow)
                    .oneshot(request)
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED,
                "{path}, legacy opt-in={allow}"
            );
        }
        let response = app_with_legacy(allow)
            .oneshot(with_key(post_json(
                "/api/v1/mining/candidate-with-txs",
                "[]",
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

// A working backend makes HTTP 200 prove that scoped admission reaches the
// handler, including JSON decoding on the supplied-transaction routes.
struct WorkingMining;

const MINER_PK: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

#[async_trait::async_trait]
impl ergo_api::mining::NodeMining for WorkingMining {
    async fn candidate(
        &self,
        _: Option<String>,
    ) -> Result<Option<ergo_rest_json::mining::WorkMessageJson>, ergo_api::mining::MiningApiError>
    {
        Ok(Some(ergo_rest_json::mining::WorkMessageJson {
            msg: "00".repeat(32),
            b: 1u8.into(),
            h: Some(1),
            pk: MINER_PK.into(),
            proof: None,
            template_seq: 1,
            clean_jobs: true,
            metrics: None,
        }))
    }

    async fn candidate_with_txs(
        &self,
        txs: Vec<ergo_rest_json::ScalaTransactionInput>,
        pk: Option<String>,
    ) -> Result<Option<ergo_rest_json::mining::WorkMessageJson>, ergo_api::mining::MiningApiError>
    {
        assert!(txs.is_empty());
        assert!(pk.is_none_or(|pk| pk == MINER_PK));
        self.candidate(None).await
    }

    async fn submit_solution(
        &self,
        _: ergo_rest_json::mining::AutolykosSolutionJson,
    ) -> Result<(), ergo_api::mining::MiningApiError> {
        Ok(())
    }

    async fn reward_address(&self) -> Result<String, ergo_api::mining::MiningApiError> {
        Ok("reward-address".into())
    }

    async fn reward_pubkey(&self) -> Result<String, ergo_api::mining::MiningApiError> {
        Ok(MINER_PK.into())
    }
}

#[tokio::test]
async fn scoped_transaction_candidates_preserve_legacy_bypass_and_revocation() {
    use ergo_api::auth::{CredentialScope, ScopedCredentialConfig};

    for allow in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let security = Arc::new(
            ApiSecurity::new(SCALA_HELLO_HASH.into())
                .unwrap()
                .with_credentials(
                    [
                        ("miner", CredentialScope::Mining),
                        ("wallet", CredentialScope::Wallet),
                    ]
                    .into_iter()
                    .map(|(id, scope)| ScopedCredentialConfig {
                        id: id.into(),
                        hash: ApiSecurity::hash_key(id.as_bytes()),
                        scopes: vec![scope],
                        revoked: false,
                    })
                    .collect(),
                    dir.path().join("revoked.json"),
                )
                .unwrap()
                .with_unauthenticated_legacy_mining(allow),
        );
        let app = app_with_mining_and_security(Arc::new(WorkingMining), security.clone());
        for request in [
            get("/mining/candidate"),
            get("/mining/rewardAddress"),
            get("/mining/rewardPublicKey"),
            post_json("/mining/solution", r#"{"n":"0001020304050607"}"#),
        ] {
            assert_eq!(
                app.clone().oneshot(request).await.unwrap().status(),
                if allow {
                    StatusCode::OK
                } else {
                    StatusCode::FORBIDDEN
                },
            );
        }
        let with_pk = format!(r#"{{"txs":[],"pk":"{MINER_PK}"}}"#);
        for (path, body, refused) in [
            ("/mining/candidateWithTxs", "[]", StatusCode::FORBIDDEN),
            (
                "/mining/candidateWithTxsAndPk",
                with_pk.as_str(),
                StatusCode::FORBIDDEN,
            ),
            (
                "/api/v1/mining/candidate-with-txs",
                "[]",
                StatusCode::UNAUTHORIZED,
            ),
            (
                "/api/v1/mining/candidate-with-txs",
                with_pk.as_str(),
                StatusCode::UNAUTHORIZED,
            ),
        ] {
            for (key, status) in [
                (None, refused),
                (Some("wallet"), refused),
                (Some("miner"), StatusCode::OK),
            ] {
                let mut request = post_json(path, body);
                if let Some(key) = key {
                    request
                        .headers_mut()
                        .insert(API_KEY_HEADER, key.parse().unwrap());
                }
                assert_eq!(
                    app.clone().oneshot(request).await.unwrap().status(),
                    status,
                    "{path}: {key:?}, legacy={allow}"
                );
            }
        }
        security.revoke_credential("miner").unwrap();
        for (path, body, refused) in [
            ("/mining/candidateWithTxs", "[]", StatusCode::FORBIDDEN),
            (
                "/mining/candidateWithTxsAndPk",
                with_pk.as_str(),
                StatusCode::FORBIDDEN,
            ),
            (
                "/api/v1/mining/candidate-with-txs",
                "[]",
                StatusCode::UNAUTHORIZED,
            ),
        ] {
            let mut request = post_json(path, body);
            request
                .headers_mut()
                .insert(API_KEY_HEADER, "miner".parse().unwrap());
            assert_eq!(
                app.clone().oneshot(request).await.unwrap().status(),
                refused,
                "revoked key: {path}, legacy={allow}"
            );
        }
    }
}
