//! Auth-gate regression for the Scala-compat `/mining/*` routes.
//!
//! `POST /mining/solution` injects a PoW solution into the block pipeline,
//! the candidate longpoll holds an API task, and the reward routes leak
//! the miner payout identity — operator surface that used to be mounted
//! with no gate (audit finding M-2; drift flagged in
//! `dev-docs/v1-api-design.md`). All four routes now sit behind the same
//! api_key middleware as `/node/shutdown` whenever security is wired —
//! which production always does, since config load mandates
//! `api_key_hash` whenever the API server is enabled.
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
    let ctx = ServerCtx {
        read: Arc::new(UnusedReadState),
        compat: None,
        submit: None,
        indexer: None,
        mempool: Arc::new(NoopMempoolView::new()),
        network: NetworkPrefix::Mainnet,
        chain_params: None,
        mining: Some(Arc::new(NoopNodeMining)),
        emission: None,
        emission_scripts: None,
        utxo_reads_supported: true,
    };
    router_with_mempool_and_wallet_and_security(
        ctx,
        None,
        Arc::new(NoopWalletAdmin),
        Some(Arc::new(
            ApiSecurity::new(SCALA_HELLO_HASH.to_string()).expect("valid hex hash"),
        )),
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
