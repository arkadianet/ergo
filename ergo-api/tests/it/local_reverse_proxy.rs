use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use ergo_api::auth::ApiSecurity;
use ergo_api::server::{
    router_with_mempool_and_wallet_and_security_with_local_reverse_proxy, ServerCtx,
};
use ergo_api::traits::{NodeReadState, NoopMempoolView};
use ergo_api::types::{
    ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction, ApiMempoolTransactions, ApiPeer,
    ApiStatus, ApiSyncStatus, ApiTip,
};
use ergo_api::wallet::NoopWalletAdmin;
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

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

fn app(local_reverse_proxy: bool) -> axum::Router {
    let ctx = ServerCtx {
        read: Arc::new(UnusedReadState),
        compat: None,
        submit: None,
        indexer: None,
        mempool: Arc::new(NoopMempoolView::new()),
        network: NetworkPrefix::Mainnet,
        chain_params: None,
        mining: None,
        emission: None,
        emission_scripts: None,
        utxo_reads_supported: true,
    };
    let security = Arc::new(
        ApiSecurity::new(
            "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf".to_string(),
        )
        .expect("valid api key hash"),
    );
    router_with_mempool_and_wallet_and_security_with_local_reverse_proxy(
        ctx,
        None,
        Arc::new(NoopWalletAdmin),
        Some(security),
        local_reverse_proxy,
    )
}

fn request() -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/script/compile")
        .header("content-type", "application/json")
        .header("x-forwarded-for", "203.0.113.7")
        .body(Body::from("{}"))
        .expect("request");
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    request
}

async fn statuses(app: axum::Router) -> Vec<StatusCode> {
    let mut statuses = Vec::new();
    for _ in 0..8 {
        statuses.push(
            app.clone()
                .oneshot(request())
                .await
                .expect("router response")
                .status(),
        );
    }
    statuses
}

#[tokio::test]
async fn production_router_applies_local_reverse_proxy_to_governor() {
    let proxied = statuses(app(true)).await;
    assert!(proxied.contains(&StatusCode::TOO_MANY_REQUESTS));

    let direct = statuses(app(false)).await;
    assert!(!direct.contains(&StatusCode::TOO_MANY_REQUESTS));
}
