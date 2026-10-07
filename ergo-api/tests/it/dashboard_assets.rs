//! The dashboard is a graph of ES modules, and browsers load it all or nothing:
//! one unrouted import leaves the page at "connecting" forever, as
//! `capabilities.js` and `transaction-source.js` did in 0.12.0-rc.1. Every
//! module under `web/js/` must be served with its exact source, every relative
//! import must name a module that exists, and every stylesheet the page links
//! must be served.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use ergo_api::server::{router_with_mempool_and_wallet_and_security, ServerCtx};
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

fn app() -> axum::Router {
    let ctx = ServerCtx {
        read: Arc::new(UnusedReadState),
        compat: None,
        submit: None,
        indexer: None,
        mempool: Arc::new(NoopMempoolView::new()),
        network: NetworkPrefix::Mainnet,
        chain_params: None,
        wallet_chain: None,
        mining: None,
        emission: None,
        emission_scripts: None,
        utxo_reads_supported: true,
        local_reverse_proxy: false,
        services: Arc::new(ergo_api::ApiServices::new()),
        script_config: Default::default(),
    };
    router_with_mempool_and_wallet_and_security(ctx, None, Arc::new(NoopWalletAdmin), None)
}

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request");
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let response = app.clone().oneshot(request).await.expect("router response");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, body.to_vec())
}

fn web_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("web")
}

/// Every `web/js/*.js` module as (file name, source bytes), sorted by name.
fn modules() -> Vec<(String, Vec<u8>)> {
    let mut modules: Vec<_> = std::fs::read_dir(web_dir().join("js"))
        .expect("web/js")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "js"))
        .map(|path| {
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            (name, std::fs::read(&path).expect("module source"))
        })
        .collect();
    modules.sort();
    modules
}

/// Relative module specifiers (`from './x.js'`, `import('./x.js')`).
fn relative_imports(source: &str) -> Vec<&str> {
    let mut targets = Vec::new();
    for marker in ["from './", "from \"./", "import('./", "import(\"./"] {
        let mut rest = source;
        while let Some(start) = rest.find(marker) {
            let after = &rest[start + marker.len()..];
            let end = after.find(['\'', '"']).unwrap_or(after.len());
            targets.push(&after[..end]);
            rest = &after[end..];
        }
    }
    targets
}

#[tokio::test]
async fn every_dashboard_module_is_served_with_its_source() {
    let app = app();
    let modules = modules();
    assert!(modules.len() >= 30, "found only {} modules", modules.len());
    for (name, source) in &modules {
        let (status, body) = get(&app, &format!("/js/{name}")).await;
        assert_eq!(status, StatusCode::OK, "/js/{name} is not served");
        assert!(body == *source, "/js/{name} differs from web/js/{name}");
    }
}

#[test]
fn every_relative_import_names_an_existing_module() {
    let modules = modules();
    let names: HashSet<&str> = modules.iter().map(|(name, _)| name.as_str()).collect();
    for (name, source) in &modules {
        let source = std::str::from_utf8(source).expect("UTF-8 module");
        for target in relative_imports(source) {
            assert!(
                names.contains(target),
                "{name} imports ./{target}, which is not in web/js"
            );
        }
    }
}

#[tokio::test]
async fn every_linked_stylesheet_is_served() {
    let app = app();
    let index = std::fs::read_to_string(web_dir().join("index.html")).expect("index.html");
    let mut checked = 0;
    for chunk in index.split("rel=\"stylesheet\" href=\"").skip(1) {
        let href = &chunk[..chunk.find('"').expect("closing quote")];
        let (status, _) = get(&app, href).await;
        assert_eq!(status, StatusCode::OK, "{href} is not served");
        checked += 1;
    }
    assert!(checked >= 3, "found only {checked} stylesheets");
}
