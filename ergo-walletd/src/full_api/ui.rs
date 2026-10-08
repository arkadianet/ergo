//! The existing wallet interface, served without linking the node API crate.
//! The static shell must be public so a browser can enter its local credential.
use axum::{
    extract::Path,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::LazyLock;

const HTML: &str = include_str!("ui/index.html");
const APP: &str = include_str!("ui/app.js");
const AUTH_SOURCE: &str = include_str!("../../../ergo-api/web/js/auth.js");
static WALLET: LazyLock<String> = LazyLock::new(|| {
    include_str!("../../../ergo-api/web/js/wallet.js")
        .replace("Your wallet, on your node", "Your wallet daemon")
        .replace(
            "wallet built into this node",
            "wallet hosted by this daemon",
        )
        .replace(
            "sent solely to this node",
            "sent solely to this wallet daemon",
        )
        .replace(
            "Keys remain on your node",
            "Keys remain in your wallet daemon",
        )
        .replace("on this node’s network", "on this wallet’s network")
});
static WALLET_TRANSACTION: LazyLock<String> = LazyLock::new(|| {
    include_str!("../../../ergo-api/web/js/wallet-transaction.js")
        .replace("stop the node, then run wallet-scan-utxo with your data directory", "stop both the node and wallet daemon, then run ergo-node wallet-scan-utxo NODE_DATA --wallet-data-dir WALLET_DATA")
        .replace("Archive nodes can use POST /wallet/rescan", "With an archive node, use the wallet daemon’s POST /wallet/rescan")
});
static AUTH: LazyLock<String> = LazyLock::new(|| {
    AUTH_SOURCE
        .replace("const KEY = 'ergo.apikey';", "const KEY = 'ergo.walletd.apikey';")
        .replace("const LEGACY = 'ergo_api_key';", "const LEGACY = 'ergo_walletd_api_key';")
        .replace("Configure [api.security] api_key_hash, then restart", "Configure local_api_key_file in the wallet daemon, then restart")
        .replace("status === 403 && reason === 'invalid.api-key'", "(status === 403 && reason === 'invalid.api-key') || (status === 401 && reason === 'unauthorized')")
        .replace("r.status === 403 ? await r.json() : null", "(r.status === 403 || r.status === 401) ? await r.json() : null")
        .replace("else if (r.status === 403) report", "else if (r.status === 403 || r.status === 401) report")
        .replace("api_key rejected (403)", "api_key rejected")
        .replace("features (logs, voting, wallet)", "wallet operations")
});

pub(super) fn router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/wallet", get(index))
        .route("/wallet/", get(index))
        .route("/js/:asset", get(javascript))
        .route("/tokens.css", get(tokens))
        .route("/components.css", get(components))
        .route("/dashboard.css", get(dashboard))
        .route("/fonts/:asset", get(font))
}

fn asset(content_type: &'static str, body: impl IntoResponse) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
async fn index() -> Response {
    asset("text/html; charset=utf-8", HTML)
}
async fn tokens() -> Response {
    asset(
        "text/css; charset=utf-8",
        include_str!("../../../ergo-api/web/tokens.css"),
    )
}
async fn components() -> Response {
    asset(
        "text/css; charset=utf-8",
        include_str!("../../../ergo-api/web/components.css"),
    )
}
async fn dashboard() -> Response {
    asset(
        "text/css; charset=utf-8",
        include_str!("../../../ergo-api/web/dashboard.css"),
    )
}

async fn javascript(Path(name): Path<String>) -> Response {
    let source = match name.as_str() {
        "wallet-app.js" => APP,
        "auth.js" => AUTH.as_str(),
        "wallet.js" => WALLET.as_str(),
        "wallet-builder.js" => include_str!("../../../ergo-api/web/js/wallet-builder.js"),
        "wallet-private.js" => include_str!("../../../ergo-api/web/js/wallet-private.js"),
        "wallet-maintenance.js" => include_str!("../../../ergo-api/web/js/wallet-maintenance.js"),
        "wallet-transaction.js" => WALLET_TRANSACTION.as_str(),
        "api-client.js" => include_str!("../../../ergo-api/web/js/api-client.js"),
        "format.js" => include_str!("../../../ergo-api/web/js/format.js"),
        "table.js" => include_str!("../../../ergo-api/web/js/table.js"),
        "token-meta.js" => include_str!("../../../ergo-api/web/js/token-meta.js"),
        _ => return asset("text/plain; charset=utf-8", StatusCode::NOT_FOUND),
    };
    asset("text/javascript; charset=utf-8", source)
}
async fn font(Path(name): Path<String>) -> Response {
    let data: &[u8] = match name.as_str() {
        "jetbrains-mono.woff2" => {
            include_bytes!("../../../ergo-api/web/fonts/jetbrains-mono.woff2")
        }
        "inter-variable.woff2" => {
            include_bytes!("../../../ergo-api/web/fonts/inter-variable.woff2")
        }
        _ => return asset("text/plain; charset=utf-8", StatusCode::NOT_FOUND),
    };
    asset("font/woff2", data)
}
