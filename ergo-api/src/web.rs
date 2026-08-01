//! Static UI assets, embedded at compile time.
//!
//! The crate ships a self-contained dashboard plus Swagger pages. No build
//! step, node_modules, or npm is required.

pub const INDEX_HTML: &str = include_str!("../web/index.html");
pub const SWAGGER_HTML: &str = include_str!("../web/swagger.html");
pub const NATIVE_SWAGGER_HTML: &str = include_str!("../web/swagger-native.html");
pub const OPENAPI_YAML: &str = include_str!("../web/openapi.yaml");
pub const TOKENS_CSS: &str = include_str!("../web/tokens.css");
pub const COMPONENTS_CSS: &str = include_str!("../web/components.css");
pub const DASHBOARD_CSS: &str = include_str!("../web/dashboard.css");

fn render_family_metadata(template: &str) -> String {
    use crate::api_family::{RUST_API, SCALA_API};

    template
        .replace("{{SCALA_API_LABEL}}", SCALA_API.label)
        .replace("{{SCALA_SWAGGER_URL}}", SCALA_API.swagger_url)
        .replace("{{SCALA_OPENAPI_URL}}", SCALA_API.openapi_url)
        .replace("{{RUST_API_LABEL}}", RUST_API.label)
        .replace("{{RUST_SWAGGER_URL}}", RUST_API.swagger_url)
        .replace("{{RUST_OPENAPI_URL}}", RUST_API.openapi_url)
}

pub fn index_html() -> &'static str {
    static HTML: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| render_family_metadata(INDEX_HTML));
    HTML.as_str()
}

pub fn scala_swagger_html() -> &'static str {
    static HTML: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| render_family_metadata(SWAGGER_HTML));
    HTML.as_str()
}

pub fn rust_swagger_html() -> &'static str {
    static HTML: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| render_family_metadata(NATIVE_SWAGGER_HTML));
    HTML.as_str()
}

// ES modules for the overhauled dashboard, served under `/js/`.
pub const JS_API_CLIENT: &str = include_str!("../web/js/api-client.js");
pub const JS_AUTH: &str = include_str!("../web/js/auth.js");
pub const JS_FORMAT: &str = include_str!("../web/js/format.js");
pub const JS_FEE_STATS: &str = include_str!("../web/js/fee-stats.js");
pub const JS_ROUTER: &str = include_str!("../web/js/router.js");
pub const JS_SETTINGS: &str = include_str!("../web/js/settings.js");
pub const JS_TABLE: &str = include_str!("../web/js/table.js");
pub const JS_SPARKLINE: &str = include_str!("../web/js/sparkline.js");
pub const JS_CHART: &str = include_str!("../web/js/chart.js");
pub const JS_OVERVIEW: &str = include_str!("../web/js/overview.js");
pub const JS_EXPLORER: &str = include_str!("../web/js/explorer.js");
pub const JS_TOKEN_META: &str = include_str!("../web/js/token-meta.js");
pub const JS_PEERS: &str = include_str!("../web/js/peers.js");
pub const JS_MEMPOOL: &str = include_str!("../web/js/mempool.js");
pub const JS_VOTING: &str = include_str!("../web/js/voting.js");
pub const JS_WALLET: &str = include_str!("../web/js/wallet.js");
pub const JS_MINERS: &str = include_str!("../web/js/miners.js");
pub const JS_MINING: &str = include_str!("../web/js/mining.js");
pub const JS_WS_CLIENT: &str = include_str!("../web/js/ws-client.js");
pub const JS_APP: &str = include_str!("../web/js/app.js");

/// Self-hosted JetBrains Mono (variable, SIL OFL 1.1) — embedded so both
/// the dashboard and the strict-CSP wallet render the same typography
/// with no external font CDN. License: `ergo-api/web/fonts/LICENSE-OFL.txt`.
pub const JETBRAINS_MONO_WOFF2: &[u8] = include_bytes!("../web/fonts/jetbrains-mono.woff2");

/// Self-hosted Inter (variable, SIL OFL 1.1) — the UI-chrome face; JetBrains
/// Mono stays for data (hashes, heights, amounts). Same no-CDN rationale.
/// License: `ergo-api/web/fonts/OFL-Inter.txt`.
pub const INTER_VARIABLE_WOFF2: &[u8] = include_bytes!("../web/fonts/inter-variable.woff2");
