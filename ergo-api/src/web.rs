//! Static UI assets, embedded at compile time.
//!
//! v1 ships a self-contained dashboard (`index.html`) plus a Swagger UI
//! page that loads the Scala node's OpenAPI spec. No build step, no
//! node_modules, no npm. Files live under `ergo-api/web/` and are
//! editable with any text editor.

pub const INDEX_HTML: &str = include_str!("../web/index.html");
pub const SWAGGER_HTML: &str = include_str!("../web/swagger.html");
pub const NATIVE_SWAGGER_HTML: &str = include_str!("../web/swagger-native.html");
pub const OPENAPI_YAML: &str = include_str!("../web/openapi.yaml");
pub const TOKENS_CSS: &str = include_str!("../web/tokens.css");
pub const COMPONENTS_CSS: &str = include_str!("../web/components.css");
pub const DASHBOARD_CSS: &str = include_str!("../web/dashboard.css");

// ES modules for the overhauled dashboard, served under `/js/`.
pub const JS_API_CLIENT: &str = include_str!("../web/js/api-client.js");
pub const JS_AUTH: &str = include_str!("../web/js/auth.js");
pub const JS_FORMAT: &str = include_str!("../web/js/format.js");
pub const JS_FEE_STATS: &str = include_str!("../web/js/fee-stats.js");
pub const JS_ROUTER: &str = include_str!("../web/js/router.js");
pub const JS_SETTINGS: &str = include_str!("../web/js/settings.js");
pub const JS_TABLE: &str = include_str!("../web/js/table.js");
pub const JS_SPARKLINE: &str = include_str!("../web/js/sparkline.js");
pub const JS_OVERVIEW: &str = include_str!("../web/js/overview.js");
pub const JS_EXPLORER: &str = include_str!("../web/js/explorer.js");
pub const JS_PEERS: &str = include_str!("../web/js/peers.js");
pub const JS_MEMPOOL: &str = include_str!("../web/js/mempool.js");
pub const JS_VOTING: &str = include_str!("../web/js/voting.js");
pub const JS_WALLET: &str = include_str!("../web/js/wallet.js");
pub const JS_APP: &str = include_str!("../web/js/app.js");

/// Self-hosted JetBrains Mono (variable, SIL OFL 1.1) — embedded so both
/// the dashboard and the strict-CSP wallet render the same typography
/// with no external font CDN. License: `ergo-api/web/fonts/LICENSE-OFL.txt`.
pub const JETBRAINS_MONO_WOFF2: &[u8] = include_bytes!("../web/fonts/jetbrains-mono.woff2");
