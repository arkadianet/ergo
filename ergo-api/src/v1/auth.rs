//! The T0/T1/T2 exposure-tier gate (`v1-api-design.md` §2.1) + the startup
//! insecure-posture boot-warn.
//!
//! Three tiers, one api-key scheme:
//! * **[`Tier::Public`]** (T0) — no gate. Bounded by the [`super::governor`],
//!   not by auth.
//! * **[`Tier::Operator`]** (T1) — requires a valid `api_key`. Reuses the
//!   EXISTING [`crate::auth::ApiSecurity::verify`] (Blake2b-256 + constant-time
//!   compare) — there is no second credential scheme.
//! * **[`Tier::Admin`]** (T2) — `api_key` AND loopback-preferred. Off-loopback
//!   the default is **warn-and-allow** (logged loudly); an operator can flip
//!   [`V1AuthConfig::admin_hard_deny_nonloopback`] to hard-deny remote admin
//!   ops with `sensitive_op_disabled`.
//!
//! The compat gate [`crate::auth::require_api_key`] answers the legacy
//! `403 {reason:"invalid.api-key"}` shape and is frozen. This v1 gate answers
//! the §1.3 envelope with `unauthorized` (401), so v1 clients get uniform
//! errors. Both call the same `verify`.
//!
//! **Boot-warn (§2.1).** [`warn_startup_posture`] logs a loud warning when
//! T1/T2 routes are network-reachable under a weak/default `api_key_hash` (or
//! none at all). The server calls it once at startup — see the call-site note
//! on that function. The underlying decision is the pure, testable
//! [`assess_posture`].
//!
//! **Interim honesty (§2.1).** Until each group mounts its tiers, T2 endpoints
//! sit behind the single gate plus an operator-side reverse-proxy loopback
//! rule; this module is the mechanism the route PRs attach.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{body::Body, extract::State, middleware::Next, response::Response};
use tracing::warn;

use super::error::{v1_error, Reason};
use super::is_trusted_loopback;
use crate::auth::{ApiSecurity, API_KEY_HEADER};

/// Exposure tier of a route (`v1-api-design.md` §2.1). Pinned per route/subtree
/// at mount time via [`V1AuthConfig::state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// T0 — open, no auth gate (still governor-bounded).
    Public,
    /// T1 — operator; requires a valid `api_key`.
    Operator,
    /// T2 — admin; `api_key` + loopback-preferred.
    Admin,
}

/// Plaintext keys treated as weak/default for the boot-warn. `"hello"` is the
/// value shipped in every Scala config template's `apiKeyHash`
/// (`crate::auth` docs) — the single most likely un-rotated default.
const KNOWN_WEAK_KEYS: &[&[u8]] = &[
    b"hello",
    b"",
    b"changeme",
    b"test",
    b"password",
    b"1234",
    b"admin",
];

/// Operator auth configuration for the v1 tier gate.
#[derive(Clone)]
pub struct V1AuthConfig {
    /// The configured api-key verifier, or `None` when the node runs with no
    /// key. With `None`, T1/T2 routes FAIL CLOSED (`unauthorized`) — the
    /// operator/admin surfaces (shutdown, secret export) must never be open.
    /// The boot-warn makes the misconfiguration loud; this gate makes it safe.
    pub security: Option<Arc<ApiSecurity>>,
    /// When `true`, [`Tier::Admin`] routes hard-deny any non-loopback caller
    /// (even with a valid key) with `sensitive_op_disabled`. Default `false`
    /// = warn-and-allow (§2.1).
    pub admin_hard_deny_nonloopback: bool,
    /// When `true`, a reverse proxy terminates in front of the v1 API on
    /// loopback, so a loopback peer socket is the PROXY, not a real local
    /// client — the Admin loopback-preferred check must not trust it. Default
    /// `false` (direct bind). See [`super::is_trusted_loopback`].
    pub local_reverse_proxy: bool,
}

impl V1AuthConfig {
    /// Build a config. `admin_hard_deny_nonloopback` defaults to `false`
    /// (warn-and-allow) per §2.1.
    pub fn new(security: Option<Arc<ApiSecurity>>) -> Self {
        Self {
            security,
            admin_hard_deny_nonloopback: false,
            local_reverse_proxy: false,
        }
    }

    /// Opt into hard-denying remote [`Tier::Admin`] callers.
    pub fn with_admin_hard_deny(mut self, hard_deny: bool) -> Self {
        self.admin_hard_deny_nonloopback = hard_deny;
        self
    }

    /// Declare that a reverse proxy terminates in front of the v1 API on
    /// loopback. When set, the Admin loopback-preferred check no longer trusts
    /// a loopback peer socket (it is the proxy), closing a spoofed-loopback
    /// privilege-escalation path. See [`super::is_trusted_loopback`].
    pub fn with_local_reverse_proxy(mut self, behind_proxy: bool) -> Self {
        self.local_reverse_proxy = behind_proxy;
        self
    }

    /// Share for use as per-route middleware state.
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Per-route middleware state for `from_fn_with_state`, pinning `tier`.
    pub fn state(self: &Arc<Self>, tier: Tier) -> V1AuthState {
        V1AuthState {
            config: Arc::clone(self),
            tier,
        }
    }
}

/// Per-route auth state: shared [`V1AuthConfig`] + the [`Tier`] of the wrapped
/// subtree. Cheap to clone.
#[derive(Clone)]
pub struct V1AuthState {
    config: Arc<V1AuthConfig>,
    tier: Tier,
}

/// axum middleware enforcing the route's [`Tier`] (`v1-api-design.md` §2.1).
///
/// Mount per subtree:
/// ```ignore
/// let auth = V1AuthConfig::new(security).into_shared();
/// operator_routes.route_layer(axum::middleware::from_fn_with_state(
///     auth.state(Tier::Operator), require_tier,
/// ))
/// ```
pub async fn require_tier(
    State(state): State<V1AuthState>,
    req: axum::http::Request<Body>,
    next: Next,
) -> Response {
    match state.tier {
        Tier::Public => next.run(req).await,
        Tier::Operator => match check_key(&state.config, &req) {
            KeyOutcome::Ok => next.run(req).await,
            KeyOutcome::NoKeyConfigured => no_key_configured(),
            KeyOutcome::Rejected(resp) => resp,
        },
        Tier::Admin => {
            match check_key(&state.config, &req) {
                KeyOutcome::Rejected(resp) => return resp,
                KeyOutcome::NoKeyConfigured => return no_key_configured(),
                KeyOutcome::Ok => {}
            }
            let is_loopback = is_trusted_loopback(&req, state.config.local_reverse_proxy);
            if !is_loopback {
                if state.config.admin_hard_deny_nonloopback {
                    return v1_error(
                        Reason::SensitiveOpDisabled,
                        "admin operations are restricted to loopback",
                        "run this from the node host, or set admin hard-deny off to allow remote",
                    );
                }
                warn!(
                    target: "ergo_api::v1::auth",
                    "T2 admin route served to a non-loopback caller (warn-and-allow); \
                     restrict to loopback or enable admin_hard_deny_nonloopback"
                );
            }
            next.run(req).await
        }
    }
}

/// Result of the api-key check shared by Operator/Admin.
enum KeyOutcome {
    /// Header present and valid.
    Ok,
    /// No key configured node-wide. Public passes; Operator/Admin FAIL CLOSED
    /// (`no_key_configured`) — sensitive routes are never open. The boot-warn
    /// surfaces the misconfiguration.
    NoKeyConfigured,
    /// Missing or invalid key — the rendered `unauthorized` response.
    Rejected(Response),
}

/// The fail-closed response when the node runs with NO api-key configured but
/// a T1/T2 route is reached. Operator/Admin routes gate sensitive operations
/// (shutdown, secret export), so an unconfigured key must DENY, not pass. The
/// boot-warn ([`warn_startup_posture`]) surfaces the misconfiguration loudly;
/// it is not the gate. Answers the §1.3 `unauthorized` (401) envelope.
fn no_key_configured() -> Response {
    v1_error(
        Reason::Unauthorized,
        "no api_key is configured; operator/admin routes are closed",
        "set [api] api_key_hash to enable authenticated v1 routes, or bind to loopback only",
    )
}

fn check_key(config: &V1AuthConfig, req: &axum::http::Request<Body>) -> KeyOutcome {
    let Some(sec) = config.security.as_ref() else {
        return KeyOutcome::NoKeyConfigured;
    };
    let presented = req.headers().get(API_KEY_HEADER);
    match presented {
        Some(val) if sec.verify(val.as_bytes()) => KeyOutcome::Ok,
        _ => KeyOutcome::Rejected(v1_error(
            Reason::Unauthorized,
            "missing or invalid api_key",
            "send the operator api_key header",
        )),
    }
}

/// Why a node's exposure posture is insecure (input to the boot-warn).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsecurePosture {
    /// Network-reachable bind with NO api-key configured — T1/T2 are open.
    NoKeyNetworkReachable,
    /// Network-reachable bind whose api-key hashes a known weak/default secret.
    WeakDefaultKey,
}

/// Pure posture check (`v1-api-design.md` §2.1): given the api-key verifier
/// and the API bind address, is the T1/T2 surface dangerously exposed?
///
/// A loopback-only bind is never flagged (only the operator can reach it).
/// A network-reachable bind is flagged when there is no key, or when the key
/// matches a [`KNOWN_WEAK_KEYS`] default. Separated from logging so it is unit-testable.
pub fn assess_posture(security: Option<&ApiSecurity>, bind: SocketAddr) -> Option<InsecurePosture> {
    if bind.ip().is_loopback() {
        return None;
    }
    match security {
        None => Some(InsecurePosture::NoKeyNetworkReachable),
        Some(sec) => {
            if KNOWN_WEAK_KEYS.iter().any(|k| sec.verify(k)) {
                Some(InsecurePosture::WeakDefaultKey)
            } else {
                None
            }
        }
    }
}

/// Boot-warn hook (`v1-api-design.md` §2.1). Logs a loud `WARN` if the v1
/// T1/T2 surface is network-reachable under a weak/default api-key (or none).
///
/// **Call site (next PR):** invoke once at server startup, right after the
/// `ApiSecurity` is built and the bind `SocketAddr` is known, before `serve`
/// — e.g. in `crate::server` alongside the `info!(addr, "api listening")`
/// line. It is intentionally not wired here: this PR mounts no routes and
/// changes no server behavior.
pub fn warn_startup_posture(security: Option<&ApiSecurity>, bind: SocketAddr) {
    match assess_posture(security, bind) {
        Some(InsecurePosture::NoKeyNetworkReachable) => warn!(
            target: "ergo_api::v1::auth",
            %bind,
            "INSECURE: the API is network-reachable with NO api_key configured — \
             T1 (operator) and T2 (admin) routes are OPEN. Configure [api] api_key_hash \
             or bind to loopback."
        ),
        Some(InsecurePosture::WeakDefaultKey) => warn!(
            target: "ergo_api::v1::auth",
            %bind,
            "INSECURE: the API is network-reachable under a weak/default api_key \
             (e.g. the shipped \"hello\" template value) — rotate api_key_hash immediately."
        ),
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use std::net::{IpAddr, Ipv4Addr};
    use tower::ServiceExt;

    // ----- helpers -----

    fn security_for(raw_key: &[u8]) -> Arc<ApiSecurity> {
        Arc::new(ApiSecurity::new(ApiSecurity::hash_key(raw_key)).expect("valid hash"))
    }

    fn strong_security() -> Arc<ApiSecurity> {
        security_for(b"a-strong-rotated-operator-secret-2026")
    }

    fn app(config: &Arc<V1AuthConfig>, tier: Tier) -> Router {
        Router::new()
            .route("/x", get(|| async { "ok" }))
            .route_layer(axum::middleware::from_fn_with_state(
                config.state(tier),
                require_tier,
            ))
    }

    fn request(key: Option<&str>, peer: Option<IpAddr>) -> axum::http::Request<Body> {
        let mut b = axum::http::Request::builder().uri("/x");
        if let Some(k) = key {
            b = b.header(API_KEY_HEADER, k);
        }
        let mut req = b.body(Body::empty()).unwrap();
        if let Some(ip) = peer {
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(SocketAddr::new(ip, 45000)));
        }
        req
    }

    async fn status(config: &Arc<V1AuthConfig>, tier: Tier, req: axum::http::Request<Body>) -> u16 {
        app(config, tier)
            .oneshot(req)
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    const REMOTE: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    // ----- happy path / accept-reject matrix -----

    #[tokio::test]
    async fn public_tier_needs_no_key() {
        let cfg = V1AuthConfig::new(Some(strong_security())).into_shared();
        assert_eq!(
            status(&cfg, Tier::Public, request(None, Some(REMOTE))).await,
            200
        );
    }

    #[tokio::test]
    async fn operator_rejects_missing_key_with_unauthorized_401() {
        let cfg = V1AuthConfig::new(Some(security_for(b"secretkey"))).into_shared();
        let resp = app(&cfg, Tier::Operator)
            .oneshot(request(None, Some(REMOTE)))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"]["reason"], "unauthorized");
    }

    #[tokio::test]
    async fn operator_rejects_wrong_key() {
        let cfg = V1AuthConfig::new(Some(security_for(b"secretkey"))).into_shared();
        assert_eq!(
            status(&cfg, Tier::Operator, request(Some("wrong"), Some(REMOTE))).await,
            401
        );
    }

    #[tokio::test]
    async fn operator_accepts_valid_key() {
        let cfg = V1AuthConfig::new(Some(security_for(b"secretkey"))).into_shared();
        assert_eq!(
            status(
                &cfg,
                Tier::Operator,
                request(Some("secretkey"), Some(REMOTE))
            )
            .await,
            200
        );
    }

    #[tokio::test]
    async fn operator_fails_closed_when_no_key_configured() {
        // No key node-wide ⇒ Operator FAILS CLOSED with `unauthorized` (401):
        // sensitive routes must never be open. Boot-warn is loud, not the gate.
        let cfg = V1AuthConfig::new(None).into_shared();
        let resp = app(&cfg, Tier::Operator)
            .oneshot(request(None, Some(REMOTE)))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"]["reason"], "unauthorized");
    }

    #[tokio::test]
    async fn admin_fails_closed_when_no_key_configured_even_from_loopback() {
        // No key ⇒ Admin FAILS CLOSED before the loopback check even runs.
        let cfg = V1AuthConfig::new(None).into_shared();
        let resp = app(&cfg, Tier::Admin)
            .oneshot(request(None, Some(LOCAL)))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"]["reason"], "unauthorized");
    }

    #[tokio::test]
    async fn admin_behind_declared_proxy_treats_loopback_as_remote() {
        // local_reverse_proxy=true + hard-deny ⇒ a loopback socket (the proxy)
        // is NOT trusted, so a "loopback" caller is denied like any remote one.
        let cfg = V1AuthConfig::new(Some(security_for(b"secretkey")))
            .with_admin_hard_deny(true)
            .with_local_reverse_proxy(true)
            .into_shared();
        let resp = app(&cfg, Tier::Admin)
            .oneshot(request(Some("secretkey"), Some(LOCAL)))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"]["reason"], "sensitive_op_disabled");
    }

    #[tokio::test]
    async fn admin_accepts_valid_key_from_loopback() {
        let cfg = V1AuthConfig::new(Some(security_for(b"secretkey"))).into_shared();
        assert_eq!(
            status(&cfg, Tier::Admin, request(Some("secretkey"), Some(LOCAL))).await,
            200
        );
    }

    #[tokio::test]
    async fn admin_warn_and_allow_remote_by_default() {
        let cfg = V1AuthConfig::new(Some(security_for(b"secretkey"))).into_shared();
        // Valid key, remote peer, default policy ⇒ allowed (with a logged warn).
        assert_eq!(
            status(&cfg, Tier::Admin, request(Some("secretkey"), Some(REMOTE))).await,
            200
        );
    }

    #[tokio::test]
    async fn admin_hard_deny_rejects_remote_even_with_valid_key() {
        let cfg = V1AuthConfig::new(Some(security_for(b"secretkey")))
            .with_admin_hard_deny(true)
            .into_shared();
        let resp = app(&cfg, Tier::Admin)
            .oneshot(request(Some("secretkey"), Some(REMOTE)))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"]["reason"], "sensitive_op_disabled");
    }

    #[tokio::test]
    async fn admin_hard_deny_still_allows_loopback() {
        let cfg = V1AuthConfig::new(Some(security_for(b"secretkey")))
            .with_admin_hard_deny(true)
            .into_shared();
        assert_eq!(
            status(&cfg, Tier::Admin, request(Some("secretkey"), Some(LOCAL))).await,
            200
        );
    }

    // ----- boot-warn predicate -----

    fn sock(ip: IpAddr) -> SocketAddr {
        SocketAddr::new(ip, 9053)
    }

    #[test]
    fn posture_loopback_bind_is_never_flagged() {
        assert_eq!(assess_posture(None, sock(LOCAL)), None);
        let weak = security_for(b"hello");
        assert_eq!(assess_posture(Some(&weak), sock(LOCAL)), None);
    }

    #[test]
    fn posture_no_key_network_reachable_is_flagged() {
        assert_eq!(
            assess_posture(None, sock(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
            Some(InsecurePosture::NoKeyNetworkReachable)
        );
    }

    #[test]
    fn posture_weak_default_key_network_reachable_is_flagged() {
        let weak = security_for(b"hello");
        assert_eq!(
            assess_posture(Some(&weak), sock(REMOTE)),
            Some(InsecurePosture::WeakDefaultKey)
        );
    }

    #[test]
    fn posture_strong_key_network_reachable_is_clean() {
        let strong = strong_security();
        assert_eq!(assess_posture(Some(&strong), sock(REMOTE)), None);
    }
}
