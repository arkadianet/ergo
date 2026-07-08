//! `/api/v1/*` product-API shared primitives (design Appendix A, item **G2**).
//!
//! Four pieces of infrastructure every future v1 endpoint depends on, built
//! ONCE here (`dev-docs/v1-api-design.md` §1–§2):
//!
//! * [`error`] — the nested error envelope `{error:{reason,message,detail}}`
//!   and the canonical [`error::Reason`] enum with its status mapping (§1.3–§1.4).
//! * [`cursor`] — the one opaque, versioned cursor codec + `page` builder (§1.5).
//! * [`governor`] — the per-IP token-bucket rate/cost governor with per-route-class
//!   weights, loopback-exempt (§2.2).
//! * [`auth`] — the T0/T1/T2 tier split reusing the existing [`crate::auth`]
//!   api-key verification, plus the boot-warn posture check (§2.1).
//!
//! **Nothing here is mounted on a route.** This module is pure infrastructure;
//! the first route-group PR consumes it. Re-exports below are the stable
//! surface those groups import.

pub mod auth;
pub mod cursor;
pub mod error;
pub mod governor;
pub mod mempool_depth;
pub mod realtime;
pub mod routes;
pub mod webhooks;

pub use auth::{
    assess_posture, warn_startup_posture, InsecurePosture, Tier, V1AuthConfig, V1AuthState,
};
pub use cursor::{
    clamp_limit, decode_cursor, decode_opt_cursor, encode_cursor, CursorError, CursorPayload, Page,
    CURSOR_VERSION, DEFAULT_LIMIT, MAX_LIMIT,
};
pub use error::{v1_error, Reason, V1Error, V1ErrorInner};
pub use governor::{Governor, GovernorConfig, GovernorConfigError, GovernorState, RouteClass};
pub use mempool_depth::{
    sample_into, spawn_depth_sampler, spawn_depth_sampler_once, MempoolDepthRing,
    MempoolDepthSample, DEFAULT_SAMPLE_INTERVAL, DEPTH_RING_CAP,
};
pub use realtime::{spawn_event_bridge, ConnLimiter, RealtimeBus, RealtimeHandle};
pub use routes::{v1_router, V1State};
pub use webhooks::{
    spawn_webhook_worker, webhooks_router, WebhookEngine, WebhookSink, WebhooksHandle,
    WebhooksState,
};

use axum::extract::ConnectInfo;
use axum::http::Request;
use std::net::{IpAddr, SocketAddr};

/// The client IP for rate-bucketing / loopback checks, read from the
/// [`ConnectInfo<SocketAddr>`] extension axum installs when the server is
/// served with `.into_make_service_with_connect_info::<SocketAddr>()`.
///
/// Returns `None` when connect-info is absent (e.g. a test harness, or a
/// server not yet wired for connect-info). Callers decide the fail-safe:
/// [`governor`] applies a shared "unknown" bucket (never a blanket exemption)
/// and [`auth`] treats an unknown IP as non-loopback.
///
/// `X-Forwarded-For` is deliberately NOT trusted here — it is client-spoofable
/// and the loopback exemption is a security boundary. Operators terminating v1
/// behind a reverse proxy configure the proxy to preserve the real peer.
pub(crate) fn client_ip<B>(req: &Request<B>) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// Whether `req` should be treated as **trusted loopback** for privilege
/// purposes — the [`governor`]'s loopback exemption and the [`auth`] Admin
/// tier's loopback-preferred check.
///
/// Trust is derived ONLY from the real peer socket ([`client_ip`]). When
/// `local_reverse_proxy` is set the operator has declared a reverse proxy on
/// loopback in front of the API: the peer socket is then the PROXY, not a real
/// local client, so its loopback-ness is meaningless and trust is withdrawn
/// (fail closed). `X-Forwarded-For` is deliberately NOT consulted
/// (client-spoofable) — loopback trust must come from a real peer address or
/// explicit operator config, never inferred from a proxy socket.
pub(crate) fn is_trusted_loopback<B>(req: &Request<B>, local_reverse_proxy: bool) -> bool {
    if local_reverse_proxy {
        return false;
    }
    client_ip(req).map(|ip| ip.is_loopback()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use std::net::Ipv4Addr;

    fn req_with_peer(ip: Option<IpAddr>) -> Request<Body> {
        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
        if let Some(ip) = ip {
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(ip, 40000)));
        }
        req
    }

    #[test]
    fn loopback_socket_is_trusted_on_direct_bind() {
        // Default (no proxy declared): a real loopback peer is trusted.
        let req = req_with_peer(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_trusted_loopback(&req, false));
    }

    #[test]
    fn loopback_socket_is_not_trusted_behind_declared_proxy() {
        // The loopback socket is the reverse proxy, not a real local client.
        let req = req_with_peer(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_trusted_loopback(&req, true));
    }

    #[test]
    fn non_loopback_peer_is_never_trusted() {
        let req = req_with_peer(Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));
        assert!(!is_trusted_loopback(&req, false));
        assert!(!is_trusted_loopback(&req, true));
    }

    #[test]
    fn absent_connect_info_is_not_trusted() {
        // No ConnectInfo ⇒ unknown peer ⇒ never loopback-privileged.
        let req = req_with_peer(None);
        assert!(!is_trusted_loopback(&req, false));
        assert!(!is_trusted_loopback(&req, true));
    }
}
