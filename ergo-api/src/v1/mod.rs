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

pub use auth::{
    assess_posture, warn_startup_posture, InsecurePosture, Tier, V1AuthConfig, V1AuthState,
};
pub use cursor::{
    clamp_limit, decode_cursor, decode_opt_cursor, encode_cursor, CursorError, CursorPayload, Page,
    CURSOR_VERSION, DEFAULT_LIMIT, MAX_LIMIT,
};
pub use error::{v1_error, Reason, V1Error, V1ErrorInner};
pub use governor::{Governor, GovernorConfig, GovernorState, RouteClass};

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
