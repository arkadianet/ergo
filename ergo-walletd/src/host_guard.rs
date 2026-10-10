//! `Host` header allowlist for the loopback TCP listener.
//!
//! A loopback listener is still reachable from a browser through DNS
//! rebinding: a page on an attacker's domain whose name resolves to
//! `127.0.0.1` can send requests that the browser treats as same-origin.
//! Such requests carry the attacker's domain in `Host`, so accepting only the
//! listener's own loopback names (plus operator-listed extras) stops them
//! before routing or authentication.
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_wallet_protocol::native::error::NativeWalletError;

/// Accepted `Host` values, lowercased, each `host:port`.
#[derive(Debug, Clone)]
pub(crate) struct AllowedHosts(BTreeSet<String>);

impl AllowedHosts {
    pub(crate) fn for_listener(address: SocketAddr, extra: &[String]) -> Self {
        let port = address.port();
        let mut hosts = BTreeSet::new();
        hosts.insert(format!("localhost:{port}"));
        hosts.insert(match address {
            SocketAddr::V4(v4) => format!("{}:{port}", v4.ip()),
            SocketAddr::V6(v6) => format!("[{}]:{port}", v6.ip()),
        });
        hosts.extend(extra.iter().map(|host| host.to_ascii_lowercase()));
        Self(hosts)
    }

    fn allows(&self, host: &str) -> bool {
        self.0.contains(&host.to_ascii_lowercase())
    }
}

pub(crate) async fn require_allowed_host(
    State(allowed): State<Arc<AllowedHosts>>,
    request: Request,
    next: Next,
) -> Response {
    let mut values = request.headers().get_all(header::HOST).iter();
    let host = match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok().map(str::to_owned),
        (None, None) => request.uri().authority().map(|a| a.as_str().to_owned()),
        _ => None,
    };
    if host.as_deref().is_some_and(|host| allowed.allows(host)) {
        return next.run(request).await;
    }
    let mut response = (
        StatusCode::FORBIDDEN,
        Json(NativeWalletError {
            reason: "host_not_allowed".to_owned(),
            detail: None,
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_names_and_extras_are_accepted_case_insensitively() {
        let v4 = AllowedHosts::for_listener("127.0.0.1:3033".parse().unwrap(), &[]);
        assert!(v4.allows("127.0.0.1:3033"));
        assert!(v4.allows("LOCALHOST:3033"));
        assert!(!v4.allows("127.0.0.1:3034"));
        assert!(!v4.allows("evil.example:3033"));
        assert!(!v4.allows("127.0.0.1"));
        let v6 = AllowedHosts::for_listener(
            "[::1]:3033".parse().unwrap(),
            &["Wallet.Internal:3033".to_string()],
        );
        assert!(v6.allows("[::1]:3033"));
        assert!(v6.allows("wallet.internal:3033"));
    }
}
