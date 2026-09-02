//! Host-header allowlist middleware — DNS-rebinding guard.
//!
//! Browsers enforce same-origin policy by *hostname*, not by IP. An
//! attacker who controls a DNS name can point it at a victim's own
//! loopback address after the victim's browser has already loaded a
//! page from that name (the DNS TTL flips post-load — "DNS rebinding").
//! Script on that page then issues same-origin `fetch()` calls that land
//! on `127.0.0.1:9099` carrying the attacker's chosen `Host` header, and
//! the browser happily sends them cross-origin cookies/credentials are
//! not required to read this API's public-by-design surface (`/info`,
//! `/blocks/*`, `/peers/*`, …) — the request looks locally-sourced to
//! the node.
//!
//! Key-gated routes (`/wallet/*`, `/node/shutdown`) are unaffected: the
//! `api_key` header can't be forged from a browser context. This guard
//! closes the read path for everything else by checking the `Host`
//! header against an allowlist *before* any routing happens.
//!
//! Mounted with `Router::layer` (not `route_layer`) around the fully
//! assembled router in [`crate::server::serve_on_with_mempool_and_wallet_and_security`],
//! so it also covers the 404 fallback — a rebound request should never
//! learn anything about the route table, not even "that path doesn't
//! exist."
//!
//! Enforcement posture:
//! * Loopback binds (`127.0.0.1`, `::1`, …) are always checked — the
//!   loopback bind is exactly the DNS-rebinding target.
//! * Non-loopback binds are checked only when `[api] allowed_hosts` is
//!   non-empty. Operators who expose the API publicly usually front it
//!   with a reverse proxy that already does host validation (or TLS SNI
//!   pinning); enforcing here by default would risk breaking that setup
//!   for no defensive gain (a rebinding attack against a routable
//!   address that's meant to be reached by many hostnames isn't the
//!   threat this guards against).
//! * A request with no `Host` header at all is allowed through — HTTP/1.0
//!   clients don't send one, and Scala's reference node tolerates the
//!   same.

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

/// Resolved allowlist for one bound listener. Built once at server boot
/// from the bind address + `[api] allowed_hosts` and handed to
/// [`require_allowed_host`] via axum state.
#[derive(Debug, Clone)]
pub struct HostAllowlist {
    /// `false` ⇒ [`require_allowed_host`] passes every request through
    /// unchecked (non-loopback bind with an empty `allowed_hosts`).
    enforce: bool,
    /// `(host, Some(port))` matches only that exact host:port; `(host,
    /// None)` matches the host on any port (including no port at all).
    /// Hosts are compared case-insensitively; ports must match exactly
    /// (the JSON list's suffix and the request's `Host` header have
    /// already round-tripped through `parse::<u16>()`).
    allowed: Vec<(String, Option<u16>)>,
}

impl HostAllowlist {
    /// Build the allowlist for a server bound at `bind_addr`, extended
    /// with the operator's `[api] allowed_hosts` entries. Always
    /// includes `localhost`, `127.0.0.1`, `::1`, and the literal bind
    /// IP — each entry (default or operator-supplied) matches with or
    /// without an explicit port, per the module docs.
    pub fn new(bind_addr: SocketAddr, allowed_hosts: &[String]) -> Self {
        let enforce = bind_addr.ip().is_loopback() || !allowed_hosts.is_empty();
        let mut allowed = vec![
            ("localhost".to_string(), None),
            ("127.0.0.1".to_string(), None),
            ("::1".to_string(), None),
        ];
        allowed.push((bind_addr.ip().to_string(), None));
        allowed.extend(allowed_hosts.iter().map(|h| split_host_port(h)));
        Self { enforce, allowed }
    }

    /// `true` ⇒ [`require_allowed_host`] evaluates every request against
    /// [`Self::permits`]; `false` ⇒ the guard is a no-op (non-loopback
    /// bind, empty `allowed_hosts`).
    fn enforce(&self) -> bool {
        self.enforce
    }

    /// Does `host_header` (the raw `Host` header value) match an entry
    /// in the allowlist?
    fn permits(&self, host_header: &str) -> bool {
        let (host, port) = split_host_port(host_header);
        self.allowed.iter().any(|(a_host, a_port)| {
            a_host.eq_ignore_ascii_case(&host) && matches_port(*a_port, port)
        })
    }
}

fn matches_port(allowed_port: Option<u16>, request_port: Option<u16>) -> bool {
    match allowed_port {
        None => true,
        Some(_) => allowed_port == request_port,
    }
}

/// Split a `Host`-header-shaped string (`host`, `host:port`,
/// `[ipv6]`, or `[ipv6]:port`) into its host and optional port parts.
/// The host is returned verbatim (case preserved; callers compare
/// case-insensitively) with IPv6 brackets stripped.
fn split_host_port(raw: &str) -> (String, Option<u16>) {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('[') {
        return match rest.find(']') {
            Some(end) => {
                let host = rest[..end].to_string();
                let port = rest[end + 1..]
                    .strip_prefix(':')
                    .and_then(|p| p.parse::<u16>().ok());
                (host, port)
            }
            // Malformed bracket (no closing `]`) — treat the whole
            // thing as an opaque host so it simply won't match any
            // allowlist entry, rather than panicking on the slice.
            None => (raw.to_string(), None),
        };
    }
    match raw.rsplit_once(':') {
        Some((host, port_str)) if !host.is_empty() => match port_str.parse::<u16>() {
            Ok(port) => (host.to_string(), Some(port)),
            // Not a numeric suffix (e.g. a bare, unbracketed IPv6
            // literal, which HTTP's Host header never legally sends) —
            // keep the original string as the host.
            Err(_) => (raw.to_string(), None),
        },
        _ => (raw.to_string(), None),
    }
}

/// axum middleware: reject requests whose `Host` header isn't in the
/// configured [`HostAllowlist`] with `421 Misdirected Request`. A
/// request with no `Host` header passes through (see module docs).
pub async fn require_allowed_host(
    State(allowlist): State<Arc<HostAllowlist>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if allowlist.enforce() {
        if let Some(host) = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
        {
            if !allowlist.permits(host) {
                return reject_misdirected();
            }
        }
    }
    next.run(req).await
}

fn reject_misdirected() -> Response {
    (
        StatusCode::MISDIRECTED_REQUEST,
        Json(json!({
            "error": 421,
            "reason": "invalid.host",
            "detail": "Host header is not in the configured allowlist; see [api] allowed_hosts",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn allowlist(bind: &str, hosts: &[&str]) -> HostAllowlist {
        let bind_addr: SocketAddr = bind.parse().unwrap();
        let hosts: Vec<String> = hosts.iter().map(|s| s.to_string()).collect();
        HostAllowlist::new(bind_addr, &hosts)
    }

    // ----- happy path -----

    #[test]
    fn split_host_port_plain_host_no_port() {
        assert_eq!(
            split_host_port("localhost"),
            ("localhost".to_string(), None)
        );
    }

    #[test]
    fn split_host_port_host_with_port() {
        assert_eq!(
            split_host_port("localhost:9099"),
            ("localhost".to_string(), Some(9099))
        );
    }

    #[test]
    fn split_host_port_bracketed_ipv6_no_port() {
        assert_eq!(split_host_port("[::1]"), ("::1".to_string(), None));
    }

    #[test]
    fn split_host_port_bracketed_ipv6_with_port() {
        assert_eq!(
            split_host_port("[::1]:9099"),
            ("::1".to_string(), Some(9099))
        );
    }

    #[test]
    fn loopback_bind_default_hosts_permitted() {
        let al = allowlist("127.0.0.1:9099", &[]);
        assert!(al.enforce());
        assert!(al.permits("localhost"));
        assert!(al.permits("localhost:9099"));
        assert!(al.permits("127.0.0.1"));
        assert!(al.permits("127.0.0.1:9099"));
        assert!(al.permits("[::1]"));
        assert!(al.permits("[::1]:9099"));
    }

    #[test]
    fn loopback_bind_evil_host_rejected() {
        let al = allowlist("127.0.0.1:9099", &[]);
        assert!(!al.permits("evil.example.com"));
        assert!(!al.permits("evil.example.com:9099"));
    }

    #[test]
    fn loopback_bind_allowed_hosts_entry_permitted() {
        let al = allowlist("127.0.0.1:9099", &["my-node.local"]);
        assert!(al.permits("my-node.local"));
        assert!(al.permits("my-node.local:9099"));
        assert!(!al.permits("other.local"));
    }

    #[test]
    fn allowed_hosts_entry_with_explicit_port_pins_port() {
        let al = allowlist("127.0.0.1:9099", &["my-node.local:8443"]);
        assert!(al.permits("my-node.local:8443"));
        assert!(!al.permits("my-node.local:9099"));
        assert!(!al.permits("my-node.local"));
    }

    #[test]
    fn host_match_is_case_insensitive() {
        let al = allowlist("127.0.0.1:9099", &[]);
        assert!(al.permits("LOCALHOST"));
        assert!(al.permits("LocalHost:9099"));
    }

    #[test]
    fn ipv6_loopback_bind_default_hosts_permitted() {
        let al = allowlist("[::1]:9099", &[]);
        assert!(al.enforce());
        assert!(al.permits("[::1]"));
        assert!(al.permits("localhost"));
    }

    #[test]
    fn non_loopback_bind_empty_allowlist_never_enforces() {
        let al = allowlist("0.0.0.0:9099", &[]);
        assert!(!al.enforce());
        // permits() would reject an arbitrary host, but enforce() is
        // false, so require_allowed_host never calls permits() here —
        // this direct call just documents that fact stays inert either
        // way (still true, since the literal bind IP is on the list —
        // an arbitrary attacker host still would not be).
        assert!(!al.permits("evil.example.com"));
    }

    #[test]
    fn non_loopback_bind_with_allowed_hosts_enforces() {
        let al = allowlist("0.0.0.0:9099", &["api.example.com"]);
        assert!(al.enforce());
        assert!(al.permits("api.example.com"));
        assert!(!al.permits("evil.example.com"));
    }

    #[test]
    fn non_loopback_bind_literal_ip_always_permitted() {
        let al = allowlist("203.0.113.5:9099", &["api.example.com"]);
        assert!(al.permits("203.0.113.5"));
        assert!(al.permits("203.0.113.5:9099"));
    }
}
