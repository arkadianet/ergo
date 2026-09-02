//! Host-header allowlist middleware — DNS-rebinding guard.
//!
//! Browsers enforce same-origin policy by *hostname*, not by IP. An
//! attacker who controls a DNS name can point it at a victim's own
//! loopback address after the victim's browser has already loaded a
//! page from that name (the DNS TTL flips post-load — "DNS rebinding").
//! Script on that page then issues same-origin `fetch()` calls that land
//! on `127.0.0.1:9099` carrying the attacker's chosen `Host` header, and
//! the browser happily sends them — cross-origin cookies/credentials are
//! not required to read this API's public-by-design surface (`/info`,
//! `/blocks/*`, `/peers/*`, …) — the request looks locally-sourced to
//! the node.
//!
//! Key-gated routes (`/wallet/*`, `/node/shutdown`) are unaffected: the
//! `api_key` header can't be forged from a browser context. This guard
//! closes the read path for everything else by checking the request's
//! host identity against an allowlist *before* any routing happens.
//!
//! Mounted with `Router::layer` (not `route_layer`) around the fully
//! assembled router in
//! [`crate::server::serve_on_with_mempool_and_wallet_and_security_and_hosts`],
//! so it also covers the 404 fallback — a rebound request should never
//! learn anything about the route table, not even "that path doesn't
//! exist."
//!
//! **HTTP/2 note:** `axum::serve` (via hyper-util's auto builder) accepts
//! h2c prior-knowledge connections, and HTTP/2 carries the request's
//! host identity in the `:authority` pseudo-header rather than a
//! synthesized `Host` header — `req.headers().get(HOST)` alone would
//! see nothing and (incorrectly) treat every h2c request as the
//! "missing Host, HTTP/1.0 client" case. [`require_allowed_host`] falls
//! back to `req.uri().authority()` whenever the `Host` header is
//! absent, and only allows the request through unconditionally when
//! *both* are absent.
//!
//! Enforcement posture:
//! * Loopback binds (`127.0.0.1`, `::1`, an IPv4-mapped IPv6 loopback
//!   like `::ffff:127.0.0.1`, …) are always checked — the loopback bind
//!   is exactly the DNS-rebinding target. The bind IP is canonicalized
//!   (`IpAddr::to_canonical`) before the loopback check so a mapped
//!   address doesn't slip past `Ipv6Addr::is_loopback`'s literal-form
//!   check.
//! * Non-loopback binds are checked only when `[api] allowed_hosts` is
//!   non-empty. Operators who expose the API publicly usually front it
//!   with a reverse proxy that already does host validation (or TLS SNI
//!   pinning); enforcing here by default would risk breaking that setup
//!   for no defensive gain (a rebinding attack against a routable
//!   address that's meant to be reached by many hostnames isn't the
//!   threat this guards against). A loopback bind fronted by a reverse
//!   proxy that forwards its own public hostname (e.g. nginx
//!   `proxy_set_header Host $host`) needs that hostname added to
//!   `allowed_hosts` — see the `[Unreleased]` `CHANGELOG.md` entry for
//!   this feature.
//! * A request with **no** host identity at all — no `Host` header and
//!   no `:authority` — is allowed through: HTTP/1.0 clients send
//!   neither, and Scala's reference node tolerates the same.
//! * A `Host` header that *is* present but fails to parse as a UTF-8
//!   string (raw obs-text bytes, `0x80..=0xFF`, are legal header-value
//!   bytes but never a legal `Host` value) is rejected outright rather
//!   than treated as "absent" — a byte sequence a legitimate client
//!   would never send is exactly the shape a bypass attempt takes.
//! * A trailing dot on the host part (`localhost.`) is stripped before
//!   matching — a bare trailing dot denotes the DNS root and is
//!   something a user can type into a browser address bar without
//!   necessarily meaning to signal anything, so treating
//!   `localhost.` the same as `localhost` avoids a surprising reject on
//!   an otherwise-legitimate request. Only ONE trailing dot is
//!   stripped; `localhost..` still fails to match anything.

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
    /// (the JSON list's suffix and the request's host identity have
    /// already round-tripped through `parse::<u16>()`).
    allowed: Vec<(String, Option<u16>)>,
}

impl HostAllowlist {
    /// Build the allowlist for a server bound at `bind_addr`, extended
    /// with the operator's `[api] allowed_hosts` entries. Always
    /// includes `localhost`, `127.0.0.1`, `::1`, and — unless
    /// `bind_addr` is a wildcard (`0.0.0.0` / `::`), which is not a
    /// value a client would ever legitimately send as its host — the
    /// literal bind IP. Each entry (default or operator-supplied)
    /// matches with or without an explicit port, per the module docs.
    pub fn new(bind_addr: SocketAddr, allowed_hosts: &[String]) -> Self {
        // Canonicalize before the loopback check: an IPv4-mapped IPv6
        // address (`::ffff:127.0.0.1`) is a loopback address in every
        // practical sense, but `Ipv6Addr::is_loopback` only recognizes
        // the literal `::1` form — `to_canonical()` folds the mapped
        // form down to plain IPv4 first (P2-2).
        let canonical_ip = bind_addr.ip().to_canonical();
        let enforce = canonical_ip.is_loopback() || !allowed_hosts.is_empty();
        let mut allowed = vec![
            ("localhost".to_string(), None),
            ("127.0.0.1".to_string(), None),
            ("::1".to_string(), None),
        ];
        // A wildcard bind IP (0.0.0.0 / ::) is never itself a value a
        // client sends as Host/:authority — pushing it would be inert
        // at best and misleading in a config dump at worst, so skip it.
        if !bind_addr.ip().is_unspecified() {
            allowed.push((bind_addr.ip().to_string(), None));
        }
        allowed.extend(allowed_hosts.iter().map(|h| split_host_port(h)));
        Self { enforce, allowed }
    }

    /// `true` ⇒ [`require_allowed_host`] evaluates every request against
    /// [`Self::permits`]; `false` ⇒ the guard is a no-op (non-loopback
    /// bind, empty `allowed_hosts`).
    fn enforce(&self) -> bool {
        self.enforce
    }

    /// Public mirror of [`Self::enforce`] for boot-time diagnostic
    /// logging (P1-2) — callers outside this module can log the
    /// resolved enforcement posture without reaching into a private
    /// field.
    pub fn is_enforced(&self) -> bool {
        self.enforce
    }

    /// Does `host_header` (the raw `Host` header value, or an
    /// HTTP/2 `:authority`) match an entry in the allowlist?
    fn permits(&self, host_header: &str) -> bool {
        let (host, port) = split_host_port(host_header);
        self.allowed.iter().any(|(a_host, a_port)| {
            a_host.eq_ignore_ascii_case(&host) && matches_port(*a_port, port)
        })
    }

    /// The resolved allowlist as `host[:port]` strings, for boot-time
    /// diagnostic logging (P1-2) — so an operator staring at an
    /// unexpected `421` can see exactly what was permitted without
    /// re-deriving it from config by hand.
    pub fn describe(&self) -> Vec<String> {
        self.allowed
            .iter()
            .map(|(host, port)| match port {
                Some(p) => format!("{host}:{p}"),
                None => host.clone(),
            })
            .collect()
    }
}

fn matches_port(allowed_port: Option<u16>, request_port: Option<u16>) -> bool {
    match allowed_port {
        None => true,
        Some(_) => allowed_port == request_port,
    }
}

/// Split a `Host`/`:authority`-shaped string (`host`, `host:port`,
/// `[ipv6]`, or `[ipv6]:port`) into its host and optional port parts.
/// The host is returned verbatim (case preserved; callers compare
/// case-insensitively) with IPv6 brackets stripped and exactly one
/// trailing dot (if present) removed.
fn split_host_port(raw: &str) -> (String, Option<u16>) {
    let raw = raw.trim();
    let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
        match rest.find(']') {
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
        }
    } else {
        match raw.rsplit_once(':') {
            Some((host, port_str)) if !host.is_empty() => match port_str.parse::<u16>() {
                Ok(port) => (host.to_string(), Some(port)),
                // Not a numeric suffix (e.g. a bare, unbracketed IPv6
                // literal, which HTTP's Host header never legally
                // sends) — keep the original string as the host.
                Err(_) => (raw.to_string(), None),
            },
            _ => (raw.to_string(), None),
        }
    };
    // Strip exactly one trailing dot (FQDN root label) — see module docs.
    let host = match host.strip_suffix('.') {
        Some(stripped) => stripped.to_string(),
        None => host,
    };
    (host, port)
}

/// axum middleware: reject requests whose host identity isn't in the
/// configured [`HostAllowlist`] with `421 Misdirected Request`.
///
/// Host identity resolution, in order:
/// 1. The `Host` header, if present. A value that fails to decode as
///    UTF-8 is rejected outright (P2-1) rather than treated as absent.
/// 2. Otherwise, the URI's `:authority` component — populated for
///    HTTP/2 requests, which carry no `Host` header at all (P1-1).
/// 3. If both are absent, the request passes through unchecked
///    (HTTP/1.0 tolerance — see module docs).
pub async fn require_allowed_host(
    State(allowlist): State<Arc<HostAllowlist>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if allowlist.enforce() {
        match req.headers().get(header::HOST) {
            Some(header_val) => match header_val.to_str() {
                Ok(host) => {
                    if !allowlist.permits(host) {
                        return reject_misdirected();
                    }
                }
                Err(_) => return reject_misdirected(),
            },
            None => {
                if let Some(authority) = req.uri().authority() {
                    if !allowlist.permits(authority.as_str()) {
                        return reject_misdirected();
                    }
                }
                // Neither Host header nor :authority — allow (HTTP/1.0).
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
    fn split_host_port_strips_one_trailing_dot() {
        assert_eq!(
            split_host_port("localhost."),
            ("localhost".to_string(), None)
        );
        assert_eq!(
            split_host_port("localhost.:9099"),
            ("localhost".to_string(), Some(9099))
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
    fn ipv4_mapped_ipv6_loopback_bind_enforces() {
        // P2-2: `::ffff:127.0.0.1` is a loopback address in every
        // practical sense but `Ipv6Addr::is_loopback` alone (without
        // canonicalization) does not recognize the mapped form.
        let al = allowlist("[::ffff:127.0.0.1]:9099", &[]);
        assert!(al.enforce());
        assert!(al.permits("localhost"));
        assert!(!al.permits("evil.example.com"));
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

    #[test]
    fn wildcard_bind_does_not_add_wildcard_as_allowed_host() {
        // Nit: a wildcard bind IP is never a legitimate Host value, so
        // it must not appear as an allowlist entry (and specifically
        // must not accidentally match anything a client could send).
        let al = allowlist("0.0.0.0:9099", &["api.example.com"]);
        assert!(!al.permits("0.0.0.0"));
        assert!(!al.permits("0.0.0.0:9099"));
    }

    // ----- error paths -----

    #[test]
    fn subdomain_bypass_attempts_rejected() {
        // P2-3: hostnames that merely *contain* an allowed name must
        // not match — `eq_ignore_ascii_case` on the whole host segment
        // (not a substring/prefix/suffix check) already rejects these;
        // pin it so a future refactor toward substring matching would
        // fail loudly.
        let al = allowlist("127.0.0.1:9099", &[]);
        assert!(!al.permits("127.0.0.1.evil.com"));
        assert!(!al.permits("localhost.evil.com"));
    }

    #[test]
    fn malformed_bracket_host_rejected() {
        let al = allowlist("127.0.0.1:9099", &[]);
        assert!(!al.permits("[::1"));
    }

    #[test]
    fn empty_host_rejected() {
        let al = allowlist("127.0.0.1:9099", &[]);
        assert!(!al.permits(""));
    }

    #[test]
    fn double_trailing_dot_rejected() {
        // Only ONE trailing dot is stripped (see module docs) — a
        // second one is left dangling and fails to match.
        let al = allowlist("127.0.0.1:9099", &[]);
        assert!(!al.permits("localhost.."));
    }
}
