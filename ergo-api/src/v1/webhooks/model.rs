//! Webhook data model: the durable-ish subscription + delivery records, their
//! wire DTOs, the HMAC-SHA256 signing recipe, and the SSRF URL policy
//! (`v1-api-design.md` §4.1, fragment `realtime-ws-webhooks.md` §3.2–§3.4).
//!
//! A [`Subscription`] is the operator-registered target: a URL, the set of
//! channel keys (the SAME vocabulary as WS §2.2, validated by
//! [`parse_channel`](crate::v1::realtime::parse_channel)), an optional signing
//! secret, and the live governor state (`consecutive_failures`, `last_status`).
//! The secret is **write-only after creation** — echoed exactly once at
//! registration / rotation, never again (`secret_not_recoverable`).
//!
//! A [`Delivery`] is one attempt-group for one matched event: a stable
//! `delivery_id`, the event `seq` (the shared global cursor, so a webhook
//! consumer and a WS consumer agree on identity), the attempt/backoff state,
//! and the rendered request body. Consumers dedupe on `delivery_id` + `seq`.
//!
//! The signature is `HMAC-SHA256(secret, "{timestamp}.{raw_body}")`, hex,
//! prefixed `sha256=` — the exact recipe a consumer recomputes and
//! constant-time compares (`X-Ergo-Signature` header, §3.4). Signing uses the
//! proven `hmac` + `sha2` workspace crates (CLAUDE.md §2 — never hand-rolled).

use utoipa::ToSchema;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hmac::{Mac, SimpleHmac};
use serde::Serialize;
use serde_json::json;
use sha2::Sha256;

use crate::v1::routes::dto::unix_ms_to_iso;

/// The signing header value prefix (`X-Ergo-Signature: sha256=<hex>`, §3.4).
pub const SIGNATURE_PREFIX: &str = "sha256=";

/// Live delivery-health of a subscription (§3.2 `delivery.last_status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebhookHealth {
    /// Last delivery succeeded (or none attempted yet).
    Delivered,
    /// One or more recent attempts failed but the subscription is still active.
    Failing,
    /// Auto-disabled after too many consecutive failures (cost governor).
    Disabled,
}

/// Status of one delivery attempt-group (§3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Enqueued, not yet attempted.
    Pending,
    /// A 2xx was observed within the timeout.
    Delivered,
    /// A prior attempt failed; a retry is scheduled (`next_retry_at`).
    Retrying,
    /// Exhausted `max_attempts` (parked) — the queue advances past it.
    Failed,
}

impl DeliveryStatus {
    /// True while the delivery still owes at least one send attempt.
    pub fn is_open(self) -> bool {
        matches!(self, DeliveryStatus::Pending | DeliveryStatus::Retrying)
    }
}

/// The reason a subscription was auto-disabled (§3.3). `None` while active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AutoDisabledReason {
    /// `consecutive_failures` crossed `MAX_CONSECUTIVE_FAILURES`.
    MaxConsecutiveFailures,
}

/// An operator-registered webhook subscription (in-memory this PR; durable
/// persistence is DEFERRED — see the module docs on `super`).
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Server-assigned stable id (`wh_<hex>`).
    pub webhook_id: String,
    /// The delivery target URL (validated by [`UrlPolicy`] at registration).
    pub url: String,
    /// Normalized channel keys (WS §2.2 vocabulary). Delivery fires when an
    /// event's routes intersect this set.
    pub channels: Vec<String>,
    /// The HMAC signing secret. `None` = unsigned deliveries (allowed, but the
    /// signature header is then omitted). Never serialized after creation.
    pub secret: Option<String>,
    /// `false` when paused (by the operator) or auto-disabled.
    pub active: bool,
    /// `0` = fire on mempool-tentative events too; `>=1` = confirmed only
    /// (§3.2 `confirmations`). The substrate only distinguishes 0-vs-1 today.
    pub min_confirmations: u32,
    /// Registration time, unix ms.
    pub created_at_unix_ms: u64,
    // ----- live governor state -----
    /// Consecutive failed deliveries since the last success (§3.3).
    pub consecutive_failures: u32,
    /// Rolled-up health for the DTO.
    pub health: WebhookHealth,
    /// Time of the last delivery attempt outcome, unix ms.
    pub last_delivery_at_unix_ms: Option<u64>,
    /// Set when `active` was flipped off automatically (§3.3).
    pub auto_disabled_reason: Option<AutoDisabledReason>,
}

impl Subscription {
    /// Does this subscription want an event delivered on `routes`, given the
    /// event's `confirmed` flag? Matches when active, a route intersects the
    /// channel set, and the confirmation gate is satisfied.
    pub fn matches(&self, routes: &[String], confirmed: bool) -> bool {
        if !self.active {
            return false;
        }
        if self.min_confirmations >= 1 && !confirmed {
            return false;
        }
        routes.iter().any(|r| self.channels.iter().any(|c| c == r))
    }

    /// The public DTO (§3.2). **Never** carries the secret — only `secret_set`.
    pub fn to_dto(&self) -> serde_json::Value {
        json!({
            "webhook_id": self.webhook_id,
            "url": self.url,
            "channels": self.channels,
            "active": self.active,
            "confirmations": self.min_confirmations,
            "created_at": self.created_at_unix_ms,
            "created_at_iso": unix_ms_to_iso(self.created_at_unix_ms),
            "secret_set": self.secret.is_some(),
            "delivery": {
                "consecutive_failures": self.consecutive_failures,
                "last_status": self.health,
                "last_delivery_at": self.last_delivery_at_unix_ms,
                "auto_disabled_reason": self.auto_disabled_reason,
            },
        })
    }

    /// The registration/rotation response DTO: the public DTO **plus** the
    /// secret, echoed exactly once (§3.2). Callers use this ONLY on the
    /// create/rotate path and never persist the returned value server-side.
    pub fn to_dto_with_secret(&self) -> serde_json::Value {
        let mut v = self.to_dto();
        if let (Some(obj), Some(secret)) = (v.as_object_mut(), self.secret.as_ref()) {
            obj.insert("secret".to_string(), json!(secret));
        }
        v
    }
}

/// One delivery attempt-group for one matched (webhook, event) pair.
#[derive(Debug, Clone)]
pub struct Delivery {
    /// Stable id across retries (`dl_<hex>`); the consumer dedupe key.
    pub delivery_id: String,
    /// Owning subscription.
    pub webhook_id: String,
    /// The global event cursor (shared with WS) — dedupe/order key.
    pub event_seq: u64,
    /// The channel key this delivery fired on (the first matched route).
    pub channel: String,
    /// The event-kind token (`block_applied`, `box_spent`, …).
    pub event_kind: &'static str,
    /// The rendered JSON body (stable across retries).
    pub body: String,
    /// Wall-clock of the source event, unix ms (signed into the payload).
    pub event_unix_ms: u64,
    /// Current status.
    pub status: DeliveryStatus,
    /// Number of send attempts made so far.
    pub attempts: u32,
    /// Outcome time of the last attempt, unix ms.
    pub last_attempt_at_unix_ms: Option<u64>,
    /// HTTP status of the last attempt (`None` = transport error / not sent).
    pub response_code: Option<u16>,
    /// When the next retry becomes due, unix ms (`None` = terminal or not
    /// scheduled).
    pub next_retry_at_unix_ms: Option<u64>,
}

impl Delivery {
    /// The delivery-log DTO (§3.5).
    pub fn to_dto(&self) -> serde_json::Value {
        json!({
            "delivery_id": self.delivery_id,
            "event_seq": self.event_seq,
            "channel": self.channel,
            "event": self.event_kind,
            "status": self.status,
            "attempts": self.attempts,
            "last_attempt_at": self.last_attempt_at_unix_ms,
            "response_code": self.response_code,
            "next_retry_at": self.next_retry_at_unix_ms,
        })
    }
}

/// Compute the `X-Ergo-Signature` value for a delivery (§3.4):
/// `sha256=` + hex(HMAC-SHA256(secret, "{timestamp}.{raw_body}")).
///
/// The `timestamp` is folded into the signed string so a consumer can reject
/// replays outside a clock-skew window. Uses `SimpleHmac` (RFC 2104 HMAC over
/// SHA-256) — the same proven primitive family the node's inbound gate uses.
pub fn sign_body(secret: &str, timestamp_unix_ms: u64, raw_body: &str) -> String {
    let mut mac = <SimpleHmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .expect("SimpleHmac accepts a key of any length");
    mac.update(timestamp_unix_ms.to_string().as_bytes());
    mac.update(b".");
    mac.update(raw_body.as_bytes());
    let digest = mac.finalize().into_bytes();
    format!("{SIGNATURE_PREFIX}{}", hex::encode(digest))
}

/// SSRF guard policy for a registration URL (§3.2). Default-deny for
/// loopback / private / link-local / unspecified targets; an operator opts
/// dev/loopback delivery in explicitly.
#[derive(Debug, Clone, Copy)]
pub struct UrlPolicy {
    /// Require the `https` scheme (reject `http` with `insecure_url`). Default
    /// `true`. An operator may allow `http` for loopback/dev targets.
    pub require_https: bool,
    /// Allow loopback targets (`127.0.0.0/8`, `::1`, `localhost`). Default
    /// `false`.
    pub allow_loopback: bool,
    /// Allow RFC1918 / ULA / link-local private targets. Default `false`.
    pub allow_private: bool,
}

impl Default for UrlPolicy {
    /// The safe default: https-only, no loopback, no private ranges.
    fn default() -> Self {
        UrlPolicy {
            require_https: true,
            allow_loopback: false,
            allow_private: false,
        }
    }
}

/// Why a registration URL was rejected. Maps to the canonical §4 reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlReject {
    /// Not `https` (and http not allowed) → `insecure_url`.
    Insecure,
    /// Malformed / unparseable / embedded-credentials → `forbidden_target`
    /// (a 400-class rejection; we fold "malformed" into forbidden so a caller
    /// never learns whether a private host merely *looks* malformed).
    Malformed,
    /// Loopback / private / link-local / unspecified target → `forbidden_target`.
    ForbiddenTarget,
}

/// Split a URL into `(scheme, authority, has_userinfo)` without pulling in a
/// URL crate. Authority is everything between `://` and the first `/`, `?`,
/// or `#`. Returns `None` for anything that is not `scheme://…`.
fn split_url(url: &str) -> Option<(&str, &str, bool)> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() {
        return None;
    }
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|a| !a.is_empty())?;
    let has_userinfo = authority.contains('@');
    Some((scheme, authority, has_userinfo))
}

/// Extract the bare host from an authority (`host`, `host:port`,
/// `[ipv6]`, `[ipv6]:port`). Userinfo must already be stripped by the caller.
fn host_of(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        // `[ipv6]` or `[ipv6]:port`
        return rest.split(']').next().unwrap_or(rest);
    }
    authority.split(':').next().unwrap_or(authority)
}

fn ipv4_is_forbidden(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        // 100.64.0.0/10 CGNAT
        || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
}

fn ipv6_is_forbidden(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // fc00::/7 unique-local
        || (ip.segments()[0] & 0xfe00) == 0xfc00
        // fe80::/10 link-local
        || (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// True when `ip` is a private / loopback / otherwise non-routable target the
/// SSRF guard blocks (unless the policy allows it).
fn ip_is_forbidden(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_is_forbidden(v4),
        IpAddr::V6(v6) => ipv6_is_forbidden(v6),
    }
}

/// Validate a registration URL against the policy (§3.2 SSRF guard).
///
/// **Scope + honest limitation:** this validates the URL's *literal* host. A
/// literal private/loopback IP or `localhost` is rejected; a hostname that
/// *resolves* to a private IP (DNS-rebinding) is NOT caught here — the real
/// network sink, when it lands, must re-check the resolved socket address
/// before connecting. Documented so the guard is not mistaken for complete.
pub fn validate_url(url: &str, policy: &UrlPolicy) -> Result<(), UrlReject> {
    let (scheme, authority, has_userinfo) = split_url(url).ok_or(UrlReject::Malformed)?;
    if has_userinfo {
        // `http://user:pass@host` — an SSRF/confusion vector; reject outright.
        return Err(UrlReject::ForbiddenTarget);
    }
    let scheme = scheme.to_ascii_lowercase();
    let is_http = match scheme.as_str() {
        "https" => false,
        "http" => true,
        _ => return Err(UrlReject::Malformed),
    };

    let host = host_of(authority);
    if host.is_empty() {
        return Err(UrlReject::Malformed);
    }

    // Plaintext HTTP is only ever excused for loopback dev targets — the
    // loopback opt-in must not waive `require_https` for public hosts.
    let loopback_host = host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    if is_http && policy.require_https && !(loopback_host && policy.allow_loopback) {
        return Err(UrlReject::Insecure);
    }

    // Literal-host SSRF checks.
    if host.eq_ignore_ascii_case("localhost") {
        return if policy.allow_loopback {
            Ok(())
        } else {
            Err(UrlReject::ForbiddenTarget)
        };
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip_is_forbidden(ip) {
            let allowed = (ip.is_loopback() && policy.allow_loopback)
                || (!ip.is_loopback() && policy.allow_private);
            if !allowed {
                return Err(UrlReject::ForbiddenTarget);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    const HEX64: &str = "6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f";

    fn sub(active: bool, min_conf: u32, channels: &[&str]) -> Subscription {
        Subscription {
            webhook_id: "wh_1".into(),
            url: "https://x.example/h".into(),
            channels: channels.iter().map(|s| s.to_string()).collect(),
            secret: Some("whsec_abc".into()),
            active,
            min_confirmations: min_conf,
            created_at_unix_ms: 1_000,
            consecutive_failures: 0,
            health: WebhookHealth::Delivered,
            last_delivery_at_unix_ms: None,
            auto_disabled_reason: None,
        }
    }

    // ----- signing: known-vector HMAC -----

    #[test]
    fn sign_body_matches_known_hmac_sha256_vector() {
        // Oracle: HMAC-SHA256(key="key") over the EXACT signed string the
        // recipe builds — "{timestamp}.{body}" = "1.The quick brown fox jumps
        // over the lazy dog". Computed independently with Python's
        // hmac/hashlib (an external oracle, not a self-oracle):
        //   hmac.new(b"key", b"1.The quick brown fox jumps over the lazy dog",
        //            hashlib.sha256).hexdigest()
        let sig = sign_body("key", 1, "The quick brown fox jumps over the lazy dog");
        assert_eq!(
            sig,
            "sha256=3ff4d3cc115b639a16dc5b217aa5c89be41d1e4b54efc356d63d0cd2a65b30f1"
        );
        // Structural: prefix + 64 hex chars.
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), SIGNATURE_PREFIX.len() + 64);
    }

    #[test]
    fn sign_body_is_deterministic_and_key_sensitive() {
        let a = sign_body("secret", 42, "body");
        let b = sign_body("secret", 42, "body");
        let c = sign_body("other", 42, "body");
        let d = sign_body("secret", 43, "body");
        assert_eq!(a, b, "same inputs → same signature");
        assert_ne!(a, c, "key changes the signature");
        assert_ne!(a, d, "timestamp is part of the signed string");
    }

    // ----- matching -----

    #[test]
    fn matches_requires_active_and_route_intersection() {
        let s = sub(true, 1, &["blocks"]);
        assert!(s.matches(&["blocks".into()], true));
        assert!(!s.matches(&["mempool".into()], true));
        let paused = sub(false, 1, &["blocks"]);
        assert!(!paused.matches(&["blocks".into()], true));
    }

    #[test]
    fn matches_confirmation_gate() {
        let confirmed_only = sub(true, 1, &["blocks"]);
        assert!(!confirmed_only.matches(&["blocks".into()], false));
        assert!(confirmed_only.matches(&["blocks".into()], true));
        let tentative_ok = sub(true, 0, &["blocks"]);
        assert!(tentative_ok.matches(&["blocks".into()], false));
    }

    // ----- secret never echoed -----

    #[test]
    fn to_dto_never_carries_secret_but_reports_secret_set() {
        let s = sub(true, 1, &["blocks"]);
        let dto = s.to_dto();
        assert!(
            dto.get("secret").is_none(),
            "secret must never be in to_dto"
        );
        assert_eq!(dto["secret_set"], true);
    }

    #[test]
    fn to_dto_with_secret_echoes_once() {
        let s = sub(true, 1, &["blocks"]);
        let dto = s.to_dto_with_secret();
        assert_eq!(dto["secret"], "whsec_abc");
        assert_eq!(dto["secret_set"], true);
    }

    // ----- SSRF url policy -----

    #[test]
    fn url_https_public_is_accepted() {
        assert!(validate_url("https://dapp.example/hook", &UrlPolicy::default()).is_ok());
        assert!(validate_url("https://93.184.216.34/hook", &UrlPolicy::default()).is_ok());
    }

    #[test]
    fn url_http_rejected_as_insecure_by_default() {
        assert_eq!(
            validate_url("http://dapp.example/hook", &UrlPolicy::default()),
            Err(UrlReject::Insecure)
        );
    }

    #[test]
    fn url_http_public_still_insecure_when_loopback_opted_in() {
        let p = UrlPolicy {
            require_https: true,
            allow_loopback: true,
            allow_private: false,
        };
        // The loopback opt-in excuses plaintext only for loopback targets.
        assert_eq!(
            validate_url("http://dapp.example/hook", &p),
            Err(UrlReject::Insecure)
        );
        assert!(validate_url("http://127.0.0.1:9099/h", &p).is_ok());
        assert!(validate_url("http://localhost:9099/h", &p).is_ok());
    }

    #[test]
    fn url_loopback_and_private_rejected_by_default() {
        let p = UrlPolicy::default();
        assert_eq!(
            validate_url("https://127.0.0.1/h", &p),
            Err(UrlReject::ForbiddenTarget)
        );
        assert_eq!(
            validate_url("https://localhost/h", &p),
            Err(UrlReject::ForbiddenTarget)
        );
        assert_eq!(
            validate_url("https://10.1.2.3/h", &p),
            Err(UrlReject::ForbiddenTarget)
        );
        assert_eq!(
            validate_url("https://192.168.0.5/h", &p),
            Err(UrlReject::ForbiddenTarget)
        );
        assert_eq!(
            validate_url("https://169.254.1.1/h", &p),
            Err(UrlReject::ForbiddenTarget)
        );
        assert_eq!(
            validate_url("https://[::1]/h", &p),
            Err(UrlReject::ForbiddenTarget)
        );
    }

    #[test]
    fn url_loopback_allowed_when_policy_opts_in() {
        let p = UrlPolicy {
            require_https: false,
            allow_loopback: true,
            allow_private: false,
        };
        assert!(validate_url("http://127.0.0.1:9099/h", &p).is_ok());
        assert!(validate_url("http://localhost:9099/h", &p).is_ok());
        // A private (non-loopback) target is still blocked.
        assert_eq!(
            validate_url("http://10.0.0.1/h", &p),
            Err(UrlReject::ForbiddenTarget)
        );
    }

    #[test]
    fn url_embedded_credentials_forbidden() {
        assert_eq!(
            validate_url("https://user:pass@evil.example/h", &UrlPolicy::default()),
            Err(UrlReject::ForbiddenTarget)
        );
    }

    #[test]
    fn url_malformed_rejected() {
        let p = UrlPolicy::default();
        assert_eq!(validate_url("not-a-url", &p), Err(UrlReject::Malformed));
        assert_eq!(validate_url("ftp://x/h", &p), Err(UrlReject::Malformed));
        assert_eq!(validate_url("https://", &p), Err(UrlReject::Malformed));
    }

    #[test]
    fn delivery_dto_shape() {
        let d = Delivery {
            delivery_id: "dl_1".into(),
            webhook_id: "wh_1".into(),
            event_seq: 42,
            channel: "blocks".into(),
            event_kind: "block_applied",
            body: "{}".into(),
            event_unix_ms: 1,
            status: DeliveryStatus::Retrying,
            attempts: 2,
            last_attempt_at_unix_ms: Some(5),
            response_code: Some(500),
            next_retry_at_unix_ms: Some(9),
        };
        let v = d.to_dto();
        assert_eq!(v["delivery_id"], "dl_1");
        assert_eq!(v["event_seq"], 42);
        assert_eq!(v["status"], "retrying");
        assert_eq!(v["attempts"], 2);
        assert_eq!(v["response_code"], 500);
        assert_eq!(v["next_retry_at"], 9);
        let _ = HEX64;
    }
}
