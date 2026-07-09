//! Per-IP rate/cost governor middleware (`v1-api-design.md` §2.1–§2.2).
//!
//! The T0 "public but **bounded**" contract's load-bearing control: every
//! open surface sits behind a per-IP token bucket whose refill and burst are
//! config knobs, and each route class ("cheap read / heavy read / compute" —
//! §2.2) consumes a different number of tokens per request. A depleted bucket
//! answers `429 rate_limited` (the §1.3 envelope) with a `Retry-After`
//! header. The operator's own UI (loopback) is exempt by default.
//!
//! Dependency-light on purpose: a plain `HashMap<IpAddr, Bucket>` behind a
//! `std::sync::Mutex`, refilled lazily on access (no timer task). The lock is
//! held only for the O(1) bucket update — never across an `.await`.
//!
//! **Mounting.** This is an axum `from_fn_with_state` middleware. A group
//! attaches it per route/subtree with the class for that surface:
//! ```ignore
//! let gov = Governor::new(GovernorConfig::default());
//! router.route_layer(axum::middleware::from_fn_with_state(
//!     gov.state(RouteClass::HeavyRead),
//!     governor_mw,
//! ))
//! ```
//! The shared [`Governor`] (one per node) is cloned by `Arc` into each
//! per-class [`GovernorState`], so every class shares ONE per-IP budget.
//!
//! **Client IP** comes from [`super::client_ip`] (the `ConnectInfo` axum
//! installs when served with `.into_make_service_with_connect_info::<SocketAddr>()`).
//! When connect-info is absent the request is bucketed under a shared
//! "unknown" key — bounded, never exempt.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::State,
    http::{header::RETRY_AFTER, HeaderValue, Request},
    middleware::Next,
    response::Response,
};

use super::error::{v1_error, Reason};
use super::{client_ip, is_trusted_loopback};

/// The bucket key used when a request carries no resolvable peer IP. All such
/// requests share ONE bucket so a connect-info gap can't become an unbounded
/// bypass.
const UNKNOWN_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Cost class of a route (`v1-api-design.md` §2.2). The weight (tokens
/// consumed per request) grows with server-side work: a cheap snapshot read,
/// a heavier indexed/scan read, or attacker-driven compute (script execute,
/// tx build/simulate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteClass {
    /// Snapshot-backed constant-work reads (`node/*`, `diagnostics`, tips).
    CheapRead,
    /// Indexed / paginated / bounded-scan reads (`boxes/*`, `holders`, chain lists).
    HeavyRead,
    /// Attacker-influenced compute (`script/*`, tx build/simulate, `graphql`).
    Compute,
}

/// Tunable governor knobs (all config-driven, shipped conservative — §2.2).
#[derive(Debug, Clone)]
pub struct GovernorConfig {
    /// Sustained refill rate, tokens per second per IP.
    pub refill_per_sec: f64,
    /// Bucket capacity (max burst) in tokens.
    pub burst: f64,
    /// Tokens a [`RouteClass::CheapRead`] request costs.
    pub cheap_weight: f64,
    /// Tokens a [`RouteClass::HeavyRead`] request costs.
    pub heavy_weight: f64,
    /// Tokens a [`RouteClass::Compute`] request costs.
    pub compute_weight: f64,
    /// Exempt loopback peers (the operator's own UI) from bucketing. Default `true`.
    pub exempt_loopback: bool,
    /// Prune idle full buckets once the table exceeds this many IPs (memory bound).
    pub max_tracked_ips: usize,
    /// A bucket idle at least this long AND full is eligible for pruning.
    pub idle_prune_after: Duration,
    /// When `true`, a reverse proxy terminates in front of the API on
    /// loopback, so the peer socket is the proxy — its loopback-ness cannot
    /// grant the [`GovernorConfig::exempt_loopback`] exemption. Default
    /// `false` (direct bind). See [`super::is_trusted_loopback`].
    pub local_reverse_proxy: bool,
}

impl Default for GovernorConfig {
    /// Conservative fleet defaults: ~20 cheap reads/sec sustained, burst 40;
    /// heavy reads cost 4×, compute 10×; loopback exempt. Groups tune per
    /// the §2.2 table.
    fn default() -> Self {
        Self {
            refill_per_sec: 20.0,
            burst: 40.0,
            cheap_weight: 1.0,
            heavy_weight: 4.0,
            compute_weight: 10.0,
            exempt_loopback: true,
            max_tracked_ips: 65_536,
            idle_prune_after: Duration::from_secs(600),
            local_reverse_proxy: false,
        }
    }
}

/// Rejection reason from [`GovernorConfig::validate`] / [`Governor::new`].
/// Invalid config must never reach the bucket math: a negative weight ADDS
/// tokens on charge, and a zero/non-finite refill or burst breaks throttling.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
pub enum GovernorConfigError {
    /// `refill_per_sec` must be finite and strictly positive.
    #[error("refill_per_sec must be finite and > 0, got {0}")]
    Refill(f64),
    /// `burst` must be finite and strictly positive.
    #[error("burst must be finite and > 0, got {0}")]
    Burst(f64),
    /// A route-class weight must be finite and strictly positive.
    #[error("{class} weight must be finite and > 0, got {value}")]
    Weight {
        /// The offending route class.
        class: &'static str,
        /// The rejected weight.
        value: f64,
    },
}

impl GovernorConfig {
    /// Validate the knobs at the constructor boundary (`v1-api-design.md`
    /// §2.2). Rejects a non-finite/non-positive `refill_per_sec` or `burst`
    /// and any non-finite/non-positive route weight (a zero weight would make
    /// its whole route class unmetered — every charge costs 0), so
    /// [`Governor::charge_at`] never operates on config that would corrupt or
    /// bypass the token bucket.
    pub fn validate(&self) -> Result<(), GovernorConfigError> {
        if !self.refill_per_sec.is_finite() || self.refill_per_sec <= 0.0 {
            return Err(GovernorConfigError::Refill(self.refill_per_sec));
        }
        if !self.burst.is_finite() || self.burst <= 0.0 {
            return Err(GovernorConfigError::Burst(self.burst));
        }
        for (class, value) in [
            ("cheap", self.cheap_weight),
            ("heavy", self.heavy_weight),
            ("compute", self.compute_weight),
        ] {
            if !value.is_finite() || value <= 0.0 {
                return Err(GovernorConfigError::Weight { class, value });
            }
        }
        Ok(())
    }

    /// Tokens a request of `class` consumes.
    fn weight(&self, class: RouteClass) -> f64 {
        match class {
            RouteClass::CheapRead => self.cheap_weight,
            RouteClass::HeavyRead => self.heavy_weight,
            RouteClass::Compute => self.compute_weight,
        }
    }
}

/// One IP's token bucket.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// The shared, node-wide rate/cost governor. Construct once
/// ([`Governor::new`]) and derive a per-class [`GovernorState`]
/// ([`Governor::state`]) for each mounted subtree.
#[derive(Debug)]
pub struct Governor {
    config: GovernorConfig,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

/// Outcome of a bucket charge: either allowed, or throttled with the
/// whole-second `Retry-After` a client should wait.
enum Charge {
    Allowed,
    Throttled { retry_after_secs: u64 },
}

impl Governor {
    /// Build the shared governor from config. `Arc`-wrapped so per-class
    /// [`GovernorState`] handles can share the one per-IP budget.
    pub fn new(config: GovernorConfig) -> Result<Arc<Self>, GovernorConfigError> {
        config.validate()?;
        Ok(Arc::new(Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }))
    }

    /// Per-route middleware state for `from_fn_with_state`, pinning the
    /// [`RouteClass`] for the subtree it wraps.
    pub fn state(self: &Arc<Self>, class: RouteClass) -> GovernorState {
        GovernorState {
            governor: Arc::clone(self),
            class,
        }
    }

    /// Charge `cost` tokens to `ip`'s bucket at wall-clock `now`. Lazily
    /// refills first (elapsed × refill, capped at burst). Deterministic in
    /// `now` for testing; [`Governor::charge`] supplies `Instant::now()`.
    fn charge_at(&self, ip: IpAddr, cost: f64, now: Instant) -> Charge {
        let mut map = self.buckets.lock().expect("governor mutex poisoned");
        let refill = self.config.refill_per_sec;
        let burst = self.config.burst;

        let bucket = map.entry(ip).or_insert(Bucket {
            tokens: burst,
            last: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill).min(burst);
        bucket.last = now;

        let outcome = if bucket.tokens >= cost {
            bucket.tokens -= cost;
            Charge::Allowed
        } else {
            let deficit = cost - bucket.tokens;
            let secs = if refill > 0.0 {
                (deficit / refill).ceil() as u64
            } else {
                u64::MAX
            };
            Charge::Throttled {
                retry_after_secs: secs.max(1),
            }
        };

        if map.len() > self.config.max_tracked_ips {
            let cutoff = self.config.idle_prune_after;
            // Virtual token count: stored tokens plus the refill accrued while
            // idle (capped at burst) — the SAME recompute the live charge does.
            // An idle bucket's stored `tokens` is stale, so the passes below must
            // use this, never `b.tokens` directly.
            let virtual_tokens = |b: &Bucket| {
                let idle = now.saturating_duration_since(b.last).as_secs_f64();
                (b.tokens + idle * refill).min(burst)
            };
            // Pass 1 (lossless): drop a bucket only once it is idle past the
            // cutoff AND has virtually refilled to full — a fresh entry also
            // starts at `burst`, so nothing is lost. A drained bucket keeps its
            // outstanding deficit (dropping it would refund the penalty).
            map.retain(|_, b| {
                let idle = now.saturating_duration_since(b.last);
                virtual_tokens(b) < burst || idle < cutoff
            });
            // Pass 2 (hard bound): pass 1 cannot shrink a table full of ACTIVE
            // peers (all `idle < cutoff`), so on its own `max_tracked_ips` never
            // bounds memory — a flood of distinct live IPs (trivial over IPv6)
            // grows the map without limit (a memory-exhaustion DoS). Evict the
            // LEAST-throttled buckets (highest virtual tokens) down to the cap: a
            // near-full bucket sheds ~no enforcement when evicted (recreated at
            // `burst`), while a drained/throttled bucket keeps its penalty.
            // Losing perfect per-IP tracking for the least-penalized IPs is the
            // correct trade against unbounded memory. Only a fresh insert can
            // exceed the cap, so in steady state this evicts at most one bucket
            // per charge.
            while map.len() > self.config.max_tracked_ips {
                let Some(victim) = map
                    .iter()
                    .max_by(|(_, a), (_, b)| {
                        virtual_tokens(a)
                            .partial_cmp(&virtual_tokens(b))
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|(&ip, _)| ip)
                else {
                    break;
                };
                map.remove(&victim);
            }
        }
        outcome
    }

    /// Charge `cost` tokens to `ip`'s bucket now.
    fn charge(&self, ip: IpAddr, cost: f64) -> Charge {
        self.charge_at(ip, cost, Instant::now())
    }

    /// The token cost of a request in `class` under this governor's
    /// configured weights (§2.2) — the ONE weight table `batch` (§4.7,
    /// `routes::batch`) and any future non-middleware caller draws from,
    /// rather than inventing a second per-endpoint cost vocabulary.
    pub(crate) fn class_weight(&self, class: RouteClass) -> f64 {
        self.config.weight(class)
    }

    /// Charge `cost` tokens against `ip`'s bucket right now, returning the
    /// whole-second `Retry-After` hint (seconds) on throttle. The one
    /// non-middleware entry point into the SAME per-IP bucket
    /// [`governor_mw`] draws from — `batch` (§4.7) charges once, up front,
    /// for its members' summed weight rather than re-entering the bucket
    /// once per dispatched item (which would double-charge every item
    /// against both batch's own charge and a per-route middleware layer).
    pub(crate) fn try_charge(&self, ip: IpAddr, cost: f64) -> Result<(), u64> {
        match self.charge(ip, cost) {
            Charge::Allowed => Ok(()),
            Charge::Throttled { retry_after_secs } => Err(retry_after_secs),
        }
    }

    /// Whether `req`'s peer is the trusted-loopback exemption under this
    /// governor's config — the exact policy [`governor_mw`] applies, reused
    /// (never forked) so a non-middleware caller like `batch`'s upfront
    /// charge agrees with what the per-route middleware would have decided
    /// for the same peer.
    pub(crate) fn exempt_loopback(&self, req: &Request<Body>) -> bool {
        self.config.exempt_loopback && is_trusted_loopback(req, self.config.local_reverse_proxy)
    }
}

/// Per-route middleware state: the shared [`Governor`] plus the [`RouteClass`]
/// for the wrapped subtree. Cheap to clone (`Arc` + a `Copy` enum).
#[derive(Debug, Clone)]
pub struct GovernorState {
    governor: Arc<Governor>,
    class: RouteClass,
}

/// axum middleware enforcing the per-IP token bucket for its route class.
/// Loopback is exempt when configured; a depleted bucket answers
/// `429 rate_limited` (§1.3 envelope) with a `Retry-After` header.
pub async fn governor_mw(
    State(state): State<GovernorState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let cfg = &state.governor.config;

    if cfg.exempt_loopback && is_trusted_loopback(&req, cfg.local_reverse_proxy) {
        return next.run(req).await;
    }

    let key = client_ip(&req).unwrap_or(UNKNOWN_IP);
    let cost = cfg.weight(state.class);
    match state.governor.try_charge(key, cost) {
        Ok(()) => next.run(req).await,
        Err(retry_after_secs) => {
            let mut resp = v1_error(
                Reason::RateLimited,
                "per-IP rate/cost limit exceeded",
                format!("retry after ~{retry_after_secs}s"),
            );
            if let Ok(val) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                resp.headers_mut().insert(RETRY_AFTER, val);
            }
            resp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    // ----- helpers -----

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, n))
    }

    /// A governor whose bucket holds exactly `burst` tokens and refills slowly,
    /// so charges are deterministic within a test's wall-clock window.
    fn tight_governor(burst: f64) -> Arc<Governor> {
        Governor::new(GovernorConfig {
            refill_per_sec: 0.0001,
            burst,
            cheap_weight: 1.0,
            heavy_weight: 4.0,
            compute_weight: 10.0,
            exempt_loopback: true,
            max_tracked_ips: 1024,
            idle_prune_after: Duration::from_secs(600),
            local_reverse_proxy: false,
        })
        .expect("valid governor config")
    }

    fn allowed(c: Charge) -> bool {
        matches!(c, Charge::Allowed)
    }

    // ----- happy path / throttling -----

    #[test]
    fn allows_up_to_burst_then_throttles() {
        let gov = tight_governor(3.0);
        let now = Instant::now();
        assert!(allowed(gov.charge_at(ip(1), 1.0, now)));
        assert!(allowed(gov.charge_at(ip(1), 1.0, now)));
        assert!(allowed(gov.charge_at(ip(1), 1.0, now)));
        // Fourth request has no tokens left → throttled with a Retry-After.
        match gov.charge_at(ip(1), 1.0, now) {
            Charge::Throttled { retry_after_secs } => assert!(retry_after_secs >= 1),
            Charge::Allowed => panic!("should have throttled"),
        }
    }

    #[test]
    fn refill_restores_tokens_over_time() {
        let gov = Governor::new(GovernorConfig {
            refill_per_sec: 10.0,
            burst: 1.0,
            exempt_loopback: false,
            ..GovernorConfig::default()
        })
        .expect("valid governor config");
        let t0 = Instant::now();
        assert!(allowed(gov.charge_at(ip(2), 1.0, t0)));
        // Immediately after: empty.
        assert!(!allowed(gov.charge_at(ip(2), 1.0, t0)));
        // 200ms later at 10 tokens/s ⇒ +2 tokens, capped at burst=1 ⇒ allowed.
        assert!(allowed(gov.charge_at(
            ip(2),
            1.0,
            t0 + Duration::from_millis(200)
        )));
    }

    // ----- weight classes -----

    #[test]
    fn compute_weight_drains_faster_than_cheap() {
        // burst 10: one compute (10) empties it; a cheap (1) then throttles.
        let gov = tight_governor(10.0);
        let now = Instant::now();
        assert!(allowed(gov.charge_at(
            ip(3),
            gov.config.weight(RouteClass::Compute),
            now,
        )));
        assert!(!allowed(gov.charge_at(
            ip(3),
            gov.config.weight(RouteClass::CheapRead),
            now,
        )));
    }

    #[test]
    fn heavy_costs_four_cheap() {
        // burst 4: four cheap reads fit, or exactly one heavy read.
        let gov = tight_governor(4.0);
        let now = Instant::now();
        assert!(allowed(gov.charge_at(
            ip(4),
            gov.config.weight(RouteClass::HeavyRead),
            now,
        )));
        assert!(!allowed(gov.charge_at(ip(4), 1.0, now)));
    }

    #[test]
    fn buckets_are_per_ip() {
        let gov = tight_governor(1.0);
        let now = Instant::now();
        assert!(allowed(gov.charge_at(ip(5), 1.0, now)));
        assert!(!allowed(gov.charge_at(ip(5), 1.0, now)));
        // A different IP has its own full bucket.
        assert!(allowed(gov.charge_at(ip(6), 1.0, now)));
    }

    // ----- middleware: loopback exemption + 429 envelope -----

    async fn body_reason(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v["error"]["reason"].as_str().unwrap().to_string()
    }

    fn app(gov: &Arc<Governor>, class: RouteClass) -> Router {
        Router::new()
            .route("/x", get(|| async { "ok" }))
            .route_layer(axum::middleware::from_fn_with_state(
                gov.state(class),
                governor_mw,
            ))
    }

    fn req_from(ip: IpAddr) -> Request<Body> {
        let mut req = Request::builder().uri("/x").body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::new(ip, 40000)));
        req
    }

    #[tokio::test]
    async fn loopback_is_exempt_by_default() {
        let gov = tight_governor(1.0); // burst 1: a non-exempt IP throttles fast
        let loop_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        // Many loopback requests all pass despite burst=1.
        for _ in 0..5 {
            let resp = app(&gov, RouteClass::CheapRead)
                .oneshot(req_from(loop_ip))
                .await
                .unwrap();
            assert_eq!(resp.status(), axum::http::StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn remote_ip_throttles_with_rate_limited_envelope_and_retry_after() {
        let gov = tight_governor(1.0);
        let remote = ip(9);
        // First passes, second is throttled.
        let ok = app(&gov, RouteClass::CheapRead)
            .oneshot(req_from(remote))
            .await
            .unwrap();
        assert_eq!(ok.status(), axum::http::StatusCode::OK);

        let throttled = app(&gov, RouteClass::CheapRead)
            .oneshot(req_from(remote))
            .await
            .unwrap();
        assert_eq!(
            throttled.status(),
            axum::http::StatusCode::TOO_MANY_REQUESTS
        );
        assert!(
            throttled.headers().contains_key(RETRY_AFTER),
            "429 must carry Retry-After",
        );
        assert_eq!(body_reason(throttled).await, "rate_limited");
    }

    #[tokio::test]
    async fn unknown_ip_is_bucketed_not_exempt() {
        // No ConnectInfo extension ⇒ shared UNKNOWN bucket, still bounded.
        let gov = tight_governor(1.0);
        let mk = || Request::builder().uri("/x").body(Body::empty()).unwrap();
        let a = app(&gov, RouteClass::CheapRead)
            .oneshot(mk())
            .await
            .unwrap();
        assert_eq!(a.status(), axum::http::StatusCode::OK);
        let b = app(&gov, RouteClass::CheapRead)
            .oneshot(mk())
            .await
            .unwrap();
        assert_eq!(b.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    // ----- config validation -----

    #[test]
    fn new_rejects_non_positive_refill() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let cfg = GovernorConfig {
                refill_per_sec: bad,
                ..GovernorConfig::default()
            };
            // NaN != NaN, so match the variant rather than compare the payload.
            assert!(matches!(
                cfg.validate(),
                Err(GovernorConfigError::Refill(_))
            ));
            assert!(Governor::new(cfg).is_err());
        }
    }

    #[test]
    fn new_rejects_non_positive_burst() {
        for bad in [0.0, -5.0, f64::NAN] {
            let cfg = GovernorConfig {
                burst: bad,
                ..GovernorConfig::default()
            };
            assert!(matches!(cfg.validate(), Err(GovernorConfigError::Burst(_))));
            assert!(Governor::new(cfg).is_err());
        }
    }

    #[test]
    fn new_rejects_negative_or_nonfinite_weight() {
        let cfg = GovernorConfig {
            heavy_weight: -1.0,
            ..GovernorConfig::default()
        };
        assert_eq!(
            cfg.validate(),
            Err(GovernorConfigError::Weight {
                class: "heavy",
                value: -1.0,
            })
        );
        assert!(Governor::new(cfg).is_err());

        let cfg = GovernorConfig {
            compute_weight: f64::NAN,
            ..GovernorConfig::default()
        };
        assert!(matches!(
            cfg.validate(),
            Err(GovernorConfigError::Weight {
                class: "compute",
                ..
            })
        ));
    }

    #[test]
    fn new_accepts_valid_default_config() {
        assert!(GovernorConfig::default().validate().is_ok());
        assert!(Governor::new(GovernorConfig::default()).is_ok());
    }

    // ----- idle-bucket pruning (virtual-refill recompute) -----

    #[test]
    fn idle_full_bucket_is_pruned_after_virtual_refill() {
        // max_tracked_ips=1: charging a second IP pushes the table over the
        // bound and triggers the retain prune. The first IP was drained to 0
        // at t0 (its STORED tokens stay 0), then sits idle past the cutoff.
        // The prune must virtually refill it to full and drop it — the old
        // stale-token predicate (0 < burst) would have kept it forever.
        let gov = Governor::new(GovernorConfig {
            refill_per_sec: 1.0,
            burst: 5.0,
            exempt_loopback: false,
            max_tracked_ips: 1,
            idle_prune_after: Duration::from_secs(10),
            ..GovernorConfig::default()
        })
        .expect("valid governor config");
        let t0 = Instant::now();
        // Drain ip(1) to zero stored tokens.
        assert!(allowed(gov.charge_at(ip(1), 5.0, t0)));
        // 20s later (> cutoff): charge a different IP to trip the prune.
        let t1 = t0 + Duration::from_secs(20);
        assert!(allowed(gov.charge_at(ip(2), 1.0, t1)));

        let map = gov.buckets.lock().expect("mutex");
        assert!(
            !map.contains_key(&ip(1)),
            "idle bucket that virtually refilled to full must be pruned"
        );
        assert!(map.contains_key(&ip(2)), "the just-charged IP is retained");
    }

    #[test]
    fn idle_but_not_yet_full_bucket_survives_prune() {
        // Idle past the cutoff but NOT virtually refilled to full ⇒ kept:
        // dropping it would refund the outstanding deficit.
        let gov = Governor::new(GovernorConfig {
            refill_per_sec: 0.01,
            burst: 100.0,
            exempt_loopback: false,
            max_tracked_ips: 1,
            idle_prune_after: Duration::from_secs(10),
            ..GovernorConfig::default()
        })
        .expect("valid governor config");
        let t0 = Instant::now();
        // Drain ip(1) to zero, then 20s later it refills only +0.2 tokens ⇒
        // far from full ⇒ must survive the prune.
        assert!(allowed(gov.charge_at(ip(1), 100.0, t0)));
        let t1 = t0 + Duration::from_secs(20);
        assert!(allowed(gov.charge_at(ip(2), 1.0, t1)));
        let map = gov.buckets.lock().expect("mutex");
        assert!(map.contains_key(&ip(1)), "non-full idle bucket is kept");
    }

    // ----- hard bound under active-peer flood (#168 review) -----

    #[test]
    fn active_peer_flood_stays_within_max_tracked_ips() {
        // Regression: the idle-only prune could not bound the table under a
        // flood of DISTINCT, ACTIVE peers (all idle < cutoff), so
        // `max_tracked_ips` was not a real cap — an unbounded-memory DoS. The
        // hard eviction pass must hold the map at/under the cap.
        let gov = Governor::new(GovernorConfig {
            refill_per_sec: 1.0,
            burst: 5.0,
            exempt_loopback: false,
            max_tracked_ips: 4,
            idle_prune_after: Duration::from_secs(600),
            ..GovernorConfig::default()
        })
        .expect("valid governor config");
        let t0 = Instant::now();
        // 50 distinct IPs, all charged at the same instant ⇒ all active, none
        // idle. Pre-fix this grew the table to 50; post-fix it stays ≤ 4.
        for n in 0..50u8 {
            let _ = gov.charge_at(ip(n), 1.0, t0);
        }
        let map = gov.buckets.lock().expect("mutex");
        assert!(
            map.len() <= 4,
            "active-peer flood must stay within max_tracked_ips=4, got {}",
            map.len()
        );
    }

    #[test]
    fn hard_eviction_sheds_the_least_throttled_bucket() {
        // Under memory pressure the evictor sheds the LEAST-throttled bucket: a
        // drained (throttled) IP keeps its penalty; a near-full IP is dropped
        // (recreated at `burst`, so ~no enforcement is lost). Both charged at
        // t0 (idle=0), so virtual tokens = stored tokens.
        let gov = Governor::new(GovernorConfig {
            refill_per_sec: 1.0,
            burst: 10.0,
            exempt_loopback: false,
            max_tracked_ips: 1,
            idle_prune_after: Duration::from_secs(600),
            ..GovernorConfig::default()
        })
        .expect("valid governor config");
        let t0 = Instant::now();
        // ip(1): drained to 0 (throttled). ip(2): fresh, near-full. Over cap=1
        // ⇒ the fuller ip(2) is evicted, the throttled ip(1) is kept.
        assert!(allowed(gov.charge_at(ip(1), 10.0, t0)));
        let _ = gov.charge_at(ip(2), 1.0, t0);
        let map = gov.buckets.lock().expect("mutex");
        assert!(map.contains_key(&ip(1)), "throttled bucket must survive");
        assert!(!map.contains_key(&ip(2)), "least-throttled bucket evicted");
        assert_eq!(map.len(), 1, "table held at the cap");
    }

    // ----- proxy loopback-trust withdrawal -----

    #[tokio::test]
    async fn loopback_behind_declared_proxy_is_not_exempt() {
        // With local_reverse_proxy=true the loopback socket is the proxy, so
        // the exemption is withdrawn and the (single-token) bucket throttles.
        let gov = Governor::new(GovernorConfig {
            refill_per_sec: 0.0001,
            burst: 1.0,
            exempt_loopback: true,
            local_reverse_proxy: true,
            ..GovernorConfig::default()
        })
        .expect("valid governor config");
        let loop_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let ok = app(&gov, RouteClass::CheapRead)
            .oneshot(req_from(loop_ip))
            .await
            .unwrap();
        assert_eq!(ok.status(), axum::http::StatusCode::OK);
        let throttled = app(&gov, RouteClass::CheapRead)
            .oneshot(req_from(loop_ip))
            .await
            .unwrap();
        assert_eq!(
            throttled.status(),
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "loopback must not be exempt when a reverse proxy is declared"
        );
    }
}
