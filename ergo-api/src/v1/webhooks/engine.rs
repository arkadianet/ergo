//! [`WebhookEngine`] — the durable-ish registry + delivery-log + retry/backoff
//! state machine (`v1-api-design.md` §4.1, fragment §3.2–§3.3).
//!
//! This is the load-bearing, **transport-free** core. It owns all state behind
//! one mutex and exposes pure, synchronous, clock-injected operations:
//! registry CRUD, [`enqueue_matches`](WebhookEngine::enqueue_matches) (called by
//! the worker for each bus event), [`take_due`](WebhookEngine::take_due) (the
//! scheduler: which signed requests are due now, respecting the per-webhook and
//! global in-flight caps), and [`record_result`](WebhookEngine::record_result)
//! (apply one attempt outcome — success resets the failure counter, failure
//! schedules an exponential-backoff retry or parks/auto-disables). Because the
//! clock and the transport are both injected, the entire at-least-once retry
//! discipline is unit-testable with **no network and no wall-clock**.
//!
//! **Persistence is DEFERRED.** State is in-memory and bounded; a node restart
//! loses all registrations and the delivery log. Durable-across-restart
//! registration needs a `*-db` schema (CLAUDE.md §2) and is intentionally NOT
//! invented here — see the PR report.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};

use serde_json::json;

use super::model::{
    sign_body, AutoDisabledReason, Delivery, DeliveryStatus, Subscription, WebhookHealth,
    SIGNATURE_PREFIX,
};
use crate::v1::realtime::RealtimeEvent;
use crate::v1::routes::dto::unix_ms_to_iso;

/// Max registered webhooks node-wide (§3.3 `MAX_WEBHOOKS_PER_KEY`; one operator
/// key → one global cap). Registration past it ⇒ `webhook_limit`.
pub const MAX_WEBHOOKS: usize = 100;
/// Max channels one webhook may subscribe (§3.3, mirrors WS `max_channels`).
pub const MAX_CHANNELS_PER_WEBHOOK: usize = 64;
/// Global bounded delivery-log ring (FIFO eviction) — the in-memory cap that
/// keeps a slow-to-drain or high-throughput hook from unbounded growth.
pub const DELIVERY_RING_CAP: usize = 4096;
/// First-retry base delay, ms (§3.3 `base=2s`).
pub const BASE_BACKOFF_MS: u64 = 2_000;
/// Backoff ceiling, ms (§3.3 `cap=1h`).
pub const MAX_BACKOFF_MS: u64 = 3_600_000;
/// Bounded attempts before a delivery is parked `failed` (§3.3 `max_attempts`).
pub const MAX_ATTEMPTS: u32 = 12;
/// Consecutive failed attempts before the subscription auto-disables (§3.3).
pub const MAX_CONSECUTIVE_FAILURES: u32 = 20;
/// Per-webhook concurrent in-flight sends (the delivery-rate cap — a slow
/// endpoint can hold at most this many attempts at once, never stalling others).
pub const MAX_INFLIGHT_PER_WEBHOOK: usize = 4;
/// Global concurrent in-flight sends across all webhooks (worker-pool bound).
pub const MAX_INFLIGHT_GLOBAL: usize = 64;
/// Random-secret length in bytes (hex-encoded into the `whsec_` value).
pub const SECRET_BYTES: usize = 32;

/// Deterministic exponential backoff for the `attempts`-th completed attempt
/// (§3.3): `BASE * 2^(attempts-1)`, saturating at `MAX_BACKOFF_MS`. Jitter is
/// applied on top by [`WebhookEngine`] from a per-delivery-id sample so retries
/// of distinct deliveries spread out; this base is kept pure for exact tests.
pub fn base_backoff_ms(attempts: u32) -> u64 {
    if attempts == 0 {
        return 0;
    }
    let shift = (attempts - 1).min(31);
    BASE_BACKOFF_MS
        .checked_shl(shift)
        .unwrap_or(MAX_BACKOFF_MS)
        .min(MAX_BACKOFF_MS)
}

/// Tunable engine knobs. `retry_jitter_frac` is the fraction of the base delay
/// added as deterministic per-delivery jitter (`0.0` = none, used by tests for
/// exact assertions).
#[derive(Debug, Clone)]
pub struct WebhookEngineConfig {
    /// Fraction of `base_backoff` added as jitter (clamped to `[0, 1]`).
    pub retry_jitter_frac: f64,
}

impl Default for WebhookEngineConfig {
    fn default() -> Self {
        WebhookEngineConfig {
            retry_jitter_frac: 0.2,
        }
    }
}

/// A signed, ready-to-POST request produced by [`WebhookEngine::take_due`]. The
/// transport ([`WebhookSink`](super::worker::WebhookSink)) is dumb: it POSTs
/// `body` to `url` with `headers` and reports the outcome back via
/// [`WebhookEngine::record_result`].
#[derive(Debug, Clone)]
pub struct PreparedRequest {
    /// The delivery this attempt belongs to (result key).
    pub delivery_id: String,
    /// Owning subscription (diagnostics / logging).
    pub webhook_id: String,
    /// Target URL.
    pub url: String,
    /// Request headers (`Content-Type` + the `X-Ergo-*` set, §3.4).
    pub headers: Vec<(&'static str, String)>,
    /// The JSON body (stable across retries of the same delivery).
    pub body: String,
}

/// The outcome of one [`PreparedRequest`] send, fed to
/// [`WebhookEngine::record_result`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// A 2xx status within the timeout — delivered.
    Success(u16),
    /// A non-2xx HTTP status — a failed attempt (retryable).
    HttpError(u16),
    /// Connect / TLS / timeout / no-response — a failed attempt (retryable).
    TransportError,
}

/// Why a registration was rejected (mapped to a §4 reason by the route layer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    /// The global webhook cap is reached.
    LimitReached,
    /// The webhook lists more channels than `MAX_CHANNELS_PER_WEBHOOK`.
    TooManyChannels,
}

struct Inner {
    subs: HashMap<String, Subscription>,
    /// Global bounded delivery log, oldest at front.
    deliveries: VecDeque<Delivery>,
    /// Dedupe set: at most one delivery per `(webhook_id, event_seq)`.
    dedupe: HashSet<(String, u64)>,
    /// Delivery ids currently being sent (removed on `record_result`).
    inflight: HashSet<String>,
    next_wh: u64,
    next_dl: u64,
    /// The bus pre-filter shared with the worker's subscription: the union of
    /// all active webhooks' channel keys. Kept in sync on every mutation so the
    /// worker is only woken for events some webhook wants (the cost governor).
    filter: Option<Arc<RwLock<HashSet<String>>>>,
}

/// The webhook subsystem's state + delivery state machine.
pub struct WebhookEngine {
    inner: Mutex<Inner>,
    config: WebhookEngineConfig,
}

impl WebhookEngine {
    /// A fresh engine with the given config.
    pub fn new(config: WebhookEngineConfig) -> Self {
        WebhookEngine {
            inner: Mutex::new(Inner {
                subs: HashMap::new(),
                deliveries: VecDeque::new(),
                dedupe: HashSet::new(),
                inflight: HashSet::new(),
                next_wh: 1,
                next_dl: 1,
                filter: None,
            }),
            config,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Attach the worker's bus pre-filter Arc and seed it with the current
    /// union. Called once when the worker starts; subsequent mutations write
    /// through it.
    pub fn attach_filter(&self, filter: Arc<RwLock<HashSet<String>>>) {
        let mut g = self.lock();
        rebuild_filter_into(&g.subs, &filter);
        g.filter = Some(filter);
    }

    /// Register a new subscription. `channels` are already parsed/validated +
    /// liveness-checked by the caller; `secret` is `Some` (generated or
    /// operator-supplied). Enforces the global cap and per-webhook channel cap.
    pub fn register(
        &self,
        url: String,
        channels: Vec<String>,
        secret: Option<String>,
        min_confirmations: u32,
        now_unix_ms: u64,
    ) -> Result<Subscription, RegisterError> {
        if channels.len() > MAX_CHANNELS_PER_WEBHOOK {
            return Err(RegisterError::TooManyChannels);
        }
        let mut g = self.lock();
        if g.subs.len() >= MAX_WEBHOOKS {
            return Err(RegisterError::LimitReached);
        }
        let id = format!("wh_{:016x}", g.next_wh);
        g.next_wh += 1;
        let sub = Subscription {
            webhook_id: id.clone(),
            url,
            channels,
            secret,
            active: true,
            min_confirmations,
            created_at_unix_ms: now_unix_ms,
            consecutive_failures: 0,
            health: WebhookHealth::Delivered,
            last_delivery_at_unix_ms: None,
            auto_disabled_reason: None,
        };
        g.subs.insert(id.clone(), sub.clone());
        Self::resync_filter(&g);
        Ok(sub)
    }

    /// Fetch one subscription by id.
    pub fn get(&self, webhook_id: &str) -> Option<Subscription> {
        self.lock().subs.get(webhook_id).cloned()
    }

    /// List subscriptions, newest-first (stable id order), offset-paginated.
    /// Returns `limit + 1` when more exist so the caller can set `has_more`.
    pub fn list(&self, offset: usize, limit_plus_one: usize) -> Vec<Subscription> {
        let g = self.lock();
        let mut all: Vec<Subscription> = g.subs.values().cloned().collect();
        // Stable, deterministic ordering: by creation counter embedded in the
        // id (newest first).
        all.sort_by(|a, b| b.webhook_id.cmp(&a.webhook_id));
        all.into_iter().skip(offset).take(limit_plus_one).collect()
    }

    /// Total registered subscriptions.
    pub fn count(&self) -> usize {
        self.lock().subs.len()
    }

    /// Deregister a subscription and drop its pending deliveries. Returns
    /// whether it existed.
    pub fn delete(&self, webhook_id: &str) -> bool {
        let mut g = self.lock();
        let existed = g.subs.remove(webhook_id).is_some();
        if existed {
            g.deliveries.retain(|d| d.webhook_id != webhook_id);
            g.dedupe.retain(|(w, _)| w != webhook_id);
            Self::resync_filter(&g);
        }
        existed
    }

    /// Pause / resume a subscription (PATCH). Resuming resets the failure
    /// counter + health so a re-enabled hook starts clean (§3.3). Returns the
    /// updated subscription, or `None` if unknown.
    pub fn set_active(&self, webhook_id: &str, active: bool) -> Option<Subscription> {
        let mut g = self.lock();
        let updated = {
            let sub = g.subs.get_mut(webhook_id)?;
            sub.active = active;
            if active {
                sub.consecutive_failures = 0;
                sub.health = WebhookHealth::Delivered;
                sub.auto_disabled_reason = None;
            }
            sub.clone()
        };
        Self::resync_filter(&g);
        Some(updated)
    }

    /// Recent deliveries for a webhook, newest-first, offset-paginated. Returns
    /// `limit + 1` for `has_more`.
    pub fn deliveries_for(
        &self,
        webhook_id: &str,
        offset: usize,
        limit_plus_one: usize,
    ) -> Vec<Delivery> {
        let g = self.lock();
        g.deliveries
            .iter()
            .rev() // newest first
            .filter(|d| d.webhook_id == webhook_id)
            .skip(offset)
            .take(limit_plus_one)
            .cloned()
            .collect()
    }

    /// For each active subscription matching `event`, enqueue exactly one new
    /// delivery (deduped on `(webhook_id, event_seq)`). Returns the number of
    /// deliveries enqueued. Called by the worker for every bus event.
    pub fn enqueue_matches(&self, event: &RealtimeEvent, now_unix_ms: u64) -> usize {
        let mut g = self.lock();
        // Snapshot the matching subs first (immutable borrow) to avoid holding
        // a mutable borrow of `subs` while mutating `deliveries`.
        let hits: Vec<(String, String)> = g
            .subs
            .values()
            .filter(|s| s.matches(&event.routes, event.confirmed))
            .map(|s| {
                let channel = matched_channel(s, &event.routes);
                (s.webhook_id.clone(), channel)
            })
            .collect();
        let mut enqueued = 0;
        for (webhook_id, channel) in hits {
            let key = (webhook_id.clone(), event.seq);
            if g.dedupe.contains(&key) {
                continue;
            }
            let delivery_id = format!("dl_{:016x}", g.next_dl);
            g.next_dl += 1;
            let body = render_body(&webhook_id, &delivery_id, &channel, event);
            let delivery = Delivery {
                delivery_id,
                webhook_id,
                event_seq: event.seq,
                channel,
                event_kind: event.event,
                body,
                event_unix_ms: event.emitted_at_unix_ms,
                status: DeliveryStatus::Pending,
                attempts: 0,
                last_attempt_at_unix_ms: None,
                response_code: None,
                next_retry_at_unix_ms: Some(now_unix_ms),
            };
            let inner = &mut *g;
            inner.dedupe.insert(key);
            push_bounded(&mut inner.deliveries, &mut inner.dedupe, delivery);
            enqueued += 1;
        }
        enqueued
    }

    /// The scheduler: collect deliveries that are due now (`next_retry_at <=
    /// now`, still open, owning sub active), respecting the per-webhook and
    /// global in-flight caps, mark them in-flight, count the attempt, and
    /// return the signed requests to POST. Never blocks; a saturated cap simply
    /// leaves work for the next tick.
    pub fn take_due(&self, now_unix_ms: u64) -> Vec<PreparedRequest> {
        let mut g = self.lock();
        if g.inflight.len() >= MAX_INFLIGHT_GLOBAL {
            return Vec::new();
        }
        // Per-webhook current in-flight tally.
        let mut per_wh: HashMap<String, usize> = HashMap::new();
        for id in &g.inflight {
            if let Some(d) = g.deliveries.iter().find(|d| &d.delivery_id == id) {
                *per_wh.entry(d.webhook_id.clone()).or_insert(0) += 1;
            }
        }

        // Pick due delivery ids in FIFO (fair) order without holding a borrow.
        let mut picks: Vec<String> = Vec::new();
        let mut global_room = MAX_INFLIGHT_GLOBAL - g.inflight.len();
        for d in g.deliveries.iter() {
            if global_room == 0 {
                break;
            }
            if !d.status.is_open() {
                continue;
            }
            if g.inflight.contains(&d.delivery_id) {
                continue;
            }
            match d.next_retry_at_unix_ms {
                Some(t) if t <= now_unix_ms => {}
                _ => continue,
            }
            // Owning sub must exist and be active.
            let active = g.subs.get(&d.webhook_id).map(|s| s.active).unwrap_or(false);
            if !active {
                continue;
            }
            let used = per_wh.get(&d.webhook_id).copied().unwrap_or(0);
            if used >= MAX_INFLIGHT_PER_WEBHOOK {
                continue;
            }
            *per_wh.entry(d.webhook_id.clone()).or_insert(0) += 1;
            picks.push(d.delivery_id.clone());
            global_room -= 1;
        }

        let mut out = Vec::with_capacity(picks.len());
        let inner = &mut *g;
        for id in picks {
            inner.inflight.insert(id.clone());
            // Build the request from a snapshot, then bump the attempt counter.
            let (webhook_id, url, secret, body, event_seq, attempt) = {
                let d = inner
                    .deliveries
                    .iter_mut()
                    .find(|d| d.delivery_id == id)
                    .expect("picked delivery exists");
                d.attempts += 1;
                d.status = DeliveryStatus::Retrying;
                let sub = g_subs_lookup(&inner.subs, &d.webhook_id);
                (
                    d.webhook_id.clone(),
                    sub.as_ref().map(|s| s.url.clone()).unwrap_or_default(),
                    sub.as_ref().and_then(|s| s.secret.clone()),
                    d.body.clone(),
                    d.event_seq,
                    d.attempts,
                )
            };
            let headers = build_headers(
                &webhook_id,
                &id,
                event_seq,
                now_unix_ms,
                attempt,
                secret.as_deref(),
                &body,
            );
            out.push(PreparedRequest {
                delivery_id: id,
                webhook_id,
                url,
                headers,
                body,
            });
        }
        out
    }

    /// Apply one attempt outcome to its delivery + the owning subscription's
    /// governor state (§3.3). Success clears the failure counter; a failure
    /// schedules an exponential-backoff retry, or parks `failed` at
    /// `MAX_ATTEMPTS`, and auto-disables the subscription at
    /// `MAX_CONSECUTIVE_FAILURES`.
    pub fn record_result(&self, delivery_id: &str, outcome: DeliveryOutcome, now_unix_ms: u64) {
        let mut g = self.lock();
        g.inflight.remove(delivery_id);

        let (webhook_id, attempts) = {
            let Some(d) = g
                .deliveries
                .iter_mut()
                .find(|d| d.delivery_id == delivery_id)
            else {
                return;
            };
            d.last_attempt_at_unix_ms = Some(now_unix_ms);
            match outcome {
                DeliveryOutcome::Success(code) => {
                    d.status = DeliveryStatus::Delivered;
                    d.response_code = Some(code);
                    d.next_retry_at_unix_ms = None;
                }
                DeliveryOutcome::HttpError(code) => {
                    d.response_code = Some(code);
                }
                DeliveryOutcome::TransportError => {
                    d.response_code = None;
                }
            }
            (d.webhook_id.clone(), d.attempts)
        };

        let jitter_frac = self.config.retry_jitter_frac.clamp(0.0, 1.0);
        let failed = !matches!(outcome, DeliveryOutcome::Success(_));

        if failed {
            let delay = base_backoff_ms(attempts);
            let jitter = jitter_for(delivery_id, delay, jitter_frac);
            let parked = attempts >= MAX_ATTEMPTS;
            if let Some(d) = g
                .deliveries
                .iter_mut()
                .find(|d| d.delivery_id == delivery_id)
            {
                if parked {
                    d.status = DeliveryStatus::Failed;
                    d.next_retry_at_unix_ms = None;
                } else {
                    d.status = DeliveryStatus::Retrying;
                    d.next_retry_at_unix_ms = Some(now_unix_ms.saturating_add(delay + jitter));
                }
            }
        }

        if let Some(sub) = g.subs.get_mut(&webhook_id) {
            sub.last_delivery_at_unix_ms = Some(now_unix_ms);
            if failed {
                sub.consecutive_failures = sub.consecutive_failures.saturating_add(1);
                if sub.health != WebhookHealth::Disabled {
                    sub.health = WebhookHealth::Failing;
                }
                if sub.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    sub.active = false;
                    sub.health = WebhookHealth::Disabled;
                    sub.auto_disabled_reason = Some(AutoDisabledReason::MaxConsecutiveFailures);
                }
            } else {
                sub.consecutive_failures = 0;
                sub.health = WebhookHealth::Delivered;
            }
        }
        Self::resync_filter(&g);
    }

    /// In-flight send count (diagnostics / tests).
    pub fn inflight_count(&self) -> usize {
        self.lock().inflight.len()
    }

    /// Total logged deliveries (diagnostics / tests).
    pub fn delivery_count(&self) -> usize {
        self.lock().deliveries.len()
    }

    fn resync_filter(g: &Inner) {
        if let Some(f) = g.filter.as_ref() {
            rebuild_filter_into(&g.subs, f);
        }
    }
}

fn g_subs_lookup<'a>(
    subs: &'a HashMap<String, Subscription>,
    webhook_id: &str,
) -> Option<&'a Subscription> {
    subs.get(webhook_id)
}

/// The channel key an event matched a subscription on (first intersecting
/// route, deterministic by the subscription's channel order).
fn matched_channel(sub: &Subscription, routes: &[String]) -> String {
    sub.channels
        .iter()
        .find(|c| routes.iter().any(|r| r == *c))
        .cloned()
        .unwrap_or_else(|| routes.first().cloned().unwrap_or_default())
}

/// Deterministic per-delivery jitter in `[0, frac * base]` derived from the
/// delivery id, so distinct deliveries retrying at the same attempt spread out
/// while a single delivery's schedule stays reproducible.
fn jitter_for(delivery_id: &str, base_delay_ms: u64, frac: f64) -> u64 {
    if frac <= 0.0 || base_delay_ms == 0 {
        return 0;
    }
    let span = ((base_delay_ms as f64) * frac) as u64;
    if span == 0 {
        return 0;
    }
    let h = fnv1a(delivery_id.as_bytes());
    h % (span + 1)
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Rebuild the shared bus pre-filter to the union of active subscriptions'
/// channel keys.
fn rebuild_filter_into(subs: &HashMap<String, Subscription>, filter: &RwLock<HashSet<String>>) {
    let mut union: HashSet<String> = HashSet::new();
    for s in subs.values() {
        if s.active {
            for c in &s.channels {
                union.insert(c.clone());
            }
        }
    }
    *filter.write().unwrap_or_else(|e| e.into_inner()) = union;
}

/// Push a delivery onto the bounded ring, evicting the oldest (and its dedupe
/// entry) when full.
fn push_bounded(
    deliveries: &mut VecDeque<Delivery>,
    dedupe: &mut HashSet<(String, u64)>,
    delivery: Delivery,
) {
    if deliveries.len() >= DELIVERY_RING_CAP {
        if let Some(old) = deliveries.pop_front() {
            dedupe.remove(&(old.webhook_id, old.event_seq));
        }
    }
    deliveries.push_back(delivery);
}

/// Render the delivery JSON body (§3.4). Stable across retries of the same
/// delivery; `data` reuses the event's v1 DTO verbatim.
fn render_body(
    webhook_id: &str,
    delivery_id: &str,
    channel: &str,
    event: &RealtimeEvent,
) -> String {
    let v = json!({
        "webhook_id": webhook_id,
        "delivery_id": delivery_id,
        "channel": channel,
        "event": event.event,
        "seq": event.seq,
        "unix_ms": event.emitted_at_unix_ms,
        "iso": unix_ms_to_iso(event.emitted_at_unix_ms),
        "confirmed": event.confirmed,
        "data": event.data,
    });
    serde_json::to_string(&v).unwrap_or_else(|_| "{}".to_string())
}

/// Build the outbound header set for one attempt (§3.4). Omits the signature
/// header when the subscription has no secret.
fn build_headers(
    webhook_id: &str,
    delivery_id: &str,
    event_seq: u64,
    timestamp_unix_ms: u64,
    attempt: u32,
    secret: Option<&str>,
    body: &str,
) -> Vec<(&'static str, String)> {
    let mut h = vec![
        ("Content-Type", "application/json".to_string()),
        ("X-Ergo-Webhook-Id", webhook_id.to_string()),
        ("X-Ergo-Delivery-Id", delivery_id.to_string()),
        ("X-Ergo-Event-Seq", event_seq.to_string()),
        ("X-Ergo-Timestamp", timestamp_unix_ms.to_string()),
        ("X-Ergo-Delivery-Attempt", attempt.to_string()),
    ];
    if let Some(sec) = secret {
        h.push(("X-Ergo-Signature", sign_body(sec, timestamp_unix_ms, body)));
    }
    let _ = SIGNATURE_PREFIX; // documented recipe constant (see model::sign_body)
    h
}

/// Generate a fresh signing secret (`whsec_` + hex of `SECRET_BYTES` random
/// bytes). Uses the `rand` workspace crate.
pub fn generate_secret() -> String {
    let mut bytes = [0u8; SECRET_BYTES];
    for b in bytes.iter_mut() {
        *b = rand::random();
    }
    format!("whsec_{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::realtime::RealtimeEvent;

    // ----- helpers -----

    fn engine_no_jitter() -> WebhookEngine {
        WebhookEngine::new(WebhookEngineConfig {
            retry_jitter_frac: 0.0,
        })
    }

    fn blocks_event(seq: u64, confirmed: bool) -> RealtimeEvent {
        RealtimeEvent {
            seq,
            emitted_at_unix_ms: 1_000 + seq,
            routes: vec!["blocks".to_string()],
            event: "block_applied",
            confirmed,
            height: Some(100),
            data: json!({"height": 100}),
            previous_seq: None,
        }
    }

    fn register_blocks(e: &WebhookEngine) -> Subscription {
        e.register(
            "https://dapp.example/hook".into(),
            vec!["blocks".to_string()],
            Some("whsec_test".into()),
            1,
            1_000,
        )
        .expect("register ok")
    }

    // ----- backoff (pure) -----

    #[test]
    fn base_backoff_is_exponential_and_capped() {
        assert_eq!(base_backoff_ms(0), 0);
        assert_eq!(base_backoff_ms(1), BASE_BACKOFF_MS);
        assert_eq!(base_backoff_ms(2), BASE_BACKOFF_MS * 2);
        assert_eq!(base_backoff_ms(3), BASE_BACKOFF_MS * 4);
        // Saturates at the cap for large attempt counts (never overflows).
        assert_eq!(base_backoff_ms(40), MAX_BACKOFF_MS);
        assert_eq!(base_backoff_ms(u32::MAX), MAX_BACKOFF_MS);
    }

    // ----- register / caps -----

    #[test]
    fn register_enforces_channel_cap() {
        let e = engine_no_jitter();
        let too_many: Vec<String> = (0..MAX_CHANNELS_PER_WEBHOOK + 1)
            .map(|i| format!("tx:{i:064}"))
            .collect();
        assert!(matches!(
            e.register("https://x/h".into(), too_many, Some("s".into()), 1, 0),
            Err(RegisterError::TooManyChannels)
        ));
    }

    #[test]
    fn register_enforces_global_cap() {
        let e = engine_no_jitter();
        for _ in 0..MAX_WEBHOOKS {
            e.register(
                "https://x/h".into(),
                vec!["blocks".into()],
                Some("s".into()),
                1,
                0,
            )
            .unwrap();
        }
        assert!(matches!(
            e.register(
                "https://x/h".into(),
                vec!["blocks".into()],
                Some("s".into()),
                1,
                0
            ),
            Err(RegisterError::LimitReached)
        ));
    }

    // ----- enqueue + dedupe -----

    #[test]
    fn enqueue_matches_creates_one_delivery_and_dedupes() {
        let e = engine_no_jitter();
        register_blocks(&e);
        let ev = blocks_event(7, true);
        assert_eq!(e.enqueue_matches(&ev, 2_000), 1);
        // Same event seq again → deduped (no second delivery).
        assert_eq!(e.enqueue_matches(&ev, 2_000), 0);
        assert_eq!(e.delivery_count(), 1);
    }

    #[test]
    fn enqueue_skips_nonmatching_and_confirmation_gated() {
        let e = engine_no_jitter();
        register_blocks(&e); // min_confirmations = 1
                             // Tentative (unconfirmed) event → gated out for a confirmed-only hook.
        assert_eq!(e.enqueue_matches(&blocks_event(1, false), 0), 0);
        // A mempool-channel event → no route intersection.
        let mut mp = blocks_event(2, true);
        mp.routes = vec!["mempool".into()];
        assert_eq!(e.enqueue_matches(&mp, 0), 0);
    }

    // ----- scheduler: take_due -----

    #[test]
    fn take_due_returns_signed_request_and_marks_inflight() {
        let e = engine_no_jitter();
        let sub = register_blocks(&e);
        e.enqueue_matches(&blocks_event(1, true), 2_000);
        let due = e.take_due(2_000);
        assert_eq!(due.len(), 1);
        let req = &due[0];
        assert_eq!(req.webhook_id, sub.webhook_id);
        assert_eq!(req.url, "https://dapp.example/hook");
        // Signature header present (secret set) + the id/seq/attempt headers.
        let names: Vec<&str> = req.headers.iter().map(|(k, _)| *k).collect();
        assert!(names.contains(&"X-Ergo-Signature"));
        assert!(names.contains(&"X-Ergo-Delivery-Id"));
        assert!(names.contains(&"X-Ergo-Event-Seq"));
        assert_eq!(e.inflight_count(), 1);
        // Not returned again while in-flight.
        assert!(e.take_due(2_000).is_empty());
    }

    #[test]
    fn take_due_respects_per_webhook_inflight_cap() {
        let e = engine_no_jitter();
        register_blocks(&e);
        for seq in 0..(MAX_INFLIGHT_PER_WEBHOOK as u64 + 3) {
            e.enqueue_matches(&blocks_event(seq, true), 0);
        }
        let due = e.take_due(0);
        assert_eq!(due.len(), MAX_INFLIGHT_PER_WEBHOOK);
        assert_eq!(e.inflight_count(), MAX_INFLIGHT_PER_WEBHOOK);
    }

    // ----- retry / backoff state machine -----

    #[test]
    fn failure_schedules_backoff_retry_then_recovers_on_success() {
        let e = engine_no_jitter();
        register_blocks(&e);
        e.enqueue_matches(&blocks_event(1, true), 0);
        let req = e.take_due(0).remove(0);
        // First attempt fails (500) → Retrying, next_retry = now + base.
        e.record_result(&req.delivery_id, DeliveryOutcome::HttpError(500), 10);
        let d = e.deliveries_for(&e.get_any_id(), 0, 10).remove(0);
        assert_eq!(d.status, DeliveryStatus::Retrying);
        assert_eq!(d.attempts, 1);
        assert_eq!(d.response_code, Some(500));
        assert_eq!(d.next_retry_at_unix_ms, Some(10 + BASE_BACKOFF_MS));
        // Not due before the backoff elapses.
        assert!(e.take_due(10 + BASE_BACKOFF_MS - 1).is_empty());
        // Due after; second attempt succeeds → Delivered, counter reset.
        let req2 = e.take_due(10 + BASE_BACKOFF_MS).remove(0);
        assert_eq!(req2.delivery_id, req.delivery_id, "stable delivery id");
        e.record_result(&req2.delivery_id, DeliveryOutcome::Success(200), 99);
        let d2 = e.deliveries_for(&e.get_any_id(), 0, 10).remove(0);
        assert_eq!(d2.status, DeliveryStatus::Delivered);
        assert_eq!(d2.attempts, 2);
        assert_eq!(d2.response_code, Some(200));
        assert_eq!(d2.next_retry_at_unix_ms, None);
    }

    #[test]
    fn delivery_parks_failed_at_max_attempts() {
        let e = engine_no_jitter();
        register_blocks(&e);
        e.enqueue_matches(&blocks_event(1, true), 0);
        let mut now = 0u64;
        let mut last_id = String::new();
        for _ in 0..MAX_ATTEMPTS {
            let due = e.take_due(now);
            assert_eq!(due.len(), 1, "one attempt due at now={now}");
            last_id = due[0].delivery_id.clone();
            e.record_result(&last_id, DeliveryOutcome::TransportError, now);
            now += MAX_BACKOFF_MS; // jump past any backoff
        }
        let d = e.deliveries_for(&e.get_any_id(), 0, 10).remove(0);
        assert_eq!(d.attempts, MAX_ATTEMPTS);
        assert_eq!(d.status, DeliveryStatus::Failed);
        assert_eq!(d.next_retry_at_unix_ms, None);
        assert!(!last_id.is_empty());
        // Parked: never due again.
        assert!(e.take_due(now + MAX_BACKOFF_MS).is_empty());
    }

    #[test]
    fn subscription_auto_disables_after_max_consecutive_failures() {
        let e = engine_no_jitter();
        let sub = register_blocks(&e);
        // Drive MAX_CONSECUTIVE_FAILURES failed attempts across enough
        // deliveries (each delivery caps at MAX_ATTEMPTS attempts).
        let mut now = 0u64;
        let mut seq = 0u64;
        let mut failures = 0u32;
        while failures < MAX_CONSECUTIVE_FAILURES {
            e.enqueue_matches(&blocks_event(seq, true), now);
            seq += 1;
            loop {
                let due = e.take_due(now);
                if due.is_empty() {
                    break;
                }
                for req in due {
                    e.record_result(&req.delivery_id, DeliveryOutcome::TransportError, now);
                    failures += 1;
                }
                now += MAX_BACKOFF_MS;
                if failures >= MAX_CONSECUTIVE_FAILURES {
                    break;
                }
            }
        }
        let s = e.get(&sub.webhook_id).unwrap();
        assert!(!s.active, "auto-disabled");
        assert_eq!(s.health, WebhookHealth::Disabled);
        assert_eq!(
            s.auto_disabled_reason,
            Some(AutoDisabledReason::MaxConsecutiveFailures)
        );
        // Disabled hook is not scheduled further.
        e.enqueue_matches(&blocks_event(9999, true), now);
        assert!(e.take_due(now).is_empty());
    }

    // ----- pause / resume + delete -----

    #[test]
    fn pause_stops_scheduling_resume_resets_and_reschedules() {
        let e = engine_no_jitter();
        let sub = register_blocks(&e);
        e.enqueue_matches(&blocks_event(1, true), 0);
        e.set_active(&sub.webhook_id, false);
        assert!(e.take_due(0).is_empty(), "paused → nothing due");
        let resumed = e.set_active(&sub.webhook_id, true).unwrap();
        assert!(resumed.active);
        assert_eq!(resumed.consecutive_failures, 0);
        assert_eq!(e.take_due(0).len(), 1, "resumed → due again");
    }

    #[test]
    fn delete_removes_sub_and_its_deliveries() {
        let e = engine_no_jitter();
        let sub = register_blocks(&e);
        e.enqueue_matches(&blocks_event(1, true), 0);
        assert!(e.delete(&sub.webhook_id));
        assert_eq!(e.count(), 0);
        assert_eq!(e.delivery_count(), 0);
        assert!(!e.delete(&sub.webhook_id), "second delete is a no-op");
    }

    // ----- jitter -----

    #[test]
    fn jitter_is_bounded_and_deterministic() {
        let base = 8_000u64;
        let a = jitter_for("dl_0000000000000001", base, 0.2);
        let b = jitter_for("dl_0000000000000001", base, 0.2);
        let c = jitter_for("dl_0000000000000002", base, 0.2);
        assert_eq!(a, b, "same id → same jitter");
        assert!(a <= (base as f64 * 0.2) as u64, "within the jitter span");
        // Different ids generally differ (not a hard guarantee, but these do).
        assert_ne!(a, c);
        assert_eq!(jitter_for("dl_x", base, 0.0), 0, "no jitter when frac=0");
    }

    // ----- secret generation -----

    #[test]
    fn generate_secret_has_prefix_and_length() {
        let s = generate_secret();
        assert!(s.starts_with("whsec_"));
        assert_eq!(s.len(), "whsec_".len() + SECRET_BYTES * 2);
        assert_ne!(s, generate_secret(), "secrets are random");
    }

    // ----- test-only helper -----

    impl WebhookEngine {
        fn get_any_id(&self) -> String {
            self.lock().subs.keys().next().cloned().unwrap_or_default()
        }
    }
}
