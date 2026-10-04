//! [`WebhookEngine`] — the durable registry + delivery-log + retry/backoff
//! state machine.
//!
//! This is the load-bearing, **transport-free** core. It owns all state behind
//! one mutex and exposes pure, synchronous, clock-injected operations:
//! registry CRUD, [`enqueue_matches`](WebhookEngine::enqueue_matches) (called by
//! the worker for each bus event), [`take_due`](WebhookEngine::take_due) (the
//! scheduler: which signed requests are due now, respecting the per-webhook and
//! global in-flight caps), and [`record_result`](WebhookEngine::record_result)
//! (apply one attempt outcome — success resets the failure counter, failure
//! schedules an exponential-backoff retry or parks/auto-disables). Because the
//! clock and the transport are both injected, the entire bounded retry
//! discipline is unit-testable with **no network and no wall-clock**.
//!
//! Production uses an atomically committed, versioned snapshot. Registry CRUD,
//! enqueue, attempt reservations and acknowledgements become durable before
//! callers receive success or a transport request. A storage failure rolls back
//! the mutation and stops management/delivery until restart.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::model::{
    sign_body, AutoDisabledReason, Delivery, DeliveryStatus, Subscription, WebhookHealth,
    SIGNATURE_PREFIX,
};
use crate::v1::realtime::RealtimeEvent;
use crate::v1::routes::dto::unix_ms_to_iso;

/// Max registered webhooks node-wide (one operator key → one global cap).
/// Registration past it ⇒ `webhook_limit`.
pub const MAX_WEBHOOKS: usize = 100;
/// Max channels one webhook may subscribe (mirrors WS `max_channels`).
pub const MAX_CHANNELS_PER_WEBHOOK: usize = 64;
/// Global bounded delivery-log ring (FIFO eviction) — the in-memory cap that
/// keeps a slow-to-drain or high-throughput hook from unbounded growth.
pub const DELIVERY_RING_CAP: usize = 4096;
/// First-retry base delay, ms.
pub const BASE_BACKOFF_MS: u64 = 2_000;
/// Backoff ceiling, ms.
pub const MAX_BACKOFF_MS: u64 = 3_600_000;
/// Bounded attempts before a delivery is parked `failed`.
pub const MAX_ATTEMPTS: u32 = 12;
/// Consecutive failed attempts before the subscription auto-disables.
pub const MAX_CONSECUTIVE_FAILURES: u32 = 20;
/// Per-webhook concurrent in-flight sends (the delivery-rate cap — a slow
/// endpoint can hold at most this many attempts at once, never stalling others).
pub const MAX_INFLIGHT_PER_WEBHOOK: usize = 4;
/// Global concurrent in-flight sends across all webhooks (worker-pool bound).
pub const MAX_INFLIGHT_GLOBAL: usize = 64;
/// Random-secret length in bytes (hex-encoded into the `whsec_` value).
pub const SECRET_BYTES: usize = 32;

/// Deterministic exponential backoff for the `attempts`-th completed attempt:
/// `BASE * 2^(attempts-1)`, saturating at `MAX_BACKOFF_MS`. Jitter is
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
    /// Request headers (`Content-Type` + the `X-Ergo-*` set).
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

/// Why a registration was rejected (mapped to a `Reason` by the route layer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    /// The global webhook cap is reached.
    LimitReached,
    /// The webhook lists more channels than `MAX_CHANNELS_PER_WEBHOOK`.
    TooManyChannels,
    /// Durable state could not be committed; no mutation was acknowledged.
    StorageUnavailable,
}

#[derive(Clone)]
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
    highest_seq: u64,
    replay_seq: u64,
    storage_failed: bool,
    /// The bus pre-filter shared with the worker's subscription: the union of
    /// all active webhooks' channel keys. Kept in sync on every mutation so the
    /// worker is only woken for events some webhook wants (the cost governor).
    filter: Option<Arc<RwLock<HashSet<String>>>>,
}

/// Opaque, atomically committed storage seam. Production supplies a private
/// redb-backed store; API tests can inject storage failures without filesystem IO.
pub trait WebhookStore: Send + Sync {
    /// The last committed versioned snapshot, or None for a fresh store.
    fn load(&self) -> Result<Option<Vec<u8>>, String>;
    /// Atomically replace the snapshot and make it durable before returning.
    fn commit(&self, snapshot: &[u8]) -> Result<(), String>;
}

#[derive(Serialize, Deserialize)]
struct StoredState {
    version: u32,
    subs: HashMap<String, Subscription>,
    deliveries: VecDeque<Delivery>,
    next_wh: u64,
    next_dl: u64,
    highest_seq: u64,
    #[serde(default)]
    replay_seq: Option<u64>,
}

impl StoredState {
    fn capture(inner: &Inner) -> Self {
        Self {
            version: 1,
            subs: inner.subs.clone(),
            deliveries: inner.deliveries.clone(),
            next_wh: inner.next_wh,
            next_dl: inner.next_dl,
            highest_seq: inner.highest_seq,
            replay_seq: Some(inner.replay_seq),
        }
    }
}

/// The webhook subsystem's state + delivery state machine.
pub struct WebhookEngine {
    inner: Mutex<Inner>,
    config: WebhookEngineConfig,
    store: Option<Arc<dyn WebhookStore>>,
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
                highest_seq: 0,
                replay_seq: 0,
                storage_failed: false,
                filter: None,
            }),
            config,
            store: None,
        }
    }

    /// Load persisted subscriptions and obligations. In-flight requests are
    /// retried with their original delivery IDs/bodies after restart; a remote
    /// acknowledgement lost during a crash can therefore produce a duplicate.
    pub fn durable(
        config: WebhookEngineConfig,
        store: Arc<dyn WebhookStore>,
    ) -> Result<Self, String> {
        let mut engine = Self::new(config);
        if let Some(bytes) = store.load()? {
            let saved: StoredState = serde_json::from_slice(&bytes)
                .map_err(|e| format!("invalid webhook snapshot: {e}"))?;
            if saved.version != 1
                || saved.subs.len() > MAX_WEBHOOKS
                || saved.deliveries.len() > DELIVERY_RING_CAP
                || saved.next_wh == 0
                || saved.next_wh == u64::MAX
                || saved.next_dl == 0
                || saved.next_dl == u64::MAX
                || saved.highest_seq >= u64::MAX - 1
                || saved.replay_seq.is_some_and(|seq| seq >= u64::MAX - 1)
            {
                return Err("unsupported or out-of-bounds webhook snapshot".into());
            }
            let inner = engine.inner.get_mut().unwrap_or_else(|e| e.into_inner());
            let valid_id = |id: &str, prefix: &str, next: u64| {
                id.strip_prefix(prefix)
                    .filter(|hex| hex.len() == 16)
                    .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                    .is_some_and(|number| number > 0 && number < next)
            };
            for (id, sub) in &saved.subs {
                if &sub.webhook_id != id
                    || sub.channels.len() > MAX_CHANNELS_PER_WEBHOOK
                    || !valid_id(id, "wh_", saved.next_wh)
                {
                    return Err("invalid webhook subscription snapshot".into());
                }
            }
            let mut delivery_ids = HashSet::new();
            for delivery in &saved.deliveries {
                if !valid_id(&delivery.delivery_id, "dl_", saved.next_dl)
                    || !delivery_ids.insert(&delivery.delivery_id)
                    || delivery.status.is_open() != delivery.next_retry_at_unix_ms.is_some()
                    || !saved.subs.contains_key(&delivery.webhook_id)
                    || delivery.event_seq > saved.highest_seq
                    || delivery.attempts > MAX_ATTEMPTS
                    || !inner
                        .dedupe
                        .insert((delivery.webhook_id.clone(), delivery.event_seq))
                {
                    return Err("invalid webhook delivery snapshot".into());
                }
            }
            inner.subs = saved.subs;
            inner.deliveries = saved.deliveries;
            inner.next_wh = saved.next_wh;
            inner.next_dl = saved.next_dl;
            inner.highest_seq = saved.highest_seq;
            inner.replay_seq = saved.replay_seq.unwrap_or(saved.highest_seq);
        }
        engine.store = Some(store);
        // Prove the store is writable before accepting any registrations.
        let snapshot = serde_json::to_vec(&StoredState::capture(
            engine.inner.get_mut().unwrap_or_else(|e| e.into_inner()),
        ))
        .map_err(|e| e.to_string())?;
        engine
            .store
            .as_ref()
            .expect("durable store installed")
            .commit(&snapshot)?;
        Ok(engine)
    }

    /// False after a durable write failure. Management routes and the scheduler
    /// fail closed until restart. RAM rolls back; a failed durable commit may
    /// leave either atomic snapshot on disk, so reconcile after reopening.
    pub fn is_available(&self) -> bool {
        !self.lock().storage_failed
    }

    pub(crate) fn fail_closed_after_panic(&self) {
        self.lock().storage_failed = true;
    }

    /// Highest cursor included in durable delivery state. Seed the realtime bus
    /// above this value at boot so a restart cannot alias a dedupe key.
    pub fn highest_event_seq(&self) -> u64 {
        self.lock().highest_seq
    }

    fn mutate<R>(&self, action: impl FnOnce(&mut Inner) -> R) -> Result<R, String> {
        let mut inner = self.lock();
        if inner.storage_failed {
            return Err("webhook store is unavailable".into());
        }
        let previous = self.store.as_ref().map(|_| inner.clone());
        let result = action(&mut inner);
        if let Some(store) = &self.store {
            if previous.as_ref().is_some_and(|before| {
                before.subs == inner.subs
                    && before.deliveries == inner.deliveries
                    && before.next_wh == inner.next_wh
                    && before.next_dl == inner.next_dl
                    && before.highest_seq == inner.highest_seq
                    && before.replay_seq == inner.replay_seq
            }) {
                return Ok(result);
            }
            let saved = serde_json::to_vec(&StoredState::capture(&inner))
                .map_err(|e| e.to_string())
                .and_then(|bytes| store.commit(&bytes));
            if let Err(error) = saved {
                *inner = previous.expect("durable mutations snapshot their previous state");
                inner.storage_failed = true;
                Self::resync_filter(&inner);
                tracing::error!(%error, "webhook persistence failed; delivery and management disabled until restart");
                return Err(error);
            }
        }
        Ok(result)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Cursor through which source observations have been admitted or skipped.
    pub fn replay_seq(&self) -> u64 {
        self.lock().replay_seq
    }

    pub(crate) fn earliest_active_start(&self) -> Option<u64> {
        self.lock()
            .subs
            .values()
            .filter(|sub| sub.active)
            .map(|sub| sub.start_seq)
            .min()
    }

    /// Save a catch-up boundary only after every matching event was admitted.
    pub fn checkpoint_replay(&self, seq: u64) {
        let _ = self.mutate(|g| {
            g.replay_seq = g.replay_seq.max(seq);
        });
    }

    /// Do not silently continue after losing source history. Open obligations
    /// stay retained; subscriptions visibly pause until the operator reconciles
    /// from REST and explicitly re-enables them.
    pub fn record_source_gap(&self, latest_seq: u64) {
        let _ = self.mutate(|g| {
            for sub in g.subs.values_mut().filter(|sub| sub.active) {
                sub.active = false;
                sub.health = WebhookHealth::Disabled;
                sub.auto_disabled_reason = Some(AutoDisabledReason::SourceGap);
            }
            g.replay_seq = g.replay_seq.max(latest_seq);
            Self::resync_filter(g);
        });
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
        self.register_after(url, channels, secret, min_confirmations, now_unix_ms, 0)
    }

    /// Production registration boundary from the bus, persisted with the key.
    pub fn register_after(
        &self,
        url: String,
        channels: Vec<String>,
        secret: Option<String>,
        min_confirmations: u32,
        now_unix_ms: u64,
        start_seq: u64,
    ) -> Result<Subscription, RegisterError> {
        if channels.len() > MAX_CHANNELS_PER_WEBHOOK {
            return Err(RegisterError::TooManyChannels);
        }
        self.mutate(|g| {
            if g.subs.len() >= MAX_WEBHOOKS {
                return Err(RegisterError::LimitReached);
            }
            let Some(next_wh) = g.next_wh.checked_add(1).filter(|next| *next != u64::MAX) else {
                return Err(RegisterError::LimitReached);
            };
            let id = format!("wh_{:016x}", g.next_wh);
            g.next_wh = next_wh;
            let sub = Subscription {
                webhook_id: id.clone(),
                url,
                channels,
                secret,
                active: true,
                min_confirmations,
                created_at_unix_ms: now_unix_ms,
                start_seq,
                consecutive_failures: 0,
                health: WebhookHealth::Delivered,
                last_delivery_at_unix_ms: None,
                auto_disabled_reason: None,
            };
            g.subs.insert(id.clone(), sub.clone());
            Self::resync_filter(g);
            Ok(sub)
        })
        .map_err(|_| RegisterError::StorageUnavailable)?
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
        self.mutate(|g| {
            let existed = g.subs.remove(webhook_id).is_some();
            if existed {
                g.deliveries.retain(|d| d.webhook_id != webhook_id);
                g.dedupe.retain(|(w, _)| w != webhook_id);
                Self::resync_filter(g);
            }
            existed
        })
        .unwrap_or(false)
    }

    /// Pause / resume a subscription (PATCH). Resuming resets the failure
    /// counter + health so a re-enabled hook starts clean. Returns the
    /// updated subscription, or `None` if unknown.
    pub fn set_active(&self, webhook_id: &str, active: bool) -> Option<Subscription> {
        self.mutate(|g| {
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
            Self::resync_filter(g);
            Some(updated)
        })
        .ok()
        .flatten()
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
        self.admit_matches_inner(event, now_unix_ms, false).0
    }

    /// Returns (new deliveries, complete). A full open-obligation ring leaves
    /// the cursor before this event, so catch-up retries it after room returns.
    pub(crate) fn admit_matches(&self, event: &RealtimeEvent, now_unix_ms: u64) -> (usize, bool) {
        self.admit_matches_inner(event, now_unix_ms, true)
    }

    fn admit_matches_inner(
        &self,
        event: &RealtimeEvent,
        now_unix_ms: u64,
        checkpoint: bool,
    ) -> (usize, bool) {
        self.mutate(|g| {
            if event.seq >= u64::MAX - 1 {
                return (0, false);
            }
            // Snapshot the matching subs first (immutable borrow) to avoid holding
            // a mutable borrow of `subs` while mutating `deliveries`.
            let hits: Vec<(String, String)> = g
                .subs
                .values()
                .filter(|s| {
                    event.seq > s.start_seq
                        && s.matches(
                            &event.routes,
                            event.confirmed
                                || matches!(
                                    event.event,
                                    "box_reverted" | "box_unspent" | "token_reverted"
                                ),
                        )
                })
                .map(|s| {
                    let channel = matched_channel(s, &event.routes);
                    (s.webhook_id.clone(), channel)
                })
                .collect();
            let mut enqueued = 0;
            let mut complete = true;
            for (webhook_id, channel) in hits {
                let key = (webhook_id.clone(), event.seq);
                if g.dedupe.contains(&key) {
                    continue;
                }
                let Some(next_dl) = g.next_dl.checked_add(1).filter(|next| *next != u64::MAX)
                else {
                    complete = false;
                    continue;
                };
                let delivery_id = format!("dl_{:016x}", g.next_dl);
                let body = render_body(&webhook_id, &delivery_id, &channel, event);
                let delivery = Delivery {
                    delivery_id,
                    webhook_id,
                    event_seq: event.seq,
                    channel,
                    event_kind: event.event.into(),
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
                if push_bounded(&mut inner.deliveries, &mut inner.dedupe, delivery) {
                    inner.next_dl = next_dl;
                    enqueued += 1;
                } else {
                    complete = false;
                }
            }
            if enqueued > 0 {
                g.highest_seq = g.highest_seq.max(event.seq);
            }
            if complete && checkpoint {
                g.replay_seq = g.replay_seq.max(event.seq);
            }
            (enqueued, complete)
        })
        .unwrap_or((0, false))
    }

    /// The scheduler: collect deliveries that are due now (`next_retry_at <=
    /// now`, still open, owning sub active), respecting the per-webhook and
    /// global in-flight caps, mark them in-flight, count the attempt, and
    /// return the signed requests to POST. A saturated cap leaves work for the
    /// next tick. Durable engines synchronously commit their reservation;
    /// production calls this through the blocking executor.
    pub fn take_due(&self, now_unix_ms: u64) -> Vec<PreparedRequest> {
        self.take_due_bounded(now_unix_ms, MAX_INFLIGHT_GLOBAL)
    }

    pub(crate) fn take_due_bounded(
        &self,
        now_unix_ms: u64,
        max_requests: usize,
    ) -> Vec<PreparedRequest> {
        self.mutate(|g| {
            // A crash after the final committed reservation still consumes
            // that attempt. Park the unknown outcome instead of exceeding
            // the same outbound budget on every restart.
            for delivery in &mut g.deliveries {
                if delivery.status.is_open()
                    && delivery.attempts >= MAX_ATTEMPTS
                    && !g.inflight.contains(&delivery.delivery_id)
                {
                    delivery.status = DeliveryStatus::Failed;
                    delivery.next_retry_at_unix_ms = None;
                }
            }
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
            let mut global_room = (MAX_INFLIGHT_GLOBAL - g.inflight.len()).min(max_requests);
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
        })
        .unwrap_or_default()
    }

    /// Apply one attempt outcome to its delivery + the owning subscription's
    /// governor state. Success clears the failure counter; a failure
    /// schedules an exponential-backoff retry, or parks `failed` at
    /// `MAX_ATTEMPTS`, and auto-disables the subscription at
    /// `MAX_CONSECUTIVE_FAILURES`.
    pub fn record_result(&self, delivery_id: &str, outcome: DeliveryOutcome, now_unix_ms: u64) {
        let _ = self.mutate(|g| {
            if !g.inflight.remove(delivery_id) {
                return;
            }

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
            Self::resync_filter(g);
        });
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

/// Push a delivery onto the bounded ring. When full, evict the oldest
/// TERMINAL (delivered/failed) entry — an open (pending/retrying) delivery is
/// an unsent obligation and must not be dropped to make room. If every entry
/// is still open (a saturated backlog), the NEW delivery is dropped instead:
/// its dedupe entry is removed so a later event burst can re-enqueue it once
/// the ring drains.
fn push_bounded(
    deliveries: &mut VecDeque<Delivery>,
    dedupe: &mut HashSet<(String, u64)>,
    delivery: Delivery,
) -> bool {
    if deliveries.len() >= DELIVERY_RING_CAP {
        match deliveries.iter().position(|d| !d.status.is_open()) {
            Some(i) => {
                if let Some(old) = deliveries.remove(i) {
                    dedupe.remove(&(old.webhook_id, old.event_seq));
                }
            }
            None => {
                // Ring saturated with unsent work — reject the newcomer
                // rather than silently dropping an open delivery.
                dedupe.remove(&(delivery.webhook_id, delivery.event_seq));
                return false;
            }
        }
    }
    deliveries.push_back(delivery);
    true
}

/// Render the delivery JSON body. Stable across retries of the same
/// delivery; `data` reuses the event's v1 DTO verbatim.
fn render_body(
    webhook_id: &str,
    delivery_id: &str,
    channel: &str,
    event: &RealtimeEvent,
) -> String {
    let mut v = json!({
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
    if let Some(previous_seq) = event.previous_seq {
        v["previous_seq"] = json!(previous_seq);
    }
    if let Some(height) = event.height {
        v["height"] = json!(height);
    }
    serde_json::to_string(&v).unwrap_or_else(|_| "{}".to_string())
}

/// Build the outbound header set for one attempt. Omits the signature
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

    #[derive(Default)]
    struct MemoryStore {
        snapshot: Mutex<Option<Vec<u8>>>,
        fail: std::sync::atomic::AtomicBool,
        commits: std::sync::atomic::AtomicUsize,
    }
    impl WebhookStore for MemoryStore {
        fn load(&self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.snapshot.lock().unwrap().clone())
        }
        fn commit(&self, snapshot: &[u8]) -> Result<(), String> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err("injected IO failure".into());
            }
            *self.snapshot.lock().unwrap() = Some(snapshot.to_vec());
            self.commits
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }
    fn durable(store: Arc<MemoryStore>) -> WebhookEngine {
        WebhookEngine::durable(
            WebhookEngineConfig {
                retry_jitter_frac: 0.0,
            },
            store,
        )
        .unwrap()
    }

    #[test]
    fn confirmed_only_hooks_receive_reorg_inverses_with_original_cursor() {
        let engine = WebhookEngine::new(Default::default());
        let subscription = engine
            .register(
                "https://receiver.example/hook".into(),
                vec!["address:owner".into()],
                None,
                1,
                0,
            )
            .unwrap();
        let mut event = blocks_event(1, true);
        event.routes = vec!["address:owner".into()];
        event.event = "box_created";
        assert_eq!(engine.enqueue_matches(&event, 0), 1);
        event.seq = 2;
        event.confirmed = false;
        event.event = "box_reverted";
        event.previous_seq = Some(1);
        assert_eq!(engine.enqueue_matches(&event, 0), 1);
        let delivery = engine
            .deliveries_for(&subscription.webhook_id, 0, 1)
            .remove(0);
        let body: serde_json::Value = serde_json::from_str(&delivery.body).unwrap();
        assert_eq!(body["previous_seq"], 1);
        assert_eq!(body["confirmed"], false);
        assert_eq!(body["height"], 100);
        event.seq = 3;
        event.event = "tx_accepted";
        assert_eq!(engine.enqueue_matches(&event, 0), 0);
    }

    #[test]
    fn restart_preserves_registration_boundary_checkpoint_and_source_gap_pause() {
        let store = Arc::new(MemoryStore::default());
        let engine = durable(store.clone());
        let sub = engine
            .register_after(
                "https://receiver.example/hook".into(),
                vec!["blocks".into()],
                None,
                1,
                0,
                20,
            )
            .unwrap();
        assert_eq!(engine.enqueue_matches(&blocks_event(19, true), 0), 0);
        assert_eq!(engine.enqueue_matches(&blocks_event(21, true), 0), 1);
        engine.checkpoint_replay(25);
        drop(engine);
        let engine = durable(store.clone());
        assert_eq!(engine.replay_seq(), 25);
        assert_eq!(engine.get(&sub.webhook_id).unwrap().start_seq, 20);
        engine.record_source_gap(50);
        drop(engine);
        let engine = durable(store);
        assert_eq!(engine.replay_seq(), 50);
        assert_eq!(
            engine.get(&sub.webhook_id).unwrap().auto_disabled_reason,
            Some(AutoDisabledReason::SourceGap)
        );
        assert_eq!(engine.deliveries_for(&sub.webhook_id, 0, 10).len(), 1);
    }

    #[test]
    fn failed_replay_checkpoint_does_not_advance_acknowledged_source_state() {
        let store = Arc::new(MemoryStore::default());
        let engine = durable(store.clone());
        engine.checkpoint_replay(7);
        store.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        engine.checkpoint_replay(8);
        assert!(!engine.is_available());
        assert_eq!(engine.replay_seq(), 7);
        drop(engine);
        store.fail.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(durable(store).replay_seq(), 7);
    }

    // ----- round-trips -----

    #[test]
    fn durable_inflight_restart_retries_same_id_and_ignores_duplicate_ack() {
        let store = Arc::new(MemoryStore::default());
        let engine = durable(store.clone());
        let subscription = register_blocks(&engine);
        engine.enqueue_matches(&blocks_event(17, true), 0);
        let first = engine.take_due(0).remove(0);
        drop(engine); // crash with request outcome unknown
        let recovered = durable(store.clone());
        assert_eq!(
            recovered
                .get(&subscription.webhook_id)
                .unwrap()
                .secret
                .as_deref(),
            Some("whsec_test")
        );
        assert_eq!(recovered.enqueue_matches(&blocks_event(17, true), 0), 0);
        let retry = recovered.take_due(0).remove(0);
        assert_eq!(retry.delivery_id, first.delivery_id);
        assert_eq!(retry.body, first.body);
        recovered.record_result(&retry.delivery_id, DeliveryOutcome::Success(204), 10);
        recovered.record_result(&retry.delivery_id, DeliveryOutcome::HttpError(500), 11);
        drop(recovered);
        let recovered = durable(store);
        assert!(recovered.take_due(u64::MAX).is_empty());
        assert_eq!(
            recovered.deliveries_for(&subscription.webhook_id, 0, 1)[0].status,
            DeliveryStatus::Delivered
        );
        assert_eq!(
            recovered
                .get(&subscription.webhook_id)
                .unwrap()
                .consecutive_failures,
            0
        );
    }

    #[test]
    fn durable_unknown_final_attempt_does_not_exceed_retry_budget() {
        let store = Arc::new(MemoryStore::default());
        let engine = durable(store.clone());
        let subscription = register_blocks(&engine);
        engine.enqueue_matches(&blocks_event(1, true), 0);
        for attempt in 1..MAX_ATTEMPTS {
            let request = engine.take_due(u64::MAX).remove(0);
            engine.record_result(&request.delivery_id, DeliveryOutcome::HttpError(503), 0);
            assert_eq!(
                engine.deliveries_for(&subscription.webhook_id, 0, 1)[0].attempts,
                attempt
            );
            // Keep this subscription active while testing the per-delivery cap.
            engine.set_active(&subscription.webhook_id, true).unwrap();
        }
        let final_attempt = engine.take_due(u64::MAX).remove(0);
        assert_eq!(final_attempt.delivery_id, "dl_0000000000000001");
        drop(engine);
        let recovered = durable(store.clone());
        assert!(recovered.take_due(u64::MAX).is_empty());
        assert_eq!(
            recovered.deliveries_for(&subscription.webhook_id, 0, 1)[0].status,
            DeliveryStatus::Failed
        );
        drop(recovered);
        assert!(durable(store).take_due(u64::MAX).is_empty());
    }

    #[test]
    fn durable_pause_delete_and_counters_survive_restart() {
        let store = Arc::new(MemoryStore::default());
        let engine = durable(store.clone());
        let first = register_blocks(&engine);
        engine.enqueue_matches(&blocks_event(9, true), 0);
        engine.set_active(&first.webhook_id, false).unwrap();
        drop(engine);
        let engine = durable(store.clone());
        assert!(engine.take_due(0).is_empty());
        engine.set_active(&first.webhook_id, true).unwrap();
        let pending = engine.take_due(0).remove(0);
        assert_eq!(pending.delivery_id, "dl_0000000000000001");
        assert!(engine.delete(&first.webhook_id));
        drop(engine);
        let engine = durable(store);
        assert_eq!(engine.count(), 0);
        assert_eq!(engine.delivery_count(), 0);
        assert_eq!(engine.highest_event_seq(), 9);
        let second = register_blocks(&engine);
        assert_eq!(second.webhook_id, "wh_0000000000000002");
        engine.enqueue_matches(&blocks_event(10, true), 0);
        assert_eq!(engine.take_due(0)[0].delivery_id, "dl_0000000000000002");
    }

    // ----- error paths -----

    #[test]
    fn durable_failed_registration_not_acknowledged_or_visible_after_restart() {
        let store = Arc::new(MemoryStore::default());
        let engine = durable(store.clone());
        store.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            engine.register(
                "https://example.com/hook".into(),
                vec!["blocks".into()],
                None,
                0,
                0
            ),
            Err(RegisterError::StorageUnavailable)
        ));
        assert!(!engine.is_available());
        assert_eq!(engine.count(), 0);
        assert!(engine.take_due(u64::MAX).is_empty());
        drop(engine);
        store.fail.store(false, std::sync::atomic::Ordering::SeqCst);
        let recovered = durable(store);
        assert_eq!(
            register_blocks(&recovered).webhook_id,
            "wh_0000000000000001"
        );
    }

    #[test]
    fn durable_failed_acknowledgement_retries_last_committed_obligation() {
        let store = Arc::new(MemoryStore::default());
        let engine = durable(store.clone());
        let subscription = register_blocks(&engine);
        engine.enqueue_matches(&blocks_event(1, true), 0);
        let first = engine.take_due(0).remove(0);
        store.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        engine.record_result(&first.delivery_id, DeliveryOutcome::Success(204), 1);
        assert!(!engine.is_available());
        assert_eq!(
            engine.deliveries_for(&subscription.webhook_id, 0, 1)[0].status,
            DeliveryStatus::Retrying
        );
        drop(engine);
        store.fail.store(false, std::sync::atomic::Ordering::SeqCst);
        let recovered = durable(store);
        let retried = recovered.take_due(1).remove(0);
        assert_eq!(retried.delivery_id, first.delivery_id);
        assert_eq!(retried.body, first.body);
    }

    #[test]
    fn durable_invalid_snapshot_counters_and_retry_bounds_fail_closed() {
        let source = Arc::new(MemoryStore::default());
        let engine = durable(source.clone());
        register_blocks(&engine);
        engine.enqueue_matches(&blocks_event(1, true), 0);
        let snapshot: serde_json::Value =
            serde_json::from_slice(&source.load().unwrap().unwrap()).unwrap();
        for field in [
            "version",
            "next_wh",
            "next_dl",
            "highest_seq",
            "attempts",
            "exhausted_wh",
            "exhausted_dl",
            "exhausted_seq",
        ] {
            let mut corrupt = snapshot.clone();
            match field {
                "version" => corrupt[field] = json!(2),
                "next_wh" | "next_dl" => corrupt[field] = json!(1),
                "highest_seq" => corrupt[field] = json!(0),
                "attempts" => corrupt["deliveries"][0][field] = json!(MAX_ATTEMPTS + 1),
                "exhausted_wh" => corrupt["next_wh"] = json!(u64::MAX),
                "exhausted_dl" => corrupt["next_dl"] = json!(u64::MAX),
                "exhausted_seq" => corrupt["highest_seq"] = json!(u64::MAX - 1),
                _ => unreachable!(),
            }
            let store = Arc::new(MemoryStore::default());
            store
                .commit(&serde_json::to_vec(&corrupt).unwrap())
                .unwrap();
            assert!(
                WebhookEngine::durable(Default::default(), store).is_err(),
                "accepted corrupt {field}"
            );
        }
    }

    #[test]
    fn durable_failed_attempt_reservation_never_reaches_transport() {
        let store = Arc::new(MemoryStore::default());
        let engine = durable(store.clone());
        register_blocks(&engine);
        engine.enqueue_matches(&blocks_event(1, true), 0);
        store.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(engine.take_due(0).is_empty());
        assert!(!engine.is_available());
        drop(engine);
        store.fail.store(false, std::sync::atomic::Ordering::SeqCst);
        let recovered = durable(store);
        assert_eq!(
            recovered.take_due(0)[0]
                .headers
                .iter()
                .find(|(key, _)| *key == "X-Ergo-Delivery-Attempt")
                .unwrap()
                .1,
            "1"
        );
    }

    #[test]
    fn durable_bounded_backlog_preserves_pending_obligations_after_restart() {
        let store = Arc::new(MemoryStore::default());
        let engine = durable(store.clone());
        let subscription = register_blocks(&engine);
        // Fill through the same bounded admission helper in one durable commit.
        engine
            .mutate(|inner| {
                for seq in 1..=DELIVERY_RING_CAP as u64 {
                    let event = blocks_event(seq, true);
                    let id = format!("dl_{seq:016x}");
                    inner.dedupe.insert((subscription.webhook_id.clone(), seq));
                    push_bounded(
                        &mut inner.deliveries,
                        &mut inner.dedupe,
                        Delivery {
                            delivery_id: id.clone(),
                            webhook_id: subscription.webhook_id.clone(),
                            event_seq: seq,
                            channel: "blocks".into(),
                            event_kind: "block_applied".into(),
                            body: render_body(&subscription.webhook_id, &id, "blocks", &event),
                            event_unix_ms: event.emitted_at_unix_ms,
                            status: DeliveryStatus::Pending,
                            attempts: 0,
                            last_attempt_at_unix_ms: None,
                            response_code: None,
                            next_retry_at_unix_ms: Some(0),
                        },
                    );
                }
                inner.next_dl = DELIVERY_RING_CAP as u64 + 1;
                inner.highest_seq = DELIVERY_RING_CAP as u64;
            })
            .unwrap();
        let before_rejection = store.load().unwrap();
        let before_commits = store.commits.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            engine.enqueue_matches(&blocks_event(DELIVERY_RING_CAP as u64 + 1, true), 0),
            0
        );
        assert_eq!(engine.highest_event_seq(), DELIVERY_RING_CAP as u64);
        assert_eq!(store.load().unwrap(), before_rejection);
        assert_eq!(
            store.commits.load(std::sync::atomic::Ordering::SeqCst),
            before_commits
        );
        drop(engine);
        let recovered = durable(store.clone());
        assert_eq!(recovered.delivery_count(), DELIVERY_RING_CAP);
        let requests = recovered.take_due(0);
        assert_eq!(requests[0].delivery_id, "dl_0000000000000001");
        recovered.record_result(&requests[0].delivery_id, DeliveryOutcome::Success(200), 1);
        assert_eq!(
            recovered.enqueue_matches(&blocks_event(DELIVERY_RING_CAP as u64 + 2, true), 1),
            1
        );
        assert_eq!(recovered.delivery_count(), DELIVERY_RING_CAP);
        let before_idle = store.commits.load(std::sync::atomic::Ordering::SeqCst);
        recovered.take_due(0); // only pending requests fill remaining per-hook slots
        recovered.take_due(0); // no mutation once cap is reached
        assert!(store.commits.load(std::sync::atomic::Ordering::SeqCst) <= before_idle + 1);
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
    fn durable_unadmitted_events_leave_cursor_and_snapshot_unchanged() {
        let store = Arc::new(MemoryStore::default());
        let engine = durable(store.clone());
        let assert_unadmitted = |event: &RealtimeEvent| {
            let before_snapshot = store.load().unwrap();
            let before_cursor = engine.highest_event_seq();
            let before_commits = store.commits.load(std::sync::atomic::Ordering::SeqCst);
            assert_eq!(engine.enqueue_matches(event, 0), 0);
            assert_eq!(engine.highest_event_seq(), before_cursor);
            assert_eq!(store.load().unwrap(), before_snapshot);
            assert_eq!(
                store.commits.load(std::sync::atomic::Ordering::SeqCst),
                before_commits
            );
        };

        assert_unadmitted(&blocks_event(10, true)); // No registrations.
        let subscription = register_blocks(&engine);
        assert_unadmitted(&blocks_event(11, false)); // Confirmation gate.
        let mut nonmatching = blocks_event(12, true);
        nonmatching.routes = vec!["mempool".into()];
        assert_unadmitted(&nonmatching);
        engine.set_active(&subscription.webhook_id, false).unwrap();
        assert_unadmitted(&blocks_event(13, true)); // Paused registration.
        engine.set_active(&subscription.webhook_id, true).unwrap();

        let before_commits = store.commits.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(engine.enqueue_matches(&blocks_event(20, true), 0), 1);
        assert_eq!(engine.highest_event_seq(), 20);
        assert_eq!(
            store.commits.load(std::sync::atomic::Ordering::SeqCst),
            before_commits + 1
        );
        assert_unadmitted(&blocks_event(20, true)); // Duplicate delivery.
        assert_eq!(engine.enqueue_matches(&blocks_event(19, true), 0), 1);
        assert_eq!(engine.highest_event_seq(), 20); // Never move backwards.

        engine.mutate(|inner| inner.next_dl = u64::MAX - 1).unwrap();
        assert_unadmitted(&blocks_event(21, true)); // Exhausted delivery IDs.
    }

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
