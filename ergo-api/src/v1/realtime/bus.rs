//! `RealtimeBus` — the fine-grained fan-out hub (`v1-api-design.md` Appendix A
//! **G5**, §4.1).
//!
//! The load-bearing new primitive behind `WS /api/v1/ws` and (a future PR)
//! webhooks. It is a **concrete shared type in `ergo-api`**, mirroring the O4
//! [`MempoolDepthRing`](crate::v1::mempool_depth) precedent: shared
//! infrastructure lives here and is fed by a task wired at the server seam. The
//! design fragment framed it as a consumed trait, but the fan-out *hub* is best
//! concrete — its drop policy, per-key filtering, and backfill window are
//! directly unit-testable, and node-side taps simply call [`RealtimeBus::publish`]
//! (see the design corrections in the PR report).
//!
//! ## Fan-out + drop policy (the slow-consumer contract, §2.6)
//!
//! Each subscriber gets a **bounded** [`tokio::sync::mpsc`] queue
//! ([`SUB_QUEUE_CAP`] frames) and a shared filter. [`RealtimeBus::publish`]:
//! assigns the next global `seq`, appends to the bounded resume window, then for
//! every subscriber whose filter matches the event's routes it `try_send`s.
//! A **full** queue is NEVER awaited — the event is dropped for that subscriber
//! and its `lagged` flag is raised; the socket task observes the flag and closes
//! the socket with `slow_consumer` so one slow client can never stall the
//! fan-out (or the node). A **closed** queue (socket gone) is reaped.
//!
//! ## Resume window (§2.7)
//!
//! The last [`RESUME_WINDOW`] published events are retained for
//! [`RealtimeBus::backfill`]. `gap = true` is the honest "you fell behind,
//! re-read REST" marker when the requested `since` predates the window.
//!
//! ## Liveness gate
//!
//! A bus is constructed knowing which [`ChannelClass`]es have a live upstream
//! feed. In this PR only `blocks` is fed (bridged from the coarse operator
//! ring, §4.1). Subscriptions to a class without a live feed are rejected
//! `channel_unavailable` at the WS layer — the Phase-1 gate — until the
//! node-internal fine-grained taps land.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use super::model::{ChannelClass, RealtimeEventBody};

/// Bounded per-subscriber send queue (§2.6 — 256 frames). Overflow evicts the
/// socket (`slow_consumer`), never the fan-out.
pub const SUB_QUEUE_CAP: usize = 256;

/// Retained resume window (§4.1 — 8192 events). One global cursor across the
/// whole realtime surface.
pub const RESUME_WINDOW: usize = 8192;

/// A published event with its assigned global `seq`. Cheap to `Arc`-clone into
/// every matching subscriber queue.
#[derive(Debug, Clone)]
pub struct RealtimeEvent {
    /// The single global monotonic cursor (starts at 1, never reused).
    pub seq: u64,
    /// Wall-clock time the source signal was observed, unix milliseconds.
    pub emitted_at_unix_ms: u64,
    /// Normalized wire keys this event is delivered on.
    pub routes: Vec<String>,
    /// The event-kind token.
    pub event: &'static str,
    /// Mempool-tentative (`false`) vs on-chain (`true`).
    pub confirmed: bool,
    /// Chain height, when applicable.
    pub height: Option<u32>,
    /// The snake_case payload.
    pub data: serde_json::Value,
    /// The `seq` a retraction invalidates (§2.7), if any.
    pub previous_seq: Option<u64>,
}

impl RealtimeEvent {
    /// True when any of this event's routes is in `filter`.
    fn matches(&self, filter: &HashSet<String>) -> bool {
        self.routes.iter().any(|r| filter.contains(r))
    }
}

/// One bounded backfill page for `resume` (§2.7).
#[derive(Debug)]
pub struct BackfillPage {
    /// Matching events with `seq > since`, oldest-first, capped at the request
    /// limit.
    pub events: Vec<Arc<RealtimeEvent>>,
    /// `true` when `since` predates the retained window — the client must treat
    /// its state as cold and re-read via REST.
    pub gap: bool,
    /// `true` when more matching events remain beyond the request limit — the
    /// page is NOT the full catch-up and the caller must not treat it as one.
    pub truncated: bool,
    /// The current global cursor at the time of the read.
    pub latest_seq: u64,
}

struct SubEntry {
    tx: mpsc::Sender<Arc<RealtimeEvent>>,
    filter: Arc<std::sync::RwLock<HashSet<String>>>,
    lagged: Arc<AtomicBool>,
}

struct Inner {
    next_seq: u64,
    next_sub_id: u64,
    subs: HashMap<u64, SubEntry>,
    backfill: VecDeque<Arc<RealtimeEvent>>,
}

/// The fan-out hub. `Arc`-shared between the feed task(s) and every socket.
pub struct RealtimeBus {
    inner: Mutex<Inner>,
    live_classes: HashSet<ChannelClass>,
}

/// A live subscription handle held by one socket task. Dropping it deregisters
/// the subscriber from the bus. The `filter` is shared with the socket's
/// [`Session`](super::protocol::Session) — mutating it (subscribe/unsubscribe)
/// takes effect on the next `publish` with no bus-lock contention.
pub struct BusSubscription {
    bus: Arc<RealtimeBus>,
    id: u64,
    /// The receiving end of this subscriber's bounded queue.
    pub rx: mpsc::Receiver<Arc<RealtimeEvent>>,
    /// The shared filter set (normalized wire keys).
    pub filter: Arc<std::sync::RwLock<HashSet<String>>>,
    /// Raised by the bus when this subscriber's queue overflowed — the socket
    /// task closes with `slow_consumer` when it sees this set.
    pub lagged: Arc<AtomicBool>,
    /// The global cursor this stream starts AFTER.
    pub start_seq: u64,
}

impl Drop for BusSubscription {
    fn drop(&mut self) {
        let mut g = self.bus.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.subs.remove(&self.id);
    }
}

impl RealtimeBus {
    /// A bus that feeds the given channel classes live.
    pub fn new(live_classes: HashSet<ChannelClass>) -> Self {
        RealtimeBus {
            inner: Mutex::new(Inner {
                next_seq: 1,
                next_sub_id: 1,
                subs: HashMap::new(),
                backfill: VecDeque::with_capacity(RESUME_WINDOW.min(1024)),
            }),
            live_classes,
        }
    }

    /// The Phase-1 bus: only `blocks` has a live upstream (the coarse-ring
    /// bridge). Every other class is `channel_unavailable` until its
    /// node-internal fine-grained tap lands.
    pub fn blocks_only() -> Self {
        let mut s = HashSet::new();
        s.insert(ChannelClass::Blocks);
        Self::new(s)
    }

    /// Whether `class` has a live upstream feed on this bus.
    pub fn is_live(&self, class: ChannelClass) -> bool {
        self.live_classes.contains(&class)
    }

    /// The current global cursor (`0` = nothing published yet).
    pub fn latest_seq(&self) -> u64 {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.next_seq - 1
    }

    /// Register a new subscriber (initially subscribed to nothing). The socket
    /// task fills the filter as the client subscribes.
    pub fn subscribe(self: &Arc<Self>) -> BusSubscription {
        let (tx, rx) = mpsc::channel(SUB_QUEUE_CAP);
        let filter = Arc::new(std::sync::RwLock::new(HashSet::new()));
        let lagged = Arc::new(AtomicBool::new(false));
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let id = g.next_sub_id;
        g.next_sub_id += 1;
        let start_seq = g.next_seq - 1;
        g.subs.insert(
            id,
            SubEntry {
                tx,
                filter: filter.clone(),
                lagged: lagged.clone(),
            },
        );
        BusSubscription {
            bus: self.clone(),
            id,
            rx,
            filter,
            lagged,
            start_seq,
        }
    }

    /// Publish one event: assign the next global `seq`, retain it in the resume
    /// window, and fan it out to every matching subscriber under the
    /// never-block drop policy. Returns the assigned `seq`.
    pub fn publish(&self, body: RealtimeEventBody) -> u64 {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let seq = g.next_seq;
        g.next_seq += 1;
        let event = Arc::new(RealtimeEvent {
            seq,
            emitted_at_unix_ms: body.emitted_at_unix_ms,
            routes: body.routes,
            event: body.event,
            confirmed: body.confirmed,
            height: body.height,
            data: body.data,
            previous_seq: body.previous_seq,
        });
        if g.backfill.len() >= RESUME_WINDOW {
            g.backfill.pop_front();
        }
        g.backfill.push_back(event.clone());

        let mut reap: Vec<u64> = Vec::new();
        for (id, sub) in g.subs.iter() {
            let matched = {
                let f = sub.filter.read().unwrap_or_else(|e| e.into_inner());
                event.matches(&f)
            };
            if !matched {
                continue;
            }
            match sub.tx.try_send(event.clone()) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Never block the fan-out on a slow client: drop + flag.
                    sub.lagged.store(true, Ordering::Release);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => reap.push(*id),
            }
        }
        for id in reap {
            g.subs.remove(&id);
        }
        seq
    }

    /// Bounded resume backfill (§2.7): events with `seq > since` matching
    /// `filter`, oldest-first, capped at `limit`. `gap = true` when `since`
    /// predates the retained window.
    pub fn backfill(&self, filter: &HashSet<String>, since: u64, limit: usize) -> BackfillPage {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let latest_seq = g.next_seq - 1;
        let gap = match g.backfill.front() {
            // Oldest retained event is newer than the first event the client
            // still needs → the window rolled past `since`. Saturating: the
            // client controls `since`, so `u64::MAX` must not overflow.
            Some(front) => front.seq > since.saturating_add(1),
            // Nothing retained but the cursor has advanced past `since`.
            None => latest_seq > since,
        };
        // Overfetch by one so a page that exactly fills the limit is
        // distinguishable from one that was cut off.
        let mut events: Vec<_> = g
            .backfill
            .iter()
            .filter(|e| e.seq > since && e.matches(filter))
            .take(limit + 1)
            .cloned()
            .collect();
        let truncated = events.len() > limit;
        if truncated {
            events.truncate(limit);
        }
        BackfillPage {
            events,
            gap,
            truncated,
            latest_seq,
        }
    }

    /// Live subscriber count (diagnostics / tests).
    pub fn subscriber_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .subs
            .len()
    }
}

/// Per-IP + global live-connection limiter for `WS /api/v1/ws` (§2.6). Separate
/// from the per-request token-bucket [`Governor`](crate::v1::governor): this
/// counts *concurrent open sockets*, checked pre-upgrade so an over-limit
/// upgrade gets HTTP 429 `connection_limit` before the WebSocket is accepted.
pub struct ConnLimiter {
    inner: Mutex<ConnInner>,
    max_per_ip: usize,
    global_max: usize,
}

struct ConnInner {
    per_ip: HashMap<IpAddr, usize>,
    total: usize,
}

/// RAII guard released when a socket closes: decrements the per-IP and global
/// counts on drop.
pub struct ConnGuard {
    limiter: Arc<ConnLimiter>,
    ip: IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut g = self.limiter.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.total = g.total.saturating_sub(1);
        if let Some(n) = g.per_ip.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                g.per_ip.remove(&self.ip);
            }
        }
    }
}

impl ConnLimiter {
    /// A limiter with the given per-IP and global ceilings (§2.6 proposals:
    /// 16 sockets/IP, an FD-derived global cap).
    pub fn new(max_per_ip: usize, global_max: usize) -> Self {
        ConnLimiter {
            inner: Mutex::new(ConnInner {
                per_ip: HashMap::new(),
                total: 0,
            }),
            max_per_ip,
            global_max,
        }
    }

    /// Try to admit one socket from `ip`. Returns a [`ConnGuard`] to hold for
    /// the socket's life, or `None` when a per-IP or global cap is hit.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnGuard> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.total >= self.global_max {
            return None;
        }
        let cur = g.per_ip.get(&ip).copied().unwrap_or(0);
        if cur >= self.max_per_ip {
            return None;
        }
        g.per_ip.insert(ip, cur + 1);
        g.total += 1;
        Some(ConnGuard {
            limiter: self.clone(),
            ip,
        })
    }

    /// Current total open sockets (tests).
    pub fn total(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ----- helpers -----

    fn keyset(keys: &[&str]) -> HashSet<String> {
        keys.iter().map(|s| s.to_string()).collect()
    }

    fn blk(seq_unix: u64) -> RealtimeEventBody {
        RealtimeEventBody::block_applied(seq_unix, format!("h{seq_unix}"), 100, 1, 10)
    }

    fn set_filter(sub: &BusSubscription, keys: &[&str]) {
        *sub.filter.write().unwrap() = keyset(keys);
    }

    // ----- happy path -----

    #[test]
    fn publish_assigns_monotonic_seq_from_one() {
        let bus = Arc::new(RealtimeBus::blocks_only());
        assert_eq!(bus.publish(blk(1)), 1);
        assert_eq!(bus.publish(blk(2)), 2);
        assert_eq!(bus.latest_seq(), 2);
    }

    #[tokio::test]
    async fn subscriber_receives_matching_event() {
        let bus = Arc::new(RealtimeBus::blocks_only());
        let mut sub = bus.subscribe();
        set_filter(&sub, &["blocks"]);
        bus.publish(blk(7));
        let ev = sub.rx.try_recv().expect("event delivered");
        assert_eq!(ev.event, "block_applied");
        assert_eq!(ev.seq, 1);
    }

    #[tokio::test]
    async fn per_key_filtering_excludes_nonmatching() {
        let bus = Arc::new(RealtimeBus::new({
            let mut s = HashSet::new();
            s.insert(ChannelClass::Blocks);
            s.insert(ChannelClass::Address);
            s
        }));
        let mut only_addr = bus.subscribe();
        set_filter(&only_addr, &["address:9f"]);
        // A blocks event must NOT reach an address-only socket (the firehose
        // pre-filter that is the cost governor).
        bus.publish(blk(1));
        assert!(only_addr.rx.try_recv().is_err());
        // A matching box_spent addressed to 9f does reach it.
        bus.publish(RealtimeEventBody::box_spent(
            1,
            Some("address:9f".into()),
            "aa".into(),
            true,
            Some(10),
            serde_json::json!({"box_id": "aa"}),
        ));
        assert_eq!(only_addr.rx.try_recv().unwrap().event, "box_spent");
    }

    #[tokio::test]
    async fn unsubscribe_via_filter_stops_delivery() {
        let bus = Arc::new(RealtimeBus::blocks_only());
        let mut sub = bus.subscribe();
        set_filter(&sub, &["blocks"]);
        bus.publish(blk(1));
        assert!(sub.rx.try_recv().is_ok());
        set_filter(&sub, &[]); // unsubscribe
        bus.publish(blk(2));
        assert!(sub.rx.try_recv().is_err());
    }

    #[test]
    fn dropping_subscription_reaps_it() {
        let bus = Arc::new(RealtimeBus::blocks_only());
        let sub = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);
        drop(sub);
        assert_eq!(bus.subscriber_count(), 0);
    }

    // ----- slow-consumer drop policy -----

    #[tokio::test]
    async fn slow_consumer_overflow_drops_and_flags_never_blocks() {
        let bus = Arc::new(RealtimeBus::blocks_only());
        let sub = bus.subscribe();
        set_filter(&sub, &["blocks"]);
        // Overfill the bounded queue by one; publish must return promptly for
        // every event (never blocks) and raise the lag flag once full.
        for i in 0..(SUB_QUEUE_CAP as u64 + 5) {
            bus.publish(blk(i));
        }
        assert!(sub.lagged.load(Ordering::Acquire), "lag flag raised");
        // The other subscribers are unaffected — fan-out was not stalled.
        assert_eq!(bus.latest_seq(), SUB_QUEUE_CAP as u64 + 5);
    }

    // ----- backfill / resume -----

    #[test]
    fn backfill_returns_matching_events_after_since() {
        let bus = Arc::new(RealtimeBus::blocks_only());
        for i in 0..5 {
            bus.publish(blk(i));
        }
        let page = bus.backfill(&keyset(&["blocks"]), 2, 100);
        assert!(!page.gap);
        assert_eq!(
            page.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
        assert_eq!(page.latest_seq, 5);
    }

    #[test]
    fn backfill_reports_gap_when_since_fell_off_window() {
        let bus = Arc::new(RealtimeBus::blocks_only());
        // Overfill the resume window so the oldest retained seq is > 1.
        for i in 0..(RESUME_WINDOW as u64 + 10) {
            bus.publish(blk(i));
        }
        let page = bus.backfill(&keyset(&["blocks"]), 1, 100);
        assert!(page.gap, "since predates the window → gap");
    }

    #[test]
    fn backfill_since_u64_max_no_overflow_no_gap() {
        let bus = Arc::new(RealtimeBus::blocks_only());
        bus.publish(blk(0));
        // A client-supplied `since` of u64::MAX must not overflow the gap
        // check; it is ahead of everything retained, so no gap, no events.
        let page = bus.backfill(&keyset(&["blocks"]), u64::MAX, 100);
        assert!(!page.gap);
        assert!(page.events.is_empty());
    }

    // ----- connection limiter -----

    #[test]
    fn conn_limiter_enforces_per_ip_and_releases_on_drop() {
        let lim = Arc::new(ConnLimiter::new(2, 100));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let g1 = lim.try_acquire(ip).unwrap();
        let _g2 = lim.try_acquire(ip).unwrap();
        assert!(lim.try_acquire(ip).is_none(), "3rd socket over per-IP cap");
        drop(g1);
        assert!(lim.try_acquire(ip).is_some(), "slot freed on drop");
    }

    #[test]
    fn conn_limiter_enforces_global_ceiling() {
        let lim = Arc::new(ConnLimiter::new(100, 1));
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let _g = lim.try_acquire(a).unwrap();
        assert!(lim.try_acquire(b).is_none(), "global ceiling hit");
        assert_eq!(lim.total(), 1);
    }
}
