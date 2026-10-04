//! Bounded asynchronous replay persistence. Publishing never waits for disk.
//! Cursor reservations prevent reuse after a crash; an uncertain interval is
//! exposed as a replay gap instead of being presented as a complete history.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::bus::{RealtimeEvent, RESUME_WINDOW};

pub const JOURNAL_QUEUE_CAP: usize = 512;
pub const JOURNAL_BYTES_CAP: usize = 64 * 1024 * 1024;
pub const JOURNAL_EVENT_BYTES_CAP: usize = 1024 * 1024;
// One boot owns a trillion cursors even if every subsequent disk write fails.
// Exhausting this epoch is a cursor-capacity limit, independent of disk health.
const CURSOR_RESERVATION: u64 = 1 << 40;

/// Owned, versioned storage/wire representation; no process-local references.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReplayEvent {
    pub seq: u64,
    pub emitted_at_unix_ms: u64,
    pub routes: Vec<String>,
    pub event: String,
    pub confirmed: bool,
    pub height: Option<u32>,
    pub data: serde_json::Value,
    pub previous_seq: Option<u64>,
}

impl From<&RealtimeEvent> for ReplayEvent {
    fn from(event: &RealtimeEvent) -> Self {
        Self {
            seq: event.seq,
            emitted_at_unix_ms: event.emitted_at_unix_ms,
            routes: event.routes.clone(),
            event: event.event.into(),
            confirmed: event.confirmed,
            height: event.height,
            data: event.data.clone(),
            previous_seq: event.previous_seq,
        }
    }
}

impl ReplayEvent {
    pub fn into_event(self) -> Result<RealtimeEvent, String> {
        // Persisted tokens are bounded vocabulary, never leaked allocations.
        let event = match self.event.as_str() {
            "block_applied" => "block_applied",
            "reorg" => "reorg",
            "peer_connected" => "peer_connected",
            "peer_disconnected" => "peer_disconnected",
            "tx_accepted" => "tx_accepted",
            "tx_dropped" => "tx_dropped",
            "tx_confirmed" => "tx_confirmed",
            "box_created" => "box_created",
            "box_spent" => "box_spent",
            "box_reverted" => "box_reverted",
            "box_unspent" => "box_unspent",
            "token_moved" => "token_moved",
            "token_reverted" => "token_reverted",
            _ => return Err("unknown persisted realtime event kind".into()),
        };
        if self.seq == 0
            || self.seq >= u64::MAX - 1
            || self.routes.is_empty()
            || self.routes.len() > 128
            || self.previous_seq.is_some_and(|seq| seq >= self.seq)
        {
            return Err("invalid persisted realtime event".into());
        }
        Ok(RealtimeEvent {
            seq: self.seq,
            emitted_at_unix_ms: self.emitted_at_unix_ms,
            routes: self.routes,
            event,
            confirmed: self.confirmed,
            height: self.height,
            data: self.data,
            previous_seq: self.previous_seq,
        })
    }
}

#[derive(Default)]
pub struct JournalRecovery {
    /// First cursor which has never been reserved by the previous process.
    pub next_seq: u64,
    pub events: Vec<ReplayEvent>,
}

/// Production implementations commit immediately and retain at most
/// RESUME_WINDOW events / JOURNAL_BYTES_CAP bytes, removing oldest first.
pub trait RealtimeStore: Send + Sync + 'static {
    fn load_events(&self) -> Result<JournalRecovery, String>;
    fn reserve_cursor(&self, next_seq: u64) -> Result<(), String>;
    fn append_events(&self, events: &[ReplayEvent]) -> Result<(), String>;
}

#[derive(Default)]
struct Health {
    committed_seq: AtomicU64,
    complete_through_seq: AtomicU64,
    reserved_next: AtomicU64,
    published_seq: AtomicU64,
    dropped: AtomicU64,
    failed: AtomicBool,
    closed: AtomicBool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct JournalStatus {
    /// Largest event cursor confirmed committed, not an acknowledgement of
    /// every lower cursor: inspect gap / dropped_events as well.
    pub committed_seq: u64,
    /// Every observed event through this boundary was committed; later records
    /// may also be committed, but drops/crash uncertainty prevent that claim.
    pub complete_through_seq: u64,
    pub dropped_events: u64,
    pub available: bool,
}

struct Worker {
    sender: Option<mpsc::SyncSender<Arc<RealtimeEvent>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

pub(crate) struct EventJournal {
    worker: Mutex<Worker>,
    health: Arc<Health>,
}

struct ThreadFailureGuard(Arc<Health>);
impl Drop for ThreadFailureGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.failed.store(true, Ordering::Release);
        }
    }
}

impl EventJournal {
    pub fn open(
        store: Arc<dyn RealtimeStore>,
        minimum_next: u64,
    ) -> Result<(Self, JournalRecovery), String> {
        let mut recovery = store.load_events()?;
        if recovery.events.len() > RESUME_WINDOW {
            return Err("realtime history exceeds retention limit".into());
        }
        let mut previous = 0;
        let mut bytes = 0;
        for event in &recovery.events {
            let size = serde_json::to_vec(event).map_err(|e| e.to_string())?.len();
            bytes += size;
            if event.seq <= previous || size > JOURNAL_EVENT_BYTES_CAP || bytes > JOURNAL_BYTES_CAP
            {
                return Err("invalid or oversized realtime history".into());
            }
            event.clone().into_event()?;
            previous = event.seq;
        }
        recovery.next_seq = recovery.next_seq.max(1).max(minimum_next);
        if recovery.next_seq <= previous {
            return Err("realtime cursor precedes persisted history".into());
        }
        let reserved = recovery
            .next_seq
            .checked_add(CURSOR_RESERVATION)
            .filter(|next| *next < u64::MAX - 1)
            .ok_or("realtime cursor exhausted")?;
        store.reserve_cursor(reserved)?;
        let health = Arc::new(Health::default());
        health.committed_seq.store(previous, Ordering::Release);
        let mut complete = recovery
            .events
            .first()
            .map(|event| event.seq - 1)
            .unwrap_or(0);
        for event in &recovery.events {
            if event.seq != complete.saturating_add(1) {
                break;
            }
            complete = event.seq;
        }
        health
            .complete_through_seq
            .store(complete, Ordering::Release);
        health
            .published_seq
            .store(recovery.next_seq - 1, Ordering::Release);
        health.reserved_next.store(reserved, Ordering::Release);
        let shared = health.clone();
        let (sender, receiver) = mpsc::sync_channel::<Arc<RealtimeEvent>>(JOURNAL_QUEUE_CAP);
        let thread = std::thread::Builder::new().name("realtime-journal".into()).spawn(move || {
            let _failure_guard = ThreadFailureGuard(shared.clone());
            let mut batch = Vec::with_capacity(128);
            while let Ok(first) = receiver.recv() {
                batch.push(ReplayEvent::from(first.as_ref()));
                for event in receiver.try_iter().take(127) {
                    batch.push(ReplayEvent::from(event.as_ref()));
                }
                let last = batch.last().expect("nonempty batch").seq;
                if shared.failed.load(Ordering::Acquire) {
                    shared.dropped.fetch_add(batch.len() as u64, Ordering::Relaxed);
                    batch.clear();
                    continue;
                }
                if let Err(error) = store.append_events(&batch) {
                    // Keep consuming the queue so pending losses are accounted
                    // for. Log once; live fanout owns its pre-reserved boot epoch.
                    shared.failed.store(true, Ordering::Release);
                    shared.dropped.fetch_add(batch.len() as u64, Ordering::Relaxed);
                    tracing::error!(%error, "realtime persistence stopped; live delivery continues; replay must reconcile from REST");
                    batch.clear();
                    continue;
                }
                shared.committed_seq.store(last, Ordering::Release);
                let mut complete = shared.complete_through_seq.load(Ordering::Acquire);
                for event in &batch {
                    if event.seq != complete.saturating_add(1) { break; }
                    complete = event.seq;
                }
                shared.complete_through_seq.store(complete, Ordering::Release);
                batch.clear();
            }
            // All publishers are gone and the queue is drained. Releasing the
            // unused reservation avoids a restart gap on orderly shutdown.
            if shared.failed.load(Ordering::Acquire) { return; }
            let next = shared.published_seq.load(Ordering::Acquire).saturating_add(1);
            if let Err(error) = store.reserve_cursor(next) {
                shared.failed.store(true, Ordering::Release);
                tracing::error!(%error, "realtime cursor finalization failed");
            }
        }).map_err(|e| e.to_string())?;
        Ok((
            Self {
                worker: Mutex::new(Worker {
                    sender: Some(sender),
                    thread: Some(thread),
                }),
                health,
            },
            recovery,
        ))
    }

    pub fn can_publish(&self, seq: u64) -> bool {
        // This boot epoch is reserved before publishing starts; no persistence
        // error can reduce it. Closure and epoch exhaustion are lifecycle limits.
        !self.health.closed.load(Ordering::Acquire)
            && seq < self.health.reserved_next.load(Ordering::Acquire)
    }

    pub fn enqueue(&self, event: Arc<RealtimeEvent>) {
        self.health
            .published_seq
            .store(event.seq, Ordering::Release);
        if self.health.failed.load(Ordering::Acquire) {
            self.health.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let worker = self
            .worker
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match worker.sender.as_ref().map(|sender| sender.try_send(event)) {
            Some(Ok(())) => {}
            Some(Err(mpsc::TrySendError::Full(_))) => {
                self.health.dropped.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.health.failed.store(true, Ordering::Release);
                self.health.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// The caller holds the bus lock until this short close operation returns.
    /// Join the returned worker outside that lock and off the async reactor.
    pub fn close(&self) -> Option<std::thread::JoinHandle<()>> {
        self.health.closed.store(true, Ordering::Release);
        let mut worker = self
            .worker
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        drop(worker.sender.take());
        worker.thread.take()
    }

    pub fn status(&self) -> JournalStatus {
        JournalStatus {
            committed_seq: self.health.committed_seq.load(Ordering::Acquire),
            complete_through_seq: self.health.complete_through_seq.load(Ordering::Acquire),
            dropped_events: self.health.dropped.load(Ordering::Acquire),
            available: !self.health.failed.load(Ordering::Acquire)
                && !self.health.closed.load(Ordering::Acquire),
        }
    }
}

impl Drop for EventJournal {
    fn drop(&mut self) {
        // Close, drain and join before releasing the database lock. Node
        // shutdown drops services after publishers have been stopped.
        if let Some(thread) = self.close() {
            if thread.join().is_err() {
                self.health.failed.store(true, Ordering::Release);
                tracing::error!("realtime persistence thread panicked");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::realtime::{ChannelClass, RealtimeBus, RealtimeEventBody};
    use std::collections::HashSet;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    #[derive(Default)]
    struct MemoryStore {
        saved: Mutex<JournalRecovery>,
        fail_append: AtomicBool,
        fail_reserve: AtomicBool,
    }
    impl RealtimeStore for MemoryStore {
        fn load_events(&self) -> Result<JournalRecovery, String> {
            let saved = self.saved.lock().unwrap();
            Ok(JournalRecovery {
                next_seq: saved.next_seq,
                events: saved.events.clone(),
            })
        }
        fn reserve_cursor(&self, next: u64) -> Result<(), String> {
            if self.fail_reserve.load(Ordering::Acquire) {
                return Err("injected reservation failure".into());
            }
            self.saved.lock().unwrap().next_seq = next;
            Ok(())
        }
        fn append_events(&self, events: &[ReplayEvent]) -> Result<(), String> {
            if self.fail_append.load(Ordering::Acquire) {
                return Err("injected append failure".into());
            }
            let mut saved = self.saved.lock().unwrap();
            saved.events.extend_from_slice(events);
            let excess = saved.events.len().saturating_sub(RESUME_WINDOW);
            saved.events.drain(..excess);
            Ok(())
        }
    }
    fn classes() -> HashSet<ChannelClass> {
        [ChannelClass::Blocks].into_iter().collect()
    }
    fn filter() -> HashSet<String> {
        ["blocks".into()].into_iter().collect()
    }
    fn body(height: u32) -> RealtimeEventBody {
        RealtimeEventBody::block_applied(
            u64::from(height),
            format!("header-{height}"),
            height,
            1,
            100,
        )
    }
    fn wait_until(mut check: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !check() {
            assert!(
                Instant::now() < deadline,
                "journal did not finish bounded test work"
            );
            std::thread::yield_now();
        }
    }

    #[test]
    fn orderly_restart_replays_original_cursors_and_reorg_links() {
        let store = Arc::new(MemoryStore::default());
        let bus = RealtimeBus::durable(classes(), store.clone(), 1).unwrap();
        assert_eq!(bus.publish(body(10)), 1);
        let mut inverse = body(11);
        inverse.event = "reorg";
        inverse.previous_seq = Some(1);
        assert_eq!(bus.publish(inverse), 2);
        drop(bus); // drains and releases unused cursor reservation
        let bus = RealtimeBus::durable(classes(), store.clone(), 1).unwrap();
        let replay = bus.backfill(&filter(), 0, 100);
        assert!(!replay.gap);
        assert_eq!(
            replay
                .events
                .iter()
                .map(|event| event.seq)
                .collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(replay.events[1].previous_seq, Some(1));
        assert_eq!(bus.publish(body(12)), 3);
        wait_until(|| bus.journal_status().unwrap().committed_seq == 3);
        assert_eq!(bus.journal_status().unwrap().complete_through_seq, 3);
    }

    #[test]
    fn crash_reservation_never_aliases_unconfirmed_events_and_reports_gap() {
        let store = Arc::new(MemoryStore::default());
        let mut saved = store.saved.lock().unwrap();
        saved.next_seq = CURSOR_RESERVATION + 1;
        saved.events.push(ReplayEvent::from(&RealtimeEvent {
            seq: 1,
            emitted_at_unix_ms: 1,
            routes: vec!["blocks".into()],
            event: "block_applied",
            confirmed: true,
            height: Some(1),
            data: serde_json::json!({"height":1}),
            previous_seq: None,
        }));
        drop(saved);
        let bus = RealtimeBus::durable(classes(), store, 1).unwrap();
        assert_eq!(bus.publish(body(2)), CURSOR_RESERVATION + 1);
        let page = bus.backfill(&filter(), 1, 100);
        assert!(page.gap);
        assert_eq!(page.events[0].seq, CURSOR_RESERVATION + 1);
        assert!(!bus.backfill(&filter(), CURSOR_RESERVATION + 1, 100).gap);
    }

    #[test]
    fn append_failure_does_not_ack_durability_or_stall_live_fanout() {
        let store = Arc::new(MemoryStore::default());
        store.fail_append.store(true, Ordering::Release);
        let bus = Arc::new(RealtimeBus::durable(classes(), store.clone(), 1).unwrap());
        let mut subscriber = bus.subscribe();
        subscriber.filter.write().unwrap().insert("blocks".into());
        assert_eq!(bus.publish(body(1)), 1);
        wait_until(|| !bus.journal_status().unwrap().available);
        assert_eq!(bus.journal_status().unwrap().committed_seq, 0);
        assert_eq!(subscriber.rx.try_recv().unwrap().seq, 1);
        drop(subscriber);
        drop(bus);
        assert_eq!(store.saved.lock().unwrap().next_seq, CURSOR_RESERVATION + 1);
        assert!(store.saved.lock().unwrap().events.is_empty());
    }

    #[test]
    fn failed_journal_keeps_live_cursors_beyond_old_reservation_and_records_losses() {
        let store = Arc::new(MemoryStore::default());
        store.fail_append.store(true, Ordering::Release);
        let bus = Arc::new(RealtimeBus::durable(classes(), store.clone(), 1).unwrap());
        bus.publish(body(1));
        wait_until(|| !bus.journal_status().unwrap().available);
        for height in 2..=100_000 {
            assert_eq!(bus.publish(body(height)), u64::from(height));
        }
        let mut subscriber = bus.subscribe();
        subscriber.filter.write().unwrap().insert("blocks".into());
        assert_eq!(bus.publish(body(100_001)), 100_001);
        assert_eq!(subscriber.rx.try_recv().unwrap().seq, 100_001);
        wait_until(|| bus.journal_status().unwrap().dropped_events == 100_001);
        assert_eq!(bus.journal_status().unwrap().committed_seq, 0);
        drop(subscriber);
        drop(bus);
        store.fail_append.store(false, Ordering::Release);
        let restarted = RealtimeBus::durable(classes(), store, 1).unwrap();
        assert!(restarted.publish(body(100_002)) > 100_001);
        assert!(restarted.backfill(&filter(), 100_001, 10).gap);
    }

    #[test]
    fn reservation_failure_and_invalid_history_fail_initialization() {
        let store = Arc::new(MemoryStore::default());
        store.fail_reserve.store(true, Ordering::Release);
        assert!(RealtimeBus::durable(classes(), store.clone(), 1).is_err());
        store.fail_reserve.store(false, Ordering::Release);
        let event = ReplayEvent {
            seq: 4,
            emitted_at_unix_ms: 0,
            routes: vec!["blocks".into()],
            event: "unknown".into(),
            confirmed: true,
            height: None,
            data: serde_json::json!({}),
            previous_seq: None,
        };
        store.saved.lock().unwrap().events.push(event);
        assert!(RealtimeBus::durable(classes(), store, 1).is_err());
    }

    struct GatedStore {
        memory: MemoryStore,
        gate: (Mutex<bool>, std::sync::Condvar),
        entered: AtomicBool,
    }
    impl RealtimeStore for GatedStore {
        fn load_events(&self) -> Result<JournalRecovery, String> {
            self.memory.load_events()
        }
        fn reserve_cursor(&self, next: u64) -> Result<(), String> {
            self.memory.reserve_cursor(next)
        }
        fn append_events(&self, events: &[ReplayEvent]) -> Result<(), String> {
            self.entered.store(true, Ordering::Release);
            let mut open = self.gate.0.lock().unwrap();
            while !*open {
                open = self.gate.1.wait(open).unwrap();
            }
            self.memory.append_events(events)
        }
    }

    #[test]
    fn saturated_journal_never_blocks_publish_and_restart_exposes_missing_tail() {
        let store = Arc::new(GatedStore {
            memory: Default::default(),
            gate: (Mutex::new(false), std::sync::Condvar::new()),
            entered: AtomicBool::new(false),
        });
        let bus = RealtimeBus::durable(classes(), store.clone(), 1).unwrap();
        bus.publish(body(1));
        wait_until(|| store.entered.load(Ordering::Acquire));
        for height in 2..=(JOURNAL_QUEUE_CAP as u32 + 3) {
            bus.publish(body(height));
        }
        assert_eq!(bus.journal_status().unwrap().dropped_events, 2);
        assert_eq!(bus.journal_status().unwrap().committed_seq, 0);
        assert!(!bus.backfill(&filter(), 0, 1000).gap); // live records still present
        *store.gate.0.lock().unwrap() = true;
        store.gate.1.notify_all();
        drop(bus);
        let bus = RealtimeBus::durable(classes(), store, 1).unwrap();
        let page = bus.backfill(&filter(), JOURNAL_QUEUE_CAP as u64, 100);
        assert!(page.gap);
        assert_eq!(page.events[0].seq, JOURNAL_QUEUE_CAP as u64 + 1);
        assert_eq!(page.latest_seq, JOURNAL_QUEUE_CAP as u64 + 3);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_joins_pending_commits_off_reactor_and_closes_publish_race() {
        let store = Arc::new(GatedStore {
            memory: Default::default(),
            gate: (Mutex::new(false), std::sync::Condvar::new()),
            entered: AtomicBool::new(false),
        });
        let bus = Arc::new(RealtimeBus::durable(classes(), store.clone(), 1).unwrap());
        bus.publish(body(1));
        wait_until(|| store.entered.load(Ordering::Acquire));
        let closing_bus = bus.clone();
        let closing = tokio::spawn(async move {
            closing_bus.shutdown_journal().await;
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while bus.journal_status().unwrap().available {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::timeout(
            Duration::from_millis(100),
            tokio::time::sleep(Duration::from_millis(5)),
        )
        .await
        .unwrap();
        assert!(!closing.is_finished());
        assert_eq!(bus.publish(body(2)), 1); // shutdown cannot race a reused cursor
        *store.gate.0.lock().unwrap() = true;
        store.gate.1.notify_all();
        closing.await.unwrap();
        assert_eq!(store.memory.load_events().unwrap().next_seq, 2);
        assert_eq!(store.memory.load_events().unwrap().events.len(), 1);
    }
}
