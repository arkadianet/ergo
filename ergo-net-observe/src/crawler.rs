//! Controlled discovery walk over the legacy peer network.
//!
//! The crawler turns a fixed seed list into a bounded network walk:
//!
//! * live sessions forward their `Peers` replies through a bounded,
//!   non-blocking channel ([`CrawlChannel`]) — a full channel drops the
//!   report, it never backpressures a session;
//! * newly learned addresses enter a bounded frontier ([`CrawlState`]) with
//!   per-address rate-limited state: consecutive failures escalate an
//!   exponential retry backoff, a completed handshake resets it;
//! * a global dial-rate cap spaces out *all* new dials, so even a burst of
//!   gossip can only produce the configured dials per minute;
//! * the frontier persists to a local state file (atomic replace, mode
//!   0600) so a restart does not re-hammer recently-failed addresses or
//!   re-walk the network from the seeds.
//!
//! The state file contains raw peer addresses. It is an operator-local
//! file like the pseudonym key, never part of the publishable dataset:
//! keep it private and never publish it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::record::Event;
use crate::sink::{unix_ms, ObserverSink};

/// Bounded frontier: when the cap is hit, the oldest entry (by insertion)
/// that is not in flight is evicted. 200k entries is a few MiB.
pub const MAX_TRACKED: usize = 200_000;

/// How often the persistence task rewrites the state file.
pub const STATE_SAVE_INTERVAL: Duration = Duration::from_secs(60);

/// Crawl rate limits and persistence location.
#[derive(Debug, Clone)]
pub struct CrawlConfig {
    /// Maximum *new* dials per minute across all slots.
    pub dial_rate_per_min: u32,
    /// Per-address retry backoff floor.
    pub backoff_min: Duration,
    /// Per-address retry backoff cap.
    pub backoff_max: Duration,
    /// Frontier cap; the oldest non-in-flight entry is evicted at the cap.
    pub max_tracked: usize,
    /// State file path. `None` disables persistence (in-memory only).
    pub state_path: Option<std::path::PathBuf>,
    /// Permit loopback / private / link-local learned addresses (lab use).
    pub allow_local: bool,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            dial_rate_per_min: 12,
            backoff_min: Duration::from_secs(60),
            backoff_max: Duration::from_secs(6 * 3600),
            max_tracked: MAX_TRACKED,
            state_path: None,
            allow_local: false,
        }
    }
}

/// One gossiped address. In memory only — never written to the dataset.
#[derive(Debug, Clone)]
pub struct GossipSpec {
    pub addr: SocketAddr,
    pub agent: String,
    pub version: String,
    pub node_name: String,
}

/// A `Peers` reply from one live session.
#[derive(Debug, Clone)]
pub struct GossipReport {
    /// Pseudonym id of the gossiping peer.
    pub via_id: String,
    pub specs: Vec<GossipSpec>,
}

/// Bounded, non-blocking gossip channel shared by all sessions.
#[derive(Debug, Clone)]
pub struct CrawlChannel {
    tx: mpsc::Sender<GossipReport>,
}

/// Receiver half of [`CrawlChannel`].
pub type GossipRx = mpsc::Receiver<GossipReport>;

impl CrawlChannel {
    pub fn new(capacity: usize) -> (Self, GossipRx) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (Self { tx }, rx)
    }

    /// Forward a report; drops it when the channel is full.
    pub fn send(&self, report: GossipReport) {
        let _ = self.tx.try_send(report);
    }
}

/// Outcome of one dial attempt, for [`CrawlState::note_result`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// TCP connect refused.
    ConnectRefused,
    /// TCP connect timed out.
    ConnectTimeout,
    /// Connected, but the handshake did not complete.
    HandshakeFail,
    /// Completed handshake.
    Handshaken,
}

impl AttemptOutcome {
    /// JSONL label for the `dial_attempt` record.
    pub fn label(self) -> &'static str {
        match self {
            Self::ConnectRefused => "connect_refused",
            Self::ConnectTimeout => "connect_timeout",
            Self::HandshakeFail => "handshake_fail",
            Self::Handshaken => "handshaken",
        }
    }

    fn is_failure(self) -> bool {
        !matches!(self, Self::Handshaken)
    }
}

#[derive(Debug, Default)]
struct Entry {
    /// Pseudonym id of the gossiping peer, or `"seed"`.
    learned_via: String,
    /// Wall-clock ms of the last attempt (0 = never attempted).
    last_attempt_ms: i64,
    /// Wall-clock ms before which the address must not be dialed.
    next_due_ms: i64,
    /// Consecutive failures since the last completed handshake.
    failures: u32,
    /// Completed handshakes since first seen.
    successes: u32,
}

struct State {
    entries: HashMap<SocketAddr, Entry>,
    /// Insertion order, for bounded eviction.
    order: VecDeque<SocketAddr>,
    /// Dial queue: learned/seeded addresses awaiting an attempt.
    queue: VecDeque<SocketAddr>,
    /// Addresses a worker currently has open (connect + session).
    in_flight: HashSet<SocketAddr>,
    /// When the next new dial is allowed (global rate cap).
    next_dial: Instant,
}

/// The crawl frontier: rate-limited, bounded, persistable.
pub struct CrawlState {
    inner: Mutex<State>,
    cfg: CrawlConfig,
    sink: ObserverSink,
}

/// Serialized form of one frontier entry.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedEntry {
    learned_via: String,
    last_attempt_ms: i64,
    next_due_ms: i64,
    failures: u32,
    successes: u32,
}

/// Serialized form of the whole state file.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedState {
    version: u32,
    updated_at_ms: i64,
    entries: Vec<(String, PersistedEntry)>,
}

impl CrawlState {
    /// Build the frontier from seeds, loading persisted state when present.
    /// Persisted entries rejoin the queue; seeds already persisted are not
    /// duplicated.
    pub fn new(cfg: CrawlConfig, sink: ObserverSink, seeds: Vec<SocketAddr>) -> Arc<Self> {
        let mut state = State {
            entries: HashMap::new(),
            order: VecDeque::new(),
            queue: VecDeque::new(),
            in_flight: HashSet::new(),
            next_dial: Instant::now(),
        };

        if let Some(path) = &cfg.state_path {
            match load_state(path) {
                Ok(persisted) => {
                    for (raw, entry) in persisted.entries {
                        let Ok(addr) = raw.parse::<SocketAddr>() else {
                            continue;
                        };
                        let entry = Entry {
                            learned_via: entry.learned_via,
                            last_attempt_ms: entry.last_attempt_ms,
                            next_due_ms: entry.next_due_ms,
                            failures: entry.failures,
                            successes: entry.successes,
                        };
                        if state.entries.insert(addr, entry).is_none() {
                            state.order.push_back(addr);
                            state.queue.push_back(addr);
                        }
                    }
                    info!(
                        tracked = state.entries.len(),
                        "crawler: loaded persisted frontier"
                    );
                }
                Err(e) => info!(error = %e, "crawler: no usable persisted frontier"),
            }
        }

        for seed in seeds {
            if state
                .entries
                .insert(
                    seed,
                    Entry {
                        learned_via: "seed".to_string(),
                        ..Default::default()
                    },
                )
                .is_none()
            {
                state.order.push_back(seed);
                state.queue.push_back(seed);
            }
        }

        Arc::new(Self {
            inner: Mutex::new(state),
            cfg,
            sink,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Ingest one session's `Peers` reply: queue never-before-seen
    /// dialable addresses and emit `peer_learned` for them.
    pub fn learn(&self, report: GossipReport) {
        let learned: Vec<(SocketAddr, String, String, String)> = {
            let mut state = self.lock();
            let mut out = Vec::new();
            for spec in &report.specs {
                if is_local(spec.addr.ip()) && !self.cfg.allow_local {
                    continue;
                }
                if state.entries.contains_key(&spec.addr) {
                    continue;
                }
                bound_evict(&mut state, spec.addr, self.cfg.max_tracked);
                state.entries.insert(
                    spec.addr,
                    Entry {
                        learned_via: report.via_id.clone(),
                        last_attempt_ms: unix_ms(),
                        ..Default::default()
                    },
                );
                state.order.push_back(spec.addr);
                state.queue.push_back(spec.addr);
                out.push((
                    spec.addr,
                    spec.agent.clone(),
                    spec.version.clone(),
                    spec.node_name.clone(),
                ));
            }
            out
        };
        let learned_count = learned.len();
        for (addr, agent, version, node_name) in learned {
            let peer = self.sink.peer_ref(
                &addr.to_string(),
                Some(&agent),
                Some(&version),
                Some(&node_name),
                Some("crawl"),
            );
            self.sink.try_emit_peer(
                peer,
                Event::PeerLearned {
                    via: report.via_id.clone(),
                },
            );
        }
        if learned_count != 0 {
            debug!(
                learned = learned_count,
                tracked = self.lock().entries.len(),
                "crawler: frontier updated"
            );
        }
    }

    /// The next address to dial: rate-cap respected, per-address backoff
    /// respected, in-flight addresses skipped. `None` when nothing is due.
    pub fn next_due(&self) -> Option<SocketAddr> {
        let mut state = self.lock();
        let now = Instant::now();
        if now < state.next_dial {
            return None;
        }
        let now_ms = unix_ms();
        let mut deferred = VecDeque::new();
        let mut chosen = None;
        while let Some(addr) = state.queue.pop_front() {
            if state.in_flight.contains(&addr) {
                continue; // a worker holds it; it will be re-queued
            }
            let Some(entry) = state.entries.get_mut(&addr) else {
                continue;
            };
            if entry.next_due_ms > now_ms {
                deferred.push_back(addr);
                continue;
            }
            entry.last_attempt_ms = now_ms;
            state.in_flight.insert(addr);
            chosen = Some(addr);
            break;
        }
        // Not-due addresses come back behind the rest.
        state.queue.extend(deferred);
        if chosen.is_some() {
            let spacing = Duration::from_secs_f64(60.0 / self.cfg.dial_rate_per_min.max(1) as f64);
            state.next_dial = now + spacing;
        }
        chosen
    }

    /// Record an attempt's outcome: update backoff and emit `dial_attempt`.
    pub fn note_result(&self, addr: SocketAddr, outcome: AttemptOutcome, connect_ms: Option<u64>) {
        let (via, retries) = {
            let mut state = self.lock();
            state.in_flight.remove(&addr);
            let Some(entry) = state.entries.get_mut(&addr) else {
                return;
            };
            let retries = entry.failures;
            if outcome.is_failure() {
                entry.failures = entry.failures.saturating_add(1);
                let exp = (entry.failures - 1).min(16);
                let delay =
                    (self.cfg.backoff_min * 2u32.saturating_pow(exp)).min(self.cfg.backoff_max);
                entry.next_due_ms = unix_ms() + delay.as_millis() as i64;
            } else {
                entry.failures = 0;
                entry.successes = entry.successes.saturating_add(1);
                entry.next_due_ms = 0;
            }
            let via = entry.learned_via.clone();
            state.queue.push_back(addr);
            (via, retries)
        };
        let peer = self
            .sink
            .peer_ref(&addr.to_string(), None, None, None, Some("crawl"));
        self.sink.try_emit_peer(
            peer,
            Event::DialAttempt {
                outcome: outcome.label().to_string(),
                connect_ms,
                retries,
                via,
            },
        );
    }

    /// Current frontier size (for logs and tests).
    pub fn tracked(&self) -> usize {
        self.lock().entries.len()
    }

    /// Write the state file atomically (tmp + rename). Best-effort: a
    /// failed write is logged, never fatal.
    pub fn save(&self) {
        let Some(path) = &self.cfg.state_path else {
            return;
        };
        let text = match self.snapshot_text() {
            Some(t) => t,
            None => return,
        };
        let tmp = path.with_extension("tmp");
        if let Err(e) = std::fs::write(&tmp, text) {
            tracing::warn!(error = %e, "crawler: state write failed");
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        if let Err(e) = std::fs::rename(&tmp, path) {
            tracing::warn!(error = %e, "crawler: state rename failed");
        }
    }

    fn snapshot_text(&self) -> Option<String> {
        let state = self.lock();
        let snapshot = PersistedState {
            version: 1,
            updated_at_ms: unix_ms(),
            entries: state
                .entries
                .iter()
                .map(|(addr, e)| {
                    (
                        addr.to_string(),
                        PersistedEntry {
                            learned_via: e.learned_via.clone(),
                            last_attempt_ms: e.last_attempt_ms,
                            next_due_ms: e.next_due_ms,
                            failures: e.failures,
                            successes: e.successes,
                        },
                    )
                })
                .collect(),
        };
        serde_json::to_string(&snapshot).ok()
    }
}

fn load_state(path: &Path) -> Result<PersistedState, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("parse: {e}"))
}

/// Loopback, private, link-local, unspecified, broadcast: undialable from
/// a public vantage, or lab-only.
fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_unicast_link_local(),
    }
}

/// Evict the oldest non-in-flight entry when the frontier is at its cap.
fn bound_evict(state: &mut State, incoming: SocketAddr, cap: usize) {
    if state.entries.len() < cap {
        return;
    }
    while let Some(old) = state.order.pop_front() {
        if state.in_flight.contains(&old) || old == incoming {
            continue;
        }
        state.queue.retain(|a| *a != old);
        state.entries.remove(&old);
        return;
    }
    // Every tracked address is in flight: take the incoming slot anyway,
    // dropping the queue tail. This is unreachable in practice (a frontier
    // of 200k all in flight is far beyond max_peers), but keeps the bound.
    if let Some(tail) = state.queue.pop_back() {
        state.entries.remove(&tail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::{ObserverSink, SinkConfig};

    fn test_sink(dir: &std::path::Path) -> (ObserverSink, std::path::PathBuf) {
        let path = dir.join("crawler.jsonl");
        (
            ObserverSink::spawn(SinkConfig::new(&path, "crawler-test")).unwrap(),
            path,
        )
    }

    fn cfg(dir: &std::path::Path) -> CrawlConfig {
        CrawlConfig {
            dial_rate_per_min: u32::MAX, // ~0 s spacing: rate cap off for tests
            backoff_min: Duration::from_secs(3600),
            backoff_max: Duration::from_secs(7200),
            state_path: Some(dir.join("state.json")),
            ..CrawlConfig::default()
        }
    }

    fn report(via: &str, specs: Vec<&str>) -> GossipReport {
        GossipReport {
            via_id: via.to_string(),
            specs: specs
                .into_iter()
                .map(|s| GossipSpec {
                    addr: s.parse().unwrap(),
                    agent: "ergo".to_string(),
                    version: "6.0.7".to_string(),
                    node_name: "n".to_string(),
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn learn_deduplicates_and_filters_local() {
        let dir = tempfile::tempdir().unwrap();
        let (sink, _) = test_sink(dir.path());
        let state = CrawlState::new(
            cfg(dir.path()),
            sink,
            vec!["93.184.216.34:9030".parse().unwrap()],
        );
        state.learn(report(
            "p1",
            vec!["93.184.216.34:9030", "203.0.113.7:9030", "192.168.1.5:9030"],
        ));
        // Seed + one new public address; the duplicate and the private
        // address are dropped.
        assert_eq!(state.tracked(), 2);
        state.learn(report("p2", vec!["203.0.113.7:9030", "203.0.113.8:9030"]));
        assert_eq!(state.tracked(), 3);
    }

    #[tokio::test]
    async fn learned_local_addresses_are_permitted_with_allow_local() {
        let dir = tempfile::tempdir().unwrap();
        let (sink, _) = test_sink(dir.path());
        let mut c = cfg(dir.path());
        c.allow_local = true;
        let state = CrawlState::new(c, sink, Vec::new());
        state.learn(report("p", vec!["127.0.0.1:9022"]));
        assert_eq!(state.tracked(), 1);
    }

    #[tokio::test]
    async fn global_rate_cap_spaces_dials() {
        let dir = tempfile::tempdir().unwrap();
        let (sink, _) = test_sink(dir.path());
        let mut c = cfg(dir.path());
        c.dial_rate_per_min = 60; // 1 s spacing
        let state = CrawlState::new(c, sink, vec!["93.184.216.34:9030".parse().unwrap()]);
        assert!(state.next_due().is_some());
        assert!(state.next_due().is_none(), "second dial is rate-limited");
    }

    #[tokio::test]
    async fn failures_escalate_backoff_and_success_resets() {
        let dir = tempfile::tempdir().unwrap();
        let (sink, _) = test_sink(dir.path());
        let addr: SocketAddr = "203.0.113.9:9030".parse().unwrap();
        let other: SocketAddr = "203.0.113.10:9030".parse().unwrap();
        let state = CrawlState::new(cfg(dir.path()), sink, vec![addr]);

        assert_eq!(state.next_due(), Some(addr));
        state.note_result(addr, AttemptOutcome::ConnectRefused, Some(5));
        assert_eq!(state.next_due(), None, "failed address is in backoff");

        state.learn(report("p", vec![other.to_string().as_str()]));
        assert_eq!(
            state.next_due(),
            Some(other),
            "other addresses stay dialable"
        );
        state.note_result(other, AttemptOutcome::Handshaken, None);
        assert_eq!(
            state.next_due(),
            Some(other),
            "a handshake resets the address's backoff"
        );
    }

    #[tokio::test]
    async fn state_roundtrips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let (sink, _) = test_sink(dir.path());
        let addr: SocketAddr = "203.0.113.11:9030".parse().unwrap();
        let state = CrawlState::new(cfg(dir.path()), sink, vec![addr]);
        state.note_result(addr, AttemptOutcome::ConnectTimeout, None);
        state.save();

        let state_path = dir.path().join("state.json");
        assert!(state_path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&state_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "state file must stay private");
        }

        let (sink2, _) = test_sink(dir.path());
        let reloaded = CrawlState::new(cfg(dir.path()), sink2, Vec::new());
        assert_eq!(reloaded.tracked(), 1);
        assert_eq!(
            reloaded.next_due(),
            None,
            "persisted backoff survives a restart"
        );
    }

    #[tokio::test]
    async fn frontier_is_bounded_and_evicts_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let (sink, _) = test_sink(dir.path());
        let mut c = cfg(dir.path());
        c.max_tracked = 3;
        let state = CrawlState::new(c, sink, Vec::new());
        state.learn(report(
            "p",
            vec![
                "203.0.113.21:9030",
                "203.0.113.22:9030",
                "203.0.113.23:9030",
            ],
        ));
        assert_eq!(state.tracked(), 3);
        state.learn(report("p", vec!["203.0.113.24:9030"]));
        assert_eq!(state.tracked(), 3, "cap holds; the oldest entry is evicted");
        assert_eq!(
            state.next_due().map(|a| a.to_string()),
            Some("203.0.113.22:9030".to_string()),
            "the evicted address is no longer dialable"
        );
    }

    #[tokio::test]
    async fn crawl_channel_drops_when_full() {
        let (tx, _rx) = CrawlChannel::new(1);
        tx.send(report("p", vec!["203.0.113.31:9030"]));
        // No receiver reads: this must drop, not block.
        tx.send(report("p", vec!["203.0.113.32:9030"]));
    }

    #[tokio::test]
    async fn peer_learned_is_emitted_with_via() {
        let dir = tempfile::tempdir().unwrap();
        let (sink, path) = test_sink(dir.path());
        let state = CrawlState::new(cfg(dir.path()), sink, Vec::new());
        state.learn(report("via-id-123", vec!["203.0.113.41:9030"]));
        // Sink idle flush is 250 ms.
        tokio::time::sleep(Duration::from_millis(400)).await;
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let learned = lines
            .iter()
            .find(|e| e["event"] == "peer_learned")
            .unwrap_or_else(|| panic!("no peer_learned in {lines:?}"));
        assert_eq!(learned["via"], "via-id-123");
        assert_eq!(learned["peer"]["direction"], "crawl");
    }
}
