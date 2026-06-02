//! Per-peer throughput limiter.
//!
//! Caps each peer at **100 msgs/sec and 2 MB/sec**, measured over a
//! 10-second sliding window. This module is the single source of
//! truth; callers (peer_loop on the read side) consult it before
//! admitting a frame.
//!
//! The limiter is pure state — no I/O, no async — and takes `now` as
//! a parameter so tests drive it deterministically. Production passes
//! `Instant::now()`.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Configuration. Defaults to 100 msg/sec and 2 MB/sec averaged over a
/// 10-second window.
#[derive(Debug, Clone, Copy)]
pub struct ThroughputLimits {
    /// Sliding-window length the limiter measures over.
    pub window: Duration,
    /// Maximum messages the peer may send per `window`.
    pub max_msgs_per_window: u32,
    /// Maximum bytes the peer may send per `window`.
    pub max_bytes_per_window: u64,
}

impl Default for ThroughputLimits {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(10),
            max_msgs_per_window: 1_000,       // 100 msg/sec × 10s
            max_bytes_per_window: 20_000_000, // 2 MB/sec × 10s
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimiterVerdict {
    /// Frame admitted and recorded.
    Ok,
    /// Message count in the window would exceed `max_msgs_per_window`.
    /// Frame is NOT recorded; caller drops + penalizes.
    MessageRateExceeded,
    /// Byte count in the window would exceed `max_bytes_per_window`.
    /// Frame is NOT recorded; caller drops + penalizes.
    ByteRateExceeded,
}

#[derive(Debug, Clone, Copy)]
struct Event {
    at: Instant,
    bytes: u32,
}

/// Per-peer sliding-window counters.
#[derive(Debug, Default)]
struct PeerState {
    events: VecDeque<Event>,
    msgs_in_window: u32,
    bytes_in_window: u64,
}

impl PeerState {
    fn prune(&mut self, now: Instant, window: Duration) {
        let cutoff = now.checked_sub(window);
        if let Some(cutoff) = cutoff {
            while let Some(front) = self.events.front().copied() {
                if front.at >= cutoff {
                    break;
                }
                self.events.pop_front();
                self.msgs_in_window = self.msgs_in_window.saturating_sub(1);
                self.bytes_in_window = self.bytes_in_window.saturating_sub(front.bytes as u64);
            }
        }
    }

    fn record(&mut self, at: Instant, bytes: u32) {
        self.events.push_back(Event { at, bytes });
        self.msgs_in_window = self.msgs_in_window.saturating_add(1);
        self.bytes_in_window = self.bytes_in_window.saturating_add(bytes as u64);
    }
}

/// Central limiter. One instance per node; peer_loop consults it on
/// every inbound frame. O(1) amortized per check thanks to FIFO
/// pruning.
pub struct ThroughputLimiter {
    limits: ThroughputLimits,
    peers: HashMap<SocketAddr, PeerState>,
}

impl ThroughputLimiter {
    pub fn new(limits: ThroughputLimits) -> Self {
        Self {
            limits,
            peers: HashMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(ThroughputLimits::default())
    }

    pub fn limits(&self) -> ThroughputLimits {
        self.limits
    }

    /// Check whether a frame of `bytes` bytes from `peer` can be
    /// admitted at time `now`. If the verdict is `Ok`, the frame has
    /// been recorded against the window; otherwise state is untouched.
    pub fn check_and_record(
        &mut self,
        peer: SocketAddr,
        now: Instant,
        bytes: u32,
    ) -> LimiterVerdict {
        let state = self.peers.entry(peer).or_default();
        state.prune(now, self.limits.window);

        // Would admitting push us over either cap?
        if state.msgs_in_window >= self.limits.max_msgs_per_window {
            return LimiterVerdict::MessageRateExceeded;
        }
        let next_bytes = state.bytes_in_window.saturating_add(bytes as u64);
        if next_bytes > self.limits.max_bytes_per_window {
            return LimiterVerdict::ByteRateExceeded;
        }

        state.record(now, bytes);
        LimiterVerdict::Ok
    }

    /// Drop per-peer state on disconnect. Frees the per-peer
    /// bookkeeping; over-limit peers that reconnect start fresh. Note
    /// the limiter does NOT enforce reconnect cooldowns — that's the
    /// job of `peer_manager`'s ban escalation.
    pub fn forget_peer(&mut self, peer: &SocketAddr) {
        self.peers.remove(peer);
    }

    /// Test helper: current message count in the window for a peer.
    #[cfg(test)]
    fn msgs_in_window(&self, peer: &SocketAddr) -> u32 {
        self.peers.get(peer).map(|s| s.msgs_in_window).unwrap_or(0)
    }

    /// Test helper: current byte count in the window for a peer.
    #[cfg(test)]
    fn bytes_in_window(&self, peer: &SocketAddr) -> u64 {
        self.peers.get(peer).map(|s| s.bytes_in_window).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn tight_limits() -> ThroughputLimits {
        // Small caps so tests don't need to enqueue thousands of
        // events.
        ThroughputLimits {
            window: Duration::from_secs(10),
            max_msgs_per_window: 3,
            max_bytes_per_window: 300,
        }
    }

    #[test]
    fn first_check_on_unseen_peer_passes() {
        let mut l = ThroughputLimiter::new(tight_limits());
        let now = Instant::now();
        assert_eq!(l.check_and_record(peer(1), now, 50), LimiterVerdict::Ok);
        assert_eq!(l.msgs_in_window(&peer(1)), 1);
        assert_eq!(l.bytes_in_window(&peer(1)), 50);
    }

    #[test]
    fn at_limit_admits_then_rejects() {
        let mut l = ThroughputLimiter::new(tight_limits());
        let now = Instant::now();
        let p = peer(1);
        // 3 messages: each 50 bytes, total 150 — under both caps.
        assert_eq!(l.check_and_record(p, now, 50), LimiterVerdict::Ok);
        assert_eq!(l.check_and_record(p, now, 50), LimiterVerdict::Ok);
        assert_eq!(l.check_and_record(p, now, 50), LimiterVerdict::Ok);
        // 4th would push msg count over cap=3.
        assert_eq!(
            l.check_and_record(p, now, 50),
            LimiterVerdict::MessageRateExceeded
        );
        // Over-limit frame NOT recorded.
        assert_eq!(l.msgs_in_window(&p), 3);
    }

    #[test]
    fn byte_cap_enforced_independently_of_msg_cap() {
        let limits = ThroughputLimits {
            window: Duration::from_secs(10),
            max_msgs_per_window: 100,
            max_bytes_per_window: 200,
        };
        let mut l = ThroughputLimiter::new(limits);
        let now = Instant::now();
        let p = peer(1);
        assert_eq!(l.check_and_record(p, now, 100), LimiterVerdict::Ok);
        assert_eq!(l.check_and_record(p, now, 100), LimiterVerdict::Ok);
        // 3rd frame of 100 bytes would push bytes_in_window to 300 > 200.
        assert_eq!(
            l.check_and_record(p, now, 100),
            LimiterVerdict::ByteRateExceeded
        );
        assert_eq!(l.bytes_in_window(&p), 200);
    }

    #[test]
    fn cross_peer_isolation() {
        let mut l = ThroughputLimiter::new(tight_limits());
        let now = Instant::now();
        // Exhaust peer 1.
        for _ in 0..3 {
            let _ = l.check_and_record(peer(1), now, 50);
        }
        assert_eq!(
            l.check_and_record(peer(1), now, 50),
            LimiterVerdict::MessageRateExceeded
        );
        // Peer 2 unaffected.
        assert_eq!(l.check_and_record(peer(2), now, 50), LimiterVerdict::Ok);
    }

    #[test]
    fn window_slide_drops_old_events() {
        let mut l = ThroughputLimiter::new(tight_limits());
        let t0 = Instant::now();
        let p = peer(1);
        for _ in 0..3 {
            let _ = l.check_and_record(p, t0, 50);
        }
        assert_eq!(l.msgs_in_window(&p), 3);
        // 11 s later all three events should be outside the 10 s
        // window.
        let later = t0 + Duration::from_secs(11);
        assert_eq!(l.check_and_record(p, later, 50), LimiterVerdict::Ok);
        // Only the freshly-recorded event remains.
        assert_eq!(l.msgs_in_window(&p), 1);
        assert_eq!(l.bytes_in_window(&p), 50);
    }

    #[test]
    fn partial_window_slide_reclaims_some_budget() {
        let mut l = ThroughputLimiter::new(tight_limits());
        let t0 = Instant::now();
        let p = peer(1);
        // 2 events at t0.
        for _ in 0..2 {
            let _ = l.check_and_record(p, t0, 50);
        }
        // 1 event at t0+5s.
        let t_mid = t0 + Duration::from_secs(5);
        let _ = l.check_and_record(p, t_mid, 50);
        // At t0+11s, the two t0 events fall out but the mid-event
        // remains, so budget allows two more messages.
        let now = t0 + Duration::from_secs(11);
        assert_eq!(l.check_and_record(p, now, 50), LimiterVerdict::Ok);
        assert_eq!(l.check_and_record(p, now, 50), LimiterVerdict::Ok);
        assert_eq!(
            l.check_and_record(p, now, 50),
            LimiterVerdict::MessageRateExceeded
        );
    }

    #[test]
    fn forget_peer_clears_state() {
        let mut l = ThroughputLimiter::new(tight_limits());
        let now = Instant::now();
        let p = peer(1);
        for _ in 0..3 {
            let _ = l.check_and_record(p, now, 50);
        }
        l.forget_peer(&p);
        // New budget — full quota available again.
        assert_eq!(l.check_and_record(p, now, 50), LimiterVerdict::Ok);
        assert_eq!(l.msgs_in_window(&p), 1);
    }

    #[test]
    fn overlimit_frame_does_not_push_further_state() {
        // A rejected check must not mutate counters — repeat calls
        // observe the same state.
        let mut l = ThroughputLimiter::new(tight_limits());
        let now = Instant::now();
        let p = peer(1);
        for _ in 0..3 {
            let _ = l.check_and_record(p, now, 50);
        }
        let before_msgs = l.msgs_in_window(&p);
        let before_bytes = l.bytes_in_window(&p);
        for _ in 0..5 {
            let v = l.check_and_record(p, now, 50);
            assert!(matches!(v, LimiterVerdict::MessageRateExceeded));
        }
        assert_eq!(l.msgs_in_window(&p), before_msgs);
        assert_eq!(l.bytes_in_window(&p), before_bytes);
    }

    #[test]
    fn default_limits_match_spec() {
        let l = ThroughputLimits::default();
        assert_eq!(l.window, Duration::from_secs(10));
        assert_eq!(l.max_msgs_per_window, 1_000); // 100 × 10
        assert_eq!(l.max_bytes_per_window, 20_000_000); // 2 MB × 10
    }
}
