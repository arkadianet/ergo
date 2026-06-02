//! Peer state machine and scoring model.
//!
//! Each connected peer transitions through states:
//!   Connecting → Handshaking → Active → Degraded → Banned/Disconnected
//!
//! Scoring uses penalty accumulation with time decay [proposed]:
//! - Degraded at score ≥ 50 (rate-limited, deprioritized)
//! - Temp ban at score > 500 (disconnect, escalating ban duration)
//! - Score decays 10 points per 10 minutes
//!
//! Normal penalty scores and the ban threshold match Scala. Non-delivery
//! during IBD is common enough that making it harsher collapses the peer
//! pool under ordinary slow-peer churn.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::handshake::{PeerSpec, Version};

// ---- Constants ----

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
pub const INACTIVE_TIMEOUT: Duration = Duration::from_secs(600); // 10 min
pub const SAFE_INTERVAL: Duration = Duration::from_secs(120); // 2 min between penalties

pub const DEGRADED_THRESHOLD: i32 = 50;
pub const BAN_THRESHOLD: i32 = 500;
pub const SCORE_DECAY_PER_INTERVAL: i32 = 10;
pub const SCORE_DECAY_INTERVAL: Duration = Duration::from_secs(600); // 10 min

/// Minimum peer version for interop (peers below this get a 1-year ban
/// via [`PeerScore::apply_permanent_ban`] — historically named "permanent"
/// but the actual expiry is one year, not forever).
pub const MIN_PEER_VERSION: Version = Version::EIP37_FORK;

/// Version threshold for sync V2 support.
pub const SYNC_V2_MIN_VERSION: Version = Version {
    major: 4,
    minor: 0,
    patch: 16,
};

// ---- Types ----

/// Unique peer identifier (socket address).
pub type PeerId = SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncVersion {
    V1,
    V2,
}

impl SyncVersion {
    pub fn for_peer(version: &Version) -> Self {
        if *version >= SYNC_V2_MIN_VERSION {
            SyncVersion::V2
        } else {
            SyncVersion::V1
        }
    }
}

// ---- Penalty model ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Penalty {
    /// Protocol violation, invalid data. +10
    Misbehavior,
    /// Timeout, no response. +2
    NonDelivery,
    /// Repeated invalid data, unsolicited modifiers. +25
    Spam,
    /// Cryptographically definitive misbehavior — bad signature, version
    /// below the supported floor, etc. Score matches Scala
    /// `PermanentPenalty.penaltyScore = 1_000_000_000`; applied immediately,
    /// bypasses the safe-interval rule, jumps directly to the
    /// year-long ban.
    Permanent,
}

impl Penalty {
    pub fn score(self) -> i32 {
        match self {
            Penalty::Misbehavior => 10,
            Penalty::NonDelivery => 2,
            Penalty::Spam => 25,
            Penalty::Permanent => 1_000_000_000,
        }
    }

    /// `true` for penalties Scala flags as `isPermanent`. Bypasses the
    /// safe-interval gate and goes straight to the permanent-ban path.
    pub fn is_permanent(self) -> bool {
        matches!(self, Penalty::Permanent)
    }
}

// ---- Peer score ----

#[derive(Debug, Clone)]
pub struct PeerScore {
    value: i32,
    last_penalty: Option<Instant>,
    last_decay: Instant,
    ban_count: u32,
    banned_until: Option<Instant>,
}

impl PeerScore {
    pub fn new(now: Instant) -> Self {
        Self {
            value: 0,
            last_penalty: None,
            last_decay: now,
            ban_count: 0,
            banned_until: None,
        }
    }

    /// Current effective score after time decay.
    pub fn effective_score(&self, now: Instant) -> i32 {
        let elapsed = now.duration_since(self.last_decay);
        let decay_intervals = elapsed.as_secs() / SCORE_DECAY_INTERVAL.as_secs();
        let decay = (decay_intervals as i32) * SCORE_DECAY_PER_INTERVAL;
        (self.value - decay).max(0)
    }

    /// Apply a penalty. Returns the new effective score.
    /// Respects the safe interval: penalties within 2 minutes of the last
    /// penalty are accepted but don't stack (the higher penalty wins).
    /// Permanent penalties bypass the safe interval — Scala's
    /// `PeerDatabase.penalize` does `applyPenalty = ... || isPermanent`.
    pub fn apply_penalty(&mut self, penalty: Penalty, now: Instant) -> i32 {
        // Apply pending decay first
        let elapsed = now.duration_since(self.last_decay);
        let decay_intervals = elapsed.as_secs() / SCORE_DECAY_INTERVAL.as_secs();
        if decay_intervals > 0 {
            let decay = (decay_intervals as i32) * SCORE_DECAY_PER_INTERVAL;
            self.value = (self.value - decay).max(0);
            self.last_decay += SCORE_DECAY_INTERVAL * decay_intervals as u32;
        }

        if penalty.is_permanent() {
            self.value = self.value.saturating_add(penalty.score());
            self.last_penalty = Some(now);
            return self.value;
        }

        // Check safe interval
        if let Some(last) = self.last_penalty {
            if now.duration_since(last) < SAFE_INTERVAL {
                // Within safe interval — don't stack, but update if higher
                self.value = self.value.max(penalty.score());
                return self.value;
            }
        }

        self.value += penalty.score();
        self.last_penalty = Some(now);
        self.value
    }

    /// Whether the peer should be in degraded state.
    pub fn is_degraded(&self, now: Instant) -> bool {
        let score = self.effective_score(now);
        (DEGRADED_THRESHOLD..BAN_THRESHOLD).contains(&score)
    }

    /// Whether the peer should be banned.
    pub fn should_ban(&self, now: Instant) -> bool {
        self.effective_score(now) > BAN_THRESHOLD
    }

    /// Whether the peer is currently banned (ban hasn't expired).
    pub fn is_banned(&self, now: Instant) -> bool {
        self.banned_until.is_some_and(|until| now < until)
    }

    /// Apply a ban with escalating duration: 30min → 2hr → 24hr → 7d.
    pub fn apply_ban(&mut self, now: Instant) {
        let duration = match self.ban_count {
            0 => Duration::from_secs(30 * 60),          // 30 min
            1 => Duration::from_secs(2 * 60 * 60),      // 2 hr
            2 => Duration::from_secs(24 * 60 * 60),     // 24 hr
            _ => Duration::from_secs(7 * 24 * 60 * 60), // 7 days (cap)
        };
        self.banned_until = Some(now + duration);
        self.ban_count += 1;
    }

    /// Mark as effectively permanently banned (1-year expiry; for version < EIP37).
    pub fn apply_permanent_ban(&mut self) {
        self.banned_until = Some(Instant::now() + Duration::from_secs(365 * 24 * 60 * 60));
        self.ban_count = u32::MAX;
    }

    pub fn raw_score(&self) -> i32 {
        self.value
    }
    pub fn ban_count(&self) -> u32 {
        self.ban_count
    }
    pub fn ban_expiry(&self) -> Option<Instant> {
        self.banned_until
    }
}

// ---- Connection state ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Handshaking,
    Active,
    Degraded,
    Disconnected,
}

// ---- PeerInfo ----

/// Full info about a connected or recently-connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: PeerId,
    pub direction: Direction,
    pub state: ConnectionState,
    pub score: PeerScore,
    pub connected_at: Instant,
    pub last_seen: Instant,
    /// Populated after handshake completes.
    pub peer_spec: Option<PeerSpec>,
    /// Determined from peer_spec.version after handshake.
    pub sync_version: SyncVersion,
    /// Post-handshake framed-message bytes received from / sent to this
    /// peer (per-frame header+checksum+payload; handshake bytes precede
    /// `peer_task` owning the connection and are not counted). Shared
    /// `Arc` so the per-peer I/O task increments lock-free while the
    /// action loop reads via the accessors. A `PeerInfo` clone SHARES
    /// these counters by design — the snapshot path only ever reads
    /// `&PeerInfo`. Read-only telemetry; never fed into scoring/throttle.
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
}

impl PeerInfo {
    pub fn new_outbound(addr: PeerId, now: Instant) -> Self {
        Self {
            addr,
            direction: Direction::Outbound,
            state: ConnectionState::Connecting,
            score: PeerScore::new(now),
            connected_at: now,
            last_seen: now,
            peer_spec: None,
            sync_version: SyncVersion::V2, // default until handshake
            bytes_in: Arc::new(AtomicU64::new(0)),
            bytes_out: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn new_inbound(addr: PeerId, now: Instant) -> Self {
        Self {
            addr,
            direction: Direction::Inbound,
            // The TCP `accept()` already completed before the action loop
            // got the stream, so this peer is past the Connecting phase
            // — start in Handshaking so `evict_timed_out` uses the 30s
            // HANDSHAKE_TIMEOUT (not the 5s CONNECT_TIMEOUT) while
            // `accept_task` exchanges handshake bytes.
            state: ConnectionState::Handshaking,
            score: PeerScore::new(now),
            connected_at: now,
            last_seen: now,
            peer_spec: None,
            sync_version: SyncVersion::V2,
            bytes_in: Arc::new(AtomicU64::new(0)),
            bytes_out: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Handles to this peer's byte counters for the per-peer I/O task to
    /// increment after each successful framed read/write — `(in, out)`.
    pub fn byte_counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
        (Arc::clone(&self.bytes_in), Arc::clone(&self.bytes_out))
    }

    /// Cumulative post-handshake framed bytes received from this peer.
    pub fn bytes_in(&self) -> u64 {
        self.bytes_in.load(Ordering::Relaxed)
    }

    /// Cumulative post-handshake framed bytes sent to this peer.
    pub fn bytes_out(&self) -> u64 {
        self.bytes_out.load(Ordering::Relaxed)
    }

    /// Transition to handshaking state (TCP established).
    pub fn mark_tcp_connected(&mut self) {
        if self.state == ConnectionState::Connecting {
            self.state = ConnectionState::Handshaking;
        }
    }

    /// Complete handshake. Returns Err if peer version is below minimum.
    pub fn complete_handshake(
        &mut self,
        spec: PeerSpec,
        now: Instant,
    ) -> Result<(), PeerRejectReason> {
        if spec.version < MIN_PEER_VERSION {
            self.score.apply_permanent_ban();
            self.state = ConnectionState::Disconnected;
            return Err(PeerRejectReason::VersionTooOld(spec.version));
        }
        self.sync_version = SyncVersion::for_peer(&spec.version);
        self.peer_spec = Some(spec);
        self.state = ConnectionState::Active;
        self.last_seen = now;
        Ok(())
    }

    /// Apply a penalty and update state accordingly. Permanent penalties
    /// skip score accumulation and route straight to the year-long ban
    /// (`apply_permanent_ban`), matching Scala's
    /// `addToBlacklist(... PermanentPenalty)` which uses
    /// `(360 * 10).days`; we cap at one year as a [proposed] divergence
    /// since at that horizon "banned" is operationally indistinguishable
    /// from "forever" and the address-book ban record stays bounded.
    pub fn penalize(&mut self, penalty: Penalty, now: Instant) -> PenaltyOutcome {
        if penalty.is_permanent() {
            self.score.apply_permanent_ban();
            self.state = ConnectionState::Disconnected;
            return PenaltyOutcome::Banned;
        }
        let new_score = self.score.apply_penalty(penalty, now);
        if self.score.should_ban(now) {
            self.score.apply_ban(now);
            self.state = ConnectionState::Disconnected;
            PenaltyOutcome::Banned
        } else if new_score >= DEGRADED_THRESHOLD {
            self.state = ConnectionState::Degraded;
            PenaltyOutcome::Degraded
        } else {
            PenaltyOutcome::Ok
        }
    }

    /// Mark peer as seen (received valid message).
    pub fn touch(&mut self, now: Instant) {
        self.last_seen = now;
    }

    /// Check if connection has timed out based on current state.
    pub fn is_timed_out(&self, now: Instant) -> bool {
        match self.state {
            ConnectionState::Connecting => now.duration_since(self.connected_at) > CONNECT_TIMEOUT,
            ConnectionState::Handshaking => {
                now.duration_since(self.connected_at) > HANDSHAKE_TIMEOUT
            }
            ConnectionState::Active | ConnectionState::Degraded => {
                now.duration_since(self.last_seen) > INACTIVE_TIMEOUT
            }
            ConnectionState::Disconnected => false,
        }
    }

    /// Whether this peer is usable for requests (active or degraded).
    pub fn is_connected(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Active | ConnectionState::Degraded
        )
    }

    /// IPv4 /16 subnet (first 2 octets). Returns None for non-IPv4.
    pub fn subnet(&self) -> Option<[u8; 2]> {
        match self.addr.ip() {
            std::net::IpAddr::V4(ip) => {
                let octets = ip.octets();
                Some([octets[0], octets[1]])
            }
            std::net::IpAddr::V6(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerRejectReason {
    VersionTooOld(Version),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenaltyOutcome {
    Ok,
    Degraded,
    Banned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> PeerId {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
    }

    #[test]
    fn peer_info_byte_counters_accumulate_and_share_on_clone() {
        use std::sync::atomic::Ordering::Relaxed;
        let p = PeerInfo::new_outbound(test_addr(9030), Instant::now());
        assert_eq!(p.bytes_in(), 0);
        assert_eq!(p.bytes_out(), 0);

        // The per-peer I/O task increments through the shared handles.
        let (cin, cout) = p.byte_counters();
        cin.fetch_add(100, Relaxed);
        cin.fetch_add(50, Relaxed);
        cout.fetch_add(25, Relaxed);
        assert_eq!(p.bytes_in(), 150);
        assert_eq!(p.bytes_out(), 25);

        // A clone SHARES the counters by design (Arc): the snapshot path
        // only ever reads `&PeerInfo`, so this aliasing is intentional.
        let q = p.clone();
        cin.fetch_add(10, Relaxed);
        assert_eq!(q.bytes_in(), 160);
    }

    #[test]
    fn new_peer_info_has_independent_zeroed_counters() {
        use std::sync::atomic::Ordering::Relaxed;
        // A reconnect on the same addr builds a fresh PeerInfo via
        // `new_outbound`; its counters start at zero and do NOT alias the
        // previous session's Arcs (no bleed across disconnect/reconnect).
        let prev = PeerInfo::new_outbound(test_addr(9030), Instant::now());
        let (prev_in, _) = prev.byte_counters();
        prev_in.fetch_add(500, Relaxed);
        assert_eq!(prev.bytes_in(), 500);

        let fresh = PeerInfo::new_outbound(test_addr(9030), Instant::now());
        assert_eq!(fresh.bytes_in(), 0, "reconnect must start at zero");
        // Bumping the old session's handle must not touch the new session.
        prev_in.fetch_add(1, Relaxed);
        assert_eq!(fresh.bytes_in(), 0);
        assert_eq!(prev.bytes_in(), 501);
    }

    fn test_spec(version: Version) -> PeerSpec {
        PeerSpec {
            agent_name: "test".into(),
            version,
            node_name: "node".into(),
            declared_address: None,
            features: Vec::new(),
        }
    }

    #[test]
    fn score_starts_at_zero() {
        let now = Instant::now();
        let score = PeerScore::new(now);
        assert_eq!(score.effective_score(now), 0);
    }

    #[test]
    fn penalty_increases_score() {
        let now = Instant::now();
        let mut score = PeerScore::new(now);
        score.apply_penalty(Penalty::Misbehavior, now);
        assert_eq!(score.effective_score(now), 10);
        // After safe interval
        let later = now + SAFE_INTERVAL;
        score.apply_penalty(Penalty::Spam, later);
        assert_eq!(score.effective_score(later), 35); // 10 + 25
    }

    #[test]
    fn penalty_within_safe_interval_does_not_stack() {
        let now = Instant::now();
        let mut score = PeerScore::new(now);
        score.apply_penalty(Penalty::Misbehavior, now); // +10
                                                        // Within safe interval — should not stack
        let soon = now + Duration::from_secs(60);
        score.apply_penalty(Penalty::NonDelivery, soon); // +2 within safe interval
                                                         // NonDelivery(2) is below Misbehavior(10), so score stays.
        assert_eq!(score.effective_score(soon), 10);
    }

    #[test]
    fn score_decays_over_time() {
        let now = Instant::now();
        let mut score = PeerScore::new(now);
        score.apply_penalty(Penalty::Spam, now); // +25
        assert_eq!(score.effective_score(now), 25);
        // After 10 minutes, score decays by 10
        let later = now + SCORE_DECAY_INTERVAL;
        assert_eq!(score.effective_score(later), 15);
        // After 30 minutes, score decays by 30 (but floors at 0)
        let much_later = now + SCORE_DECAY_INTERVAL * 3;
        assert_eq!(score.effective_score(much_later), 0);
    }

    #[test]
    fn degraded_threshold() {
        let now = Instant::now();
        let mut score = PeerScore::new(now);
        // Apply 3 spam penalties (+25 each = 75 before decay) at safe interval.
        // At 6 min total, no decay interval has passed, so score = 75.
        let mut t = now;
        for _ in 0..3 {
            t += SAFE_INTERVAL;
            score.apply_penalty(Penalty::Spam, t);
        }
        assert!(
            score.is_degraded(t),
            "score {} should be >= {DEGRADED_THRESHOLD}",
            score.effective_score(t)
        );
        assert!(!score.should_ban(t));
    }

    #[test]
    fn ban_threshold_and_escalation() {
        let now = Instant::now();
        let mut score = PeerScore::new(now);
        let mut t = now;
        // Push score above Scala's 500-point ban threshold with spam penalties (+25 each).
        // At safe interval of 2min, decay kicks in at 10min intervals (-10).
        for _ in 0..25 {
            t += SAFE_INTERVAL;
            score.apply_penalty(Penalty::Spam, t);
        }
        assert!(
            score.should_ban(t),
            "score {} should be >= {BAN_THRESHOLD}",
            score.effective_score(t)
        );

        // First ban: 30 minutes
        score.apply_ban(t);
        assert!(score.is_banned(t));
        assert!(!score.is_banned(t + Duration::from_secs(31 * 60)));
        assert_eq!(score.ban_count(), 1);

        // Second ban: 2 hours
        score.apply_ban(t);
        assert_eq!(score.ban_count(), 2);
    }

    #[test]
    fn handshake_rejects_old_version() {
        let now = Instant::now();
        let mut peer = PeerInfo::new_outbound(test_addr(9030), now);
        peer.mark_tcp_connected();
        let old_spec = test_spec(Version {
            major: 3,
            minor: 0,
            patch: 0,
        });
        let result = peer.complete_handshake(old_spec, now);
        assert!(matches!(result, Err(PeerRejectReason::VersionTooOld(_))));
        assert_eq!(peer.state, ConnectionState::Disconnected);
        assert!(peer.score.is_banned(now));
    }

    #[test]
    fn handshake_accepts_current_version() {
        let now = Instant::now();
        let mut peer = PeerInfo::new_outbound(test_addr(9030), now);
        peer.mark_tcp_connected();
        let spec = test_spec(Version::NIPOPOW);
        peer.complete_handshake(spec, now).unwrap();
        assert_eq!(peer.state, ConnectionState::Active);
        assert_eq!(peer.sync_version, SyncVersion::V2);
    }

    /// Pin both sides of the version floor at 4.0.100 (EIP-37). Scala's
    /// `MinAgentVersion` is the same boundary; a refactor that flips
    /// the comparison or shifts the constant gets caught here.
    #[test]
    fn version_floor_boundary() {
        assert_eq!(MIN_PEER_VERSION, Version::EIP37_FORK);
        assert_eq!(MIN_PEER_VERSION.major, 4);
        assert_eq!(MIN_PEER_VERSION.minor, 0);
        assert_eq!(MIN_PEER_VERSION.patch, 100);

        let now = Instant::now();

        // Exact floor: 4.0.100 must be accepted.
        let mut peer_at = PeerInfo::new_outbound(test_addr(9030), now);
        peer_at.mark_tcp_connected();
        peer_at
            .complete_handshake(test_spec(Version::EIP37_FORK), now)
            .unwrap();
        assert_eq!(peer_at.state, ConnectionState::Active);

        // One below: 4.0.99 must be rejected.
        let mut peer_below = PeerInfo::new_outbound(test_addr(9031), now);
        peer_below.mark_tcp_connected();
        let below = test_spec(Version {
            major: 4,
            minor: 0,
            patch: 99,
        });
        let result = peer_below.complete_handshake(below, now);
        assert!(matches!(result, Err(PeerRejectReason::VersionTooOld(_))));
    }

    #[test]
    fn sync_version_gating() {
        // Pre-4.0.16 gets V1
        assert_eq!(
            SyncVersion::for_peer(&Version {
                major: 4,
                minor: 0,
                patch: 15
            }),
            SyncVersion::V1
        );
        // Exactly 4.0.16 gets V2
        assert_eq!(
            SyncVersion::for_peer(&Version {
                major: 4,
                minor: 0,
                patch: 16
            }),
            SyncVersion::V2
        );
        // 5.0.13 gets V2
        assert_eq!(SyncVersion::for_peer(&Version::NIPOPOW), SyncVersion::V2);
    }

    #[test]
    fn connection_timeouts() {
        let now = Instant::now();
        let peer = PeerInfo::new_outbound(test_addr(9030), now);
        assert!(!peer.is_timed_out(now));
        assert!(peer.is_timed_out(now + CONNECT_TIMEOUT + Duration::from_secs(1)));
    }

    #[test]
    fn penalize_transitions_to_degraded_then_banned() {
        let now = Instant::now();
        let mut peer = PeerInfo::new_outbound(test_addr(9030), now);
        peer.mark_tcp_connected();
        peer.complete_handshake(test_spec(Version::NIPOPOW), now)
            .unwrap();

        let mut t = now;
        // Apply 3 spam penalties (+25 each = 75 before decay) → degraded
        for _ in 0..3 {
            t += SAFE_INTERVAL;
            peer.penalize(Penalty::Spam, t);
        }
        assert_eq!(
            peer.state,
            ConnectionState::Degraded,
            "score {} should trigger degraded",
            peer.score.effective_score(t)
        );

        // Keep applying spam until the Scala-parity ban threshold.
        for _ in 0..25 {
            t += SAFE_INTERVAL;
            peer.penalize(Penalty::Spam, t);
        }
        assert_eq!(peer.state, ConnectionState::Disconnected);
        assert!(peer.score.is_banned(t));
    }

    /// Pin per-type penalty scores to the Scala source of truth in
    /// `org.ergoplatform.network.peer.PenaltyType`. Drift here means a
    /// peer that misbehaves against us is judged on different terms
    /// than the same misbehavior against a Scala peer — operators
    /// looking at cross-implementation ban logs see asymmetric counts
    /// that don't reflect a real protocol difference.
    #[test]
    fn penalty_scores_match_scala() {
        assert_eq!(Penalty::NonDelivery.score(), 2);
        assert_eq!(Penalty::Misbehavior.score(), 10);
        assert_eq!(Penalty::Spam.score(), 25);
        assert_eq!(Penalty::Permanent.score(), 1_000_000_000);
        assert!(Penalty::Permanent.is_permanent());
        assert!(!Penalty::Misbehavior.is_permanent());
        assert!(!Penalty::NonDelivery.is_permanent());
        assert!(!Penalty::Spam.is_permanent());
    }

    #[test]
    fn permanent_penalty_bans_immediately() {
        let now = Instant::now();
        let mut peer = PeerInfo::new_outbound(test_addr(9030), now);
        peer.mark_tcp_connected();
        peer.complete_handshake(test_spec(Version::NIPOPOW), now)
            .unwrap();
        let outcome = peer.penalize(Penalty::Permanent, now);
        assert_eq!(outcome, PenaltyOutcome::Banned);
        assert_eq!(peer.state, ConnectionState::Disconnected);
        assert!(peer.score.is_banned(now));
    }

    #[test]
    fn permanent_penalty_bypasses_safe_interval() {
        // A non-permanent penalty within SAFE_INTERVAL of a prior one
        // doesn't stack (the higher wins). Permanent must bypass that
        // gate per Scala `PeerDatabase.penalize`.
        let now = Instant::now();
        let mut score = PeerScore::new(now);
        score.apply_penalty(Penalty::Misbehavior, now); // +10
        let soon = now + Duration::from_secs(30); // inside SAFE_INTERVAL
        let after = score.apply_penalty(Penalty::Permanent, soon);
        assert!(
            after >= Penalty::Permanent.score(),
            "permanent must accumulate even inside SAFE_INTERVAL, got {after}",
        );
    }

    #[test]
    fn subnet_extraction() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 9030);
        let peer = PeerInfo::new_outbound(addr, Instant::now());
        assert_eq!(peer.subnet(), Some([192, 168]));
    }
}
