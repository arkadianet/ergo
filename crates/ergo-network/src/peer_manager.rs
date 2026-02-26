use std::collections::HashMap;
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// PenaltyType
// ---------------------------------------------------------------------------

/// Categories of peer penalties with associated scores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenaltyType {
    /// Peer failed to deliver expected data. Score: 2.
    NonDelivery,
    /// Peer sent invalid or contradictory data. Score: 10.
    Misbehavior,
    /// Peer is sending excessive unsolicited messages. Score: 25.
    Spam,
    /// Permanent ban (e.g. protocol violation). Score: 1_000_000.
    Permanent,
}

impl PenaltyType {
    /// The numeric score for this penalty category.
    pub fn score(self) -> u32 {
        match self {
            PenaltyType::NonDelivery => 2,
            PenaltyType::Misbehavior => 10,
            PenaltyType::Spam => 25,
            PenaltyType::Permanent => 1_000_000,
        }
    }
}

// ---------------------------------------------------------------------------
// PenaltyTracker
// ---------------------------------------------------------------------------

/// Tracks cumulative penalty scores per IP address and determines bans.
pub struct PenaltyTracker {
    scores: HashMap<IpAddr, u32>,
    threshold: u32,
}

impl PenaltyTracker {
    /// Create a new tracker with the default ban threshold of 100.
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
            threshold: 100,
        }
    }

    /// Add a penalty to the given IP address.
    pub fn add_penalty(&mut self, addr: &IpAddr, penalty: PenaltyType) {
        let entry = self.scores.entry(*addr).or_insert(0);
        *entry = entry.saturating_add(penalty.score());
    }

    /// Get the current penalty score for an IP address (0 if unknown).
    pub fn score(&self, addr: &IpAddr) -> u32 {
        self.scores.get(addr).copied().unwrap_or(0)
    }

    /// Returns `true` if the IP's cumulative score meets or exceeds the ban
    /// threshold.
    pub fn is_banned(&self, addr: &IpAddr) -> bool {
        self.score(addr) >= self.threshold
    }
}

impl Default for PenaltyTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn penalty_score_increments() {
        let mut tracker = PenaltyTracker::new();
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        tracker.add_penalty(&addr, PenaltyType::NonDelivery);
        assert_eq!(tracker.score(&addr), 2);
        tracker.add_penalty(&addr, PenaltyType::Misbehavior);
        assert_eq!(tracker.score(&addr), 12);
    }

    #[test]
    fn penalty_threshold_bans() {
        let mut tracker = PenaltyTracker::new();
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..10 {
            tracker.add_penalty(&addr, PenaltyType::Misbehavior);
        }
        assert!(tracker.is_banned(&addr));
    }

    #[test]
    fn permanent_penalty_bans_immediately() {
        let mut tracker = PenaltyTracker::new();
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        tracker.add_penalty(&addr, PenaltyType::Permanent);
        assert!(tracker.is_banned(&addr));
    }

    #[test]
    fn unknown_addr_score_is_zero() {
        let tracker = PenaltyTracker::new();
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(tracker.score(&addr), 0);
        assert!(!tracker.is_banned(&addr));
    }

    #[test]
    fn below_threshold_not_banned() {
        let mut tracker = PenaltyTracker::new();
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        // 9 * 10 = 90, below the 100 threshold
        for _ in 0..9 {
            tracker.add_penalty(&addr, PenaltyType::Misbehavior);
        }
        assert_eq!(tracker.score(&addr), 90);
        assert!(!tracker.is_banned(&addr));
    }

    #[test]
    fn spam_penalty_score() {
        let mut tracker = PenaltyTracker::new();
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        tracker.add_penalty(&addr, PenaltyType::Spam);
        assert_eq!(tracker.score(&addr), 25);
    }

    #[test]
    fn default_trait() {
        let tracker = PenaltyTracker::default();
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(tracker.score(&addr), 0);
    }
}
