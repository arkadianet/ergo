use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::connection_pool::PeerId;

/// Types of penalties with different severity weights.
#[derive(Debug, Clone, Copy)]
pub enum PenaltyType {
    InvalidHeader,
    InvalidBlock,
    InvalidTransaction,
    SpamMessage,
    DeliveryTimeout,
}

impl PenaltyType {
    pub fn weight(self) -> u32 {
        match self {
            PenaltyType::InvalidHeader => 100,
            PenaltyType::InvalidBlock => 100,
            PenaltyType::InvalidTransaction => 50,
            PenaltyType::SpamMessage => 10,
            PenaltyType::DeliveryTimeout => 5,
        }
    }
}

/// Action to take after evaluating penalties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PenaltyAction {
    None,
    Warn,
    Ban,
}

struct PeerPenalty {
    score: u32,
    last_update: Instant,
}

/// Manages per-peer penalty scores with time decay.
pub struct PenaltyManager {
    scores: HashMap<PeerId, PeerPenalty>,
    banned: HashMap<PeerId, Instant>,
    banned_ips: HashMap<IpAddr, Instant>,
    ban_threshold: u32,
    warn_threshold: u32,
    ban_duration: Duration,
    decay_per_second: u32,
}

impl PenaltyManager {
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
            banned: HashMap::new(),
            banned_ips: HashMap::new(),
            ban_threshold: 100,
            warn_threshold: 50,
            ban_duration: Duration::from_secs(3600),
            decay_per_second: 1,
        }
    }

    /// Add a penalty to a peer and return the resulting action.
    pub fn add_penalty(&mut self, peer_id: PeerId, penalty: PenaltyType) -> PenaltyAction {
        let entry = self.scores.entry(peer_id).or_insert(PeerPenalty {
            score: 0,
            last_update: Instant::now(),
        });

        // Apply time decay
        let elapsed = entry.last_update.elapsed().as_secs() as u32;
        entry.score = entry.score.saturating_sub(elapsed * self.decay_per_second);
        entry.last_update = Instant::now();

        // Add penalty
        entry.score = entry.score.saturating_add(penalty.weight());

        if entry.score >= self.ban_threshold {
            self.banned.insert(peer_id, Instant::now());
            self.scores.remove(&peer_id);
            PenaltyAction::Ban
        } else if entry.score >= self.warn_threshold {
            PenaltyAction::Warn
        } else {
            PenaltyAction::None
        }
    }

    /// Check if a peer is currently banned.
    pub fn is_banned(&self, peer_id: PeerId) -> bool {
        if let Some(ban_time) = self.banned.get(&peer_id) {
            ban_time.elapsed() < self.ban_duration
        } else {
            false
        }
    }

    /// Ban an IP address.
    pub fn ban_ip(&mut self, ip: IpAddr) {
        self.banned_ips.insert(ip, Instant::now());
    }

    /// Check if an IP is currently banned.
    pub fn is_ip_banned(&self, ip: &IpAddr) -> bool {
        self.banned_ips
            .get(ip)
            .map(|t| t.elapsed() < self.ban_duration)
            .unwrap_or(false)
    }

    /// Return all currently banned (non-expired) IPs.
    pub fn banned_ips(&self) -> Vec<IpAddr> {
        self.banned_ips
            .iter()
            .filter(|(_, t)| t.elapsed() < self.ban_duration)
            .map(|(&ip, _)| ip)
            .collect()
    }

    /// Remove expired bans.
    pub fn cleanup_expired_bans(&mut self) {
        self.banned
            .retain(|_, ban_time| ban_time.elapsed() < self.ban_duration);
        self.banned_ips
            .retain(|_, ban_time| ban_time.elapsed() < self.ban_duration);
    }

    /// Get the current penalty score for a peer (0 if unknown).
    pub fn score(&self, peer_id: PeerId) -> u32 {
        self.scores.get(&peer_id).map_or(0, |p| p.score)
    }

    /// Return IDs of all currently banned (non-expired) peers.
    pub fn banned_peer_ids(&self) -> Vec<PeerId> {
        self.banned
            .iter()
            .filter(|(_, ban_time)| ban_time.elapsed() < self.ban_duration)
            .map(|(&peer_id, _)| peer_id)
            .collect()
    }
}

impl Default for PenaltyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_peer_has_zero_score() {
        let mgr = PenaltyManager::new();
        assert_eq!(mgr.score(1), 0);
    }

    #[test]
    fn add_penalty_increases_score() {
        let mut mgr = PenaltyManager::new();
        mgr.add_penalty(1, PenaltyType::DeliveryTimeout);
        assert_eq!(mgr.score(1), 5);
    }

    #[test]
    fn invalid_block_triggers_immediate_ban() {
        let mut mgr = PenaltyManager::new();
        let action = mgr.add_penalty(1, PenaltyType::InvalidBlock);
        assert_eq!(action, PenaltyAction::Ban);
        assert!(mgr.is_banned(1));
    }

    #[test]
    fn cumulative_penalties_trigger_ban() {
        let mut mgr = PenaltyManager::new();
        // 10 spam messages = 100 points = ban
        for i in 0..9 {
            let action = mgr.add_penalty(1, PenaltyType::SpamMessage);
            if i < 4 {
                assert_eq!(action, PenaltyAction::None, "iteration {i}");
            } else {
                assert_eq!(action, PenaltyAction::Warn, "iteration {i}");
            }
        }
        let action = mgr.add_penalty(1, PenaltyType::SpamMessage);
        assert_eq!(action, PenaltyAction::Ban);
    }

    #[test]
    fn is_banned_returns_true_after_ban() {
        let mut mgr = PenaltyManager::new();
        assert!(!mgr.is_banned(1));
        mgr.add_penalty(1, PenaltyType::InvalidHeader);
        assert!(mgr.is_banned(1));
    }

    #[test]
    fn warn_threshold_returns_warn() {
        let mut mgr = PenaltyManager::new();
        let action = mgr.add_penalty(1, PenaltyType::InvalidTransaction);
        // 50 points = warn threshold
        assert_eq!(action, PenaltyAction::Warn);
    }

    #[test]
    fn cleanup_removes_expired_bans() {
        let mut mgr = PenaltyManager::new();
        mgr.add_penalty(1, PenaltyType::InvalidBlock);
        assert!(mgr.is_banned(1));

        // Manually set ban time to the past
        mgr.banned
            .insert(1, Instant::now() - Duration::from_secs(7200));
        mgr.cleanup_expired_bans();
        assert!(!mgr.is_banned(1));
    }

    #[test]
    fn banned_peer_ids_returns_banned() {
        let mut mgr = PenaltyManager::new();
        // InvalidBlock has weight 100 = instant ban
        mgr.add_penalty(42, PenaltyType::InvalidBlock);
        mgr.add_penalty(99, PenaltyType::InvalidHeader);
        let banned = mgr.banned_peer_ids();
        assert!(banned.contains(&42));
        assert!(banned.contains(&99));
        assert_eq!(banned.len(), 2);
    }

    #[test]
    fn banned_peer_ids_excludes_expired() {
        let mut mgr = PenaltyManager::new();
        mgr.add_penalty(42, PenaltyType::InvalidBlock);
        assert!(mgr.banned_peer_ids().contains(&42));

        // Manually expire the ban
        mgr.banned
            .insert(42, Instant::now() - Duration::from_secs(7200));
        assert!(mgr.banned_peer_ids().is_empty());
    }

    #[test]
    fn ban_ip_and_check() {
        let mut mgr = PenaltyManager::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!mgr.is_ip_banned(&ip));
        mgr.ban_ip(ip);
        assert!(mgr.is_ip_banned(&ip));
    }

    #[test]
    fn ip_ban_expires_after_cleanup() {
        let mut mgr = PenaltyManager::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        mgr.ban_ip(ip);
        assert!(mgr.is_ip_banned(&ip));

        // Manually set ban time to the past
        mgr.banned_ips
            .insert(ip, Instant::now() - Duration::from_secs(7200));
        mgr.cleanup_expired_bans();
        assert!(!mgr.is_ip_banned(&ip));
    }

    #[test]
    fn banned_ips_returns_active_bans() {
        let mut mgr = PenaltyManager::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        mgr.ban_ip(ip1);
        mgr.ban_ip(ip2);
        let banned = mgr.banned_ips();
        assert_eq!(banned.len(), 2);
        assert!(banned.contains(&ip1));
        assert!(banned.contains(&ip2));
    }

    #[test]
    fn cleanup_removes_expired_ip_bans() {
        let mut mgr = PenaltyManager::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        mgr.ban_ip(ip);

        // Set to past
        mgr.banned_ips
            .insert(ip, Instant::now() - Duration::from_secs(7200));
        mgr.cleanup_expired_bans();
        assert!(mgr.banned_ips().is_empty());
    }
}
