use std::collections::HashSet;
use std::net::SocketAddr;

use ergo_wire::peer_spec::{self, PeerAddr};

/// Manages discovery and tracking of peer addresses.
pub struct PeerDiscovery {
    known_peers: HashSet<SocketAddr>,
    seed_peers: Vec<SocketAddr>,
    max_known: usize,
}

impl PeerDiscovery {
    pub fn new(seed_peers: Vec<SocketAddr>, max_known: usize) -> Self {
        let mut known_peers = HashSet::new();
        for addr in &seed_peers {
            known_peers.insert(*addr);
        }
        Self {
            known_peers,
            seed_peers,
            max_known,
        }
    }

    /// Add a discovered peer address. Returns true if the peer was new.
    pub fn add_peer(&mut self, addr: SocketAddr) -> bool {
        if self.known_peers.len() >= self.max_known {
            return false;
        }
        self.known_peers.insert(addr)
    }

    /// Add multiple peers from a Peers message body.
    pub fn add_peers_from_message(&mut self, data: &[u8]) {
        if let Ok(peers) = peer_spec::parse_peers(data) {
            for peer in peers {
                self.add_peer(peer.address);
            }
        }
    }

    /// Build a Peers response body with up to `count` known peers.
    pub fn build_peers_response(&self, count: usize) -> Vec<u8> {
        let addrs: Vec<PeerAddr> = self
            .known_peers
            .iter()
            .take(count)
            .map(|addr| PeerAddr { address: *addr })
            .collect();
        peer_spec::serialize_peers(&addrs)
    }

    /// Get addresses to try connecting to (not already connected).
    pub fn peers_to_connect(&self, connected: &HashSet<SocketAddr>) -> Vec<SocketAddr> {
        let mut result = Vec::new();
        for addr in &self.seed_peers {
            if !connected.contains(addr) {
                result.push(*addr);
            }
        }
        for addr in &self.known_peers {
            if !connected.contains(addr) && !self.seed_peers.contains(addr) {
                result.push(*addr);
            }
        }
        result
    }

    /// All known peer addresses.
    pub fn known_peers(&self) -> &HashSet<SocketAddr> {
        &self.known_peers
    }

    /// Number of known peers.
    pub fn known_count(&self) -> usize {
        self.known_peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn new_contains_seed_peers() {
        let seeds = vec![addr(9001), addr(9002)];
        let disc = PeerDiscovery::new(seeds.clone(), 100);
        assert_eq!(disc.known_count(), 2);
        assert!(disc.known_peers().contains(&addr(9001)));
        assert!(disc.known_peers().contains(&addr(9002)));
    }

    #[test]
    fn add_peer_returns_true_for_new() {
        let mut disc = PeerDiscovery::new(vec![], 100);
        assert!(disc.add_peer(addr(9001)));
        assert_eq!(disc.known_count(), 1);
    }

    #[test]
    fn add_peer_returns_false_for_duplicate() {
        let mut disc = PeerDiscovery::new(vec![addr(9001)], 100);
        assert!(!disc.add_peer(addr(9001)));
        assert_eq!(disc.known_count(), 1);
    }

    #[test]
    fn peers_to_connect_excludes_connected() {
        let seeds = vec![addr(9001), addr(9002), addr(9003)];
        let disc = PeerDiscovery::new(seeds, 100);

        let connected: HashSet<SocketAddr> = [addr(9002)].into_iter().collect();
        let to_connect = disc.peers_to_connect(&connected);

        assert!(!to_connect.contains(&addr(9002)));
        assert!(to_connect.contains(&addr(9001)));
        assert!(to_connect.contains(&addr(9003)));
    }

    #[test]
    fn build_peers_response_roundtrip() {
        let seeds = vec![addr(9001), addr(9002)];
        let disc = PeerDiscovery::new(seeds, 100);

        let response = disc.build_peers_response(10);
        let parsed = peer_spec::parse_peers(&response).unwrap();

        let addrs: HashSet<SocketAddr> = parsed.iter().map(|p| p.address).collect();
        assert!(addrs.contains(&addr(9001)));
        assert!(addrs.contains(&addr(9002)));
    }

    #[test]
    fn max_known_limit_enforced() {
        let mut disc = PeerDiscovery::new(vec![], 2);
        assert!(disc.add_peer(addr(9001)));
        assert!(disc.add_peer(addr(9002)));
        assert!(!disc.add_peer(addr(9003)));
        assert_eq!(disc.known_count(), 2);
    }
}
