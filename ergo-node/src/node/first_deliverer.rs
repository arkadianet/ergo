//! First-block-deliverer ring.
//!
//! For each recently-validated header we record the FIRST peer that
//! delivered it to us — the peer whose `Modifier` message carried the
//! header bytes we accepted. The miner/pool's node typically announces a
//! freshly-mined block first, so `header_id → first deliverer` lets an
//! operator attribute a block to a peer (and, with out-of-band peer→pool
//! knowledge, to a mining pool).
//!
//! This is pure observability: it never feeds sync, consensus, or peer
//! scoring. The ring is BOUNDED (FIFO eviction at [`FirstDelivererRing::CAP`])
//! so it can never grow for the life of the node, and it records only the
//! FIRST deliverer for a given header id — later duplicate deliveries of
//! the same header are ignored.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;

/// A header's first deliverer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FirstDeliverer {
    /// Socket address of the peer that first delivered the header.
    pub(crate) peer: SocketAddr,
    /// Monotonic instant the header was first accepted from that peer.
    pub(crate) first_seen: Instant,
}

/// Bounded `header_id → first deliverer` ring.
///
/// Keyed by the 32-byte header id. New entries evict the oldest when the
/// ring is at capacity (FIFO), so the map size is capped at [`Self::CAP`]
/// regardless of how many headers the node validates over its lifetime.
pub(crate) struct FirstDelivererRing {
    /// First-deliverer record per header id.
    by_id: HashMap<[u8; 32], FirstDeliverer>,
    /// Insertion order, oldest at the front — drives FIFO eviction.
    order: VecDeque<[u8; 32]>,
}

impl FirstDelivererRing {
    /// Maximum number of header ids retained. Bounds the ring's memory;
    /// older entries are evicted FIFO past this. 256 covers a generous
    /// window of recent blocks (well past the 32-entry recent-blocks
    /// tail) while staying tiny.
    pub(crate) const CAP: usize = 256;

    pub(crate) fn new() -> Self {
        Self {
            by_id: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Record `peer` as the first deliverer of `header_id` at `now`.
    ///
    /// Idempotent on the FIRST-deliverer invariant: if `header_id` is
    /// already present, this is a no-op — the original deliverer is kept
    /// and the duplicate is ignored. Inserting a new id past [`Self::CAP`]
    /// evicts the oldest entry.
    pub(crate) fn record(&mut self, header_id: [u8; 32], peer: SocketAddr, now: Instant) {
        if self.by_id.contains_key(&header_id) {
            // First deliverer already recorded; later duplicates are ignored.
            return;
        }
        self.by_id.insert(
            header_id,
            FirstDeliverer {
                peer,
                first_seen: now,
            },
        );
        self.order.push_back(header_id);
        while self.order.len() > Self::CAP {
            if let Some(old) = self.order.pop_front() {
                self.by_id.remove(&old);
            }
        }
    }

    /// Look up the first deliverer of `header_id`, if recorded.
    pub(crate) fn get(&self, header_id: &[u8; 32]) -> Option<&FirstDeliverer> {
        self.by_id.get(header_id)
    }

    /// Current number of retained entries (≤ [`Self::CAP`]).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_id.len()
    }
}

impl Default for FirstDelivererRing {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
    }

    fn id(v: u8) -> [u8; 32] {
        [v; 32]
    }

    #[test]
    fn first_deliverer_ring_records_first_peer_only() {
        let mut ring = FirstDelivererRing::new();
        let now = Instant::now();
        let a = peer(9030);
        let b = peer(9031);

        // Record header from peer A, then the SAME header from peer B.
        ring.record(id(1), a, now);
        ring.record(id(1), b, now + std::time::Duration::from_secs(1));

        // The ring must return A — the first deliverer — not B.
        let rec = ring.get(&id(1)).expect("header id recorded");
        assert_eq!(
            rec.peer, a,
            "ring must keep the FIRST deliverer, not the later one"
        );
        assert_eq!(
            rec.first_seen, now,
            "first_seen must be the first delivery instant"
        );
        assert_eq!(ring.len(), 1, "a duplicate must not add a second entry");
    }

    #[test]
    fn first_deliverer_ring_is_bounded_evicting_oldest() {
        let mut ring = FirstDelivererRing::new();
        let now = Instant::now();
        let p = peer(9030);

        // Insert one MORE than the cap; each id is distinct.
        let overflow = FirstDelivererRing::CAP + 1;
        for i in 0..overflow {
            let mut arr = [0u8; 32];
            arr[..2].copy_from_slice(&(i as u16).to_be_bytes());
            ring.record(arr, p, now);
        }

        // Size is capped.
        assert_eq!(ring.len(), FirstDelivererRing::CAP);

        // The oldest entry (i == 0) was evicted; the newest is retained.
        let mut oldest = [0u8; 32];
        oldest[..2].copy_from_slice(&0u16.to_be_bytes());
        assert!(
            ring.get(&oldest).is_none(),
            "oldest entry must be evicted past the cap"
        );
        let mut newest = [0u8; 32];
        newest[..2].copy_from_slice(&((overflow - 1) as u16).to_be_bytes());
        assert!(ring.get(&newest).is_some(), "newest entry must be retained");
    }

    #[test]
    fn first_deliverer_ring_absent_id_returns_none() {
        let ring = FirstDelivererRing::new();
        assert!(ring.get(&id(7)).is_none());
    }
}
