//! Short-TTL cache keyed on raw-bytes hash. Blocks repeated deserialize
//! + overlay lookups for txs whose inputs are unresolvable at tip.
//!
//! Scala does not have this cache — its immutable pool re-hashes
//! anyway. We add it because our admission has real cost in the
//! resolution step.

use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use lru::LruCache;

use ergo_primitives::digest::{blake2b256, Digest32};

#[derive(Debug, Clone, Copy)]
struct Record {
    inserted_at: Instant,
}

pub struct UnresolvedCache {
    entries: Option<LruCache<Digest32, Record>>,
    ttl: Duration,
}

impl UnresolvedCache {
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        Self {
            entries: NonZeroUsize::new(max_size).map(LruCache::new),
            ttl,
        }
    }

    /// Hash of received transaction bytes. Equal byte strings share a key;
    /// this helper itself makes no parsing or canonicality assertion.
    pub fn key_of(bytes: &[u8]) -> Digest32 {
        blake2b256(bytes)
    }

    pub fn len(&self) -> usize {
        self.entries.as_ref().map_or(0, LruCache::len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn prune_expired(&mut self, now: Instant) {
        let Some(entries) = self.entries.as_mut() else {
            return;
        };
        while let Some((_, record)) = entries.peek_lru() {
            if now.duration_since(record.inserted_at) < self.ttl {
                break;
            }
            entries.pop_lru();
        }
    }

    /// Returns `true` if the bytes-hash is still cached. Admission
    /// early-drops on `true`.
    pub fn contains(&mut self, bytes: &[u8], now: Instant) -> bool {
        self.prune_expired(now);
        self.contains_key(&Self::key_of(bytes))
    }

    pub fn contains_key(&self, key: &Digest32) -> bool {
        self.entries
            .as_ref()
            .is_some_and(|entries| entries.contains(key))
    }

    /// Drop the suppression entry for `bytes`, if present. Used when the
    /// staging pool promotes an orphan: the same bytes are about to be
    /// re-validated through admission, so the step-3 unresolved-cache gate
    /// must not short-circuit them as `RecentlyUnresolved`.
    pub fn remove(&mut self, bytes: &[u8]) {
        let key = Self::key_of(bytes);
        if let Some(entries) = self.entries.as_mut() {
            entries.pop(&key);
        }
    }

    /// Record an unresolved-input drop. Keyed on raw bytes hash so a
    /// different peer re-sending the same bytes hits the cache.
    pub fn insert(&mut self, bytes: &[u8], now: Instant) {
        self.prune_expired(now);
        let key = Self::key_of(bytes);
        if let Some(entries) = self.entries.as_mut() {
            entries.put(key, Record { inserted_at: now });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache() -> UnresolvedCache {
        UnresolvedCache::new(4, Duration::from_secs(60))
    }

    // ----- happy path -----

    #[test]
    fn not_cached_by_default() {
        let mut c = cache();
        let now = Instant::now();
        assert!(!c.contains(b"hello", now));
    }

    #[test]
    fn insert_then_contains() {
        let mut c = cache();
        let now = Instant::now();
        c.insert(b"txbytes", now);
        assert!(c.contains(b"txbytes", now));
    }

    #[test]
    fn ttl_prunes_expired() {
        let mut c = cache();
        let t0 = Instant::now();
        c.insert(b"txbytes", t0);
        let later = t0 + Duration::from_secs(120);
        assert!(!c.contains(b"txbytes", later));
    }

    #[test]
    fn different_bytes_are_different_keys() {
        let mut c = cache();
        let now = Instant::now();
        c.insert(b"tx_a", now);
        assert!(!c.contains(b"tx_b", now));
    }

    #[test]
    fn capacity_evicts_oldest() {
        let mut c = cache();
        let t0 = Instant::now();
        c.insert(b"one", t0);
        c.insert(b"two", t0);
        c.insert(b"three", t0);
        c.insert(b"four", t0);
        c.insert(b"five", t0);
        assert!(!c.contains(b"one", t0));
        assert!(c.contains(b"five", t0));
    }

    #[test]
    fn refresh_owns_one_node_and_preserves_latest_insertion_order() {
        let mut c = UnresolvedCache::new(2, Duration::from_secs(60));
        let now = Instant::now();
        c.insert(b"one", now);
        c.insert(b"two", now);
        c.insert(b"one", now);
        c.insert(b"one", now);
        assert_eq!(c.entries.as_ref().unwrap().iter().count(), 2);
        assert!(
            c.contains(b"two", now),
            "a lookup does not refresh insertion order"
        );
        c.insert(b"three", now);
        assert!(c.contains(b"one", now));
        assert!(!c.contains(b"two", now));
        c.remove(b"one");
        assert_eq!(c.entries.as_ref().unwrap().iter().count(), 1);
        c.prune_expired(now + Duration::from_secs(60));
        assert!(c.is_empty());
    }

    #[test]
    fn zero_capacity_disables_unresolved_suppression() {
        let mut c = UnresolvedCache::new(0, Duration::from_secs(60));
        let now = Instant::now();
        c.insert(b"one", now);
        assert!(!c.contains(b"one", now));
        assert!(c.entries.is_none());
    }
}
