//! Short-TTL cache keyed on raw-bytes hash. Blocks repeated deserialize
//! + overlay lookups for txs whose inputs are unresolvable at tip.
//!
//! Scala does not have this cache — its immutable pool re-hashes
//! anyway. We add it because our admission has real cost in the
//! resolution step.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use ergo_primitives::digest::{blake2b256, Digest32};

#[derive(Debug, Clone, Copy)]
struct Record {
    inserted_at: Instant,
}

pub struct UnresolvedCache {
    entries: HashMap<Digest32, Record>,
    by_insertion: VecDeque<(Digest32, Instant)>,
    max_size: usize,
    ttl: Duration,
}

impl UnresolvedCache {
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::with_capacity(max_size),
            by_insertion: VecDeque::with_capacity(max_size),
            max_size,
            ttl,
        }
    }

    /// Hash of raw canonical tx bytes. This is stable across peers
    /// because we've already canonical-checked before calling here.
    pub fn key_of(bytes: &[u8]) -> Digest32 {
        blake2b256(bytes)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn prune_expired(&mut self, now: Instant) {
        while let Some((key, inserted_at)) = self.by_insertion.front().copied() {
            if now.duration_since(inserted_at) < self.ttl {
                break;
            }
            self.by_insertion.pop_front();
            if let Some(rec) = self.entries.get(&key) {
                if rec.inserted_at == inserted_at {
                    self.entries.remove(&key);
                }
            }
        }
    }

    /// Returns `true` if the bytes-hash is still cached. Admission
    /// early-drops on `true`.
    pub fn contains(&mut self, bytes: &[u8], now: Instant) -> bool {
        self.prune_expired(now);
        self.entries.contains_key(&Self::key_of(bytes))
    }

    pub fn contains_key(&self, key: &Digest32) -> bool {
        self.entries.contains_key(key)
    }

    /// Drop the suppression entry for `bytes`, if present. Used when the
    /// staging pool promotes an orphan: the same bytes are about to be
    /// re-validated through admission, so the step-3 unresolved-cache gate
    /// must not short-circuit them as `RecentlyUnresolved`.
    pub fn remove(&mut self, bytes: &[u8]) {
        let key = Self::key_of(bytes);
        if self.entries.remove(&key).is_some() {
            self.by_insertion.retain(|(k, _)| k != &key);
        }
    }

    /// Record an unresolved-input drop. Keyed on raw bytes hash so a
    /// different peer re-sending the same bytes hits the cache.
    pub fn insert(&mut self, bytes: &[u8], now: Instant) {
        self.prune_expired(now);
        let key = Self::key_of(bytes);
        if self.entries.len() >= self.max_size && !self.entries.contains_key(&key) {
            if let Some((oldest, _)) = self.by_insertion.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(key, Record { inserted_at: now });
        self.by_insertion.push_back((key, now));
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
}
