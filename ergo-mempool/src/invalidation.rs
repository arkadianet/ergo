//! Invalidation cache for txs that failed validation.
//!
//! Simple LRU + TTL, capped at `max_size` entries. First hit on a
//! tx_id is a silent drop (we might have tagged it on a stale tip).
//! A repeat hit within `spam_window` is peer-spammy and admission
//! escalates to a spam penalty.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::types::TxId;

/// Why a tx was marked invalid. Preserved for observability only — the
/// cache does not treat reasons differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidationReason {
    /// Validation failed (script, structural, monetary, …).
    ValidationFailed,
    /// Tx was evicted as a double-spend loser and subsequently
    /// re-presented. Separate tag so metrics can distinguish.
    DoubleSpendLoser,
    /// Repeated known-bad delivery from a peer. Not cached here; kept
    /// for completeness at the admission call-site.
    ResubmissionSpam,
}

#[derive(Debug, Clone, Copy)]
struct Record {
    inserted_at: Instant,
    last_hit_at: Instant,
    hits: u32,
    reason: InvalidationReason,
}

/// Result of an invalidation lookup. Admission routes each case
/// separately at step 7 of the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupResult {
    NotCached,
    FirstHit,
    RepeatHit { hits: u32 },
}

pub struct InvalidationCache {
    entries: HashMap<TxId, Record>,
    /// FIFO of (tx_id, inserted_at) for O(1) eviction on overflow and
    /// O(1)-amortized pruning of expired entries.
    by_insertion: VecDeque<(TxId, Instant)>,
    max_size: usize,
    ttl: Duration,
    spam_window: Duration,
}

impl InvalidationCache {
    /// `max_size` matches `MempoolConfig::invalidation_cache_size`
    /// (default 10_000). `ttl` is the entry lifetime (default 4h).
    /// `spam_window` is the gap after which a repeat hit counts as
    /// spam rather than a coincidental retry (default 60 s).
    pub fn new(max_size: usize, ttl: Duration, spam_window: Duration) -> Self {
        Self {
            entries: HashMap::with_capacity(max_size),
            by_insertion: VecDeque::with_capacity(max_size),
            max_size,
            ttl,
            spam_window,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Prune entries older than `ttl` from the insertion-time front.
    /// Called at the start of every admission — amortized O(1).
    pub fn prune_expired(&mut self, now: Instant) {
        while let Some((tx_id, inserted_at)) = self.by_insertion.front().copied() {
            if now.duration_since(inserted_at) < self.ttl {
                break;
            }
            self.by_insertion.pop_front();
            // Only remove if the entry in `entries` is the one this
            // insertion-event refers to (re-inserts after eviction may
            // leave stale front entries).
            if let Some(rec) = self.entries.get(&tx_id) {
                if rec.inserted_at == inserted_at {
                    self.entries.remove(&tx_id);
                }
            }
        }
    }

    /// Record an invalidation. Evicts oldest if at capacity.
    pub fn insert(&mut self, tx_id: TxId, reason: InvalidationReason, now: Instant) {
        self.prune_expired(now);
        if self.entries.len() >= self.max_size && !self.entries.contains_key(&tx_id) {
            // Evict oldest.
            if let Some((oldest_id, _)) = self.by_insertion.pop_front() {
                self.entries.remove(&oldest_id);
            }
        }
        let rec = Record {
            inserted_at: now,
            last_hit_at: now,
            hits: 0,
            reason,
        };
        self.entries.insert(tx_id, rec);
        self.by_insertion.push_back((tx_id, now));
    }

    /// Look up a tx. Increments the hit counter and returns whether
    /// this is the first hit or a repeat (with hit count).
    pub fn record_hit(&mut self, tx_id: &TxId, now: Instant) -> LookupResult {
        self.prune_expired(now);
        match self.entries.get_mut(tx_id) {
            None => LookupResult::NotCached,
            Some(rec) => {
                let is_repeat_in_window =
                    rec.hits > 0 && now.duration_since(rec.last_hit_at) < self.spam_window;
                rec.hits = rec.hits.saturating_add(1);
                rec.last_hit_at = now;
                if is_repeat_in_window {
                    LookupResult::RepeatHit { hits: rec.hits }
                } else if rec.hits == 1 {
                    LookupResult::FirstHit
                } else {
                    // Outside-window repeat: treat as a first hit again
                    // so a long-absent peer isn't penalized for a single
                    // stale retry.
                    LookupResult::FirstHit
                }
            }
        }
    }

    pub fn contains(&self, tx_id: &TxId) -> bool {
        self.entries.contains_key(tx_id)
    }

    pub fn reason(&self, tx_id: &TxId) -> Option<InvalidationReason> {
        self.entries.get(tx_id).map(|r| r.reason)
    }

    /// Test hook: bulk-insert without prune (for deterministic seeds).
    #[cfg(test)]
    fn insert_raw(&mut self, tx_id: TxId, inserted_at: Instant, reason: InvalidationReason) {
        self.entries.insert(
            tx_id,
            Record {
                inserted_at,
                last_hit_at: inserted_at,
                hits: 0,
                reason,
            },
        );
        self.by_insertion.push_back((tx_id, inserted_at));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::Digest32;

    fn id(b: u8) -> Digest32 {
        Digest32::from_bytes([b; 32])
    }

    fn cache() -> InvalidationCache {
        InvalidationCache::new(4, Duration::from_secs(60), Duration::from_secs(1))
    }

    // ----- happy path -----

    #[test]
    fn not_cached_by_default() {
        let mut c = cache();
        let now = Instant::now();
        assert_eq!(c.record_hit(&id(1), now), LookupResult::NotCached);
    }

    #[test]
    fn first_hit_then_repeat_within_window() {
        let mut c = cache();
        let t0 = Instant::now();
        c.insert(id(1), InvalidationReason::ValidationFailed, t0);
        assert_eq!(c.record_hit(&id(1), t0), LookupResult::FirstHit);
        let t1 = t0 + Duration::from_millis(500);
        assert_eq!(
            c.record_hit(&id(1), t1),
            LookupResult::RepeatHit { hits: 2 }
        );
    }

    #[test]
    fn hit_outside_window_counts_as_first_again() {
        let mut c = cache();
        let t0 = Instant::now();
        c.insert(id(1), InvalidationReason::ValidationFailed, t0);
        c.record_hit(&id(1), t0);
        let t_far = t0 + Duration::from_secs(30);
        assert_eq!(c.record_hit(&id(1), t_far), LookupResult::FirstHit);
    }

    #[test]
    fn ttl_prunes_old_entries() {
        let mut c = cache();
        let t0 = Instant::now();
        c.insert_raw(id(1), t0, InvalidationReason::ValidationFailed);
        assert!(c.contains(&id(1)));
        let later = t0 + Duration::from_secs(120);
        c.prune_expired(later);
        assert!(!c.contains(&id(1)));
    }

    #[test]
    fn capacity_evicts_oldest_on_overflow() {
        let mut c = cache();
        let base = Instant::now();
        for i in 0..4 {
            c.insert(id(i), InvalidationReason::ValidationFailed, base);
        }
        assert_eq!(c.len(), 4);
        // Insert fifth at the same instant: oldest (id 0) evicted.
        c.insert(id(4), InvalidationReason::ValidationFailed, base);
        assert_eq!(c.len(), 4);
        assert!(!c.contains(&id(0)));
        assert!(c.contains(&id(4)));
    }

    #[test]
    fn re_insert_of_same_id_does_not_grow_pool() {
        let mut c = cache();
        let t0 = Instant::now();
        c.insert(id(1), InvalidationReason::ValidationFailed, t0);
        c.insert(id(1), InvalidationReason::DoubleSpendLoser, t0);
        assert_eq!(c.len(), 1);
        assert_eq!(c.reason(&id(1)), Some(InvalidationReason::DoubleSpendLoser));
    }

    #[test]
    fn reason_returned_for_cached_tx() {
        let mut c = cache();
        let t0 = Instant::now();
        c.insert(id(1), InvalidationReason::DoubleSpendLoser, t0);
        assert_eq!(c.reason(&id(1)), Some(InvalidationReason::DoubleSpendLoser));
        assert_eq!(c.reason(&id(2)), None);
    }

    #[test]
    fn first_lookup_returns_first_hit_not_repeat() {
        let mut c = cache();
        let t0 = Instant::now();
        c.insert(id(1), InvalidationReason::ValidationFailed, t0);
        // First hit ever: FirstHit, not RepeatHit.
        assert_eq!(c.record_hit(&id(1), t0), LookupResult::FirstHit);
    }
}
