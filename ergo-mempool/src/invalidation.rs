//! Invalidation cache for txs that failed validation.
//!
//! Insertion-order eviction + TTL, capped at `max_size` entries. Reinserting
//! an ID refreshes its position; lookups do not. First hit on a
//! tx_id and a repeat within `spam_window` have distinct library lookup
//! results. Production uses this cache to filter inventory fetches;
//! received transaction bytes still undergo full admission validation.
//!
//! A transaction id does not cover its input proofs, so entries come in two
//! scopes. A failure the proofs cannot change (structure, amounts, relay
//! policy) is recorded for the id and filters every peer's inventory. A
//! failure that depends on the delivered proofs (script, cost) is recorded
//! for the id *and the peer that delivered it*, so another peer can still
//! serve the same id with different proofs. Every lookup honours the TTL,
//! whether or not a later insert has pruned the entry yet.

use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use lru::LruCache;

use crate::types::{PeerId, TxId};

/// Cache key: an id-wide entry (`None`) or one scoped to the delivering peer.
type Key = (TxId, Option<PeerId>);

/// Why a tx was marked invalid. Preserved for observability only — the
/// cache does not treat reasons differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidationReason {
    /// Validation failed (script, structural, monetary, …).
    ValidationFailed,
    /// Locally declined by relay policy; suppress repeated inventory fetches.
    RelayPolicy,
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

/// Result of the optional hit-counting lookup. Production's inventory filter
/// uses `contains` and does not translate these results into peer penalties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupResult {
    NotCached,
    FirstHit,
    RepeatHit { hits: u32 },
}

pub struct InvalidationCache {
    // One bounded node per ID, with no stale insertion descriptors. Use
    // peek/peek_mut for reads so this cache retains insertion-order policy.
    entries: Option<LruCache<Key, Record>>,
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
            entries: NonZeroUsize::new(max_size).map(LruCache::new),
            ttl,
            spam_window,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.as_ref().map_or(0, LruCache::len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Prune entries older than `ttl` from the insertion-time front.
    /// Called at the start of every admission — amortized O(1).
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

    /// Record an id-wide invalidation (filters the id from every peer).
    /// Evicts oldest if at capacity.
    pub fn insert(&mut self, tx_id: TxId, reason: InvalidationReason, now: Instant) {
        self.insert_key((tx_id, None), reason, now);
    }

    /// Record an invalidation that holds only for bytes delivered by `peer`
    /// (a proof-dependent failure). Evicts oldest if at capacity.
    pub fn insert_for_peer(
        &mut self,
        tx_id: TxId,
        peer: PeerId,
        reason: InvalidationReason,
        now: Instant,
    ) {
        self.insert_key((tx_id, Some(peer)), reason, now);
    }

    fn insert_key(&mut self, key: Key, reason: InvalidationReason, now: Instant) {
        self.prune_expired(now);
        let Some(entries) = self.entries.as_mut() else {
            return;
        };
        let rec = Record {
            inserted_at: now,
            last_hit_at: now,
            hits: 0,
            reason,
        };
        entries.put(key, rec);
    }

    /// Look up a tx. Increments the hit counter and returns whether
    /// this is the first hit or a repeat (with hit count).
    pub fn record_hit(&mut self, tx_id: &TxId, now: Instant) -> LookupResult {
        self.prune_expired(now);
        match self
            .entries
            .as_mut()
            .and_then(|entries| entries.peek_mut(&(*tx_id, None)))
        {
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

    /// Is there a live id-wide entry for `tx_id`?
    pub fn contains(&self, tx_id: &TxId) -> bool {
        self.contains_at(tx_id, Instant::now())
    }

    /// [`Self::contains`] evaluated at `now`: an entry older than the TTL
    /// does not count, even before a later insert prunes it.
    pub fn contains_at(&self, tx_id: &TxId, now: Instant) -> bool {
        self.live(&(*tx_id, None), now).is_some()
    }

    /// Should an inventory of `tx_id` from `peer` be skipped at `now`? True
    /// for a live id-wide entry or a live entry scoped to that peer.
    pub fn contains_for_peer(&self, tx_id: &TxId, peer: PeerId, now: Instant) -> bool {
        self.contains_at(tx_id, now) || self.live(&(*tx_id, Some(peer)), now).is_some()
    }

    pub fn reason(&self, tx_id: &TxId) -> Option<InvalidationReason> {
        self.live(&(*tx_id, None), Instant::now()).map(|r| r.reason)
    }

    fn live(&self, key: &Key, now: Instant) -> Option<&Record> {
        self.entries
            .as_ref()
            .and_then(|entries| entries.peek(key))
            .filter(|record| now.saturating_duration_since(record.inserted_at) < self.ttl)
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
        c.insert(id(1), InvalidationReason::ValidationFailed, t0);
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
        assert_eq!(c.entries.as_ref().unwrap().iter().count(), 1);
    }

    #[test]
    fn refreshed_id_has_one_node_and_survives_older_entry_eviction() {
        let mut c = InvalidationCache::new(2, Duration::from_secs(60), Duration::from_secs(1));
        let t0 = Instant::now();
        c.insert(id(1), InvalidationReason::ValidationFailed, t0);
        c.insert(id(2), InvalidationReason::ValidationFailed, t0);
        // Same-instant refresh must replace ownership, not leave a second
        // descriptor that can later evict this refreshed record.
        c.insert(id(1), InvalidationReason::DoubleSpendLoser, t0);
        c.insert(id(1), InvalidationReason::DoubleSpendLoser, t0);
        assert_eq!(c.entries.as_ref().unwrap().iter().count(), 2);
        c.insert(id(3), InvalidationReason::ValidationFailed, t0);
        assert!(c.contains(&id(1)));
        assert!(!c.contains(&id(2)));
        assert!(c.contains(&id(3)));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn refresh_extends_ttl_but_hits_do_not_change_eviction_order() {
        let mut c = InvalidationCache::new(2, Duration::from_secs(60), Duration::from_secs(1));
        let t0 = Instant::now();
        c.insert(id(1), InvalidationReason::ValidationFailed, t0);
        c.insert(id(2), InvalidationReason::ValidationFailed, t0);
        c.insert(
            id(1),
            InvalidationReason::DoubleSpendLoser,
            t0 + Duration::from_secs(30),
        );
        c.prune_expired(t0 + Duration::from_secs(60));
        assert!(!c.contains(&id(2)));
        assert!(c.contains(&id(1)));
        c.insert(
            id(2),
            InvalidationReason::ValidationFailed,
            t0 + Duration::from_secs(60),
        );
        c.record_hit(&id(1), t0 + Duration::from_secs(61));
        c.insert(
            id(3),
            InvalidationReason::ValidationFailed,
            t0 + Duration::from_secs(61),
        );
        assert!(
            !c.contains(&id(1)),
            "a lookup does not refresh insertion order"
        );
        c.prune_expired(t0 + Duration::from_secs(121));
        assert!(c.is_empty());
    }

    #[test]
    fn zero_capacity_retains_no_invalidation_or_ordering_nodes() {
        let mut c = InvalidationCache::new(0, Duration::from_secs(60), Duration::from_secs(1));
        let now = Instant::now();
        c.insert(id(1), InvalidationReason::ValidationFailed, now);
        assert!(c.entries.is_none());
        assert!(c.is_empty());
        assert_eq!(c.record_hit(&id(1), now), LookupResult::NotCached);
    }

    #[test]
    fn reason_returned_for_cached_tx() {
        let mut c = cache();
        let t0 = Instant::now();
        c.insert(id(1), InvalidationReason::DoubleSpendLoser, t0);
        assert_eq!(c.reason(&id(1)), Some(InvalidationReason::DoubleSpendLoser));
        assert_eq!(c.reason(&id(2)), None);
    }

    fn peer(port: u16) -> PeerId {
        PeerId::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn lookups_honour_the_ttl_without_a_later_insert() {
        let c = {
            let mut c = cache();
            c.insert(id(1), InvalidationReason::ValidationFailed, Instant::now());
            c
        };
        let now = Instant::now();
        assert!(c.contains_at(&id(1), now));
        assert!(!c.contains_at(&id(1), now + Duration::from_secs(61)));
        assert!(!c.contains_for_peer(&id(1), peer(1), now + Duration::from_secs(61)));
    }

    #[test]
    fn peer_scoped_entry_filters_only_that_peer() {
        let mut c = cache();
        let now = Instant::now();
        c.insert_for_peer(id(1), peer(1), InvalidationReason::ValidationFailed, now);
        assert!(c.contains_for_peer(&id(1), peer(1), now));
        assert!(!c.contains_for_peer(&id(1), peer(2), now));
        assert!(!c.contains_at(&id(1), now), "no id-wide entry");
        c.insert(id(1), InvalidationReason::ValidationFailed, now);
        assert!(c.contains_for_peer(&id(1), peer(2), now));
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
