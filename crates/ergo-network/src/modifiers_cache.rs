//! Two-tier LRU cache for out-of-order modifier buffering.
//!
//! Mirrors the Scala `ErgoModifiersCache`: headers (type 101) go into a
//! dedicated high-capacity cache while body sections (102, 104, 108) share a
//! second, smaller cache.  Both tiers use `lru::LruCache` for automatic
//! least-recently-used eviction.

use std::num::NonZeroUsize;

use ergo_types::header::Header;
use ergo_types::modifier_id::ModifierId;
use lru::LruCache;

/// Default capacity for the headers cache (type 101).
const DEFAULT_HEADERS_CAPACITY: usize = 8192;

/// Default capacity for the body-sections cache (types 102, 104, 108).
const DEFAULT_BODY_CAPACITY: usize = 384;

/// Modifier type id for headers.
const HEADER_TYPE_ID: u8 = 101;

/// A modifier payload stored in the cache.
#[derive(Debug, Clone)]
pub struct CachedModifier {
    /// The modifier type identifier (101, 102, 104, 108).
    pub type_id: u8,
    /// Raw serialized modifier bytes.
    pub data: Vec<u8>,
    /// For headers (type_id=101), the pre-parsed header for height inspection.
    pub header: Option<Header>,
}

/// Two-tier LRU cache for buffering modifiers received out of order.
///
/// Headers (type 101) are stored in `headers`, while body sections
/// (BlockTransactions 102, ADProofs 104, Extension 108) are stored in
/// `body_sections`.
pub struct ModifiersCache {
    headers: LruCache<ModifierId, CachedModifier>,
    body_sections: LruCache<ModifierId, CachedModifier>,
}

impl ModifiersCache {
    /// Creates a new cache with the given per-tier capacities.
    pub fn new(headers_capacity: usize, body_capacity: usize) -> Self {
        Self {
            headers: LruCache::new(
                NonZeroUsize::new(headers_capacity).expect("headers_capacity must be > 0"),
            ),
            body_sections: LruCache::new(
                NonZeroUsize::new(body_capacity).expect("body_capacity must be > 0"),
            ),
        }
    }

    /// Creates a new cache with the default capacities (8192 headers, 384 body).
    pub fn with_default_capacities() -> Self {
        Self::new(DEFAULT_HEADERS_CAPACITY, DEFAULT_BODY_CAPACITY)
    }

    /// Inserts a modifier into the appropriate cache tier.
    ///
    /// Returns the evicted entry `(id, type_id, data)` if the cache was at
    /// capacity before the insert, or `None` otherwise.
    pub fn put(
        &mut self,
        id: ModifierId,
        type_id: u8,
        data: Vec<u8>,
        header: Option<Header>,
    ) -> Option<(ModifierId, u8, Vec<u8>)> {
        let entry = CachedModifier { type_id, data, header };
        let cache = self.cache_for_mut(type_id);

        // If at capacity and this key is not already present, the LRU entry
        // will be evicted.  We need to capture it manually because
        // `LruCache::push` only returns the *old value for the same key*.
        let evicted = if cache.len() == cache.cap().get() && cache.peek(&id).is_none() {
            // Pop the least-recently-used entry before inserting.
            cache
                .pop_lru()
                .map(|(eid, emod)| (eid, emod.type_id, emod.data))
        } else {
            None
        };

        cache.push(id, entry);
        evicted
    }

    /// Removes and returns the modifier for `id` from the appropriate cache
    /// tier, or `None` if not present.
    pub fn remove(&mut self, id: &ModifierId, type_id: u8) -> Option<(ModifierId, u8, Vec<u8>)> {
        let cache = self.cache_for_mut(type_id);
        cache
            .pop(id)
            .map(|cm| (*id, cm.type_id, cm.data))
    }

    /// Returns `true` if the modifier is present in the appropriate cache tier.
    pub fn contains(&mut self, id: &ModifierId, type_id: u8) -> bool {
        self.cache_for_mut(type_id).contains(id)
    }

    /// Total number of entries across both tiers.
    pub fn len(&self) -> usize {
        self.headers.len() + self.body_sections.len()
    }

    /// Returns `true` if both tiers are empty.
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty() && self.body_sections.is_empty()
    }

    /// Drains all entries from both cache tiers, returning them as a `Vec`.
    ///
    /// Headers are drained first, then body sections.
    pub fn drain_all(&mut self) -> Vec<(ModifierId, u8, Vec<u8>)> {
        let mut result = Vec::with_capacity(self.len());
        while let Some((id, cached)) = self.headers.pop_lru() {
            result.push((id, cached.type_id, cached.data));
        }
        while let Some((id, cached)) = self.body_sections.pop_lru() {
            result.push((id, cached.type_id, cached.data));
        }
        result
    }

    /// Drains all headers from the cache, returning them as a `Vec`.
    pub fn drain_all_headers(&mut self) -> Vec<(ModifierId, u8, Vec<u8>)> {
        let mut out = Vec::with_capacity(self.headers.len());
        while let Some((id, cm)) = self.headers.pop_lru() {
            out.push((id, cm.type_id, cm.data));
        }
        out
    }

    /// Drains all body sections from the cache, returning them as a `Vec`.
    pub fn drain_all_body_sections(&mut self) -> Vec<(ModifierId, u8, Vec<u8>)> {
        let mut out = Vec::with_capacity(self.body_sections.len());
        while let Some((id, cm)) = self.body_sections.pop_lru() {
            out.push((id, cm.type_id, cm.data));
        }
        out
    }

    /// Drains body sections whose `ModifierId` is in the given list.
    ///
    /// This is useful when a header has been applied and we want to pull out
    /// only the body sections that belong to it.
    pub fn drain_body_sections_for(
        &mut self,
        header_ids: &[ModifierId],
    ) -> Vec<(ModifierId, u8, Vec<u8>)> {
        let mut out = Vec::new();
        for hid in header_ids {
            if let Some(cm) = self.body_sections.pop(hid) {
                out.push((*hid, cm.type_id, cm.data));
            }
        }
        out
    }

    /// Find and remove the first cached header at `current_headers_height + 1`.
    pub fn pop_header_candidate(
        &mut self,
        current_headers_height: u32,
    ) -> Option<(ModifierId, u8, Vec<u8>, Option<Header>)> {
        let target_height = current_headers_height + 1;
        let candidate_id = self.headers.iter().find_map(|(id, cm)| {
            if let Some(ref h) = cm.header {
                if h.height == target_height {
                    return Some(*id);
                }
            }
            None
        });
        candidate_id.and_then(|id| {
            self.headers
                .pop(&id)
                .map(|cm| (id, cm.type_id, cm.data, cm.header))
        })
    }

    /// Find and remove a cached body section matching one of the given header IDs.
    pub fn pop_body_candidate(
        &mut self,
        header_ids_at_next_height: &[ModifierId],
    ) -> Option<(ModifierId, u8, Vec<u8>, Option<Header>)> {
        for hid in header_ids_at_next_height {
            if let Some(cm) = self.body_sections.pop(hid) {
                return Some((*hid, cm.type_id, cm.data, cm.header));
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Returns a mutable reference to the appropriate cache tier for the given
    /// modifier type.
    fn cache_for_mut(&mut self, type_id: u8) -> &mut LruCache<ModifierId, CachedModifier> {
        if type_id == HEADER_TYPE_ID {
            &mut self.headers
        } else {
            &mut self.body_sections
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(byte: u8) -> ModifierId {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        ModifierId(bytes)
    }

    #[test]
    fn new_cache_is_empty() {
        let cache = ModifiersCache::with_default_capacities();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn put_header_goes_to_headers_cache() {
        let mut cache = ModifiersCache::with_default_capacities();
        let id = make_id(1);
        cache.put(id, 101, vec![0xAA], None);
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&id, 101));
        // Should not be in body sections
        assert!(!cache.contains(&id, 102));
    }

    #[test]
    fn put_body_goes_to_body_cache() {
        let mut cache = ModifiersCache::with_default_capacities();
        let id_bt = make_id(1);
        let id_ad = make_id(2);
        let id_ext = make_id(3);
        cache.put(id_bt, 102, vec![0x01], None);
        cache.put(id_ad, 104, vec![0x02], None);
        cache.put(id_ext, 108, vec![0x03], None);
        assert_eq!(cache.len(), 3);
        assert!(cache.contains(&id_bt, 102));
        assert!(cache.contains(&id_ad, 104));
        assert!(cache.contains(&id_ext, 108));
        // None of them should be in headers
        assert!(!cache.contains(&id_bt, 101));
    }

    #[test]
    fn remove_returns_entry() {
        let mut cache = ModifiersCache::with_default_capacities();
        let id = make_id(42);
        cache.put(id, 101, vec![0xBB, 0xCC], None);
        let removed = cache.remove(&id, 101);
        assert!(removed.is_some());
        let (rid, rtype, rdata) = removed.unwrap();
        assert_eq!(rid, id);
        assert_eq!(rtype, 101);
        assert_eq!(rdata, vec![0xBB, 0xCC]);
        assert!(cache.is_empty());
    }

    #[test]
    fn lru_eviction_at_capacity() {
        // Use capacity 2 so inserting a 3rd entry evicts the LRU.
        let mut cache = ModifiersCache::new(2, 2);
        let id1 = make_id(1);
        let id2 = make_id(2);
        let id3 = make_id(3);

        assert!(cache.put(id1, 101, vec![0x01], None).is_none());
        assert!(cache.put(id2, 101, vec![0x02], None).is_none());

        // This insert should evict id1 (the LRU entry).
        let evicted = cache.put(id3, 101, vec![0x03], None);
        assert!(evicted.is_some());
        let (eid, etype, edata) = evicted.unwrap();
        assert_eq!(eid, id1);
        assert_eq!(etype, 101);
        assert_eq!(edata, vec![0x01]);

        // id1 is gone, id2 and id3 remain.
        assert!(!cache.contains(&id1, 101));
        assert!(cache.contains(&id2, 101));
        assert!(cache.contains(&id3, 101));
    }

    #[test]
    fn contains_false_for_missing() {
        let mut cache = ModifiersCache::with_default_capacities();
        let id = make_id(99);
        assert!(!cache.contains(&id, 101));
        assert!(!cache.contains(&id, 102));
        assert!(!cache.contains(&id, 104));
        assert!(!cache.contains(&id, 108));
    }

    #[test]
    fn drain_body_sections_for_extracts_matching() {
        let mut cache = ModifiersCache::with_default_capacities();
        let id_a = make_id(10);
        let id_b = make_id(20);
        let id_c = make_id(30);

        cache.put(id_a, 102, vec![0xA0], None);
        cache.put(id_b, 104, vec![0xB0], None);
        cache.put(id_c, 108, vec![0xC0], None);

        // Only drain body sections matching id_a and id_c.
        let drained = cache.drain_body_sections_for(&[id_a, id_c]);
        assert_eq!(drained.len(), 2);

        // Verify the drained entries.
        assert!(drained.iter().any(|(id, ty, _)| *id == id_a && *ty == 102));
        assert!(drained.iter().any(|(id, ty, _)| *id == id_c && *ty == 108));

        // id_b should still be in the cache.
        assert!(cache.contains(&id_b, 104));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn drain_all_headers_empties_header_cache() {
        let mut cache = ModifiersCache::with_default_capacities();
        let id1 = make_id(1);
        let id2 = make_id(2);
        cache.put(id1, 101, vec![0x01], None);
        cache.put(id2, 101, vec![0x02], None);
        // Also add a body section to verify it's not drained.
        let id3 = make_id(3);
        cache.put(id3, 102, vec![0x03], None);

        let headers = cache.drain_all_headers();
        assert_eq!(headers.len(), 2);
        assert_eq!(cache.len(), 1); // only the body section remains
    }

    #[test]
    fn drain_all_body_sections_empties_body_cache() {
        let mut cache = ModifiersCache::with_default_capacities();
        let id1 = make_id(1);
        cache.put(id1, 101, vec![0x01], None);
        let id2 = make_id(2);
        let id3 = make_id(3);
        cache.put(id2, 102, vec![0x02], None);
        cache.put(id3, 108, vec![0x03], None);

        let bodies = cache.drain_all_body_sections();
        assert_eq!(bodies.len(), 2);
        assert_eq!(cache.len(), 1); // only the header remains
    }

    #[test]
    fn drain_all_returns_all_entries() {
        let mut cache = ModifiersCache::with_default_capacities();
        let id1 = make_id(1);
        let id2 = make_id(2);
        cache.put(id1, 101, vec![0xAA], None);
        cache.put(id2, 102, vec![0xBB], None);

        let drained = cache.drain_all();
        assert_eq!(drained.len(), 2);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        // Verify both entries are present (order: headers first, then body).
        assert!(drained.iter().any(|(id, ty, data)| *id == id1 && *ty == 101 && data == &[0xAA]));
        assert!(drained.iter().any(|(id, ty, data)| *id == id2 && *ty == 102 && data == &[0xBB]));
    }

    // ------------------------------------------------------------------
    // pop_header_candidate / pop_body_candidate tests
    // ------------------------------------------------------------------

    fn make_header_at_height(height: u32) -> Header {
        let mut h = Header::default_for_test();
        h.height = height;
        h
    }

    #[test]
    fn pop_header_candidate_sequential() {
        let mut cache = ModifiersCache::new(100, 100);
        // Insert heights 5, 3, 4 (out of order)
        for h in [5u32, 3, 4] {
            let header = make_header_at_height(h);
            cache.put(make_id(h as u8), 101, vec![h as u8], Some(header));
        }

        // Pop at chain height 2 -> should get height 3
        let c = cache.pop_header_candidate(2).unwrap();
        assert_eq!(c.3.unwrap().height, 3);

        // Pop at chain height 3 -> should get height 4
        let c = cache.pop_header_candidate(3).unwrap();
        assert_eq!(c.3.unwrap().height, 4);

        // Pop at chain height 4 -> should get height 5
        let c = cache.pop_header_candidate(4).unwrap();
        assert_eq!(c.3.unwrap().height, 5);

        // Cache is empty now
        assert!(cache.pop_header_candidate(5).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn pop_header_candidate_skips_wrong_height() {
        let mut cache = ModifiersCache::new(100, 100);
        let header = make_header_at_height(10);
        cache.put(make_id(10), 101, vec![10], Some(header));

        // Chain at 5, need 6 — no match
        assert!(cache.pop_header_candidate(5).is_none());
        // Entry is still in cache
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn pop_header_candidate_returns_none_on_empty() {
        let mut cache = ModifiersCache::new(100, 100);
        assert!(cache.pop_header_candidate(0).is_none());
    }

    #[test]
    fn pop_header_candidate_ignores_entries_without_parsed_header() {
        let mut cache = ModifiersCache::new(100, 100);
        // Insert a header entry with no parsed Header (legacy path)
        cache.put(make_id(1), 101, vec![0x01], None);

        // Even at correct height, can't match without parsed header
        assert!(cache.pop_header_candidate(0).is_none());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn pop_body_candidate_matches_header_id() {
        let mut cache = ModifiersCache::new(100, 100);
        let id_a = make_id(1);
        let id_b = make_id(2);
        cache.put(id_a, 102, vec![0xAA], None);
        cache.put(id_b, 104, vec![0xBB], None);

        // Only id_a is at next height
        let c = cache.pop_body_candidate(&[id_a]).unwrap();
        assert_eq!(c.0, id_a);
        assert_eq!(c.1, 102);

        // id_b still in cache
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn pop_body_candidate_returns_none_when_no_match() {
        let mut cache = ModifiersCache::new(100, 100);
        cache.put(make_id(1), 102, vec![0xAA], None);

        // No matching header ID
        assert!(cache.pop_body_candidate(&[make_id(99)]).is_none());
        assert_eq!(cache.len(), 1);
    }
}
