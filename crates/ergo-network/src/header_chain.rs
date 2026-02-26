//! In-memory storage for validated block headers.
//!
//! Tracks headers by ID and by height, maintaining the best (highest) chain tip.
//! In Phase 3, this will be backed by persistent storage.

use ergo_types::header::Header;
use ergo_types::modifier_id::ModifierId;
use std::collections::HashMap;

/// In-memory storage for validated block headers.
///
/// Tracks headers by ID and by height, maintaining the best (highest) chain tip.
/// In Phase 3, this will be backed by persistent storage.
pub struct HeaderChain {
    headers: HashMap<ModifierId, Header>,
    height_index: HashMap<u32, ModifierId>,
    best_height: u32,
}

impl HeaderChain {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
            height_index: HashMap::new(),
            best_height: 0,
        }
    }

    /// Insert a header. Updates best_height if this header is higher.
    pub fn insert(&mut self, id: ModifierId, header: Header) {
        if header.height > self.best_height {
            self.best_height = header.height;
        }
        self.height_index.insert(header.height, id);
        self.headers.insert(id, header);
    }

    pub fn get(&self, id: &ModifierId) -> Option<&Header> {
        self.headers.get(id)
    }

    pub fn contains(&self, id: &ModifierId) -> bool {
        self.headers.contains_key(id)
    }

    pub fn best_height(&self) -> u32 {
        self.best_height
    }

    pub fn id_at_height(&self, height: u32) -> Option<ModifierId> {
        self.height_index.get(&height).copied()
    }

    pub fn best_header(&self) -> Option<&Header> {
        self.height_index
            .get(&self.best_height)
            .and_then(|id| self.headers.get(id))
    }
}

impl Default for HeaderChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::header::Header;
    use ergo_types::modifier_id::ModifierId;

    fn make_header(height: u32, parent_id: ModifierId) -> (ModifierId, Header) {
        let mut h = Header::default_for_test();
        h.height = height;
        h.parent_id = parent_id;
        h.timestamp = height as u64 * 120_000;
        let mut id_bytes = [0u8; 32];
        id_bytes[0..4].copy_from_slice(&height.to_be_bytes());
        (ModifierId(id_bytes), h)
    }

    #[test]
    fn insert_and_retrieve() {
        let mut chain = HeaderChain::new();
        let (id, header) = make_header(1, ModifierId::GENESIS_PARENT);
        chain.insert(id, header);
        assert_eq!(chain.get(&id).unwrap().height, 1);
    }

    #[test]
    fn best_header_tracks_highest() {
        let mut chain = HeaderChain::new();
        let (id1, h1) = make_header(1, ModifierId::GENESIS_PARENT);
        chain.insert(id1, h1);
        assert_eq!(chain.best_height(), 1);
        let (id2, h2) = make_header(2, id1);
        chain.insert(id2, h2);
        assert_eq!(chain.best_height(), 2);
    }

    #[test]
    fn header_by_height() {
        let mut chain = HeaderChain::new();
        let (id1, h1) = make_header(1, ModifierId::GENESIS_PARENT);
        chain.insert(id1, h1);
        let (id2, h2) = make_header(2, id1);
        chain.insert(id2, h2);
        assert_eq!(chain.id_at_height(1), Some(id1));
        assert_eq!(chain.id_at_height(2), Some(id2));
        assert_eq!(chain.id_at_height(3), None);
    }

    #[test]
    fn contains() {
        let mut chain = HeaderChain::new();
        let (id, h) = make_header(1, ModifierId::GENESIS_PARENT);
        assert!(!chain.contains(&id));
        chain.insert(id, h);
        assert!(chain.contains(&id));
    }

    #[test]
    fn best_header() {
        let mut chain = HeaderChain::new();
        assert!(chain.best_header().is_none());
        let (id, h) = make_header(1, ModifierId::GENESIS_PARENT);
        chain.insert(id, h);
        assert_eq!(chain.best_header().unwrap().height, 1);
    }
}
