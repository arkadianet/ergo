//! Block section assembly: tracks which sections have arrived for each
//! header and determines when a full block can be assembled.
//!
//! Per P2P protocol spec Section 9:
//! - A full block in UTXO mode requires: Header + BlockTransactions + Extension
//! - Sections are keyed by their computed modifier_id (not header_id)
//! - Section ID = blake2b256_prefixed(type_id, header_id, section_digest)
//! - Duplicate sections for the same modifier_id are ignored
//!
//! The protocol-level identity for non-header block sections — type
//! constants, the `compute_section_id` hash recipe, and the
//! `ExpectedSections` projection over a header's three roots — lives
//! in [`ergo_ser::modifier_id`] so non-transport crates can derive
//! section IDs without depending on `ergo-p2p`. This module owns the
//! runtime aggregator that tracks which sections have arrived per
//! pending header.

use std::collections::HashMap;

use ergo_ser::modifier_id::{
    ExpectedSections, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
};

/// Tracks section arrival for pending blocks.
///
/// Uses a reverse index (section modifier_id → header_id) for O(1) lookup
/// on section arrival, instead of scanning all tracked headers.
pub struct AssemblyTracker {
    /// header_id → section completion state.
    headers: HashMap<[u8; 32], SectionState>,
    /// Reverse index: section modifier_id → (section_type, header_id).
    section_index: HashMap<[u8; 32], (u8, [u8; 32])>,
}

struct SectionState {
    has_transactions: bool,
    has_extension: bool,
    has_ad_proofs: bool,
}

impl AssemblyTracker {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
            section_index: HashMap::new(),
        }
    }

    /// Register expected sections for a header (call after header is validated).
    pub fn register_header(&mut self, expected: ExpectedSections) {
        let hid = expected.header_id;
        if self.headers.contains_key(&hid) {
            return; // already tracking
        }
        // Build reverse index entries
        self.section_index
            .insert(expected.transactions_id, (TYPE_BLOCK_TRANSACTIONS, hid));
        self.section_index
            .insert(expected.extension_id, (TYPE_EXTENSION, hid));
        self.section_index
            .insert(expected.ad_proofs_id, (TYPE_AD_PROOFS, hid));

        self.headers.insert(
            hid,
            SectionState {
                has_transactions: false,
                has_extension: false,
                has_ad_proofs: false,
            },
        );
    }

    /// Record that a section with the given modifier_id has been received.
    /// Returns Some(header_id) only on the FIRST completion (idempotent).
    /// Subsequent calls for the same section return None.
    pub fn section_received(&mut self, modifier_id: &[u8; 32]) -> Option<[u8; 32]> {
        let (section_type, header_id) = self.section_index.get(modifier_id)?;
        let header_id = *header_id;
        let section_type = *section_type;
        let state = self.headers.get_mut(&header_id)?;

        let was_complete = state.has_transactions && state.has_extension;

        match section_type {
            TYPE_BLOCK_TRANSACTIONS => state.has_transactions = true,
            TYPE_EXTENSION => state.has_extension = true,
            TYPE_AD_PROOFS => state.has_ad_proofs = true,
            _ => return None,
        }

        let is_complete = state.has_transactions && state.has_extension;
        // Only signal completion on the transition from incomplete → complete.
        if is_complete && !was_complete {
            Some(header_id)
        } else {
            None
        }
    }

    /// Check if a full block is ready for a given header (UTXO mode).
    pub fn is_complete(&self, header_id: &[u8; 32]) -> bool {
        self.headers
            .get(header_id)
            .is_some_and(|s| s.has_transactions && s.has_extension)
    }

    /// Remove tracking for a header (after block assembled and applied).
    /// Also cleans up the reverse index.
    pub fn remove(&mut self, header_id: &[u8; 32]) {
        self.headers.remove(header_id);
        self.section_index.retain(|_, (_, hid)| hid != header_id);
    }

    /// Number of headers being tracked.
    pub fn pending_count(&self) -> usize {
        self.headers.len()
    }

    /// Look up which header a section modifier_id belongs to. O(1).
    pub fn identify_section(&self, modifier_id: &[u8; 32]) -> Option<(u8, [u8; 32])> {
        self.section_index.get(modifier_id).copied()
    }

    /// Get the expected section IDs for a header (type_id, section_id pairs).
    /// Returns None if the header isn't tracked.
    pub fn expected_section_ids(&self, header_id: &[u8; 32]) -> Option<Vec<(u8, [u8; 32])>> {
        if !self.headers.contains_key(header_id) {
            return None;
        }
        let mut result = Vec::new();
        for (section_id, (type_id, hid)) in &self.section_index {
            if hid == header_id {
                result.push((*type_id, *section_id));
            }
        }
        Some(result)
    }
}

impl Default for AssemblyTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn mk(v: u8) -> [u8; 32] {
        [v; 32]
    }

    // ----- happy path -----

    #[test]
    fn assembly_tracks_sections() {
        let mut tracker = AssemblyTracker::new();
        let header_id = mk(1);
        let tx_root = mk(2);
        let ext_root = mk(3);
        let proof_root = mk(4);

        let expected = ExpectedSections::from_header(&header_id, &tx_root, &ext_root, &proof_root);
        let tx_id = expected.transactions_id;
        let ext_id = expected.extension_id;

        tracker.register_header(expected);
        assert!(!tracker.is_complete(&header_id));

        // Receive transactions — not complete yet
        let result = tracker.section_received(&tx_id);
        assert!(result.is_none());
        assert!(!tracker.is_complete(&header_id));

        // Receive extension — now complete
        let result = tracker.section_received(&ext_id);
        assert_eq!(result, Some(header_id));
        assert!(tracker.is_complete(&header_id));
    }

    #[test]
    fn unknown_section_returns_none() {
        let mut tracker = AssemblyTracker::new();
        let result = tracker.section_received(&mk(99));
        assert!(result.is_none());
    }

    #[test]
    fn identify_section_type() {
        let mut tracker = AssemblyTracker::new();
        let header_id = mk(1);
        let expected = ExpectedSections::from_header(&header_id, &mk(2), &mk(3), &mk(4));
        let tx_id = expected.transactions_id;
        let ext_id = expected.extension_id;

        tracker.register_header(expected);

        let (type_id, hid) = tracker.identify_section(&tx_id).unwrap();
        assert_eq!(type_id, TYPE_BLOCK_TRANSACTIONS);
        assert_eq!(hid, header_id);

        let (type_id, _) = tracker.identify_section(&ext_id).unwrap();
        assert_eq!(type_id, TYPE_EXTENSION);

        assert!(tracker.identify_section(&mk(99)).is_none());
    }

    #[test]
    fn remove_cleans_up() {
        let mut tracker = AssemblyTracker::new();
        let header_id = mk(1);
        let expected = ExpectedSections::from_header(&header_id, &mk(2), &mk(3), &mk(4));
        tracker.register_header(expected);
        assert_eq!(tracker.pending_count(), 1);

        tracker.remove(&header_id);
        assert_eq!(tracker.pending_count(), 0);
    }
}
