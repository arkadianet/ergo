//! One-shot read snapshot of the mempool.
//!
//! Mining-candidate generation snapshots the pool at the start of a
//! candidate pass, then iterates the snapshot at its leisure without
//! holding any borrow into `Mempool`. The action loop is free to
//! mutate the pool concurrently; the snapshot is an owned `Vec` of
//! `Entry` clones and outlives any subsequent pool mutation.
//!
//! Constructed via [`MempoolReadSnapshot::from_pool`]. Iteration order
//! is relay priority (highest weight first), matching the in-pool
//! `iter_transactions()` ordering at the moment of snapshot.

use crate::pool::Entry;
use crate::Mempool;

/// Owned snapshot of pooled transactions in relay-priority order.
///
/// Each entry is a `Clone` of an in-pool `Entry`, so the snapshot
/// holds no borrow against the source mempool. `Entry::bytes` is an
/// `Arc<[u8]>`, so the per-entry clone is cheap (refcount bump +
/// copy of small per-entry metadata, no payload reallocation).
#[derive(Debug, Clone)]
pub struct MempoolReadSnapshot {
    entries: Vec<Entry>,
}

impl MempoolReadSnapshot {
    /// Snapshot the current pool in relay-priority order.
    ///
    /// Takes a one-shot copy. The returned snapshot is independent of
    /// `mempool` — subsequent mutations to the pool do not affect it.
    pub fn from_pool(mempool: &Mempool) -> Self {
        Self {
            entries: mempool.iter_transactions().cloned().collect(),
        }
    }

    /// Build a snapshot from an explicit set of entries. Used by
    /// tests that bypass the pool plumbing.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_entries(entries: Vec<Entry>) -> Self {
        Self { entries }
    }

    /// An empty snapshot, for tests only. Production candidate triggers —
    /// including startup and wallet-ready rebuilds — always snapshot the live
    /// pool via [`MempoolReadSnapshot::from_pool`] (which yields an empty
    /// snapshot naturally when the pool happens to be empty), so no real build
    /// intent is ever constructed on a forced-empty mempool. Gating this
    /// constructor out of production builds keeps that guarantee structural.
    #[cfg(any(test, feature = "test-support"))]
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Iterate the snapshot in its captured priority order.
    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter()
    }

    /// Number of entries captured.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if the snapshot is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Consume the snapshot, returning the owned `Vec<Entry>`.
    pub fn into_entries(self) -> Vec<Entry> {
        self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::Entry;
    use crate::types::TxSource;
    use ergo_primitives::digest::Digest32;

    fn synth_entry(weight: u64, tx_id_seed: u8) -> Entry {
        let mut tx_id_bytes = [0u8; 32];
        tx_id_bytes[0] = tx_id_seed;
        let tx_id = Digest32::from_bytes(tx_id_bytes);
        Entry {
            tx_id,
            bytes: std::sync::Arc::from(Vec::<u8>::new().into_boxed_slice()),
            inputs: Vec::new(),
            outputs: Vec::new(),
            parents_in_pool: Vec::new(),
            fee: 0,
            weight,
            size_bytes: 0,
            cost: 0,
            created_at: std::time::Instant::now(),
            last_checked_at: std::time::Instant::now(),
            source: TxSource::Api,
            output_boxes: Vec::new(),
        }
    }

    // ----- happy path -----

    #[test]
    fn from_entries_preserves_order_and_count() {
        let entries = vec![synth_entry(100, 1), synth_entry(50, 2), synth_entry(75, 3)];
        let snap = MempoolReadSnapshot::from_entries(entries.clone());
        assert_eq!(snap.len(), 3);
        assert!(!snap.is_empty());
        let snap_ids: Vec<u8> = snap.iter().map(|e| e.tx_id.as_bytes()[0]).collect();
        assert_eq!(snap_ids, vec![1, 2, 3]);
    }

    #[test]
    fn empty_snapshot_is_empty() {
        let snap = MempoolReadSnapshot::from_entries(Vec::new());
        assert!(snap.is_empty());
        assert_eq!(snap.len(), 0);
        assert_eq!(snap.iter().count(), 0);
    }

    #[test]
    fn into_entries_returns_owned_vec() {
        let entries = vec![synth_entry(10, 1), synth_entry(20, 2)];
        let snap = MempoolReadSnapshot::from_entries(entries);
        let owned = snap.into_entries();
        assert_eq!(owned.len(), 2);
    }

    // ----- snapshot independence -----

    #[test]
    fn snapshot_clone_is_independent() {
        let snap_a = MempoolReadSnapshot::from_entries(vec![synth_entry(1, 1)]);
        let snap_b = snap_a.clone();
        // Both hold their own owned Vec.
        assert_eq!(snap_a.len(), 1);
        assert_eq!(snap_b.len(), 1);
    }
}
