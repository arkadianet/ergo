//! Revalidation queue for txs demoted from rolled-back blocks.
//!
//! Demoted txs don't re-enter the active pool directly — they sit in
//! a FIFO queue that is drained per-tick back through the admission
//! pipeline with source `TxSource::DemotedFromBlock`. Bounded at
//! `max_depth` to guard against pathological deep reorgs.

use std::collections::VecDeque;

use crate::types::DemotedTx;

pub struct RevalidationQueue {
    queue: VecDeque<DemotedTx>,
    max_depth: usize,
}

impl RevalidationQueue {
    pub fn new(max_depth: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            max_depth,
        }
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Push a demoted tx onto the tail. Returns the number of oldest
    /// entries dropped to stay within `max_depth`. A pathological deep
    /// reorg losing a few revalidations is strictly better than OOM.
    pub fn push(&mut self, tx: DemotedTx) -> usize {
        self.queue.push_back(tx);
        let mut dropped = 0usize;
        while self.queue.len() > self.max_depth {
            self.queue.pop_front();
            dropped += 1;
        }
        dropped
    }

    /// Push a whole batch in order, capping at `max_depth`. Returns
    /// the number of oldest entries dropped.
    pub fn push_batch(&mut self, txs: Vec<DemotedTx>) -> usize {
        let mut dropped = 0usize;
        for tx in txs {
            dropped += self.push(tx);
        }
        dropped
    }

    /// Pop up to `limit` entries from the head. Order preserved.
    pub fn drain(&mut self, limit: usize) -> Vec<DemotedTx> {
        let take = limit.min(self.queue.len());
        let mut out = Vec::with_capacity(take);
        for _ in 0..take {
            if let Some(tx) = self.queue.pop_front() {
                out.push(tx);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::Digest32;
    use std::sync::Arc;

    fn demoted(byte: u8) -> DemotedTx {
        DemotedTx {
            tx_id: Digest32::from_bytes([byte; 32]),
            bytes: Arc::from(vec![byte; 10].into_boxed_slice()),
        }
    }

    // ----- happy path -----

    #[test]
    fn push_respects_cap_and_reports_dropped() {
        let mut q = RevalidationQueue::new(2);
        assert_eq!(q.push(demoted(1)), 0);
        assert_eq!(q.push(demoted(2)), 0);
        assert_eq!(q.push(demoted(3)), 1, "oldest evicted");
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn drain_preserves_order() {
        let mut q = RevalidationQueue::new(10);
        for i in 1..=5u8 {
            q.push(demoted(i));
        }
        let out = q.drain(3);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].tx_id.as_bytes()[0], 1);
        assert_eq!(out[2].tx_id.as_bytes()[0], 3);
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn drain_cap_respects_available() {
        let mut q = RevalidationQueue::new(10);
        q.push(demoted(1));
        let out = q.drain(100);
        assert_eq!(out.len(), 1);
        assert!(q.is_empty());
    }

    #[test]
    fn empty_drain_returns_empty_vec() {
        let mut q = RevalidationQueue::new(10);
        assert!(q.drain(5).is_empty());
    }

    #[test]
    fn push_batch_caps_and_counts() {
        let mut q = RevalidationQueue::new(3);
        let batch = (1..=5u8).map(demoted).collect();
        let dropped = q.push_batch(batch);
        assert_eq!(
            dropped, 2,
            "oldest 2 dropped from a 5-element batch into cap 3"
        );
        assert_eq!(q.len(), 3);
        let out = q.drain(3);
        // Survivors are the 3 most recent: 3, 4, 5.
        assert_eq!(out[0].tx_id.as_bytes()[0], 3);
        assert_eq!(out[2].tx_id.as_bytes()[0], 5);
    }
}
