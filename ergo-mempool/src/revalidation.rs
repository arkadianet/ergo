//! Revalidation queue for txs demoted from rolled-back blocks.
//!
//! Demoted txs don't re-enter the active pool directly — they sit in
//! a FIFO queue that is drained per-tick back through the admission
//! pipeline with source `TxSource::DemotedFromBlock`. Bounded at
//! `max_depth` to guard against pathological deep reorgs.

use std::collections::VecDeque;

use crate::types::{DemotedTx, TxId};

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

/// Order demoted txs PARENT-BEFORE-CHILD for re-admission by `tick_revalidation`.
///
/// `snapshot` is `(tx_id, in_pool_parents, bytes)` for every demoted tx, in
/// priority (weight) order. `demote_all_for_revalidation` demotes the WHOLE
/// pool, so every parent edge points within the set. A child's inputs resolve
/// against its parent's pool output, so the drain must re-admit the parent
/// first; the raw weight order can place a high-fee child ahead of its low-fee
/// parent. Kahn's topological sort, sweeping in the input (priority) order so
/// independent txs keep their relative priority as a tie-break. The spend DAG is
/// acyclic; any entry left unemitted by an unexpected cycle is appended in input
/// order so nothing is dropped. O(N²) worst case (a deep chain), bounded by
/// `max_pool_size` and only run on the infrequent demote-all (epoch/reorg) path.
pub(crate) fn topological_demote_order(
    snapshot: Vec<(TxId, Vec<TxId>, std::sync::Arc<[u8]>)>,
) -> Vec<DemotedTx> {
    use std::collections::{HashMap, HashSet};
    let in_set: HashSet<TxId> = snapshot.iter().map(|(id, _, _)| *id).collect();
    // Remaining in-degree = count of in-set parents not yet emitted.
    let mut indeg: HashMap<TxId, usize> = HashMap::with_capacity(snapshot.len());
    let mut children: HashMap<TxId, Vec<TxId>> = HashMap::new();
    for (id, parents, _) in &snapshot {
        indeg.insert(*id, parents.iter().filter(|p| in_set.contains(p)).count());
        for p in parents {
            if in_set.contains(p) {
                children.entry(*p).or_default().push(*id);
            }
        }
    }
    let bytes_of: HashMap<TxId, std::sync::Arc<[u8]>> =
        snapshot.iter().map(|(id, _, b)| (*id, b.clone())).collect();
    let order: Vec<TxId> = snapshot.iter().map(|(id, _, _)| *id).collect();
    let mut emitted: HashSet<TxId> = HashSet::with_capacity(snapshot.len());
    let mut out: Vec<DemotedTx> = Vec::with_capacity(snapshot.len());
    loop {
        let mut progressed = false;
        for id in &order {
            if emitted.contains(id) || indeg.get(id).copied().unwrap_or(0) != 0 {
                continue;
            }
            emitted.insert(*id);
            out.push(DemotedTx {
                tx_id: *id,
                bytes: bytes_of[id].clone(),
            });
            progressed = true;
            if let Some(ch) = children.get(id) {
                for c in ch {
                    if let Some(d) = indeg.get_mut(c) {
                        *d = d.saturating_sub(1);
                    }
                }
            }
        }
        if !progressed {
            break;
        }
    }
    // Defensive: append any unemitted entries (only on an unexpected cycle) in
    // input order — never drop a demoted tx.
    if out.len() < order.len() {
        for id in &order {
            if !emitted.contains(id) {
                out.push(DemotedTx {
                    tx_id: *id,
                    bytes: bytes_of[id].clone(),
                });
            }
        }
    }
    out
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

    /// Digest32 with all bytes = `b` (test id constructor).
    fn d(b: u8) -> Digest32 {
        Digest32::from_bytes([b; 32])
    }

    // ----- topological_demote_order (parent-before-child ordering) -----

    #[test]
    fn topological_demote_order_emits_parents_before_children() {
        // A child listed BEFORE its parent (as the weight-ordered pool would
        // place a high-fee child) must be reordered AFTER the parent, so the
        // drain re-admits the parent first and the child's input resolves.
        // snapshot order: child (d2, parent=[d1]), parent (d1, no parent).
        let snapshot = vec![
            (d(2), vec![d(1)], Arc::from(vec![2u8; 4].into_boxed_slice())),
            (d(1), vec![], Arc::from(vec![1u8; 4].into_boxed_slice())),
        ];
        let out = super::topological_demote_order(snapshot);
        let ids: Vec<_> = out.iter().map(|t| t.tx_id).collect();
        assert_eq!(ids, vec![d(1), d(2)], "parent must come before child");
        assert_eq!(out.len(), 2, "no tx dropped");
    }

    #[test]
    fn topological_demote_order_preserves_priority_for_independent_txs() {
        // Independent txs (no parent edges) keep their input (priority) order.
        let snapshot = vec![
            (d(3), vec![], Arc::from(vec![3u8; 4].into_boxed_slice())),
            (d(1), vec![], Arc::from(vec![1u8; 4].into_boxed_slice())),
            (d(2), vec![], Arc::from(vec![2u8; 4].into_boxed_slice())),
        ];
        let out = super::topological_demote_order(snapshot);
        let ids: Vec<_> = out.iter().map(|t| t.tx_id).collect();
        assert_eq!(ids, vec![d(3), d(1), d(2)], "input order preserved");
    }

    #[test]
    fn topological_demote_order_chain_parent_before_each_descendant() {
        // A 3-deep chain listed leaf-first reorders to root-first.
        // d3 spends d2's output, d2 spends d1's.
        let snapshot = vec![
            (d(3), vec![d(2)], Arc::from(vec![3u8; 4].into_boxed_slice())),
            (d(2), vec![d(1)], Arc::from(vec![2u8; 4].into_boxed_slice())),
            (d(1), vec![], Arc::from(vec![1u8; 4].into_boxed_slice())),
        ];
        let out = super::topological_demote_order(snapshot);
        let ids: Vec<_> = out.iter().map(|t| t.tx_id).collect();
        assert_eq!(ids, vec![d(1), d(2), d(3)], "root-to-leaf order");
    }

    #[test]
    fn topological_demote_order_empty_is_empty() {
        assert!(super::topological_demote_order(vec![]).is_empty());
    }

    #[test]
    fn topological_demote_order_diamond_root_first_join_last() {
        // d1 -> d2, d1 -> d3, {d2,d3} -> d4. Listed leaf-first.
        let b = |x: u8| Arc::from(vec![x; 4].into_boxed_slice());
        let snapshot = vec![
            (d(4), vec![d(2), d(3)], b(4)),
            (d(3), vec![d(1)], b(3)),
            (d(2), vec![d(1)], b(2)),
            (d(1), vec![], b(1)),
        ];
        let out = super::topological_demote_order(snapshot);
        let ids: Vec<_> = out.iter().map(|t| t.tx_id).collect();
        let pos = |x: u8| ids.iter().position(|i| *i == d(x)).unwrap();
        assert_eq!(ids.len(), 4, "no tx dropped");
        assert!(
            pos(1) < pos(2) && pos(1) < pos(3),
            "root before its children"
        );
        assert!(
            pos(2) < pos(4) && pos(3) < pos(4),
            "join after both parents"
        );
    }

    #[test]
    fn topological_demote_order_ignores_outside_parent_edge() {
        // A parent edge pointing OUTSIDE the demoted set (d99 not present) is
        // ignored — the tx is treated as a root, not blocked forever.
        let snapshot = vec![(
            d(1),
            vec![d(99)],
            Arc::from(vec![1u8; 4].into_boxed_slice()),
        )];
        let out = super::topological_demote_order(snapshot);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tx_id, d(1));
    }

    #[test]
    fn topological_demote_order_cycle_appends_leftovers_without_dropping() {
        // A 2-cycle (d1<->d2) can never reach in-degree 0; the defensive tail
        // appends both in input order so nothing is silently dropped. (The real
        // spend DAG is acyclic; this just proves robustness.)
        let b = |x: u8| Arc::from(vec![x; 4].into_boxed_slice());
        let snapshot = vec![(d(1), vec![d(2)], b(1)), (d(2), vec![d(1)], b(2))];
        let out = super::topological_demote_order(snapshot);
        let ids: Vec<_> = out.iter().map(|t| t.tx_id).collect();
        assert_eq!(
            ids,
            vec![d(1), d(2)],
            "cycle members preserved in input order"
        );
    }
}
