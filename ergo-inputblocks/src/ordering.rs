//! Ordering-block announcement storage and the block-reconstruction plan
//! the node acts on (spec 2.5 `orderingBlockAnnouncements` /
//! `orderingBlockTransactions`, spec 9.3).
//!
//! Scala keeps both maps unbounded and prunes the announcement map only
//! inside `prune()` (`bestHeight - header.height > PruningThreshold * 3`
//! or the block's transactions are already in history). This port keeps
//! that rule and adds an explicit entry cap (spec 7.4) whose overflow
//! drops the oldest announcement.

use indexmap::IndexMap;

use ergo_ser::input_block::OrderingBlockAnnouncement;
use ergo_ser::transaction::Transaction;

use crate::types::{InputBlockId, OrderingId, TxRef};

/// Everything the node needs to rebuild a full block's transaction
/// section from an [`OrderingBlockAnnouncement`] plus the input-block
/// chain the processor collected (spec 9.3).
///
/// `input_chain_txs` is keyed by the announced header's own id when that
/// has a tree and by its PARENT otherwise — divergence D5, upstream
/// finding F5. [`ReconstructionPlan::reconstruction_key`] records which
/// answered, so the divergence stays measurable.
#[derive(Debug, Clone, PartialEq)]
pub struct ReconstructionPlan {
    /// The announced ordering block's header id.
    pub header_id: OrderingId,
    /// Transactions the announcement carried in full.
    pub non_broadcasted: Vec<Transaction>,
    /// Transactions the announcement referenced by id; the node resolves
    /// these from its mempool and fails the plan if any is missing.
    pub broadcasted_ids: Vec<[u8; 32]>,
    /// The collected best input chain's transactions.
    pub input_chain_txs: Vec<TxRef>,
    /// Which ordering id the chain above was read under (D5 telemetry).
    pub reconstruction_key: ReconstructionKey,
    /// The `03 02` extension field's value, when present: the last input
    /// block the ordering block builds on.
    pub prev_input_block_id: Option<InputBlockId>,
}

/// Which ordering id the collected input chain was read under.
///
/// Divergence **D5**, upstream finding **F5**. Scala's follower keys the
/// chain by the announced header's own id
/// (`getCollectedInputBlocksTransactions(headerId)`) while its miner
/// seats the chain collected under the PARENT
/// (`getBestOrderingCollectedInputBlocksTransactions`). The trees are
/// keyed by the block the chain sits ON, so the follower's key names a
/// block with no tree and the lookup returns nothing. Scala's key is
/// tried first and the parent's is the fallback; this says which won.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReconstructionKey {
    /// The announced header's own id — Scala's key.
    #[default]
    SelfId,
    /// The announced header's parent — what the miner's candidate
    /// committed to.
    Parent,
}

impl ReconstructionKey {
    /// The name the event feed and telemetry use.
    pub fn name(self) -> &'static str {
        match self {
            Self::SelfId => "self",
            Self::Parent => "parent",
        }
    }
}

/// Announcements by ordering-block header id, plus the transactions the
/// node has told us an ordering block committed
/// (`saveOrderingBlockTransactions`). Insertion-ordered so "drop the
/// oldest" is well defined.
#[derive(Debug, Default)]
pub struct OrderingStore {
    announcements: IndexMap<OrderingId, OrderingBlockAnnouncement>,
    block_transactions: IndexMap<OrderingId, Vec<TxRef>>,
}

impl OrderingStore {
    /// Store `ann` under its header id. Returns the id of the oldest
    /// announcement evicted to stay within `cap`, if any.
    pub fn insert(
        &mut self,
        header_id: OrderingId,
        ann: OrderingBlockAnnouncement,
        cap: usize,
    ) -> Option<OrderingId> {
        self.announcements.insert(header_id, ann);
        if self.announcements.len() > cap {
            // `shift_remove_index(0)` keeps insertion order for the rest,
            // which is what makes "oldest" meaningful on the next overflow.
            let evicted = self.announcements.shift_remove_index(0).map(|(id, _)| id);
            if let Some(id) = &evicted {
                // The cap bounds `announcements`; without this it would not
                // bound `block_transactions`, whose entry for an evicted
                // announcement can otherwise never be reached by `prune`.
                self.block_transactions.shift_remove(id);
            }
            return evicted;
        }
        None
    }

    /// Scala `getOrderingBlockAnnouncement`.
    pub fn get(&self, header_id: &OrderingId) -> Option<&OrderingBlockAnnouncement> {
        self.announcements.get(header_id)
    }

    /// Number of stored announcements.
    pub fn len(&self) -> usize {
        self.announcements.len()
    }

    /// Whether no announcement is stored.
    pub fn is_empty(&self) -> bool {
        self.announcements.is_empty()
    }

    /// Scala `saveOrderingBlockTransactions`.
    ///
    /// Bounded by `cap` — the same cap [`OrderingStore::insert`] applies
    /// to announcements — because `prune` can only reach a section
    /// through its announcement: a section saved after its announcement
    /// was evicted or height-pruned, or one whose announcement never
    /// arrives at all, is otherwise retained forever. Returns the id of
    /// the oldest section evicted to stay within `cap`, if any.
    pub fn save_block_transactions(
        &mut self,
        header_id: OrderingId,
        txs: Vec<TxRef>,
        cap: usize,
    ) -> Option<OrderingId> {
        self.block_transactions.insert(header_id, txs);
        if self.block_transactions.len() > cap {
            // `shift_remove_index(0)` keeps insertion order for the rest,
            // which is what makes "oldest" meaningful on the next overflow.
            return self
                .block_transactions
                .shift_remove_index(0)
                .map(|(id, _)| id);
        }
        None
    }

    /// Scala `getOrderingBlockTransactions`.
    pub fn block_transactions(&self, header_id: &OrderingId) -> Option<&[TxRef]> {
        self.block_transactions.get(header_id).map(|v| v.as_slice())
    }

    /// Number of stored transaction sections. Bounded by the cap passed
    /// to [`OrderingStore::save_block_transactions`].
    pub fn block_transactions_len(&self) -> usize {
        self.block_transactions.len()
    }

    /// Scala `prune()`'s announcement phase: drop announcements more than
    /// `threshold` ordering blocks behind `best_height`, and those whose
    /// block transactions the node already has in history
    /// (`historyReader.contains(header.transactionsId)`, supplied here as
    /// `block_transactions_known`). Returns the dropped ids.
    ///
    /// The `block_transactions` map is swept by the same height rule.
    /// Scala never prunes it at all — an unbounded leak this port
    /// deliberately closes, recorded as a divergence in the task report.
    pub fn prune(
        &mut self,
        best_height: u32,
        threshold: u32,
        block_transactions_known: &dyn Fn(&OrderingId) -> bool,
    ) -> Vec<OrderingId> {
        let stale = |height: u32| best_height.saturating_sub(height) > threshold;
        let dropped: Vec<OrderingId> = self
            .announcements
            .iter()
            .filter(|(id, ann)| stale(ann.header.height) || block_transactions_known(id))
            .map(|(id, _)| *id)
            .collect();
        for id in &dropped {
            self.announcements.shift_remove(id);
        }
        // A transaction list carries no height of its own, so the height
        // rule can only reach it through its announcement: sweep the ids
        // this very pass dropped as well as the ones history already has.
        // An entry whose announcement is merely MISSING is kept —
        // `saveOrderingBlockTransactions` can land before the announcement
        // it belongs to, and dropping it then would lose a live section.
        let tx_stale: Vec<OrderingId> = self
            .block_transactions
            .keys()
            .filter(|id| block_transactions_known(id) || dropped.contains(id))
            .copied()
            .collect();
        for id in &tx_stale {
            self.block_transactions.shift_remove(id);
        }
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_ser::header::Header;

    // ----- helpers -----

    fn id(b: u8) -> OrderingId {
        [b; 32]
    }

    fn tx(b: u8) -> TxRef {
        TxRef {
            tx_id: [b; 32],
            witness_id: [b; 31],
        }
    }

    fn ann(height: u32) -> OrderingBlockAnnouncement {
        use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
        use ergo_primitives::group_element::GroupElement;
        use ergo_ser::autolykos::AutolykosSolution;
        OrderingBlockAnnouncement {
            version: 1,
            header: Header {
                version: 2,
                parent_id: ModifierId::from_bytes([0x11; 32]),
                ad_proofs_root: Digest32::from_bytes([0x22; 32]),
                transactions_root: Digest32::from_bytes([0x44; 32]),
                state_root: ADDigest::from_bytes([0x33; 33]),
                timestamp: 1,
                extension_root: Digest32::from_bytes([0x55; 32]),
                n_bits: 1,
                height,
                votes: [0, 0, 0],
                unparsed_bytes: vec![],
                solution: AutolykosSolution::V2 {
                    pk: GroupElement::from_bytes([0x02; 33]),
                    nonce: [0; 8],
                },
            },
            non_broadcasted_transactions: Vec::new(),
            broadcasted_transaction_ids: Vec::new(),
            extension_fields: Vec::new(),
            unparsed_bytes: Vec::new(),
        }
    }

    // ----- happy path -----

    #[test]
    fn insert_and_get_round_trip() {
        let mut s = OrderingStore::default();
        assert!(s.is_empty());
        assert_eq!(s.insert(id(1), ann(10), 4), None);
        assert_eq!(s.get(&id(1)).map(|a| a.header.height), Some(10));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn block_transactions_round_trip() {
        let mut s = OrderingStore::default();
        let t = TxRef {
            tx_id: [1; 32],
            witness_id: [2; 31],
        };
        s.save_block_transactions(id(1), vec![t], 64);
        assert_eq!(s.block_transactions(&id(1)), Some(&[t][..]));
    }

    // ----- error paths -----

    #[test]
    fn insert_over_cap_evicts_oldest() {
        let mut s = OrderingStore::default();
        assert_eq!(s.insert(id(1), ann(1), 2), None);
        assert_eq!(s.insert(id(2), ann(2), 2), None);
        assert_eq!(s.insert(id(3), ann(3), 2), Some(id(1)));
        assert!(s.get(&id(1)).is_none());
        assert_eq!(s.len(), 2);
    }

    /// The entry cap has to bound both maps: an evicted announcement is
    /// unreachable by `prune`'s height rule, so its transaction list would
    /// otherwise stay forever.
    #[test]
    fn insert_over_cap_evicts_the_matching_block_transactions() {
        let mut s = OrderingStore::default();
        s.insert(id(1), ann(1), 2);
        s.save_block_transactions(id(1), vec![tx(1)], 64);
        s.insert(id(2), ann(2), 2);
        s.save_block_transactions(id(2), vec![tx(2)], 64);

        assert_eq!(s.insert(id(3), ann(3), 2), Some(id(1)));
        assert!(s.block_transactions(&id(1)).is_none());
        assert!(s.block_transactions(&id(2)).is_some());
    }

    /// A losing ordering block's transaction section never reaches
    /// history, so `block_transactions_known` stays false for it forever.
    /// Pruning its announcement by height must take the section with it,
    /// or repeated distinct saves grow the map without bound.
    #[test]
    fn prune_drops_block_transactions_of_height_pruned_announcements() {
        let mut s = OrderingStore::default();
        s.insert(id(1), ann(100 - 7), 64);
        s.save_block_transactions(id(1), vec![tx(1)], 64);
        s.insert(id(2), ann(100), 64);
        s.save_block_transactions(id(2), vec![tx(2)], 64);

        let never_known = |_: &OrderingId| false;
        let dropped = s.prune(100, 6, &never_known);

        assert_eq!(dropped, vec![id(1)]);
        assert!(s.block_transactions(&id(1)).is_none());
        assert!(s.block_transactions(&id(2)).is_some());
    }

    /// The section map needs a cap of its own: repeated saves for ids
    /// whose announcements never arrive are exactly the case `prune`
    /// cannot reach (no announcement to carry the height rule, and
    /// `block_transactions_known` stays false for a block history never
    /// accepts), so without one the map grows without bound.
    #[test]
    fn save_block_transactions_over_cap_evicts_oldest() {
        let mut s = OrderingStore::default();
        for i in 0..3u8 {
            assert_eq!(s.save_block_transactions(id(i), vec![tx(i)], 3), None);
        }
        // Nothing has an announcement, and nothing is in history: prune
        // is powerless here, so only the cap can bound the map.
        let never_known = |_: &OrderingId| false;

        for i in 3..64u8 {
            let evicted = s.save_block_transactions(id(i), vec![tx(i)], 3);
            assert_eq!(evicted, Some(id(i - 3)), "eviction must be oldest-first");
            assert!(s.prune(1_000, 6, &never_known).is_empty());
        }

        // Only the three most recent saves survive; 64 distinct saves
        // did not grow the map past the cap.
        assert_eq!(s.block_transactions_len(), 3);
        for i in 61..64u8 {
            assert!(s.block_transactions(&id(i)).is_some(), "id({i}) evicted");
        }
        assert!(s.block_transactions(&id(60)).is_none());
        assert!(s.block_transactions(&id(0)).is_none());
    }

    /// A transaction section can be saved before its announcement
    /// arrives. A missing announcement is not evidence of staleness, so
    /// the sweep must leave such an entry alone.
    #[test]
    fn prune_keeps_block_transactions_whose_announcement_has_not_arrived() {
        let mut s = OrderingStore::default();
        s.save_block_transactions(id(9), vec![tx(9)], 64);

        let never_known = |_: &OrderingId| false;
        assert!(s.prune(100, 6, &never_known).is_empty());
        assert!(s.block_transactions(&id(9)).is_some());
    }

    // ----- oracle parity -----

    #[test]
    fn prune_drops_stale_and_known_announcements() {
        // Scala prune(): `(bestHeight - header.height) > threshold ||
        // historyReader.contains(header.transactionsId)`.
        let mut s = OrderingStore::default();
        s.insert(id(1), ann(100 - 7), 64);
        s.insert(id(2), ann(100 - 6), 64);
        s.insert(id(3), ann(100), 64);
        let known = |x: &OrderingId| *x == id(3);
        let dropped = s.prune(100, 6, &known);
        assert_eq!(dropped, vec![id(1), id(3)]);
        assert_eq!(s.len(), 1);
        assert!(s.get(&id(2)).is_some());
    }
}
