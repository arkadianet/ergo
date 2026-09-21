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
/// `input_chain_txs` is keyed by the **announced header's own id**, not
/// by its parent: that is what Scala does, and it is preserved here as-is
/// so the devnet campaign can measure finding F5 instead of hiding it.
#[derive(Debug, Clone, PartialEq)]
pub struct ReconstructionPlan {
    /// The announced ordering block's header id.
    pub header_id: OrderingId,
    /// Transactions the announcement carried in full.
    pub non_broadcasted: Vec<Transaction>,
    /// Transactions the announcement referenced by id; the node resolves
    /// these from its mempool and fails the plan if any is missing.
    pub broadcasted_ids: Vec<[u8; 32]>,
    /// The collected best input chain's transactions for `header_id`
    /// (finding F5: Scala keys this by the announced header's id).
    pub input_chain_txs: Vec<TxRef>,
    /// The `03 02` extension field's value, when present: the last input
    /// block the ordering block builds on.
    pub prev_input_block_id: Option<InputBlockId>,
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
            return self.announcements.shift_remove_index(0).map(|(id, _)| id);
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
    pub fn save_block_transactions(&mut self, header_id: OrderingId, txs: Vec<TxRef>) {
        self.block_transactions.insert(header_id, txs);
    }

    /// Scala `getOrderingBlockTransactions`.
    pub fn block_transactions(&self, header_id: &OrderingId) -> Option<&[TxRef]> {
        self.block_transactions.get(header_id).map(|v| v.as_slice())
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
        let tx_stale: Vec<OrderingId> = self
            .block_transactions
            .keys()
            .filter(|id| block_transactions_known(id))
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
        s.save_block_transactions(id(1), vec![t]);
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
