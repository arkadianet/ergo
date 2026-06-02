//! UTXO overlays for mempool admission.
//!
//! The overlay does NOT mask pool-spent committed boxes — replacement
//! txs legitimately spend the same committed box that an existing
//! pool tx spends. Conflict detection runs separately via the
//! `by_input` index.
//!
//! Data inputs are resolved through `CommittedOnly`, never the
//! overlay, so they cannot depend on unconfirmed pool outputs.

use std::collections::HashMap;

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_validation::UtxoView;

/// Overlay over a committed UTXO view, augmented with outputs created by
/// currently-pooled transactions. Used to resolve regular inputs during
/// admission.
pub struct PoolUtxoOverlay<'a> {
    base: &'a dyn UtxoView,
    created_by_pool: &'a HashMap<Digest32, ErgoBox>,
}

impl<'a> PoolUtxoOverlay<'a> {
    pub fn new(base: &'a dyn UtxoView, created_by_pool: &'a HashMap<Digest32, ErgoBox>) -> Self {
        Self {
            base,
            created_by_pool,
        }
    }
}

impl UtxoView for PoolUtxoOverlay<'_> {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        // Pool-created outputs shadow `base`. In practice the two
        // never overlap because `box_id = H(tx_id || out_idx)` and
        // tx_ids are unique. Explicit priority keeps the contract
        // unambiguous.
        if let Some(b) = self.created_by_pool.get(box_id) {
            return Some(b.clone());
        }
        self.base.get_box(box_id)
    }
}

/// Committed-UTXO-only view. Used for data-input resolution so a tx
/// cannot observe an unconfirmed pool output via a data input.
pub struct CommittedOnly<'a> {
    base: &'a dyn UtxoView,
}

impl<'a> CommittedOnly<'a> {
    pub fn new(base: &'a dyn UtxoView) -> Self {
        Self { base }
    }
}

impl UtxoView for CommittedOnly<'_> {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.base.get_box(box_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::read_ergo_tree;
    use ergo_ser::register::AdditionalRegisters;

    struct FakeUtxo {
        boxes: HashMap<Digest32, ErgoBox>,
    }

    impl FakeUtxo {
        fn empty() -> Self {
            Self {
                boxes: HashMap::new(),
            }
        }

        fn with_box(mut self, id: Digest32, b: ErgoBox) -> Self {
            self.boxes.insert(id, b);
            self
        }
    }

    impl UtxoView for FakeUtxo {
        fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
            self.boxes.get(box_id).cloned()
        }
    }

    fn id(b: u8) -> Digest32 {
        Digest32::from_bytes([b; 32])
    }

    /// Minimal ErgoBox: version 0 tree with body `0x01 0x01` (SBoolean
    /// true). Contents are immaterial to overlay semantics; the tests
    /// only check that `get_box()` returns the right instance.
    fn dummy_box(id_byte: u8) -> ErgoBox {
        let tree_bytes = vec![0x00u8, 0x01, 0x01];
        let mut r = VlqReader::new(&tree_bytes);
        let tree = read_ergo_tree(&mut r).expect("parse tree");
        let candidate =
            ErgoBoxCandidate::new(1_000_000, tree, 0, vec![], AdditionalRegisters::empty())
                .expect("candidate");
        ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes([id_byte; 32]),
            index: 0,
        }
    }

    // ----- happy path -----

    #[test]
    fn overlay_passes_through_committed_box() {
        let committed = FakeUtxo::empty().with_box(id(1), dummy_box(1));
        let pool: HashMap<Digest32, ErgoBox> = HashMap::new();
        let view = PoolUtxoOverlay::new(&committed, &pool);
        assert!(view.get_box(&id(1)).is_some());
        assert!(view.get_box(&id(2)).is_none());
    }

    #[test]
    fn overlay_returns_pool_output_when_present() {
        let committed = FakeUtxo::empty();
        let mut pool: HashMap<Digest32, ErgoBox> = HashMap::new();
        pool.insert(id(5), dummy_box(5));
        let view = PoolUtxoOverlay::new(&committed, &pool);
        assert!(view.get_box(&id(5)).is_some());
    }

    #[test]
    fn overlay_does_not_mask_pool_spent_committed() {
        // Replacement-via-double-spend invariant: a committed box that
        // a pool tx already spends must remain visible through the
        // overlay, so a replacement tx can resolve it and admission
        // can then route to double-spend resolution via `by_input`.
        let committed = FakeUtxo::empty().with_box(id(1), dummy_box(1));
        let pool: HashMap<Digest32, ErgoBox> = HashMap::new();
        let view = PoolUtxoOverlay::new(&committed, &pool);
        // Even if the mempool's by_input.contains(id(1)) (simulated by
        // the caller), the overlay still returns the box.
        assert!(view.get_box(&id(1)).is_some());
    }

    #[test]
    fn committed_only_ignores_pool() {
        let committed = FakeUtxo::empty().with_box(id(7), dummy_box(7));
        let view = CommittedOnly::new(&committed);
        assert!(view.get_box(&id(7)).is_some());
        assert!(view.get_box(&id(8)).is_none());
    }

    #[test]
    fn committed_only_is_pool_blind() {
        // Even if a pool map were supplied to overlay, CommittedOnly
        // wouldn't see it.
        let committed = FakeUtxo::empty();
        let view = CommittedOnly::new(&committed);
        assert!(view.get_box(&id(42)).is_none());
    }
}
