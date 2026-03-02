//! Full block assembly and progress signaling for [`HistoryDb`].
//!
//! After individual block sections (header, block transactions, extension,
//! AD proofs) have been received from the network, this module provides
//! logic to check completeness, assemble full blocks, and signal what the
//! coordinator should do next via [`ProgressInfo`].

use ergo_types::modifier_id::ModifierId;
use ergo_types::transaction::ErgoFullBlock;

use crate::history_db::{HistoryDb, StorageError};

// ---------------------------------------------------------------------------
// Section type IDs (matching Scala modifier type IDs)
// ---------------------------------------------------------------------------

/// Header modifier type ID.
const HEADER_TYPE_ID: u8 = 101;

/// BlockTransactions modifier type ID.
const BLOCK_TX_TYPE_ID: u8 = 102;

/// ADProofs modifier type ID.
const AD_PROOFS_TYPE_ID: u8 = 104;

/// Extension modifier type ID.
const EXTENSION_TYPE_ID: u8 = 108;

// ---------------------------------------------------------------------------
// ProgressInfo
// ---------------------------------------------------------------------------

/// Signals what the coordinator should do after processing a modifier.
///
/// Returned by `process_header` and `process_block_section` to instruct the
/// caller about chain switches, block application, or further downloads.
#[derive(Debug, Clone)]
pub struct ProgressInfo {
    /// Rollback target for chain switch (`None` if no switch).
    pub branch_point: Option<ModifierId>,
    /// Block IDs to unapply (old chain).
    pub to_remove: Vec<ModifierId>,
    /// Block IDs to apply (new chain).
    pub to_apply: Vec<ModifierId>,
    /// Sections to download: `(type_id, modifier_id)`.
    pub to_download: Vec<(u8, ModifierId)>,
}

impl ProgressInfo {
    /// Creates an empty `ProgressInfo` with no actions.
    pub fn empty() -> Self {
        Self {
            branch_point: None,
            to_remove: Vec::new(),
            to_apply: Vec::new(),
            to_download: Vec::new(),
        }
    }

    /// Creates a `ProgressInfo` requesting downloads for the given items.
    pub fn download(items: Vec<(u8, ModifierId)>) -> Self {
        Self {
            branch_point: None,
            to_remove: Vec::new(),
            to_apply: Vec::new(),
            to_download: items,
        }
    }

    /// Creates a `ProgressInfo` requesting application of the given block IDs.
    pub fn apply(ids: Vec<ModifierId>) -> Self {
        Self {
            branch_point: None,
            to_remove: Vec::new(),
            to_apply: ids,
            to_download: Vec::new(),
        }
    }

    /// Creates a `ProgressInfo` for a chain switch.
    ///
    /// `branch_point` is the lowest common ancestor between the old and new
    /// chains. `to_remove` lists the blocks to unapply (old chain, from tip
    /// back to just after the branch point). `to_apply` lists the blocks to
    /// apply (new chain, from just after the branch point to the new tip).
    pub fn chain_switch(
        branch_point: ModifierId,
        to_remove: Vec<ModifierId>,
        to_apply: Vec<ModifierId>,
    ) -> Self {
        Self {
            branch_point: Some(branch_point),
            to_remove,
            to_apply,
            to_download: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// HistoryDb block processing methods
// ---------------------------------------------------------------------------

impl HistoryDb {
    /// Walk the header chain from `best_full_block_height + 1` forward,
    /// collecting missing block body sections up to `max` entries.
    ///
    /// Returns `Vec<(type_id, section_id)>` for sections that need downloading.
    /// The section_id is the computed wire ID (`blake2b256([type_id] ++ header_id ++ root)`),
    /// which peers use to identify body sections on the network.
    /// Internal DB lookups still use header_id.
    pub fn next_modifiers_to_download(&self, max: usize) -> Vec<(u8, ModifierId)> {
        let start_height = self.best_full_block_height().unwrap_or(0) + 1;
        let mut result = Vec::new();

        for height in start_height.. {
            let ids = match self.header_ids_at_height(height) {
                Ok(ids) if !ids.is_empty() => ids,
                _ => break, // no headers at this height — end of chain
            };

            for header_id in ids {
                let header = match self.load_header(&header_id) {
                    Ok(Some(h)) => h,
                    _ => continue,
                };
                let sections = header.section_ids(&header_id);
                for (type_id, section_id) in &sections {
                    // Check by header_id (internal DB key)
                    if !self.contains_modifier(*type_id, &header_id).unwrap_or(true) {
                        // Return section_id for the wire
                        result.push((*type_id, *section_id));
                        if result.len() >= max {
                            return result;
                        }
                    }
                }
            }
        }

        result
    }

    /// Get the height of the best full block, or `None` if no full blocks exist.
    pub fn best_full_block_height(&self) -> Option<u32> {
        let best_id = self.best_full_block_id().ok()??;
        let header = self.load_header(&best_id).ok()??;
        Some(header.height)
    }

    /// Check if all required sections for a full block are present.
    ///
    /// A full block needs: Header (101) + BlockTransactions (102) +
    /// Extension (108). ADProofs (104) is optional.
    pub fn has_all_sections(&self, header_id: &ModifierId) -> Result<bool, StorageError> {
        let has_header = self.contains_modifier(HEADER_TYPE_ID, header_id)?;
        let has_block_tx = self.contains_modifier(BLOCK_TX_TYPE_ID, header_id)?;
        let has_extension = self.contains_modifier(EXTENSION_TYPE_ID, header_id)?;
        Ok(has_header && has_block_tx && has_extension)
    }

    /// Assemble a full block from its stored sections.
    ///
    /// Returns `Ok(None)` if any required section (header, block transactions,
    /// or extension) is missing. ADProofs are included when present but are
    /// not required.
    pub fn assemble_full_block(
        &self,
        header_id: &ModifierId,
    ) -> Result<Option<ErgoFullBlock>, StorageError> {
        let header = match self.load_header(header_id)? {
            Some(h) => h,
            None => return Ok(None),
        };

        let block_transactions = match self.load_block_transactions(header_id)? {
            Some(bt) => bt,
            None => return Ok(None),
        };

        let extension = match self.load_extension(header_id)? {
            Some(ext) => ext,
            None => return Ok(None),
        };

        let ad_proofs = self.load_ad_proofs(header_id)?;

        Ok(Some(ErgoFullBlock {
            header,
            block_transactions,
            extension,
            ad_proofs,
        }))
    }

    /// Process a newly received header: determine what sections to download.
    ///
    /// Returns a [`ProgressInfo`] with `to_download` containing the three
    /// section types needed for a full block: BlockTransactions (102),
    /// ADProofs (104), and Extension (108).
    pub fn process_header(&self, header_id: &ModifierId) -> Result<ProgressInfo, StorageError> {
        let to_download = vec![
            (BLOCK_TX_TYPE_ID, *header_id),
            (AD_PROOFS_TYPE_ID, *header_id),
            (EXTENSION_TYPE_ID, *header_id),
        ];
        Ok(ProgressInfo::download(to_download))
    }

    /// Process a received block section: check for block completion and
    /// detect chain switches.
    ///
    /// The actual section data is expected to already be stored by the caller
    /// before invoking this method. This function checks whether all required
    /// sections are now present and, if so, determines whether this block
    /// belongs to a heavier chain than the current best full block.
    ///
    /// Returns:
    /// - An empty [`ProgressInfo`] if the block is still incomplete.
    /// - A simple `to_apply` if there is no current best full block (first
    ///   complete block) or the new block extends the current best chain.
    /// - A [`ProgressInfo::chain_switch`] with `branch_point`, `to_remove`,
    ///   and `to_apply` when a fork switch is required.
    /// - A simple `to_apply` even for a lighter fork (the block still needs
    ///   to be tracked).
    pub fn process_block_section(
        &self,
        _type_id: u8,
        _section_id: &ModifierId,
        header_id: &ModifierId,
    ) -> Result<ProgressInfo, StorageError> {
        if !self.has_all_sections(header_id)? {
            return Ok(ProgressInfo::empty());
        }

        // Block is complete. Check if we need a chain switch.
        let current_best = self.best_full_block_id()?;
        match current_best {
            None => {
                // First complete block — just apply it.
                Ok(ProgressInfo::apply(vec![*header_id]))
            }
            Some(best_id) => {
                // Compare cumulative scores.
                let new_score = self
                    .get_header_score(header_id)?
                    .unwrap_or_else(|| vec![0u8]);
                let best_score = self
                    .get_header_score(&best_id)?
                    .unwrap_or_else(|| vec![0u8]);

                if Self::is_score_greater(&new_score, &best_score) {
                    // New block is on a heavier chain — compute fork info.
                    match self.find_common_ancestor(header_id, &best_id)? {
                        Some(branch_point) => {
                            let to_remove = self.chain_from_ancestor(&branch_point, &best_id)?;
                            let to_apply = self.chain_from_ancestor(&branch_point, header_id)?;
                            Ok(ProgressInfo::chain_switch(
                                branch_point,
                                to_remove,
                                to_apply,
                            ))
                        }
                        None => {
                            // No common ancestor found (shouldn't happen
                            // in practice) — just apply.
                            Ok(ProgressInfo::apply(vec![*header_id]))
                        }
                    }
                } else {
                    // Lighter or equal fork — still apply (tracked by caller).
                    Ok(ProgressInfo::apply(vec![*header_id]))
                }
            }
        }
    }

    /// Find the lowest common ancestor of two block IDs.
    ///
    /// Walks both chains backwards from their tips until they meet at the same
    /// block. Returns `None` if the chains share no common ancestor (e.g. one
    /// of the IDs doesn't exist in the database).
    pub fn find_common_ancestor(
        &self,
        id_a: &ModifierId,
        id_b: &ModifierId,
    ) -> Result<Option<ModifierId>, StorageError> {
        let mut a = *id_a;
        let mut b = *id_b;

        let mut h_a = self.load_header(&a)?.map(|h| h.height).unwrap_or(0);
        let mut h_b = self.load_header(&b)?.map(|h| h.height).unwrap_or(0);

        // Walk the higher chain down to the same height.
        while h_a > h_b {
            a = self
                .load_header(&a)?
                .map(|h| h.parent_id)
                .unwrap_or(ModifierId::GENESIS_PARENT);
            h_a -= 1;
        }
        while h_b > h_a {
            b = self
                .load_header(&b)?
                .map(|h| h.parent_id)
                .unwrap_or(ModifierId::GENESIS_PARENT);
            h_b -= 1;
        }

        // Walk both up until they meet.
        while a != b {
            if a == ModifierId::GENESIS_PARENT || b == ModifierId::GENESIS_PARENT {
                return Ok(None);
            }
            a = self
                .load_header(&a)?
                .map(|h| h.parent_id)
                .unwrap_or(ModifierId::GENESIS_PARENT);
            b = self
                .load_header(&b)?
                .map(|h| h.parent_id)
                .unwrap_or(ModifierId::GENESIS_PARENT);
        }
        Ok(Some(a))
    }

    /// Collect the chain of block IDs from `ancestor` (exclusive) to `tip`
    /// (inclusive), ordered from oldest to newest.
    ///
    /// Walks backwards from `tip` to `ancestor`, then reverses the collected
    /// list so that the first element is the block immediately after the
    /// ancestor.
    pub fn chain_from_ancestor(
        &self,
        ancestor: &ModifierId,
        tip: &ModifierId,
    ) -> Result<Vec<ModifierId>, StorageError> {
        let mut chain = Vec::new();
        let mut current = *tip;
        while current != *ancestor && current != ModifierId::GENESIS_PARENT {
            chain.push(current);
            current = self
                .load_header(&current)?
                .map(|h| h.parent_id)
                .unwrap_or(ModifierId::GENESIS_PARENT);
        }
        chain.reverse();
        Ok(chain)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::ad_proofs::ADProofs;
    use ergo_types::block_transactions::BlockTransactions;
    use ergo_types::extension::Extension;
    use ergo_types::header::Header;
    use tempfile::TempDir;

    fn open_test_db() -> (HistoryDb, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = HistoryDb::open(dir.path()).unwrap();
        (db, dir)
    }

    fn make_id(fill: u8) -> ModifierId {
        ModifierId([fill; 32])
    }

    fn make_header(height: u32, fill: u8) -> Header {
        let mut h = Header::default_for_test();
        h.version = 2;
        h.height = height;
        h.parent_id = ModifierId([fill; 32]);
        h
    }

    fn sample_block_transactions(header_id: &ModifierId) -> BlockTransactions {
        use ergo_types::transaction::*;
        use ergo_wire::transaction_ser::serialize_transaction;

        let valid_tree = {
            let mut t = vec![0x08];
            ergo_wire::vlq::put_uint(&mut t, 35);
            t.push(0x08);
            t.push(0xCD);
            t.extend_from_slice(&[0x02; 33]);
            t
        };
        let tx_bytes = serialize_transaction(&ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0x11; 32]),
                proof_bytes: Vec::new(),
                extension_bytes: vec![0x00],
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: valid_tree,
                creation_height: 100_000,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0; 32]),
        });

        BlockTransactions {
            header_id: *header_id,
            block_version: 2,
            tx_bytes: vec![tx_bytes],
        }
    }

    fn sample_extension(header_id: &ModifierId) -> Extension {
        Extension {
            header_id: *header_id,
            fields: vec![([0x00, 0x01], vec![0x10, 0x20])],
        }
    }

    fn sample_ad_proofs(header_id: &ModifierId) -> ADProofs {
        ADProofs {
            header_id: *header_id,
            proof_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }
    }

    /// Store all required sections (header, block transactions, extension)
    /// for the given ID.
    fn store_required_sections(db: &HistoryDb, id: &ModifierId) {
        let header = make_header(100, id.0[0]);
        db.store_header(id, &header).unwrap();
        db.store_block_transactions(id, &sample_block_transactions(id))
            .unwrap();
        db.store_extension(id, &sample_extension(id)).unwrap();
    }

    // 1. ProgressInfo::empty has no items
    #[test]
    fn progress_info_empty_has_no_items() {
        let info = ProgressInfo::empty();
        assert!(info.branch_point.is_none());
        assert!(info.to_remove.is_empty());
        assert!(info.to_apply.is_empty());
        assert!(info.to_download.is_empty());
    }

    // 2. has_all_sections: false when only header stored
    #[test]
    fn has_all_sections_false_when_only_header() {
        let (db, _dir) = open_test_db();
        let id = make_id(0x01);
        let header = make_header(10, 0xAA);
        db.store_header(&id, &header).unwrap();

        assert!(!db.has_all_sections(&id).unwrap());
    }

    // 3. has_all_sections: true when header + block_tx + extension stored
    #[test]
    fn has_all_sections_true_when_all_required_present() {
        let (db, _dir) = open_test_db();
        let id = make_id(0x02);
        store_required_sections(&db, &id);

        assert!(db.has_all_sections(&id).unwrap());
    }

    // 4. assemble_full_block: returns None when sections missing
    #[test]
    fn assemble_full_block_none_when_missing() {
        let (db, _dir) = open_test_db();
        let id = make_id(0x03);

        // No sections stored at all.
        assert!(db.assemble_full_block(&id).unwrap().is_none());

        // Only header stored.
        let header = make_header(10, 0xBB);
        db.store_header(&id, &header).unwrap();
        assert!(db.assemble_full_block(&id).unwrap().is_none());

        // Header + block transactions, but no extension.
        db.store_block_transactions(&id, &sample_block_transactions(&id))
            .unwrap();
        assert!(db.assemble_full_block(&id).unwrap().is_none());
    }

    // 5. assemble_full_block: returns ErgoFullBlock when all present
    #[test]
    fn assemble_full_block_returns_block_when_complete() {
        let (db, _dir) = open_test_db();
        let id = make_id(0x04);
        store_required_sections(&db, &id);

        let block = db
            .assemble_full_block(&id)
            .unwrap()
            .expect("full block should be assembled");

        assert_eq!(block.header.height, 100);
        assert_eq!(block.block_transactions.block_version, 2);
        assert_eq!(block.extension.fields.len(), 1);
        assert!(block.ad_proofs.is_none());
    }

    // 6. assemble_full_block: includes ad_proofs when present
    #[test]
    fn assemble_full_block_includes_ad_proofs() {
        let (db, _dir) = open_test_db();
        let id = make_id(0x05);
        store_required_sections(&db, &id);
        db.store_ad_proofs(&id, &sample_ad_proofs(&id)).unwrap();

        let block = db
            .assemble_full_block(&id)
            .unwrap()
            .expect("full block should be assembled");

        let proofs = block.ad_proofs.expect("ad_proofs should be present");
        assert_eq!(proofs.proof_bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    // 7. process_header: returns to_download for sections
    #[test]
    fn process_header_returns_download_items() {
        let (db, _dir) = open_test_db();
        let id = make_id(0x06);

        let info = db.process_header(&id).unwrap();

        assert_eq!(info.to_download.len(), 3);
        assert!(info.to_apply.is_empty());
        assert!(info.to_remove.is_empty());
        assert!(info.branch_point.is_none());

        // Should request BlockTransactions (102), ADProofs (104), Extension (108).
        let type_ids: Vec<u8> = info.to_download.iter().map(|(t, _)| *t).collect();
        assert!(type_ids.contains(&102));
        assert!(type_ids.contains(&104));
        assert!(type_ids.contains(&108));

        // All downloads should reference the same header ID.
        for (_, mid) in &info.to_download {
            assert_eq!(mid, &id);
        }
    }

    // 8. process_block_section: returns empty when block incomplete
    #[test]
    fn process_block_section_empty_when_incomplete() {
        let (db, _dir) = open_test_db();
        let id = make_id(0x07);

        // Store only header.
        let header = make_header(10, 0xCC);
        db.store_header(&id, &header).unwrap();

        let info = db.process_block_section(102, &id, &id).unwrap();
        assert!(info.to_apply.is_empty());
        assert!(info.to_download.is_empty());
    }

    // 9. process_block_section: returns to_apply when section completes block
    #[test]
    fn process_block_section_apply_when_complete() {
        let (db, _dir) = open_test_db();
        let id = make_id(0x08);
        store_required_sections(&db, &id);

        // All sections are already stored; process_block_section should
        // detect completeness and signal to_apply.
        let info = db
            .process_block_section(EXTENSION_TYPE_ID, &id, &id)
            .unwrap();

        assert_eq!(info.to_apply.len(), 1);
        assert_eq!(info.to_apply[0], id);
        assert!(info.to_download.is_empty());
    }

    // 10. ProgressInfo::download constructs correct items
    #[test]
    fn progress_info_download_constructs_items() {
        let id1 = make_id(0x10);
        let id2 = make_id(0x20);
        let items = vec![(102, id1), (108, id2)];

        let info = ProgressInfo::download(items.clone());

        assert!(info.branch_point.is_none());
        assert!(info.to_remove.is_empty());
        assert!(info.to_apply.is_empty());
        assert_eq!(info.to_download.len(), 2);
        assert_eq!(info.to_download[0].0, 102);
        assert_eq!(info.to_download[0].1, id1);
        assert_eq!(info.to_download[1].0, 108);
        assert_eq!(info.to_download[1].1, id2);
    }

    // -----------------------------------------------------------------------
    // Chain selection and fork detection tests
    // -----------------------------------------------------------------------

    /// Helper: build a unique ModifierId from two bytes so we can create
    /// distinct IDs for complex chain topologies without collisions.
    fn make_id2(a: u8, b: u8) -> ModifierId {
        let mut arr = [a; 32];
        arr[1] = b;
        ModifierId(arr)
    }

    /// Helper: build a header at `height` with `parent_id` and a given
    /// `n_bits` (for score computation). Uses `store_header_with_score` to
    /// persist the header and its cumulative score.
    fn store_chain_header(
        db: &HistoryDb,
        id: &ModifierId,
        height: u32,
        parent_id: ModifierId,
        n_bits: u64,
    ) {
        let mut h = Header::default_for_test();
        h.version = 2;
        h.height = height;
        h.parent_id = parent_id;
        h.n_bits = n_bits;
        db.store_header_with_score(id, &h).unwrap();
    }

    /// Helper: store all block body sections (block_transactions + extension)
    /// for a given header_id so that `has_all_sections` returns true.
    /// The header must already be stored.
    fn store_body_sections(db: &HistoryDb, id: &ModifierId) {
        db.store_block_transactions(id, &sample_block_transactions(id))
            .unwrap();
        db.store_extension(id, &sample_extension(id)).unwrap();
    }

    // 11. find_common_ancestor on a linear chain.
    //     Chain: A(h=1) -> B(h=2) -> C(h=3)
    //     find_common_ancestor(C, B) should return B (B is itself an
    //     ancestor of C).
    //     find_common_ancestor(C, A) should return A.
    #[test]
    fn find_common_ancestor_same_chain() {
        let (db, _dir) = open_test_db();

        let id_a = make_id2(0xA0, 0x01);
        let id_b = make_id2(0xB0, 0x01);
        let id_c = make_id2(0xC0, 0x01);

        store_chain_header(&db, &id_a, 1, ModifierId::GENESIS_PARENT, 0x01010000);
        store_chain_header(&db, &id_b, 2, id_a, 0x01010000);
        store_chain_header(&db, &id_c, 3, id_b, 0x01010000);

        // B is an ancestor of C, so common ancestor is B itself.
        let ancestor = db.find_common_ancestor(&id_c, &id_b).unwrap();
        assert_eq!(ancestor, Some(id_b));

        // A is the common ancestor when comparing C and A.
        let ancestor2 = db.find_common_ancestor(&id_c, &id_a).unwrap();
        assert_eq!(ancestor2, Some(id_a));
    }

    // 12. find_common_ancestor with a fork.
    //     Chain: A(h=1) -> B(h=2) -> C(h=3)
    //            A(h=1) -> D(h=2)
    //     find_common_ancestor(C, D) should return A.
    #[test]
    fn find_common_ancestor_fork() {
        let (db, _dir) = open_test_db();

        let id_a = make_id2(0xA0, 0x02);
        let id_b = make_id2(0xB0, 0x02);
        let id_c = make_id2(0xC0, 0x02);
        let id_d = make_id2(0xD0, 0x02);

        store_chain_header(&db, &id_a, 1, ModifierId::GENESIS_PARENT, 0x01010000);
        store_chain_header(&db, &id_b, 2, id_a, 0x01010000);
        store_chain_header(&db, &id_c, 3, id_b, 0x01010000);
        store_chain_header(&db, &id_d, 2, id_a, 0x01010000);

        let ancestor = db.find_common_ancestor(&id_c, &id_d).unwrap();
        assert_eq!(ancestor, Some(id_a));
    }

    // 13. chain_from_ancestor on a linear chain.
    //     Chain: A(h=1) -> B(h=2) -> C(h=3)
    //     chain_from_ancestor(A, C) should return [B, C].
    #[test]
    fn chain_from_ancestor_linear() {
        let (db, _dir) = open_test_db();

        let id_a = make_id2(0xA0, 0x03);
        let id_b = make_id2(0xB0, 0x03);
        let id_c = make_id2(0xC0, 0x03);

        store_chain_header(&db, &id_a, 1, ModifierId::GENESIS_PARENT, 0x01010000);
        store_chain_header(&db, &id_b, 2, id_a, 0x01010000);
        store_chain_header(&db, &id_c, 3, id_b, 0x01010000);

        let chain = db.chain_from_ancestor(&id_a, &id_c).unwrap();
        assert_eq!(chain, vec![id_b, id_c]);
    }

    // 14. process_block_section: first complete block produces simple to_apply.
    #[test]
    fn process_block_section_first_block() {
        let (db, _dir) = open_test_db();

        let id_a = make_id2(0xA0, 0x04);
        store_chain_header(&db, &id_a, 1, ModifierId::GENESIS_PARENT, 0x01010000);
        store_body_sections(&db, &id_a);

        // No best full block is set yet — this is the first complete block.
        let info = db
            .process_block_section(EXTENSION_TYPE_ID, &id_a, &id_a)
            .unwrap();

        assert!(info.branch_point.is_none());
        assert!(info.to_remove.is_empty());
        assert_eq!(info.to_apply, vec![id_a]);
    }

    // 15. process_block_section: completing a block on a heavier fork triggers
    //     chain switch with branch_point, to_remove, and to_apply.
    //
    //     Chain:  A(h=1) -> B(h=2, n_bits=0x01010000)  [current best full block]
    //             A(h=1) -> C(h=2, n_bits=0x03010000) -> D(h=3, n_bits=0x03010000)
    //
    //     When D becomes complete its chain (A->C->D) is heavier than (A->B).
    //     Expected: branch_point=A, to_remove=[B], to_apply=[C, D].
    #[test]
    fn process_block_section_better_fork() {
        let (db, _dir) = open_test_db();

        // Shared ancestor.
        let id_a = make_id2(0xA0, 0x05);
        store_chain_header(&db, &id_a, 1, ModifierId::GENESIS_PARENT, 0x01010000);
        store_body_sections(&db, &id_a);

        // Old chain: A -> B (light difficulty).
        let id_b = make_id2(0xB0, 0x05);
        store_chain_header(&db, &id_b, 2, id_a, 0x01010000);
        store_body_sections(&db, &id_b);

        // Mark B as the current best full block.
        db.set_best_full_block_id(&id_b).unwrap();

        // Fork chain: A -> C -> D (heavy difficulty).
        let id_c = make_id2(0xC0, 0x05);
        store_chain_header(&db, &id_c, 2, id_a, 0x03010000);
        store_body_sections(&db, &id_c);

        let id_d = make_id2(0xD0, 0x05);
        store_chain_header(&db, &id_d, 3, id_c, 0x03010000);
        store_body_sections(&db, &id_d);

        // Process the last section of D.
        let info = db
            .process_block_section(EXTENSION_TYPE_ID, &id_d, &id_d)
            .unwrap();

        assert_eq!(info.branch_point, Some(id_a));
        assert_eq!(info.to_remove, vec![id_b]);
        assert_eq!(info.to_apply, vec![id_c, id_d]);
    }

    // 16. process_block_section: completing a block on a lighter fork still
    //     produces a to_apply (no chain switch).
    //
    //     Chain:  A(h=1) -> B(h=2, n_bits=0x03010000) [current best full block]
    //             A(h=1) -> C(h=2, n_bits=0x01010000) (lighter fork)
    //
    //     Completing C should just yield to_apply=[C], no branch_point.
    #[test]
    fn process_block_section_worse_fork_still_applies() {
        let (db, _dir) = open_test_db();

        // Shared ancestor.
        let id_a = make_id2(0xA0, 0x06);
        store_chain_header(&db, &id_a, 1, ModifierId::GENESIS_PARENT, 0x01010000);
        store_body_sections(&db, &id_a);

        // Heavy chain: A -> B.
        let id_b = make_id2(0xB0, 0x06);
        store_chain_header(&db, &id_b, 2, id_a, 0x03010000);
        store_body_sections(&db, &id_b);

        // Mark B as the current best full block.
        db.set_best_full_block_id(&id_b).unwrap();

        // Light fork: A -> C.
        let id_c = make_id2(0xC0, 0x06);
        store_chain_header(&db, &id_c, 2, id_a, 0x01010000);
        store_body_sections(&db, &id_c);

        let info = db
            .process_block_section(EXTENSION_TYPE_ID, &id_c, &id_c)
            .unwrap();

        // No chain switch — lighter fork just gets applied.
        assert!(info.branch_point.is_none());
        assert!(info.to_remove.is_empty());
        assert_eq!(info.to_apply, vec![id_c]);
    }

    // -----------------------------------------------------------------------
    // next_modifiers_to_download tests
    // -----------------------------------------------------------------------

    // 17. Returns empty when no headers exist at all.
    #[test]
    fn next_modifiers_to_download_empty_when_no_headers() {
        let (db, _dir) = open_test_db();
        let result = db.next_modifiers_to_download(10);
        assert!(result.is_empty());
    }

    // 18. Finds missing body sections for a header that has no body stored.
    #[test]
    fn next_modifiers_to_download_finds_missing_sections() {
        use ergo_types::header::compute_section_id;

        let (db, _dir) = open_test_db();

        // Store a header at height 1 (no best full block set, so scan starts at 1).
        let id = make_id(0x01);
        let header = make_header(1, 0xAA);
        db.store_header(&id, &header).unwrap();

        // Don't store any body sections.
        let result = db.next_modifiers_to_download(10);

        // Should find 3 missing sections: BlockTransactions(102), ADProofs(104), Extension(108).
        // IDs returned are computed section_ids (not header_ids).
        assert_eq!(result.len(), 3);
        let expected_sections = header.section_ids(&id);
        for (type_id, section_id) in &expected_sections {
            assert!(
                result
                    .iter()
                    .any(|(t, mid)| *t == *type_id && *mid == *section_id),
                "missing section_id for type {type_id}"
            );
        }
        // Verify they are NOT the raw header_id.
        for (_, mid) in &result {
            assert_ne!(*mid, id, "section_id should differ from header_id");
        }
    }

    // 19. Skips blocks that already have all body sections.
    #[test]
    fn next_modifiers_to_download_skips_complete_blocks() {
        let (db, _dir) = open_test_db();

        // Store a header at height 1 with all body sections.
        let id = make_id(0x02);
        let header = make_header(1, 0xBB);
        db.store_header(&id, &header).unwrap();
        store_body_sections(&db, &id);
        // Also store AD proofs so all 3 section types are present.
        db.store_ad_proofs(&id, &sample_ad_proofs(&id)).unwrap();

        let result = db.next_modifiers_to_download(10);
        assert!(result.is_empty());
    }

    // 20. Respects the max parameter, returning at most max entries.
    #[test]
    fn next_modifiers_to_download_respects_max() {
        let (db, _dir) = open_test_db();

        // Store headers at heights 1 and 2 without any body sections.
        // Use unique parent IDs so they don't collide.
        for h in 1u32..=2 {
            let id = make_id(h as u8);
            let header = make_header(h, 0x10 + h as u8);
            db.store_header(&id, &header).unwrap();
        }

        // Total possible missing: 3 sections × 2 headers = 6.
        // max=4 should cap at 4.
        let result = db.next_modifiers_to_download(4);
        assert_eq!(result.len(), 4);
    }
}
