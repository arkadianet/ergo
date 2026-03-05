use std::collections::VecDeque;

use bytes::Bytes;
use ergo_avldb::{ADKey, ADValue, AuthenticatedTree, KeyValue, Operation};
use ergo_consensus::tx_stateful_validation::validate_tx_stateful;
use ergo_consensus::validation_rules::ValidationSettings;
use ergo_types::modifier_id::ModifierId;
use ergo_types::transaction::{BoxId, ErgoBox, ErgoTransaction, TxId, DEFAULT_MIN_VALUE_PER_BYTE};

use crate::digest_state::StateError;
use crate::state_changes::{compute_state_changes, StateChanges};

/// Maximum number of undo log entries retained for rollback.
const MAX_ROLLBACK_DEPTH: usize = 1000;

/// An undo log entry that records the information needed to reverse
/// a single block application.
struct UndoEntry {
    /// The version (block ID) at which this entry was the current state.
    version: ModifierId,
    /// The tree digest before the block was applied.
    /// Retained for future digest-verification during rollback.
    #[allow(dead_code)]
    digest: Vec<u8>,
    /// Boxes that were removed (spent) -- saved with their data for re-insertion.
    removed_boxes: Vec<(BoxId, Vec<u8>)>,
    /// Box IDs that were inserted (created) -- to be removed on undo.
    inserted_box_ids: Vec<BoxId>,
}

/// Full UTXO state backed by an authenticated AVL+ tree.
pub struct UtxoState {
    tree: AuthenticatedTree,
    version: ModifierId,
    /// Bounded undo log for rollback support.
    undo_log: VecDeque<UndoEntry>,
    /// Optional persistent UTXO store (RocksDB).
    utxo_db: Option<ergo_storage::utxo_db::UtxoDb>,
    /// Emission box ID (if known). Updated when emission tx is applied.
    emission_box_id: Option<BoxId>,
}

impl UtxoState {
    /// Create a new empty `UtxoState` without persistent storage.
    pub fn new() -> Self {
        Self {
            tree: AuthenticatedTree::default_ergo(),
            version: ModifierId([0u8; 32]),
            undo_log: VecDeque::new(),
            utxo_db: None,
            emission_box_id: None,
        }
    }

    /// Create a new `UtxoState` backed by a persistent UTXO RocksDB store.
    ///
    /// Block applications and rollbacks will be mirrored to the database.
    pub fn with_persistence(utxo_db: ergo_storage::utxo_db::UtxoDb) -> Self {
        Self {
            tree: AuthenticatedTree::default_ergo(),
            version: ModifierId([0u8; 32]),
            undo_log: VecDeque::new(),
            utxo_db: Some(utxo_db),
            emission_box_id: None,
        }
    }

    /// Restore the UTXO AVL tree from a persistent UtxoDb.
    ///
    /// Reads all entries from the DB, inserts them into a fresh AVL tree,
    /// and verifies the resulting digest matches the stored metadata.
    pub fn restore_from_db(utxo_db: ergo_storage::utxo_db::UtxoDb) -> Result<Self, StateError> {
        let metadata = utxo_db
            .metadata()
            .map_err(|e| StateError::TxStateful(format!("utxo_db metadata: {e}")))?
            .ok_or_else(|| StateError::TxStateful("no UTXO metadata found".into()))?;

        let mut tree = AuthenticatedTree::default_ergo();
        let mut count = 0u64;

        for (key, value) in utxo_db.iter_entries() {
            let ad_key: ADKey = Bytes::copy_from_slice(&key);
            let ad_value: ADValue = Bytes::copy_from_slice(&value);
            tree.insert(ad_key, ad_value).map_err(StateError::Avl)?;
            count += 1;
            if count.is_multiple_of(10_000) {
                let _ = tree.generate_proof();
            }
        }
        let _ = tree.generate_proof();

        let actual_digest = tree.digest().map_err(StateError::Avl)?;
        if actual_digest.as_ref() != metadata.digest.as_slice() {
            return Err(StateError::DigestMismatch {
                expected: hex_string(&metadata.digest),
                got: hex_string(actual_digest.as_ref()),
            });
        }

        Ok(Self {
            tree,
            version: ModifierId(metadata.version),
            undo_log: VecDeque::new(),
            utxo_db: Some(utxo_db),
            emission_box_id: None,
        })
    }

    /// Returns a reference to the underlying UTXO database, if present.
    pub fn utxo_db(&self) -> Option<&ergo_storage::utxo_db::UtxoDb> {
        self.utxo_db.as_ref()
    }

    /// Set the tracked emission box ID.
    pub fn set_emission_box_id(&mut self, box_id: Option<BoxId>) {
        self.emission_box_id = box_id;
    }

    /// Get the tracked emission box ID, if known.
    pub fn emission_box_id(&self) -> Option<&BoxId> {
        self.emission_box_id.as_ref()
    }

    /// Check whether a box exists in the UTXO set by its box ID.
    pub fn contains_box(&self, box_id: &BoxId) -> bool {
        self.get_box(box_id).is_some()
    }

    /// Current state root digest (33 bytes).
    pub fn state_root(&self) -> Result<Vec<u8>, StateError> {
        let digest = self.tree.digest().map_err(StateError::Avl)?;
        Ok(digest.to_vec())
    }

    /// Current version.
    pub fn version(&self) -> &ModifierId {
        &self.version
    }

    /// Apply state changes to the AVL+ tree.
    ///
    /// 1. For each `to_lookup`: `tree.lookup(box_id)`
    /// 2. For each `to_remove`: `tree.remove(box_id)`
    /// 3. For each `to_insert`: `tree.insert(box_id, serialized_box)`
    /// 4. Generate proof (finalizes the batch)
    /// 5. If `expected_digest` is `Some`, verify resulting digest matches
    /// 6. Return generated proof bytes
    pub fn apply_changes(
        &mut self,
        changes: &StateChanges,
        expected_digest: Option<&[u8]>,
    ) -> Result<Vec<u8>, StateError> {
        // Lookups
        for box_id in &changes.to_lookup {
            let key: ADKey = Bytes::copy_from_slice(&box_id.0);
            self.tree.lookup(key).map_err(StateError::Avl)?;
        }

        // Removals
        for box_id in &changes.to_remove {
            let key: ADKey = Bytes::copy_from_slice(&box_id.0);
            self.tree.remove(key).map_err(StateError::Avl)?;
        }

        // Insertions
        for (box_id, data) in &changes.to_insert {
            let key: ADKey = Bytes::copy_from_slice(&box_id.0);
            let value: ADValue = Bytes::copy_from_slice(data);
            self.tree.insert(key, value).map_err(StateError::Avl)?;
        }

        // Generate proof (finalizes the batch)
        let proof = self.tree.generate_proof();

        // Verify digest if expected
        if let Some(expected) = expected_digest {
            let actual = self.tree.digest().map_err(StateError::Avl)?;
            if actual.as_ref() != expected {
                return Err(StateError::DigestMismatch {
                    expected: hex_string(expected),
                    got: hex_string(actual.as_ref()),
                });
            }
        }

        Ok(proof.to_vec())
    }

    /// Apply state changes speculatively (without committing) and return
    /// the serialized AD proof and the new state root digest.
    ///
    /// Used during mining candidate construction to compute the correct
    /// state root for the block header without mutating the real UTXO state.
    ///
    /// The returned digest is 33 bytes (32-byte hash + 1-byte tree height).
    pub fn proofs_for_transactions(
        &self,
        state_changes: &StateChanges,
    ) -> Result<(Vec<u8>, Vec<u8>), StateError> {
        // Convert StateChanges into a Vec<Operation> in the same order as
        // apply_changes: lookups, then removals, then insertions.
        let mut operations = Vec::new();

        for box_id in &state_changes.to_lookup {
            let key: ADKey = Bytes::copy_from_slice(&box_id.0);
            operations.push(Operation::Lookup(key));
        }

        for box_id in &state_changes.to_remove {
            let key: ADKey = Bytes::copy_from_slice(&box_id.0);
            operations.push(Operation::Remove(key));
        }

        for (box_id, data) in &state_changes.to_insert {
            let key: ADKey = Bytes::copy_from_slice(&box_id.0);
            let value: ADValue = Bytes::copy_from_slice(data);
            operations.push(Operation::Insert(KeyValue { key, value }));
        }

        // generate_proof_for_operations clones the tree internally, applies
        // operations to the clone, and returns the proof + new digest.
        let (proof, new_digest) = self
            .tree
            .generate_proof_for_operations(&operations)
            .map_err(StateError::Avl)?;

        Ok((proof.to_vec(), new_digest.to_vec()))
    }

    /// Lookup a box by ID using unauthenticated lookup (no proof).
    pub fn get_box(&self, box_id: &BoxId) -> Option<Vec<u8>> {
        let key: ADKey = Bytes::copy_from_slice(&box_id.0);
        self.tree.unauthenticated_lookup(&key).map(|v| v.to_vec())
    }

    /// Look up a box by ID from the UTXO AVL tree (unauthenticated) and
    /// deserialize the result into an [`ErgoBox`].
    pub fn get_ergo_box(&self, box_id: &BoxId) -> Result<Option<ErgoBox>, StateError> {
        let key: ADKey = Bytes::copy_from_slice(&box_id.0);
        match self.tree.unauthenticated_lookup(&key) {
            Some(value) => {
                let ergo_box = deserialize_ergo_box(&value, box_id)?;
                Ok(Some(ergo_box))
            }
            None => Ok(None),
        }
    }

    /// Apply a full block to the UTXO state.
    ///
    /// For each transaction:
    /// 1. Fetches input boxes from the tree via unauthenticated lookup.
    /// 2. Calls `validate_tx_stateful()` to check ERG/token preservation,
    ///    dust limits, and creation height constraints.
    /// 3. Computes state changes (removals + insertions) and applies them.
    /// 4. Optionally verifies the resulting digest matches `expected_state_root`.
    /// 5. Updates the version to `header_id`.
    ///
    /// `transactions` must be the pre-parsed transactions from the block.
    /// `block_height` is the height of the block being applied.
    /// `expected_state_root` is the 33-byte AD digest from the block header;
    /// pass `None` to skip digest verification (useful in tests).
    pub fn apply_block(
        &mut self,
        transactions: &[ErgoTransaction],
        block_height: u32,
        block_version: u8,
        header_id: &ModifierId,
        expected_state_root: Option<&[u8]>,
        settings: &ValidationSettings,
    ) -> Result<Vec<u8>, StateError> {
        // 1. For each transaction, fetch input boxes and validate statefully.
        for tx in transactions {
            let mut input_boxes = Vec::new();
            for input in &tx.inputs {
                let key: ADKey = Bytes::copy_from_slice(&input.box_id.0);
                let box_bytes = self
                    .tree
                    .unauthenticated_lookup(&key)
                    .ok_or(StateError::BoxNotFound(input.box_id))?;
                let ergo_box = deserialize_ergo_box(&box_bytes, &input.box_id)?;
                input_boxes.push(ergo_box);
            }
            validate_tx_stateful(
                tx,
                &input_boxes,
                block_height,
                block_version,
                DEFAULT_MIN_VALUE_PER_BYTE,
                settings,
            )
            .map_err(|e| StateError::TxStateful(format!("{e}")))?;
        }

        // 2. Compute state changes and apply to the tree.
        let changes = compute_state_changes(transactions);

        // 3. Build undo entry: save current digest, look up boxes about
        //    to be removed, and record which boxes will be inserted.
        let digest_before = self.tree.digest().map_err(StateError::Avl)?.to_vec();

        let mut removed_boxes = Vec::new();
        for box_id in &changes.to_remove {
            let key: ADKey = Bytes::copy_from_slice(&box_id.0);
            if let Some(val) = self.tree.unauthenticated_lookup(&key) {
                removed_boxes.push((*box_id, val.to_vec()));
            }
        }

        let inserted_box_ids: Vec<BoxId> = changes.to_insert.iter().map(|(id, _)| *id).collect();

        let undo = UndoEntry {
            version: self.version,
            digest: digest_before,
            removed_boxes,
            inserted_box_ids,
        };

        // 4. Apply state changes to the tree.
        let proof = self.apply_changes(&changes, expected_state_root)?;

        // 5. Persist to the UTXO database if one is attached.
        if let Some(ref db) = self.utxo_db {
            let to_insert: Vec<([u8; 32], Vec<u8>)> = changes
                .to_insert
                .iter()
                .map(|(box_id, data)| (box_id.0, data.clone()))
                .collect();
            let to_remove: Vec<[u8; 32]> =
                changes.to_remove.iter().map(|box_id| box_id.0).collect();
            let digest = self.tree.digest().map_err(StateError::Avl)?;
            let meta = ergo_storage::utxo_db::UtxoMetadata {
                digest: digest.as_ref().try_into().unwrap_or([0u8; 33]),
                version: header_id.0,
            };
            db.apply_changes(&to_insert, &to_remove, &meta)
                .map_err(|e| StateError::TxStateful(format!("utxo_db: {e}")))?;
        }

        // 6. Record undo entry (cap at MAX_ROLLBACK_DEPTH).
        self.undo_log.push_back(undo);
        if self.undo_log.len() > MAX_ROLLBACK_DEPTH {
            self.undo_log.pop_front();
        }

        // 7. Update version to the applied block's header ID.
        self.version = *header_id;
        Ok(proof)
    }

    /// Apply a block below checkpoint — no tx validation, no digest verification.
    ///
    /// Skips input lookups and stateful validation (trusted chain below checkpoint).
    /// Removes for non-existent boxes (e.g. un-seeded genesis boxes) are silently
    /// skipped. Lookups for non-existent data inputs are also skipped.
    pub fn apply_block_lenient(
        &mut self,
        transactions: &[ErgoTransaction],
        _block_height: u32,
        header_id: &ModifierId,
    ) -> Result<Vec<u8>, StateError> {
        let mut changes = compute_state_changes(transactions);

        // Filter out removes and lookups for boxes not in the tree.
        // This handles un-seeded genesis boxes (emission, no-premine, founders)
        // that the Scala node inserts at startup but we skip.
        changes.to_remove.retain(|box_id| {
            let key: ADKey = Bytes::copy_from_slice(&box_id.0);
            self.tree.unauthenticated_lookup(&key).is_some()
        });
        changes.to_lookup.retain(|box_id| {
            let key: ADKey = Bytes::copy_from_slice(&box_id.0);
            self.tree.unauthenticated_lookup(&key).is_some()
        });

        // Build undo entry.
        let digest_before = self.tree.digest().map_err(StateError::Avl)?.to_vec();

        let mut removed_boxes = Vec::new();
        for box_id in &changes.to_remove {
            let key: ADKey = Bytes::copy_from_slice(&box_id.0);
            if let Some(val) = self.tree.unauthenticated_lookup(&key) {
                removed_boxes.push((*box_id, val.to_vec()));
            }
        }

        let inserted_box_ids: Vec<BoxId> = changes.to_insert.iter().map(|(id, _)| *id).collect();

        let undo = UndoEntry {
            version: self.version,
            digest: digest_before,
            removed_boxes,
            inserted_box_ids,
        };

        // Apply state changes without digest verification.
        let proof = self.apply_changes(&changes, None)?;

        // Persist to UTXO database if attached.
        if let Some(ref db) = self.utxo_db {
            let to_insert: Vec<([u8; 32], Vec<u8>)> = changes
                .to_insert
                .iter()
                .map(|(box_id, data)| (box_id.0, data.clone()))
                .collect();
            let to_remove: Vec<[u8; 32]> =
                changes.to_remove.iter().map(|box_id| box_id.0).collect();
            let digest = self.tree.digest().map_err(StateError::Avl)?;
            let meta = ergo_storage::utxo_db::UtxoMetadata {
                digest: digest.as_ref().try_into().unwrap_or([0u8; 33]),
                version: header_id.0,
            };
            db.apply_changes(&to_insert, &to_remove, &meta)
                .map_err(|e| StateError::TxStateful(format!("utxo_db: {e}")))?;
        }

        // Record undo entry.
        self.undo_log.push_back(undo);
        if self.undo_log.len() > MAX_ROLLBACK_DEPTH {
            self.undo_log.pop_front();
        }

        self.version = *header_id;

        Ok(proof)
    }

    /// Rollback to a previous version by replaying undo entries in reverse.
    ///
    /// Finds the undo entry matching `version`, then for each entry from
    /// the most recent back to (but not including) the found entry:
    /// - Re-inserts any boxes that were removed.
    /// - Removes any boxes that were inserted.
    ///
    /// After replay, restores the version and truncates the undo log.
    pub fn rollback_to_version(&mut self, version: &ModifierId) -> Result<(), StateError> {
        let pos = self
            .undo_log
            .iter()
            .position(|e| e.version == *version)
            .ok_or(StateError::RollbackFailed(*version))?;

        // Replay undo entries in reverse order: from the back down to pos (inclusive).
        let count = self.undo_log.len();
        for i in (pos..count).rev() {
            let entry = &self.undo_log[i];

            // Remove boxes that were inserted by this block.
            for box_id in &entry.inserted_box_ids {
                let key: ADKey = Bytes::copy_from_slice(&box_id.0);
                self.tree.remove(key).map_err(StateError::Avl)?;
            }

            // Re-insert boxes that were removed by this block.
            for (box_id, data) in &entry.removed_boxes {
                let key: ADKey = Bytes::copy_from_slice(&box_id.0);
                let value: ADValue = Bytes::copy_from_slice(data);
                self.tree.insert(key, value).map_err(StateError::Avl)?;
            }

            // Finalize the batch to commit tree changes.
            let _ = self.tree.generate_proof();
        }

        // Persist rollback changes to the UTXO database if one is attached.
        if let Some(ref db) = self.utxo_db {
            let mut db_to_insert: Vec<([u8; 32], Vec<u8>)> = Vec::new();
            let mut db_to_remove: Vec<[u8; 32]> = Vec::new();

            for i in (pos..count).rev() {
                let entry = &self.undo_log[i];
                for (box_id, data) in &entry.removed_boxes {
                    db_to_insert.push((box_id.0, data.clone()));
                }
                for box_id in &entry.inserted_box_ids {
                    db_to_remove.push(box_id.0);
                }
            }

            let digest = self.tree.digest().map_err(StateError::Avl)?;
            let meta = ergo_storage::utxo_db::UtxoMetadata {
                digest: digest.as_ref().try_into().unwrap_or([0u8; 33]),
                version: self.undo_log[pos].version.0,
            };
            db.apply_changes(&db_to_insert, &db_to_remove, &meta)
                .map_err(|e| StateError::TxStateful(format!("utxo_db rollback: {e}")))?;
        }

        // Restore version from the entry.
        self.version = self.undo_log[pos].version;

        // Truncate the undo log: remove all entries from pos onwards.
        self.undo_log.truncate(pos);

        Ok(())
    }
}

/// Deserialize an ErgoBox from wire-format (VLQ-encoded) stored bytes.
///
/// Uses `ergo_wire::box_ser::parse_ergo_box` to parse the standalone
/// box format (zigzag+VLQ value, VLQ tree_len, etc.). Fields not stored
/// in the AVL+ tree (transaction_id, index) are set to defaults.
fn deserialize_ergo_box(data: &[u8], box_id: &BoxId) -> Result<ErgoBox, StateError> {
    let candidate = ergo_wire::box_ser::parse_ergo_box(data)
        .map_err(|e| StateError::BoxDeserializationFailed(e.to_string()))?;
    Ok(ErgoBox {
        candidate,
        transaction_id: TxId([0u8; 32]),
        index: 0,
        box_id: *box_id,
    })
}

impl Default for UtxoState {
    fn default() -> Self {
        Self::new()
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::transaction::ErgoBoxCandidate;

    /// Helper: build a BoxId filled with a single byte (must be non-zero).
    fn make_box_id(b: u8) -> BoxId {
        BoxId([b; 32])
    }

    /// Valid P2PK ErgoTree bytes (secp256k1 generator point G).
    /// sigma-rust requires a fully valid ErgoTree in compute_box_id.
    fn p2pk_tree() -> Vec<u8> {
        let mut v = vec![0x00, 0x08, 0xCD];
        v.extend_from_slice(
            &hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        );
        v
    }

    // ---------------------------------------------------------------
    // Test 1: New UtxoState has a digest (non-empty)
    // ---------------------------------------------------------------
    #[test]
    fn new_utxo_state_has_digest() {
        let state = UtxoState::new();
        let digest = state.state_root().expect("new state should have a digest");
        assert!(!digest.is_empty(), "digest should not be empty");
    }

    // ---------------------------------------------------------------
    // Test 2: Insert box -> unauthenticated lookup returns it
    // ---------------------------------------------------------------
    #[test]
    fn insert_box_then_lookup() {
        let mut state = UtxoState::new();

        let box_id = make_box_id(0x01);
        let data = vec![0xAA, 0xBB, 0xCC];

        let changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(box_id, data.clone())],
            to_lookup: Vec::new(),
        };

        // apply_changes calls generate_proof internally
        state
            .apply_changes(&changes, None)
            .expect("insert should succeed");

        let found = state.get_box(&make_box_id(0x01));
        assert_eq!(found, Some(data));
    }

    // ---------------------------------------------------------------
    // Test 3: Remove box -> lookup returns None
    // ---------------------------------------------------------------
    #[test]
    fn remove_box_then_lookup_returns_none() {
        let mut state = UtxoState::new();

        let box_id = make_box_id(0x02);
        let data = vec![0x11, 0x22];

        // Insert first
        let insert_changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(box_id, data)],
            to_lookup: Vec::new(),
        };
        state
            .apply_changes(&insert_changes, None)
            .expect("insert should succeed");

        // Remove
        let remove_changes = StateChanges {
            to_remove: vec![make_box_id(0x02)],
            to_insert: Vec::new(),
            to_lookup: Vec::new(),
        };
        state
            .apply_changes(&remove_changes, None)
            .expect("remove should succeed");

        assert!(state.get_box(&make_box_id(0x02)).is_none());
    }

    // ---------------------------------------------------------------
    // Test 4: apply_changes: insert + remove sequence, verify digest changes
    // ---------------------------------------------------------------
    #[test]
    fn apply_changes_digest_changes_after_insert_and_remove() {
        let mut state = UtxoState::new();
        let digest_empty = state.state_root().expect("initial digest");

        // Insert a box
        let box_id = make_box_id(0x03);
        let insert_changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(box_id, vec![0xDD])],
            to_lookup: Vec::new(),
        };
        state
            .apply_changes(&insert_changes, None)
            .expect("insert should succeed");
        let digest_after_insert = state.state_root().expect("digest after insert");
        assert_ne!(
            digest_empty, digest_after_insert,
            "digest should change after insert"
        );

        // Remove the box
        let remove_changes = StateChanges {
            to_remove: vec![make_box_id(0x03)],
            to_insert: Vec::new(),
            to_lookup: Vec::new(),
        };
        state
            .apply_changes(&remove_changes, None)
            .expect("remove should succeed");
        let digest_after_remove = state.state_root().expect("digest after remove");
        assert_ne!(
            digest_after_insert, digest_after_remove,
            "digest should change after remove"
        );
    }

    // ---------------------------------------------------------------
    // Test 5: apply_changes: digest mismatch -> StateError::DigestMismatch
    // ---------------------------------------------------------------
    #[test]
    fn apply_changes_digest_mismatch() {
        let mut state = UtxoState::new();

        let changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(make_box_id(0x04), vec![0xFF])],
            to_lookup: Vec::new(),
        };

        // Pass a wrong expected digest
        let wrong_digest = vec![0x00; 33];
        let result = state.apply_changes(&changes, Some(&wrong_digest));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, StateError::DigestMismatch { .. }),
            "expected DigestMismatch, got: {err}"
        );
    }

    // ---------------------------------------------------------------
    // Test 6: apply_changes: returns non-empty proof bytes
    // ---------------------------------------------------------------
    #[test]
    fn apply_changes_returns_nonempty_proof() {
        let mut state = UtxoState::new();

        let changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(make_box_id(0x05), vec![0x42])],
            to_lookup: Vec::new(),
        };

        let proof = state.apply_changes(&changes, None).expect("should succeed");
        assert!(!proof.is_empty(), "proof should not be empty");
    }

    // ---------------------------------------------------------------
    // Test 7: get_box for existing box returns bytes
    // ---------------------------------------------------------------
    #[test]
    fn get_box_existing_returns_bytes() {
        let mut state = UtxoState::new();

        let box_id = make_box_id(0x06);
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];

        let changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(box_id, data.clone())],
            to_lookup: Vec::new(),
        };
        state
            .apply_changes(&changes, None)
            .expect("insert should succeed");

        let result = state.get_box(&make_box_id(0x06));
        assert_eq!(result, Some(data));
    }

    // ---------------------------------------------------------------
    // Test 8: get_box for missing box returns None
    // ---------------------------------------------------------------
    #[test]
    fn get_box_missing_returns_none() {
        let state = UtxoState::new();
        let missing = make_box_id(0x99);
        assert!(state.get_box(&missing).is_none());
    }

    // ---------------------------------------------------------------
    // Helper: serialize a box value + ergo_tree into wire format
    // Uses ergo_wire::box_ser::serialize_ergo_box (VLQ encoding)
    // ---------------------------------------------------------------
    fn serialize_box(value: u64, ergo_tree: &[u8]) -> Vec<u8> {
        use ergo_wire::box_ser::serialize_ergo_box;
        serialize_ergo_box(&ErgoBoxCandidate {
            value,
            ergo_tree_bytes: ergo_tree.to_vec(),
            creation_height: 0,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        })
    }

    // ---------------------------------------------------------------
    // Test 9: deserialize_ergo_box basic round-trip
    // ---------------------------------------------------------------
    #[test]
    fn deserialize_ergo_box_basic() {
        let value = 1_000_000_000u64;
        let ergo_tree = p2pk_tree();
        let data = serialize_box(value, &ergo_tree);
        let bid = make_box_id(0xAB);

        let result = deserialize_ergo_box(&data, &bid);
        assert!(result.is_ok(), "deserialization should succeed");

        let ergo_box = result.unwrap();
        assert_eq!(ergo_box.candidate.value, value);
        assert_eq!(ergo_box.candidate.ergo_tree_bytes, ergo_tree);
        assert_eq!(ergo_box.box_id, bid);
        assert_eq!(ergo_box.candidate.creation_height, 0);
        assert!(ergo_box.candidate.tokens.is_empty());
    }

    // ---------------------------------------------------------------
    // Test 10: deserialize_ergo_box with data too short
    // ---------------------------------------------------------------
    #[test]
    fn deserialize_ergo_box_too_short() {
        // Empty data is too short for even a VLQ-encoded value
        let data = vec![];
        let bid = make_box_id(0xCD);

        let result = deserialize_ergo_box(&data, &bid);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, StateError::BoxDeserializationFailed(..)),
            "expected BoxDeserializationFailed, got: {err}"
        );
    }

    // ---------------------------------------------------------------
    // Test 11: apply_block updates version after successful application
    // ---------------------------------------------------------------
    #[test]
    fn apply_block_updates_version() {
        use ergo_types::transaction::{ErgoBoxCandidate, Input, TxId};

        let mut state = UtxoState::new();

        // Pre-populate the UTXO set with a box
        let input_box_id = make_box_id(0x10);
        let value = 1_000_000_000u64;
        let ergo_tree = p2pk_tree();
        let box_data = serialize_box(value, &ergo_tree);

        let insert_changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(input_box_id, box_data)],
            to_lookup: Vec::new(),
        };
        state
            .apply_changes(&insert_changes, None)
            .expect("pre-insert should succeed");

        // Build a transaction that spends the box
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: input_box_id,
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value,
                ergo_tree_bytes: ergo_tree,
                creation_height: 100,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0xAA; 32]),
        };

        let header_id = ModifierId([0xBB; 32]);

        // Apply block without digest verification
        let proof = state
            .apply_block(
                &[tx],
                200_000,
                1,
                &header_id,
                None,
                &ValidationSettings::initial(),
            )
            .expect("apply_block should succeed");

        assert!(!proof.is_empty(), "proof should not be empty");
        assert_eq!(
            *state.version(),
            header_id,
            "version should be updated to header_id"
        );
    }

    // ---------------------------------------------------------------
    // Test 12: apply_block fails when input box is not in UTXO set
    // ---------------------------------------------------------------
    #[test]
    fn apply_block_missing_input_fails() {
        use ergo_types::transaction::{ErgoBoxCandidate, Input, TxId};

        let mut state = UtxoState::new();

        let missing_box_id = make_box_id(0x77);

        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: missing_box_id,
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: p2pk_tree(),
                creation_height: 100,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0xCC; 32]),
        };

        let header_id = ModifierId([0xDD; 32]);

        let result = state.apply_block(
            &[tx],
            200_000,
            1,
            &header_id,
            None,
            &ValidationSettings::initial(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, StateError::BoxNotFound(bid) if bid == missing_box_id),
            "expected BoxNotFound, got: {err}"
        );
    }

    // ---------------------------------------------------------------
    // Test 13: apply_block fails when ERG not preserved (stateful validation)
    // ---------------------------------------------------------------
    #[test]
    fn apply_block_erg_not_preserved_fails() {
        use ergo_types::transaction::{ErgoBoxCandidate, Input, TxId};

        let mut state = UtxoState::new();

        // Pre-populate the UTXO set
        let input_box_id = make_box_id(0x20);
        let value = 1_000_000_000u64;
        let ergo_tree = p2pk_tree();
        let box_data = serialize_box(value, &ergo_tree);

        let insert_changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(input_box_id, box_data)],
            to_lookup: Vec::new(),
        };
        state
            .apply_changes(&insert_changes, None)
            .expect("pre-insert should succeed");

        // Build a transaction that outputs MORE than the input (invalid)
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: input_box_id,
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 2_000_000_000, // more than input
                ergo_tree_bytes: ergo_tree,
                creation_height: 100,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0xEE; 32]),
        };

        let header_id = ModifierId([0xFF; 32]);

        let result = state.apply_block(
            &[tx],
            200_000,
            1,
            &header_id,
            None,
            &ValidationSettings::initial(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, StateError::TxStateful(..)),
            "expected TxStateful, got: {err}"
        );
    }

    // ---------------------------------------------------------------
    // Test 14: apply_block with empty transactions succeeds
    // ---------------------------------------------------------------
    #[test]
    fn apply_block_empty_transactions() {
        let mut state = UtxoState::new();

        let header_id = ModifierId([0x11; 32]);

        // No transactions means no validation, just apply empty changes
        let proof = state
            .apply_block(
                &[],
                100,
                1,
                &header_id,
                None,
                &ValidationSettings::initial(),
            )
            .expect("empty block should succeed");

        assert!(!proof.is_empty(), "proof should not be empty");
        assert_eq!(*state.version(), header_id);
    }

    // ---------------------------------------------------------------
    // Rollback tests
    // ---------------------------------------------------------------

    /// Helper: apply a block via `apply_block` that spends `input_box_id`
    /// (which must already exist in the UTXO set with the given value/tree)
    /// and creates a new output. Returns the new output's BoxId.
    fn apply_spending_block(
        state: &mut UtxoState,
        input_box_id: BoxId,
        value: u64,
        ergo_tree: &[u8],
        block_id_byte: u8,
        block_height: u32,
    ) -> BoxId {
        use ergo_types::transaction::{ErgoBoxCandidate, Input, TxId};

        let tx_id = TxId([block_id_byte; 32]);
        let output = ErgoBoxCandidate {
            value,
            ergo_tree_bytes: ergo_tree.to_vec(),
            creation_height: block_height,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        };
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: input_box_id,
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![output.clone()],
            tx_id,
        };

        let header_id = ModifierId([block_id_byte; 32]);
        state
            .apply_block(
                &[tx],
                block_height,
                1,
                &header_id,
                None,
                &ValidationSettings::initial(),
            )
            .expect("apply_block should succeed");

        ergo_wire::box_ser::compute_box_id(&output, &tx_id, 0)
    }

    #[test]
    fn utxo_rollback_restores_removed_boxes() {
        let mut state = UtxoState::new();

        // Insert a box directly.
        let box_id = make_box_id(0xA1);
        let value = 1_000_000_000u64;
        let ergo_tree = p2pk_tree();
        let box_data = serialize_box(value, &ergo_tree);

        let insert_changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(box_id, box_data.clone())],
            to_lookup: Vec::new(),
        };
        state
            .apply_changes(&insert_changes, None)
            .expect("pre-insert should succeed");

        // Record the version before the spending block.
        let version_before = *state.version();

        // Apply a block that spends (removes) the box.
        let _output_id = apply_spending_block(&mut state, box_id, value, &ergo_tree, 0xB1, 100);

        // Verify the box is gone.
        assert!(
            state.get_box(&box_id).is_none(),
            "box should be removed after apply_block"
        );

        // Rollback to the version before the spending block.
        state
            .rollback_to_version(&version_before)
            .expect("rollback_to_version should succeed");

        // The removed box should be back.
        let found = state.get_box(&box_id);
        assert!(found.is_some(), "box should exist after rollback");
        assert_eq!(found.unwrap(), box_data);
    }

    #[test]
    fn utxo_rollback_removes_inserted_boxes() {
        use ergo_types::transaction::{ErgoBoxCandidate, Input, TxId};

        let mut state = UtxoState::new();

        // Insert a box directly to serve as the input for the next block.
        let input_box_id = make_box_id(0xC1);
        let value = 1_000_000_000u64;
        let ergo_tree = p2pk_tree();
        let box_data = serialize_box(value, &ergo_tree);

        let insert_changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(input_box_id, box_data)],
            to_lookup: Vec::new(),
        };
        state
            .apply_changes(&insert_changes, None)
            .expect("pre-insert should succeed");

        let version_before = *state.version();

        // Apply a block that spends the input and creates a new output.
        let tx_id = TxId([0xD1; 32]);
        let output_candidate = ErgoBoxCandidate {
            value,
            ergo_tree_bytes: ergo_tree,
            creation_height: 200,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        };
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: input_box_id,
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![output_candidate.clone()],
            tx_id,
        };

        let header_id = ModifierId([0xD1; 32]);
        state
            .apply_block(
                &[tx],
                200,
                1,
                &header_id,
                None,
                &ValidationSettings::initial(),
            )
            .expect("apply_block should succeed");

        // Compute the output box ID using the real derivation.
        let output_box_id = ergo_wire::box_ser::compute_box_id(&output_candidate, &tx_id, 0);

        // Verify the new box exists.
        assert!(
            state.get_box(&output_box_id).is_some(),
            "inserted box should exist after apply_block"
        );

        // Rollback.
        state
            .rollback_to_version(&version_before)
            .expect("rollback_to_version should succeed");

        // The inserted box should be gone.
        assert!(
            state.get_box(&output_box_id).is_none(),
            "inserted box should be gone after rollback"
        );
    }

    #[test]
    fn utxo_rollback_beyond_history_fails() {
        let mut state = UtxoState::new();

        let unknown_version = ModifierId([0xEE; 32]);
        let result = state.rollback_to_version(&unknown_version);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, StateError::RollbackFailed(v) if v == unknown_version),
            "expected RollbackFailed, got: {err}"
        );
    }

    // ---------------------------------------------------------------
    // Test: deserialize_ergo_box with tokens round-trips correctly
    // ---------------------------------------------------------------
    #[test]
    fn deserialize_ergo_box_with_tokens() {
        use ergo_wire::box_ser::serialize_ergo_box;

        let candidate = ErgoBoxCandidate {
            value: 2_000_000_000,
            ergo_tree_bytes: p2pk_tree(),
            creation_height: 600_000,
            tokens: vec![(BoxId([0xAA; 32]), 1_000), (BoxId([0xBB; 32]), 999_999)],
            additional_registers: Vec::new(),
        };

        let data = serialize_ergo_box(&candidate);
        let bid = make_box_id(0xF1);

        let result = deserialize_ergo_box(&data, &bid);
        assert!(result.is_ok(), "deserialization should succeed");

        let ergo_box = result.unwrap();
        assert_eq!(ergo_box.candidate.value, 2_000_000_000);
        assert_eq!(ergo_box.candidate.tokens.len(), 2);
        assert_eq!(ergo_box.candidate.tokens[0].0, BoxId([0xAA; 32]));
        assert_eq!(ergo_box.candidate.tokens[0].1, 1_000);
        assert_eq!(ergo_box.candidate.tokens[1].0, BoxId([0xBB; 32]));
        assert_eq!(ergo_box.candidate.tokens[1].1, 999_999);
        assert_eq!(ergo_box.box_id, bid);
    }

    // ---------------------------------------------------------------
    // Test: deserialize_ergo_box with registers round-trips correctly
    // ---------------------------------------------------------------
    #[test]
    fn deserialize_ergo_box_with_registers() {
        use ergo_wire::box_ser::serialize_ergo_box;
        use ergo_wire::vlq::put_long as vlq_put_long;

        // R4: Long constant (type 5 + zigzag VLQ value 42)
        let mut reg_r4 = vec![0x05]; // TYPE_LONG
        vlq_put_long(&mut reg_r4, 42);

        // R5: Boolean constant (type 1 + 1 byte value=true)
        let reg_r5 = vec![0x01, 0x01];

        let candidate = ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: p2pk_tree(),
            creation_height: 100_000,
            tokens: Vec::new(),
            additional_registers: vec![(4, reg_r4.clone()), (5, reg_r5.clone())],
        };

        let data = serialize_ergo_box(&candidate);
        let bid = make_box_id(0xF2);

        let result = deserialize_ergo_box(&data, &bid);
        assert!(result.is_ok(), "deserialization should succeed");

        let ergo_box = result.unwrap();
        assert_eq!(ergo_box.candidate.value, 1_000_000_000);
        assert_eq!(ergo_box.candidate.additional_registers.len(), 2);
        assert_eq!(ergo_box.candidate.additional_registers[0].0, 4); // R4
        assert_eq!(ergo_box.candidate.additional_registers[0].1, reg_r4);
        assert_eq!(ergo_box.candidate.additional_registers[1].0, 5); // R5
        assert_eq!(ergo_box.candidate.additional_registers[1].1, reg_r5);
        assert_eq!(ergo_box.box_id, bid);
    }

    // ---------------------------------------------------------------
    // UTXO DB persistence tests
    // ---------------------------------------------------------------

    #[test]
    fn apply_block_persists_to_utxo_db() {
        use ergo_types::transaction::{Input, TxId};

        let dir = tempfile::tempdir().unwrap();
        let db = ergo_storage::utxo_db::UtxoDb::open(dir.path().join("utxo")).unwrap();
        let mut state = UtxoState::with_persistence(db);

        // Seed the AVL tree with a box (tree-only, no DB write).
        let box_id = make_box_id(0x10);
        let value = 1_000_000_000u64;
        let ergo_tree = p2pk_tree();
        let box_data = serialize_box(value, &ergo_tree);
        let insert_changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(box_id, box_data)],
            to_lookup: Vec::new(),
        };
        state.apply_changes(&insert_changes, None).unwrap();

        // Apply a block that spends the seeded box and creates a new output.
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id,
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value,
                ergo_tree_bytes: ergo_tree,
                creation_height: 100,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0xDD; 32]),
        };
        let header_id = ModifierId([0xEE; 32]);
        state
            .apply_block(
                &[tx],
                200_000,
                1,
                &header_id,
                None,
                &ValidationSettings::initial(),
            )
            .unwrap();

        // Verify the DB was updated.
        let db = state.utxo_db().unwrap();
        let meta = db.metadata().unwrap().unwrap();
        assert_eq!(meta.version, header_id.0);
        assert!(
            db.get(&box_id.0).unwrap().is_none(),
            "spent box should be removed from DB"
        );
        assert!(db.entry_count() > 0, "new output should be in DB");
    }

    #[test]
    fn rollback_also_reverts_utxo_db() {
        use ergo_types::transaction::{Input, TxId};

        let dir = tempfile::tempdir().unwrap();
        let db = ergo_storage::utxo_db::UtxoDb::open(dir.path().join("utxo")).unwrap();
        let mut state = UtxoState::with_persistence(db);

        // Seed the AVL tree with a box (tree-only, no DB write).
        let box_id = make_box_id(0xA1);
        let value = 1_000_000_000u64;
        let ergo_tree = p2pk_tree();
        let box_data = serialize_box(value, &ergo_tree);
        let insert_changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(box_id, box_data)],
            to_lookup: Vec::new(),
        };
        state.apply_changes(&insert_changes, None).unwrap();

        let version_before = *state.version();

        // Apply a block that spends the seeded box.
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id,
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value,
                ergo_tree_bytes: ergo_tree,
                creation_height: 100,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0xB1; 32]),
        };
        let header_id = ModifierId([0xB1; 32]);
        state
            .apply_block(
                &[tx],
                200_000,
                1,
                &header_id,
                None,
                &ValidationSettings::initial(),
            )
            .unwrap();

        // The DB should have the new output and metadata pointing to header_id.
        assert!(state.utxo_db().unwrap().entry_count() > 0);

        // Rollback to the version before the block.
        state.rollback_to_version(&version_before).unwrap();

        // Verify the DB metadata was rolled back.
        let db = state.utxo_db().unwrap();
        let meta = db.metadata().unwrap().unwrap();
        assert_eq!(
            meta.version, version_before.0,
            "metadata version should match pre-block version after rollback"
        );
    }

    // ---------------------------------------------------------------
    // restore_from_db tests
    // ---------------------------------------------------------------

    #[test]
    fn restore_from_db_roundtrip() {
        use ergo_types::transaction::{ErgoBoxCandidate, Input, TxId};

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("utxo");

        // Phase 1: Create state with persistence, apply a block, record digest.
        let digest_after_block;
        let header_id_bytes;
        {
            let db = ergo_storage::utxo_db::UtxoDb::open(&db_path).unwrap();
            let mut state = UtxoState::with_persistence(db);

            // Insert a genesis box (tree-only, not persisted to DB).
            let box_id = make_box_id(0x10);
            let value = 1_000_000_000u64;
            let ergo_tree = p2pk_tree();
            let box_data = serialize_box(value, &ergo_tree);
            let insert_changes = StateChanges {
                to_remove: Vec::new(),
                to_insert: vec![(box_id, box_data)],
                to_lookup: Vec::new(),
            };
            state.apply_changes(&insert_changes, None).unwrap();

            // Apply a block that spends the genesis box and creates a new one.
            let tx = ErgoTransaction {
                inputs: vec![Input {
                    box_id,
                    proof_bytes: Vec::new(),
                    extension_bytes: Vec::new(),
                }],
                data_inputs: Vec::new(),
                output_candidates: vec![ErgoBoxCandidate {
                    value,
                    ergo_tree_bytes: ergo_tree,
                    creation_height: 100,
                    tokens: Vec::new(),
                    additional_registers: Vec::new(),
                }],
                tx_id: TxId([0xDD; 32]),
            };
            let header_id = ModifierId([0xEE; 32]);
            state
                .apply_block(
                    &[tx],
                    200_000,
                    1,
                    &header_id,
                    None,
                    &ValidationSettings::initial(),
                )
                .unwrap();

            digest_after_block = state.state_root().unwrap();
            header_id_bytes = header_id.0;
        }
        // UtxoDb is dropped here but the RocksDB files persist on disk.

        // Phase 2: Reopen DB, restore state, verify.
        {
            let db = ergo_storage::utxo_db::UtxoDb::open(&db_path).unwrap();
            let state = UtxoState::restore_from_db(db).unwrap();

            assert_eq!(state.state_root().unwrap(), digest_after_block);
            assert_eq!(state.version().0, header_id_bytes);
        }
    }

    #[test]
    fn restore_from_empty_db_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db = ergo_storage::utxo_db::UtxoDb::open(dir.path().join("utxo")).unwrap();
        let result = UtxoState::restore_from_db(db);
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // proofs_for_transactions tests
    // ---------------------------------------------------------------

    #[test]
    fn proofs_for_transactions_does_not_mutate_state() {
        let mut state = UtxoState::new();

        // Insert a box into the tree first.
        let box_id = make_box_id(0x50);
        let data = vec![0xAA, 0xBB, 0xCC];
        let insert_changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(box_id, data.clone())],
            to_lookup: Vec::new(),
        };
        state
            .apply_changes(&insert_changes, None)
            .expect("insert should succeed");

        let digest_before = state.state_root().expect("digest before speculative apply");

        // Speculatively remove the box.
        let speculative_changes = StateChanges {
            to_remove: vec![box_id],
            to_insert: Vec::new(),
            to_lookup: Vec::new(),
        };
        let result = state.proofs_for_transactions(&speculative_changes);
        assert!(result.is_ok(), "proofs_for_transactions should succeed");

        // Verify the original state is unchanged.
        let digest_after = state.state_root().expect("digest after speculative apply");
        assert_eq!(
            digest_before, digest_after,
            "original state digest must not change after speculative apply"
        );

        // The box should still be present in the original tree.
        let found = state.get_box(&box_id);
        assert_eq!(
            found,
            Some(data),
            "box should still exist after speculative removal"
        );
    }

    #[test]
    fn proofs_for_transactions_returns_new_digest() {
        let mut state = UtxoState::new();

        // Insert a box into the tree first.
        let box_id = make_box_id(0x51);
        let data = vec![0xDD, 0xEE];
        let insert_changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(box_id, data)],
            to_lookup: Vec::new(),
        };
        state
            .apply_changes(&insert_changes, None)
            .expect("insert should succeed");

        let original_digest = state.state_root().expect("original digest");

        // Speculatively insert a new box.
        let new_box_id = make_box_id(0x52);
        let new_data = vec![0xFF];
        let speculative_changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(new_box_id, new_data)],
            to_lookup: Vec::new(),
        };
        let (proof, new_digest) = state
            .proofs_for_transactions(&speculative_changes)
            .expect("proofs_for_transactions should succeed");

        // The returned digest should differ from the original.
        assert_ne!(
            original_digest, new_digest,
            "speculative digest should differ from original"
        );

        // The proof should be non-empty.
        assert!(!proof.is_empty(), "proof should not be empty");

        // The new digest should be 33 bytes (32-byte hash + 1-byte height).
        assert_eq!(new_digest.len(), 33, "digest should be 33 bytes");
    }

    #[test]
    fn proofs_for_transactions_matches_real_apply() {
        // Create two identical states.
        let mut state_a = UtxoState::new();
        let mut state_b = UtxoState::new();

        // Insert the same box into both.
        let box_id = make_box_id(0x60);
        let data = vec![0x11, 0x22, 0x33];
        let insert_changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: vec![(box_id, data.clone())],
            to_lookup: Vec::new(),
        };
        state_a
            .apply_changes(&insert_changes, None)
            .expect("insert a");
        state_b
            .apply_changes(&insert_changes, None)
            .expect("insert b");

        // Define a modification: remove the box, insert a new one.
        let new_box_id = make_box_id(0x61);
        let new_data = vec![0x44, 0x55];
        let changes = StateChanges {
            to_remove: vec![box_id],
            to_insert: vec![(new_box_id, new_data)],
            to_lookup: Vec::new(),
        };

        // Get speculative result from state_a.
        let (spec_proof, spec_digest) = state_a
            .proofs_for_transactions(&changes)
            .expect("speculative");

        // Actually apply to state_b.
        let real_proof = state_b.apply_changes(&changes, None).expect("real apply");
        let real_digest = state_b.state_root().expect("real digest");

        // The proofs and digests should match.
        assert_eq!(
            spec_proof, real_proof,
            "speculative proof should match real proof"
        );
        assert_eq!(
            spec_digest, real_digest,
            "speculative digest should match real digest"
        );
    }

    #[test]
    fn proofs_for_transactions_with_empty_changes() {
        let state = UtxoState::new();
        let original_digest = state.state_root().expect("original digest");

        let empty_changes = StateChanges {
            to_remove: Vec::new(),
            to_insert: Vec::new(),
            to_lookup: Vec::new(),
        };

        let (proof, new_digest) = state
            .proofs_for_transactions(&empty_changes)
            .expect("empty changes should succeed");

        assert!(
            !proof.is_empty(),
            "proof should not be empty even for no-op"
        );
        assert_eq!(
            original_digest, new_digest,
            "digest should be unchanged for empty changes"
        );
    }
}
