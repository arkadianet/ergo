use std::collections::VecDeque;

use bytes::Bytes;
use ergo_avldb::{
    ADDigest as AvlDigest, ADKey, ADValue, AvlError, KeyValue, Operation, SerializedAdProof,
    VerifierTree,
};
use ergo_storage::history_db::StorageError;
use ergo_types::modifier_id::ModifierId;
use ergo_types::transaction::{BoxId, ErgoFullBlock};

use crate::state_changes::StateChanges;

/// Maximum number of version history entries retained for rollback.
const MAX_ROLLBACK_DEPTH: usize = 1000;

/// Errors specific to state management.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// An underlying storage operation failed.
    #[error("storage: {0}")]
    Storage(#[from] StorageError),

    /// An AVL tree operation failed.
    #[error("AVL tree: {0}")]
    Avl(#[from] AvlError),

    /// The computed state root does not match the expected value.
    #[error("digest mismatch: expected {expected}, got {got}")]
    DigestMismatch { expected: String, got: String },

    /// A rollback to a previous version failed.
    #[error("rollback failed for {0}")]
    RollbackFailed(ModifierId),

    /// The block is missing required AD proofs.
    #[error("missing AD proofs")]
    MissingAdProofs,

    /// An input box referenced by a transaction was not found in the UTXO set.
    #[error("box not found: {0}")]
    BoxNotFound(BoxId),

    /// Stateful transaction validation failed.
    #[error("stateful tx validation: {0}")]
    TxStateful(String),

    /// Deserialization of a stored box failed.
    #[error("box deserialization failed: {0}")]
    BoxDeserializationFailed(String),
}

/// Lightweight state that stores only the AVL+ tree root digest.
///
/// Validates blocks using AD proofs from the network rather than
/// maintaining a full UTXO set. This corresponds to `DigestState`
/// in the Scala Ergo node.
///
/// The root digest is 33 bytes: a 32-byte hash followed by a 1-byte
/// tree height.
pub struct DigestState {
    /// Current AVL+ digest (33 bytes: 32-byte hash + 1-byte height).
    root_digest: Vec<u8>,
    /// Current version, typically the ID of the last applied block.
    version: ModifierId,
    /// Bounded history of (version, digest) pairs for rollback support.
    /// Ordered oldest-first; capped at [`MAX_ROLLBACK_DEPTH`] entries.
    version_history: VecDeque<(ModifierId, Vec<u8>)>,
}

impl DigestState {
    /// Create a new `DigestState` with the given genesis digest and version.
    pub fn new(genesis_digest: Vec<u8>, version: ModifierId) -> Self {
        Self {
            root_digest: genesis_digest,
            version,
            version_history: VecDeque::new(),
        }
    }

    /// Returns the current state root digest bytes.
    pub fn state_root(&self) -> &[u8] {
        &self.root_digest
    }

    /// Returns the current version (block ID).
    pub fn version(&self) -> &ModifierId {
        &self.version
    }

    /// Validate and apply a full block's state transition using AD proof
    /// verification.
    ///
    /// 1. Verifies that AD proofs are present.
    /// 2. Constructs a [`VerifierTree`] with the current digest and the
    ///    block's AD proof bytes.
    /// 3. Replays all lookup, remove, and insert operations derived from the
    ///    provided [`StateChanges`] through the verifier.
    /// 4. Obtains the resulting digest from the verifier and compares it to
    ///    the expected new state root in the header.
    /// 5. Updates the stored digest and version on success.
    ///
    /// The caller is responsible for parsing the block's transactions and
    /// computing [`StateChanges`] (via [`compute_state_changes`]), since
    /// [`BlockTransactions`] stores raw transaction bytes.
    ///
    /// [`compute_state_changes`]: crate::state_changes::compute_state_changes
    /// [`BlockTransactions`]: ergo_types::block_transactions::BlockTransactions
    pub fn apply_full_block(
        &mut self,
        block: &ErgoFullBlock,
        header_id: &ModifierId,
        changes: &StateChanges,
    ) -> Result<(), StateError> {
        // AD proofs must be present for digest-mode validation.
        let ad_proofs = block
            .ad_proofs
            .as_ref()
            .ok_or(StateError::MissingAdProofs)?;

        // Build verifier from current digest + proof bytes.
        let starting_digest: AvlDigest = Bytes::copy_from_slice(&self.root_digest);
        let proof: SerializedAdProof = Bytes::copy_from_slice(&ad_proofs.proof_bytes);
        let mut verifier = VerifierTree::new(&starting_digest, &proof)?;

        // Replay operations: lookups, then removals, then insertions.
        for box_id in &changes.to_lookup {
            let key: ADKey = Bytes::copy_from_slice(&box_id.0);
            verifier.perform_operation(&Operation::Lookup(key))?;
        }
        for box_id in &changes.to_remove {
            let key: ADKey = Bytes::copy_from_slice(&box_id.0);
            verifier.perform_operation(&Operation::Remove(key))?;
        }
        for (box_id, data) in &changes.to_insert {
            let key: ADKey = Bytes::copy_from_slice(&box_id.0);
            let value: ADValue = Bytes::copy_from_slice(data);
            verifier.perform_operation(&Operation::Insert(KeyValue { key, value }))?;
        }

        // Verify resulting digest matches header.state_root.
        let computed_digest = verifier.digest()?;
        let expected_root = &block.header.state_root.0;

        if computed_digest.len() < 33 || computed_digest[..33] != expected_root[..] {
            return Err(StateError::DigestMismatch {
                expected: hex::encode(expected_root),
                got: hex::encode(&computed_digest),
            });
        }

        // Save current state to version history before updating.
        self.version_history
            .push_back((self.version, self.root_digest.clone()));
        if self.version_history.len() > MAX_ROLLBACK_DEPTH {
            self.version_history.pop_front();
        }

        // Update state.
        self.root_digest = computed_digest.to_vec();
        self.version = *header_id;

        Ok(())
    }

    /// Rollback to a previous state version.
    ///
    /// Directly replaces the stored digest and version with the
    /// provided values. Does not consult or modify the version history.
    pub fn rollback_to(&mut self, version: &ModifierId, digest: Vec<u8>) -> Result<(), StateError> {
        self.root_digest = digest;
        self.version = *version;
        Ok(())
    }

    /// Rollback to a previous version by searching the version history.
    ///
    /// Finds the entry matching `version`, restores the stored digest
    /// and version, and truncates all history entries after that point.
    pub fn rollback_to_version(&mut self, version: &ModifierId) -> Result<(), StateError> {
        let pos = self
            .version_history
            .iter()
            .position(|(v, _)| v == version)
            .ok_or(StateError::RollbackFailed(*version))?;

        let (_ver, digest) = self.version_history[pos].clone();

        // Truncate everything after the found position (keep entries 0..=pos-1).
        self.version_history.truncate(pos);

        self.root_digest = digest;
        self.version = *version;
        Ok(())
    }

    /// Returns the number of entries currently in the version history.
    #[cfg(test)]
    fn history_len(&self) -> usize {
        self.version_history.len()
    }

    /// Simulate applying a block by updating version/digest and recording
    /// history, without performing AD proof verification.
    ///
    /// This is used in tests to exercise the rollback mechanism without
    /// needing a prover/verifier round-trip for every block.
    #[cfg(test)]
    fn simulate_block(&mut self, new_digest: Vec<u8>, header_id: ModifierId) {
        self.version_history
            .push_back((self.version, self.root_digest.clone()));
        if self.version_history.len() > MAX_ROLLBACK_DEPTH {
            self.version_history.pop_front();
        }
        self.root_digest = new_digest;
        self.version = header_id;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_avldb::AuthenticatedTree;
    use ergo_types::ad_proofs::ADProofs;
    use ergo_types::block_transactions::BlockTransactions;
    use ergo_types::extension::Extension;
    use ergo_types::header::Header;
    use ergo_types::modifier_id::ADDigest;
    use ergo_types::transaction::ErgoFullBlock;

    fn genesis_version() -> ModifierId {
        ModifierId([0u8; 32])
    }

    /// Helper: build a 32-byte key from a single byte value (padded with zeros).
    /// Uses byte at position [31] to avoid collision with the AVL tree's
    /// negative infinity sentinel (all-zeros key).
    fn make_key(b: u8) -> ADKey {
        let mut v = vec![0u8; 32];
        v[31] = b;
        Bytes::from(v)
    }

    /// Helper: build a value from a byte slice.
    fn make_value(bs: &[u8]) -> ADValue {
        Bytes::copy_from_slice(bs)
    }

    /// Helper: convert ADKey bytes to a BoxId.
    fn key_to_box_id(key: &ADKey) -> BoxId {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(key);
        BoxId(arr)
    }

    /// Build a test `ErgoFullBlock` with the given state root and optional
    /// AD proof bytes.
    fn make_block(state_root: [u8; 33], ad_proof_bytes: Option<Vec<u8>>) -> ErgoFullBlock {
        let mut header = Header::default_for_test();
        header.state_root = ADDigest(state_root);

        let header_id = ModifierId([0xAA; 32]);

        let ad_proofs = ad_proof_bytes.map(|proof_bytes| ADProofs {
            header_id,
            proof_bytes,
        });

        ErgoFullBlock {
            header,
            block_transactions: BlockTransactions {
                header_id,
                block_version: 2,
                tx_bytes: Vec::new(),
            },
            extension: Extension {
                header_id,
                fields: Vec::new(),
            },
            ad_proofs,
        }
    }

    // ---------------------------------------------------------------
    // Basic getters
    // ---------------------------------------------------------------

    #[test]
    fn new_digest_state_has_genesis_digest() {
        let digest = vec![0u8; 33];
        let state = DigestState::new(digest.clone(), genesis_version());
        assert_eq!(state.state_root(), digest.as_slice());
    }

    #[test]
    fn version_and_state_root_getters() {
        let digest = vec![0x42; 33];
        let version = ModifierId([0x99; 32]);
        let state = DigestState::new(digest.clone(), version);

        assert_eq!(state.state_root(), digest.as_slice());
        assert_eq!(*state.version(), version);
    }

    // ---------------------------------------------------------------
    // Test: apply_block_with_valid_proof
    //
    // Uses a prover tree to insert some keys, generates a proof,
    // then verifies the proof through DigestState.apply_full_block.
    // ---------------------------------------------------------------

    #[test]
    fn apply_block_with_valid_proof() {
        // 1. Build a prover tree and get the initial (empty) digest.
        let mut prover = AuthenticatedTree::default_ergo();
        let digest_before = prover.digest().unwrap();

        // 2. Insert some "boxes" into the prover.
        let key1 = make_key(1);
        let val1 = make_value(b"box_data_1");
        let key2 = make_key(2);
        let val2 = make_value(b"box_data_2");

        prover.insert(key1.clone(), val1.clone()).unwrap();
        prover.insert(key2.clone(), val2.clone()).unwrap();

        // 3. Generate a proof for the insertions.
        let proof = prover.generate_proof();
        let digest_after = prover.digest().unwrap();

        // 4. Construct an ErgoFullBlock with matching state root and AD proof.
        let mut state_root = [0u8; 33];
        state_root.copy_from_slice(&digest_after[..33]);
        let block = make_block(state_root, Some(proof.to_vec()));

        // 5. Create a DigestState from the pre-insertion digest.
        let mut state = DigestState::new(digest_before.to_vec(), genesis_version());

        // 6. Build the matching StateChanges (only insertions).
        let changes = StateChanges {
            to_lookup: Vec::new(),
            to_remove: Vec::new(),
            to_insert: vec![
                (key_to_box_id(&key1), val1.to_vec()),
                (key_to_box_id(&key2), val2.to_vec()),
            ],
        };

        // 7. Call apply_full_block - should succeed.
        let header_id = ModifierId([0xBB; 32]);
        state
            .apply_full_block(&block, &header_id, &changes)
            .expect("should succeed with valid proof");

        // 8. Verify state root matches post-insertion digest.
        assert_eq!(state.state_root(), &digest_after[..]);
        assert_eq!(*state.version(), header_id);
    }

    // ---------------------------------------------------------------
    // Test: apply_block_with_wrong_operations_fails
    //
    // Uses a valid proof generated for one set of operations but
    // replays a different set of operations through the verifier,
    // resulting in a DigestMismatch.
    // ---------------------------------------------------------------

    #[test]
    fn apply_block_with_wrong_operations_fails() {
        let mut prover = AuthenticatedTree::default_ergo();
        let digest_before = prover.digest().unwrap();

        // Generate a proof for inserting key=3 with value "box_data_3".
        let key1 = make_key(3);
        let val1 = make_value(b"box_data_3");

        prover.insert(key1.clone(), val1.clone()).unwrap();
        let proof = prover.generate_proof();
        let digest_after = prover.digest().unwrap();

        // Build the block with the correct state root and proof.
        let mut state_root = [0u8; 33];
        state_root.copy_from_slice(&digest_after[..33]);
        let block = make_block(state_root, Some(proof.to_vec()));

        let mut state = DigestState::new(digest_before.to_vec(), genesis_version());

        // Replay with a DIFFERENT value than the proof was generated for.
        // The verifier will accept the operation (the proof structure still
        // guides tree traversal), but the resulting digest will differ
        // because the leaf content is wrong.
        let wrong_val = make_value(b"WRONG_VALUE");
        let changes = StateChanges {
            to_lookup: Vec::new(),
            to_remove: Vec::new(),
            to_insert: vec![(key_to_box_id(&key1), wrong_val.to_vec())],
        };

        let header_id = ModifierId([0xCC; 32]);
        let result = state.apply_full_block(&block, &header_id, &changes);

        assert!(result.is_err(), "should fail with wrong operations");
        let err = result.unwrap_err();
        assert!(
            matches!(err, StateError::DigestMismatch { .. }),
            "expected DigestMismatch, got: {err}"
        );

        // State should remain unchanged after failure.
        assert_eq!(state.state_root(), &digest_before[..]);
        assert_eq!(*state.version(), genesis_version());
    }

    // ---------------------------------------------------------------
    // Test: apply_block_missing_ad_proofs_fails
    // ---------------------------------------------------------------

    #[test]
    fn apply_block_missing_ad_proofs_fails() {
        let prover = AuthenticatedTree::default_ergo();
        let digest = prover.digest().unwrap();

        let mut state = DigestState::new(digest.to_vec(), genesis_version());

        let block = make_block([0x11; 33], None);
        let header_id = ModifierId([0xDD; 32]);
        let empty_changes = StateChanges {
            to_lookup: Vec::new(),
            to_remove: Vec::new(),
            to_insert: Vec::new(),
        };

        let result = state.apply_full_block(&block, &header_id, &empty_changes);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(
            matches!(err, StateError::MissingAdProofs),
            "expected MissingAdProofs, got: {err}"
        );

        // State should remain unchanged after failure.
        assert_eq!(state.state_root(), &digest[..]);
        assert_eq!(*state.version(), genesis_version());
    }

    // ---------------------------------------------------------------
    // Test: insert then remove round-trip through DigestState
    // ---------------------------------------------------------------

    #[test]
    fn apply_block_insert_then_remove() {
        // Step 1: Insert a key using the prover, get proof.
        let mut prover = AuthenticatedTree::default_ergo();
        let digest_empty = prover.digest().unwrap();

        let key = make_key(10);
        let val = make_value(b"removable_box");

        prover.insert(key.clone(), val.clone()).unwrap();
        let insert_proof = prover.generate_proof();
        let digest_with_key = prover.digest().unwrap();

        // Apply insertion to DigestState.
        let mut state_root_insert = [0u8; 33];
        state_root_insert.copy_from_slice(&digest_with_key[..33]);
        let insert_block = make_block(state_root_insert, Some(insert_proof.to_vec()));

        let mut state = DigestState::new(digest_empty.to_vec(), genesis_version());
        let insert_changes = StateChanges {
            to_lookup: Vec::new(),
            to_remove: Vec::new(),
            to_insert: vec![(key_to_box_id(&key), val.to_vec())],
        };
        let insert_id = ModifierId([0x01; 32]);
        state
            .apply_full_block(&insert_block, &insert_id, &insert_changes)
            .expect("insert should succeed");
        assert_eq!(state.state_root(), &digest_with_key[..]);

        // Step 2: Remove the key using the prover, get proof.
        prover.remove(key.clone()).unwrap();
        let remove_proof = prover.generate_proof();
        let digest_after_remove = prover.digest().unwrap();

        let mut state_root_remove = [0u8; 33];
        state_root_remove.copy_from_slice(&digest_after_remove[..33]);
        let remove_block = make_block(state_root_remove, Some(remove_proof.to_vec()));

        let remove_changes = StateChanges {
            to_lookup: Vec::new(),
            to_remove: vec![key_to_box_id(&key)],
            to_insert: Vec::new(),
        };
        let remove_id = ModifierId([0x02; 32]);
        state
            .apply_full_block(&remove_block, &remove_id, &remove_changes)
            .expect("remove should succeed");
        assert_eq!(state.state_root(), &digest_after_remove[..]);
    }

    // ---------------------------------------------------------------
    // Rollback tests
    // ---------------------------------------------------------------

    #[test]
    fn rollback_to_updates_state() {
        let mut prover = AuthenticatedTree::default_ergo();
        let initial_digest = prover.digest().unwrap();

        let mut state = DigestState::new(initial_digest.to_vec(), genesis_version());

        // Insert a key via prover to get a valid proof.
        let key = make_key(20);
        let val = make_value(b"rollback_test");
        prover.insert(key.clone(), val.clone()).unwrap();
        let proof = prover.generate_proof();
        let new_digest = prover.digest().unwrap();

        let mut state_root = [0u8; 33];
        state_root.copy_from_slice(&new_digest[..33]);
        let block = make_block(state_root, Some(proof.to_vec()));
        let block_id = ModifierId([0x01; 32]);
        let changes = StateChanges {
            to_lookup: Vec::new(),
            to_remove: Vec::new(),
            to_insert: vec![(key_to_box_id(&key), val.to_vec())],
        };

        state.apply_full_block(&block, &block_id, &changes).unwrap();
        assert_eq!(state.state_root(), &new_digest[..]);

        // Rollback to initial digest.
        let rollback_version = genesis_version();
        state
            .rollback_to(&rollback_version, initial_digest.to_vec())
            .expect("rollback should succeed");

        assert_eq!(state.state_root(), &initial_digest[..]);
        assert_eq!(*state.version(), rollback_version);
    }

    // ---------------------------------------------------------------
    // Version-tracked rollback tests
    //
    // These tests exercise the version history and rollback_to_version
    // logic using simulate_block() to avoid BatchAVLVerifier resolver
    // limitations when the tree depth exceeds 1.
    // ---------------------------------------------------------------

    #[test]
    fn digest_rollback_to_previous_version() {
        let genesis_digest = vec![0x00; 33];
        let mut state = DigestState::new(genesis_digest, genesis_version());

        // Simulate 3 blocks with distinct digests.
        let digest1 = vec![0x11; 33];
        let id1 = ModifierId([0x01; 32]);
        state.simulate_block(digest1.clone(), id1);

        let digest2 = vec![0x22; 33];
        let id2 = ModifierId([0x02; 32]);
        state.simulate_block(digest2, id2);

        let digest3 = vec![0x33; 33];
        let id3 = ModifierId([0x03; 32]);
        state.simulate_block(digest3, id3);

        // Rollback to block 1.
        state
            .rollback_to_version(&id1)
            .expect("rollback_to_version should succeed");

        assert_eq!(state.state_root(), digest1.as_slice());
        assert_eq!(*state.version(), id1);
    }

    #[test]
    fn digest_rollback_beyond_history_fails() {
        let genesis_digest = vec![0x00; 33];
        let mut state = DigestState::new(genesis_digest, genesis_version());

        // Simulate 1 block.
        state.simulate_block(vec![0x11; 33], ModifierId([0x01; 32]));

        // Try to rollback to a version that was never applied.
        let unknown_version = ModifierId([0xFF; 32]);
        let result = state.rollback_to_version(&unknown_version);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, StateError::RollbackFailed(v) if v == unknown_version),
            "expected RollbackFailed, got: {err}"
        );
    }

    #[test]
    fn digest_rollback_truncates_history() {
        let genesis_digest = vec![0x00; 33];
        let mut state = DigestState::new(genesis_digest, genesis_version());

        // Simulate 3 blocks.
        let id1 = ModifierId([0x21; 32]);
        state.simulate_block(vec![0xA1; 33], id1);

        let id2 = ModifierId([0x22; 32]);
        state.simulate_block(vec![0xA2; 33], id2);

        let id3 = ModifierId([0x23; 32]);
        state.simulate_block(vec![0xA3; 33], id3);

        assert_eq!(state.history_len(), 3); // genesis, block1, block2

        // Rollback to block 1.
        state
            .rollback_to_version(&id1)
            .expect("rollback_to_version should succeed");

        // History before block 1 should remain, but block 1 and later are gone.
        // Block 2 should no longer be in history.
        let result = state.rollback_to_version(&id2);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, StateError::RollbackFailed(v) if v == id2),
            "expected RollbackFailed for block 2, got: {err}"
        );
    }
}
