//! Thin wrapper around [`ergo_avltree_rust`] providing an ergonomic
//! `AuthenticatedTree` API for Ergo's AVL+ authenticated dictionary.
//!
//! This crate will be the foundation for state management (UTXO set, digest
//! state) in later phases. For now it exposes a prover-side tree that
//! supports insert, remove, lookup, digest computation, and proof generation.

use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
use ergo_avltree_rust::batch_avl_verifier::BatchAVLVerifier;
use ergo_avltree_rust::batch_node::AVLTree;

// Re-export the fundamental types so users do not need a direct dependency
// on `ergo_avltree_rust`.
pub use ergo_avltree_rust::batch_node::SerializedAdProof;
pub use ergo_avltree_rust::operation::{ADDigest, ADKey, ADValue, KeyValue, Operation};

/// Errors that can occur in AVL tree operations.
#[derive(Debug, thiserror::Error)]
pub enum AvlError {
    /// An operation on the underlying AVL tree failed.
    #[error("AVL tree operation failed: {0}")]
    OperationFailed(String),

    /// The tree has no root (should not happen after initialization).
    #[error("tree has no digest (empty/uninitialized)")]
    NoDigest,
}

/// Result alias used throughout this crate.
pub type Result<T> = std::result::Result<T, AvlError>;

/// Default key length used by Ergo (32-byte Blake2b-256 hashes).
pub const DEFAULT_KEY_LENGTH: usize = 32;

/// An authenticated AVL+ tree backed by [`BatchAVLProver`].
///
/// This is the prover side of the authenticated dictionary. It can:
/// - insert / remove / look up key-value pairs,
/// - compute the current Merkle digest,
/// - generate cryptographic proofs of performed operations.
pub struct AuthenticatedTree {
    prover: BatchAVLProver,
}

impl AuthenticatedTree {
    /// Create a new, empty authenticated tree.
    ///
    /// `key_length` is the fixed byte-length of keys (use [`DEFAULT_KEY_LENGTH`]
    /// for Ergo's 32-byte keys).
    ///
    /// `value_length` may be `None` for variable-length values.
    #[must_use]
    pub fn new(key_length: usize, value_length: Option<usize>) -> Self {
        let tree = AVLTree::new(
            |_| panic!("resolver not available for in-memory tree"),
            key_length,
            value_length,
        );
        let prover = BatchAVLProver::new(tree, false);
        Self { prover }
    }

    /// Create an empty tree with Ergo's default 32-byte key length and
    /// variable-length values.
    #[must_use]
    pub fn default_ergo() -> Self {
        Self::new(DEFAULT_KEY_LENGTH, None)
    }

    /// Insert a key-value pair. Returns `Ok(None)` on success (the key did not
    /// previously exist) or an error if the insert failed (e.g. duplicate key).
    pub fn insert(&mut self, key: ADKey, value: ADValue) -> Result<()> {
        let op = Operation::Insert(KeyValue { key, value });
        self.prover
            .perform_one_operation(&op)
            .map_err(|e| AvlError::OperationFailed(format!("{e}")))?;
        Ok(())
    }

    /// Remove a key from the tree. Returns the previously stored value on
    /// success, or an error if the key was not found.
    pub fn remove(&mut self, key: ADKey) -> Result<Option<ADValue>> {
        let op = Operation::Remove(key);
        self.prover
            .perform_one_operation(&op)
            .map_err(|e| AvlError::OperationFailed(format!("{e}")))
    }

    /// Look up a key via an authenticated lookup operation.
    ///
    /// Returns `Ok(Some(value))` if the key exists, `Ok(None)` otherwise.
    pub fn lookup(&mut self, key: ADKey) -> Result<Option<ADValue>> {
        let op = Operation::Lookup(key);
        self.prover
            .perform_one_operation(&op)
            .map_err(|e| AvlError::OperationFailed(format!("{e}")))
    }

    /// Fast, unauthenticated lookup (no proof generated).
    ///
    /// Returns `Some(value)` if the key exists, `None` otherwise.
    #[must_use]
    pub fn unauthenticated_lookup(&self, key: &ADKey) -> Option<ADValue> {
        self.prover.unauthenticated_lookup(key)
    }

    /// Return the current Merkle root digest of the tree.
    pub fn digest(&self) -> Result<ADDigest> {
        self.prover.digest().ok_or(AvlError::NoDigest)
    }

    /// Generate a serialized proof covering all operations performed since the
    /// last call to `generate_proof` (or since tree creation).
    ///
    /// This also resets the internal operation log.
    pub fn generate_proof(&mut self) -> SerializedAdProof {
        self.prover.generate_proof()
    }

    /// Generate a proof for the given operations without modifying this tree.
    ///
    /// Internally clones the tree, applies the operations to the clone,
    /// and returns the serialized AD proof and new digest. The original
    /// tree is left unchanged.
    pub fn generate_proof_for_operations(
        &self,
        operations: &[Operation],
    ) -> Result<(SerializedAdProof, ADDigest)> {
        self.prover
            .generate_proof_for_operations(&operations.to_vec())
            .map_err(|e| AvlError::OperationFailed(format!("{e}")))
    }

    /// Provide direct, read-only access to the underlying prover.
    #[must_use]
    pub fn prover(&self) -> &BatchAVLProver {
        &self.prover
    }

    /// Provide mutable access to the underlying prover for advanced use cases.
    pub fn prover_mut(&mut self) -> &mut BatchAVLProver {
        &mut self.prover
    }
}

/// A verifier-side AVL+ tree that replays operations against a proof
/// to verify state transitions without maintaining the full tree.
///
/// Used by `DigestState` to verify AD proofs included in blocks.
pub struct VerifierTree {
    verifier: BatchAVLVerifier,
}

impl VerifierTree {
    /// Create a new verifier from a starting digest and serialized proof.
    ///
    /// `starting_digest` is the 33-byte Merkle root (32-byte hash + 1-byte height).
    /// `proof` is the serialized AD proof bytes from the block.
    pub fn new(starting_digest: &ADDigest, proof: &SerializedAdProof) -> Result<Self> {
        let tree = AVLTree::new(
            |_| panic!("resolver not available for verifier"),
            DEFAULT_KEY_LENGTH,
            None, // variable-length values
        );
        let verifier = BatchAVLVerifier::new(
            starting_digest,
            proof,
            tree,
            None, // no operation limit
            None, // no delete limit
        )
        .map_err(|e| AvlError::OperationFailed(format!("{e}")))?;
        Ok(Self { verifier })
    }

    /// Perform a single operation (Lookup, Insert, Remove, etc.).
    pub fn perform_operation(&mut self, op: &Operation) -> Result<Option<ADValue>> {
        self.verifier
            .perform_one_operation(op)
            .map_err(|e| AvlError::OperationFailed(format!("{e}")))
    }

    /// Get the current digest after all operations have been performed.
    pub fn digest(&self) -> Result<ADDigest> {
        self.verifier.digest().ok_or(AvlError::NoDigest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a 32-byte key from a single byte (padded with zeros).
    fn make_key(b: u8) -> ADKey {
        let mut v = vec![0u8; 32];
        v[31] = b;
        v.into()
    }

    /// Helper: build a value from a byte slice.
    fn make_value(bs: &[u8]) -> ADValue {
        bs.to_vec().into()
    }

    #[test]
    fn empty_tree_has_digest() {
        let tree = AuthenticatedTree::default_ergo();
        let digest = tree.digest().expect("empty tree should have a digest");
        assert!(!digest.is_empty(), "digest should not be empty");
    }

    #[test]
    fn insert_and_lookup() {
        let mut tree = AuthenticatedTree::default_ergo();

        let key = make_key(1);
        let value = make_value(b"hello");

        tree.insert(key.clone(), value.clone())
            .expect("insert should succeed");

        // Generate proof to finalize batch, then lookup.
        let _proof = tree.generate_proof();

        let found = tree
            .unauthenticated_lookup(&key)
            .expect("key should be found after insert");
        assert_eq!(found, value);
    }

    #[test]
    fn digest_changes_after_insert() {
        let mut tree = AuthenticatedTree::default_ergo();
        let digest_before = tree.digest().expect("digest before insert");

        let key = make_key(42);
        let value = make_value(b"world");
        tree.insert(key, value).expect("insert should succeed");

        // Need to generate proof to commit the batch
        let _proof = tree.generate_proof();

        let digest_after = tree.digest().expect("digest after insert");
        assert_ne!(digest_before, digest_after, "digest should change after insert");
    }

    #[test]
    fn insert_and_remove() {
        let mut tree = AuthenticatedTree::default_ergo();

        let key = make_key(7);
        let value = make_value(b"temporary");

        tree.insert(key.clone(), value.clone())
            .expect("insert should succeed");
        let _proof = tree.generate_proof();

        let digest_with_key = tree.digest().expect("digest with key");

        let removed = tree.remove(key.clone()).expect("remove should succeed");
        assert_eq!(removed, Some(value), "removed value should match inserted value");
        let _proof = tree.generate_proof();

        let digest_without_key = tree.digest().expect("digest without key");
        assert_ne!(digest_with_key, digest_without_key, "digest should change after remove");

        // Key should no longer be found.
        assert!(
            tree.unauthenticated_lookup(&key).is_none(),
            "key should not be found after remove"
        );
    }

    #[test]
    fn authenticated_lookup() {
        let mut tree = AuthenticatedTree::default_ergo();

        let key = make_key(99);
        let value = make_value(b"authenticated");

        tree.insert(key.clone(), value.clone())
            .expect("insert should succeed");
        let _proof = tree.generate_proof();

        let found = tree.lookup(key).expect("lookup should succeed");
        assert_eq!(found, Some(value));
        let _proof = tree.generate_proof();
    }

    #[test]
    fn lookup_missing_key_returns_none() {
        let mut tree = AuthenticatedTree::default_ergo();

        // Insert one key so the tree is not empty
        tree.insert(make_key(1), make_value(b"exists"))
            .expect("insert should succeed");
        let _proof = tree.generate_proof();

        let missing = make_key(200);
        let found = tree.lookup(missing).expect("lookup should not error");
        assert_eq!(found, None);
        let _proof = tree.generate_proof();
    }

    #[test]
    fn proof_is_nonempty_after_operations() {
        let mut tree = AuthenticatedTree::default_ergo();

        tree.insert(make_key(10), make_value(b"a"))
            .expect("insert should succeed");

        let proof = tree.generate_proof();
        assert!(!proof.is_empty(), "proof should not be empty after insert");
    }

    #[test]
    fn multiple_inserts() {
        let mut tree = AuthenticatedTree::default_ergo();

        // Start from 1 because key 0 (all zeros) equals the negative infinity key.
        for i in 1..=10u8 {
            tree.insert(make_key(i), make_value(&[i; 4]))
                .expect("insert should succeed");
        }
        let _proof = tree.generate_proof();

        for i in 1..=10u8 {
            let found = tree
                .unauthenticated_lookup(&make_key(i))
                .expect("key should be found");
            assert_eq!(found, make_value(&[i; 4]));
        }
    }

    // ---- VerifierTree tests ----

    #[test]
    #[should_panic]
    fn verifier_rejects_empty_proof() {
        let tree = AuthenticatedTree::default_ergo();
        let digest = tree.digest().expect("empty tree should have a digest");
        let empty_proof: SerializedAdProof = vec![].into();
        // BatchAVLVerifier::new panics on an empty proof (index out of bounds
        // when reading the first proof byte), so we expect a panic here.
        let _ = VerifierTree::new(&digest, &empty_proof);
    }

    #[test]
    fn verifier_round_trip_insert() {
        let mut prover = AuthenticatedTree::default_ergo();
        let digest_before = prover.digest().unwrap();

        prover.insert(make_key(1), make_value(b"hello")).unwrap();
        let proof = prover.generate_proof();
        let digest_after = prover.digest().unwrap();

        let mut verifier = VerifierTree::new(&digest_before, &proof).unwrap();
        let op = Operation::Insert(KeyValue {
            key: make_key(1),
            value: make_value(b"hello"),
        });
        verifier.perform_operation(&op).unwrap();
        let verifier_digest = verifier.digest().unwrap();
        assert_eq!(verifier_digest, digest_after);
    }

    #[test]
    fn verifier_round_trip_remove() {
        let mut prover = AuthenticatedTree::default_ergo();
        prover.insert(make_key(1), make_value(b"hello")).unwrap();
        let _ = prover.generate_proof();
        let digest_with_key = prover.digest().unwrap();

        prover.remove(make_key(1)).unwrap();
        let proof = prover.generate_proof();
        let digest_without_key = prover.digest().unwrap();

        let mut verifier = VerifierTree::new(&digest_with_key, &proof).unwrap();
        verifier
            .perform_operation(&Operation::Remove(make_key(1)))
            .unwrap();
        assert_eq!(verifier.digest().unwrap(), digest_without_key);
    }

    #[test]
    fn verifier_wrong_operation_produces_different_digest() {
        let mut prover = AuthenticatedTree::default_ergo();
        let digest_before = prover.digest().unwrap();

        prover.insert(make_key(1), make_value(b"hello")).unwrap();
        let proof = prover.generate_proof();
        let digest_after = prover.digest().unwrap();

        let mut verifier = VerifierTree::new(&digest_before, &proof).unwrap();
        // Use a different value than what the proof was generated for.
        // The verifier accepts the operation (the proof structure still
        // guides tree traversal), but the resulting digest will differ
        // from the prover's because the leaf content is wrong.
        let wrong_op = Operation::Insert(KeyValue {
            key: make_key(1),
            value: make_value(b"wrong_value"),
        });
        verifier.perform_operation(&wrong_op).unwrap();
        let verifier_digest = verifier.digest().unwrap();
        assert_ne!(
            verifier_digest, digest_after,
            "wrong operation should produce a different digest than the prover"
        );
    }
}
