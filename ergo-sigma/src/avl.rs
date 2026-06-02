//! Thin wrapper around `ergo_avltree_rust` for AVL+ tree proof verification.
//!
//! All `ergo_avltree_rust` imports are confined to this module, providing a
//! single dependency boundary for the evaluator. The crate is a pure-Rust
//! implementation of the Scorex authenticated AVL+ tree and is intentionally
//! accepted as a runtime consensus dependency (not sigma-rust).
//!
//! Operations supported: lookup, update, insert, digest extraction.

use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
use ergo_avltree_rust::batch_avl_verifier::BatchAVLVerifier;
use ergo_avltree_rust::batch_node::{AVLTree, Node, NodeHeader};
use ergo_avltree_rust::operation::{KeyValue, Operation};

/// Opaque handle to a BatchAVLVerifier from `ergo_avltree_rust`.
///
/// Operation methods return `Result<_, ()>` because the underlying crate's
/// error types are opaque — callers map failures to their own error type.
///
/// Wraps the verifier so the evaluator does not need direct imports from
/// the underlying crate. All proof verification operations go through
/// this type's methods.
pub struct AvlVerifier(BatchAVLVerifier);

// `clippy::result_unit_err`: the underlying `ergo_avltree_rust` crate
// returns opaque errors from `perform_one_operation`; collapsing to
// `Result<_, ()>` at this boundary lets callers map the failure into
// their own error type without leaking the upstream type.
#[allow(clippy::result_unit_err)]
impl AvlVerifier {
    /// Construct from raw AVL tree parameters and proof bytes.
    ///
    /// `digest`: 33-byte tree digest (32 bytes + 1 height byte).
    /// `proof`: serialized batch proof bytes.
    /// `key_length`: fixed key length in bytes.
    /// `value_length_opt`: optional fixed value length.
    pub fn new(
        digest: &[u8],
        proof: &[u8],
        key_length: usize,
        value_length_opt: Option<usize>,
    ) -> Result<Self, String> {
        let digest = bytes::Bytes::from(digest.to_vec());
        let proof = bytes::Bytes::from(proof.to_vec());
        BatchAVLVerifier::new(
            &digest,
            &proof,
            AVLTree::new(
                |d| Node::LabelOnly(NodeHeader::new(Some(*d), None)),
                key_length,
                value_length_opt,
            ),
            None,
            None,
        )
        .map(AvlVerifier)
        .map_err(|e| format!("{e}"))
    }

    /// Single-key lookup. Returns the value bytes if found.
    pub fn lookup(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        match self
            .0
            .perform_one_operation(&Operation::Lookup(bytes::Bytes::from(key.to_vec())))
        {
            Ok(Some(v)) => Ok(Some(v.to_vec())),
            Ok(None) => Ok(None),
            Err(_) => Err(()),
        }
    }

    /// Update an existing key with a new value. Returns Ok(true) on success.
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<(), ()> {
        self.0
            .perform_one_operation(&Operation::Update(KeyValue {
                key: bytes::Bytes::from(key.to_vec()),
                value: bytes::Bytes::from(value.to_vec()),
            }))
            .map(|_| ())
            .map_err(|_| ())
    }

    /// Insert a new key-value pair. Returns Ok(()) on success.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), ()> {
        self.0
            .perform_one_operation(&Operation::Insert(KeyValue {
                key: bytes::Bytes::from(key.to_vec()),
                value: bytes::Bytes::from(value.to_vec()),
            }))
            .map(|_| ())
            .map_err(|_| ())
    }

    /// Insert a new entry OR overwrite an existing one for the same
    /// key. Backs the EIP-50 v6 `SAvlTree.insertOrUpdate` MethodCall
    /// (Scala `SAvlTreeMethods.insertOrUpdateMethod` at
    /// `methods.scala:1671-1686`). Returns Ok(()) on success.
    pub fn insert_or_update(&mut self, key: &[u8], value: &[u8]) -> Result<(), ()> {
        self.0
            .perform_one_operation(&Operation::InsertOrUpdate(KeyValue {
                key: bytes::Bytes::from(key.to_vec()),
                value: bytes::Bytes::from(value.to_vec()),
            }))
            .map(|_| ())
            .map_err(|_| ())
    }

    /// Remove a key from the tree. Returns Ok(()) on success.
    pub fn remove(&mut self, key: &[u8]) -> Result<(), ()> {
        self.0
            .perform_one_operation(&Operation::Remove(bytes::Bytes::from(key.to_vec())))
            .map(|_| ())
            .map_err(|_| ())
    }

    /// Remove a key AND report whether the key was present in the
    /// tree according to the proof. Distinguishes the two failure
    /// classes the wrapping caller needs to separate:
    ///
    /// - `Ok(true)`: the proof asserted the key was present, the
    ///   Remove succeeded, and the digest advanced.
    /// - `Ok(false)`: the proof asserted the key was NOT in the
    ///   tree; the Remove is a no-op success. Cryptographically
    ///   definitive evidence the input doesn't exist — callers
    ///   classify this as "input absent per proof", not "verifier
    ///   failure".
    /// - `Err(())`: the verifier itself failed (witness missing
    ///   for the access path, malformed envelope partway through,
    ///   etc.). Opaque from this side; treat as session-scoped.
    pub fn remove_with_presence(&mut self, key: &[u8]) -> Result<bool, ()> {
        self.0
            .perform_one_operation(&Operation::Remove(bytes::Bytes::from(key.to_vec())))
            .map(|opt| opt.is_some())
            .map_err(|_| ())
    }

    /// Remove a key AND return the old value the proof witnessed — the
    /// serialized bytes of the box being spent. `Ok(Some(bytes))` is a
    /// present-key remove (the digest advances); `Ok(None)` is an
    /// explicit non-membership witness; `Err(())` is an opaque verifier
    /// failure. The digest-mode validator needs the old value to
    /// resolve spent input boxes from the ADProofs (Scala's
    /// `proofs.verify` returns these), so this variant keeps the value
    /// that `remove_with_presence` discards.
    pub fn remove_returning_value(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        self.0
            .perform_one_operation(&Operation::Remove(bytes::Bytes::from(key.to_vec())))
            .map(|opt| opt.map(|v| v.to_vec()))
            .map_err(|_| ())
    }

    /// Extract the updated tree digest after mutations.
    /// Returns the 33-byte digest (32 hash bytes + 1 height byte).
    pub fn digest(&self) -> Option<Vec<u8>> {
        self.0.digest().map(|d| d.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
    use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
    use ergo_avltree_rust::batch_node::{AVLTree as ProverTree, Node, NodeHeader};
    use ergo_avltree_rust::operation::{KeyValue as ProverKv, Operation as ProverOp};

    // ----- helpers -----

    fn new_prover() -> BatchAVLProver {
        let tree = ProverTree::new(
            |d| Node::LabelOnly(NodeHeader::new(Some(*d), None)),
            32,
            None,
        );
        BatchAVLProver::new(tree, true)
    }

    fn prover_digest(prover: &mut BatchAVLProver) -> Vec<u8> {
        prover.digest().expect("prover digest").to_vec()
    }

    fn pk(key: [u8; 32], value: Vec<u8>) -> ProverKv {
        ProverKv {
            key: bytes::Bytes::from(key.to_vec()),
            value: bytes::Bytes::from(value),
        }
    }

    // ----- happy path -----

    #[test]
    fn remove_with_presence_present_key_returns_true() {
        // Stand up a prover with one box; capture the parent
        // digest; then perform a Remove on that key and grab
        // the witness. Feed the witness into AvlVerifier and
        // confirm `remove_with_presence` returns Ok(true) —
        // proof asserted membership.
        let mut prover = new_prover();
        let key = [0x42u8; 32];
        prover
            .perform_one_operation(&ProverOp::Insert(pk(key, vec![0x01])))
            .expect("seed insert");
        let _ = prover.generate_proof();
        let parent = prover_digest(&mut prover);
        prover
            .perform_one_operation(&ProverOp::Remove(bytes::Bytes::from(key.to_vec())))
            .expect("prover remove");
        let proof = prover.generate_proof().to_vec();
        let mut verifier =
            AvlVerifier::new(&parent, &proof, 32, None).expect("verifier construction");
        let result = verifier.remove_with_presence(&key);
        assert_eq!(result, Ok(true), "present-key remove must return Ok(true)");
    }

    // ----- error paths -----

    #[test]
    fn remove_with_presence_uncovered_key_returns_err() {
        // The witness covers `covered_key`, but the caller
        // queries a DIFFERENT key. The upstream verifier has
        // no access path for it and returns Err — the wrapper
        // surfaces that as `Err(())`. This is the realistic
        // session-scoped failure class (distinct from the
        // unexercised `Ok(false)` non-membership-witness arm).
        let mut prover = new_prover();
        let covered_key = [0x10u8; 32];
        prover
            .perform_one_operation(&ProverOp::Insert(pk(covered_key, vec![0x01])))
            .expect("seed");
        let _ = prover.generate_proof();
        let parent = prover_digest(&mut prover);
        prover
            .perform_one_operation(&ProverOp::Remove(bytes::Bytes::from(covered_key.to_vec())))
            .expect("prover remove");
        let proof = prover.generate_proof().to_vec();
        let mut verifier =
            AvlVerifier::new(&parent, &proof, 32, None).expect("verifier construction");
        let uncovered = [0x99u8; 32];
        let result = verifier.remove_with_presence(&uncovered);
        assert_eq!(
            result,
            Err(()),
            "uncovered-key remove must surface session-scoped Err(())",
        );
    }

    // The third arm of remove_with_presence — Ok(false) for an
    // explicit non-membership witness — cannot be cleanly
    // synthesized through `BatchAVLProver`'s public API: the
    // RemoveIfExists+absent-key path emits a witness shape the
    // verifier's Remove does not consume as Ok(None). Closing
    // that gap requires either a real Scala/mainnet ADProof
    // corpus or a synthetic witness builder outside the
    // upstream prover API. The arm is correct by inspection
    // against the upstream return type.
}
