//! Mining-candidate dry-run: speculative AVL+ apply without persistence.
//!
//! `apply_change_set_via_prover` hydrates an `ergo_avltree_rust`
//! `BatchAVLProver` from the current `AvlTree` state, applies a batch
//! of (remove, insert) UTXO mutations in the same order as
//! `apply_mutations` (BTreeMap-ascending removes, then BTreeMap-
//! ascending inserts), and returns the resulting `(new_state_root,
//! raw_proof_bytes)`. The caller of [`crate::StateStore::candidate_dry_run`]
//! later frames the raw proof into a type-104 ADProofs section and
//! hashes it via `ad_proofs_root = blake2b256(raw_proof_bytes)`
//! (Phase 1c step c0 resolved — see
//! `ergo-state/tests/ad_proofs_root_oracle.rs`).
//!
//! Uses plain `BatchAVLProver`, NEVER `PersistentBatchAVLProver`.
//! The latter has hidden storage paths that would defeat the
//! no-persist guarantee.

use std::collections::BTreeMap;

use bytes::Bytes;
use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
use ergo_avltree_rust::operation::{KeyValue, Operation};
use ergo_primitives::digest::ADDigest;

use crate::avl::hydrate::hydrate_batch_avl_prover;
use crate::avl::tree::AvlTree;
use crate::store::StateError;

pub(crate) type DryRunRemoveMap = BTreeMap<[u8; 32], ()>;
pub(crate) type DryRunInsertMap = BTreeMap<[u8; 32], Vec<u8>>;

/// Hydrate a `BatchAVLProver` from `tree`, apply a batch of removes
/// then inserts in BTreeMap-ascending key order, and return the
/// resulting `(new_state_root, raw_proof_bytes)`. Does not mutate
/// `tree` or touch persistent storage.
///
/// Ordering matches `apply_mutations` (`store/mod.rs:apply_mutations`)
/// exactly: all removes processed before any insert, both maps
/// iterated in ascending key order via `BTreeMap`. The intra-block
/// create-then-spend cancellation that the caller's `BoxChanges`
/// builder applies (via `to_insert.remove(&box_id)` when a remove
/// later in the batch references a freshly-inserted box) is already
/// baked into the input maps — this function trusts them.
pub(crate) fn apply_change_set_via_prover(
    tree: &AvlTree,
    to_remove: &DryRunRemoveMap,
    to_insert: &DryRunInsertMap,
) -> Result<(ADDigest, Vec<u8>), StateError> {
    let mut prover = hydrate_batch_avl_prover(tree)?;
    apply_change_set_to_prover(&mut prover, to_remove, to_insert)
}

/// Apply a batch of removes then inserts to an already-hydrated
/// `BatchAVLProver` and return `(new_state_root, raw_proof_bytes)`.
///
/// Shared by the live-tree dry-run ([`apply_change_set_via_prover`]) and
/// the off-loop committed-snapshot dry-run
/// ([`crate::store::snapshot::CommittedSnapshot::candidate_dry_run`]):
/// both hydrate a prover from equivalent committed state, then run this
/// identical mutation → digest → proof sequence, so for the same parent
/// and change-set they produce byte-identical `(state_root, proof)`.
///
/// Takes `&mut BatchAVLProver` so callers that need the post-op tree
/// (e.g. the cached-base advance path) can extract `prover.base.tree`
/// after this call. The prover's `visited` flags are cleaned by the
/// internal `generate_proof` call, so the tree is pristine for reuse.
pub(crate) fn apply_change_set_to_prover(
    prover: &mut BatchAVLProver,
    to_remove: &DryRunRemoveMap,
    to_insert: &DryRunInsertMap,
) -> Result<(ADDigest, Vec<u8>), StateError> {
    // Removes first, BTreeMap-ascending (matches apply_mutations order).
    for box_id in to_remove.keys() {
        prover
            .perform_one_operation(&Operation::Remove(Bytes::copy_from_slice(box_id)))
            .map_err(|e| StateError::CandidateDryRunProverFailed {
                op: "remove",
                box_id: hex::encode(box_id),
                error: e.to_string(),
            })?;
    }

    // Inserts, BTreeMap-ascending. `value` cloned per upstream
    // `KeyValue` ownership; cheap because the slice is the serialized
    // box bytes we already own here.
    for (box_id, value) in to_insert {
        prover
            .perform_one_operation(&Operation::Insert(KeyValue {
                key: Bytes::copy_from_slice(box_id),
                value: Bytes::copy_from_slice(value),
            }))
            .map_err(|e| StateError::CandidateDryRunProverFailed {
                op: "insert",
                box_id: hex::encode(box_id),
                error: e.to_string(),
            })?;
    }

    let digest_bytes = prover
        .digest()
        .ok_or_else(|| StateError::InternalInvariant {
            what: "candidate_dry_run: prover returned no digest",
        })?;
    if digest_bytes.len() != 33 {
        return Err(StateError::InternalInvariant {
            what: "candidate_dry_run: prover digest length != 33",
        });
    }
    let mut new_root = [0u8; 33];
    new_root.copy_from_slice(&digest_bytes);
    let new_root = ADDigest::from_bytes(new_root);

    // Extract the raw proof bytes. Also clears `visited` flags on the
    // shared nodes (via `pack_tree`'s post-order `mark_visited(false)`),
    // leaving the prover's tree pristine for reuse.
    let proof = prover.generate_proof().to_vec();

    Ok((new_root, proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::avl::tree::AvlTree;

    // ----- helpers -----

    fn make_key(seed: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = seed.wrapping_mul(17).wrapping_add(5);
        k[31] = seed;
        k
    }

    // ----- happy path -----

    #[test]
    fn empty_change_set_preserves_root() {
        let mut tree = AvlTree::new();
        for i in 0u8..10 {
            tree.insert(make_key(i), vec![i, i + 1]);
        }
        let before = tree.root_digest();

        let to_remove: DryRunRemoveMap = BTreeMap::new();
        let to_insert: DryRunInsertMap = BTreeMap::new();
        let (after, proof) = apply_change_set_via_prover(&tree, &to_remove, &to_insert)
            .expect("dry-run empty batch");

        assert_eq!(
            after.as_bytes(),
            before.as_bytes(),
            "zero-op batch must not change the root"
        );
        // Proof bytes still non-empty (the prover always emits the
        // packaged-tree + END marker, even for a no-op batch). Just
        // verify it's present.
        assert!(!proof.is_empty(), "no-op proof should still be encoded");
    }

    #[test]
    fn insert_then_dry_run_matches_a_separate_real_insert() {
        // Build identical starting state in two trees, mutate one,
        // dry-run the same mutation against the other, compare roots.
        let mut shared = AvlTree::new();
        for i in 0u8..5 {
            shared.insert(make_key(i), vec![i]);
        }

        let new_key = make_key(99);
        let new_val = vec![0xAB, 0xCD];

        // Real apply: clone-by-replay (AvlTree isn't Clone, so we
        // rebuild the same starting state in a second tree).
        let mut real = AvlTree::new();
        for i in 0u8..5 {
            real.insert(make_key(i), vec![i]);
        }
        real.insert(new_key, new_val.clone());
        let real_root = real.root_digest();

        // Dry-run on the *original* state — must produce the same root.
        let to_remove: DryRunRemoveMap = BTreeMap::new();
        let mut to_insert: DryRunInsertMap = BTreeMap::new();
        to_insert.insert(new_key, new_val);
        let (dry_root, _proof) =
            apply_change_set_via_prover(&shared, &to_remove, &to_insert).expect("dry-run insert");

        assert_eq!(
            dry_root.as_bytes(),
            real_root.as_bytes(),
            "dry-run insert must produce the same root as a real apply"
        );
    }

    #[test]
    fn remove_then_dry_run_matches_a_separate_real_remove() {
        let mut shared = AvlTree::new();
        for i in 0u8..5 {
            shared.insert(make_key(i), vec![i]);
        }

        let mut real = AvlTree::new();
        for i in 0u8..5 {
            real.insert(make_key(i), vec![i]);
        }
        real.remove(&make_key(2));
        let real_root = real.root_digest();

        let mut to_remove: DryRunRemoveMap = BTreeMap::new();
        to_remove.insert(make_key(2), ());
        let to_insert: DryRunInsertMap = BTreeMap::new();
        let (dry_root, _proof) =
            apply_change_set_via_prover(&shared, &to_remove, &to_insert).expect("dry-run remove");

        assert_eq!(dry_root.as_bytes(), real_root.as_bytes());
    }

    #[test]
    fn mixed_batch_dry_run_matches_real_apply() {
        // Build a tree, then dry-run a batch with removes AND inserts,
        // and compare against a separate tree that applied the same
        // operations in the apply_mutations order (removes first,
        // then inserts).
        let mut shared = AvlTree::new();
        for i in 0u8..8 {
            shared.insert(make_key(i), vec![i, i + 1]);
        }

        let mut real = AvlTree::new();
        for i in 0u8..8 {
            real.insert(make_key(i), vec![i, i + 1]);
        }
        // Apply the same removes + inserts to the real tree in the
        // apply_mutations order: removes (BTreeMap asc) then inserts
        // (BTreeMap asc).
        let mut to_remove: DryRunRemoveMap = BTreeMap::new();
        to_remove.insert(make_key(2), ());
        to_remove.insert(make_key(5), ());
        let mut to_insert: DryRunInsertMap = BTreeMap::new();
        to_insert.insert(make_key(10), vec![0xAA]);
        to_insert.insert(make_key(20), vec![0xBB]);
        to_insert.insert(make_key(30), vec![0xCC]);

        for k in to_remove.keys() {
            real.remove(k);
        }
        for (k, v) in &to_insert {
            real.insert(*k, v.clone());
        }
        let real_root = real.root_digest();

        let (dry_root, _proof) =
            apply_change_set_via_prover(&shared, &to_remove, &to_insert).expect("dry-run mixed");
        assert_eq!(
            dry_root.as_bytes(),
            real_root.as_bytes(),
            "dry-run mixed batch root must equal real-apply root"
        );
    }

    #[test]
    fn dry_run_does_not_persist_or_mutate_source_tree() {
        // Run a dry-run a few times against the same tree and verify
        // the tree's root is unchanged each time. This is the
        // "no-persist" gate from the v12 plan.
        let mut tree = AvlTree::new();
        for i in 0u8..6 {
            tree.insert(make_key(i), vec![i]);
        }
        let before = tree.root_digest();

        let to_remove: DryRunRemoveMap = BTreeMap::new();
        let mut to_insert: DryRunInsertMap = BTreeMap::new();
        to_insert.insert(make_key(100), vec![0x42]);

        for _ in 0..10 {
            let _ =
                apply_change_set_via_prover(&tree, &to_remove, &to_insert).expect("dry-run loop");
        }

        let after = tree.root_digest();
        assert_eq!(
            after.as_bytes(),
            before.as_bytes(),
            "tree root must NOT change across repeated dry-runs"
        );
    }

    // ----- error paths -----

    #[test]
    fn remove_missing_key_returns_error() {
        let tree = AvlTree::new();
        let mut to_remove: DryRunRemoveMap = BTreeMap::new();
        to_remove.insert(make_key(99), ()); // never inserted
        let to_insert: DryRunInsertMap = BTreeMap::new();
        let err = apply_change_set_via_prover(&tree, &to_remove, &to_insert)
            .expect_err("removing absent key must fail");
        match err {
            StateError::CandidateDryRunProverFailed { op, box_id, error } => {
                assert_eq!(op, "remove");
                assert_eq!(box_id, hex::encode(make_key(99)));
                assert!(!error.is_empty(), "prover error detail must be preserved");
            }
            other => panic!("expected CandidateDryRunProverFailed, got {other:?}"),
        }
    }
}
