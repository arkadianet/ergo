//! Mining-candidate dry-run: speculative AVL+ apply without persistence.
//!
//! `apply_change_set_via_prover` hydrates an `ergo_avltree_rust`
//! `BatchAVLProver` from the current `AvlTree` state, applies the
//! CANONICAL operation stream — data-input lookups first (transaction
//! order, duplicates included), then removes, then inserts (both
//! BTreeMap-ascending, matching `apply_mutations`) — and returns the
//! resulting `(new_state_root, raw_proof_bytes)`. The caller of
//! [`crate::StateStore::candidate_dry_run`] later frames the raw proof
//! into a type-104 ADProofs section and hashes it via
//! `ad_proofs_root = blake2b256(raw_proof_bytes)` (oracle-verified —
//! see `ergo-state/tests/ad_proofs_root_oracle.rs`).
//!
//! CONSENSUS — the lookup prefix is part of the canonical stream:
//! Scala `StateChanges.operations = toLookup ++ toRemove ++ toAppend`,
//! where `ErgoState.stateChanges` emits one `Lookup` per transaction
//! data input. Lookups are digest-NEUTRAL but proof-VISIBLE — they
//! expand visited nodes and direction bits in the proof transcript
//! without mutating the tree — so omitting them yields a bit-correct
//! `state_root` with a non-canonical `ad_proofs_root`, and the
//! reference rejects the mined block with "Regenerated proofHash is
//! not equal to the declared one" (incident: mainnet block 344f5a2f…
//! at height 1,805,523).
//! The verifier-side replay (`digest_apply.rs`) has always consumed
//! the lookup prefix; this module is the generator-side mirror.
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

/// Hydrate a `BatchAVLProver` from `tree`, apply the canonical op
/// stream (data-input lookups, then removes, then inserts), and return
/// the resulting `(new_state_root, raw_proof_bytes)`. Does not mutate
/// `tree` or touch persistent storage.
///
/// `to_lookup` carries the data-input box ids in TRANSACTION order,
/// duplicates included, NOT sorted — exactly as the verifier-side
/// replay consumes them (`digest_apply.rs`) and as Scala's
/// `ErgoState.stateChanges` emits them. Remove/insert ordering matches
/// `apply_mutations` (`store/mod.rs:apply_mutations`) exactly: all
/// removes processed before any insert, both maps iterated in
/// ascending key order via `BTreeMap`. The intra-block
/// create-then-spend cancellation that the caller's `BoxChanges`
/// builder applies (via `to_insert.remove(&box_id)` when a remove
/// later in the batch references a freshly-inserted box) is already
/// baked into the input maps — this function trusts them.
pub(crate) fn apply_change_set_via_prover(
    tree: &AvlTree,
    to_lookup: &[[u8; 32]],
    to_remove: &DryRunRemoveMap,
    to_insert: &DryRunInsertMap,
) -> Result<(ADDigest, Vec<u8>), StateError> {
    let mut prover = hydrate_batch_avl_prover(tree)?;
    apply_change_set_to_prover(&mut prover, to_lookup, to_remove, to_insert)
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
    to_lookup: &[[u8; 32]],
    to_remove: &DryRunRemoveMap,
    to_insert: &DryRunInsertMap,
) -> Result<(ADDigest, Vec<u8>), StateError> {
    // Data-input lookups first, in the given (transaction) order —
    // Scala `StateChanges.operations = toLookup ++ toRemove ++ toAppend`.
    // Read-only: never mutates the tree or the digest, but each lookup
    // marks visited nodes and appends direction bits to the proof, so
    // the proof bytes are NOT the same without them. A lookup of an
    // absent key (e.g. a data input on a box created later in this
    // same block) is valid and yields a non-inclusion path, exactly as
    // in the reference (lookups precede all removals/insertions).
    for box_id in to_lookup {
        prover
            .perform_one_operation(&Operation::Lookup(Bytes::copy_from_slice(box_id)))
            .map_err(|e| StateError::CandidateDryRunProverFailed {
                op: "lookup",
                box_id: hex::encode(box_id),
                error: e.to_string(),
            })?;
    }

    // Removes next, BTreeMap-ascending (matches apply_mutations order).
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

/// Pre-broadcast self-check of a candidate's generated ADProofs.
///
/// Replays `proof` through the production verifier
/// (`ergo_sigma::avl::AvlVerifier` — the same type the Mode-5 digest
/// path drives against real network ADProofs) seeded with
/// `parent_root`, performing the canonical operation stream (lookups
/// in transaction order, removes ascending, inserts ascending), and
/// requires the verifier's final digest to equal `expected_root`.
///
/// A reference validator regenerates the proof from our transactions
/// and compares digests (`UtxoState`: "Regenerated proofHash is not
/// equal to the declared one"), so a candidate whose proof fails this
/// replay would be invalidated network-wide — the h1,805,523 incident
/// shipped exactly because no such check existed. Fail-safe direction:
/// a false failure only withholds a candidate (the miner keeps working
/// on the previous one); it can never cause an invalid broadcast.
///
/// Construction is wrapped in `catch_unwind`, mirroring
/// `digest_apply.rs`: the upstream crate has a known deterministic
/// panic site on malformed proof envelopes, and the mining loop must
/// never crash on a self-generated artifact — a panic is reported as a
/// self-check failure instead.
pub(crate) fn self_check_candidate_proof(
    parent_root: &ADDigest,
    to_lookup: &[[u8; 32]],
    to_remove: &DryRunRemoveMap,
    to_insert: &DryRunInsertMap,
    proof: &[u8],
    expected_root: &ADDigest,
) -> Result<(), StateError> {
    let fail = |stage: &'static str, detail: String| StateError::CandidateProofSelfCheckFailed {
        stage,
        detail,
    };

    let parent_bytes = parent_root.as_bytes().to_vec();
    let proof_owned = proof.to_vec();
    let construct = || ergo_sigma::avl::AvlVerifier::new(&parent_bytes, &proof_owned, 32, None);
    let verifier_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(construct))
        .map_err(|panic_payload| {
            let reason = panic_payload
                .downcast_ref::<&'static str>()
                .map(|s| s.to_string())
                .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "verifier construction panicked".to_string());
            fail("construct(panic)", reason)
        })?;
    let mut verifier = verifier_result.map_err(|e| fail("construct", e))?;

    for key in to_lookup {
        verifier
            .lookup(key)
            .map_err(|()| fail("lookup", hex::encode(key)))?;
    }
    for box_id in to_remove.keys() {
        verifier
            .remove(box_id)
            .map_err(|()| fail("remove", hex::encode(box_id)))?;
    }
    for (box_id, value) in to_insert {
        verifier
            .insert(box_id, value)
            .map_err(|()| fail("insert", hex::encode(box_id)))?;
    }

    let verified_digest = verifier
        .digest()
        .ok_or_else(|| fail("digest", "verifier returned no digest".to_string()))?;
    if verified_digest.as_slice() != expected_root.as_bytes() {
        return Err(fail(
            "digest-compare",
            format!(
                "verifier reproduced {} but candidate claims {}",
                hex::encode(&verified_digest),
                hex::encode(expected_root.as_bytes())
            ),
        ));
    }
    Ok(())
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
        let (after, proof) = apply_change_set_via_prover(&tree, &[], &to_remove, &to_insert)
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
        let (dry_root, _proof) = apply_change_set_via_prover(&shared, &[], &to_remove, &to_insert)
            .expect("dry-run insert");

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
        let (dry_root, _proof) = apply_change_set_via_prover(&shared, &[], &to_remove, &to_insert)
            .expect("dry-run remove");

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

        let (dry_root, _proof) = apply_change_set_via_prover(&shared, &[], &to_remove, &to_insert)
            .expect("dry-run mixed");
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
            let _ = apply_change_set_via_prover(&tree, &[], &to_remove, &to_insert)
                .expect("dry-run loop");
        }

        let after = tree.root_digest();
        assert_eq!(
            after.as_bytes(),
            before.as_bytes(),
            "tree root must NOT change across repeated dry-runs"
        );
    }

    // ----- data-input lookup prefix (h1805523 incident regression) -----

    #[test]
    fn lookup_prefix_changes_proof_bytes_but_not_digest() {
        // CONSENSUS regression for the height-1,805,523 incident: the
        // same change set with and without a data-input lookup prefix
        // must reach the SAME digest but produce DIFFERENT proof bytes.
        // Lookups are digest-neutral, proof-visible — omitting them
        // produced a bit-correct state_root with a non-canonical
        // ad_proofs_root that the reference rejected.
        let mut tree = AvlTree::new();
        for i in 0u8..8 {
            tree.insert(make_key(i), vec![i]);
        }
        let mut to_remove: DryRunRemoveMap = BTreeMap::new();
        to_remove.insert(make_key(3), ());
        let mut to_insert: DryRunInsertMap = BTreeMap::new();
        to_insert.insert(make_key(50), vec![0xAA]);

        let (root_plain, proof_plain) =
            apply_change_set_via_prover(&tree, &[], &to_remove, &to_insert)
                .expect("lookup-free dry-run");
        let lookups = [make_key(1), make_key(6)];
        let (root_lk, proof_lk) =
            apply_change_set_via_prover(&tree, &lookups, &to_remove, &to_insert)
                .expect("lookup-prefixed dry-run");

        assert_eq!(
            root_lk.as_bytes(),
            root_plain.as_bytes(),
            "lookups must be digest-neutral"
        );
        assert_ne!(
            proof_lk, proof_plain,
            "lookups must be proof-visible (h1805523 regression)"
        );
    }

    #[test]
    fn empty_lookup_prefix_is_byte_identical_to_pre_fix_behavior() {
        // Negative control guarding the 1804848-shaped (no data inputs)
        // case: an empty lookup slice must not perturb the proof stream
        // in any way.
        let mut tree = AvlTree::new();
        for i in 0u8..8 {
            tree.insert(make_key(i), vec![i]);
        }
        let mut to_remove: DryRunRemoveMap = BTreeMap::new();
        to_remove.insert(make_key(2), ());
        let mut to_insert: DryRunInsertMap = BTreeMap::new();
        to_insert.insert(make_key(40), vec![0xCC]);

        let (r1, p1) =
            apply_change_set_via_prover(&tree, &[], &to_remove, &to_insert).expect("first run");
        let (r2, p2) =
            apply_change_set_via_prover(&tree, &[], &to_remove, &to_insert).expect("second run");
        assert_eq!(r1.as_bytes(), r2.as_bytes());
        assert_eq!(p1, p2, "empty lookup prefix must be a byte-level no-op");
    }

    #[test]
    fn lookup_of_absent_key_is_valid_non_inclusion() {
        // A data input referencing a box created later in the same
        // block is looked up BEFORE any insert (canonical order:
        // toLookup ++ toRemove ++ toAppend) — the prover must emit a
        // non-inclusion path, not fail.
        let mut tree = AvlTree::new();
        for i in 0u8..4 {
            tree.insert(make_key(i), vec![i]);
        }
        let absent = make_key(200);
        let to_remove: DryRunRemoveMap = BTreeMap::new();
        let mut to_insert: DryRunInsertMap = BTreeMap::new();
        to_insert.insert(absent, vec![0x01]);
        let (root, _proof) = apply_change_set_via_prover(&tree, &[absent], &to_remove, &to_insert)
            .expect("absent-key lookup must be a valid non-inclusion, not an error");
        // ...and the insert still landed.
        let mut twin = AvlTree::new();
        for i in 0u8..4 {
            twin.insert(make_key(i), vec![i]);
        }
        twin.insert(absent, vec![0x01]);
        assert_eq!(root.as_bytes(), twin.root_digest().as_bytes());
    }

    #[test]
    fn generated_proof_round_trips_through_production_verifier() {
        // Generator/verifier symmetry: this is the SAME AvlVerifier the
        // Mode-5 digest apply path (digest_apply.rs) drives against
        // real mainnet ADProofs — including data-input blocks — so
        // agreement here transitively pins the generator to the
        // network's canonical proof format. Replay order matches
        // digest_apply exactly: lookups (transaction order, duplicates
        // included) → removes (ascending) → inserts (ascending).
        let mut tree = AvlTree::new();
        for i in 0u8..10 {
            tree.insert(make_key(i), vec![i, i]);
        }
        let parent_root = tree.root_digest();

        let lookups = [make_key(2), make_key(7), make_key(2)]; // dup allowed
        let mut to_remove: DryRunRemoveMap = BTreeMap::new();
        to_remove.insert(make_key(4), ());
        let mut to_insert: DryRunInsertMap = BTreeMap::new();
        to_insert.insert(make_key(60), vec![0xBE]);

        let (new_root, proof) =
            apply_change_set_via_prover(&tree, &lookups, &to_remove, &to_insert)
                .expect("dry-run with lookups");

        let mut verifier =
            ergo_sigma::avl::AvlVerifier::new(parent_root.as_bytes(), &proof, 32, None)
                .expect("verifier construction from generated proof");
        for k in &lookups {
            verifier.lookup(k).expect("lookup replay");
        }
        for k in to_remove.keys() {
            verifier.remove(k).expect("remove replay");
        }
        for (k, v) in &to_insert {
            verifier.insert(k, v).expect("insert replay");
        }
        let vd = verifier.digest().expect("verifier digest");
        assert_eq!(
            vd.as_slice(),
            new_root.as_bytes(),
            "verifier must reproduce the prover digest from the generated proof"
        );
    }

    // ----- pre-broadcast self-check -----

    #[test]
    fn self_check_passes_on_canonical_proof() {
        let mut tree = AvlTree::new();
        for i in 0u8..10 {
            tree.insert(make_key(i), vec![i]);
        }
        let parent_root = tree.root_digest();
        let lookups = [make_key(3), make_key(8)];
        let mut to_remove: DryRunRemoveMap = BTreeMap::new();
        to_remove.insert(make_key(5), ());
        let mut to_insert: DryRunInsertMap = BTreeMap::new();
        to_insert.insert(make_key(70), vec![0x11]);

        let (new_root, proof) =
            apply_change_set_via_prover(&tree, &lookups, &to_remove, &to_insert).expect("dry-run");
        self_check_candidate_proof(
            &parent_root,
            &lookups,
            &to_remove,
            &to_insert,
            &proof,
            &new_root,
        )
        .expect("canonical proof must pass the self-check");
    }

    #[test]
    fn self_check_rejects_missing_lookup_prefix() {
        // THE h1,805,523 incident, pinned at the self-check layer: a
        // proof generated WITHOUT the data-input lookups cannot be
        // verifier-replayed with the canonical stream. Even if the
        // generator regresses again, this check withholds the
        // candidate instead of broadcasting an invalid block.
        let mut tree = AvlTree::new();
        for i in 0u8..10 {
            tree.insert(make_key(i), vec![i]);
        }
        let parent_root = tree.root_digest();
        let lookups = [make_key(3)];
        let mut to_remove: DryRunRemoveMap = BTreeMap::new();
        to_remove.insert(make_key(5), ());
        let mut to_insert: DryRunInsertMap = BTreeMap::new();
        to_insert.insert(make_key(70), vec![0x11]);

        // Buggy generator: no lookup prefix.
        let (new_root, bad_proof) = apply_change_set_via_prover(&tree, &[], &to_remove, &to_insert)
            .expect("lookup-free dry-run");
        let err = self_check_candidate_proof(
            &parent_root,
            &lookups,
            &to_remove,
            &to_insert,
            &bad_proof,
            &new_root,
        )
        .expect_err("lookup-free proof must fail the canonical replay");
        assert!(
            matches!(err, StateError::CandidateProofSelfCheckFailed { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn self_check_rejects_tampered_proof() {
        let mut tree = AvlTree::new();
        for i in 0u8..10 {
            tree.insert(make_key(i), vec![i]);
        }
        let parent_root = tree.root_digest();
        let mut to_remove: DryRunRemoveMap = BTreeMap::new();
        to_remove.insert(make_key(2), ());
        let to_insert: DryRunInsertMap = BTreeMap::new();

        let (new_root, mut proof) =
            apply_change_set_via_prover(&tree, &[], &to_remove, &to_insert).expect("dry-run");
        let mid = proof.len() / 2;
        proof[mid] ^= 0xFF;
        let err = self_check_candidate_proof(
            &parent_root,
            &[],
            &to_remove,
            &to_insert,
            &proof,
            &new_root,
        )
        .expect_err("tampered proof must fail the self-check");
        assert!(
            matches!(err, StateError::CandidateProofSelfCheckFailed { .. }),
            "got {err:?}"
        );
    }

    // ----- error paths -----

    #[test]
    fn remove_missing_key_returns_error() {
        let tree = AvlTree::new();
        let mut to_remove: DryRunRemoveMap = BTreeMap::new();
        to_remove.insert(make_key(99), ()); // never inserted
        let to_insert: DryRunInsertMap = BTreeMap::new();
        let err = apply_change_set_via_prover(&tree, &[], &to_remove, &to_insert)
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
