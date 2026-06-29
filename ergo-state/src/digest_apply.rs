//! Mode 5 digest-verifier apply seam — proof-backed view over the
//! authenticated UTXO state.
//!
//! `DigestProofVerifier` wraps `ergo_sigma::avl::AvlVerifier` with an
//! explicit ADProofs section-linkage binding so a persisted section
//! blob from a different header cannot be paired with this header
//! even when the root hash matches. The verifier's constructor takes
//! `(modifier_id, proof_bytes, header)` together so the binding is
//! unforgeable at the API boundary — a caller cannot construct the
//! verifier without naming both the header and the persisted
//! section's id, and the verifier rejects mismatches.
//!
//! This module exposes only the operations the digest-backed block
//! apply seam needs (proof construction, batch insert/remove,
//! final-digest extraction). It does NOT touch persistence; a later
//! phase lifts the persisted backend.
//!
//! Items below have no in-crate production callers yet — the
//! persisted store, rollback, and boot-dispatch phases that will
//! consume the seam are not in tree. `#![allow(dead_code)]` keeps
//! the lib-only build clean while the seam is being wired up.
#![allow(dead_code)]

use std::collections::BTreeMap;

use ergo_primitives::digest::blake2b256;
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::modifier_id::{compute_section_id, TYPE_AD_PROOFS};
use ergo_sigma::avl::AvlVerifier;

/// Authenticated UTXO box-id key length in bytes — the AVL+ tree
/// indexes boxes by their 32-byte `ErgoBox.box_id`.
const BOX_ID_KEY_LENGTH: usize = 32;

/// Box bytes the ADProofs witness for a block's data-input lookups and
/// spent-input removes: `(box_id, serialized_box_bytes)` pairs. These
/// are the input/data-input boxes the digest-mode validator resolves
/// against (with the block's own outputs) — Scala's `proofs.verify`
/// return value.
pub type ResolvedBoxes = Vec<([u8; 32], Vec<u8>)>;

/// Failure arms for the digest-mode apply seam. Each arm is a
/// distinct rejection cause — the apply orchestrator uses these to
/// classify failures into `session-scoped invalid` vs
/// `cryptographically definitive invalid` per the design doc.
#[derive(Debug, thiserror::Error)]
pub enum DigestApplyError {
    /// `blake2b256(proof_bytes) != header.ad_proofs_root`. The
    /// persisted section bytes don't hash to the digest the header
    /// commits to.
    #[error(
        "ADProofs root mismatch: blake2b256(proof_bytes) = {computed}, header.ad_proofs_root = {expected}"
    )]
    AdProofsRootMismatch { computed: String, expected: String },
    /// `modifier_id != compute_section_id(TYPE_AD_PROOFS,
    /// header_id, header.ad_proofs_root)`. The section's persisted
    /// id doesn't bind to THIS header — root-only checks would
    /// accept a foreign blob.
    #[error(
        "ADProofs section-linkage mismatch: persisted modifier_id = {persisted}, expected = {expected}"
    )]
    AdProofsModifierIdMismatch { persisted: String, expected: String },
    /// The `AvlVerifier` constructor returned a typed error.
    /// SESSION-scoped because we cannot reliably tell apart, at
    /// this layer, three failure classes that the upstream crate
    /// surfaces through the same `Err` channel:
    ///
    /// 1. The proof is structurally invalid (cryptographically
    ///    definitive bad data),
    /// 2. The proof's embedded starting digest does not match
    ///    the supplied `parent_state_root` (could be bad data OR
    ///    could be that OUR local parent root is stale from
    ///    rollback/reorg/state-rebuild drift), or
    /// 3. Some other upstream condition the wrapper reports as
    ///    a typed Err.
    ///
    /// Per the "treat-unknown-as-our-bug" half of the
    /// invalidity contract, default all three to session-scoped.
    /// The orchestrator can only promote to persistent
    /// invalidity after independently re-deriving the parent
    /// root from a trusted source AND re-running construction
    /// with that root. Classification does not depend on the
    /// upstream error wording — a string-match contract would
    /// be too fragile a third-party dependency.
    #[error("ADProofs verifier construction failed (session-scoped): {reason}")]
    VerifierConstructionRejected { reason: String },
    /// The underlying `ergo_avltree_rust` crate panicked during
    /// verifier construction. The current upstream version panics
    /// on certain malformed envelopes instead of returning Err;
    /// caught here so it does not tear down the node. SEPARATE from
    /// `MalformedProof` because a panic from the third-party crate
    /// is not the same evidence class as an explicit reject — it
    /// could be a library/integration bug rather than definitively
    /// bad data. Treat as session-scoped invalid until upstream
    /// fixes the unwrap.
    #[error("verifier construction panicked (treat as session-scoped invalid): {reason}")]
    VerifierConstructionPanic { reason: String },
    /// The proof carries an explicit non-membership witness for
    /// the box id (the upstream `BatchAVLVerifier::remove` returned
    /// `Ok(None)`). Cryptographically definitive evidence that the
    /// input box does not exist in the parent state — distinct
    /// from `VerifierOpFailed`, which is opaque. The Mode 5
    /// orchestrator decides whether to promote this to persistent
    /// invalidity; the seam only emits the precise classification.
    ///
    /// This arm is currently unexercised by in-tree tests because
    /// `BatchAVLProver` does not surface a normal block-shaped op
    /// sequence that drives a verifier `Remove` to the `Ok(None)`
    /// path — the producer either drives `Ok(Some)` (real removes)
    /// or fails the whole batch. A real Scala/mainnet ADProof
    /// corpus is required to exercise this path end-to-end, and
    /// the boot dispatch gate keeps Mode 5 off until that corpus
    /// is wired into CI.
    #[error("input box {box_id} explicitly absent from parent state per proof")]
    InputNotInProof { box_id: String },
    /// The caller passed a `(to_remove, to_insert)` pair that
    /// is not yet netted — the same box id appears in BOTH
    /// sets, indicating intra-block create-then-spend pairs
    /// were not cancelled by the upstream block-changes
    /// computation. Driving the verifier with this shape would
    /// look up a created box in the proof that doesn't cover it
    /// (the proof only covers the parent state), reintroducing
    /// the exact intra-block proof bug this seam exists to
    /// avoid. SESSION-scoped: a Mode 5 orchestrator bug, NOT
    /// bad block data.
    #[error("non-netted change set (intra-block overlap): box id {box_id} appears in both to_remove and to_insert")]
    NotNettedChangeSet { box_id: String },
    /// `serialize_header(header)` failed for the binding check.
    /// Indicates a local header-construction or serializer bug,
    /// NOT bad ADProofs data. Session-scoped invalidity at most.
    #[error("internal header-id derivation failure for binding check: {reason}")]
    InternalSerializeFailure { reason: String },
    /// A `lookup` / `remove` / `insert` operation against the
    /// verifier failed for opaque reasons in the underlying crate.
    #[error("verifier operation '{op}' failed for key {key}")]
    VerifierOpFailed { op: &'static str, key: String },
    /// The post-apply digest extracted from the verifier doesn't
    /// match `header.state_root`. Either the proof didn't cover the
    /// inputs/outputs the block actually changed, or there's a
    /// consensus bug.
    #[error(
        "post-apply digest mismatch: verifier extracted {computed}, header.state_root = {expected}"
    )]
    DigestMismatch { computed: String, expected: String },
}

/// Proof-backed AVL+ tree view for digest-mode block apply.
///
/// Constructed once per block, mutated through `remove` / `insert`
/// matching the block's net `boxChanges`, then `finalize_digest`
/// extracts the post-apply digest for comparison against
/// `header.state_root`. The parent's state_root is held internally
/// so `finalize_digest` returns a deterministic 33-byte digest
/// even for an empty / no-op block (which would otherwise leave
/// the underlying verifier's digest as `None`).
pub struct DigestProofVerifier {
    inner: AvlVerifier,
    /// Cached parent `state_root` (33 bytes). Returned by
    /// `finalize_digest` when the verifier has never been mutated
    /// — an empty block yields the parent's digest unchanged, and
    /// callers MUST receive a deterministic 33-byte answer.
    parent_state_root: [u8; 33],
}

impl DigestProofVerifier {
    /// Construct a verifier bound to a specific header AND a specific
    /// persisted ADProofs section. Three checks fire before the
    /// underlying `AvlVerifier` is even constructed:
    ///
    /// 1. `blake2b256(proof_bytes) == header.ad_proofs_root` — the
    ///    bytes hash to the digest the header commits to.
    /// 2. `modifier_id == compute_section_id(TYPE_AD_PROOFS,
    ///    header_id, header.ad_proofs_root)` — the persisted section
    ///    ID belongs to THIS header. Without this an adversary could
    ///    feed a foreign blob whose root happens to collide with
    ///    the target.
    /// 3. The verifier is seeded with `parent_state_root`, NOT
    ///    `header.state_root`. The AD-proof contract is
    ///    `verify(prev_state_digest, txs) -> new_state_digest`:
    ///    the proof bytes carry the AVL+ subgraph rooted at the
    ///    PARENT block's `state_root`; applying the block's
    ///    removes + inserts mutates the verifier toward THIS
    ///    block's `state_root`, which the caller then cross-checks
    ///    via `finalize_digest`. Seeding with the post-state
    ///    `header.state_root` would reject every honest proof.
    ///
    /// The caller MUST pass through:
    /// - the same `modifier_id` it used to fetch the bytes from
    ///   `BLOCK_SECTIONS` (so the binding check is meaningful), AND
    /// - the parent block's persisted `state_root` (33 bytes).
    pub fn new(
        modifier_id: [u8; 32],
        proof_bytes: &[u8],
        header: &Header,
        parent_state_root: &[u8; 33],
    ) -> Result<Self, DigestApplyError> {
        // 1. Root hash check.
        let computed_root = blake2b256(proof_bytes);
        let header_root_bytes = header.ad_proofs_root.as_bytes();
        if computed_root.as_bytes() != header_root_bytes {
            return Err(DigestApplyError::AdProofsRootMismatch {
                computed: hex::encode(computed_root.as_bytes()),
                expected: hex::encode(header_root_bytes),
            });
        }

        // 2. Section-id linkage check. The header_id derives from a
        // round-trip serialize; we don't carry a precomputed id on
        // the in-memory struct. A failure here is a LOCAL bug
        // (header construction or serializer), NOT bad ADProofs
        // data — surface it through the dedicated internal arm so
        // the apply orchestrator doesn't mis-classify it as
        // definitive invalidity.
        let (_, header_id_modifier) =
            serialize_header(header).map_err(|e| DigestApplyError::InternalSerializeFailure {
                reason: format!("{e:?}"),
            })?;
        let header_id = *header_id_modifier.as_bytes();
        let expected_modifier_id =
            compute_section_id(TYPE_AD_PROOFS, &header_id, header_root_bytes);
        if modifier_id != expected_modifier_id {
            return Err(DigestApplyError::AdProofsModifierIdMismatch {
                persisted: hex::encode(modifier_id),
                expected: hex::encode(expected_modifier_id),
            });
        }

        // 3. Verifier construction seeded with the PARENT's
        // state_root. The proof asserts the AVL+ subgraph rooted
        // at `parent_state_root`; mutating the verifier walks
        // toward this block's `header.state_root`, which the
        // caller cross-checks via `finalize_digest`.
        //
        // `AvlVerifier::new` now self-guards construction panics
        // and returns a typed Err, so in practice failures arrive
        // as `VerifierConstructionRejected`. The outer panic catch
        // here is belt-and-suspenders for any unexpected panic
        // escaping `new()`; both variants are session-scoped and
        // observationally identical ("definitive bad proof" vs
        // "stale local parent root"), so the orchestrator only
        // promotes to persistent invalidity after independently
        // re-deriving the parent root. Catching the panic is sound:
        // it is deterministic on the proof bytes, mutates no shared
        // state, and the verifier under construction is a fresh
        // stack-local value.
        let proof_owned = proof_bytes.to_vec();
        let parent_owned = parent_state_root.to_vec();
        let construct = || AvlVerifier::new(&parent_owned, &proof_owned, BOX_ID_KEY_LENGTH, None);
        let inner_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(construct))
            .map_err(|panic_payload| {
                let reason = panic_payload
                    .downcast_ref::<&'static str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "verifier construction panicked".to_string());
                DigestApplyError::VerifierConstructionPanic { reason }
            })?;
        let inner = inner_result
            .map_err(|e| DigestApplyError::VerifierConstructionRejected { reason: e })?;
        Ok(Self {
            inner,
            parent_state_root: *parent_state_root,
        })
    }

    /// Insert a new box (output). Applies the operation to the
    /// proof-backed view; the digest changes accordingly.
    fn insert(&mut self, box_id: &[u8; 32], box_bytes: &[u8]) -> Result<(), DigestApplyError> {
        self.inner
            .insert(box_id, box_bytes)
            .map_err(|_| DigestApplyError::VerifierOpFailed {
                op: "insert",
                key: hex::encode(box_id),
            })
    }

    /// Drive the verifier with a block's data-input lookups and net
    /// `boxChanges`, and return the post-state digest. Op order MUST
    /// match the proof generator's exactly — Scala's
    /// `StateChanges.operations = toLookup ++ toRemove ++ toAppend`
    /// (`ErgoState.stateChanges`): data-input `Lookup`s in transaction
    /// order (duplicates kept) first, then all removes in
    /// BTreeMap-ascending key order, then all inserts in
    /// BTreeMap-ascending key order. The lookups are read-only and do
    /// not move the digest, but a `BatchAVLVerifier` consumes its proof
    /// as a stream, so they must still be replayed to keep the stream
    /// aligned for the removes.
    ///
    /// `to_remove` and `to_insert` mirror Mode 1's
    /// `build_utxo_changes_checked` output: intra-block
    /// create-then-spend pairs are already cancelled (a box that
    /// is created AND spent within the same block appears in
    /// neither set). The non-netted shape is rejected by
    /// `apply_block_in_memory`'s contract — driving the verifier
    /// per-tx would miss intra-block creates because the proof
    /// only covers pre-state.
    ///
    /// Classification preserves the upstream evidence boundary:
    ///
    /// - `Ok(true)`  : the proof asserted membership, the Remove
    ///   succeeded, the digest advanced. Continue.
    /// - `Ok(false)` : the proof carried an explicit
    ///   non-membership witness (the upstream verifier returned
    ///   `Ok(None)`). Cryptographically definitive: the input
    ///   box does not exist in the parent state. Surface as
    ///   `InputNotInProof` (precise classification — the
    ///   orchestrator decides whether to promote to persistent).
    /// - `Err(())`   : opaque verifier failure (witness missing
    ///   for the access path, structurally bad envelope, library
    ///   bug). Surface as `VerifierOpFailed` (session-scoped per
    ///   the "treat-unknown-as-our-bug" half of the contract).
    ///
    /// Inserts that fail surface as `VerifierOpFailed`.
    pub fn apply_net_box_changes(
        &mut self,
        to_lookup: &[[u8; 32]],
        to_remove: &BTreeMap<[u8; 32], ()>,
        to_insert: &BTreeMap<[u8; 32], Vec<u8>>,
    ) -> Result<(), DigestApplyError> {
        self.apply_net_box_changes_resolving(to_lookup, to_remove, to_insert)
            .map(|_| ())
    }

    /// As [`Self::apply_net_box_changes`], but also returns the
    /// serialized box bytes the proof witnessed for the data-input
    /// lookups and the spent-input removes — the old values Scala's
    /// `proofs.verify(stateChanges, ...)` yields. The digest-mode
    /// validator resolves these (combined with the block's own raw
    /// outputs) into a `UtxoView`, so it can run full transaction
    /// validation against a box arena it does not store. Inserts carry
    /// no old value. A lookup the proof witnesses as non-membership
    /// (`Ok(None)` — e.g. a data input that references a box created
    /// earlier in the same block) is omitted here; the caller resolves
    /// it from the block outputs.
    pub fn apply_net_box_changes_resolving(
        &mut self,
        to_lookup: &[[u8; 32]],
        to_remove: &BTreeMap<[u8; 32], ()>,
        to_insert: &BTreeMap<[u8; 32], Vec<u8>>,
    ) -> Result<ResolvedBoxes, DigestApplyError> {
        // Enforce the net-changeset invariant the caller's
        // contract promises: no box id may appear in both
        // sides. The docstring above explains why this matters
        // (driving the verifier with an overlapping key would
        // look up a created box that the proof does not
        // cover). Check via BTreeMap intersection — both sides
        // are key-ordered, so this is O(n + m).
        let mut left = to_remove.keys();
        let mut right = to_insert.keys();
        let mut l = left.next();
        let mut r = right.next();
        while let (Some(li), Some(ri)) = (l, r) {
            match li.cmp(ri) {
                std::cmp::Ordering::Equal => {
                    return Err(DigestApplyError::NotNettedChangeSet {
                        box_id: hex::encode(li),
                    });
                }
                std::cmp::Ordering::Less => l = left.next(),
                std::cmp::Ordering::Greater => r = right.next(),
            }
        }
        // Box bytes the proof witnesses for lookups + removes — Scala's
        // `proofs.verify` return value, the spent-input + data-input boxes
        // the validator needs.
        //
        // Operation order MUST mirror Scala's
        // `StateChanges.operations = toLookup ++ toRemove ++ toAppend`
        // (`ErgoState.stateChanges`): the ADProofs were generated by
        // replaying data-input lookups FIRST (in transaction order, not
        // sorted), then removes (box-id ascending), then inserts (box-id
        // ascending). A `BatchAVLVerifier` consumes its proof as a stream,
        // so each lookup — though read-only and digest-neutral — must still
        // be replayed here to keep the stream aligned for the removes that
        // follow. `to_lookup` carries the data-input box ids in that exact
        // order, duplicates included.
        //
        // No `catch_unwind` is needed HERE: both upstream panic classes are
        // already contained below this call. Construction panics (proof-graph
        // rebuild in `new()`) are guarded at construction (see
        // `VerifierConstructionPanic`). Operation-time panics — a structurally-
        // valid-but-wrong proof drives the crate to `panic!` mid-stream
        // (`authenticated_tree_ops.rs` 413/431/635; see `ergo-sigma`'s
        // `remove_structurally_valid_wrong_proof_fails_closed_not_panic`) — are
        // caught inside `AvlVerifier` itself (`ergo-sigma`'s `avl::guarded`),
        // which poisons the verifier and surfaces `Err(())`. So every op call
        // here observes only `Ok`/`Err`; a caught op-time panic arrives as the
        // `Err(())` arms below and is mapped to a session-scoped
        // `VerifierOpFailed` (fail closed, matching Scala).
        let mut resolved: Vec<([u8; 32], Vec<u8>)> =
            Vec::with_capacity(to_lookup.len() + to_remove.len());
        for key in to_lookup {
            match self.inner.lookup(key) {
                Ok(Some(value)) => resolved.push((*key, value)),
                Ok(None) => {} // non-membership; resolved from block outputs
                Err(()) => {
                    return Err(DigestApplyError::VerifierOpFailed {
                        op: "lookup",
                        key: hex::encode(key),
                    });
                }
            }
        }
        // Removes next, BTreeMap-ascending — capturing the old value.
        for box_id in to_remove.keys() {
            match self.inner.remove_returning_value(box_id) {
                Ok(Some(value)) => resolved.push((*box_id, value)),
                Ok(None) => {
                    return Err(DigestApplyError::InputNotInProof {
                        box_id: hex::encode(box_id),
                    });
                }
                Err(()) => {
                    return Err(DigestApplyError::VerifierOpFailed {
                        op: "remove",
                        key: hex::encode(box_id),
                    });
                }
            }
        }
        for (box_id, bytes) in to_insert {
            self.insert(box_id, bytes)?;
        }
        Ok(resolved)
    }

    /// Pure-function post-state oracle for the Mode 5 apply seam:
    /// given the parent state root, an ADProofs section, this
    /// block's header, and the block's net `boxChanges`, returns
    /// the post-apply digest the verifier extracted AFTER applying
    /// the changes, AND cross-checks it against
    /// `header.state_root`.
    ///
    /// `Ok(_)` => the proof + applied changes describe exactly the
    /// state transition the header commits to.
    /// `Err(DigestMismatch)` => the computed and expected post-
    /// state digests diverge (the proof did NOT cover the right
    /// changes, or the changes weren't the right ones).
    pub fn apply_block_in_memory(
        modifier_id: [u8; 32],
        proof_bytes: &[u8],
        header: &Header,
        parent_state_root: &[u8; 33],
        to_lookup: &[[u8; 32]],
        to_remove: &BTreeMap<[u8; 32], ()>,
        to_insert: &BTreeMap<[u8; 32], Vec<u8>>,
    ) -> Result<[u8; 33], DigestApplyError> {
        let mut verifier =
            DigestProofVerifier::new(modifier_id, proof_bytes, header, parent_state_root)?;
        verifier.apply_net_box_changes(to_lookup, to_remove, to_insert)?;
        let computed = verifier.finalize_digest();
        let expected: &[u8; 33] = header.state_root.as_bytes();
        if computed != *expected {
            return Err(DigestApplyError::DigestMismatch {
                computed: hex::encode(computed),
                expected: hex::encode(expected),
            });
        }
        Ok(computed)
    }

    /// As [`Self::apply_block_in_memory`], but also returns the box
    /// bytes the proof witnessed (spent inputs + data inputs). The
    /// digest-mode block validator pairs these with the block's raw
    /// outputs to build a `UtxoView` for full transaction validation,
    /// then commits the returned root. Mirrors Scala's
    /// `DigestState.validateTransactions`, where `proofs.verify` both
    /// confirms the root transition AND yields the old box values.
    pub fn apply_block_resolving_boxes(
        modifier_id: [u8; 32],
        proof_bytes: &[u8],
        header: &Header,
        parent_state_root: &[u8; 33],
        to_lookup: &[[u8; 32]],
        to_remove: &BTreeMap<[u8; 32], ()>,
        to_insert: &BTreeMap<[u8; 32], Vec<u8>>,
    ) -> Result<([u8; 33], ResolvedBoxes), DigestApplyError> {
        let mut verifier =
            DigestProofVerifier::new(modifier_id, proof_bytes, header, parent_state_root)?;
        let resolved = verifier.apply_net_box_changes_resolving(to_lookup, to_remove, to_insert)?;
        let computed = verifier.finalize_digest();
        let expected: &[u8; 33] = header.state_root.as_bytes();
        if computed != *expected {
            return Err(DigestApplyError::DigestMismatch {
                computed: hex::encode(computed),
                expected: hex::encode(expected),
            });
        }
        Ok((computed, resolved))
    }

    /// Extract the post-apply digest. Compared against
    /// `header.state_root` by the apply orchestrator to confirm
    /// the proof + the applied operations describe the same final
    /// state.
    ///
    /// Deterministic 33-byte answer in every case: if the verifier
    /// has been mutated, returns the underlying digest; if no
    /// operations were applied (empty block — no transactions),
    /// returns the parent's `state_root` so the caller can
    /// directly compare against `header.state_root` without
    /// special-casing the empty path.
    pub fn finalize_digest(&self) -> [u8; 33] {
        match self.inner.digest() {
            Some(bytes) => {
                debug_assert_eq!(bytes.len(), 33, "AVL+ digest is always 33 bytes");
                let mut out = [0u8; 33];
                out.copy_from_slice(&bytes);
                out
            }
            None => self.parent_state_root,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::autolykos::AutolykosSolution;

    /// Synthesize a minimal header with the supplied ad_proofs_root.
    /// state_root is left at the default-empty AVL digest (33 bytes,
    /// all zero except the height byte at index 32).
    fn synth_header(ad_proofs_root: [u8; 32]) -> Header {
        let mut state_root_bytes = [0u8; 33];
        state_root_bytes[32] = 0;
        Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0u8; 32]),
            ad_proofs_root: Digest32::from_bytes(ad_proofs_root),
            state_root: ADDigest::from_bytes(state_root_bytes),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            timestamp: 1_700_000_000,
            n_bits: 0x1d00ffff,
            height: 1,
            extension_root: Digest32::from_bytes([0u8; 32]),
            votes: [0u8; 3],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0xAA; 8],
            },
        }
    }

    fn correct_modifier_id_for(header: &Header) -> [u8; 32] {
        let (_, id) = serialize_header(header).expect("serialize");
        compute_section_id(
            TYPE_AD_PROOFS,
            id.as_bytes(),
            header.ad_proofs_root.as_bytes(),
        )
    }

    #[test]
    fn new_rejects_root_hash_mismatch() {
        // The header commits to an `ad_proofs_root` that does NOT
        // match `blake2b256(proof_bytes)`. The verifier must refuse
        // to construct.
        let proof_bytes = b"any bytes here, hash=specific";
        let wrong_root = [0xABu8; 32];
        let header = synth_header(wrong_root);
        let modifier_id = correct_modifier_id_for(&header);
        let err = match DigestProofVerifier::new(
            modifier_id,
            proof_bytes,
            &header,
            &empty_avl_digest(),
        ) {
            Ok(_) => panic!("must reject"),
            Err(e) => e,
        };
        match err {
            DigestApplyError::AdProofsRootMismatch { computed, expected } => {
                assert_eq!(expected, hex::encode(wrong_root));
                assert_eq!(computed, hex::encode(blake2b256(proof_bytes).as_bytes()));
            }
            other => panic!("expected AdProofsRootMismatch, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_foreign_modifier_id() {
        // The root hash matches but the persisted `modifier_id`
        // points at a different header. The full-triple binding
        // catches this even when root-only would pass.
        let proof_bytes = b"proof bytes";
        let actual_root = *blake2b256(proof_bytes).as_bytes();
        let header = synth_header(actual_root);
        // Foreign modifier_id — pretend a section from a different
        // header sneaked in.
        let foreign_modifier_id = [0xFFu8; 32];
        let err = match DigestProofVerifier::new(
            foreign_modifier_id,
            proof_bytes,
            &header,
            &empty_avl_digest(),
        ) {
            Ok(_) => panic!("must reject foreign modifier_id"),
            Err(e) => e,
        };
        match err {
            DigestApplyError::AdProofsModifierIdMismatch {
                persisted,
                expected,
            } => {
                assert_eq!(persisted, hex::encode(foreign_modifier_id));
                assert_eq!(expected, hex::encode(correct_modifier_id_for(&header)));
            }
            other => panic!("expected AdProofsModifierIdMismatch, got {other:?}"),
        }
    }

    /// Default 33-byte empty-tree digest accepted by AvlVerifier as
    /// a starting digest. Used as placeholder parent state in tests
    /// that exercise the binding rejections (which fire before the
    /// verifier construction runs).
    fn empty_avl_digest() -> [u8; 33] {
        [0u8; 33]
    }

    // The `finalize_digest` empty-block-returns-parent branch
    // is exercised by the parity suite below via a real prover
    // witness for a no-op block, not by a synthetic empty-bytes
    // shortcut.

    #[test]
    fn new_classifies_garbage_proof_envelope_as_session_scoped_panic_arm() {
        // Both binding checks pass (root + modifier_id match the
        // bytes), but the bytes are not a valid AVL+ proof
        // envelope. The current upstream
        // `ergo_avltree_rust::BatchAVLVerifier` panics during
        // construction (stack underflow during graph rebuild).
        // The seam catches it and surfaces as
        // `VerifierConstructionPanic` (session-scoped). A typed
        // Err from a future upstream revision would route to
        // `VerifierConstructionRejected` — both arms are
        // session-scoped, so the orchestrator does not promote
        // either to persistent invalidity without independent
        // re-derivation of the parent root.
        let proof_bytes = b"clearly not a real avl proof envelope";
        let actual_root = *blake2b256(proof_bytes).as_bytes();
        let header = synth_header(actual_root);
        let modifier_id = correct_modifier_id_for(&header);
        let err = match DigestProofVerifier::new(
            modifier_id,
            proof_bytes,
            &header,
            &empty_avl_digest(),
        ) {
            Ok(_) => panic!("must reject"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err,
                DigestApplyError::VerifierConstructionPanic { .. }
                    | DigestApplyError::VerifierConstructionRejected { .. }
            ),
            "expected session-scoped construction failure, got {err:?}",
        );
    }

    // ----- cross-mode interop (Mode 1 producer vs Mode 5 verifier) -----
    // Internal consistency between the two in-tree implementations —
    // NOT external Scala/mainnet oracle parity, which is a separate
    // corpus-backed gate.

    use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
    use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
    use ergo_avltree_rust::batch_node::{AVLTree, Node, NodeHeader};
    use ergo_avltree_rust::operation::{KeyValue, Operation};
    use std::collections::BTreeMap;

    fn new_prover() -> BatchAVLProver {
        let tree = AVLTree::new(
            |d| Node::LabelOnly(NodeHeader::new(Some(*d), None)),
            32,
            None,
        );
        BatchAVLProver::new(tree, true)
    }

    fn prover_digest(prover: &mut BatchAVLProver) -> [u8; 33] {
        let raw = prover.digest().expect("prover has a digest");
        let mut out = [0u8; 33];
        out.copy_from_slice(&raw);
        out
    }

    fn kv(box_id: [u8; 32], value: Vec<u8>) -> KeyValue {
        KeyValue {
            key: bytes::Bytes::from(box_id.to_vec()),
            value: bytes::Bytes::from(value),
        }
    }

    struct SyntheticBlock {
        to_remove: BTreeMap<[u8; 32], ()>,
        to_insert: BTreeMap<[u8; 32], Vec<u8>>,
    }

    fn synthesize_block_witness(
        prover: &mut BatchAVLProver,
        block: &SyntheticBlock,
    ) -> (Vec<u8>, [u8; 33]) {
        // Mirror the production producer's op order in
        // `ergo-state/src/store/dry_run.rs::apply_change_set_via_prover`:
        // all removes in BTreeMap-ascending key order, then all
        // inserts in BTreeMap-ascending key order. No Lookups —
        // the witness encodes the access path inline.
        for box_id in block.to_remove.keys() {
            prover
                .perform_one_operation(&Operation::Remove(bytes::Bytes::from(box_id.to_vec())))
                .expect("remove");
        }
        for (box_id, value) in &block.to_insert {
            prover
                .perform_one_operation(&Operation::Insert(kv(*box_id, value.clone())))
                .expect("insert");
        }
        let proof_bytes = prover.generate_proof().to_vec();
        let post = prover_digest(prover);
        (proof_bytes, post)
    }

    fn synth_header_with_roots(state_root: [u8; 33], ad_proofs_root: [u8; 32]) -> Header {
        let mut h = synth_header(ad_proofs_root);
        h.state_root = ergo_primitives::digest::ADDigest::from_bytes(state_root);
        h
    }

    #[test]
    fn parity_single_insert_only_block() {
        let mut prover = new_prover();
        let parent = prover_digest(&mut prover);
        let new_box_id = [0xCDu8; 32];
        let new_box_bytes = vec![0xAA, 0xBB, 0xCC];
        let mut block = SyntheticBlock {
            to_remove: BTreeMap::new(),
            to_insert: BTreeMap::new(),
        };
        block.to_insert.insert(new_box_id, new_box_bytes);
        let (proof_bytes, expected_post) = synthesize_block_witness(&mut prover, &block);
        let ad_proofs_root = *blake2b256(&proof_bytes).as_bytes();
        let header = synth_header_with_roots(expected_post, ad_proofs_root);
        let modifier_id = correct_modifier_id_for(&header);
        let mode5_post = DigestProofVerifier::apply_block_in_memory(
            modifier_id,
            &proof_bytes,
            &header,
            &parent,
            &[],
            &block.to_remove,
            &block.to_insert,
        )
        .expect("Mode 5 apply must succeed and match Mode 1 digest");
        assert_eq!(mode5_post, expected_post);
    }

    #[test]
    fn parity_remove_then_insert_block() {
        // Pre-state has one box. Block removes it and adds a new one.
        let mut prover = new_prover();
        let pre_box_id = [0x11u8; 32];
        prover
            .perform_one_operation(&Operation::Insert(kv(pre_box_id, vec![0x01, 0x02, 0x03])))
            .expect("pre-state insert");
        let _ = prover.generate_proof(); // discard pre-state witness
        let parent = prover_digest(&mut prover);
        let new_box_id = [0x22u8; 32];
        let mut block = SyntheticBlock {
            to_remove: BTreeMap::new(),
            to_insert: BTreeMap::new(),
        };
        block.to_remove.insert(pre_box_id, ());
        block.to_insert.insert(new_box_id, vec![0x04, 0x05, 0x06]);
        let (proof_bytes, expected_post) = synthesize_block_witness(&mut prover, &block);
        let ad_proofs_root = *blake2b256(&proof_bytes).as_bytes();
        let header = synth_header_with_roots(expected_post, ad_proofs_root);
        let modifier_id = correct_modifier_id_for(&header);
        let mode5_post = DigestProofVerifier::apply_block_in_memory(
            modifier_id,
            &proof_bytes,
            &header,
            &parent,
            &[],
            &block.to_remove,
            &block.to_insert,
        )
        .expect("Mode 5 apply must succeed");
        assert_eq!(mode5_post, expected_post);
    }

    #[test]
    fn parity_intra_block_create_then_spend_yields_net_no_change() {
        // Critical case: TxA creates B1, TxB spends B1 within the
        // same block. The net `boxChanges` cancels B1 entirely.
        // Mode 5 must NOT try to look up B1 in the proof (it
        // doesn't cover B1 — intra-block). Post-state digest
        // equals parent.
        let mut prover = new_prover();
        let parent = prover_digest(&mut prover);
        let block = SyntheticBlock {
            to_remove: BTreeMap::new(),
            to_insert: BTreeMap::new(),
        };
        let (proof_bytes, expected_post) = synthesize_block_witness(&mut prover, &block);
        assert_eq!(expected_post, parent);
        let ad_proofs_root = *blake2b256(&proof_bytes).as_bytes();
        let header = synth_header_with_roots(expected_post, ad_proofs_root);
        let modifier_id = correct_modifier_id_for(&header);
        let mode5_post = DigestProofVerifier::apply_block_in_memory(
            modifier_id,
            &proof_bytes,
            &header,
            &parent,
            &[],
            &block.to_remove,
            &block.to_insert,
        )
        .expect("Mode 5 apply with empty net changes must succeed");
        assert_eq!(
            mode5_post, parent,
            "empty net changes means post-state digest equals parent",
        );
    }

    #[test]
    fn parity_rejects_wrong_parent_state_root() {
        // Consensus-critical binding: the verifier must reject a
        // witness whose embedded root does not match the
        // claimed parent state root. Otherwise an attacker could
        // pair an honest witness for parent P with a header
        // claiming parent P' and slip a fraudulent transition
        // past the digest check. The seam exposes this binding
        // through the `parent_state_root` parameter to
        // `DigestProofVerifier::new`.
        let mut prover = new_prover();
        let real_parent = prover_digest(&mut prover);
        let new_box_id = [0x77u8; 32];
        let mut block = SyntheticBlock {
            to_remove: BTreeMap::new(),
            to_insert: BTreeMap::new(),
        };
        block.to_insert.insert(new_box_id, vec![0xCA, 0xFE]);
        let (proof_bytes, expected_post) = synthesize_block_witness(&mut prover, &block);
        let ad_proofs_root = *blake2b256(&proof_bytes).as_bytes();
        let header = synth_header_with_roots(expected_post, ad_proofs_root);
        let modifier_id = correct_modifier_id_for(&header);
        // Flip one byte of the real parent root — claim a
        // different pre-state.
        let mut wrong_parent = real_parent;
        wrong_parent[0] ^= 0xFF;
        let err = match DigestProofVerifier::apply_block_in_memory(
            modifier_id,
            &proof_bytes,
            &header,
            &wrong_parent,
            &[],
            &block.to_remove,
            &block.to_insert,
        ) {
            Ok(_) => panic!("Mode 5 must reject witness/parent root mismatch"),
            Err(e) => e,
        };
        // The underlying crate either returns a typed error
        // (MalformedProof) or panics (VerifierConstructionPanic)
        // when the seeded root does not match the witness; both
        // are acceptable rejections.
        // The wrong-parent case must surface in the session-
        // scoped construction-failure CLASS — the seam routes
        // both upstream channels (typed Err →
        // `VerifierConstructionRejected`; panic →
        // `VerifierConstructionPanic`) to session-scoped arms.
        // The test pins the CLASS, not the specific arm,
        // because the upstream crate could shift the
        // wrong-parent case between the two channels without
        // changing the seam's externally-visible contract.
        assert!(
            matches!(
                err,
                DigestApplyError::VerifierConstructionRejected { .. }
                    | DigestApplyError::VerifierConstructionPanic { .. }
            ),
            "expected session-scoped construction failure for wrong parent root, got {err:?}",
        );
    }

    #[test]
    fn rejects_non_netted_change_set() {
        // The seam contract requires `to_remove` and `to_insert`
        // to be disjoint — the upstream block-changes computation
        // is expected to have cancelled intra-block
        // create-then-spend pairs already. If a caller violates
        // that, the verifier would try to look up a created box
        // in the proof that does not cover it. The seam must
        // reject the shape BEFORE driving the verifier, with a
        // session-scoped variant so the orchestrator does not
        // promote a caller bug to persistent invalidity.
        let mut prover = new_prover();
        let pre_box = [0x44u8; 32];
        prover
            .perform_one_operation(&Operation::Insert(kv(pre_box, vec![0x01])))
            .expect("pre-state insert");
        let _ = prover.generate_proof();
        let parent = prover_digest(&mut prover);
        let mut block = SyntheticBlock {
            to_remove: BTreeMap::new(),
            to_insert: BTreeMap::new(),
        };
        block.to_remove.insert(pre_box, ());
        let (proof_bytes, expected_post) = synthesize_block_witness(&mut prover, &block);
        let ad_proofs_root = *blake2b256(&proof_bytes).as_bytes();
        let header = synth_header_with_roots(expected_post, ad_proofs_root);
        let modifier_id = correct_modifier_id_for(&header);
        // Caller bug: pass the SAME id in both sides.
        let overlap_id = [0xEEu8; 32];
        let mut bad_remove: BTreeMap<[u8; 32], ()> = BTreeMap::new();
        let mut bad_insert: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
        bad_remove.insert(overlap_id, ());
        bad_insert.insert(overlap_id, vec![0xCA, 0xFE]);
        let err = match DigestProofVerifier::apply_block_in_memory(
            modifier_id,
            &proof_bytes,
            &header,
            &parent,
            &[],
            &bad_remove,
            &bad_insert,
        ) {
            Ok(_) => panic!("seam must reject non-netted change set"),
            Err(e) => e,
        };
        let DigestApplyError::NotNettedChangeSet { box_id } = err else {
            panic!("expected NotNettedChangeSet, got {err:?}");
        };
        assert_eq!(box_id, hex::encode(overlap_id));
    }

    #[test]
    fn parity_multi_remove_multi_insert_ordering() {
        // Drives the producer's BTreeMap-ascending order across
        // multiple removes AND multiple inserts. The verifier
        // must consume the same ordering and reach the producer's
        // post-state digest. Two pre-state boxes are spent, two
        // new boxes are created.
        use crate::avl::tree::AvlTree;
        use crate::store::apply_change_set_via_prover;

        let mut tree = AvlTree::new();
        let pre_a = [0x20u8; 32];
        let pre_b = [0x30u8; 32];
        tree.insert(pre_a, vec![0x01]);
        tree.insert(pre_b, vec![0x02]);
        let parent_bytes = *tree.root_digest().as_bytes();

        let new_a = [0x60u8; 32];
        let new_b = [0x70u8; 32];
        let mut to_remove: BTreeMap<[u8; 32], ()> = BTreeMap::new();
        let mut to_insert: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
        to_remove.insert(pre_a, ());
        to_remove.insert(pre_b, ());
        to_insert.insert(new_a, vec![0x10, 0x11]);
        to_insert.insert(new_b, vec![0x12, 0x13]);

        let (new_root, proof_bytes) =
            apply_change_set_via_prover(&tree, &[], &to_remove, &to_insert)
                .expect("producer must succeed");
        let new_root_bytes = *new_root.as_bytes();

        let ad_proofs_root = *blake2b256(&proof_bytes).as_bytes();
        let header = synth_header_with_roots(new_root_bytes, ad_proofs_root);
        let modifier_id = correct_modifier_id_for(&header);

        let mode5_post = DigestProofVerifier::apply_block_in_memory(
            modifier_id,
            &proof_bytes,
            &header,
            &parent_bytes,
            &[],
            &to_remove,
            &to_insert,
        )
        .expect("Mode 5 must accept multi-key witness and reach producer post-state");
        assert_eq!(
            mode5_post, new_root_bytes,
            "multi-key producer/consumer digest mismatch — op-ordering contract broken",
        );
    }

    #[test]
    fn parity_remove_against_uncovered_key_is_session_scoped() {
        // The realistic dishonest-block scenario: an honest
        // producer generates a witness covering ONLY the boxes
        // its block actually spent. A dishonest block claims to
        // spend a different box; that key's access path is not
        // in the witness, and the underlying verifier returns an
        // opaque Err.
        //
        // Opaque verifier Err — the witness doesn't cover this
        // access path. Distinct from `InputNotInProof` (which
        // requires an explicit non-membership witness, an arm
        // the upstream prover does not surface from normal
        // block-shaped ops — see the variant docstring).
        let mut prover = new_prover();
        let real_box_id = [0x10u8; 32];
        prover
            .perform_one_operation(&Operation::Insert(kv(real_box_id, vec![0x01])))
            .expect("pre-state insert");
        let _ = prover.generate_proof();
        let parent = prover_digest(&mut prover);
        // Synthesize a Remove witness for real_box_id (a key
        // the verifier WILL find).
        prover
            .perform_one_operation(&Operation::Remove(bytes::Bytes::from(real_box_id.to_vec())))
            .expect("remove real id");
        let proof_bytes = prover.generate_proof().to_vec();
        // The block claims to spend a DIFFERENT key that the
        // witness does not cover.
        let phantom_box_id = [0x99u8; 32];
        let mut block = SyntheticBlock {
            to_remove: BTreeMap::new(),
            to_insert: BTreeMap::new(),
        };
        block.to_remove.insert(phantom_box_id, ());
        let ad_proofs_root = *blake2b256(&proof_bytes).as_bytes();
        let header = synth_header_with_roots(parent, ad_proofs_root);
        let modifier_id = correct_modifier_id_for(&header);
        let err = match DigestProofVerifier::apply_block_in_memory(
            modifier_id,
            &proof_bytes,
            &header,
            &parent,
            &[],
            &block.to_remove,
            &block.to_insert,
        ) {
            Ok(_) => panic!("Mode 5 must reject phantom remove"),
            Err(e) => e,
        };
        assert!(
            matches!(err, DigestApplyError::VerifierOpFailed { op: "remove", .. }),
            "expected VerifierOpFailed (session-scoped) for uncovered-key remove, got {err:?}",
        );
    }

    #[test]
    fn end_to_end_producer_consumer_interop_via_dry_run() {
        // Witness-shape interop: the production proof producer
        // (`apply_change_set_via_prover` in
        // `ergo-state::store::dry_run`) emits Remove + Insert ops
        // with no Lookups. The Mode 5 verifier
        // (`apply_block_in_memory`) must accept that exact shape
        // and reach the same post-state digest the producer
        // reports.
        use crate::avl::tree::AvlTree;
        use crate::store::apply_change_set_via_prover;

        // Build a pre-state AvlTree with a few boxes. The
        // parent state_root is its current digest.
        let mut tree = AvlTree::new();
        let pre_id_1 = [0x40u8; 32];
        let pre_id_2 = [0x41u8; 32];
        tree.insert(pre_id_1, vec![0x01, 0x02]);
        tree.insert(pre_id_2, vec![0x03, 0x04]);
        let parent_root = tree.root_digest();
        let parent_bytes = *parent_root.as_bytes();

        // Synthesize a block: spend pre_id_1, create new_id_1.
        let new_id_1 = [0x50u8; 32];
        let mut to_remove: BTreeMap<[u8; 32], ()> = BTreeMap::new();
        let mut to_insert: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
        to_remove.insert(pre_id_1, ());
        to_insert.insert(new_id_1, vec![0xAA, 0xBB]);

        // Run the production producer to get the canonical
        // witness + post-state.
        let (new_root, proof_bytes) =
            apply_change_set_via_prover(&tree, &[], &to_remove, &to_insert)
                .expect("producer must succeed");
        let new_root_bytes = *new_root.as_bytes();

        // Build a Mode 5 view of this block.
        let ad_proofs_root = *blake2b256(&proof_bytes).as_bytes();
        let header = synth_header_with_roots(new_root_bytes, ad_proofs_root);
        let modifier_id = correct_modifier_id_for(&header);

        // Mode 5 must consume the producer's witness and reach
        // the producer's reported post-state.
        let mode5_post = DigestProofVerifier::apply_block_in_memory(
            modifier_id,
            &proof_bytes,
            &header,
            &parent_bytes,
            &[],
            &to_remove,
            &to_insert,
        )
        .expect(
            "Mode 5 verifier must accept the production producer's witness AND reach the producer's post-state",
        );
        assert_eq!(
            mode5_post, new_root_bytes,
            "producer/consumer digest mismatch — Mode 5 witness contract is out of sync",
        );
    }

    #[test]
    fn parity_rejects_lying_about_header_state_root() {
        let mut prover = new_prover();
        let parent = prover_digest(&mut prover);
        let new_box_id = [0x33u8; 32];
        let mut block = SyntheticBlock {
            to_remove: BTreeMap::new(),
            to_insert: BTreeMap::new(),
        };
        block
            .to_insert
            .insert(new_box_id, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let (proof_bytes, real_post) = synthesize_block_witness(&mut prover, &block);
        let mut lied_post = real_post;
        lied_post[0] ^= 0xFF;
        let ad_proofs_root = *blake2b256(&proof_bytes).as_bytes();
        let header = synth_header_with_roots(lied_post, ad_proofs_root);
        let modifier_id = correct_modifier_id_for(&header);
        let err = match DigestProofVerifier::apply_block_in_memory(
            modifier_id,
            &proof_bytes,
            &header,
            &parent,
            &[],
            &block.to_remove,
            &block.to_insert,
        ) {
            Ok(_) => panic!("Mode 5 must reject mismatched state_root"),
            Err(e) => e,
        };
        assert!(
            matches!(err, DigestApplyError::DigestMismatch { .. }),
            "expected DigestMismatch, got {err:?}",
        );
    }

    /// Phase 5.7 — the real consensus oracle. Replays a contiguous run
    /// of mainnet blocks through the digest verifier: seed at each
    /// block's parent `state_root`, apply its real net box changes
    /// against its real ADProofs, and assert the finalized root equals
    /// the block's mainnet `header.state_root`. The corpus
    /// (`test-vectors/mode5/ad_proofs_replay/`) was extracted from a
    /// Scala node with every inserted box's bytes gated by
    /// `blake2b256(bytes) == boxId`; this test is the end-to-end
    /// cross-check that the Rust AVL+ verifier reproduces Scala's
    /// authenticated-state transition byte-for-byte.
    mod mainnet_replay {
        use super::*;
        use std::collections::BTreeMap;
        use std::fs;
        use std::path::PathBuf;

        #[derive(serde::Deserialize)]
        struct Row {
            height: u32,
            parent_state_root: String,
            state_root: String,
            ad_proofs_root: String,
            proof_bytes: String,
            /// Data-input box ids in transaction order (duplicates kept) —
            /// the `toLookup` prefix of Scala's operation sequence.
            #[serde(default)]
            to_lookup: Vec<String>,
            to_remove: Vec<String>,
            to_insert: Vec<InsertRow>,
        }
        #[derive(serde::Deserialize)]
        struct InsertRow {
            box_id: String,
            bytes: String,
        }

        fn arr32(h: &str) -> [u8; 32] {
            let v = hex::decode(h).expect("hex32");
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            a
        }
        fn arr33(h: &str) -> [u8; 33] {
            let v = hex::decode(h).expect("hex33");
            let mut a = [0u8; 33];
            a.copy_from_slice(&v);
            a
        }

        fn load_rows() -> Vec<Row> {
            let dir = PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../test-vectors/mode5/ad_proofs_replay"
            ));
            let mut rows: Vec<Row> = fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("read corpus dir {dir:?}: {e}"))
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .map(|p| {
                    serde_json::from_str::<Row>(&fs::read_to_string(&p).expect("read row"))
                        .unwrap_or_else(|e| panic!("parse {p:?}: {e}"))
                })
                .collect();
            rows.sort_by_key(|r| r.height);
            rows
        }

        type ChangeMaps = (BTreeMap<[u8; 32], ()>, BTreeMap<[u8; 32], Vec<u8>>);

        fn change_maps(r: &Row) -> ChangeMaps {
            let mut to_remove = BTreeMap::new();
            for id in &r.to_remove {
                to_remove.insert(arr32(id), ());
            }
            let mut to_insert = BTreeMap::new();
            for ins in &r.to_insert {
                to_insert.insert(
                    arr32(&ins.box_id),
                    hex::decode(&ins.bytes).expect("box bytes"),
                );
            }
            (to_remove, to_insert)
        }

        // ----- oracle parity -----

        // The Rust digest verifier reproduces mainnet's authenticated
        // state transition for every block in the corpus, including the
        // data-input blocks. The replay drives the verifier in Scala's
        // operation order — data-input lookups (tx order), then removes
        // (box-id ascending), then inserts (box-id ascending) — because
        // a BatchAVLVerifier consumes its proof as a stream and roots
        // are order-independent (so a root-match alone, as in Mode 1,
        // does not validate proof-consumption order). An earlier cut
        // omitted the lookups and failed on the first data-input block
        // (1795969) — caught only by this real-ADProof oracle.
        #[test]
        fn mainnet_ad_proofs_replay_matches_state_roots() {
            let rows = load_rows();
            assert!(
                rows.len() >= 100,
                "corpus unexpectedly small ({} rows) — re-extract via the \
                 extract_mode5_corpus example",
                rows.len(),
            );
            // Heights must be a contiguous run.
            for w in rows.windows(2) {
                assert_eq!(w[1].height, w[0].height + 1, "corpus is not contiguous");
            }

            let mut prev_computed: Option<[u8; 33]> = None;
            for r in &rows {
                let parent = arr33(&r.parent_state_root);
                // Chain replay: this block's parent IS the prior block's
                // verified output root.
                if let Some(pc) = prev_computed {
                    assert_eq!(
                        parent, pc,
                        "h{}: parent_state_root diverges from the prior verified root",
                        r.height
                    );
                }
                let state_root = arr33(&r.state_root);
                let ad_root = arr32(&r.ad_proofs_root);
                let proof = hex::decode(&r.proof_bytes).expect("proof hex");
                let to_lookup: Vec<[u8; 32]> = r.to_lookup.iter().map(|h| arr32(h)).collect();
                let (to_remove, to_insert) = change_maps(r);

                let header = synth_header_with_roots(state_root, ad_root);
                let modifier_id = correct_modifier_id_for(&header);
                let computed = DigestProofVerifier::apply_block_in_memory(
                    modifier_id,
                    &proof,
                    &header,
                    &parent,
                    &to_lookup,
                    &to_remove,
                    &to_insert,
                )
                .unwrap_or_else(|e| panic!("h{}: digest replay rejected: {e:?}", r.height));
                assert_eq!(
                    computed, state_root,
                    "h{}: computed post-root != mainnet header.state_root",
                    r.height
                );
                prev_computed = Some(computed);
            }
            eprintln!(
                "Mode 5 replay: {} mainnet blocks verified (heights {}..={})",
                rows.len(),
                rows.first().unwrap().height,
                rows.last().unwrap().height,
            );
        }

        #[test]
        fn mainnet_replay_resolves_canonical_input_boxes_from_proofs() {
            let rows = load_rows();
            let mut checked = 0usize;
            for r in &rows {
                let parent = arr33(&r.parent_state_root);
                let state_root = arr33(&r.state_root);
                let ad_root = arr32(&r.ad_proofs_root);
                let proof = hex::decode(&r.proof_bytes).expect("proof hex");
                let to_lookup: Vec<[u8; 32]> = r.to_lookup.iter().map(|h| arr32(h)).collect();
                let (to_remove, to_insert) = change_maps(r);
                let header = synth_header_with_roots(state_root, ad_root);
                let modifier_id = correct_modifier_id_for(&header);

                let (computed, resolved) = DigestProofVerifier::apply_block_resolving_boxes(
                    modifier_id,
                    &proof,
                    &header,
                    &parent,
                    &to_lookup,
                    &to_remove,
                    &to_insert,
                )
                .unwrap_or_else(|e| panic!("h{}: resolve failed: {e:?}", r.height));
                // Resolving must not perturb the digest transition.
                assert_eq!(computed, state_root, "h{}: root mismatch", r.height);

                // Every box the proof yields is canonical: its bytes hash
                // to its claimed id — these are the real spent-input /
                // data-input boxes the validator resolves against.
                let resolved_ids: Vec<[u8; 32]> = resolved.iter().map(|(id, _)| *id).collect();
                for (box_id, value) in &resolved {
                    assert_eq!(
                        blake2b256(value).as_bytes(),
                        box_id,
                        "h{}: resolved box bytes do not hash to its id",
                        r.height
                    );
                    checked += 1;
                }
                // Every spent input is resolved (a remove always carries
                // an old value); data-input lookups may be Ok(None) for
                // in-block boxes, so those resolve from outputs instead.
                for rm in to_remove.keys() {
                    assert!(
                        resolved_ids.contains(rm),
                        "h{}: removed box {} was not resolved from the proof",
                        r.height,
                        hex::encode(rm),
                    );
                }
            }
            assert!(checked > 100, "expected many resolved boxes, got {checked}");
            eprintln!("Mode 5 resolve: {checked} proof-witnessed boxes verified canonical");
        }

        #[test]
        fn mainnet_replay_corrupt_proof_byte_is_rejected() {
            let rows = load_rows();
            let r = &rows[0];
            let parent = arr33(&r.parent_state_root);
            let ad_root = arr32(&r.ad_proofs_root);
            let mut proof = hex::decode(&r.proof_bytes).expect("proof hex");
            proof[0] ^= 0xFF; // no longer hashes to ad_proofs_root
            let (to_remove, to_insert) = change_maps(r);
            let header = synth_header_with_roots(arr33(&r.state_root), ad_root);
            let modifier_id = correct_modifier_id_for(&header);
            let err = DigestProofVerifier::apply_block_in_memory(
                modifier_id,
                &proof,
                &header,
                &parent,
                &[], // root-hash gate fails before lookups are consumed
                &to_remove,
                &to_insert,
            )
            .expect_err("a corrupted proof must be rejected");
            assert!(
                matches!(err, DigestApplyError::AdProofsRootMismatch { .. }),
                "got {err:?}",
            );
        }
    }

    /// Genesis -> height-1 cross-validation: the Mode 1 prover derives
    /// the ADProofs for block 1 over the real genesis state, and the
    /// Mode 5 verifier consumes that exact witness back to the same
    /// post-state. This closes the producer/consumer loop at the chain
    /// origin — the one height with no Scala-extracted ADProof corpus
    /// (the `mainnet_replay` corpus starts at h=1795968) — so the two
    /// in-tree authenticated-state implementations are pinned to agree
    /// on the height-0 -> height-1 transition that
    /// `ergo-state/tests/genesis_digest.rs` already pins for Mode 1.
    ///
    /// Internal producer/consumer interop, NOT external Scala parity:
    /// the witness is self-derived, so `ad_proofs_root` is synthesized
    /// from it rather than asserted against mainnet's committed value.
    mod genesis_cross_validation {
        use super::*;
        use crate::avl::tree::AvlTree;
        use crate::store::{apply_change_set_via_prover, StateStore};
        use ergo_chain_spec::GenesisParams;
        use ergo_primitives::digest::ModifierId;
        use ergo_primitives::reader::VlqReader;
        use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
        use ergo_ser::ergo_tree::read_ergo_tree;
        use ergo_ser::register::{AdditionalRegisters, RegisterValue};
        use ergo_ser::sigma_value::read_constant;
        use ergo_ser::transaction::{read_transaction, Transaction};

        const GENESIS_STATE_DIGEST_HEX: &str =
            "a5df145d41ab15a01e0cd3ffbab046f0d029e5412293072ad0f5827428589b9302";
        const HEIGHT_1_STATE_DIGEST_HEX: &str =
            "18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303";

        // Block 1's bytes, from the same corpus genesis_digest.rs uses.
        const BLOCKS_1_5_JSON: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/mainnet/blocks_1_5.json"
        ));

        #[derive(serde::Deserialize)]
        struct GenesisBoxJson {
            #[serde(rename = "value")]
            value: u64,
            #[serde(rename = "ergoTree")]
            ergo_tree: String,
            #[serde(rename = "creationHeight")]
            creation_height: u32,
            #[serde(rename = "additionalRegisters", default)]
            additional_registers: std::collections::HashMap<String, String>,
            #[serde(rename = "transactionId")]
            transaction_id: String,
            index: u16,
        }

        #[derive(serde::Deserialize)]
        struct BlockJson {
            height: u32,
            transactions: Vec<TxJson>,
        }
        #[derive(serde::Deserialize)]
        struct TxJson {
            bytes: String,
        }

        fn arr33(h: &str) -> [u8; 33] {
            let v = hex::decode(h).expect("hex33");
            let mut a = [0u8; 33];
            a.copy_from_slice(&v);
            a
        }

        /// Parse one genesis box from its JSON row. Mirrors
        /// `ergo-state/tests/genesis_digest.rs::parse_genesis_box`,
        /// reproduced here because that integration test cannot be
        /// imported into a `src/` unit-test module.
        fn parse_genesis_box(json: &GenesisBoxJson) -> ErgoBox {
            let tree_bytes = hex::decode(&json.ergo_tree).expect("ergo_tree hex");
            let mut r = VlqReader::new(&tree_bytes);
            let ergo_tree = read_ergo_tree(&mut r).expect("read_ergo_tree");

            let mut reg_vec: Vec<(usize, RegisterValue)> = Vec::new();
            for (key, val_hex) in &json.additional_registers {
                let reg_idx = match key.as_str() {
                    "R4" => 0,
                    "R5" => 1,
                    "R6" => 2,
                    "R7" => 3,
                    "R8" => 4,
                    "R9" => 5,
                    other => panic!("unknown register {other}"),
                };
                let val_bytes = hex::decode(val_hex).expect("register hex");
                let mut vr = VlqReader::new(&val_bytes);
                let (tpe, value) = read_constant(&mut vr).expect("read_constant");
                reg_vec.push((reg_idx, RegisterValue { tpe, value }));
            }
            reg_vec.sort_by_key(|(idx, _)| *idx);
            let registers = AdditionalRegisters {
                registers: reg_vec.into_iter().map(|(_, rv)| rv).collect(),
            };

            let candidate = ErgoBoxCandidate::new(
                json.value,
                ergo_tree,
                json.creation_height,
                Vec::new(),
                registers,
            )
            .expect("ErgoBoxCandidate::new");

            let tx_id_bytes: [u8; 32] = hex::decode(&json.transaction_id)
                .expect("tx id hex")
                .try_into()
                .expect("tx id len");
            ErgoBox {
                candidate,
                transaction_id: ModifierId::from_bytes(tx_id_bytes),
                index: json.index,
            }
        }

        /// Build the genesis AVL+ tree from the chain-spec-embedded
        /// genesis boxes.
        fn genesis_tree() -> AvlTree {
            let boxes_json = GenesisParams::mainnet()
                .boxes_json
                .expect("mainnet genesis boxes embedded");
            let boxes: Vec<GenesisBoxJson> =
                serde_json::from_str(boxes_json).expect("parse genesis boxes");
            assert_eq!(boxes.len(), 3, "mainnet genesis has 3 boxes");
            let mut tree = AvlTree::new();
            for jb in &boxes {
                let eb = parse_genesis_box(jb);
                let box_id = eb.box_id().expect("box_id");
                let serialized = serialize_ergo_box(&eb).expect("serialize_ergo_box");
                tree.insert(*box_id.as_bytes(), serialized);
            }
            tree
        }

        fn block_1_tx() -> Transaction {
            let blocks: Vec<BlockJson> =
                serde_json::from_str(BLOCKS_1_5_JSON).expect("parse blocks_1_5");
            let block1 = blocks
                .iter()
                .find(|b| b.height == 1)
                .expect("block 1 present");
            assert_eq!(block1.transactions.len(), 1, "block 1 has exactly one tx");
            let tx_bytes = hex::decode(&block1.transactions[0].bytes).expect("tx bytes hex");
            let mut r = VlqReader::new(&tx_bytes);
            read_transaction(&mut r).expect("read block-1 tx")
        }

        // ----- oracle parity -----

        #[test]
        fn genesis_to_height_1_producer_consumer_round_trip() {
            // 1. The genesis tree's root is the consensus-pinned genesis
            //    digest AND agrees with the chain-spec constant — closing
            //    the chain-spec <-> in-memory-tree agreement.
            let genesis_pinned = arr33(GENESIS_STATE_DIGEST_HEX);
            let tree = genesis_tree();
            assert_eq!(
                *tree.root_digest().as_bytes(),
                genesis_pinned,
                "genesis tree root != consensus-pinned genesis digest",
            );
            assert_eq!(
                GenesisParams::mainnet().state_digest,
                genesis_pinned,
                "GenesisParams::mainnet().state_digest != consensus-pinned genesis digest",
            );

            // 2/3. Net box changes for block 1 via the SAME builder both
            //      legs consume (no second netting path).
            let tx = block_1_tx();
            let (to_remove, to_insert) =
                StateStore::build_utxo_changes_raw(&[&tx]).expect("build_utxo_changes_raw");

            // 4. PRODUCER (Mode 1 prover): derive (post-root, witness).
            let (new_root, proof_bytes) =
                apply_change_set_via_prover(&tree, &[], &to_remove, &to_insert)
                    .expect("producer prover");
            let new_root_bytes = *new_root.as_bytes();
            let height_1_pinned = arr33(HEIGHT_1_STATE_DIGEST_HEX);
            assert_eq!(
                new_root_bytes, height_1_pinned,
                "producer post-root != consensus-pinned height-1 digest",
            );

            // 5. Header view: state_root = the producer's post-root,
            //    ad_proofs_root SYNTHESIZED from the self-derived witness
            //    (internal interop — NOT mainnet's committed value).
            let ad_proofs_root = *blake2b256(&proof_bytes).as_bytes();
            let header = synth_header_with_roots(new_root_bytes, ad_proofs_root);
            let modifier_id = correct_modifier_id_for(&header);

            // 6. CONSUMER (Mode 5 verifier): parent seed is the GENESIS
            //    digest (a5df...02), NEVER [0;33]; block 1's data inputs
            //    are empty so to_lookup is &[].
            let to_lookup: Vec<[u8; 32]> = tx
                .data_inputs
                .iter()
                .map(|di| *di.box_id.as_bytes())
                .collect();
            let computed = DigestProofVerifier::apply_block_in_memory(
                modifier_id,
                &proof_bytes,
                &header,
                &genesis_pinned,
                &to_lookup,
                &to_remove,
                &to_insert,
            )
            .expect("Mode 5 verifier must accept the producer's genesis-block witness");

            assert_eq!(
                computed, height_1_pinned,
                "Mode 5 consumer post-root != consensus-pinned height-1 digest",
            );
            assert_eq!(
                computed, new_root_bytes,
                "producer/consumer disagree on the height-1 root",
            );
        }
    }
}
