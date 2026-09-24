//! Input-block and ordering-block announcement validity (spec 6.1–6.3,
//! 6.5, 2.4): PoW against the (possibly multiplied) target, the extension
//! proof reducing to the header's extension root, nBits agreement with
//! chain context, and — under the strict policy — that the proof's leaves
//! are exactly the announced fields (spec 6.3 item 2; see the crate docs
//! and `test-vectors/weak-blocks/extension_proof.json` for findings F4/F4b).
//!
//! F4b: Scala's `merkleProof.valid(root)` accepts a proof whose leaves
//! don't match the announced fields as long as it still reduces to the
//! header's root — not caught by the Scala-parity check alone, only by
//! [`verify_field_binding`].
//!
//! F4 (boundary fix, not a Scala behavior): scrypto's real
//! `BatchMerkleProof.valid` — what Scala's `InputBlockAnnouncement.valid`
//! actually calls — does NOT accept an empty proof against an arbitrary
//! root; it returns `false` (see `test-vectors/weak-blocks/extension_proof.json`'s
//! `empty_proof` case, `scala_ext_valid: false`). But this crate's own
//! `ergo_validation::popow::merkle::verify_batch_merkle_proof` (a shared
//! PoPoW reducer, tuned for a different genesis-style empty-proof special
//! case) *does* treat an empty proof as trivially valid against any root.
//! [`verify_extension_proof`] closes that gap at the announcement boundary
//! — rejecting an empty proof before ever calling the shared reducer —
//! rather than changing the shared reducer itself. That rejection reports
//! `ProofInvalid` (the same verdict scrypto's `valid == false` reports),
//! not `ProofEmpty` — `ProofEmpty` is reserved for
//! [`verify_field_binding`]'s strict-binding check.

use ergo_crypto::merkle::extension_leaf_digest;
use ergo_crypto::pow::verify_input_block_pow;
use ergo_ser::input_block::{InputBlockAnnouncement, InputBlockFields, OrderingBlockAnnouncement};
use ergo_validation::popow::merkle::verify_batch_merkle_proof;

/// Announcement-validation policy. `strict_field_binding` (spec 6.3 item 2,
/// default `true`) additionally requires the proof's leaves to equal the
/// announced [`InputBlockFields`] exactly — closing finding F4/F4b, where
/// Scala's own check only requires the proof to reduce to the header's
/// extension root, regardless of which fields the leaves actually cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnouncementPolicy {
    pub strict_field_binding: bool,
}

impl Default for AnnouncementPolicy {
    fn default() -> Self {
        Self {
            strict_field_binding: true,
        }
    }
}

/// Announcement-validation failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AnnouncementError {
    #[error("subblocks-per-block parameter unavailable (input blocks not active)")]
    MultiplierUnavailable,
    #[error("input-block PoW invalid: {0}")]
    Pow(String),
    #[error("nBits {got} != expected {expected}")]
    NBitsMismatch { got: u32, expected: u32 },
    #[error("extension proof does not reduce to the header's extension root")]
    ProofInvalid,
    /// Strict binding only (spec 6.3 item 2) — see [`verify_field_binding`].
    /// Not raised by the Scala-parity path ([`verify_extension_proof`]),
    /// which reports an empty proof as [`AnnouncementError::ProofInvalid`]
    /// instead, matching scrypto's plain `valid == false` verdict.
    #[error("extension proof is empty")]
    ProofEmpty,
    /// Strict binding only (spec 6.3 item 2) — the proof reduces to the
    /// header's root but its leaves don't match the announced fields (F4b).
    #[error("proof leaves do not bind the announced fields: {0}")]
    FieldsUnbound(String),
}

/// nBits agreement with chain context, shared by [`validate_announcement_parity`]
/// and [`validate_ordering_announcement`] (spec 6.1/2.4's identical nBits
/// clause for both announcement kinds).
fn check_expected_n_bits(n_bits: u32, expected: Option<u32>) -> Result<(), AnnouncementError> {
    if let Some(expected) = expected {
        if n_bits != expected {
            return Err(AnnouncementError::NBitsMismatch {
                got: n_bits,
                expected,
            });
        }
    }
    Ok(())
}

/// The extension-proof-reduces-to-root check alone: the proof must be
/// non-empty and must reduce (via the shared popow batch-merkle reducer)
/// to `extension_root`. Rejects an empty proof before ever calling the
/// shared reducer — see the crate doc for why: `ergo_validation`'s reducer
/// treats an empty proof as valid against any root, which Scala's own
/// `BatchMerkleProof.valid` does not (finding F4). Returns `ProofInvalid`
/// for the empty case (not `ProofEmpty`, which is `verify_field_binding`'s
/// strict-binding error): this is the Scala-parity path, and scrypto's
/// `valid == false` is a plain invalid-proof verdict, not a distinct
/// "empty" classification — see findings-8-r2.md.
pub fn verify_extension_proof(
    fields: &InputBlockFields,
    extension_root: &[u8; 32],
) -> Result<(), AnnouncementError> {
    if fields.proof.indices.is_empty() && fields.proof.proofs.is_empty() {
        return Err(AnnouncementError::ProofInvalid);
    }
    if !verify_batch_merkle_proof(&fields.proof, extension_root) {
        return Err(AnnouncementError::ProofInvalid);
    }
    Ok(())
}

/// The Scala-parity part of announcement validity only: PoW, the proof
/// reducing to the header's extension root, and nBits agreement. Does
/// *not* check that the proof's leaves actually bind the announced
/// fields — see [`verify_field_binding`] and [`AnnouncementPolicy`] for
/// that. Used to compute the `parity` verdict for oracle findings.
pub fn validate_announcement_parity(
    ann: &InputBlockAnnouncement,
    multiplier: Option<i32>,
    expected_n_bits: Option<u32>,
) -> Result<(), AnnouncementError> {
    let multiplier = multiplier.ok_or(AnnouncementError::MultiplierUnavailable)?;
    verify_input_block_pow(&ann.header, multiplier)
        .map_err(|e| AnnouncementError::Pow(e.to_string()))?;
    verify_extension_proof(&ann.fields, ann.header.extension_root.as_bytes())?;
    check_expected_n_bits(ann.header.n_bits, expected_n_bits)
}

/// The binding check alone (spec 6.3 item 2): the proof's leaves must be
/// exactly the announced fields' extension-leaf digests (in any order),
/// and the proof must not be empty.
pub fn verify_field_binding(fields: &InputBlockFields) -> Result<(), AnnouncementError> {
    if fields.proof.indices.is_empty() {
        return Err(AnnouncementError::ProofEmpty);
    }
    // `InputBlockFields::extension_fields()` yields `[u8; 2]` keys, so
    // `extension_leaf_digest`'s length-prefix guard cannot return `None`
    // here today. Collect fallibly anyway, and treat a `None` as an
    // unbound field rather than dropping it: a dropped expectation would
    // SHORTEN `want`, and a proof that omits the very same leaf would
    // then compare equal — laxer, not stricter. If the key type ever
    // becomes variable-length this stays fail-closed without revisiting.
    let Some(mut want) = fields
        .extension_fields()
        .iter()
        .map(|(k, v)| extension_leaf_digest(k, v))
        .collect::<Option<Vec<[u8; 32]>>>()
    else {
        return Err(AnnouncementError::FieldsUnbound(
            "extension field key exceeds the 255-byte leaf prefix".into(),
        ));
    };
    let mut proved: Vec<[u8; 32]> = fields.proof.indices.iter().map(|(_, d)| *d).collect();
    want.sort_unstable();
    proved.sort_unstable();
    if proved != want {
        return Err(AnnouncementError::FieldsUnbound(format!(
            "{} proved leaves vs {} announced fields",
            proved.len(),
            want.len()
        )));
    }
    Ok(())
}

/// Full announcement validity per spec 6.1–6.3 and 6.5. `multiplier` is the
/// current state's `subblocks_per_block`; `expected_n_bits` is
/// `Some(encode(required_difficulty_after(parent)))` when the parent
/// header is known (skipped otherwise — no chain context to check against).
pub fn validate_announcement(
    ann: &InputBlockAnnouncement,
    multiplier: Option<i32>,
    expected_n_bits: Option<u32>,
    policy: AnnouncementPolicy,
) -> Result<(), AnnouncementError> {
    validate_announcement_parity(ann, multiplier, expected_n_bits)?;
    if policy.strict_field_binding {
        verify_field_binding(&ann.fields)?;
    }
    Ok(())
}

/// Ordering-block announcement validity (spec 2.4): the restated extension
/// fields must hash to the header's extension root, the header's own PoW
/// (ordinary target, no multiplier) must be valid, and nBits must agree
/// with chain context when known.
pub fn validate_ordering_announcement(
    ann: &OrderingBlockAnnouncement,
    expected_n_bits: Option<u32>,
) -> Result<(), AnnouncementError> {
    let refs: Vec<(&[u8], &[u8])> = ann
        .extension_fields
        .iter()
        .map(|(k, v)| (&k[..], &v[..]))
        .collect();
    // Keys here are `[u8; 2]`, so `extension_root` cannot refuse them;
    // comparing against `Some(..)` keeps a hypothetical `None` a
    // mismatch — i.e. a rejection — rather than a panic on a wire path.
    if ergo_crypto::merkle::extension_root(&refs) != Some(*ann.header.extension_root.as_bytes()) {
        return Err(AnnouncementError::ProofInvalid);
    }
    ergo_crypto::pow::verify_pow_solution(&ann.header)
        .map_err(|e| AnnouncementError::Pow(e.to_string()))?;
    check_expected_n_bits(ann.header.n_bits, expected_n_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_ser::batch_merkle_proof::BatchMerkleProof;

    // ----- helpers -----

    fn fields_with_proof(proof: BatchMerkleProof) -> InputBlockFields {
        InputBlockFields {
            prev_input_block_id: None,
            transactions_digest: [0x11; 32],
            prev_transactions_digest: [0x22; 32],
            proof,
        }
    }

    fn matching_proof(fields: &InputBlockFields) -> BatchMerkleProof {
        let indices = fields
            .extension_fields()
            .iter()
            .enumerate()
            .map(|(i, (k, v))| {
                (
                    i as u32,
                    extension_leaf_digest(k, v).expect("two-byte extension key"),
                )
            })
            .collect();
        BatchMerkleProof {
            indices,
            proofs: Vec::new(),
        }
    }

    // ----- happy path -----

    #[test]
    fn policy_default_is_strict() {
        assert!(AnnouncementPolicy::default().strict_field_binding);
    }

    // ----- error paths -----

    #[test]
    fn binding_rejects_empty_proof() {
        let fields = fields_with_proof(BatchMerkleProof {
            indices: Vec::new(),
            proofs: Vec::new(),
        });
        assert_eq!(
            verify_field_binding(&fields),
            Err(AnnouncementError::ProofEmpty)
        );
    }

    #[test]
    fn extension_proof_rejects_empty_proof_before_reducer() {
        // fix round 1, finding 1: the shared popow reducer
        // (`ergo_validation::popow::merkle::verify_batch_merkle_proof`)
        // treats an empty proof as valid against any root; Scala's real
        // `BatchMerkleProof.valid` does not. `verify_extension_proof` must
        // reject the empty proof itself, before ever calling the reducer.
        //
        // fix round 2 (findings-8-r2.md): the rejection reports
        // `ProofInvalid`, not `ProofEmpty` — this is the Scala-parity
        // path, and scrypto's `valid == false` is a plain invalid-proof
        // verdict, not a distinct "empty" classification. `ProofEmpty`
        // stays reserved for `verify_field_binding`'s strict-binding
        // check (see `binding_rejects_empty_proof` below).
        let fields = fields_with_proof(BatchMerkleProof {
            indices: Vec::new(),
            proofs: Vec::new(),
        });
        assert_eq!(
            verify_extension_proof(&fields, &[0x42; 32]),
            Err(AnnouncementError::ProofInvalid)
        );
    }

    #[test]
    fn binding_accepts_exact_leaf_set() {
        let fields = fields_with_proof(BatchMerkleProof {
            indices: Vec::new(),
            proofs: Vec::new(),
        });
        let proof = matching_proof(&fields);
        let fields = fields_with_proof(proof);
        assert_eq!(verify_field_binding(&fields), Ok(()));
    }

    #[test]
    fn binding_rejects_extra_leaf() {
        let base = fields_with_proof(BatchMerkleProof {
            indices: Vec::new(),
            proofs: Vec::new(),
        });
        let mut proof = matching_proof(&base);
        proof.indices.push((99, [0xAB; 32]));
        let fields = fields_with_proof(proof);
        assert!(matches!(
            verify_field_binding(&fields),
            Err(AnnouncementError::FieldsUnbound(_))
        ));
    }

    #[test]
    fn ordering_announcement_digest_mismatch_rejected() {
        use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
        use ergo_primitives::group_element::GroupElement;
        use ergo_ser::autolykos::AutolykosSolution;
        use ergo_ser::header::Header;

        let header = Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0x11; 32]),
            ad_proofs_root: Digest32::from_bytes([0x22; 32]),
            transactions_root: Digest32::from_bytes([0x44; 32]),
            state_root: ADDigest::from_bytes([0x33; 33]),
            timestamp: 1_000_000_000,
            extension_root: Digest32::from_bytes([0x55; 32]),
            n_bits: 0x0200_E800,
            height: 47_262,
            votes: [0, 0, 0],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            },
        };
        let ann = OrderingBlockAnnouncement {
            version: 1,
            header,
            non_broadcasted_transactions: Vec::new(),
            broadcasted_transaction_ids: Vec::new(),
            extension_fields: vec![([0x03, 0x00], vec![0xAA; 32])],
            unparsed_bytes: Vec::new(),
        };
        assert_eq!(
            validate_ordering_announcement(&ann, None),
            Err(AnnouncementError::ProofInvalid)
        );
    }
}
