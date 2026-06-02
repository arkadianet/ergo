//! Solution acceptance API-side pre-check (v12 §6 steps 1–4).
//!
//! The API handler:
//! 1. Looks the candidate up in the cache (by miner pk).
//! 2. Reconstructs the header with `solution = AutolykosV2 { pk, n }`.
//! 3. Runs the PoW pre-check: `hit_for_v2(msg, n, height, N) <= target`.
//! 4. Runs the parent-id pre-check: the cached candidate's parent must
//!    still equal `state.chain_state().best_full_block_id`.
//!
//! On success: returns a `SubmittedBlock` packaging everything the
//! `Action::SubmitMinedBlock` executor handler will need. The executor
//! re-runs the parent-id check inside the action-loop lock (the
//! consensus-bearing gate), then assembles and applies the block.
//!
//! The two parent-id checks aren't redundant. Step 4 fails the
//! obviously-stale case fast on the HTTP path without occupying the
//! action loop; step 6 (executor) is the authoritative TOCTOU close
//! since state can change between step 4 and pickup.

use ergo_crypto::autolykos::common::calc_n;
use ergo_crypto::autolykos::v2::hit_for_v2;
use ergo_crypto::difficulty::get_target;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::Header;
use ergo_ser::transaction::Transaction;
use ergo_state::store::StateStore;
use num_bigint::BigUint;

use crate::candidate::Candidate;
use crate::error::MiningError;
use crate::work_message::MinerSolution;

/// Outcome of [`verify_solution`]. Either ready to submit (everything
/// the executor needs is bundled here) or rejected with a precise
/// reason the API handler maps to HTTP status.
///
/// The `Accepted` variant is the larger one (carries `SubmittedBlock`)
/// and is also the hot mining path; boxing it to equalize variant sizes
/// would force an allocation on every successful solution and is not
/// worth the indirection.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum SolutionOutcome {
    /// Pre-checks passed. Submit via `Action::SubmitMinedBlock`. The
    /// executor will re-check `parent_id` under the action-loop lock.
    Accepted(SubmittedBlock),
    /// PoW hit > target. Returns 400.
    InvalidPow,
    /// Cached candidate's parent no longer equals the live best-full
    /// block id. Returns 400 "stale candidate (best-full flipped)".
    StaleParent {
        /// What the candidate was built against.
        candidate_parent: [u8; 32],
        /// What the chain currently has.
        live_parent: [u8; 32],
    },
}

/// Block ready for executor submission. Holds owned copies of every
/// section the executor needs to persist + apply.
#[derive(Debug, Clone)]
pub struct SubmittedBlock {
    /// Header with the real Autolykos v2 solution patched in.
    pub header: Header,
    /// Block transactions, in canonical order.
    pub transactions: Vec<Transaction>,
    /// Extension fields, already packed.
    pub extension_fields: Vec<(Vec<u8>, Vec<u8>)>,
    /// Raw AVL+ proof bytes; the executor wraps with the header id at
    /// section-encode time.
    pub ad_proof_bytes: Vec<u8>,
    /// Frozen parent_id. Carried alongside so the executor's
    /// authoritative recheck can compare against the same parent the
    /// candidate was built against (not, say, a fresher tip read).
    pub parent_id: [u8; 32],
}

/// Run the API-handler-side pre-checks against a cached candidate and
/// a posted solution JSON.
///
/// `state` is read-only here — we only need `chain_state` for the
/// parent_id pre-check.
pub fn verify_solution(
    candidate: &Candidate,
    solution: &MinerSolution,
    state: &StateStore,
) -> Result<SolutionOutcome, MiningError> {
    // Nonce + pk arrive already decoded (the node's mining bridge runs the
    // JSON hex-decode via `MinerSolution::from_hex` before calling), so this
    // path stays presentation-free.
    let nonce = solution.nonce;
    let pk_bytes: [u8; 33] = match solution.pk {
        Some(pk) => pk,
        // Solution omitted pk: use the miner's reward pk that the candidate
        // was built for. Matches Scala's `CandidateGenerator.scala:202-207`
        // "inject miner pubkey when accepting the solution" path.
        None => candidate.validation_ctx.pre_header.miner_pubkey,
    };
    let pow_solution = AutolykosSolution::V2 {
        pk: ergo_primitives::group_element::GroupElement::from(pk_bytes),
        nonce,
    };
    let mut header = candidate.header.clone();
    header.solution = pow_solution;

    // 3. PoW pre-check.
    let n = calc_n(header.version, header.height);
    let hit = hit_for_v2(&candidate.msg, &nonce, header.height, n);
    let target = get_target(header.n_bits);
    if hit > target {
        return Ok(SolutionOutcome::InvalidPow);
    }

    // 4. Parent-id pre-check (TOCTOU-prone fail-fast). The executor
    //    will re-check under its action-loop lock.
    let live_parent: [u8; 32] = state.chain_state().best_full_block_id;
    if live_parent != candidate.parent_id {
        return Ok(SolutionOutcome::StaleParent {
            candidate_parent: candidate.parent_id,
            live_parent,
        });
    }

    Ok(SolutionOutcome::Accepted(SubmittedBlock {
        header,
        transactions: candidate.transactions.clone(),
        extension_fields: candidate.extension_fields.clone(),
        ad_proof_bytes: candidate.ad_proof_bytes.clone(),
        parent_id: candidate.parent_id,
    }))
}

/// Equality on `target` derived from `n_bits`. Returns the encoded
/// numeric target. Useful for the candidate cache when comparing two
/// candidates at the same height with the same nBits (e.g., one was
/// built for h=N, the chain advances, a new one is built for h=N+1,
/// the old one is moved to `previous_candidate`).
pub fn target_for(n_bits: u32) -> BigUint {
    get_target(n_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::Digest32;

    fn dummy_candidate() -> Candidate {
        use ergo_primitives::digest::ADDigest;
        use ergo_ser::header::Header;
        use ergo_validation::pre_header::{
            build_last_block_utxo_root, CandidatePreHeader, CandidateValidationContext,
        };

        let placeholder_pk = [0x02u8; 33];
        let pre_header = CandidatePreHeader {
            version: 3,
            parent_id: [0xAAu8; 32],
            height: 1_786_189,
            timestamp: 1_700_000_000_000,
            n_bits: 0x1c00ffff,
            votes: [0u8; 3],
            miner_pubkey: placeholder_pk,
        };
        let last_block_utxo_root = build_last_block_utxo_root(ADDigest::from_bytes([0u8; 33]));
        // 10-header window: just use the same synthetic header repeated.
        let h = Header {
            version: 3,
            parent_id: Digest32::from_bytes([0xAAu8; 32]).into(),
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            state_root: ADDigest::from_bytes([0u8; 33]),
            timestamp: 1_700_000_000_000,
            extension_root: Digest32::from_bytes([0u8; 32]),
            n_bits: 0x1c00ffff,
            height: 1_786_188,
            votes: [0u8; 3],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                nonce: [0u8; 8],
            },
        };
        let last_headers: [Header; 10] = std::array::from_fn(|_| h.clone());

        let validation_ctx = CandidateValidationContext {
            pre_header: pre_header.clone(),
            activated_script_version: 2,
            last_headers,
            last_block_utxo_root,
        };
        Candidate {
            header: h.clone(),
            validation_ctx,
            transactions: Vec::new(),
            ad_proof_bytes: Vec::new(),
            extension_fields: Vec::new(),
            msg: [0u8; 32],
            target: get_target(0x1c00ffff),
            parent_id: [0xAAu8; 32],
        }
    }

    // ----- happy path -----

    #[test]
    fn pk_none_falls_back_to_candidate_miner_pubkey() {
        // pk omitted ⇒ verify_solution injects the candidate's miner pubkey
        // (Scala's accept-time inject). Exercise the fallback branch end to
        // end. The all-zero nonce can't satisfy the target, so the outcome is
        // InvalidPow (or StaleParent against the fresh store) — the point is
        // the None-pk path runs without panic.
        let candidate = dummy_candidate();
        let solution = MinerSolution {
            nonce: [0u8; 8],
            pk: None,
        };
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("state.redb")).unwrap();
        let outcome = verify_solution(&candidate, &solution, &state)
            .expect("typed solution cannot fail to decode");
        assert!(matches!(
            outcome,
            SolutionOutcome::InvalidPow | SolutionOutcome::StaleParent { .. }
        ));
    }

    #[test]
    fn from_hex_nonce_8_byte_length_required() {
        let err = MinerSolution::from_hex("00", Some(&hex::encode([0x02u8; 33])))
            .expect_err("1-byte nonce must err");
        match err {
            MiningError::WrongLength {
                field,
                expected,
                got,
            } => {
                assert_eq!(field, "nonce");
                assert_eq!(expected, 8);
                assert_eq!(got, 1);
            }
            other => panic!("expected WrongLength {{ field: \"nonce\", .. }}, got {other:?}"),
        }
    }

    #[test]
    fn from_hex_nonce_invalid_hex_returns_hex_decode_variant() {
        let err = MinerSolution::from_hex(&"ZZ".repeat(8), Some(&hex::encode([0x02u8; 33])))
            .expect_err("non-hex nonce must err");
        match err {
            MiningError::HexDecode { field, .. } => assert_eq!(field, "nonce"),
            other => panic!("expected HexDecode {{ field: \"nonce\", .. }}, got {other:?}"),
        }
    }

    #[test]
    fn from_hex_pk_invalid_hex_returns_hex_decode_variant() {
        let err = MinerSolution::from_hex(&hex::encode([0u8; 8]), Some(&"ZZ".repeat(33)))
            .expect_err("non-hex pk must err");
        match err {
            MiningError::HexDecode { field, .. } => assert_eq!(field, "pk"),
            other => panic!("expected HexDecode {{ field: \"pk\", .. }}, got {other:?}"),
        }
    }

    #[test]
    fn from_hex_pk_33_byte_length_required() {
        let err = MinerSolution::from_hex(&hex::encode([0u8; 8]), Some("aa"))
            .expect_err("1-byte pk must err");
        match err {
            MiningError::WrongLength {
                field,
                expected,
                got,
            } => {
                assert_eq!(field, "pk");
                assert_eq!(expected, 33);
                assert_eq!(got, 1);
            }
            other => panic!("expected WrongLength {{ field: \"pk\", .. }}, got {other:?}"),
        }
    }
}
