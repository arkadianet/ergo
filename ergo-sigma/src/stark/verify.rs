//! The FRI/STARK verify seam and the host-side orchestration that feeds it.
//!
//! [`prepare_verify_stark`] performs every non-FRI host step of the reference
//! `VerifyStark.eval` (@9372697) up to `runtime.verify`: profile match,
//! `contractId` derivation, `ErgoStatementV1` + claim reconstruction, raw-seal
//! transport decode, and the cheap `programId`/claim binding. On success it
//! hands the decoded seal words + expected claim to [`verify_raw_seal`] — the
//! single function PR-B (`ergo-stark`) implements. For PR-A that function is a
//! fail-closed stub, so nothing spoofable ships.

use ergo_primitives::digest::blake2b256;

use super::{raw_seal, statement, DIGEST_BYTES, MAX_APPLICATION_PAYLOAD_BYTES, STOCK_PROFILE_ID};

/// Immutable verifier-profile handle passed to the FRI core. For PR-A this is
/// the single stock profile; PR-B may thread the manifest-loaded control roots
/// / FRI parameters through it. Kept opaque so the opcode ↔ verifier seam is
/// stable across the PR boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockProfile;

/// **The FRI/STARK verify seam**, now wired to the `ergo-stark` verifier. Verify
/// the decoded raw succinct seal against the host-derived expected RISC0
/// `ReceiptClaim` under the stock profile.
///
/// * `seal_words` — the 55,667 canonical wire words from [`raw_seal::decode`].
/// * `expected_claim` — the SHA-256 tagged-struct `ReceiptClaim` digest from
///   [`statement::build`] (binds `programId`, `chainDomainId`, `profileId`,
///   `contractId`, and the `applicationPayload`).
///
/// Fail-closed: any claim mismatch, malformed seal, control-root mismatch, or
/// FRI failure returns `false` and never panics. `ergo-stark` loads the single
/// stock profile internally (fail-closed on a load error), so the opaque
/// [`StockProfile`] handle carries no state — it stays only to keep the opcode ↔
/// verifier seam signature frozen across the PR boundary.
pub fn verify_raw_seal(
    seal_words: &[u32],
    expected_claim: &[u8; DIGEST_BYTES],
    _profile: StockProfile,
) -> bool {
    ergo_stark::verify_stock_profile_seal(seal_words, expected_claim)
}

/// Outcome of the host-side preparation that precedes the FRI verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparedVerify {
    /// A profile, payload, chunk, transport, or `programId`/claim-binding check
    /// failed. The opcode returns `Bool(false)` WITHOUT invoking the verifier —
    /// this is the "false before proof work" fast path.
    Reject,
    /// Every host-side check passed; the decoded seal and expected claim are
    /// ready for [`verify_raw_seal`].
    Ready {
        words: Vec<u32>,
        expected_claim: [u8; DIGEST_BYTES],
    },
}

/// Host-side reconstruction + transport decode + claim binding, mirroring
/// `VerifyStark.eval` up to (but not including) `runtime.verify`. The caller
/// (the opcode) has already evaluated the four children and charged the two
/// upfront fixed costs; this function owns everything spoof-resistant:
///
/// * `chain_domain_id` — the host capability (never a script child).
/// * `contract_id = BLAKE2b-256(self_proposition_bytes)`.
/// * the `profileId` match, `programId`/payload length gates, and the
///   `expectedClaim == decoded-seal claim` binding.
pub fn prepare_verify_stark(
    profile_id: &[u8],
    program_id: &[u8],
    application_payload: &[u8],
    chunks: &[&[u8]],
    self_proposition_bytes: &[u8],
    chain_domain_id: &[u8; DIGEST_BYTES],
) -> PreparedVerify {
    // profileId selects the immutable profile. A wrong length or a non-stock id
    // is a soft reject (reference: length gate + `snapshot.lookup` → None).
    if profile_id != STOCK_PROFILE_ID.as_slice() {
        return PreparedVerify::Reject;
    }
    let profile_id_arr = STOCK_PROFILE_ID;

    // programId must be a 32-byte digest.
    let program_id_arr: [u8; DIGEST_BYTES] = match program_id.try_into() {
        Ok(a) => a,
        Err(_) => return PreparedVerify::Reject,
    };

    // Payload must fit the profile-owned maximum (reference: `>
    // maxApplicationPayloadBytes` → false).
    if application_payload.len() > MAX_APPLICATION_PAYLOAD_BYTES {
        return PreparedVerify::Reject;
    }

    // contractId is host-derived from SELF; never a script child.
    let mut contract_id = [0u8; DIGEST_BYTES];
    contract_id.copy_from_slice(blake2b256(self_proposition_bytes).as_bytes());

    // Reconstruct the exact statement and its expected OK ReceiptClaim.
    let binding = statement::build(
        chain_domain_id,
        &profile_id_arr,
        &program_id_arr,
        &contract_id,
        application_payload,
    );

    // Decode the fixed four-chunk raw seal (fail-closed on any shape/content
    // violation — this also re-validates the chunk partition).
    let decoded = match raw_seal::decode(chunks) {
        Ok(d) => d,
        Err(_) => return PreparedVerify::Reject,
    };

    // Bind programId + statement to the proof: the seal's own decoded claim must
    // equal the host-derived expectedClaim. A wrong programId changes the claim,
    // so this single comparison enforces `programId == proof imageId` and the
    // statement binding — cheaply, before any FRI work.
    if decoded.claim_digest != binding.claim.expected_claim {
        return PreparedVerify::Reject;
    }

    PreparedVerify::Ready {
        words: decoded.words,
        expected_claim: binding.claim.expected_claim,
    }
}

#[cfg(test)]
mod tests {
    use super::super::{babybear, raw_seal};
    use super::*;

    // ----- helpers -----

    /// Synthesize a raw seal whose decoded claim digest equals `claim`. The FRI
    /// content is otherwise zero — valid only for the transport/claim stage,
    /// which is all `prepare_verify_stark` exercises (the FRI verify is stubbed).
    fn seal_for_claim(claim: &[u8; 32]) -> Vec<Vec<u8>> {
        let mut words = vec![0u32; raw_seal::WORD_COUNT];
        words[32] = raw_seal::EXPECTED_OUTER_PO2;
        for i in 0..16 {
            let halfword = u16::from_le_bytes(claim[i * 2..i * 2 + 2].try_into().unwrap());
            words[16 + i] = babybear::to_raw(halfword as u32);
        }
        let mut bytes = Vec::with_capacity(raw_seal::BYTE_COUNT);
        for w in &words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let mut chunks = Vec::new();
        let mut offset = 0usize;
        for &len in &raw_seal::CANONICAL_CHUNK_LENGTHS {
            chunks.push(bytes[offset..offset + len].to_vec());
            offset += len;
        }
        chunks
    }

    fn refs(chunks: &[Vec<u8>]) -> Vec<&[u8]> {
        chunks.iter().map(|c| c.as_slice()).collect()
    }

    const PROGRAM: [u8; 32] = [0x11u8; 32];
    const CHAIN: [u8; 32] = [0x22u8; 32];
    const SELF_PROP: &[u8] = b"self-proposition-bytes";
    const PAYLOAD: &[u8] = b"aegis-application-payload";

    /// The expected claim the opcode derives for the fixed happy-path inputs.
    fn happy_expected_claim() -> [u8; 32] {
        let mut contract = [0u8; 32];
        contract.copy_from_slice(blake2b256(SELF_PROP).as_bytes());
        statement::build(&CHAIN, &STOCK_PROFILE_ID, &PROGRAM, &contract, PAYLOAD)
            .claim
            .expected_claim
    }

    // ----- happy path (reaches the verify seam) -----

    #[test]
    fn well_formed_inputs_reach_the_verify_seam() {
        let claim = happy_expected_claim();
        let chunks = seal_for_claim(&claim);
        let prepared = prepare_verify_stark(
            &STOCK_PROFILE_ID,
            &PROGRAM,
            PAYLOAD,
            &refs(&chunks),
            SELF_PROP,
            &CHAIN,
        );
        match prepared {
            PreparedVerify::Ready {
                expected_claim,
                words,
            } => {
                assert_eq!(expected_claim, claim);
                assert_eq!(words.len(), raw_seal::WORD_COUNT);
                // The seam reaches the wired verifier; a zero-content seal is not
                // a valid proof, so it is rejected (fail-closed).
                assert!(!verify_raw_seal(&words, &expected_claim, StockProfile));
            }
            PreparedVerify::Reject => panic!("well-formed happy path must reach the verify seam"),
        }
    }

    // ----- error paths (false before proof work) -----

    #[test]
    fn wrong_profile_id_rejects() {
        let claim = happy_expected_claim();
        let chunks = seal_for_claim(&claim);
        let mut wrong = STOCK_PROFILE_ID;
        wrong[0] ^= 1;
        assert_eq!(
            prepare_verify_stark(&wrong, &PROGRAM, PAYLOAD, &refs(&chunks), SELF_PROP, &CHAIN),
            PreparedVerify::Reject
        );
    }

    #[test]
    fn program_id_mismatch_rejects_via_claim_binding() {
        // The seal encodes the claim for PROGRAM, but the opcode is asked to
        // verify a different programId -> derived claim differs -> reject.
        let claim = happy_expected_claim();
        let chunks = seal_for_claim(&claim);
        let mut other_program = PROGRAM;
        other_program[0] ^= 1;
        assert_eq!(
            prepare_verify_stark(
                &STOCK_PROFILE_ID,
                &other_program,
                PAYLOAD,
                &refs(&chunks),
                SELF_PROP,
                &CHAIN
            ),
            PreparedVerify::Reject
        );
    }

    #[test]
    fn claim_mismatch_from_tampered_seal_rejects() {
        let claim = happy_expected_claim();
        let mut chunks = seal_for_claim(&claim);
        // Flip a claim-halfword word (word 16) -> decoded claim no longer matches.
        chunks[0][16 * 4] ^= 0x01;
        assert_eq!(
            prepare_verify_stark(
                &STOCK_PROFILE_ID,
                &PROGRAM,
                PAYLOAD,
                &refs(&chunks),
                SELF_PROP,
                &CHAIN
            ),
            PreparedVerify::Reject
        );
    }

    #[test]
    fn oversized_payload_rejects() {
        let claim = happy_expected_claim();
        let chunks = seal_for_claim(&claim);
        let payload = vec![0u8; MAX_APPLICATION_PAYLOAD_BYTES + 1];
        assert_eq!(
            prepare_verify_stark(
                &STOCK_PROFILE_ID,
                &PROGRAM,
                &payload,
                &refs(&chunks),
                SELF_PROP,
                &CHAIN
            ),
            PreparedVerify::Reject
        );
    }

    #[test]
    fn malformed_chunks_reject() {
        let short = [vec![0u8; 10], vec![0u8; 10], vec![0u8; 10], vec![0u8; 10]];
        assert_eq!(
            prepare_verify_stark(
                &STOCK_PROFILE_ID,
                &PROGRAM,
                PAYLOAD,
                &refs(&short),
                SELF_PROP,
                &CHAIN
            ),
            PreparedVerify::Reject
        );
    }

    #[test]
    fn verifier_is_fail_closed_on_degenerate_input() {
        // A too-short, all-zero seal is not a valid proof: the wired verifier
        // rejects it without panicking.
        assert!(!verify_raw_seal(&[0u32; 4], &[0u8; 32], StockProfile));
    }
}
