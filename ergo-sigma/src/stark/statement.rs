//! Host-only reconstruction of the EIP-0045 `ErgoStatementV1` and its RISC0 OK
//! `ReceiptClaim` digest. Faithful port of sigmastate
//! `sigma.stark.profile.Risc0ClaimBuilder` (@9372697).
//!
//! No script value or caller-supplied claim participates: the opcode derives
//! `chainDomainId` (host capability), `contractId` (`BLAKE2b-256(SELF.
//! propositionBytes)`), and the profile-authenticated `profileId`, then binds
//! them with the script's `programId` + `applicationPayload` into the exact
//! 159-byte-prefixed statement and its SHA-256 tagged-struct claim.

use sha2::{Digest, Sha256};

use super::DIGEST_BYTES;

/// ASCII domain-separation tag, 26 bytes: `Ergo.VerifyStark.Statement`.
const STATEMENT_DOMAIN: &[u8; 26] = b"Ergo.VerifyStark.Statement";
/// Statement format version byte.
const STATEMENT_VERSION: u8 = 0x01;
/// Fixed statement prefix length: 26 + 1 + 32 + 32 + 32 + 32 + 4.
pub const STATEMENT_PREFIX_BYTES: usize = 159;

/// RISC0 tagged-struct tags.
const SYSTEM_STATE_TAG: &[u8] = b"risc0.SystemState";
const OUTPUT_TAG: &[u8] = b"risc0.Output";
const RECEIPT_CLAIM_TAG: &[u8] = b"risc0.ReceiptClaim";

/// The all-zero digest used as the `pre` state root and the (unused) assumptions
/// digest in an OK receipt claim.
const ZERO_DIGEST: [u8; DIGEST_BYTES] = [0u8; DIGEST_BYTES];

/// SHA-256 of `bytes`.
fn sha256(bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// The RISC0 OK `ReceiptClaim` chain derived from a `(programId, journal)` pair.
/// Every field is a SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimDigests {
    /// `SHA-256(journal)` — for the opcode, the journal is the whole statement.
    pub journal_digest: [u8; DIGEST_BYTES],
    /// `SystemState` post-state tagged-struct digest.
    pub post_digest: [u8; DIGEST_BYTES],
    /// `Output` tagged-struct digest binding the journal digest.
    pub output_digest: [u8; DIGEST_BYTES],
    /// `ReceiptClaim` tagged-struct digest binding `programId` (the guest image
    /// id) and the output — this is the value compared against the seal's own
    /// decoded claim digest.
    pub expected_claim: [u8; DIGEST_BYTES],
}

/// The complete host-derived binding: the exact statement bytes and their claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// Exact `ErgoStatementV1` bytes (159-byte prefix + payload).
    pub statement: Vec<u8>,
    /// The claim chain over `programId` and the statement (as journal).
    pub claim: ClaimDigests,
}

/// Build the exact `ErgoStatementV1` bytes:
///
/// `ASCII("Ergo.VerifyStark.Statement")(26) ‖ 0x01 ‖ chainDomainId(32) ‖`
/// `profileId(32) ‖ programId(32) ‖ contractId(32) ‖ u32le(payload.len) ‖`
/// `applicationPayload`.
pub fn encode_statement(
    chain_domain_id: &[u8; DIGEST_BYTES],
    profile_id: &[u8; DIGEST_BYTES],
    program_id: &[u8; DIGEST_BYTES],
    contract_id: &[u8; DIGEST_BYTES],
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(STATEMENT_PREFIX_BYTES + payload.len());
    out.extend_from_slice(STATEMENT_DOMAIN);
    out.push(STATEMENT_VERSION);
    out.extend_from_slice(chain_domain_id);
    out.extend_from_slice(profile_id);
    out.extend_from_slice(program_id);
    out.extend_from_slice(contract_id);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    debug_assert_eq!(out.len(), STATEMENT_PREFIX_BYTES + payload.len());
    out
}

/// RISC0 tagged-struct digest:
/// `SHA-256(SHA-256(tag) ‖ down* ‖ data:u32le* ‖ u16le(down.len))`.
/// There is deliberately no encoded data-count suffix.
fn tagged_struct_digest(
    tag: &[u8],
    down: &[[u8; DIGEST_BYTES]],
    data: &[u32],
) -> [u8; DIGEST_BYTES] {
    let mut preimage =
        Vec::with_capacity(DIGEST_BYTES + down.len() * DIGEST_BYTES + data.len() * 4 + 2);
    preimage.extend_from_slice(&sha256(tag));
    for d in down {
        preimage.extend_from_slice(d);
    }
    for &x in data {
        preimage.extend_from_slice(&x.to_le_bytes());
    }
    preimage.extend_from_slice(&(down.len() as u16).to_le_bytes());
    sha256(&preimage)
}

/// Derive the OK `ReceiptClaim` chain for `(programId, journal)`.
pub fn derive_ok_claim(program_id: &[u8; DIGEST_BYTES], journal: &[u8]) -> ClaimDigests {
    let journal_digest = sha256(journal);
    let post_digest = tagged_struct_digest(SYSTEM_STATE_TAG, &[ZERO_DIGEST], &[0]);
    let output_digest = tagged_struct_digest(OUTPUT_TAG, &[journal_digest, ZERO_DIGEST], &[]);
    let expected_claim = tagged_struct_digest(
        RECEIPT_CLAIM_TAG,
        &[ZERO_DIGEST, *program_id, post_digest, output_digest],
        &[0, 0],
    );
    ClaimDigests {
        journal_digest,
        post_digest,
        output_digest,
        expected_claim,
    }
}

/// Reconstruct the statement and its OK `ReceiptClaim`. The guest commits the
/// WHOLE statement, so the claim's journal is the statement bytes.
pub fn build(
    chain_domain_id: &[u8; DIGEST_BYTES],
    profile_id: &[u8; DIGEST_BYTES],
    program_id: &[u8; DIGEST_BYTES],
    contract_id: &[u8; DIGEST_BYTES],
    payload: &[u8],
) -> Binding {
    let statement = encode_statement(
        chain_domain_id,
        profile_id,
        program_id,
        contract_id,
        payload,
    );
    let claim = derive_ok_claim(program_id, &statement);
    Binding { statement, claim }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn d32(s: &str) -> [u8; 32] {
        hx(s).try_into().unwrap()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// One `ergo_statement_v1.json` vector: inputs + the reference-pinned
    /// expected statement / journal digest / claim chain.
    struct Vector {
        chain: &'static str,
        profile: &'static str,
        program: &'static str,
        contract: &'static str,
        payload: &'static str,
        statement: &'static str,
        statement_len: usize,
        journal_digest: &'static str,
        post: &'static str,
        output: &'static str,
        claim: &'static str,
    }

    // Vectors 1-4 of test-vectors/eip0045/ergo_statement_v1.json, pinned
    // byte-for-byte by the reference KAT (ErgoStarkStatementSpec.scala @9372697).
    const VECTORS: &[Vector] = &[
        Vector {
            chain: "0000000000000000000000000000000000000000000000000000000000000000",
            profile: "0000000000000000000000000000000000000000000000000000000000000000",
            program: "0000000000000000000000000000000000000000000000000000000000000000",
            contract: "0000000000000000000000000000000000000000000000000000000000000000",
            payload: "",
            statement: "4572676f2e566572696679537461726b2e53746174656d656e7401000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            statement_len: 159,
            journal_digest: "9b8899bb1fa709880a1d3ce2a5fb87b8c82d067c9ceaa3efd88eb99e37624f89",
            post: "a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2",
            output: "65071bef11ffec7f370df403257a4cfa56c265bafb6ca28b61b8f0b36a042a33",
            claim: "f2ac8e12159acd390c902931248b799f97376ee80b49735cea788122b0f99c5b",
        },
        Vector {
            chain: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            profile: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            program: "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            contract: "96f2898a7d4a18a164943804351e489c38af0f2f6cd897b31e73437fb26f0e7d",
            payload: "4549502d303034352073796e746865746963207061796c6f61643b206e6f6e2d66696e616c",
            statement: "4572676f2e566572696679537461726b2e53746174656d656e7401000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f96f2898a7d4a18a164943804351e489c38af0f2f6cd897b31e73437fb26f0e7d250000004549502d303034352073796e746865746963207061796c6f61643b206e6f6e2d66696e616c",
            statement_len: 196,
            journal_digest: "7d2c8dc514f5a929fe38a6be100e500b86d31e41bcf08846c71866f843155cf4",
            post: "a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2",
            output: "229a3e672940599f8ce4f2bd1a4bd2103dbfd28f4883cafa6b0c1524f4490894",
            claim: "fd71ff1ad9b73ef403ac1bbb919a509f67d33816ab0334c685785f0cf6b4bc9e",
        },
        Vector {
            chain: "b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b",
            profile: "23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383",
            program: "d82a9f903bdb2c7e68dcf15686cf75b3220fe457fa6bc1042529df288de222d8",
            contract: "d4fde033ba3d2d696696cb7d0e80abd39aa84db8ba93038157338e85aac6f5b8",
            payload: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            statement: "4572676f2e566572696679537461726b2e53746174656d656e7401b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383d82a9f903bdb2c7e68dcf15686cf75b3220fe457fa6bc1042529df288de222d8d4fde033ba3d2d696696cb7d0e80abd39aa84db8ba93038157338e85aac6f5b820000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            statement_len: 191,
            journal_digest: "ba80801e59c8bcd8ffff6eddcbbd91a43c36206539d217c7944edef81cd9c297",
            post: "a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2",
            output: "c5068190e04dd7d5a1bef489605f1bf3fad87148e65b97bf70d5693bbbc0658e",
            claim: "a88ae10e9e0bf2a3458becf3ff26b2ac617f1054a35d1b88e37f9f5a62c14415",
        },
        Vector {
            chain: "41454749532d4445564e45542d47454e455349532d49442d504c414345484c44",
            profile: "23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383",
            program: "d82a9f903bdb2c7e68dcf15686cf75b3220fe457fa6bc1042529df288de222d8",
            contract: "d4fde033ba3d2d696696cb7d0e80abd39aa84db8ba93038157338e85aac6f5b8",
            payload: "414547495350563111111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333344444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555666666666666666666666666666666666666666666666666666666666666666677777777777777777777777777777777777777777777777777777777777777770000000000000001000000003b9aca0000000000000000240008cdababababababababababababababababababababababababababababababababab",
            statement: "4572676f2e566572696679537461726b2e53746174656d656e740141454749532d4445564e45542d47454e455349532d49442d504c414345484c4423c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383d82a9f903bdb2c7e68dcf15686cf75b3220fe457fa6bc1042529df288de222d8d4fde033ba3d2d696696cb7d0e80abd39aa84db8ba93038157338e85aac6f5b824010000414547495350563111111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333344444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555666666666666666666666666666666666666666666666666666666666666666677777777777777777777777777777777777777777777777777777777777777770000000000000001000000003b9aca0000000000000000240008cdababababababababababababababababababababababababababababababababab",
            statement_len: 451,
            journal_digest: "21de7b4b7dfaf5eb5a1e9cf85691e6742b4b88cf4639a1dcb3d5568926c3fb9e",
            post: "a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2",
            output: "7a186bf4146d48e2a9e8ab92445874cede4612eb6dec0a4bf079d9198f7b4b6c",
            claim: "ea19e07a4bb14cbe6cf6423cd474ac1aa2eea00c79135dd9ded527757b05c8fb",
        },
    ];

    // ----- oracle parity -----

    #[test]
    fn statement_and_claim_match_reference_kat_vectors() {
        for (i, v) in VECTORS.iter().enumerate() {
            let binding = build(
                &d32(v.chain),
                &d32(v.profile),
                &d32(v.program),
                &d32(v.contract),
                &hx(v.payload),
            );
            assert_eq!(binding.statement.len(), v.statement_len, "vector {i} len");
            assert_eq!(hex(&binding.statement), v.statement, "vector {i} statement");
            assert_eq!(
                hex(&binding.claim.journal_digest),
                v.journal_digest,
                "vector {i} journalDigest"
            );
            assert_eq!(hex(&binding.claim.post_digest), v.post, "vector {i} post");
            assert_eq!(
                hex(&binding.claim.output_digest),
                v.output,
                "vector {i} output"
            );
            assert_eq!(
                hex(&binding.claim.expected_claim),
                v.claim,
                "vector {i} claim"
            );
        }
    }

    #[test]
    fn statement_prefix_offsets_are_fixed() {
        let chain = d32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let profile = d32("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        let program = d32("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        let contract = d32("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f");
        let payload = vec![0xAAu8; 258];
        let s = encode_statement(&chain, &profile, &program, &contract, &payload);
        assert_eq!(&s[0..26], STATEMENT_DOMAIN);
        assert_eq!(s[26], 0x01);
        assert_eq!(&s[27..59], &chain);
        assert_eq!(&s[59..91], &profile);
        assert_eq!(&s[91..123], &program);
        assert_eq!(&s[123..155], &contract);
        // 258 = 0x0102 -> LE 02 01 00 00
        assert_eq!(&s[155..159], &[0x02, 0x01, 0x00, 0x00]);
        assert_eq!(&s[159..], &payload[..]);
    }

    #[test]
    fn claim_chain_matches_reference_unframed_journal_kat() {
        // ErgoStarkStatementSpec.scala:25-38 — deriveOkClaim over a raw journal.
        let digests = derive_ok_claim(
            &d32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            b"EIP-0045 independent claim oracle KAT",
        );
        assert_eq!(
            hex(&digests.journal_digest),
            "67261f6e1ed8c95ccb856bab6331a9a3ea4bb16ba53d1993a2840b0a2f5dfb25"
        );
        assert_eq!(
            hex(&digests.post_digest),
            "a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2"
        );
        assert_eq!(
            hex(&digests.output_digest),
            "63b627d856c66a3a8ed83ba5e1f28b172234e1c7b15d3370977bf157019d38f2"
        );
        assert_eq!(
            hex(&digests.expected_claim),
            "14fd85f19032d53ce5ae85f10dab8c6c3f12ae9e11a9c6b778e26cd751170e16"
        );
    }

    #[test]
    fn claim_chain_matches_independent_binary_fixture() {
        // eip0045-arkadia-independent: deriveOkClaim(image-id, journal) must
        // equal the real receipt's decoded claim digest (claim-digest.bin).
        let image_id = include_bytes!("../../test-vectors/eip0045/image-id-arkadia.bin");
        let journal = include_bytes!("../../test-vectors/eip0045/journal-arkadia.bin");
        let expected = include_bytes!("../../test-vectors/eip0045/claim-digest-arkadia.bin");
        let digests = derive_ok_claim(image_id, journal);
        assert_eq!(&digests.expected_claim, expected);
    }
}
