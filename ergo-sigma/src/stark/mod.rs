//! EIP-0045 `verifyStark` (0xB9) host-side profile logic — the non-FRI "shell"
//! of the native STARK verifier.
//!
//! This module reconstructs the host-authenticated `ErgoStatementV1` and its
//! RISC0 OK `ReceiptClaim`, decodes the fixed four-chunk raw succinct seal, and
//! hands the decoded words + expected claim to [`verify::verify_raw_seal`] — the
//! single seam the FRI/STARK verifier core (`ergo-stark`, PR-B) drops into.
//! Everything here is consensus-critical and byte-exact against sigmastate
//! @9372697 (`sigma.stark.profile.{Risc0ClaimBuilder, RawSealV1Decoder}`,
//! `sigma.stark.BabyBear`, `sigma.ast.VerifyStark`).
//!
//! Entry point for the opcode: [`verify::prepare_verify_stark`] →
//! [`verify::verify_raw_seal`].

pub mod babybear;
pub mod raw_seal;
pub mod statement;
pub mod verify;

/// Digest length shared by every profile-authenticated identity (chainDomainId,
/// profileId, programId, contractId) and every claim digest.
pub const DIGEST_BYTES: usize = 32;

/// Immutable stock verifier-profile id (EIP-0045 first / "B3" profile). FIXED
/// and chain-independent —
/// `BLAKE2b-256(ASCII("Ergo.StarkProfileId.v1") ‖ 0x00 ‖ u32le(458) ‖ manifest[458])`,
/// pinned upstream. `profileId` is the only script child that selects the
/// profile; a mismatch fails the opcode closed before any proof work.
pub const STOCK_PROFILE_ID: [u8; DIGEST_BYTES] = [
    0x23, 0xc4, 0xa1, 0x23, 0xff, 0xb3, 0x3a, 0x1c, 0x8d, 0xb8, 0x94, 0x36, 0xfe, 0x0e, 0x79, 0x72,
    0xbd, 0x8e, 0x4e, 0x28, 0x94, 0x59, 0xee, 0x5f, 0xd7, 0x1b, 0xe5, 0x44, 0x06, 0x07, 0xd3, 0x83,
];

/// Maximum `applicationPayload` length the stock profile accepts (bounding the
/// statement at 16,543 bytes). From the profile manifest
/// (`maxApplicationPayloadBytes`); enforced before statement construction.
pub const MAX_APPLICATION_PAYLOAD_BYTES: usize = 16_384;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stock_profile_id_matches_pinned_hex() {
        let hex = "23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383";
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(STOCK_PROFILE_ID.to_vec(), bytes);
    }
}
