use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{serialize_header_without_pow, Header};
use num_bigint::BigUint;
use thiserror::Error;

use crate::autolykos::common::blake2b256;
use crate::autolykos::v1;
use crate::autolykos::v2;
use crate::difficulty::{get_target, verify_nbits, DifficultyParams};

/// Errors produced by the PoW-equation half of header verification.
#[derive(Debug, Error)]
pub enum PowError {
    /// The Autolykos equation rejected the solution (`v1` EC equation
    /// failed, or `v2` hit ≥ target). The contained string carries a
    /// short reason for telemetry.
    #[error("invalid PoW solution: {0}")]
    InvalidSolution(String),
    /// `serialize_header_without_pow` rejected the header before the
    /// PoW message bytes could be hashed (e.g. caller-supplied
    /// `unparsed_bytes` violates the Scala wire format). Treated as
    /// an InvalidSolution-class failure for chain-acceptance — a
    /// header we cannot serialize cannot have a valid PoW commitment.
    #[error("header bytes-without-pow serialize: {0}")]
    HeaderEncode(String),
}

/// `getB(nBits) * multiplier` (Scala `checkInputBlockPoW`'s
/// `inputTarget = orderingTarget * parameters.subBlocksPerBlock`);
/// `multiplier` is the raw voted `subBlocksPerBlock` value, used as-is.
/// A non-positive multiplier (never legitimately voted, but the type
/// is a signed `i32` because Scala's `Parameters` table stores votes
/// as `Int`) collapses the target to zero rather than panicking on the
/// `as u32` cast.
pub fn input_block_target(n_bits: u32, multiplier: i32) -> BigUint {
    if multiplier <= 0 {
        return BigUint::ZERO;
    }
    get_target(n_bits) * BigUint::from(multiplier as u32)
}

/// Pure comparison: `hit < input_block_target(n_bits, multiplier)`.
/// Matches Scala `AutolykosPowScheme.checkInputBlockPoW`'s strict `<`
/// — the verifier's boundary. Scala's miner-side `checkNonces`
/// classifies a solution as an input block under `hit <= target`
/// instead (see `AutolykosPowScheme.scala:429-434`); a `hit` exactly
/// equal to the target is therefore a solution the miner believes
/// qualifies but the verifier rejects (upstream finding F2), which is
/// why this function stays deliberately strict rather than folding in
/// the miner's `<=` — softening it here would silently paper over F2
/// instead of surfacing it.
pub fn input_block_hit_valid(hit: &BigUint, n_bits: u32, multiplier: i32) -> bool {
    *hit < input_block_target(n_bits, multiplier)
}

/// Hit of a v2 header: `hit_for_v2(blake2b256(bytes_without_pow), nonce,
/// height, calc_n(version, height))`. Mirrors Scala
/// `AutolykosPowScheme.hitForVersion2` (`AutolykosPowScheme.scala:182-192`).
///
/// Returns `Err(PowError::InvalidSolution)` for a v1 solution — input
/// blocks require an Autolykos v2 header, and v1's `d` isn't a hit at
/// all (it's the EC-equation blinding factor), so there is no
/// meaningful hit to compute.
pub fn header_hit_v2(header: &Header) -> Result<BigUint, PowError> {
    let nonce = match &header.solution {
        AutolykosSolution::V2 { nonce, .. } => nonce,
        AutolykosSolution::V1 { .. } => {
            return Err(PowError::InvalidSolution(
                "input blocks require an Autolykos v2 solution".into(),
            ))
        }
    };
    let bytes =
        serialize_header_without_pow(header).map_err(|e| PowError::HeaderEncode(e.to_string()))?;
    let msg = blake2b256(&bytes);
    let n = crate::autolykos::common::calc_n(header.version, header.height);
    Ok(v2::hit_for_v2(&msg, nonce, header.height, n))
}

/// Verify a header's PoW against the input-block target: Scala
/// `AutolykosPowScheme.checkInputBlockPoW` (`AutolykosPowScheme.scala:130-136`),
/// `hit < getB(nBits) * multiplier` (strict).
pub fn verify_input_block_pow(header: &Header, multiplier: i32) -> Result<(), PowError> {
    let hit = header_hit_v2(header)?;
    if input_block_hit_valid(&hit, header.n_bits, multiplier) {
        Ok(())
    } else {
        Err(PowError::InvalidSolution(
            "v2 hit >= input-block target".into(),
        ))
    }
}

/// Verify the Autolykos PoW solution against the header's own nBits target.
/// Dispatches to v1 or v2 based on the `header.solution` variant — the
/// header serializer couples `header.version` to the solution variant at
/// parse time, so this is byte-equivalent to Scala's
/// `AutolykosPowScheme.validate` (`AutolykosPowScheme.scala:104-111`)
/// which dispatches on `header.version`.
///
/// Does NOT verify that `nBits` itself is correct — that requires chain
/// context, see [`verify_header_difficulty`]. Does NOT enforce
/// version-by-height: Scala's `HeaderValidator`
/// (`HeadersProcessor.scala:418-430`) has no such check and accepts any
/// `header.version`/`header.height` pairing whose PoW equation holds, so
/// rejecting more here would be the chain-split direction.
pub fn verify_pow_solution(header: &Header) -> Result<(), PowError> {
    let target = get_target(header.n_bits);
    if target == BigUint::ZERO {
        return Err(PowError::InvalidSolution("zero target from nBits".into()));
    }

    // msg = Blake2b256(header_bytes_without_pow)
    let header_bytes =
        serialize_header_without_pow(header).map_err(|e| PowError::HeaderEncode(e.to_string()))?;
    let msg = blake2b256(&header_bytes);

    match &header.solution {
        AutolykosSolution::V1 { pk, w, nonce, d } => {
            if !v1::check_pow_v1(&msg, nonce, pk.as_bytes(), w.as_bytes(), d, &target) {
                return Err(PowError::InvalidSolution("v1 PoW equation failed".into()));
            }
        }
        AutolykosSolution::V2 { pk: _, nonce } => {
            if !v2::check_pow_v2(&msg, nonce, header.height, header.version, &target) {
                return Err(PowError::InvalidSolution("v2 PoW hit >= target".into()));
            }
        }
    }

    Ok(())
}

/// Errors produced by the difficulty-recalculation half of header
/// verification.
#[derive(Debug, Error)]
pub enum DifficultyError {
    /// Header's `nBits` does not equal the value derived from the
    /// supplied epoch headers under the active `DifficultyParams`.
    #[error("nBits mismatch at height {height}: expected {expected:#010x}, got {actual:#010x}")]
    NbitsMismatch {
        /// Height of the offending header.
        height: u32,
        /// `nBits` value the difficulty math required.
        expected: u32,
        /// `nBits` value the header actually carried.
        actual: u32,
    },

    /// Header's `height` is not exactly `parent.height + 1`.
    #[error("height mismatch: expected parent.height+1={expected}, got {actual}")]
    HeightMismatch {
        /// Required height (`parent.height + 1`).
        expected: u32,
        /// Height the header carried.
        actual: u32,
    },

    /// Caller did not supply enough headers for the active recalculation
    /// branch. Empty slice always errors here; an EIP-37 recalculation
    /// height additionally requires at least the parent and the previous
    /// epoch boundary (`epoch_headers.len() >= 2`).
    #[error("missing epoch headers for difficulty recalculation")]
    MissingEpochHeaders,
}

/// Verify that a header's nBits matches the expected difficulty derived
/// from ancestor epoch headers under the supplied [`DifficultyParams`]. Also
/// checks `height == parent.height + 1` and that the supplied window is
/// large enough for the active recalculation branch.
///
/// `epoch_headers`: the headers at epoch boundary heights needed for
/// recalculation. The last element must be the parent header.
pub fn verify_header_difficulty(
    header: &Header,
    epoch_headers: &[Header],
    config: &DifficultyParams,
) -> Result<(), DifficultyError> {
    verify_nbits(header.height, epoch_headers, header.n_bits, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn load_header_at(path: &str, height: u32) -> Header {
        let data = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let headers: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap();
        let h = headers
            .iter()
            .find(|h| h["height"].as_u64().unwrap() == u64::from(height))
            .unwrap_or_else(|| panic!("no header at height {height} in {path}"));
        let header_bytes = hex::decode(h["bytes"].as_str().unwrap()).unwrap();
        let mut r = ergo_primitives::reader::VlqReader::new(&header_bytes);
        ergo_ser::header::read_header(&mut r).unwrap()
    }

    // ----- happy path -----

    #[test]
    fn input_block_target_zero_or_negative_multiplier_is_zero() {
        assert_eq!(input_block_target(0x1a_01_76_5e, 0), BigUint::ZERO);
        assert_eq!(input_block_target(0x1a_01_76_5e, -5), BigUint::ZERO);
    }

    /// Task 11 relies on this test existing: with a target of 1 (the
    /// widest possible `nBits`) and the maximum representable
    /// multiplier, `input_block_target` overflows past any realistic
    /// hit — pinning that `input_block_hit_valid` stays permissive
    /// rather than silently saturating/wrapping at extreme votes.
    #[test]
    fn max_multiplier_makes_any_v2_header_pass_pow() {
        let n_bits = ergo_ser::difficulty::encode_compact_bits(&BigUint::from(1u32));
        assert!(input_block_hit_valid(
            &(BigUint::from(1u8) << 255),
            n_bits,
            i32::MAX
        ));
    }

    // ----- error paths -----

    #[test]
    fn header_hit_v2_rejects_v1_solution() {
        let header = load_header_at("../test-vectors/mainnet/headers_1_2000.json", 200);
        assert_eq!(header.version, 1, "height 200 should be v1 on mainnet");
        match header_hit_v2(&header) {
            Err(PowError::InvalidSolution(_)) => {}
            other => panic!("expected InvalidSolution for a v1 header, got {other:?}"),
        }
    }

    #[test]
    fn verify_header_difficulty_empty_epoch_headers_returns_missing() {
        let header = load_header_at("../test-vectors/mainnet/headers_1_2000.json", 100);
        let cfg = DifficultyParams::mainnet();
        match verify_header_difficulty(&header, &[], &cfg) {
            Err(DifficultyError::MissingEpochHeaders) => {}
            other => panic!("expected MissingEpochHeaders, got {other:?}"),
        }
    }

    #[test]
    fn verify_header_difficulty_height_mismatch_returns_height_mismatch() {
        let parent = load_header_at("../test-vectors/mainnet/headers_1_2000.json", 100);
        let child = load_header_at("../test-vectors/mainnet/headers_1_2000.json", 105);
        assert_ne!(child.height, parent.height + 1);
        let cfg = DifficultyParams::mainnet();

        match verify_header_difficulty(&child, std::slice::from_ref(&parent), &cfg) {
            Err(DifficultyError::HeightMismatch { expected, actual }) => {
                assert_eq!(expected, parent.height + 1);
                assert_eq!(actual, child.height);
            }
            other => panic!("expected HeightMismatch, got {other:?}"),
        }
    }

    // ----- oracle parity -----

    /// Pins the Scala-parity rule: `verify_pow_solution` does not enforce
    /// version-by-height. Scala's `AutolykosPowScheme.validate`
    /// (`reference/ergo/.../AutolykosPowScheme.scala:104-111`) dispatches
    /// purely on `header.version`, and `HeaderValidator.validateChildBlockHeader`
    /// (`reference/ergo/.../HeadersProcessor.scala:418-430`) has no
    /// version-vs-height check, so a v1 header is accepted at any
    /// height as long as its EC equation holds — including across
    /// what mainnet considers the v2 activation. Rejecting more here
    /// would be the chain-split direction.
    #[test]
    fn verify_pow_solution_accepts_real_v1_header_regardless_of_height() {
        let data = std::fs::read_to_string("../test-vectors/mainnet/headers_1_2000.json")
            .expect("need headers_1_2000.json for this test");
        let headers: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap();
        let h = headers
            .iter()
            .find(|h| h["height"].as_u64().unwrap() == 200)
            .unwrap();
        let header_bytes = hex::decode(h["bytes"].as_str().unwrap()).unwrap();
        let mut r = ergo_primitives::reader::VlqReader::new(&header_bytes);
        let header = ergo_ser::header::read_header(&mut r).unwrap();
        assert_eq!(header.height, 200);
        assert_eq!(header.version, 1, "height 200 should be v1 on mainnet");

        // Real mainnet v1 header passes — the EC equation holds regardless
        // of any "is this height supposed to be v1?" question.
        assert!(
            verify_pow_solution(&header).is_ok(),
            "real mainnet v1 header at h=200 must pass"
        );
    }
}
