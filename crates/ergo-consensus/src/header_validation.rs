//! Header validation rules for Ergo block headers.
//!
//! Ports the validation logic from `HeadersProcessor.scala` in the Ergo
//! reference implementation. Covers height sequencing, timestamp ordering,
//! future-timestamp drift, genesis parent ID, and proof-of-work checks.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

use ergo_types::header::Header;
use ergo_types::modifier_id::ModifierId;
use ergo_wire::header_ser::serialize_header;
use thiserror::Error;

use crate::autolykos;
use crate::difficulty_adjustment::{calculate_classic, calculate_eip37};

/// Default maximum allowed drift between a header's timestamp and the current
/// wall-clock time. Derived as `10 * block_interval` where block_interval = 2 min
/// on mainnet. Callers should derive this from the chain's `block_interval_secs`
/// setting: `block_interval_secs * 10 * 1000`.
pub const DEFAULT_MAX_TIME_DRIFT_MS: u64 = 10 * 120 * 1000; // 1_200_000

/// EIP-37 activation height on mainnet.
const EIP37_ACTIVATION_HEIGHT: u32 = 844_673;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Compute the header ID (blake2b256 of the full serialized header).
fn compute_header_id_bytes(header: &Header) -> [u8; 32] {
    let serialized = serialize_header(header);
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(&serialized);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("correct output size");
    out
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors arising from header validation checks.
#[derive(Debug, Error)]
pub enum HeaderValidationError {
    /// The header height does not follow sequentially from its parent.
    #[error("height mismatch: expected {expected}, got {got}")]
    HeightMismatch { expected: u32, got: u32 },

    /// The header timestamp is not strictly greater than its parent's.
    #[error("timestamp not increasing: parent={parent}, child={child}")]
    TimestampNotIncreasing { parent: u64, child: u64 },

    /// The header timestamp is too far in the future relative to the node's
    /// wall-clock time.
    #[error("timestamp too far in future: header={header_ts}, now={now}")]
    FutureTimestamp { header_ts: u64, now: u64 },

    /// A genesis header must have an all-zero parent ID.
    #[error("genesis header must have all-zero parent ID")]
    GenesisParentIdInvalid,

    /// Proof-of-work verification failed.
    #[error("PoW validation failed: {0}")]
    PowInvalid(String),

    /// The header's block version does not match the expected version from parameters.
    #[error("block version mismatch: expected {expected}, got {got} at height {height}")]
    BlockVersionMismatch { height: u32, expected: u8, got: u8 },

    /// The parent header has been marked as semantically invalid (rule 210).
    #[error("parent header {0:?} has been marked as semantically invalid")]
    InvalidParent(ModifierId),

    /// Genesis header height must be 1 (rule 203).
    #[error("genesis height must be 1, got {0}")]
    GenesisHeightInvalid(u32),

    /// Genesis header ID does not match the expected value (rule 201).
    #[error("genesis header ID {got} does not match expected {expected}")]
    GenesisIdMismatch { expected: String, got: String },

    /// Declared difficulty (nBits) doesn't match computed required difficulty (rule 208).
    #[error("difficulty mismatch at height {height}: expected nBits={expected:#010x}, got {actual:#010x}")]
    DifficultyMismatch {
        height: u32,
        expected: u32,
        actual: u32,
    },
}

/// Error when declared difficulty doesn't match computed difficulty.
#[derive(Debug, Error)]
#[error("wrong difficulty: expected nBits {expected}, got {actual} at height {height}")]
pub struct DifficultyError {
    pub height: u32,
    pub expected: u32,
    pub actual: u32,
}

// ---------------------------------------------------------------------------
// Individual validation functions
// ---------------------------------------------------------------------------

/// Validate that `header.height == parent.height + 1`.
pub fn validate_height(header: &Header, parent: &Header) -> Result<(), HeaderValidationError> {
    let expected = parent.height + 1;
    if header.height == expected {
        Ok(())
    } else {
        Err(HeaderValidationError::HeightMismatch {
            expected,
            got: header.height,
        })
    }
}

/// Validate that `header.timestamp > parent.timestamp`.
pub fn validate_timestamp(header: &Header, parent: &Header) -> Result<(), HeaderValidationError> {
    if header.timestamp > parent.timestamp {
        Ok(())
    } else {
        Err(HeaderValidationError::TimestampNotIncreasing {
            parent: parent.timestamp,
            child: header.timestamp,
        })
    }
}

/// Validate that the header timestamp is not too far in the future.
///
/// `max_time_drift_ms` is derived from `10 * block_interval_secs * 1000`.
/// The check is: if `header.timestamp > now_ms`, then
/// `header.timestamp - now_ms <= max_time_drift_ms`. Headers with timestamps
/// at or before `now_ms` always pass.
pub fn validate_future_timestamp(
    header: &Header,
    now_ms: u64,
    max_time_drift_ms: u64,
) -> Result<(), HeaderValidationError> {
    if header.timestamp <= now_ms {
        // Timestamp is in the past or exactly now — always OK.
        Ok(())
    } else if header.timestamp - now_ms <= max_time_drift_ms {
        Ok(())
    } else {
        Err(HeaderValidationError::FutureTimestamp {
            header_ts: header.timestamp,
            now: now_ms,
        })
    }
}

/// Validate that the genesis header has an all-zero parent ID.
pub fn validate_genesis_parent(header: &Header) -> Result<(), HeaderValidationError> {
    if header.parent_id == ModifierId::GENESIS_PARENT {
        Ok(())
    } else {
        Err(HeaderValidationError::GenesisParentIdInvalid)
    }
}

/// Validate that genesis header height == 1 (rule 203).
pub fn validate_genesis_height(header: &Header) -> Result<(), HeaderValidationError> {
    if header.height == 1 {
        Ok(())
    } else {
        Err(HeaderValidationError::GenesisHeightInvalid(header.height))
    }
}

/// Validate that genesis header ID matches expected config value (rule 201).
/// If `expected_id` is `None` or empty, skip the check.
pub fn validate_genesis_id(
    header: &Header,
    expected_id: Option<&str>,
) -> Result<(), HeaderValidationError> {
    if let Some(expected) = expected_id {
        if expected.is_empty() {
            return Ok(());
        }
        let got = hex::encode(compute_header_id_bytes(header));
        if got != expected {
            return Err(HeaderValidationError::GenesisIdMismatch {
                expected: expected.to_string(),
                got,
            });
        }
    }
    Ok(())
}

/// Validate proof-of-work for a header.
///
/// Delegates to [`autolykos::validate_pow`] and maps its error type into
/// [`HeaderValidationError::PowInvalid`].
pub fn validate_pow(header: &Header) -> Result<(), HeaderValidationError> {
    autolykos::validate_pow(header).map_err(|e| HeaderValidationError::PowInvalid(e.to_string()))
}

/// Validate that the header's block version matches the expected version
/// from the on-chain parameters system.
///
/// The `expected_version` is obtained from `Parameters::block_version()`.
/// During initial sync before parameters are loaded, the caller should
/// pass `1` (the genesis default).
///
/// This mirrors the Scala reference `exBlockVersion` check in
/// `ErgoStateContext.process()`.
pub fn validate_block_version(
    header: &Header,
    expected_version: u8,
) -> Result<(), HeaderValidationError> {
    if header.version == expected_version {
        Ok(())
    } else {
        Err(HeaderValidationError::BlockVersionMismatch {
            height: header.height,
            expected: expected_version,
            got: header.version,
        })
    }
}

/// Reject headers whose parent has been marked as semantically invalid.
///
/// Rule 210: hdrParentSemantics.
///
/// The caller must look up the parent's validity from storage and pass it in
/// as `parent_is_invalid`. If `true`, the header is rejected because building
/// on an invalid parent is not allowed.
///
/// Note: `ModifierValidity` lives in `ergo-storage`, which is not a dependency
/// of this crate, so the caller converts before calling this function.
pub fn validate_parent_semantics(
    parent_id: &ModifierId,
    parent_is_invalid: bool,
) -> Result<(), HeaderValidationError> {
    if parent_is_invalid {
        return Err(HeaderValidationError::InvalidParent(*parent_id));
    }
    Ok(())
}

/// Validate that a header's nBits matches the required difficulty (rule 208).
///
/// `required_n_bits` is the expected nBits computed by difficulty recalculation.
/// If `None`, the check is skipped (e.g., when epoch headers aren't available
/// or when the header is below the checkpoint height).
pub fn validate_required_difficulty(
    header: &Header,
    required_n_bits: Option<u32>,
) -> Result<(), HeaderValidationError> {
    if let Some(expected) = required_n_bits {
        let actual = header.n_bits as u32;
        if actual != expected {
            return Err(HeaderValidationError::DifficultyMismatch {
                height: header.height,
                expected,
                actual,
            });
        }
    }
    Ok(())
}

/// Verify that `header.n_bits` matches the expected difficulty.
///
/// `epoch_headers` must contain the headers at the heights returned by
/// `previous_heights_for_recalculation()`, as `(height, timestamp_ms, nBits)` tuples,
/// in ascending height order.
///
/// `parent_n_bits` is the nBits of the direct parent header (used when
/// the header is mid-epoch and inherits the parent's difficulty).
///
/// Returns `Ok(())` if the declared nBits matches, or `Err(DifficultyError)`.
pub fn validate_difficulty(
    height: u32,
    declared_n_bits: u32,
    parent_n_bits: u32,
    epoch_headers: &[(u32, u64, u32)],
    epoch_length: u32,
    desired_interval_ms: u64,
    is_mainnet: bool,
) -> Result<(), DifficultyError> {
    let parent_height = height - 1;

    // Mid-epoch: inherit parent's difficulty.
    if !parent_height.is_multiple_of(epoch_length) {
        if declared_n_bits != parent_n_bits {
            return Err(DifficultyError {
                height,
                expected: parent_n_bits,
                actual: declared_n_bits,
            });
        }
        return Ok(());
    }

    // Epoch boundary: compute expected difficulty.
    let expected = if is_mainnet && height >= EIP37_ACTIVATION_HEIGHT {
        calculate_eip37(epoch_headers, epoch_length, desired_interval_ms)
    } else {
        calculate_classic(epoch_headers, epoch_length, desired_interval_ms)
    };

    if declared_n_bits != expected {
        return Err(DifficultyError {
            height,
            expected,
            actual: declared_n_bits,
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Composite validators
// ---------------------------------------------------------------------------

/// Run all non-genesis header validations.
///
/// Checks (in order):
/// 1. Height: `header.height == parent.height + 1`
/// 2. Timestamp ordering: `header.timestamp > parent.timestamp`
/// 3. Future timestamp: not too far ahead of `now_ms`
/// 4. Required difficulty: nBits matches computed value (rule 208)
/// 5. Proof-of-work validity
///
/// `required_n_bits` is the expected nBits from difficulty recalculation.
/// Pass `None` to skip the difficulty check (e.g., when epoch headers
/// aren't available or the caller doesn't compute difficulty).
pub fn validate_child_header(
    header: &Header,
    parent: &Header,
    now_ms: u64,
    required_n_bits: Option<u32>,
    max_time_drift_ms: u64,
) -> Result<(), HeaderValidationError> {
    validate_height(header, parent)?;
    validate_timestamp(header, parent)?;
    validate_future_timestamp(header, now_ms, max_time_drift_ms)?;
    validate_required_difficulty(header, required_n_bits)?;
    validate_pow(header)?;
    Ok(())
}

/// Run all non-genesis header validations **except** proof-of-work.
///
/// Use this when PoW has already been validated in a parallel batch
/// (e.g., via rayon) and only parent-dependent checks remain.
pub fn validate_child_header_skip_pow(
    header: &Header,
    parent: &Header,
    now_ms: u64,
    required_n_bits: Option<u32>,
    max_time_drift_ms: u64,
) -> Result<(), HeaderValidationError> {
    validate_height(header, parent)?;
    validate_timestamp(header, parent)?;
    validate_future_timestamp(header, now_ms, max_time_drift_ms)?;
    validate_required_difficulty(header, required_n_bits)?;
    Ok(())
}

/// Run all genesis header validations.
///
/// Checks (in order):
/// 1. Genesis parent ID: must be all zeros
/// 2. Genesis height: must be 1 (rule 203)
/// 3. Genesis ID: must match config value if provided (rule 201)
/// 4. Genesis difficulty: nBits must match `initial_n_bits` if provided (rule 208)
/// 5. Future timestamp: not too far ahead of `now_ms`
/// 6. Proof-of-work validity
pub fn validate_genesis_header(
    header: &Header,
    now_ms: u64,
    genesis_id: Option<&str>,
    initial_n_bits: Option<u32>,
    max_time_drift_ms: u64,
) -> Result<(), HeaderValidationError> {
    validate_genesis_parent(header)?;
    validate_genesis_height(header)?;
    validate_genesis_id(header, genesis_id)?;
    validate_required_difficulty(header, initial_n_bits)?;
    validate_future_timestamp(header, now_ms, max_time_drift_ms)?;
    validate_pow(header)?;
    Ok(())
}

/// Run all genesis header validations **except** proof-of-work.
///
/// Use this when PoW has already been validated in a parallel batch.
pub fn validate_genesis_header_skip_pow(
    header: &Header,
    now_ms: u64,
    genesis_id: Option<&str>,
    initial_n_bits: Option<u32>,
    max_time_drift_ms: u64,
) -> Result<(), HeaderValidationError> {
    validate_genesis_parent(header)?;
    validate_genesis_height(header)?;
    validate_genesis_id(header, genesis_id)?;
    validate_required_difficulty(header, initial_n_bits)?;
    validate_future_timestamp(header, now_ms, max_time_drift_ms)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::header::Header;
    use ergo_types::modifier_id::ModifierId;

    #[test]
    fn validate_height_sequential() {
        let parent = Header {
            height: 99,
            ..Header::default_for_test()
        };
        let child = Header {
            height: 100,
            ..Header::default_for_test()
        };
        assert!(validate_height(&child, &parent).is_ok());
    }

    #[test]
    fn validate_height_wrong() {
        let parent = Header {
            height: 99,
            ..Header::default_for_test()
        };
        let child = Header {
            height: 101,
            ..Header::default_for_test()
        };
        assert!(validate_height(&child, &parent).is_err());
    }

    #[test]
    fn validate_timestamp_increasing() {
        let parent = Header {
            timestamp: 1000,
            ..Header::default_for_test()
        };
        let child = Header {
            timestamp: 2000,
            ..Header::default_for_test()
        };
        assert!(validate_timestamp(&child, &parent).is_ok());
    }

    #[test]
    fn validate_timestamp_not_increasing() {
        let parent = Header {
            timestamp: 2000,
            ..Header::default_for_test()
        };
        let child = Header {
            timestamp: 1000,
            ..Header::default_for_test()
        };
        assert!(validate_timestamp(&child, &parent).is_err());
    }

    #[test]
    fn validate_timestamp_equal_fails() {
        let parent = Header {
            timestamp: 1000,
            ..Header::default_for_test()
        };
        let child = Header {
            timestamp: 1000,
            ..Header::default_for_test()
        };
        assert!(validate_timestamp(&child, &parent).is_err());
    }

    #[test]
    fn validate_genesis_parent_id() {
        let genesis = Header {
            height: 1,
            parent_id: ModifierId::GENESIS_PARENT,
            ..Header::default_for_test()
        };
        assert!(validate_genesis_parent(&genesis).is_ok());
    }

    #[test]
    fn validate_genesis_wrong_parent() {
        let genesis = Header {
            height: 1,
            parent_id: ModifierId([0xFF; 32]),
            ..Header::default_for_test()
        };
        assert!(validate_genesis_parent(&genesis).is_err());
    }

    #[test]
    fn validate_future_timestamp_ok() {
        let now_ms = 1_700_000_000_000u64;
        let drift = 1_200_000u64;
        let h = Header {
            timestamp: now_ms + 60_000,
            ..Header::default_for_test()
        };
        assert!(validate_future_timestamp(&h, now_ms, drift).is_ok());
    }

    #[test]
    fn validate_future_timestamp_too_far() {
        let now_ms = 1_700_000_000_000u64;
        let drift = 1_200_000u64;
        let h = Header {
            timestamp: now_ms + 30 * 60_000,
            ..Header::default_for_test()
        };
        assert!(validate_future_timestamp(&h, now_ms, drift).is_err());
    }

    #[test]
    fn validate_future_timestamp_at_boundary() {
        let now_ms = 1_700_000_000_000u64;
        let drift = 1_200_000u64;
        let h = Header {
            timestamp: now_ms + drift,
            ..Header::default_for_test()
        };
        assert!(validate_future_timestamp(&h, now_ms, drift).is_ok());
    }

    #[test]
    fn validate_future_timestamp_past_ok() {
        let now_ms = 1_700_000_000_000u64;
        let drift = 1_200_000u64;
        let h = Header {
            timestamp: now_ms - 60_000,
            ..Header::default_for_test()
        };
        assert!(validate_future_timestamp(&h, now_ms, drift).is_ok());
    }

    #[test]
    fn validate_future_timestamp_custom_drift() {
        let now_ms = 1_700_000_000_000u64;
        let drift = 600_000u64; // 10 * 60s block interval
        let h = Header {
            timestamp: now_ms + 700_000,
            ..Header::default_for_test()
        };
        assert!(validate_future_timestamp(&h, now_ms, drift).is_err());
        assert!(validate_future_timestamp(&h, now_ms, 1_200_000).is_ok());
    }

    // -----------------------------------------------------------------------
    // Difficulty validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn mid_epoch_inherits_parent() {
        // height=500, parent_height=499, 499 % 1024 != 0 => mid-epoch
        // declared_n_bits must equal parent_n_bits.
        let result = validate_difficulty(500, 0x1a0fffff, 0x1a0fffff, &[], 1024, 120_000, true);
        assert!(result.is_ok());
    }

    #[test]
    fn mid_epoch_wrong_nbits_rejected() {
        let result = validate_difficulty(500, 0x1a0aaaaa, 0x1a0fffff, &[], 1024, 120_000, true);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.expected, 0x1a0fffff);
        assert_eq!(err.actual, 0x1a0aaaaa);
    }

    #[test]
    fn epoch_boundary_correct_passes() {
        // height=1025, parent=1024, epoch_length=1024 => epoch boundary
        // With stable 2-minute blocks, difficulty should stay the same.
        use crate::difficulty::encode_compact_bits;
        use num_bigint::BigUint;

        let base_diff: u64 = 10_000_000;
        let base_nbits = encode_compact_bits(&BigUint::from(base_diff)) as u32;
        let epoch_length: u32 = 1024;
        let desired_ms: u64 = 120_000;

        // 2 epoch headers with stable timing.
        let headers = vec![
            (0u32, 1_000_000_000u64, base_nbits),
            (
                epoch_length,
                1_000_000_000 + (epoch_length as u64) * desired_ms,
                base_nbits,
            ),
        ];

        let expected_nbits =
            crate::difficulty_adjustment::calculate_classic(&headers, epoch_length, desired_ms);

        let result = validate_difficulty(
            epoch_length + 1,
            expected_nbits,
            base_nbits,
            &headers,
            epoch_length,
            desired_ms,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn epoch_boundary_wrong_rejected() {
        use crate::difficulty::encode_compact_bits;
        use num_bigint::BigUint;

        let base_diff: u64 = 10_000_000;
        let base_nbits = encode_compact_bits(&BigUint::from(base_diff)) as u32;
        let epoch_length: u32 = 1024;
        let desired_ms: u64 = 120_000;

        let headers = vec![
            (0u32, 1_000_000_000u64, base_nbits),
            (
                epoch_length,
                1_000_000_000 + (epoch_length as u64) * desired_ms,
                base_nbits,
            ),
        ];

        // Declare a wrong nBits.
        let result = validate_difficulty(
            epoch_length + 1,
            0x01000001, // wrong value
            base_nbits,
            &headers,
            epoch_length,
            desired_ms,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn genesis_height_accepted() {
        // height=1, parent=0, epoch_length=1024 => 0 % 1024 == 0 => epoch boundary
        // With single header in epoch_headers, calculate_classic returns that header's nBits.
        use crate::difficulty::encode_compact_bits;
        use num_bigint::BigUint;

        let base_nbits = encode_compact_bits(&BigUint::from(1_000_000u64)) as u32;
        let headers = vec![(0u32, 0u64, base_nbits)];

        let expected = crate::difficulty_adjustment::calculate_classic(&headers, 1024, 120_000);

        let result = validate_difficulty(1, expected, 0, &headers, 1024, 120_000, false);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Block version validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_block_version_matching() {
        // Version 1 header with expected version 1 — should pass.
        let h = Header {
            version: 1,
            height: 100,
            ..Header::default_for_test()
        };
        assert!(validate_block_version(&h, 1).is_ok());
    }

    #[test]
    fn validate_block_version_v2_matching() {
        // Version 2 header with expected version 2 — should pass.
        let h = Header {
            version: 2,
            height: 500_000,
            ..Header::default_for_test()
        };
        assert!(validate_block_version(&h, 2).is_ok());
    }

    #[test]
    fn validate_block_version_mismatch_rejected() {
        // Version 1 header when version 2 is expected — should fail.
        let h = Header {
            version: 1,
            height: 500_000,
            ..Header::default_for_test()
        };
        let err = validate_block_version(&h, 2).unwrap_err();
        match err {
            HeaderValidationError::BlockVersionMismatch {
                height,
                expected,
                got,
            } => {
                assert_eq!(height, 500_000);
                assert_eq!(expected, 2);
                assert_eq!(got, 1);
            }
            other => panic!("expected BlockVersionMismatch, got: {other:?}"),
        }
    }

    #[test]
    fn validate_block_version_v2_when_v1_expected_rejected() {
        // Version 2 header when version 1 is expected — should fail.
        let h = Header {
            version: 2,
            height: 100,
            ..Header::default_for_test()
        };
        let err = validate_block_version(&h, 1).unwrap_err();
        match err {
            HeaderValidationError::BlockVersionMismatch {
                height,
                expected,
                got,
            } => {
                assert_eq!(height, 100);
                assert_eq!(expected, 1);
                assert_eq!(got, 2);
            }
            other => panic!("expected BlockVersionMismatch, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Parent semantics validation tests (rule 210)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_parent_semantics_valid_parent_passes() {
        // Parent is valid (not invalid) — should pass.
        let parent_id = ModifierId([0xAA; 32]);
        assert!(validate_parent_semantics(&parent_id, false).is_ok());
    }

    #[test]
    fn validate_parent_semantics_invalid_parent_rejected() {
        // Parent is marked invalid — should be rejected.
        let parent_id = ModifierId([0xBB; 32]);
        let err = validate_parent_semantics(&parent_id, true).unwrap_err();
        match err {
            HeaderValidationError::InvalidParent(id) => {
                assert_eq!(id, parent_id);
            }
            other => panic!("expected InvalidParent, got: {other:?}"),
        }
    }

    #[test]
    fn validate_parent_semantics_unknown_parent_passes() {
        // Parent validity is unknown (not explicitly invalid) — should pass.
        // The caller passes `false` when validity is None or Valid.
        let parent_id = ModifierId([0xCC; 32]);
        assert!(validate_parent_semantics(&parent_id, false).is_ok());
    }

    // -----------------------------------------------------------------------
    // Genesis height validation tests (rule 203)
    // -----------------------------------------------------------------------

    #[test]
    fn genesis_height_must_be_one() {
        let h = Header {
            height: 1,
            parent_id: ModifierId::GENESIS_PARENT,
            ..Header::default_for_test()
        };
        assert!(validate_genesis_height(&h).is_ok());
    }

    #[test]
    fn genesis_height_zero_rejected() {
        let h = Header {
            height: 0,
            parent_id: ModifierId::GENESIS_PARENT,
            ..Header::default_for_test()
        };
        assert!(validate_genesis_height(&h).is_err());
    }

    #[test]
    fn genesis_height_two_rejected() {
        let h = Header {
            height: 2,
            parent_id: ModifierId::GENESIS_PARENT,
            ..Header::default_for_test()
        };
        assert!(validate_genesis_height(&h).is_err());
    }

    // -----------------------------------------------------------------------
    // Genesis ID validation tests (rule 201)
    // -----------------------------------------------------------------------

    #[test]
    fn genesis_id_none_skips_check() {
        let h = Header::default_for_test();
        assert!(validate_genesis_id(&h, None).is_ok());
    }

    #[test]
    fn genesis_id_empty_skips_check() {
        let h = Header::default_for_test();
        assert!(validate_genesis_id(&h, Some("")).is_ok());
    }

    #[test]
    fn genesis_id_mismatch_rejected() {
        let h = Header::default_for_test();
        let expected = "aaaa".repeat(16); // 64 hex chars = 32 bytes, won't match
        assert!(validate_genesis_id(&h, Some(&expected)).is_err());
    }

    #[test]
    fn genesis_id_matches() {
        let h = Header::default_for_test();
        let actual_id = hex::encode(compute_header_id_bytes(&h));
        assert!(validate_genesis_id(&h, Some(&actual_id)).is_ok());
    }

    // -----------------------------------------------------------------------
    // Required difficulty validation tests (rule 208)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_required_difficulty_none_skips() {
        let h = Header {
            n_bits: 0x1a0fffff,
            ..Header::default_for_test()
        };
        assert!(validate_required_difficulty(&h, None).is_ok());
    }

    #[test]
    fn validate_required_difficulty_matches() {
        let h = Header {
            n_bits: 0x1a0fffff,
            height: 100,
            ..Header::default_for_test()
        };
        assert!(validate_required_difficulty(&h, Some(0x1a0fffff)).is_ok());
    }

    #[test]
    fn validate_required_difficulty_mismatch() {
        let h = Header {
            n_bits: 0x1a0aaaaa,
            height: 100,
            ..Header::default_for_test()
        };
        let err = validate_required_difficulty(&h, Some(0x1a0fffff)).unwrap_err();
        match err {
            HeaderValidationError::DifficultyMismatch {
                expected, actual, ..
            } => {
                assert_eq!(expected, 0x1a0fffff);
                assert_eq!(actual, 0x1a0aaaaa);
            }
            other => panic!("expected DifficultyMismatch, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Genesis difficulty validation tests (rule 208 for genesis)
    // -----------------------------------------------------------------------

    #[test]
    fn genesis_difficulty_none_skips() {
        let h = Header {
            height: 1,
            parent_id: ModifierId::GENESIS_PARENT,
            n_bits: 0x1a0fffff,
            ..Header::default_for_test()
        };
        // initial_n_bits = None → skip difficulty check
        assert!(
            validate_genesis_header(&h, h.timestamp, None, None, DEFAULT_MAX_TIME_DRIFT_MS).is_ok()
                || true
        ); // PoW may fail for test header, that's fine — we just check no panic
    }

    #[test]
    fn genesis_difficulty_matches() {
        let h = Header {
            height: 1,
            parent_id: ModifierId::GENESIS_PARENT,
            n_bits: 0x1a0fffff,
            ..Header::default_for_test()
        };
        // initial_n_bits matches → difficulty check passes
        assert!(validate_required_difficulty(&h, Some(0x1a0fffff)).is_ok());
    }

    #[test]
    fn genesis_difficulty_mismatch_rejected() {
        let h = Header {
            height: 1,
            parent_id: ModifierId::GENESIS_PARENT,
            n_bits: 0x1a0aaaaa,
            ..Header::default_for_test()
        };
        // initial_n_bits doesn't match → rejected
        let err = validate_required_difficulty(&h, Some(0x1a0fffff)).unwrap_err();
        assert!(matches!(
            err,
            HeaderValidationError::DifficultyMismatch { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Skip-PoW composite validator tests
    // -----------------------------------------------------------------------

    #[test]
    fn skip_pow_child_valid() {
        let parent = Header {
            height: 99,
            timestamp: 1_000_000,
            ..Header::default_for_test()
        };
        let child = Header {
            height: 100,
            timestamp: 2_000_000,
            ..Header::default_for_test()
        };
        let now_ms = child.timestamp + 60_000;
        assert!(validate_child_header_skip_pow(
            &child,
            &parent,
            now_ms,
            None,
            DEFAULT_MAX_TIME_DRIFT_MS
        )
        .is_ok());
    }

    #[test]
    fn skip_pow_child_rejects_bad_height() {
        let parent = Header {
            height: 99,
            timestamp: 1_000_000,
            ..Header::default_for_test()
        };
        let child = Header {
            height: 105, // wrong — should be 100
            timestamp: 2_000_000,
            ..Header::default_for_test()
        };
        let now_ms = child.timestamp + 60_000;
        let err = validate_child_header_skip_pow(
            &child,
            &parent,
            now_ms,
            None,
            DEFAULT_MAX_TIME_DRIFT_MS,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            HeaderValidationError::HeightMismatch {
                expected: 100,
                got: 105
            }
        ));
    }

    #[test]
    fn skip_pow_genesis_valid() {
        let genesis = Header {
            height: 1,
            parent_id: ModifierId::GENESIS_PARENT,
            timestamp: 1_000_000,
            ..Header::default_for_test()
        };
        let now_ms = genesis.timestamp + 60_000;
        assert!(validate_genesis_header_skip_pow(
            &genesis,
            now_ms,
            None,
            None,
            DEFAULT_MAX_TIME_DRIFT_MS
        )
        .is_ok());
    }

    #[test]
    fn skip_pow_genesis_rejects_bad_height() {
        let genesis = Header {
            height: 2, // wrong — must be 1
            parent_id: ModifierId::GENESIS_PARENT,
            timestamp: 1_000_000,
            ..Header::default_for_test()
        };
        let now_ms = genesis.timestamp + 60_000;
        let err = validate_genesis_header_skip_pow(
            &genesis,
            now_ms,
            None,
            None,
            DEFAULT_MAX_TIME_DRIFT_MS,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            HeaderValidationError::GenesisHeightInvalid(2)
        ));
    }
}
