use ergo_ser::header::Header;

use super::HeaderValidationError;

/// Scala `Constants.FutureTimestampThreshold` — 20 minutes in
/// milliseconds. A header more than this far ahead of the validator's
/// clock is rejected as recoverable (peer can retry once the local
/// clock catches up).
pub const FUTURE_TIMESTAMP_DRIFT_MS: u64 = 20 * 60 * 1000;

/// Check that header.parent_id matches the computed ID of the parent.
pub fn check_parent_id(header: &Header, parent_id: &[u8; 32]) -> Result<(), HeaderValidationError> {
    if header.parent_id.as_bytes() != parent_id {
        return Err(HeaderValidationError::ParentMismatch {
            expected: *parent_id,
            got: *header.parent_id.as_bytes(),
        });
    }
    Ok(())
}

/// Check that header.timestamp > parent.timestamp.
pub fn check_timestamp(header: &Header, parent: &Header) -> Result<(), HeaderValidationError> {
    if header.timestamp <= parent.timestamp {
        return Err(HeaderValidationError::TimestampNotMonotonic {
            parent_ts: parent.timestamp,
            child_ts: header.timestamp,
        });
    }
    Ok(())
}

/// Scala `hdrFutureTimestamp` (rule 211) — reject headers whose
/// timestamp is more than [`FUTURE_TIMESTAMP_DRIFT_MS`] ahead of
/// `now_ms`.
///
/// Standalone (not invoked by [`validate_header_after_pow`](super::validate_header_after_pow))
/// because the validator clock is a runtime input that varies by caller:
/// production reads `SystemTime::now()` at the ingress site, tests
/// pin an explicit timestamp. Header-proc and any future
/// mempool-style header ingress must call this themselves with the
/// chosen clock value. Returning a typed error rather than a bool
/// keeps the rejection surface symmetric with the other rule
/// helpers.
pub fn check_future_timestamp(header: &Header, now_ms: u64) -> Result<(), HeaderValidationError> {
    let cap_ms = FUTURE_TIMESTAMP_DRIFT_MS;
    if header.timestamp > now_ms.saturating_add(cap_ms) {
        return Err(HeaderValidationError::FutureTimestamp {
            header_ts: header.timestamp,
            now_ms,
            drift_ms: header.timestamp - now_ms,
            cap_ms,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::autolykos::AutolykosSolution;

    fn test_header(votes: [u8; 3], timestamp: u64) -> Header {
        Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0; 32]),
            ad_proofs_root: Digest32::from_bytes([0; 32]),
            transactions_root: Digest32::from_bytes([0; 32]),
            state_root: ADDigest::from_bytes([0; 33]),
            timestamp,
            extension_root: Digest32::from_bytes([0; 32]),
            n_bits: 0x20000000,
            height: 1,
            votes,
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0; 8],
            },
        }
    }

    // ----- check_future_timestamp (rule 211) -----

    #[test]
    fn future_timestamp_accepts_at_boundary() {
        // header.ts == now + cap: exactly at the cap, accepted
        // (the rejection is `>`, not `>=`).
        let now = 1_700_000_000_000u64;
        let header = test_header([0; 3], now + FUTURE_TIMESTAMP_DRIFT_MS);
        assert!(check_future_timestamp(&header, now).is_ok());
    }

    #[test]
    fn future_timestamp_accepts_in_past() {
        // Headers in the past (or at present) trivially pass.
        let now = 1_700_000_000_000u64;
        let header = test_header([0; 3], now - 60_000);
        assert!(check_future_timestamp(&header, now).is_ok());
    }

    #[test]
    fn future_timestamp_rejects_one_ms_over_cap() {
        let now = 1_700_000_000_000u64;
        let header = test_header([0; 3], now + FUTURE_TIMESTAMP_DRIFT_MS + 1);
        let err = check_future_timestamp(&header, now).unwrap_err();
        match err {
            HeaderValidationError::FutureTimestamp {
                drift_ms, cap_ms, ..
            } => {
                assert_eq!(cap_ms, FUTURE_TIMESTAMP_DRIFT_MS);
                assert_eq!(drift_ms, FUTURE_TIMESTAMP_DRIFT_MS + 1);
            }
            other => panic!("expected FutureTimestamp, got {other:?}"),
        }
    }

    #[test]
    fn future_timestamp_handles_now_near_u64_max() {
        // saturating_add guards: a `now` near u64::MAX must not panic
        // even if the cap addition would overflow. The header.ts would
        // be ≤ u64::MAX which is ≤ saturating_add(now, cap), so
        // accepted.
        let now = u64::MAX - 1_000_000;
        let header = test_header([0; 3], u64::MAX - 500_000);
        assert!(check_future_timestamp(&header, now).is_ok());
    }
}
