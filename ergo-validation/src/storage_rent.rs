//! Consensus-economics arithmetic for the storage-rent rule.
//!
//! Scala uses `Int * Int` for `storageFeeFactor * boxBytesLength` and
//! the result wraps on overflow — by default at `box_bytes_len > 1717`
//! with factor `1_250_000`. The Rust mirror MUST do the same i32
//! wrapping multiplication; widening to i64 silently diverges from
//! mainnet on every wrap-eligible box and breaks consensus.
//!
//! Both consumers of this helper:
//! - `tx::script::check_storage_rent` (consensus path) — block
//!   validation calls this when an empty proof + storage-rent context
//!   variable signals the rent-collection branch.
//! - The `/blockchain/storageRent/eligible` API handler — reaches
//!   the helper indirectly through `ChainParamsView::compute_storage_fee`
//!   so `ergo-api` does not take a direct `ergo-validation` dep.

/// Storage fee for a box of `box_bytes_len` bytes at `storage_fee_factor`
/// nanoErg per byte per storage period. Returns the consensus-canonical
/// i32 result, including the wrap-on-overflow regime that mainnet
/// validation depends on.
///
/// Both inputs are i32 because the underlying voted parameter is i32
/// (`ProtocolParams::storage_fee_factor`) and the canonical box length
/// is bounded well below `i32::MAX` by the wire format. Callers MUST
/// pass the same `box_bytes_len` they would feed to the validator —
/// `ergo_ser::ergo_box::serialize_ergo_box(box)?.len() as i32` — not a
/// re-derived length.
#[inline]
pub fn compute_storage_fee(box_bytes_len: i32, storage_fee_factor: i32) -> i32 {
    storage_fee_factor.wrapping_mul(box_bytes_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn small_box_default_factor_yields_positive_fee() {
        // 76-byte box × 1_250_000 nanoErg/byte = 95_000_000.
        assert_eq!(compute_storage_fee(76, 1_250_000), 95_000_000);
    }

    // ----- overflow cliff -----

    #[test]
    fn at_1716_bytes_default_factor_stays_positive() {
        // 1716 × 1_250_000 = 2_145_000_000 — under i32::MAX (2_147_483_647).
        assert_eq!(compute_storage_fee(1716, 1_250_000), 2_145_000_000);
    }

    #[test]
    fn at_1717_bytes_default_factor_overflows_negative() {
        // 1717 × 1_250_000 = 2_146_250_000 — STILL under i32::MAX. The
        // first wrap with the default factor is at 1718 — pin both.
        assert_eq!(compute_storage_fee(1717, 1_250_000), 2_146_250_000);
    }

    #[test]
    fn at_1718_bytes_default_factor_wraps_to_negative() {
        // 1718 × 1_250_000 = 2_147_500_000 — exceeds i32::MAX, wraps.
        let got = compute_storage_fee(1718, 1_250_000);
        assert!(got < 0, "expected wrap-negative at 1718 bytes; got {got}",);
    }

    #[test]
    fn at_2000_bytes_default_factor_wraps_negative_too() {
        let got = compute_storage_fee(2000, 1_250_000);
        assert!(got < 0, "expected wrap-negative at 2000 bytes; got {got}");
    }

    #[test]
    fn at_10000_bytes_default_factor_wraps_negative_too() {
        let got = compute_storage_fee(10_000, 1_250_000);
        assert!(got < 0, "expected wrap-negative at 10000 bytes; got {got}");
    }

    // ----- invariants -----

    #[test]
    fn zero_factor_zero_fee() {
        assert_eq!(compute_storage_fee(76, 0), 0);
        assert_eq!(compute_storage_fee(10_000, 0), 0);
    }

    #[test]
    fn zero_length_zero_fee() {
        assert_eq!(compute_storage_fee(0, 1_250_000), 0);
    }
}
