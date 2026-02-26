//! Difficulty adjustment algorithms for Ergo epoch boundaries.
//!
//! Ports `DifficultyAdjustment.scala` from the Ergo reference implementation.
//! Two variants are provided:
//!
//! - **Classic** (pre-EIP-37): linear interpolation over the last few epochs
//! - **EIP-37** (post height 844,673): blends Bitcoin-style with predictive,
//!   capped at +/-50%

use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Signed, Zero};

use crate::difficulty::{decode_compact_bits, encode_compact_bits};

/// Precision constant for integer-based linear regression (avoids floats).
const PRECISION: i64 = 1_000_000_000;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Calculate difficulty using the classic (pre-EIP-37) algorithm.
///
/// `previous_headers` is an ordered slice of `(height, timestamp_ms, nBits)`
/// tuples from epoch boundaries, oldest first.  For mainnet with
/// `epoch_length = 1024` and `use_last_epochs = 8` this is up to 9 headers.
///
/// Returns the new `nBits` value for the next epoch.
pub fn calculate_classic(
    previous_headers: &[(u32, u64, u32)],
    epoch_length: u32,
    desired_interval_ms: u64,
) -> u32 {
    if previous_headers.len() <= 1 {
        return previous_headers
            .last()
            .map(|h| h.2)
            .unwrap_or(0);
    }

    let first_ts = previous_headers.first().unwrap().1;
    let last_ts = previous_headers.last().unwrap().1;
    if first_ts >= last_ts {
        return previous_headers.last().unwrap().2;
    }

    let desired = BigInt::from(desired_interval_ms);
    let epoch_len = BigInt::from(epoch_length);

    // Build adjusted-difficulty data points from consecutive pairs.
    let data: Vec<(BigInt, BigInt)> = previous_headers
        .windows(2)
        .map(|w| {
            let (_start_h, start_ts, _start_nbits) = w[0];
            let (end_h, end_ts, end_nbits) = w[1];
            let end_diff = decode_compact_bits(end_nbits as u64).to_bigint().unwrap();
            let actual_time = BigInt::from(end_ts) - BigInt::from(start_ts);
            let adjusted = &end_diff * &desired * &epoch_len / &actual_time;
            (BigInt::from(end_h), adjusted)
        })
        .collect();

    let diff = interpolate(&data, epoch_length);
    let diff = if diff >= BigInt::one() {
        diff
    } else {
        BigInt::one()
    };

    normalize(&diff)
}

/// Calculate difficulty using the EIP-37 algorithm.
///
/// Blends a clamped predictive (classic) difficulty with a Bitcoin-style
/// calculation, then applies a secondary +/-50% clamp.
pub fn calculate_eip37(
    previous_headers: &[(u32, u64, u32)],
    epoch_length: u32,
    desired_interval_ms: u64,
) -> u32 {
    if previous_headers.len() < 2 {
        return previous_headers
            .last()
            .map(|h| h.2)
            .unwrap_or(0);
    }

    let last_nbits = previous_headers.last().unwrap().2;
    let last_diff = decode_compact_bits(last_nbits as u64)
        .to_bigint()
        .unwrap();

    // 1. Predictive difficulty (classic, without normalization).
    let predictive = calculate_classic_raw(previous_headers, epoch_length, desired_interval_ms);

    // 2. Clamp predictive to +/-50% of last difficulty.
    let limited_predictive = clamp_50(&predictive, &last_diff);

    // 3. Bitcoin-style: use only last two headers.
    let bitcoin = bitcoin_calculate(previous_headers, epoch_length, desired_interval_ms);

    // 4. Average.
    let avg = (&limited_predictive + &bitcoin) / BigInt::from(2);

    // 5. Secondary clamp.
    let uncompressed = clamp_50(&avg, &last_diff);

    normalize(&uncompressed)
}

/// Return the heights of previous headers required for difficulty recalculation
/// at `height`.
///
/// - At an epoch boundary (where `(height - 1) % epoch_length == 0`): returns
///   up to `use_last_epochs + 1` heights going back.
/// - Mid-epoch: returns `[height - 1]`.
pub fn previous_heights_for_recalculation(
    height: u32,
    epoch_length: u32,
    use_last_epochs: u32,
) -> Vec<u32> {
    if epoch_length <= 1 || height == 0 {
        // Degenerate: every block is an epoch boundary with epoch_length=1,
        // or genesis has no parents.
        if height == 0 {
            return vec![];
        }
        // epoch_length <= 1: fall through to parent-height check
    }

    let parent_height = height - 1;

    if epoch_length > 1 && parent_height.is_multiple_of(epoch_length) {
        // At epoch boundary — go back through previous epochs.
        let mut heights: Vec<u32> = (0..=use_last_epochs)
            .filter_map(|i| parent_height.checked_sub(i * epoch_length))
            .collect();
        heights.reverse();
        heights
    } else {
        vec![parent_height]
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Classic algorithm returning the raw BigInt (no normalization).
fn calculate_classic_raw(
    previous_headers: &[(u32, u64, u32)],
    epoch_length: u32,
    desired_interval_ms: u64,
) -> BigInt {
    if previous_headers.len() <= 1 {
        return previous_headers
            .last()
            .map(|h| decode_compact_bits(h.2 as u64).to_bigint().unwrap())
            .unwrap_or_else(BigInt::zero);
    }

    let first_ts = previous_headers.first().unwrap().1;
    let last_ts = previous_headers.last().unwrap().1;
    if first_ts >= last_ts {
        return decode_compact_bits(previous_headers.last().unwrap().2 as u64)
            .to_bigint()
            .unwrap();
    }

    let desired = BigInt::from(desired_interval_ms);
    let epoch_len = BigInt::from(epoch_length);

    let data: Vec<(BigInt, BigInt)> = previous_headers
        .windows(2)
        .map(|w| {
            let start_ts = w[0].1;
            let (end_h, end_ts, end_nbits) = w[1];
            let end_diff = decode_compact_bits(end_nbits as u64).to_bigint().unwrap();
            let actual_time = BigInt::from(end_ts) - BigInt::from(start_ts);
            let adjusted = &end_diff * &desired * &epoch_len / &actual_time;
            (BigInt::from(end_h), adjusted)
        })
        .collect();

    let diff = interpolate(&data, epoch_length);
    if diff >= BigInt::one() {
        diff
    } else {
        BigInt::one()
    }
}

/// Bitcoin-style difficulty calculation using only the last two epoch headers.
fn bitcoin_calculate(
    previous_headers: &[(u32, u64, u32)],
    epoch_length: u32,
    desired_interval_ms: u64,
) -> BigInt {
    let hs = &previous_headers[previous_headers.len().saturating_sub(2)..];
    let start = &hs[0];
    let end = &hs[hs.len() - 1];
    let end_diff = decode_compact_bits(end.2 as u64).to_bigint().unwrap();
    let actual_time = BigInt::from(end.1) - BigInt::from(start.1);
    if actual_time.is_zero() {
        return end_diff;
    }
    &end_diff * BigInt::from(desired_interval_ms) * BigInt::from(epoch_length) / actual_time
}

/// Clamp `value` to +/-50% of `reference`.
fn clamp_50(value: &BigInt, reference: &BigInt) -> BigInt {
    let upper = reference * 3 / 2;
    let lower = reference / 2;
    if value > &upper {
        upper
    } else if value < &lower {
        lower
    } else {
        value.clone()
    }
}

/// Linear interpolation: fits `y = a + b*x` through data points and predicts
/// at `max_x + epoch_length`.
///
/// Uses fixed-point integer arithmetic with `PRECISION` to avoid floats.
fn interpolate(data: &[(BigInt, BigInt)], epoch_length: u32) -> BigInt {
    if data.len() == 1 {
        return data[0].1.clone();
    }

    let n = BigInt::from(data.len());
    let precision = BigInt::from(PRECISION);

    let xy_sum: BigInt = data.iter().map(|(x, y)| x * y).sum();
    let x_sum: BigInt = data.iter().map(|(x, _)| x.clone()).sum();
    let x2_sum: BigInt = data.iter().map(|(x, _)| x * x).sum();
    let y_sum: BigInt = data.iter().map(|(_, y)| y.clone()).sum();

    let denominator = &x2_sum * &n - &x_sum * &x_sum;
    if denominator.is_zero() {
        // All points at the same x-coordinate — can't fit a line.
        return data.last().unwrap().1.clone();
    }

    let b = (&xy_sum * &n - &x_sum * &y_sum) * &precision / &denominator;
    let a = (&y_sum * &precision - &b * &x_sum) / &n / &precision;

    let max_x = data.iter().map(|(x, _)| x).max().unwrap();
    let point = max_x + BigInt::from(epoch_length);

    &a + &b * &point / &precision
}

/// Normalize a difficulty value through an encode/decode round-trip, returning
/// the compact nBits (u32).
fn normalize(diff: &BigInt) -> u32 {
    // Convert to BigUint (should always be positive at this point).
    let biguint = if diff.is_positive() {
        diff.to_biguint().unwrap()
    } else {
        BigUint::one()
    };
    let compact = encode_compact_bits(&biguint);
    // The top 32 bits are always zero for valid difficulties.
    compact as u32
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    /// Helper: build an nBits value from a u64 difficulty.
    fn nbits_from(difficulty: u64) -> u32 {
        encode_compact_bits(&BigUint::from(difficulty)) as u32
    }

    /// Helper: decode nBits to a BigUint difficulty.
    fn diff_from_nbits(nbits: u32) -> BigUint {
        decode_compact_bits(nbits as u64)
    }

    // -----------------------------------------------------------------------
    // previous_heights_for_recalculation tests
    // -----------------------------------------------------------------------

    #[test]
    fn previous_heights_at_epoch_boundary() {
        // height=1025, epoch_length=1024, use_last_epochs=8
        // parent=1024, 1024 % 1024 == 0 => epoch boundary
        // Go back: [1024, 0], reversed => [0, 1024]
        let heights = previous_heights_for_recalculation(1025, 1024, 8);
        assert_eq!(heights, vec![0, 1024]);
    }

    #[test]
    fn previous_heights_mid_epoch() {
        // height=500, parent=499, 499 % 1024 != 0 => mid-epoch
        let heights = previous_heights_for_recalculation(500, 1024, 8);
        assert_eq!(heights, vec![499]);
    }

    #[test]
    fn previous_heights_deep_history() {
        // height=8193, epoch_length=1024, use_last_epochs=8
        // parent=8192, 8192 % 1024 == 0 => epoch boundary
        // (0..=8).map(|i| 8192 - i*1024) = [8192, 7168, 6144, 5120, 4096, 3072, 2048, 1024, 0]
        // reversed => [0, 1024, 2048, 3072, 4096, 5120, 6144, 7168, 8192]
        let heights = previous_heights_for_recalculation(8193, 1024, 8);
        assert_eq!(heights.len(), 9);
        assert_eq!(
            heights,
            vec![0, 1024, 2048, 3072, 4096, 5120, 6144, 7168, 8192]
        );
    }

    // -----------------------------------------------------------------------
    // calculate_classic tests
    // -----------------------------------------------------------------------

    #[test]
    fn calculate_classic_single_epoch() {
        // Two headers (one epoch pair).
        // Blocks take exactly 1 minute (60_000 ms) each over 1024 blocks.
        // desired_interval_ms = 120_000 (2 minutes).
        // Actual time for epoch = 1024 * 60_000 = 61_440_000 ms
        // Desired time = 1024 * 120_000 = 122_880_000 ms
        // Adjustment: diff * 122_880_000 / 61_440_000 = diff * 2
        let base_diff: u64 = 1_000_000;
        let base_nbits = nbits_from(base_diff);
        let epoch_length: u32 = 1024;
        let desired_ms: u64 = 120_000;
        let actual_block_time: u64 = 60_000; // half the desired => difficulty should double

        let headers = vec![
            (0u32, 1_000_000_000u64, base_nbits),
            (
                epoch_length,
                1_000_000_000 + actual_block_time * epoch_length as u64,
                base_nbits,
            ),
        ];

        let result = calculate_classic(&headers, epoch_length, desired_ms);
        let result_diff = diff_from_nbits(result);
        let expected_diff = BigUint::from(base_diff * 2);

        // Should approximately double (within normalization rounding).
        let ratio: BigInt =
            result_diff.to_bigint().unwrap() * 100 / expected_diff.to_bigint().unwrap();
        let ratio_val: i64 = ratio.try_into().unwrap_or(0i64);
        // Allow 1% tolerance due to compact encoding normalization.
        assert!(
            (99..=101).contains(&ratio_val),
            "Expected ~2x difficulty, got ratio {}%",
            ratio_val
        );
    }

    #[test]
    fn calculate_classic_stable_chain() {
        // Constant 2-minute blocks across multiple epochs.
        // Difficulty should remain approximately unchanged.
        let base_diff: u64 = 10_000_000;
        let base_nbits = nbits_from(base_diff);
        let epoch_length: u32 = 1024;
        let desired_ms: u64 = 120_000;

        // 5 epoch headers, each exactly epoch_length * desired_ms apart.
        let headers: Vec<(u32, u64, u32)> = (0..5)
            .map(|i| {
                let h = i * epoch_length;
                let ts = 1_000_000_000u64 + (h as u64) * desired_ms;
                (h, ts, base_nbits)
            })
            .collect();

        let result = calculate_classic(&headers, epoch_length, desired_ms);
        let result_diff = diff_from_nbits(result);
        let base = BigUint::from(base_diff);

        // Should be very close to base_diff.
        let diff_signed = result_diff.to_bigint().unwrap() - base.to_bigint().unwrap();
        let tolerance = base.to_bigint().unwrap() / 100; // 1%
        assert!(
            diff_signed.abs() <= tolerance,
            "Expected stable difficulty, got diff delta {}",
            diff_signed
        );
    }

    #[test]
    fn calculate_classic_fast_blocks() {
        // 1-minute blocks with 2-minute target => difficulty roughly doubles.
        let base_diff: u64 = 5_000_000;
        let base_nbits = nbits_from(base_diff);
        let epoch_length: u32 = 1024;
        let desired_ms: u64 = 120_000;
        let actual_block_time: u64 = 60_000;

        let headers: Vec<(u32, u64, u32)> = (0..5)
            .map(|i| {
                let h = i * epoch_length;
                let ts = 1_000_000_000u64 + (h as u64) * actual_block_time;
                (h, ts, base_nbits)
            })
            .collect();

        let result = calculate_classic(&headers, epoch_length, desired_ms);
        let result_diff = diff_from_nbits(result);
        let base = BigUint::from(base_diff);

        // Should be roughly 2x (constant fast blocks across all epochs).
        let ratio = &result_diff * BigUint::from(100u32) / &base;
        let ratio_val: u64 = ratio.try_into().unwrap_or(0);
        assert!(
            (180..=220).contains(&ratio_val),
            "Expected ~2x difficulty, got ratio {}%",
            ratio_val
        );
    }

    #[test]
    fn calculate_classic_slow_blocks() {
        // 4-minute blocks with 2-minute target => difficulty roughly halves.
        let base_diff: u64 = 10_000_000;
        let base_nbits = nbits_from(base_diff);
        let epoch_length: u32 = 1024;
        let desired_ms: u64 = 120_000;
        let actual_block_time: u64 = 240_000;

        let headers: Vec<(u32, u64, u32)> = (0..5)
            .map(|i| {
                let h = i * epoch_length;
                let ts = 1_000_000_000u64 + (h as u64) * actual_block_time;
                (h, ts, base_nbits)
            })
            .collect();

        let result = calculate_classic(&headers, epoch_length, desired_ms);
        let result_diff = diff_from_nbits(result);
        let base = BigUint::from(base_diff);

        // Should be roughly 0.5x.
        let ratio = &result_diff * BigUint::from(100u32) / &base;
        let ratio_val: u64 = ratio.try_into().unwrap_or(0);
        assert!(
            (40..=60).contains(&ratio_val),
            "Expected ~0.5x difficulty, got ratio {}%",
            ratio_val
        );
    }

    // -----------------------------------------------------------------------
    // calculate_eip37 tests
    // -----------------------------------------------------------------------

    #[test]
    fn calculate_eip37_capped_increase() {
        // Blocks so fast that uncapped difficulty would triple.
        // EIP-37 should cap at +50%.
        let base_diff: u64 = 10_000_000;
        let base_nbits = nbits_from(base_diff);
        let epoch_length: u32 = 1024;
        let desired_ms: u64 = 120_000;
        // Blocks take 1/3 of the desired time => uncapped 3x increase.
        let actual_block_time: u64 = 40_000;

        let headers: Vec<(u32, u64, u32)> = (0..5)
            .map(|i| {
                let h = i * epoch_length;
                let ts = 1_000_000_000u64 + (h as u64) * actual_block_time;
                (h, ts, base_nbits)
            })
            .collect();

        let result = calculate_eip37(&headers, epoch_length, desired_ms);
        let result_diff = diff_from_nbits(result);
        let base = BigUint::from(base_diff);

        // Should be capped at 150% of base.
        let ratio = &result_diff * BigUint::from(100u32) / &base;
        let ratio_val: u64 = ratio.try_into().unwrap_or(0);
        assert!(
            ratio_val <= 155,
            "Expected at most ~150% of base, got {}%",
            ratio_val
        );
        // Should still increase (at least 140%).
        assert!(
            ratio_val >= 140,
            "Expected at least ~140% of base, got {}%",
            ratio_val
        );
    }

    #[test]
    fn calculate_eip37_capped_decrease() {
        // Blocks so slow that uncapped difficulty would drop to ~10%.
        // EIP-37 should cap at -50%.
        let base_diff: u64 = 10_000_000;
        let base_nbits = nbits_from(base_diff);
        let epoch_length: u32 = 1024;
        let desired_ms: u64 = 120_000;
        // Blocks take 10x the desired time => uncapped 0.1x.
        let actual_block_time: u64 = 1_200_000;

        let headers: Vec<(u32, u64, u32)> = (0..5)
            .map(|i| {
                let h = i * epoch_length;
                let ts = 1_000_000_000u64 + (h as u64) * actual_block_time;
                (h, ts, base_nbits)
            })
            .collect();

        let result = calculate_eip37(&headers, epoch_length, desired_ms);
        let result_diff = diff_from_nbits(result);
        let base = BigUint::from(base_diff);

        // Should be floored at 50% of base.
        let ratio = &result_diff * BigUint::from(100u32) / &base;
        let ratio_val: u64 = ratio.try_into().unwrap_or(0);
        assert!(
            ratio_val >= 45,
            "Expected at least ~50% of base, got {}%",
            ratio_val
        );
        assert!(
            ratio_val <= 55,
            "Expected at most ~55% of base, got {}%",
            ratio_val
        );
    }

    // -----------------------------------------------------------------------
    // Normalization test
    // -----------------------------------------------------------------------

    #[test]
    fn serialization_normalization() {
        // The result of calculate_classic should survive an encode/decode
        // round-trip unchanged (since it already normalizes internally).
        let base_diff: u64 = 7_654_321;
        let base_nbits = nbits_from(base_diff);
        let epoch_length: u32 = 1024;
        let desired_ms: u64 = 120_000;

        let headers: Vec<(u32, u64, u32)> = (0..5)
            .map(|i| {
                let h = i * epoch_length;
                let ts = 1_000_000_000u64 + (h as u64) * 90_000; // slightly fast
                (h, ts, base_nbits)
            })
            .collect();

        let result_nbits = calculate_classic(&headers, epoch_length, desired_ms);
        let diff = decode_compact_bits(result_nbits as u64);
        let re_encoded = encode_compact_bits(&diff) as u32;

        assert_eq!(
            result_nbits, re_encoded,
            "nBits should survive encode/decode round-trip"
        );
    }
}
