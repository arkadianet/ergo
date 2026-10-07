use ergo_ser::difficulty::{
    decode_compact_bits, decode_compact_bits_signed, encode_compact_bits, normalize_difficulty,
};
use ergo_ser::header::Header;
use num_bigint::BigUint;

use crate::autolykos::v1::secp256k1_order;
use crate::pow::{DifficultyError, PowError};

pub use ergo_chain_spec::DifficultyParams;

/// Number of previous epochs used for difficulty recalculation.
/// Same on mainnet and testnet (Scala `useLastEpochs` in
/// `DifficultyAdjustment.scala`).
const USE_LAST_EPOCHS: u32 = 8;

/// Precision constant for linear interpolation (matches Scala
/// `DifficultyAdjustment.PrecisionConstant`). Pure math, not network-
/// specific.
const PRECISION: u64 = 1_000_000_000;

/// Compute PoW target b from encoded nBits: b = q / decode_compact_bits(nBits).
pub fn get_target(nbits: u32) -> BigUint {
    get_target_checked(nbits).unwrap_or_default()
}

pub(crate) fn get_target_checked(nbits: u32) -> Result<BigUint, PowError> {
    let difficulty = decode_compact_bits_signed(nbits);
    // Deliberately distinguish the reference's division-by-zero exception from
    // a negative target's false PoW verdict, for consensus script evaluation.
    // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/pow/Autolykos2PowValidation.scala#L165-L179
    match difficulty.sign() {
        num_bigint::Sign::NoSign => Err(PowError::ZeroDifficulty),
        num_bigint::Sign::Minus => Err(PowError::InvalidSolution(
            "negative difficulty from nBits".into(),
        )),
        num_bigint::Sign::Plus => Ok(secp256k1_order() / difficulty.into_parts().1),
    }
}

/// Get the epoch length for a height using network-specific config.
/// Pre-EIP-37 epochs use `config.epoch_length`; once
/// `config.eip37_activation_height` is reached the network switches to
/// `config.eip37_epoch_length` (if both are `Some`).
pub fn epoch_length_for_height(height: u32, config: &DifficultyParams) -> u32 {
    match (config.eip37_activation_height, config.eip37_epoch_length) {
        (Some(activation), Some(epoch_len)) if height >= activation => epoch_len,
        _ => config.epoch_length,
    }
}

/// Determine whether difficulty should be recalculated at this height.
/// Recalculation happens at the first block of each epoch:
/// height where `parent_height % epoch_length == 0`. Uses
/// `epoch_length_for_height(child_height, config)` so the EIP-37 boundary
/// (child_height == 844_673 on mainnet) correctly takes the post-EIP-37
/// epoch length.
pub fn is_recalculation_height(child_height: u32, config: &DifficultyParams) -> bool {
    let Some(parent_height) = child_height.checked_sub(1) else {
        return false;
    };
    let epoch_len = epoch_length_for_height(child_height, config);
    epoch_len != 0 && parent_height.is_multiple_of(epoch_len)
}

/// Heights of previous headers needed for difficulty recalculation.
/// Matches Scala `previousHeightsRequiredForRecalculation` on valid inputs.
/// Height zero or epoch length zero returns no usable heights; out-of-range
/// older offsets are omitted using checked arithmetic.
///
/// The `epoch_length == 1` arm below is the Scala-mirror degenerate-case
/// path: when epoch length collapses to 1, every parent height is a
/// recalculation point and `parent_height.checked_sub(i * 1)` reduces
/// to `parent_height - i`. Mainnet never sees `epoch_length == 1` (the
/// configured values are 1024 pre-EIP-37 and 128 after), so this arm is
/// effectively unreachable in production but kept for byte-faithful
/// parity with the Scala `previousHeightsRequiredForRecalculation` shape.
pub fn previous_heights_for_recalculation(height: u32, epoch_length: u32) -> Vec<u32> {
    let Some(parent_height) = height.checked_sub(1) else {
        return Vec::new();
    };
    if epoch_length == 0 {
        return Vec::new();
    }
    if parent_height.is_multiple_of(epoch_length) && epoch_length > 1 {
        // Mainnet path: epoch_length >= 128, parent_height at an epoch boundary.
        let mut heights: Vec<u32> = (0..=USE_LAST_EPOCHS)
            .filter_map(|i| {
                i.checked_mul(epoch_length)
                    .and_then(|offset| parent_height.checked_sub(offset))
            })
            .collect();
        heights.sort();
        heights
    } else if parent_height.is_multiple_of(epoch_length) && height > epoch_length * USE_LAST_EPOCHS
    {
        // Scala-parity branch for epoch_length <= 1 (degenerate; never on mainnet).
        let mut heights: Vec<u32> = (0..=USE_LAST_EPOCHS)
            .map(|i| parent_height - i * epoch_length)
            .collect();
        heights.sort();
        heights
    } else {
        vec![parent_height]
    }
}

/// Pre-EIP-37 difficulty calculation (predictive, with normalization).
/// Matches Scala `DifficultyAdjustment.calculate`. `desired_interval_ms`
/// is the network's target block interval (Scala
/// `chainSettings.blockInterval`).
fn calculate(
    previous_headers: &[Header],
    epoch_length: u32,
    initial_difficulty: &BigUint,
    desired_interval_ms: u64,
) -> BigUint {
    if previous_headers.len() == 1 {
        return normalize_difficulty(&decode_compact_bits(previous_headers[0].n_bits));
    }

    let first = &previous_headers[0];
    let last = previous_headers.last().unwrap();
    if first.timestamp >= last.timestamp {
        return normalize_difficulty(&decode_compact_bits(first.n_bits));
    }

    // Build (height, difficulty) data points from sliding pairs
    let data: Vec<(u32, BigUint)> = previous_headers
        .windows(2)
        .map(|pair| {
            let start = &pair[0];
            let end = &pair[1];
            let diff = decode_compact_bits(end.n_bits);
            let elapsed = end.timestamp - start.timestamp;
            let computed = &diff * desired_interval_ms * u64::from(epoch_length) / elapsed;
            (end.height, computed)
        })
        .collect();

    let diff = interpolate(&data, epoch_length);
    if diff >= BigUint::from(1u32) {
        normalize_difficulty(&diff)
    } else {
        // Interpolation went negative (e.g., mixed v1/v2 epoch data).
        // Scala falls back to chainSettings.initialDifficulty, not 1.
        normalize_difficulty(initial_difficulty)
    }
}

/// EIP-37 difficulty calculation: predictive + classic, averaged, both ±50% capped.
/// Matches Scala `DifficultyAdjustment.eip37Calculate`.
///
/// Caller contract: `previous_headers.len() >= 2`.
/// [`required_difficulty_checked`] intercepts undersized windows and
/// returns `DifficultyError::MissingEpochHeaders`, so this `debug_assert!`
/// is only there to catch a future direct caller in dev/test builds.
fn eip37_calculate(
    previous_headers: &[Header],
    epoch_length: u32,
    initial_difficulty: &BigUint,
    desired_interval_ms: u64,
) -> BigUint {
    debug_assert!(
        previous_headers.len() >= 2,
        "need at least 2 headers for eip37 diff recalc"
    );

    let last_diff = decode_compact_bits(previous_headers.last().unwrap().n_bits);

    // Predictive difficulty — Scala calls calculate() which normalizes
    let predictive_diff = calculate(
        previous_headers,
        epoch_length,
        initial_difficulty,
        desired_interval_ms,
    );
    let limited_predictive = cap_change(&predictive_diff, &last_diff);

    // Classic (Bitcoin-style) difficulty
    let classic_diff = bitcoin_calculate(previous_headers, epoch_length, desired_interval_ms);

    // Average and cap again
    let avg = (&classic_diff + &limited_predictive) / 2u32;
    let result = cap_change(&avg, &last_diff);

    normalize_difficulty(&result)
}

/// Bitcoin-style simple difficulty calculation from last two epoch headers.
/// Matches Scala `bitcoinCalculate`. `desired_interval_ms` is the
/// network's target block interval.
fn bitcoin_calculate(
    previous_headers: &[Header],
    epoch_length: u32,
    desired_interval_ms: u64,
) -> BigUint {
    let n = previous_headers.len();
    let start = &previous_headers[n - 2];
    let end = &previous_headers[n - 1];
    let diff = decode_compact_bits(end.n_bits);
    let elapsed = end.timestamp - start.timestamp;
    if elapsed == 0 {
        return diff;
    }
    diff * desired_interval_ms * u64::from(epoch_length) / elapsed
}

/// Cap difficulty change to ±50% of last_diff.
fn cap_change(new_diff: &BigUint, last_diff: &BigUint) -> BigUint {
    if new_diff > last_diff {
        // Cap at 150% of last
        let max = last_diff * 3u32 / 2u32;
        if *new_diff > max {
            max
        } else {
            new_diff.clone()
        }
    } else {
        // Cap at 50% of last
        let min = last_diff / 2u32;
        if *new_diff < min {
            min
        } else {
            new_diff.clone()
        }
    }
}

/// Linear least-squares interpolation using signed BigInt arithmetic.
/// y = a + b*x, evaluated at x = max(data.x) + epoch_length.
/// Matches Scala `DifficultyAdjustment.interpolate` exactly.
fn interpolate(data: &[(u32, BigUint)], epoch_length: u32) -> BigUint {
    use num_bigint::BigInt;
    let size = data.len();
    if size == 1 {
        return data[0].1.clone();
    }

    let precision = BigInt::from(PRECISION);
    let n = BigInt::from(size);

    let xy_sum: BigInt = data
        .iter()
        .map(|(x, y)| BigInt::from(*x) * BigInt::from(y.clone()))
        .sum();
    let x_sum: BigInt = data.iter().map(|(x, _)| BigInt::from(*x)).sum();
    let x2_sum: BigInt = data
        .iter()
        .map(|(x, _)| BigInt::from(*x) * BigInt::from(*x))
        .sum();
    let y_sum: BigInt = data.iter().map(|(_, y)| BigInt::from(y.clone())).sum();

    let denom = &x2_sum * &n - &x_sum * &x_sum;
    if denom == BigInt::ZERO {
        return data.last().unwrap().1.clone();
    }

    let b = (&xy_sum * &n - &x_sum * &y_sum) * &precision / &denom;
    let a = (&y_sum * &precision - &b * &x_sum) / &n / &precision;

    let point = BigInt::from(data.iter().map(|(x, _)| *x).max().unwrap() + epoch_length);
    let result = &a + &b * &point / &precision;

    result.to_biguint().unwrap_or(BigUint::ZERO)
}

/// Compute required difficulty using network-specific config, returning a
/// structured error rather than panicking on caller misuse.
///
/// Reads epoch length, EIP-37 activation, and v2 activation from the
/// supplied [`DifficultyParams`]. Enforces `parent.height + 1 == child_height`
/// and the EIP-37 window-size precondition. Retarget windows must have
/// increasing heights/timestamps and representable interpolation heights.
/// The caller remains responsible for supplying the actual chain ancestors.
///
/// Errors:
/// - [`DifficultyError::MissingEpochHeaders`] — empty slice, or an EIP-37
///   recalculation height with fewer than 2 headers (the EIP-37 branch
///   needs at least the parent and the previous epoch boundary).
/// - [`DifficultyError::HeightMismatch`] — `parent.height + 1 != child_height`.
/// - [`DifficultyError::HeightOverflow`] — the child or interpolation height
///   cannot be represented as u32.
/// - [`DifficultyError::InvalidConfiguration`] — a used epoch/interval is zero.
/// - [`DifficultyError::InvalidEpochWindow`] — retarget heights/times do not
///   increase. Correct epoch selection and ancestry remain caller obligations.
pub(crate) fn required_difficulty_checked(
    child_height: u32,
    epoch_headers: &[Header],
    config: &DifficultyParams,
) -> Result<BigUint, DifficultyError> {
    let parent = epoch_headers
        .last()
        .ok_or(DifficultyError::MissingEpochHeaders)?;
    let parent_height = parent.height;
    let expected_child = parent_height
        .checked_add(1)
        .ok_or(DifficultyError::HeightOverflow {
            height: parent_height,
            increment: 1,
        })?;
    if expected_child != child_height {
        return Err(DifficultyError::HeightMismatch {
            expected: expected_child,
            actual: child_height,
        });
    }

    // v2 activation special case: return fixed initial difficulty when
    // the parent IS the v2 activation block, or when the child IS it.
    // Matches Scala: parentHeight == v2ActivationHeight || parent.height + 1 == v2ActivationHeight.
    // Networks with no v1 → v2 hardfork (e.g. new public testnet, which
    // launches at Interpreter60Version block version) carry
    // `v2_activation = None` and skip the special case entirely.
    if let Some(v2) = &config.v2_activation {
        if parent_height == v2.height || expected_child == v2.height {
            return Ok(BigUint::from_bytes_be(&v2.initial_difficulty));
        }
    }

    let initial_diff = BigUint::from_bytes_be(&config.initial_difficulty);
    let is_eip37 = config
        .eip37_activation_height
        .is_some_and(|ah| child_height >= ah);
    let epoch_len = if is_eip37 {
        config.eip37_epoch_length.unwrap_or(config.epoch_length)
    } else {
        config.epoch_length
    };
    if epoch_len == 0 {
        return Err(DifficultyError::InvalidConfiguration {
            field: "epoch length",
        });
    }

    if !parent_height.is_multiple_of(epoch_len) {
        return Ok(decode_compact_bits(parent.n_bits));
    }

    if config.desired_interval_ms == 0 {
        return Err(DifficultyError::InvalidConfiguration {
            field: "desired interval",
        });
    }
    for (index, pair) in epoch_headers.windows(2).enumerate() {
        if pair[1].height <= pair[0].height {
            return Err(DifficultyError::InvalidEpochWindow {
                index,
                reason: "heights must increase",
            });
        }
        if pair[1].timestamp <= pair[0].timestamp {
            return Err(DifficultyError::InvalidEpochWindow {
                index,
                reason: "timestamps must increase",
            });
        }
    }
    if epoch_headers.len() > 2 {
        parent_height
            .checked_add(epoch_len)
            .ok_or(DifficultyError::HeightOverflow {
                height: parent_height,
                increment: epoch_len,
            })?;
    }

    if is_eip37 {
        if epoch_headers.len() < 2 {
            return Err(DifficultyError::MissingEpochHeaders);
        }
        Ok(eip37_calculate(
            epoch_headers,
            epoch_len,
            &initial_diff,
            config.desired_interval_ms,
        ))
    } else {
        Ok(calculate(
            epoch_headers,
            epoch_len,
            &initial_diff,
            config.desired_interval_ms,
        ))
    }
}

/// Compute the encoded `nBits` value a candidate block at
/// `child_height` must use, given the same `epoch_headers` window the
/// verifier reads. Wraps `required_difficulty_checked` +
/// [`encode_compact_bits`] so mining can produce the right value
/// without re-implementing the retarget logic.
///
/// Returns the same `DifficultyError` variants as
/// `required_difficulty_checked`.
pub fn next_n_bits(
    child_height: u32,
    epoch_headers: &[Header],
    config: &DifficultyParams,
) -> Result<u32, DifficultyError> {
    let diff = required_difficulty_checked(child_height, epoch_headers, config)?;
    Ok(encode_compact_bits(&diff))
}

/// Verify that a header's nBits matches the expected difficulty under
/// the supplied [`DifficultyParams`]. Internal-only — downstream consumers go
/// through [`crate::pow::verify_header_difficulty`].
///
/// Surfaces [`DifficultyError`] for missing/invalid epoch context, arithmetic
/// bounds/configuration, child/parent height mismatch or an actual-vs-expected
/// `nBits` mismatch.
pub(crate) fn verify_nbits(
    child_height: u32,
    epoch_headers: &[Header],
    actual_nbits: u32,
    config: &DifficultyParams,
) -> Result<(), DifficultyError> {
    let expected_diff = required_difficulty_checked(child_height, epoch_headers, config)?;
    let expected_nbits = encode_compact_bits(&expected_diff);
    // Compare values, including the MPI sign, rather than compact encodings.
    // https://github.com/ergoplatform/ergo/blob/v6.0.7/src/main/scala/org/ergoplatform/nodeView/history/storage/modifierprocessors/HeadersProcessor.scala#L423
    if decode_compact_bits_signed(actual_nbits) == num_bigint::BigInt::from(expected_diff) {
        Ok(())
    } else {
        Err(DifficultyError::NbitsMismatch {
            height: child_height,
            expected: expected_nbits,
            actual: actual_nbits,
        })
    }
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

    #[test]
    fn selectors_handle_invalid_and_large_context_without_arithmetic_panics() {
        let mut cfg = DifficultyParams::mainnet();
        assert!(!is_recalculation_height(0, &cfg));
        assert_eq!(
            previous_heights_for_recalculation(0, 1024),
            Vec::<u32>::new()
        );
        cfg.epoch_length = 0;
        assert!(!is_recalculation_height(1, &cfg));
        assert_eq!(previous_heights_for_recalculation(1, 0), Vec::<u32>::new());
        assert_eq!(
            previous_heights_for_recalculation(u32::MAX, u32::MAX - 1),
            vec![0, u32::MAX - 1]
        );
    }

    #[test]
    fn checked_difficulty_reports_invalid_caller_context() {
        let base = load_header_at("../test-vectors/mainnet/headers_1_2000.json", 1024);
        let mut parent = base.clone();
        parent.height = u32::MAX;
        assert!(matches!(
            next_n_bits(0, &[parent], &DifficultyParams::mainnet()),
            Err(DifficultyError::HeightOverflow {
                height: u32::MAX,
                increment: 1
            })
        ));
        let mut cfg = DifficultyParams::mainnet();
        cfg.epoch_length = 0;
        assert!(matches!(
            next_n_bits(1025, std::slice::from_ref(&base), &cfg),
            Err(DifficultyError::InvalidConfiguration {
                field: "epoch length"
            })
        ));
        cfg.epoch_length = 1024;
        cfg.desired_interval_ms = 0;
        assert!(matches!(
            next_n_bits(1025, std::slice::from_ref(&base), &cfg),
            Err(DifficultyError::InvalidConfiguration {
                field: "desired interval"
            })
        ));

        cfg.desired_interval_ms = 120_000;
        let make_header = |height, timestamp| {
            let mut h = base.clone();
            h.height = height;
            h.timestamp = timestamp;
            h
        };
        for last_time in [1000, 999] {
            let window = [
                make_header(0, 0),
                make_header(1024, 1000),
                make_header(2048, last_time),
            ];
            assert!(matches!(
                next_n_bits(2049, &window, &cfg),
                Err(DifficultyError::InvalidEpochWindow {
                    index: 1,
                    reason: "timestamps must increase"
                })
            ));
        }
        let duplicated = [
            make_header(0, 0),
            make_header(1024, 1000),
            make_header(1024, 2000),
        ];
        assert!(matches!(
            next_n_bits(1025, &duplicated, &cfg),
            Err(DifficultyError::InvalidEpochWindow {
                index: 1,
                reason: "heights must increase"
            })
        ));
        cfg.epoch_length = 2;
        cfg.eip37_activation_height = None;
        let window = [
            make_header(u32::MAX - 5, 1000),
            make_header(u32::MAX - 3, 2000),
            make_header(u32::MAX - 1, 3000),
        ];
        assert!(
            matches!(next_n_bits(u32::MAX, &window, &cfg), Err(DifficultyError::HeightOverflow { height, increment: 2 }) if height == u32::MAX - 1)
        );
    }

    // ----- happy path -----

    #[test]
    fn get_target_returns_nonzero_for_valid_nbits() {
        let target = get_target(0x1a_01_76_5e);
        assert!(target > BigUint::ZERO);
    }

    #[test]
    fn epoch_length_for_height_switches_at_eip37_boundary() {
        let cfg = DifficultyParams::mainnet();
        // Mainnet: pre-EIP-37 1024-block epochs, post-EIP-37 128-block
        // epochs, switch at height 844_673.
        assert_eq!(epoch_length_for_height(1, &cfg), 1024);
        assert_eq!(epoch_length_for_height(844_672, &cfg), 1024);
        assert_eq!(epoch_length_for_height(844_673, &cfg), 128);
        assert_eq!(epoch_length_for_height(1_000_000, &cfg), 128);
    }

    #[test]
    fn is_recalculation_height_uses_child_regime_at_eip37_boundary() {
        // Discriminating test: the predicate must select the epoch length
        // for the *child*'s regime, not the parent's. A wrong implementation
        // that read `epoch_length_for_height(parent_height, cfg)` would
        // diverge here.
        //
        // Synthetic config: pre = 10, post = 7, activation = 8.
        // - child = 8 (first post-activation block), parent = 7.
        // - correct rule: epoch_len for child 8 = post = 7; 7 % 7 == 0 ⇒ TRUE.
        // - wrong rule:   epoch_len for parent 7 = pre  = 10; 7 % 10 != 0 ⇒ FALSE.
        // Picking pre/post that are coprime at the boundary parent height
        // is what makes the two paths visibly disagree.
        let cfg = DifficultyParams {
            epoch_length: 10,
            eip37_epoch_length: Some(7),
            eip37_activation_height: Some(8),
            v2_activation: Some(ergo_chain_spec::V2Activation {
                height: 100,
                initial_difficulty: vec![0x01],
            }),
            initial_difficulty: vec![0x01],
            desired_interval_ms: 120_000,
            use_last_epochs: 8,
        };
        assert!(
            is_recalculation_height(8, &cfg),
            "child = activation must use post epoch_len (7) and recognize parent (7) as boundary"
        );
        // child = 9, parent = 8: 8 % 7 == 1, NOT a recalc height
        assert!(!is_recalculation_height(9, &cfg));
        // Mainnet sanity at the EIP-37 boundary (non-discriminating but documents
        // expected behavior on the real config).
        let mainnet = DifficultyParams::mainnet();
        assert!(is_recalculation_height(844_673, &mainnet));
        assert!(!is_recalculation_height(844_674, &mainnet));
    }

    #[test]
    fn cap_change_clamps_to_50_to_150_percent_of_last() {
        let last = BigUint::from(1000u32);
        // Within range
        assert_eq!(
            cap_change(&BigUint::from(1200u32), &last),
            BigUint::from(1200u32)
        );
        // Cap at 150%
        assert_eq!(
            cap_change(&BigUint::from(2000u32), &last),
            BigUint::from(1500u32)
        );
        // Cap at 50%
        assert_eq!(
            cap_change(&BigUint::from(100u32), &last),
            BigUint::from(500u32)
        );
    }

    #[test]
    fn interpolate_single_data_point_returns_input_value() {
        let data = vec![(1024u32, BigUint::from(100u32))];
        assert_eq!(interpolate(&data, 1024), BigUint::from(100u32));
    }

    #[test]
    fn previous_heights_epoch_length_one_matches_scala_height_bound() {
        // Scala: `(height - 1) % 1 == 0 && height > 1 * useLastEpochs`.
        assert_eq!(
            previous_heights_for_recalculation(9, 1),
            (0..=8).collect::<Vec<u32>>()
        );
        assert_eq!(previous_heights_for_recalculation(8, 1), vec![7]);
    }

    #[test]
    fn previous_heights_non_boundary_returns_just_parent() {
        let heights = previous_heights_for_recalculation(500, 1024);
        assert_eq!(heights, vec![499]);
    }

    #[test]
    fn previous_heights_at_boundary_returns_full_window() {
        // Height 1025: parent is 1024, which is 1024 % 1024 == 0
        let heights = previous_heights_for_recalculation(1025, 1024);
        assert_eq!(heights, vec![0, 1024]);
    }

    // ----- error paths -----

    #[test]
    fn required_difficulty_checked_empty_headers_errors_missing() {
        let cfg = DifficultyParams::mainnet();
        match required_difficulty_checked(1, &[], &cfg) {
            Err(DifficultyError::MissingEpochHeaders) => {}
            other => panic!("expected MissingEpochHeaders, got {other:?}"),
        }
    }

    #[test]
    fn required_difficulty_checked_height_mismatch_errors() {
        let parent = load_header_at("../test-vectors/mainnet/headers_1_2000.json", 100);
        let child_height = parent.height + 5;
        let cfg = DifficultyParams::mainnet();
        match required_difficulty_checked(child_height, std::slice::from_ref(&parent), &cfg) {
            Err(DifficultyError::HeightMismatch { expected, actual }) => {
                assert_eq!(expected, parent.height + 1);
                assert_eq!(actual, child_height);
            }
            other => panic!("expected HeightMismatch, got {other:?}"),
        }
    }

    #[test]
    fn required_difficulty_checked_eip37_undersized_window_errors_missing() {
        // EIP-37 epoch-boundary parent (1_761_792 = 13_764 * 128) with a
        // window of just `[parent]`. Pre-Phase-1 this hit
        // `eip37_calculate`'s `assert!(len >= 2)` and panicked; the
        // helper must now intercept and return MissingEpochHeaders.
        let parent = load_header_at(
            "../test-vectors/mainnet/headers_1761792_1761795_eip37_curated.json",
            1_761_792,
        );
        // Post-EIP-37 epoch boundary on mainnet is every 128 blocks.
        assert_eq!(parent.height % 128, 0);
        let child_height = parent.height + 1;
        let cfg = DifficultyParams::mainnet();
        match required_difficulty_checked(child_height, std::slice::from_ref(&parent), &cfg) {
            Err(DifficultyError::MissingEpochHeaders) => {}
            other => panic!("expected MissingEpochHeaders, got {other:?}"),
        }
    }

    #[test]
    fn next_n_bits_non_boundary_matches_parent_n_bits() {
        // Non-recalc height: required difficulty == decode(parent.n_bits),
        // so encoded `next_n_bits` must equal parent.n_bits verbatim. Pick
        // a non-boundary mainnet height and confirm round-trip.
        let parent = load_header_at("../test-vectors/mainnet/headers_1_2000.json", 100);
        let child_height = parent.height + 1;
        let cfg = DifficultyParams::mainnet();
        let next = next_n_bits(child_height, std::slice::from_ref(&parent), &cfg)
            .expect("non-boundary next_n_bits");
        assert_eq!(next, parent.n_bits);
    }

    #[test]
    fn verify_nbits_empty_headers_errors_missing() {
        let cfg = DifficultyParams::mainnet();
        match verify_nbits(1, &[], 0x1a_01_76_5e, &cfg) {
            Err(DifficultyError::MissingEpochHeaders) => {}
            other => panic!("expected MissingEpochHeaders, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod use_last_epochs_agreement {
    use super::*;

    /// The interpolator's module constant and the chain-spec field must
    /// agree — the popow paths consume `DifficultyParams.use_last_epochs`
    /// while the consensus difficulty math (this module) keeps its
    /// private const because no supported network varies it. If a chain
    /// ever ships a different value, this test forces the interpolator
    /// to grow config plumbing rather than silently diverging.
    #[test]
    fn chain_spec_field_matches_interpolator_constant() {
        assert_eq!(DifficultyParams::mainnet().use_last_epochs, USE_LAST_EPOCHS);
        assert_eq!(DifficultyParams::testnet().use_last_epochs, USE_LAST_EPOCHS);
    }
}
