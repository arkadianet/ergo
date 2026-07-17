use ergo_crypto::autolykos::common::{blake2b256, calc_n};
use ergo_crypto::autolykos::v1::secp256k1_order;
use ergo_crypto::autolykos::v2::hit_for_v2;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::difficulty::decode_compact_bits;
use ergo_ser::header::{serialize_header_without_pow, Header};
use num_bigint::BigUint;
use num_traits::ToPrimitive;

use super::is_genesis;

/// Sentinel μ-level for genesis. Matches Scala's `Int.MaxValue`
/// (`NipopowAlgos.scala:75`). A genesis header is at infinite level
/// because its required-target / real-target ratio is degenerate
/// and the consensus definition assigns it the top of the lattice.
pub const GENESIS_LEVEL: u32 = u32::MAX;

/// μ-level of `header` per KMZ17 §2.2:
///
/// ```text
/// μ = log2(requiredTarget) - log2(realTarget)
/// requiredTarget = q / decode_compact_bits(nBits)
/// realTarget     = powHit(header)
/// ```
///
/// `q` is the secp256k1 group order (Autolykos `Q`). `powHit` is the
/// header's PoW hit value: for header version 1 it is the
/// solution's `d` component; for v2+ it is the
/// `hit_for_v2(msg, nonce, height, n)` value where
/// `msg = Blake2b256(header bytes without PoW)`.
///
/// Genesis returns [`GENESIS_LEVEL`].
///
/// Returns `0` if either target is non-positive after `BigUint -> f64`
/// conversion (defensive — would indicate corrupt nBits or a hit of
/// zero). The Scala `.toInt` truncation on a negative `log2` diff is
/// matched by clamping to `0` here, since unsigned `u32::from`
/// otherwise wraps.
///
/// Scala source: `NipopowAlgos.scala:68-76`.
pub fn max_level_of(header: &Header) -> u32 {
    if is_genesis(header) {
        return GENESIS_LEVEL;
    }

    let required_target = secp256k1_order() / decode_compact_bits(header.n_bits);
    // If pow_hit can't serialize the header (unreachable from honest
    // callers — pre-gates filter), fall through to level 0 (the same
    // defensive return used below for non-positive targets and
    // non-finite log diffs). This keeps `max_level_of` infallible
    // without re-introducing a panic.
    let real_target = match pow_hit(header) {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!(error = ?e, "popow: pow_hit failed in max_level_of; degrading header to level 0");
            return 0;
        }
    };

    let required_f = biguint_to_f64(&required_target);
    let real_f = biguint_to_f64(&real_target);

    if required_f <= 0.0 || real_f <= 0.0 {
        tracing::debug!(
            required_f,
            real_f,
            "popow: non-positive target in max_level_of; degrading header to level 0"
        );
        return 0;
    }

    let level = required_f.log2() - real_f.log2();
    if !level.is_finite() || level <= 0.0 {
        tracing::debug!(level, "popow: non-finite or non-positive mu-level in max_level_of; degrading header to level 0");
        return 0;
    }
    level as u32
}

/// Best argument score for `chain` under minimum-superchain-length `m`.
/// Iterates μ-levels from 0 upward, accumulating `(level, count_at_or_above)`
/// for each level whose super-chain has length ≥ `m`. Level 0 is always
/// accumulated with `count = chain.len()`. Returns the maximum of
/// `2^level * count` over the accumulated pairs.
///
/// KMZ17 Algorithm 4. Scala source: `NipopowAlgos.scala:98-111`.
///
/// `u64` return covers any realistic chain × level product without
/// overflow; Scala returns `Int` and would overflow at extreme inputs.
/// Empty chain returns `0` (level 0 contributes `2^0 * 0 = 0`; no
/// higher level reaches the m-cutoff).
pub fn best_arg(chain: &[Header], m: u32) -> u64 {
    // `max_level_of` is a deterministic function of the header, so
    // computing each level once and scoring over the vector is
    // score-identical to the previous per-level recomputation.
    let levels: Vec<u32> = chain.iter().map(max_level_of).collect();
    best_arg_from_levels(&levels, m)
}

/// [`best_arg`] over pre-computed μ-levels instead of headers — the
/// same KMZ17 Algorithm 4 score for callers that track per-header
/// levels without retaining full `Header`s (e.g. a light
/// header-follower scoring its own followed chain against a NiPoPoW
/// proof). `levels[i]` must be `max_level_of` of the i-th chain
/// header; the genesis sentinel [`GENESIS_LEVEL`] participates in
/// every level's count, exactly as the header form does.
pub fn best_arg_from_levels(levels: &[u32], m: u32) -> u64 {
    let mut best: u64 = 0;

    // Level 0: always included with count = levels.len(). Every header
    // is by definition at least level 0; Scala explicitly skips the
    // m-cutoff at level 0 (`NipopowAlgos.scala:101-102`).
    let level_0_count = levels.len() as u64;
    best = best.max(level_0_count); // 2^0 * count

    let mut level: u32 = 1;
    loop {
        let count = levels.iter().filter(|&&l| l >= level).count() as u64;
        if count < m as u64 {
            return best;
        }
        // 2^level * count, saturating at u64::MAX so a hypothetical
        // 2^64 wrap-around can't underestimate the score.
        let score = (1u64)
            .checked_shl(level)
            .unwrap_or(u64::MAX)
            .saturating_mul(count);
        if score > best {
            best = score;
        }
        // u32 level cap: a chain whose every header has level ≥ 32 is
        // already at score ~chain.len() * 2^32. Beyond that we'd need
        // u64 levels, which KMZ17 does not produce in practice. Cap
        // here defensively rather than overflowing the shift.
        if level == u32::MAX {
            return best;
        }
        level += 1;
    }
}

/// `powHit(header)` per Scala `AutolykosPowScheme.scala:219-225`:
/// v1 reads `header.solution.d`; v2+ computes `hit_for_v2`.
fn pow_hit(header: &Header) -> Result<BigUint, ergo_ser::error::WriteError> {
    match &header.solution {
        AutolykosSolution::V1 { d, .. } => Ok(BigUint::from_bytes_be(d)),
        AutolykosSolution::V2 { nonce, .. } => {
            // Same pre-gate as `header_id` in the parent module.
            // Returning Result lets `max_level_of` degrade to level 0
            // ("not a μ-level qualifier") instead of panicking when
            // production callers hit malformed headers.
            let header_bytes = serialize_header_without_pow(header)?;
            let msg = blake2b256(&header_bytes);
            let n = calc_n(header.version, header.height);
            Ok(hit_for_v2(&msg, nonce, header.height, n))
        }
    }
}

fn biguint_to_f64(v: &BigUint) -> f64 {
    v.to_f64().unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::read_header;

    // ----- helpers -----

    /// Deserialize a hex-encoded header. Panics on bad hex / decode.
    fn header_from_hex(hex_bytes: &str) -> Header {
        let raw = hex::decode(hex_bytes).expect("valid hex");
        let mut r = VlqReader::new(&raw);
        read_header(&mut r).expect("valid header bytes")
    }

    /// Mainnet genesis header (height 1). Used by `is_genesis` /
    /// `max_level_of` genesis-path tests. Sourced from
    /// `test-vectors/mainnet/headers_1_10.json[0]`.
    const GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b";

    /// Mainnet height 2 (v1 Autolykos, non-genesis). Used by
    /// `max_level_of` non-genesis-path tests for the v1 branch.
    /// Sourced from `headers_1_10.json[1]`.
    const HEIGHT_2_V1_HEX: &str = "01b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b828b0f6a0e6cb98ed4649c6e4cc00599ae78755324c79a8cec51e94ecca339d7a3a11a92de9c0ba1e95068f39bc1e08afa4ca23dff16de135fac64d0cf7dd1ab6291b70477f591ee8efb8a962d36ddbe3ac57591e39fe45ffb8c51c4939e41980387d9cfe9ba2d6b46bcba6f750f5be67d89679e921b78c277c5546a08cdb0955376fa0ea271e30601176502000000033c46c7fd7085638bf4bc902badb4e5a1942d3251d92d0eddd6fbe5d57e91553703df646d7f6138aede718a2a4f1a76d4125750e8ab496b7a8a25292d07e14cbadb0000000a03d0d0191b06164a2e86a170f0d8ac96cffa2e3312f2f5b0b1c3b1e082b9a0cd";

    // ----- happy path -----

    #[test]
    fn max_level_of_genesis_returns_sentinel() {
        let h = header_from_hex(GENESIS_HEX);
        assert_eq!(max_level_of(&h), GENESIS_LEVEL);
    }

    #[test]
    fn max_level_of_non_genesis_v1_returns_finite_level() {
        // Height 2: real mainnet v1 header. We don't pin a specific
        // level value here (no Scala-extracted oracle vector is
        // available for this height yet); instead we pin that the
        // function:
        //   * does not panic
        //   * returns a finite value (< GENESIS_LEVEL)
        //   * returns 0 or more (no underflow/wraparound)
        let h = header_from_hex(HEIGHT_2_V1_HEX);
        let level = max_level_of(&h);
        assert!(level < GENESIS_LEVEL, "level should be finite, got {level}");
    }

    #[test]
    fn best_arg_empty_chain_returns_zero() {
        let score = best_arg(&[], 2);
        assert_eq!(score, 0);
    }

    #[test]
    fn best_arg_single_genesis_chain_returns_one_at_level_zero() {
        // Genesis has max_level_of == u32::MAX. For m=2, the level-0
        // count is 1 (< m). Higher levels would all pass the filter
        // (genesis satisfies any level), but the count there is also
        // 1 < m, so the loop terminates immediately after level 0.
        // The level-0 entry contributes 2^0 * 1 = 1.
        let h = header_from_hex(GENESIS_HEX);
        let score = best_arg(std::slice::from_ref(&h), 2);
        assert_eq!(score, 1);
    }

    #[test]
    fn best_arg_from_levels_matches_header_form_on_real_headers() {
        // The refactor-parity pin: `best_arg` must equal
        // `best_arg_from_levels` over `max_level_of`-derived levels for
        // real headers, for several m values.
        let chain = vec![
            header_from_hex(GENESIS_HEX),
            header_from_hex(HEIGHT_2_V1_HEX),
        ];
        let levels: Vec<u32> = chain.iter().map(max_level_of).collect();
        for m in [1u32, 2, 6] {
            assert_eq!(best_arg(&chain, m), best_arg_from_levels(&levels, m));
        }
    }

    #[test]
    fn best_arg_from_levels_empty_returns_zero() {
        assert_eq!(best_arg_from_levels(&[], 2), 0);
    }

    #[test]
    fn best_arg_from_levels_level_zero_skips_m_cutoff() {
        // One level-0 header with m=6: level 0 always counts
        // (2^0 * 1 = 1) even though 1 < m.
        assert_eq!(best_arg_from_levels(&[0], 6), 1);
    }

    #[test]
    fn best_arg_from_levels_scores_superchain_over_length() {
        // Six level-3 headers with m=2: level 3 passes the cutoff
        // (count 6 >= 2) and scores 2^3 * 6 = 48, beating the level-0
        // score of 6. A longer all-level-0 chain of 20 scores only 20.
        assert_eq!(best_arg_from_levels(&[3; 6], 2), 48);
        assert_eq!(best_arg_from_levels(&[0; 20], 2), 20);
    }

    #[test]
    fn best_arg_from_levels_m_cutoff_stops_at_thin_level() {
        // Levels [2, 2, 0]: at level 1 and 2 the count is 2 >= m=2
        // (score 2^2 * 2 = 8); at level 3 the count 0 < m stops the
        // loop. Max(3, 4, 8) = 8.
        assert_eq!(best_arg_from_levels(&[2, 2, 0], 2), 8);
        // Same levels with m=3: count 2 < 3 already at level 1, so
        // only level 0 contributes.
        assert_eq!(best_arg_from_levels(&[2, 2, 0], 3), 3);
    }
}
