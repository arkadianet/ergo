//! Per-height emission math.
//!
//! Direct Rust port of Scala `EmissionRules` from
//! `sigmastate-interpreter/.../mining/emission/EmissionRules.scala`.
//! Mainnet constants are pinned from `application.conf`:
//!
//! | Constant              | Value          | Source                          |
//! |---|---|---|
//! | `fixedRate`           | 75 × 1e9 nERG  | `application.conf:178`          |
//! | `fixedRatePeriod`     | 525,600 blocks | `application.conf:176`          |
//! | `epochLength`         | 64,800 blocks  | `application.conf:182`          |
//! | `oneEpochReduction`   | 3 × 1e9 nERG   | `application.conf:184`          |
//! | `foundersInitialReward`| 7.5 × 1e9 nERG| `application.conf:180`          |
//! | `minerRewardDelay`    | 720 blocks     | `application.conf:186`          |
//!
//! Byte-parity verified against captured mainnet emission-tx outputs
//! at heights 1,700,000–1,786,180 (see `tests` below).

/// 10⁹ nanoERG per ERG. From `EmissionRules.CoinsInOneErgo` (`EmissionRules.scala:129`).
pub const COINS_IN_ONE_ERGO: u64 = 1_000_000_000;

/// Per-network monetary parameters (fixed-rate window, per-epoch
/// reduction, founder split, miner reward delay). Re-exported from
/// `ergo-chain-spec` so existing consumers see the same name while
/// the type lives in the chain-spec crate.
pub use ergo_chain_spec::MonetaryParams as MonetarySettings;

/// Per-height total emission. Mirror of `EmissionRules.emissionAtHeight`
/// (`EmissionRules.scala:67-74`).
///
/// Below `fixed_rate_period`: returns `fixed_rate` flat.
/// At/above: per-epoch reduction starting from epoch 1, clamped at 0.
pub fn emission_at_height(h: u32, s: &MonetarySettings) -> u64 {
    if h < s.fixed_rate_period {
        s.fixed_rate
    } else {
        let epoch = 1 + u64::from(h - s.fixed_rate_period) / u64::from(s.epoch_length);
        s.fixed_rate
            .saturating_sub(s.one_epoch_reduction.saturating_mul(epoch))
    }
}

/// Per-height miner share. Mirror of `EmissionRules.minersRewardAtHeight`
/// (`EmissionRules.scala:79-86`).
///
/// During the foundation-funded window (`h < fixed_rate_period + 2 * epoch_length`),
/// miner gets `fixed_rate - founders_initial_reward`. After that, miner gets
/// the full per-height emission (foundation share has stopped).
pub fn miners_reward_at_height(h: u32, s: &MonetarySettings) -> u64 {
    let minersfixed_end = s.fixed_rate_period + 2 * s.epoch_length;
    if h < minersfixed_end {
        s.fixed_rate - s.founders_initial_reward
    } else {
        let epoch = 1 + u64::from(h - s.fixed_rate_period) / u64::from(s.epoch_length);
        s.fixed_rate
            .saturating_sub(s.one_epoch_reduction.saturating_mul(epoch))
    }
}

/// Cumulative coins issued at height `h` and before. Mirror of
/// `EmissionRules.issuedCoinsAfterHeight` (`EmissionRules.scala:42-60`).
///
/// Note the fixed-rate term `fixed_rate * (fixed_rate_period - 1)`:
/// heights are 1-based and the block AT `fixed_rate_period` is already
/// the first epoch-1 (reduced) block, so only `fixed_rate_period - 1`
/// full-rate blocks exist. The `h < fixed_rate_period` branch counts
/// `h` blocks directly (so `h = fixed_rate_period - 1` and the boundary
/// agree). Pinned by the live-Scala oracle vector at h = 525_600.
pub fn issued_coins_after_height(h: u32, s: &MonetarySettings) -> u64 {
    if h < s.fixed_rate_period {
        s.fixed_rate * u64::from(h)
    } else {
        let fixed_rate_issue = s.fixed_rate * u64::from(s.fixed_rate_period - 1);
        let epoch = u64::from(h - s.fixed_rate_period) / u64::from(s.epoch_length);
        // Σ over complete epochs of max(fixed_rate − reduction·e, 0) ·
        // epoch_length. Once the rate clamps to 0 every later term is 0
        // too, so the early break is arithmetically identical to
        // Scala's full `(1 to epoch).map(...).sum`.
        let mut full_epochs_issued = 0u64;
        for e in 1..=epoch {
            let rate = s
                .fixed_rate
                .saturating_sub(s.one_epoch_reduction.saturating_mul(e));
            if rate == 0 {
                break;
            }
            full_epochs_issued += rate * u64::from(s.epoch_length);
        }
        let height_in_this_epoch =
            u64::from(h - s.fixed_rate_period) % u64::from(s.epoch_length) + 1;
        let rate_this_epoch = s
            .fixed_rate
            .saturating_sub(s.one_epoch_reduction.saturating_mul(epoch + 1));
        fixed_rate_issue + full_epochs_issued + height_in_this_epoch * rate_this_epoch
    }
}

/// Total coins ever emitted and the last height with positive emission.
/// Mirror of the Scala lazy pair `EmissionRules.{coinsTotal, blocksTotal}`
/// (`EmissionRules.scala:22-34`) — a verbatim port of its walk from
/// height 1 until `emissionAtHeight` first returns 0 (mainnet: ~2.08M
/// trivial iterations, microseconds in release; callers cache the result).
pub fn coins_and_blocks_total(s: &MonetarySettings) -> (u64, u32) {
    let mut acc = 0u64;
    let mut h = 1u32;
    loop {
        let rate = emission_at_height(h, s);
        if rate == 0 {
            return (acc, h - 1);
        }
        acc += rate;
        h += 1;
    }
}

/// One `/emission/at/{height}` row: plain numbers, no serde — the API
/// crate owns the JSON shape. Field semantics mirror Scala
/// `EmissionApiRoute.EmissionInfo` (`EmissionApiRoute.scala:65-69`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmissionInfo {
    pub height: u32,
    pub miner_reward: u64,
    pub total_coins_issued: u64,
    pub total_remain_coins: u64,
    pub reemitted: u64,
}

/// Scala-parity composition for `/emission/at/{height}`. Mirror of
/// `EmissionApiRoute.emissionInfoAtHeight` (`EmissionApiRoute.scala:71-79`):
///
/// ```text
/// reemitted        = reemissionForHeight(h)
/// minerReward      = minersRewardAtHeight(h) − reemitted
/// totalCoinsIssued = issuedCoinsAfterHeight(h)
/// totalRemainCoins = coinsTotal − totalCoinsIssued
/// ```
///
/// `coins_total` is passed in precomputed (Scala caches it as a lazy
/// val; callers here cache [`coins_and_blocks_total`] at boot).
///
/// `r = None` (a chain spec without EIP-27 reemission, e.g. synthetic
/// dev chains) means `reemitted` is always 0 and `minerReward` is the
/// plain pre-EIP-27 share — mirroring a Scala node with reemission
/// disabled.
pub fn emission_info_at_height(
    h: u32,
    s: &MonetarySettings,
    r: Option<&crate::reemission::ReemissionSettings>,
    coins_total: u64,
) -> EmissionInfo {
    let reemitted = r.map_or(0, |r| crate::reemission::reemission_for_height(h, s, r));
    // The EIP-27 charge never exceeds the miner share by construction
    // (12 ERG only while emission ≥ 15 ERG; proportional with a 3 ERG
    // floor below that), so the saturation never fires on real params —
    // it exists so absurd custom params clamp instead of panicking.
    let miner_reward = miners_reward_at_height(h, s).saturating_sub(reemitted);
    let total_coins_issued = issued_coins_after_height(h, s);
    let total_remain_coins = coins_total.saturating_sub(total_coins_issued);
    EmissionInfo {
        height: h,
        miner_reward,
        total_coins_issued,
        total_remain_coins,
        reemitted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct RewardBoxVector {
        height: u32,
        reward_box: RewardBoxFields,
    }
    #[derive(Deserialize)]
    struct RewardBoxFields {
        value: u64,
        #[allow(dead_code)]
        creation_height: u32,
        #[allow(dead_code)]
        ergo_tree_hex: String,
    }

    fn load(h: u32) -> RewardBoxVector {
        let path = format!(
            "{}/../test-vectors/mining/reward_boxes/{}.json",
            env!("CARGO_MANIFEST_DIR"),
            h
        );
        let bytes = std::fs::read(&path).expect("read");
        serde_json::from_slice(&bytes).expect("parse")
    }

    // ----- happy path -----

    #[test]
    fn miners_reward_matches_captured_mainnet_boxes() {
        let s = MonetarySettings::mainnet();
        let heights = [
            1_700_000u32,
            1_720_000,
            1_740_000,
            1_760_000,
            1_770_000,
            1_780_000,
            1_783_000,
            1_785_000,
            1_786_000,
            1_786_180,
        ];
        for h in heights {
            let v = load(h);
            assert_eq!(v.height, h);
            let computed = miners_reward_at_height(h, &s);
            assert_eq!(
                computed, v.reward_box.value,
                "h={h}: computed {} != mainnet reward box value {}",
                computed, v.reward_box.value,
            );
        }
    }

    #[test]
    fn fixed_rate_window_returns_full_rate() {
        let s = MonetarySettings::mainnet();
        assert_eq!(emission_at_height(0, &s), s.fixed_rate);
        assert_eq!(emission_at_height(100_000, &s), s.fixed_rate);
        assert_eq!(
            emission_at_height(s.fixed_rate_period - 1, &s),
            s.fixed_rate
        );
    }

    #[test]
    fn first_post_fixed_epoch_loses_one_step() {
        // h = fixed_rate_period: epoch = 1, reward = 75 - 3 = 72 ERG.
        let s = MonetarySettings::mainnet();
        let expected = 72 * COINS_IN_ONE_ERGO;
        assert_eq!(emission_at_height(s.fixed_rate_period, &s), expected);
    }

    #[test]
    fn known_height_1786000_is_15_erg() {
        let s = MonetarySettings::mainnet();
        let expected = 15 * COINS_IN_ONE_ERGO;
        assert_eq!(miners_reward_at_height(1_786_000, &s), expected);
        assert_eq!(emission_at_height(1_786_000, &s), expected);
    }

    #[test]
    fn miner_share_during_founders_window_excludes_founder_cut() {
        let s = MonetarySettings::mainnet();
        let miners_share = s.fixed_rate - s.founders_initial_reward; // 67.5 ERG
        for h in [
            0u32,
            100_000,
            s.fixed_rate_period,
            s.fixed_rate_period + s.epoch_length,
        ] {
            assert_eq!(miners_reward_at_height(h, &s), miners_share, "h={h}");
        }
    }

    #[test]
    fn miner_share_after_founders_window_equals_full_emission() {
        let s = MonetarySettings::mainnet();
        let after = s.fixed_rate_period + 2 * s.epoch_length;
        for h in [after, after + 1, after + 1_000, 1_500_000, 1_800_000] {
            assert_eq!(
                miners_reward_at_height(h, &s),
                emission_at_height(h, &s),
                "h={h}"
            );
        }
    }

    // ----- /emission/at oracle differential -----
    //
    // Vectors captured live from the reference Scala mainnet node
    // (`GET 127.0.0.1:9053/emission/at/{h}`, 2026-06-07, node v6-era)
    // BEFORE the Rust implementation existed — a true external oracle.
    // Heights cover: genesis edge (0, 1), the fixed-rate boundary
    // (525_599 / 525_600 — pins the `fixedRatePeriod − 1` quirk), the
    // founders-window end (655_199 / 655_200), EIP-27 activation
    // (777_216 / 777_217), the 15 ERG era (1_786_000, reemission charge
    // 12 → miner 3), emission end (2_080_799 / 2_080_800), and
    // past-the-end heights where issued must clamp at coinsTotal.

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EmissionAtVector {
        height: u32,
        miner_reward: u64,
        total_coins_issued: u64,
        total_remain_coins: u64,
        reemitted: u64,
    }

    fn load_emission_at(h: u32) -> EmissionAtVector {
        let path = format!(
            "{}/../test-vectors/api/emission/at_{}.json",
            env!("CARGO_MANIFEST_DIR"),
            h
        );
        let bytes = std::fs::read(&path).expect("read emission vector");
        serde_json::from_slice(&bytes).expect("parse emission vector")
    }

    const EMISSION_AT_ORACLE_HEIGHTS: &[u32] = &[
        0, 1, 1000, 525_599, 525_600, 590_400, 655_199, 655_200, 777_216, 777_217, 1_000_000,
        1_786_000, 2_080_799, 2_080_800, 2_143_999, 2_144_000, 3_000_000,
    ];

    #[test]
    fn emission_info_matches_live_scala_oracle() {
        let s = MonetarySettings::mainnet();
        let r = crate::reemission::ReemissionSettings::mainnet();
        let (coins_total, _) = coins_and_blocks_total(&s);
        for &h in EMISSION_AT_ORACLE_HEIGHTS {
            let v = load_emission_at(h);
            assert_eq!(v.height, h, "vector file/height mismatch");
            let info = emission_info_at_height(h, &s, Some(&r), coins_total);
            assert_eq!(info.height, v.height, "height h={h}");
            assert_eq!(info.miner_reward, v.miner_reward, "minerReward h={h}");
            assert_eq!(
                info.total_coins_issued, v.total_coins_issued,
                "totalCoinsIssued h={h}"
            );
            assert_eq!(
                info.total_remain_coins, v.total_remain_coins,
                "totalRemainCoins h={h}"
            );
            assert_eq!(info.reemitted, v.reemitted, "reemitted h={h}");
        }
    }

    #[test]
    fn coins_and_blocks_total_mainnet_pins() {
        // coinsTotal = issued + remain from any oracle row
        // (97_739_925 ERG); blocksTotal: the oracle shows minerReward
        // 3 ERG at 2_080_799 and 0 from 2_080_800 on.
        let s = MonetarySettings::mainnet();
        assert_eq!(
            coins_and_blocks_total(&s),
            (97_739_925_000_000_000, 2_080_799)
        );
    }

    #[test]
    fn issued_coins_fixed_rate_boundary_quirk() {
        // Scala counts only `fixedRatePeriod − 1` full-rate blocks: the
        // block AT the boundary is the first epoch-1 block (72 ERG).
        let s = MonetarySettings::mainnet();
        assert_eq!(issued_coins_after_height(0, &s), 0);
        assert_eq!(
            issued_coins_after_height(s.fixed_rate_period - 1, &s),
            u64::from(s.fixed_rate_period - 1) * s.fixed_rate
        );
        assert_eq!(
            issued_coins_after_height(s.fixed_rate_period, &s),
            u64::from(s.fixed_rate_period - 1) * s.fixed_rate
                + (s.fixed_rate - s.one_epoch_reduction)
        );
    }

    // ----- saturation guard -----

    #[test]
    fn emission_saturates_to_zero_eventually() {
        let s = MonetarySettings::mainnet();
        // Far past block when emission should be 0.
        let h: u32 = s.fixed_rate_period + 30 * s.epoch_length;
        assert_eq!(emission_at_height(h, &s), 0);
    }
}
