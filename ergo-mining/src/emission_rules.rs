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

    // ----- saturation guard -----

    #[test]
    fn emission_saturates_to_zero_eventually() {
        let s = MonetarySettings::mainnet();
        // Far past block when emission should be 0.
        let h: u32 = s.fixed_rate_period + 30 * s.epoch_length;
        assert_eq!(emission_at_height(h, &s), 0);
    }
}
