//! Ergo emission schedule and re-emission (EIP-27) computations.
//!
//! Pure-computation module implementing the Ergo token emission schedule,
//! including the fixed-rate period, reduction epochs, founders' reward,
//! and EIP-27 re-emission parameters. Used by the `/emission/at/{height}` API.

use serde::Serialize;

// ---------------------------------------------------------------------------
// Constants (mainnet)
// ---------------------------------------------------------------------------

/// Number of nanoErgs in one ERG.
pub const COINS_IN_ONE_ERG: u64 = 1_000_000_000;

/// Number of blocks during the fixed-rate emission period.
pub const FIXED_RATE_PERIOD: u32 = 525_600;

/// Block reward during the fixed-rate period (75 ERG).
pub const FIXED_RATE: u64 = 75 * COINS_IN_ONE_ERG;

/// Emission reduction per epoch after the fixed-rate period (3 ERG).
pub const ONE_EPOCH_REDUCTION: u64 = 3 * COINS_IN_ONE_ERG;

/// Number of blocks in each reduction epoch.
pub const EPOCH_LENGTH: u32 = 64_800;

/// Initial founders' reward per block (7.5 ERG = 10% of fixed rate).
pub const FOUNDERS_INITIAL_REWARD: u64 = FIXED_RATE / 10;

/// Total supply of nanoErgs that will ever be emitted (97,739,925 ERG).
pub const COINS_TOTAL: u64 = 97_739_925_000_000_000;

// ---------------------------------------------------------------------------
// Re-emission (EIP-27) constants
// ---------------------------------------------------------------------------

/// Height at which re-emission rules activate.
pub const REEMISSION_ACTIVATION_HEIGHT: u32 = 777_217;

/// Height at which the re-emission fund starts paying out.
pub const REEMISSION_START_HEIGHT: u32 = 2_080_800;

/// Re-emission reward per block (3 ERG).
pub const REEMISSION_REWARD: u64 = 3 * COINS_IN_ONE_ERG;

/// Basic storage-rent charge amount deducted for the re-emission fund (12 ERG).
pub const BASIC_CHARGE_AMOUNT: u64 = 12 * COINS_IN_ONE_ERG;

// ---------------------------------------------------------------------------
// EmissionInfo
// ---------------------------------------------------------------------------

/// Full emission information at a given height, suitable for JSON serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmissionInfo {
    /// Block height.
    pub height: u32,
    /// Miner reward at this height (after founders' share and re-emission charge).
    pub miner_reward: u64,
    /// Total coins issued through this height (cumulative).
    pub total_coins_issued: u64,
    /// Coins remaining to be issued.
    pub total_remaining_coins: u64,
}

// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------

/// Total block emission at height `h` (before any splits).
///
/// During the fixed-rate period (`h < FIXED_RATE_PERIOD`) this is 75 ERG.
/// After that, the emission decreases by 3 ERG per epoch until it reaches zero.
pub fn emission_at_height(h: u32) -> u64 {
    if h < FIXED_RATE_PERIOD {
        FIXED_RATE
    } else {
        let epoch = 1 + (h - FIXED_RATE_PERIOD) / EPOCH_LENGTH;
        let reduction = ONE_EPOCH_REDUCTION * u64::from(epoch);
        FIXED_RATE.saturating_sub(reduction)
    }
}

/// Miner's share of the block reward at height `h`.
///
/// During the foundation period (first `FIXED_RATE_PERIOD + 2 * EPOCH_LENGTH`
/// blocks) the founders receive 7.5 ERG per block, so the miner gets
/// `emission - 7.5 ERG`. After that the entire emission goes to the miner.
pub fn miner_reward_at_height(h: u32) -> u64 {
    let emission = emission_at_height(h);
    if h < FIXED_RATE_PERIOD + 2 * EPOCH_LENGTH {
        emission.saturating_sub(FOUNDERS_INITIAL_REWARD)
    } else {
        emission
    }
}

/// Re-emission charge (EIP-27) at height `h`.
///
/// Returns the amount charged from the miner reward to fund the re-emission
/// contract. Before activation height the charge is zero. After activation:
/// - If emission is large enough, charge `BASIC_CHARGE_AMOUNT` (12 ERG).
/// - If emission is smaller but still above `REEMISSION_REWARD`, charge
///   `emission - REEMISSION_REWARD` (leaving the miner at least 3 ERG).
/// - Otherwise, charge nothing.
pub fn reemission_for_height(h: u32) -> u64 {
    if h < REEMISSION_ACTIVATION_HEIGHT {
        return 0;
    }
    let emission = emission_at_height(h);
    if emission >= BASIC_CHARGE_AMOUNT + REEMISSION_REWARD {
        BASIC_CHARGE_AMOUNT
    } else {
        emission.saturating_sub(REEMISSION_REWARD)
    }
}

/// Total coins issued (cumulative) through height `h`.
///
/// - Height 0: no blocks mined, returns 0.
/// - Heights 1 through `FIXED_RATE_PERIOD - 1`: `FIXED_RATE * h`.
/// - Heights >= `FIXED_RATE_PERIOD`: sum of fixed-rate portion plus
///   full reduction epochs plus partial current epoch.
pub fn issued_coins_after_height(h: u32) -> u64 {
    if h == 0 {
        return 0;
    }
    let h64 = u64::from(h);
    let frp = u64::from(FIXED_RATE_PERIOD);
    let el = u64::from(EPOCH_LENGTH);

    if h < FIXED_RATE_PERIOD {
        return FIXED_RATE * h64;
    }

    // Heights 1..FIXED_RATE_PERIOD-1 each emit FIXED_RATE.
    // That is (FIXED_RATE_PERIOD - 1) blocks in the fixed-rate range.
    let fixed_portion = FIXED_RATE * (frp - 1);

    // 0-indexed offset within the reduction phase.
    // offset = 0 means the very first block of epoch 1 (height = FIXED_RATE_PERIOD).
    let offset = h64 - frp;

    // Number of fully completed epochs before the block at `offset`.
    let full_epochs = offset / el;

    // Number of blocks in the current (partial) epoch, including the block
    // at height h itself.
    let partial_blocks = offset % el + 1;

    // Sum over full epochs: epoch k (1-indexed) has per-block reward
    //   FIXED_RATE - k * ONE_EPOCH_REDUCTION.
    // Sum for k=1..n of (FIXED_RATE - k * ONE_EPOCH_REDUCTION)
    //   = n * FIXED_RATE - ONE_EPOCH_REDUCTION * n*(n+1)/2
    // Each full epoch has EPOCH_LENGTH blocks.
    let full_epoch_coins = if full_epochs > 0 {
        let n = full_epochs;
        let sum_per_block = n * FIXED_RATE - ONE_EPOCH_REDUCTION * n * (n + 1) / 2;
        sum_per_block * el
    } else {
        0
    };

    // Current epoch number (1-indexed).
    let current_epoch = full_epochs + 1;
    let current_rate = FIXED_RATE.saturating_sub(ONE_EPOCH_REDUCTION * current_epoch);
    let partial_coins = current_rate * partial_blocks;

    fixed_portion + full_epoch_coins + partial_coins
}

/// Compute full emission info at height `h`.
///
/// The miner reward is the miner's share minus the re-emission charge.
pub fn emission_info(h: u32) -> EmissionInfo {
    let miner_raw = miner_reward_at_height(h);
    let reemission_charge = reemission_for_height(h);
    let miner_reward = miner_raw.saturating_sub(reemission_charge);
    let total_coins_issued = issued_coins_after_height(h);
    let total_remaining_coins = COINS_TOTAL.saturating_sub(total_coins_issued);

    EmissionInfo {
        height: h,
        miner_reward,
        total_coins_issued,
        total_remaining_coins,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emission_at_genesis() {
        assert_eq!(emission_at_height(1), 75 * COINS_IN_ONE_ERG);
    }

    #[test]
    fn emission_at_fixed_rate_end() {
        assert_eq!(emission_at_height(525_599), 75 * COINS_IN_ONE_ERG);
    }

    #[test]
    fn emission_first_reduction_epoch() {
        // Height 525,600 is the start of epoch 1: 75 - 3 = 72 ERG
        assert_eq!(emission_at_height(525_600), 72 * COINS_IN_ONE_ERG);
    }

    #[test]
    fn emission_reaches_zero() {
        // Height 2,080,800: epoch = 1 + (2,080,800 - 525,600)/64,800 = 25
        // emission = 75 - 3*25 = 0
        assert_eq!(emission_at_height(2_080_800), 0);
    }

    #[test]
    fn miner_reward_during_foundation_period() {
        // During foundation period: 75 - 7.5 = 67.5 ERG
        assert_eq!(
            miner_reward_at_height(1),
            67 * COINS_IN_ONE_ERG + 500_000_000
        );
    }

    #[test]
    fn miner_reward_after_foundation_ends() {
        // Height 655,200: epoch = 1 + (655,200 - 525,600)/64,800 = 3
        // emission = 75 - 3*3 = 66 ERG; foundation period ended, miner gets all.
        assert_eq!(miner_reward_at_height(655_200), 66 * COINS_IN_ONE_ERG);
    }

    #[test]
    fn issued_coins_at_genesis() {
        assert_eq!(issued_coins_after_height(0), 0);
        assert_eq!(issued_coins_after_height(1), 75 * COINS_IN_ONE_ERG);
    }

    #[test]
    fn issued_coins_end_of_fixed_rate() {
        assert_eq!(
            issued_coins_after_height(525_599),
            75 * COINS_IN_ONE_ERG * 525_599
        );
    }

    #[test]
    fn reemission_charge_before_activation() {
        assert_eq!(reemission_for_height(777_216), 0);
    }

    #[test]
    fn reemission_charge_after_activation() {
        // Height 777,217: epoch = 1 + (777,217 - 525,600)/64,800
        //   = 1 + 251,617/64,800 = 1 + 3 = 4
        // emission = 75 - 3*4 = 63 ERG
        // 63 >= 12 + 3 = 15, so charge = 12 ERG
        assert_eq!(reemission_for_height(777_217), 12 * COINS_IN_ONE_ERG);
    }

    #[test]
    fn reemission_charge_when_emission_low() {
        // Need a height where emission = 6 ERG.
        // 75 - 3*epoch = 6 => epoch = 23
        // Epoch 23 starts at: 525,600 + 22*64,800 = 1,951,200
        let h = 1_951_200;
        assert_eq!(emission_at_height(h), 6 * COINS_IN_ONE_ERG);
        // 6 < 12 + 3, but 6 > 3, so charge = 6 - 3 = 3 ERG
        assert_eq!(reemission_for_height(h), 3 * COINS_IN_ONE_ERG);
    }

    #[test]
    fn emission_info_at_height_1() {
        let info = emission_info(1);
        assert_eq!(info.height, 1);
        // Miner reward = 67.5 ERG - reemission(0) = 67.5 ERG
        // (height 1 < reemission activation, so no charge)
        assert_eq!(info.miner_reward, 67 * COINS_IN_ONE_ERG + 500_000_000);
        assert_eq!(info.total_coins_issued, 75 * COINS_IN_ONE_ERG);
        assert_eq!(
            info.total_remaining_coins,
            COINS_TOTAL - 75 * COINS_IN_ONE_ERG
        );
    }

    #[test]
    fn emission_beyond_last_epoch_is_zero() {
        // Well past all epochs, emission should be 0.
        assert_eq!(emission_at_height(3_000_000), 0);
    }

    #[test]
    fn issued_coins_across_epoch_boundary() {
        // At the end of the fixed-rate period (last block):
        let at_fixed_end = issued_coins_after_height(FIXED_RATE_PERIOD - 1);
        assert_eq!(at_fixed_end, FIXED_RATE * u64::from(FIXED_RATE_PERIOD - 1));

        // First block of epoch 1 (height FIXED_RATE_PERIOD): emits 72 ERG.
        // Total = (FIXED_RATE_PERIOD - 1) blocks * 75 ERG + 1 block * 72 ERG.
        let one_into_epoch1 = issued_coins_after_height(FIXED_RATE_PERIOD);
        let expected = FIXED_RATE * u64::from(FIXED_RATE_PERIOD - 1) + 72 * COINS_IN_ONE_ERG;
        assert_eq!(one_into_epoch1, expected);
    }

    #[test]
    fn miner_reward_at_foundation_boundary() {
        // Last block of foundation period: h = 655,199
        // Epoch 2: emission = 75 - 3*2 = 69 ERG; miner = 69 - 7.5 = 61.5 ERG
        let h = FIXED_RATE_PERIOD + 2 * EPOCH_LENGTH - 1;
        assert_eq!(h, 655_199);
        assert_eq!(
            miner_reward_at_height(h),
            emission_at_height(h) - FOUNDERS_INITIAL_REWARD
        );

        // First block after foundation period: h = 655,200
        assert_eq!(miner_reward_at_height(655_200), emission_at_height(655_200));
    }

    #[test]
    fn miner_reward_in_foundation_overlap_zone() {
        // Heights 525,600-655,199: emission is reduced but foundation still active.
        // Epoch 1 (h=525,600): emission = 72 ERG, miner = 72 - 7.5 = 64.5 ERG
        let h = FIXED_RATE_PERIOD;
        assert_eq!(emission_at_height(h), 72 * COINS_IN_ONE_ERG);
        assert_eq!(
            miner_reward_at_height(h),
            72 * COINS_IN_ONE_ERG - FOUNDERS_INITIAL_REWARD
        );

        // Epoch 2 (h=590,400): emission = 69 ERG, miner = 69 - 7.5 = 61.5 ERG
        let h2 = FIXED_RATE_PERIOD + EPOCH_LENGTH;
        assert_eq!(emission_at_height(h2), 69 * COINS_IN_ONE_ERG);
        assert_eq!(
            miner_reward_at_height(h2),
            69 * COINS_IN_ONE_ERG - FOUNDERS_INITIAL_REWARD
        );
    }

    #[test]
    fn emission_info_uses_camel_case() {
        let info = emission_info(1);
        let json = serde_json::to_value(&info).unwrap();
        assert!(json.get("minerReward").is_some(), "expected minerReward");
        assert!(
            json.get("totalCoinsIssued").is_some(),
            "expected totalCoinsIssued"
        );
        assert!(
            json.get("totalRemainingCoins").is_some(),
            "expected totalRemainingCoins"
        );
        assert!(json.get("miner_reward").is_none(), "unexpected snake_case");
    }
}
