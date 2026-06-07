//! `/emission/at` schedule bridge: implements
//! [`ergo_api::emission::EmissionSchedule`] over `ergo-mining`'s
//! Scala-parity emission math (`emission_rules`, oracle-tested against
//! the live Scala node).
//!
//! Pure per-network arithmetic — no node state. Built once at boot from
//! the chain spec's monetary + reemission params; `coinsTotal` is
//! computed in the constructor and cached for the process lifetime,
//! mirroring Scala's `EmissionRules.coinsTotal` lazy val.

use ergo_api::emission::{EmissionInfoJson, EmissionSchedule};
use ergo_chain_spec::{MonetaryParams, ReemissionParams};
use ergo_mining::emission_rules;

/// See module docs. Construct via [`EmissionScheduleBridge::new`] and
/// hand into `ServerCtx.emission` as an `Arc<dyn EmissionSchedule>`.
pub struct EmissionScheduleBridge {
    monetary: MonetaryParams,
    /// `None` on chain specs without EIP-27 (synthetic dev chains):
    /// `reemitted` is then always 0, mirroring a Scala node with
    /// reemission disabled.
    reemission: Option<ReemissionParams>,
    /// Cached `EmissionRules.coinsTotal` (~2M-iteration walk, done once).
    coins_total: u64,
}

impl EmissionScheduleBridge {
    pub fn new(monetary: MonetaryParams, reemission: Option<ReemissionParams>) -> Self {
        let (coins_total, _blocks_total) = emission_rules::coins_and_blocks_total(&monetary);
        Self {
            monetary,
            reemission,
            coins_total,
        }
    }
}

impl EmissionSchedule for EmissionScheduleBridge {
    fn emission_info_at(&self, height: u32) -> EmissionInfoJson {
        let i = emission_rules::emission_info_at_height(
            height,
            &self.monetary,
            self.reemission.as_ref(),
            self.coins_total,
        );
        EmissionInfoJson {
            height: i.height,
            miner_reward: i.miner_reward,
            total_coins_issued: i.total_coins_issued,
            total_remain_coins: i.total_remain_coins,
            reemitted: i.reemitted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    /// Spot-checks the bridge's field mapping against two live-Scala
    /// vector rows (`test-vectors/api/emission/at_*.json`); the full
    /// 17-height differential lives in
    /// `ergo-mining::emission_rules::tests`.
    #[test]
    fn bridge_matches_live_scala_vectors() {
        let b = EmissionScheduleBridge::new(
            MonetaryParams::mainnet(),
            Some(ReemissionParams::mainnet()),
        );
        let i = b.emission_info_at(1_786_000);
        assert_eq!(
            (
                i.height,
                i.miner_reward,
                i.total_coins_issued,
                i.total_remain_coins,
                i.reemitted
            ),
            (
                1_786_000,
                3_000_000_000,
                95_261_940_000_000_000,
                2_477_985_000_000_000,
                12_000_000_000
            ),
            "h=1_786_000 (15 ERG era: charge 12, miner 3)"
        );
        let i = b.emission_info_at(777_217);
        assert_eq!(
            (i.miner_reward, i.reemitted),
            (51_000_000_000, 12_000_000_000),
            "h=777_217 (EIP-27 activation: 63 − 12)"
        );
    }

    // ----- no-reemission spec -----

    #[test]
    fn no_reemission_spec_reports_zero_reemitted() {
        let b = EmissionScheduleBridge::new(MonetaryParams::mainnet(), None);
        let i = b.emission_info_at(1_786_000);
        assert_eq!(i.reemitted, 0);
        assert_eq!(
            i.miner_reward, 15_000_000_000,
            "plain pre-EIP-27 miner share when reemission is absent"
        );
    }
}
