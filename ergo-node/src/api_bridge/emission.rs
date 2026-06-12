//! `/emission/at` schedule bridge: implements
//! [`ergo_api::emission::EmissionSchedule`] over `ergo-mining`'s
//! Scala-parity emission math (`emission_rules`, oracle-tested against
//! the live Scala node).
//!
//! Pure per-network arithmetic — no node state. Built once at boot from
//! the chain spec's monetary + reemission params; `coinsTotal` is
//! computed in the constructor and cached for the process lifetime,
//! mirroring Scala's `EmissionRules.coinsTotal` lazy val.

use ergo_api::emission::{EmissionInfoJson, EmissionSchedule, EmissionScriptsJson};
use ergo_chain_spec::{MonetaryParams, ReemissionParams};
use ergo_mining::emission_rules;

/// Render the chain spec's verified emission-script trees as the
/// `/emission/scripts` response — three P2S addresses, exactly Scala's
/// `Pay2SAddress(tree).toString()` (P2S addresses embed the tree bytes
/// verbatim). `None` where the spec carries no verified trees
/// (testnet/dev): the route then stays unmounted. Oracle-pinned below
/// against the live-Scala capture.
pub fn render_emission_scripts(spec: &ergo_chain_spec::ChainSpec) -> Option<EmissionScriptsJson> {
    let trees = spec.emission_script_trees()?;
    let network = spec.network_params.address_prefix;
    let render = |tree: &[u8]| {
        ergo_ser::address::encode_address_from_tree_bytes(network, tree)
            .expect("verified spec trees parse as ErgoTree")
    };
    Some(EmissionScriptsJson {
        emission: render(&trees.emission),
        reemission: render(&trees.reemission),
        pay2_reemission: render(&trees.pay_to_reemission),
    })
}

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

    // ----- /emission/scripts -----

    /// Live-Scala oracle parity: rendering the mainnet chain-spec trees
    /// as P2S addresses must reproduce the captured `/emission/scripts`
    /// response byte-for-byte (`test-vectors/api/emission/scripts.json`).
    /// This exercises the full path the route serves: verified tree
    /// constants -> base58 P2S address encoding.
    #[test]
    fn mainnet_scripts_match_live_scala_oracle() {
        let scripts = render_emission_scripts(&ergo_chain_spec::ChainSpec::mainnet())
            .expect("mainnet has verified script trees");

        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/api/emission/scripts.json"
        ))
        .unwrap();
        assert_eq!(scripts.emission, oracle["emission"].as_str().unwrap());
        assert_eq!(scripts.reemission, oracle["reemission"].as_str().unwrap());
        assert_eq!(
            scripts.pay2_reemission,
            oracle["pay2Reemission"].as_str().unwrap()
        );
    }

    #[test]
    fn testnet_scripts_absent() {
        assert!(render_emission_scripts(&ergo_chain_spec::ChainSpec::testnet()).is_none());
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
