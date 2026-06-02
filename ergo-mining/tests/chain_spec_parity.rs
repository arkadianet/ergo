//! Cross-crate parity guard: `ergo-mining::emission_rules::MonetarySettings`
//! and `ergo-mining::reemission::ReemissionSettings` are now re-exports of
//! the chain-spec param types, so the constructors must produce
//! identical values. The struct-equality check below would fail at
//! compile time if the re-export ever drifted to a different type.

use ergo_chain_spec::{MonetaryParams, ReemissionParams};
use ergo_mining::emission_rules::MonetarySettings;
use ergo_mining::reemission::ReemissionSettings;

#[test]
fn monetary_mainnet_constructors_agree() {
    let new: MonetaryParams = MonetaryParams::mainnet();
    let old: MonetarySettings = MonetarySettings::mainnet();
    assert_eq!(new, old);
}

#[test]
fn reemission_mainnet_constructors_agree() {
    let new: ReemissionParams = ReemissionParams::mainnet();
    let old: ReemissionSettings = ReemissionSettings::mainnet();
    assert_eq!(new, old);
}
