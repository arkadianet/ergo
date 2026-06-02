//! Cross-crate parity guard: the narrow `VotingParams` in
//! `ergo-chain-spec` must agree field-by-field with the
//! `VotingSettings` that `ergo-validation::voting` consumes. Catches
//! silent divergence between the two sources of truth while
//! `VotingSettings` is being migrated to read the `ChainSpec.voting`
//! view.

use ergo_chain_spec::VotingParams;
use ergo_validation::voting::recompute::VotingSettings;

#[test]
fn voting_params_mainnet_matches_validation_voting_settings() {
    let new = VotingParams::mainnet();
    let old = VotingSettings::mainnet();

    assert_eq!(new.voting_length, old.voting_length);
    assert_eq!(new.soft_fork_epochs, old.soft_fork_epochs);
    assert_eq!(new.activation_epochs, old.activation_epochs);
    assert_eq!(new.version2_activation, old.version2_activation);
}
