use ergo_chain_spec::Network;

use super::ActiveProtocolParameters;
use crate::voting::validation_settings::ErgoValidationSettingsUpdate;

/// Mainnet launch parameters. Mirrors Scala `MainnetLaunchParameters`
/// (`settings/LaunchParameters.scala`). Used as the height-0 row in
/// `voted_params` so the snapshot read path always finds *some* row.
pub fn scala_launch_mainnet() -> ActiveProtocolParameters {
    ActiveProtocolParameters {
        epoch_start_height: 0,
        block_version: 1,
        storage_fee_factor: 1_250_000,
        min_value_per_byte: 360,
        max_block_size: 524_288,
        max_block_cost: 1_000_000,
        token_access_cost: 100,
        input_cost: 2_000,
        data_input_cost: 100,
        output_cost: 100,
        subblocks_per_block: None,
        extra: Vec::new(),
        proposed_update: ErgoValidationSettingsUpdate::empty(),
        activated_update: ErgoValidationSettingsUpdate::empty(),
    }
}

/// Testnet launch parameters. Mirrors Scala `TestnetLaunchParameters`
/// (`settings/LaunchParameters.scala`), which is byte-identical to
/// `MainnetLaunchParameters`: `height = 0`, `parametersTable =
/// Parameters.DefaultParameters` (so `BlockVersion = 1`), and
/// `proposedUpdate = ErgoValidationSettingsUpdate.empty`. The two
/// network-specific Scala objects exist as named symbols only — they
/// carry no differing data. The validation rules that are disabled on
/// mainnet today (e.g. 215, 409) reached that state through real
/// soft-fork voting on the live mainnet chain, never via a seeded
/// launch row. The Scala objects that DO override `BlockVersion` at
/// genesis are `DevnetLaunchParameters` (= 50) and
/// `Devnet60LaunchParameters` (= 60), neither of which is the public
/// testnet.
pub fn scala_launch_testnet() -> ActiveProtocolParameters {
    scala_launch_mainnet()
}

/// Launch parameters for the given network. Production callers that
/// hold a `Network` should use this; consumers without network
/// context (most tests) can keep calling [`scala_launch`].
pub fn scala_launch_for_network(net: Network) -> ActiveProtocolParameters {
    match net {
        Network::Mainnet => scala_launch_mainnet(),
        Network::Testnet => scala_launch_testnet(),
    }
}

/// Backwards-compatible alias for [`scala_launch_mainnet`]. Kept so
/// existing test fixtures and snapshot-init paths that don't carry a
/// `Network` keep producing the original mainnet launch row.
pub fn scala_launch() -> ActiveProtocolParameters {
    scala_launch_mainnet()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scala_launch_testnet_matches_mainnet() {
        // Scala `TestnetLaunchParameters` is byte-identical to
        // `MainnetLaunchParameters` (see
        // `ergo-core/src/main/scala/org/ergoplatform/settings/LaunchParameters.scala`).
        // A regression that re-introduces a divergent testnet launch row
        // would re-create the h=1024 `exMatchValidationSettings` rejection
        // that surfaces only after `--network testnet` actually applies
        // real blocks.
        assert_eq!(scala_launch_testnet(), scala_launch_mainnet());
    }

    #[test]
    fn scala_launch_for_network_returns_mainnet_row_on_both_arms() {
        // Same data on both arms today; this pins the invariant so a
        // future intentional divergence (e.g. devnet-style block version
        // override) has to update this test deliberately.
        let m = scala_launch_for_network(Network::Mainnet);
        let t = scala_launch_for_network(Network::Testnet);
        assert_eq!(m, t);
        assert_eq!(m.block_version, 1);
        assert_eq!(m.proposed_update.rules_to_disable, Vec::<u16>::new());
        assert!(m.proposed_update.status_updates.is_empty());
        assert_eq!(m.activated_update.rules_to_disable, Vec::<u16>::new());
        assert!(m.activated_update.status_updates.is_empty());
    }
}
