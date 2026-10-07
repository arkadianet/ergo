//! Oracle: test-vectors/ergo-sigma/cost-ledger/scala-constants.json

use ergo_chain_spec::Network;

use super::ActiveProtocolParameters;
use crate::voting::validation_settings::ErgoValidationSettingsUpdate;

/// Mainnet launch parameters. Mirrors Scala `MainnetLaunchParameters`
/// (`settings/LaunchParameters.scala`). Used as the height-0 row in
/// `voted_params` so the snapshot read path always finds *some* row.
pub fn scala_launch_mainnet() -> ActiveProtocolParameters {
    ActiveProtocolParameters {
        announced_settings: None,
        missing_core_parameters: 0,
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

/// Testnet launch parameters from pinned Scala v6.0.5
/// `settings/LaunchParameters.scala`: version 4 with a *proposed* update
/// disabling rules 215 and 409. The activated cumulative settings remain
/// empty until voting activates an update. The public height-1 genesis header
/// is still version 1; that header exception does not change this launch row.
/// See `test-vectors/testnet/initial-context/` for source and early captures.
pub fn scala_launch_testnet() -> ActiveProtocolParameters {
    ActiveProtocolParameters {
        announced_settings: None,
        block_version: 4,
        proposed_update: ErgoValidationSettingsUpdate {
            rules_to_disable: vec![215, 409],
            status_updates: Vec::new(),
        },
        ..scala_launch_mainnet()
    }
}

/// Launch parameters for the given network. Production callers that
/// hold a `Network` should use this; consumers without network
/// context (most tests) can keep calling [`scala_launch`].
pub fn scala_launch_for_network(net: Network) -> ActiveProtocolParameters {
    match net {
        Network::Mainnet => scala_launch_mainnet(),
        Network::Testnet => scala_launch_testnet(),
        Network::Devnet => ActiveProtocolParameters {
            announced_settings: None,
            block_version: 4,
            ..scala_launch_mainnet()
        },
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

    // ----- happy path -----

    #[test]
    fn devnet_launch_scala_devnet60_params_match() {
        let devnet = scala_launch_for_network(Network::Devnet);
        assert_eq!(devnet.block_version, 4);
        assert_eq!(devnet.max_block_cost, 1_000_000);
        assert!(devnet.proposed_update.rules_to_disable.is_empty());
        assert!(devnet.activated_update.rules_to_disable.is_empty());
        assert_eq!(scala_launch_for_network(Network::Mainnet).block_version, 1);
        assert_eq!(scala_launch_for_network(Network::Testnet).block_version, 4);
    }

    #[test]
    fn scala_launch_testnet_matches_pinned_source() {
        let testnet = scala_launch_testnet();
        assert_eq!(testnet.epoch_start_height, 0);
        assert_eq!(testnet.block_version, 4);
        assert_eq!(testnet.proposed_update.rules_to_disable, vec![215, 409]);
        assert!(testnet.proposed_update.status_updates.is_empty());
        assert_eq!(
            testnet.activated_update,
            ErgoValidationSettingsUpdate::empty()
        );
        assert_eq!(testnet.subblocks_per_block, None);
        // The eight numeric cost/size defaults are shared with mainnet.
        let mut normalized = testnet;
        normalized.block_version = 1;
        normalized.proposed_update = ErgoValidationSettingsUpdate::empty();
        assert_eq!(normalized, scala_launch_mainnet());
    }

    #[test]
    fn network_dispatch_preserves_distinct_launch_rows() {
        assert_eq!(
            scala_launch_for_network(Network::Mainnet),
            scala_launch_mainnet()
        );
        assert_eq!(
            scala_launch_for_network(Network::Testnet),
            scala_launch_testnet()
        );
        assert_eq!(scala_launch().block_version, 1);
    }

    // ----- oracle parity -----

    // ledger: BLOCK-cost-parameter-defaults-B008
    #[test]
    fn launch_cost_defaults_match_jvm() {
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/ergo-sigma/cost-ledger/scala-constants.json"
        ))
        .unwrap();
        let active = scala_launch_mainnet();
        assert_eq!(active.epoch_start_height, 0);
        let params = crate::ProtocolParams::from_active(&active);
        for (name, actual) in [
            ("TokenAccessCostDefault", params.token_access_cost),
            ("InputCostDefault", params.input_cost),
            ("DataInputCostDefault", params.data_input_cost),
            ("OutputCostDefault", params.output_cost),
            ("MaxBlockCostDefault", params.max_block_cost),
        ] {
            assert_eq!(
                Some(actual),
                oracle["constants"][format!("Parameters.{name}")]["value"].as_u64(),
                "{name}"
            );
        }
    }
}
