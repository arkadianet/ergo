//! Oracle: test-vectors/ergo-sigma/cost-ledger/scala-constants.json

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

/// `Parameters.SubsPerBlockDefault` on the `weak-blocks` branch: the
/// number of input (sub-) blocks per ordering block that the branch's
/// `Parameters.DefaultParameters` carries under id 9 from genesis.
pub const SUBBLOCKS_PER_BLOCK_DEFAULT: i32 = 64;

/// Launch parameters for the given network. Production callers that
/// hold a `Network` should use this; consumers without network
/// context (most tests) can keep calling [`scala_launch`].
pub fn scala_launch_for_network(net: Network) -> ActiveProtocolParameters {
    scala_launch_for_network_with_input_blocks(net, false)
}

/// Launch parameters for the given network, optionally seeding the
/// input-block multiplier (id 9).
///
/// Stock Scala 6.0.x has no id 9 in `Parameters.DefaultParameters`, so
/// with `input_blocks = false` this is byte-identical to
/// [`scala_launch_for_network`] on every network. The pinned
/// `weak-blocks` branch DOES carry id 9 = `SubsPerBlockDefault` (64)
/// from genesis, so a devnet node that follows that branch must seed
/// the same row — otherwise its multiplier is `None` and every
/// input-block announcement drops with `MultiplierUnavailable`.
///
/// This is consensus-visible (the parameters table is hashed into the
/// extension at epoch boundaries), which is why it is gated on the
/// devnet-only `[input_blocks] enabled` switch and refused elsewhere:
/// see spec §12 finding F10.
pub fn scala_launch_for_network_with_input_blocks(
    net: Network,
    input_blocks: bool,
) -> ActiveProtocolParameters {
    let mut params = match net {
        Network::Mainnet => scala_launch_mainnet(),
        Network::Testnet => scala_launch_testnet(),
        Network::Devnet => ActiveProtocolParameters {
            block_version: 4,
            ..scala_launch_mainnet()
        },
    };
    if input_blocks && net == Network::Devnet {
        params.subblocks_per_block = Some(SUBBLOCKS_PER_BLOCK_DEFAULT);
    }
    params
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
        assert_eq!(scala_launch_for_network(Network::Testnet).block_version, 1);
    }

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

    #[test]
    fn launch_with_input_blocks_seeds_id_9_on_devnet_only() {
        // The `weak-blocks` branch's `Parameters.DefaultParameters`
        // carries id 9 = 64 from genesis; the Rust devnet node must
        // match it or every announcement drops with
        // `MultiplierUnavailable`.
        let devnet = scala_launch_for_network_with_input_blocks(Network::Devnet, true);
        assert_eq!(devnet.subblocks_per_block, Some(64));
        assert_eq!(
            ActiveProtocolParameters {
                subblocks_per_block: None,
                ..devnet
            },
            scala_launch_for_network(Network::Devnet),
            "seeding id 9 must change nothing else in the devnet row"
        );

        // The switch is devnet-only; even a caller that passes `true`
        // for a public network gets the stock row.
        for net in [Network::Mainnet, Network::Testnet] {
            assert_eq!(
                scala_launch_for_network_with_input_blocks(net, true),
                scala_launch_for_network(net),
                "{net:?} launch row must be untouched"
            );
        }
    }

    #[test]
    fn launch_without_input_blocks_is_unchanged_on_every_network() {
        for net in [Network::Mainnet, Network::Testnet, Network::Devnet] {
            let row = scala_launch_for_network_with_input_blocks(net, false);
            assert_eq!(row, scala_launch_for_network(net));
            assert_eq!(row.subblocks_per_block, None, "{net:?} carries no id 9");
        }
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
