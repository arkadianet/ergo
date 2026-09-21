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

    /// The launch tables as they were BEFORE id 9 could be seeded,
    /// captured from `git show 18ff2943:.../launch.rs` and written out
    /// here as literals. A regression test that called the new
    /// constructor for both sides would only prove it agrees with
    /// itself; these tuples are an independent record of what the three
    /// networks used to produce.
    ///
    /// `(block_version, storage_fee_factor, min_value_per_byte,
    ///   max_block_size, max_block_cost, token_access_cost, input_cost,
    ///   data_input_cost, output_cost, subblocks_per_block)`
    const BASELINE_MAINNET: (u8, i32, i32, i32, i32, i32, i32, i32, i32, Option<i32>) = (
        1, 1_250_000, 360, 524_288, 1_000_000, 100, 2_000, 100, 100, None,
    );
    const BASELINE_TESTNET: (u8, i32, i32, i32, i32, i32, i32, i32, i32, Option<i32>) =
        BASELINE_MAINNET;
    /// Devnet differs from mainnet in exactly one field at 18ff2943:
    /// `block_version = 4` (Scala `Devnet60LaunchParameters`).
    const BASELINE_DEVNET: (u8, i32, i32, i32, i32, i32, i32, i32, i32, Option<i32>) = (
        4, 1_250_000, 360, 524_288, 1_000_000, 100, 2_000, 100, 100, None,
    );

    fn as_tuple(
        p: &ActiveProtocolParameters,
    ) -> (u8, i32, i32, i32, i32, i32, i32, i32, i32, Option<i32>) {
        (
            p.block_version,
            p.storage_fee_factor,
            p.min_value_per_byte,
            p.max_block_size,
            p.max_block_cost,
            p.token_access_cost,
            p.input_cost,
            p.data_input_cost,
            p.output_cost,
            p.subblocks_per_block,
        )
    }

    fn baseline(net: Network) -> (u8, i32, i32, i32, i32, i32, i32, i32, i32, Option<i32>) {
        match net {
            Network::Mainnet => BASELINE_MAINNET,
            Network::Testnet => BASELINE_TESTNET,
            Network::Devnet => BASELINE_DEVNET,
        }
    }

    #[test]
    fn launch_without_input_blocks_matches_the_pre_change_tables() {
        for net in [Network::Mainnet, Network::Testnet, Network::Devnet] {
            assert_eq!(
                as_tuple(&scala_launch_for_network(net)),
                baseline(net),
                "{net:?} launch row moved"
            );
            assert_eq!(
                as_tuple(&scala_launch_for_network_with_input_blocks(net, false)),
                baseline(net),
                "{net:?} with the switch off moved"
            );
            let row = scala_launch_for_network(net);
            assert_eq!(row.epoch_start_height, 0);
            assert!(row.extra.is_empty());
            assert_eq!(row.proposed_update, ErgoValidationSettingsUpdate::empty());
            assert_eq!(row.activated_update, ErgoValidationSettingsUpdate::empty());
        }
    }

    #[test]
    fn enabling_input_blocks_touches_only_id_9_and_only_on_devnet() {
        let enabled = scala_launch_for_network_with_input_blocks(Network::Devnet, true);
        let mut without_id_9 = as_tuple(&enabled);
        without_id_9.9 = None;
        assert_eq!(
            without_id_9, BASELINE_DEVNET,
            "seeding id 9 must change nothing else"
        );
        // The switch is devnet-only: a caller that passes `true` for a
        // public network still gets the pre-change table.
        for net in [Network::Mainnet, Network::Testnet] {
            assert_eq!(
                as_tuple(&scala_launch_for_network_with_input_blocks(net, true)),
                baseline(net),
                "{net:?} must be untouched"
            );
        }
    }

    // ----- oracle parity -----

    /// The seeded value and its id come from the pinned Scala branch's
    /// own `Parameters.DefaultParameters`, not from this file.
    // oracle: scripts/jvm_weak_blocks_oracle/WeakBlocksOracle.scala launch_params
    #[test]
    fn devnet_input_block_launch_table_matches_the_scala_defaults() {
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/weak-blocks/launch_params.json"
        ))
        .unwrap();
        let case = &oracle["cases"][0];
        assert_eq!(case["name"], "default_parameters");
        let id_9 = case["subblocks_per_block_id"].as_u64().unwrap();
        assert_eq!(
            id_9,
            u64::from(crate::active_params::ids::SUBBLOCKS_PER_BLOCK)
        );

        let table: std::collections::BTreeMap<u64, i64> = case["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (e["id"].as_u64().unwrap(), e["value"].as_i64().unwrap()))
            .collect();
        assert_eq!(
            table.get(&id_9).copied(),
            Some(i64::from(SUBBLOCKS_PER_BLOCK_DEFAULT)),
            "the branch's SubsPerBlockDefault"
        );

        let row = scala_launch_for_network_with_input_blocks(Network::Devnet, true);
        use crate::active_params::ids;
        for (id, actual) in [
            (ids::STORAGE_FEE_FACTOR, row.storage_fee_factor),
            (ids::MIN_VALUE_PER_BYTE, row.min_value_per_byte),
            (ids::MAX_BLOCK_SIZE, row.max_block_size),
            (ids::MAX_BLOCK_COST, row.max_block_cost),
            (ids::TOKEN_ACCESS_COST, row.token_access_cost),
            (ids::INPUT_COST, row.input_cost),
            (ids::DATA_INPUT_COST, row.data_input_cost),
            (ids::OUTPUT_COST, row.output_cost),
            (ids::SUBBLOCKS_PER_BLOCK, row.subblocks_per_block.unwrap()),
        ] {
            assert_eq!(
                table.get(&u64::from(id)).copied(),
                Some(i64::from(actual)),
                "parameter id {id}"
            );
        }
        // id 123 (BlockVersion) is the one field the devnet launch
        // object deliberately overrides: the Scala defaults carry 1,
        // `Devnet60LaunchParameters` seeds 4. Pinned here so the
        // divergence stays intentional.
        assert_eq!(table.get(&u64::from(ids::BLOCK_VERSION)).copied(), Some(1));
        assert_eq!(row.block_version, 4);
    }

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
