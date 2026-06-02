//! Node configuration: TOML file + CLI overrides.
//!
//! Priority: CLI args override TOML file values override defaults.
//!
//! Example ergo-node.toml:
//! ```toml
//! network = "mainnet"
//! data_dir = "./ergo-data"
//!
//! [node]
//! agent_name = "opus"
//! node_name = "my-node"
//!
//! [peers]
//! known = ["213.239.193.208:9030", "159.65.11.55:9030"]
//! target_outbound = 60
//! max_connections = 80
//! ```

use ergo_chain_spec::ChainSpec;
pub use ergo_chain_spec::Network;

mod cli;
mod load;
mod resolved;
mod toml_sections;

pub use cli::Cli;
pub use resolved::{LoggingConfig, LoggingFileConfig, LoggingFormat, NodeConfig, StateType};

#[cfg(test)]
mod tests;

/// Upper bound on `download_window`: keeps the pending buffer and any
/// height arithmetic bounded. Anything larger is a config error.
const MAX_DOWNLOAD_WINDOW: usize = 100_000;

/// Single source of truth for "is this the canonical Mode 6
/// (headers-only) combo". Used by `NodeConfig::load` (TOML reject
/// path) and `validate_runtime_mode_support` (programmatic-config
/// reject path) so the two gates can never drift on what counts as
/// canonical headers-only.
///
/// All four conditions must hold:
/// - `state_type == Digest`: header chain only, no UTXO backend.
/// - `verify_transactions == false`: no tx validation.
/// - `blocks_to_keep == 0`: nothing to retain (Scala
///   `application.conf:15`).
/// - `utxo_bootstrap == false`: snapshot bootstrap installs a UTXO
///   tree the rest of the runtime cannot use in headers-only mode.
pub(crate) fn is_canonical_mode_6_combo(
    state_type: StateType,
    verify_transactions: bool,
    blocks_to_keep: i32,
    utxo_bootstrap: bool,
) -> bool {
    state_type == StateType::Digest
        && !verify_transactions
        && blocks_to_keep == 0
        && !utxo_bootstrap
}

/// The canonical Mode 5 (Digest Verifier) combo: full transaction
/// validation against an authenticated UTXO digest, with no box arena.
///
/// - `state_type == Digest`: digest backend, no UTXO box store.
/// - `verify_transactions == true`: full tx validation, resolving input
///   boxes from each block's ADProofs.
/// - `blocks_to_keep == -1`: archive. Digest mode retains every full
///   block (no Mode-3 prune); a retention window is a separate concern.
/// - `utxo_bootstrap == false`: a digest node has no box arena to
///   install a UTXO snapshot into.
///
/// Admits ONLY the bare Mode 5 row; every other digest combo
/// (`blocks_to_keep > 0`, `utxo_bootstrap`, `verify_transactions=false`
/// which is Mode 6) stays rejected by the activation gate, and the
/// mining/indexer/mempool subsystem gates still fire on
/// `state_type == Digest`.
pub(crate) fn is_canonical_mode_5_combo(
    state_type: StateType,
    verify_transactions: bool,
    blocks_to_keep: i32,
    utxo_bootstrap: bool,
) -> bool {
    state_type == StateType::Digest
        && verify_transactions
        && blocks_to_keep == -1
        && !utxo_bootstrap
}

/// Decide whether the mempool subsystem must be force-disabled for
/// a given mode. Tx admission needs UTXO box bytes to validate
/// inputs, so any mode without a UTXO box store must force-off:
///
/// - Mode 6 (`state_type=Digest`, `verify_transactions=false`):
///   covered by `!verify_transactions`.
/// - Mode 5 (`state_type=Digest`, `verify_transactions=true`):
///   covered by `state_type == Digest`.
///
/// Operator-supplied `mempool_disabled_via_cli` and
/// `mempool_disabled_via_toml` also force off.
///
/// Extracted as a free function so the policy can be unit-tested
/// against the Mode 5 truth row directly — the activation gate
/// blocks Mode 5 through `NodeConfig::load`, so a TOML-driven test
/// can only reach the policy through Mode 6, which would not prove
/// the Mode 5 branch.
pub(crate) fn mempool_force_off_for_mode(
    state_type: StateType,
    verify_transactions: bool,
    mempool_disabled_via_toml: bool,
    mempool_disabled_via_cli: bool,
) -> bool {
    mempool_disabled_via_cli
        || mempool_disabled_via_toml
        || !verify_transactions
        || state_type == StateType::Digest
}

/// Returns `Ok(())` if the supplied [`ChainSpec`] carries everything
/// the node needs to start end-to-end on that network. Otherwise
/// returns a message naming the missing artifact. Currently the
/// readiness criterion is "genesis header id and embedded boxes JSON
/// must both be `Some(_)`"; this is the data the genesis-loading and
/// NiPoPoW verifier paths require at startup. The runtime path
/// `NodeConfig::load` calls this gate immediately after building the
/// spec, so any network whose artifacts aren't yet extracted fails
/// fast with a pointer to the provisioning doc instead of drifting on
/// partial config.
pub fn validate_supported(spec: &ChainSpec) -> Result<(), String> {
    let net = spec.network.as_str();
    if spec.genesis.header_id.is_none() {
        return Err(format!(
            "{net} genesis header_id not embedded — \
             extract via test-vectors/{net}/PROVISIONING.md and \
             populate GenesisParams::{net}() in ergo-chain-spec"
        ));
    }
    if spec.genesis.boxes_json.is_none() {
        return Err(format!(
            "{net} genesis boxes_json not embedded — \
             extract via test-vectors/{net}/PROVISIONING.md and \
             populate GenesisParams::{net}() in ergo-chain-spec"
        ));
    }
    Ok(())
}
