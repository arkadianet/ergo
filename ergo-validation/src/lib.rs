//! Block, header, and transaction validation for the Ergo Rust node.
//!
//! Sits on top of [`ergo_primitives`] (cost accumulator), [`ergo_ser`]
//! (parsed wire types), [`ergo_crypto`] (PoW + difficulty + Merkle),
//! and [`ergo_sigma`] (script evaluator + sigma proofs). Provides:
//!
//! * [`block`] — full-block validation orchestration: header check,
//!   transactions root, parallel per-tx validation, cost-budget tally.
//! * [`header`] — pre-validated [`CheckedHeader`] type and the
//!   header-level rules (PoW, difficulty, version-for-height).
//! * [`tx`] — transaction validation broken into structural / monetary
//!   / script phases, plus the [`CheckedTransaction`] container.
//! * [`context`] — [`ProtocolParams`] / [`LocalPolicy`] /
//!   [`TransactionContext`] / [`UtxoView`]: the parameter, policy, and
//!   per-tx context surfaces a validator needs.
//! * [`voting`] — voted-protocol-parameter recomputation, miner-vote
//!   tallies, and validation-rule status updates persisted via
//!   `ErgoValidationSettings` / `ErgoValidationSettingsUpdate`.
//! * [`active_params`] — the per-epoch active set persisted in
//!   `voted_params`, including the wire-format `serialize` /
//!   `deserialize` round-trip.
//! * [`error`] — [`ValidationError`] enumerating every consensus
//!   rejection reason with Scala-parity error codes.
//! * [`cost`] — re-exports the JIT-cost accumulator from
//!   `ergo_primitives` so callers can stay on `ergo_validation` types.
//!
//! What is **not** here:
//!
//! * No fork-choice / chain-graph logic — that lives in `ergo-state`.
//! * No P2P framing or sync orchestration — `ergo-p2p` / `ergo-sync`.
//! * No mempool admission policies — `ergo-mempool`.

pub mod active_params;
pub mod block;
pub mod context;
pub mod cost;
pub mod error;
pub mod header;
pub mod popow;
pub mod pre_header;
pub mod storage_rent;
pub mod tx;
pub mod voting;

pub use active_params::{
    parse_active_params, scala_launch, scala_launch_for_network, scala_launch_mainnet,
    scala_launch_testnet, ActiveParamsError, ActiveProtocolParameters,
};
pub use context::{LocalPolicy, ProtocolParams, TransactionContext, UtxoView};
pub use cost::{CostAccumulator, CostError, JitCost};
pub use error::ValidationError;
pub use header::CheckedHeader;
pub use tx::reemission::{verify_reemission_spending, ReemissionRuleInputs};
pub use tx::script::{
    compute_tx_init_cost, compute_tx_init_cost_with_costs, INTERPRETER_INIT_COST,
};
pub use tx::CheckedTransaction;
pub use tx::TxValidationCtx;
pub use tx::{validate_transaction, validate_transaction_parsed};
pub use voting::{
    compute_epoch_votes, compute_next_params, derive_activated_script_version, neutral_votes,
    validate_epoch_extension, ChainHeaderReader, ChainHeaderReaderError, ErgoValidationSettings,
    ErgoValidationSettingsUpdate, ExtensionValidationError, ExtensionValidationOutcome, HeaderView,
    RecomputeError, RuleStatus, ValidationSettingsCodecError, VotingSettings,
};

/// Test-only helpers for integration tests. Delegates to the production
/// bridge in tx/script.rs — same code path, feature-gated exposure.
#[cfg(feature = "test-helpers")]
pub mod test_helpers {
    use crate::error::ValidationError;
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_sigma::evaluator::EvalBox;

    /// Convert a sealed [`ErgoBox`] (with its in-block index) into the
    /// evaluator's per-input box representation.
    pub fn ergo_box_to_eval_box(b: &ErgoBox, index: usize) -> Result<EvalBox, ValidationError> {
        crate::tx::script::ergo_box_to_eval_box(b, index)
    }

    /// Convert an [`ErgoBoxCandidate`] (with the parent transaction id
    /// and output index) into the evaluator's per-input box
    /// representation.
    pub fn candidate_to_eval_box(
        c: &ErgoBoxCandidate,
        tx_id: &ModifierId,
        index: u16,
    ) -> Result<EvalBox, ValidationError> {
        crate::tx::script::candidate_to_eval_box(c, tx_id, index)
    }
}
