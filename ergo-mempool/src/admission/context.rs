//! Admission context + validation-boundary types: the borrows the
//! pipeline threads (`TipContext`, `AdmissionCtx`), the validation result
//! projection (`Validated`), the error taxonomy (`ValidationErr`), the
//! cheap pre-check digest (`PeekedTx`), and the pluggable [`Validator`]
//! trait.

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::Header;
use ergo_validation::{
    ProtocolParams, ReemissionRuleInputs, TransactionContext, TxValidationCtx, UtxoView,
};

use crate::budget::CostBudgets;
use crate::invalidation::InvalidationCache;
use crate::pool::OrderedPool;
use crate::types::{MempoolConfig, TipPointer, TxId};
use crate::weight::WeightFunction;

pub struct TipContext<'a> {
    pub tip: TipPointer,
    pub best_header_height: u32,
    pub best_full_block_height: u32,
    pub utxo: &'a dyn UtxoView,
    pub tx_context: &'a TransactionContext,
    pub params: &'a ProtocolParams,
    pub last_headers: &'a [Header],
    /// EIP-27 re-emission rule inputs for this network, or `None` where EIP-27
    /// is not enabled (testnet). Threaded into the per-tx validator's rule
    /// bundle so admission enforces the same burning condition as block
    /// application — same code path, no separate mempool check.
    pub reemission: Option<&'a ReemissionRuleInputs>,
}

impl TipContext<'_> {
    /// Block gap used for the IBD gate. We are "synced" when
    /// `best_header - best_full <= ibd_gate_block_lag`.
    pub fn block_gap(&self) -> u32 {
        self.best_header_height
            .saturating_sub(self.best_full_block_height)
    }
}

/// Bundle of borrows the admission pipeline (`process`, `check`,
/// `commit`) threads end-to-end. Replaces the 11-positional-arg
/// pattern that used to require `#[allow(too_many_arguments)]`.
///
/// `pool` is `&mut` because `commit` (which `process` runs after
/// `check`) inserts and evicts. `check` borrows the same bundle but
/// must NOT mutate `pool` — pool changes belong in `commit` per the
/// 17-step admission contract. The borrow-checker can't enforce
/// that distinction inside a single `&mut AdmissionCtx`, so the
/// invariant is documented and protected by the existing test
/// coverage.
pub struct AdmissionCtx<'a> {
    pub tip_ctx: &'a TipContext<'a>,
    pub config: &'a MempoolConfig,
    pub pool: &'a mut OrderedPool,
    pub budgets: &'a mut CostBudgets,
    pub invalidated: &'a mut InvalidationCache,
    pub unresolved: &'a mut crate::unresolved::UnresolvedCache,
    pub weight_fn: &'a dyn WeightFunction,
}

/// Result of a successful validation. Decoupled from `CheckedTransaction`
/// because the mempool only needs the extracted projection.
#[derive(Debug, Clone)]
pub struct Validated {
    pub tx_id: TxId,
    pub input_box_ids: Vec<Digest32>,
    pub output_box_ids: Vec<Digest32>,
    pub outputs: Vec<ErgoBox>,
    pub fee: u64,
    pub size_bytes: u32,
    pub consumed_cost: u64,
}

/// Validator error classification. Mempool translates each variant
/// into the corresponding admission outcome + peer penalty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationErr {
    /// Bytes did not deserialize into a well-formed transaction.
    Deserialize,
    /// Re-serialization produced different bytes.
    NonCanonical,
    /// Stateless structural violation (size, duplicates, fee output).
    Structural,
    /// An input box was not present in the supplied UTXO view.
    UnresolvedInput,
    /// A data input box was not present in the committed view.
    UnresolvedDataInput,
    /// Script execution rejected the proof.
    ScriptFailed,
    /// ERG/token conservation violated.
    MonetaryFailed,
    /// Cost accumulator exceeded its configured limit.
    CostExceeded,
    /// Anything else validator-defined. Carries a human string for
    /// logs only; admission does not branch on the payload.
    Other(String),
}

/// Pluggable tx validator. Production wires this to ergo-validation;
/// tests inject canned behavior. The validator owns the decision to
/// invoke script evaluation — admission has no opinion on internal
/// validation order, only on the outcome.
/// Cheap pre-validation digest of a parsed tx: just the identity +
/// miner fee. Returned by [`Validator::peek_fee`] so admission can
/// route DroppedBelowMinFee observations with a real tx_id and keep
/// event identity across the min-fee gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeekedTx {
    pub tx_id: TxId,
    pub fee: u64,
}

pub trait Validator {
    /// Cheap pre-check: deserialize `tx_bytes` and extract
    /// `(tx_id, declared miner fee)` without running scripts,
    /// resolving inputs, or touching a `CostAccumulator`. Both
    /// returned fields must match what `validate(..)` would later
    /// expose on its `Validated` for the same bytes; any divergence
    /// is a validator bug.
    ///
    /// Errors: `Deserialize` on malformed bytes. This is the only
    /// error variant `peek_fee` is allowed to return — every other
    /// classification belongs to full validation.
    ///
    /// Overflow policy: fee summation MUST saturate (not panic, not
    /// wrap). A peek_fee value of `u64::MAX` signals "suspiciously
    /// large, pass the gate and let full validation reject via
    /// monetary/structural rules" — cheap gate should never be the
    /// place a malicious tx terminates.
    fn peek_fee(&self, tx_bytes: &[u8]) -> Result<PeekedTx, ValidationErr>;

    /// Validate `tx_bytes` against the supplied UTXO views. The
    /// `input_view` is the `PoolUtxoOverlay` (committed + pool-created),
    /// the `data_input_view` is `CommittedOnly`. Charge consumed cost
    /// to `cx.cost` so the caller can read `cx.cost.consumed()`
    /// afterwards.
    fn validate(
        &self,
        tx_bytes: &[u8],
        input_view: &dyn UtxoView,
        data_input_view: &dyn UtxoView,
        cx: &mut TxValidationCtx<'_>,
    ) -> Result<Validated, ValidationErr>;
}
