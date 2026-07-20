//! Test-only [`Validator`] with canned per-bytes decisions. Gated behind
//! `#[cfg(any(test, feature = "test-support"))]` at the module
//! declaration so it never enters production builds.

use std::collections::HashMap;

use ergo_primitives::cost::JitCost;
use ergo_primitives::digest::Digest32;
use ergo_validation::{TxValidationCtx, UtxoView};

use crate::types::TxId;

use super::context::{PeekedStructure, PeekedTx, Validated, ValidationErr, Validator};

/// Canned structural peek for [`MockValidator::peek_structure`], keyed by
/// raw bytes independently of the [`MockPlan`] `validate` result. Lets an
/// orphan test return real input/output box-ids from `peek_structure`
/// while `validate` still returns `UnresolvedInput` — the two are
/// deliberately decoupled (production derives both from the same parse,
/// but the mock must stage them separately).
#[derive(Debug, Clone)]
pub struct MockStructure {
    pub tx_id: TxId,
    pub fee: u64,
    pub input_box_ids: Vec<Digest32>,
    pub output_box_ids: Vec<Digest32>,
}

/// Test-only validator: returns canned decisions per (tx_id, bytes).
/// Exposed at the crate root behind `feature = "test-support"` so
/// integration tests can inject predictable outcomes without leaking
/// the mock into production builds.
pub struct MockValidator {
    /// Responses keyed by raw bytes. If absent, validator errors with
    /// `ValidationErr::Deserialize` so callers can tell "unconfigured"
    /// from "canned success".
    plans: HashMap<Vec<u8>, MockPlan>,
    /// Canned structural peeks, keyed by raw bytes. Consulted first by
    /// `peek_structure`; absent an entry it falls back to deriving the
    /// projection from the plan (see `peek_structure`).
    structures: HashMap<Vec<u8>, MockStructure>,
    /// Counts calls to `validate(..)`. Used by tests that prove the
    /// admission pipeline short-circuited before full validation
    /// (e.g. below-min-fee gate).
    validate_calls: std::cell::Cell<usize>,
    /// Counts calls to `peek_fee(..)`. Useful for asserting the cheap
    /// gate runs exactly once per admission.
    peek_fee_calls: std::cell::Cell<usize>,
}

#[derive(Debug, Clone)]
pub struct MockPlan {
    pub result: Result<Validated, ValidationErr>,
    /// Cost to charge into the accumulator before returning.
    pub charge: u64,
    /// Fee value returned from `peek_fee`. Independent of `result` so
    /// tests can stage scenarios like "fee passes min-fee gate but
    /// full validation rejects." If `None`, derived from the plan:
    /// successful `result.fee` or 0 for rejections.
    pub peek_fee: Option<u64>,
    /// Tx id returned from `peek_fee`. If `None`, derived from the
    /// plan: successful `result.tx_id` or `Digest32::ZERO` for
    /// rejections. Tests staging Err-result-with-passing-peek-fee
    /// should set this so the admission event carries a meaningful
    /// id.
    pub peek_tx_id: Option<TxId>,
}

impl Default for MockValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl MockValidator {
    pub fn new() -> Self {
        Self {
            plans: HashMap::new(),
            structures: HashMap::new(),
            validate_calls: std::cell::Cell::new(0),
            peek_fee_calls: std::cell::Cell::new(0),
        }
    }

    pub fn plan(mut self, bytes: impl Into<Vec<u8>>, plan: MockPlan) -> Self {
        self.plans.insert(bytes.into(), plan);
        self
    }

    /// Register a canned structural peek for `bytes`, independent of the
    /// plan's `validate` result. Needed to stage orphans: `peek_structure`
    /// returns these ids while `validate` still fails `UnresolvedInput`.
    pub fn structure(mut self, bytes: impl Into<Vec<u8>>, structure: MockStructure) -> Self {
        self.structures.insert(bytes.into(), structure);
        self
    }

    pub fn validate_call_count(&self) -> usize {
        self.validate_calls.get()
    }

    pub fn peek_fee_call_count(&self) -> usize {
        self.peek_fee_calls.get()
    }
}

impl Validator for MockValidator {
    fn peek_fee(&self, tx_bytes: &[u8]) -> Result<PeekedTx, ValidationErr> {
        self.peek_fee_calls.set(self.peek_fee_calls.get() + 1);
        // Mock reports (tx_id, fee) per the plan's overrides, or
        // falls back to the plan's result (successful validation's
        // values, or zeros on a planned error). Production
        // `ErgoValidator` deserializes + computes tx_id via
        // bytes_to_sign + matches fee proposition.
        let plan = self.plans.get(tx_bytes).ok_or(ValidationErr::Deserialize)?;
        let default_fee = match &plan.result {
            Ok(v) => v.fee,
            Err(_) => 0,
        };
        let default_tx_id = match &plan.result {
            Ok(v) => v.tx_id,
            Err(_) => ergo_primitives::digest::Digest32::ZERO,
        };
        Ok(PeekedTx {
            tx_id: plan.peek_tx_id.unwrap_or(default_tx_id),
            fee: plan.peek_fee.unwrap_or(default_fee),
        })
    }

    fn peek_structure(&self, tx_bytes: &[u8]) -> Result<PeekedStructure, ValidationErr> {
        // A registered structure wins outright — the orphan-staging path.
        if let Some(s) = self.structures.get(tx_bytes) {
            return Ok(PeekedStructure {
                tx_id: s.tx_id,
                fee: s.fee,
                input_box_ids: s.input_box_ids.clone(),
                // The mock does not model data inputs; tests exercising
                // data-input paths use the pool-aware probe instead.
                data_input_box_ids: Vec::new(),
                output_box_ids: s.output_box_ids.clone(),
            });
        }
        // Otherwise derive from the plan, mirroring `peek_fee` for
        // tx_id/fee and reusing the validated projection for box-ids on a
        // planned success (empty on a planned error, matching an orphan
        // that registered no structure).
        let plan = self.plans.get(tx_bytes).ok_or(ValidationErr::Deserialize)?;
        let (default_fee, default_tx_id, inputs, outputs) = match &plan.result {
            Ok(v) => (
                v.fee,
                v.tx_id,
                v.input_box_ids.clone(),
                v.output_box_ids.clone(),
            ),
            Err(_) => (0, Digest32::ZERO, Vec::new(), Vec::new()),
        };
        Ok(PeekedStructure {
            tx_id: plan.peek_tx_id.unwrap_or(default_tx_id),
            fee: plan.peek_fee.unwrap_or(default_fee),
            input_box_ids: inputs,
            data_input_box_ids: Vec::new(),
            output_box_ids: outputs,
        })
    }

    fn validate(
        &self,
        tx_bytes: &[u8],
        _input_view: &dyn UtxoView,
        _data_input_view: &dyn UtxoView,
        cx: &mut TxValidationCtx<'_>,
    ) -> Result<Validated, ValidationErr> {
        self.validate_calls.set(self.validate_calls.get() + 1);
        let plan = self
            .plans
            .get(tx_bytes)
            .cloned()
            .ok_or(ValidationErr::Deserialize)?;
        // Always charge; even on rejection the mempool must see the
        // consumed cost to apply partial-charge semantics. Test stub
        // tolerates JitCost overflow by silently skipping the charge —
        // tests exercising overflow set `plan.charge` themselves.
        if let Ok(jc) = JitCost::from_block_cost(plan.charge) {
            let _ = cx.cost.add(jc);
        }
        plan.result
    }
}
