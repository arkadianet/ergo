//! Blockchain context types for the proving orchestrator.
//!
//! Provides the per-transaction context that `Prover::sign` needs to
//! reduce each input's ErgoTree to a `SigmaBoolean` before proving.
//!
//! Mirrors Scala `ErgoLikeContext` / `BlockchainStateContext`.

use ergo_primitives::digest::ADDigest;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::input::ContextExtension;
use ergo_ser::sigma_value::AvlTreeData;
use ergo_sigma::evaluator::{EvalBox, EvalHeader, ReductionContext};
use ergo_validation::pre_header::{build_last_block_utxo_root, CandidatePreHeader};
use indexmap::IndexMap;

/// Blockchain state snapshot needed for signing.
///
/// Populated by `ChainStateAccessor::build_signing_context` in the wallet
/// writer task. Carries only the fields the per-input evaluator needs;
/// chain-apply state stays in `StateStore`.
pub struct BlockchainStateContext {
    /// Last ≤10 applied headers, tip-first. `sigma_last_headers[0]` is
    /// the parent of the candidate block.
    pub sigma_last_headers: Vec<ergo_ser::header::Header>,
    /// Pre-header for the candidate block under construction.
    pub sigma_pre_header: CandidatePreHeader,
    /// AVL+ root of the UTXO state before applying the candidate.
    /// Used to construct `CONTEXT.LastBlockUtxoRootHash`.
    pub previous_state_digest: ADDigest,
}

/// Per-block parameters used by the prover for cost accounting.
pub struct BlockchainParameters {
    /// Maximum aggregate JIT cost the block is allowed to accumulate.
    pub max_block_cost: u64,
    /// Per-input base cost charged before script evaluation.
    pub input_cost: u64,
    /// Per-data-input base cost.
    pub data_input_cost: u64,
    /// Per-output cost.
    pub output_cost: u64,
    /// Cost per distinct token access across inputs/outputs.
    pub token_access_cost: u64,
    /// Interpreter initialization cost (constant per block).
    pub interpreter_init_cost: u64,
    /// Wire block version (from the block header's version byte).
    pub block_version: u8,
}

impl BlockchainParameters {
    /// Returns `block_version - 1`, the activated script version the
    /// evaluator uses to gate soft-fork method calls.
    pub fn activated_script_version(&self) -> u8 {
        self.block_version.saturating_sub(1)
    }
}

/// Owned counterpart to `ergo_sigma::evaluator::ReductionContext<'a>`.
///
/// Holds all per-input evaluation data in owned form so the caller can
/// produce the borrowed `ReductionContext<'_>` without lifetime gymnastics.
/// Built once per input by `BlockchainStateContext::build_reduction_owned`.
pub struct ReductionContextOwned {
    pub height: u32,
    pub self_box: EvalBox,
    pub self_creation_height: u32,
    pub outputs: Vec<EvalBox>,
    pub inputs: Vec<EvalBox>,
    pub data_inputs: Vec<EvalBox>,
    pub miner_pubkey: [u8; 33],
    pub pre_header_timestamp: u64,
    pub pre_header_version: u8,
    pub pre_header_parent_id: [u8; 32],
    pub pre_header_n_bits: u64,
    pub pre_header_votes: [u8; 3],
    pub extension: IndexMap<
        u8,
        (
            ergo_ser::sigma_type::SigmaType,
            ergo_ser::sigma_value::SigmaValue,
        ),
    >,
    pub input_extensions: Vec<
        IndexMap<
            u8,
            (
                ergo_ser::sigma_type::SigmaType,
                ergo_ser::sigma_value::SigmaValue,
            ),
        >,
    >,
    pub last_headers: Vec<EvalHeader>,
    pub last_block_utxo_root: Option<AvlTreeData>,
    pub activated_script_version: u8,
}

impl ReductionContextOwned {
    /// Produce the borrowed `ReductionContext<'_>` that `reduce_expr_with_cost`
    /// and `verify_spending_proof_with_context_and_cost` require.
    pub fn as_borrowed(&self) -> ReductionContext<'_> {
        ReductionContext {
            height: self.height,
            self_box: Some(&self.self_box),
            self_creation_height: self.self_creation_height,
            outputs: &self.outputs,
            inputs: &self.inputs,
            data_inputs: &self.data_inputs,
            miner_pubkey: self.miner_pubkey,
            pre_header_timestamp: self.pre_header_timestamp,
            pre_header_version: self.pre_header_version,
            pre_header_parent_id: self.pre_header_parent_id,
            pre_header_n_bits: self.pre_header_n_bits,
            pre_header_votes: self.pre_header_votes,
            extension: self.extension.clone(),
            input_extensions: &self.input_extensions,
            last_headers: &self.last_headers,
            last_block_utxo_root: self.last_block_utxo_root.clone(),
            activated_script_version: self.activated_script_version,
            // ErgoTree HEADER version of the box being spent (low 3 bits of the
            // tree's first byte), distinct from activatedScriptVersion. Drives
            // the v6 SHeader data-serialization gate (isV3OrLaterErgoTreeVersion).
            ergo_tree_version: self.self_box.script_bytes.first().map_or(0, |b| b & 0x07),
        }
    }
}

impl BlockchainStateContext {
    /// Build a per-input `ReductionContextOwned` from the transaction-level context.
    ///
    /// Arguments:
    /// - `self_box_ergo`: the input box being spent.
    /// - `extension`: context extension from the unsigned input's spending proof slot.
    /// - `all_inputs`: all boxes being spent in the transaction (in input order).
    /// - `data_inputs`: all read-only data boxes referenced by the transaction.
    /// - `outputs`: output candidates that this transaction will create.
    /// - `all_input_extensions`: per-input extensions indexed by input position.
    pub fn build_reduction_owned(
        &self,
        self_box_ergo: &ErgoBox,
        extension: &ContextExtension,
        all_inputs: &[ErgoBox],
        data_inputs: &[ErgoBox],
        outputs: &[ErgoBoxCandidate],
        all_input_extensions: &[ContextExtension],
    ) -> ReductionContextOwned {
        // Convert headers — compute header_id via serialize_header.
        let last_headers: Vec<EvalHeader> = self
            .sigma_last_headers
            .iter()
            .filter_map(|h| {
                ergo_ser::header::serialize_header(h)
                    .ok()
                    .map(|(_, id)| EvalHeader::from_header(h, *id.as_bytes()))
            })
            .collect();

        // Derive last_block_utxo_root from the previous state digest.
        // Matches Scala's ErgoInterpreter.avlTreeFromDigest + AllOperationsAllowed.
        let last_block_utxo_root = Some(build_last_block_utxo_root(self.previous_state_digest));

        // Build EvalBoxes for all transaction participants. Failures are
        // swallowed with simple fallback EvalBox so signing can proceed;
        // the verifier step (test / production self-verify) will catch any
        // semantics mismatch.
        let eval_inputs: Vec<EvalBox> = all_inputs
            .iter()
            .enumerate()
            .map(|(i, b)| ergo_box_to_eval_box_simple(b, i))
            .collect();

        let eval_outputs: Vec<EvalBox> = outputs
            .iter()
            .enumerate()
            .map(|(i, c)| candidate_to_eval_box_simple(c, i))
            .collect();

        let eval_data_inputs: Vec<EvalBox> = data_inputs
            .iter()
            .enumerate()
            .map(|(i, b)| ergo_box_to_eval_box_simple(b, i))
            .collect();

        // Locate self_box in eval_inputs (matched by box_id bytes).
        // Falls back to a freshly converted box if not found.
        let self_box_id = self_box_ergo
            .box_id()
            .map(|id| *id.as_bytes())
            .unwrap_or([0u8; 32]);
        let self_box = eval_inputs
            .iter()
            .find(|b| b.id == self_box_id)
            .cloned()
            .unwrap_or_else(|| ergo_box_to_eval_box_simple(self_box_ergo, 0));

        // Build per-input extension map slice (for SContext.getVarFromInput).
        let input_extensions: Vec<
            IndexMap<
                u8,
                (
                    ergo_ser::sigma_type::SigmaType,
                    ergo_ser::sigma_value::SigmaValue,
                ),
            >,
        > = all_input_extensions
            .iter()
            .map(|ext| ext.values.clone())
            .collect();

        let ph = &self.sigma_pre_header;
        ReductionContextOwned {
            height: ph.height,
            self_box,
            self_creation_height: self_box_ergo.candidate.creation_height,
            outputs: eval_outputs,
            inputs: eval_inputs,
            data_inputs: eval_data_inputs,
            miner_pubkey: ph.miner_pubkey,
            pre_header_timestamp: ph.timestamp,
            pre_header_version: ph.version,
            pre_header_parent_id: ph.parent_id,
            pre_header_n_bits: ph.n_bits as u64,
            pre_header_votes: ph.votes,
            extension: extension.values.clone(),
            input_extensions,
            last_headers,
            last_block_utxo_root,
            activated_script_version: ph.version.saturating_sub(1),
        }
    }
}

/// Convert an `ErgoBox` to `EvalBox` for evaluation.
///
/// Mirrors `ergo_validation::tx::script::ergo_box_to_eval_box` but
/// without requiring the `ergo-validation` crate as a dependency.
/// `raw_bytes` is populated for `ExtractBytes` (0xC3) script access;
/// fallback to empty on serialization failure keeps signing alive while
/// the verifier step surfaces any semantics issues.
fn ergo_box_to_eval_box_simple(b: &ErgoBox, _index: usize) -> EvalBox {
    let id = b.box_id().map(|id| *id.as_bytes()).unwrap_or([0u8; 32]);

    let raw_bytes = {
        let mut w = ergo_primitives::writer::VlqWriter::new();
        ergo_ser::ergo_box::write_ergo_box(&mut w, b)
            .ok()
            .map(|_| w.result())
            .unwrap_or_default()
    };

    let registers = copy_registers_to_eval(&b.candidate);

    EvalBox {
        creation_height: b.candidate.creation_height,
        script_bytes: b.candidate.ergo_tree_bytes().to_vec(),
        value: b.candidate.value as i64,
        id,
        transaction_id: *b.transaction_id.as_bytes(),
        output_index: b.index,
        registers,
        tokens: b
            .candidate
            .tokens
            .iter()
            .map(|t| (*t.token_id.as_bytes(), t.amount))
            .collect(),
        raw_bytes,
    }
}

/// Convert an output `ErgoBoxCandidate` to `EvalBox` for evaluation.
/// The box ID is derived from a synthetic box with a zero transaction ID.
fn candidate_to_eval_box_simple(c: &ErgoBoxCandidate, index: usize) -> EvalBox {
    // Build a temporary ErgoBox to derive the box_id.
    let temp_box = ErgoBox {
        candidate: c.clone(),
        transaction_id: ergo_primitives::digest::ModifierId::from_bytes([0u8; 32]),
        index: index as u16,
    };
    let id = temp_box
        .box_id()
        .map(|id| *id.as_bytes())
        .unwrap_or([0u8; 32]);
    let raw_bytes = {
        let mut w = ergo_primitives::writer::VlqWriter::new();
        ergo_ser::ergo_box::write_ergo_box(&mut w, &temp_box)
            .ok()
            .map(|_| w.result())
            .unwrap_or_default()
    };
    let registers = copy_registers_to_eval(c);
    EvalBox {
        creation_height: c.creation_height,
        script_bytes: c.ergo_tree_bytes().to_vec(),
        value: c.value as i64,
        id,
        transaction_id: [0u8; 32],
        output_index: index as u16,
        registers,
        tokens: c
            .tokens
            .iter()
            .map(|t| (*t.token_id.as_bytes(), t.amount))
            .collect(),
        raw_bytes,
    }
}

/// Copy the additional registers from an `ErgoBoxCandidate` into the
/// `[Option<RegisterValue>; 6]` layout that `EvalBox` uses.
///
/// `AdditionalRegisters.registers` is a densely-packed `Vec` (R4 first);
/// slots past the vec's length are `None`.
fn copy_registers_to_eval(c: &ErgoBoxCandidate) -> [Option<ergo_ser::register::RegisterValue>; 6] {
    let regs = &c.additional_registers.registers;
    std::array::from_fn(|i| regs.get(i).cloned())
}
