//! Blockchain context types for the proving orchestrator.
//!
//! Provides the per-transaction context that `Prover::sign` needs to
//! reduce each input's ErgoTree to a `SigmaBoolean` before proving.
//!
//! Mirrors Scala `ErgoLikeContext` / `BlockchainStateContext`.

use crate::WalletError;
use ergo_primitives::digest::ADDigest;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::input::ContextExtension;
use ergo_ser::pre_header::CandidatePreHeader;
use ergo_ser::sigma_value::AvlTreeData;
use ergo_sigma::evaluator::SigmaValidationSettings;
use ergo_sigma::evaluator::{EvalBox, EvalHeader, ReductionContext};
use indexmap::IndexMap;

/// Blockchain state snapshot needed for signing.
///
/// Populated by the wallet engine's committed signing view
/// (`WalletChainAccess::signing_view` / `build_signing_context`). Carries
/// only the fields the per-input evaluator needs; chain-apply state stays in
/// `StateStore`.
#[derive(Clone)]
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
#[derive(Clone)]
pub struct BlockchainParameters {
    /// Maximum aggregate block cost the block is allowed to accumulate.
    pub max_block_cost: u64,
    /// Per-input base cost charged before script evaluation.
    pub input_cost: u64,
    /// Per-data-input base cost.
    pub data_input_cost: u64,
    /// Per-output cost.
    pub output_cost: u64,
    /// Cost per distinct token access across inputs/outputs.
    pub token_access_cost: u64,
    /// Interpreter initialization cost (constant per transaction).
    pub interpreter_init_cost: u64,
    /// Wire block version (from the block header's version byte).
    pub block_version: u8,
}

impl BlockchainParameters {
    /// Returns `block_version - 1`, the activated script version the
    /// evaluator uses to gate soft-fork method calls.
    pub fn activated_script_version(&self) -> u8 {
        self.block_version.wrapping_sub(1)
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
    pub validation_settings: SigmaValidationSettings,
}

impl ReductionContextOwned {
    /// Produce the borrowed `ReductionContext<'_>` that `reduce_expr_with_cost`
    /// and `verify_spending_proof_with_context_and_cost` require.
    pub fn as_borrowed(&self) -> ReductionContext<'_> {
        ReductionContext {
            validation_settings: self.validation_settings.clone(),
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
            activated_script_version: ph.version.wrapping_sub(1),
            validation_settings: Default::default(),
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
        lazy_vals: Default::default(),
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
        register_bytes: b.candidate.register_bytes().to_vec(),
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
        lazy_vals: Default::default(),
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
        register_bytes: c.register_bytes().to_vec(),
    }
}

/// Copy the additional registers from an `ErgoBoxCandidate` into the
/// `[Option<RegisterValue>; 6]` layout that `EvalBox` uses.
///
/// `AdditionalRegisters.registers` is a densely-packed `Vec` (R4 first);
/// slots past the vec's length are `None`.
fn copy_registers_to_eval(c: &ErgoBoxCandidate) -> [Option<ergo_ser::register::RegisterValue>; 6] {
    let regs = &c.additional_registers().registers;
    std::array::from_fn(|i| regs.get(i).cloned())
}

/// An explicit frozen chain context for full contract reduction.
/// The caller supplies the chain snapshot and its trusted header ids, rather
/// than re-creating ids from potentially noncanonical wire encodings. The
/// library checks context coherence; it does not authenticate the chain.
pub struct SigningContext<'a> {
    pub state_context: &'a BlockchainStateContext,
    pub header_ids: &'a [[u8; 32]],
    pub validation_settings: &'a SigmaValidationSettings,
}

fn build_last_block_utxo_root(digest: ADDigest) -> AvlTreeData {
    AvlTreeData {
        digest: digest.as_bytes().to_vec(),
        insert_allowed: true,
        update_allowed: true,
        remove_allowed: true,
        key_length: 32,
        value_length_opt: None,
    }
}

impl SigningContext<'_> {
    /// Build one input's context without fallback ids or discarded serialization errors.
    pub fn build_reduction_owned_for_tx(
        &self,
        tx: &ergo_ser::transaction::UnsignedTransaction,
        input_index: usize,
        inputs: &[ErgoBox],
        data_inputs: &[ErgoBox],
        activated_script_version: u8,
    ) -> Result<ReductionContextOwned, WalletError> {
        if tx.inputs.len() != inputs.len()
            || tx.data_inputs.len() != data_inputs.len()
            || input_index >= inputs.len()
            || self.header_ids.len() != self.state_context.sigma_last_headers.len()
            || self.header_ids.len() > 10
            || tx.inputs.len() > i16::MAX as usize
            || tx.data_inputs.len() > i16::MAX as usize
            || tx.output_candidates.is_empty()
            || tx.output_candidates.len() > i16::MAX as usize
        {
            return Err(WalletError::TxBuild(
                "inconsistent transaction or header context".into(),
            ));
        }
        let ph = &self.state_context.sigma_pre_header;
        if let Some(header) = self.state_context.sigma_last_headers.first() {
            if ph.parent_id != self.header_ids[0]
                || header.height.checked_add(1) != Some(ph.height)
                || header.state_root != self.state_context.previous_state_digest
            {
                return Err(WalletError::TxBuild(
                    "pre-header or UTXO root differs from chain tip".into(),
                ));
            }
        }
        for (index, headers) in self.state_context.sigma_last_headers.windows(2).enumerate() {
            if headers[0].parent_id.as_bytes() != &self.header_ids[index + 1]
                || headers[1].height.checked_add(1) != Some(headers[0].height)
            {
                return Err(WalletError::TxBuild(
                    "headers are not a contiguous tip-first chain".into(),
                ));
            }
        }
        // Check serialization bounds without substituting recomputed identities.
        // A malformed header must not disappear from the context or survive as
        // an invalid script-visible Header merely because this script ignores it.
        let mut header_writer = ergo_primitives::writer::VlqWriter::new();
        for header in &self.state_context.sigma_last_headers {
            ergo_ser::header::write_header(&mut header_writer, header)
                .map_err(|e| WalletError::TxBuild(e.to_string()))?;
        }
        for (input, b) in tx.inputs.iter().zip(inputs) {
            if input.box_id
                != b.box_id()
                    .map_err(|e| WalletError::TxBuild(e.to_string()))?
            {
                return Err(WalletError::TxBuild(
                    "spending box does not match input id/order".into(),
                ));
            }
        }
        for (input, b) in tx.data_inputs.iter().zip(data_inputs) {
            if input.box_id
                != b.box_id()
                    .map_err(|e| WalletError::TxBuild(e.to_string()))?
            {
                return Err(WalletError::TxBuild(
                    "data box does not match input id/order".into(),
                ));
            }
        }
        let message = crate::reduced_message::bytes_to_sign_bounded(
            tx,
            crate::reduced::MAX_REDUCED_TRANSACTION_BYTES,
        )?;
        let tx_id = ergo_primitives::digest::blake2b256(&message);
        let mut all_outputs = Vec::with_capacity(tx.output_candidates.len());
        for (i, candidate) in tx.output_candidates.iter().enumerate() {
            all_outputs.push(strict_eval_box(&ErgoBox {
                candidate: candidate.clone(),
                transaction_id: ergo_primitives::digest::ModifierId::from_bytes(*tx_id.as_bytes()),
                index: i as u16,
            })?);
        }
        let eval_inputs = inputs
            .iter()
            .map(strict_eval_box)
            .collect::<Result<Vec<_>, _>>()?;
        let eval_data = data_inputs
            .iter()
            .map(strict_eval_box)
            .collect::<Result<Vec<_>, _>>()?;
        let last_headers = self
            .state_context
            .sigma_last_headers
            .iter()
            .zip(self.header_ids)
            .map(|(h, id)| EvalHeader::from_header(h, *id))
            .collect();
        Ok(ReductionContextOwned {
            height: ph.height,
            self_box: eval_inputs[input_index].clone(),
            self_creation_height: inputs[input_index].candidate.creation_height,
            inputs: eval_inputs,
            outputs: all_outputs,
            data_inputs: eval_data,
            miner_pubkey: ph.miner_pubkey,
            pre_header_timestamp: ph.timestamp,
            pre_header_version: ph.version,
            pre_header_parent_id: ph.parent_id,
            pre_header_n_bits: ph.n_bits as u64,
            pre_header_votes: ph.votes,
            extension: tx.inputs[input_index].extension.values.clone(),
            input_extensions: tx
                .inputs
                .iter()
                .map(|i| i.extension.values.clone())
                .collect(),
            last_headers,
            last_block_utxo_root: Some(build_last_block_utxo_root(
                self.state_context.previous_state_digest,
            )),
            validation_settings: self.validation_settings.clone(),
            activated_script_version,
        })
    }
}

fn strict_eval_box(b: &ErgoBox) -> Result<EvalBox, WalletError> {
    if b.candidate.value > i64::MAX as u64
        || b.candidate
            .tokens
            .iter()
            .any(|t| t.amount > i64::MAX as u64)
    {
        return Err(WalletError::TxBuild("box value exceeds signed Long".into()));
    }
    let id = b
        .box_id()
        .map_err(|e| WalletError::TxBuild(e.to_string()))?;
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::ergo_box::write_ergo_box(&mut w, b)
        .map_err(|e| WalletError::TxBuild(e.to_string()))?;
    Ok(EvalBox {
        lazy_vals: std::sync::Arc::new(ergo_sigma::evaluator::EvalBoxLazyVals::from_candidate(
            &b.candidate,
        )),
        creation_height: b.candidate.creation_height,
        script_bytes: b.candidate.ergo_tree_bytes().to_vec(),
        value: b.candidate.value as i64,
        id: *id.as_bytes(),
        transaction_id: *b.transaction_id.as_bytes(),
        output_index: b.index,
        registers: copy_registers_to_eval(&b.candidate),
        tokens: b
            .candidate
            .tokens
            .iter()
            .map(|t| (*t.token_id.as_bytes(), t.amount))
            .collect(),
        raw_bytes: w.result(),
        register_bytes: b.candidate.register_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::{
        digest::{Digest32, ModifierId},
        group_element::GroupElement,
        reader::VlqReader,
    };
    use ergo_ser::{autolykos::AutolykosSolution, header::Header};

    fn sample_transaction() -> (crate::ReducedTransaction, Vec<ErgoBox>) {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../test-vectors/wallet/reduced_scala_6_0_7.json"
        ))
        .unwrap();
        let row = &fixture["cases"][0];
        let bytes = hex::decode(row["reduced_hex"].as_str().unwrap()).unwrap();
        let reduced = crate::ReducedTransaction::from_bytes(&bytes, 4).unwrap();
        let inputs = row["input_boxes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| {
                let bytes = hex::decode(value.as_str().unwrap()).unwrap();
                ergo_ser::ergo_box::read_ergo_box(
                    &mut VlqReader::new(&bytes).with_activated_script_version(3),
                )
                .unwrap()
            })
            .collect();
        (reduced, inputs)
    }

    fn header(height: u32, parent: [u8; 32]) -> Header {
        Header {
            version: 4,
            parent_id: ModifierId::from_bytes(parent),
            ad_proofs_root: Digest32::from_bytes([1; 32]),
            transactions_root: Digest32::from_bytes([2; 32]),
            state_root: ADDigest::from_bytes([9; 33]),
            timestamp: 1,
            extension_root: Digest32::from_bytes([3; 32]),
            n_bits: 0,
            height,
            votes: [0; 3],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes(ergo_sigma::evaluator::SECP256K1_GENERATOR),
                nonce: [0; 8],
            },
        }
    }

    fn state() -> BlockchainStateContext {
        BlockchainStateContext {
            sigma_last_headers: vec![header(399_999, [8; 32]), header(399_998, [6; 32])],
            sigma_pre_header: CandidatePreHeader {
                version: 4,
                parent_id: [7; 32],
                height: 400_000,
                timestamp: 2,
                n_bits: 0,
                votes: [0; 3],
                miner_pubkey: ergo_sigma::evaluator::SECP256K1_GENERATOR,
            },
            previous_state_digest: ADDigest::from_bytes([9; 33]),
        }
    }

    #[test]
    fn explicit_context_preserves_supplied_header_ids_and_validation_settings() {
        let (reduced, inputs) = sample_transaction();
        let state = state();
        let ids = [[7; 32], [8; 32]];
        let mut settings = SigmaValidationSettings::default();
        settings
            .0
            .insert(1001, ergo_sigma::evaluator::RuleStatus::Disabled);
        let context = SigningContext {
            state_context: &state,
            header_ids: &ids,
            validation_settings: &settings,
        };
        let owned = context
            .build_reduction_owned_for_tx(&reduced.unsigned_transaction, 0, &inputs, &[], 3)
            .unwrap();
        assert_eq!(owned.last_headers[0].id, ids[0]);
        assert_eq!(owned.last_headers[1].id, ids[1]);
        assert_ne!(
            owned.last_headers[0].id,
            *ergo_ser::header::serialize_header(&state.sigma_last_headers[0])
                .unwrap()
                .1
                .as_bytes(),
        );
        assert_eq!(owned.as_borrowed().validation_settings, settings);
    }

    #[test]
    fn explicit_context_rejects_mixed_header_snapshots() {
        let (reduced, inputs) = sample_transaction();
        let ids = [[7; 32], [8; 32]];
        let settings = SigmaValidationSettings::default();
        let build = |state: &BlockchainStateContext, ids: &[[u8; 32]], version| {
            SigningContext {
                state_context: state,
                header_ids: ids,
                validation_settings: &settings,
            }
            .build_reduction_owned_for_tx(
                &reduced.unsigned_transaction,
                0,
                &inputs,
                &[],
                version,
            )
        };
        let mut mixed = state();
        mixed.sigma_pre_header.parent_id = [1; 32];
        assert!(build(&mixed, &ids, 3).is_err());
        let mut mixed = state();
        mixed.previous_state_digest = ADDigest::from_bytes([1; 33]);
        assert!(build(&mixed, &ids, 3).is_err());
        let mut mixed = state();
        mixed.sigma_last_headers[1].height += 1;
        assert!(build(&mixed, &ids, 3).is_err());
        let mut mixed = state();
        mixed.sigma_last_headers[0].parent_id = ModifierId::from_bytes([1; 32]);
        assert!(build(&mixed, &ids, 3).is_err());
        let mut mixed = state();
        mixed.sigma_last_headers[0].unparsed_bytes = vec![1];
        assert!(build(&mixed, &ids, 3).is_err());
        assert!(build(&state(), &ids[..1], 3).is_err());
    }

    #[test]
    fn activated_script_version_is_independent_of_script_visible_preheader_version() {
        let (reduced, inputs) = sample_transaction();
        let state = state();
        let settings = SigmaValidationSettings::default();
        let context = SigningContext {
            state_context: &state,
            header_ids: &[[7; 32], [8; 32]],
            validation_settings: &settings,
        };
        // Protocol parameters fix activation independently of a mid-epoch
        // physical header version, as SDK ReducingInterpreter's context does.
        let owned = context
            .build_reduction_owned_for_tx(&reduced.unsigned_transaction, 0, &inputs, &[], 2)
            .unwrap();
        assert_eq!(owned.as_borrowed().activated_script_version, 2);
        assert_eq!(owned.as_borrowed().pre_header_version, 4);

        let params = BlockchainParameters {
            max_block_cost: 1_000_000,
            input_cost: 2000,
            data_input_cost: 100,
            output_cost: 100,
            token_access_cost: 100,
            interpreter_init_cost: 10000,
            block_version: 3,
        };
        let prover = crate::proving::prover::Prover::new(
            crate::proving::secrets::SecretRegistry::empty(),
            params,
        );
        let actual = prover
            .reduce_transaction(&reduced.unsigned_transaction, &inputs, &[], &context)
            .unwrap();
        assert_eq!(actual.to_bytes().unwrap(), reduced.to_bytes().unwrap());
    }

    #[test]
    fn strict_context_rejects_unrepresentable_box_values_without_fallback() {
        let (mut reduced, mut inputs) = sample_transaction();
        inputs[0].candidate.value = u64::MAX;
        reduced.unsigned_transaction.inputs[0].box_id = inputs[0].box_id().unwrap();
        let state = state();
        let settings = SigmaValidationSettings::default();
        let context = SigningContext {
            state_context: &state,
            header_ids: &[[7; 32], [8; 32]],
            validation_settings: &settings,
        };
        assert!(context
            .build_reduction_owned_for_tx(&reduced.unsigned_transaction, 0, &inputs, &[], 3)
            .is_err());
    }
}
