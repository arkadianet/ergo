//! Tx-level signing orchestrator. Single entry point: `Prover::sign`.
//!
//! Mirrors Scala `ErgoProvingInterpreter.sign` /
//! `ErgoProvingInterpreter.signInputs`. For each input:
//!
//! 1. **Script gate**: reject any input whose ErgoTree is not in the
//!    currently-supported set (bare ProveDlog/ProveDHTuple or matured
//!    miner-reward wrapper). Context-sensitive scripts verified against a
//!    synthetic context could self-verify against a different context than
//!    the chain uses, producing proofs that the chain rejects.
//! 2. Build a per-input `ReductionContext` from the frozen
//!    `BlockchainStateContext` + box/tx data.
//! 3. Try `trivial_reduce` (cheap path for bare P2PK scripts); fall back
//!    to `reduce_expr_with_cost` for wrapper scripts.
//! 4. Pass the residual `SigmaBoolean` to `prove_sigma`.
//! 5. Wrap proof bytes into `SpendingProof::new`.
//!
//! Cost enforcement is NOT performed here. The bridge self-verify
//! (`self_verify_signed_tx` in `wallet_bridge.rs`) applies the authoritative
//! chain-parity cost gate after signing and rejects any cost overage.
//!
//! The script gate in step 1 can be lifted once the evaluation context is
//! derived from committed chain state rather than a synthetic pre-header.

use ergo_primitives::cost::CostAccumulator;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::input::{Input, SpendingProof};
use ergo_ser::transaction::{bytes_to_sign, Transaction, UnsignedTransaction};

use crate::error::WalletError;
use crate::proving::hints::TransactionHintsBag;
use crate::proving::randomness::OsRngBackend;
use crate::proving::secrets::SecretRegistry;
use crate::proving::sigma::prove_sigma;
use crate::tx_context::{BlockchainParameters, BlockchainStateContext};

/// Transaction-level prover. Holds the pre-derived secret keys and the
/// block-level cost parameters.
pub struct Prover {
    secrets: SecretRegistry,
    // Retained for future use (e.g. chain-state context derivation). The
    // authoritative cost-enforcement gate is the bridge self-verify, not
    // this prover.
    #[allow(dead_code)]
    params: BlockchainParameters,
}

impl Prover {
    pub fn new(secrets: SecretRegistry, params: BlockchainParameters) -> Self {
        Self { secrets, params }
    }

    /// Sign `unsigned_tx`. `boxes_to_spend` MUST be in the same order as
    /// `unsigned_tx.inputs`; `hints` defaults to empty for single-sig.
    ///
    /// **Script gate**: rejects any input whose ErgoTree is not in the
    /// currently-supported set:
    /// - Bare `ProveDlog` / `ProveDHTuple` (trivial_reduce returns Ok).
    /// - Canonical miner-reward wrapper `{ HEIGHT >= R_4 && proveDlog(R_5) }`
    ///   (detected by `ergo_state::wallet::miner_reward::extract_miner_reward_pubkey`).
    ///
    /// Context-sensitive scripts could self-verify against the synthetic
    /// pre-header but fail on the chain's real context. This gate can be
    /// lifted once the context is derived from committed chain state.
    ///
    /// Returns the fully-signed `Transaction` or a `WalletError`.
    pub fn sign(
        &self,
        unsigned_tx: &UnsignedTransaction,
        boxes_to_spend: &[ErgoBox],
        data_boxes: &[ErgoBox],
        state_context: &BlockchainStateContext,
        hints: &TransactionHintsBag,
    ) -> Result<Transaction, WalletError> {
        if unsigned_tx.inputs.len() != boxes_to_spend.len() {
            return Err(WalletError::TxBuild(format!(
                "input count {} != boxes count {}",
                unsigned_tx.inputs.len(),
                boxes_to_spend.len(),
            )));
        }
        if unsigned_tx.data_inputs.len() != data_boxes.len() {
            return Err(WalletError::TxBuild(format!(
                "data input count {} != data boxes count {}",
                unsigned_tx.data_inputs.len(),
                data_boxes.len(),
            )));
        }

        // Script gate: reject unsupported script families before
        // reaching the (synthetic-context) self-verify.
        for (idx, input_box) in boxes_to_spend.iter().enumerate() {
            let ergo_tree = input_box.candidate.ergo_tree();
            let is_trivially_reducible = ergo_sigma::reduce::trivial_reduce(ergo_tree).is_ok();
            let is_miner_reward = ergo_state::wallet::miner_reward::extract_miner_reward_pubkey(
                input_box.candidate.ergo_tree_bytes(),
            )
            .is_some();
            if !is_trivially_reducible && !is_miner_reward {
                return Err(WalletError::TxBuild(format!(
                    "input {idx} has an unsupported script family; \
                     only bare ProveDlog/ProveDHTuple and matured miner-reward \
                     boxes are currently spendable"
                )));
            }
        }

        let message = self.bytes_to_sign_for_tx(unsigned_tx)?;

        // Collect all input extensions once; `build_reduction_owned`
        // borrows the full slice for `input_extensions`.
        let all_input_extensions: Vec<ergo_ser::input::ContextExtension> = unsigned_tx
            .inputs
            .iter()
            .map(|ui| ui.extension.clone())
            .collect();

        let mut signed_inputs = Vec::with_capacity(unsigned_tx.inputs.len());

        for (idx, (unsigned_input, input_box)) in unsigned_tx
            .inputs
            .iter()
            .zip(boxes_to_spend.iter())
            .enumerate()
        {
            let hints_for_input = hints.all_for_input(idx as u32);

            let owned_rc = state_context.build_reduction_owned(
                input_box,
                &unsigned_input.extension,
                boxes_to_spend,
                data_boxes,
                &unsigned_tx.output_candidates,
                &all_input_extensions,
            );
            let reduction_ctx = owned_rc.as_borrowed();

            // Cost enforcement is handled by the bridge self-verify gate
            // (self_verify_signed_tx), which uses chain-parity accounting.
            // An unbounded accumulator suffices here — it will never reject.
            let mut reduce_cost = CostAccumulator::recording_only();

            let ergo_tree = input_box.candidate.ergo_tree();
            let residual_sigma = match ergo_sigma::reduce::trivial_reduce(ergo_tree) {
                Ok(prop) => prop,
                Err(ergo_sigma::reduce::ReductionError::NotTriviallyReducible)
                | Err(ergo_sigma::reduce::ReductionError::BodyConstantNotSigmaProp(_)) => {
                    ergo_sigma::evaluator::reduce_expr_with_cost(
                        &ergo_tree.body,
                        &reduction_ctx,
                        &ergo_tree.constants,
                        &mut reduce_cost,
                    )
                    .map_err(|e| WalletError::TxBuild(format!("reduce: {e:?}")))?
                }
                Err(e) => return Err(WalletError::TxBuild(format!("trivial_reduce: {e:?}"))),
            };

            let (proof, _prove_cost) = prove_sigma(
                &residual_sigma,
                &self.secrets,
                &message,
                &hints_for_input,
                &mut OsRngBackend,
            )?;

            let spending_proof = SpendingProof::new(proof, unsigned_input.extension.clone())
                .map_err(|e| WalletError::TxBuild(format!("SpendingProof::new: {e:?}")))?;
            signed_inputs.push(Input {
                box_id: unsigned_input.box_id,
                spending_proof,
            });
        }

        Ok(Transaction {
            inputs: signed_inputs,
            data_inputs: unsigned_tx.data_inputs.clone(),
            output_candidates: unsigned_tx.output_candidates.clone(),
        })
    }

    /// Compute the Fiat-Shamir message for `unsigned_tx`.
    ///
    /// Mirrors Scala: `bytes_to_sign(Transaction(inputs.map(_.bytesWithoutProof), ...))`.
    fn bytes_to_sign_for_tx(
        &self,
        unsigned_tx: &UnsignedTransaction,
    ) -> Result<Vec<u8>, WalletError> {
        let placeholder_tx = Transaction {
            inputs: unsigned_tx
                .inputs
                .iter()
                .map(|ui| {
                    let sp = SpendingProof::new(Vec::new(), ui.extension.clone())
                        .map_err(|e| WalletError::TxBuild(format!("SpendingProof::new: {e:?}")))?;
                    Ok(Input {
                        box_id: ui.box_id,
                        spending_proof: sp,
                    })
                })
                .collect::<Result<Vec<_>, WalletError>>()?,
            data_inputs: unsigned_tx.data_inputs.clone(),
            output_candidates: unsigned_tx.output_candidates.clone(),
        };
        bytes_to_sign(&placeholder_tx)
            .map_err(|e| WalletError::TxBuild(format!("bytes_to_sign: {e:?}")))
    }
}
