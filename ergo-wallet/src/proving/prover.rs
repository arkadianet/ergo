//! Transaction-level signing and explicit-context reduction.
//!
//! [`Prover::sign`] preserves the conservative script gate when passed the
//! legacy [`BlockchainStateContext`]. A caller passing an explicit
//! [`crate::tx_context::SigningContext`] signs by reducing all contracts once
//! against its intended candidate context, then proving the frozen propositions.
//! The caller supplies chain trust and must check that the transaction is valid
//! for the context where it will be submitted.
//!
//! [`Prover::reduce_transaction`] and [`Prover::sign_reduced`] enforce reduction
//! and proof budgets. The legacy path still relies on host self-verification for
//! consensus cost enforcement and structural validation.

use ergo_primitives::cost::CostAccumulator;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::input::{Input, SpendingProof};
use ergo_ser::transaction::{bytes_to_sign, Transaction, UnsignedTransaction};

use crate::error::WalletError;
use crate::proving::hints::TransactionHintsBag;
use crate::proving::miner_reward::extract_miner_reward_pubkey;
use crate::proving::randomness::OsRngBackend;
use crate::proving::secrets::SecretRegistry;
use crate::proving::sigma::prove_sigma;
use crate::tx_context::{BlockchainParameters, BlockchainStateContext};

/// Transaction-level prover. Holds the pre-derived secret keys and the
/// block-level cost parameters.
pub struct Prover {
    secrets: SecretRegistry,
    params: BlockchainParameters,
}

impl Prover {
    pub fn new(secrets: SecretRegistry, params: BlockchainParameters) -> Self {
        Self { secrets, params }
    }

    /// Reduce all contracts against an explicit frozen chain context, enforcing
    /// the Scala transaction initialization, token access and interpreter budget.
    /// This checks participant identity and script evaluation, not transaction
    /// validity or asset intent. The caller validates ERG/token conservation,
    /// mint IDs, approved burns, output constraints and network-specific rules.
    /// Unlike AppKit's higher-level reducer, this API has no `tokensToBurn` policy.
    pub fn reduce_transaction(
        &self,
        tx: &UnsignedTransaction,
        boxes: &[ErgoBox],
        data_boxes: &[ErgoBox],
        context: &crate::tx_context::SigningContext<'_>,
    ) -> Result<crate::ReducedTransaction, WalletError> {
        use ergo_primitives::cost::JitCost;
        use std::collections::BTreeSet;
        if tx.inputs.is_empty()
            || tx.output_candidates.is_empty()
            || tx.inputs.len() != boxes.len()
            || tx.data_inputs.len() != data_boxes.len()
            || tx.inputs.len() > i16::MAX as usize
            || tx.data_inputs.len() > i16::MAX as usize
            || tx.output_candidates.len() > i16::MAX as usize
        {
            return Err(WalletError::TxBuild(
                "inconsistent or empty transaction participants".into(),
            ));
        }
        // Reject caller-built message amplification before cloning participants
        // or allocating distinct-token tables. This is the offline API's
        // resource policy; the consensus transaction writer remains unchanged.
        crate::reduced_message::bytes_to_sign_bounded(
            tx,
            crate::reduced::MAX_REDUCED_TRANSACTION_BYTES,
        )?;
        if boxes
            .iter()
            .chain(data_boxes)
            .any(|b| b.candidate.tokens.len() > u8::MAX as usize)
        {
            return Err(WalletError::TxBuild(
                "input token collection exceeds wire bound".into(),
            ));
        }
        let limit = JitCost::from_block_cost(self.params.max_block_cost)
            .map_err(|e| WalletError::TxBuild(e.to_string()))?;
        let mut cost = CostAccumulator::new(limit);
        let add = |acc: &mut CostAccumulator, block: u64| -> Result<(), WalletError> {
            acc.add(
                JitCost::from_block_cost(block).map_err(|e| WalletError::TxBuild(e.to_string()))?,
            )
            .map_err(|e| WalletError::TxBuild(e.to_string()))
        };
        add(&mut cost, self.params.interpreter_init_cost)?;
        for (n, per) in [
            (boxes.len(), self.params.input_cost),
            (data_boxes.len(), self.params.data_input_cost),
            (tx.output_candidates.len(), self.params.output_cost),
        ] {
            add(
                &mut cost,
                (n as u64)
                    .checked_mul(per)
                    .ok_or_else(|| WalletError::TxBuild("cost overflow".into()))?,
            )?;
        }
        let input_distinct: BTreeSet<_> = boxes
            .iter()
            .flat_map(|b| b.candidate.tokens.iter().map(|t| *t.token_id.as_bytes()))
            .collect();
        let output_distinct: BTreeSet<_> = tx
            .output_candidates
            .iter()
            .flat_map(|b| b.tokens.iter().map(|t| *t.token_id.as_bytes()))
            .collect();
        let token_entries = boxes
            .iter()
            .map(|b| b.candidate.tokens.len())
            .sum::<usize>()
            + tx.output_candidates
                .iter()
                .map(|b| b.tokens.len())
                .sum::<usize>()
            + input_distinct.len()
            + output_distinct.len();
        add(
            &mut cost,
            (token_entries as u64)
                .checked_mul(self.params.token_access_cost)
                .ok_or_else(|| WalletError::TxBuild("token cost overflow".into()))?,
        )?;
        // Build and check every participant once. Each input shares these frozen
        // outputs/data/header values; only SELF and its extension change.
        let mut owned = context.build_reduction_owned_for_tx(
            tx,
            0,
            boxes,
            data_boxes,
            self.params.activated_script_version(),
        )?;
        let mut reduced_inputs = Vec::with_capacity(boxes.len());
        for (idx, b) in boxes.iter().enumerate() {
            // SDK ReducingInterpreter.reduce requires positive remaining budget,
            // even when a soft-fork reduction will perform no evaluation work.
            if cost.total() >= limit {
                return Err(WalletError::TxBuild("reduction cost limit reached".into()));
            }
            owned.self_box = owned.inputs[idx].clone();
            owned.self_creation_height = b.candidate.creation_height;
            owned.extension = tx.inputs[idx].extension.values.clone();
            let sigma = ergo_sigma::reduce::reduce_ergo_tree_with_context_and_cost(
                b.candidate.ergo_tree(),
                &owned.as_borrowed(),
                &mut cost,
            )
            .map_err(|e| WalletError::TxBuild(e.to_string()))?;
            reduced_inputs.push(crate::ReducedInput {
                sigma,
                cost: cost.total_block_cost(),
            });
        }
        let cost = u32::try_from(cost.total_block_cost())
            .map_err(|_| WalletError::TxBuild("reduction cost overflow".into()))?;
        Ok(crate::ReducedTransaction {
            unsigned_transaction: tx.clone(),
            reduced_inputs,
            cost,
        })
    }

    /// Sign already reduced contracts without chain access or script evaluation.
    /// Received reductions must be reviewed by the caller before signing.
    /// An own nonce in the reusable hints bag must be used for one signing
    /// operation only. Prefer [`Self::sign_reduced_bound`] for native ownership.
    pub fn sign_reduced(
        &self,
        reduced: &crate::ReducedTransaction,
        hints: &TransactionHintsBag,
    ) -> Result<Transaction, WalletError> {
        self.sign_reduced_inner(reduced, hints, false)
    }

    /// Produce a first-round transaction proof with another party's public
    /// commitments. This result may be incomplete and must not be submitted.
    /// An own nonce in the reusable bag must not be reused in another round.
    /// Prefer [`Self::sign_reduced_partial_bound`] for native ownership.
    pub fn sign_reduced_partial(
        &self,
        reduced: &crate::ReducedTransaction,
        hints: &TransactionHintsBag,
    ) -> Result<Transaction, WalletError> {
        self.sign_reduced_inner(reduced, hints, true)
    }

    fn sign_reduced_inner(
        &self,
        reduced: &crate::ReducedTransaction,
        hints: &TransactionHintsBag,
        partial: bool,
    ) -> Result<Transaction, WalletError> {
        use ergo_primitives::cost::JitCost;
        // Apply wire/depth bounds even to caller-built structures.
        let bytes = reduced.to_bytes()?;
        let checked = crate::ReducedTransaction::from_bytes(&bytes, self.params.block_version)?;
        checked.validate_for_proving()?;
        let message = crate::reduced_message::bytes_to_sign_bounded(
            &checked.unsigned_transaction,
            crate::reduced::MAX_REDUCED_TRANSACTION_BYTES,
        )?;
        let mut cost = CostAccumulator::new(
            JitCost::from_block_cost(self.params.max_block_cost)
                .map_err(|e| WalletError::TxBuild(e.to_string()))?,
        );
        cost.add(
            JitCost::from_block_cost(u64::from(checked.cost))
                .map_err(|e| WalletError::TxBuild(e.to_string()))?,
        )
        .map_err(|e| WalletError::TxBuild(e.to_string()))?;
        // Check the complete budget before generating any response, including
        // when a later input would otherwise exceed the aggregate limit.
        for reduction in &checked.reduced_inputs {
            cost.add(JitCost::from_jit_block_aligned(
                ergo_sigma::crypto_cost::estimate_crypto_cost(&reduction.sigma),
            ))
            .map_err(|e| WalletError::TxBuild(e.to_string()))?;
        }
        let mut inputs = Vec::with_capacity(checked.reduced_inputs.len());
        for (idx, (input, reduction)) in checked
            .unsigned_transaction
            .inputs
            .iter()
            .zip(&checked.reduced_inputs)
            .enumerate()
        {
            let prove = if partial {
                crate::proving::sigma::prove_sigma_partial
            } else {
                prove_sigma
            };
            let (proof, _) = prove(
                &reduction.sigma,
                &self.secrets,
                &message,
                &hints.all_for_input(idx as u32),
                &mut OsRngBackend,
            )?;
            inputs.push(Input {
                box_id: input.box_id,
                spending_proof: SpendingProof::new(proof, input.extension.clone())
                    .map_err(|e| WalletError::TxBuild(e.to_string()))?,
            });
        }
        Ok(Transaction {
            inputs,
            data_inputs: checked.unsigned_transaction.data_inputs,
            output_candidates: checked.unsigned_transaction.output_candidates,
        })
    }

    /// Consume nonce-bearing commitments bound to the message and frozen reduction.
    pub fn sign_reduced_bound(
        &self,
        reduced: &crate::ReducedTransaction,
        commitments: crate::proving::hints::BoundTransactionHints,
    ) -> Result<Transaction, WalletError> {
        self.sign_reduced(reduced, &commitments.into_for_reduced(reduced)?)
    }

    /// First-round partial proof, consuming this party's bound nonces once.
    pub fn sign_reduced_partial_bound(
        &self,
        reduced: &crate::ReducedTransaction,
        commitments: crate::proving::hints::BoundTransactionHints,
    ) -> Result<Transaction, WalletError> {
        self.sign_reduced_partial(reduced, &commitments.into_for_reduced(reduced)?)
    }

    /// Native commitment-signing entry point. Consume the commitments and
    /// reject a different transaction before any nonce response is produced.
    pub fn sign_bound(
        &self,
        unsigned_tx: &UnsignedTransaction,
        boxes_to_spend: &[ErgoBox],
        data_boxes: &[ErgoBox],
        state_context: &BlockchainStateContext,
        commitments: crate::proving::hints::BoundTransactionHints,
    ) -> Result<Transaction, WalletError> {
        let message = Self::bytes_to_sign_for_tx(unsigned_tx)?;
        let hints = commitments.into_for_message(&message)?;
        self.sign(
            unsigned_tx,
            boxes_to_spend,
            data_boxes,
            state_context,
            &hints,
        )
    }

    /// Sign `unsigned_tx` using the selected context.
    ///
    /// Passing `&BlockchainStateContext` preserves the legacy gate: only
    /// constant Sigma propositions and canonical matured miner rewards are
    /// supported. Passing `&SigningContext` explicitly selects full contract
    /// reduction against the caller's intended candidate, with cost enforcement.
    /// Inputs and data boxes must match transaction order. Neither context form
    /// replaces structural or consensus validation by the transaction's host.
    ///
    /// This low-level API accepts reusable hints bags. An own commitment nonce
    /// must be used for only one signing operation. For explicit-context nonce
    /// ownership, reduce once and use [`Self::sign_reduced_bound`]. Legacy
    /// callers can use [`Self::sign_bound`].
    pub fn sign<'context>(
        &self,
        unsigned_tx: &UnsignedTransaction,
        boxes_to_spend: &[ErgoBox],
        data_boxes: &[ErgoBox],
        context: impl Into<crate::tx_context::ProverSigningContext<'context>>,
        hints: &TransactionHintsBag,
    ) -> Result<Transaction, WalletError> {
        match context.into() {
            crate::tx_context::ProverSigningContext::Synthetic(context) => {
                self.sign_synthetic(unsigned_tx, boxes_to_spend, data_boxes, context, hints)
            }
            crate::tx_context::ProverSigningContext::Explicit(context) => self.sign_reduced(
                &self.reduce_transaction(unsigned_tx, boxes_to_spend, data_boxes, &context)?,
                hints,
            ),
        }
    }

    /// Preserve the synthetic-context script gate for host operations that
    /// reduce contracts before commitment generation or hint extraction.
    pub fn require_context_independent_scripts(boxes: &[ErgoBox]) -> Result<(), WalletError> {
        // Script gate: reject unsupported script families before
        // reaching the (synthetic-context) self-verify.
        for (idx, input_box) in boxes.iter().enumerate() {
            let ergo_tree = input_box.candidate.ergo_tree();
            let is_trivially_reducible = ergo_sigma::reduce::trivial_reduce(ergo_tree).is_ok();
            let is_miner_reward =
                extract_miner_reward_pubkey(input_box.candidate.ergo_tree_bytes()).is_some();
            if !is_trivially_reducible && !is_miner_reward {
                return Err(WalletError::TxBuild(format!(
                    "input {idx} has an unsupported script family; \
                     only bare ProveDlog/ProveDHTuple and matured miner-reward \
                     boxes are currently spendable"
                )));
            }
        }

        Ok(())
    }

    fn sign_synthetic(
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

        Self::require_context_independent_scripts(boxes_to_spend)?;

        let message = Self::bytes_to_sign_for_tx(unsigned_tx)?;

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
    pub(crate) fn bytes_to_sign_for_tx(
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
