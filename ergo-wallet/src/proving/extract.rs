//! Hint extraction from (partially) signed sigma proofs for
//! distributed signing applications.
//!
//! Mirrors Scala `sigmastate.interpreter.ProverUtils.bagForMultisig`:
//! given a proof and a list of public keys, parses the proof tree
//! and for each leaf matching `real_secrets_to_extract` emits
//! `RealCommitment + RealSecretProof`; for `simulated_secrets_to_extract`
//! emits `SimulatedCommitment + SimulatedSecretProof`.

use crate::error::WalletError;
use crate::proving::hints::{
    FirstProverMessage, Hint, HintsBag, RealCommitment, RealSecretProof, SimulatedCommitment,
    SimulatedSecretProof,
};
use crate::proving::node_position::NodePosition;
use ergo_ser::sigma_value::SigmaBoolean;
use ergo_sigma::verify::ProofLeaf;

/// Extract hints from a sigma proof against `sigma_tree`. Walks the
/// parsed proof tree depth-first; for each leaf:
///   - if proposition in `real_secrets` → emit `RealCommitment + RealSecretProof`.
///   - if proposition in `simulated_secrets` → emit `SimulatedCommitment + SimulatedSecretProof`.
///   - otherwise → skip.
///
/// The parsed proof tree's challenges + commitments come from
/// re-running ergo-sigma's proof parser + commitment recomputation —
/// the same path the verifier uses.
///
/// Mirrors Scala `sigmastate.interpreter.ProverUtils.bagForMultisig`.
pub fn bag_for_multisig(
    sigma_tree: &SigmaBoolean,
    proof_bytes: &[u8],
    real_secrets: &[SigmaBoolean],
    simulated_secrets: &[SigmaBoolean],
) -> Result<HintsBag, WalletError> {
    let leaves = ergo_sigma::verify::extract_proof_leaves(sigma_tree, proof_bytes)
        .map_err(|e| WalletError::MultiSigProofStructure(format!("proof parse: {e:?}")))?;

    let mut bag = HintsBag::empty();
    for leaf in leaves {
        let position = NodePosition {
            positions: leaf.position.clone(),
        };
        let fpm = first_prover_message(&leaf).ok_or_else(|| {
            WalletError::MultiSigProofStructure(format!(
                "unexpected commitment length {} at {:?}",
                leaf.commitment_bytes.len(),
                leaf.position
            ))
        })?;

        if real_secrets.iter().any(|p| p == &leaf.proposition) {
            bag.add(Hint::RealCommitment(RealCommitment {
                image: leaf.proposition.clone(),
                commitment: fpm.clone(),
                position: position.clone(),
            }));
            bag.add(Hint::RealSecretProof(RealSecretProof {
                image: leaf.proposition.clone(),
                challenge: leaf.challenge,
                response: leaf.response,
                position,
            }));
        } else if simulated_secrets.iter().any(|p| p == &leaf.proposition) {
            bag.add(Hint::SimulatedCommitment(SimulatedCommitment {
                image: leaf.proposition.clone(),
                commitment: fpm,
                challenge: leaf.challenge,
                position: position.clone(),
            }));
            bag.add(Hint::SimulatedSecretProof(SimulatedSecretProof {
                image: leaf.proposition.clone(),
                challenge: leaf.challenge,
                response: leaf.response,
                position,
            }));
        }
    }
    Ok(bag)
}

/// Decode a `ProofLeaf`'s commitment bytes into a `FirstProverMessage`.
///
/// Schnorr leaves: 33 bytes = `R` (compressed SEC1).
/// DHT leaves: 66 bytes = `a(33) || b(33)`.
fn first_prover_message(leaf: &ProofLeaf) -> Option<FirstProverMessage> {
    match leaf.commitment_bytes.len() {
        33 => {
            let mut a = [0u8; 33];
            a.copy_from_slice(&leaf.commitment_bytes);
            Some(FirstProverMessage::Schnorr(a))
        }
        66 => {
            let mut a = [0u8; 33];
            let mut b = [0u8; 33];
            a.copy_from_slice(&leaf.commitment_bytes[..33]);
            b.copy_from_slice(&leaf.commitment_bytes[33..]);
            Some(FirstProverMessage::DhTuple { a, b })
        }
        _ => None,
    }
}

/// Tx-level hint extraction. Mirrors Scala
/// `ErgoProvingInterpreter.bagForTransaction`.
///
/// For each input: reduces the input box's ErgoTree to a residual
/// `SigmaBoolean`, calls `bag_for_multisig` on the input's proof bytes,
/// and stores the result in a `TransactionHintsBag` at the input index.
pub fn bag_for_transaction(
    tx: &ergo_ser::transaction::Transaction,
    boxes_to_spend: &[ergo_ser::ergo_box::ErgoBox],
    data_boxes: &[ergo_ser::ergo_box::ErgoBox],
    state_context: &crate::tx_context::BlockchainStateContext,
    real_secrets: &[SigmaBoolean],
    simulated_secrets: &[SigmaBoolean],
) -> Result<crate::proving::hints::TransactionHintsBag, WalletError> {
    if tx.inputs.len() != boxes_to_spend.len() {
        return Err(WalletError::TxBuild(format!(
            "input count {} != boxes count {}",
            tx.inputs.len(),
            boxes_to_spend.len(),
        )));
    }

    // Sanity check from Scala: each input's box_id must match the
    // corresponding box.
    for (idx, (input, box_)) in tx.inputs.iter().zip(boxes_to_spend.iter()).enumerate() {
        let computed_box_id = box_.box_id().map_err(|e| {
            WalletError::TxBuild(format!("box_id computation for box[{idx}]: {e:?}"))
        })?;
        if input.box_id != computed_box_id {
            return Err(WalletError::TxBuild(format!(
                "input[{idx}].box_id mismatch with boxes_to_spend[{idx}]"
            )));
        }
    }

    let all_input_extensions: Vec<ergo_ser::input::ContextExtension> = tx
        .inputs
        .iter()
        .map(|i| i.spending_proof.extension.clone())
        .collect();

    let mut tbag = crate::proving::hints::TransactionHintsBag::empty();

    for (idx, (input, input_box)) in tx.inputs.iter().zip(boxes_to_spend.iter()).enumerate() {
        let owned_rc = state_context.build_reduction_owned(
            input_box,
            &input.spending_proof.extension,
            boxes_to_spend,
            data_boxes,
            &tx.output_candidates,
            &all_input_extensions,
        );
        let reduction_ctx = owned_rc.as_borrowed();

        let mut reduce_cost = ergo_primitives::cost::CostAccumulator::recording_only();
        let ergo_tree = input_box.candidate.ergo_tree();
        let residual_sigma: SigmaBoolean = match ergo_sigma::reduce::trivial_reduce(ergo_tree) {
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

        let bag = bag_for_multisig(
            &residual_sigma,
            &input.spending_proof.proof,
            real_secrets,
            simulated_secrets,
        )?;
        tbag.replace_for_input(idx as u32, bag);
    }

    Ok(tbag)
}
