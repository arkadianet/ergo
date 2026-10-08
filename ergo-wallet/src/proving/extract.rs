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
use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_ser::sigma_value::SigmaBoolean;
use ergo_sigma::verify::ProofLeaf;

// Wallet resource ceiling: 10 million block cost units (100 million JIT units).
// This bounds hint extraction work independently of consensus validation.
const HINT_EXTRACTION_COST_LIMIT: JitCost = JitCost::from_jit(100_000_000);

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
/// Enforces a wallet resource ceiling of 100 million JIT cost units.
///
/// Mirrors Scala `sigmastate.interpreter.ProverUtils.bagForMultisig`.
pub fn bag_for_multisig(
    sigma_tree: &SigmaBoolean,
    proof_bytes: &[u8],
    real_secrets: &[SigmaBoolean],
    simulated_secrets: &[SigmaBoolean],
) -> Result<HintsBag, WalletError> {
    let mut cost = CostAccumulator::new(HINT_EXTRACTION_COST_LIMIT);
    bag_for_multisig_with_cost(
        sigma_tree,
        proof_bytes,
        real_secrets,
        simulated_secrets,
        &mut cost,
    )
}

fn bag_for_multisig_with_cost(
    sigma_tree: &SigmaBoolean,
    proof_bytes: &[u8],
    real_secrets: &[SigmaBoolean],
    simulated_secrets: &[SigmaBoolean],
    cost: &mut CostAccumulator,
) -> Result<HintsBag, WalletError> {
    let leaves = ergo_sigma::verify::extract_proof_leaves_with_cost(sigma_tree, proof_bytes, cost)
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
/// `SigmaBoolean`, extracts hints from the input's proof bytes,
/// and stores the result in a `TransactionHintsBag` at the input index.
/// Reduction and proof extraction share a 100 million JIT cost budget across
/// all inputs, bounding logical occurrences of shared propositions.
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
        .map(|i| i.spending_proof.extension().clone())
        .collect();

    let mut tbag = crate::proving::hints::TransactionHintsBag::empty();
    let mut cost = CostAccumulator::new(HINT_EXTRACTION_COST_LIMIT);

    for (idx, (input, input_box)) in tx.inputs.iter().zip(boxes_to_spend.iter()).enumerate() {
        let owned_rc = state_context.build_reduction_owned(
            input_box,
            input.spending_proof.extension(),
            boxes_to_spend,
            data_boxes,
            &tx.output_candidates,
            &all_input_extensions,
        );
        let reduction_ctx = owned_rc.as_borrowed();

        let ergo_tree = input_box.candidate.ergo_tree();
        let residual_sigma: SigmaBoolean = match ergo_sigma::reduce::trivial_reduce(ergo_tree) {
            Ok(prop) => prop,
            Err(ergo_sigma::reduce::ReductionError::NotTriviallyReducible)
            | Err(ergo_sigma::reduce::ReductionError::BodyConstantNotSigmaProp(_)) => {
                ergo_sigma::evaluator::reduce_expr_with_cost(
                    &ergo_tree.body,
                    &reduction_ctx,
                    &ergo_tree.constants,
                    &mut cost,
                )
                .map_err(|e| WalletError::TxBuild(format!("reduce: {e:?}")))?
            }
            Err(e) => return Err(WalletError::TxBuild(format!("trivial_reduce: {e:?}"))),
        };

        let bag = bag_for_multisig_with_cost(
            &residual_sigma,
            &input.spending_proof.proof,
            real_secrets,
            simulated_secrets,
            &mut cost,
        )?;
        tbag.replace_for_input(idx as u32, bag);
    }

    Ok(tbag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_context::BlockchainStateContext;
    use ergo_primitives::{
        digest::{ADDigest, ModifierId},
        group_element::GroupElement,
        reader::VlqReader,
    };
    use ergo_ser::pre_header::CandidatePreHeader;
    use ergo_ser::{
        ergo_box::{ErgoBox, ErgoBoxCandidate},
        ergo_tree::read_ergo_tree,
        input::{ContextExtension, Input, SpendingProof},
        register::AdditionalRegisters,
        transaction::Transaction,
    };

    // ----- helpers -----

    fn extraction_transaction(
        tree_bytes: &[u8],
    ) -> (Transaction, Vec<ErgoBox>, BlockchainStateContext) {
        let mut reader = VlqReader::new(tree_bytes).with_activated_script_version(3);
        let tree = read_ergo_tree(&mut reader).unwrap();
        let input_box = ErgoBox {
            candidate: ErgoBoxCandidate::new(
                1_000_000,
                tree,
                0,
                vec![],
                AdditionalRegisters::empty(),
            )
            .unwrap(),
            transaction_id: ModifierId::from_bytes([0; 32]),
            index: 0,
        };
        let tx = Transaction {
            inputs: vec![Input {
                box_id: input_box.box_id().unwrap(),
                spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![],
        };
        let state = BlockchainStateContext {
            sigma_last_headers: vec![],
            sigma_pre_header: CandidatePreHeader {
                version: 4,
                parent_id: [0; 32],
                height: 1,
                timestamp: 0,
                n_bits: 0,
                votes: [0; 3],
                miner_pubkey: [2; 33],
            },
            previous_state_digest: ADDigest::from_bytes([0; 33]),
        };
        (tx, vec![input_box], state)
    }

    // ----- happy path -----

    #[test]
    fn transaction_trivial_proposition_still_extracts_no_hints() {
        let (tx, boxes, state) = extraction_transaction(&[0, 1, 1]);
        let bag = bag_for_transaction(&tx, &boxes, &[], &state, &[], &[]).unwrap();
        assert!(bag.all_for_input(0).hints.is_empty());
    }

    // ----- error paths -----

    #[test]
    fn multisig_rejects_shared_expansion_before_parsing() {
        let mut prop = SigmaBoolean::ProveDlog(GroupElement::from_bytes([2; 33]));
        for _ in 0..64 {
            prop = SigmaBoolean::Cand(vec![prop.clone(), prop].into());
        }
        let err = bag_for_multisig(&prop, &[], &[], &[]).unwrap_err();
        assert!(
            matches!(err, WalletError::MultiSigProofStructure(ref msg) if msg.contains("LimitExceeded"))
        );
    }

    #[test]
    fn extraction_preserves_cost_already_spent_on_reduction() {
        let prop = SigmaBoolean::ProveDlog(GroupElement::from_bytes([2; 33]));
        let crypto = ergo_sigma::crypto_cost::estimate_crypto_cost(&prop);
        let mut cost = CostAccumulator::new(crypto);
        cost.add(JitCost::from_jit(1)).unwrap();
        let err = bag_for_multisig_with_cost(&prop, &[], &[], &[], &mut cost).unwrap_err();
        assert!(
            matches!(err, WalletError::MultiSigProofStructure(ref msg) if msg.contains("LimitExceeded"))
        );
    }

    // ----- oracle parity -----

    #[test]
    fn transaction_rejects_shared_fold_before_proof_extraction() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/scala/sigma_shared_growth.json"
        ))
        .unwrap();
        let case = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["iterations"] == 16)
            .unwrap();
        assert!(case["crypto_jit"].as_u64().unwrap() > HINT_EXTRACTION_COST_LIMIT.value());
        let bytes = hex::decode(case["tree_hex"].as_str().unwrap()).unwrap();
        let (tx, boxes, state) = extraction_transaction(&bytes);
        let err = bag_for_transaction(&tx, &boxes, &[], &state, &[], &[]).unwrap_err();
        assert!(
            matches!(err, WalletError::MultiSigProofStructure(ref msg) if msg.contains("LimitExceeded"))
        );
    }
}
