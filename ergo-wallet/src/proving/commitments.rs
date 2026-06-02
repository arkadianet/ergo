//! Commitment generation for multi-sig sigma proofs.
//!
//! Mirrors Scala `sigmastate.interpreter.ProverUtils.generateCommitmentsFor`
//! and `ErgoProvingInterpreter.generateCommitmentsFor(unsignedTx, ...)`.
//!
//! Walks a sigma tree depth-first; for each leaf whose proposition is in
//! `generate_for`, samples a random commitment via the injected RNG and
//! emits `OwnCommitment + RealCommitment` hints tagged with the leaf's
//! `NodePosition` so duplicate leaves in asymmetric trees stay distinct.

use crate::error::WalletError;
use crate::proving::hints::{FirstProverMessage, Hint, HintsBag, OwnCommitment, RealCommitment};
use crate::proving::node_position::NodePosition;
use crate::proving::randomness::ProvingRng;
use ergo_ser::sigma_value::SigmaBoolean;

/// Generate commitments for every leaf in `sigma_tree` whose proposition
/// appears in `generate_for`. Mirrors Scala
/// `ProverUtils.generateCommitmentsFor(sigmaTree, generateFor)`.
///
/// Only `ProveDlog` and `ProveDHTuple` leaves are commitment-able.
/// Compound nodes (`Cand`, `Cor`, `Cthreshold`) are walked recursively.
/// `TrivialProp` and leaves outside `generate_for` are skipped.
pub fn generate_commitments_for(
    sigma_tree: &SigmaBoolean,
    generate_for: &[SigmaBoolean],
    rng: &mut dyn ProvingRng,
) -> Result<HintsBag, WalletError> {
    let mut bag = HintsBag::empty();
    traverse_node(
        sigma_tree,
        generate_for,
        &mut bag,
        NodePosition::crypto_tree_prefix(),
        rng,
    )?;
    Ok(bag)
}

fn traverse_node(
    sb: &SigmaBoolean,
    generate_for: &[SigmaBoolean],
    bag: &mut HintsBag,
    position: NodePosition,
    rng: &mut dyn ProvingRng,
) -> Result<(), WalletError> {
    match sb {
        SigmaBoolean::TrivialProp(_) => Ok(()),

        SigmaBoolean::ProveDlog(_) | SigmaBoolean::ProveDHTuple { .. } => {
            if generate_for.iter().any(|p| p == sb) {
                let (r, commitment) = sample_commitment_for(sb, rng)?;
                bag.add(Hint::OwnCommitment(OwnCommitment {
                    image: sb.clone(),
                    secret_randomness: r,
                    commitment: commitment.clone(),
                    position: position.clone(),
                }));
                bag.add(Hint::RealCommitment(RealCommitment {
                    image: sb.clone(),
                    commitment,
                    position,
                }));
            }
            Ok(())
        }

        SigmaBoolean::Cand(children) | SigmaBoolean::Cor(children) => {
            for (idx, child) in children.iter().enumerate() {
                traverse_node(child, generate_for, bag, position.child(idx as u32), rng)?;
            }
            Ok(())
        }

        SigmaBoolean::Cthreshold { children, .. } => {
            for (idx, child) in children.iter().enumerate() {
                traverse_node(child, generate_for, bag, position.child(idx as u32), rng)?;
            }
            Ok(())
        }
    }
}

/// Sample `(r_bytes, FirstProverMessage)` for a sigma leaf.
///
/// - `ProveDlog`: samples `r`, computes `A = g^r` (standard generator).
///   Returns `FirstProverMessage::Schnorr(A)`.
/// - `ProveDHTuple`: samples `r`, reads `g` and `h` from the proposition,
///   computes `A = g^r` and `B = h^r`. Returns `FirstProverMessage::DhTuple { a, b }`.
///   Both points are included so cooperating parties can reconstruct the
///   joint commitment without access to `r`.
fn sample_commitment_for(
    sb: &SigmaBoolean,
    rng: &mut dyn ProvingRng,
) -> Result<([u8; 32], FirstProverMessage), WalletError> {
    let r = rng.sample_scalar();
    let r_bytes: [u8; 32] = r.to_bytes().into();

    match sb {
        SigmaBoolean::ProveDlog(_) => {
            let big_a = k256::ProjectivePoint::GENERATOR * r;
            let a = compressed_point(big_a);
            Ok((r_bytes, FirstProverMessage::Schnorr(a)))
        }
        SigmaBoolean::ProveDHTuple { g, h, .. } => {
            let g_pt = decompress_point(g.as_bytes())?;
            let h_pt = decompress_point(h.as_bytes())?;
            let a = compressed_point(g_pt * r);
            let b = compressed_point(h_pt * r);
            Ok((r_bytes, FirstProverMessage::DhTuple { a, b }))
        }
        _ => Err(WalletError::MissingSecret(format!(
            "sample_commitment_for: not a commitment-able leaf: {sb:?}"
        ))),
    }
}

fn compressed_point(p: k256::ProjectivePoint) -> [u8; 33] {
    use k256::elliptic_curve::group::GroupEncoding;
    let bytes = k256::AffinePoint::from(p).to_bytes();
    let mut out = [0u8; 33];
    out.copy_from_slice(&bytes);
    out
}

fn decompress_point(bytes: &[u8; 33]) -> Result<k256::ProjectivePoint, WalletError> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    let encoded = k256::EncodedPoint::from_bytes(bytes.as_slice())
        .map_err(|e| WalletError::MissingSecret(format!("decompress: {e}")))?;
    let opt = k256::AffinePoint::from_encoded_point(&encoded);
    if opt.is_some().into() {
        Ok(k256::ProjectivePoint::from(opt.unwrap()))
    } else {
        Err(WalletError::MissingSecret("invalid SEC1 point".to_string()))
    }
}

/// Tx-level commitment generation. Mirrors Scala
/// `ErgoProvingInterpreter.generateCommitmentsFor(unsignedTx, ...)`.
///
/// For each input: builds the per-input `ReductionContext`, reduces the
/// input's `ErgoTree` to a sigma proposition, generates commitments for
/// that proposition, and stores the result in the `TransactionHintsBag`
/// at the input's index.
pub fn generate_commitments_for_tx(
    unsigned_tx: &ergo_ser::transaction::UnsignedTransaction,
    boxes_to_spend: &[ergo_ser::ergo_box::ErgoBox],
    data_boxes: &[ergo_ser::ergo_box::ErgoBox],
    state_context: &crate::tx_context::BlockchainStateContext,
    generate_for: &[SigmaBoolean],
    rng: &mut dyn ProvingRng,
) -> Result<crate::proving::hints::TransactionHintsBag, WalletError> {
    if unsigned_tx.inputs.len() != boxes_to_spend.len() {
        return Err(WalletError::TxBuild(format!(
            "input count {} != boxes count {}",
            unsigned_tx.inputs.len(),
            boxes_to_spend.len(),
        )));
    }

    let all_input_extensions: Vec<ergo_ser::input::ContextExtension> = unsigned_tx
        .inputs
        .iter()
        .map(|ui| ui.extension.clone())
        .collect();

    let mut tbag = crate::proving::hints::TransactionHintsBag::empty();

    for (idx, (unsigned_input, input_box)) in unsigned_tx
        .inputs
        .iter()
        .zip(boxes_to_spend.iter())
        .enumerate()
    {
        let owned_rc = state_context.build_reduction_owned(
            input_box,
            &unsigned_input.extension,
            boxes_to_spend,
            data_boxes,
            &unsigned_tx.output_candidates,
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

        let bag = generate_commitments_for(&residual_sigma, generate_for, rng)?;
        tbag.replace_for_input(idx as u32, bag);
    }

    Ok(tbag)
}
