//! Membership evidence for caller-supplied transactions in an unproven block.

use ergo_crypto::merkle::merkle_proof_by_index;
use ergo_primitives::digest::blake2b256;
use ergo_ser::header::{serialize_header_without_pow, Header};
use ergo_ser::transaction::{transaction_id, Transaction};

use crate::error::MiningError;
use crate::work_message::{TransactionMembershipProof, UpcomingTransactionsProof};

/// Construct Scala's `ProofOfUpcomingTransactions` from the final block order.
/// Requested transactions that were not included produce no proof. For v2+
/// the tree commits to transaction IDs followed by witness IDs, exactly as
/// `BlockTransactions.proofFor` does, including empty-sibling padding.
pub fn upcoming_transactions_proof(
    header: &Header,
    transactions: &[Transaction],
    requested: &[Transaction],
) -> Result<Option<UpcomingTransactionsProof>, MiningError> {
    if requested.is_empty() {
        return Ok(None);
    }
    let ids: Vec<_> = transactions
        .iter()
        .map(transaction_id)
        .collect::<Result<_, _>>()
        .map_err(|error| MiningError::IdComputation {
            op: "candidate_proof_tx_id",
            reason: format!("{error:?}"),
        })?;
    let witnesses: Vec<Vec<u8>> = if header.version >= 2 {
        transactions
            .iter()
            .map(|tx| {
                let proofs: Vec<_> = tx
                    .inputs
                    .iter()
                    .flat_map(|input| input.spending_proof.proof.iter().copied())
                    .collect();
                blake2b256(&proofs).as_bytes()[1..].to_vec()
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut leaves: Vec<&[u8]> = ids.iter().map(|id| id.as_bytes().as_slice()).collect();
    leaves.extend(witnesses.iter().map(Vec::as_slice));
    let mut tx_proofs = Vec::new();
    for tx in requested {
        let Ok(id) = transaction_id(tx) else { continue };
        let Some(index) = ids.iter().position(|included| *included == id) else {
            continue;
        };
        let Some(proof) = merkle_proof_by_index(&leaves, index) else {
            continue;
        };
        tx_proofs.push(TransactionMembershipProof {
            leaf: *id.as_bytes(),
            levels: proof
                .levels
                .into_iter()
                .map(|(digest, side)| {
                    let mut encoded = Vec::with_capacity(1 + digest.len());
                    encoded.push(side);
                    encoded.extend(digest);
                    encoded
                })
                .collect(),
        });
    }
    Ok(Some(UpcomingTransactionsProof {
        msg_preimage: serialize_header_without_pow(header)?,
        tx_proofs,
    }))
}
