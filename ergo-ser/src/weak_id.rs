//! Weak transaction ids (Scala `ErgoTransaction.weakId`, BIP-152 style):
//! 6 bytes, `tx_id[0..3] ++ witness_id[0..3]`. Not collision-resistant; used
//! only for input-block transaction propagation.

use ergo_primitives::digest::blake2b256;

use crate::error::WriteError;
use crate::transaction::{transaction_id, Transaction};

/// A weak transaction id: 6 bytes, `tx_id[0..3] ++ witness_id[0..3]`.
pub type WeakId = [u8; 6];
pub const WEAK_ID_LENGTH: usize = 6;

/// Scala `ErgoTransaction.witnessSerializedId`: `Blake2b256(concat(inputs[i].spending_proof.proof))[1..32]`
/// (the first byte of the digest is dropped, leaving 31 bytes).
pub fn witness_id(tx: &Transaction) -> [u8; 31] {
    let mut all = Vec::new();
    for input in &tx.inputs {
        all.extend_from_slice(&input.spending_proof.proof);
    }
    let h = blake2b256(&all);
    let mut out = [0u8; 31];
    out.copy_from_slice(&h.as_bytes()[1..]);
    out
}

/// Scala `ErgoTransaction.weakId`: `tx_id[0..3] ++ witness_id[0..3]`.
pub fn weak_tx_id(tx_id: &[u8; 32], witness_id: &[u8; 31]) -> WeakId {
    let mut w = [0u8; 6];
    w[..3].copy_from_slice(&tx_id[..3]);
    w[3..].copy_from_slice(&witness_id[..3]);
    w
}

/// Compute the weak id of a transaction directly from its parsed form.
pub fn weak_id_of(tx: &Transaction) -> Result<WeakId, WriteError> {
    let id = transaction_id(tx)?;
    Ok(weak_tx_id(id.as_bytes(), &witness_id(tx)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::Input;
    use crate::transaction::Transaction;

    // ----- helpers -----

    fn tx_with_proofs(proofs: &[&[u8]]) -> Transaction {
        // Minimal transaction shape sufficient to exercise witness_id /
        // weak_tx_id; oracle-vectored parity is covered by the
        // Scala-anchored integration test, not here.
        use crate::input::{ContextExtension, SpendingProof};
        use ergo_primitives::digest::Digest32;
        let inputs = proofs
            .iter()
            .map(|p| Input {
                box_id: Digest32::from_bytes([0u8; 32]),
                spending_proof: SpendingProof::new(p.to_vec(), ContextExtension::empty()).unwrap(),
            })
            .collect();
        Transaction {
            inputs,
            data_inputs: Vec::new(),
            output_candidates: Vec::new(),
        }
    }

    // ----- happy path -----
    //
    // No shape/length assertion on `witness_id` lives here: computing the
    // expectation with the same `blake2b256` helper the production code
    // calls would be a self-oracle (CLAUDE.md's oracle-parity rule) that
    // proves internal consistency, not correctness. The Scala-anchored
    // expectation lives in `weak_ids_match_scala_for_witness_variants`
    // (`ergo-ser/tests/it/input_block_scala_oracle.rs`), sourced from
    // `test-vectors/weak-blocks/weak_ids.json`.

    #[test]
    fn weak_tx_id_concatenates_first_three_bytes_of_each_half() {
        let tx_id = [0x11u8; 32];
        let wid = [0x22u8; 31];
        let weak = weak_tx_id(&tx_id, &wid);
        assert_eq!(weak, [0x11, 0x11, 0x11, 0x22, 0x22, 0x22]);
    }

    // ----- round-trips -----

    #[test]
    fn weak_id_of_differs_when_witness_differs_same_tx_id() {
        let tx_a = tx_with_proofs(&[&[0x01, 0x02]]);
        let tx_b = tx_with_proofs(&[&[0x03, 0x04]]);
        // Different witness bytes -> different weak id (tx_id portion is
        // unaffected by the spending proof, so the two halves diverge
        // only in the witness half — this is exactly the collision this
        // type is meant to avoid on the input-block propagation path).
        assert_ne!(
            weak_id_of(&tx_a).unwrap(),
            weak_id_of(&tx_b).unwrap(),
            "distinct witnesses must yield distinct weak ids"
        );
    }
}
