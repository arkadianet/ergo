//! EIP-19 cold signing's EIP-43 reduced transaction representation.
//!
//! Reduction freezes script evaluation; signing needs only this object and secrets.
//! A received reduction is a claim by its producer, not proof of chain validity.
use crate::{proving::prover::Prover, WalletError};
use ergo_primitives::{reader::VlqReader, writer::VlqWriter};
use ergo_ser::{
    input::UnsignedInput,
    sigma_value::{read_sigma_boolean, write_sigma_boolean_bounded, SigmaBoolean},
    transaction::{read_transaction, UnsignedTransaction},
};

/// Bound untrusted offline payloads before allocation or proof generation.
pub const MAX_REDUCED_TRANSACTION_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq)]
pub struct ReducedInput {
    pub sigma: SigmaBoolean,
    /// Cumulative block cost after reducing this input (Scala ReductionResult.cost).
    pub cost: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReducedTransaction {
    pub unsigned_transaction: UnsignedTransaction,
    pub reduced_inputs: Vec<ReducedInput>,
    /// Aggregate reduction cost, including transaction initialization and token access.
    pub cost: u32,
}

impl ReducedTransaction {
    /// The wire codec preserves propositions as supplied. Proof construction
    /// requires reduced normal form: trivial propositions can only be roots,
    /// because compound proof nodes carry only cryptographic leaves.
    pub(crate) fn validate_for_proving(&self) -> Result<(), WalletError> {
        for input in &self.reduced_inputs {
            let mut pending = vec![(&input.sigma, true)];
            while let Some((node, is_root)) = pending.pop() {
                match node {
                    SigmaBoolean::TrivialProp(_) if !is_root => {
                        return Err(invalid(
                            "nested trivial proposition is not in reduced normal form",
                        ));
                    }
                    SigmaBoolean::Cand(children) | SigmaBoolean::Cor(children) => {
                        if children.len() < 2 {
                            return Err(invalid(
                                "degenerate compound is not in reduced normal form",
                            ));
                        }
                        pending.extend(children.iter().map(|child| (child, false)));
                    }
                    SigmaBoolean::Cthreshold { k, children } => {
                        if *k == 0 || usize::from(*k) >= children.len() {
                            return Err(invalid(
                                "degenerate threshold is not in reduced normal form",
                            ));
                        }
                        pending.extend(children.iter().map(|child| (child, false)));
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Serialize exactly as Scala SDK ReducedErgoLikeTransaction.serializer.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WalletError> {
        if self.reduced_inputs.len() != self.unsigned_transaction.inputs.len()
            || self.cost > i32::MAX as u32
        {
            return Err(invalid(
                "inconsistent reduced input count or aggregate cost",
            ));
        }
        let message = crate::reduced_message::bytes_to_sign_bounded(
            &self.unsigned_transaction,
            MAX_REDUCED_TRANSACTION_BYTES,
        )?;
        if message.len() > MAX_REDUCED_TRANSACTION_BYTES {
            return Err(invalid("reduced transaction too large"));
        }
        let mut w = VlqWriter::new();
        w.put_u32(message.len() as u32);
        w.put_bytes(&message);
        for input in &self.reduced_inputs {
            if input.cost > i64::MAX as u64 {
                return Err(invalid("negative/out-of-range reduction cost"));
            }
            let remaining = MAX_REDUCED_TRANSACTION_BYTES.saturating_sub(w.len());
            write_sigma_boolean_bounded(&mut w, &input.sigma, remaining)
                .map_err(|e| invalid(&e.to_string()))?;
            w.put_u64(input.cost);
        }
        w.put_u32(self.cost);
        let bytes = w.result();
        if bytes.len() > MAX_REDUCED_TRANSACTION_BYTES {
            return Err(invalid("reduced transaction too large"));
        }
        Ok(bytes)
    }

    /// Parse with the caller's active block version, bounded trees and exact consumption.
    /// The transaction prefix must be canonical messageToSign bytes with empty proofs.
    pub fn from_bytes(bytes: &[u8], block_version: u8) -> Result<Self, WalletError> {
        if bytes.len() > MAX_REDUCED_TRANSACTION_BYTES {
            return Err(invalid("reduced transaction too large"));
        }
        let mut r =
            VlqReader::new(bytes).with_activated_script_version(block_version.wrapping_sub(1));
        let n = r.get_u32_exact().map_err(read_error)? as usize;
        let message = r.get_bytes(n).map_err(read_error)?;
        let mut tx_reader =
            VlqReader::new(message).with_activated_script_version(block_version.wrapping_sub(1));
        let tx = read_transaction(&mut tx_reader).map_err(read_error)?;
        if tx_reader.remaining() != 0
            || tx.inputs.iter().any(|i| !i.spending_proof.proof.is_empty())
        {
            return Err(invalid(
                "reduced transaction prefix must contain only empty proofs",
            ));
        }
        let unsigned_transaction = UnsignedTransaction {
            inputs: tx
                .inputs
                .into_iter()
                .map(|i| UnsignedInput {
                    box_id: i.box_id,
                    extension: i.spending_proof.extension().clone(),
                })
                .collect(),
            data_inputs: tx.data_inputs,
            output_candidates: tx.output_candidates,
        };
        if Prover::bytes_to_sign_for_tx(&unsigned_transaction)? != message {
            return Err(invalid("noncanonical reduced transaction message"));
        }
        let mut reduced_inputs = Vec::with_capacity(unsigned_transaction.inputs.len());
        for _ in &unsigned_transaction.inputs {
            let sigma = read_sigma_boolean(&mut r).map_err(read_error)?;
            let cost = r.get_u64().map_err(read_error)?;
            if cost > i64::MAX as u64 {
                return Err(invalid("negative/out-of-range reduction cost"));
            }
            reduced_inputs.push(ReducedInput { sigma, cost });
        }
        for point in r.group_elements().iter().chain(tx_reader.group_elements()) {
            ergo_sigma::evaluator::validate_group_element(*point)
                .map_err(|e| invalid(&e.to_string()))?;
        }
        let cost = r.get_u32_exact().map_err(read_error)?;
        if r.remaining() != 0 {
            return Err(invalid("trailing reduced transaction bytes"));
        }
        let result = Self {
            unsigned_transaction,
            reduced_inputs,
            cost,
        };
        if result.to_bytes()? != bytes {
            return Err(invalid("noncanonical reduced transaction encoding"));
        }
        Ok(result)
    }
}
fn invalid(message: &str) -> WalletError {
    WalletError::TxBuild(message.into())
}
fn read_error(e: ergo_primitives::reader::ReadError) -> WalletError {
    invalid(&e.to_string())
}
