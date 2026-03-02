//! Binary serialization of Ergo transactions, delegating to sigma-rust (ergo-lib).
//!
//! Our lightweight byte-oriented types (`ErgoTransaction`, `ErgoBoxCandidate`, etc.) are
//! used across 12 crates. Rather than replacing them with sigma-rust types, we provide
//! thin conversion functions at the serialization boundary:
//!
//! - **Serialize**: our types → sigma-rust types → `sigma_serialize_bytes()`
//! - **Parse**: `sigma_parse_bytes()` → sigma-rust types → our types

use std::collections::HashMap;
use std::convert::TryFrom;

use ergo_lib::chain::transaction::ergo_transaction::ErgoTransaction as _;
use ergo_lib::chain::transaction::input::prover_result::ProverResult as SigmaProverResult;
use ergo_lib::chain::transaction::{DataInput as SigmaDataInput, Transaction as SigmaTransaction};
use ergo_lib::ergo_chain_types::Digest32 as SigmaDigest32;
use ergo_lib::ergotree_interpreter::sigma_protocol::prover::ProofBytes as SigmaProofBytes;
use ergo_lib::ergotree_ir::chain::context_extension::ContextExtension as SigmaContextExtension;
use ergo_lib::ergotree_ir::chain::ergo_box::box_value::BoxValue as SigmaBoxValue;
use ergo_lib::ergotree_ir::chain::ergo_box::RegisterValue as SigmaRegisterValue;
use ergo_lib::ergotree_ir::chain::ergo_box::{
    BoxId as SigmaBoxId, BoxTokens, ErgoBoxCandidate as SigmaErgoBoxCandidate,
    NonMandatoryRegisterId as SigmaNonMandatoryRegisterId,
    NonMandatoryRegisters as SigmaNonMandatoryRegisters,
};
use ergo_lib::ergotree_ir::chain::token::{Token as SigmaToken, TokenAmount, TokenId};
use ergo_lib::ergotree_ir::ergo_tree::ErgoTree as SigmaErgoTree;
use ergo_lib::ergotree_ir::serialization::SigmaSerializable;

use ergo_types::transaction::*;

use crate::vlq::CodecError;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Serialize a transaction to bytes (full, with proofs).
pub fn serialize_transaction(tx: &ErgoTransaction) -> Vec<u8> {
    let sigma_tx = to_sigma_transaction(tx).expect("valid tx conversion");
    sigma_tx
        .sigma_serialize_bytes()
        .expect("sigma serialization")
}

/// Serialize a transaction without proofs (for tx_id computation).
/// Proof bytes are replaced with VLQ(0).
pub fn serialize_transaction_without_proofs(tx: &ErgoTransaction) -> Vec<u8> {
    let mut tx_copy = tx.clone();
    for input in &mut tx_copy.inputs {
        input.proof_bytes.clear();
    }
    serialize_transaction(&tx_copy)
}

/// Parse a transaction from raw bytes.
pub fn parse_transaction(data: &[u8]) -> Result<ErgoTransaction, CodecError> {
    let sigma_tx = SigmaTransaction::sigma_parse_bytes(data)
        .map_err(|e| CodecError::InvalidData(format!("sigma parse: {e}")))?;
    from_sigma_transaction(&sigma_tx)
}

/// Parse a transaction from a shared reader, advancing it past the transaction bytes.
///
/// This is used by `parse_block_transactions` to parse inline transactions
/// from a shared byte stream (Scala writes transactions without length prefixes).
///
/// Approach: parse with sigma-rust (which reads one complete tx from the front of
/// the buffer), then re-serialize to measure the consumed byte count. This works
/// because Ergo transaction serialization is canonical.
pub fn parse_transaction_from_reader(reader: &mut &[u8]) -> Result<ErgoTransaction, CodecError> {
    let sigma_tx = SigmaTransaction::sigma_parse_bytes(reader)
        .map_err(|e| CodecError::InvalidData(format!("sigma parse: {e}")))?;
    let reserialized = sigma_tx
        .sigma_serialize_bytes()
        .map_err(|e| CodecError::InvalidData(format!("sigma reserialize: {e}")))?;
    let consumed = reserialized.len();
    if consumed > reader.len() {
        return Err(CodecError::InvalidData(
            "reserialized tx longer than input buffer".into(),
        ));
    }
    *reader = &reader[consumed..];
    from_sigma_transaction(&sigma_tx)
}

/// Compute transaction ID = Blake2b256(serialize_without_proofs).
///
/// Uses sigma-rust's tx_id computation for consistency.
pub fn compute_tx_id(tx: &ErgoTransaction) -> TxId {
    let sigma_tx = to_sigma_transaction(tx).expect("valid tx conversion");
    let id_digest: SigmaDigest32 = sigma_tx.id().0;
    TxId(id_digest.into())
}

// ---------------------------------------------------------------------------
// Conversion: our types → sigma-rust
// ---------------------------------------------------------------------------

/// Convert our `ErgoTransaction` → sigma-rust `Transaction`.
fn to_sigma_transaction(tx: &ErgoTransaction) -> Result<SigmaTransaction, CodecError> {
    let inputs: Vec<ergo_lib::chain::transaction::Input> = tx
        .inputs
        .iter()
        .map(to_sigma_input)
        .collect::<Result<_, _>>()?;

    let data_inputs: Vec<SigmaDataInput> = tx
        .data_inputs
        .iter()
        .map(|di| {
            let box_id: SigmaBoxId = SigmaDigest32::from(di.box_id.0).into();
            SigmaDataInput::from(box_id)
        })
        .collect();

    let output_candidates: Vec<SigmaErgoBoxCandidate> = tx
        .output_candidates
        .iter()
        .map(to_sigma_box_candidate)
        .collect::<Result<_, _>>()?;

    SigmaTransaction::new_from_vec(inputs, data_inputs, output_candidates)
        .map_err(|e| CodecError::InvalidData(format!("tx conversion: {e}")))
}

/// Convert a single `Input` → sigma-rust `Input`.
fn to_sigma_input(input: &Input) -> Result<ergo_lib::chain::transaction::Input, CodecError> {
    let box_id: SigmaBoxId = SigmaDigest32::from(input.box_id.0).into();
    let proof = SigmaProofBytes::from(input.proof_bytes.clone());
    let extension = if input.extension_bytes.is_empty() || input.extension_bytes == [0x00] {
        SigmaContextExtension::empty()
    } else {
        SigmaContextExtension::sigma_parse_bytes(&input.extension_bytes)
            .map_err(|e| CodecError::InvalidData(format!("extension parse: {e}")))?
    };
    let prover_result = SigmaProverResult { proof, extension };
    Ok(ergo_lib::chain::transaction::Input::new(
        box_id,
        prover_result,
    ))
}

/// Convert an `ErgoBoxCandidate` → sigma-rust `ErgoBoxCandidate`.
fn to_sigma_box_candidate(
    candidate: &ErgoBoxCandidate,
) -> Result<SigmaErgoBoxCandidate, CodecError> {
    let value = SigmaBoxValue::try_from(candidate.value)
        .map_err(|e| CodecError::InvalidData(format!("box value: {e}")))?;
    let ergo_tree = SigmaErgoTree::sigma_parse_bytes(&candidate.ergo_tree_bytes)
        .map_err(|e| CodecError::InvalidData(format!("ergo tree: {e}")))?;

    let tokens_vec: Vec<SigmaToken> = candidate
        .tokens
        .iter()
        .map(|(token_id, amount)| {
            let tid: TokenId = SigmaDigest32::from(token_id.0).into();
            let ta = TokenAmount::try_from(*amount)
                .map_err(|e| CodecError::InvalidData(format!("token amount: {e}")))?;
            Ok(SigmaToken {
                token_id: tid,
                amount: ta,
            })
        })
        .collect::<Result<_, CodecError>>()?;

    let tokens = if tokens_vec.is_empty() {
        None
    } else {
        Some(
            BoxTokens::from_vec(tokens_vec)
                .map_err(|e| CodecError::InvalidData(format!("tokens: {e}")))?,
        )
    };

    let additional_registers = to_sigma_registers(&candidate.additional_registers)?;

    Ok(SigmaErgoBoxCandidate {
        value,
        ergo_tree,
        tokens,
        additional_registers,
        creation_height: candidate.creation_height,
    })
}

/// Convert our register list → sigma-rust `NonMandatoryRegisters`.
fn to_sigma_registers(regs: &[(u8, Vec<u8>)]) -> Result<SigmaNonMandatoryRegisters, CodecError> {
    if regs.is_empty() {
        return Ok(SigmaNonMandatoryRegisters::empty());
    }

    let mut map: HashMap<SigmaNonMandatoryRegisterId, SigmaRegisterValue> = HashMap::new();
    for (idx, bytes) in regs {
        let reg_id = match *idx {
            4 => SigmaNonMandatoryRegisterId::R4,
            5 => SigmaNonMandatoryRegisterId::R5,
            6 => SigmaNonMandatoryRegisterId::R6,
            7 => SigmaNonMandatoryRegisterId::R7,
            8 => SigmaNonMandatoryRegisterId::R8,
            9 => SigmaNonMandatoryRegisterId::R9,
            other => {
                return Err(CodecError::InvalidData(format!(
                    "invalid register index: {other}"
                )))
            }
        };
        let reg_value = SigmaRegisterValue::sigma_parse_bytes(bytes);
        map.insert(reg_id, reg_value);
    }

    SigmaNonMandatoryRegisters::try_from(map)
        .map_err(|e| CodecError::InvalidData(format!("registers: {e}")))
}

// ---------------------------------------------------------------------------
// Conversion: sigma-rust → our types
// ---------------------------------------------------------------------------

/// Convert sigma-rust `Transaction` → our `ErgoTransaction`.
fn from_sigma_transaction(sigma_tx: &SigmaTransaction) -> Result<ErgoTransaction, CodecError> {
    let id_digest: SigmaDigest32 = sigma_tx.id().0;
    let tx_id = TxId(id_digest.into());

    let inputs: Vec<Input> = sigma_tx
        .inputs
        .iter()
        .map(from_sigma_input)
        .collect::<Result<_, _>>()?;

    let data_inputs: Vec<DataInput> = sigma_tx
        .data_inputs()
        .map(|dis| {
            dis.iter()
                .map(|di| {
                    let d32: SigmaDigest32 = di.box_id.into();
                    DataInput {
                        box_id: BoxId(d32.into()),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let output_candidates: Vec<ErgoBoxCandidate> = sigma_tx
        .output_candidates
        .iter()
        .map(from_sigma_box_candidate)
        .collect::<Result<_, _>>()?;

    Ok(ErgoTransaction {
        inputs,
        data_inputs,
        output_candidates,
        tx_id,
    })
}

/// Convert a sigma-rust `Input` → our `Input`.
fn from_sigma_input(input: &ergo_lib::chain::transaction::Input) -> Result<Input, CodecError> {
    let d32: SigmaDigest32 = input.box_id.into();
    let box_id = BoxId(d32.into());

    let proof_bytes: Vec<u8> = Vec::from(input.spending_proof.proof.clone());

    let extension_bytes = input
        .spending_proof
        .extension
        .sigma_serialize_bytes()
        .map_err(|e| CodecError::InvalidData(format!("extension serialize: {e}")))?;

    Ok(Input {
        box_id,
        proof_bytes,
        extension_bytes,
    })
}

/// Convert a sigma-rust `ErgoBoxCandidate` → our `ErgoBoxCandidate`.
fn from_sigma_box_candidate(
    candidate: &SigmaErgoBoxCandidate,
) -> Result<ErgoBoxCandidate, CodecError> {
    let value: u64 = *candidate.value.as_u64();

    let ergo_tree_bytes = candidate
        .ergo_tree
        .sigma_serialize_bytes()
        .map_err(|e| CodecError::InvalidData(format!("ergo tree serialize: {e}")))?;

    let creation_height = candidate.creation_height;

    let tokens: Vec<(BoxId, u64)> = candidate
        .tokens
        .as_ref()
        .map(|bt| {
            bt.iter()
                .map(|t| {
                    let d32: SigmaDigest32 = t.token_id.into();
                    (BoxId(d32.into()), u64::from(t.amount))
                })
                .collect()
        })
        .unwrap_or_default();

    let additional_registers = from_sigma_registers(&candidate.additional_registers)?;

    Ok(ErgoBoxCandidate {
        value,
        ergo_tree_bytes,
        creation_height,
        tokens,
        additional_registers,
    })
}

/// Convert sigma-rust `NonMandatoryRegisters` → our register list.
///
/// Note: we use `get_constant()` instead of `get()` because sigma-rust's `get()`
/// method has an indexing bug (uses `reg_id as usize` directly on a 0-based Vec,
/// but R4's discriminant is 4). `get_constant()` correctly subtracts `START_INDEX`.
fn from_sigma_registers(
    regs: &SigmaNonMandatoryRegisters,
) -> Result<Vec<(u8, Vec<u8>)>, CodecError> {
    let mut result = Vec::new();
    let register_ids = [
        (4u8, SigmaNonMandatoryRegisterId::R4),
        (5, SigmaNonMandatoryRegisterId::R5),
        (6, SigmaNonMandatoryRegisterId::R6),
        (7, SigmaNonMandatoryRegisterId::R7),
        (8, SigmaNonMandatoryRegisterId::R8),
        (9, SigmaNonMandatoryRegisterId::R9),
    ];
    for (i, (idx, reg_id)) in register_ids.iter().enumerate() {
        if i >= regs.len() {
            break;
        }
        match regs.get_constant(*reg_id) {
            Ok(Some(constant)) => {
                let bytes = constant
                    .sigma_serialize_bytes()
                    .map_err(|e| CodecError::InvalidData(format!("register R{idx}: {e}")))?;
                result.push((*idx, bytes));
            }
            Ok(None) => break,
            Err(_) => {
                return Err(CodecError::InvalidData(format!(
                    "unparseable register R{idx}"
                )));
            }
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Low-level reader helpers (still used by block_transactions_ser.rs)
// ---------------------------------------------------------------------------

pub fn read_array<const N: usize>(reader: &mut &[u8]) -> Result<[u8; N], CodecError> {
    if reader.len() < N {
        return Err(CodecError::UnexpectedEof);
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&reader[..N]);
    *reader = &reader[N..];
    Ok(arr)
}

pub fn read_bytes(reader: &mut &[u8], len: usize) -> Result<Vec<u8>, CodecError> {
    if reader.len() < len {
        return Err(CodecError::UnexpectedEof);
    }
    let data = reader[..len].to_vec();
    *reader = &reader[len..];
    Ok(data)
}

pub fn read_u8(reader: &mut &[u8]) -> Result<u8, CodecError> {
    if reader.is_empty() {
        return Err(CodecError::UnexpectedEof);
    }
    let byte = reader[0];
    *reader = &reader[1..];
    Ok(byte)
}

pub fn skip_bytes(reader: &mut &[u8], n: usize) -> Result<(), CodecError> {
    if reader.len() < n {
        return Err(CodecError::UnexpectedEof);
    }
    *reader = &reader[n..];
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: make a minimal valid extension_bytes (empty extension = count 0).
    fn empty_extension() -> Vec<u8> {
        vec![0x00]
    }

    /// Helper: make a P2PK-like ErgoTree with size bit set.
    /// header=0x08 (v0, size bit set), body = 0x08 0xCD <33-byte pubkey>
    fn make_p2pk_tree() -> Vec<u8> {
        use crate::vlq::put_uint;
        let mut body = vec![0x08, 0xCD];
        body.extend_from_slice(&[0x02; 33]); // dummy compressed point
        let mut tree = Vec::new();
        tree.push(0x08); // header: v0 + size bit
        put_uint(&mut tree, body.len() as u32);
        tree.extend_from_slice(&body);
        tree
    }

    /// Helper: make an ErgoTree with the "size included" bit set.
    fn make_ergo_tree(body: &[u8]) -> Vec<u8> {
        use crate::vlq::put_uint;
        let mut tree = Vec::new();
        tree.push(0x08); // header: v0 + size bit
        put_uint(&mut tree, body.len() as u32);
        tree.extend_from_slice(body);
        tree
    }

    /// Helper: make a simple ErgoTransaction.
    fn make_simple_tx() -> ErgoTransaction {
        let input = Input {
            box_id: BoxId([0x11; 32]),
            proof_bytes: Vec::new(),
            extension_bytes: empty_extension(),
        };
        let output = ErgoBoxCandidate {
            value: 1_000_000_000, // 1 ERG
            ergo_tree_bytes: make_p2pk_tree(),
            creation_height: 100_000,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        };
        let mut tx = ErgoTransaction {
            inputs: vec![input],
            data_inputs: Vec::new(),
            output_candidates: vec![output],
            tx_id: TxId([0; 32]),
        };
        tx.tx_id = compute_tx_id(&tx);
        tx
    }

    // -----------------------------------------------------------------------
    // 1. Roundtrip: simple tx (1 input, 1 output, no tokens, no registers)
    // -----------------------------------------------------------------------
    #[test]
    fn roundtrip_simple_tx() {
        let tx = make_simple_tx();
        let bytes = serialize_transaction(&tx);
        let parsed = parse_transaction(&bytes).unwrap();
        assert_eq!(parsed.inputs, tx.inputs);
        assert_eq!(parsed.data_inputs, tx.data_inputs);
        assert_eq!(parsed.output_candidates, tx.output_candidates);
        assert_eq!(parsed.tx_id, tx.tx_id);
    }

    // -----------------------------------------------------------------------
    // 2. Roundtrip: tx with multiple inputs and outputs
    // -----------------------------------------------------------------------
    #[test]
    fn roundtrip_multiple_inputs_outputs() {
        let mut tx = ErgoTransaction {
            inputs: vec![
                Input {
                    box_id: BoxId([0x11; 32]),
                    proof_bytes: Vec::new(),
                    extension_bytes: empty_extension(),
                },
                Input {
                    box_id: BoxId([0x22; 32]),
                    proof_bytes: Vec::new(),
                    extension_bytes: empty_extension(),
                },
                Input {
                    box_id: BoxId([0x33; 32]),
                    proof_bytes: Vec::new(),
                    extension_bytes: empty_extension(),
                },
            ],
            data_inputs: Vec::new(),
            output_candidates: vec![
                ErgoBoxCandidate {
                    value: 500_000_000,
                    ergo_tree_bytes: make_p2pk_tree(),
                    creation_height: 200_000,
                    tokens: Vec::new(),
                    additional_registers: Vec::new(),
                },
                ErgoBoxCandidate {
                    value: 300_000_000,
                    ergo_tree_bytes: make_ergo_tree(&[0xAB, 0xCD]),
                    creation_height: 200_001,
                    tokens: Vec::new(),
                    additional_registers: Vec::new(),
                },
            ],
            tx_id: TxId([0; 32]),
        };
        tx.tx_id = compute_tx_id(&tx);
        let bytes = serialize_transaction(&tx);
        let parsed = parse_transaction(&bytes).unwrap();
        assert_eq!(parsed, tx);
    }

    // -----------------------------------------------------------------------
    // 3. Roundtrip: tx with tokens (test deduplication)
    // -----------------------------------------------------------------------
    #[test]
    fn roundtrip_tokens_deduplication() {
        let token_a = BoxId([0xAA; 32]);
        let token_b = BoxId([0xBB; 32]);

        let mut tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0x11; 32]),
                proof_bytes: Vec::new(),
                extension_bytes: empty_extension(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![
                ErgoBoxCandidate {
                    value: 1_000_000,
                    ergo_tree_bytes: make_p2pk_tree(),
                    creation_height: 100,
                    tokens: vec![(token_a, 50), (token_b, 100)],
                    additional_registers: Vec::new(),
                },
                ErgoBoxCandidate {
                    value: 2_000_000,
                    ergo_tree_bytes: make_p2pk_tree(),
                    creation_height: 100,
                    tokens: vec![(token_a, 25)],
                    additional_registers: Vec::new(),
                },
            ],
            tx_id: TxId([0; 32]),
        };
        tx.tx_id = compute_tx_id(&tx);

        let bytes = serialize_transaction(&tx);
        let parsed = parse_transaction(&bytes).unwrap();
        assert_eq!(parsed, tx);
    }

    // -----------------------------------------------------------------------
    // 4. Roundtrip: tx with data inputs
    // -----------------------------------------------------------------------
    #[test]
    fn roundtrip_data_inputs() {
        let mut tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0x11; 32]),
                proof_bytes: Vec::new(),
                extension_bytes: empty_extension(),
            }],
            data_inputs: vec![
                DataInput {
                    box_id: BoxId([0xD1; 32]),
                },
                DataInput {
                    box_id: BoxId([0xD2; 32]),
                },
            ],
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: make_p2pk_tree(),
                creation_height: 300_000,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0; 32]),
        };
        tx.tx_id = compute_tx_id(&tx);
        let bytes = serialize_transaction(&tx);
        let parsed = parse_transaction(&bytes).unwrap();
        assert_eq!(parsed, tx);
    }

    // -----------------------------------------------------------------------
    // 5. Roundtrip: tx with non-empty proof bytes
    // -----------------------------------------------------------------------
    #[test]
    fn roundtrip_with_proofs() {
        let mut tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0x11; 32]),
                proof_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
                extension_bytes: empty_extension(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: make_p2pk_tree(),
                creation_height: 100_000,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0; 32]),
        };
        tx.tx_id = compute_tx_id(&tx);
        let bytes = serialize_transaction(&tx);
        let parsed = parse_transaction(&bytes).unwrap();
        assert_eq!(parsed.inputs[0].proof_bytes, tx.inputs[0].proof_bytes);
        assert_eq!(parsed, tx);
    }

    // -----------------------------------------------------------------------
    // 6. compute_tx_id: verify it produces a 32-byte hash
    // -----------------------------------------------------------------------
    #[test]
    fn compute_tx_id_produces_32_bytes() {
        let tx = make_simple_tx();
        let id = compute_tx_id(&tx);
        assert_eq!(id.0.len(), 32);
        assert_ne!(id.0, [0u8; 32]);
    }

    // -----------------------------------------------------------------------
    // 7. compute_tx_id: same tx → same id, different tx → different id
    // -----------------------------------------------------------------------
    #[test]
    fn compute_tx_id_deterministic_and_unique() {
        let tx1 = make_simple_tx();
        let id1a = compute_tx_id(&tx1);
        let id1b = compute_tx_id(&tx1);
        assert_eq!(id1a, id1b, "same tx must produce same id");

        let mut tx2 = make_simple_tx();
        tx2.output_candidates[0].creation_height = 999_999;
        let id2 = compute_tx_id(&tx2);
        assert_ne!(id1a, id2, "different tx must produce different id");
    }

    // -----------------------------------------------------------------------
    // 8. compute_tx_id: proofs don't affect tx_id
    // -----------------------------------------------------------------------
    #[test]
    fn compute_tx_id_proofs_independent() {
        let tx_no_proof = make_simple_tx();
        let id1 = compute_tx_id(&tx_no_proof);

        let mut tx_with_proof = make_simple_tx();
        tx_with_proof.inputs[0].proof_bytes = vec![0xFF; 64];
        let id2 = compute_tx_id(&tx_with_proof);

        assert_eq!(id1, id2, "proofs must not affect tx_id");
    }

    // -----------------------------------------------------------------------
    // 9. serialize_without_proofs: proof bytes are replaced with VLQ(0)
    // -----------------------------------------------------------------------
    #[test]
    fn serialize_without_proofs_replaces_proofs() {
        let mut tx = make_simple_tx();
        tx.inputs[0].proof_bytes = vec![0xAA; 10];

        let with_proofs = serialize_transaction(&tx);
        let without_proofs = serialize_transaction_without_proofs(&tx);

        // Without proofs should be shorter (no 10 proof bytes, just VLQ(0))
        assert!(without_proofs.len() < with_proofs.len());
    }

    // -----------------------------------------------------------------------
    // 10. Parse truncated input → error
    // -----------------------------------------------------------------------
    #[test]
    fn parse_truncated_input_eof() {
        let tx = make_simple_tx();
        let bytes = serialize_transaction(&tx);
        let result = parse_transaction(&bytes[..10]);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // 11. Box candidate with registers
    // -----------------------------------------------------------------------
    #[test]
    fn roundtrip_box_with_registers() {
        use crate::vlq::put_long as vlq_put_long;

        // Build a register value: a serialized Long constant (type 5 + zigzag VLQ)
        let mut reg_r4 = vec![0x05]; // TYPE_LONG
        vlq_put_long(&mut reg_r4, 42);

        // Build another register: a Boolean constant (type 1 + 1 byte value)
        let reg_r5 = vec![0x01, 0x01]; // TYPE_BOOLEAN, value=true

        let mut tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0x11; 32]),
                proof_bytes: Vec::new(),
                extension_bytes: empty_extension(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: make_p2pk_tree(),
                creation_height: 100_000,
                tokens: Vec::new(),
                additional_registers: vec![(4, reg_r4.clone()), (5, reg_r5.clone())],
            }],
            tx_id: TxId([0; 32]),
        };
        tx.tx_id = compute_tx_id(&tx);

        let bytes = serialize_transaction(&tx);
        let parsed = parse_transaction(&bytes).unwrap();
        assert_eq!(parsed, tx);

        // With registers should be longer than without
        let without_regs_tx = {
            let mut t = tx.clone();
            t.output_candidates[0].additional_registers.clear();
            t
        };
        let bytes_no_regs = serialize_transaction(&without_regs_tx);
        assert!(bytes.len() > bytes_no_regs.len());
    }

    // -----------------------------------------------------------------------
    // 12. parse_transaction_from_reader: inline parsing with shared buffer
    // -----------------------------------------------------------------------
    #[test]
    fn parse_from_reader_advances_correctly() {
        let tx1 = make_simple_tx();
        let tx1_bytes = serialize_transaction(&tx1);

        // Create a second tx with different data
        let mut tx2 = make_simple_tx();
        tx2.output_candidates[0].value = 500_000_000;
        tx2.output_candidates[0].creation_height = 200_000;
        tx2.tx_id = compute_tx_id(&tx2);
        let tx2_bytes = serialize_transaction(&tx2);

        // Concatenate two serialized txs
        let mut combined = tx1_bytes.clone();
        combined.extend_from_slice(&tx2_bytes);

        let mut reader: &[u8] = &combined;

        // Parse first tx
        let parsed1 = parse_transaction_from_reader(&mut reader).unwrap();
        assert_eq!(parsed1.tx_id, tx1.tx_id);
        assert_eq!(reader.len(), tx2_bytes.len());

        // Parse second tx
        let parsed2 = parse_transaction_from_reader(&mut reader).unwrap();
        assert_eq!(parsed2.tx_id, tx2.tx_id);
        assert_eq!(reader.len(), 0);
    }
}
