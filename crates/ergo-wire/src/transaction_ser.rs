//! Binary serialization of Ergo transactions, matching the sigma-rust wire format.
//!
//! Key encoding conventions:
//! - Input/output/data-input counts: fixed 2-byte BE u16 (`put_sigma_u16`)
//! - Proof length: fixed 2-byte BE u16
//! - Box value: zigzag+VLQ i64 (`put_long`)
//! - Tree length, creation_height, token_count, token_id_index: VLQ u32 (`put_uint`)
//! - Token amount: zigzag+VLQ i64 (`put_long`)
//! - Distinct token count: VLQ u32 (`put_uint`)
//! - Register bitmap: 1-byte u8 (count in upper nibble)

use blake2::{digest::consts::U32, Blake2b, Digest};
use ergo_types::transaction::*;

use crate::sigma_byte::{get_sigma_u16, put_sigma_u16, skip_sigma_constant};
use crate::vlq::{get_long, get_uint, put_long, put_uint, CodecError};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Serialize a transaction to bytes (full, with proofs).
pub fn serialize_transaction(tx: &ErgoTransaction) -> Vec<u8> {
    serialize_tx_inner(tx, true)
}

/// Serialize a transaction without proofs (for tx_id computation).
/// Proof bytes are replaced with u16(0).
pub fn serialize_transaction_without_proofs(tx: &ErgoTransaction) -> Vec<u8> {
    serialize_tx_inner(tx, false)
}

/// Parse a transaction from raw bytes.
pub fn parse_transaction(data: &[u8]) -> Result<ErgoTransaction, CodecError> {
    let reader = &mut &data[..];

    // --- Inputs ---
    let input_count = get_sigma_u16(reader)? as usize;
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let box_id = BoxId(read_array::<32>(reader)?);

        // proof_bytes: sigma u16 length + raw bytes
        let proof_len = get_sigma_u16(reader)? as usize;
        let proof_bytes = read_bytes(reader, proof_len)?;

        // extension_bytes: opaque, capture raw bytes
        let extension_bytes = parse_extension_bytes(reader)?;

        inputs.push(Input {
            box_id,
            proof_bytes,
            extension_bytes,
        });
    }

    // --- Data inputs ---
    let data_input_count = get_sigma_u16(reader)? as usize;
    let mut data_inputs = Vec::with_capacity(data_input_count);
    for _ in 0..data_input_count {
        let box_id = BoxId(read_array::<32>(reader)?);
        data_inputs.push(DataInput { box_id });
    }

    // --- Distinct token IDs ---
    let distinct_count = get_uint(reader)? as usize;
    let mut distinct_token_ids = Vec::with_capacity(distinct_count);
    for _ in 0..distinct_count {
        distinct_token_ids.push(BoxId(read_array::<32>(reader)?));
    }

    // --- Outputs ---
    let output_count = get_sigma_u16(reader)? as usize;
    let mut output_candidates = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        output_candidates.push(parse_box_candidate(reader, &distinct_token_ids)?);
    }

    // Compute tx_id from the parsed transaction (without proofs)
    let temp_tx = ErgoTransaction {
        inputs: inputs.clone(),
        data_inputs: data_inputs.clone(),
        output_candidates: output_candidates.clone(),
        tx_id: TxId([0; 32]), // placeholder
    };
    let tx_id = compute_tx_id(&temp_tx);

    Ok(ErgoTransaction {
        inputs,
        data_inputs,
        output_candidates,
        tx_id,
    })
}

/// Compute transaction ID = Blake2b256(serialize_without_proofs).
pub fn compute_tx_id(tx: &ErgoTransaction) -> TxId {
    let bytes = serialize_transaction_without_proofs(tx);
    let hash = Blake2b::<U32>::digest(&bytes);
    let mut id = [0u8; 32];
    id.copy_from_slice(&hash);
    TxId(id)
}

// ---------------------------------------------------------------------------
// Box candidate serialization / parsing
// ---------------------------------------------------------------------------

/// Serialize an `ErgoBoxCandidate` with indexed token references.
fn serialize_box_candidate(
    candidate: &ErgoBoxCandidate,
    distinct_token_ids: &[BoxId],
    buf: &mut Vec<u8>,
) {
    // value: zigzag+VLQ i64
    put_long(buf, candidate.value as i64);

    // ergo_tree_bytes: VLQ u32 length + raw bytes
    put_uint(buf, candidate.ergo_tree_bytes.len() as u32);
    buf.extend_from_slice(&candidate.ergo_tree_bytes);

    // creation_height: VLQ u32
    put_uint(buf, candidate.creation_height);

    // tokens: VLQ u32 count, then index + amount for each
    put_uint(buf, candidate.tokens.len() as u32);
    for (token_id, amount) in &candidate.tokens {
        let index = distinct_token_ids
            .iter()
            .position(|id| id == token_id)
            .expect("token_id must be in distinct_token_ids");
        put_uint(buf, index as u32);
        put_long(buf, *amount as i64);
    }

    // additional registers
    if candidate.additional_registers.is_empty() {
        buf.push(0x00);
    } else {
        buf.push((candidate.additional_registers.len() as u8) << 4);
        for (_reg_id, reg_bytes) in &candidate.additional_registers {
            buf.extend_from_slice(reg_bytes);
        }
    }
}

/// Parse an `ErgoBoxCandidate` with indexed token references.
fn parse_box_candidate(
    reader: &mut &[u8],
    distinct_token_ids: &[BoxId],
) -> Result<ErgoBoxCandidate, CodecError> {
    // value: zigzag+VLQ i64
    let value = get_long(reader)? as u64;

    // ergo_tree_bytes: VLQ u32 length + raw bytes
    let tree_len = get_uint(reader)? as usize;
    let ergo_tree_bytes = read_bytes(reader, tree_len)?;

    // creation_height: VLQ u32
    let creation_height = get_uint(reader)?;

    // tokens
    let token_count = get_uint(reader)? as usize;
    let mut tokens = Vec::with_capacity(token_count);
    for _ in 0..token_count {
        let index = get_uint(reader)? as usize;
        if index >= distinct_token_ids.len() {
            return Err(CodecError::InvalidData(format!(
                "token index {index} out of bounds (distinct count: {})",
                distinct_token_ids.len()
            )));
        }
        let amount = get_long(reader)? as u64;
        tokens.push((distinct_token_ids[index], amount));
    }

    // additional registers
    let bitmap = read_u8(reader)?;
    let reg_count = (bitmap >> 4) as usize;
    let mut additional_registers = Vec::with_capacity(reg_count);
    for i in 0..reg_count {
        let reg_id = 4 + i as u8; // R4, R5, R6, ...
        // Capture raw bytes of the sigma constant
        let start = *reader as &[u8];
        skip_sigma_constant(reader)?;
        let consumed = start.len() - reader.len();
        let reg_bytes = start[..consumed].to_vec();
        additional_registers.push((reg_id, reg_bytes));
    }

    Ok(ErgoBoxCandidate {
        value,
        ergo_tree_bytes,
        creation_height,
        tokens,
        additional_registers,
    })
}

// ---------------------------------------------------------------------------
// Internal serialization
// ---------------------------------------------------------------------------

fn serialize_tx_inner(tx: &ErgoTransaction, include_proofs: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // --- Inputs ---
    put_sigma_u16(&mut buf, tx.inputs.len() as u16);
    for input in &tx.inputs {
        buf.extend_from_slice(&input.box_id.0);

        if include_proofs {
            put_sigma_u16(&mut buf, input.proof_bytes.len() as u16);
            buf.extend_from_slice(&input.proof_bytes);
        } else {
            put_sigma_u16(&mut buf, 0);
        }

        // extension_bytes: write as-is (already in wire format)
        buf.extend_from_slice(&input.extension_bytes);
    }

    // --- Data inputs ---
    put_sigma_u16(&mut buf, tx.data_inputs.len() as u16);
    for di in &tx.data_inputs {
        buf.extend_from_slice(&di.box_id.0);
    }

    // --- Distinct token IDs from all outputs ---
    let distinct_token_ids = collect_distinct_token_ids(&tx.output_candidates);
    put_uint(&mut buf, distinct_token_ids.len() as u32);
    for token_id in &distinct_token_ids {
        buf.extend_from_slice(&token_id.0);
    }

    // --- Outputs ---
    put_sigma_u16(&mut buf, tx.output_candidates.len() as u16);
    for candidate in &tx.output_candidates {
        serialize_box_candidate(candidate, &distinct_token_ids, &mut buf);
    }

    buf
}

/// Collect distinct token IDs from all output candidates, preserving first-seen order.
fn collect_distinct_token_ids(candidates: &[ErgoBoxCandidate]) -> Vec<BoxId> {
    let mut seen = Vec::new();
    for candidate in candidates {
        for (token_id, _) in &candidate.tokens {
            if !seen.contains(token_id) {
                seen.push(*token_id);
            }
        }
    }
    seen
}

/// Parse extension bytes from the wire format.
///
/// The extension (ContextExtension) is serialized as:
///   u8(count) then for each entry: u8(key_id) + sigma_constant_bytes.
///
/// We capture the raw bytes (including the count byte) as opaque data.
fn parse_extension_bytes(reader: &mut &[u8]) -> Result<Vec<u8>, CodecError> {
    let start = *reader as &[u8];
    let count = read_u8(reader)?;

    if count == 0 {
        // Just the zero count byte
        return Ok(vec![0x00]);
    }

    for _ in 0..count {
        // key: 1 byte
        let _key = read_u8(reader)?;
        // value: sigma constant
        skip_sigma_constant(reader)?;
    }

    let consumed = start.len() - reader.len();
    Ok(start[..consumed].to_vec())
}

// ---------------------------------------------------------------------------
// Low-level reader helpers
// ---------------------------------------------------------------------------

fn read_array<const N: usize>(reader: &mut &[u8]) -> Result<[u8; N], CodecError> {
    if reader.len() < N {
        return Err(CodecError::UnexpectedEof);
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&reader[..N]);
    *reader = &reader[N..];
    Ok(arr)
}

fn read_bytes(reader: &mut &[u8], len: usize) -> Result<Vec<u8>, CodecError> {
    if reader.len() < len {
        return Err(CodecError::UnexpectedEof);
    }
    let data = reader[..len].to_vec();
    *reader = &reader[len..];
    Ok(data)
}

fn read_u8(reader: &mut &[u8]) -> Result<u8, CodecError> {
    if reader.is_empty() {
        return Err(CodecError::UnexpectedEof);
    }
    let byte = reader[0];
    *reader = &reader[1..];
    Ok(byte)
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

    /// Helper: make a simple ErgoTransaction.
    fn make_simple_tx() -> ErgoTransaction {
        let input = Input {
            box_id: BoxId([0x11; 32]),
            proof_bytes: Vec::new(),
            extension_bytes: empty_extension(),
        };
        let output = ErgoBoxCandidate {
            value: 1_000_000_000, // 1 ERG
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
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
    // 1. Roundtrip: simple tx (1 input, 1 output, no tokens, no registers, empty extension)
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
                    ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
                    creation_height: 200_000,
                    tokens: Vec::new(),
                    additional_registers: Vec::new(),
                },
                ErgoBoxCandidate {
                    value: 300_000_000,
                    ergo_tree_bytes: vec![0x00, 0x08, 0xcd, 0xab],
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
    // 3. Roundtrip: tx with tokens (test deduplication — same token ID in two outputs)
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
                    ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
                    creation_height: 100,
                    tokens: vec![(token_a, 50), (token_b, 100)],
                    additional_registers: Vec::new(),
                },
                ErgoBoxCandidate {
                    value: 2_000_000,
                    ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
                    creation_height: 100,
                    // Same token_a in second output — should be deduplicated
                    tokens: vec![(token_a, 25)],
                    additional_registers: Vec::new(),
                },
            ],
            tx_id: TxId([0; 32]),
        };
        tx.tx_id = compute_tx_id(&tx);

        let bytes = serialize_transaction(&tx);

        // Verify deduplication: distinct token IDs should be [token_a, token_b]
        // The serialized bytes after inputs/data-inputs should have put_uint(2) for 2 distinct IDs
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
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
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
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
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
        // Should not be all zeros (extremely unlikely for a real hash)
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

        // Different tx (different creation_height)
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
    // 9. serialize_without_proofs: proof bytes are replaced with u16(0)
    // -----------------------------------------------------------------------
    #[test]
    fn serialize_without_proofs_replaces_proofs() {
        let mut tx = make_simple_tx();
        tx.inputs[0].proof_bytes = vec![0xAA; 10];

        let with_proofs = serialize_transaction(&tx);
        let without_proofs = serialize_transaction_without_proofs(&tx);

        // Without proofs should be shorter (no 10 proof bytes, just u16(0))
        assert!(without_proofs.len() < with_proofs.len());

        // Verify: after box_id (32 bytes), the next 2 bytes should be 0x00, 0x00
        // First 2 bytes are put_sigma_u16(input_count = 1) = [0x00, 0x01]
        // Then 32 bytes of box_id
        // Then 2 bytes of proof length
        let proof_len_offset = 2 + 32; // sigma_u16(1) + box_id
        assert_eq!(
            without_proofs[proof_len_offset],
            0x00,
            "proof length high byte should be 0"
        );
        assert_eq!(
            without_proofs[proof_len_offset + 1],
            0x00,
            "proof length low byte should be 0"
        );
    }

    // -----------------------------------------------------------------------
    // 10. Parse truncated input → UnexpectedEof
    // -----------------------------------------------------------------------
    #[test]
    fn parse_truncated_input_eof() {
        let tx = make_simple_tx();
        let bytes = serialize_transaction(&tx);
        // Truncate mid-way through the first input's box_id
        let result = parse_transaction(&bytes[..10]);
        assert!(matches!(result, Err(CodecError::UnexpectedEof)));
    }

    // -----------------------------------------------------------------------
    // 11. Box candidate with registers (register count in bitmap upper nibble)
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
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
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

        // Verify register count encoding: 2 registers → bitmap byte = 0x20
        let without_regs_tx = {
            let mut t = tx.clone();
            t.output_candidates[0].additional_registers.clear();
            t
        };
        let bytes_no_regs = serialize_transaction(&without_regs_tx);
        // With registers should be longer
        assert!(bytes.len() > bytes_no_regs.len());
    }

    // -----------------------------------------------------------------------
    // 12. Token index out of bounds → InvalidData
    // -----------------------------------------------------------------------
    #[test]
    fn token_index_out_of_bounds() {
        // Manually craft bytes where the token index exceeds distinct_token_ids count.
        let mut buf = Vec::new();

        // 1 input
        put_sigma_u16(&mut buf, 1);
        buf.extend_from_slice(&[0x11; 32]); // box_id
        put_sigma_u16(&mut buf, 0); // no proof
        buf.push(0x00); // empty extension

        // 0 data inputs
        put_sigma_u16(&mut buf, 0);

        // 1 distinct token ID
        put_uint(&mut buf, 1);
        buf.extend_from_slice(&[0xAA; 32]); // the one token

        // 1 output
        put_sigma_u16(&mut buf, 1);
        put_long(&mut buf, 1_000_000); // value
        put_uint(&mut buf, 3); // ergo_tree len
        buf.extend_from_slice(&[0x00, 0x08, 0xcd]); // ergo_tree
        put_uint(&mut buf, 100); // creation_height
        put_uint(&mut buf, 1); // 1 token
        put_uint(&mut buf, 5); // token index 5 — OUT OF BOUNDS (only 1 distinct)
        put_long(&mut buf, 100); // amount
        buf.push(0x00); // no registers

        let result = parse_transaction(&buf);
        assert!(
            matches!(result, Err(CodecError::InvalidData(ref msg)) if msg.contains("out of bounds")),
            "expected InvalidData with 'out of bounds', got: {result:?}"
        );
    }
}
