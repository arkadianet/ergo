use ergo_primitives::digest::{blake2b256, ModifierId};
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::ergo_box::{
    read_ergo_box_candidate_indexed, write_ergo_box_candidate_indexed, ErgoBoxCandidate,
};
use crate::error::WriteError;
use crate::input::*;
use crate::token::TokenId;

/// Signed Ergo transaction: a complete set of spending inputs
/// (with proofs), read-only data inputs, and the output box candidates
/// the transaction creates. Authenticated by `transaction_id` =
/// `Blake2b256(bytes_to_sign(tx))`.
#[derive(Debug, Clone, PartialEq)]
pub struct Transaction {
    /// Spending inputs, each with its own sigma proof + context extension.
    pub inputs: Vec<Input>,
    /// Read-only references used inside scripts; do not consume the box.
    pub data_inputs: Vec<DataInput>,
    /// Output box candidates this transaction will create on apply.
    pub output_candidates: Vec<ErgoBoxCandidate>,
}

/// Pre-signing form of a [`Transaction`]: every spending input still
/// carries its caller-supplied context extension but the proof has not
/// yet been computed, so [`UnsignedInput`] is used in place of [`Input`].
#[derive(Debug, Clone, PartialEq)]
pub struct UnsignedTransaction {
    /// Spending inputs without proofs (proofs are filled in after signing).
    pub inputs: Vec<UnsignedInput>,
    /// Read-only references used inside scripts.
    pub data_inputs: Vec<DataInput>,
    /// Output box candidates this transaction will create on apply.
    pub output_candidates: Vec<ErgoBoxCandidate>,
}

/// Wire-format collection bounds shared by all three transaction writers
/// (`write_transaction`, `write_unsigned_transaction`, `bytes_to_sign_into`).
///
/// Scala writes input/data-input/output counts as VLQ-`u16` and the
/// distinct-token-table count as `getUIntExact` (`u32` capped at
/// `i32::MAX`). A caller-built collection past either bound would
/// silently wrap on `as u16`/`as u32` while the writer still emitted
/// every element, producing malformed bytes the reader would reject
/// with no traceable cause. Keep the three writers in lockstep so a
/// fix here cannot drift between the signed/unsigned/bytes_to_sign tx
/// id paths.
fn check_transaction_collection_bounds(
    inputs_len: usize,
    data_inputs_len: usize,
    outputs_len: usize,
    token_table_len: usize,
) -> Result<(), WriteError> {
    if inputs_len > u16::MAX as usize {
        return Err(WriteError::InvalidData(format!(
            "transaction inputs count too large for Scala wire format: {inputs_len} (max 65535)",
        )));
    }
    if data_inputs_len > u16::MAX as usize {
        return Err(WriteError::InvalidData(format!(
            "transaction data_inputs count too large for Scala wire format: {data_inputs_len} (max 65535)",
        )));
    }
    if outputs_len > u16::MAX as usize {
        return Err(WriteError::InvalidData(format!(
            "transaction outputs count too large for Scala wire format: {outputs_len} (max 65535)",
        )));
    }
    // Read side uses `get_u32_exact` (rejects > i32::MAX); mirror that
    // bound here so the write side cannot emit a count the read side
    // would refuse. In practice the table is bounded by 65535 outputs
    // × 255 tokens each ≈ 16.7M, so this check is defense in depth.
    if token_table_len > i32::MAX as usize {
        return Err(WriteError::InvalidData(format!(
            "transaction token-table count exceeds Scala getUIntExact bound: {token_table_len} (max {})",
            i32::MAX,
        )));
    }
    Ok(())
}

/// Build the distinct token ID table from output candidates.
/// Token IDs appear in first-occurrence order across all outputs.
fn extract_distinct_token_ids(outputs: &[ErgoBoxCandidate]) -> Vec<TokenId> {
    // First-occurrence order is consensus-relevant (the table indexes
    // token amounts in the transaction wire form), so the output `Vec`
    // is order-preserving. The `BTreeSet<[u8; 32]>` is only a membership
    // gate — `Digest32` itself does not implement `Ord`, so we compare
    // on the underlying byte arrays.
    let mut seen_ids: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
    let mut order = Vec::new();
    for out in outputs {
        for token in &out.tokens {
            if seen_ids.insert(*token.token_id.as_bytes()) {
                order.push(token.token_id);
            }
        }
    }
    order
}

/// Emit the post-inputs tail shared by all three transaction writers:
/// `data_inputs · token_table · outputs(indexed against token_table)`.
/// Callers MUST run `check_transaction_collection_bounds` beforehand —
/// the casts here rely on that pre-check.
fn write_transaction_tail(
    w: &mut VlqWriter,
    data_inputs: &[DataInput],
    token_table: &[TokenId],
    output_candidates: &[ErgoBoxCandidate],
) -> Result<(), WriteError> {
    w.put_u16(data_inputs.len() as u16);
    for di in data_inputs {
        write_data_input(w, di);
    }
    w.put_u32(token_table.len() as u32);
    for tid in token_table {
        w.put_bytes(tid.as_bytes());
    }
    w.put_u16(output_candidates.len() as u16);
    for out in output_candidates {
        write_ergo_box_candidate_indexed(w, out, token_table)?;
    }
    Ok(())
}

/// Consume the post-inputs tail and return `(data_inputs,
/// output_candidates)`. The per-tx token table is reconstructed from
/// the wire to resolve indexed outputs but is not returned — it has
/// no place in the parsed `Transaction` / `UnsignedTransaction`.
fn read_transaction_tail_after_inputs(
    r: &mut VlqReader,
) -> Result<(Vec<DataInput>, Vec<ErgoBoxCandidate>), ReadError> {
    let di_count = r.get_u16()? as usize;
    let mut data_inputs = Vec::with_capacity(di_count);
    for _ in 0..di_count {
        data_inputs.push(read_data_input(r)?);
    }
    // `get_u32_exact` only rejects values above i32::MAX, so `token_count`
    // can be ~2.1e9 — `Vec::with_capacity(token_count)` would then request
    // tens of GiB and abort the process before the first token is read. Each
    // entry is a 32-byte `TokenId`, so the table can hold at most
    // `remaining / 32` entries; cap the reservation there. Acceptance is
    // unchanged: the loop still reads `token_count` entries and returns
    // `UnexpectedEnd` if the payload is short.
    let token_count = r.get_u32_exact()? as usize;
    let mut token_table = Vec::with_capacity(token_count.min(r.remaining() / 32));
    for _ in 0..token_count {
        token_table.push(TokenId::from_bytes(r.get_array::<32>()?));
    }
    let output_count = r.get_u16()? as usize;
    let mut output_candidates = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        output_candidates.push(read_ergo_box_candidate_indexed(r, &token_table)?);
    }
    Ok((data_inputs, output_candidates))
}

/// Serialize a signed [`Transaction`] in canonical wire form: inputs
/// (full spending proofs), data inputs, the per-tx distinct token ID
/// table, and outputs serialized in indexed mode against that table.
pub fn write_transaction(w: &mut VlqWriter, tx: &Transaction) -> Result<(), WriteError> {
    let token_table = extract_distinct_token_ids(&tx.output_candidates);
    check_transaction_collection_bounds(
        tx.inputs.len(),
        tx.data_inputs.len(),
        tx.output_candidates.len(),
        token_table.len(),
    )?;
    w.put_u16(tx.inputs.len() as u16);
    for input in &tx.inputs {
        write_input(w, input)?;
    }
    write_transaction_tail(w, &tx.data_inputs, &token_table, &tx.output_candidates)
}

/// Decode the wire form produced by [`write_transaction`].
pub fn read_transaction(r: &mut VlqReader) -> Result<Transaction, ReadError> {
    let input_count = r.get_u16()? as usize;
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        inputs.push(read_input(r)?);
    }
    let (data_inputs, output_candidates) = read_transaction_tail_after_inputs(r)?;
    Ok(Transaction {
        inputs,
        data_inputs,
        output_candidates,
    })
}

/// Serialize an [`UnsignedTransaction`]. Same shape as
/// [`write_transaction`] except inputs use the unsigned wire form
/// (no proof bytes; only `box_id + extension`).
pub fn write_unsigned_transaction(
    w: &mut VlqWriter,
    utx: &UnsignedTransaction,
) -> Result<(), WriteError> {
    let token_table = extract_distinct_token_ids(&utx.output_candidates);
    check_transaction_collection_bounds(
        utx.inputs.len(),
        utx.data_inputs.len(),
        utx.output_candidates.len(),
        token_table.len(),
    )?;
    w.put_u16(utx.inputs.len() as u16);
    for input in &utx.inputs {
        write_unsigned_input(w, input)?;
    }
    write_transaction_tail(w, &utx.data_inputs, &token_table, &utx.output_candidates)
}

/// Decode the wire form produced by [`write_unsigned_transaction`].
pub fn read_unsigned_transaction(r: &mut VlqReader) -> Result<UnsignedTransaction, ReadError> {
    let input_count = r.get_u16()? as usize;
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        inputs.push(read_unsigned_input(r)?);
    }
    let (data_inputs, output_candidates) = read_transaction_tail_after_inputs(r)?;
    Ok(UnsignedTransaction {
        inputs,
        data_inputs,
        output_candidates,
    })
}

/// Serialize a signed transaction in bytes_to_sign form into a caller-provided
/// writer. APPENDS to whatever is already in `w`; caller is responsible for
/// passing an empty (or freshly cleared) writer if they want only these bytes.
///
/// Used as a primitive by `bytes_to_sign` (single-shot) and `transaction_id_with`
/// (scratch-reuse path that wants the bytes-then-hash sequence without the
/// intermediate `Vec<u8>` allocation).
///
/// Format invariant: byte-identical to `bytes_to_sign(tx)` for the same `tx`,
/// regardless of writer history before the call (since this function only
/// appends).
pub fn bytes_to_sign_into(w: &mut VlqWriter, tx: &Transaction) -> Result<(), WriteError> {
    let token_table = extract_distinct_token_ids(&tx.output_candidates);
    check_transaction_collection_bounds(
        tx.inputs.len(),
        tx.data_inputs.len(),
        tx.output_candidates.len(),
        token_table.len(),
    )?;
    w.put_u16(tx.inputs.len() as u16);
    // The signed-vs-unsigned-vs-bytes_to_sign distinction lives here:
    // this writer zeroes proofs via write_input_to_sign; the post-inputs
    // tail is identical across all three writers.
    for input in &tx.inputs {
        write_input_to_sign(w, input)?;
    }
    write_transaction_tail(w, &tx.data_inputs, &token_table, &tx.output_candidates)
}

/// Serialize a signed transaction in bytes_to_sign form: each input's proof
/// is replaced with an empty proof (VLQ u16 = 0), preserving ContextExtension.
///
/// NOTE: This is the signed transaction wire format with zeroed proofs, NOT
/// the UnsignedTransaction wire format. The difference: bytes_to_sign writes
/// `boxId + proof_len(0) + extension` per input (signed format), while
/// UnsignedTransaction writes `boxId + extension` (no proof_len field).
pub fn bytes_to_sign(tx: &Transaction) -> Result<Vec<u8>, WriteError> {
    let mut w = VlqWriter::new();
    bytes_to_sign_into(&mut w, tx)?;
    Ok(w.result())
}

/// Compute the transaction ID: Blake2b256(bytes_to_sign).
pub fn transaction_id(tx: &Transaction) -> Result<ModifierId, WriteError> {
    Ok(blake2b256(&bytes_to_sign(tx)?).into())
}

/// Self-cleaning scratch variant of `transaction_id`. Clears `w` first, writes
/// `bytes_to_sign(tx)` into it, hashes the resulting slice, returns the digest.
/// Leaves `w` containing the hashed bytes (caller may inspect them via
/// `as_slice()` before the next emit).
///
/// Use this when you have a long-lived `VlqWriter` you reuse across many txs —
/// avoids the per-call `Vec<u8>` allocation of `bytes_to_sign`. Byte-identical
/// to `transaction_id(tx)` modulo writer state.
pub fn transaction_id_with(w: &mut VlqWriter, tx: &Transaction) -> Result<ModifierId, WriteError> {
    w.clear();
    bytes_to_sign_into(w, tx)?;
    Ok(blake2b256(w.as_slice()).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ergo_box::ErgoBoxCandidate;
    use crate::ergo_tree::ErgoTree;
    use crate::opcode::Expr;
    use crate::register::AdditionalRegisters;
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::SigmaValue;
    use crate::token::Token;
    use ergo_primitives::digest::Digest32;

    // ----- helpers -----

    fn size_delimited_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            // Root must be SSigmaProp: under `has_size`, a non-SigmaProp root
            // (e.g. `Const(SBoolean, true)`) fails Scala's
            // CheckDeserializedScriptIsSigmaProp and is soft-fork-wrapped into
            // `Expr::Unparsed` on re-parse, so it would not survive a
            // round-trip as a parsed body.
            body: Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(crate::sigma_value::SigmaBoolean::TrivialProp(true)),
            },
        }
    }

    fn make_box_id(fill: u8) -> Digest32 {
        Digest32::from_bytes([fill; 32])
    }

    fn make_token_id(fill: u8) -> TokenId {
        TokenId::from_bytes([fill; 32])
    }

    fn make_candidate(value: u64, height: u32, tokens: Vec<Token>) -> ErgoBoxCandidate {
        ErgoBoxCandidate::new(
            value,
            size_delimited_tree(),
            height,
            tokens,
            AdditionalRegisters::empty(),
        )
        .unwrap()
    }

    // ----- happy path -----

    #[test]
    fn token_table_extraction_dedup_and_order() {
        let t1 = make_token_id(0x01);
        let t2 = make_token_id(0x02);
        let t3 = make_token_id(0x03);

        let outputs = vec![
            make_candidate(
                1_000_000,
                100,
                vec![
                    Token {
                        token_id: t2,
                        amount: 10,
                    },
                    Token {
                        token_id: t1,
                        amount: 20,
                    },
                ],
            ),
            make_candidate(
                2_000_000,
                100,
                vec![
                    Token {
                        token_id: t1,
                        amount: 5,
                    }, // duplicate
                    Token {
                        token_id: t3,
                        amount: 30,
                    },
                ],
            ),
        ];

        let table = extract_distinct_token_ids(&outputs);
        // First occurrence order: t2 (output 0, token 0), t1 (output 0, token 1), t3 (output 1, token 1)
        assert_eq!(table, vec![t2, t1, t3]);
    }

    #[test]
    fn token_table_empty_outputs() {
        let table = extract_distinct_token_ids(&[]);
        assert!(table.is_empty());

        let outputs = vec![make_candidate(1_000_000, 100, vec![])];
        let table = extract_distinct_token_ids(&outputs);
        assert!(table.is_empty());
    }

    // ----- round-trips -----

    #[test]
    fn transaction_roundtrip_no_tokens() {
        let tx = Transaction {
            inputs: vec![Input {
                box_id: make_box_id(0xAA),
                spending_proof: SpendingProof::new(vec![0xDE, 0xAD], ContextExtension::empty())
                    .unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![make_candidate(1_000_000, 100, vec![])],
        };
        let mut w = VlqWriter::new();
        write_transaction(&mut w, &tx).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_transaction(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert_eq!(decoded, tx);
    }

    #[test]
    fn transaction_roundtrip_with_tokens_and_data_inputs() {
        let t1 = make_token_id(0x01);
        let t2 = make_token_id(0x02);

        let tx = Transaction {
            inputs: vec![
                Input {
                    box_id: make_box_id(0xAA),
                    spending_proof: SpendingProof::new(
                        vec![0x01, 0x02, 0x03],
                        ContextExtension::empty(),
                    )
                    .unwrap(),
                },
                Input {
                    box_id: make_box_id(0xBB),
                    spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
                },
            ],
            data_inputs: vec![DataInput {
                box_id: make_box_id(0xCC),
            }],
            output_candidates: vec![
                make_candidate(
                    5_000_000,
                    200,
                    vec![Token {
                        token_id: t1,
                        amount: 100,
                    }],
                ),
                make_candidate(
                    3_000_000,
                    200,
                    vec![
                        Token {
                            token_id: t2,
                            amount: 50,
                        },
                        Token {
                            token_id: t1,
                            amount: 25,
                        },
                    ],
                ),
            ],
        };
        let mut w = VlqWriter::new();
        write_transaction(&mut w, &tx).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_transaction(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert_eq!(decoded, tx);
    }

    #[test]
    fn unsigned_transaction_roundtrip() {
        let utx = UnsignedTransaction {
            inputs: vec![UnsignedInput {
                box_id: make_box_id(0x11),
                extension: ContextExtension::empty(),
            }],
            data_inputs: vec![],
            output_candidates: vec![make_candidate(1_000_000, 50, vec![])],
        };
        let mut w = VlqWriter::new();
        write_unsigned_transaction(&mut w, &utx).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_unsigned_transaction(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert_eq!(decoded, utx);
    }

    #[test]
    fn bytes_to_sign_zeroes_proof_preserves_extension() {
        use crate::sigma_type::SigmaType;
        use crate::sigma_value::SigmaValue;

        let mut ext = ContextExtension::empty();
        ext.values.insert(0, (SigmaType::SInt, SigmaValue::Int(42)));

        let tx = Transaction {
            inputs: vec![Input {
                box_id: make_box_id(0xAA),
                spending_proof: SpendingProof::new(vec![0xCA, 0xFE, 0xBA, 0xBE], ext.clone())
                    .unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![make_candidate(1_000_000, 100, vec![])],
        };

        let sign_bytes = bytes_to_sign(&tx).unwrap();

        // bytes_to_sign uses the signed-tx wire format with proof_len=0.
        // Parse it as a Transaction -- all proofs should be empty.
        let mut r = VlqReader::new(&sign_bytes);
        let parsed = read_transaction(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes in bytes_to_sign parse");

        assert_eq!(parsed.inputs.len(), 1);
        assert_eq!(parsed.inputs[0].box_id, make_box_id(0xAA));
        assert!(parsed.inputs[0].spending_proof.proof.is_empty());
        assert_eq!(parsed.inputs[0].spending_proof.extension, ext);

        // Re-serialize the parsed (empty-proof) tx in bytes_to_sign form
        // should produce identical bytes
        let bts_of_parsed = bytes_to_sign(&parsed).unwrap();
        assert_eq!(sign_bytes, bts_of_parsed);
    }

    #[test]
    fn transaction_id_is_blake2b256_of_bytes_to_sign() {
        let tx = Transaction {
            inputs: vec![Input {
                box_id: make_box_id(0xFF),
                spending_proof: SpendingProof::new(vec![0x01], ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![make_candidate(1_000_000, 100, vec![])],
        };
        let bts = bytes_to_sign(&tx).unwrap();
        let expected: ModifierId = blake2b256(&bts).into();
        assert_eq!(transaction_id(&tx).unwrap(), expected);
    }

    #[test]
    fn bytes_to_sign_into_matches_bytes_to_sign() {
        // bytes_to_sign_into APPENDS — feeding it an empty writer must reproduce
        // bytes_to_sign exactly. This is the contract that lets callers reuse a
        // single VlqWriter as scratch across many signed-bytes emits.
        let tx = Transaction {
            inputs: vec![
                Input {
                    box_id: make_box_id(0x11),
                    spending_proof: SpendingProof::new(vec![0xCA, 0xFE], ContextExtension::empty())
                        .unwrap(),
                },
                Input {
                    box_id: make_box_id(0x22),
                    spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
                },
            ],
            data_inputs: vec![DataInput {
                box_id: make_box_id(0x33),
            }],
            output_candidates: vec![
                make_candidate(
                    7_500_000,
                    300,
                    vec![Token {
                        token_id: make_token_id(0xAA),
                        amount: 1_000,
                    }],
                ),
                make_candidate(2_500_000, 300, vec![]),
            ],
        };
        let direct = bytes_to_sign(&tx).unwrap();
        let mut w = VlqWriter::new();
        bytes_to_sign_into(&mut w, &tx).unwrap();
        assert_eq!(w.as_slice(), direct.as_slice());
    }

    #[test]
    fn transaction_id_with_clears_then_matches_transaction_id() {
        // transaction_id_with must clear pre-existing writer state and produce
        // the same digest as transaction_id(tx). Pre-fills the writer with junk
        // to prove the clear() path is exercised.
        let tx = Transaction {
            inputs: vec![Input {
                box_id: make_box_id(0x44),
                spending_proof: SpendingProof::new(vec![0x99, 0x88], ContextExtension::empty())
                    .unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![make_candidate(3_141_592, 250, vec![])],
        };

        let mut w = VlqWriter::new();
        // Pre-fill with junk that would corrupt the bytes if not cleared.
        w.put_bytes(&[0xFF; 64]);
        w.put_u32(987_654);

        let id_with = transaction_id_with(&mut w, &tx).unwrap();
        let id_direct = transaction_id(&tx).unwrap();
        assert_eq!(id_with, id_direct);

        // After the call, w.as_slice() must equal bytes_to_sign(tx) exactly
        // (the writer is left holding the hashed bytes).
        let bts = bytes_to_sign(&tx).unwrap();
        assert_eq!(w.as_slice(), bts.as_slice());

        // And re-using the same writer (which now contains stale bytes) must
        // still produce the correct digest, proving clear() is called every time.
        let id_again = transaction_id_with(&mut w, &tx).unwrap();
        assert_eq!(id_again, id_direct);
    }

    // ----- error paths -----

    #[test]
    fn read_transaction_huge_token_count_does_not_oom() {
        // Hostile tx: input_count = 0, di_count = 0, token_count = i32::MAX,
        // and no token bytes. Before the cap, `Vec::with_capacity(token_count)`
        // reserved ~68 GiB and aborted the process; the `min(remaining / 32)`
        // bound reserves only what the payload can hold, so this returns a
        // clean `UnexpectedEnd` instead of crashing. (The test reaching its
        // assertion at all is the regression guard.)
        let mut bytes = vec![0u8, 0u8]; // VLQ input_count = 0, di_count = 0
        bytes.extend_from_slice(&ergo_primitives::vlq::encode_vlq(i32::MAX as u64));
        let mut r = VlqReader::new(&bytes);
        assert!(matches!(
            read_transaction(&mut r),
            Err(ReadError::UnexpectedEnd { .. })
        ));
    }

    #[test]
    fn check_transaction_collection_bounds_inputs_above_u16_rejected() {
        let err = check_transaction_collection_bounds(u16::MAX as usize + 1, 0, 0, 0).unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(msg.contains("inputs"), "msg should name field, got: {msg}");
        assert!(msg.contains("65536"), "msg should name count, got: {msg}");
    }

    #[test]
    fn check_transaction_collection_bounds_data_inputs_above_u16_rejected() {
        let err = check_transaction_collection_bounds(0, u16::MAX as usize + 1, 0, 0).unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("data_inputs"),
            "msg should name field, got: {msg}"
        );
    }

    #[test]
    fn check_transaction_collection_bounds_outputs_above_u16_rejected() {
        let err = check_transaction_collection_bounds(0, 0, u16::MAX as usize + 1, 0).unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(msg.contains("outputs"), "msg should name field, got: {msg}");
    }

    #[test]
    fn check_transaction_collection_bounds_token_table_above_i32_rejected() {
        // 64-bit only: skip on 32-bit targets where `i32::MAX as usize +
        // 1` overflows usize.
        if usize::BITS < 64 {
            return;
        }
        let err = check_transaction_collection_bounds(0, 0, 0, i32::MAX as usize + 1).unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("token-table"),
            "msg should name field, got: {msg}"
        );
    }

    #[test]
    fn check_transaction_collection_bounds_at_caps_accepted() {
        // u16::MAX inputs + u16::MAX data inputs + u16::MAX outputs + i32::MAX token table
        // is the boundary that must round-trip through the read side
        // (`get_u16` / `get_u32_exact`).
        if usize::BITS < 64 {
            return;
        }
        check_transaction_collection_bounds(
            u16::MAX as usize,
            u16::MAX as usize,
            u16::MAX as usize,
            i32::MAX as usize,
        )
        .expect("bounds at caps must succeed");
    }

    // ----- oracle parity -----

    /// Parse a real mainnet transaction from raw wire bytes, compute tx_id
    /// and box_id for each output, and compare against explorer-known values.
    /// This tests the EXACT code path used during block sync:
    ///   raw bytes → read_transaction → transaction_id → ErgoBox { candidate, tx_id, idx } → box_id
    #[test]
    fn box_ids_from_parsed_transaction_block_700000() {
        use crate::ergo_box::{serialize_ergo_box, ErgoBox};
        use ergo_primitives::digest::blake2b256;

        // Transaction cba71e32... from block 700000.
        // Has 2 inputs, 1 data input, 3 outputs (one with token+registers).
        let tx_hex = "02ff30511557bab24769274ad8b31be7bfb791608c695b70950957ed655f630def38dcf11cccad217fd3120f2abcc0b706e2916630a1f266bfba18a47f849f1dcce0b4c00ab4a52f5d888d42014ac9b98349f210b2ad827ebcbf0028b111fcc692be6be99cd29bde11fd10435df815163ba8b3227c834af042686238ce430d0d57d5ae3b908655ddc769a1ea95ee76d97adce01a2333c56905af3d13ca2262f3d2fbbd8757cfe40687e1ff59569b1e5d8b55a1b00001c57f8a9938e16575413ae6fa00eb45686e8e4158a6dd2b20904e078f4b675743018c27dd9d8a35aac1e3167d58858c0a8b4059b277da790552e37eba22df9b903503c0843d100504000400050004000e20011d3364de07e5a26f0c4eef0852cddb387039a921b7154ef3cab22c6eda887fd803d601b2a5730000d602e4c6a70407d603b2db6501fe730100ea02d1ededededed93e4c672010407720293e4c67201050ec5720391e4c672010605730293c27201c2a793db63087201db6308a7938cb2db63087203730300017304cd7202dedc2a01000103070331b99a9fcc7bceb0a238446cdab944402dd4b2e79f9dcab898ec3b46aea285c80e20c57f8a9938e16575413ae6fa00eb45686e8e4158a6dd2b20904e078f4b675743058ec7faaa02e091431005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304dedc2a0000a0a489ce210008cd0333920f80ca39477cb57ccdff9847ed6cbd46cf2c7237b6b085979622349910e9dedc2a0000";
        let tx_bytes = hex::decode(tx_hex).unwrap();

        // Parse the transaction
        let mut r = VlqReader::new(&tx_bytes);
        let tx = read_transaction(&mut r).unwrap();
        assert!(
            r.is_empty(),
            "leftover bytes after parsing: {}",
            r.remaining()
        );

        // Compute tx_id
        let tx_id = transaction_id(&tx).unwrap();
        let expected_tx_id = "cba71e328904bfc47b02b4b573fa654ad53db2df19e24a76edbbf3c929336c06";
        assert_eq!(
            hex::encode(tx_id.as_bytes()),
            expected_tx_id,
            "tx_id mismatch"
        );

        // Expected output box IDs from explorer
        let expected_box_ids = [
            "aa61e97c00978fab96e905d76d13c1e8b1f95812837bb56f90adf1ffcbd63d4f",
            "e2fd3036020836e40d1fb22095fd632eb4a9386c3063db7aa51bb64817a11414",
            "e6eca48a4ac4608fc6ac6abd4668561416e2533348b4e2927058e0b8b8141477",
        ];

        assert_eq!(tx.output_candidates.len(), expected_box_ids.len());

        for (idx, (candidate, expected_hex)) in tx
            .output_candidates
            .iter()
            .zip(expected_box_ids.iter())
            .enumerate()
        {
            let ergo_box = ErgoBox {
                candidate: candidate.clone(),
                transaction_id: tx_id,
                index: idx as u16,
            };
            let box_bytes = serialize_ergo_box(&ergo_box).unwrap();
            let computed_id = blake2b256(&box_bytes);
            assert_eq!(
                hex::encode(computed_id.as_bytes()),
                *expected_hex,
                "output {idx}: box_id mismatch\n  serialized box bytes: {}",
                hex::encode(&box_bytes),
            );
        }
    }
}
