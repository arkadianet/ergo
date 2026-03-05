//! Standalone box serialization for AVL+ tree storage, and box ID computation.
//!
//! Ergo stores boxes in the AVL+ tree using a "standalone" format where token
//! IDs are written as full 32-byte values (unlike the transaction wire format
//! which uses indexed references into a distinct-token-ID array).
//!
//! The canonical box ID is:
//!   `blake2b256(sigma_serialize(ErgoBox { candidate, tx_id, index }))`
//! which is computed via sigma-rust's `ErgoBox::from_box_candidate`.

use crate::sigma_byte::skip_sigma_constant;
use crate::vlq::{get_long, get_uint, put_long, put_uint, CodecError};
use ergo_types::transaction::{BoxId, ErgoBoxCandidate, TxId};

/// Compute the canonical Ergo box ID for an output at the given index.
///
/// Ergo box ID = `blake2b256(sigma_serialize(ErgoBox { candidate, tx_id, index }))`.
/// The serialized box includes: box-candidate bytes (value, ergoTree, height,
/// tokens, registers) followed by the raw 32-byte tx_id and VLQ-encoded index.
///
/// This uses sigma-rust's `ErgoBox::from_box_candidate` to ensure byte-for-byte
/// compatibility with the Scala reference implementation.
///
/// # Panics
///
/// Panics if the candidate contains an unparseable ErgoTree or invalid field
/// values (e.g., value out of range), which should not occur for well-formed
/// transactions received from the network.
pub fn compute_box_id(candidate: &ErgoBoxCandidate, tx_id: &TxId, output_index: u16) -> BoxId {
    use ergo_lib::ergo_chain_types::Digest32 as SigmaDigest32;
    use ergo_lib::ergotree_ir::chain::ergo_box::box_value::BoxValue as SigmaBoxValue;
    use ergo_lib::ergotree_ir::chain::ergo_box::{
        ErgoBox as SigmaErgoBox, ErgoBoxCandidate as SigmaErgoBoxCandidate,
        NonMandatoryRegisterId as SigmaNonMandatoryRegisterId,
        NonMandatoryRegisters as SigmaNonMandatoryRegisters, RegisterValue as SigmaRegisterValue,
    };
    use ergo_lib::ergotree_ir::chain::token::{Token as SigmaToken, TokenAmount, TokenId};
    use ergo_lib::ergotree_ir::chain::tx_id::TxId as SigmaTxId;
    use ergo_lib::ergotree_ir::ergo_tree::ErgoTree as SigmaErgoTree;
    use ergo_lib::ergotree_ir::serialization::SigmaSerializable;

    // Convert value
    let value =
        SigmaBoxValue::try_from(candidate.value).expect("box value out of range in compute_box_id");

    // Convert ErgoTree
    let ergo_tree = SigmaErgoTree::sigma_parse_bytes(&candidate.ergo_tree_bytes)
        .expect("invalid ErgoTree bytes in compute_box_id");

    // Convert tokens
    let tokens_vec: Vec<SigmaToken> = candidate
        .tokens
        .iter()
        .map(|(token_id, amount)| {
            let tid: TokenId = SigmaDigest32::from(token_id.0).into();
            let ta = TokenAmount::try_from(*amount)
                .expect("token amount out of range in compute_box_id");
            SigmaToken {
                token_id: tid,
                amount: ta,
            }
        })
        .collect();
    let tokens = if tokens_vec.is_empty() {
        None
    } else {
        use ergo_lib::ergotree_ir::chain::ergo_box::BoxTokens;
        Some(BoxTokens::from_vec(tokens_vec).expect("token list too long in compute_box_id"))
    };

    // Convert registers
    let additional_registers = if candidate.additional_registers.is_empty() {
        SigmaNonMandatoryRegisters::empty()
    } else {
        let mut map = std::collections::HashMap::new();
        for (idx, bytes) in &candidate.additional_registers {
            let reg_id = match *idx {
                4 => SigmaNonMandatoryRegisterId::R4,
                5 => SigmaNonMandatoryRegisterId::R5,
                6 => SigmaNonMandatoryRegisterId::R6,
                7 => SigmaNonMandatoryRegisterId::R7,
                8 => SigmaNonMandatoryRegisterId::R8,
                9 => SigmaNonMandatoryRegisterId::R9,
                other => panic!("invalid register index {other} in compute_box_id"),
            };
            let reg_value = SigmaRegisterValue::sigma_parse_bytes(bytes);
            map.insert(reg_id, reg_value);
        }
        SigmaNonMandatoryRegisters::try_from(map)
            .expect("register conversion failed in compute_box_id")
    };

    // Convert tx_id
    let sigma_tx_id: SigmaTxId = SigmaDigest32::from(tx_id.0).into();

    // Build sigma ErgoBoxCandidate
    let sigma_candidate = SigmaErgoBoxCandidate {
        value,
        ergo_tree,
        tokens,
        additional_registers,
        creation_height: candidate.creation_height,
    };

    // Compute box ID via sigma-rust (blake2b256(sigma_serialize(box)))
    let sigma_box = SigmaErgoBox::from_box_candidate(&sigma_candidate, sigma_tx_id, output_index)
        .expect("ErgoBox construction failed in compute_box_id");

    let id_digest: SigmaDigest32 = sigma_box.box_id().into();
    let id_bytes: [u8; 32] = id_digest.into();
    BoxId(id_bytes)
}

/// Serialize an `ErgoBoxCandidate` in standalone format (full token IDs).
///
/// Layout:
/// ```text
/// value:           zigzag+VLQ i64
/// ergo_tree_len:   VLQ u32
/// ergo_tree:       raw bytes
/// creation_height: VLQ u32
/// token_count:     VLQ u32
///   for each token:
///     token_id:    32 raw bytes
///     amount:      zigzag+VLQ i64
/// register_bitmap: 1 byte (count in upper nibble, 0x00 if none)
///   for each register:
///     raw sigma constant bytes
/// ```
pub fn serialize_ergo_box(candidate: &ErgoBoxCandidate) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    put_long(&mut buf, candidate.value as i64);
    put_uint(&mut buf, candidate.ergo_tree_bytes.len() as u32);
    buf.extend_from_slice(&candidate.ergo_tree_bytes);
    put_uint(&mut buf, candidate.creation_height);

    put_uint(&mut buf, candidate.tokens.len() as u32);
    for (token_id, amount) in &candidate.tokens {
        buf.extend_from_slice(&token_id.0);
        put_long(&mut buf, *amount as i64);
    }

    if candidate.additional_registers.is_empty() {
        buf.push(0x00);
    } else {
        buf.push((candidate.additional_registers.len() as u8) << 4);
        for (_reg_id, reg_bytes) in &candidate.additional_registers {
            buf.extend_from_slice(reg_bytes);
        }
    }

    buf
}

/// Parse an `ErgoBoxCandidate` from standalone format (full token IDs).
pub fn parse_ergo_box(data: &[u8]) -> Result<ErgoBoxCandidate, CodecError> {
    let reader = &mut &data[..];

    let value = get_long(reader)? as u64;

    let tree_len = get_uint(reader)? as usize;
    if reader.len() < tree_len {
        return Err(CodecError::UnexpectedEof);
    }
    let ergo_tree_bytes = reader[..tree_len].to_vec();
    *reader = &reader[tree_len..];

    let creation_height = get_uint(reader)?;

    let token_count = get_uint(reader)? as usize;
    let mut tokens = Vec::with_capacity(token_count);
    for _ in 0..token_count {
        if reader.len() < 32 {
            return Err(CodecError::UnexpectedEof);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&reader[..32]);
        *reader = &reader[32..];
        let amount = get_long(reader)? as u64;
        tokens.push((BoxId(id), amount));
    }

    let bitmap = if reader.is_empty() {
        0u8
    } else {
        let b = reader[0];
        *reader = &reader[1..];
        b
    };
    let reg_count = (bitmap >> 4) as usize;

    let mut additional_registers = Vec::with_capacity(reg_count);
    for i in 0..reg_count {
        let reg_id = 4 + i as u8;
        let start: &[u8] = reader;
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vlq::put_long as vlq_put_long;

    /// Helper: minimal ErgoTree bytes (P2PK-like prefix).
    fn simple_ergo_tree() -> Vec<u8> {
        vec![0x00, 0x08, 0xcd]
    }

    // 1. roundtrip_simple_box — value + ergo_tree + creation_height, no tokens, no registers
    #[test]
    fn roundtrip_simple_box() {
        let candidate = ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: simple_ergo_tree(),
            creation_height: 500_000,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        };

        let bytes = serialize_ergo_box(&candidate);
        let parsed = parse_ergo_box(&bytes).unwrap();
        assert_eq!(parsed, candidate);
    }

    // 2. roundtrip_box_with_tokens — box with 2 tokens (full 32-byte IDs)
    #[test]
    fn roundtrip_box_with_tokens() {
        let candidate = ErgoBoxCandidate {
            value: 2_000_000_000,
            ergo_tree_bytes: simple_ergo_tree(),
            creation_height: 600_000,
            tokens: vec![(BoxId([0xAA; 32]), 1_000), (BoxId([0xBB; 32]), 999_999)],
            additional_registers: Vec::new(),
        };

        let bytes = serialize_ergo_box(&candidate);
        let parsed = parse_ergo_box(&bytes).unwrap();
        assert_eq!(parsed, candidate);
    }

    // 3. roundtrip_box_with_registers — box with R4 (Long) and R5 (Boolean)
    #[test]
    fn roundtrip_box_with_registers() {
        // R4: Long constant (type 5 + zigzag VLQ value 42)
        let mut reg_r4 = vec![0x05]; // TYPE_LONG
        vlq_put_long(&mut reg_r4, 42);

        // R5: Boolean constant (type 1 + 1 byte value=true)
        let reg_r5 = vec![0x01, 0x01];

        let candidate = ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: simple_ergo_tree(),
            creation_height: 100_000,
            tokens: Vec::new(),
            additional_registers: vec![(4, reg_r4), (5, reg_r5)],
        };

        let bytes = serialize_ergo_box(&candidate);
        let parsed = parse_ergo_box(&bytes).unwrap();
        assert_eq!(parsed, candidate);
    }

    // 4. roundtrip_box_with_tokens_and_registers — combined
    #[test]
    fn roundtrip_box_with_tokens_and_registers() {
        let mut reg_r4 = vec![0x05]; // TYPE_LONG
        vlq_put_long(&mut reg_r4, -9999);

        let reg_r5 = vec![0x01, 0x00]; // TYPE_BOOLEAN, value=false

        let candidate = ErgoBoxCandidate {
            value: 5_000_000_000,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd, 0x03, 0xfe, 0xdc],
            creation_height: 750_000,
            tokens: vec![
                (BoxId([0x11; 32]), 42),
                (BoxId([0x22; 32]), 100_000_000),
                (BoxId([0x33; 32]), 1),
            ],
            additional_registers: vec![(4, reg_r4), (5, reg_r5)],
        };

        let bytes = serialize_ergo_box(&candidate);
        let parsed = parse_ergo_box(&bytes).unwrap();
        assert_eq!(parsed, candidate);
    }

    // 5. parse_truncated_eof — truncated data -> CodecError::UnexpectedEof
    #[test]
    fn parse_truncated_eof() {
        let candidate = ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: simple_ergo_tree(),
            creation_height: 100_000,
            tokens: vec![(BoxId([0xCC; 32]), 500)],
            additional_registers: Vec::new(),
        };

        let bytes = serialize_ergo_box(&candidate);

        // Truncate in the middle of the token ID (after value + tree + height + token_count)
        // This should be somewhere in the token data, causing EOF
        let truncated = &bytes[..bytes.len() - 10];
        let result = parse_ergo_box(truncated);
        assert!(result.is_err());
        assert!(matches!(result, Err(CodecError::UnexpectedEof)));
    }

    // 6. roundtrip_zero_tokens_empty_registers — edge case: token_count=0, bitmap=0x00
    #[test]
    fn roundtrip_zero_tokens_empty_registers() {
        let candidate = ErgoBoxCandidate {
            value: 10_800, // MIN_BOX_VALUE
            ergo_tree_bytes: vec![0x00],
            creation_height: 0,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        };

        let bytes = serialize_ergo_box(&candidate);
        let parsed = parse_ergo_box(&bytes).unwrap();
        assert_eq!(parsed, candidate);

        // Verify the bitmap byte is 0x00
        // The last byte should be the register bitmap
        assert_eq!(*bytes.last().unwrap(), 0x00);
    }

    // 7. Bonus: verify register bitmap encoding matches expected value
    #[test]
    fn register_bitmap_encoding() {
        let mut reg_r4 = vec![0x05]; // TYPE_LONG
        vlq_put_long(&mut reg_r4, 100);

        let candidate = ErgoBoxCandidate {
            value: 1_000_000,
            ergo_tree_bytes: simple_ergo_tree(),
            creation_height: 1,
            tokens: Vec::new(),
            additional_registers: vec![(4, reg_r4)],
        };

        let bytes = serialize_ergo_box(&candidate);

        // With 1 register, bitmap should be 0x10 (1 << 4)
        // Find bitmap position: after value + tree_len + tree + creation_height + token_count
        // The bitmap comes right after token_count (which is 0), so we parse up to it
        let parsed = parse_ergo_box(&bytes).unwrap();
        assert_eq!(parsed.additional_registers.len(), 1);
        assert_eq!(parsed.additional_registers[0].0, 4); // R4
    }

    // 8. Bonus: large value roundtrip
    #[test]
    fn roundtrip_large_value() {
        let candidate = ErgoBoxCandidate {
            value: u64::MAX / 2, // large but fits in i64
            ergo_tree_bytes: simple_ergo_tree(),
            creation_height: u32::MAX,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        };

        let bytes = serialize_ergo_box(&candidate);
        let parsed = parse_ergo_box(&bytes).unwrap();
        assert_eq!(parsed, candidate);
    }

    // 9. Genesis block transaction output 0 — protocol correctness test vector.
    //
    //    Block 1, tx 4c6282be413c6e300a530618b37790be5f286ded758accc2aebd41554a1be308,
    //    output index 0.
    //    Expected box ID (from Scala reference / Ergo Explorer API):
    //      71bc9534d4a4fe8ff67698a5d0f29782836970635de8418da39fee1cd964fcbe
    //
    //    This test verifies that `compute_box_id` matches the Scala implementation.
    //    The old formula blake2b256(tx_id ++ vlq(index)) produced the WRONG result:
    //      fcc4588acaf1c29625f7fbabe4fd7081bac915fd8a1af9f213f3defa8bb1c10a
    #[test]
    fn compute_box_id_genesis_tx_vector() {
        use ergo_types::transaction::TxId;

        // ergoTree bytes for the genesis emission contract
        // Source: https://api.ergoplatform.com/api/v1/boxes/71bc9534d4a4fe8ff67698a5d0f29782836970635de8418da39fee1cd964fcbe
        let ergo_tree_bytes = hex::decode(
            "101004020e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a7017300730110010204020404040004c0fd4f05808c82f5f6030580b8c9e5ae040580f882ad16040204c0944004c0f407040004000580f882ad16d19683030191a38cc7a7019683020193c2b2a57300007473017302830108cdeeac93a38cc7b2a573030001978302019683040193b1a5730493c2a7c2b2a573050093958fa3730673079973089c73097e9a730a9d99a3730b730c0599c1a7c1b2a5730d00938cc7b2a5730e0001a390c1a7730f"
        ).unwrap();

        let candidate = ErgoBoxCandidate {
            value: 93_409_065_000_000_000u64,
            ergo_tree_bytes,
            creation_height: 1,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        };

        let tx_id_hex = "4c6282be413c6e300a530618b37790be5f286ded758accc2aebd41554a1be308";
        let mut tx_id_bytes = [0u8; 32];
        hex::decode_to_slice(tx_id_hex, &mut tx_id_bytes).unwrap();
        let tx_id = TxId(tx_id_bytes);

        let box_id = compute_box_id(&candidate, &tx_id, 0);

        let expected_hex = "71bc9534d4a4fe8ff67698a5d0f29782836970635de8418da39fee1cd964fcbe";
        let expected: [u8; 32] = hex::decode(expected_hex).unwrap().try_into().unwrap();

        assert_eq!(
            box_id.0,
            expected,
            "compute_box_id genesis vector mismatch: got {}, want {}",
            hex::encode(box_id.0),
            expected_hex
        );
    }
}
