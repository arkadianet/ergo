//! Standalone box serialization for AVL+ tree storage.
//!
//! Ergo stores boxes in the AVL+ tree using a "standalone" format where token
//! IDs are written as full 32-byte values (unlike the transaction wire format
//! which uses indexed references into a distinct-token-ID array).

use crate::sigma_byte::skip_sigma_constant;
use crate::vlq::{get_long, get_uint, put_long, put_uint, CodecError};
use ergo_types::transaction::{BoxId, ErgoBoxCandidate};

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
}
