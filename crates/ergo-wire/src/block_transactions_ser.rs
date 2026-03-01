//! Binary serialization of Ergo block transactions, matching `BlockTransactionsSerializer.scala`.
//!
//! **Wire format**: Transactions are written inline WITHOUT length prefixes,
//! matching Scala's `ErgoTransactionSerializer.serialize(tx, w)` directly
//! into the shared output stream.

use ergo_types::block_transactions::{BlockTransactions, MAX_TRANSACTIONS_IN_BLOCK};
use ergo_types::modifier_id::ModifierId;

use crate::transaction_ser::parse_transaction_from_reader;
use crate::vlq::{get_uint, put_uint, CodecError};

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Serialize `BlockTransactions` into its wire format.
///
/// Wire layout (matches Scala's `BlockTransactionsSerializer`):
/// ```text
/// [32 bytes: header_id]
/// if block_version > 1:
///   [VLQ UInt: MAX_TRANSACTIONS_IN_BLOCK + block_version]   <- version sentinel
/// [VLQ UInt: tx_count]
/// for each tx:
///   [inline tx bytes — NO length prefix]
/// ```
pub fn serialize_block_transactions(bt: &BlockTransactions) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    // header_id: 32 bytes
    buf.extend_from_slice(&bt.header_id.0);

    // version sentinel: only for block_version > 1
    if bt.block_version > 1 {
        put_uint(
            &mut buf,
            MAX_TRANSACTIONS_IN_BLOCK + bt.block_version as u32,
        );
    }

    // tx_count: VLQ UInt
    put_uint(&mut buf, bt.tx_bytes.len() as u32);

    // each transaction: inline bytes, NO length prefix (matches Scala)
    for tx in &bt.tx_bytes {
        buf.extend_from_slice(tx);
    }

    buf
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse `BlockTransactions` from its serialized wire bytes.
///
/// Transactions are parsed inline from the shared reader (no length prefix),
/// matching Scala's `ErgoTransactionSerializer.parse(r)` called in a loop.
pub fn parse_block_transactions(data: &[u8]) -> Result<BlockTransactions, CodecError> {
    let reader = &mut &data[..];

    // header_id: 32 bytes
    let header_id = ModifierId(read_array::<32>(reader)?);

    // Read the first VLQ UInt: either a version sentinel or the tx_count itself.
    let first_value = get_uint(reader)?;

    let (block_version, tx_count) = if first_value > MAX_TRANSACTIONS_IN_BLOCK {
        // It is a version sentinel: version = value - MAX_TRANSACTIONS_IN_BLOCK
        let version = (first_value - MAX_TRANSACTIONS_IN_BLOCK) as u8;
        let count = get_uint(reader)? as usize;
        (version, count)
    } else {
        // No sentinel: block_version == 1, and this value is the tx_count
        (1u8, first_value as usize)
    };

    // Parse each transaction inline from the shared reader.
    // We capture raw bytes by measuring how far the reader advances.
    let mut tx_bytes = Vec::with_capacity(tx_count);
    for _ in 0..tx_count {
        let before: &[u8] = reader;
        // Parse the transaction, advancing reader past it
        let _tx = parse_transaction_from_reader(reader)?;
        let consumed = before.len() - reader.len();
        tx_bytes.push(before[..consumed].to_vec());
    }

    Ok(BlockTransactions {
        header_id,
        block_version,
        tx_bytes,
    })
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction_ser::serialize_transaction;
    use ergo_types::transaction::*;

    /// Build a minimal valid serialized transaction (1 input, 0 data inputs,
    /// 0 tokens, 1 output, no registers, no proofs).
    fn make_serialized_tx(box_id_fill: u8, value: u64, creation_height: u32) -> Vec<u8> {
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([box_id_fill; 32]),
                proof_bytes: Vec::new(),
                extension_bytes: vec![0x00], // empty extension
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
                creation_height,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0; 32]),
        };
        serialize_transaction(&tx)
    }

    #[test]
    fn block_transactions_roundtrip_v1() {
        let tx1 = make_serialized_tx(0x11, 1_000_000_000, 100_000);
        let tx2 = make_serialized_tx(0x22, 500_000_000, 200_000);
        let bt = BlockTransactions {
            header_id: ModifierId([0xAA; 32]),
            block_version: 1,
            tx_bytes: vec![tx1, tx2],
        };
        let bytes = serialize_block_transactions(&bt);
        let parsed = parse_block_transactions(&bytes).unwrap();
        assert_eq!(parsed, bt);
    }

    #[test]
    fn block_transactions_roundtrip_v2() {
        let tx1 = make_serialized_tx(0x33, 2_000_000_000, 300_000);
        let bt = BlockTransactions {
            header_id: ModifierId([0xBB; 32]),
            block_version: 2,
            tx_bytes: vec![tx1],
        };
        let bytes = serialize_block_transactions(&bt);
        let parsed = parse_block_transactions(&bytes).unwrap();
        assert_eq!(parsed, bt);
    }

    #[test]
    fn block_transactions_empty() {
        let bt = BlockTransactions {
            header_id: ModifierId([0xCC; 32]),
            block_version: 2,
            tx_bytes: Vec::new(),
        };
        let bytes = serialize_block_transactions(&bt);
        let parsed = parse_block_transactions(&bytes).unwrap();
        assert_eq!(parsed, bt);
        assert!(parsed.tx_bytes.is_empty());
    }

    #[test]
    fn block_transactions_v1_no_sentinel() {
        let tx1 = make_serialized_tx(0x44, 1_000_000, 100);
        let bt = BlockTransactions {
            header_id: ModifierId([0xDD; 32]),
            block_version: 1,
            tx_bytes: vec![tx1],
        };
        let bytes = serialize_block_transactions(&bt);

        // After the 32-byte header_id, the next VLQ UInt should be the tx_count
        // directly (value 1), not a sentinel. A sentinel would be > 10_000_000.
        let mut reader: &[u8] = &bytes[32..];
        let first_vlq = get_uint(&mut reader).unwrap();
        assert!(
            first_vlq <= MAX_TRANSACTIONS_IN_BLOCK,
            "v1 should NOT write a version sentinel"
        );
        assert_eq!(first_vlq, 1, "first VLQ should be the tx_count");
    }

    #[test]
    fn block_transactions_v2_has_sentinel() {
        let tx1 = make_serialized_tx(0x55, 1_000_000, 100);
        let bt = BlockTransactions {
            header_id: ModifierId([0xEE; 32]),
            block_version: 2,
            tx_bytes: vec![tx1],
        };
        let bytes = serialize_block_transactions(&bt);

        // After the 32-byte header_id, the first VLQ should be the sentinel
        // encoding: MAX_TRANSACTIONS_IN_BLOCK + block_version.
        let mut reader: &[u8] = &bytes[32..];
        let first_vlq = get_uint(&mut reader).unwrap();
        assert!(
            first_vlq > MAX_TRANSACTIONS_IN_BLOCK,
            "v2 should write a version sentinel"
        );
        assert_eq!(
            first_vlq,
            MAX_TRANSACTIONS_IN_BLOCK + 2,
            "sentinel should encode version 2"
        );
    }

    #[test]
    fn block_transactions_parse_truncated_returns_error() {
        let tx1 = make_serialized_tx(0x66, 1_000_000, 100);
        let bt = BlockTransactions {
            header_id: ModifierId([0xFF; 32]),
            block_version: 2,
            tx_bytes: vec![tx1],
        };
        let bytes = serialize_block_transactions(&bt);
        // Truncate: only keep header_id + partial sentinel
        let result = parse_block_transactions(&bytes[..20]);
        assert!(result.is_err());
    }

    #[test]
    fn block_transactions_multiple_txs_v2() {
        let txs: Vec<Vec<u8>> = (0..5u8)
            .map(|i| make_serialized_tx(i + 1, (i as u64 + 1) * 1_000_000, 100 + i as u32))
            .collect();
        let bt = BlockTransactions {
            header_id: ModifierId([0xAB; 32]),
            block_version: 4,
            tx_bytes: txs,
        };
        let bytes = serialize_block_transactions(&bt);
        let parsed = parse_block_transactions(&bytes).unwrap();
        assert_eq!(parsed.header_id, bt.header_id);
        assert_eq!(parsed.block_version, 4);
        assert_eq!(parsed.tx_bytes.len(), 5);
        assert_eq!(parsed, bt);
    }
}
