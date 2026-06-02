//! `IndexedErgoBox` wire format:
//!
//! ```text
//! inclusionHeight: i32
//! Opt[spendingTxId: 32B raw]
//! Opt[spendingHeight: i32]
//! Opt[spendingProof: ProverResult bytes]
//! box: ErgoBoxSerializer bytes
//! globalIndex: i64
//! ```
//!
//! Source: `IndexedErgoBox.scala:53-60`.

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{read_ergo_box, write_ergo_box};
use ergo_ser::input::{read_spending_proof, write_spending_proof};

use super::{read_opt, write_opt};
use ergo_indexer_types::IndexedErgoBox;

pub fn write_indexed_box(w: &mut VlqWriter, b: &IndexedErgoBox) -> Result<(), ReadError> {
    w.put_i32(b.inclusion_height);
    write_opt(w, b.spending_tx_id.as_ref(), |w, id| {
        w.put_bytes(id.as_bytes());
        Ok(())
    })?;
    write_opt(w, b.spending_height.as_ref(), |w, h| {
        w.put_i32(*h);
        Ok(())
    })?;
    write_opt(w, b.spending_proof.as_ref(), write_spending_proof)?;
    write_ergo_box(w, &b.box_data)?;
    w.put_i64(b.global_index);
    Ok(())
}

pub fn read_indexed_box(r: &mut VlqReader) -> Result<IndexedErgoBox, ReadError> {
    let inclusion_height = r.get_i32()?;
    let spending_tx_id = read_opt(r, |r| {
        let bytes = r.get_bytes(32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Digest32::from_bytes(arr))
    })?;
    let spending_height = read_opt(r, |r| r.get_i32())?;
    let spending_proof = read_opt(r, read_spending_proof)?;
    let box_data = read_ergo_box(r)?;
    let global_index = r.get_i64()?;
    Ok(IndexedErgoBox {
        inclusion_height,
        spending_tx_id,
        spending_height,
        spending_proof,
        box_data,
        global_index,
    })
}

pub fn serialize_indexed_box(b: &IndexedErgoBox) -> Result<Vec<u8>, ReadError> {
    let mut w = VlqWriter::new();
    write_indexed_box(&mut w, b)?;
    Ok(w.result())
}

pub fn deserialize_indexed_box(bytes: &[u8]) -> Result<IndexedErgoBox, ReadError> {
    let mut r = VlqReader::new(bytes);
    let b = read_indexed_box(&mut r)?;
    if !r.is_empty() {
        return Err(ReadError::InvalidData(format!(
            "{} leftover bytes after IndexedErgoBox",
            r.remaining()
        )));
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::input::{ContextExtension, SpendingProof};
    use ergo_ser::opcode::{Body, Expr};
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;

    fn size_delimited_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            } as Body,
        }
    }

    fn sample_box(value: u64, idx: u16) -> ErgoBox {
        let candidate = ErgoBoxCandidate::new(
            value,
            size_delimited_tree(),
            100,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap();
        ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes([0x42; 32]),
            index: idx,
        }
    }

    #[test]
    fn unspent_box_roundtrip() {
        let b = IndexedErgoBox {
            inclusion_height: 700_000,
            spending_tx_id: None,
            spending_height: None,
            spending_proof: None,
            box_data: sample_box(1_000_000, 0),
            global_index: 12345,
        };
        let bytes = serialize_indexed_box(&b).unwrap();
        let decoded = deserialize_indexed_box(&bytes).unwrap();
        assert_eq!(decoded, b);
    }

    #[test]
    fn spent_box_roundtrip_preserves_proof_and_height() {
        let proof = SpendingProof::new(vec![0xCA, 0xFE], ContextExtension::empty()).unwrap();
        let b = IndexedErgoBox {
            inclusion_height: 1234,
            spending_tx_id: Some(Digest32::from_bytes([0xAA; 32])),
            spending_height: Some(1235),
            spending_proof: Some(proof),
            box_data: sample_box(50_000_000, 3),
            global_index: 999,
        };
        let bytes = serialize_indexed_box(&b).unwrap();
        let decoded = deserialize_indexed_box(&bytes).unwrap();
        assert_eq!(decoded, b);
        assert!(decoded.is_spent());
    }

    #[test]
    fn opt_marker_byte_is_a_single_byte() {
        // Verify the on-wire `Opt[None]` is exactly the byte 0x00 — i.e.
        // we are not VLQ-encoding the marker. This pins the wire layout
        // against accidentally swapping put_u8 → put_i32 etc.
        let b = IndexedErgoBox {
            inclusion_height: 0,
            spending_tx_id: None,
            spending_height: None,
            spending_proof: None,
            box_data: sample_box(1, 0),
            global_index: 0,
        };
        let bytes = serialize_indexed_box(&b).unwrap();
        // Layout: i32(0)=0x00 | u8(0) | u8(0) | u8(0) | <box bytes> | i64(0)=0x00
        // First four bytes pin: i32 zigzag(0) = 0x00, then three Opt markers.
        assert_eq!(&bytes[0..4], &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn invalid_opt_marker_rejected() {
        let mut w = VlqWriter::new();
        w.put_i32(1);
        w.put_u8(2); // bogus
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let err = read_indexed_box(&mut r).expect_err("must reject");
        assert!(matches!(err, ReadError::InvalidData(_)));
    }
}
