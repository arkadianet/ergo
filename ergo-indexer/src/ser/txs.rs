//! `IndexedErgoTransaction` wire format:
//!
//! ```text
//! idLen: u8 (always = 32)
//! id: 32B raw
//! index: i32
//! height: i32
//! size: i32
//! globalIndex: i64
//! inputNums.len: u16
//! inputNums: len × i64
//! outputNums.len: u16
//! outputNums: len × i64
//! dataInputs.len: u16
//! dataInputs: len × 32B raw boxId
//! ```
//!
//! Source: `IndexedErgoTransaction.scala:72-85`. `numConfirmations` is
//! transient (not persisted).

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use ergo_indexer_types::IndexedErgoTransaction;

const TX_ID_LEN: u8 = 32;

/// Serialize an indexed-tx record from individual field references rather than
/// a constructed `IndexedErgoTransaction`. This is the apply-path entry point:
/// it lets the indexer feed `&scratch.input_nums`, `&scratch.output_nums`, and
/// `&scratch.data_inputs` directly, avoiding the per-tx `Vec` ownership transfer
/// that the struct-shaped `write_indexed_tx` would require for scratch reuse.
///
/// Wire format is byte-identical to `write_indexed_tx`. See module docs for the
/// canonical layout. `write_indexed_tx` delegates to this; new callers should
/// prefer `write_indexed_tx_parts` if they already hold the fields by reference.
#[allow(clippy::too_many_arguments)]
pub fn write_indexed_tx_parts(
    w: &mut VlqWriter,
    id: &Digest32,
    index_in_block: i32,
    height: i32,
    size: i32,
    global_index: i64,
    input_nums: &[i64],
    output_nums: &[i64],
    data_inputs: &[Digest32],
) -> Result<(), ReadError> {
    w.put_u8(TX_ID_LEN);
    w.put_bytes(id.as_bytes());
    w.put_i32(index_in_block);
    w.put_i32(height);
    w.put_i32(size);
    w.put_i64(global_index);

    write_i64_array(w, input_nums)?;
    write_i64_array(w, output_nums)?;

    let di_len: u16 = data_inputs.len().try_into().map_err(|_| {
        ReadError::InvalidData(format!(
            "indexer: dataInputs.len {} exceeds u16",
            data_inputs.len()
        ))
    })?;
    w.put_u16(di_len);
    for di in data_inputs {
        w.put_bytes(di.as_bytes());
    }
    Ok(())
}

pub fn write_indexed_tx(w: &mut VlqWriter, tx: &IndexedErgoTransaction) -> Result<(), ReadError> {
    write_indexed_tx_parts(
        w,
        &tx.id,
        tx.index_in_block,
        tx.height,
        tx.size,
        tx.global_index,
        &tx.input_nums,
        &tx.output_nums,
        &tx.data_inputs,
    )
}

pub fn read_indexed_tx(r: &mut VlqReader) -> Result<IndexedErgoTransaction, ReadError> {
    let id_len = r.get_u8()?;
    if id_len != TX_ID_LEN {
        return Err(ReadError::InvalidData(format!(
            "indexer: TxId length must be 32, got {id_len}"
        )));
    }
    let id_bytes = r.get_bytes(32)?;
    let mut id_arr = [0u8; 32];
    id_arr.copy_from_slice(id_bytes);
    let id = Digest32::from_bytes(id_arr);

    let index_in_block = r.get_i32()?;
    let height = r.get_i32()?;
    let size = r.get_i32()?;
    let global_index = r.get_i64()?;

    let input_nums = read_i64_array(r)?;
    let output_nums = read_i64_array(r)?;

    let di_len = r.get_u16()? as usize;
    let mut data_inputs = Vec::with_capacity(di_len);
    for _ in 0..di_len {
        let bytes = r.get_bytes(32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        data_inputs.push(Digest32::from_bytes(arr));
    }

    Ok(IndexedErgoTransaction {
        id,
        index_in_block,
        height,
        size,
        global_index,
        input_nums,
        output_nums,
        data_inputs,
    })
}

fn write_i64_array(w: &mut VlqWriter, vs: &[i64]) -> Result<(), ReadError> {
    let len: u16 = vs.len().try_into().map_err(|_| {
        ReadError::InvalidData(format!("indexer: i64 array len {} exceeds u16", vs.len()))
    })?;
    w.put_u16(len);
    for v in vs {
        w.put_i64(*v);
    }
    Ok(())
}

fn read_i64_array(r: &mut VlqReader) -> Result<Vec<i64>, ReadError> {
    let len = r.get_u16()? as usize;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(r.get_i64()?);
    }
    Ok(out)
}

pub fn serialize_indexed_tx(tx: &IndexedErgoTransaction) -> Result<Vec<u8>, ReadError> {
    let mut w = VlqWriter::new();
    write_indexed_tx(&mut w, tx)?;
    Ok(w.result())
}

pub fn deserialize_indexed_tx(bytes: &[u8]) -> Result<IndexedErgoTransaction, ReadError> {
    let mut r = VlqReader::new(bytes);
    let tx = read_indexed_tx(&mut r)?;
    if !r.is_empty() {
        return Err(ReadError::InvalidData(format!(
            "{} leftover bytes after IndexedErgoTransaction",
            r.remaining()
        )));
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> Digest32 {
        Digest32::from_bytes([seed; 32])
    }

    // ----- happy path -----

    #[test]
    fn empty_tx_roundtrip() {
        let tx = IndexedErgoTransaction {
            id: id(0x11),
            index_in_block: 0,
            height: 1,
            size: 100,
            global_index: 0,
            input_nums: vec![],
            output_nums: vec![],
            data_inputs: vec![],
        };
        let bytes = serialize_indexed_tx(&tx).unwrap();
        let decoded = deserialize_indexed_tx(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn tx_with_inputs_outputs_data_inputs_roundtrip() {
        let tx = IndexedErgoTransaction {
            id: id(0xAB),
            index_in_block: 7,
            height: 700_000,
            size: 1234,
            global_index: 50_000,
            input_nums: vec![100, 101, 102],
            output_nums: vec![200, 201],
            data_inputs: vec![id(0x01), id(0x02)],
        };
        let bytes = serialize_indexed_tx(&tx).unwrap();
        let decoded = deserialize_indexed_tx(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn id_len_byte_is_first() {
        let tx = IndexedErgoTransaction {
            id: id(0xFF),
            index_in_block: 0,
            height: 0,
            size: 0,
            global_index: 0,
            input_nums: vec![],
            output_nums: vec![],
            data_inputs: vec![],
        };
        let bytes = serialize_indexed_tx(&tx).unwrap();
        assert_eq!(bytes[0], 32, "first byte must be id_len = 32");
        // Bytes 1..33 are the raw id
        assert_eq!(&bytes[1..33], &[0xFF; 32]);
    }

    #[test]
    fn rejects_wrong_id_len() {
        let mut w = VlqWriter::new();
        w.put_u8(31); // wrong
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let err = read_indexed_tx(&mut r).expect_err("must reject");
        assert!(matches!(err, ReadError::InvalidData(_)));
    }

    #[test]
    fn negative_input_nums_roundtrip() {
        // VLQ-zigzag handles negatives. Inputs can be conceptually
        // signed if the segment-side spent flag ever bleeds through;
        // pin that the encoder/decoder are symmetric around zero.
        let tx = IndexedErgoTransaction {
            id: id(0x33),
            index_in_block: 0,
            height: 1,
            size: 50,
            global_index: 1,
            input_nums: vec![-100, -1, 0, 1, 100],
            output_nums: vec![],
            data_inputs: vec![],
        };
        let bytes = serialize_indexed_tx(&tx).unwrap();
        let decoded = deserialize_indexed_tx(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn write_indexed_tx_parts_matches_write_indexed_tx() {
        // The apply path will switch from `write_indexed_tx(&IndexedErgoTransaction)`
        // to `write_indexed_tx_parts(refs...)` to avoid allocating the struct's
        // owned `Vec<i64>` / `Vec<BoxId>` fields per tx. This must produce
        // byte-identical wire output for every tx shape, since the bytes hit
        // the INDEXED_TX redb table and feed downstream readers.
        let cases: Vec<IndexedErgoTransaction> = vec![
            // Empty tx
            IndexedErgoTransaction {
                id: id(0x00),
                index_in_block: 0,
                height: 1,
                size: 32,
                global_index: 0,
                input_nums: vec![],
                output_nums: vec![],
                data_inputs: vec![],
            },
            // Mainnet-shaped tx with all fields populated
            IndexedErgoTransaction {
                id: id(0xAB),
                index_in_block: 7,
                height: 700_000,
                size: 1234,
                global_index: 50_000,
                input_nums: vec![100, 101, 102],
                output_nums: vec![200, 201],
                data_inputs: vec![id(0x01), id(0x02)],
            },
            // Negative globals (sentinel-style values)
            IndexedErgoTransaction {
                id: id(0x55),
                index_in_block: i32::MAX,
                height: -1,
                size: i32::MIN,
                global_index: i64::MIN,
                input_nums: vec![i64::MIN, -1, 0, 1, i64::MAX],
                output_nums: vec![-7],
                data_inputs: vec![],
            },
            // Many data inputs (exercises the u16-len boundary path)
            IndexedErgoTransaction {
                id: id(0xCC),
                index_in_block: 3,
                height: 100,
                size: 500,
                global_index: 12345,
                input_nums: vec![],
                output_nums: vec![1, 2, 3, 4, 5],
                data_inputs: (0..50u8).map(id).collect(),
            },
        ];

        for (i, tx) in cases.iter().enumerate() {
            // Reference: struct-shaped writer.
            let mut w_struct = VlqWriter::new();
            write_indexed_tx(&mut w_struct, tx).unwrap();
            let struct_bytes = w_struct.result();

            // Candidate: parts-shaped writer fed the same data via refs.
            let mut w_parts = VlqWriter::new();
            write_indexed_tx_parts(
                &mut w_parts,
                &tx.id,
                tx.index_in_block,
                tx.height,
                tx.size,
                tx.global_index,
                &tx.input_nums,
                &tx.output_nums,
                &tx.data_inputs,
            )
            .unwrap();
            let parts_bytes = w_parts.result();

            assert_eq!(
                struct_bytes, parts_bytes,
                "case {i}: write_indexed_tx_parts must produce byte-identical output to write_indexed_tx",
            );

            // Round-trip the parts bytes through read_indexed_tx — must decode
            // back to the original IndexedErgoTransaction value.
            let decoded = deserialize_indexed_tx(&parts_bytes).unwrap();
            assert_eq!(&decoded, tx, "case {i}: parts bytes must round-trip");
        }
    }

    #[test]
    fn write_indexed_tx_parts_after_clear_byte_identical() {
        // Apply-path pattern: clear writer, write tx N, copy bytes to redb,
        // clear writer, write tx N+1, copy. Pin that this sequence produces
        // the same bytes as two fresh writers.
        let tx_a = IndexedErgoTransaction {
            id: id(0xA1),
            index_in_block: 0,
            height: 100,
            size: 64,
            global_index: 10,
            input_nums: vec![1, 2],
            output_nums: vec![3],
            data_inputs: vec![id(0xD0)],
        };
        let tx_b = IndexedErgoTransaction {
            id: id(0xB2),
            index_in_block: 1,
            height: 100,
            size: 32,
            global_index: 11,
            input_nums: vec![],
            output_nums: vec![4, 5, 6],
            data_inputs: vec![],
        };

        let mut shared = VlqWriter::new();
        let mut emit = |tx: &IndexedErgoTransaction| -> Vec<u8> {
            shared.clear();
            write_indexed_tx_parts(
                &mut shared,
                &tx.id,
                tx.index_in_block,
                tx.height,
                tx.size,
                tx.global_index,
                &tx.input_nums,
                &tx.output_nums,
                &tx.data_inputs,
            )
            .unwrap();
            shared.as_slice().to_vec()
        };
        let shared_a = emit(&tx_a);
        let shared_b = emit(&tx_b);

        let fresh_a = serialize_indexed_tx(&tx_a).unwrap();
        let fresh_b = serialize_indexed_tx(&tx_b).unwrap();

        assert_eq!(shared_a, fresh_a);
        assert_eq!(shared_b, fresh_b);
        // tx_b is shorter than tx_a — confirms no residual tail.
        assert!(shared_b.len() < shared_a.len());
    }
}
