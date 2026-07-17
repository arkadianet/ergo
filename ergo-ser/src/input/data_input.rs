//! [`DataInput`] — read-only box reference — and its wire codec.

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

/// Read-only reference to an existing UTXO box, used for in-script lookups.
/// Carries no spending proof and no context extension — purely a pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataInput {
    /// Identifier of the referenced box.
    pub box_id: Digest32,
}

/// Serialize a [`DataInput`] as 32 raw bytes.
pub fn write_data_input(w: &mut VlqWriter, di: &DataInput) {
    w.put_bytes(di.box_id.as_bytes());
}

/// Decode a [`DataInput`] from the next 32 bytes of `r`.
pub fn read_data_input(r: &mut VlqReader) -> Result<DataInput, ReadError> {
    Ok(DataInput {
        box_id: Digest32::from_bytes(r.get_array::<32>()?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn make_box_id(fill: u8) -> Digest32 {
        Digest32::from_bytes([fill; 32])
    }

    fn roundtrip<T: PartialEq + std::fmt::Debug>(
        write_fn: fn(&mut VlqWriter, &T),
        read_fn: fn(&mut VlqReader) -> Result<T, ReadError>,
        val: &T,
    ) {
        let mut w = VlqWriter::new();
        write_fn(&mut w, val);
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_fn(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after roundtrip");
        assert_eq!(&decoded, val);
    }

    // ----- round-trips -----

    #[test]
    fn data_input_roundtrip() {
        let di = DataInput {
            box_id: make_box_id(0xAB),
        };
        roundtrip(write_data_input, read_data_input, &di);
    }
}
