//! [`UnsignedInput`] — spending input before proof computation — and its
//! wire codec.

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;

use super::context_extension::{read_context_extension, write_context_extension, ContextExtension};

/// Spending input before the proof has been computed: box id plus the
/// context extension that the eventual signer will commit to.
#[derive(Debug, Clone, PartialEq)]
pub struct UnsignedInput {
    /// Identifier of the box being spent.
    pub box_id: Digest32,
    /// Caller-supplied context variables for script evaluation.
    pub extension: ContextExtension,
}

/// Serialize an [`UnsignedInput`] as 32-byte `box_id` followed by the
/// context extension wire form.
pub fn write_unsigned_input(w: &mut VlqWriter, ui: &UnsignedInput) -> Result<(), WriteError> {
    w.put_bytes(ui.box_id.as_bytes());
    write_context_extension(w, &ui.extension)?;
    Ok(())
}

/// Decode the wire form produced by [`write_unsigned_input`].
pub fn read_unsigned_input(r: &mut VlqReader) -> Result<UnsignedInput, ReadError> {
    let box_id = Digest32::from_bytes(r.get_array::<32>()?);
    let extension = read_context_extension(r)?;
    Ok(UnsignedInput { box_id, extension })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::SigmaValue;

    // ----- helpers -----

    fn make_box_id(fill: u8) -> Digest32 {
        Digest32::from_bytes([fill; 32])
    }

    fn roundtrip_result<T: PartialEq + std::fmt::Debug>(
        write_fn: fn(&mut VlqWriter, &T) -> Result<(), WriteError>,
        read_fn: fn(&mut VlqReader) -> Result<T, ReadError>,
        val: &T,
    ) {
        let mut w = VlqWriter::new();
        write_fn(&mut w, val).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_fn(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after roundtrip");
        assert_eq!(&decoded, val);
    }

    // ----- round-trips -----

    #[test]
    fn unsigned_input_roundtrip() {
        let mut ext = ContextExtension::empty();
        ext.values.insert(1, (SigmaType::SInt, SigmaValue::Int(-7)));

        let ui = UnsignedInput {
            box_id: make_box_id(0x01),
            extension: ext,
        };
        roundtrip_result(write_unsigned_input, read_unsigned_input, &ui);
    }
}
