use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;

/// One key-value entry inside a block's [`Extension`].
///
/// Keys are 2 bytes — by convention the high byte selects a namespace
/// (`0x00` system parameters, `0x01` NIPoPoW interlinks, `0x02`
/// validation rules) and the low byte indexes within that namespace.
/// Values are opaque to this layer; consensus interpretation lives in
/// `ergo-validation` (parameter and validation-rules parsing) and in
/// the NIPoPoW prover (interlinks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionField {
    /// Two-byte namespace + index key.
    pub key: [u8; 2],
    /// Opaque payload for the field.
    pub value: Vec<u8>,
}

/// Block extension section: an unordered key-value bag attached to a
/// block header by [`ModifierId`]. Used for miner voting, parameter
/// updates, NiPoPoW interlinks, and other meta-data that is committed to
/// in the header's `extension_root` Merkle digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// Identifier of the header this extension hangs off.
    pub header_id: ModifierId,
    /// All key-value entries, in their on-wire order.
    pub fields: Vec<ExtensionField>,
}

/// Serialize an extension as 32-byte header id, then a VLQ-`u16` count,
/// then for each field the 2-byte key, a 1-byte value length, and
/// the raw value bytes.
///
/// **Note on the value-length byte:** Scala's
/// `ExtensionSerializer.scala:17` writes this as
/// `w.putUByte(value.length)` (single unsigned byte, max 255). VLQ-u32
/// would emit byte-identical output for value lengths under 128 (VLQ
/// 1-byte aliases raw u8 in that range), so a writer using VLQ here
/// passes mainnet round-trip but desyncs from Scala for any value
/// length in 128..=255. The wire is `put_u8`.
pub fn write_extension(w: &mut VlqWriter, ext: &Extension) -> Result<(), WriteError> {
    if ext.fields.len() > u16::MAX as usize {
        return Err(WriteError::InvalidData(format!(
            "extension field count too large for Scala wire format: {} (max 65535)",
            ext.fields.len()
        )));
    }
    w.put_bytes(ext.header_id.as_bytes());
    w.put_u16(ext.fields.len() as u16);
    for field in &ext.fields {
        // Scala caps extension field value length at 255 (single
        // unsigned byte); a longer payload would silently wrap on
        // `as u8`. Surface as WriteError so REST/JSON callers
        // (`decode_extension`) can return DESERIALIZE instead of
        // panicking the process on attacker-controlled JSON.
        if field.value.len() > u8::MAX as usize {
            return Err(WriteError::InvalidData(format!(
                "extension field value too long for Scala wire format: {} bytes (max 255)",
                field.value.len()
            )));
        }
        w.put_bytes(&field.key);
        w.put_u8(field.value.len() as u8);
        w.put_bytes(&field.value);
    }
    Ok(())
}

/// Decode the wire form produced by [`write_extension`].
pub fn read_extension(r: &mut VlqReader) -> Result<Extension, ReadError> {
    let header_id = ModifierId::from_bytes(r.get_array::<32>()?);
    let count = r.get_u16()? as usize;
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let key = r.get_array::<2>()?;
        // 1-byte length per Scala ExtensionSerializer.scala:29
        // (`r.getUByte()`, max 255).
        let val_len = r.get_u8()? as usize;
        let value = r.get_bytes(val_len)?.to_vec();
        fields.push(ExtensionField { key, value });
    }
    Ok(Extension { header_id, fields })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- round-trips -----

    #[test]
    fn extension_roundtrip_empty_fields() {
        let ext = Extension {
            header_id: ModifierId::from_bytes([0x33; 32]),
            fields: vec![],
        };
        let mut w = VlqWriter::new();
        write_extension(&mut w, &ext).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_extension(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert_eq!(decoded, ext);
    }

    #[test]
    fn extension_roundtrip_multiple_fields() {
        // Max value length is 255 bytes — Scala's `putUByte(length)`
        // / `getUByte()` is a single unsigned byte. Using 256 here would
        // pass round-trip against this writer but diverge from Scala,
        // so the test pins the real wire-format max.
        let value_max = (0u8..=254).collect::<Vec<u8>>();
        assert_eq!(value_max.len(), 255);
        let ext = Extension {
            header_id: ModifierId::from_bytes([0x44; 32]),
            fields: vec![
                ExtensionField {
                    key: [0x00, 0x01],
                    value: vec![0xDE, 0xAD, 0xBE, 0xEF],
                },
                ExtensionField {
                    key: [0x01, 0x00],
                    value: vec![],
                },
                ExtensionField {
                    key: [0xFF, 0xFE],
                    value: value_max,
                },
            ],
        };
        let mut w = VlqWriter::new();
        write_extension(&mut w, &ext).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_extension(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert_eq!(decoded, ext);
    }

    #[test]
    fn extension_field_value_at_255_byte_max_roundtrips() {
        // Boundary test: exactly the Scala max (255 bytes) encodes as
        // 1-byte length prefix `0xFF` followed by 255 payload bytes.
        // This is the largest payload that round-trips through both
        // sides; 256+ would silently truncate on Scala write
        // (`putUByte(256) == 0`).
        let ext = Extension {
            header_id: ModifierId::from_bytes([0xAA; 32]),
            fields: vec![ExtensionField {
                key: [0x07, 0xC4],
                value: vec![0x42u8; 255],
            }],
        };
        let mut w = VlqWriter::new();
        write_extension(&mut w, &ext).expect("at-cap value must serialize");
        let bytes = w.result();
        // Sanity: locate the length byte. Layout for 1 field:
        // 32 id + VLQ-u16(1) [= 1 byte] + 2 key + 1 length + payload.
        let len_byte_pos = 32 + 1 + 2;
        assert_eq!(
            bytes[len_byte_pos], 0xFF,
            "max-length-byte expectation broken"
        );
        let mut r = VlqReader::new(&bytes);
        assert_eq!(read_extension(&mut r).unwrap(), ext);
    }

    // ----- error paths -----

    #[test]
    fn extension_field_value_above_255_returns_invalid_data() {
        // Programmer constructing an Extension with a 256+ byte
        // field value violates Scala's `putUByte(value.length)`
        // single-byte length limit. `decode_extension` reaches this
        // writer with attacker-controllable JSON, so the writer
        // returns `WriteError::InvalidData` rather than panicking.
        let ext = Extension {
            header_id: ModifierId::from_bytes([0xCC; 32]),
            fields: vec![ExtensionField {
                key: [0x07, 0xC4],
                value: vec![0u8; 256],
            }],
        };
        let mut w = VlqWriter::new();
        let err = write_extension(&mut w, &ext).unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("256"),
            "message should name the value length, got: {msg}"
        );
        assert!(
            msg.contains("max 255"),
            "message should name the cap, got: {msg}"
        );
    }

    #[test]
    fn extension_field_count_above_u16_returns_invalid_data() {
        // Field count is written as VLQ-`u16`. A 65536-field extension
        // would silently wrap on `as u16` to 0 while the writer still
        // emitted every field, producing malformed bytes that the read
        // side rejects with no traceable cause. Surface the bound at
        // the construction site.
        //
        // Building 65536 ExtensionField values is fast (each is 2 + ~1
        // bytes); skip on 32-bit targets where conversion is awkward.
        if usize::BITS < 64 {
            return;
        }
        let fields: Vec<ExtensionField> = (0..=u16::MAX as u32)
            .map(|i| ExtensionField {
                key: (i as u16).to_be_bytes(),
                value: vec![],
            })
            .collect();
        assert_eq!(fields.len(), u16::MAX as usize + 1);
        let ext = Extension {
            header_id: ModifierId::from_bytes([0xDD; 32]),
            fields,
        };
        let mut w = VlqWriter::new();
        let err = write_extension(&mut w, &ext).unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("65536"),
            "message should name count, got: {msg}"
        );
        assert!(msg.contains("65535"), "message should name cap, got: {msg}");
    }

    // ----- properties -----

    proptest::proptest! {
        /// Round-trip property for `Extension`: any field list within
        /// the two wire-format caps (≤65535 fields, each value ≤255
        /// bytes) survives `read_extension ∘ write_extension`. Bounds
        /// match the same caps the writer enforces in
        /// `extension_too_many_fields_returns_invalid_data` and
        /// `extension_value_too_long_returns_invalid_data`; this
        /// property covers everything inside both caps.
        ///
        /// Field count cap of 256 chosen for proptest tractability
        /// (the Scala-wire-format cap of 65535 is exercised by the
        /// regression tests above). Per-value length cap is the full
        /// 0..=255 the wire format allows.
        #[test]
        fn proptest_extension_roundtrips_within_wire_caps(
            header_id_bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 32..=32),
            fields in proptest::collection::vec(
                (
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 2..=2),
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=255),
                ),
                0..=256,
            ),
        ) {
            let header_id_arr: [u8; 32] = header_id_bytes.try_into().unwrap();
            let fields: Vec<ExtensionField> = fields
                .into_iter()
                .map(|(k, v)| ExtensionField {
                    key: k.try_into().unwrap(),
                    value: v,
                })
                .collect();
            let ext = Extension {
                header_id: ModifierId::from_bytes(header_id_arr),
                fields,
            };
            let mut w = VlqWriter::new();
            write_extension(&mut w, &ext).unwrap();
            let data = w.result();
            let mut r = VlqReader::new(&data);
            let decoded = read_extension(&mut r).unwrap();
            proptest::prop_assert_eq!(decoded, ext);
        }
    }
}
