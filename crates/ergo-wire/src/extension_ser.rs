//! Binary serialization of Ergo block extensions, matching `ExtensionSerializer.scala`.

use ergo_types::extension::{Extension, FIELD_VALUE_MAX_SIZE};
use ergo_types::modifier_id::ModifierId;

use crate::vlq::{get_ushort, put_ushort, CodecError};

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Serialize an `Extension` into its wire format.
///
/// Wire layout:
/// ```text
/// [32 bytes: header_id]
/// [VLQ UShort: field_count]
/// for each field:
///   [2 bytes: key]
///   [1 byte UByte: value_length (0-64)]
///   [value_length bytes: value]
/// ```
pub fn serialize_extension(ext: &Extension) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    // header_id: 32 bytes
    buf.extend_from_slice(&ext.header_id.0);

    // field_count: VLQ UShort
    put_ushort(&mut buf, ext.fields.len() as u16);

    // each field: key(2) + value_length(1) + value(variable)
    for (key, value) in &ext.fields {
        buf.extend_from_slice(key);
        buf.push(value.len() as u8);
        buf.extend_from_slice(value);
    }

    buf
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse an `Extension` from its serialized wire bytes.
pub fn parse_extension(data: &[u8]) -> Result<Extension, CodecError> {
    let reader = &mut &data[..];

    // header_id: 32 bytes
    let header_id = ModifierId(read_array::<32>(reader)?);

    // field_count: VLQ UShort
    let field_count = get_ushort(reader)? as usize;

    let mut fields = Vec::with_capacity(field_count);
    for _ in 0..field_count {
        // key: 2 raw bytes
        let key = read_array::<2>(reader)?;

        // value_length: 1 byte UByte
        let value_len = read_byte(reader)? as usize;
        if value_len > FIELD_VALUE_MAX_SIZE {
            return Err(CodecError::InvalidData(format!(
                "extension field value length {value_len} exceeds max {FIELD_VALUE_MAX_SIZE}"
            )));
        }

        // value: value_len bytes
        let value = read_bytes(reader, value_len)?;

        fields.push((key, value));
    }

    Ok(Extension { header_id, fields })
}

// ---------------------------------------------------------------------------
// Low-level reader helpers
// ---------------------------------------------------------------------------

fn read_byte(reader: &mut &[u8]) -> Result<u8, CodecError> {
    if reader.is_empty() {
        return Err(CodecError::UnexpectedEof);
    }
    let b = reader[0];
    *reader = &reader[1..];
    Ok(b)
}

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_roundtrip_empty() {
        let ext = Extension {
            header_id: ModifierId([0xAA; 32]),
            fields: Vec::new(),
        };
        let bytes = serialize_extension(&ext);
        let parsed = parse_extension(&bytes).unwrap();
        assert_eq!(parsed, ext);
    }

    #[test]
    fn extension_roundtrip_with_fields() {
        let ext = Extension {
            header_id: ModifierId([0xBB; 32]),
            fields: vec![
                ([0x00, 0x01], vec![0x10, 0x20]),
                ([0x01, 0x00], vec![0xFF; 32]),
                ([0x02, 0x05], vec![0x42]),
            ],
        };
        let bytes = serialize_extension(&ext);
        let parsed = parse_extension(&bytes).unwrap();
        assert_eq!(parsed, ext);
    }

    #[test]
    fn extension_roundtrip_max_value() {
        let ext = Extension {
            header_id: ModifierId([0xCC; 32]),
            fields: vec![([0x00, 0x00], vec![0xAB; FIELD_VALUE_MAX_SIZE])],
        };
        let bytes = serialize_extension(&ext);
        let parsed = parse_extension(&bytes).unwrap();
        assert_eq!(parsed, ext);
        // Verify the value is exactly 64 bytes
        assert_eq!(parsed.fields[0].1.len(), 64);
    }

    #[test]
    fn extension_parse_truncated_returns_error() {
        let ext = Extension {
            header_id: ModifierId([0xDD; 32]),
            fields: vec![([0x00, 0x01], vec![0x10, 0x20, 0x30])],
        };
        let bytes = serialize_extension(&ext);
        // Truncate: only keep header_id + part of field count
        let result = parse_extension(&bytes[..33]);
        assert!(result.is_err());
    }

    #[test]
    fn extension_format_header_id_first() {
        let header_id = ModifierId([0xEE; 32]);
        let ext = Extension {
            header_id,
            fields: vec![([0x01, 0x02], vec![0x03])],
        };
        let bytes = serialize_extension(&ext);
        // First 32 bytes must be the header_id
        assert_eq!(&bytes[..32], &[0xEE; 32]);
    }
}
