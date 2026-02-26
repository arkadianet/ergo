//! Sigma byte utilities for reading sigma-rust encoded constants.
//!
//! Sigma-rust uses fixed 2-byte big-endian u16 for collection counts (NOT VLQ),
//! and its own type-code system for serialized constants. This module provides
//! helpers to read those values and skip over serialized constants without fully
//! decoding them.

use crate::vlq::{get_long, CodecError};

// ---------------------------------------------------------------------------
// Fixed 2-byte big-endian u16 (sigma-rust count encoding)
// ---------------------------------------------------------------------------

/// Write a fixed 2-byte big-endian u16.
pub fn put_sigma_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_be_bytes());
}

/// Read a fixed 2-byte big-endian u16.
pub fn get_sigma_u16(reader: &mut &[u8]) -> Result<u16, CodecError> {
    if reader.len() < 2 {
        return Err(CodecError::UnexpectedEof);
    }
    let value = u16::from_be_bytes([reader[0], reader[1]]);
    *reader = &reader[2..];
    Ok(value)
}

// ---------------------------------------------------------------------------
// Constant skipper
// ---------------------------------------------------------------------------

/// Sigma type codes used in serialized constants.
const TYPE_BOOLEAN: u8 = 1;
const TYPE_BYTE: u8 = 2;
const TYPE_SHORT: u8 = 3;
const TYPE_INT: u8 = 4;
const TYPE_LONG: u8 = 5;
const TYPE_BIG_INT: u8 = 6;
const TYPE_GROUP_ELEMENT: u8 = 7;
const TYPE_SIGMA_PROP: u8 = 8;
const TYPE_COLL_BOOLEAN: u8 = 12;
const TYPE_COLL_BYTE: u8 = 13;
const TYPE_COLL_SHORT: u8 = 14;
const TYPE_COLL_INT: u8 = 15;
const TYPE_COLL_LONG: u8 = 16;

/// Skip over a single serialized sigma constant (type code + value), advancing
/// the reader past it. This does not decode the value; it only moves the cursor
/// forward by the appropriate number of bytes.
pub fn skip_sigma_constant(reader: &mut &[u8]) -> Result<(), CodecError> {
    if reader.is_empty() {
        return Err(CodecError::UnexpectedEof);
    }
    let type_code = reader[0];
    *reader = &reader[1..];

    match type_code {
        TYPE_BOOLEAN | TYPE_BYTE => {
            skip_bytes(reader, 1)?;
        }
        TYPE_SHORT | TYPE_INT | TYPE_LONG => {
            // ZigZag + VLQ encoded; get_long consumes the right number of bytes
            let _ = get_long(reader)?;
        }
        TYPE_BIG_INT => {
            let len = get_sigma_u16(reader)? as usize;
            skip_bytes(reader, len)?;
        }
        TYPE_GROUP_ELEMENT => {
            skip_bytes(reader, 33)?;
        }
        TYPE_SIGMA_PROP => {
            return Err(CodecError::InvalidData(
                "SigmaProp constants are not supported".into(),
            ));
        }
        TYPE_COLL_BOOLEAN | TYPE_COLL_BYTE => {
            let len = get_sigma_u16(reader)? as usize;
            skip_bytes(reader, len)?;
        }
        TYPE_COLL_SHORT | TYPE_COLL_INT | TYPE_COLL_LONG => {
            let count = get_sigma_u16(reader)? as usize;
            for _ in 0..count {
                let _ = get_long(reader)?;
            }
        }
        _ => {
            return Err(CodecError::InvalidData(format!(
                "unsupported sigma type code {type_code}"
            )));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Advance the reader by `n` bytes, returning `UnexpectedEof` if insufficient.
fn skip_bytes(reader: &mut &[u8], n: usize) -> Result<(), CodecError> {
    if reader.len() < n {
        return Err(CodecError::UnexpectedEof);
    }
    *reader = &reader[n..];
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::vlq::put_long;

    use super::*;

    // -- put/get sigma_u16 --------------------------------------------------

    #[test]
    fn sigma_u16_roundtrip_zero() {
        let mut buf = Vec::new();
        put_sigma_u16(&mut buf, 0);
        let value = get_sigma_u16(&mut buf.as_slice()).unwrap();
        assert_eq!(value, 0);
    }

    #[test]
    fn sigma_u16_roundtrip_max() {
        let mut buf = Vec::new();
        put_sigma_u16(&mut buf, 65535);
        let value = get_sigma_u16(&mut buf.as_slice()).unwrap();
        assert_eq!(value, 65535);
    }

    #[test]
    fn sigma_u16_roundtrip_256() {
        let mut buf = Vec::new();
        put_sigma_u16(&mut buf, 256);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf, vec![0x01, 0x00]); // 256 in big-endian
        let value = get_sigma_u16(&mut buf.as_slice()).unwrap();
        assert_eq!(value, 256);
    }

    #[test]
    fn sigma_u16_eof() {
        let buf: &[u8] = &[];
        let result = get_sigma_u16(&mut &buf[..]);
        assert!(matches!(result, Err(CodecError::UnexpectedEof)));
    }

    // -- skip_sigma_constant ------------------------------------------------

    #[test]
    fn skip_boolean() {
        // type 1 (Boolean) + 1 byte value
        let buf: Vec<u8> = vec![TYPE_BOOLEAN, 0x01];
        let mut reader = buf.as_slice();
        skip_sigma_constant(&mut reader).unwrap();
        assert!(reader.is_empty());
    }

    #[test]
    fn skip_int() {
        // type 4 (Int) + zigzag VLQ for value 42
        let mut buf = vec![TYPE_INT];
        put_long(&mut buf, 42);
        let original_len = buf.len();
        let mut reader = buf.as_slice();
        skip_sigma_constant(&mut reader).unwrap();
        assert_eq!(reader.len(), 0, "cursor should advance by {original_len} bytes");
    }

    #[test]
    fn skip_long() {
        // type 5 (Long) + zigzag VLQ for value -1000
        let mut buf = vec![TYPE_LONG];
        put_long(&mut buf, -1000);
        let mut reader = buf.as_slice();
        skip_sigma_constant(&mut reader).unwrap();
        assert!(reader.is_empty());
    }

    #[test]
    fn skip_group_element() {
        // type 7 (GroupElement) + 33 bytes compressed EC point
        let mut buf = vec![TYPE_GROUP_ELEMENT];
        buf.extend_from_slice(&[0x02; 33]);
        let mut reader = buf.as_slice();
        skip_sigma_constant(&mut reader).unwrap();
        assert!(reader.is_empty());
    }

    #[test]
    fn skip_coll_byte() {
        // type 13 (Coll[Byte]) + u16 length 5 + 5 bytes
        let mut buf = vec![TYPE_COLL_BYTE];
        put_sigma_u16(&mut buf, 5);
        buf.extend_from_slice(&[0xAA; 5]);
        let mut reader = buf.as_slice();
        skip_sigma_constant(&mut reader).unwrap();
        assert!(reader.is_empty());
    }

    #[test]
    fn skip_unknown_type() {
        let buf: Vec<u8> = vec![200];
        let mut reader = buf.as_slice();
        let result = skip_sigma_constant(&mut reader);
        assert!(matches!(result, Err(CodecError::InvalidData(_))));
    }

    #[test]
    fn skip_empty_reader() {
        let buf: &[u8] = &[];
        let result = skip_sigma_constant(&mut &buf[..]);
        assert!(matches!(result, Err(CodecError::UnexpectedEof)));
    }

    #[test]
    fn skip_multiple_constants() {
        // Constant 1: Boolean (type 1) + 1-byte value
        // Constant 2: Coll[Byte] (type 13) + u16 len 3 + 3 bytes
        // Constant 3: Long (type 5) + zigzag VLQ value
        let mut buf = Vec::new();

        // Boolean constant
        buf.push(TYPE_BOOLEAN);
        buf.push(0x00);

        // Coll[Byte] constant
        buf.push(TYPE_COLL_BYTE);
        put_sigma_u16(&mut buf, 3);
        buf.extend_from_slice(&[0x01, 0x02, 0x03]);

        // Long constant
        buf.push(TYPE_LONG);
        put_long(&mut buf, 999_999);

        let total_len = buf.len();
        let mut reader = buf.as_slice();

        skip_sigma_constant(&mut reader).unwrap();
        assert_eq!(reader.len(), total_len - 2); // Boolean: 1 type + 1 value

        skip_sigma_constant(&mut reader).unwrap();
        // Coll[Byte]: 1 type + 2 u16 + 3 data = 6 bytes
        assert_eq!(reader.len(), total_len - 2 - 6);

        skip_sigma_constant(&mut reader).unwrap();
        assert!(reader.is_empty());
    }
}
