use thiserror::Error;

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("VLQ overflow")]
    VlqOverflow,
    #[error("invalid UTF-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
    #[error("invalid data: {0}")]
    InvalidData(String),
}

// ---------------------------------------------------------------------------
// VLQ unsigned (Scorex putULong / putUInt)
// ---------------------------------------------------------------------------

/// Write a VLQ-encoded unsigned long (Scorex putULong / putUInt format)
pub fn put_ulong(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Read a VLQ-encoded unsigned long
pub fn get_ulong(reader: &mut &[u8]) -> Result<u64, CodecError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if reader.is_empty() {
            return Err(CodecError::UnexpectedEof);
        }
        let byte = reader[0];
        *reader = &reader[1..];
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(CodecError::VlqOverflow);
        }
    }
    Ok(result)
}

/// Scorex putUInt: VLQ-encoded unsigned 32-bit value
pub fn put_uint(buf: &mut Vec<u8>, value: u32) {
    put_ulong(buf, value as u64);
}

/// Scorex getUInt: VLQ-encoded unsigned 32-bit value
pub fn get_uint(reader: &mut &[u8]) -> Result<u32, CodecError> {
    let v = get_ulong(reader)?;
    Ok(v as u32)
}

/// Scorex putUShort: VLQ-encoded unsigned 16-bit value
pub fn put_ushort(buf: &mut Vec<u8>, value: u16) {
    put_ulong(buf, value as u64);
}

/// Scorex getUShort: VLQ-encoded unsigned 16-bit value
pub fn get_ushort(reader: &mut &[u8]) -> Result<u16, CodecError> {
    let v = get_ulong(reader)?;
    Ok(v as u16)
}

// ---------------------------------------------------------------------------
// ZigZag + VLQ signed (Scorex putInt / putLong)
// ---------------------------------------------------------------------------

fn encode_zigzag_i32(v: i32) -> u32 {
    ((v << 1) ^ (v >> 31)) as u32
}

fn decode_zigzag_i32(v: u32) -> i32 {
    ((v >> 1) as i32) ^ (-((v & 1) as i32))
}

fn encode_zigzag_i64(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn decode_zigzag_i64(v: u64) -> i64 {
    ((v >> 1) as i64) ^ (-((v & 1) as i64))
}

/// Scorex putInt: ZigZag + VLQ signed 32-bit
pub fn put_int(buf: &mut Vec<u8>, value: i32) {
    put_ulong(buf, encode_zigzag_i32(value) as u64);
}

/// Scorex getInt: ZigZag + VLQ signed 32-bit
pub fn get_int(reader: &mut &[u8]) -> Result<i32, CodecError> {
    let v = get_ulong(reader)?;
    Ok(decode_zigzag_i32(v as u32))
}

/// Scorex putLong: ZigZag + VLQ signed 64-bit
pub fn put_long(buf: &mut Vec<u8>, value: i64) {
    put_ulong(buf, encode_zigzag_i64(value));
}

/// Scorex getLong: ZigZag + VLQ signed 64-bit
pub fn get_long(reader: &mut &[u8]) -> Result<i64, CodecError> {
    let v = get_ulong(reader)?;
    Ok(decode_zigzag_i64(v))
}

// ---------------------------------------------------------------------------
// String and Option helpers
// ---------------------------------------------------------------------------

/// Write a length-prefixed short string (1-byte length + UTF-8 bytes)
pub fn put_short_string(buf: &mut Vec<u8>, s: &str) {
    buf.push(s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
}

/// Read a length-prefixed short string
pub fn get_short_string(data: &[u8]) -> Result<(String, &[u8]), CodecError> {
    if data.is_empty() {
        return Err(CodecError::UnexpectedEof);
    }
    let len = data[0] as usize;
    let rest = &data[1..];
    if rest.len() < len {
        return Err(CodecError::UnexpectedEof);
    }
    let s = String::from_utf8(rest[..len].to_vec())?;
    Ok((s, &rest[len..]))
}

/// Write an Option: 1 byte (0=None, 1=Some) + serialized value if Some
pub fn put_option<T, F: Fn(&mut Vec<u8>, &T)>(buf: &mut Vec<u8>, opt: &Option<T>, f: F) {
    match opt {
        None => buf.push(0),
        Some(val) => {
            buf.push(1);
            f(buf, val);
        }
    }
}

/// Read an Option
pub fn get_option<T, F: Fn(&mut &[u8]) -> Result<T, CodecError>>(
    reader: &mut &[u8],
    f: F,
) -> Result<Option<T>, CodecError> {
    if reader.is_empty() {
        return Err(CodecError::UnexpectedEof);
    }
    let marker = reader[0];
    *reader = &reader[1..];
    if marker == 0 {
        Ok(None)
    } else {
        Ok(Some(f(reader)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_ulong_zero() {
        let mut buf = Vec::new();
        put_ulong(&mut buf, 0);
        assert_eq!(buf, vec![0]);
    }

    #[test]
    fn encode_ulong_127() {
        let mut buf = Vec::new();
        put_ulong(&mut buf, 127);
        assert_eq!(buf, vec![127]);
    }

    #[test]
    fn encode_ulong_128() {
        let mut buf = Vec::new();
        put_ulong(&mut buf, 128);
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn roundtrip_ulong() {
        for val in [
            0u64,
            1,
            127,
            128,
            255,
            256,
            16383,
            16384,
            1_000_000,
            u64::MAX >> 1,
        ] {
            let mut buf = Vec::new();
            put_ulong(&mut buf, val);
            let decoded = get_ulong(&mut buf.as_slice()).unwrap();
            assert_eq!(decoded, val, "roundtrip failed for {val}");
        }
    }

    #[test]
    fn uint_port_9030() {
        let mut buf = Vec::new();
        put_uint(&mut buf, 9030);
        // VLQ(9030): 9030 = 70*128 + 70, so [0xC6, 0x46]
        assert_eq!(buf, vec![0xC6, 0x46]);
        let decoded = get_uint(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, 9030);
    }

    #[test]
    fn zigzag_int_minus_one() {
        let mut buf = Vec::new();
        put_int(&mut buf, -1);
        // ZigZag(-1) = 1, VLQ(1) = [0x01]
        assert_eq!(buf, vec![0x01]);
        let decoded = get_int(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, -1);
    }

    #[test]
    fn zigzag_int_roundtrip() {
        for val in [0i32, 1, -1, 127, -128, 1000, -1000, i32::MAX, i32::MIN] {
            let mut buf = Vec::new();
            put_int(&mut buf, val);
            let decoded = get_int(&mut buf.as_slice()).unwrap();
            assert_eq!(decoded, val, "roundtrip failed for {val}");
        }
    }

    #[test]
    fn zigzag_long_roundtrip() {
        for val in [0i64, 1, -1, 1000, -1000, i64::MAX, i64::MIN] {
            let mut buf = Vec::new();
            put_long(&mut buf, val);
            let decoded = get_long(&mut buf.as_slice()).unwrap();
            assert_eq!(decoded, val, "roundtrip failed for {val}");
        }
    }

    #[test]
    fn put_short_string_roundtrip() {
        let mut buf = Vec::new();
        put_short_string(&mut buf, "ergoref");
        let (decoded, rest) = get_short_string(&buf).unwrap();
        assert_eq!(decoded, "ergoref");
        assert!(rest.is_empty());
    }

    #[test]
    fn put_option_some() {
        let mut buf = Vec::new();
        put_option(&mut buf, &Some(42u32), |b, v| {
            b.extend_from_slice(&v.to_be_bytes());
        });
        assert_eq!(buf[0], 1);
    }

    #[test]
    fn put_option_none() {
        let mut buf = Vec::new();
        put_option::<u32, _>(&mut buf, &None, |_, _| {});
        assert_eq!(buf, vec![0]);
    }

    #[test]
    fn ushort_roundtrip() {
        for val in [0u16, 1, 127, 128, 255, 256, 16383, 16384, 65535] {
            let mut buf = Vec::new();
            put_ushort(&mut buf, val);
            let decoded = get_ushort(&mut buf.as_slice()).unwrap();
            assert_eq!(decoded, val, "roundtrip failed for {val}");
        }
    }

    #[test]
    fn ushort_zero_single_byte() {
        let mut buf = Vec::new();
        put_ushort(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);
    }
}
