//! Serialization of `ErgoSyncInfo` V1 and V2 messages.
//!
//! V2 carries full serialized headers; V1 carries only header IDs.
//! We always *send* V2, but must be able to *parse* either version from peers.
//!
//! **V2 wire format (ErgoSyncInfo):**
//! ```text
//! UShort(0):       VLQ (signals "not V1")
//! Byte(-1):        1 byte signed (0xFF, the V2 marker)
//! UByte(count):    1 byte (number of headers, max 50)
//! for each header:
//!   UShort(size):  VLQ (header bytes length)
//!   bytes:         size bytes (serialized header)
//! ```
//!
//! **V1 wire format (legacy):**
//! ```text
//! UShort(count):   VLQ (number of header IDs, max 1000)
//! for each ID:
//!   bytes:         32 bytes (ModifierId)
//! ```
//!
//! **Parsing discrimination:** read VLQ UShort for count.
//! - If count > 0 => V1 (read count x 32-byte IDs).
//! - If count == 0 => read next byte: if 0xFF => V2 (read UByte count, then headers).

use ergo_types::header::Header;
use ergo_types::modifier_id::ModifierId;

use crate::header_ser::{parse_header, serialize_header};
use crate::vlq::{get_ushort, put_ushort, CodecError};

// ---------------------------------------------------------------------------
// V1 (legacy — parse-only)
// ---------------------------------------------------------------------------

/// SyncInfo V1: a list of up to 1000 header IDs (no full headers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoSyncInfoV1 {
    /// The most recent header IDs, oldest first.
    pub last_header_ids: Vec<ModifierId>,
}

// ---------------------------------------------------------------------------
// V2 (current)
// ---------------------------------------------------------------------------

/// SyncInfo V2: a list of up to 50 full serialized headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoSyncInfoV2 {
    /// The most recent headers, oldest first.
    pub last_headers: Vec<Header>,
}

impl ErgoSyncInfoV2 {
    /// Serialize to the V2 wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        // UShort(0) as VLQ — signals "not V1"
        put_ushort(&mut buf, 0);

        // V2 marker: -1 as signed byte = 0xFF
        buf.push(0xFF);

        // UByte count (1 byte, max 50)
        buf.push(self.last_headers.len() as u8);

        // Each header: UShort(size) as VLQ + serialized bytes
        for header in &self.last_headers {
            let header_bytes = serialize_header(header);
            put_ushort(&mut buf, header_bytes.len() as u16);
            buf.extend_from_slice(&header_bytes);
        }

        buf
    }
}

// ---------------------------------------------------------------------------
// Enum wrapper
// ---------------------------------------------------------------------------

/// Either a V1 or V2 sync info message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErgoSyncInfo {
    V1(ErgoSyncInfoV1),
    V2(ErgoSyncInfoV2),
}

impl ErgoSyncInfo {
    /// Parse a sync info message from raw bytes, discriminating V1 vs V2.
    pub fn parse(data: &[u8]) -> Result<Self, CodecError> {
        let reader = &mut &data[..];

        // First: VLQ UShort — in V1 this is the ID count; in V2 it is 0.
        let count = get_ushort(reader)?;

        if count > 0 {
            // V1: `count` header IDs, each 32 bytes.
            let count = count as usize;
            let mut ids = Vec::with_capacity(count);
            for _ in 0..count {
                if reader.len() < 32 {
                    return Err(CodecError::UnexpectedEof);
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&reader[..32]);
                *reader = &reader[32..];
                ids.push(ModifierId(arr));
            }
            Ok(ErgoSyncInfo::V1(ErgoSyncInfoV1 {
                last_header_ids: ids,
            }))
        } else {
            // count == 0 => read next byte for V2 marker.
            if reader.is_empty() {
                return Err(CodecError::UnexpectedEof);
            }
            let marker = reader[0];
            *reader = &reader[1..];

            if marker != 0xFF {
                return Err(CodecError::VlqOverflow); // unexpected marker
            }

            // UByte: header count (1 byte)
            if reader.is_empty() {
                return Err(CodecError::UnexpectedEof);
            }
            let header_count = reader[0] as usize;
            *reader = &reader[1..];

            let mut headers = Vec::with_capacity(header_count);
            for _ in 0..header_count {
                // UShort size as VLQ
                let size = get_ushort(reader)? as usize;
                if reader.len() < size {
                    return Err(CodecError::UnexpectedEof);
                }
                let header_bytes = &reader[..size];
                let header = parse_header(header_bytes)?;
                *reader = &reader[size..];
                headers.push(header);
            }

            Ok(ErgoSyncInfo::V2(ErgoSyncInfoV2 {
                last_headers: headers,
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::header::Header;
    use ergo_types::modifier_id::ModifierId;

    #[test]
    fn sync_info_v2_empty_roundtrip() {
        let si = ErgoSyncInfoV2 {
            last_headers: vec![],
        };
        let bytes = si.serialize();
        let parsed = ErgoSyncInfo::parse(&bytes).unwrap();
        match parsed {
            ErgoSyncInfo::V2(v2) => assert!(v2.last_headers.is_empty()),
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn sync_info_v2_with_headers_roundtrip() {
        let h = Header::default_for_test();
        let si = ErgoSyncInfoV2 {
            last_headers: vec![h.clone()],
        };
        let bytes = si.serialize();
        let parsed = ErgoSyncInfo::parse(&bytes).unwrap();
        match parsed {
            ErgoSyncInfo::V2(v2) => {
                assert_eq!(v2.last_headers.len(), 1);
                assert_eq!(v2.last_headers[0].version, h.version);
            }
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn sync_info_v2_marker_bytes() {
        let si = ErgoSyncInfoV2 {
            last_headers: vec![],
        };
        let bytes = si.serialize();
        // First byte: VLQ(0) = 0x00
        // Second byte: -1 as i8 = 0xFF
        // Third byte: count = 0
        assert_eq!(bytes[0], 0x00); // UShort(0) as VLQ
        assert_eq!(bytes[1], 0xFF); // V2 marker (-1 as byte)
        assert_eq!(bytes[2], 0x00); // UByte count = 0
    }

    #[test]
    fn sync_info_v1_parse() {
        // Manually construct a V1 message: VLQ(2) + 2 x 32-byte IDs
        let mut data = Vec::new();
        put_ushort(&mut data, 2); // count = 2
        data.extend_from_slice(&[0xAA; 32]); // id 1
        data.extend_from_slice(&[0xBB; 32]); // id 2

        let parsed = ErgoSyncInfo::parse(&data).unwrap();
        match parsed {
            ErgoSyncInfo::V1(v1) => {
                assert_eq!(v1.last_header_ids.len(), 2);
                assert_eq!(v1.last_header_ids[0], ModifierId([0xAA; 32]));
                assert_eq!(v1.last_header_ids[1], ModifierId([0xBB; 32]));
            }
            _ => panic!("expected V1"),
        }
    }

    #[test]
    fn sync_info_v2_multiple_headers_roundtrip() {
        let h1 = Header::default_for_test();
        let mut h2 = Header::default_for_test();
        h2.height = 42;
        h2.timestamp = 1_700_000_000_000;

        let si = ErgoSyncInfoV2 {
            last_headers: vec![h1.clone(), h2.clone()],
        };
        let bytes = si.serialize();
        let parsed = ErgoSyncInfo::parse(&bytes).unwrap();
        match parsed {
            ErgoSyncInfo::V2(v2) => {
                assert_eq!(v2.last_headers.len(), 2);
                assert_eq!(v2.last_headers[0], h1);
                assert_eq!(v2.last_headers[1], h2);
            }
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn sync_info_v2_full_header_equality() {
        let h = Header::default_for_test();
        let si = ErgoSyncInfoV2 {
            last_headers: vec![h.clone()],
        };
        let bytes = si.serialize();
        let parsed = ErgoSyncInfo::parse(&bytes).unwrap();
        match parsed {
            ErgoSyncInfo::V2(v2) => {
                assert_eq!(v2.last_headers[0], h);
            }
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn sync_info_parse_truncated_returns_error() {
        // Just a single byte — not enough for even the VLQ count
        let result = ErgoSyncInfo::parse(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn sync_info_v1_truncated_ids_returns_error() {
        let mut data = Vec::new();
        put_ushort(&mut data, 1); // claims 1 ID
        data.extend_from_slice(&[0xAA; 16]); // only 16 bytes, need 32
        let result = ErgoSyncInfo::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn v2_round_trip_ten_headers() {
        let headers: Vec<_> = (0..10)
            .map(|i| {
                let mut h = Header::default_for_test();
                h.height = i;
                h
            })
            .collect();
        let v2 = ErgoSyncInfoV2 {
            last_headers: headers,
        };
        let bytes = v2.serialize();
        let parsed = ErgoSyncInfo::parse(&bytes).unwrap();
        match parsed {
            ErgoSyncInfo::V2(v) => {
                assert_eq!(v.last_headers.len(), 10);
                for (i, h) in v.last_headers.iter().enumerate() {
                    assert_eq!(h.height, i as u32);
                }
            }
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn v2_round_trip_fifty_headers() {
        let headers: Vec<_> = (0..50)
            .map(|i| {
                let mut h = Header::default_for_test();
                h.height = i;
                h
            })
            .collect();
        let v2 = ErgoSyncInfoV2 {
            last_headers: headers,
        };
        let bytes = v2.serialize();
        let parsed = ErgoSyncInfo::parse(&bytes).unwrap();
        match parsed {
            ErgoSyncInfo::V2(v) => {
                assert_eq!(v.last_headers.len(), 50);
                for (i, h) in v.last_headers.iter().enumerate() {
                    assert_eq!(h.height, i as u32);
                }
            }
            _ => panic!("expected V2"),
        }
    }
}
