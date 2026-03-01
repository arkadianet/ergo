//! Serialization of `InvData` and `ModifiersData` messages.
//!
//! These correspond to `InvSpec` and `ModifiersSpec` in Scorex/Ergo.

use ergo_types::modifier_id::ModifierId;

use crate::vlq::{get_uint, put_uint, CodecError};

// ---------------------------------------------------------------------------
// InvData
// ---------------------------------------------------------------------------

/// Inventory announcement: a modifier type plus a list of modifier IDs.
///
/// Wire format:
/// ```text
/// typeId:  1 byte (signed i8, getByte)
/// count:   VLQ unsigned (putUInt)
/// ids:     count x 32 bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvData {
    /// The modifier type (e.g. 101 = Header, 2 = Transaction).
    pub type_id: i8,
    /// The modifier IDs being announced.
    pub ids: Vec<ModifierId>,
}

impl InvData {
    /// Serialize to the Ergo wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 5 + self.ids.len() * 32);
        buf.push(self.type_id as u8);
        put_uint(&mut buf, self.ids.len() as u32);
        for id in &self.ids {
            buf.extend_from_slice(&id.0);
        }
        buf
    }

    /// Parse from the Ergo wire format.
    pub fn parse(data: &[u8]) -> Result<Self, CodecError> {
        let reader = &mut &data[..];

        // typeId: 1 signed byte
        if reader.is_empty() {
            return Err(CodecError::UnexpectedEof);
        }
        let type_id = reader[0] as i8;
        *reader = &reader[1..];

        // count: VLQ u32
        let count = get_uint(reader)? as usize;

        // ids: count x 32 bytes
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

        Ok(InvData { type_id, ids })
    }
}

// ---------------------------------------------------------------------------
// ModifiersData
// ---------------------------------------------------------------------------

/// Response carrying full modifier payloads.
///
/// Wire format:
/// ```text
/// typeId:   1 byte (signed i8, getByte)
/// count:    VLQ unsigned (putUInt)
/// for each modifier:
///   id:     32 bytes
///   size:   VLQ unsigned (putUInt)
///   bytes:  size bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifiersData {
    /// The modifier type.
    pub type_id: i8,
    /// (modifier ID, payload bytes) pairs.
    pub modifiers: Vec<(ModifierId, Vec<u8>)>,
}

impl ModifiersData {
    /// Serialize to the Ergo wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.push(self.type_id as u8);
        put_uint(&mut buf, self.modifiers.len() as u32);
        for (id, payload) in &self.modifiers {
            buf.extend_from_slice(&id.0);
            put_uint(&mut buf, payload.len() as u32);
            buf.extend_from_slice(payload);
        }
        buf
    }

    /// Parse from the Ergo wire format.
    pub fn parse(data: &[u8]) -> Result<Self, CodecError> {
        let reader = &mut &data[..];

        // typeId: 1 signed byte
        if reader.is_empty() {
            return Err(CodecError::UnexpectedEof);
        }
        let type_id = reader[0] as i8;
        *reader = &reader[1..];

        // count: VLQ u32
        let count = get_uint(reader)? as usize;

        let mut modifiers = Vec::with_capacity(count);
        for _ in 0..count {
            // id: 32 bytes
            if reader.len() < 32 {
                return Err(CodecError::UnexpectedEof);
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&reader[..32]);
            *reader = &reader[32..];
            let id = ModifierId(arr);

            // size: VLQ u32
            let size = get_uint(reader)? as usize;

            // bytes: size bytes
            if reader.len() < size {
                return Err(CodecError::UnexpectedEof);
            }
            let payload = reader[..size].to_vec();
            *reader = &reader[size..];

            modifiers.push((id, payload));
        }

        Ok(ModifiersData { type_id, modifiers })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::modifier_id::ModifierId;

    #[test]
    fn inv_data_roundtrip() {
        let inv = InvData {
            type_id: 101, // Header
            ids: vec![ModifierId([0xAA; 32]), ModifierId([0xBB; 32])],
        };
        let bytes = inv.serialize();
        let parsed = InvData::parse(&bytes).unwrap();
        assert_eq!(parsed.type_id, 101);
        assert_eq!(parsed.ids.len(), 2);
        assert_eq!(parsed.ids[0], ModifierId([0xAA; 32]));
    }

    #[test]
    fn inv_data_single_id() {
        let inv = InvData {
            type_id: 2, // Transaction
            ids: vec![ModifierId([0xFF; 32])],
        };
        let bytes = inv.serialize();
        // type(1) + VLQ(1)=1 + id(32) = 34 bytes
        assert_eq!(bytes.len(), 34);
    }

    #[test]
    fn inv_data_empty_ids() {
        let inv = InvData {
            type_id: 101,
            ids: vec![],
        };
        let bytes = inv.serialize();
        let parsed = InvData::parse(&bytes).unwrap();
        assert_eq!(parsed.type_id, 101);
        assert!(parsed.ids.is_empty());
    }

    #[test]
    fn inv_data_negative_type_id() {
        let inv = InvData {
            type_id: -1,
            ids: vec![ModifierId([0x01; 32])],
        };
        let bytes = inv.serialize();
        let parsed = InvData::parse(&bytes).unwrap();
        assert_eq!(parsed.type_id, -1);
        assert_eq!(parsed.ids.len(), 1);
    }

    #[test]
    fn modifiers_data_roundtrip() {
        let modifiers = vec![
            (ModifierId([0xAA; 32]), vec![1u8, 2, 3, 4, 5]),
            (ModifierId([0xBB; 32]), vec![6u8, 7, 8]),
        ];
        let data = ModifiersData {
            type_id: 101,
            modifiers,
        };
        let bytes = data.serialize();
        let parsed = ModifiersData::parse(&bytes).unwrap();
        assert_eq!(parsed.type_id, 101);
        assert_eq!(parsed.modifiers.len(), 2);
        assert_eq!(parsed.modifiers[0].1, vec![1, 2, 3, 4, 5]);
        assert_eq!(parsed.modifiers[1].1, vec![6, 7, 8]);
    }

    #[test]
    fn modifiers_data_empty() {
        let data = ModifiersData {
            type_id: 102,
            modifiers: vec![],
        };
        let bytes = data.serialize();
        let parsed = ModifiersData::parse(&bytes).unwrap();
        assert_eq!(parsed.type_id, 102);
        assert!(parsed.modifiers.is_empty());
    }

    #[test]
    fn modifiers_data_full_equality() {
        let data = ModifiersData {
            type_id: 104,
            modifiers: vec![
                (ModifierId([0x11; 32]), vec![0xDE, 0xAD]),
                (ModifierId([0x22; 32]), vec![0xBE, 0xEF, 0xCA, 0xFE]),
            ],
        };
        let bytes = data.serialize();
        let parsed = ModifiersData::parse(&bytes).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    fn inv_data_parse_truncated_returns_error() {
        let inv = InvData {
            type_id: 101,
            ids: vec![ModifierId([0xAA; 32])],
        };
        let bytes = inv.serialize();
        // Truncate — only provide type_id + count but not the full ID
        let result = InvData::parse(&bytes[..5]);
        assert!(result.is_err());
    }

    #[test]
    fn modifiers_data_parse_truncated_returns_error() {
        let data = ModifiersData {
            type_id: 101,
            modifiers: vec![(ModifierId([0xAA; 32]), vec![1, 2, 3])],
        };
        let bytes = data.serialize();
        // Truncate before payload
        let result = ModifiersData::parse(&bytes[..10]);
        assert!(result.is_err());
    }
}
