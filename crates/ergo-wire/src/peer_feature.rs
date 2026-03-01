use crate::vlq::{self, CodecError};

// Feature IDs from PeerFeatureDescriptors.scala
pub const FEATURE_ID_LOCAL_ADDRESS: u8 = 2;
pub const FEATURE_ID_SESSION: u8 = 3;
pub const FEATURE_ID_REST_API_URL: u8 = 4;
pub const FEATURE_ID_MODE: u8 = 16;

/// State type code (matches StateType.stateTypeCode in Scala)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StateTypeCode {
    Utxo = 0,
    Digest = 1,
}

impl StateTypeCode {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Utxo),
            1 => Some(Self::Digest),
            _ => None,
        }
    }
}

/// Mode peer feature (id=16): describes node operating mode
///
/// Scorex VLQ serialization:
/// - stateType: putUByte (1 byte)
/// - verifyingTransactions: putBoolean (1 byte)
/// - nipopowSuffix: putOption { putUInt (VLQ) }
/// - blocksToKeep: putInt (ZigZag + VLQ)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeFeature {
    pub state_type: StateTypeCode,
    pub verifying_transactions: bool,
    pub nipopow_bootstrapped: Option<i32>,
    pub blocks_to_keep: i32,
}

impl ModeFeature {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.state_type as u8);
        buf.push(u8::from(self.verifying_transactions));
        vlq::put_option(&mut buf, &self.nipopow_bootstrapped, |b, v| {
            vlq::put_int(b, *v);
        });
        vlq::put_int(&mut buf, self.blocks_to_keep);
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() < 3 {
            return Err(CodecError::UnexpectedEof);
        }
        let state_type = StateTypeCode::from_byte(data[0]).ok_or(CodecError::UnexpectedEof)?;
        let verifying_transactions = data[1] > 0;
        let mut reader = &data[2..];
        let nipopow_bootstrapped = vlq::get_option(&mut reader, |r| vlq::get_int(r))?;
        let blocks_to_keep = vlq::get_int(&mut reader)?;
        Ok(Self {
            state_type,
            verifying_transactions,
            nipopow_bootstrapped,
            blocks_to_keep,
        })
    }
}

/// Session peer feature (id=3): network magic + random session ID
///
/// Scorex VLQ serialization:
/// - networkMagic: put (4 raw bytes)
/// - sessionId: putLong (ZigZag + VLQ)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionFeature {
    pub network_magic: [u8; 4],
    pub session_id: i64,
}

impl SessionFeature {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.network_magic);
        vlq::put_long(&mut buf, self.session_id);
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() < 5 {
            return Err(CodecError::UnexpectedEof);
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);
        let mut reader = &data[4..];
        let session_id = vlq::get_long(&mut reader)?;
        Ok(Self {
            network_magic: magic,
            session_id,
        })
    }
}

/// Parsed peer feature (any type)
#[derive(Debug, Clone)]
pub enum PeerFeature {
    Mode(ModeFeature),
    Session(SessionFeature),
    Unknown { id: u8, data: Vec<u8> },
}

impl PeerFeature {
    pub fn feature_id(&self) -> u8 {
        match self {
            Self::Mode(_) => FEATURE_ID_MODE,
            Self::Session(_) => FEATURE_ID_SESSION,
            Self::Unknown { id, .. } => *id,
        }
    }

    pub fn serialize_bytes(&self) -> Vec<u8> {
        match self {
            Self::Mode(m) => m.serialize(),
            Self::Session(s) => s.serialize(),
            Self::Unknown { data, .. } => data.clone(),
        }
    }

    pub fn parse_feature(id: u8, data: &[u8]) -> Result<Self, CodecError> {
        match id {
            FEATURE_ID_MODE => Ok(Self::Mode(ModeFeature::parse(data)?)),
            FEATURE_ID_SESSION => Ok(Self::Session(SessionFeature::parse(data)?)),
            _ => Ok(Self::Unknown {
                id,
                data: data.to_vec(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_ids_match_scala() {
        assert_eq!(FEATURE_ID_LOCAL_ADDRESS, 2);
        assert_eq!(FEATURE_ID_SESSION, 3);
        assert_eq!(FEATURE_ID_REST_API_URL, 4);
        assert_eq!(FEATURE_ID_MODE, 16);
    }

    #[test]
    fn mode_feature_roundtrip() {
        let mode = ModeFeature {
            state_type: StateTypeCode::Utxo,
            verifying_transactions: true,
            nipopow_bootstrapped: None,
            blocks_to_keep: -1,
        };
        let bytes = mode.serialize();
        let parsed = ModeFeature::parse(&bytes).unwrap();
        assert_eq!(parsed.state_type, StateTypeCode::Utxo);
        assert!(parsed.verifying_transactions);
        assert!(parsed.nipopow_bootstrapped.is_none());
        assert_eq!(parsed.blocks_to_keep, -1);
    }

    #[test]
    fn mode_feature_wire_format() {
        let mode = ModeFeature {
            state_type: StateTypeCode::Utxo,
            verifying_transactions: true,
            nipopow_bootstrapped: None,
            blocks_to_keep: -1,
        };
        let bytes = mode.serialize();
        // stateType=0, verifying=1, nipopow=None(0), blocksToKeep=ZigZag(-1)=VLQ(1)=0x01
        assert_eq!(bytes, vec![0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn mode_feature_with_nipopow() {
        let mode = ModeFeature {
            state_type: StateTypeCode::Digest,
            verifying_transactions: false,
            nipopow_bootstrapped: Some(1),
            blocks_to_keep: 1000,
        };
        let bytes = mode.serialize();
        let parsed = ModeFeature::parse(&bytes).unwrap();
        assert_eq!(parsed.nipopow_bootstrapped, Some(1));
        assert_eq!(parsed.blocks_to_keep, 1000);
    }

    #[test]
    fn session_feature_roundtrip() {
        let session = SessionFeature {
            network_magic: [2, 0, 0, 1],
            session_id: 0xDEADBEEFCAFEBABEu64 as i64,
        };
        let bytes = session.serialize();
        let parsed = SessionFeature::parse(&bytes).unwrap();
        assert_eq!(parsed.network_magic, [2, 0, 0, 1]);
        assert_eq!(parsed.session_id, 0xDEADBEEFCAFEBABEu64 as i64);
    }

    #[test]
    fn session_feature_small_id() {
        let session = SessionFeature {
            network_magic: [1, 0, 2, 4],
            session_id: 123,
        };
        let bytes = session.serialize();
        // 4 bytes magic + VLQ(ZigZag(123)) = VLQ(246) = 2 bytes
        assert_eq!(bytes.len(), 6);
        let parsed = SessionFeature::parse(&bytes).unwrap();
        assert_eq!(parsed.session_id, 123);
    }
}
