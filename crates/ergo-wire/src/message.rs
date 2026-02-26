/// All known P2P message type codes in the Ergo protocol.
/// Values must match the Scala reference node exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageCode {
    GetPeers = 1,
    Peers = 2,
    RequestModifier = 22,
    Modifier = 33,
    Inv = 55,
    SyncInfo = 65,
    Handshake = 75,
    GetSnapshotsInfo = 76,
    SnapshotsInfo = 77,
    GetManifest = 78,
    Manifest = 79,
    GetUtxoSnapshotChunk = 80,
    UtxoSnapshotChunk = 81,
    GetNipopowProof = 90,
    NipopowProof = 91,
}

impl MessageCode {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::GetPeers),
            2 => Some(Self::Peers),
            22 => Some(Self::RequestModifier),
            33 => Some(Self::Modifier),
            55 => Some(Self::Inv),
            65 => Some(Self::SyncInfo),
            75 => Some(Self::Handshake),
            76 => Some(Self::GetSnapshotsInfo),
            77 => Some(Self::SnapshotsInfo),
            78 => Some(Self::GetManifest),
            79 => Some(Self::Manifest),
            80 => Some(Self::GetUtxoSnapshotChunk),
            81 => Some(Self::UtxoSnapshotChunk),
            90 => Some(Self::GetNipopowProof),
            91 => Some(Self::NipopowProof),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_codes_match_scala() {
        assert_eq!(MessageCode::GetPeers as u8, 1);
        assert_eq!(MessageCode::Peers as u8, 2);
        assert_eq!(MessageCode::RequestModifier as u8, 22);
        assert_eq!(MessageCode::Modifier as u8, 33);
        assert_eq!(MessageCode::Inv as u8, 55);
        assert_eq!(MessageCode::SyncInfo as u8, 65);
        assert_eq!(MessageCode::Handshake as u8, 75);
        assert_eq!(MessageCode::GetSnapshotsInfo as u8, 76);
        assert_eq!(MessageCode::SnapshotsInfo as u8, 77);
        assert_eq!(MessageCode::GetManifest as u8, 78);
        assert_eq!(MessageCode::Manifest as u8, 79);
        assert_eq!(MessageCode::GetUtxoSnapshotChunk as u8, 80);
        assert_eq!(MessageCode::UtxoSnapshotChunk as u8, 81);
        assert_eq!(MessageCode::GetNipopowProof as u8, 90);
        assert_eq!(MessageCode::NipopowProof as u8, 91);
    }

    #[test]
    fn from_byte_roundtrip() {
        for code in [1u8, 2, 22, 33, 55, 65, 75, 76, 77, 78, 79, 80, 81, 90, 91] {
            let mc = MessageCode::from_byte(code).unwrap();
            assert_eq!(mc as u8, code);
        }
    }

    #[test]
    fn unknown_code_returns_none() {
        assert!(MessageCode::from_byte(99).is_none());
    }
}
