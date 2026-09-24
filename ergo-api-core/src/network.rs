use crate::page::SnapshotRevision;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDirection {
    Inbound,
    Outbound,
}

impl PeerDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Connecting,
    Handshaking,
    Active,
    Degraded,
    Disconnected,
}

impl PeerState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Handshaking => "handshaking",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Disconnected => "disconnected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerChainStatus {
    Equal,
    Younger,
    Older,
    Fork,
    Unknown,
    Nonsense,
}

impl PeerChainStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equal => "equal",
            Self::Younger => "younger",
            Self::Older => "older",
            Self::Fork => "fork",
            Self::Unknown => "unknown",
            Self::Nonsense => "nonsense",
        }
    }

    pub fn from_name(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "equal" => Self::Equal,
            "younger" => Self::Younger,
            "older" => Self::Older,
            "fork" => Self::Fork,
            "nonsense" => Self::Nonsense,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    pub addr: String,
    pub direction: PeerDirection,
    pub state: PeerState,
    pub score: i32,
    pub agent: Option<String>,
    pub node_name: Option<String>,
    pub version: Option<String>,
    pub sync_version: String,
    pub connected_seconds: u64,
    pub last_seen_seconds: u64,
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
    pub peer_height: Option<u32>,
    pub rest_api_url: Option<String>,
    pub declared_address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlacklistedPeerRecord {
    pub addr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSyncRecord {
    pub addr: String,
    pub peer_height: Option<u32>,
    pub status: PeerChainStatus,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrackInfoRecord {
    pub requested: u32,
    pub received: u32,
    pub failed: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSnapshot {
    pub revision: SnapshotRevision,
    pub peers: Vec<PeerRecord>,
    pub blacklisted: Vec<BlacklistedPeerRecord>,
    pub sync_info: Vec<PeerSyncRecord>,
    pub track_info: TrackInfoRecord,
}

impl Default for NetworkSnapshot {
    fn default() -> Self {
        Self {
            revision: SnapshotRevision(0),
            peers: Vec::new(),
            blacklisted: Vec::new(),
            sync_info: Vec::new(),
            track_info: TrackInfoRecord::default(),
        }
    }
}

pub trait PeerSnapshotSource: Send + Sync + 'static {
    fn snapshot(&self) -> NetworkSnapshot;

    fn network_snapshot(&self) -> NetworkSnapshot {
        self.snapshot()
    }

    fn peers(&self) -> Vec<PeerRecord> {
        self.snapshot().peers
    }

    fn blacklisted(&self) -> Vec<BlacklistedPeerRecord> {
        self.snapshot().blacklisted
    }

    fn sync_info(&self) -> Vec<PeerSyncRecord> {
        self.snapshot().sync_info
    }

    fn track_info(&self) -> TrackInfoRecord {
        self.snapshot().track_info
    }
}

pub use PeerSnapshotSource as NetworkSnapshotSource;
pub use PeerSnapshotSource as PeerSource;
pub type BlacklistedRecord = BlacklistedPeerRecord;
pub type BlacklistedPeer = BlacklistedPeerRecord;
pub type PeerSyncSnapshot = PeerSyncRecord;
pub type PeerSyncInfo = PeerSyncRecord;
pub type PeerTrackInfo = TrackInfoRecord;
pub type PeerNetworkSnapshot = NetworkSnapshot;
pub type NetworkPeerSnapshot = NetworkSnapshot;
pub type PeerSnapshot = NetworkSnapshot;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_enums_use_native_wire_names() {
        assert_eq!(PeerDirection::Inbound.as_str(), "inbound");
        assert_eq!(PeerDirection::Outbound.as_str(), "outbound");
        assert_eq!(PeerState::Active.as_str(), "active");
        assert_eq!(PeerChainStatus::Younger.as_str(), "younger");
        assert_eq!(PeerChainStatus::from_name("OLDER"), PeerChainStatus::Older);
        assert_eq!(
            PeerChainStatus::from_name("unknown-value"),
            PeerChainStatus::Unknown
        );
    }
}
