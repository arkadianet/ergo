use std::sync::Arc;

use ergo_api::types::{ApiPeer, ApiPeerDirection, ApiPeerState};
use ergo_api_core::network::{
    BlacklistedPeerRecord, NetworkSnapshot, PeerChainStatus, PeerDirection, PeerRecord,
    PeerSnapshotSource, PeerState, PeerSyncRecord, TrackInfoRecord,
};

use super::SnapshotReadState;
use crate::snapshot::{NodeSnapshot, SnapshotHandle};

fn direction(value: ApiPeerDirection) -> PeerDirection {
    match value {
        ApiPeerDirection::Inbound => PeerDirection::Inbound,
        ApiPeerDirection::Outbound => PeerDirection::Outbound,
    }
}

fn state(value: ApiPeerState) -> PeerState {
    match value {
        ApiPeerState::Connecting => PeerState::Connecting,
        ApiPeerState::Handshaking => PeerState::Handshaking,
        ApiPeerState::Active => PeerState::Active,
        ApiPeerState::Degraded => PeerState::Degraded,
        ApiPeerState::Disconnected => PeerState::Disconnected,
    }
}

fn peer(value: &ApiPeer) -> PeerRecord {
    PeerRecord {
        addr: value.addr.clone(),
        direction: direction(value.direction),
        state: state(value.state),
        score: value.score,
        agent: value.agent.clone(),
        node_name: value.node_name.clone(),
        version: value.version.clone(),
        sync_version: value.sync_version.clone(),
        connected_seconds: value.connected_seconds,
        last_seen_seconds: value.last_seen_seconds,
        bytes_in: value.bytes_in,
        bytes_out: value.bytes_out,
        peer_height: value.peer_height,
        rest_api_url: value.rest_api_url.clone(),
        declared_address: value.declared_address.clone(),
    }
}

fn snapshot_value(value: &NodeSnapshot) -> NetworkSnapshot {
    let mut sync_info = value
        .peer_sync
        .iter()
        .map(|(addr, projection)| PeerSyncRecord {
            addr: addr.to_string(),
            peer_height: projection.peer_height,
            status: PeerChainStatus::from_name(projection.status),
        })
        .collect::<Vec<_>>();
    sync_info.sort_by(|left, right| left.addr.cmp(&right.addr));
    let mut blacklisted = value
        .banned_ips
        .iter()
        .map(|ip| BlacklistedPeerRecord {
            addr: ip.to_string(),
        })
        .collect::<Vec<_>>();
    blacklisted.sort_by(|left, right| left.addr.cmp(&right.addr));
    NetworkSnapshot {
        revision: ergo_api_core::page::SnapshotRevision(value.revision),
        peers: value.peers.iter().map(peer).collect(),
        blacklisted,
        sync_info,
        track_info: TrackInfoRecord {
            requested: value.delivery_counts.requested,
            received: value.delivery_counts.received,
            failed: value.delivery_counts.failed,
        },
    }
}

pub struct SnapshotPeerSource {
    handle: SnapshotHandle,
}

pub type SnapshotNetworkSource = SnapshotPeerSource;

impl SnapshotPeerSource {
    pub fn new(handle: SnapshotHandle) -> Self {
        Self { handle }
    }

    pub fn into_dyn(self) -> Arc<dyn PeerSnapshotSource> {
        Arc::new(self)
    }
}

impl PeerSnapshotSource for SnapshotPeerSource {
    fn snapshot(&self) -> NetworkSnapshot {
        snapshot_value(&self.handle.load())
    }
}

impl PeerSnapshotSource for SnapshotReadState {
    fn snapshot(&self) -> NetworkSnapshot {
        snapshot_value(&self.handle.load())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;

    use arc_swap::ArcSwap;
    use ergo_api::types::{ApiInfo, ApiPeer, ApiPeerDirection, ApiPeerState, ApiWeightFunction};

    use super::*;
    use crate::snapshot::{DeliveryCounters, PeerSyncProjection};

    #[test]
    fn snapshot_source_projects_peer_fields_and_network_data() {
        let mut snapshot = NodeSnapshot::empty(
            ApiInfo {
                agent_name: "test".into(),
                node_name: "test".into(),
                network: "mainnet".into(),
                version: "0".into(),
                started_at_unix_ms: 0,
                uptime_seconds: 0,
                target_block_interval_ms: 1,
            },
            ApiWeightFunction::Cost,
        );
        snapshot.revision = 12;
        snapshot.peers = vec![ApiPeer {
            addr: "1.2.3.4:9030".into(),
            direction: ApiPeerDirection::Inbound,
            state: ApiPeerState::Active,
            score: 4,
            agent: Some("agent".into()),
            node_name: Some("node".into()),
            version: Some("1".into()),
            sync_version: "V2".into(),
            connected_seconds: 8,
            last_seen_seconds: 2,
            bytes_in: Some(10),
            bytes_out: Some(20),
            peer_height: Some(44),
            rest_api_url: Some("http://peer".into()),
            declared_address: Some("1.2.3.4:9030".into()),
        }];
        snapshot.peer_sync = Arc::new(HashMap::from([(
            "1.2.3.4:9030".parse().unwrap(),
            PeerSyncProjection {
                status: "Older",
                peer_height: Some(44),
            },
        )]));
        snapshot.delivery_counts = DeliveryCounters {
            requested: 7,
            received: 6,
            failed: 5,
        };
        snapshot.banned_ips = Arc::new(vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);
        let handle: SnapshotHandle = Arc::new(ArcSwap::from_pointee(snapshot));
        let value = SnapshotPeerSource::new(handle).snapshot();
        assert_eq!(value.revision, ergo_api_core::page::SnapshotRevision(12));
        assert_eq!(value.peers[0].direction, PeerDirection::Inbound);
        assert_eq!(value.peers[0].state, PeerState::Active);
        assert_eq!(value.peers[0].peer_height, Some(44));
        assert_eq!(value.sync_info[0].status, PeerChainStatus::Older);
        assert_eq!(value.blacklisted[0].addr, "192.0.2.1");
        assert_eq!(value.track_info.requested, 7);
        assert_eq!(value.track_info.received, 6);
        assert_eq!(value.track_info.failed, 5);
    }
}
