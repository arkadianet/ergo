//! Peer-manager view DTOs: the per-peer row plus its direction and
//! connection-state enums.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiPeer {
    pub addr: String,
    pub direction: ApiPeerDirection,
    pub state: ApiPeerState,
    pub score: i32,
    pub agent: Option<String>,
    pub node_name: Option<String>,
    pub version: Option<String>,
    pub sync_version: String,
    pub connected_seconds: u64,
    pub last_seen_seconds: u64,
    /// Cumulative post-handshake framed-message bytes received from this
    /// peer (per-frame header+checksum+payload), counted at the per-peer
    /// I/O task's transport boundary. Excludes the handshake exchange,
    /// which precedes that task. Read-only telemetry, never fed into peer
    /// scoring/throttle. `None` only on snapshots that predate the peer's
    /// connection.
    pub bytes_in: Option<u64>,
    /// Cumulative post-handshake framed-message bytes sent to this peer.
    /// Same accounting as [`Self::bytes_in`].
    pub bytes_out: Option<u64>,
    /// Peer's own best-block height as advertised in the most recent
    /// `SyncInfo` exchange. `None` until the sync layer plumbs it through.
    pub peer_height: Option<u32>,
    /// Peer's advertised REST API URL (the `RestApiUrl` handshake
    /// feature), verbatim as the peer sent it. `None` when the peer
    /// advertised none. Identity/observability only — not validated
    /// here beyond what the handshake parser already did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rest_api_url: Option<String>,
    /// Peer's declared public address (`ip:port`) from its `PeerSpec`,
    /// what it advertises as reachable. `None` when the peer declared no
    /// address (anonymous / not gossipable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_address: Option<String>,
}

/// Which side initiated the peer connection.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiPeerDirection {
    Inbound,
    Outbound,
}

/// Connection lifecycle state observed by the peer manager.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiPeerState {
    Connecting,
    Handshaking,
    Active,
    Degraded,
    Disconnected,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- ApiPeerDirection: wire shape -----

    #[test]
    fn api_peer_direction_serializes_to_canonical_lowercase() {
        for (variant, expected) in [
            (ApiPeerDirection::Inbound, "inbound"),
            (ApiPeerDirection::Outbound, "outbound"),
        ] {
            let got = serde_json::to_value(variant).unwrap();
            assert_eq!(got, serde_json::Value::String(expected.into()));
        }
    }

    #[test]
    fn api_peer_direction_roundtrips_and_rejects_unknown() {
        for v in [ApiPeerDirection::Inbound, ApiPeerDirection::Outbound] {
            let s = serde_json::to_string(&v).unwrap();
            let back: ApiPeerDirection = serde_json::from_str(&s).unwrap();
            assert_eq!(back, v);
        }
        let err = serde_json::from_value::<ApiPeerDirection>(serde_json::json!("lateral"));
        assert!(err.is_err(), "unknown direction variant must reject");
    }

    // ----- ApiPeerState: wire shape -----

    #[test]
    fn api_peer_state_serializes_to_canonical_lowercase() {
        for (variant, expected) in [
            (ApiPeerState::Connecting, "connecting"),
            (ApiPeerState::Handshaking, "handshaking"),
            (ApiPeerState::Active, "active"),
            (ApiPeerState::Degraded, "degraded"),
            (ApiPeerState::Disconnected, "disconnected"),
        ] {
            let got = serde_json::to_value(variant).unwrap();
            assert_eq!(got, serde_json::Value::String(expected.into()));
        }
    }

    #[test]
    fn api_peer_state_roundtrips_and_rejects_unknown() {
        for v in [
            ApiPeerState::Connecting,
            ApiPeerState::Handshaking,
            ApiPeerState::Active,
            ApiPeerState::Degraded,
            ApiPeerState::Disconnected,
        ] {
            let s = serde_json::to_string(&v).unwrap();
            let back: ApiPeerState = serde_json::from_str(&s).unwrap();
            assert_eq!(back, v);
        }
        let err = serde_json::from_value::<ApiPeerState>(serde_json::json!("dormant"));
        assert!(err.is_err(), "unknown peer state variant must reject");
    }
}
