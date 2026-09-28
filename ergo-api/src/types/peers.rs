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
    /// Version advertised in the peer handshake (not a verified build version).
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
    /// Height parsed from a peer tip header or inferred from shared header IDs.
    /// The latter can understate the remote tip. `None` without an observation.
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
    /// Additional local observations and peer-reported handshake metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<ApiPeerDetails>,
    /// IP metadata, resolved independently of the P2P/sync loop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<ApiPeerNetwork>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiPeerDetails {
    pub last_progress_seconds: u64,
    /// Score after time decay; lower is better. `ApiPeer.score` is the raw score.
    pub effective_score: i32,
    pub delivery_failure_streak: u32,
    pub preferred_for_downloads: bool,
    /// TCP connection/accept through completed handshake, including scheduling.
    /// This is connection setup time, NOT ping or request round-trip latency.
    pub connection_setup_ms: Option<u64>,
    pub chain_status: Option<String>,
    pub last_sync_seconds: Option<u64>,
    /// `reported_header` or `inferred_from_overlap`, only with a known height.
    pub height_source: Option<String>,
    /// Clock for comparing successive traffic snapshots.
    pub sampled_at_unix_ms: u64,
    pub mode: Option<ApiPeerMode>,
    pub local_address: Option<String>,
    /// Decimal string preserves all signed 64-bit session IDs in JavaScript.
    pub session_id: Option<String>,
    pub network_magic: Option<String>,
    pub feature_ids: Vec<u8>,
}

/// Peer-reported settings, not independently verified capabilities.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiPeerMode {
    /// Wire value: 0 = UTXO, 1 = digest; unknown values are preserved.
    pub state_type: u8,
    pub verifies_transactions: bool,
    pub nipopow_bootstrap: Option<i32>,
    /// -1 = all, -2 = UTXO bootstrap, positive = retained suffix.
    pub blocks_to_keep: i32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct ApiPeerNetwork {
    pub ip: String,
    pub ip_version: String,
    pub scope: String,
    pub hostname: Option<String>,
    /// `pending`, `resolved`, `unavailable`, `timeout`, `disabled`, `not_public`.
    pub hostname_status: String,
    pub hostname_checked_at_unix_ms: Option<u64>,
    /// `available`, `not_found`, `not_configured`, `downloading`, `error`, `not_public`.
    pub geo_status: String,
    pub asn_status: String,
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub continent: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub time_zone: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub accuracy_radius_km: Option<u16>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub network_cidr: Option<String>,
    pub geo_database: Option<String>,
    pub geo_database_built_at_unix_seconds: Option<u64>,
    pub asn_database: Option<String>,
    pub asn_database_built_at_unix_seconds: Option<u64>,
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
