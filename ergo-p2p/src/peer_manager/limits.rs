//! Connection-limit configuration for [`super::PeerManager`].
//!
//! Carries the four anti-eclipse caps (max total, target outbound,
//! per-IP, per-/16 subnet) and the [`ConnectError`] variants the
//! manager surfaces when a dial / accept hits a limit.

use thiserror::Error;

use crate::handshake::Version;

pub const DEFAULT_MAX_CONNECTIONS: usize = 80;
pub const DEFAULT_TARGET_OUTBOUND: usize = 60;
pub const DEFAULT_PER_IP_LIMIT: usize = 1;
pub const DEFAULT_PER_SUBNET_LIMIT: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLimits {
    pub max_connections: usize,
    pub target_outbound: usize,
    pub per_ip_limit: usize,
    pub per_subnet_limit: usize,
}

impl PeerLimits {
    pub fn max_inbound(&self) -> usize {
        self.max_connections.saturating_sub(self.target_outbound)
    }
}

impl Default for PeerLimits {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            target_outbound: DEFAULT_TARGET_OUTBOUND,
            per_ip_limit: DEFAULT_PER_IP_LIMIT,
            per_subnet_limit: DEFAULT_PER_SUBNET_LIMIT,
        }
    }
}

/// Why a [`super::PeerManager::register_outbound`] /
/// [`super::PeerManager::register_inbound`] /
/// [`super::PeerManager::complete_handshake`] call was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConnectError {
    #[error("already connected")]
    AlreadyConnected,
    #[error("peer is banned")]
    Banned,
    #[error("max connections reached")]
    TooManyConnections,
    #[error("no inbound slots available")]
    TooManyInbound,
    #[error("per-IP limit reached")]
    PerIpLimitReached,
    #[error("per-subnet limit reached")]
    PerSubnetLimitReached,
    #[error("self-connection detected via session_id")]
    SelfConnection,
    #[error("peer version {0} below minimum")]
    VersionTooOld(Version),
    #[error("unknown peer")]
    UnknownPeer,
}
