//! Connection-limit configuration for [`super::PeerManager`].
//!
//! Carries the four anti-eclipse caps (max total, target outbound,
//! per-IP, per-/16 subnet) and the [`ConnectError`] variants the
//! manager surfaces when a dial / accept hits a limit.

use thiserror::Error;

use crate::handshake::Version;

pub const DEFAULT_MAX_CONNECTIONS: usize = 384;
pub const DEFAULT_TARGET_OUTBOUND: usize = 96;
pub const DEFAULT_MAX_INBOUND: usize = 256;
pub const DEFAULT_PER_IP_LIMIT: usize = 1;
pub const DEFAULT_PER_SUBNET_LIMIT: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLimits {
    /// Hard ceiling on total concurrent connections (inbound + outbound).
    /// Enforced on every register via `check_can_connect`; caps the sum
    /// even when `target_outbound + max_inbound` would exceed it.
    pub max_connections: usize,
    /// Outbound connections the node actively maintains (dials to reach).
    pub target_outbound: usize,
    /// Inbound connections the node accepts. Decoupled from
    /// `target_outbound`: a full outbound set never reduces inbound
    /// capacity. `0` = outbound-only (accept no inbound).
    pub max_inbound: usize,
    pub per_ip_limit: usize,
    pub per_subnet_limit: usize,
}

impl PeerLimits {
    /// Maximum inbound connections accepted. An explicit budget,
    /// independent of `max_connections` / `target_outbound` (the total
    /// ceiling still applies on top via `check_can_connect`).
    pub fn max_inbound(&self) -> usize {
        self.max_inbound
    }
}

impl Default for PeerLimits {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            target_outbound: DEFAULT_TARGET_OUTBOUND,
            max_inbound: DEFAULT_MAX_INBOUND,
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
