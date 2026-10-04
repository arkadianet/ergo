//! Consensus-independent operator controls shared with the node runtime.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Request budgets which may be changed without rebuilding the API router.
/// Proxy trust and loopback exemptions are intentionally restart-only.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ApiLimits {
    pub refill_per_sec: f64,
    pub burst: f64,
    pub cheap_weight: f64,
    pub heavy_weight: f64,
    pub compute_weight: f64,
    pub max_tracked_ips: usize,
    pub idle_prune_after_secs: u64,
}

impl Default for ApiLimits {
    fn default() -> Self {
        Self {
            refill_per_sec: 20.0,
            burst: 40.0,
            cheap_weight: 1.0,
            heavy_weight: 4.0,
            compute_weight: 10.0,
            max_tracked_ips: 65_536,
            idle_prune_after_secs: 600,
        }
    }
}

impl ApiLimits {
    pub fn governor_config(&self, behind_proxy: bool) -> crate::v1::GovernorConfig {
        crate::v1::GovernorConfig {
            refill_per_sec: self.refill_per_sec,
            burst: self.burst,
            cheap_weight: self.cheap_weight,
            heavy_weight: self.heavy_weight,
            compute_weight: self.compute_weight,
            max_tracked_ips: self.max_tracked_ips,
            idle_prune_after: std::time::Duration::from_secs(self.idle_prune_after_secs),
            local_reverse_proxy: behind_proxy,
            ..Default::default()
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.governor_config(false)
            .validate()
            .map_err(|e| e.to_string())?;
        if !(1..=1_000_000).contains(&self.max_tracked_ips) {
            return Err("max_tracked_ips must be between 1 and 1000000".into());
        }
        if !(1..=86_400).contains(&self.idle_prune_after_secs) {
            return Err("idle_prune_after_secs must be between 1 and 86400".into());
        }
        if self.burst
            < self
                .cheap_weight
                .max(self.heavy_weight)
                .max(self.compute_weight)
        {
            return Err("burst must admit at least one request of every route class".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ProbePolicy {
    pub heartbeat_max_age_ms: u64,
    pub snapshot_max_age_ms: u64,
    pub tip_max_age_ms: u64,
    pub require_indexer: bool,
    pub require_wallet: bool,
}

impl Default for ProbePolicy {
    fn default() -> Self {
        Self {
            heartbeat_max_age_ms: 600_000,
            snapshot_max_age_ms: 30_000,
            tip_max_age_ms: 2 * 60 * 60 * 1000,
            require_indexer: false,
            require_wallet: false,
        }
    }
}

impl ProbePolicy {
    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("heartbeat_max_age_ms", self.heartbeat_max_age_ms),
            ("snapshot_max_age_ms", self.snapshot_max_age_ms),
            ("tip_max_age_ms", self.tip_max_age_ms),
        ] {
            if !(1_000..=86_400_000).contains(&value) {
                return Err(format!("{name} must be between 1000 and 86400000"));
            }
        }
        Ok(())
    }
}

/// PATCH members merge into the live settings; unknown members are rejected.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfigPatch {
    pub expected_revision: Option<String>,
    pub api_limits: Option<serde_json::Value>,
    pub readiness: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProbeReport {
    pub ready: bool,
    pub reasons: Vec<String>,
    pub heartbeat_age_ms: Option<u64>,
    pub snapshot_age_ms: u64,
    pub tip_age_ms: Option<u64>,
    pub indexer_height: Option<u64>,
    pub wallet_height: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct NodeProbes {
    pub startup: ProbeReport,
    pub liveness: ProbeReport,
    pub readiness: ProbeReport,
}

#[derive(Debug, Clone)]
pub enum PeerControl {
    Ban { ip: IpAddr, duration_secs: u64 },
    Unban { ip: IpAddr },
    Disconnect { addr: SocketAddr },
    Remove { addr: SocketAddr },
}

#[derive(Debug, thiserror::Error)]
pub enum OperatorControlError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Storage(String),
    #[error("{0}")]
    NotFound(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct PeerControlResult {
    /// Present for disconnect/remove: whether an active session was closed.
    pub session_closed: Option<bool>,
}

pub type PeerControlFuture<'a> =
    Pin<Box<dyn Future<Output = Result<PeerControlResult, OperatorControlError>> + Send + 'a>>;
