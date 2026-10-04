//! Live operator budgets, redacted boot configuration and runtime heartbeat.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use ergo_api::operator_control::{
    ApiLimits, NodeProbes, OperatorControlError, ProbePolicy, ProbeReport, RuntimeConfigPatch,
};
use serde_json::{json, Value};

use crate::config::NodeConfig;
use crate::snapshot::NodeSnapshot;

#[derive(Default)]
pub(crate) struct Dependencies {
    pub indexer_height: Option<u64>,
    pub indexer_healthy: bool,
    pub wallet_height: Option<u32>,
    pub wallet_healthy: bool,
}

pub struct PeerControlRequest {
    pub command: ergo_api::operator_control::PeerControl,
    pub deadline: Instant,
    pub reply: tokio::sync::oneshot::Sender<Result<(), OperatorControlError>>,
}

type DependencyReader = Arc<dyn Fn(bool, bool) -> Dependencies + Send + Sync>;

struct LiveConfig {
    revision: u64,
    limits: ApiLimits,
    policy: ProbePolicy,
}

pub struct RuntimeControl {
    started_at: Instant,
    heartbeat: AtomicU64,
    stopped: AtomicBool,
    config: RwLock<LiveConfig>,
    dependencies: RwLock<Option<DependencyReader>>,
    governor: Arc<ergo_api::v1::Governor>,
    boot: Value,
    behind_proxy: bool,
    headers_only: bool,
}

impl RuntimeControl {
    pub fn new(config: &NodeConfig) -> Result<Arc<Self>, String> {
        config.api_limits.validate()?;
        config.api_readiness.validate()?;
        let governor = ergo_api::v1::Governor::new(
            config
                .api_limits
                .governor_config(config.api_local_reverse_proxy),
        )
        .map_err(|e| e.to_string())?;
        // Deliberate allowlist: never serialize NodeConfig's Debug representation,
        // checkpoint internals, shadow credentials, key hashes or wallet secrets.
        let boot = json!({
            "network": format!("{:?}", config.network).to_lowercase(),
            "data_dir": config.data_dir,
            "node": {
                "agent_name": config.agent_name, "node_name": config.node_name,
                "state_type": config.state_type.as_str(), "verify_transactions": config.verify_transactions,
                "blocks_to_keep": config.blocks_to_keep, "keep_versions": config.keep_versions,
                "utxo_bootstrap": config.utxo_bootstrap, "nipopow_bootstrap": config.nipopow_bootstrap,
                "script_validation_checkpoint_configured": config.script_validation_checkpoint.is_some(),
                "header_checkpoint_configured": config.header_checkpoint.is_some(),
            },
            "peers": {
                "known": config.known_peers.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "bind_addr": config.bind_addr.map(|a| a.to_string()),
                "declared_addr": config.declared_addr.map(|a| a.to_string()),
                "target_outbound": config.peer_limits.target_outbound,
                "max_inbound": config.peer_limits.max_inbound,
                "max_connections": config.peer_limits.max_connections,
                "allow_local": config.allow_local,
            },
            "sync": {
                "download_window": config.download_window,
                "sync_interval_secs": config.sync_interval.as_secs(),
                "sync_interval_stable_secs": config.sync_interval_stable.as_secs(),
                "ibd_flush_interval": config.ibd_flush_interval,
            },
            "api": {
                "bind": config.api_bind.map(|a| a.to_string()),
                "allowed_hosts": config.api_allowed_hosts,
                "local_reverse_proxy": config.api_local_reverse_proxy,
                "authentication_configured": config.api_key_hash.is_some(),
                "scoped_credential_count": config.api_scoped_keys.len(),
                "script": {"require_api_key": config.api_script.require_api_key, "max_cost": config.api_script.max_cost},
            },
            "indexer": {"enabled": config.indexer_config.enabled, "db_filename": config.indexer_config.db_filename},
            "mining": {"enabled": config.mining_config.enabled},
            "mempool": {
                "capacity_count": config.mempool_config.max_pool_size,
                "capacity_bytes": config.mempool_config.max_pool_bytes,
                "min_relay_fee_nano_erg": config.mempool_config.min_relay_fee_nano_erg,
                "sort_policy": config.mempool_sort_policy,
            },
            "wallet": {"expose_private_keys": config.wallet_expose_private_keys},
            "logging": {"default_level": config.logging.default_level, "modules": config.logging.modules},
        });
        Ok(Arc::new(Self {
            started_at: Instant::now(),
            heartbeat: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
            config: RwLock::new(LiveConfig {
                revision: 0,
                limits: config.api_limits.clone(),
                policy: config.api_readiness.clone(),
            }),
            dependencies: RwLock::new(None),
            governor,
            boot,
            behind_proxy: config.api_local_reverse_proxy,
            headers_only: !config.verify_transactions,
        }))
    }

    pub(crate) fn set_dependencies(&self, reader: DependencyReader) {
        *self
            .dependencies
            .write()
            .expect("probe dependencies poisoned") = Some(reader);
    }

    pub fn governor(&self) -> Arc<ergo_api::v1::Governor> {
        self.governor.clone()
    }

    pub(crate) fn beat(&self) {
        self.heartbeat.store(
            self.started_at.elapsed().as_millis() as u64 + 1,
            Ordering::Release,
        );
    }

    pub(crate) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        // Snapshot readers may be retained by embedders after shutdown. Release
        // dependency database handles here so those readers cannot retain locks.
        self.dependencies
            .write()
            .expect("probe dependencies poisoned")
            .take();
    }

    fn view(&self, live: &LiveConfig) -> Value {
        json!({
            "revision": live.revision, "boot": self.boot,
            "runtime": {"api_limits": live.limits, "readiness": live.policy},
            "reloadable": ["api_limits", "readiness"],
            "persistence": "runtime patches are process-local; update TOML to retain across restart",
            "restart_required": ["network", "node", "peers", "sync", "api", "indexer", "mining", "mempool", "wallet", "logging"],
        })
    }

    pub fn effective_config(&self) -> Value {
        self.view(&self.config.read().expect("runtime config poisoned"))
    }

    pub fn patch(&self, patch: RuntimeConfigPatch) -> Result<Value, OperatorControlError> {
        let mut live = self.config.write().expect("runtime config poisoned");
        if patch
            .expected_revision
            .is_some_and(|expected| expected != live.revision)
        {
            return Err(OperatorControlError::Conflict(
                "runtime configuration revision changed; read config and retry".into(),
            ));
        }
        if patch.api_limits.is_none() && patch.readiness.is_none() {
            return Err(OperatorControlError::Invalid(
                "supply api_limits or readiness; other settings require a restart".into(),
            ));
        }
        let limits: ApiLimits = merge(&live.limits, patch.api_limits)?;
        let policy: ProbePolicy = merge(&live.policy, patch.readiness)?;
        limits.validate().map_err(OperatorControlError::Invalid)?;
        policy.validate().map_err(OperatorControlError::Invalid)?;
        let revision = live
            .revision
            .checked_add(1)
            .ok_or_else(|| OperatorControlError::Conflict("runtime revision exhausted".into()))?;
        // All members were validated before any live state changes. The governor
        // holds its own write lock and carries existing bucket debt forward.
        self.governor
            .reconfigure(limits.governor_config(self.behind_proxy))
            .map_err(|e| OperatorControlError::Invalid(e.to_string()))?;
        *live = LiveConfig {
            revision,
            limits,
            policy,
        };
        Ok(self.view(&live))
    }

    pub(crate) fn probes(
        &self,
        snapshot: &NodeSnapshot,
        status: &ergo_api::types::ApiStatus,
    ) -> NodeProbes {
        self.probes_with_status_at(
            snapshot,
            status,
            Instant::now(),
            crate::snapshot::unix_now_ms(),
        )
    }

    #[cfg(test)]
    fn probes_at(&self, snapshot: &NodeSnapshot, now: Instant, unix_ms: u64) -> NodeProbes {
        self.probes_with_status_at(snapshot, &snapshot.status, now, unix_ms)
    }

    fn probes_with_status_at(
        &self,
        snapshot: &NodeSnapshot,
        status: &ergo_api::types::ApiStatus,
        now: Instant,
        unix_ms: u64,
    ) -> NodeProbes {
        let live = self.config.read().expect("runtime config poisoned");
        let heartbeat = self.heartbeat.load(Ordering::Acquire);
        let elapsed = now.saturating_duration_since(self.started_at).as_millis() as u64;
        let heartbeat_age_ms = (heartbeat > 0).then(|| elapsed.saturating_sub(heartbeat - 1));
        let snapshot_age_ms = now
            .saturating_duration_since(snapshot.produced_at)
            .as_millis() as u64;
        let tip = if self.headers_only {
            &snapshot.tip.best_header.timestamp_unix_ms
        } else {
            &snapshot.tip.best_full_block.timestamp_unix_ms
        };
        let tip_age_ms = (*tip > 0).then(|| unix_ms.saturating_sub(*tip));
        let deps = if live.policy.require_indexer || live.policy.require_wallet {
            self.dependencies
                .read()
                .expect("probe dependencies poisoned")
                .as_ref()
                .map(|reader| reader(live.policy.require_indexer, live.policy.require_wallet))
                .unwrap_or_default()
        } else {
            Dependencies::default()
        };
        let report = ProbeReport {
            ready: false,
            reasons: Vec::new(),
            heartbeat_age_ms,
            snapshot_age_ms,
            tip_age_ms,
            indexer_height: live
                .policy
                .require_indexer
                .then_some(deps.indexer_height)
                .flatten(),
            wallet_height: live
                .policy
                .require_wallet
                .then_some(deps.wallet_height)
                .flatten(),
        };
        let mut startup = report.clone();
        if heartbeat == 0 {
            startup.reasons.push("runtime_not_started".into());
        }
        if self.stopped.load(Ordering::Acquire) {
            startup.reasons.push("runtime_stopped".into());
        }
        startup.ready = startup.reasons.is_empty();
        let mut liveness = startup.clone();
        let apply_progressing = status.apply_age_ms.is_some_and(|age| {
            age >= 0 && age < crate::node::telemetry::APPLY_WEDGED_THRESHOLD.as_millis() as i64
        }) && !status.apply_wedged;
        if status.apply_wedged {
            liveness.reasons.push("runtime_apply_stuck".into());
        }
        if heartbeat_age_ms.is_some_and(|age| age > live.policy.heartbeat_max_age_ms)
            && !apply_progressing
        {
            liveness.reasons.push("runtime_heartbeat_stale".into());
        }
        liveness.ready = liveness.reasons.is_empty();
        let mut readiness = liveness.clone();
        if snapshot_age_ms > live.policy.snapshot_max_age_ms {
            readiness.reasons.push("runtime_snapshot_stale".into());
        }
        if snapshot.status.bootstrap.is_some() {
            readiness.reasons.push("bootstrap_in_progress".into());
        }
        if !snapshot.sync.headers_chain_synced {
            readiness.reasons.push("headers_syncing".into());
        }
        if !self.headers_only && !snapshot.sync.recovery_done {
            readiness.reasons.push("state_recovery_in_progress".into());
        }
        if !self.headers_only && snapshot.sync.gap > crate::snapshot::AT_TIP_GAP {
            readiness.reasons.push("blocks_syncing".into());
        }
        if snapshot.health.status != ergo_api::types::HealthStatus::Ok {
            // Headers-only nodes naturally have no full blocks; their sync-derived
            // health is ignored, while true bootstrap/deep-fork faults remain.
            if !self.headers_only
                || snapshot.health.status != ergo_api::types::HealthStatus::Stalled
                || snapshot.status.sync_wedged.is_some()
            {
                readiness.reasons.push(format!(
                    "node_{}",
                    serde_json::to_value(snapshot.health.status)
                        .unwrap()
                        .as_str()
                        .unwrap()
                ));
            }
        }
        if *tip > unix_ms.saturating_add(120_000) {
            readiness.reasons.push("chain_tip_clock_skew".into());
        }
        match tip_age_ms {
            None => readiness.reasons.push("chain_tip_unavailable".into()),
            Some(age) if age > live.policy.tip_max_age_ms => {
                readiness.reasons.push("chain_tip_stale".into())
            }
            _ => {}
        }
        if status.apply_wedged || status.last_storage_error.is_some() {
            readiness.reasons.push("runtime_or_storage_fault".into());
        }
        let height = if self.headers_only {
            snapshot.tip.best_header.height
        } else {
            snapshot.tip.best_full_block.height
        };
        if live.policy.require_indexer
            && (!deps.indexer_healthy || deps.indexer_height.is_none_or(|h| h < u64::from(height)))
        {
            readiness.reasons.push("indexer_not_ready".into());
        }
        if live.policy.require_wallet
            && (!deps.wallet_healthy || deps.wallet_height.is_none_or(|h| h < height))
        {
            readiness.reasons.push("wallet_not_ready".into());
        }
        readiness.ready = readiness.reasons.is_empty();
        NodeProbes {
            startup,
            liveness,
            readiness,
        }
    }
}

fn merge<T: serde::Serialize + serde::de::DeserializeOwned>(
    current: &T,
    patch: Option<Value>,
) -> Result<T, OperatorControlError> {
    let mut value =
        serde_json::to_value(current).map_err(|e| OperatorControlError::Invalid(e.to_string()))?;
    if let Some(patch) = patch {
        let object = patch.as_object().ok_or_else(|| {
            OperatorControlError::Invalid("runtime patch members must be JSON objects".into())
        })?;
        for (key, value_patch) in object {
            value
                .as_object_mut()
                .unwrap()
                .insert(key.clone(), value_patch.clone());
        }
    }
    serde_json::from_value(value).map_err(|e| OperatorControlError::Invalid(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use ergo_api::types::HealthStatus;

    fn config() -> NodeConfig {
        NodeConfig::load(crate::config::Cli::parse_from([
            "ergo-node",
            "--network",
            "devnet",
            "--peers",
            "127.0.0.1:1",
        ]))
        .unwrap()
    }

    #[test]
    fn patch_is_atomic_redacted_and_revision_checked() {
        let mut config = config();
        config.api_key_hash = Some("a".repeat(64));
        let control = RuntimeControl::new(&config).unwrap();
        let before = control.effective_config();
        assert!(!before.to_string().contains(&"a".repeat(64)));
        let bad = serde_json::from_value(
            json!({"api_limits":{"burst":80}, "readiness":{"tip_max_age_ms":0}}),
        )
        .unwrap();
        assert!(control.patch(bad).is_err());
        assert_eq!(control.effective_config(), before);
        let good = serde_json::from_value(json!({"expected_revision":0,"api_limits":{"burst":80}}))
            .unwrap();
        let result = control.patch(good).unwrap();
        assert_eq!(result["revision"], 1);
        assert_eq!(
            result["runtime"]["api_limits"]["burst"].as_f64(),
            Some(80.0)
        );
        assert!(control
            .patch(
                serde_json::from_value(json!({"expected_revision":0,"api_limits":{"burst":90}}))
                    .unwrap()
            )
            .is_err());
        assert!(
            serde_json::from_value::<RuntimeConfigPatch>(json!({"network":"mainnet"})).is_err()
        );
    }

    #[test]
    fn sync_is_live_but_unready_and_stale_heartbeat_fails_liveness() {
        let control = RuntimeControl::new(&config()).unwrap();
        let now = Instant::now();
        let mut snapshot = crate::snapshot::NodeSnapshot::empty(
            ergo_api::types::ApiInfo {
                agent_name: "test".into(),
                node_name: "test".into(),
                network: "devnet".into(),
                version: "test".into(),
                started_at_unix_ms: 0,
                uptime_seconds: 0,
                target_block_interval_ms: 120_000,
            },
            ergo_api::types::ApiWeightFunction::Cost,
        );
        assert!(!control.probes_at(&snapshot, now, 100_000).startup.ready);
        control.beat();
        snapshot.health.status = HealthStatus::Ok;
        snapshot.tip.best_full_block.timestamp_unix_ms = 100_000;
        snapshot.sync.headers_chain_synced = true;
        snapshot.sync.gap = 3;
        let probes = control.probes_at(&snapshot, now, 100_000);
        assert!(probes.startup.ready);
        assert!(probes.liveness.ready);
        assert!(!probes.readiness.ready);
        assert!(probes.readiness.reasons.contains(&"blocks_syncing".into()));
        snapshot.sync.gap = 0;
        snapshot.sync.recovery_done = true;
        assert!(control.probes_at(&snapshot, now, 100_000).readiness.ready);
        let later = now + std::time::Duration::from_secs(601);
        assert!(!control.probes_at(&snapshot, later, 161_000).liveness.ready);
        control.stop();
        assert!(!control.probes_at(&snapshot, now, 100_000).startup.ready);
    }

    #[test]
    fn bounded_apply_keeps_stale_heartbeat_live_but_idle_or_wedged_does_not() {
        let mut config = config();
        config.api_readiness.heartbeat_max_age_ms = 60_000;
        let control = RuntimeControl::new(&config).unwrap();
        control.beat();
        let mut snapshot = probe_snapshot();
        let now = Instant::now() + std::time::Duration::from_secs(180);
        assert!(!control.probes_at(&snapshot, now, 0).liveness.ready);
        snapshot.status.apply_age_ms = Some(180_000);
        assert!(control.probes_at(&snapshot, now, 0).liveness.ready);
        snapshot.status.apply_age_ms = Some(600_000);
        assert!(!control.probes_at(&snapshot, now, 0).liveness.ready);
        snapshot.status.apply_age_ms = Some(180_000);
        snapshot.status.apply_wedged = true;
        assert!(!control.probes_at(&snapshot, now, 0).liveness.ready);
        control.stop();
        snapshot.status.apply_wedged = false;
        assert!(!control.probes_at(&snapshot, now, 0).liveness.ready);
        assert_eq!(ProbePolicy::default().heartbeat_max_age_ms, 600_000);
    }

    fn probe_snapshot() -> NodeSnapshot {
        NodeSnapshot::empty(
            ergo_api::types::ApiInfo {
                agent_name: "test".into(),
                node_name: "test".into(),
                network: "devnet".into(),
                version: "test".into(),
                started_at_unix_ms: 0,
                uptime_seconds: 0,
                target_block_interval_ms: 120_000,
            },
            ergo_api::types::ApiWeightFunction::Cost,
        )
    }

    #[test]
    fn readiness_tolerates_at_tip_gap_and_long_network_block_interval() {
        let control = RuntimeControl::new(&config()).unwrap();
        control.beat();
        let mut snapshot = probe_snapshot();
        snapshot.health.status = HealthStatus::Ok;
        snapshot.sync.headers_chain_synced = true;
        snapshot.sync.recovery_done = true;
        snapshot.tip.best_full_block.timestamp_unix_ms = 1_000_000;
        for gap in 0..=crate::snapshot::AT_TIP_GAP {
            snapshot.sync.gap = gap;
            assert!(
                control
                    .probes_at(&snapshot, Instant::now(), 2_800_000)
                    .readiness
                    .ready
            );
        }
        snapshot.sync.gap = crate::snapshot::AT_TIP_GAP + 1;
        assert!(
            !control
                .probes_at(&snapshot, Instant::now(), 2_800_000)
                .readiness
                .ready
        );
        snapshot.sync.gap = 0;
        assert!(
            !control
                .probes_at(&snapshot, Instant::now(), 8_200_001)
                .readiness
                .ready
        );
    }

    #[test]
    fn probes_only_read_and_disclose_required_dependencies() {
        let control = RuntimeControl::new(&config()).unwrap();
        control.beat();
        control.set_dependencies(Arc::new(|_, _| {
            panic!("optional dependencies must not be read")
        }));
        let snapshot = probe_snapshot();
        let report = control.probes_at(&snapshot, Instant::now(), 0).readiness;
        assert!(report.indexer_height.is_none());
        assert!(report.wallet_height.is_none());
        control
            .patch(serde_json::from_value(json!({"readiness":{"require_indexer":true}})).unwrap())
            .unwrap();
        control.set_dependencies(Arc::new(|indexer, wallet| {
            assert!(indexer);
            assert!(!wallet);
            Dependencies {
                indexer_height: Some(10),
                wallet_height: Some(12),
                ..Default::default()
            }
        }));
        let report = control.probes_at(&snapshot, Instant::now(), 0).readiness;
        assert_eq!(report.indexer_height, Some(10));
        assert!(report.wallet_height.is_none());
    }

    #[test]
    fn stop_releases_storage_dependencies_even_if_control_is_retained() {
        let control = RuntimeControl::new(&config()).unwrap();
        let dependency = Arc::new(());
        let weak = Arc::downgrade(&dependency);
        control.set_dependencies(Arc::new(move |_, _| {
            let _keep_alive = &dependency;
            Dependencies::default()
        }));
        assert!(weak.upgrade().is_some());
        control.stop();
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn required_dependencies_and_tip_freshness_gate_readiness() {
        let mut config = config();
        config.api_readiness.require_indexer = true;
        config.api_readiness.require_wallet = true;
        let control = RuntimeControl::new(&config).unwrap();
        control.beat();
        let now = Instant::now();
        let mut snapshot = crate::snapshot::NodeSnapshot::empty(
            ergo_api::types::ApiInfo {
                agent_name: "test".into(),
                node_name: "test".into(),
                network: "devnet".into(),
                version: "test".into(),
                started_at_unix_ms: 0,
                uptime_seconds: 0,
                target_block_interval_ms: 120_000,
            },
            ergo_api::types::ApiWeightFunction::Cost,
        );
        snapshot.health.status = HealthStatus::Ok;
        snapshot.sync.headers_chain_synced = true;
        snapshot.sync.recovery_done = true;
        snapshot.tip.best_full_block.height = 10;
        snapshot.tip.best_full_block.timestamp_unix_ms = 2_000_000;
        control.set_dependencies(Arc::new(|_, _| Dependencies {
            indexer_height: Some(9),
            indexer_healthy: true,
            wallet_height: Some(10),
            wallet_healthy: false,
        }));
        let report = control.probes_at(&snapshot, now, 2_000_000).readiness;
        assert!(report.reasons.contains(&"indexer_not_ready".into()));
        assert!(report.reasons.contains(&"wallet_not_ready".into()));
        assert!(control.probes_at(&snapshot, now, 2_000_000).liveness.ready);
        control.set_dependencies(Arc::new(|_, _| Dependencies {
            indexer_height: Some(10),
            indexer_healthy: true,
            wallet_height: Some(10),
            wallet_healthy: true,
        }));
        assert!(control.probes_at(&snapshot, now, 2_000_000).readiness.ready);
        snapshot.tip.best_full_block.timestamp_unix_ms = 1;
        assert!(control
            .probes_at(&snapshot, now, 8_000_000)
            .readiness
            .reasons
            .contains(&"chain_tip_stale".into()));
    }
}
