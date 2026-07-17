//! Node status / lifecycle DTOs: the collapsed dashboard status, block
//! apply / deep-fork / shadow-validation alarms, UTXO + NiPoPoW
//! bootstrap progress, sync-pipeline state, and the health probe.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Single-call dashboard view: collapses sync + tip + peer count.
/// Polled at 1 Hz by the UI header strip.
///
/// Derives `Default` (like [`ApiIdentity`]) so test stubs can write
/// `ApiStatus { <overrides>, ..Default::default() }` and stop breaking
/// on every added field.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct ApiStatus {
    pub sync_state: SyncStateLabel,
    pub peer_count: u32,
    pub best_header_height: u32,
    pub best_full_block_height: u32,
    pub headers_ahead_of_full_blocks: u32,
    pub mempool_size: u32,
    pub snapshot_age_ms: u64,
    /// Mode 2 bootstrap progress. Populated while a UTXO snapshot
    /// bootstrap is in flight — i.e. operator config has
    /// `utxo_bootstrap = true` AND `best_full_block_height == 0`.
    /// Cleared (`None`) once the snapshot installs and the node
    /// transitions to normal block sync. Operators rendering the
    /// dashboard panel should treat `Some(_)` as "show the
    /// bootstrap card, hide the normal block-sync pipeline row".
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bootstrap: Option<ApiBootstrapStatus>,
    /// The most recent block this node REJECTED during apply — a consensus
    /// fork-from-network signal (the node refused a block its peers may have
    /// accepted). `None` when no rejection has occurred this session. A
    /// persistent `Some(_)` is an operator page.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_block_apply_error: Option<ApiBlockApplyError>,
    /// Monotonic count of block-apply rejections since node start (the
    /// `ergo_node_block_apply_errors_total` Prometheus counter source).
    /// Session-scoped — resets on restart, which `rate()` handles.
    #[serde(default)]
    pub block_apply_errors_total: u64,
    /// Terminal deep-fork wedge: the best-header chain forks below the
    /// state backend's rollback window, so this node can never reorg onto
    /// it and will not apply another block. A persistent `Some(_)` is an
    /// operator page — the only recovery is a resync (wipe the data dir
    /// and sync fresh). `None` in normal operation.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sync_wedged: Option<ApiSyncWedged>,
    /// Shadow-validation status (`[shadow]` — live cross-check against a
    /// Scala reference node). Present only when the mode is enabled.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub shadow: Option<ApiShadowStatus>,
    /// Monotonic count of unconfirmed-tx ids this node REQUESTED from peers
    /// in response to a tx-typed `Inv` (the
    /// `ergo_node_mempool_tx_requested_total` Prometheus counter source).
    /// Counts ids passed to the coordinator's `request_transactions`, i.e.
    /// the `unknown` (not-already-pooled / not-invalidated) advertised set.
    /// Session-scoped — resets on restart, which `rate()` handles.
    #[serde(default)]
    pub mempool_tx_requested_total: u64,
    /// Monotonic count of peer-sourced (`TxSource::Peer`) transactions
    /// ADMITTED to the mempool (the
    /// `ergo_node_mempool_peer_tx_admitted_total` Prometheus counter
    /// source). API/Wallet-sourced admissions are excluded. Session-scoped
    /// — resets on restart, which `rate()` handles.
    #[serde(default)]
    pub mempool_peer_tx_admitted_total: u64,
    /// Monotonic count of peer-sourced (`TxSource::Peer`) transactions
    /// REJECTED by admission (the
    /// `ergo_node_mempool_peer_tx_rejected_total` Prometheus counter
    /// source). API/Wallet-sourced rejections are excluded. Session-scoped
    /// — resets on restart, which `rate()` handles.
    #[serde(default)]
    pub mempool_peer_tx_rejected_total: u64,
    /// Session-total tip-replacement reorgs detected by the operator event
    /// differ (`ergo_node_reorg_total`).
    #[serde(default)]
    pub reorgs_total: u64,
    /// Depth of the most recent retained reorg, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reorg_depth: Option<u32>,
    /// Unix-ms of the most recent retained reorg, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reorg_unix_ms: Option<u64>,
    /// `1` while the action loop is inside full-block `process_block`
    /// (`ergo_node_apply_in_progress`). Live atomic — not snapshot-stale.
    #[serde(default)]
    pub apply_in_progress: bool,
    /// Wall-clock ms of the last finished apply attempt
    /// (`ergo_node_last_apply_duration_ms`).
    #[serde(default)]
    pub last_apply_duration_ms: u64,
    /// Height of the last *successful* full-block apply
    /// (`ergo_node_last_applied_height`). `0` until the first success.
    #[serde(default)]
    pub last_applied_height: u32,
    /// ms since the last finished apply attempt, if any
    /// (`ergo_node_last_apply_age_ms`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_apply_age_ms: Option<u64>,
}

/// A block this node rejected during apply, surfaced to operators. Distinct
/// from a benign data-wait (section not yet downloaded) or reorg — this is a
/// block the node refused on validation while its peers may have accepted it.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiBlockApplyError {
    /// Hex-encoded rejected header id.
    pub block_id: String,
    /// Height the rejected block claimed.
    pub height: u32,
    /// Operator-facing rejection reason (the `BlockProcessError` Display).
    pub reason: String,
    /// Milliseconds since the rejection was recorded (computed at read time).
    pub age_ms: u64,
}

/// Terminal deep-fork wedge, surfaced to operators. The best-header chain
/// (the heaviest chain the network is on) forks below this node's rollback
/// window: the undo data needed to reorg onto it was pruned, so block apply
/// is permanently stuck at `stuck_height` while headers keep advancing.
/// Matches the Scala reference node's `keepVersions` horizon — a Scala node
/// in the same position is equally unrecoverable. Only a resync recovers.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiSyncWedged {
    /// Hex-encoded id of the stuck full-block tip (on the abandoned branch).
    pub stuck_block_id: String,
    /// Height of the stuck full-block tip.
    pub stuck_height: u32,
    /// Lowest height the fork-point walk examined — the best-header chain
    /// still disagreed there, so the true fork is at or below it.
    pub fork_below_height: u32,
    /// The rollback window the fork depth exceeded.
    pub max_rollback_depth: u32,
    /// Milliseconds since the wedge was detected, computed when the snapshot
    /// is PUBLISHED (staleness bounded by `snapshot_age_ms`, ~1 s ticks) —
    /// not recomputed per read.
    pub age_ms: u64,
}

/// Shadow-validation status (`[shadow]`): the outcome of the live
/// cross-check against the configured Scala reference node. Sourced from
/// the watch task's shared state at snapshot publish; backs the
/// `ergo_node_shadow_*` Prometheus series and the `shadowDivergence`
/// operator event.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiShadowStatus {
    /// Reference answered on the most recent compare tick.
    pub reference_reachable: bool,
    /// Highest height a compare completed at (0 = none yet).
    pub last_compared_height: u32,
    /// Confirmed divergences since node start (monotonic).
    pub divergence_total: u64,
    /// The ACTIVE confirmed divergence, or `None` when the chains agree.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub diverged: Option<ApiShadowDivergence>,
}

/// One active shadow divergence: `header_mismatch` (this node and the
/// reference follow different canonical headers at `height`) or
/// `tip_stall` (the reference's full-block tip is advancing past ours).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiShadowDivergence {
    /// `header_mismatch | tip_stall`.
    pub kind: String,
    pub height: u32,
    /// Our canonical header id at `height` (empty for `tip_stall`).
    pub ours: String,
    /// The reference's canonical header id at `height` (empty for `tip_stall`).
    pub theirs: String,
}

/// Bootstrap progress for the Mode 2 (UTXO snapshot) consume side.
/// Surfaced to operators so the ~30–60 minute boot window doesn't
/// look like a stuck node (fullHeight=0, indexer=0%, etc.). Each
/// field maps directly to a dashboard cell or progress bar.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiBootstrapStatus {
    /// Current bootstrap phase. UI maps each variant to its human
    /// label and phase indicator.
    pub phase: ApiBootstrapPhase,
    /// Snapshot height as selected by the discovery quorum.
    /// `0` when still in `discovery` and no manifest has been picked.
    pub snapshot_height: u32,
    /// Hex-encoded manifest_id when known (post-discovery), else `None`.
    /// 32 bytes / 64 hex chars.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub manifest_id: Option<String>,
    /// Number of peers in the quorum that voted for the selected
    /// manifest. `0` during the `discovery` phase before quorum.
    pub voters: u32,
    /// Chunks received and committed to assembly. `0` until the
    /// `downloading_chunks` phase starts.
    pub chunks_received: u32,
    /// Total chunks expected per the verified manifest. `0` before
    /// `manifest_verified`.
    pub chunks_total: u32,
    /// `true` once the manifest's root label has been compared
    /// against the canonical header.state_root at `snapshot_height`
    /// and matched. False until the trust check fires.
    pub trust_check_passed: bool,
    /// Unix-ms timestamp when the bootstrap reducer first transitioned
    /// out of `Idle`. Lets the UI compute an "elapsed" clock without
    /// holding state of its own.
    pub started_unix_ms: u64,
    /// NiPoPoW bootstrap phase, when enabled. Absent when NiPoPoW
    /// bootstrap is disabled (legacy Mode 2-only flow) or hasn't
    /// started.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub popow_phase: Option<ApiPopowPhase>,
    /// Number of distinct peers that have responded with a NiPoPoW
    /// proof so far. `0` when popow_phase is absent or before any
    /// inbound proof.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub popow_providers: Option<u32>,
    /// Header-chain availability mode as reported by the store —
    /// `dense` for a full-node-sync history, `sparse` for a NiPoPoW-
    /// bootstrapped history. Absent when the store reports the
    /// default (Dense) and no NiPoPoW bootstrap is in progress.
    ///
    /// Distinct from [`ApiIdentity::history_mode`] — that field is the
    /// operator-configured chain-retention policy (archive / pruned /
    /// utxo-bootstrapped / headers-only), this field is the on-disk
    /// header-section shape (dense from genesis vs sparse with a
    /// NiPoPoW dense-suffix anchor).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub header_availability: Option<ApiHeaderAvailability>,
    /// In `HeaderAvailability::PoPowSparse` mode, the lowest height
    /// for which a `HEADER_CHAIN_INDEX` row exists locally. Heights
    /// below this are sparse-prefix witnesses (not chain-indexed).
    /// `None` when mode is Dense.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub popow_dense_from_height: Option<u32>,
}

/// UTXO snapshot bootstrap reducer phase, as surfaced on
/// [`ApiBootstrapStatus`]. UI maps each variant to a human label and
/// phase indicator.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiBootstrapPhase {
    /// Outbound peer-query fan-out; no manifest selected yet.
    Discovery,
    /// Manifest selected by quorum; download in flight.
    ManifestRequested,
    /// Manifest bytes verified against `header.state_root`; chunk
    /// download has not started yet.
    ManifestVerified,
    /// Chunk download in progress.
    DownloadingChunks,
    /// All chunks received; reconstructing the UTXO tree.
    Reconstructing,
    /// Tree reconstructed; install into the chain store in flight.
    Installing,
    /// Snapshot installed; catching up from snapshot height to tip.
    PostInstallCatchup,
}

/// NiPoPoW bootstrap reducer phase, as surfaced on
/// [`ApiBootstrapStatus::popow_phase`]. UI mirrors the UTXO bootstrap
/// progression but for the NiPoPoW chain-prefix path.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiPopowPhase {
    /// Outbound NiPoPoW proof requests in flight; quorum not yet met.
    Requesting,
    /// Quorum met; the dominant proof has been selected.
    QuorumMet,
    /// Proof applied to the chain state — `header_availability` is
    /// now `Sparse`.
    Applied,
    /// Bounded forward catch-up from the proof's anchor height in
    /// flight.
    Catchup,
}

/// Header-chain density reported by the chain store.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiHeaderAvailability {
    /// Full-node-sync header chain — every height has a row in
    /// `HEADER_CHAIN_INDEX`.
    Dense,
    /// NiPoPoW-bootstrapped history — heights below
    /// `popow_dense_from_height` are sparse-prefix witnesses, not
    /// chain-indexed.
    Sparse,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SyncStateLabel {
    /// No connected peers. The `Default` — matches the pre-first-publish
    /// snapshot (`SnapshotPublisher` empty state).
    #[default]
    Disconnected,
    /// Catching up — header chain not yet near tip, or block-application
    /// gap > tolerance.
    Syncing,
    /// Header chain synced, full-block tip within tolerance.
    AtTip,
    /// Connected but no progress within stall threshold.
    Stalled,
}

/// Sync pipeline state.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiSyncStatus {
    pub headers_chain_synced: bool,
    pub best_header_height: u32,
    pub best_full_block_height: u32,
    pub gap: u32,
    pub download_window: u32,
    pub pending_blocks: u32,
    pub recovery_done: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiHealth {
    pub status: HealthStatus,
    pub behind: u32,
    pub last_progress_age_ms: u64,
    pub peer_count: u32,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Ok,
    Stalled,
    Disconnected,
    /// A block-apply rejection is outstanding — the node refused a block its
    /// peers may have accepted (a possible consensus fork from the network).
    /// /health maps this to HTTP 503 so operators page on it.
    Rejecting,
    /// Terminal deep-fork wedge — the best-header chain forks below the
    /// rollback window and this node can never reorg onto it (see
    /// [`ApiSyncWedged`]). /health maps this to HTTP 503; the only recovery
    /// is a resync.
    Wedged,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- ApiBootstrapPhase: wire shape -----

    #[test]
    fn api_bootstrap_phase_serializes_to_canonical_lowercase() {
        for (variant, expected) in [
            (ApiBootstrapPhase::Discovery, "discovery"),
            (ApiBootstrapPhase::ManifestRequested, "manifest_requested"),
            (ApiBootstrapPhase::ManifestVerified, "manifest_verified"),
            (ApiBootstrapPhase::DownloadingChunks, "downloading_chunks"),
            (ApiBootstrapPhase::Reconstructing, "reconstructing"),
            (ApiBootstrapPhase::Installing, "installing"),
            (
                ApiBootstrapPhase::PostInstallCatchup,
                "post_install_catchup",
            ),
        ] {
            let got = serde_json::to_value(variant).unwrap();
            assert_eq!(got, serde_json::Value::String(expected.into()));
        }
    }

    #[test]
    fn api_bootstrap_phase_roundtrips_and_rejects_unknown() {
        for v in [
            ApiBootstrapPhase::Discovery,
            ApiBootstrapPhase::ManifestRequested,
            ApiBootstrapPhase::ManifestVerified,
            ApiBootstrapPhase::DownloadingChunks,
            ApiBootstrapPhase::Reconstructing,
            ApiBootstrapPhase::Installing,
            ApiBootstrapPhase::PostInstallCatchup,
        ] {
            let s = serde_json::to_string(&v).unwrap();
            let back: ApiBootstrapPhase = serde_json::from_str(&s).unwrap();
            assert_eq!(back, v);
        }
        let err = serde_json::from_value::<ApiBootstrapPhase>(serde_json::json!("paused"));
        assert!(err.is_err(), "unknown bootstrap phase must reject");
    }

    // ----- ApiPopowPhase: wire shape -----

    #[test]
    fn api_popow_phase_serializes_to_canonical_lowercase() {
        for (variant, expected) in [
            (ApiPopowPhase::Requesting, "requesting"),
            (ApiPopowPhase::QuorumMet, "quorum_met"),
            (ApiPopowPhase::Applied, "applied"),
            (ApiPopowPhase::Catchup, "catchup"),
        ] {
            let got = serde_json::to_value(variant).unwrap();
            assert_eq!(got, serde_json::Value::String(expected.into()));
        }
    }

    #[test]
    fn api_popow_phase_roundtrips_and_rejects_unknown() {
        for v in [
            ApiPopowPhase::Requesting,
            ApiPopowPhase::QuorumMet,
            ApiPopowPhase::Applied,
            ApiPopowPhase::Catchup,
        ] {
            let s = serde_json::to_string(&v).unwrap();
            let back: ApiPopowPhase = serde_json::from_str(&s).unwrap();
            assert_eq!(back, v);
        }
        let err = serde_json::from_value::<ApiPopowPhase>(serde_json::json!("aborted"));
        assert!(err.is_err(), "unknown popow phase must reject");
    }

    // ----- ApiHeaderAvailability: wire shape -----

    #[test]
    fn api_header_availability_serializes_to_canonical_lowercase() {
        for (variant, expected) in [
            (ApiHeaderAvailability::Dense, "dense"),
            (ApiHeaderAvailability::Sparse, "sparse"),
        ] {
            let got = serde_json::to_value(variant).unwrap();
            assert_eq!(got, serde_json::Value::String(expected.into()));
        }
    }

    #[test]
    fn api_header_availability_roundtrips_and_rejects_unknown() {
        for v in [ApiHeaderAvailability::Dense, ApiHeaderAvailability::Sparse] {
            let s = serde_json::to_string(&v).unwrap();
            let back: ApiHeaderAvailability = serde_json::from_str(&s).unwrap();
            assert_eq!(back, v);
        }
        let err = serde_json::from_value::<ApiHeaderAvailability>(serde_json::json!("partial"));
        assert!(
            err.is_err(),
            "unknown header availability variant must reject"
        );
    }

    fn bootstrap_status_with(
        phase: ApiBootstrapPhase,
        popow_phase: Option<ApiPopowPhase>,
        header_availability: Option<ApiHeaderAvailability>,
    ) -> ApiBootstrapStatus {
        ApiBootstrapStatus {
            phase,
            snapshot_height: 0,
            manifest_id: None,
            voters: 0,
            chunks_received: 0,
            chunks_total: 0,
            trust_check_passed: false,
            started_unix_ms: 0,
            popow_phase,
            popow_providers: None,
            header_availability,
            popow_dense_from_height: None,
        }
    }

    #[test]
    fn api_bootstrap_status_phase_serializes_to_each_canonical_literal() {
        for (variant, expected) in [
            (ApiBootstrapPhase::Discovery, "discovery"),
            (ApiBootstrapPhase::ManifestRequested, "manifest_requested"),
            (ApiBootstrapPhase::ManifestVerified, "manifest_verified"),
            (ApiBootstrapPhase::DownloadingChunks, "downloading_chunks"),
            (ApiBootstrapPhase::Reconstructing, "reconstructing"),
            (ApiBootstrapPhase::Installing, "installing"),
            (
                ApiBootstrapPhase::PostInstallCatchup,
                "post_install_catchup",
            ),
        ] {
            let v = serde_json::to_value(bootstrap_status_with(variant, None, None)).unwrap();
            assert_eq!(
                v["phase"],
                serde_json::Value::String(expected.into()),
                "phase wire literal must remain {expected}"
            );
        }
    }

    #[test]
    fn api_bootstrap_status_renames_history_mode_to_header_availability() {
        let v = serde_json::to_value(bootstrap_status_with(
            ApiBootstrapPhase::Discovery,
            None,
            Some(ApiHeaderAvailability::Sparse),
        ))
        .unwrap();
        let obj = v.as_object().expect("object");
        assert!(
            !obj.contains_key("history_mode"),
            "old key must not appear on the wire"
        );
        assert_eq!(
            obj.get("header_availability"),
            Some(&serde_json::Value::String("sparse".into())),
            "new key carries the value"
        );
    }

    #[test]
    fn api_bootstrap_status_omits_optional_fields_when_none() {
        let v = serde_json::to_value(bootstrap_status_with(
            ApiBootstrapPhase::Discovery,
            None,
            None,
        ))
        .unwrap();
        let obj = v.as_object().expect("object");
        for key in [
            "popow_phase",
            "header_availability",
            "popow_providers",
            "popow_dense_from_height",
            "manifest_id",
        ] {
            assert!(
                !obj.contains_key(key),
                "{key} must be omitted (not serialized as null) when None"
            );
        }
    }
}
