//! Per-tick state the publisher keeps to derive deltas (stall detection)
//! across snapshots, and the `publish` entry point that assembles + stores
//! a fresh [`NodeSnapshot`](super::NodeSnapshot) via [`build_snapshot`](super::build::build_snapshot).

use std::time::Instant;

use arc_swap::ArcSwap;
use ergo_api::types::{ApiInfo, ApiWeightFunction};

use super::build::build_snapshot;
use super::{NodeSnapshot, SnapshotHandle, SnapshotParts};

pub struct SnapshotPublisher {
    handle: SnapshotHandle,
    info: ApiInfo,
    started_at: Instant,
    /// Last time *either* the best-header height or the best-full-block
    /// height strictly advanced. Used as the stall clock during initial
    /// header-only sync (no full block has applied yet) — header advance
    /// must count as progress there, otherwise the node would flag
    /// itself stalled before block sync has even started.
    last_progress_at: Instant,
    /// Last time the best-full-block height strictly advanced. Once any
    /// block has applied (`last_full_block_height > 0`) this becomes the
    /// authoritative stall clock: header advances cannot mask a node
    /// that has stopped applying blocks while peers keep streaming
    /// fresh headers (the original `last_progress_at`-only behaviour
    /// failed to detect this).
    last_block_progress_at: Instant,
    last_header_height: u32,
    last_full_block_height: u32,
}

impl SnapshotPublisher {
    pub fn new(info: ApiInfo, started_at: Instant, weight_function: ApiWeightFunction) -> Self {
        let handle = std::sync::Arc::new(ArcSwap::from_pointee(NodeSnapshot::empty(
            info.clone(),
            weight_function,
        )));
        Self {
            handle,
            info,
            started_at,
            last_progress_at: started_at,
            last_block_progress_at: started_at,
            last_header_height: 0,
            last_full_block_height: 0,
        }
    }

    pub fn handle(&self) -> SnapshotHandle {
        self.handle.clone()
    }

    /// Refresh `info.uptime_seconds` and write a fresh snapshot built
    /// from the supplied projections.
    pub fn publish(&mut self, mut parts: SnapshotParts<'_>) {
        // Resolve n_bits on read failure (`*_n_bits == None`): carry the
        // last-known value forward, never a synthetic 0 — but ONLY when the
        // prior snapshot's value genuinely describes the SAME tip. A read
        // failure on a tip that has already advanced to a different block
        // must not silently relabel the OLD tip's difficulty as belonging
        // to the new one; skip publishing this tick instead; the next tick
        // retries the read. If the tip is live (height > 0) but there is no
        // real prior to carry — the very first publish on a non-empty
        // chain hit a header-read fault — likewise retain the previous
        // snapshot rather than publish a live tip with 0 difficulty (the
        // fault was already logged in `read_tip_n_bits`).
        let (prior_header_tip_id, prior_header_n_bits, prior_full_tip_id, prior_full_n_bits) = {
            let prior = self.handle.load();
            (
                prior.tip.best_header.header_id.clone(),
                prior.tip.best_header.n_bits,
                prior.tip.best_full_block.header_id.clone(),
                prior.tip.best_full_block.n_bits,
            )
        };
        if parts.best_header_n_bits.is_none() {
            let same_tip = hex::encode(parts.best_header_id) == prior_header_tip_id;
            if !same_tip || (parts.best_header_height > 0 && prior_header_n_bits == 0) {
                return;
            }
            parts.best_header_n_bits = Some(prior_header_n_bits);
        }
        if parts.best_full_block_n_bits.is_none() {
            let same_tip = hex::encode(parts.best_full_block_id) == prior_full_tip_id;
            if !same_tip || (parts.best_full_block_height > 0 && prior_full_n_bits == 0) {
                return;
            }
            parts.best_full_block_n_bits = Some(prior_full_n_bits);
        }
        let now = Instant::now();
        // A rollback (height dropping below the last-observed value -- a
        // reorg) resets the baseline DOWN to the new height. Without this,
        // re-applying blocks back through the pre-reorg height would never
        // register as "advanced" relative to the stale (higher) baseline,
        // so `last_block_progress_at` would sit frozen at its pre-reorg
        // value for the whole recovery replay -- an actively, successfully
        // recovering node would misreport itself as stalled if that replay
        // takes longer than `STALL_THRESHOLD_SECS`.
        if parts.best_header_height < self.last_header_height {
            self.last_header_height = parts.best_header_height;
        }
        if parts.best_full_block_height < self.last_full_block_height {
            self.last_full_block_height = parts.best_full_block_height;
        }
        let header_advanced = parts.best_header_height > self.last_header_height;
        let block_advanced = parts.best_full_block_height > self.last_full_block_height;
        if header_advanced || block_advanced {
            self.last_progress_at = now;
        }
        if block_advanced {
            self.last_block_progress_at = now;
        }
        if header_advanced {
            self.last_header_height = parts.best_header_height;
        }
        if block_advanced {
            self.last_full_block_height = parts.best_full_block_height;
        }
        // Once a block has applied, the authoritative stall signal is
        // block progress; header advances cannot reset it (the
        // header-only-resets-stall bug). Before the first block applies
        // the combined clock still wins so the initial header sync
        // doesn't flag itself stalled.
        let effective_progress_age_ms = if self.last_full_block_height > 0 {
            now.duration_since(self.last_block_progress_at).as_millis() as u64
        } else {
            now.duration_since(self.last_progress_at).as_millis() as u64
        };

        let mut info = self.info.clone();
        info.uptime_seconds = now.duration_since(self.started_at).as_secs();

        let snap = build_snapshot(parts, info, effective_progress_age_ms);
        self.handle.store(std::sync::Arc::new(snap));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_api::types::{ApiMempoolTransactions, HealthStatus};
    use ergo_primitives::digest::Digest32;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    fn fake_info() -> ApiInfo {
        ApiInfo {
            agent_name: "test".into(),
            node_name: "test".into(),
            network: "mainnet".into(),
            version: "0.0.0".into(),
            started_at_unix_ms: 0,
            uptime_seconds: 0,
            target_block_interval_ms: 120_000,
        }
    }

    fn make_parts<'a>(
        header_h: u32,
        full_h: u32,
        peers: &'a [&'a ergo_p2p::peer::PeerInfo],
    ) -> SnapshotParts<'a> {
        make_parts_with_ids(header_h, full_h, [1u8; 32], [3u8; 32], peers)
    }

    fn make_parts_with_ids<'a>(
        header_h: u32,
        full_h: u32,
        header_id: [u8; 32],
        full_id: [u8; 32],
        peers: &'a [&'a ergo_p2p::peer::PeerInfo],
    ) -> SnapshotParts<'a> {
        SnapshotParts {
            now_unix_ms: 0,
            snapshot_built_at: Instant::now(),
            best_header_height: header_h,
            best_header_id: header_id,
            best_header_parent_id: [2u8; 32],
            best_header_timestamp_ms: 1_700_000_000_000,
            best_full_block_height: full_h,
            best_full_block_id: full_id,
            best_full_block_parent_id: [4u8; 32],
            best_full_block_timestamp_ms: 1_700_000_000_000,
            // Captured Scala mainnet nBits (test-vectors scala_chainslice);
            // decodes to difficulty "263500538576896" — an external oracle.
            best_header_n_bits: Some(117_501_863),
            best_full_block_n_bits: Some(117_501_863),
            state_digest: [5u8; 33],
            headers_chain_synced: false,
            download_window: 384,
            pending_blocks: 0,
            recovery_done: false,
            peer_count: 1,
            mempool_size: 0,
            mempool_total_bytes: 0,
            mempool_capacity_count: 1000,
            mempool_capacity_bytes: 1024,
            mempool_revalidation_pending: 0,
            mempool_transactions: ApiMempoolTransactions {
                transactions: Vec::new(),
                weight_function: ApiWeightFunction::Cost,
            },
            peers,
            best_header_score: Vec::new(),
            best_full_block_score: Vec::new(),
            genesis_block_id: [0u8; 32],
            last_seen_message_unix_ms: 0,
            last_mempool_update_unix_ms: 0,
            active_params: ergo_validation::scala_launch(),
            pool_outputs: Arc::new(HashMap::new()),
            pool_inputs: Arc::new(HashMap::new()),
            pool_full_txs: Arc::new(Vec::new()),
            peer_sync: Arc::new(HashMap::new()),
            delivery_counts: super::super::DeliveryCounters::default(),
            banned_ips: Arc::new(Vec::new()),
            bootstrap: None,
            recent_blocks: Arc::new(Vec::new()),
            events: Arc::new(ergo_api::types::ApiNodeEvents::default()),
            reorgs: Arc::new(ergo_api::types::ApiReorgHistory::default()),
            max_peer_height: 0,
            mining_enabled: false,
            snapshot_manifests: Vec::new(),
            last_block_apply_error: None,
            block_apply_errors_total: 0,
            sync_wedged: None,
            shadow: None,
            mempool_tx_requested_total: 0,
            mempool_peer_tx_admitted_total: 0,
            mempool_peer_tx_rejected_total: 0,
        }
    }

    /// Wiring + oracle-parity: the tip surfaces the header's `n_bits` and
    /// the difficulty decoded from it. The `(n_bits, difficulty)` pair is
    /// captured from a Scala mainnet header (not self-derived), so this
    /// also pins `decode_compact_bits` against the reference value.
    #[test]
    fn tip_surfaces_n_bits_and_scala_difficulty() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        publisher.publish(make_parts(100, 100, &[]));
        let snap = publisher.handle().load_full();
        assert_eq!(snap.tip.best_header.n_bits, 117_501_863);
        assert_eq!(snap.tip.best_header.difficulty, "263500538576896");
        assert_eq!(snap.tip.best_full_block.n_bits, 117_501_863);
        assert_eq!(snap.tip.best_full_block.difficulty, "263500538576896");
    }

    /// A header-read failure (`n_bits == None`) on the SAME tip (height can
    /// still advance from e.g. header/full-block asymmetry, but the header_id
    /// itself hasn't changed — a transient re-read of the identical block)
    /// carries the prior snapshot's difficulty forward — never a false-zero
    /// (a 0 fallback would flicker `/info difficulty` to 0 on a transient
    /// read fault).
    #[test]
    fn snapshot_carries_n_bits_forward_on_read_failure_for_same_tip() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        let header_id = [7u8; 32];
        let full_id = [9u8; 32];
        publisher.publish(make_parts_with_ids(100, 100, header_id, full_id, &[]));
        let mut parts = make_parts_with_ids(100, 100, header_id, full_id, &[]);
        parts.best_header_n_bits = None;
        parts.best_full_block_n_bits = None;
        publisher.publish(parts);
        let snap = publisher.handle().load_full();
        assert_eq!(snap.tip.best_header.n_bits, 117_501_863);
        assert_eq!(snap.tip.best_header.difficulty, "263500538576896");
        assert_ne!(snap.tip.best_header.difficulty, "0");
    }

    /// A header-read failure on a tip that has advanced to a DIFFERENT
    /// header_id must NOT carry the OLD tip's difficulty forward under the
    /// new tip's identity — that would misreport a stale value as belonging
    /// to a block it was never read from. The publish is skipped entirely
    /// (the prior snapshot, still describing the old tip, is retained
    /// unchanged) until a later tick reads the new tip's difficulty
    /// successfully.
    #[test]
    fn snapshot_skips_publish_on_read_failure_for_a_new_tip() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        publisher.publish(make_parts_with_ids(100, 100, [1u8; 32], [3u8; 32], &[]));
        let mut parts = make_parts_with_ids(101, 101, [11u8; 32], [13u8; 32], &[]);
        parts.best_header_n_bits = None;
        parts.best_full_block_n_bits = None;
        publisher.publish(parts);
        let snap = publisher.handle().load_full();
        // Unchanged: still the height-100 snapshot from the first publish,
        // not a height-101 snapshot wearing the old tip's difficulty.
        assert_eq!(snap.tip.best_header.height, 100);
        assert_eq!(snap.tip.best_header.n_bits, 117_501_863);
    }

    /// First publish on a non-empty chain whose tip header is unreadable
    /// (`n_bits == None`, no real prior to carry): the publisher retains
    /// the empty pre-publish snapshot rather than emit a live tip with 0
    /// difficulty.
    #[test]
    fn first_publish_with_unreadable_n_bits_retains_empty_not_live_zero() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        let mut parts = make_parts(100, 100, &[]);
        parts.best_header_n_bits = None;
        parts.best_full_block_n_bits = None;
        publisher.publish(parts);
        let snap = publisher.handle().load_full();
        // Retained the empty snapshot — no live tip with a synthetic 0.
        assert_eq!(snap.tip.best_header.height, 0);
        assert_eq!(snap.tip.best_header.difficulty, "0");
    }

    /// During IBD, `best_header` runs far ahead of `best_full_block`.
    /// The DTO must surface both — collapsing them would lose the
    /// information operators rely on to see header-sync progress while
    /// blocks are still at genesis. Regresses the splitting that was
    /// the motivating reason for the `ApiTip` schema.
    #[test]
    fn tip_dto_splits_header_and_full_block_during_ibd() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        publisher.publish(make_parts(31_881, 0, &[]));
        let snap = publisher.handle().load_full();

        assert_eq!(snap.tip.best_header.height, 31_881);
        assert_eq!(snap.tip.best_full_block.height, 0);
        assert_eq!(snap.tip.headers_ahead_of_full_blocks, 31_881);
        assert_eq!(snap.status.headers_ahead_of_full_blocks, 31_881);
        assert_eq!(snap.sync.gap, 31_881);
        assert_eq!(snap.sync.best_header_height, 31_881);
        assert_eq!(snap.sync.best_full_block_height, 0);
    }

    /// Header-only progress must reset the stall clock *during initial
    /// header sync* (no full block has applied yet). Before the first
    /// block applies, headers running ahead is the only progress signal
    /// available, so flipping the node to `Stalled` would be wrong.
    #[test]
    fn header_only_progress_resets_stall_clock_pre_first_block() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);

        publisher.publish(make_parts(100, 0, &[]));
        let age0 = publisher.handle().load_full().health.last_progress_age_ms;
        assert!(age0 < 100, "first publish should be fresh, got {age0}ms");

        sleep(Duration::from_millis(80));
        publisher.publish(make_parts(200, 0, &[]));
        let age_after_header = publisher.handle().load_full().health.last_progress_age_ms;
        assert!(
            age_after_header < 50,
            "header-only advance must reset stall clock pre-first-block, got {age_after_header}ms",
        );

        sleep(Duration::from_millis(120));
        publisher.publish(make_parts(200, 0, &[]));
        let age_after_idle = publisher.handle().load_full().health.last_progress_age_ms;
        assert!(
            age_after_idle >= 100,
            "no advance must let stall clock grow, got {age_after_idle}ms",
        );
    }

    /// Once at least one block has applied, the stall clock tracks
    /// **block** progress only — header-only advance must NOT reset it.
    /// This was the silent-stall bug: a node stuck applying block N+1
    /// while peers kept streaming headers showed `sync_state=syncing`
    /// indefinitely, because every header tick reset the combined
    /// clock. Now the publisher uses `last_block_progress_at` as the
    /// authoritative clock once `last_full_block_height > 0`.
    #[test]
    fn header_only_progress_does_not_mask_block_stall_post_first_block() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);

        // First block applies — switches publisher to block-progress mode.
        publisher.publish(make_parts(100, 50, &[]));
        let age0 = publisher.handle().load_full().health.last_progress_age_ms;
        assert!(age0 < 100, "first publish should be fresh, got {age0}ms");

        // Headers advance, blocks stuck. The block clock must keep
        // running; header advance must NOT mask the stall.
        sleep(Duration::from_millis(80));
        publisher.publish(make_parts(200, 50, &[]));
        let age_after_header = publisher.handle().load_full().health.last_progress_age_ms;
        assert!(
            age_after_header >= 80,
            "header-only advance must not reset the block-stall clock, got {age_after_header}ms",
        );

        // Block finally advances — clock resets.
        publisher.publish(make_parts(200, 51, &[]));
        let age_after_block = publisher.handle().load_full().health.last_progress_age_ms;
        assert!(
            age_after_block < 50,
            "block advance must reset stall clock, got {age_after_block}ms",
        );
    }

    /// A reorg (`best_full_block_height` dropping below a previously
    /// observed value) must not freeze the stall clock at its pre-reorg
    /// baseline: once the baseline resets down to the post-reorg height,
    /// blocks re-applied through the (lower) recovery range are recognized
    /// as forward progress again and refresh `last_block_progress_at` -- an
    /// actively recovering node must not be misreported as stalled while
    /// replaying back up toward its pre-reorg height.
    #[test]
    fn rollback_resets_stall_baseline_so_recovery_progress_is_recognized() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);

        // Chain climbs to height 100 pre-reorg.
        publisher.publish(make_parts(100, 100, &[]));

        // Reorg drops the tip to height 90. Without the baseline reset,
        // last_full_block_height would stay pinned at 100.
        sleep(Duration::from_millis(80));
        publisher.publish(make_parts(90, 90, &[]));

        // Recovery re-applies through height 95 -- still below the
        // pre-reorg height of 100, but above the (correctly reset) new
        // baseline of 90.
        sleep(Duration::from_millis(80));
        publisher.publish(make_parts(95, 95, &[]));
        let age = publisher.handle().load_full().health.last_progress_age_ms;
        assert!(
            age < 50,
            "recovery progress through the reorg range must refresh the stall clock, got {age}ms",
        );
    }

    /// `active_params` must travel through `SnapshotParts → build_snapshot
    /// → NodeSnapshot` so the API bridge sees exactly what the publisher
    /// read from `voted_params`. A field added to one struct but not
    /// threaded would silently fall back to the test-default `scala_launch`
    /// here — this guard catches that.
    #[test]
    fn active_params_round_trips_through_snapshot() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        let mut parts = make_parts(1_024, 1_024, &[]);
        let mut p = ergo_validation::scala_launch();
        p.epoch_start_height = 1024;
        p.input_cost = 7777;
        p.subblocks_per_block = Some(30);
        parts.active_params = p.clone();

        publisher.publish(parts);
        let snap = publisher.handle().load_full();

        assert_eq!(snap.active_params, p);
    }

    /// `pool_inputs` must travel through `SnapshotParts → build_snapshot
    /// → NodeSnapshot` alongside `pool_outputs`. Same threading guard as
    /// `active_params_round_trips_through_snapshot`: if a reader can't
    /// see a value the publisher set, the overlay would silently behave
    /// like `NoopMempoolView` even when the pool has entries.
    #[test]
    fn pool_inputs_round_trip_through_snapshot() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        let mut parts = make_parts(1, 1, &[]);

        let spent_box = Digest32::from_bytes([0xAA; 32]);
        let spending_tx = Digest32::from_bytes([0xBB; 32]);
        let mut inputs = HashMap::new();
        inputs.insert(spent_box, spending_tx);
        parts.pool_inputs = Arc::new(inputs);

        publisher.publish(parts);
        let snap = publisher.handle().load_full();

        assert_eq!(snap.pool_inputs.len(), 1);
        assert_eq!(snap.pool_inputs.get(&spent_box), Some(&spending_tx));
    }

    /// A block-apply rejection threads from `SnapshotParts` through
    /// `build_snapshot` onto `status.last_block_apply_error` + the counter, AND
    /// overrides health to `Rejecting` (a node refusing blocks is unhealthy
    /// however the sync axis looks). Absent ⇒ `None` and the normal
    /// sync-derived health, never `Rejecting`.
    #[test]
    fn build_snapshot_surfaces_block_apply_rejection_and_health() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        let mut parts = make_parts(500, 500, &[]);
        parts.last_block_apply_error = Some(ergo_api::types::ApiBlockApplyError {
            block_id: "ab".repeat(32),
            height: 1234,
            reason: "tx invalid".to_string(),
            age_ms: 42,
        });
        parts.block_apply_errors_total = 3;
        publisher.publish(parts);
        let snap = publisher.handle().load_full();
        let e = snap
            .status
            .last_block_apply_error
            .as_ref()
            .expect("rejection surfaced on status");
        assert_eq!(e.height, 1234);
        assert_eq!(e.reason, "tx invalid");
        assert_eq!(snap.status.block_apply_errors_total, 3);
        assert_eq!(snap.health.status, HealthStatus::Rejecting);

        // No rejection set above ⇒ the three new mempool-gossip counters
        // default to 0 on this publish path.
        assert_eq!(snap.status.mempool_tx_requested_total, 0);
        assert_eq!(snap.status.mempool_peer_tx_admitted_total, 0);
        assert_eq!(snap.status.mempool_peer_tx_rejected_total, 0);

        // No rejection: None on status, and health is NOT Rejecting.
        let mut publisher2 =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        publisher2.publish(make_parts(500, 500, &[]));
        let snap2 = publisher2.handle().load_full();
        assert!(snap2.status.last_block_apply_error.is_none());
        assert_ne!(snap2.health.status, HealthStatus::Rejecting);
    }

    /// The terminal deep-fork wedge threads from `SnapshotParts` through
    /// `build_snapshot` onto `status.sync_wedged` AND overrides health to
    /// `Wedged` — winning even over an outstanding `Rejecting` (nothing can
    /// ever apply again without a resync, which is strictly worse).
    #[test]
    fn build_snapshot_surfaces_sync_wedge_and_health() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        let mut parts = make_parts(500, 500, &[]);
        parts.last_block_apply_error = Some(ergo_api::types::ApiBlockApplyError {
            block_id: "ab".repeat(32),
            height: 1234,
            reason: "tx invalid".to_string(),
            age_ms: 42,
        });
        parts.sync_wedged = Some(ergo_api::types::ApiSyncWedged {
            stuck_block_id: "b7".repeat(32),
            stuck_height: 434_471,
            fork_below_height: 434_271,
            max_rollback_depth: 200,
            age_ms: 1_000,
        });
        publisher.publish(parts);
        let snap = publisher.handle().load_full();
        let w = snap
            .status
            .sync_wedged
            .as_ref()
            .expect("wedge surfaced on status");
        assert_eq!(w.stuck_height, 434_471);
        assert_eq!(w.max_rollback_depth, 200);
        assert_eq!(snap.health.status, HealthStatus::Wedged);

        // Wedge CLEARS on the same publisher: a healthy publish replaces the
        // wedged snapshot (the production path — one publisher per process).
        publisher.publish(make_parts(500, 500, &[]));
        let snap2 = publisher.handle().load_full();
        assert!(snap2.status.sync_wedged.is_none());
        assert_ne!(snap2.health.status, HealthStatus::Wedged);
    }

    /// The three mempool-tx-gossip observability counters travel from
    /// `SnapshotParts` through `build_snapshot` onto `ApiStatus` (the
    /// `/metrics` source). Same threading guard as
    /// `build_snapshot_surfaces_block_apply_rejection_and_health`: a field
    /// added to one struct but not threaded would silently fall back to 0
    /// here, leaving the Prometheus counter stuck at zero.
    #[test]
    fn build_snapshot_carries_mempool_tx_gossip_counters() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        let mut parts = make_parts(500, 500, &[]);
        parts.mempool_tx_requested_total = 11;
        parts.mempool_peer_tx_admitted_total = 7;
        parts.mempool_peer_tx_rejected_total = 4;

        publisher.publish(parts);
        let snap = publisher.handle().load_full();

        assert_eq!(snap.status.mempool_tx_requested_total, 11);
        assert_eq!(snap.status.mempool_peer_tx_admitted_total, 7);
        assert_eq!(snap.status.mempool_peer_tx_rejected_total, 4);
    }

    /// `max_peer_height` and `mining_enabled` travel from `SnapshotParts`
    /// through `build_snapshot` to `NodeSnapshot`. A field added to one struct
    /// but not threaded would silently fall back to 0/false here.
    #[test]
    fn build_snapshot_carries_mining_enabled_and_max_peer_height() {
        let mut publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Cost);
        let mut parts = make_parts(500, 500, &[]);
        parts.max_peer_height = 1_000;
        parts.mining_enabled = true;

        publisher.publish(parts);
        let snap = publisher.handle().load_full();

        assert_eq!(snap.max_peer_height, 1_000);
        assert!(snap.mining_enabled);
    }

    /// Threading the configured weight function through `SnapshotPublisher::new`
    /// preserves it on the boot-empty snapshot — i.e. the constructor isn't
    /// hardcoded to `Cost`. A node booted with the `"size"` policy must emit
    /// `"size"` on the boot snapshot, not the default. Pins against accidental
    /// regression to a `Default::default()` shortcut on the publisher init
    /// path. (Post-publish snapshots carry whatever `SnapshotParts.mempool_transactions`
    /// the projection built — exercised indirectly via the `project_mempool_transactions`
    /// path in production, not here.)
    #[test]
    fn empty_snapshot_preserves_non_default_weight_function() {
        let publisher =
            SnapshotPublisher::new(fake_info(), Instant::now(), ApiWeightFunction::Size);
        let snap = publisher.handle().load_full();
        assert_eq!(
            snap.mempool_transactions.weight_function,
            ApiWeightFunction::Size,
            "boot-empty snapshot must carry the threaded weight function",
        );
    }
}
