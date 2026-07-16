//! Per-tick snapshot publish: read `NodeState` into a `SnapshotParts`
//! and hand it to the runtime's `SnapshotPublisher` so the API layer
//! sees fresh observable state.
//!
//! [`publish_snapshot`] is the orchestrator; the field groups it collects
//! are built by sibling submodules:
//! - [`recent_blocks`] — the tip-cached recent-blocks tail + first-deliverer
//!   merge.
//! - [`bootstrap_panel`] — the Mode 2 bootstrap dashboard projection.
//! - [`mempool_projection`] — the mempool-transaction DTO list.
//! - [`events_projection`] — the operator event-feed DTO projection.

mod bootstrap_panel;
mod events_projection;
mod mempool_projection;
mod recent_blocks;

use ergo_primitives::reader::VlqReader;
use ergo_ser::header::read_header;
use ergo_state::reader::ChainStoreReader;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use std::sync::Arc;
use std::time::Instant;

use super::NodeState;
use crate::snapshot::{unix_now_ms, SnapshotParts};

/// Read a tip header's compact difficulty (`n_bits`). Height 0 = no tip
/// yet (legit 0, no read). For a real tip the header bytes are retained in
/// every mode, so a failure is a store/serializer fault — logged with its
/// cause; `None` then tells the publisher to retain the last-known value
/// (never a synthetic 0).
fn read_tip_n_bits(state: &NodeState, id: &[u8; 32], height: u32, which: &str) -> Option<u32> {
    if height == 0 {
        return Some(0);
    }
    match state.store.get_header(id) {
        Ok(Some(bytes)) => match read_header(&mut VlqReader::new(&bytes)) {
            Ok(h) => Some(h.n_bits),
            Err(e) => {
                tracing::error!(error = %e, which, "snapshot: tip header parse failed; carrying prior difficulty");
                None
            }
        },
        Ok(None) => {
            tracing::error!(
                which,
                "snapshot: tip header bytes absent; carrying prior difficulty"
            );
            None
        }
        Err(e) => {
            tracing::error!(error = %e, which, "snapshot: tip header read failed; carrying prior difficulty");
            None
        }
    }
}

/// Build the operator-API snapshot once per sync_tick.
///
/// Bounded work: collects connected peers (capped naturally by socket
/// count), reads `chain_state()` + `root_digest()` (already on the hot
/// path for the heartbeat above), one `get_header_meta` lookup each for
/// the best-header and best-full-block tips, a priority-ordered mempool
/// walk capped by `MempoolConfig::max_pool_size`, and the recent-blocks
/// tail — which is cached by the full-block tip id and rebuilt only when
/// the tip advances (`recent_blocks::recent_blocks_for_tip`), so steady-state
/// ticks pay a single id comparison rather than 32 header + section reads.
pub(super) fn publish_snapshot(state: &mut NodeState, now: Instant) {
    let now_unix_ms = unix_now_ms();
    let bootstrap = bootstrap_panel::build_bootstrap_status(state, now_unix_ms);
    let cs = state.store.chain_state_meta();
    let cs_best_header_id = cs.best_header_id;
    let cs_best_full_block_id = cs.best_full_block_id;
    let cs_best_header_height = cs.best_header_height;
    let cs_best_full_block_height = cs.best_full_block_height;

    let (best_header_parent, best_header_ts, best_header_score) = state
        .store
        .get_header_meta(&cs_best_header_id)
        .ok()
        .flatten()
        .map(|m| (m.parent_id, m.timestamp, m.cumulative_score))
        .unwrap_or(([0u8; 32], 0, Vec::new()));
    let (best_full_parent, best_full_ts, best_full_block_score) = state
        .store
        .get_header_meta(&cs_best_full_block_id)
        .ok()
        .flatten()
        .map(|m| (m.parent_id, m.timestamp, m.cumulative_score))
        .unwrap_or(([0u8; 32], 0, Vec::new()));
    // Difficulty surface: HeaderMeta doesn't carry `n_bits`, so deserialize
    // each tip header for it. Height 0 = no tip yet (legit 0); for a real
    // tip a failure is a store/serializer fault, logged with its cause, and
    // `None` tells the publisher to carry the last-known value forward
    // (never a synthetic 0).
    let best_header_n_bits = read_tip_n_bits(
        state,
        &cs_best_header_id,
        cs_best_header_height,
        "best_header",
    );
    let best_full_block_n_bits = read_tip_n_bits(
        state,
        &cs_best_full_block_id,
        cs_best_full_block_height,
        "best_full_block",
    );
    // Ergo genesis is height 1 in HEADER_CHAIN_INDEX (h=0 is never written —
    // see `rewrite_best_chain_into_index` walk terminating at cur_height == 1).
    // Matches Scala's chain numbering.
    let genesis_block_id = state
        .store
        .get_header_id_at_height(1)
        .ok()
        .flatten()
        .unwrap_or([0u8; 32]);

    // Backend-agnostic tip state-root digest (UTXO arena root or digest
    // verifier's ADProof-derived root); both equal the tip header's
    // `state_root`. A digest-backend (Mode 5) node publishes a real value
    // here rather than panicking on a UTXO-only assumption.
    let state_digest = state.store.state_root_digest();
    // Recent-blocks tail for the dashboard, cached by the full-block tip
    // id (rebuilt only when the tip advances — see
    // `recent_blocks::recent_blocks_for_tip`).
    //
    // Anchored to the *committed* full-block tip, not the in-memory
    // `cs_best_full_block_id`: section bytes are committed before the apply
    // that advances `chain_state_meta`, so the committed tip's sections are
    // always durably readable. Anchoring there keeps the list internally
    // coherent — its newest entry is a block whose sections actually exist —
    // rather than claiming a tip whose sections are still in flight on the
    // async persist pipeline. Computed here, before `peers_vec` borrows
    // `state.peer_manager`, so the `&mut state.recent_blocks_cache` borrow
    // has no live aliases; the two arguments touch disjoint `NodeState`
    // fields.
    let recent_blocks_committed = match ChainStoreReader::new_from_db(state.store.db_arc())
        .committed_tip()
    {
        Ok(Some((tip_height, tip_id))) => recent_blocks::recent_blocks_for_tip(
            &mut state.recent_blocks_cache,
            &state.store,
            tip_id,
            tip_height,
            state.network,
        ),
        // No committed full-block chain yet, or a transient read fault:
        // serve an empty tail this tick (best-effort; recovers next tick).
        Ok(None) => Arc::new(Vec::new()),
        Err(e) => {
            tracing::warn!(error = %e, "recent_blocks: committed_tip read failed; serving empty tail");
            Arc::new(Vec::new())
        }
    };
    // Merge the transient first-deliverer fact onto the committed,
    // tip-cached tail. The cache holds committed-state only (so its Arc
    // can be reused across ticks until the tip advances); `delivered_by`
    // is a live P2P observation that can land AFTER the tip cached, so it
    // is layered on here at serve-build time. Returns the same Arc
    // untouched when no block in the window has a recorded deliverer (the
    // steady-state synced case), so the common path stays allocation-free.
    let recent_blocks =
        recent_blocks::merge_delivered_by(recent_blocks_committed, &state.first_deliverer_ring);
    let download_window = state.coordinator.sync_state().download_window() as u32;
    let pending_blocks = state.coordinator.sync_state().pending_count() as u32;
    let headers_chain_synced = state.coordinator.sync_state().headers_chain_synced();
    let max_peer_height = state.coordinator.sync_state().best_known_header_height();
    let recovery_done = state.executor.recovery_done();
    // Project the executor's most recent block-apply REJECTION to the
    // API DTO, computing `age_ms` from the captured `Instant` against this
    // snapshot's `now` (the executor stores an `Instant`, not a wall-clock).
    let block_apply_errors_total = state.executor.block_apply_error_count();
    let last_block_apply_error =
        state
            .executor
            .last_block_apply_error()
            .map(|e| ergo_api::types::ApiBlockApplyError {
                block_id: hex::encode(e.header_id),
                height: e.height,
                reason: e.reason.clone(),
                age_ms: now.saturating_duration_since(e.at).as_millis() as u64,
            });
    // Terminal deep-fork wedge, projected the same way (age at publish time).
    let sync_wedged = state
        .executor
        .deep_fork_wedge()
        .map(|w| ergo_api::types::ApiSyncWedged {
            stuck_block_id: hex::encode(w.best_full_id),
            stuck_height: w.best_full_height,
            fork_below_height: w.scanned_to_height,
            max_rollback_depth: w.max_rollback_depth,
            age_ms: now.saturating_duration_since(w.since).as_millis() as u64,
        });

    // Shadow-validation outcome (None when the mode is off).
    let shadow = state.shadow.as_ref().map(|sh| {
        use std::sync::atomic::Ordering;
        ergo_api::types::ApiShadowStatus {
            reference_reachable: !sh.reference_unreachable.load(Ordering::Relaxed),
            last_compared_height: sh.last_compared_height.load(Ordering::Relaxed),
            divergence_total: sh.divergence_total.load(Ordering::Relaxed),
            diverged: sh
                .snapshot_active()
                .map(|d| ergo_api::types::ApiShadowDivergence {
                    kind: d.kind.to_string(),
                    height: d.height,
                    ours: d.ours,
                    theirs: d.theirs,
                }),
        }
    });

    let peer_count = state.peer_manager.connected_peers().count() as u32;
    let peers_vec: Vec<&ergo_p2p::peer::PeerInfo> = state.peer_manager.connected_peers().collect();
    // Most-recent peer message: convert each peer's `last_seen` Instant to
    // wall-clock by subtracting from `now_unix_ms`. 0 if no peers.
    let last_seen_message_unix_ms = peers_vec
        .iter()
        .map(|p| {
            let age_ms = now.saturating_duration_since(p.last_seen).as_millis() as u64;
            now_unix_ms.saturating_sub(age_ms)
        })
        .max()
        .unwrap_or(0);

    let mempool_size = state.mempool.size() as u32;
    let mempool_total_bytes = state.mempool.total_bytes() as u64;
    let mempool_capacity_count = state.mempool.config().max_pool_size as u32;
    let mempool_capacity_bytes = state.mempool.config().max_pool_bytes as u64;
    let mempool_revalidation_pending = state.mempool.revalidation_pending() as u32;
    let mempool_transactions = mempool_projection::project_mempool_transactions(
        &state.mempool,
        state.api_weight_function,
        now,
        now_unix_ms,
    );
    let last_mempool_update_unix_ms = mempool_transactions
        .transactions
        .iter()
        .map(|t| t.first_seen_unix_ms)
        .max()
        .unwrap_or(0);
    // Snapshot the pool overlays once per tick. Bounded by
    // `MempoolConfig::max_pool_size`; entries with no materialized
    // output_boxes contribute nothing to `pool_outputs`.
    // `pool_inputs` is the `by_input` index — spent committed-box id
    // → pool tx — used by the extra-index mempool overlay.
    let pool_outputs = Arc::new(state.mempool.pool_output_overlay());
    let pool_inputs = Arc::new(state.mempool.pool_input_overlay());

    // Per-peer sync-info projection — Scala's
    // `syncTracker.fullInfo` analogue. Snapshotted from
    // `SyncCoordinator::peer_sync_snapshots()` and projected to a
    // leaf-type map the api bridge can read without depending on
    // ergo-p2p / ergo-sync types.
    let peer_sync: Arc<
        std::collections::HashMap<std::net::SocketAddr, crate::snapshot::PeerSyncProjection>,
    > = Arc::new(
        state
            .coordinator
            .peer_sync_snapshots()
            .iter()
            .map(|(peer, snap)| {
                use ergo_p2p::sync::PeerChainStatus;
                let status: &'static str = match snap.status {
                    PeerChainStatus::Equal => "Equal",
                    PeerChainStatus::Younger => "Younger",
                    PeerChainStatus::Older => "Older",
                    PeerChainStatus::Fork => "Fork",
                    PeerChainStatus::Unknown => "Unknown",
                    PeerChainStatus::Nonsense => "Nonsense",
                };
                (
                    *peer,
                    crate::snapshot::PeerSyncProjection {
                        status,
                        peer_height: snap.peer_height,
                    },
                )
            })
            .collect(),
    );

    // Delivery-tracker counters — Scala's
    // `deliveryTracker.fullInfo` triple. Caps each counter at
    // u32::MAX (saturating) so a long-lived node with high
    // received-set churn can't overflow the wire u32.
    let delivery_counts = {
        let d = state.coordinator.delivery();
        crate::snapshot::DeliveryCounters {
            requested: d.total_inflight().min(u32::MAX as usize) as u32,
            received: d.received_count().min(u32::MAX as usize) as u32,
            failed: d.failed_count().min(u32::MAX as usize) as u32,
        }
    };
    // Currently-banned IPs from the peer manager — filtered to
    // entries whose ban hasn't expired at snapshot time so a stale
    // row that's aged past `until` doesn't appear in
    // `/peers/blacklisted`. Drives the blacklisted route.
    let banned_ips: Arc<Vec<std::net::IpAddr>> =
        Arc::new(state.peer_manager.currently_banned_ips(now));

    // Full-tx bytes in priority order: (tx_id, serialized bytes) per
    // pool entry. Drives the unconfirmed full-tx endpoints
    // (`/transactions/unconfirmed?offset=&limit=`, `byTransactionId/{id}`,
    // `POST byTransactionIds`). `Arc<[u8]>` is shared with the
    // mempool's own Entry, so no copy here.
    let pool_full_txs: Arc<Vec<(ergo_primitives::digest::Digest32, Arc<[u8]>)>> = Arc::new(
        state
            .mempool
            .iter_transactions()
            .map(|entry| (entry.tx_id, entry.bytes.clone()))
            .collect(),
    );

    // Active protocol parameters at the current full-block tip.
    // Read from `StateStore`'s in-memory cache, kept synchronously
    // consistent with `chain_state.best_full_block_height` by the apply
    // / rollback / reorg paths. No redb round-trip, no persist-pipeline
    // flush — the cache advances atomically with the in-memory tip.
    let active_params = state.store.active_params().clone();

    // Operator event feed: diff this tick's observations against the previous
    // tick's — the single derivation site (no subsystem instrumentation).
    // Everything consumed here is already collected above on the hot path.
    let api_events = {
        let recent_tuples: Vec<(u32, String, u32, u64)> = recent_blocks
            .iter()
            .map(|b| (b.height, b.header_id.clone(), b.txs, b.size_bytes))
            .collect();
        let indexer_status = state.indexer_handle.as_ref().map(|h| {
            use ergo_indexer::{IndexerQuery, IndexerStatus};
            match h.status() {
                IndexerStatus::Syncing => ("syncing".to_string(), None),
                IndexerStatus::CaughtUp => ("caughtUp".to_string(), None),
                IndexerStatus::Halted(r) => {
                    ("halted".to_string(), Some(r.as_kebab_case().to_string()))
                }
            }
        });
        let tick_reorgs = super::event_feed::derive_events(
            &mut state.event_feed,
            &mut state.event_feed_prev,
            super::event_feed::FeedObservation {
                unix_ms: now_unix_ms,
                // COMMITTED tip — the newest entry of the committed tail
                // itself, NOT the in-memory chain_state tip. During the
                // async-persist window the in-memory tip runs ahead of the
                // committed tail; feeding it here would advance the differ's
                // cursor past heights `recent` doesn't contain yet and
                // permanently drop their block events.
                // Same-source tip + tail keeps the differ self-consistent:
                // events simply emit a tick later, when the commit lands.
                tip_height: recent_tuples.first().map(|(h, ..)| *h).unwrap_or(0),
                tip_id: recent_tuples
                    .first()
                    .map(|(_, id, ..)| id.clone())
                    .unwrap_or_default(),
                recent: &recent_tuples,
                peers: peers_vec.iter().map(|p| p.addr.to_string()).collect(),
                indexer_status,
                sync_wedged: sync_wedged
                    .as_ref()
                    .map(|w| (w.stuck_height, w.stuck_block_id.clone())),
                shadow_diverged: state.shadow.as_ref().and_then(|sh| {
                    sh.snapshot_active()
                        .map(|d| (d.kind.to_string(), d.height, d.ours, d.theirs))
                }),
                reorg_enrichment: state.last_reorg_enrichment.clone(),
            },
        );
        for r in tick_reorgs {
            state.reorg_history.push(r);
        }
        // Seq-keyed cache: a quiet tick re-publishes the same Arc instead of
        // re-cloning 100 events per second.
        let seq_now = state.event_feed.latest_seq();
        match &state.event_feed_projection {
            Some((cached_seq, cached)) if *cached_seq == seq_now => cached.clone(),
            _ => {
                let built = events_projection::build_events_projection(&state.event_feed);
                state.event_feed_projection = Some((seq_now, built.clone()));
                built
            }
        }
    };

    let parts = SnapshotParts {
        now_unix_ms,
        snapshot_built_at: now,
        best_header_height: cs_best_header_height,
        best_header_id: cs_best_header_id,
        best_header_parent_id: best_header_parent,
        best_header_timestamp_ms: best_header_ts,
        best_full_block_height: cs_best_full_block_height,
        best_full_block_id: cs_best_full_block_id,
        best_full_block_parent_id: best_full_parent,
        best_full_block_timestamp_ms: best_full_ts,
        best_header_n_bits,
        best_full_block_n_bits,
        state_digest,
        headers_chain_synced,
        download_window,
        pending_blocks,
        recovery_done,
        peer_count,
        mempool_size,
        mempool_total_bytes,
        mempool_capacity_count,
        mempool_capacity_bytes,
        mempool_revalidation_pending,
        mempool_transactions,
        peers: &peers_vec,
        best_header_score,
        best_full_block_score,
        genesis_block_id,
        last_seen_message_unix_ms,
        last_mempool_update_unix_ms,
        active_params,
        pool_outputs,
        pool_inputs,
        pool_full_txs,
        peer_sync,
        delivery_counts,
        banned_ips,
        bootstrap,
        recent_blocks,
        events: api_events,
        reorgs: {
            let key = state.reorg_history.projection_key(now_unix_ms);
            match &state.reorg_history_projection {
                Some((cached_key, cached)) if *cached_key == key => cached.clone(),
                _ => {
                    let list = state.reorg_history.list(now_unix_ms);
                    let built = Arc::new(ergo_api::types::ApiReorgHistory {
                        total: state.reorg_history.total(),
                        cap: crate::node::reorg_history::ReorgHistory::CAP as u32,
                        max_age_ms: crate::node::reorg_history::ReorgHistory::MAX_AGE_MS,
                        reorgs: list
                            .into_iter()
                            .map(|r| ergo_api::types::ApiReorgRecord {
                                unix_ms: r.unix_ms,
                                height: r.height,
                                header_id: r.header_id,
                                depth: r.depth,
                                dropped_header_ids: r.dropped_header_ids,
                                orphans_truncated: r.orphans_truncated,
                                returned_tx_ids: r.returned_tx_ids,
                                returned_txs_total: r.returned_txs_total,
                                delivered_by: r.delivered_by,
                            })
                            .collect(),
                    });
                    state.reorg_history_projection = Some((key, built.clone()));
                    built
                }
            }
        },
        max_peer_height,
        mining_enabled: state.mining_enabled,
        snapshot_manifests: state
            .snapshot_state
            .available_manifests()
            .into_iter()
            .map(|(h, id)| (h, hex::encode(id)))
            .collect(),
        last_block_apply_error,
        block_apply_errors_total,
        sync_wedged,
        shadow,
        mempool_tx_requested_total: state.mempool_tx_requested_total,
        mempool_peer_tx_admitted_total: state.mempool_peer_tx_admitted_total,
        mempool_peer_tx_rejected_total: state.mempool_peer_tx_rejected_total,
    };

    if let Some(pub_) = state.snapshot_publisher.as_mut() {
        pub_.publish(parts);
    }
}
