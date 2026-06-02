//! Per-tick snapshot publish: read `NodeState` into a `SnapshotParts`
//! and hand it to the runtime's `SnapshotPublisher` so the API layer
//! sees fresh observable state.

use ergo_api::types::{
    ApiBootstrapStatus, ApiMempoolTransaction, ApiMempoolTransactions, ApiRecentBlock, ApiTxSource,
    ApiWeightFunction,
};
use ergo_mempool::types::TxSource;
use ergo_mempool::Mempool;
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::read_block_transactions;
use ergo_ser::header::{read_header, Header};
use ergo_ser::modifier_id::ExpectedSections;
use ergo_state::reader::ChainStoreReader;
use ergo_state::{ChainStateRead, HeaderSectionStore, StateBackendKind};
use ergo_sync::snapshot_bootstrap::BootstrapState;
use std::sync::Arc;
use std::time::Instant;

use super::NodeState;
use crate::snapshot::{unix_now_ms, RecentBlocksCache, SnapshotParts};

/// Tolerance for hiding the bootstrap panel post-install. Matches
/// `AT_TIP_GAP` in `crate::snapshot` — once full-block tip is within
/// this many blocks of the header tip, catch-up is done and the
/// panel auto-hides.
const BOOTSTRAP_PANEL_HIDE_GAP: u32 = 2;

/// Build the operator-API snapshot once per sync_tick.
///
/// Bounded work: collects connected peers (capped naturally by socket
/// count), reads `chain_state()` + `root_digest()` (already on the hot
/// path for the heartbeat above), one `get_header_meta` lookup each for
/// the best-header and best-full-block tips, a priority-ordered mempool
/// walk capped by `MempoolConfig::max_pool_size`, and the recent-blocks
/// tail — which is cached by the full-block tip id and rebuilt only when
/// the tip advances (`recent_blocks_for_tip`), so steady-state ticks pay
/// a single id comparison rather than 32 header + section reads.
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

pub(super) fn publish_snapshot(state: &mut NodeState, now: Instant) {
    let now_unix_ms = unix_now_ms();
    let bootstrap = build_bootstrap_status(state, now_unix_ms);
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

    let state_digest = *state
        .store
        .as_utxo_mut()
        .expect("utxo-only: AVL state-root digest is gated off in digest mode")
        .root_digest()
        .as_bytes();
    // Recent-blocks tail for the dashboard, cached by the full-block tip
    // id (rebuilt only when the tip advances — see `recent_blocks_for_tip`).
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
    let recent_blocks = match ChainStoreReader::new_from_db(state.store.db_arc()).committed_tip() {
        Ok(Some((tip_height, tip_id))) => recent_blocks_for_tip(
            &mut state.recent_blocks_cache,
            &state.store,
            tip_id,
            tip_height,
        ),
        // No committed full-block chain yet, or a transient read fault:
        // serve an empty tail this tick (best-effort; recovers next tick).
        Ok(None) => Arc::new(Vec::new()),
        Err(e) => {
            tracing::warn!(error = %e, "recent_blocks: committed_tip read failed; serving empty tail");
            Arc::new(Vec::new())
        }
    };
    let download_window = state.coordinator.sync_state().download_window() as u32;
    let pending_blocks = state.coordinator.sync_state().pending_count() as u32;
    let headers_chain_synced = state.coordinator.sync_state().headers_chain_synced();
    let recovery_done = state.executor.recovery_done();

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
    let mempool_transactions =
        project_mempool_transactions(&state.mempool, state.api_weight_function, now, now_unix_ms);
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
    // `/peers/blacklisted`. Drives the §10.6 blacklisted route.
    let banned_ips: Arc<Vec<std::net::IpAddr>> =
        Arc::new(state.peer_manager.currently_banned_ips(now));

    // Full-tx bytes in priority order: (tx_id, serialized bytes) per
    // pool entry. Drives the §10.4 unconfirmed full-tx endpoints
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
    };

    if let Some(pub_) = state.snapshot_publisher.as_mut() {
        pub_.publish(parts);
    }
}

/// Number of recent full blocks the dashboard tail holds, and the upper
/// bound on the chain walk that builds it.
const RECENT_BLOCKS_CAP: usize = 32;

/// Return the recent-blocks tail for `tip_id`, reusing the cached `Arc`
/// when the full-block tip is unchanged.
///
/// Walking the full-block ancestor chain (header parse + section reads)
/// is too heavy to redo on every `sync_tick`; the tail only changes when
/// the full-block tip advances, so we recompute only when `tip_id` differs
/// from the cached entry and otherwise hand back the cached allocation.
/// Takes the cache and store as separate borrows (disjoint `NodeState`
/// fields) so the call site can hold a `&mut` to the cache without aliasing
/// the rest of `state`.
///
/// Caching keyed on `tip_id` alone (no per-tick section re-validation) is
/// sound because a *committed* block is immutable: its header and sections
/// never change once written, so a tail that was contiguous when cached stays
/// correct until the tip advances. Re-reading all 32 sections every tick to
/// detect post-commit corruption would reintroduce exactly the hot-path cost
/// this cache exists to avoid; such corruption is an apply-path fault, not a
/// dashboard concern.
///
/// `tip_id`/`tip_height` are the *committed* full-block tip (the caller reads
/// it from `ChainStoreReader::committed_tip`), whose sections are durably
/// stored, so the walk normally reaches it.
///
/// The result is cached only when the tail is a *contiguous* run anchored at
/// the tip — heights `tip, tip-1, tip-2, …` with no gaps. `build_recent_blocks`
/// walks past a faulted ancestor section (leaving a gap) rather than
/// truncating, and such a fault is usually transient; caching a gappy or
/// tip-short tail would pin it until the next tip change. Requiring contiguity
/// means a one-tick read fault recomputes next tick instead (cheap and brief),
/// filling the tail back in once the section reads cleanly.
fn recent_blocks_for_tip(
    cache: &mut Option<RecentBlocksCache>,
    store: &StateBackendKind,
    tip_id: [u8; 32],
    tip_height: u32,
) -> Arc<Vec<ApiRecentBlock>> {
    if let Some(c) = cache {
        if c.tip_id == tip_id {
            return c.blocks.clone();
        }
    }
    let blocks = Arc::new(build_recent_blocks(store, tip_id, tip_height));
    // Contiguous-from-tip: `blocks[i]` must be height `tip_height - i`. This
    // implies the tip itself was emitted (i = 0) and that no ancestor inside
    // the window was skipped on a transient fault. An empty tail (tip block
    // unreadable this tick) is therefore not cached — it retries next tick.
    let contiguous = !blocks.is_empty()
        && blocks
            .iter()
            .enumerate()
            .all(|(i, b)| Some(b.height) == tip_height.checked_sub(i as u32));
    if contiguous {
        *cache = Some(RecentBlocksCache {
            tip_id,
            blocks: blocks.clone(),
        });
    }
    blocks
}

/// Walk the canonical full-block chain backwards from the best full block,
/// newest-first, building up to [`RECENT_BLOCKS_CAP`] entries.
///
/// The walk follows each header's `parent_id` rather than the best-*header*
/// height index (`get_header_id_at_height`): a heavier header-only fork can
/// run the header index ahead of — and away from — the applied full-block
/// chain, and this endpoint must only ever surface applied full blocks.
/// Every ancestor of an applied full block is itself an applied full block,
/// so the parent walk stays on the canonical full chain by construction.
///
/// The walk is bounded to at most `RECENT_BLOCKS_CAP` headers regardless of
/// how many emit, so a run of corrupt sections near the tip can leave a
/// gap but can never turn this into a walk to genesis.
///
/// Headers are read through `store` (which sees the in-flight `batch_headers`
/// tip), but block sections are read through a non-draining
/// [`ChainStoreReader`]: the draining `StateStore::get_block_section` reaps
/// the async persist pipeline's results and would surface — and thereby
/// consume — a `PersistFailed` on this read-only snapshot path, masking a
/// storage fault the apply path must own. The reader reads committed sections
/// only, which is exactly what the draining path saw anyway (sections aren't
/// readable until their persist job commits); it just never steals the fault.
///
/// UTXO-only: [`try_recent_block`] treats an absent `adProofs` section as the
/// benign 0-byte case, which holds for UTXO mode but not for digest backends,
/// where a missing `adProofs` section is a fault (`DigestAdProofsSectionMissing`).
/// `publish_snapshot` is itself UTXO-only today (its state-root read asserts
/// that), but gate here too so a digest backend never adopts the wrong size
/// rule — it gets an empty tail instead.
fn build_recent_blocks(
    store: &StateBackendKind,
    tip_id: [u8; 32],
    tip_height: u32,
) -> Vec<ApiRecentBlock> {
    let mut out = Vec::new();
    if tip_height == 0 || store.as_utxo().is_none() {
        return out; // no full block applied yet, or a non-UTXO backend
    }
    let sections = ChainStoreReader::new_from_db(store.db_arc());
    let mut id = tip_id;
    let mut height = tip_height;
    for _ in 0..RECENT_BLOCKS_CAP {
        // The header is the walk anchor: we need its `parent_id` to step
        // back, and an applied full block always retains its header. A
        // miss or parse fault here means we cannot continue the walk
        // (older entries become unreachable), so stop.
        let header_bytes = match store.get_header(&id) {
            Ok(Some(b)) => b,
            Ok(None) => {
                tracing::warn!(height, "recent_blocks: header bytes absent; stopping walk");
                break;
            }
            Err(e) => {
                tracing::warn!(error = %e, height, "recent_blocks: header read failed; stopping walk");
                break;
            }
        };
        let header = match read_header(&mut VlqReader::new(&header_bytes)) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, height, "recent_blocks: header parse failed; stopping walk");
                break;
            }
        };
        let parent = *header.parent_id.as_bytes();
        if let Some(block) = try_recent_block(&sections, &id, height, &header, header_bytes.len()) {
            out.push(block);
        }
        // Step to the parent even when this block was skipped, so a single
        // faulty section near the tip doesn't truncate the whole list.
        // Genesis is height 1 with a zero parent id — stop there.
        if height <= 1 || parent == [0u8; 32] {
            break;
        }
        id = parent;
        height -= 1;
    }
    out
}

/// Build one recent-blocks entry from a parsed header plus its on-disk
/// sections, or `None` when the block must be omitted.
///
/// Sections are read through the non-draining [`ChainStoreReader`] (see
/// `build_recent_blocks`), so a section read `Err` here is a redb read fault,
/// never an async-persist `PersistFailed`.
///
/// `size_bytes` sums the on-disk section byte lengths. `transactions` and
/// `extension` are required — an applied full block always has both (see
/// `AssemblyTracker::is_complete`) — so a missing or unreadable required
/// section omits the block rather than under-reporting its size. `adProofs`
/// is optional in UTXO mode (apply does not retain it): a genuine absence
/// (`Ok(None)`) contributes 0, but a read *error* still omits the block
/// rather than reporting a silently wrong size. Omitting keeps a corrupt or
/// partial block out of the list instead of undercounting it.
fn try_recent_block(
    sections: &ChainStoreReader,
    id: &[u8; 32],
    height: u32,
    header: &Header,
    header_len: usize,
) -> Option<ApiRecentBlock> {
    let expected = ExpectedSections::from_header(
        id,
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );
    // transactions — required; we need the bytes for both the size and
    // the tx count.
    let tx_bytes = match sections.get_block_section(&expected.transactions_id) {
        Ok(Some(b)) => b,
        Ok(None) => {
            tracing::warn!(
                height,
                "recent_blocks: transactions section absent; omitting block"
            );
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, height, "recent_blocks: transactions read failed; omitting block");
            return None;
        }
    };
    let bt = match read_block_transactions(&mut VlqReader::new(&tx_bytes)) {
        Ok(bt) => bt,
        Err(e) => {
            tracing::warn!(error = %e, height, "recent_blocks: blockTransactions parse failed; omitting block");
            return None;
        }
    };
    // Defense-in-depth: the section was looked up by the id derived from the
    // header's `transactions_root`, so its embedded `header_id` must point
    // back at the block we walked. A mismatch means the stored section bytes
    // are inconsistent with the header (corruption / cross-block write); omit
    // rather than report a tx count from the wrong block.
    if bt.header_id.as_bytes() != id {
        tracing::warn!(
            height,
            "recent_blocks: blockTransactions header_id mismatch; omitting block"
        );
        return None;
    }
    // extension — required.
    let ext_len = match sections.get_block_section(&expected.extension_id) {
        Ok(Some(b)) => b.len(),
        Ok(None) => {
            tracing::warn!(
                height,
                "recent_blocks: extension section absent; omitting block"
            );
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, height, "recent_blocks: extension read failed; omitting block");
            return None;
        }
    };
    // adProofs — optional in UTXO mode; a genuine absence contributes 0,
    // but a read error still omits the block.
    let adp_len = match sections.get_block_section(&expected.ad_proofs_id) {
        Ok(Some(b)) => b.len(),
        Ok(None) => 0,
        Err(e) => {
            tracing::warn!(error = %e, height, "recent_blocks: adProofs read failed; omitting block");
            return None;
        }
    };
    Some(ApiRecentBlock {
        height,
        header_id: hex::encode(id),
        ts_unix_ms: header.timestamp,
        txs: bt.transactions.len() as u32,
        size_bytes: (header_len + tx_bytes.len() + ext_len + adp_len) as u64,
    })
}

/// Reducer-independent inputs that drive [`select_bootstrap_phase`].
/// Extracted so the phase cascade can be unit-tested without a full
/// `NodeState`.
struct BootstrapPhaseInputs {
    in_catchup: bool,
    has_reconstructed_tree: bool,
    chunk_assembly_complete: bool,
    has_chunk_assembly: bool,
}

/// Map the live bootstrap reducer state + install-side progress flags
/// to the wire-visible phase. Single source of truth for the phase
/// cascade — keeps the producer and its unit tests in sync.
fn select_bootstrap_phase(
    reducer_state: &BootstrapState,
    inputs: &BootstrapPhaseInputs,
) -> ergo_api::types::ApiBootstrapPhase {
    use ergo_api::types::ApiBootstrapPhase;
    if inputs.in_catchup {
        return ApiBootstrapPhase::PostInstallCatchup;
    }
    match reducer_state {
        BootstrapState::Idle | BootstrapState::Querying | BootstrapState::Selected { .. } => {
            ApiBootstrapPhase::Discovery
        }
        BootstrapState::ManifestRequested { .. } => ApiBootstrapPhase::ManifestRequested,
        BootstrapState::ManifestVerified { .. } => {
            if inputs.has_reconstructed_tree {
                ApiBootstrapPhase::Installing
            } else if inputs.chunk_assembly_complete {
                ApiBootstrapPhase::Reconstructing
            } else if inputs.has_chunk_assembly {
                ApiBootstrapPhase::DownloadingChunks
            } else {
                ApiBootstrapPhase::ManifestVerified
            }
        }
    }
}

/// Project the live bootstrap state into the dashboard DTO, or
/// `None` if the operator shouldn't see a bootstrap panel right now.
///
/// Visibility rules:
/// - Not Mode 2 (utxo_bootstrap not configured): always `None`.
/// - Mode 2, pre-install (`best_full_block_height == 0`): `Some` —
///   show discovery / chunks / reconstruct / install progress.
/// - Mode 2, post-install but still catching up (`gap > 2`): `Some`
///   with phase `post_install_catchup` — show "applying blocks from
///   snapshot height" until tip.
/// - Mode 2, at tip: `None` — panel auto-hides.
fn build_bootstrap_status(state: &mut NodeState, now_unix_ms: u64) -> Option<ApiBootstrapStatus> {
    if !state.utxo_bootstrap_enabled {
        return None;
    }
    let cs = state.store.chain_state_meta();
    let best_full = cs.best_full_block_height;
    let best_header = cs.best_header_height;

    let reducer_state = state.snapshot_bootstrap.state();
    if !matches!(reducer_state, BootstrapState::Idle) {
        // Any non-Idle reducer state is evidence the bootstrap flow is
        // genuinely active this session. Latch the flag so a later
        // post-install catch-up window still renders the panel even
        // after the reducer transitions back to a quiet state.
        state.bootstrap_was_active_this_session = true;
    }

    let pre_install = best_full == 0;
    let post_install_catchup = !pre_install
        && state.bootstrap_was_active_this_session
        && best_header.saturating_sub(best_full) > BOOTSTRAP_PANEL_HIDE_GAP;
    if !pre_install && !post_install_catchup {
        return None;
    }
    let in_catchup = post_install_catchup;

    if state.bootstrap_started_unix_ms.is_none() {
        state.bootstrap_started_unix_ms = Some(now_unix_ms);
    }

    let voters = state
        .snapshot_bootstrap
        .voters_for_selected_manifest()
        .len() as u32;
    let (chunks_received, chunks_total) = state
        .chunk_assembly
        .as_ref()
        .map(|ca| (ca.received_count() as u32, ca.total_count() as u32))
        .unwrap_or((0, 0));

    let phase_inputs = BootstrapPhaseInputs {
        in_catchup,
        has_reconstructed_tree: state.reconstructed_tree.is_some(),
        chunk_assembly_complete: state
            .chunk_assembly
            .as_ref()
            .is_some_and(|c| c.is_complete()),
        has_chunk_assembly: state.chunk_assembly.is_some(),
    };
    let phase = select_bootstrap_phase(&reducer_state, &phase_inputs);
    let (snapshot_height, manifest_id, trust_check_passed) = if in_catchup {
        // Post-install: report the height we installed at, derived
        // from chain_state. manifest_id no longer carried in the
        // reducer (it's been cleared post-install); use the
        // best_full_block_id at snapshot_height as a stable proxy.
        (best_full, None, true)
    } else {
        match reducer_state {
            BootstrapState::Idle | BootstrapState::Querying => (0, None, false),
            BootstrapState::Selected {
                height,
                manifest_id,
            } => (height as u32, Some(hex::encode(manifest_id)), false),
            BootstrapState::ManifestRequested {
                height,
                manifest_id,
                ..
            } => (height as u32, Some(hex::encode(manifest_id)), false),
            BootstrapState::ManifestVerified {
                height,
                manifest_id,
            } => (height as u32, Some(hex::encode(manifest_id)), true),
        }
    };

    // NiPoPoW + header-availability dashboard fields (Part 2 §14.8).
    // popow_phase / popow_providers report on the popow_bootstrap
    // reducer when wired (14.6 orchestration follow-up). Until then,
    // these stay None.
    // header_availability + popow_dense_from_height reflect what the
    // store reports — surfaceable today since the persistence layer
    // (14.4.5) is already on disk.
    let (header_availability, popow_dense_from_height) =
        match state.store.chain_state_meta().header_availability {
            ergo_state::chain::HeaderAvailability::Dense => (None, None),
            ergo_state::chain::HeaderAvailability::PoPowSparse {
                dense_from_height, ..
            } => (
                Some(ergo_api::types::ApiHeaderAvailability::Sparse),
                Some(dense_from_height),
            ),
        };

    Some(ApiBootstrapStatus {
        phase,
        snapshot_height,
        manifest_id,
        voters,
        chunks_received,
        chunks_total,
        trust_check_passed,
        started_unix_ms: state.bootstrap_started_unix_ms.unwrap_or(now_unix_ms),
        popow_phase: None,
        popow_providers: None,
        header_availability,
        popow_dense_from_height,
    })
}

fn project_mempool_transactions(
    mempool: &Mempool,
    weight_function: ApiWeightFunction,
    snapshot_built_at: Instant,
    now_unix_ms: u64,
) -> ApiMempoolTransactions {
    let transactions: Vec<ApiMempoolTransaction> = mempool
        .iter_transactions()
        .map(|entry| {
            let first_seen_age_ms = snapshot_built_at
                .saturating_duration_since(entry.created_at)
                .as_millis() as u64;
            let last_checked_age_ms = snapshot_built_at
                .saturating_duration_since(entry.last_checked_at)
                .as_millis() as u64;
            let source = match &entry.source {
                TxSource::Peer(peer) => ApiTxSource::Peer {
                    addr: peer.to_string(),
                },
                TxSource::Api => ApiTxSource::Api,
                TxSource::Wallet => ApiTxSource::Wallet,
                TxSource::DemotedFromBlock => ApiTxSource::DemotedFromBlock,
            };
            ApiMempoolTransaction {
                tx_id: hex::encode(entry.tx_id.as_bytes()),
                fee_nano_erg: entry.fee,
                fee_per_byte_nano_erg: if entry.size_bytes > 0 {
                    entry.fee / entry.size_bytes as u64
                } else {
                    0
                },
                size_bytes: entry.size_bytes,
                validation_cost_units: entry.cost,
                priority_weight: entry.weight,
                source,
                input_count: entry.inputs.len() as u32,
                output_count: entry.outputs.len() as u32,
                parents_in_pool: entry.parents_in_pool.len() as u32,
                first_seen_unix_ms: now_unix_ms.saturating_sub(first_seen_age_ms),
                first_seen_age_ms,
                last_checked_age_ms,
            }
        })
        .collect();
    ApiMempoolTransactions {
        transactions,
        weight_function,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
    use ergo_ser::header::serialize_header;
    use ergo_ser::modifier_id::{TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION};
    use ergo_state::store::StateStore;

    // ----- helpers -----

    /// A minimal v2 header chained to `parent`, with its three section
    /// roots derived from `tag` (distinct blocks → distinct roots, though
    /// the header id already disambiguates section ids). Returns the
    /// header plus its canonical id and wire bytes.
    fn header(height: u32, parent: [u8; 32], tag: u8) -> (Header, [u8; 32], Vec<u8>) {
        let h = Header {
            version: 2,
            parent_id: ModifierId::from_bytes(parent),
            ad_proofs_root: Digest32::from_bytes([tag.wrapping_add(1); 32]),
            transactions_root: Digest32::from_bytes([tag.wrapping_add(2); 32]),
            state_root: ADDigest::from_bytes([0x04; 33]),
            timestamp: 1_700_000_000_000 + height as u64,
            extension_root: Digest32::from_bytes([tag.wrapping_add(3); 32]),
            n_bits: 0x1a01_7660,
            height,
            votes: [0; 3],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0xAA; 8],
            },
        };
        let (bytes, id) = serialize_header(&h).unwrap();
        (h, *id.as_bytes(), bytes)
    }

    /// Canonical bytes of an empty `BlockTransactions` — valid input for
    /// `read_block_transactions` (tx count 0), enough to exercise the
    /// section read + parse + size path.
    fn tx_section(header_id: [u8; 32]) -> Vec<u8> {
        let bt = BlockTransactions {
            header_id: ModifierId::from_bytes(header_id),
            transactions: vec![],
        };
        let mut w = VlqWriter::new();
        write_block_transactions(&mut w, &bt).unwrap();
        w.result()
    }

    /// Store a header and any subset of its three sections. `ext`/`adp`
    /// are the raw section bytes to store (the walk only measures their
    /// length); `None` leaves that section absent.
    fn store_block(
        store: &StateStore,
        h: &Header,
        id: [u8; 32],
        header_bytes: &[u8],
        tx: bool,
        ext: Option<&[u8]>,
        adp: Option<&[u8]>,
    ) {
        store.store_header(&id, header_bytes).unwrap();
        let expected = ExpectedSections::from_header(
            &id,
            h.transactions_root.as_bytes(),
            h.extension_root.as_bytes(),
            h.ad_proofs_root.as_bytes(),
        );
        if tx {
            let b = tx_section(id);
            store
                .store_block_section_typed(&expected.transactions_id, &b, TYPE_BLOCK_TRANSACTIONS)
                .unwrap();
        }
        if let Some(e) = ext {
            store
                .store_block_section_typed(&expected.extension_id, e, TYPE_EXTENSION)
                .unwrap();
        }
        if let Some(a) = adp {
            store
                .store_block_section_typed(&expected.ad_proofs_id, a, TYPE_AD_PROOFS)
                .unwrap();
        }
    }

    fn open_store() -> (tempfile::TempDir, StateStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::open(&tmp.path().join("state.redb")).unwrap();
        (tmp, store)
    }

    // ----- happy path -----

    /// Newest-first over the canonical full chain, with `size_bytes` summing
    /// the on-disk sections and adProofs being optional: the block without
    /// an adProofs section is still emitted, its size just excludes it.
    #[test]
    fn recent_blocks_walks_full_chain_newest_first_with_section_sizes() {
        let (_tmp, store) = open_store();
        let (h1, id1, b1) = header(1, [0u8; 32], 10);
        let (h2, id2, b2) = header(2, id1, 20);
        let (h3, id3, b3) = header(3, id2, 30);
        let ext = vec![0xEEu8; 7];
        let adp = vec![0xAAu8; 5];
        store_block(&store, &h1, id1, &b1, true, Some(&ext), Some(&adp));
        store_block(&store, &h2, id2, &b2, true, Some(&ext), None); // no adProofs
        store_block(&store, &h3, id3, &b3, true, Some(&ext), Some(&adp));
        let backend = StateBackendKind::Utxo(store);

        let out = build_recent_blocks(&backend, id3, 3);

        assert_eq!(out.len(), 3);
        assert_eq!(out[0].height, 3);
        assert_eq!(out[1].height, 2);
        assert_eq!(out[2].height, 1);
        assert_eq!(out[0].header_id, hex::encode(id3));
        assert_eq!(out[0].ts_unix_ms, 1_700_000_000_003);
        assert_eq!(out[0].txs, 0);
        // h3 has adProofs → size includes all four sections.
        assert_eq!(
            out[0].size_bytes,
            b3.len() as u64 + tx_section(id3).len() as u64 + ext.len() as u64 + adp.len() as u64,
        );
        // h2 has no adProofs → size excludes it; block still present.
        assert_eq!(
            out[1].size_bytes,
            b2.len() as u64 + tx_section(id2).len() as u64 + ext.len() as u64,
        );
    }

    /// The walk follows `parent_id`, so a header on a different branch
    /// (not an ancestor of the full tip) never appears — the fork-safety
    /// invariant that the best-*header* height index could not provide.
    #[test]
    fn recent_blocks_follows_parent_links_not_unrelated_headers() {
        let (_tmp, store) = open_store();
        let (h1, id1, b1) = header(1, [0u8; 32], 10);
        let (h2, id2, b2) = header(2, id1, 20);
        let (h3, id3, b3) = header(3, id2, 30);
        let ext = vec![0xEEu8; 7];
        store_block(&store, &h1, id1, &b1, true, Some(&ext), None);
        store_block(&store, &h2, id2, &b2, true, Some(&ext), None);
        store_block(&store, &h3, id3, &b3, true, Some(&ext), None);
        // Competing height-2 header on a different branch (parent is not
        // id1). Present in the store but not an ancestor of id3.
        let (hf, idf, bf) = header(2, [0x77u8; 32], 99);
        store_block(&store, &hf, idf, &bf, true, Some(&ext), None);
        let backend = StateBackendKind::Utxo(store);

        let out = build_recent_blocks(&backend, id3, 3);

        let ids: Vec<String> = out.iter().map(|b| b.header_id.clone()).collect();
        assert_eq!(
            ids,
            vec![hex::encode(id3), hex::encode(id2), hex::encode(id1)],
        );
        assert!(
            !ids.contains(&hex::encode(idf)),
            "fork header must not appear in the recent-blocks tail",
        );
    }

    /// The walk is bounded to `RECENT_BLOCKS_CAP` headers even when more
    /// blocks exist — it never runs to genesis.
    #[test]
    fn recent_blocks_caps_walk_at_recent_blocks_cap() {
        let (_tmp, store) = open_store();
        let ext = vec![0xEEu8; 3];
        let total = RECENT_BLOCKS_CAP as u32 + 8;
        let mut parent = [0u8; 32];
        let mut tip_id = [0u8; 32];
        for h in 1..=total {
            let (hdr, id, bytes) = header(h, parent, (h % 200) as u8);
            store_block(&store, &hdr, id, &bytes, true, Some(&ext), None);
            parent = id;
            tip_id = id;
        }
        let backend = StateBackendKind::Utxo(store);

        let out = build_recent_blocks(&backend, tip_id, total);

        assert_eq!(out.len(), RECENT_BLOCKS_CAP);
        assert_eq!(out[0].height, total);
        assert_eq!(
            out[RECENT_BLOCKS_CAP - 1].height,
            total - RECENT_BLOCKS_CAP as u32 + 1,
        );
    }

    /// No full block applied yet (`tip_height == 0`) → empty, no reads.
    #[test]
    fn recent_blocks_empty_when_no_full_block() {
        let (_tmp, store) = open_store();
        let backend = StateBackendKind::Utxo(store);
        assert!(build_recent_blocks(&backend, [0u8; 32], 0).is_empty());
    }

    /// Digest backends treat an absent adProofs section as a fault, not the
    /// benign 0-byte case the recent-blocks size rule assumes; the list is
    /// UTXO-only and yields an empty tail on a digest backend regardless of
    /// the requested tip.
    #[test]
    fn recent_blocks_empty_on_digest_backend() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ergo_state::DigestStateStore::open(
            &tmp.path().join("digest.redb"),
            ergo_validation::scala_launch(),
            ergo_chain_spec::VotingParams {
                voting_length: 2,
                ..ergo_chain_spec::VotingParams::mainnet()
            },
            [0u8; 33], // EMPTY_AVL_DIGEST — a fresh digest store seeds from it
        )
        .unwrap();
        let backend = StateBackendKind::Digest(store);
        assert!(build_recent_blocks(&backend, [7u8; 32], 5).is_empty());
    }

    /// The tail tracks the *committed* full-block tip, not the highest header
    /// present in the store. With h3 fully persisted but the committed tip
    /// still at h2 (the async-persist / in-memory-ahead window), the snapshot
    /// path reads committed_tip = h2 and never advertises h3.
    #[test]
    fn recent_blocks_reflects_committed_tip_not_uncommitted_headers() {
        let (_tmp, mut store) = open_store();
        let (h1, id1, b1) = header(1, [0u8; 32], 10);
        let (h2, id2, b2) = header(2, id1, 20);
        let (h3, id3, b3) = header(3, id2, 30);
        let ext = vec![0xEEu8; 7];
        store_block(&store, &h1, id1, &b1, true, Some(&ext), None);
        store_block(&store, &h2, id2, &b2, true, Some(&ext), None);
        // h3 is fully present in the store, but is not the committed tip.
        store_block(&store, &h3, id3, &b3, true, Some(&ext), None);
        store.set_best_full_block_for_test(id2, 2).unwrap();
        let backend = StateBackendKind::Utxo(store);

        // The snapshot path anchors on committed_tip (= h2), not the highest
        // present header (h3).
        let reader = ChainStoreReader::new_from_db(backend.db_arc());
        assert_eq!(reader.committed_tip().unwrap(), Some((2, id2)));

        let out = build_recent_blocks(&backend, id2, 2);
        let heights: Vec<u32> = out.iter().map(|b| b.height).collect();
        assert_eq!(
            heights,
            vec![2, 1],
            "tail reflects committed tip h2, never the uncommitted h3",
        );
    }

    /// The cache hands back the same `Arc` while the tip is unchanged and
    /// rebuilds (new allocation + contents) once the tip moves.
    #[test]
    fn recent_blocks_cache_reuses_arc_until_tip_changes() {
        let (_tmp, store) = open_store();
        let (h1, id1, b1) = header(1, [0u8; 32], 10);
        let (h2, id2, b2) = header(2, id1, 20);
        let ext = vec![0xEEu8; 4];
        store_block(&store, &h1, id1, &b1, true, Some(&ext), None);
        store_block(&store, &h2, id2, &b2, true, Some(&ext), None);
        let backend = StateBackendKind::Utxo(store);

        let mut cache = None;
        let first = recent_blocks_for_tip(&mut cache, &backend, id2, 2);
        let second = recent_blocks_for_tip(&mut cache, &backend, id2, 2);
        assert!(
            Arc::ptr_eq(&first, &second),
            "unchanged tip must reuse the cached Arc"
        );

        let third = recent_blocks_for_tip(&mut cache, &backend, id1, 1);
        assert!(
            !Arc::ptr_eq(&first, &third),
            "tip change must rebuild the tail"
        );
        assert_eq!(third.len(), 1);
        assert_eq!(third[0].height, 1);
    }

    /// A transient fault on an *ancestor* section leaves a gap in the tail;
    /// the contiguity guard refuses to cache it, so the next tick (same tip)
    /// recomputes and self-heals once the section reads cleanly — no tip
    /// advance required.
    #[test]
    fn recent_blocks_cache_self_heals_after_transient_ancestor_gap() {
        let (_tmp, store) = open_store();
        let (h1, id1, b1) = header(1, [0u8; 32], 10);
        let (h2, id2, b2) = header(2, id1, 20);
        let (h3, id3, b3) = header(3, id2, 30);
        let ext = vec![0xEEu8; 7];
        store_block(&store, &h1, id1, &b1, true, Some(&ext), None);
        // h2: header + tx present, extension missing (the transient gap).
        store_block(&store, &h2, id2, &b2, true, None, None);
        store_block(&store, &h3, id3, &b3, true, Some(&ext), None);
        let backend = StateBackendKind::Utxo(store);

        let mut cache = None;
        // First tick: h2 omitted → gappy tail [3, 1]. Not contiguous from the
        // tip, so it must not be cached.
        let gappy = recent_blocks_for_tip(&mut cache, &backend, id3, 3);
        assert_eq!(
            gappy.iter().map(|b| b.height).collect::<Vec<_>>(),
            vec![3, 1]
        );
        assert!(cache.is_none(), "a gappy tail must not be cached");

        // The missing ancestor section appears (the fault was transient).
        let expected = ExpectedSections::from_header(
            &id2,
            h2.transactions_root.as_bytes(),
            h2.extension_root.as_bytes(),
            h2.ad_proofs_root.as_bytes(),
        );
        backend
            .as_utxo()
            .unwrap()
            .store_block_section_typed(&expected.extension_id, &ext, TYPE_EXTENSION)
            .unwrap();

        // Second tick, same tip id: recomputes (was never cached) and now
        // yields the full contiguous tail, which is cached.
        let healed = recent_blocks_for_tip(&mut cache, &backend, id3, 3);
        assert_eq!(
            healed.iter().map(|b| b.height).collect::<Vec<_>>(),
            vec![3, 2, 1]
        );
        assert!(cache.is_some(), "a contiguous tail is cached");
    }

    // ----- error paths -----

    /// A block missing a *required* section (extension) is omitted rather
    /// than size-undercounted, and the walk still reaches older blocks via
    /// the parent links.
    #[test]
    fn recent_blocks_omits_block_with_missing_required_section_and_continues() {
        let (_tmp, store) = open_store();
        let (h1, id1, b1) = header(1, [0u8; 32], 10);
        let (h2, id2, b2) = header(2, id1, 20);
        let (h3, id3, b3) = header(3, id2, 30);
        let ext = vec![0xEEu8; 7];
        store_block(&store, &h1, id1, &b1, true, Some(&ext), None);
        store_block(&store, &h2, id2, &b2, true, None, None); // missing extension
        store_block(&store, &h3, id3, &b3, true, Some(&ext), None);
        let backend = StateBackendKind::Utxo(store);

        let out = build_recent_blocks(&backend, id3, 3);

        let heights: Vec<u32> = out.iter().map(|b| b.height).collect();
        assert_eq!(heights, vec![3, 1], "h2 omitted, walk continued to h1");
    }

    /// A block whose stored transactions section embeds a different
    /// `header_id` than the walked block (corruption / cross-block write) is
    /// omitted — the tx count must never be reported from the wrong block.
    #[test]
    fn recent_blocks_omits_block_with_mismatched_tx_header_id() {
        let (_tmp, store) = open_store();
        let (h1, id1, b1) = header(1, [0u8; 32], 10);
        let (h2, id2, b2) = header(2, id1, 20);
        let ext = vec![0xEEu8; 7];
        store_block(&store, &h1, id1, &b1, true, Some(&ext), None);
        // h2: well-formed header + extension, but a transactions section
        // whose embedded `header_id` points at h1, not h2.
        store.store_header(&id2, &b2).unwrap();
        let expected = ExpectedSections::from_header(
            &id2,
            h2.transactions_root.as_bytes(),
            h2.extension_root.as_bytes(),
            h2.ad_proofs_root.as_bytes(),
        );
        store
            .store_block_section_typed(
                &expected.transactions_id,
                &tx_section(id1),
                TYPE_BLOCK_TRANSACTIONS,
            )
            .unwrap();
        store
            .store_block_section_typed(&expected.extension_id, &ext, TYPE_EXTENSION)
            .unwrap();
        let backend = StateBackendKind::Utxo(store);

        let out = build_recent_blocks(&backend, id2, 2);

        let heights: Vec<u32> = out.iter().map(|b| b.height).collect();
        assert_eq!(
            heights,
            vec![1],
            "h2 omitted on tx header_id mismatch, walk continued to h1"
        );
    }

    // ----- bootstrap phase mapping -----

    #[test]
    fn build_bootstrap_status_returns_none_when_utxo_bootstrap_disabled() {
        // Sanity guard for the producer's gate. `make_state` builds a
        // NodeState with `utxo_bootstrap_enabled = false`, so the
        // producer must short-circuit and skip the panel.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = super::super::tests::make_state(&tmp.path().join("state.redb"));
        let status = build_bootstrap_status(&mut state, 0);
        assert!(
            status.is_none(),
            "non-Mode-2 nodes must not surface the bootstrap panel"
        );
    }

    #[test]
    fn build_bootstrap_status_emits_discovery_for_idle_reducer_in_mode_2() {
        // End-to-end producer test: Mode 2 enabled, no chain progress yet,
        // reducer state Idle → wire phase = discovery, with the canonical
        // wire literal "discovery" pinned via JSON serialization.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = super::super::tests::make_state(&tmp.path().join("state.redb"));
        state.utxo_bootstrap_enabled = true;
        let status = build_bootstrap_status(&mut state, 1_000)
            .expect("Mode 2 + pre-install must yield a status");
        assert_eq!(status.phase, ergo_api::types::ApiBootstrapPhase::Discovery);
        let v = serde_json::to_value(&status).unwrap();
        assert_eq!(
            v["phase"],
            serde_json::Value::String("discovery".into()),
            "the producer must wire phase under the `phase` key with the canonical literal"
        );
        assert!(
            v.as_object().unwrap().contains_key("header_availability")
                || !v.as_object().unwrap().contains_key("history_mode"),
            "must use the renamed key (or omit it entirely), never the old name"
        );
    }

    fn phase_inputs(
        in_catchup: bool,
        has_reconstructed_tree: bool,
        chunk_assembly_complete: bool,
        has_chunk_assembly: bool,
    ) -> BootstrapPhaseInputs {
        BootstrapPhaseInputs {
            in_catchup,
            has_reconstructed_tree,
            chunk_assembly_complete,
            has_chunk_assembly,
        }
    }

    #[test]
    fn select_bootstrap_phase_in_catchup_wins_over_reducer_state() {
        // Even with ManifestVerified + all install flags set, in_catchup
        // forces PostInstallCatchup — the post-install branch always
        // outranks the reducer state for wire-phase selection.
        let phase = select_bootstrap_phase(
            &BootstrapState::ManifestVerified {
                height: 100,
                manifest_id: [0u8; 32],
            },
            &phase_inputs(true, true, true, true),
        );
        assert_eq!(
            phase,
            ergo_api::types::ApiBootstrapPhase::PostInstallCatchup
        );
    }

    #[test]
    fn select_bootstrap_phase_idle_querying_selected_all_map_to_discovery() {
        for state in [
            BootstrapState::Idle,
            BootstrapState::Querying,
            BootstrapState::Selected {
                height: 5,
                manifest_id: [1u8; 32],
            },
        ] {
            let phase = select_bootstrap_phase(&state, &phase_inputs(false, false, false, false));
            assert_eq!(
                phase,
                ergo_api::types::ApiBootstrapPhase::Discovery,
                "{state:?} must wire as discovery"
            );
        }
    }

    #[test]
    fn select_bootstrap_phase_manifest_requested_maps_to_manifest_requested() {
        let phase = select_bootstrap_phase(
            &BootstrapState::ManifestRequested {
                peer: "127.0.0.1:9006".parse().unwrap(),
                height: 42,
                manifest_id: [2u8; 32],
            },
            &phase_inputs(false, false, false, false),
        );
        assert_eq!(phase, ergo_api::types::ApiBootstrapPhase::ManifestRequested);
    }

    #[test]
    fn select_bootstrap_phase_manifest_verified_cascade_pins_each_branch() {
        let verified = BootstrapState::ManifestVerified {
            height: 7,
            manifest_id: [3u8; 32],
        };
        // No assembly yet: bare ManifestVerified.
        assert_eq!(
            select_bootstrap_phase(&verified, &phase_inputs(false, false, false, false)),
            ergo_api::types::ApiBootstrapPhase::ManifestVerified
        );
        // Chunk assembly created, still receiving: DownloadingChunks.
        assert_eq!(
            select_bootstrap_phase(&verified, &phase_inputs(false, false, false, true)),
            ergo_api::types::ApiBootstrapPhase::DownloadingChunks
        );
        // Assembly complete, tree not yet reconstructed: Reconstructing.
        // (complete implies has_chunk_assembly is also true at runtime.)
        assert_eq!(
            select_bootstrap_phase(&verified, &phase_inputs(false, false, true, true)),
            ergo_api::types::ApiBootstrapPhase::Reconstructing
        );
        // Reconstructed tree latched in state: Installing — outranks the
        // chunk-assembly flags below it.
        assert_eq!(
            select_bootstrap_phase(&verified, &phase_inputs(false, true, true, true)),
            ergo_api::types::ApiBootstrapPhase::Installing
        );
        // Reconstructed tree latched with no surviving assembly flags:
        // still Installing (the post-reconstruct hand-off path).
        assert_eq!(
            select_bootstrap_phase(&verified, &phase_inputs(false, true, false, false)),
            ergo_api::types::ApiBootstrapPhase::Installing
        );
    }
}
