//! Periodic sync-tick driver.
//!
//! Fired every 1 s by the action loop. Owns the six-step sync work
//! cycle:
//!
//! 1. Drain delivery timeouts from the executor.
//! 2. Evict peers that exceeded the per-peer inactivity bound and
//!    apply dial backoff so the dial cycle stops re-trying dead
//!    addresses.
//! 3. If headers caught the tip, advance `best_full_block` by
//!    applying any sequential blocks whose sections are present and
//!    re-request missing sections inside the download window.
//!    Includes a head-of-line hedge for the next-sequential block
//!    when its sections have been inflight > 8 s.
//! 4. Send `SyncInfo` to each peer whose per-peer timer elapsed —
//!    Step C anchor variant if eligible, otherwise tip-tail payload.
//! 5. Emit the operator heartbeat (always — surfaces stalls).
//! 6. Publish the operator-API snapshot.
//!
//! All state mutation flows through `NodeState`; the helper calls into
//! `flush_actions`, `cleanup_disconnected_peer`, `send_to_peer`, and the
//! sibling `heartbeat` / `snapshot_emit` / `sync_helpers` submodules.

use std::time::Instant;

use ergo_p2p::handshake::PeerFeature;
use ergo_p2p::message;
use ergo_p2p::peer::{PeerId, SyncVersion};
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::read_header;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_sync::snapshot_bootstrap::BootstrapState;
use tracing::{info, warn};

use super::heartbeat;
use super::snapshot_emit::publish_snapshot;
use super::sync_helpers::try_send_anchor_sync_info;
use super::{cleanup_disconnected_peer, flush_actions, send_to_peer, NodeState};

pub(super) fn handle_sync_tick(state: &mut NodeState) {
    let now = Instant::now();

    // 0-pre. NiPoPoW bootstrap (Part 2 §14.6). Runs BEFORE Mode 2
    // discovery so the proof apply can complete before snapshot
    // manifest verification needs a canonical header at
    // snapshot_height (Phase 0 §6.1 corrected ordering). No-op
    // unless `[node] nipopow_bootstrap = true` AND history is
    // empty AND the reducer hasn't reached terminal state.
    drive_popow_bootstrap(state, now);

    // 0. Mode 2 consume-side discovery fan-out. No-op unless this
    // node was booted with `utxo_bootstrap = true` AND we have no
    // UTXO state yet AND quorum hasn't been reached. Currently
    // wedged behind the activation gate in `validate_runtime_mode_support`
    // — fires for real once part 2j lifts the gate.
    request_snapshots_info_fan_out(state);
    // 0b. Once Selected, drive the manifest-download phase: send
    // GetManifest to a voter, evict silent voters on timeout. Same
    // activation-gated dormancy as the discovery fan-out.
    drive_manifest_request(state, now);
    // 0c. Once ManifestVerified, drive chunk download:
    // initialize ChunkAssembly if needed, fan out chunk requests
    // across quorum voters, expire stalled slots, and when complete
    // hand the bytes to the reconstructor.
    drive_chunk_download(state, now);
    // 0d. Once reconstruction completes, install the snapshot
    // atomically. Re-fetches header.state_root at snapshot_height
    // to catch any reorg that happened between 2g's trust check
    // and now.
    install_reconstructed_snapshot(state);
    // 0e. Serve-side: rebuild the cached SnapshotServer when the
    // tip crosses a Scala-aligned snapshot height. Runs for any
    // node with full UTXO state — peers asking for snapshots get
    // the current cached one.
    maybe_rebuild_serve_snapshot(state);

    // 1. Check delivery timeouts
    let timeout_actions =
        state
            .executor
            .check_timeouts(&mut state.coordinator, &state.peer_manager, now);
    flush_actions(state, timeout_actions);

    // 2. Evict stale peers
    let evicted = state.peer_manager.evict_timed_out(now);
    if !evicted.is_empty() {
        info!(count = evicted.len(), "evicted stale peers");
    }
    for addr in evicted {
        let actions = state.executor.on_peer_disconnected(
            &addr,
            &mut state.coordinator,
            &state.peer_manager,
            now,
        );
        cleanup_disconnected_peer(state, &addr);
        // Timeout eviction is a dial failure for known addresses too
        // (peer never completed handshake) — apply backoff so the dial
        // cycle stops re-trying the same dead address every tick.
        state.peer_manager.mark_dial_failed(&addr, now);
        flush_actions(state, actions);
    }

    // 2.5 Level-triggered headers-synced fallback (deliberate, consensus-safe
    // divergence from Scala). `check_headers_synced` flips the latch only on
    // the edge of validating a header that is *fresh* per `header.isNew`; on an
    // idle/stale tip (common when syncing a quiet testnet from genesis) that
    // edge never fires and the entire block-download pipeline below stays
    // gated off forever. If we have demonstrably caught up to the network —
    // a majority of peers confirm our exact CURRENT tip — start block
    // downloads anyway. Blocks are still fully validated, so this only affects
    // WHEN download begins, never WHAT is accepted.
    let current_best_header_id = state.store.chain_state_meta().best_header_id;
    if state
        .coordinator
        .try_mark_caught_up_to_peers(now, current_best_header_id)
    {
        info!("headers chain synced — caught up to peers (level-triggered fallback)");
    }

    // 3. Try to apply the next sequential block if sections are available.
    if state.coordinator.sync_state().headers_chain_synced() {
        // Startup recovery bailed with "headers not near tip" when
        // best_header's timestamp was > HEADER_CHAIN_DIFF * block_time
        // stale. Once incoming headers catch up and flip the flag, re-run
        // recovery once so the pending-block queue gets seeded for the
        // header-gap the startup pass skipped. Without this, section
        // requests only go out for tip-adjacent blocks and best_full_block
        // never advances through the gap.
        if !state.executor.recovery_done() {
            // Mid-loop corruption is unrecoverable: the same persisted row
            // will fail validation downstream too. Panic so the operator
            // sees the affected id rather than busy-looping silently.
            let recovered = state
                .executor
                .recover_coordinator(&state.store, &mut state.coordinator)
                .expect("recover_coordinator: persistent header table integrity failure");
            if recovered > 0 {
                info!(
                    recovered,
                    "recovered pending blocks after headers caught up"
                );
            }
        }

        let cs = state.store.chain_state_meta();
        let next_height = cs.best_full_block_height + 1;
        let next_header_height = cs.best_header_height;
        if next_height <= next_header_height {
            // Try to assemble and apply blocks sequentially. No actions to
            // flush — try_apply_next_blocks emits state mutations only
            // (best_full_block_height, assembly), per executor doc.
            //
            // M5 wallet-hook plumbing: build a `WalletWiring` (hook +
            // rescan guard) and thread it through the executor so:
            //   - synchronous-path forward apply commits chain +
            //     wallet inside the same redb write_txn (truly
            //     atomic).
            //   - pipeline-path forward apply flushes the queued
            //     chain batch (with fsync in IBD) BEFORE the wallet
            //     write_txn — chain durable, then wallet. Still
            //     two-commit, not atomic; pipeline-worker
            //     integration is the M5 final slice in audit-todo.
            //   - rollback path (executor →
            //     rollback_full_chain_to_best_header → store
            //     rollback_to) rolls back chain + wallet inside a
            //     single write_txn; the rescan guard
            //     unconditionally invalidates wallet scan state
            //     when wallet history cannot be replayed (missing
            //     section / read error), forcing a rescan on
            //     restart.
            // The prior post-apply hook fire on a separate write_txn
            // is removed — it was the pre-M5 non-atomic seam.
            let rescan_guard = crate::wallet_boot::ProdRescanGuard;
            let wallet_wiring =
                state
                    .wallet_hook
                    .as_deref()
                    .map(|h| ergo_state::wallet::WalletWiring {
                        hook: h as &dyn ergo_state::wallet::WalletApplyHook,
                        rescan_guard: &rescan_guard,
                    });
            state.executor.try_apply_next_blocks(
                &mut state.store,
                &mut state.coordinator,
                now,
                wallet_wiring,
            );
            // Mirror the post-apply prune sentinel into
            // sync_state. Mode 2 / NiPoPoW writers can advance
            // the sentinel even when blocks_to_keep = -1. Only
            // mirror when > 1 so archive nodes don't pay the
            // per-Inv index lookup overhead.
            if let Ok(sentinel) = state.store.read_minimal_full_block_height() {
                if sentinel > 1 {
                    state
                        .coordinator
                        .sync_state_mut()
                        .set_prune_sentinel(sentinel);
                }
            }
        }

        // Also request sections for pending blocks in the download window.
        let missing_actions = state.executor.request_missing_sections(
            &mut state.coordinator,
            &state.store,
            &state.peer_manager,
            now,
        );
        flush_actions(state, missing_actions);

        // HOL hedge: early-reassign the next sequential block's sections
        // if they've been inflight > 8 s so a slow peer doesn't stall
        // the entire apply pipeline for the full 30 s timeout.
        let hol_h = state.store.chain_state_meta().best_full_block_height;
        let hol_actions = state.executor.check_hol_hedges(
            hol_h,
            &mut state.coordinator,
            &state.peer_manager,
            now,
        );
        flush_actions(state, hol_actions);
    }

    // 4. Send SyncInfo to each connected peer whose per-peer timer
    //    has elapsed. Per-peer (not global) so every peer's Inv pump
    //    stays primed independently — without this filter the global
    //    timer collapsed header request fanout to ~1-2 active peers
    //    per interval. The collect()-then-iter pattern dodges a
    //    borrow conflict between coordinator (read for filter, mut
    //    for mark_sync_sent) and peer_manager.
    let peer_list: Vec<(PeerId, SyncVersion)> = state
        .peer_manager
        .connected_peers()
        .map(|p| (p.addr, p.sync_version))
        .filter(|(addr, _)| state.registry.peers.contains_key(addr))
        .filter(|(addr, _)| state.coordinator.sync_state().should_send_sync(*addr, now))
        .collect();
    for (peer_id, sv) in peer_list {
        // Step C path: if eligible, send a single-anchor V1 SyncInfo
        // (Scala interprets as `Fork`, returns up to 400 novel IDs).
        // Otherwise fall back to the standard tip-tail payload.
        // `chain` is acquired inside the fallback branch so the
        // outer `&state.store` borrow doesn't conflict with the
        // `&mut state` taken by `try_send_anchor_sync_info`.
        if !try_send_anchor_sync_info(state, &peer_id, now) {
            let payload = ergo_sync::coordinator::build_sync_info_payload(sv, &state.store);
            send_to_peer(state, &peer_id, message::CODE_SYNC_INFO, payload);
        }
        state
            .coordinator
            .sync_state_mut()
            .mark_sync_sent(peer_id, now);
    }

    // 5. Heartbeat: always fires so a stalled sync is visible.
    heartbeat::emit_heartbeat(state, now);

    // 6. Publish operator-API snapshot.
    publish_snapshot(state, now);
}

/// Mode 2 consume-side discovery fan-out.
///
/// Sends `GetSnapshotsInfo` (code 76) to handshaken peers that
/// advertise UTXO+verify_tx in their `PeerFeature::Mode` (i.e. Mode
/// 1/2/3 peers — Mode 5/6 peers serve nothing and are skipped).
/// Each eligible peer is queried at most once per discovery epoch;
/// the reducer's `should_query` / `mark_queried` enforces this.
///
/// Returns early when:
/// * the node wasn't booted with `utxo_bootstrap = true`, or
/// * we already have applied UTXO state (`best_full_block > 0`), or
/// * quorum has been reached (`BootstrapState::Selected`).
///
/// Until part 2j lifts the activation gate this is effectively
/// dead code in production — `utxo_bootstrap_enabled` is always
/// false because `validate_runtime_mode_support` refuses the
/// config that would set it true. The plumbing flips on
/// automatically when the gate lifts.
fn request_snapshots_info_fan_out(state: &mut NodeState) {
    if !state.utxo_bootstrap_enabled {
        return;
    }
    if state.store.chain_state_meta().best_full_block_height > 0 {
        return;
    }
    if matches!(
        state.snapshot_bootstrap.state(),
        BootstrapState::Selected { .. }
    ) {
        return;
    }

    // Collect eligible peers up front so the registry borrow ends
    // before the mutating `mark_queried` calls.
    let eligible: Vec<PeerId> = state
        .peer_manager
        .active_peers()
        .filter_map(|info| {
            let spec = info.peer_spec.as_ref()?;
            let utxo_serving = spec.features.iter().any(|f| {
                matches!(
                    f,
                    PeerFeature::Mode {
                        state_type: 0,
                        verify_tx: true,
                        ..
                    }
                )
            });
            if utxo_serving && state.snapshot_bootstrap.should_query(&info.addr) {
                Some(info.addr)
            } else {
                None
            }
        })
        .collect();

    if eligible.is_empty() {
        return;
    }

    let payload = message::serialize_get_snapshots_info();
    for peer in eligible {
        // try_send returns false when the per-peer outbound channel
        // is full; in that case we skip the mark so we'll retry the
        // peer next tick. Avoids a "marked but never delivered" leak
        // that would silently exclude the peer from the discovery
        // round.
        if send_to_peer(
            state,
            &peer,
            message::CODE_GET_SNAPSHOTS_INFO,
            payload.clone(),
        ) {
            state.snapshot_bootstrap.mark_queried(peer);
        }
    }
}

/// NiPoPoW bootstrap (Part 2 sub-phase 14.6) consume side. Three
/// actions per tick, gated by `popow_bootstrap.is_active`:
///
/// 1. Request fan-out: send `GetNipopowProof(m=6, k=10)` to each
///    active peer we haven't already asked. Scala peers respond
///    with their pre-computed proof anchored at
///    `snapshot_height - LastHeadersInContext`
///    (`HeadersProcessor.scala:179`).
/// 2. Apply on quorum: once the reducer transitions to
///    `BestSelected` (after at least `quorum` valid proofs have
///    been latched), hand the best proof to
///    `StateStore::apply_popow_proof`. On success, mark the
///    reducer terminal.
/// 3. After apply, the existing header_proc pipeline picks up
///    the bounded forward catchup from `best_header_height + 1`
///    naturally — no separate code path needed.
///
/// No-op when `nipopow_bootstrap` is disabled or when the reducer
/// has reached terminal state.
fn drive_popow_bootstrap(state: &mut NodeState, now: Instant) {
    use ergo_p2p::message;
    use ergo_validation::popow::NipopowVerificationResult;

    // Activity gate: the reducer stays active while the store is
    // still in Dense mode (no proof applied yet). We deliberately do
    // NOT gate on `best_header_height == 0` — normal header sync can
    // race ahead between boot and quorum-met, but apply_popow_proof
    // only refuses to run after the mode flips to PoPowSparse.
    let store_is_dense = matches!(
        state.store.chain_state_meta().header_availability,
        ergo_state::chain::HeaderAvailability::Dense
    );
    let Some(popow) = state.popow_bootstrap.as_mut() else {
        return;
    };
    if !store_is_dense
        || matches!(
            popow.state(),
            ergo_sync::popow_bootstrap::PopowBootstrapState::Applied
        )
    {
        return;
    }

    // Apply phase first: if quorum reached, run the apply path. We
    // do this BEFORE the request phase so a node that just hit
    // quorum doesn't waste a tick fan-out before applying.
    if popow.quorum_reached() {
        // Clone the best proof out so we can release the &mut popow
        // borrow before calling state.store.apply_popow_proof (which
        // also takes &mut self via the store).
        let proof_opt = popow.best_proof().cloned();
        if let Some(proof) = proof_opt {
            match state
                .store
                .as_utxo_mut()
                .expect("utxo-only: NiPoPoW proof apply is gated off in digest mode")
                .apply_popow_proof(&proof)
            {
                Ok(()) => {
                    info!(
                        suffix_height = proof.suffix_head.header.height,
                        tail_len = proof.suffix_tail.len(),
                        "NiPoPoW: applied verified proof to history",
                    );
                    // Mode 3 Phase 4 — mirror the proof-time prune
                    // sentinel into SyncState so the coordinator's
                    // request-side gate denies sub-sentinel sections
                    // from the first post-proof tick. Symmetric with
                    // the install_snapshot_state branch above.
                    if let Ok(sentinel) = state.store.read_minimal_full_block_height() {
                        if sentinel > 1 {
                            state
                                .coordinator
                                .sync_state_mut()
                                .set_prune_sentinel(sentinel);
                        }
                    }
                    refresh_api_identity(state);
                    if let Some(popow) = state.popow_bootstrap.as_mut() {
                        popow.mark_applied();
                    }
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "NiPoPoW: apply_popow_proof failed; bootstrap aborted",
                    );
                    // Best-effort: clear the reducer so subsequent
                    // ticks don't loop on the same proof.
                    if let Some(popow) = state.popow_bootstrap.as_mut() {
                        popow.mark_applied();
                    }
                }
            }
        }
        return;
    }

    // Request phase: fan out to peers that pass the NipopowSupport
    // filter (Scala parity:
    // VersionBasedPeerFilteringRule.NipopowSupportFilter at
    // VersionBasedPeerFilteringRule.scala:79-91). Excludes peers
    // that are themselves NiPoPoW-bootstrapped (they have no
    // extension/interlinks data to prove from) and peers below the
    // Version::NIPOPOW threshold.
    let eligible: Vec<_> = state.peer_manager.popow_capable_peers(now);
    let pending = popow.pending_request_peers(&eligible);
    if pending.is_empty() {
        return;
    }
    // header_id_opt = None lets Scala serve its pre-computed
    // anchored proof (HeadersProcessor.scala:179 takes the proof
    // at snapshot_height - LastHeadersInContext).
    let payload = message::serialize_get_nipopow_proof(&ergo_p2p::types::NipopowProofData {
        m: ergo_p2p::types::P2P_NIPOPOW_PROOF_M,
        k: ergo_p2p::types::P2P_NIPOPOW_PROOF_K,
        header_id_opt: None,
    });
    for peer in pending {
        if send_to_peer(
            state,
            &peer,
            message::CODE_GET_NIPOPOW_PROOF,
            payload.clone(),
        ) {
            if let Some(popow) = state.popow_bootstrap.as_mut() {
                popow.mark_requested(peer, now);
            }
        }
    }
    // Silence the unused warning when only the apply path was hit
    // above; the borrow-checker forced us to scope reads of `popow`
    // tightly around state.store mutations.
    let _ = NipopowVerificationResult::ValidationError;
}

/// Mode 2 consume-side: drive the post-Selected manifest-download
/// state machine. Three actions, in this fixed order:
///
/// 1. Evict the pending voter if they've stayed silent longer than
///    [`ergo_sync::snapshot_bootstrap::MANIFEST_REQUEST_TIMEOUT`].
///    This unblocks rotation when the chosen peer is slow or
///    censoring.
/// 2. Park if the header chain hasn't reached the snapshot height
///    yet — the trust check needs the canonical state_root at
///    that height, which isn't available until headers catch up.
/// 3. Send `GetManifest` to a quorum voter and mark the request
///    pending. Strict ownership: only that peer's reply will be
///    accepted (enforced by the reducer).
fn drive_manifest_request(state: &mut NodeState, now: Instant) {
    if !state.utxo_bootstrap_enabled {
        return;
    }
    if state.store.chain_state_meta().best_full_block_height > 0 {
        return;
    }

    state.snapshot_bootstrap.check_request_timeout(now);

    let Some((peer, height, manifest_id)) = state.snapshot_bootstrap.should_request_manifest()
    else {
        return;
    };

    // Park while headers lag. The trust check requires the
    // canonical header at `height`; until best-header catches up
    // we can't verify, so we don't request. Each sync_tick re-checks.
    let best_header = state.store.chain_state_meta().best_header_height as i32;
    if best_header < height {
        return;
    }

    let payload = message::serialize_get_manifest(&manifest_id);
    if send_to_peer(state, &peer, message::CODE_GET_MANIFEST, payload) {
        state
            .snapshot_bootstrap
            .mark_manifest_requested(peer, height, manifest_id, now);
    }
}

/// Mode 2 consume-side: drive the chunk-download phase. Runs at
/// the top of every sync_tick once the manifest has been verified.
///
/// Step 1 — lazy init: when state is `ManifestVerified` and no
///   `ChunkAssembly` exists yet, take the verified manifest bytes,
///   enumerate expected chunk IDs, create the assembly, stash the
///   bytes in `state.pending_manifest_bytes` for the eventual
///   reconstruction.
/// Step 2 — drive: check timeouts (frees stalled slots into the
///   next-request queue), then send `GetUtxoSnapshotChunk` to
///   round-robin'd quorum voters for each freshly issuable slot.
/// Step 3 — complete: when every chunk has arrived, take chunks +
///   manifest bytes and run `reconstruct_tree`. Stash the result
///   in `state.reconstructed_tree` for 2i.
fn drive_chunk_download(state: &mut NodeState, now: Instant) {
    if !state.utxo_bootstrap_enabled {
        return;
    }
    if state.store.chain_state_meta().best_full_block_height > 0 {
        return;
    }

    // Step 1: lazy init.
    if state.chunk_assembly.is_none()
        && matches!(
            state.snapshot_bootstrap.state(),
            BootstrapState::ManifestVerified { .. }
        )
    {
        let Some(bytes) = state.snapshot_bootstrap.take_verified_manifest_bytes() else {
            return;
        };
        let expected_ids =
            match ergo_state::avl::snapshot_codec::enumerate_expected_chunk_ids(&bytes) {
                Ok(ids) => ids,
                Err(e) => {
                    warn!(
                        error = %e,
                        "Mode 2: manifest enumeration failed; bootstrap halted (restart data_dir)",
                    );
                    return;
                }
            };
        info!(
            count = expected_ids.len(),
            "Mode 2: initialized chunk assembly from verified manifest",
        );
        state.chunk_assembly = Some(ergo_sync::snapshot_bootstrap::ChunkAssembly::new(
            expected_ids,
        ));
        state.pending_manifest_bytes = Some(bytes);
    }

    // Steps 2 + 3: drive the assembly (split borrows below).
    let Some(to_request) = state.chunk_assembly.as_mut().map(|ca| {
        let stale = ca.check_timeouts(now);
        if !stale.is_empty() {
            info!(
                count = stale.len(),
                "Mode 2: chunk-request slots timed out, re-queued",
            );
        }
        ca.next_to_request()
    }) else {
        return;
    };

    if !to_request.is_empty() {
        // Build the chunk-serving peer pool: voters from the manifest
        // quorum FIRST (they self-attested to having this snapshot
        // indexed), then any other connected archive peer as fallback.
        // Chunks are hash-authenticated via the manifest commitment
        // (`on_chunk_received` recomputes the subtree label and drops
        // anything not in the expected set), so trust is irrelevant
        // for the chunk wire — broadening the pool just spreads load
        // and survives voter churn during the ~5-15 min download.
        // Restricting to voters alone deadlocks if voters disconnect:
        // `try_send` returns false silently, the slot never gets
        // `mark_requested`, and `next_to_request` re-offers the same
        // chunk indefinitely.
        let voters = state.snapshot_bootstrap.voters_for_selected_manifest();
        let voter_set: std::collections::HashSet<PeerId> = voters.iter().copied().collect();
        let mut pool: Vec<PeerId> = voters;
        for p in state.peer_manager.block_section_capable_peers(now) {
            if !voter_set.contains(&p) {
                pool.push(p);
            }
        }
        if pool.is_empty() {
            return;
        }
        let mut sent = 0usize;
        for (i, subtree_id) in to_request.iter().enumerate() {
            // Rotate through the pool; on a re-queue this hands the
            // chunk to a different peer than the one that just timed
            // out, which is the entire point.
            let peer = pool[i % pool.len()];
            let payload = message::serialize_get_utxo_chunk(subtree_id.as_bytes());
            if send_to_peer(state, &peer, message::CODE_GET_UTXO_CHUNK, payload) {
                if let Some(ca) = state.chunk_assembly.as_mut() {
                    ca.mark_requested(*subtree_id, peer, now);
                }
                sent += 1;
            }
        }
        if sent > 0 || !to_request.is_empty() {
            if let Some(ca) = state.chunk_assembly.as_ref() {
                info!(
                    sent,
                    requested = to_request.len(),
                    pool_size = pool.len(),
                    received = ca.received_count(),
                    total = ca.total_count(),
                    "Mode 2: chunk batch dispatched",
                );
            }
        }
    }

    // Step 3: reconstruct when complete.
    let ready_to_reconstruct = state
        .chunk_assembly
        .as_ref()
        .is_some_and(|ca| ca.is_complete())
        && state.reconstructed_tree.is_none()
        && state.pending_manifest_bytes.is_some();
    if ready_to_reconstruct {
        let chunks = state
            .chunk_assembly
            .as_mut()
            .and_then(|ca| ca.take_chunks());
        let manifest_bytes = state.pending_manifest_bytes.take();
        match (chunks, manifest_bytes) {
            (Some(chunks), Some(bytes)) => {
                match ergo_state::avl::snapshot_codec::reconstruct_tree(&bytes, &chunks) {
                    Ok(tree) => {
                        info!(
                            root_label = %hex::encode(tree.root_label.as_bytes()),
                            tree_height = tree.tree_height,
                            node_count = tree.nodes.len(),
                            "Mode 2: UTXO tree reconstructed from snapshot",
                        );
                        state.reconstructed_tree = Some(tree);
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "Mode 2: reconstruction failed; bootstrap halted (restart data_dir)",
                        );
                    }
                }
            }
            _ => {
                warn!(
                    "Mode 2: assembly complete but missing chunks or manifest bytes — \
                     init-time bug; bootstrap halted",
                );
            }
        }
    }
}

/// Mode 2 consume-side: install the reconstructed UTXO snapshot
/// into the running `StateStore`. Final step of bootstrap.
///
/// Re-verifies trust at install time: looks up
/// `header.state_root` at the snapshot height again and confirms
/// the reconstructed tree's root still matches. This catches
/// reorgs that may have flipped the canonical header at the
/// snapshot height between 2g's trust check and now. On
/// mismatch, the reconstructed tree is discarded — operator
/// restarts with a fresh data_dir.
///
/// On success, sets `best_full_block_height = snapshot_height`
/// and `best_full_block_id = header_id`, atomically with the
/// AVL_NODES bulk-write and STATE_META update. The normal block-
/// sync path then takes over from `snapshot_height + 1`.
fn install_reconstructed_snapshot(state: &mut NodeState) {
    let Some(reconstructed) = state.reconstructed_tree.take() else {
        return;
    };

    // Pull snapshot_height from the bootstrap state.
    let (snapshot_height, manifest_id) = match state.snapshot_bootstrap.state() {
        BootstrapState::ManifestVerified {
            height,
            manifest_id,
        } => (height, manifest_id),
        other => {
            warn!(
                state = ?other,
                "Mode 2: install called without ManifestVerified — bootstrap halted",
            );
            return;
        }
    };

    // Sanity: reconstructed.root_label must equal manifest_id (both
    // come from authenticated sources; failure here is a code bug).
    if reconstructed.root_label.as_bytes() != &manifest_id {
        warn!(
            reconstructed = %hex::encode(reconstructed.root_label.as_bytes()),
            manifest_id = %hex::encode(manifest_id),
            "Mode 2: reconstructed root mismatches manifest_id (code bug); halted",
        );
        return;
    }

    // Re-fetch the canonical header at snapshot_height. A reorg
    // since 2g's trust check would flip this; the install would
    // then refuse on root mismatch and the operator restarts.
    //
    // In PoPowSparse mode (NiPoPoW-bootstrapped node), `SparseGap`
    // at `snapshot_height` means bounded forward catchup hasn't
    // populated the row yet — defer the install until the next tick
    // (Phase 0 §6.1 + §10.E). `AboveTip` and `Err` are still halt
    // conditions (operator must intervene).
    use ergo_state::chain::HeightLookup;
    let header_id = match state
        .store
        .as_utxo()
        .expect("utxo-only: Mode 2 snapshot install is gated off in digest mode")
        .lookup_header_at_height(snapshot_height as u32)
    {
        Ok(HeightLookup::Dense(id)) => id,
        Ok(HeightLookup::SparseGap) => {
            tracing::debug!(
                height = snapshot_height,
                "Mode 2: install — SparseGap at snapshot height; deferring (catchup pending)",
            );
            return;
        }
        Ok(HeightLookup::AboveTip) => {
            warn!(
                height = snapshot_height,
                "Mode 2: install — snapshot height above best_header_height; halted",
            );
            return;
        }
        Err(e) => {
            warn!(error = %e, "Mode 2: install — chain index lookup failed; halted");
            return;
        }
    };
    let header_bytes = match state.store.get_header(&header_id) {
        Ok(Some(b)) => b,
        _ => {
            warn!(
                header_id = %hex::encode(header_id),
                "Mode 2: install — header bytes missing; halted",
            );
            return;
        }
    };
    let header = match read_header(&mut VlqReader::new(&header_bytes)) {
        Ok(h) => h,
        Err(e) => {
            warn!(error = %e, "Mode 2: install — header parse failed; halted");
            return;
        }
    };

    let snapshot_height_u32 = snapshot_height as u32;
    match state
        .store
        .as_utxo_mut()
        .expect("utxo-only: Mode 2 snapshot install is gated off in digest mode")
        .install_snapshot_state(
            reconstructed,
            snapshot_height_u32,
            header_id,
            &header.state_root,
        ) {
        Ok(()) => {
            info!(
                snapshot_height = snapshot_height,
                header_id = %hex::encode(header_id),
                manifest_id = %hex::encode(manifest_id),
                "Mode 2: bootstrap complete — UTXO state installed; \
                 normal block sync resumes from snapshot_height + 1",
            );
            // Align the coordinator's SyncState with the store's new
            // best_full_block_height. WITHOUT this, the coordinator
            // keeps its SyncState.best_full_block_height = 0 (from
            // boot), and `blocks_to_download()` filters the pending
            // queue by `best_full_block_height + download_window` =
            // [0, 384]. Recovery seeds pending blocks at heights
            // ~1.78M (snapshot+1 onwards), which all fall OUTSIDE
            // that stale window → empty request batch every tick →
            // post-install stall.
            //
            // Mode 2 part 2T fix — found by Codex audit of our flow
            // vs Scala's. Scala doesn't have this split-brain because
            // `nextModifiersToDownload` reads `bestFullBlockOpt` from
            // the history reader each call rather than a coordinator-
            // side cached copy
            // (ToDownloadProcessor.scala:82-103). Our cached
            // SyncState needs explicit sync after install.
            state
                .coordinator
                .sync_state_mut()
                .set_best_full_block(snapshot_height_u32);
            // Mode 3 Phase 4 — mirror the install-time prune
            // sentinel into SyncState so the coordinator's
            // request-side gate denies sub-sentinel sections from
            // the first post-install tick rather than waiting for
            // the first post-install block apply. Without this,
            // there is a window where the request gate misclassifies
            // and the executor/storage gates have to catch the
            // resulting sections.
            if let Ok(sentinel) = state.store.read_minimal_full_block_height() {
                if sentinel > 1 {
                    state
                        .coordinator
                        .sync_state_mut()
                        .set_prune_sentinel(sentinel);
                }
            }
            refresh_api_identity(state);
            // Release the section-suppression gate so the normal
            // block-section pipeline can take over from
            // `snapshot_height + 1`. Without this the coordinator
            // would keep dropping section requests + payloads even
            // though the bootstrap is over.
            state.coordinator.set_bootstrap_in_progress(false);
            // Reset the recovery latch so the next sync_tick
            // re-runs `recover_coordinator` against the new
            // `best_full_block_height`. Without this, the
            // coordinator's pending-block queue stays empty for
            // the post-snapshot window `[snapshot_height+1,
            // best_header_height]` and the executor never requests
            // sections — Mode 2 part 2L fix found during live-test
            // of the 2k path.
            state.executor.reset_recovery_done();
        }
        Err(e) => {
            warn!(
                error = %e,
                "Mode 2: install failed (reorg between 2g and 2i? \
                 reconstruction bug?) — operator must restart \
                 with a fresh data_dir",
            );
        }
    }
}

/// Mode 2 serve-side: rebuild the cached `SnapshotServer` when
/// the tip crosses a Scala-aligned snapshot boundary. Replaces
/// the previous cache (only one snapshot held at a time, matching
/// Scala's `SnapshotsDb` retention).
///
/// Build is `O(N)` in tree size — for mainnet's million-leaf
/// UTXO state this is non-trivial (seconds). It runs synchronously
/// on the sync_tick task. A real production deployment would
/// move this to a background worker; the MVP accepts the
/// blocking cost since snapshot heights are 52,224 blocks apart
/// (~5-7 days at mainnet block times).
fn maybe_rebuild_serve_snapshot(state: &mut NodeState) {
    // Mode-2 snapshot serving is UTXO-only: the digest backend has no AVL+
    // box arena to build a manifest from. Gate on the backend KIND (not the
    // `state_type` config) and BEFORE the tip checks, so a digest-backend node
    // returns here on every tick — covered by `mode_5_survives_a_sync_tick` —
    // rather than ever reaching the UTXO-only `build_snapshot_at_tip` below.
    if state.store.as_utxo().is_none() {
        return;
    }
    let tip = state.store.chain_state_meta().best_full_block_height;
    if tip == 0 {
        return;
    }
    if !tip.is_multiple_of(SNAPSHOT_EVERY) {
        return;
    }
    if state.snapshot_state.cached_height() == Some(tip) {
        return;
    }
    match state
        .store
        .as_utxo()
        .expect("utxo-only: gated by the as_utxo().is_none() early-return at fn top")
        .build_snapshot_at_tip(ergo_state::avl::snapshot_codec::MAINNET_MANIFEST_DEPTH)
    {
        Ok(server) => {
            info!(
                height = tip,
                manifest_id = %hex::encode(server.manifest_id.as_bytes()),
                chunk_count = server.chunks.len(),
                manifest_bytes = server.manifest_bytes.len(),
                "Mode 2 serve: snapshot rebuilt at tip",
            );
            state.snapshot_state.set(server);
        }
        Err(e) => {
            warn!(
                height = tip,
                error = %e,
                "Mode 2 serve: snapshot build failed",
            );
        }
    }
}

/// Scala-aligned snapshot cadence. Mainnet builds a snapshot
/// every 52,224 blocks (~5-7 days). Peers requesting
/// `SnapshotsInfo` get the latest snapshot at one of these
/// boundaries; off-cadence heights aren't served because no
/// other peer would know to ask for them.
const SNAPSHOT_EVERY: u32 = 52_224;

/// Rebuild `/api/v1/identity` from current store state and
/// publish into the lock-free slot the API bridge reads. Called
/// after each bootstrap transition that changes the prune
/// sentinel or bootstrap provenance. Errors are logged at
/// `warn` level so a stale identity is operator-visible rather
/// than silent.
fn refresh_api_identity(state: &mut NodeState) {
    if let Err(e) = crate::node::identity::rebuild_and_publish_identity(
        state
            .store
            .as_utxo()
            .expect("utxo-only: identity rebuild seam is gated off in digest mode"),
        &state.identity_inputs,
        &state.identity_slot,
    ) {
        warn!(
            error = %e,
            "Mode 3: failed to refresh /api/v1/identity after bootstrap transition; \
             API may report stale state until the next successful refresh",
        );
    }
}
