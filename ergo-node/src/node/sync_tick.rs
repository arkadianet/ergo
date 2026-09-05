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
//! 4. Proactive `SyncInfo` fanout on the global IBD/stable cadence
//!    (default 5 s / 15 s) to the Scala `peersToSyncWith` subset —
//!    Step C anchor variant if eligible, otherwise tip-tail payload.
//!    Reciprocal SyncInfo replies (inbound SyncInfo / post-header-
//!    progress) are handled off this tick and keep single-peer IBD fed.
//! 5. Emit the operator heartbeat (always — surfaces stalls).
//! 6. Publish the operator-API snapshot.
//!
//! All state mutation flows through `NodeState`; the helper calls into
//! `flush_actions`, `cleanup_disconnected_peer`, `send_to_peer`, and the
//! sibling `heartbeat` / `snapshot_emit` / `sync_helpers` submodules.

use std::time::{Duration, Instant};

use ergo_p2p::handshake::PeerFeature;
use ergo_p2p::message;
use ergo_p2p::peer::{ConnectionState, PeerId, SyncVersion};
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::read_header;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_sync::snapshot_bootstrap::BootstrapState;
use tracing::{info, warn};

use super::heartbeat;
use super::snapshot_emit::publish_snapshot;
use super::sync_helpers::try_send_anchor_sync_info;
use super::{cleanup_disconnected_peer, flush_actions, send_to_peer, NodeState};

/// Cadence for the subsystem-gauge line (audit #257): one structured
/// snapshot per minute gives RSS/leak attribution without flooding.
const GAUGE_INTERVAL: Duration = Duration::from_secs(60);

pub(super) fn handle_sync_tick(state: &mut NodeState) {
    let now = Instant::now();
    maybe_emit_gauges(state, now);

    // 0-pre. NiPoPoW bootstrap. Runs BEFORE Mode 2 discovery so the
    // proof apply can complete before snapshot manifest verification
    // needs a canonical header at snapshot_height. No-op
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
    for (addr, was_state) in evicted {
        let actions = state.executor.on_peer_disconnected(
            &addr,
            &mut state.coordinator,
            &state.peer_manager,
            now,
        );
        cleanup_disconnected_peer(state, &addr);
        // A pre-handshake timeout is a dial failure for known addresses
        // too (the peer never got as far as a handshake) — apply backoff
        // so the dial cycle stops re-trying the same dead address every
        // tick.
        //
        // A handshaked peer evicted for making no progress is NOT a dial
        // failure: the address answered, handshaked, and stayed reachable.
        // Counting it would bump `consecutive_failures` and push a
        // perfectly dialable address down the ranking, which is exactly
        // backwards — we want to be free to try it again later.
        if !matches!(
            was_state,
            ConnectionState::Active | ConnectionState::Degraded
        ) {
            state.peer_manager.mark_dial_failed(&addr, now);
        }
        flush_actions(state, actions);
    }

    // 2b. Sweep expired bans (internally cadence-gated to ~hourly; between
    // sweeps this is a cheap no-op). Keeps the ban list and its persisted
    // rows bounded without waiting for a restart.
    let swept = state.peer_manager.sweep_expired_bans(now);
    if swept > 0 {
        info!(count = swept, "swept expired bans");
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
            //     two-commit, not atomic; closing this seam requires
            //     pipeline-worker integration that does not yet exist.
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

    // 4. Proactive SyncInfo fanout — Scala `sendSync` +
    //    `peersToSyncWith` (ErgoSyncTracker.scala:180-205,
    //    ErgoNodeViewSynchronizer.scala:342-360).
    //
    //    Global cadence: IBD → `sync_interval` (default 5 s), stable →
    //    `sync_interval_stable` (default 15 s). The outer sync_tick
    //    still runs every 1 s for timeouts/HOL/heartbeat; only this
    //    fanout is gated. Peer subset (not all-peer broadcast):
    //    outdated peers, else Unknown + one random Older + all Fork,
    //    each respecting MinSyncInterval (20 s).
    //
    //    Single-peer IBD is kept fed by the reciprocal SyncInfo path
    //    in `on_sync_info` / post-header-progress dispatch — those
    //    bypass both the global cadence and MinSyncInterval.
    // Regime switch: Scala keys stable cadence on `numOfSeniors() == 0`
    // (no Older peers), not on full-block catch-up. Using `has_older_peers`
    // matches that header-sync regime; `is_ibd()` (body backlog) would
    // keep the 5 s tick through the entire post-header block download.
    let broadcast_interval = if state.coordinator.has_older_peers() {
        state.sync_interval
    } else {
        state.sync_interval_stable
    };
    if now.duration_since(state.last_sync_broadcast) >= broadcast_interval {
        state.last_sync_broadcast = now;

        let connected: Vec<(PeerId, SyncVersion)> = state
            .peer_manager
            .connected_peers()
            .map(|p| (p.addr, p.sync_version))
            .filter(|(addr, _)| state.registry.peers.contains_key(addr))
            .collect();
        let connected_addrs: Vec<PeerId> = connected.iter().map(|(a, _)| *a).collect();
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let selected = state
            .coordinator
            .peers_to_sync_with(&connected_addrs, now, seed);
        // collect()-then-iter: avoid borrow conflict between
        // coordinator (mark_sync_sent) and peer_manager / registry.
        let peer_list: Vec<(PeerId, SyncVersion)> = connected
            .into_iter()
            .filter(|(addr, _)| selected.contains(addr))
            .collect();
        for (peer_id, sv) in peer_list {
            // Step C path: if eligible, send a single-anchor V1 SyncInfo
            // (Scala interprets as `Fork`, returns up to 400 novel IDs).
            // Otherwise fall back to the standard tip-tail payload.
            // Stamp last_sync_sent / dispatch stats only after a real
            // send — a serialize failure must leave the peer eligible
            // for the next cadence tick (warn + retry), not burn the
            // MinSyncInterval / outdated clocks.
            let sent = if try_send_anchor_sync_info(state, &peer_id, now) {
                true
            } else {
                match ergo_sync::coordinator::build_sync_info_payload(sv, &state.store) {
                    Ok(payload) => {
                        send_to_peer(state, &peer_id, message::CODE_SYNC_INFO, payload);
                        true
                    }
                    Err(e) => {
                        warn!(peer = %peer_id, error = %e, "failed to serialize SyncInfo; skipping send");
                        false
                    }
                }
            };
            if sent {
                state
                    .coordinator
                    .sync_state_mut()
                    .mark_sync_sent(peer_id, now);
                state.coordinator.note_sync_info_dispatched(peer_id);
            }
        }
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

/// NiPoPoW bootstrap consume side. Three actions per tick, gated
/// by `popow_bootstrap.is_active`:
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
            // Header-level checkpoint (Scala `hdrCheckpoint`), defence in
            // depth. Proofs are already checked at ingress
            // (`messaging::popow`) so a violating proof never reaches the
            // verifier; this second check covers any future path that latches
            // a best proof without going through that handler.
            //
            // Rejection is NOT terminal: dropping only the latched proof and
            // returning to `Requesting` keeps the honest quorum count and lets
            // other providers finish the bootstrap. Marking the reducer
            // `Applied` here would let one bad proof disable NiPoPoW for the
            // whole run while reporting a bootstrap that never happened.
            let checkpoint = state.executor.header_checkpoint();
            if let Err(e) =
                ergo_sync::popow_bootstrap::check_proof_against_checkpoint(&proof, checkpoint)
            {
                let culprit = state
                    .popow_bootstrap
                    .as_mut()
                    .and_then(|popow| popow.reject_best_proof());
                warn!(
                    error = %e,
                    peer = ?culprit,
                    "NiPoPoW: best proof violates the configured header checkpoint; \
                     proof dropped, bootstrap continues",
                );
                if let Some(peer) = culprit {
                    flush_actions(
                        state,
                        vec![ergo_sync::coordinator::Action::Penalize {
                            peer,
                            penalty: ergo_p2p::peer::Penalty::Misbehavior,
                        }],
                    );
                }
                return;
            }
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
                    // Mode 3 — mirror the proof-time prune
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

/// Resolution of the canonical header id at a snapshot anchor
/// height, for the Mode 2 / Mode 4 install re-fetch and the
/// manifest-verification trust check.
///
/// The arms are NOT interchangeable, and in particular a
/// [`ergo_state::chain::HeightLookup::SparseGap`] splits into two
/// operationally opposite outcomes on a NiPoPoW-bootstrapped store:
///
/// * `Defer` — the anchor is inside the proof's dense range
///   `[dense_from_height, best_header_height]` but the index row has
///   not landed yet. Retry; the row materializes on its own.
/// * `UnreachableGap` — the anchor is BELOW `dense_from_height`, in
///   the proof's sparse prefix. Bounded forward catch-up starts at
///   `best_header_height + 1` and `rewrite_best_chain_into_index`
///   (`ergo-state/src/store/height_index.rs:204`) stops its backward
///   walk at the first height whose row already matches, so nothing
///   ever back-fills `HEADER_CHAIN_INDEX` below `dense_from_height`.
///   Treating this as `Defer` retries forever while logging "catchup
///   pending", so the bootstrap silently never completes. It is
///   terminal for THIS manifest/anchor: the discovered snapshot
///   epoch predates the NiPoPoW proof this node bootstrapped from,
///   and that specific (height, manifest_id) pair can never be
///   installed. Both call sites self-heal rather than halt the
///   node — `messaging/manifest.rs` evicts the voter and lets
///   discovery reselect; `install_reconstructed_snapshot` additionally
///   drops the already-verified manifest and any in-flight chunk
///   assembly for it before falling back to discovery, since the
///   race that produces `UnreachableGap` at install time (the proof
///   landing after this manifest already verified) means the bytes
///   in hand are for a manifest that can never be installed either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstallAnchor {
    /// `HEADER_CHAIN_INDEX[height]` is populated — install may run.
    Ready([u8; 32]),
    /// Index row absent but reachable: retry on the next tick.
    Defer,
    /// Index row absent and unreachable — the anchor sits in the
    /// NiPoPoW sparse prefix, which forward catch-up never fills.
    UnreachableGap { dense_from_height: u32 },
    /// The anchor is above `best_header_height`. Header sync cannot
    /// reach it from here; the operator must intervene.
    AboveTip,
}

/// Classify the snapshot anchor height against the store's
/// sparse-aware height lookup. Split out of
/// [`install_reconstructed_snapshot`] so the composed Mode 4
/// handoff — a `SparseGap` deferral resolving to `Dense` once
/// bounded forward catch-up indexes the height, versus the
/// permanently-unreachable sparse-prefix anchor — is directly
/// testable without standing up a full `NodeState`.
pub(crate) fn resolve_install_anchor(
    store: &ergo_state::store::StateStore,
    snapshot_height: u32,
) -> Result<InstallAnchor, ergo_state::store::StateError> {
    use ergo_state::chain::{HeaderAvailability, HeightLookup};
    Ok(match store.lookup_header_at_height(snapshot_height)? {
        HeightLookup::Dense(id) => InstallAnchor::Ready(id),
        HeightLookup::SparseGap => {
            match store.chain_state().header_availability {
                HeaderAvailability::PoPowSparse {
                    dense_from_height, ..
                } if snapshot_height < dense_from_height => {
                    InstallAnchor::UnreachableGap { dense_from_height }
                }
                // Dense-mode gaps and in-dense-range gaps are the
                // corruption / not-yet-indexed shapes the store
                // already logs; retrying is the safe response.
                _ => InstallAnchor::Defer,
            }
        }
        HeightLookup::AboveTip => InstallAnchor::AboveTip,
    })
}

/// Put a taken-but-not-yet-installed `reconstructed_tree` back so
/// the next `sync_tick` can retry the install. Centralizes the
/// restore so `install_reconstructed_snapshot`'s early returns
/// (and PR #313's checkpoint-anchor early return in the same
/// function) converge on one call site instead of each
/// reimplementing `state.reconstructed_tree = Some(reconstructed)`.
/// Deliberately NOT used by the `InstallAnchor::UnreachableGap`
/// arm, which abandons this manifest/epoch rather than deferring
/// a retry of it.
fn defer_reconstructed_tree(
    state: &mut NodeState,
    reconstructed: ergo_state::avl::snapshot_codec::ReconstructedTree,
) {
    state.reconstructed_tree = Some(reconstructed);
}

/// Mode 2 consume-side: install the reconstructed UTXO snapshot
/// into the running `StateStore`. Final step of bootstrap.
///
/// Re-verifies trust at install time: looks up
/// `header.state_root` at the snapshot height again and confirms
/// the reconstructed tree's root still matches. This catches
/// reorgs that may have flipped the canonical header at the
/// snapshot height between 2g's trust check and now. On
/// mismatch, the mismatch is permanent (a code bug, not a
/// transient condition) — the tree is put back so the function
/// stays retry-safe, but the same check will keep failing every
/// tick and the operator restarts with a fresh data_dir.
///
/// On success, sets `best_full_block_height = snapshot_height`
/// and `best_full_block_id = header_id`, atomically with the
/// AVL_NODES bulk-write and STATE_META update. The normal block-
/// sync path then takes over from `snapshot_height + 1`.
///
/// Every early return below that has not moved `reconstructed`
/// into [`defer_reconstructed_tree`] (or handed it to
/// `install_snapshot_state` at the bottom) MUST route through
/// that helper first. Reconstruction is one-shot: the step-3
/// trigger above requires both `chunk_assembly` completion and
/// `pending_manifest_bytes`, and this function's `take()` already
/// consumed both (`take_chunks()` + `.take()`) by the time any of
/// these arms run. Drop the tree here without restoring it and no
/// later tick can ever rebuild it — bootstrap silently stalls
/// forever with a verified manifest it can never install. The one
/// deliberate exception is `InstallAnchor::UnreachableGap`: that
/// arm is abandoning this manifest/epoch on purpose, not deferring
/// a retry of the same one, so the stale tree must NOT come back.
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
            return defer_reconstructed_tree(state, reconstructed);
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
        return defer_reconstructed_tree(state, reconstructed);
    }

    // Re-fetch the canonical header at snapshot_height. A reorg
    // since the earlier trust check would flip this; the install
    // would then refuse on root mismatch and the operator restarts.
    let header_id = match resolve_install_anchor(
        state
            .store
            .as_utxo()
            .expect("utxo-only: Mode 2 snapshot install is gated off in digest mode"),
        snapshot_height as u32,
    ) {
        Ok(InstallAnchor::Ready(id)) => id,
        Ok(InstallAnchor::Defer) => {
            tracing::debug!(
                height = snapshot_height,
                "Mode 2: install — SparseGap at snapshot height; deferring (catchup pending)",
            );
            return defer_reconstructed_tree(state, reconstructed);
        }
        Ok(InstallAnchor::UnreachableGap { dense_from_height }) => {
            // Reaching this arm at install time (rather than at
            // manifest-verify time in `messaging/manifest.rs`) means
            // the NiPoPoW proof landed AFTER this manifest already
            // verified against the canonical header — a narrow
            // tick-ordering race; Scala has no install-time check
            // here at all. The manifest itself is not dishonest, it
            // is just unreachable now: forward catchup can never
            // index below `dense_from_height`. Self-heal exactly like
            // the manifest-phase arm — drop the now-unreachable
            // manifest and any in-flight chunk-assembly state for it,
            // evict its voter, and fall back to discovery so a voter
            // advertising a reachable epoch can be selected instead,
            // rather than halting the node permanently.
            warn!(
                height = snapshot_height,
                dense_from_height,
                "Mode 4: install — snapshot anchor is below the NiPoPoW proof's \
                 dense_from_height, so forward catchup can never index it. The \
                 verified manifest is unreachable from this proof; dropping it \
                 and returning to manifest discovery for a reachable epoch.",
            );
            state.chunk_assembly = None;
            state.pending_manifest_bytes = None;
            // Evict a voter for the manifest we are ACTUALLY committed
            // to (verified > pending > selected, via
            // `voters_for_selected_manifest`'s latched target) — not
            // `voter_for_selected_manifest`'s live `selected` tally.
            // `selected` is recomputed on every incoming vote even
            // while a manifest sits `verified` (`recompute_selection`
            // does not consult the latch), so a later quorum for a
            // *different* manifest B can silently repoint `selected`
            // at B while `state()` still reports A as verified. Using
            // the live tally here would evict a B voter and clear A's
            // latch — leaving unreachable A retryable and damaging B's
            // still-good quorum. The latched voter list always names A.
            match state
                .snapshot_bootstrap
                .voters_for_selected_manifest()
                .into_iter()
                .next()
            {
                Some(peer) => state
                    .snapshot_bootstrap
                    .reject_manifest_and_evict_voter(peer),
                None => state.snapshot_bootstrap.drop_verified_manifest(),
            }
            return;
        }
        Ok(InstallAnchor::AboveTip) => {
            warn!(
                height = snapshot_height,
                "Mode 2: install — snapshot height above best_header_height; halted",
            );
            return defer_reconstructed_tree(state, reconstructed);
        }
        Err(e) => {
            warn!(error = %e, "Mode 2: install — chain index lookup failed; halted");
            return defer_reconstructed_tree(state, reconstructed);
        }
    };
    let header_bytes = match state.store.get_header(&header_id) {
        Ok(Some(b)) => b,
        _ => {
            warn!(
                header_id = %hex::encode(header_id),
                "Mode 2: install — header bytes missing; halted",
            );
            return defer_reconstructed_tree(state, reconstructed);
        }
    };
    let header = match read_header(&mut VlqReader::new(&header_bytes)) {
        Ok(h) => h,
        Err(e) => {
            warn!(error = %e, "Mode 2: install — header parse failed; halted");
            return defer_reconstructed_tree(state, reconstructed);
        }
    };

    let snapshot_height_u32 = snapshot_height as u32;

    // Header-checkpoint anchor (Scala `ergo.node.checkpoint`). A Mode 2
    // install adopts state the node never computed; the manifest is bound to
    // the header chain's `state_root`, and the header chain in turn is bound
    // to the operator's anchor. Refuse to install state at or above an anchor
    // this node has not actually passed. See the trust argument in
    // `ergo_sync::snapshot_bootstrap::manifest`.
    if let Some(ckpt) = state.executor.header_checkpoint() {
        let observed = match state
            .store
            .as_utxo()
            .expect("utxo-only: Mode 2 snapshot install is gated off in digest mode")
            .lookup_header_at_height(ckpt.height)
        {
            Ok(ergo_state::chain::HeightLookup::Dense(id)) => Some(id),
            Ok(ergo_state::chain::HeightLookup::SparseGap)
            | Ok(ergo_state::chain::HeightLookup::AboveTip) => None,
            Err(e) => {
                warn!(
                    error = %e,
                    "Mode 2: install — checkpoint-height chain lookup failed; halted",
                );
                return;
            }
        };
        if let Err(e) = ergo_sync::snapshot_bootstrap::snapshot_install_anchor_check(
            snapshot_height_u32,
            Some(ckpt),
            observed,
        ) {
            // Standing condition, re-evaluated every tick: warn once, then
            // keep it at debug so a refused install is visible without
            // flooding the log.
            if state.snapshot_anchor_refusal_warned {
                tracing::debug!(
                    error = %e,
                    snapshot_height = snapshot_height_u32,
                    "Mode 2: install still refused by the header checkpoint anchor",
                );
            } else {
                state.snapshot_anchor_refusal_warned = true;
                warn!(
                    error = %e,
                    snapshot_height = snapshot_height_u32,
                    checkpoint_height = ckpt.height,
                    "Mode 2: install refused — the configured header checkpoint has not \
                     been passed on this node's header chain; no snapshot will be \
                     installed until it is (clear [chain] checkpoint to install unanchored)",
                );
            }
            // Not a halt: the anchor may still become observed (bounded
            // catchup filling in the header chain). Put the reconstructed
            // tree back so the next tick's `take()` finds it again — the
            // tree can't be rebuilt otherwise, since `pending_manifest_bytes`
            // is already consumed by this point.
            return defer_reconstructed_tree(state, reconstructed);
        }
    }

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
            // Latch the install-time facts before the reducer clears its own
            // copy — see `NodeState::installed_snapshot`'s doc comment.
            state.installed_snapshot = Some((snapshot_height_u32, manifest_id));
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
            // Scala doesn't have this split-brain because
            // `nextModifiersToDownload` reads `bestFullBlockOpt` from
            // the history reader each call rather than a coordinator-
            // side cached copy
            // (ToDownloadProcessor.scala:82-103). Our cached
            // SyncState needs explicit sync after install.
            state
                .coordinator
                .sync_state_mut()
                .set_best_full_block(snapshot_height_u32);
            // Mode 3 — mirror the install-time prune
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

/// Emit one structured subsystem-gauge line per [`GAUGE_INTERVAL`].
///
/// Every counter here is a known memory lever or leak indicator (issue
/// #257): delivery-tracker maps, orphan buffer, peer/ban/address-book
/// containers, mempool depth. Static cadence anchor follows the
/// `RESCAN_IN_PROGRESS` static precedent — the action loop is the single
/// caller, so a process-wide millisecond anchor is sufficient and avoids
/// growing `NodeState`'s constructor surface again.
fn maybe_emit_gauges(state: &mut NodeState, now: Instant) {
    static LAST_GAUGE_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static BASE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let base = BASE.get_or_init(Instant::now);
    let rel_ms = now.duration_since(*base).as_millis() as u64;
    let last = LAST_GAUGE_MS.load(std::sync::atomic::Ordering::Relaxed);
    if last != 0 && rel_ms.saturating_sub(last) < GAUGE_INTERVAL.as_millis() as u64 {
        return;
    }
    LAST_GAUGE_MS.store(rel_ms, std::sync::atomic::Ordering::Relaxed);

    let dg = state.coordinator.delivery_gauges();
    let (orphan_groups, orphan_headers) = state.executor.orphan_header_gauges();
    let (peers, bans, known_addrs) = state.peer_manager.gauge_counts();
    let mempool_txs = state.mempool.size();

    // RSS KiB (Linux; 0 elsewhere) — pairs the gauge line with the
    // ergo_rss_kb /metrics series for attribution.
    let rss_kb = {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|status| {
                    status.lines().find_map(|l| {
                        l.strip_prefix("VmRSS:")
                            .and_then(|rest| rest.split_whitespace().next())
                            .and_then(|v| v.parse::<u64>().ok())
                    })
                })
                .unwrap_or(0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            0u64
        }
    };

    // Feed the incident ring's last-gauges slot so error snapshots carry
    // fresh attribution even between gauge ticks.
    crate::incidents::set_last_gauges(
        serde_json::json!({
            "dl_inflight": dg.inflight,
            "dl_late_acceptable": dg.late_acceptable,
            "dl_received": dg.received_set,
            "orphan_headers": orphan_headers,
            "peers": peers,
            "bans": bans,
            "known_addrs": known_addrs,
            "mempool_txs": mempool_txs,
            "rss_kb": rss_kb,
        })
        .to_string(),
    );

    info!(
        target: "node_gauges",
        rss_kb,
        peers, bans, known_addrs, mempool_txs,
        dl_inflight = dg.inflight,
        dl_peers_inflight = dg.peers_with_inflight,
        dl_received = dg.received_set,
        dl_late_acceptable = dg.late_acceptable,
        dl_recently_released = dg.recently_released,
        orphan_groups,
        orphan_headers,
        "subsystem gauges"
    );
}

#[cfg(test)]
mod tests {
    use super::{install_reconstructed_snapshot, resolve_install_anchor, InstallAnchor};
    use ergo_state::store::StateStore;
    use ergo_state::test_helpers::nipopow_proof_dense_from_2;
    use ergo_sync::snapshot_bootstrap::BootstrapState;

    // ----- helpers -----

    /// Open a store and commit the k=4 NiPoPoW fixture proof, which
    /// leaves the chain in `PoPowSparse { dense_from_height = 2 }`
    /// over heights 1..=8: height 1 is the sparse prefix (headers
    /// present in `HEADERS_BY_HEIGHT` but NOT in
    /// `HEADER_CHAIN_INDEX`), heights 2..=8 are the dense suffix.
    /// This is exactly the shape a Mode 4 node has between the
    /// NiPoPoW apply and bounded forward catch-up.
    fn popow_sparse_store(dir: &tempfile::TempDir) -> StateStore {
        let mut store = StateStore::open(&dir.path().join("state.redb")).expect("open store");
        store.initialize_genesis(&[]).expect("init genesis");
        store
            .apply_popow_proof(&nipopow_proof_dense_from_2())
            .expect("apply popow proof");
        store
    }

    /// Sparse-prefix height for the fixture above (`< dense_from_height`).
    const SPARSE_PREFIX_HEIGHT: u32 = 1;
    /// Dense-suffix tip height for the fixture above.
    const DENSE_TIP_HEIGHT: u32 = 8;
    /// `dense_from_height` the fixture proof commits.
    const PROOF_DENSE_FROM_HEIGHT: u32 = 2;

    // ----- happy path -----

    #[test]
    fn resolve_install_anchor_dense_suffix_height_is_ready() {
        let dir = tempfile::tempdir().unwrap();
        let store = popow_sparse_store(&dir);
        let expected = store
            .get_header_id_at_height(DENSE_TIP_HEIGHT)
            .unwrap()
            .expect("popow indexes the dense suffix");
        assert_eq!(
            resolve_install_anchor(&store, DENSE_TIP_HEIGHT).unwrap(),
            InstallAnchor::Ready(expected),
        );
    }

    #[test]
    fn resolve_install_anchor_deferred_gap_resolves_to_ready_after_catchup() {
        // The deferred branch must actually RESOLVE: once bounded
        // forward catch-up writes the `HEADER_CHAIN_INDEX` row for the
        // anchor height, the very next call returns `Ready` with the
        // canonical id. Without this the Mode 4 install would defer
        // forever and the node would never leave bootstrap.
        //
        // Driven at a DENSE-range height whose index row is missing —
        // the shape a mid-flight index write leaves — because the
        // sparse-prefix gap is terminal by construction (see the
        // `unreachable` test below).
        let dir = tempfile::tempdir().unwrap();
        let store = popow_sparse_store(&dir);
        let canonical_id = store
            .get_header_id_at_height(DENSE_TIP_HEIGHT)
            .unwrap()
            .expect("popow indexes the dense suffix");
        store
            .test_remove_header_chain_index_row(DENSE_TIP_HEIGHT)
            .unwrap();
        assert_eq!(
            resolve_install_anchor(&store, DENSE_TIP_HEIGHT).unwrap(),
            InstallAnchor::Defer,
            "a gap INSIDE the dense range is reachable — retry, do not halt",
        );

        store
            .test_force_put_header_chain_index(DENSE_TIP_HEIGHT, &canonical_id)
            .unwrap();
        assert_eq!(
            resolve_install_anchor(&store, DENSE_TIP_HEIGHT).unwrap(),
            InstallAnchor::Ready(canonical_id),
            "a deferred gap must become Ready once catch-up indexes the height",
        );
    }

    // ----- error paths -----

    #[test]
    fn resolve_install_anchor_sparse_prefix_height_is_unreachable_not_deferred() {
        // Composed Mode 4 bug guard. A snapshot anchor below the
        // proof's `dense_from_height` was previously classified as
        // `SparseGap` → "defer, catchup pending". But bounded forward
        // catch-up starts at `best_header_height + 1`, and
        // `rewrite_best_chain_into_index` stops its backward walk at
        // the first height whose index row already matches — so
        // nothing ever writes `HEADER_CHAIN_INDEX` below
        // `dense_from_height`. Deferring there is an infinite loop
        // that reports itself as healthy. It must be terminal.
        let dir = tempfile::tempdir().unwrap();
        let store = popow_sparse_store(&dir);
        assert_eq!(
            store.get_header_id_at_height(SPARSE_PREFIX_HEIGHT).unwrap(),
            None,
            "precondition: sparse prefix height is not in HEADER_CHAIN_INDEX",
        );
        assert!(
            !store
                .header_ids_at_height_all(SPARSE_PREFIX_HEIGHT)
                .unwrap()
                .is_empty(),
            "precondition: the header itself IS persisted — the gap is the INDEX",
        );
        assert_eq!(
            resolve_install_anchor(&store, SPARSE_PREFIX_HEIGHT).unwrap(),
            InstallAnchor::UnreachableGap {
                dense_from_height: PROOF_DENSE_FROM_HEIGHT,
            },
        );
    }

    #[test]
    fn resolve_install_anchor_above_header_tip_halts() {
        let dir = tempfile::tempdir().unwrap();
        let store = popow_sparse_store(&dir);
        assert_eq!(
            resolve_install_anchor(&store, DENSE_TIP_HEIGHT + 1).unwrap(),
            InstallAnchor::AboveTip,
            "an anchor past the validated header tip is a halt, never a deferral",
        );
    }

    // ----- reconstructed-tree retry (#319 review) -----

    fn synthetic_voter(port: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            port,
        )
    }

    /// Drive a fresh `SnapshotBootstrap` to `ManifestVerified` for
    /// `(height, manifest_id)`, voted in by three synthetic peers
    /// starting at `first_port`. Mirrors the real handshake: quorum
    /// vote → `Selected` → `mark_manifest_requested` → trust check
    /// passes → `accept_verified_manifest`.
    fn verified_bootstrap(
        height: i32,
        manifest_id: [u8; 32],
        first_port: u16,
    ) -> ergo_sync::snapshot_bootstrap::SnapshotBootstrap {
        let mut boot = ergo_sync::snapshot_bootstrap::SnapshotBootstrap::new();
        for p in first_port..first_port + 3 {
            boot.on_snapshots_info(synthetic_voter(p), &[(height, manifest_id)]);
        }
        let (peer, h, mid) = boot
            .should_request_manifest()
            .expect("3 matching votes must clear quorum and select a voter");
        boot.mark_manifest_requested(peer, h, mid, std::time::Instant::now());
        boot.accept_verified_manifest(Vec::new());
        boot
    }

    #[test]
    fn install_reconstructed_snapshot_deferred_gap_restores_tree_for_retry() {
        // CodeRabbit #319 (PRRT_kwDOSmAf_c6feH2w): `reconstructed_tree.take()`
        // runs unconditionally at the top of `install_reconstructed_snapshot`.
        // Reconstruction is one-shot — `take_chunks()` and
        // `pending_manifest_bytes.take()` are already consumed by the time
        // this function runs — so an `InstallAnchor::Defer` early return that
        // does not put the tree back leaves `reconstructed_tree` `None`
        // forever: bootstrap can vote, verify, and reconstruct once, then
        // stall silently on every later tick.
        let dir = tempfile::tempdir().unwrap();
        let store = popow_sparse_store(&dir);
        let canonical_id = store
            .get_header_id_at_height(DENSE_TIP_HEIGHT)
            .unwrap()
            .expect("popow indexes the dense suffix");
        // Remove the dense-suffix index row so the anchor height resolves
        // to `Defer` rather than `Ready` (mirrors a mid-flight catchup gap).
        store
            .test_remove_header_chain_index_row(DENSE_TIP_HEIGHT)
            .unwrap();

        let manifest_id = [0xABu8; 32];
        let mut state = crate::node::tests::make_state_with_store(store);
        state.snapshot_bootstrap = verified_bootstrap(DENSE_TIP_HEIGHT as i32, manifest_id, 1);
        state.reconstructed_tree = Some(ergo_state::avl::snapshot_codec::ReconstructedTree {
            nodes: Vec::new(),
            root_label: ergo_primitives::digest::Digest32::from_bytes(manifest_id),
            tree_height: 0,
        });

        install_reconstructed_snapshot(&mut state);

        assert!(
            state.reconstructed_tree.is_some(),
            "a Defer early return must restore reconstructed_tree so the next \
             tick can retry the install — dropping it here stalls bootstrap \
             forever, since reconstruction cannot re-run",
        );
        assert_eq!(
            state.snapshot_bootstrap.state(),
            BootstrapState::ManifestVerified {
                height: DENSE_TIP_HEIGHT as i32,
                manifest_id,
            },
            "Defer must not disturb the verified manifest — only retry the install",
        );

        // And the retry actually resolves: once the index row is written
        // (bounded forward catch-up completing), install succeeds on the
        // very next tick and consumes the restored tree.
        state
            .store
            .as_utxo()
            .unwrap()
            .test_force_put_header_chain_index(DENSE_TIP_HEIGHT, &canonical_id)
            .unwrap();

        install_reconstructed_snapshot(&mut state);
        assert!(
            state.reconstructed_tree.is_none(),
            "install must consume the restored tree once the gap resolves",
        );
    }

    #[test]
    fn install_reconstructed_snapshot_unreachable_gap_evicts_latched_voter_not_selected() {
        // CodeRabbit #319 (PRRT_kwDOSmAf_c6feH2x): the `UnreachableGap`
        // recovery arm used `voter_for_selected_manifest()`, which reads the
        // live `selected` tally. `selected` is recomputed on every vote
        // regardless of whether a manifest is already `verified` — so once
        // manifest A verifies and a later quorum selects a higher-height
        // manifest B, `selected` silently flips to B while `state()` still
        // reports A. Evicting "the selected manifest's voter" then evicts a
        // B voter and clears A's latch, leaving A retryable and damaging B's
        // still-good quorum. The fix targets `voters_for_selected_manifest()`
        // (verified > pending > selected), which stays pinned to A.
        let dir = tempfile::tempdir().unwrap();
        let store = popow_sparse_store(&dir);

        let manifest_a = [0xAAu8; 32];
        let manifest_b = [0xBBu8; 32];
        let mut state = crate::node::tests::make_state_with_store(store);

        // A verifies first, at the sparse-prefix height (unreachable once a
        // NiPoPoW proof lands — this is exactly the install-time race).
        state.snapshot_bootstrap = verified_bootstrap(SPARSE_PREFIX_HEIGHT as i32, manifest_a, 1);
        assert_eq!(
            state.snapshot_bootstrap.state(),
            BootstrapState::ManifestVerified {
                height: SPARSE_PREFIX_HEIGHT as i32,
                manifest_id: manifest_a,
            },
        );

        // A fresh quorum now lands for B at a higher, reachable height.
        // `selected` flips to B; `verified` still latches A.
        for p in 10u16..13 {
            state
                .snapshot_bootstrap
                .on_snapshots_info(synthetic_voter(p), &[(DENSE_TIP_HEIGHT as i32, manifest_b)]);
        }

        state.reconstructed_tree = Some(ergo_state::avl::snapshot_codec::ReconstructedTree {
            nodes: Vec::new(),
            root_label: ergo_primitives::digest::Digest32::from_bytes(manifest_a),
            tree_height: 0,
        });

        install_reconstructed_snapshot(&mut state);

        assert_eq!(
            state.snapshot_bootstrap.state(),
            BootstrapState::Selected {
                height: DENSE_TIP_HEIGHT as i32,
                manifest_id: manifest_b,
            },
            "recovering from A's UnreachableGap must evict an A voter and drop \
             A's latch, leaving B's untouched 3-vote quorum selected — the \
             buggy `voter_for_selected_manifest()` path evicted a B voter \
             instead, which would drop B below quorum here",
        );
        assert!(
            state.reconstructed_tree.is_none(),
            "UnreachableGap abandons this manifest/epoch on purpose — the \
             stale tree for A must not come back",
        );
    }
}
