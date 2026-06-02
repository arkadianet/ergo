//! Peer-event dispatcher: action loop drains the inbound channel into
//! `handle_event_batch`, which fast-paths a header-modifier coalescing
//! window through `process_header_modifier_batch` and falls back to
//! per-event dispatch via `handle_event` for everything else.

use std::time::Instant;

use ergo_api::SubmitError;
use ergo_p2p::handshake::PeerFeature;
use ergo_p2p::message;
use ergo_p2p::peer::{PeerId, SyncVersion};
use ergo_p2p::peer_manager::ConnectError;
use ergo_p2p::types::ModifierTypeId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::read_header;
use ergo_ser::modifier_id::ExpectedSections;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_sync::coordinator::Action;
use ergo_sync::header_proc::HeaderProcessError;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::anchor_map::parse_rest_url;
use crate::peer_loop::{self, PeerEvent};

use super::{
    cleanup_disconnected_peer, flush_actions, handle_message, send_to_peer,
    try_send_anchor_sync_info, NodeState, PeerRuntime,
};

/// events flow through `handle_event` individually as before.
///
/// Per-tick caller drains up to `MAX_COALESCE` events from the
/// channel before invoking this — see the `event_rx.recv()` arm in
/// the action loop.
pub(super) fn handle_event_batch(state: &mut NodeState, events: Vec<PeerEvent>) {
    if events.is_empty() {
        return;
    }
    if events.len() == 1 {
        // Common case (single event): no point doing the partition
        // dance, just dispatch.
        handle_event(state, events.into_iter().next().unwrap());
        return;
    }

    let now = Instant::now();
    let mut header_mods: Vec<(PeerId, ergo_p2p::types::ModifiersData)> = Vec::new();
    let mut other: Vec<PeerEvent> = Vec::new();

    for ev in events {
        if let PeerEvent::Message {
            peer,
            code,
            payload,
        } = &ev
        {
            if *code == message::CODE_MODIFIER {
                // Pre-deserialize so we can route header-Modifiers
                // to the coalesced path without re-parsing. Tx-typed
                // Modifiers and parse failures fall through to
                // individual handle_event dispatch (unchanged
                // semantics — Tx admission is per-message, parse
                // failures emit Penalize per-message).
                if let Ok(mods) = message::deserialize_modifiers(payload) {
                    if mods.type_id != ModifierTypeId::Transaction.as_byte() {
                        header_mods.push((*peer, mods));
                        continue;
                    }
                }
            }
        }
        other.push(ev);
    }

    if !header_mods.is_empty() {
        process_header_modifier_batch(state, header_mods, now);
    }

    for ev in other {
        handle_event(state, ev);
    }
}

/// Coalesced header-Modifier processor. Accumulates coordinator
/// actions across all messages, runs ONE `execute_all` call so the
/// executor's batch path (rayon pre-validate + sequential finalize +
/// one redb txn) amortizes its overhead over the entire combined
/// batch.
///
/// Per-peer post-processing (immediate-SyncInfo, mark_sync_sent) is
/// still done per contributing peer so anchored fanout stays
/// disjoint and Lever 1's throttle stays accurate.
fn process_header_modifier_batch(
    state: &mut NodeState,
    messages: Vec<(PeerId, ergo_p2p::types::ModifiersData)>,
    now: Instant,
) {
    let cs_before = state.store.chain_state_meta();
    let bh_before = cs_before.best_header_height;
    let fb_before = cs_before.best_full_block_height;

    let mut batch_actions = Vec::new();
    let mut contributing_peers: Vec<PeerId> = Vec::with_capacity(messages.len());

    for (peer, mods) in messages {
        // Same admission gates as handle_event Message path:
        // unknown peers get dropped; touching updates last-seen.
        if state.peer_manager.get(&peer).is_none() {
            continue;
        }
        state.peer_manager.touch(&peer, now);

        let type_id = mods.type_id;
        state.sections_received_total += mods.modifiers.len() as u64;
        state.coordinator.note_modifier_response(peer);
        for (mod_id, data) in mods.modifiers {
            batch_actions.extend(
                state
                    .coordinator
                    .on_modifier_received(peer, type_id, mod_id, data),
            );
        }
        contributing_peers.push(peer);
    }

    if batch_actions.is_empty() {
        return;
    }

    let rescan_guard = crate::wallet_boot::ProdRescanGuard;
    let wallet_wiring = state
        .wallet_hook
        .as_deref()
        .map(|h| ergo_state::wallet::WalletWiring {
            hook: h as &dyn ergo_state::wallet::WalletApplyHook,
            rescan_guard: &rescan_guard,
        });
    let mut all_actions = state.executor.execute_all(
        batch_actions,
        &mut state.store,
        &mut state.coordinator,
        now,
        wallet_wiring,
    );

    let cs_after = state.store.chain_state_meta();
    let bh = cs_after.best_header_height;
    let fb = cs_after.best_full_block_height;

    if fb > fb_before
        && state
            .store
            .as_utxo()
            .expect("utxo-only: IBD durability mode is gated off in digest mode")
            .ibd_mode()
        && bh > 0
        && bh.saturating_sub(fb) < 10
    {
        state
            .store
            .as_utxo_mut()
            .expect("utxo-only: IBD durability mode is gated off in digest mode")
            .set_ibd_mode(false, 0);
        info!(gap = bh - fb, durability = "Immediate", "IBD complete",);
    }

    if state.coordinator.sync_state().headers_chain_synced() {
        let window_advanced = fb > fb_before;
        let drain_triggered = state.executor.pipeline_needs_refill(&state.coordinator);
        if window_advanced || drain_triggered {
            let missing = state.executor.request_missing_sections(
                &mut state.coordinator,
                &state.store,
                &state.peer_manager,
                now,
            );
            all_actions.extend(missing);
        }
    }

    // Per-peer immediate-SyncInfo dispatch — same as the per-message
    // path's tail. Each contributing peer gets the next anchor (or
    // tip-tail fallback). Dedup the peer list since two messages
    // from the same peer in this coalesce window only need one
    // SyncInfo response.
    if bh > bh_before {
        contributing_peers.sort();
        contributing_peers.dedup();
        for peer in contributing_peers {
            if state.registry.peers.contains_key(&peer) {
                if !try_send_anchor_sync_info(state, &peer, now) {
                    if let Some(rt) = state.registry.peers.get(&peer) {
                        let payload = match rt.sync_version {
                            SyncVersion::V2 => {
                                let headers = state.executor.cached_header_bytes(50);
                                message::serialize_sync_info(&message::SyncInfo::V2 { headers })
                            }
                            SyncVersion::V1 => ergo_sync::coordinator::build_sync_info_payload(
                                rt.sync_version,
                                &state.store,
                            ),
                        };
                        all_actions.push(Action::SendToPeer {
                            peer,
                            code: message::CODE_SYNC_INFO,
                            payload,
                        });
                    }
                }
                state.coordinator.sync_state_mut().mark_sync_sent(peer, now);
            }
        }
    }

    if bh.is_multiple_of(500) && bh > 0 {
        let h = state.store.height();
        info!(height = h, headers = bh, "chain progress");
    }

    flush_actions(state, all_actions);
}

fn handle_event(state: &mut NodeState, event: PeerEvent) {
    let now = Instant::now();

    match event {
        PeerEvent::TcpConnected { addr } => {
            // Outbound TCP connect succeeded. Flip Connecting → Handshaking
            // so `evict_timed_out` switches to the 30s HANDSHAKE_TIMEOUT
            // for the duration of the bidirectional handshake. Without
            // this, slow handshakes get evicted after 5s and their
            // `HandshakeComplete` event lands on a removed peer entry,
            // surfacing as `unknown peer`. `mark_tcp_connected` is a
            // no-op if the peer was already evicted between dial and
            // now (Connecting->… filter inside the helper), so this
            // arm is safe even on a tight race.
            state.peer_manager.mark_tcp_connected(&addr);
        }
        PeerEvent::HandshakeComplete {
            addr,
            peer_spec,
            time: _,
            conn,
        } => {
            // Skip if already connected (late HandshakeComplete from a previous dial)
            if state.registry.peers.contains_key(&addr) {
                drop(conn);
                return;
            }
            // Extract session_id for self-connection check
            let session_id = peer_spec.features.iter().find_map(|f| {
                if let PeerFeature::SessionId { session_id, .. } = f {
                    Some(*session_id)
                } else {
                    None
                }
            });
            // Surface RestApiUrl advertisement for header-anchor-map
            // bootstrap (Step A — observation only). Logged per
            // handshake; counted in the heartbeat as `rest_peers=X/Y`.
            // Note: actual ingestion into the Step B anchor builder
            // happens AFTER `complete_handshake` succeeds (below) so
            // a rejected admission never leaks a peer-controlled URL
            // into the builder's request stream.
            for f in &peer_spec.features {
                if let PeerFeature::RestApiUrl { url } = f {
                    debug!(peer = %addr, url = %url, "peer advertises REST");
                }
                if let PeerFeature::Mode {
                    state_type,
                    verify_tx,
                    nipopow,
                    blocks_to_keep,
                } = f
                {
                    // Step D follow-up: Mode tells us whether the
                    // peer can actually serve historical headers.
                    //   blocks_to_keep = -1 → archival (full chain)
                    //   blocks_to_keep = -2 → UTXO-bootstrapped
                    //   blocks_to_keep > 0  → only suffix N kept
                    // For anchored fanout we need the peer to know
                    // headers at specific historical heights — only
                    // archival peers (and arguably UTXO-bootstrapped)
                    // qualify. Suffix-pruned peers don't have the
                    // anchor's height in their best chain and Scala's
                    // continuationIdsV1 returns Empty for those.
                    debug!(
                        peer = %addr,
                        state_type = state_type,
                        verify_tx = verify_tx,
                        nipopow = ?nipopow,
                        blocks_to_keep = blocks_to_keep,
                        "peer mode advertised",
                    );
                }
            }

            state.peer_manager.mark_tcp_connected(&addr);
            match state
                .peer_manager
                .complete_handshake(&addr, peer_spec.clone(), session_id, now)
            {
                Ok(()) => {
                    state.peer_manager.mark_dial_succeeded(&addr, now);
                    // Step B: ingest the peer's REST URL into the
                    // shared map keyed by PeerId. Validate strictly
                    // before storage so the builder never sees
                    // CRLF-smuggled / IPv6 / userinfo URLs that could
                    // confuse the request line on the receiving REST
                    // server. Map is bounded by peer_manager's
                    // max_connections cap (the same natural bound as
                    // connected_peers).
                    for f in &peer_spec.features {
                        if let PeerFeature::RestApiUrl { url } = f {
                            match parse_rest_url(url) {
                                Ok(_) => {
                                    if let Ok(mut g) = state.rest_peer_urls.write() {
                                        g.insert(addr, url.clone());
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        peer = %addr,
                                        url = %url,
                                        error = %e,
                                        "peer REST url rejected",
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    // After the TcpConnected fix, `UnknownPeer` here
                    // means the peer was evicted between TCP-up and
                    // handshake-bytes-done — typically a stalled
                    // handshake exceeding HANDSHAKE_TIMEOUT (30s) or
                    // a `Disconnected` event observed first. Defensive
                    // cleanup, no consensus impact — the peer simply
                    // isn't admitted and will be re-dialed on the next
                    // dial tick if still in `known_addresses`.
                    let reason: &str = match e {
                        ConnectError::UnknownPeer => {
                            "handshake exceeded 30s timeout (peer evicted before HandshakeComplete arrived)"
                        }
                        _ => "",
                    };
                    if reason.is_empty() {
                        warn!(peer = %addr, error = %e, "handshake not admitted");
                    } else {
                        warn!(peer = %addr, error = %e, reason = reason, "handshake not admitted");
                    }
                    state.peer_manager.disconnect(&addr);
                    state.peer_manager.mark_dial_failed(&addr, now);
                    return;
                }
            }

            let sync_version = SyncVersion::for_peer(&peer_spec.version);
            // 2048: enough for burst of 400 headers × 2 section requests + SyncInfo
            let (outbound_tx, outbound_rx) = mpsc::channel(2048);

            // Hand the per-peer byte counters to the I/O task so it can
            // record post-handshake framed bytes. complete_handshake just
            // succeeded and mutates the PeerInfo in place, so this `get`
            // yields the same instance the snapshot projection reads — the
            // task increments exactly the Arcs `/api/v1/peers` surfaces.
            let (peer_bytes_in, peer_bytes_out) = state
                .peer_manager
                .get(&addr)
                .map(|pi| pi.byte_counters())
                .unwrap_or_else(|| {
                    (
                        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    )
                });

            tokio::spawn(peer_loop::peer_task(
                addr,
                conn,
                state.event_tx.clone(),
                outbound_rx,
                peer_bytes_in,
                peer_bytes_out,
            ));

            state.registry.peers.insert(
                addr,
                PeerRuntime {
                    sync_version,
                    outbound_tx,
                },
            );

            debug!(
                peer = %addr,
                version = ?peer_spec.version,
                sync = ?sync_version,
                mgr = state.peer_manager.peer_count(),
                reg = state.registry.peers.len(),
                "peer connected",
            );

            // Send initial SyncInfo immediately. Step C may swap our
            // tip-tail for a single anchor ID for REST-capable peers
            // (see `try_send_anchor_sync_info` for the eligibility
            // gate); fall back to the standard payload otherwise.
            // Mark sync_sent in either branch so Lever 1's per-peer
            // throttle accounts for this send — without it, the next
            // periodic dispatch would re-send a redundant SyncInfo
            // ~1s later (the throttle would think no recent send had
            // happened on this peer).
            if !try_send_anchor_sync_info(state, &addr, now) {
                let chain = state
                    .store
                    .as_utxo()
                    .expect("utxo-only: ChainView sync-info seam is gated off in digest mode");
                let payload = ergo_sync::coordinator::build_sync_info_payload(sync_version, chain);
                send_to_peer(state, &addr, message::CODE_SYNC_INFO, payload);
            }
            state.coordinator.sync_state_mut().mark_sync_sent(addr, now);

            // Sync-S4: request the peer's known addresses so the dial
            // pool can fill beyond the CLI-seeded peer(s) over time.
            if state.peer_manager.needs_outbound() {
                send_to_peer(state, &addr, message::CODE_GET_PEERS, Vec::new());
                debug!(
                    peer = %addr,
                    deficit = state.peer_manager.outbound_deficit(),
                    "sent GetPeers",
                );
            }

            // Request missing sections (runs on every handshake).
            let chain = state
                .store
                .as_utxo()
                .expect("utxo-only: ChainView section-request seam is gated off in digest mode");
            let missing_actions = state.executor.request_missing_sections(
                &mut state.coordinator,
                chain,
                &state.peer_manager,
                now,
            );
            flush_actions(state, missing_actions);
        }

        PeerEvent::ConnectFailed { addr } => {
            state.peer_manager.disconnect(&addr);
            state.peer_manager.mark_dial_failed(&addr, now);
        }

        PeerEvent::InboundConnect { peer_addr, stream } => {
            // Apply per-IP / per-subnet / max-inbound limits before
            // committing to the handshake. On reject, dropping `stream`
            // closes the TCP connection cleanly. On accept, spawn the
            // accept_task which mirrors dial_task and emits a
            // HandshakeComplete on success — same admission path as
            // outbound from that point on.
            match state.peer_manager.register_inbound(peer_addr, now) {
                Ok(()) => {
                    debug!(peer = %peer_addr, "inbound peer accepted");
                    tokio::spawn(peer_loop::accept_task(
                        peer_addr,
                        stream,
                        state.magic,
                        state.our_handshake.clone(),
                        state.event_tx.clone(),
                    ));
                }
                Err(e) => {
                    warn!(peer = %peer_addr, error = %e, "inbound peer rejected");
                    drop(stream);
                }
            }
        }

        PeerEvent::Message {
            peer,
            code,
            payload,
        } => {
            if state.peer_manager.get(&peer).is_none() {
                warn!(peer = %peer, "dropping message from untracked peer");
                cleanup_disconnected_peer(state, &peer);
                return;
            }
            state.peer_manager.touch(&peer, now);
            let actions = handle_message(state, peer, code, &payload, now);
            flush_actions(state, actions);
        }

        PeerEvent::Disconnected { peer } => {
            // The single disconnect record is emitted by
            // `peer_manager.disconnect()` below (state/age/score/caller,
            // at DEBUG) — no separate INFO line here, which would double-log.
            let actions = state.executor.on_peer_disconnected(
                &peer,
                &mut state.coordinator,
                &state.peer_manager,
                now,
            );
            state.peer_manager.disconnect(&peer);
            cleanup_disconnected_peer(state, &peer);
            flush_actions(state, actions);
        }

        PeerEvent::LocalFullBlock {
            header_bytes,
            bt_bytes,
            ext_bytes,
            ad_proofs_bytes,
            reply,
        } => {
            let result = inject_local_full_block(
                state,
                header_bytes,
                bt_bytes,
                ext_bytes,
                ad_proofs_bytes,
                now,
            );
            // The receiver may have dropped (API task gave up on the
            // request); ignore the SendError. The block apply already
            // happened; the local result is just for the HTTP reply.
            let _ = reply.send(result);
        }
    }
}

/// Drive a locally-mined block through the same apply pipeline P2P
/// modifiers walk, but bypassing the per-peer coordinator path
/// (delivery tracker, on_header_validated section requests) — those
/// fire `Action::SendToPeer` / `delivery.request` against whichever
/// peer submitted the header, and there is no peer here.
///
/// Pipeline:
/// 1. `verify_section_modifier_id` checks each section's bytes hash to
///    the section id derived from the header's `*_root` commitments.
/// 2. `header_proc::process_header_cfg` runs the same PoW + chain
///    linkage + difficulty + persist path peer headers take, with the
///    executor's chain_config so testnet stays on testnet's schedule.
///    `AlreadyKnown` is idempotent: fall through to step 4 in case
///    the previous submission stored the header but not the sections.
/// 3. `store.store_block_section_typed` persists each section under
///    the canonical section id derived from header roots.
/// 4. `executor.execute(Action::AssembleBlock { header_id })` triggers
///    `process_block` if `best_full_block_height + 1 == header.height`,
///    otherwise it no-ops and the block waits for `try_apply_next_blocks`
///    to pick it up later.
/// 5. Follow-up actions (chain-extension Inv broadcasts after a
///    successful apply, etc.) are flushed via `flush_actions`.
///
/// Returns `Ok(header_id_hex)` when the header is in the store after
/// the apply pipeline runs — matches Scala's `sendMinedBlock`
/// semantics where 200 means "bytes accepted into the pipeline", not
/// "block is now the tip" (a soon-to-be-stale block still gets 200).
///
/// `Err(SubmitError)` reasons:
/// - `deserialize` — header bytes won't re-parse or section bytes
///   inconsistent with header's `*_root` commitments;
/// - `header_rejected` — validator rejected the header (PoW already
///   passed in the bridge, so this is the chain-context call:
///   ParentNotFound / Invalid / HeightMismatch / EpochContextIncomplete
///   / validation failure);
/// - `internal_error` — storage write failed.
fn inject_local_full_block(
    state: &mut super::NodeState,
    header_bytes: Vec<u8>,
    bt_bytes: Vec<u8>,
    ext_bytes: Vec<u8>,
    ad_proofs_bytes: Option<Vec<u8>>,
    now: Instant,
) -> Result<String, SubmitError> {
    // ----- Parse header for the section-id commitments -----
    let mut r = VlqReader::new(&header_bytes);
    let header = read_header(&mut r).map_err(|e| SubmitError {
        reason: "deserialize".to_string(),
        detail: Some(format!("header re-parse failed: {e:?}")),
    })?;
    let header_id_bytes: [u8; 32] = ergo_crypto::autolykos::common::blake2b256(&header_bytes);
    let expected = ExpectedSections::from_header(
        &header_id_bytes,
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );

    // ----- Section-id sanity (caller-side parity check) -----
    // Reuse the same verifier the P2P CODE_MODIFIER arm runs on
    // incoming sections (`messaging.rs:268-289`): parses each
    // section's bytes, recomputes the canonical section id from
    // the parsed digest + header_id + type_id, and compares
    // against the expected id derived from the header's
    // `*_root` commitments. Catches a miner that produced a
    // header whose `*_root` doesn't match the section bodies it
    // submitted alongside, before we hand bytes to the
    // assembly tracker.
    if let Err(reason) = ergo_sync::coordinator::verify_section_modifier_id(
        ModifierTypeId::BlockTransactions.as_byte(),
        &expected.transactions_id,
        &bt_bytes,
    ) {
        return Err(SubmitError {
            reason: "deserialize".to_string(),
            detail: Some(format!(
                "blockTransactions bytes inconsistent with header.transactionsRoot: {reason}",
            )),
        });
    }
    if let Err(reason) = ergo_sync::coordinator::verify_section_modifier_id(
        ModifierTypeId::Extension.as_byte(),
        &expected.extension_id,
        &ext_bytes,
    ) {
        return Err(SubmitError {
            reason: "deserialize".to_string(),
            detail: Some(format!(
                "extension bytes inconsistent with header.extensionRoot: {reason}",
            )),
        });
    }
    if let Some(ad) = &ad_proofs_bytes {
        if let Err(reason) = ergo_sync::coordinator::verify_section_modifier_id(
            ModifierTypeId::ADProofs.as_byte(),
            &expected.ad_proofs_id,
            ad,
        ) {
            return Err(SubmitError {
                reason: "deserialize".to_string(),
                detail: Some(format!(
                    "adProofs bytes inconsistent with header.adProofsRoot: {reason}",
                )),
            });
        }
    }

    // ----- Header: PoW + chain linkage + persist -----
    // `executor.process_local_header` is the same single-header
    // pipeline `Action::ValidateHeader` runs (pre_validate +
    // finalize + push_validated_header + drain_orphans), minus the
    // `coordinator.on_header_validated` hop that would emit
    // `delivery.request` + `SendToPeer` for a phantom peer.
    //
    // `push_validated_header` is the load-bearing call — it adds
    // the header to `recently_installed` so any peer-orphan headers
    // buffered on top of this locally-mined block as parent can
    // drain on the next P2P `ValidateHeader` flush. Calling the
    // raw `process_header_cfg` (an earlier draft) would have stranded
    // those orphans indefinitely. Codex follow-up on the prior
    // attempt.
    //
    // `HeaderProcessError::Deserialize` here means "re-parse of a
    // persisted parent header failed" — NOT "caller sent bad bytes".
    // We already parsed the caller bytes successfully at the top
    // (`read_header(&mut r)`), so any Deserialize from process_local_header
    // is internal-state corruption, not a submitter error.
    match state.executor.process_local_header(
        &mut state.store,
        &mut state.coordinator,
        &header_bytes,
        now,
    ) {
        Ok((_processed, drain_actions)) => {
            // `drain_orphans` can re-validate peer-orphan headers
            // that were waiting on this locally-mined parent.
            // Those follow-up actions include real `SendToPeer`
            // targeted at the orphan-buffering peers, plus
            // `Penalize` for failed parent-walks. Must reach
            // `flush_actions` — otherwise the delivery tracker has
            // requests marked in-flight that never went out, and
            // affected peers eat false non-delivery penalties.
            flush_actions(state, drain_actions);
        }
        Err(HeaderProcessError::AlreadyKnown { .. }) => {
            // Idempotent re-submission. Fall through to persist
            // sections + AssembleBlock — the previous submission may
            // have stored the header without finishing the apply
            // (operator restart between phases, transient storage
            // hiccup on a section write). All downstream calls are
            // store-write-idempotent.
        }
        Err(
            e @ (HeaderProcessError::ParentNotFound { .. }
            | HeaderProcessError::Invalid { .. }
            | HeaderProcessError::HeightMismatch { .. }
            | HeaderProcessError::EpochContextIncomplete { .. }
            | HeaderProcessError::EpochHeaderMissing { .. }
            | HeaderProcessError::Validation(_)),
        ) => {
            return Err(SubmitError {
                reason: "header_rejected".to_string(),
                detail: Some(format!("header rejected by validator: {e}")),
            });
        }
        Err(e @ (HeaderProcessError::Storage(_) | HeaderProcessError::Deserialize(_))) => {
            return Err(SubmitError {
                reason: "internal_error".to_string(),
                detail: Some(format!("local store error during header apply: {e}")),
            });
        }
    }

    // ----- Sections: persist directly under canonical section ids -----
    let persist = |id: &[u8; 32], bytes: &[u8], type_id: u8| -> Result<(), SubmitError> {
        state
            .store
            .store_block_section_typed(id, bytes, type_id)
            .map_err(|e| SubmitError {
                reason: "internal_error".to_string(),
                detail: Some(format!("store_block_section_typed (type {type_id}): {e}")),
            })
    };
    persist(
        &expected.transactions_id,
        &bt_bytes,
        ModifierTypeId::BlockTransactions.as_byte(),
    )?;
    persist(
        &expected.extension_id,
        &ext_bytes,
        ModifierTypeId::Extension.as_byte(),
    )?;
    if let Some(ad) = &ad_proofs_bytes {
        persist(
            &expected.ad_proofs_id,
            ad,
            ModifierTypeId::ADProofs.as_byte(),
        )?;
    }

    // ----- Apply: AssembleBlock kicks process_block if next in line -----
    // executor.execute on a single AssembleBlock action. The handler
    // loads sections from the store directly (which we just wrote),
    // verifies `best_full_block_height + 1 == header.height`, and
    // calls `process_block`. If the local block isn't at tip+1 yet,
    // no-op — `try_apply_next_blocks` will pick it up on the next
    // chain advance.
    let rescan_guard = crate::wallet_boot::ProdRescanGuard;
    let wallet_wiring = state
        .wallet_hook
        .as_deref()
        .map(|h| ergo_state::wallet::WalletWiring {
            hook: h as &dyn ergo_state::wallet::WalletApplyHook,
            rescan_guard: &rescan_guard,
        });
    let follow_ups = state.executor.execute(
        Action::AssembleBlock {
            header_id: header_id_bytes,
        },
        &mut state.store,
        &mut state.coordinator,
        now,
        wallet_wiring,
    );
    flush_actions(state, follow_ups);

    // ----- Post-state: header is in the store -----
    let header_now_known = state
        .store
        .get_header(&header_id_bytes)
        .map(|opt| opt.is_some())
        .unwrap_or(false);
    if header_now_known {
        Ok(hex::encode(header_id_bytes))
    } else {
        Err(SubmitError {
            reason: "header_rejected".to_string(),
            detail: Some(
                "validator rejected the header before persistence — check chain context (parent, nBits, height)".into(),
            ),
        })
    }
}
