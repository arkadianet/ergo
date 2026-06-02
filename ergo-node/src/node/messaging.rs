//! Inbound peer-message dispatcher.
//!
//! `handle_message` is the action loop's per-frame entry point: per-peer
//! throughput throttle, then one match arm per `message::CODE_*` opcode
//! that deserializes the payload and routes through the appropriate
//! coordinator / executor / mempool-validator path. Returns the action
//! list the runtime then drains via `flush_actions`.

use std::time::Instant;

use ergo_p2p::handshake::PeerSpec;
use ergo_p2p::message;
use ergo_p2p::peer::{PeerId, Penalty, SyncVersion};
use ergo_p2p::throttle::LimiterVerdict;
use ergo_p2p::types::{ModifierTypeId, ModifiersData};
use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::read_header;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_sync::coordinator::Action;
use ergo_sync::snapshot_bootstrap::{verify_manifest_against_state_root, ChunkReceiveOutcome};
use tracing::{debug, info, warn};

use super::{
    admit_transaction, hedge_request_modifiers, send_to_peer, try_send_anchor_sync_info, NodeState,
};

#[tracing::instrument(
    name = "msg",
    level = "debug",
    skip_all,
    fields(peer = %peer, code = code, bytes = payload.len()),
)]
pub(super) fn handle_message(
    state: &mut NodeState,
    peer: PeerId,
    code: u8,
    payload: &[u8],
    now: Instant,
) -> Vec<Action> {
    // Per-peer throughput cap. Payload size + header bytes (9)
    // approximate the on-wire cost; precise framing size isn't
    // necessary for rate bounding. Over-limit frames drop and the
    // peer picks up a Misbehavior penalty.
    let frame_bytes = payload.len().saturating_add(9) as u32;
    match state.throttle.check_and_record(peer, now, frame_bytes) {
        LimiterVerdict::Ok => {}
        LimiterVerdict::MessageRateExceeded | LimiterVerdict::ByteRateExceeded => {
            warn!(peer = %peer, code = code, "throttle exceeded; dropping frame");
            return vec![Action::Penalize {
                peer,
                penalty: Penalty::Misbehavior,
            }];
        }
    }
    match code {
        message::CODE_SYNC_INFO => match message::deserialize_sync_info(payload) {
            Ok(sync_info) => {
                let sv = state
                    .registry
                    .peers
                    .get(&peer)
                    .map(|r| r.sync_version)
                    .unwrap_or(SyncVersion::V2);
                let actions =
                    state
                        .coordinator
                        .on_sync_info(peer, sv, &sync_info, &state.store, now);
                let rescan_guard = crate::wallet_boot::ProdRescanGuard;
                let wallet_wiring =
                    state
                        .wallet_hook
                        .as_deref()
                        .map(|h| ergo_state::wallet::WalletWiring {
                            hook: h as &dyn ergo_state::wallet::WalletApplyHook,
                            rescan_guard: &rescan_guard,
                        });
                state.executor.execute_all(
                    actions,
                    &mut state.store,
                    &mut state.coordinator,
                    now,
                    wallet_wiring,
                )
            }
            Err(e) => {
                warn!(peer = %peer, error = %e, "bad SyncInfo");
                vec![Action::Penalize {
                    peer,
                    penalty: Penalty::Misbehavior,
                }]
            }
        },
        message::CODE_INV => {
            match message::deserialize_inv(payload) {
                Ok(inv) => {
                    if inv.type_id == ModifierTypeId::Transaction.as_byte() {
                        if !state.mempool.config().enabled {
                            return Vec::new();
                        }
                        // Tx-typed Inv. Filter the advertised set
                        // before asking the coordinator to register a
                        // RequestModifier. `contains` / `is_invalidated`
                        // cover the pool + rejection cache; the
                        // coordinator dedups against in-flight/failed
                        // state itself.
                        let unknown: Vec<[u8; 32]> = inv
                            .ids
                            .iter()
                            .filter_map(|id| {
                                let tx_id = Digest32::from_bytes(*id);
                                if state.mempool.contains(&tx_id) {
                                    return None;
                                }
                                if state.mempool.is_invalidated(&tx_id) {
                                    return None;
                                }
                                Some(*id)
                            })
                            .collect();
                        if unknown.is_empty() {
                            Vec::new()
                        } else {
                            state.coordinator.request_transactions(peer, &unknown, now)
                        }
                    } else {
                        let actions = state.coordinator.on_inv(peer, &inv, &state.store, now);
                        // Hedge dispatch: after on_inv registers
                        // `peer` as primary owner of the admitted
                        // IDs, also send the same RequestModifier
                        // to HEDGE_PEERS additional peers. Their
                        // responses arrive via the late_acceptable
                        // path → DeliveryAction::Accept. First
                        // valid delivery wins; later arrivals are
                        // Ignore (not Spam) because mark_received
                        // clears late_acceptable. Slow peers become
                        // harmless losers in a race for fastest
                        // delivery.
                        let actions = hedge_request_modifiers(state, actions, peer);
                        let rescan_guard = crate::wallet_boot::ProdRescanGuard;
                        let wallet_wiring = state.wallet_hook.as_deref().map(|h| {
                            ergo_state::wallet::WalletWiring {
                                hook: h as &dyn ergo_state::wallet::WalletApplyHook,
                                rescan_guard: &rescan_guard,
                            }
                        });
                        state.executor.execute_all(
                            actions,
                            &mut state.store,
                            &mut state.coordinator,
                            now,
                            wallet_wiring,
                        )
                    }
                }
                Err(e) => {
                    warn!(peer = %peer, error = %e, "bad Inv");
                    vec![Action::Penalize {
                        peer,
                        penalty: Penalty::Misbehavior,
                    }]
                }
            }
        }
        message::CODE_REQUEST_MODIFIER => match message::deserialize_inv(payload) {
            Ok(inv) => {
                let type_id = inv.type_id;
                let hits: Vec<([u8; 32], Vec<u8>)> = match ModifierTypeId::from_byte(type_id) {
                    Some(ModifierTypeId::Transaction) => inv
                        .ids
                        .iter()
                        .filter_map(|id| {
                            state
                                .mempool
                                .get_bytes(&Digest32::from_bytes(*id))
                                .map(|b| (*id, b.to_vec()))
                        })
                        .collect(),
                    Some(ModifierTypeId::Header) => inv
                        .ids
                        .iter()
                        .filter_map(|id| {
                            state.store.get_header(id).ok().flatten().map(|b| (*id, b))
                        })
                        .collect(),
                    Some(
                        ModifierTypeId::BlockTransactions
                        | ModifierTypeId::ADProofs
                        | ModifierTypeId::Extension,
                    ) => {
                        // Mode 3 Phase 3b — serve gating. Silently
                        // skip sections whose parent header is
                        // below our prune sentinel. The peer is
                        // not penalized — they may legitimately
                        // not know our pruned suffix-window
                        // setting, and serving stale section bytes
                        // for a pruned height would advertise
                        // availability we can't sustainably honor.
                        // Matches Scala's
                        // `ErgoNodeViewSynchronizer.processModifierRequest`
                        // silent-skip.
                        //
                        // Fail-CLOSED on missing or unreadable
                        // SECTION_HEIGHT_INDEX rows (plan §284 +
                        // get_section_height docstring at
                        // ergo-state/src/store/mod.rs): a pruned
                        // node only serves sections it can prove
                        // are above its sentinel. Unindexed
                        // sections (legacy / never seen) are
                        // denied even if BLOCK_SECTIONS would
                        // return bytes — otherwise an attacker
                        // could resurrect pruned content via
                        // orphan-id requests.
                        // Sentinel unreadable → serve nothing
                        // (fail-closed).
                        let sentinel: u32 = match state.store.read_minimal_full_block_height() {
                            Ok(s) => s,
                            Err(_) => return Vec::new(),
                        };
                        // Gate fires on `sentinel > 1`: covers
                        // Mode 2 / NiPoPoW bootstrapped nodes, not just
                        // pruned mode. Fresh archive-from-genesis reads
                        // sentinel = 1 (default) → no gating, full serve.
                        let gate_active = sentinel > 1;
                        inv.ids
                            .iter()
                            .filter_map(|id| {
                                if gate_active {
                                    match state.store.get_section_height(id) {
                                        Ok(Some(h)) if h >= sentinel => {}
                                        // sub-sentinel: deny
                                        Ok(Some(_)) => return None,
                                        // unindexed / unreadable: fail-closed
                                        Ok(None) | Err(_) => return None,
                                    }
                                }
                                state
                                    .store
                                    .get_block_section(id)
                                    .ok()
                                    .flatten()
                                    .map(|b| (*id, b))
                            })
                            .collect()
                    }
                    None => Vec::new(),
                };
                if hits.is_empty() {
                    Vec::new()
                } else {
                    let data = ModifiersData {
                        type_id,
                        modifiers: hits,
                    };
                    match message::serialize_modifiers(&data) {
                        Ok(payload) => vec![Action::SendToPeer {
                            peer,
                            code: message::CODE_MODIFIER,
                            payload,
                        }],
                        Err(e) => {
                            warn!(type_id = type_id, error = %e, "failed to serialize Modifier");
                            Vec::new()
                        }
                    }
                }
            }
            Err(e) => {
                warn!(peer = %peer, error = %e, "bad RequestModifier");
                vec![Action::Penalize {
                    peer,
                    penalty: Penalty::Misbehavior,
                }]
            }
        },
        message::CODE_MODIFIER => {
            match message::deserialize_modifiers(payload) {
                Ok(mods) => {
                    let type_id = mods.type_id;
                    // Tx-typed Modifier goes through the coordinator's
                    // tx delivery check only — no chain pipeline. The
                    // admission path checks delivery ownership,
                    // penalizes unsolicited senders, and logs accepted
                    // bytes so the pipeline is observable.
                    if type_id == ModifierTypeId::Transaction.as_byte() {
                        let mut actions = Vec::new();
                        for (mod_id, bytes) in mods.modifiers {
                            use ergo_p2p::delivery::DeliveryAction as DA;
                            match state.coordinator.on_transaction_received(peer, &mod_id) {
                                DA::Accept => {
                                    let mut admission_actions =
                                        admit_transaction(state, peer, &bytes, now);
                                    actions.append(&mut admission_actions);
                                }
                                DA::Ignore => {}
                                DA::RejectSpam => {
                                    actions.push(Action::Penalize {
                                        peer,
                                        penalty: Penalty::Spam,
                                    });
                                }
                            }
                        }
                        return actions;
                    }
                    let mod_count = mods.modifiers.len();
                    state.sections_received_total += mod_count as u64;
                    state
                        .coordinator
                        .note_modifier_response_n(peer, mod_count as u64);
                    // Collect all coordinator actions from the entire modifier
                    // batch, then execute_all once. This lets the executor's
                    // batch header path (rayon pre-validate + sequential
                    // finalize) process the full batch rather than one-at-a-time.
                    let mut batch_actions = Vec::new();
                    for (mod_id, data) in mods.modifiers {
                        // Scala parity: at receive, verify the section
                        // bytes actually re-hash to the claimed
                        // modifier_id (`ErgoNodeViewSynchronizer
                        // .parseModifiers:801-813` — penalize-and-
                        // discard on `id != mod.id`). Penalize the
                        // lying peer immediately rather than letting
                        // bad bytes sit until apply time.
                        //
                        // Gated on the canonical three section types
                        // (102 / 104 / 108) rather than the broader
                        // `is_block_section(>= 50)` rule, because the
                        // latter also matches Header (101) — which
                        // has its own validation path inside
                        // `coordinator::on_modifier_received` — and
                        // would also wrongly route type-spoofed
                        // values (e.g. 255) through this branch.
                        if matches!(type_id, 102 | 104 | 108) {
                            if let Err(reason) = ergo_sync::coordinator::verify_section_modifier_id(
                                type_id, &mod_id, &data,
                            ) {
                                warn!(
                                    peer = %peer,
                                    type_id = type_id,
                                    modifier_id = %hex::encode(mod_id),
                                    reason = %reason,
                                    "section bytes don't match modifier_id; penalizing",
                                );
                                batch_actions.push(ergo_sync::coordinator::Action::Penalize {
                                    peer,
                                    penalty: Penalty::Misbehavior,
                                });
                                continue;
                            }
                        }
                        batch_actions.extend(
                            state
                                .coordinator
                                .on_modifier_received(peer, type_id, mod_id, data),
                        );
                    }
                    let cs_before = state.store.chain_state_meta();
                    let bh_before = cs_before.best_header_height;
                    let fb_before = cs_before.best_full_block_height;

                    let rescan_guard = crate::wallet_boot::ProdRescanGuard;
                    let wallet_wiring =
                        state
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

                    // Auto-exit IBD durability when near tip
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

                    // Refill downloads without waiting for the next
                    // sync tick when (a) blocks were just applied —
                    // the window slid forward so new pending heights
                    // need requests — or (b) Sync-S2 drain trigger:
                    // total in-flight has dropped below DRAIN_WATERMARK
                    // and the peer would otherwise sit idle for up to
                    // 3 seconds.
                    if state.coordinator.sync_state().headers_chain_synced() {
                        let window_advanced = fb > fb_before;
                        let drain_triggered =
                            state.executor.pipeline_needs_refill(&state.coordinator);
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

                    // Immediately request more headers after processing a batch.
                    // Without this, the next SyncInfo waits for the sync_tick timer,
                    // throttling header throughput to batch_size/sync_tick.
                    //
                    // Step C+D: when the scheduler is enabled, route this
                    // through the same anchor path as the periodic dispatch.
                    // Sending tip-tail here causes massive Inv duplication —
                    // peer A's tip-tail response overlaps with peer B's
                    // anchored response, the on_inv filter rejects 87-99% of
                    // incoming IDs as "already received", and effective
                    // throughput collapses (instrumentation 2026-05-05). The
                    // anchored path keeps each peer on a disjoint chain
                    // slice. mark_sync_sent fires either way so Lever 1's
                    // throttle accounts for the dispatch.
                    if bh > bh_before && state.registry.peers.contains_key(&peer) {
                        if !try_send_anchor_sync_info(state, &peer, now) {
                            if let Some(rt) = state.registry.peers.get(&peer) {
                                let payload = match rt.sync_version {
                                    SyncVersion::V2 => {
                                        let headers = state.executor.cached_header_bytes(50);
                                        message::serialize_sync_info(&message::SyncInfo::V2 {
                                            headers,
                                        })
                                    }
                                    SyncVersion::V1 => {
                                        ergo_sync::coordinator::build_sync_info_payload(
                                            rt.sync_version,
                                            &state.store,
                                        )
                                    }
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

                    // Log progress periodically
                    if bh.is_multiple_of(500) && bh > 0 {
                        let h = state.store.height();
                        info!(height = h, headers = bh, "chain progress");
                    }

                    all_actions
                }
                Err(e) => {
                    warn!(peer = %peer, error = %e, "bad Modifier");
                    vec![Action::Penalize {
                        peer,
                        penalty: Penalty::Misbehavior,
                    }]
                }
            }
        }
        message::CODE_GET_PEERS => {
            // Seed for rotation: wall-clock nanos give a different
            // starting offset on each `Peers` reply so the same prefix
            // of our peer list isn't sent to every requester.
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let spec_refs = state.peer_manager.peers_for_sharing(100, seed);
            let specs: Vec<PeerSpec> = spec_refs.into_iter().cloned().collect();
            let payload = message::serialize_peers(&specs);
            send_to_peer(state, &peer, message::CODE_PEERS, payload);
            Vec::new()
        }
        message::CODE_PEERS => {
            match message::deserialize_peers(payload, 100) {
                Ok(peers) => {
                    use ergo_p2p::peer_manager::{AddKnownOutcome, PeerOrigin};
                    let total = peers.len();
                    let mut added = 0usize;
                    let mut upgraded = 0usize;
                    let mut already_known = 0usize;
                    let mut no_declared = 0usize;
                    let mut malformed = 0usize;
                    let mut filtered = 0usize;
                    let mut dropped_pool_full = 0usize;
                    for spec in peers {
                        let Some(declared) = &spec.declared_address else {
                            no_declared += 1;
                            continue;
                        };
                        // Handle both IPv4 (4 bytes) and IPv6 (16 bytes)
                        // declared addresses. The previous parser used
                        // `<[u8;4]>::try_from(...).unwrap_or([0;4])`,
                        // silently coercing IPv6 to 0.0.0.0:port and
                        // poisoning the dial pool.
                        let Some(sock) = ergo_p2p::peer_manager::declared_to_socket(declared)
                        else {
                            malformed += 1;
                            continue;
                        };
                        match state
                            .peer_manager
                            .add_known_address(sock, PeerOrigin::Gossip)
                        {
                            AddKnownOutcome::Added => added += 1,
                            AddKnownOutcome::UpgradedToSeed => upgraded += 1,
                            AddKnownOutcome::AlreadyKnown => already_known += 1,
                            AddKnownOutcome::FilteredNonRoutable => filtered += 1,
                            AddKnownOutcome::DroppedPoolFull => dropped_pool_full += 1,
                        }
                    }
                    // Suppress the log when the entire response was
                    // duplicates of addresses we already know — the
                    // common case during a sustained outbound deficit
                    // where the dial-tick fans GetPeers every 5s and
                    // peers re-emit the same address book each time.
                    // Keep emitting when something actionable happened
                    // (real adds, seed upgrades, malformed bytes,
                    // filter rejects, pool eviction failures).
                    let actionable = added + upgraded + malformed + filtered + dropped_pool_full;
                    if actionable > 0 {
                        debug!(
                            peer = %peer,
                            total = total,
                            added = added,
                            upgraded = upgraded,
                            already_known = already_known,
                            no_declared = no_declared,
                            malformed = malformed,
                            filtered = filtered,
                            dropped_pool_full = dropped_pool_full,
                            "received peer specs",
                        );
                    }
                    Vec::new()
                }
                Err(e) => {
                    warn!(peer = %peer, error = %e, "bad Peers");
                    Vec::new()
                }
            }
        }
        message::CODE_SNAPSHOTS_INFO => match message::deserialize_snapshots_info(payload) {
            Ok(info) => {
                // Feed the discovery reducer (sub-phase 2f-1). The reducer
                // tracks per-peer votes and applies the Scala quorum rule.
                // Eligibility filtering — restricting which peers we *ask*
                // for SnapshotsInfo — lives in the outbound fan-out (sub-
                // phase 2f-3). Inbound, we accept what we're given: a
                // Mode 5/6 peer that pushes a SnapshotsInfo unsolicited
                // will send an empty list anyway (they have no UTXO
                // state) and the reducer drops empty-list votes.
                state
                    .snapshot_bootstrap
                    .on_snapshots_info(peer, &info.available_manifests);
                Vec::new()
            }
            Err(e) => {
                warn!(peer = %peer, error = %e, "bad SnapshotsInfo");
                vec![Action::Penalize {
                    peer,
                    penalty: Penalty::Misbehavior,
                }]
            }
        },
        message::CODE_GET_SNAPSHOTS_INFO => {
            match message::deserialize_get_snapshots_info(payload) {
                Ok(()) => {
                    let info = ergo_p2p::types::SnapshotsInfo {
                        available_manifests: state.snapshot_state.available_manifests(),
                    };
                    let reply = message::serialize_snapshots_info(&info);
                    send_to_peer(state, &peer, message::CODE_SNAPSHOTS_INFO, reply);
                    Vec::new()
                }
                Err(e) => {
                    warn!(peer = %peer, error = %e, "bad GetSnapshotsInfo");
                    vec![Action::Penalize {
                        peer,
                        penalty: Penalty::Misbehavior,
                    }]
                }
            }
        }
        message::CODE_GET_MANIFEST => match message::deserialize_get_manifest(payload) {
            Ok(manifest_id) => {
                // Lookup is by exact id. Mismatched id is a silent
                // drop, matching Scala `peer.handlerRef !` no-op when
                // `SnapshotsDb.get(manifestId)` returns None.
                if let Some(bytes) = state.snapshot_state.manifest_bytes(&manifest_id) {
                    let reply = message::serialize_manifest(bytes);
                    send_to_peer(state, &peer, message::CODE_MANIFEST, reply);
                }
                Vec::new()
            }
            Err(e) => {
                warn!(peer = %peer, error = %e, "bad GetManifest");
                vec![Action::Penalize {
                    peer,
                    penalty: Penalty::Misbehavior,
                }]
            }
        },
        message::CODE_MANIFEST => match message::deserialize_manifest(payload) {
            Ok(manifest_bytes) => {
                handle_inbound_manifest(state, peer, manifest_bytes);
                Vec::new()
            }
            Err(e) => {
                warn!(peer = %peer, error = %e, "bad Manifest");
                vec![Action::Penalize {
                    peer,
                    penalty: Penalty::Misbehavior,
                }]
            }
        },
        message::CODE_UTXO_CHUNK => match message::deserialize_utxo_chunk(payload) {
            Ok(chunk_bytes) => {
                handle_inbound_utxo_chunk(state, peer, chunk_bytes);
                Vec::new()
            }
            Err(e) => {
                warn!(peer = %peer, error = %e, "bad UtxoSnapshotChunk");
                vec![Action::Penalize {
                    peer,
                    penalty: Penalty::Misbehavior,
                }]
            }
        },
        message::CODE_GET_UTXO_CHUNK => match message::deserialize_get_utxo_chunk(payload) {
            Ok(subtree_id) => {
                if let Some(bytes) = state.snapshot_state.chunk_bytes(&subtree_id) {
                    let reply = message::serialize_utxo_chunk(bytes);
                    send_to_peer(state, &peer, message::CODE_UTXO_CHUNK, reply);
                }
                Vec::new()
            }
            Err(e) => {
                warn!(peer = %peer, error = %e, "bad GetUtxoSnapshotChunk");
                vec![Action::Penalize {
                    peer,
                    penalty: Penalty::Misbehavior,
                }]
            }
        },
        message::CODE_NIPOPOW_PROOF => handle_inbound_popow_proof(state, peer, payload.to_vec()),
        message::CODE_GET_NIPOPOW_PROOF => {
            // Serve side (Part 2 sub-phase 14.10). Phase 0 §8.4 +
            // Scala parity (HeadersProcessor.scala:166-169): a
            // NiPoPoW-bootstrapped (sparse-mode) node has no
            // extension/interlinks data for prefix headers and so
            // cannot construct a proof — silent no-op. A Dense
            // archive node returns its cached proof if one has been
            // built (by StateStore::compute_and_cache_popow_proof_dense
            // or a future apply-time snapshot-epoch hook).
            let is_sparse = matches!(
                state.store.chain_state_meta().header_availability,
                ergo_state::chain::HeaderAvailability::PoPowSparse { .. }
            );
            if is_sparse {
                return Vec::new();
            }
            let cached = match state
                .store
                .as_utxo()
                .expect("utxo-only: NiPoPoW proof serving is gated off in digest mode")
                .get_cached_popow_proof_bytes()
            {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    // Dense archive node but no proof has been
                    // computed yet — silent no-op. Operator can
                    // trigger compute via the public API.
                    return Vec::new();
                }
                Err(e) => {
                    warn!(error = %e, "GetNipopowProof: cache read failed");
                    return Vec::new();
                }
            };
            // Wrap the proof bytes in the wire frame (length prefix
            // + pad_length = 0) and send.
            match message::serialize_nipopow_proof(&cached) {
                Ok(payload) => {
                    info!(
                        peer = %peer,
                        bytes = cached.len(),
                        "GetNipopowProof: serving cached proof"
                    );
                    if !send_to_peer(state, &peer, message::CODE_NIPOPOW_PROOF, payload) {
                        warn!(
                            peer = %peer,
                            "GetNipopowProof: failed to send proof (peer channel full/closed)"
                        );
                    }
                    Vec::new()
                }
                Err(e) => {
                    warn!(error = %e, "GetNipopowProof: serialize wire frame failed");
                    Vec::new()
                }
            }
        }
        _ => {
            // Ignore unknown message codes (forward compatibility)
            Vec::new()
        }
    }
}

/// Handle an inbound NiPoPoW proof (message code 91). Decode the
/// wire frame, parse the proof bytes, hand to the
/// `popow_bootstrap` reducer's `on_proof_received`, and penalize on
/// `ValidationError` / `WrongGenesis` (strong signals of malicious
/// or misconfigured peers).
///
/// No-op when `popow_bootstrap` is `None` (either feature disabled
/// or already terminal). Silent drop on decode errors plus a
/// telemetry warn; the wire codec is byte-strict, so a parse
/// failure is either a malicious peer (penalize) or a peer running
/// an incompatible protocol version (degrade).
fn handle_inbound_popow_proof(
    state: &mut NodeState,
    peer: PeerId,
    payload: Vec<u8>,
) -> Vec<Action> {
    use ergo_validation::popow::NipopowVerificationResult;

    if state.popow_bootstrap.is_none() {
        // Either NiPoPoW disabled or reducer already terminal —
        // silently drop. A peer responding late after we've already
        // applied a proof is not misbehavior.
        return Vec::new();
    }

    // Step 1: parse the outer wire frame (length-prefixed proof
    // bytes + mandatory pad_length).
    let proof_bytes = match message::deserialize_nipopow_proof(&payload) {
        Ok(b) => b,
        Err(e) => {
            warn!(peer = %peer, error = %e, "bad NipopowProof wire frame");
            return vec![Action::Penalize {
                peer,
                penalty: Penalty::Misbehavior,
            }];
        }
    };

    // Scala-oracle capture hook. If env var
    // `ERGO_CAPTURE_NIPOPOW_PROOF` is set, write the raw inbound
    // proof bytes to that path as a one-shot capture. Lets an
    // operator dump a real Scala-served proof for use as a pinned
    // test vector (`test-vectors/mainnet/nipopow_proof_<peer>_<ts>.bin`)
    // without recompiling. Capture once per node lifetime — first
    // proof wins to keep the dump deterministic.
    if let Ok(capture_path) = std::env::var("ERGO_CAPTURE_NIPOPOW_PROOF") {
        if !capture_path.is_empty() && !std::path::Path::new(&capture_path).exists() {
            if let Err(e) = std::fs::write(&capture_path, &proof_bytes) {
                warn!(peer = %peer, error = %e, "failed to write NipopowProof capture");
            } else {
                info!(
                    peer = %peer,
                    path = %capture_path,
                    bytes = proof_bytes.len(),
                    "NipopowProof captured for Scala-oracle test fixture",
                );
            }
        }
    }

    // Step 2: parse the proof structure.
    let proof = match ergo_ser::popow_proof::deserialize_nipopow_proof(&proof_bytes) {
        Ok(p) => p,
        Err(e) => {
            warn!(peer = %peer, error = %e, "bad NipopowProof body");
            return vec![Action::Penalize {
                peer,
                penalty: Penalty::Misbehavior,
            }];
        }
    };

    // Step 3: hand to reducer + verifier.
    let result = match state.popow_bootstrap.as_mut() {
        Some(popow) => popow.on_proof_received(peer, proof),
        None => return Vec::new(),
    };

    match result {
        NipopowVerificationResult::BetterChain { total_proofs } => {
            info!(
                peer = %peer,
                total_proofs,
                "NiPoPoW: BetterChain (best-proof replaced)"
            );
            Vec::new()
        }
        NipopowVerificationResult::NoBetterChain { total_proofs } => {
            info!(
                peer = %peer,
                total_proofs,
                "NiPoPoW: NoBetterChain (proof valid but not better)"
            );
            Vec::new()
        }
        NipopowVerificationResult::WrongGenesis => {
            // Strong signal of malicious peer or wrong-network
            // configuration — penalize.
            warn!(peer = %peer, "NiPoPoW: WrongGenesis");
            vec![Action::Penalize {
                peer,
                penalty: Penalty::Misbehavior,
            }]
        }
        NipopowVerificationResult::ValidationError => {
            warn!(peer = %peer, "NiPoPoW: ValidationError");
            vec![Action::Penalize {
                peer,
                penalty: Penalty::Misbehavior,
            }]
        }
        NipopowVerificationResult::MalformedHeader => {
            // Peer sent a proof containing a header that decodes
            // cleanly via `read_header` but cannot be reserialized
            // via `serialize_header` (e.g., `version ∈ [2, 4]` with
            // non-empty `unparsed_bytes`, or `unparsed_bytes.len() > 255`).
            // Same penalty class as `ValidationError` — both indicate
            // a peer that is either malicious or running broken
            // software. The verifier rejects this input rather than
            // panicking on it.
            warn!(peer = %peer, "NiPoPoW: MalformedHeader (header reserialize bounds)");
            vec![Action::Penalize {
                peer,
                penalty: Penalty::Misbehavior,
            }]
        }
    }
}

/// Mode 2 consume-side: process an inbound `Manifest` (code 79).
///
/// Three-step funnel:
/// 1. Reducer ownership check — `on_manifest_received` returns
///    `Some((height, manifest_id, bytes))` iff the reply matches
///    our outstanding `GetManifest` request from this peer. A
///    `None` here means stale/unsolicited/wrong-peer; silently
///    drop.
/// 2. Canonical-header lookup — fetch the header at `height` from
///    the best-header chain, deserialize, extract `state_root`.
///    Any failure (chain doesn't have that height, header bytes
///    missing, deserialization error) is treated as "we can't
///    verify this manifest" → evict the voter, recompute selection.
/// 3. Trust check — compare the manifest_id against
///    `state_root[..32]` via `verify_manifest_against_state_root`.
///    On match, latch the bytes via `accept_verified_manifest`.
///    On mismatch, evict the voter — they advertised a manifest
///    inconsistent with our canonical chain.
fn handle_inbound_manifest(state: &mut NodeState, peer: PeerId, manifest_bytes: Vec<u8>) {
    let Some((height, manifest_id, bytes)) = state
        .snapshot_bootstrap
        .on_manifest_received(peer, manifest_bytes)
    else {
        // Stale, unsolicited, or wrong peer — silent drop.
        return;
    };

    // Canonical header lookup. In Dense mode any `None` is "not on
    // our best chain" → evict the voter. In PoPowSparse mode a
    // `SparseGap` at `snapshot_height` means "we haven't completed
    // bounded forward catchup yet" → silent drop (the voter is
    // still valid; re-poll on the next tick). Distinguishing the
    // two requires the 3-arm `HeightLookup` (Phase 0 §4.2 + §4.4 +
    // §10.E resolution).
    use ergo_state::chain::HeightLookup;
    let header_id = match state
        .store
        .as_utxo()
        .expect("utxo-only: Mode 2 snapshot-bootstrap manifest verify is gated off in digest mode")
        .lookup_header_at_height(height as u32)
    {
        Ok(HeightLookup::Dense(id)) => id,
        Ok(HeightLookup::SparseGap) => {
            // Catchup hasn't filled the snapshot-height row yet.
            // Per-tick re-poll until the row materializes; do NOT
            // evict — the voter is consistent with the chain, we're
            // just not ready locally.
            tracing::debug!(
                peer = %peer,
                height = height,
                "SparseGap at snapshot height; deferring manifest verify until catchup completes",
            );
            return;
        }
        Ok(HeightLookup::AboveTip) => {
            // Snapshot height exceeds best_header_height — same as
            // Dense's `None` for an above-tip height; the voter has
            // advertised a height we don't have any canonical claim
            // to. Evict, recompute selection.
            warn!(
                peer = %peer,
                height = height,
                "snapshot height above best_header_height; evicting manifest voter",
            );
            state
                .snapshot_bootstrap
                .reject_manifest_and_evict_voter(peer);
            return;
        }
        Err(e) => {
            warn!(
                peer = %peer,
                height = height,
                error = %e,
                "chain index lookup failed during manifest verification; evicting voter",
            );
            state
                .snapshot_bootstrap
                .reject_manifest_and_evict_voter(peer);
            return;
        }
    };

    let header_bytes = match state.store.get_header(&header_id) {
        Ok(Some(b)) => b,
        Ok(None) => {
            warn!(
                peer = %peer,
                header_id = %hex::encode(header_id),
                "header bytes missing for snapshot-height header; evicting voter",
            );
            state
                .snapshot_bootstrap
                .reject_manifest_and_evict_voter(peer);
            return;
        }
        Err(e) => {
            warn!(
                peer = %peer,
                error = %e,
                "header bytes lookup failed; evicting voter",
            );
            state
                .snapshot_bootstrap
                .reject_manifest_and_evict_voter(peer);
            return;
        }
    };

    let header = match read_header(&mut VlqReader::new(&header_bytes)) {
        Ok(h) => h,
        Err(e) => {
            warn!(
                peer = %peer,
                header_id = %hex::encode(header_id),
                error = %e,
                "failed to deserialize canonical header; evicting voter",
            );
            state
                .snapshot_bootstrap
                .reject_manifest_and_evict_voter(peer);
            return;
        }
    };

    // The trust boundary. `state_root.as_bytes()[..32]` must equal
    // `manifest_id` for the peer's snapshot to be canonical.
    match verify_manifest_against_state_root(&manifest_id, &header.state_root) {
        Ok(()) => {
            // Proof-anchor check: if NiPoPoW bootstrap was active,
            // compare the discovered snapshot_height to the proof's
            // anticipated anchor. Scala's serve side picks an anchor
            // at snapshot_height - LastHeadersInContext = -10; a
            // mismatch means the proof was for a different snapshot
            // epoch than the one Mode 2 selected, and bounded
            // forward catchup will need a window larger than
            // LastHeadersInContext. Logged as WARN so an operator
            // tail -f sees it.
            if let Some(popow) = state.popow_bootstrap.as_ref() {
                if let Some(proof) = popow.best_proof() {
                    let proof_suffix_h = proof.suffix_head.header.height;
                    let expected_snapshot_h = proof_suffix_h.saturating_add(10);
                    if expected_snapshot_h != height as u32 {
                        let delta = (height as i64) - (expected_snapshot_h as i64);
                        warn!(
                            proof_suffix_height = proof_suffix_h,
                            expected_snapshot_height = expected_snapshot_h,
                            actual_snapshot_height = height,
                            delta,
                            "NiPoPoW proof anchor does not match discovered snapshot height; \
                             bounded forward catchup window will exceed LastHeadersInContext",
                        );
                    }
                }
            }
            info!(
                peer = %peer,
                height = height,
                manifest_id = %hex::encode(manifest_id),
                "manifest verified against canonical state_root",
            );
            state.snapshot_bootstrap.accept_verified_manifest(bytes);
        }
        Err(e) => {
            warn!(
                peer = %peer,
                height = height,
                error = ?e,
                "manifest failed trust check; evicting voter",
            );
            state
                .snapshot_bootstrap
                .reject_manifest_and_evict_voter(peer);
        }
    }
}

/// Mode 2 consume-side: process an inbound `UtxoSnapshotChunk`
/// (code 81).
///
/// Chunk authentication is by hash, not by peer ownership: any
/// peer can serve any chunk; we accept whatever recomputes to a
/// subtree_id we expect. The bytes' first prover-node yields the
/// chunk's root structure; `recompute_chunk_root_label` produces
/// the same `Digest32` the producer's `compute_node_label` would
/// have. If that label isn't in the assembly's expected set, drop.
///
/// Strict request ownership is enforced by the assembly's inflight
/// map: `on_chunk_received` returns `WrongPeer` if a different
/// peer than the one we asked tries to fulfill the slot. That
/// case is logged (debug) and silently dropped — no penalty, since
/// races between requests and responses are normal.
fn handle_inbound_utxo_chunk(state: &mut NodeState, peer: PeerId, chunk_bytes: Vec<u8>) {
    let Some(assembly) = state.chunk_assembly.as_mut() else {
        // No active chunk-download phase — silent drop. This is
        // the common case for non-Mode-2 nodes (chunk_assembly is
        // always None) and for late-arriving chunks after
        // reconstruction completed.
        return;
    };

    // Authenticate via recomputed root label.
    let subtree_id = match ergo_state::avl::snapshot_codec::recompute_chunk_root_label(&chunk_bytes)
    {
        Ok(id) => id,
        Err(e) => {
            warn!(
                peer = %peer,
                error = %e,
                "Mode 2: chunk parse failed during root-label recompute",
            );
            return;
        }
    };

    match assembly.on_chunk_received(peer, subtree_id, chunk_bytes) {
        ChunkReceiveOutcome::Accepted => {
            debug!(
                peer = %peer,
                subtree_id = %hex::encode(subtree_id.as_bytes()),
                progress = format!("{}/{}", assembly.received_count(), assembly.total_count()),
                "Mode 2: chunk accepted",
            );
        }
        ChunkReceiveOutcome::WrongPeer
        | ChunkReceiveOutcome::Duplicate
        | ChunkReceiveOutcome::UnknownSubtreeId => {
            // All silent-drop cases. No peer penalty — these are
            // benign races (peer races, retransmits, late arrivals
            // after reconstruction).
            debug!(
                peer = %peer,
                subtree_id = %hex::encode(subtree_id.as_bytes()),
                "Mode 2: chunk drop",
            );
        }
    }
}
