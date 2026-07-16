//! Per-frame message dispatch: throttle check, then one match arm per
//! `message::CODE_*` opcode. The three arms with substantial per-batch
//! logic (`CODE_INV`, `CODE_MODIFIER`, `CODE_PEERS`) are factored into
//! named helpers below, all following the same `&mut NodeState -> Vec<Action>`
//! convention as `handle_message` itself.

use std::time::Instant;

use ergo_p2p::handshake::PeerSpec;
use ergo_p2p::message;
use ergo_p2p::peer::{PeerId, Penalty, SyncVersion};
use ergo_p2p::throttle::LimiterVerdict;
use ergo_p2p::types::{InvData, ModifierTypeId, ModifiersData};
use ergo_primitives::digest::Digest32;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_sync::coordinator::Action;
use tracing::{debug, info, warn};

use super::super::{
    admit_transaction, hedge_request_modifiers, send_to_peer, try_send_anchor_sync_info, NodeState,
};
use super::{manifest, popow, utxo_chunk};

#[tracing::instrument(
    name = "msg",
    level = "debug",
    skip_all,
    fields(peer = %peer, code = code, bytes = payload.len()),
)]
pub(in crate::node) fn handle_message(
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
        message::CODE_INV => match message::deserialize_inv(payload) {
            Ok(inv) => handle_inv(state, peer, inv, now),
            Err(e) => {
                warn!(peer = %peer, error = %e, "bad Inv");
                vec![Action::Penalize {
                    peer,
                    penalty: Penalty::Misbehavior,
                }]
            }
        },
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
                        // Mode 3 serve gating. Silently
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
                        // SECTION_HEIGHT_INDEX rows (see the
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
        message::CODE_MODIFIER => match message::deserialize_modifiers(payload) {
            Ok(mods) => handle_modifier_batch(state, peer, mods, now),
            Err(e) => {
                warn!(peer = %peer, error = %e, "bad Modifier");
                vec![Action::Penalize {
                    peer,
                    penalty: Penalty::Misbehavior,
                }]
            }
        },
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
        message::CODE_PEERS => match message::deserialize_peers(payload, 100) {
            Ok(peers) => handle_peers_response(state, peer, peers),
            Err(e) => {
                warn!(peer = %peer, error = %e, "bad Peers");
                Vec::new()
            }
        },
        message::CODE_SNAPSHOTS_INFO => match message::deserialize_snapshots_info(payload) {
            Ok(info) => {
                // Feed the discovery reducer. The reducer tracks per-peer
                // votes and applies the Scala quorum rule. Eligibility
                // filtering — restricting which peers we *ask* for
                // SnapshotsInfo — lives in the outbound fan-out instead.
                // Inbound, we accept what we're given: a
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
                manifest::handle_inbound_manifest(state, peer, manifest_bytes);
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
                utxo_chunk::handle_inbound_utxo_chunk(state, peer, chunk_bytes);
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
        message::CODE_NIPOPOW_PROOF => {
            popow::handle_inbound_popow_proof(state, peer, payload.to_vec())
        }
        message::CODE_GET_NIPOPOW_PROOF => {
            // Serve side. Scala parity (HeadersProcessor.scala:166-169): a
            // NiPoPoW-bootstrapped (sparse-mode) node has no
            // extension/interlinks data for prefix headers and so
            // cannot construct a proof — silent no-op. A Dense
            // archive node returns its cached proof if one has been
            // built (by StateStore::compute_and_cache_popow_proof_dense
            // or a future apply-time snapshot-epoch hook).
            // Scala parity (`ErgoNodeViewSynchronizer.scala:1046-1058`
            // `sendNipopowProof`): serve ONLY the canonical
            // `(P2P_NIPOPOW_PROOF_M, P2P_NIPOPOW_PROOF_K)` request with
            // no anchor id — anything else warns and drops (previously
            // we served the cached default proof to ANY request, a
            // silent wrong-proof divergence). A malformed payload is
            // peer misbehavior, as on the other request arms.
            let data = match message::deserialize_get_nipopow_proof(payload) {
                Ok(d) => d,
                Err(e) => {
                    warn!(peer = %peer, error = %e, "bad GetNipopowProof payload");
                    return vec![Action::Penalize {
                        peer,
                        penalty: Penalty::Misbehavior,
                    }];
                }
            };
            if !data.p2p_servable() {
                warn!(
                    peer = %peer,
                    m = data.m,
                    k = data.k,
                    anchored = data.header_id_opt.is_some(),
                    "GetNipopowProof: params can't be served (only default m/k, unanchored)"
                );
                return Vec::new();
            }
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

/// Handle a parsed `Inv` (message code 60): tx-typed advertisements are
/// filtered against the pool + rejection cache before requesting, then
/// dispatched via `request_transactions` (which does its own dedupe/cap
/// accounting); any other type routes through the coordinator's normal
/// `on_inv` + hedge-dispatch + executor path.
fn handle_inv(state: &mut NodeState, peer: PeerId, inv: InvData, now: Instant) -> Vec<Action> {
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
            // P2 observability: this branch was previously
            // silent. Count only the ids ACTUALLY requested
            // (always-on, mainnet-safe aggregate via
            // `/metrics`) and emit a per-tx-batch `debug`
            // trace so an operator can see, at default `info`,
            // whether a given tx was requested at all (counter)
            // and which peer/how many (debug).
            //
            // The counter must reflect ids for which a
            // RequestModifier was truly emitted, NOT the
            // advertised `unknown.len()`: the coordinator
            // dedupes against in-flight/failed ids and applies
            // a per-peer cap, so a repeated Inv for an
            // already-in-flight id would otherwise overcount
            // "requested" with no matching RequestModifier
            // sent. `request_transactions` returns the real
            // post-dedupe/cap count alongside its actions.
            let (actions, requested) = state.coordinator.request_transactions(peer, &unknown, now);
            state.mempool_tx_requested_total = state
                .mempool_tx_requested_total
                .saturating_add(requested as u64);
            debug!(
                peer = %peer,
                requested,
                "requesting unconfirmed txs from peer",
            );
            actions
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
}

/// Handle a parsed `Modifier` batch (message code 33): tx-typed modifiers
/// go through per-tx delivery-check + admission with no chain pipeline;
/// everything else (headers/sections) is id-verified, handed to the
/// coordinator one at a time, then executed as a single batch so the
/// executor's rayon pre-validate + sequential finalize can process the
/// whole batch rather than one modifier at a time. Also drives the
/// post-batch IBD-exit check, download refill, and immediate re-request
/// of more headers.
fn handle_modifier_batch(
    state: &mut NodeState,
    peer: PeerId,
    mods: ModifiersData,
    now: Instant,
) -> Vec<Action> {
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
                    // NB: a tx delivery deliberately does NOT
                    // touch the body-only download-failure
                    // streak — only block-body sections do
                    // (see coordinator::on_modifier_received).
                    let mut admission_actions = admit_transaction(state, peer, &bytes, now);
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
            if let Err(reason) =
                ergo_sync::coordinator::verify_section_modifier_id(type_id, &mod_id, &data)
            {
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

    super::super::maybe_exit_ibd(&mut state.store, fb_before, fb, bh);

    // Refill downloads without waiting for the next
    // sync tick when (a) blocks were just applied —
    // the window slid forward so new pending heights
    // need requests — or (b) Sync-S2 drain trigger:
    // total in-flight has dropped below DRAIN_WATERMARK
    // and the peer would otherwise sit idle for up to
    // 3 seconds.
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

    // Log progress periodically
    if bh.is_multiple_of(500) && bh > 0 {
        let h = state.store.height();
        info!(height = h, headers = bh, "chain progress");
    }

    all_actions
}

/// Handle a parsed `Peers` gossip response (message code 61): each
/// advertised spec is fed to the peer manager's known-address table,
/// tallying outcomes for a single summary log (suppressed entirely when
/// every entry was a duplicate of what we already know).
fn handle_peers_response(state: &mut NodeState, peer: PeerId, peers: Vec<PeerSpec>) -> Vec<Action> {
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
        let Some(sock) = ergo_p2p::peer_manager::declared_to_socket(declared) else {
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
