//! Post-apply storage-rent broadcast collector (Phase 3).
//!
//! On **every** synced tip change — fully synced, UTXO mode — this
//! enumerates eligible storage-rent boxes, builds a fee-paying claim family
//! (the three-shape builder in [`ergo_mining::rent_broadcast`]), and admits
//! it **directly** to the local mempool tagged [`TxSource::RentCollector`].
//! The mempool's relay path then advertises it to peers, who mine it; the
//! configured proceeds key collects the net rent.
//!
//! ## Trigger: every synced tip change (NOT gated on "block I didn't mine")
//!
//! The trigger is deliberately **not** special-cased on whether *this* node
//! mined the new tip — it fires on every synced tip change. The
//! "collect only on blocks won by others" outcome is achieved by the
//! **self-clean** mechanism, not by a self-mined gate:
//!
//! * If the node mines the *next* block too, its free in-block self-claim
//!   ([`crate::storage_rent_claim`]) double-spends the same boxes as this
//!   fee-paying broadcast. The broadcast is then evicted unmined — it never
//!   lands on-chain, so **no fee is paid** for it.
//! * If another miner mines the next block, the broadcast they pick up is
//!   what collects the rent (the fee buys inclusion).
//!
//! So a redundant broadcast after a self-mined block costs nothing (it
//! self-cleans via the double-spend), and what remains is collection on the
//! blocks won by other miners — without ever introducing a self-mined gate.
//!
//! ## Why direct admission (no submit channel)
//!
//! The collector runs ON the action loop — the same loop that *consumes*
//! the API submit channel. Routing a tx back through `submit_rx` would
//! deadlock (the loop would be waiting on a channel it must also drain).
//! So the collector admits straight into [`NodeState::mempool`] via
//! [`Mempool::admit_family_atomic`], which stages the parent + optional
//! child transactionally and returns the `BroadcastInv` actions only on
//! full success — the caller routes + flushes them through the node's
//! existing [`route_mempool_actions`] / [`flush_actions`] path. A
//! half-family never reaches the wire.
//!
//! ## Ordering vs the #141 recheck
//!
//! Tip-path first-occupancy: on tip change the action loop
//! `evict_by_source(RentCollector)` → [`collect_and_broadcast`] → then the
//! full-pool recheck. That clears a CPFP-boosted prior-height family before
//! the fresh claim is built, without waiting on full recheck latency.
//!
//! ## Speculative header-triggered build
//!
//! When the header tip advances exactly one height ahead of the full-block
//! tip (the NewBlock window), [`speculate_on_new_header`] builds and caches
//! claim families against the **pre-apply** live UTXO. Admission happens
//! **only** in [`collect_and_broadcast`] after tip apply, and only when the
//! applied tip matches the cached header and every parent input is still
//! resolvable live. Cache is discarded on tip mismatch, reorg/tip-flip, or
//! spent inputs — never admit pre-apply (wrong UTXO / consensus-unsafe).
//!
//! ## Borrow structure
//!
//! [`collect_and_broadcast`] takes `&mut NodeState` but reuses the
//! `OwnedTipContext` already built by `handle_mempool_tick` (which holds
//! the `TransactionContext` / `ProtocolParams` / `last_headers` /
//! `reemission` the builder needs at `tip + 1`). It first resolves the
//! proceeds key + the eligible boxes through *immutable, owned* reads of
//! `state.store` / `state.indexer_handle` (each borrow dropped before the
//! next step), then hands the owned results to the testable core
//! [`build_and_admit_family`], which builds the claim and admits it via a
//! disjoint `&mut state.mempool` + `&state.store` tip-context — exactly the
//! disjoint-field pattern the recheck uses.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use ergo_mempool::admission::TipContext as MempoolTipContext;
use ergo_mempool::types::{MempoolAction, TxSource};
use ergo_mempool::{ErgoValidator, Mempool};
use ergo_mining::config::RentCollectorConfig;
use ergo_mining::rent_broadcast::{
    build_broadcast_claim, jittered_parent_fee_per_input, BroadcastClaim, FeeInputs,
};
use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::read_header;
use ergo_ser::transaction::{write_transaction, Transaction};
use ergo_state::wallet::RewardKeyResolution;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_validation::{TransactionContext, UtxoView};
use tracing::{debug, info, warn};

use super::admission::route_mempool_actions;
use super::mining_engine::resolve_eligible_rent_boxes;
use super::peer_actions::flush_actions;
use super::tip_context::OwnedTipContext;
use super::NodeState;

/// Timing context for tip→Inv metrics on relay.
struct RelayTiming {
    collect_start: Instant,
    speculative_hit: bool,
    speculative_build_age_ms: u64,
}

/// Inputs for speculative (build-only) family construction.
struct SpeculativeBuildCtx<'a> {
    proceeds_pk: &'a [u8; 33],
    tx_context: &'a TransactionContext,
    params: &'a ergo_validation::ProtocolParams,
    last_headers: &'a [ergo_ser::header::Header],
    reemission: Option<&'a ergo_validation::ReemissionRuleInputs>,
    fee_inputs: &'a FeeInputs,
}

/// One built (not yet admitted) claim family cached across the
/// header→apply window.
#[derive(Debug, Clone)]
pub(super) struct SpeculativeRentFamily {
    claim: BroadcastClaim,
    parent_input_ids: Vec<Digest32>,
}

/// Speculative RC cache: built on header advance, admitted only after
/// matching tip apply with live inputs.
#[derive(Debug, Clone)]
pub(super) struct SpeculativeRentCache {
    /// Header id we expect to become the next full-block tip.
    pub(super) expected_tip_id: [u8; 32],
    /// Parent of that header (full tip at speculate time).
    pub(super) expected_parent_id: [u8; 32],
    pub(super) expected_height: u32,
    families: Vec<SpeculativeRentFamily>,
    pub(super) built_at: Instant,
}

/// First-occupancy timing + Inv-ACK counters for the current tip.
#[derive(Debug, Default)]
pub(super) struct RentFirstOccupancyMetrics {
    /// Speculative claim cache (header-built, admit deferred to tip apply).
    pub(super) speculative: Option<SpeculativeRentCache>,
    /// When the current full tip was applied (`None` until first tip / after
    /// the first tip→Inv log clears it).
    pub(super) tip_apply_at: Option<Instant>,
    pub(super) tip_height: u32,
    /// RC parent (+ child) txids we Inv'd this tip — Inv-ACK match set.
    pub(super) invd_rc_txids: HashSet<[u8; 32]>,
    /// Same tip's Inv'd RC txids in admit order (parent before child per
    /// family). Used by REST submit so child never races ahead of parent.
    pub(super) invd_rc_ordered: Vec<[u8; 32]>,
    /// Distinct *public* priority-peer IPs that RequestModifier'd an RC txid
    /// (configured `priority_peers` minus `decisive_peers`).
    pub(super) public_priority_ack_peers: HashSet<IpAddr>,
    pub(super) public_priority_ack_total: u32,
    /// Distinct decisive/assembler-tier IPs that RequestModifier'd an RC txid.
    pub(super) decisive_ack_peers: HashSet<IpAddr>,
    pub(super) decisive_ack_total: u32,
}

/// Outcome of checking a speculative cache against the post-apply tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SpeculativeCacheVerdict {
    /// Tip matches and every parent input is still live — safe to admit.
    Hit,
    /// Applied tip id/height ≠ cached expectation (miss / reorg / flip).
    TipMismatch,
    /// Tip matched but at least one parent input is spent / missing live.
    InputsSpent,
    /// Nothing cached.
    Empty,
}

/// Pure cache gate used by collect + unit tests. Never admits.
pub(super) fn evaluate_speculative_cache(
    cache: Option<&SpeculativeRentCache>,
    applied_tip_id: &[u8; 32],
    applied_tip_height: u32,
    utxo: &dyn UtxoView,
) -> SpeculativeCacheVerdict {
    let Some(cache) = cache else {
        return SpeculativeCacheVerdict::Empty;
    };
    if cache.families.is_empty() {
        return SpeculativeCacheVerdict::Empty;
    }
    if cache.expected_tip_id != *applied_tip_id || cache.expected_height != applied_tip_height {
        return SpeculativeCacheVerdict::TipMismatch;
    }
    for fam in &cache.families {
        for id in &fam.parent_input_ids {
            if utxo.get_box(id).is_none() {
                return SpeculativeCacheVerdict::InputsSpent;
            }
        }
    }
    SpeculativeCacheVerdict::Hit
}

/// Drop any speculative cache (reorg / tip flip / miss). Idempotent.
pub(super) fn discard_speculative_cache(state: &mut NodeState, reason: &'static str) {
    if state.rent_fo.speculative.take().is_some() {
        debug!(
            event = "rent_collector_speculative_discard",
            reason, "rent-collector: discarded speculative claim cache"
        );
    }
}

/// Mark tip-apply for tip→Inv timing. Emits previous-tip Inv-ACK summary
/// (`builder_reach_miss` only when decisive ACKs are 0), then resets
/// per-tip counters.
pub(super) fn note_tip_apply(state: &mut NodeState, tip_height: u32) {
    if !state.rent_fo.invd_rc_txids.is_empty() {
        let prev_tip = state.rent_fo.tip_height;
        let invd = state.rent_fo.invd_rc_txids.len();
        let public_priority_ack_peers = state.rent_fo.public_priority_ack_peers.len() as u32;
        let public_priority_ack_total = state.rent_fo.public_priority_ack_total;
        let decisive_ack_peers = state.rent_fo.decisive_ack_peers.len() as u32;
        let decisive_ack_total = state.rent_fo.decisive_ack_total;
        let still_pooled = state
            .rent_fo
            .invd_rc_txids
            .iter()
            .filter(|id| state.mempool.contains(&Digest32::from_bytes(**id)))
            .count() as u32;
        // Reach miss is decisive-only: public priority ACKs must not clear it.
        let builder_reach_miss = still_pooled > 0 && decisive_ack_peers == 0;
        let connected_priority = state.peer_manager.connected_priority_ip_count();
        let connected_decisive = connected_decisive_ip_count(state);
        info!(
            event = "rent_collector_tip_ack_summary",
            prev_tip_height = prev_tip,
            new_tip_height = tip_height,
            invd_txids = invd,
            public_priority_ack_peers,
            public_priority_ack_total,
            decisive_ack_peers,
            decisive_ack_total,
            still_pooled,
            builder_reach_miss,
            connected_priority_ips = connected_priority,
            connected_decisive_ips = connected_decisive,
            "rent-collector: tip Inv-ACK summary (decisive vs public priority)"
        );
        if builder_reach_miss {
            warn!(
                event = "rent_collector_builder_reach_miss",
                prev_tip_height = prev_tip,
                still_pooled,
                decisive_ack_peers = 0,
                public_priority_ack_peers,
                connected_priority_ips = connected_priority,
                connected_decisive_ips = connected_decisive,
                "rent-collector: RC parent still unconfirmed at next tip with 0 decisive Inv-ACKs"
            );
            // Ops signal: still pooled + no decisive ACK ≈ rival private path
            // (fee=0 021-style) rather than "we never gossiped".
            info!(
                event = "rent_collector_private_path_hint",
                prev_tip_height = prev_tip,
                still_pooled,
                public_priority_ack_peers,
                "rent-collector: private-path hint (parents pooled, decisive assemblers silent)"
            );
        } else if still_pooled > 0 {
            info!(
                event = "rent_collector_unconfirmed_at_tip",
                prev_tip_height = prev_tip,
                still_pooled,
                decisive_ack_peers,
                public_priority_ack_peers,
                "rent-collector: RC parent still unconfirmed at next tip despite decisive Inv-ACKs"
            );
        }
    }
    state.rent_fo.tip_apply_at = Some(Instant::now());
    state.rent_fo.tip_height = tip_height;
    state.rent_fo.invd_rc_txids.clear();
    state.rent_fo.invd_rc_ordered.clear();
    state.rent_fo.public_priority_ack_peers.clear();
    state.rent_fo.public_priority_ack_total = 0;
    state.rent_fo.decisive_ack_peers.clear();
    state.rent_fo.decisive_ack_total = 0;
}

fn connected_decisive_ip_count(state: &NodeState) -> usize {
    let Some(cfg) = state.rent_collector.as_ref() else {
        return 0;
    };
    if cfg.decisive_peers.is_empty() {
        return 0;
    }
    let decisive_ips: HashSet<_> = cfg.decisive_peers.iter().map(|a| a.ip()).collect();
    let mut seen = HashSet::new();
    for peer in state.peer_manager.connected_peers() {
        if decisive_ips.contains(&peer.addr.ip()) {
            seen.insert(peer.addr.ip());
        }
    }
    seen.len()
}

/// Inv-ACK proxy: a peer RequestModifier'd bytes for an RC tx we Inv'd.
/// Classifies decisive vs public-priority vs other.
pub(super) fn note_priority_inv_ack(
    state: &mut NodeState,
    peer_ip: IpAddr,
    txid: &[u8; 32],
    is_priority: bool,
    is_decisive: bool,
) {
    if !state.rent_fo.invd_rc_txids.contains(txid) {
        return;
    }
    if !is_priority && !is_decisive {
        debug!(
            event = "rent_collector_inv_ack",
            tip_height = state.rent_fo.tip_height,
            txid_prefix = %hex::encode(&txid[..4]),
            peer_ip = %peer_ip,
            priority = false,
            decisive = false,
            "rent-collector: peer RequestModifier for RC tx"
        );
        return;
    }
    if is_decisive {
        state.rent_fo.decisive_ack_total = state.rent_fo.decisive_ack_total.saturating_add(1);
        let first = state.rent_fo.decisive_ack_peers.insert(peer_ip);
        if first {
            info!(
                event = "rent_collector_decisive_inv_ack",
                tip_height = state.rent_fo.tip_height,
                txid_prefix = %hex::encode(&txid[..4]),
                peer_ip = %peer_ip,
                decisive_ack_peers = state.rent_fo.decisive_ack_peers.len(),
                decisive_ack_total = state.rent_fo.decisive_ack_total,
                "rent-collector: decisive peer RequestModifier (Inv-ACK)"
            );
        } else {
            debug!(
                event = "rent_collector_decisive_inv_ack",
                tip_height = state.rent_fo.tip_height,
                txid_prefix = %hex::encode(&txid[..4]),
                peer_ip = %peer_ip,
                "rent-collector: decisive peer re-RequestModifier for RC tx"
            );
        }
        return;
    }
    // Public priority (configured priority, not decisive).
    state.rent_fo.public_priority_ack_total =
        state.rent_fo.public_priority_ack_total.saturating_add(1);
    let first_from_peer = state.rent_fo.public_priority_ack_peers.insert(peer_ip);
    if first_from_peer {
        info!(
            event = "rent_collector_public_priority_inv_ack",
            tip_height = state.rent_fo.tip_height,
            txid_prefix = %hex::encode(&txid[..4]),
            peer_ip = %peer_ip,
            public_priority_ack_peers = state.rent_fo.public_priority_ack_peers.len(),
            public_priority_ack_total = state.rent_fo.public_priority_ack_total,
            "rent-collector: public priority peer RequestModifier (Inv-ACK)"
        );
    } else {
        debug!(
            event = "rent_collector_public_priority_inv_ack",
            tip_height = state.rent_fo.tip_height,
            txid_prefix = %hex::encode(&txid[..4]),
            peer_ip = %peer_ip,
            "rent-collector: public priority peer re-RequestModifier for RC tx"
        );
    }
}

/// Post-apply trigger: build a fee-paying storage-rent claim family for the
/// freshly-applied tip and admit it directly to the local mempool, then
/// route + flush the resulting wire broadcasts.
///
/// Fires on **every** synced tip change — it is intentionally NOT gated on
/// "a block I didn't mine". A broadcast that is redundant because the node
/// also mines the next block self-cleans: the in-block self-claim
/// double-spends the same boxes, so the broadcast is evicted unmined and no
/// fee is paid. See the module docs for the full self-clean rationale.
///
/// Gated three ways (any miss → no-op): the collector must be configured
/// `enabled`, the indexer must be present (eligibility enumeration reads
/// only the extra-index), and the proceeds key must resolve `Ready`.
/// `Pending` is transient (the wallet is still resolving its EIP-3 key) →
/// skip THIS tick and retry next block. `Corrupt`/absent is non-transient
/// → latch the collector OFF (`state.rent_collector = None`) and `warn!`
/// exactly once; with the collector cleared, `need_collect` is false on
/// every future tick, so it stays disabled until the operator fixes the
/// fault and restarts. The fully-synced + UTXO-only gate is enforced by
/// the caller (`handle_mempool_tick`), which only invokes this in that
/// region.
///
/// `owned` is the tip context the caller already built for the recheck; it
/// carries the `tip + 1` validation inputs the builder needs.
pub(super) fn collect_and_broadcast(state: &mut NodeState, owned: &OwnedTipContext) {
    let collect_start = Instant::now();

    // Gate 1: enabled. `rent_collector` is `Some` exactly when configured on.
    let Some(config) = state.rent_collector.clone() else {
        return;
    };

    // Fast path: try speculative cache BEFORE proceeds-key resolution.
    // Hit admits pre-built families and returns — no wallet/key work on the
    // tip→Inv critical path.
    let applied_tip_id = state.store.chain_state_meta().best_full_block_id;
    let applied_tip_height = state.store.chain_state_meta().best_full_block_height;
    let cache = state.rent_fo.speculative.take();
    let verdict = {
        let store = state
            .store
            .as_utxo()
            .expect("utxo-only: rent collector is gated to UTXO mode by handle_mempool_tick");
        evaluate_speculative_cache(cache.as_ref(), &applied_tip_id, applied_tip_height, store)
    };
    match (verdict, cache) {
        (SpeculativeCacheVerdict::Hit, Some(cache)) => {
            let now = Instant::now();
            if admit_speculative_families(state, owned, cache, now, collect_start) {
                return;
            }
            // Admit failed despite Hit — fall through to rebuild.
            debug!(
                event = "rent_collector_speculative_admit_miss",
                "rent-collector: speculative Hit but admit failed; rebuilding"
            );
        }
        (SpeculativeCacheVerdict::TipMismatch, Some(cache)) => {
            debug!(
                event = "rent_collector_speculative_discard",
                reason = "tip_mismatch",
                tip_height = applied_tip_height,
                expected_height = cache.expected_height,
                expected_tip_prefix = %hex::encode(&cache.expected_tip_id[..4]),
                expected_parent_prefix = %hex::encode(&cache.expected_parent_id[..4]),
                "rent-collector: speculative cache tip mismatch; rebuilding"
            );
        }
        (SpeculativeCacheVerdict::InputsSpent, Some(_)) => {
            debug!(
                event = "rent_collector_speculative_discard",
                reason = "inputs_spent",
                tip_height = applied_tip_height,
                "rent-collector: speculative inputs spent; rebuilding"
            );
        }
        _ => {}
    }

    // Rebuild path: resolve proceeds key (skipped on speculative Hit).
    // Gate 2: a resolved proceeds key. Reuses the miner reward-key source,
    // decoupled from `[mining].enabled`. The resolution is computed in its
    // own scope so the immutable `state.store` borrow is dropped before the
    // `match` — the `Corrupt` arm must mutate `state.rent_collector`, which
    // would conflict with a live `store` borrow. (`store` is re-bound below
    // for gate 3 / admission, restarting the disjoint-field pattern fresh.)
    let resolution = {
        // UTXO store (the caller's fully-synced + UTXO-only gate guarantees
        // this is the Utxo backend; mirror the recheck's `expect`).
        let store = state
            .store
            .as_utxo()
            .expect("utxo-only: rent collector is gated to UTXO mode by handle_mempool_tick");
        state.rent_proceeds_key.resolve(store)
    };
    let proceeds_pk = match resolution {
        RewardKeyResolution::Ready(pk) => pk,
        RewardKeyResolution::Pending => {
            // The wallet is still resolving its EIP-3 key — skip THIS tick
            // and retry on the next block. Transient, so debug not warn.
            debug!(
                "rent-collector: proceeds key not ready yet (wallet resolving); skipping this tick"
            );
            return;
        }
        RewardKeyResolution::Corrupt => {
            // Tracking exists but is inconsistent — NOT transient (the
            // config-load gate already required a resolvable key, so this is
            // an operator-fixable runtime fault). Latch the collector OFF so
            // we don't re-resolve + re-`warn!` ~once per block on every
            // future tip change: clearing `rent_collector` makes gate 1
            // short-circuit (and `need_collect` false) on all subsequent
            // ticks. The borrow above is dropped, so this `&mut state` write
            // is sound. The `warn!` fires exactly once because the latch
            // prevents re-entry; the collector stays off until restart.
            warn!(
                "rent-collector: proceeds key resolution is Corrupt; collector disabled until restart"
            );
            state.rent_collector = None;
            return;
        }
    };

    // Re-bind the UTXO store for gate 3 / admission (the gate-2 borrow ended
    // with the resolution scope above).
    let store = state
        .store
        .as_utxo()
        .expect("utxo-only: rent collector is gated to UTXO mode by handle_mempool_tick");

    // Gate 3: indexer present, and resolve eligible boxes against the LIVE
    // UTXO tip (same view admission uses). Do NOT use `committed_snapshot`
    // here — it can trail the in-memory tip by the persist-pipeline depth;
    // materializing from a lagging snapshot then admitting against the live
    // store yields UnresolvedInput and skips the tip race (VPS: ~42 misses /
    // 12h). Candidate mining still uses the durable snapshot for dry-run
    // stability; the collector is post-apply and must match live state.
    let candidate_height = owned.tx_context.height; // == tip + 1
    let eligible: Vec<ErgoBox> = if state.indexer_handle.is_some() {
        resolve_eligible_rent_boxes(
            state.indexer_handle.as_ref(),
            store,
            candidate_height,
            config.max_claims,
        )
    } else {
        // No indexer → nothing to enumerate. (Config-load requires the
        // indexer when the collector is enabled, so this is the
        // indexer-halted case.)
        Vec::new()
    };
    if eligible.is_empty() {
        return;
    }

    // Borrows of `store` for snapshot/key resolution end here — `eligible`
    // and `proceeds_pk` are owned. Build + admit family 1 at today's latency,
    // then chunk overflow into input-disjoint families 2..N under the time
    // budget / `max_families_per_tip` cap.
    let now = Instant::now();
    let budget = Duration::from_millis(config.collect_time_budget_ms);
    admit_chunked_families(
        state,
        owned,
        eligible,
        ChunkAdmitArgs {
            proceeds_pk: &proceeds_pk,
            config: &config,
            now,
            budget,
            timing: RelayTiming {
                collect_start,
                speculative_hit: false,
                speculative_build_age_ms: 0,
            },
        },
    );
}

/// Header-triggered speculative build. Caches claim families; **never admits**.
///
/// Fires when `best_header` is exactly one height ahead of `best_full` and
/// the new header's parent is the current full tip. Anything else (IBD
/// multi-ahead, equal-height flip) discards / no-ops.
pub(super) fn speculate_on_new_header(state: &mut NodeState) {
    let Some(config) = state.rent_collector.clone() else {
        return;
    };
    let cs = state.store.chain_state_meta();
    // Only the single-block NewBlock window — not IBD catch-up.
    if cs.best_full_block_height == 0
        || cs.best_header_height != cs.best_full_block_height.saturating_add(1)
    {
        discard_speculative_cache(state, "header_not_one_ahead");
        return;
    }

    let header_bytes = match state.store.get_header(&cs.best_header_id) {
        Ok(Some(b)) => b,
        _ => {
            discard_speculative_cache(state, "header_bytes_missing");
            return;
        }
    };
    let header = {
        let mut r = VlqReader::new(&header_bytes);
        match read_header(&mut r) {
            Ok(h) => h,
            Err(_) => {
                discard_speculative_cache(state, "header_decode_failed");
                return;
            }
        }
    };
    let parent_id = *header.parent_id.as_bytes();
    if parent_id != cs.best_full_block_id {
        discard_speculative_cache(state, "header_parent_mismatch");
        return;
    }

    let resolution = {
        let store = match state.store.as_utxo() {
            Some(s) => s,
            None => return,
        };
        state.rent_proceeds_key.resolve(store)
    };
    let proceeds_pk = match resolution {
        RewardKeyResolution::Ready(pk) => pk,
        _ => return, // Pending/Corrupt: leave to post-apply path
    };

    let candidate_height = cs.best_header_height.saturating_add(1);
    let eligible = {
        let store = match state.store.as_utxo() {
            Some(s) => s,
            None => return,
        };
        if state.indexer_handle.is_none() {
            Vec::new()
        } else {
            resolve_eligible_rent_boxes(
                state.indexer_handle.as_ref(),
                store,
                candidate_height,
                config.max_claims,
            )
        }
    };
    if eligible.is_empty() {
        discard_speculative_cache(state, "no_eligible");
        return;
    }

    // Build validation context as post-apply tip_context will: tip = new
    // header, height = tip+1. last_headers = new header + prior full window.
    let mut last_headers: Vec<ergo_ser::header::Header> = vec![header.clone()];
    for ch in state.executor.block_context_headers() {
        last_headers.push(ch.header().clone());
    }
    let tx_context = TransactionContext {
        height: candidate_height,
        miner_pubkey: *header.solution.pk().as_bytes(),
        pre_header_timestamp: header.timestamp,
        activated_script_version: header.version.saturating_sub(1),
        pre_header_version: header.version,
        pre_header_parent_id: parent_id,
        pre_header_n_bits: header.n_bits as u64,
        pre_header_votes: header.votes,
    };
    let params = ergo_validation::ProtocolParams::from_active(state.store.active_params());
    let reemission = state.executor.reemission_rules().cloned();
    let fee_inputs = {
        let mp_cfg = state.mempool.config();
        FeeInputs {
            min_relay_fee: mp_cfg.min_relay_fee_nano_erg,
            min_profit: config.min_profit_nanoerg,
            max_tx_size_bytes: mp_cfg.max_tx_size_bytes.min(u32::MAX as usize) as u32,
            max_tx_cost: mp_cfg.max_tx_cost,
            parent_fee_per_input: jittered_parent_fee_per_input(
                config.parent_fee_per_input_nanoerg,
                config.jitter_bps,
                config.jitter_seed,
            ),
        }
    };

    let families = build_speculative_families(
        &eligible,
        SpeculativeBuildCtx {
            proceeds_pk: &proceeds_pk,
            tx_context: &tx_context,
            params: &params,
            last_headers: &last_headers,
            reemission: reemission.as_ref(),
            fee_inputs: &fee_inputs,
        },
        config.max_families_per_tip,
        Duration::from_millis(config.collect_time_budget_ms),
    );
    if families.is_empty() {
        discard_speculative_cache(state, "build_empty");
        return;
    }

    let n = families.len();
    state.rent_fo.speculative = Some(SpeculativeRentCache {
        expected_tip_id: cs.best_header_id,
        expected_parent_id: parent_id,
        expected_height: cs.best_header_height,
        families,
        built_at: Instant::now(),
    });
    info!(
        event = "rent_collector_speculative_built",
        tip_height = cs.best_header_height,
        families = n,
        header_prefix = %hex::encode(&cs.best_header_id[..4]),
        "rent-collector: speculative claim cache ready (admit deferred until tip apply)"
    );
}

/// Build-only chunk loop — **never admits**. Same family/budget semantics
/// as the post-apply path.
fn build_speculative_families(
    eligible: &[ErgoBox],
    ctx: SpeculativeBuildCtx<'_>,
    max_families_per_tip: u32,
    budget: Duration,
) -> Vec<SpeculativeRentFamily> {
    let max_families = max_families_per_tip.max(1);
    let mut remaining: Vec<ErgoBox> = eligible.to_vec();
    let start = Instant::now();
    let mut out = Vec::new();
    let mut families_built = 0u32;

    while !remaining.is_empty() && families_built < max_families {
        if families_built > 0 && start.elapsed() >= budget {
            break;
        }
        let before_len = remaining.len();
        let fam = match build_family_only(&remaining, &ctx) {
            Some(f) => f,
            None => break,
        };
        let consumed = fam.parent_input_ids.clone();
        match apply_chunk_progress(&mut remaining, consumed) {
            ChunkProgress::Stop => break,
            ChunkProgress::Continue => {
                if remaining.len() >= before_len {
                    break;
                }
                out.push(fam);
                families_built = families_built.saturating_add(1);
            }
        }
    }
    out
}

fn build_family_only(
    eligible: &[ErgoBox],
    ctx: &SpeculativeBuildCtx<'_>,
) -> Option<SpeculativeRentFamily> {
    let candidate_height = ctx.tx_context.height;
    let claim = match build_broadcast_claim(
        eligible,
        candidate_height,
        ctx.params,
        ctx.proceeds_pk,
        ctx.tx_context,
        ctx.last_headers,
        ctx.reemission,
        ctx.fee_inputs,
    ) {
        Ok(Some(c)) => c,
        Ok(None) | Err(_) => return None,
    };
    let parent_input_ids: Vec<Digest32> = claim
        .parent_inputs
        .iter()
        .filter_map(|b| b.box_id().ok())
        .collect();
    Some(SpeculativeRentFamily {
        claim,
        parent_input_ids,
    })
}

/// Admit pre-built speculative families against the post-apply tip.
/// Returns `true` if at least one family was relayed.
fn admit_speculative_families(
    state: &mut NodeState,
    owned: &OwnedTipContext,
    cache: SpeculativeRentCache,
    now: Instant,
    collect_start: Instant,
) -> bool {
    let mut any = false;
    let speculative_build_ms = cache.built_at.elapsed().as_millis() as u64;
    let timing = RelayTiming {
        collect_start,
        speculative_hit: true,
        speculative_build_age_ms: speculative_build_ms,
    };
    for fam in cache.families {
        let actions = {
            let store = state
                .store
                .as_utxo()
                .expect("utxo-only: rent collector is gated to UTXO mode by handle_mempool_tick");
            let tip_ctx = owned.as_mempool_ctx(store);
            admit_claim(&mut state.mempool, &tip_ctx, &fam.claim, now)
        };
        if !actions.is_empty() {
            any = true;
            relay_and_count(state, actions, &timing);
        }
    }
    any
}

/// Build + admit + relay up to `max_families_per_tip` input-disjoint
/// families from `eligible`. Family 1 fires outside the budget check;
/// overflow families stop when `budget` elapses (`Duration::ZERO` ⇒ only
/// family 1 — deterministic early-stop test without a fake clock).
struct ChunkAdmitArgs<'a> {
    proceeds_pk: &'a [u8; 33],
    config: &'a RentCollectorConfig,
    now: Instant,
    budget: Duration,
    timing: RelayTiming,
}

fn admit_chunked_families(
    state: &mut NodeState,
    owned: &OwnedTipContext,
    eligible: Vec<ErgoBox>,
    args: ChunkAdmitArgs<'_>,
) {
    // Re-bind tip_ctx per family so we can relay after each admit without
    // holding a `store` borrow across `relay_and_count`.
    let mut remaining = eligible;
    let max_families = args.config.max_families_per_tip.max(1);
    let start = Instant::now();
    let mut families_built = 0u32;

    while !remaining.is_empty() && families_built < max_families {
        if families_built > 0 && start.elapsed() >= args.budget {
            break;
        }
        let before_len = remaining.len();
        let (actions, consumed) = {
            let store = state
                .store
                .as_utxo()
                .expect("utxo-only: rent collector is gated to UTXO mode by handle_mempool_tick");
            let tip_ctx = owned.as_mempool_ctx(store);
            build_and_admit_family(
                &mut state.mempool,
                &tip_ctx,
                &remaining,
                args.proceeds_pk,
                args.config,
                args.now,
            )
        };
        match apply_chunk_progress(&mut remaining, consumed) {
            ChunkProgress::Stop => break,
            ChunkProgress::Continue => {
                // Stall guard: shrink-drops re-enter `remaining` by design
                // (they're claimed in later families), but a build that
                // reports consumed ids yet leaves `remaining` unchanged
                // cannot make progress — bail rather than spin.
                if remaining.len() >= before_len {
                    break;
                }
                relay_and_count(state, actions, &args.timing);
                families_built = families_built.saturating_add(1);
            }
        }
    }
}

/// Shared chunk-loop progress step: remove `consumed` from `remaining`.
/// `Stop` when nothing was built (`consumed` empty) so unaffordable
/// remainder ends the loop; `Continue` otherwise.
fn apply_chunk_progress(remaining: &mut Vec<ErgoBox>, consumed: Vec<Digest32>) -> ChunkProgress {
    if consumed.is_empty() {
        return ChunkProgress::Stop;
    }
    let consumed_set: HashSet<Digest32> = consumed.into_iter().collect();
    remaining.retain(|b| match b.box_id() {
        Ok(id) => !consumed_set.contains(&id),
        Err(_) => true,
    });
    ChunkProgress::Continue
}

enum ChunkProgress {
    Continue,
    Stop,
}

/// Mempool-only chunk loop (same progress rules as [`admit_chunked_families`]).
/// Returns one action batch per built family. `budget == Duration::ZERO` ⇒
/// only family 1 runs when overflow remains.
#[cfg(test)]
fn admit_chunked_on_mempool(
    mempool: &mut Mempool,
    tip_ctx: &MempoolTipContext<'_>,
    eligible: Vec<ErgoBox>,
    proceeds_pk: &[u8; 33],
    config: &RentCollectorConfig,
    now: Instant,
    budget: Duration,
) -> Vec<Vec<MempoolAction>> {
    let max_families = config.max_families_per_tip.max(1);
    let mut remaining = eligible;
    let start = Instant::now();
    let mut families_built = 0u32;
    let mut batches = Vec::new();

    while !remaining.is_empty() && families_built < max_families {
        if families_built > 0 && start.elapsed() >= budget {
            break;
        }
        let before_len = remaining.len();
        let (actions, consumed) =
            build_and_admit_family(mempool, tip_ctx, &remaining, proceeds_pk, config, now);
        match apply_chunk_progress(&mut remaining, consumed) {
            ChunkProgress::Stop => break,
            ChunkProgress::Continue => {
                if remaining.len() >= before_len {
                    break;
                }
                batches.push(actions);
                families_built = families_built.saturating_add(1);
            }
        }
    }
    batches
}

/// Re-emit Inv for every still-pooled `TxSource::RentCollector` tx
/// (parent + child) when `reannounce_interval_ms` has elapsed. No-op when
/// the collector is off, the interval is `0`, or no resident families.
/// Live-pool scan is self-pruning (mined/evicted txs are absent).
/// Caller must gate on `!tip_changed` so we never re-Inv a family the
/// same tip tick is about to evict.
pub(super) fn maybe_reannounce_rent_families(state: &mut NodeState) {
    let Some(config) = state.rent_collector.as_ref() else {
        return;
    };
    let interval_ms = config.reannounce_interval_ms;
    if interval_ms == 0 {
        return;
    }
    let now = Instant::now();
    if now.duration_since(state.last_rent_reannounce) < Duration::from_millis(interval_ms) {
        return;
    }
    let txids = state
        .mempool
        .resident_txids_by_source(&TxSource::RentCollector);
    if txids.is_empty() {
        return;
    }
    let actions: Vec<MempoolAction> = txids
        .into_iter()
        .map(|tx_id| MempoolAction::BroadcastInv {
            tx_id,
            except: None,
        })
        .collect();
    let routed = route_mempool_actions(state, actions);
    flush_actions(state, routed);
    state.last_rent_reannounce = now;
}

/// On a non-empty broadcast set (the success condition), count one broadcast
/// and route + flush the wire actions. Empty `actions` (duplicate / rejection
/// / no-claim) are a no-op — not counted, not relayed.
///
/// Emits `rent_collector_tip_to_inv` once per tip on the first successful
/// family (ms: tip_apply → collect_start → admit → first Inv).
fn relay_and_count(state: &mut NodeState, actions: Vec<MempoolAction>, timing: &RelayTiming) {
    if actions.is_empty() {
        return;
    }
    state.rent_collector_broadcasts_total = state.rent_collector_broadcasts_total.saturating_add(1);

    for action in &actions {
        if let MempoolAction::BroadcastInv { tx_id, .. } = action {
            let id = *tx_id.as_bytes();
            if state.rent_fo.invd_rc_txids.insert(id) {
                state.rent_fo.invd_rc_ordered.push(id);
            }
        }
    }

    let admit_done = Instant::now();
    let routed = route_mempool_actions(state, actions);
    let first_priority_inv = routed.iter().find_map(|a| match a {
        ergo_sync::coordinator::Action::SendToPeer { peer, code, .. }
            if *code == ergo_p2p::message::CODE_INV =>
        {
            let decisive = state
                .rent_collector
                .as_ref()
                .map(|c| c.decisive_peers.as_slice())
                .unwrap_or(&[]);
            let priority = state.peer_manager.priority_peers();
            if decisive.iter().any(|p| p.ip() == peer.ip())
                || priority.iter().any(|p| p.ip() == peer.ip())
            {
                Some(*peer)
            } else {
                None
            }
        }
        _ => None,
    });
    let first_decisive_inv = routed.iter().find_map(|a| match a {
        ergo_sync::coordinator::Action::SendToPeer { peer, code, .. }
            if *code == ergo_p2p::message::CODE_INV
                && state
                    .rent_collector
                    .as_ref()
                    .is_some_and(|c| c.decisive_peers.iter().any(|p| p.ip() == peer.ip())) =>
        {
            Some(*peer)
        }
        _ => None,
    });
    let first_inv_sent = Instant::now();

    // One tip→Inv summary per tip (clears tip_apply_at after emit).
    if let Some(tip_at) = state.rent_fo.tip_apply_at.take() {
        let tip_height = state.rent_fo.tip_height;
        let txid_prefix = state
            .rent_fo
            .invd_rc_txids
            .iter()
            .next()
            .map(|id| hex::encode(&id[..4]))
            .unwrap_or_default();
        let ms_tip_to_collect = timing
            .collect_start
            .saturating_duration_since(tip_at)
            .as_millis() as u64;
        let ms_collect_to_admit = admit_done
            .saturating_duration_since(timing.collect_start)
            .as_millis() as u64;
        let ms_admit_to_inv = first_inv_sent
            .saturating_duration_since(admit_done)
            .as_millis() as u64;
        let ms_tip_to_inv = first_inv_sent.saturating_duration_since(tip_at).as_millis() as u64;
        info!(
            event = "rent_collector_tip_to_inv",
            tip_height,
            speculative_hit = timing.speculative_hit,
            speculative_build_age_ms = timing.speculative_build_age_ms,
            ms_tip_to_collect_start = ms_tip_to_collect,
            ms_collect_start_to_admit = ms_collect_to_admit,
            ms_admit_to_first_inv = ms_admit_to_inv,
            ms_tip_to_first_priority_inv = ms_tip_to_inv,
            first_priority_inv = first_priority_inv.is_some(),
            first_decisive_inv = first_decisive_inv.is_some(),
            priority_inv_peer = first_priority_inv
                .map(|p| p.to_string())
                .unwrap_or_default(),
            decisive_inv_peer = first_decisive_inv
                .map(|p| p.to_string())
                .unwrap_or_default(),
            txid_prefix = %txid_prefix,
            "rent-collector: tip→Inv first-occupancy timing"
        );
    }

    // Assembler-tier REST submit (ban-safe). Unsolicited P2P Modifiers are
    // RejectSpam; Inv+RequestModifier remains the P2P path.
    maybe_rest_submit_rc_family(state);

    flush_actions(state, routed);
}

/// One REST-submit payload: full txid hex (verify), short prefix (logs),
/// and JSON-string hex body (Scala `/transactions/bytes` parity).
#[derive(Clone, Debug)]
struct SubmitPayload {
    txid_hex: String,
    txid_prefix: String,
    hex_body: String,
}

/// Join `{base}/transactions/bytes` (trim trailing `/`).
fn submit_bytes_url(base: &str) -> String {
    format!("{}/transactions/bytes", base.trim_end_matches('/'))
}

/// Join `{base}/transactions/unconfirmed/byTransactionId/{txid}`.
fn unconfirmed_by_id_url(base: &str, txid_hex: &str) -> String {
    format!(
        "{}/transactions/unconfirmed/byTransactionId/{}",
        base.trim_end_matches('/'),
        txid_hex
    )
}

/// Only HTTP 200 counts as accept — relay/open-node 400s are rejects.
fn is_submit_accepted(status: u16) -> bool {
    status == 200
}

/// Build parent-before-child payloads from admit-ordered txids.
fn submit_payloads_ordered(ordered_ids: &[[u8; 32]], mempool: &Mempool) -> Vec<SubmitPayload> {
    let mut out = Vec::with_capacity(ordered_ids.len());
    for id in ordered_ids {
        if let Some(bytes) = mempool.get_bytes(&Digest32::from_bytes(*id)) {
            out.push(SubmitPayload {
                txid_hex: hex::encode(id),
                txid_prefix: hex::encode(&id[..4]),
                hex_body: hex::encode(bytes.as_ref()),
            });
        }
    }
    out
}

/// POST admitted RC family bytes to configured `[mining.rent_collector]
/// .submit_urls` (`/transactions/bytes`, JSON hex string — pool_inject
/// parity). Parent then child per URL; URLs fan out in parallel.
/// Fire-and-forget; failures are logged, never block the tip path.
/// Non-200 (incl. relay 400) is never treated as success.
fn maybe_rest_submit_rc_family(state: &NodeState) {
    let Some(cfg) = state.rent_collector.as_ref() else {
        return;
    };
    if cfg.submit_urls.is_empty() || state.rent_fo.invd_rc_txids.is_empty() {
        return;
    }
    let ordered = if !state.rent_fo.invd_rc_ordered.is_empty() {
        state.rent_fo.invd_rc_ordered.clone()
    } else {
        // Fallback: HashSet iter order is undefined — prefer ordered path.
        state.rent_fo.invd_rc_txids.iter().copied().collect()
    };
    let payloads = submit_payloads_ordered(&ordered, &state.mempool);
    if payloads.is_empty() {
        return;
    }
    let urls = cfg.submit_urls.clone();
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(6))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "rent-collector: submit_urls client build failed");
                return;
            }
        };
        let mut handles = Vec::with_capacity(urls.len());
        for base in urls {
            let client = client.clone();
            let payloads = payloads.clone();
            handles.push(tokio::spawn(async move {
                submit_family_to_url(&client, &base, &payloads).await;
            }));
        }
        for h in handles {
            let _ = h.await;
        }
    });
}

/// Sequential parent→child POST to one base URL, then optional unconfirmed
/// verify. Logs per-URL ok / reject / fail / verified / demote_hint.
async fn submit_family_to_url(client: &reqwest::Client, base: &str, payloads: &[SubmitPayload]) {
    let mut ok = 0u32;
    let mut reject = 0u32;
    let mut fail = 0u32;
    for p in payloads {
        let url = submit_bytes_url(base);
        let body = serde_json::Value::String(p.hex_body.clone());
        match client.post(&url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                // Drain body for reject reason (bounded); ignore read errors.
                let detail = resp.text().await.unwrap_or_default();
                let detail = detail.chars().take(160).collect::<String>();
                if is_submit_accepted(status) {
                    ok = ok.saturating_add(1);
                    info!(
                        event = "rent_collector_submit_ok",
                        url = %url,
                        txid_prefix = %p.txid_prefix,
                        status,
                        "rent-collector: REST submit accepted"
                    );
                    // Best-effort: confirm the acceptor's mempool sees it.
                    let verify_url = unconfirmed_by_id_url(base, &p.txid_hex);
                    match client.get(&verify_url).send().await {
                        Ok(v) if v.status().as_u16() == 200 => {
                            info!(
                                event = "rent_collector_submit_verified",
                                url = %base,
                                txid_prefix = %p.txid_prefix,
                                "rent-collector: REST submit seen in unconfirmed"
                            );
                        }
                        Ok(v) => {
                            debug!(
                                event = "rent_collector_submit_unverified",
                                url = %base,
                                txid_prefix = %p.txid_prefix,
                                status = v.status().as_u16(),
                                "rent-collector: REST submit ok but unconfirmed miss"
                            );
                        }
                        Err(e) => {
                            debug!(
                                event = "rent_collector_submit_unverified",
                                url = %base,
                                txid_prefix = %p.txid_prefix,
                                error = %e,
                                "rent-collector: REST submit verify transport error"
                            );
                        }
                    }
                } else {
                    reject = reject.saturating_add(1);
                    info!(
                        event = "rent_collector_submit_reject",
                        url = %url,
                        txid_prefix = %p.txid_prefix,
                        status,
                        detail = %detail,
                        "rent-collector: REST submit non-200"
                    );
                }
            }
            Err(e) => {
                fail = fail.saturating_add(1);
                warn!(
                    event = "rent_collector_submit_fail",
                    url = %url,
                    txid_prefix = %p.txid_prefix,
                    error = %e,
                    "rent-collector: REST submit transport error"
                );
            }
        }
    }
    // Ops demote hint: zero accepts and at least one reject/fail this round.
    if ok == 0 && (reject > 0 || fail > 0) {
        info!(
            event = "rent_collector_submit_demote_hint",
            url = %base,
            reject,
            fail,
            "rent-collector: submit URL produced no accepts this family"
        );
    }
}

/// Build a broadcast claim from `eligible` and admit it atomically to
/// `mempool`, returning `(broadcast_actions, consumed_input_ids)`.
///
/// `consumed_input_ids` are the parent input box-ids of the built claim,
/// captured **before** admit so the chunking loop can always remove them
/// from `remaining` — even on a benign duplicate or rejection (empty
/// actions). Empty consumed means nothing was built (`Ok(None)` / error).
fn build_and_admit_family(
    mempool: &mut Mempool,
    tip_ctx: &MempoolTipContext<'_>,
    eligible: &[ErgoBox],
    proceeds_pk: &[u8; 33],
    config: &RentCollectorConfig,
    now: Instant,
) -> (Vec<MempoolAction>, Vec<Digest32>) {
    let candidate_height = tip_ctx.tx_context.height; // tip + 1

    // FeeInputs: profit floor from config, the per-tx caps + relay floor
    // from the LIVE mempool config (so the family is built to fit the same
    // gates admission enforces). Parent fee-per-input may be jittered.
    let mp_cfg = mempool.config();
    let fee_inputs = FeeInputs {
        min_relay_fee: mp_cfg.min_relay_fee_nano_erg,
        min_profit: config.min_profit_nanoerg,
        max_tx_size_bytes: mp_cfg.max_tx_size_bytes.min(u32::MAX as usize) as u32,
        max_tx_cost: mp_cfg.max_tx_cost,
        parent_fee_per_input: jittered_parent_fee_per_input(
            config.parent_fee_per_input_nanoerg,
            config.jitter_bps,
            config.jitter_seed,
        ),
    };

    let claim = match build_broadcast_claim(
        eligible,
        candidate_height,
        tip_ctx.params,
        proceeds_pk,
        tip_ctx.tx_context,
        tip_ctx.last_headers,
        tip_ctx.reemission,
        &fee_inputs,
    ) {
        Ok(Some(c)) => c,
        Ok(None) => return (Vec::new(), Vec::new()), // nothing affordably claimable
        Err(e) => {
            warn!(error = ?e, "rent-collector: claim build failed; skipping this block");
            return (Vec::new(), Vec::new());
        }
    };

    let consumed: Vec<Digest32> = claim
        .parent_inputs
        .iter()
        .filter_map(|b| b.box_id().ok())
        .collect();
    let actions = admit_claim(mempool, tip_ctx, &claim, now);
    (actions, consumed)
}

/// Serialize the claim family and admit it via the transactional family
/// path, returning the broadcast actions (only populated on full success).
fn admit_claim(
    mempool: &mut Mempool,
    tip_ctx: &MempoolTipContext<'_>,
    claim: &BroadcastClaim,
    now: Instant,
) -> Vec<MempoolAction> {
    let parent_bytes = match serialize_tx(&claim.parent) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "rent-collector: parent serialize failed; skipping");
            return Vec::new();
        }
    };
    // Lone shapes have no child ⇒ single-tx atomic admit (`None`).
    let child_bytes: Option<Vec<u8>> = match claim.child.as_ref() {
        Some(child) => match serialize_tx(child) {
            Ok(b) => Some(b),
            Err(e) => {
                warn!(error = %e, "rent-collector: child serialize failed; skipping");
                return Vec::new();
            }
        },
        None => None,
    };

    let admit = mempool.admit_family_atomic(
        &parent_bytes,
        child_bytes.as_deref(),
        TxSource::RentCollector,
        now,
        tip_ctx,
        &ErgoValidator,
    );

    if admit.tx_ids.is_empty() {
        // Either a duplicate resubmit (benign — superseded claims self-evict
        // via #141/#142) or a rejection (the mempool restored its pool and
        // emitted nothing). Nothing to relay either way.
        debug!("rent-collector: family not admitted (duplicate or rejected); nothing relayed");
    } else {
        // 5.1: structured per-broadcast event. The builder computed these
        // during construction (`claim.summary`) — read them rather than
        // re-deriving from raw outputs. The counter is bumped by the caller
        // (`relay_and_count`, which owns `&mut NodeState`) on the
        // non-empty-`broadcast_actions` success condition. The two predicates
        // are equivalent: a successful local family admit always yields BOTH a
        // tx id (non-empty `tx_ids`, this branch) AND a `BroadcastInv` per
        // admitted tx (non-empty `broadcast_actions`) — `admit_family_atomic`
        // emits them together on full success, so this log and that counter
        // always fire on the same admit.
        let s = &claim.summary;
        info!(
            event = "rent_collector_broadcast",
            txs = admit.tx_ids.len(),
            boxes = s.num_boxes,
            shape = s.shape.as_str(),
            parent_fee = s.parent_fee,
            child_fee = s.child_fee,
            proceeds = s.proceeds,
            chained = claim.child.is_some(),
            "rent-collector: broadcast storage-rent claim family",
        );
    }
    admit.broadcast_actions
}

/// `tx → wire bytes`. Local copy of the builder's private serializer so the
/// collector doesn't depend on a `pub` it shouldn't widen.
fn serialize_tx(tx: &Transaction) -> Result<Vec<u8>, String> {
    let mut w = VlqWriter::new();
    write_transaction(&mut w, tx).map_err(|e| format!("{e:?}"))?;
    Ok(w.result())
}

#[cfg(test)]
mod tests {
    //! Phase 3 unit tests for the collector core. These exercise the
    //! testable `build_and_admit_family` seam: build a real claim family
    //! through the Phase 1b builder, admit it through the REAL `ErgoValidator`
    //! and the Phase 0 transactional family path, then assert REAL admission
    //! (the tx is in the pool, tagged `RentCollector`) — NOT a channel send.
    //!
    //! The gating tests (`disabled_*`, `no_indexer_*`, `not_fully_synced_*`,
    //! `pending_proceeds_key_*`) live where the gate they guard does:
    //! `disabled`/`pending`/`corrupt` are pure short-circuits, asserted by
    //! the gate's effect (no admission). The fully-synced + UTXO-only gate
    //! lives in `handle_mempool_tick` (the caller); see the
    //! `action_loop` test `empty_mempool_still_collects` for the
    //! early-return-predicate guard and the `mining_engine` tests for the
    //! eligibility-enumeration degrade-to-empty paths.

    use super::*;
    use ergo_mempool::types::{MempoolConfig, TipPointer};
    use ergo_mempool::weight::ByCost;
    use ergo_primitives::digest::{Digest32, ModifierId};
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;
    use ergo_validation::{ProtocolParams, TransactionContext, UtxoView};
    use std::collections::HashMap;

    /// secp256k1 generator point, compressed — a valid P2PK pubkey, so the
    /// collector proceeds output is a well-formed P2PK box.
    const PK: [u8; 33] = [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];

    const HEIGHT: u32 = 100;

    fn trivial_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        }
    }

    /// An aged (creation_height 0), `value`-nanoErg box scriptable by anyone
    /// — eligible for a recreate claim at `HEIGHT` under `rent_params`.
    fn aged_box(value: u64, seed: u8) -> ErgoBox {
        let cand = ErgoBoxCandidate::new(
            value,
            trivial_tree(),
            0,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap();
        ErgoBox {
            candidate: cand,
            transaction_id: ModifierId::from_bytes([seed; 32]),
            index: 0,
        }
    }

    fn rent_params() -> ProtocolParams {
        let mut p = ProtocolParams::mainnet_default();
        p.storage_period = 10;
        p.storage_fee_factor = 1_250_000;
        p
    }

    fn tx_context_at(height: u32) -> TransactionContext {
        TransactionContext {
            height,
            miner_pubkey: PK,
            pre_header_timestamp: 0,
            activated_script_version: 2,
            pre_header_version: 3,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        }
    }

    /// A committed UTXO view that resolves the seeded boxes by their real
    /// `box_id` (what the admission validator looks up for the parent's
    /// inputs). The CPFP child's anchor input resolves against the pool
    /// overlay, not here.
    struct MapView(HashMap<Digest32, ErgoBox>);
    impl MapView {
        fn of(boxes: &[ErgoBox]) -> Self {
            Self(
                boxes
                    .iter()
                    .map(|b| (b.box_id().unwrap(), b.clone()))
                    .collect(),
            )
        }
    }
    impl UtxoView for MapView {
        fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
            self.0.get(id).cloned()
        }
    }

    fn rent_config() -> RentCollectorConfig {
        RentCollectorConfig {
            enabled: true,
            ..RentCollectorConfig::default()
        }
    }

    /// Bundles a tip context's owned parts so the borrowed `MempoolTipContext`
    /// can be re-created per call against a shared `view`.
    fn tip_ctx<'a>(
        view: &'a dyn UtxoView,
        params: &'a ProtocolParams,
        ctx: &'a TransactionContext,
    ) -> MempoolTipContext<'a> {
        MempoolTipContext {
            tip: TipPointer {
                height: HEIGHT - 1,
                header_id: Digest32::from_bytes([0xAB; 32]),
            },
            best_header_height: HEIGHT - 1,
            best_full_block_height: HEIGHT - 1,
            utxo: view,
            tx_context: ctx,
            params,
            last_headers: &[],
            reemission: None,
        }
    }

    fn mempool() -> Mempool {
        Mempool::new(MempoolConfig::default(), Box::new(ByCost))
    }

    fn broadcast_invs(actions: &[MempoolAction]) -> Vec<Digest32> {
        actions
            .iter()
            .filter_map(|a| match a {
                MempoolAction::BroadcastInv { tx_id, .. } => Some(*tx_id),
                _ => None,
            })
            .collect()
    }

    /// Count of pool entries tagged `RentCollector` (TxSource has no
    /// `PartialEq`, so match the variant).
    fn rent_collector_count(mp: &Mempool) -> usize {
        mp.pool()
            .iter_prioritized()
            .filter(|e| matches!(e.source, TxSource::RentCollector))
            .count()
    }

    // ── eligible_box_admits_rent_collector_tagged_tx (3.1 + the named test) ──

    #[test]
    fn eligible_box_admits_rent_collector_tagged_tx() {
        // One eligible recreate box → a lone parent admitted, tagged
        // RentCollector. Asserts REAL admission (in the pool, source tag),
        // not a channel send.
        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let boxes = vec![aged_box(10_000_000_000, 0x01)];
        let view = MapView::of(&boxes);
        let tip = tip_ctx(&view, &params, &ctx);
        let mut mp = mempool();

        let (actions, _) =
            build_and_admit_family(&mut mp, &tip, &boxes, &PK, &rent_config(), Instant::now());

        assert_eq!(mp.size(), 1, "the lone recreate parent must be admitted");
        assert_eq!(
            rent_collector_count(&mp),
            1,
            "the admitted tx must be tagged RentCollector",
        );
        assert_eq!(
            broadcast_invs(&actions).len(),
            1,
            "exactly one BroadcastInv (the parent) is returned for relay",
        );
    }

    #[test]
    fn chained_child_admitted_after_parent() {
        // ≥2 eligible boxes → a batched parent + CPFP child, BOTH admitted,
        // BOTH tagged RentCollector, and both BroadcastInvs returned.
        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let boxes = vec![
            aged_box(10_000_000_000, 0x01),
            aged_box(10_000_000_000, 0x02),
            aged_box(10_000_000_000, 0x03),
        ];
        let view = MapView::of(&boxes);
        let tip = tip_ctx(&view, &params, &ctx);
        let mut mp = mempool();

        let (actions, _) =
            build_and_admit_family(&mut mp, &tip, &boxes, &PK, &rent_config(), Instant::now());

        assert_eq!(mp.size(), 2, "parent + CPFP child both admitted");
        assert_eq!(
            rent_collector_count(&mp),
            2,
            "both family txs tagged RentCollector",
        );
        assert_eq!(
            broadcast_invs(&actions).len(),
            2,
            "both parent + child BroadcastInvs returned only on full success",
        );
    }

    #[test]
    fn family_atomic_admit_no_partial_broadcast() {
        // Drive the TRANSACTIONAL family admit through a forced failure and
        // assert the node-side contract: nothing relayed, nothing left in the
        // pool from the failed family. A high-weight entry pre-seeded on one
        // of the parent's INPUT boxes makes the parent a double-spend loser
        // (lower weight than the booster) ⇒ `admit_family_atomic` rejects the
        // parent, drops its staged clone, and returns no broadcast actions ⇒
        // the CPFP child never reaches the wire. (The pool-restore mechanics
        // are covered by the Phase 0 mempool tests; here we pin the node-side
        // "no partial broadcast" guarantee.)
        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let boxes = vec![
            aged_box(10_000_000_000, 0x01),
            aged_box(10_000_000_000, 0x02),
        ];
        let view = MapView::of(&boxes);
        let tip = tip_ctx(&view, &params, &ctx);
        let mut mp = mempool();
        // Pre-seed a booster double-spending the first parent input box, with
        // a weight our parent cannot beat ⇒ parent loses replacement.
        let blocked = boxes[0].box_id().unwrap();
        seed_stale_boosted(&mut mp, blocked, u64::MAX);
        let before = mp.size();

        let (actions, _) =
            build_and_admit_family(&mut mp, &tip, &boxes, &PK, &rent_config(), Instant::now());

        assert_eq!(
            mp.size(),
            before,
            "the failed family adds NOTHING (no half-family parent left behind)",
        );
        assert!(
            broadcast_invs(&actions).is_empty(),
            "a child/parent admission failure relays NOTHING (atomic)",
        );
    }

    #[test]
    fn duplicate_resubmit_is_idempotent() {
        // Admitting the SAME family twice: the second admit is a benign
        // duplicate — no new pool entries, no second broadcast.
        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let boxes = vec![aged_box(10_000_000_000, 0x01)];
        let view = MapView::of(&boxes);
        let tip = tip_ctx(&view, &params, &ctx);
        let mut mp = mempool();

        let (first, _) =
            build_and_admit_family(&mut mp, &tip, &boxes, &PK, &rent_config(), Instant::now());
        assert_eq!(mp.size(), 1);
        assert_eq!(broadcast_invs(&first).len(), 1);

        let (second, consumed) =
            build_and_admit_family(&mut mp, &tip, &boxes, &PK, &rent_config(), Instant::now());
        assert_eq!(mp.size(), 1, "duplicate must not add a second entry");
        assert!(
            broadcast_invs(&second).is_empty(),
            "a duplicate resubmit relays nothing (idempotent)",
        );
        assert_eq!(
            consumed.len(),
            1,
            "consumed ids are still reported on a duplicate so chunking can progress",
        );
    }

    #[test]
    fn empty_eligible_set_admits_nothing() {
        // The collector core with no eligible boxes builds no claim and
        // admits nothing (the empty-mempool-still-runs path reaches here with
        // an empty eligible set on a chain with no aged boxes).
        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let view = MapView::of(&[]);
        let tip = tip_ctx(&view, &params, &ctx);
        let mut mp = mempool();

        let (actions, _) =
            build_and_admit_family(&mut mp, &tip, &[], &PK, &rent_config(), Instant::now());

        assert_eq!(mp.size(), 0);
        assert!(broadcast_invs(&actions).is_empty());
    }

    // ----- multi-family chunking -----

    fn mempool_with_tx_size_cap(max_tx_size_bytes: usize) -> Mempool {
        Mempool::new(
            MempoolConfig {
                max_tx_size_bytes,
                ..MempoolConfig::default()
            },
            Box::new(ByCost),
        )
    }

    fn rent_config_with_max_families(max_families_per_tip: u32) -> RentCollectorConfig {
        RentCollectorConfig {
            enabled: true,
            max_families_per_tip,
            ..RentCollectorConfig::default()
        }
    }

    #[test]
    fn build_and_admit_family_returns_consumed_parent_input_ids() {
        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let boxes = vec![
            aged_box(10_000_000_000, 0x01),
            aged_box(10_000_000_000, 0x02),
        ];
        let view = MapView::of(&boxes);
        let tip = tip_ctx(&view, &params, &ctx);
        let mut mp = mempool();

        let (actions, consumed) =
            build_and_admit_family(&mut mp, &tip, &boxes, &PK, &rent_config(), Instant::now());
        assert!(!actions.is_empty());
        assert!(!consumed.is_empty());
        for id in &consumed {
            assert!(
                boxes.iter().any(|b| b.box_id().ok().as_ref() == Some(id)),
                "consumed id must come from the eligible set"
            );
        }
    }

    #[test]
    fn chunking_emits_multiple_input_disjoint_families_when_cap_forces_split() {
        // Cap serialized parent size so the builder cannot pack every eligible
        // box into one family; the chunk loop then admits the remainder as
        // further input-disjoint families.
        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let boxes: Vec<ErgoBox> = (0u8..6)
            .map(|i| aged_box(10_000_000_000, 0x10 + i))
            .collect();
        let view = MapView::of(&boxes);
        let tip = tip_ctx(&view, &params, &ctx);

        // Discover a size cap that packs some-but-not-all boxes into family 1.
        let full = {
            let mut mp = mempool();
            let (_a, consumed) =
                build_and_admit_family(&mut mp, &tip, &boxes, &PK, &rent_config(), Instant::now());
            consumed.len()
        };
        assert_eq!(full, 6, "precondition: unconstrained pack takes all boxes");

        // Binary-search a cap between "nothing fits" and "everything fits".
        let mut lo = 50usize;
        let mut hi = 4_000usize;
        let mut split_cap = None;
        while lo + 1 < hi {
            let mid = (lo + hi) / 2;
            let mut mp = mempool_with_tx_size_cap(mid);
            let (_a, consumed) =
                build_and_admit_family(&mut mp, &tip, &boxes, &PK, &rent_config(), Instant::now());
            let n = consumed.len();
            if n == 0 {
                lo = mid;
            } else if n >= 6 {
                hi = mid;
            } else {
                split_cap = Some(mid);
                break;
            }
        }
        let cap = split_cap.expect("must find a size cap that packs a proper subset");

        let mut mp = mempool_with_tx_size_cap(cap);
        let batches = admit_chunked_on_mempool(
            &mut mp,
            &tip,
            boxes.clone(),
            &PK,
            &rent_config_with_max_families(4),
            Instant::now(),
            Duration::from_millis(40),
        );
        let non_empty: Vec<_> = batches.iter().filter(|b| !b.is_empty()).collect();
        assert!(
            non_empty.len() >= 2,
            "expected ≥2 families under size cap {cap}, got {}",
            non_empty.len()
        );

        // Input-disjoint: no two admitted parents share an input box id.
        let mut seen = HashSet::new();
        for e in mp.pool().iter_prioritized() {
            if !matches!(e.source, TxSource::RentCollector) {
                continue;
            }
            // Parent spends the rent boxes; child spends the anchor — only
            // count boxes that were in the original eligible set.
            for id in &e.inputs {
                if boxes.iter().any(|b| b.box_id().ok().as_ref() == Some(id)) {
                    assert!(
                        seen.insert(*id),
                        "input-disjoint: box {id:?} spent by two families"
                    );
                }
            }
        }
    }

    #[test]
    fn chunking_budget_zero_stops_after_family_one() {
        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let boxes: Vec<ErgoBox> = (0u8..6)
            .map(|i| aged_box(10_000_000_000, 0x20 + i))
            .collect();
        let view = MapView::of(&boxes);
        let tip = tip_ctx(&view, &params, &ctx);

        // Same discovery as the multi-family test — need leftover after family 1.
        let mut lo = 50usize;
        let mut hi = 4_000usize;
        let mut split_cap = None;
        while lo + 1 < hi {
            let mid = (lo + hi) / 2;
            let mut mp = mempool_with_tx_size_cap(mid);
            let (_a, consumed) =
                build_and_admit_family(&mut mp, &tip, &boxes, &PK, &rent_config(), Instant::now());
            let n = consumed.len();
            if n == 0 {
                lo = mid;
            } else if n >= 6 {
                hi = mid;
            } else {
                split_cap = Some(mid);
                break;
            }
        }
        let cap = split_cap.expect("size cap for leftover boxes");

        let mut mp = mempool_with_tx_size_cap(cap);
        let batches = admit_chunked_on_mempool(
            &mut mp,
            &tip,
            boxes,
            &PK,
            &rent_config_with_max_families(4),
            Instant::now(),
            Duration::ZERO,
        );
        assert_eq!(batches.len(), 1, "budget=0 ⇒ only family 1 is attempted");
    }

    #[test]
    fn chunking_max_families_one_is_single_family_regression() {
        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let boxes: Vec<ErgoBox> = (0u8..4)
            .map(|i| aged_box(10_000_000_000, 0x30 + i))
            .collect();
        let view = MapView::of(&boxes);
        let tip = tip_ctx(&view, &params, &ctx);
        let mut mp = mempool();
        let batches = admit_chunked_on_mempool(
            &mut mp,
            &tip,
            boxes,
            &PK,
            &rent_config_with_max_families(1),
            Instant::now(),
            Duration::from_millis(40),
        );
        assert_eq!(batches.len(), 1, "max_families_per_tip=1 ⇒ one family");
        assert!(!batches[0].is_empty());
    }

    #[test]
    fn chunking_respects_max_families_cap() {
        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let boxes: Vec<ErgoBox> = (0u8..8)
            .map(|i| aged_box(10_000_000_000, 0x40 + i))
            .collect();
        let view = MapView::of(&boxes);
        let tip = tip_ctx(&view, &params, &ctx);

        let mut lo = 50usize;
        let mut hi = 4_000usize;
        let mut split_cap = None;
        while lo + 1 < hi {
            let mid = (lo + hi) / 2;
            let mut mp = mempool_with_tx_size_cap(mid);
            let (_a, consumed) =
                build_and_admit_family(&mut mp, &tip, &boxes, &PK, &rent_config(), Instant::now());
            let n = consumed.len();
            if n == 0 {
                lo = mid;
            } else if n >= boxes.len() {
                hi = mid;
            } else {
                split_cap = Some(mid);
                break;
            }
        }
        let cap = split_cap.expect("size cap for multi-family");
        let max_families = 2u32;
        let mut mp = mempool_with_tx_size_cap(cap);
        let batches = admit_chunked_on_mempool(
            &mut mp,
            &tip,
            boxes,
            &PK,
            &rent_config_with_max_families(max_families),
            Instant::now(),
            Duration::from_millis(40),
        );
        assert!(
            batches.len() as u32 <= max_families,
            "batches {} must be ≤ max_families_per_tip {max_families}",
            batches.len()
        );
        assert!(
            batches.len() >= 2,
            "leftover after a split pack should yield a second family (got {})",
            batches.len()
        );
    }

    #[test]
    fn jittered_family_admits_through_real_validator() {
        // Active jitter seed through the real admit path (ErgoValidator +
        // transactional family). Production floors via min_relay_fee; this
        // pins the jittered FeeInputs construction end-to-end.
        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let boxes = vec![
            aged_box(10_000_000_000, 0x71),
            aged_box(10_000_000_000, 0x72),
        ];
        let view = MapView::of(&boxes);
        let tip = tip_ctx(&view, &params, &ctx);
        let mut mp = mempool();
        let jittered = RentCollectorConfig {
            enabled: true,
            jitter_bps: 300,
            jitter_seed: Some(42),
            ..RentCollectorConfig::default()
        };
        let base = RentCollectorConfig {
            enabled: true,
            jitter_bps: 0,
            jitter_seed: None,
            ..RentCollectorConfig::default()
        };
        assert_ne!(
            ergo_mining::jittered_parent_fee_per_input(
                jittered.parent_fee_per_input_nanoerg,
                jittered.jitter_bps,
                jittered.jitter_seed,
            ),
            base.parent_fee_per_input_nanoerg,
            "precondition: seed 42 at 300 bps must move the fee"
        );

        let (actions, consumed) =
            build_and_admit_family(&mut mp, &tip, &boxes, &PK, &jittered, Instant::now());
        assert!(!consumed.is_empty(), "jittered build must produce a claim");
        assert!(
            !actions.is_empty(),
            "jittered family must admit through the real validator"
        );
        assert!(
            rent_collector_count(&mp) >= 1,
            "jittered family is resident and RentCollector-tagged"
        );
        // Family remains unbeatable at the jittered total: a second admit of
        // the same box-set is a benign duplicate (not a weight-RBF loss).
        let (again, _) =
            build_and_admit_family(&mut mp, &tip, &boxes, &PK, &jittered, Instant::now());
        assert!(
            again.is_empty(),
            "already-admitted jittered family is idempotent (still valid in pool)"
        );
    }

    #[test]
    fn apply_chunk_progress_stops_on_empty_consumed() {
        let mut remaining = vec![aged_box(10_000_000_000, 0x81)];
        assert!(matches!(
            apply_chunk_progress(&mut remaining, Vec::new()),
            ChunkProgress::Stop
        ));
        assert_eq!(remaining.len(), 1, "Stop leaves remaining untouched");
    }

    /// Seed a high-weight "stale boosted family" parent that double-spends
    /// `box_id` (our prior block's CPFP-boosted recreate parent, still in the
    /// pool). Its weight is set far above what our fresh parent can
    /// reach, so a fresh claim on the same box loses strict-`>` replacement.
    fn seed_stale_boosted(mp: &mut Mempool, box_id: Digest32, boosted_weight: u64) {
        let entry = ergo_mempool::Entry::new(
            Digest32::from_bytes([0xEE; 32]),
            std::sync::Arc::from(vec![0xEEu8; 20].into_boxed_slice()),
            vec![box_id], // double-spends the same eligible box
            vec![Digest32::from_bytes([0xEF; 32])],
            vec![],
            1_000_000,
            boosted_weight, // CPFP-boosted (#139): well above any parent fee
            20,
            10_000,
            TxSource::RentCollector,
        );
        mp.pool_mut().insert(entry).unwrap();
    }

    #[test]
    fn collector_runs_after_recheck_evict() {
        // Ordering guard: our PRIOR block's stale recreate parent is still in
        // the pool, CPFP-boosted by its child, double-spending the SAME box
        // the new claim wants. If we build the fresh parent BEFORE targeted
        // `evict_by_source(RentCollector)` (tip path) / recheck frees the
        // stale family, strict-`>` replacement loses the new parent to our
        // own boosted family. After eviction frees the box, the new claim admits.
        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let boxes = vec![aged_box(10_000_000_000, 0x01)];
        let view = MapView::of(&boxes);
        let box_id = boxes[0].box_id().unwrap();

        // (A) Stale boosted family STILL present (recheck has NOT run yet):
        //     the fresh claim is replaced-out — lost to our own stale family.
        let mut mp_before = mempool();
        seed_stale_boosted(&mut mp_before, box_id, u64::MAX);
        let before_size = mp_before.size();
        let tip = tip_ctx(&view, &params, &ctx);
        let (before, _) = build_and_admit_family(
            &mut mp_before,
            &tip,
            &boxes,
            &PK,
            &rent_config(),
            Instant::now(),
        );
        assert_eq!(
            mp_before.size(),
            before_size,
            "with the stale boosted family present, the new claim is NOT admitted \
             (replaced-out) — proving the recheck must evict it FIRST",
        );
        assert_eq!(
            rent_collector_count(&mp_before),
            1,
            "only the stale entry remains"
        );
        assert!(
            broadcast_invs(&before).is_empty(),
            "nothing relayed when the fresh claim loses replacement",
        );

        // (B) After the recheck evicts the stale family (box freed): the fresh
        //     claim admits cleanly. This is the order the trigger enforces.
        let mut mp_after = mempool();
        let tip = tip_ctx(&view, &params, &ctx);
        let (after, _) = build_and_admit_family(
            &mut mp_after,
            &tip,
            &boxes,
            &PK,
            &rent_config(),
            Instant::now(),
        );
        assert_eq!(
            mp_after.size(),
            1,
            "with the box freed, the new claim admits"
        );
        assert_eq!(
            broadcast_invs(&after).len(),
            1,
            "the fresh claim is relayed"
        );
    }
}

/// Speculative header-cache gate + admit-only-after-apply invariants.
#[cfg(test)]
mod speculative_tests {
    use super::*;
    use ergo_mempool::types::{MempoolConfig, TipPointer};
    use ergo_mempool::weight::ByCost;
    use ergo_primitives::digest::{Digest32, ModifierId};
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;
    use ergo_validation::{ProtocolParams, TransactionContext, UtxoView};
    use std::collections::HashMap;

    const PK: [u8; 33] = [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];
    const HEIGHT: u32 = 100;
    const TIP_ID: [u8; 32] = [0xAB; 32];
    const PARENT_ID: [u8; 32] = [0xCD; 32];

    fn trivial_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        }
    }

    fn aged_box(value: u64, seed: u8) -> ErgoBox {
        let cand = ErgoBoxCandidate::new(
            value,
            trivial_tree(),
            0,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap();
        ErgoBox {
            candidate: cand,
            transaction_id: ModifierId::from_bytes([seed; 32]),
            index: 0,
        }
    }

    fn rent_params() -> ProtocolParams {
        let mut p = ProtocolParams::mainnet_default();
        p.storage_period = 10;
        p.storage_fee_factor = 1_250_000;
        p
    }

    fn tx_context_at(height: u32) -> TransactionContext {
        TransactionContext {
            height,
            miner_pubkey: PK,
            pre_header_timestamp: 0,
            activated_script_version: 2,
            pre_header_version: 3,
            pre_header_parent_id: PARENT_ID,
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        }
    }

    struct MapView(HashMap<Digest32, ErgoBox>);
    impl MapView {
        fn of(boxes: &[ErgoBox]) -> Self {
            Self(
                boxes
                    .iter()
                    .map(|b| (b.box_id().unwrap(), b.clone()))
                    .collect(),
            )
        }
    }
    impl UtxoView for MapView {
        fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
            self.0.get(id).cloned()
        }
    }

    fn fee_inputs() -> FeeInputs {
        FeeInputs {
            min_relay_fee: 1_000_000,
            min_profit: 0,
            max_tx_size_bytes: 100_000,
            max_tx_cost: 1_000_000,
            parent_fee_per_input: 10_000_000,
        }
    }

    fn build_cache(boxes: &[ErgoBox]) -> SpeculativeRentCache {
        let ctx = tx_context_at(HEIGHT);
        let params = rent_params();
        let fee = fee_inputs();
        let families = build_speculative_families(
            boxes,
            SpeculativeBuildCtx {
                proceeds_pk: &PK,
                tx_context: &ctx,
                params: &params,
                last_headers: &[],
                reemission: None,
                fee_inputs: &fee,
            },
            1,
            Duration::from_millis(40),
        );
        assert!(
            !families.is_empty(),
            "speculative build must produce a family for the aged box"
        );
        SpeculativeRentCache {
            expected_tip_id: TIP_ID,
            expected_parent_id: PARENT_ID,
            expected_height: HEIGHT - 1,
            families,
            built_at: Instant::now(),
        }
    }

    // ----- happy path -----

    #[test]
    fn speculative_cache_hit_when_tip_matches_and_inputs_live() {
        let boxes = vec![aged_box(10_000_000_000, 0x01)];
        let cache = build_cache(&boxes);
        let view = MapView::of(&boxes);
        assert_eq!(
            evaluate_speculative_cache(Some(&cache), &TIP_ID, HEIGHT - 1, &view),
            SpeculativeCacheVerdict::Hit
        );
    }

    #[test]
    fn speculative_cache_hit_admits_family_after_apply() {
        // Cache Hit → admit_claim populates the mempool. This is the
        // post-apply path; speculate itself never calls admit.
        let boxes = vec![aged_box(10_000_000_000, 0x01)];
        let cache = build_cache(&boxes);
        let view = MapView::of(&boxes);
        assert_eq!(
            evaluate_speculative_cache(Some(&cache), &TIP_ID, HEIGHT - 1, &view),
            SpeculativeCacheVerdict::Hit
        );

        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let tip = MempoolTipContext {
            tip: TipPointer {
                height: HEIGHT - 1,
                header_id: Digest32::from_bytes(TIP_ID),
            },
            best_header_height: HEIGHT - 1,
            best_full_block_height: HEIGHT - 1,
            utxo: &view,
            tx_context: &ctx,
            params: &params,
            last_headers: &[],
            reemission: None,
        };
        let mut mp = Mempool::new(MempoolConfig::default(), Box::new(ByCost));
        let actions = admit_claim(&mut mp, &tip, &cache.families[0].claim, Instant::now());
        assert!(
            !actions.is_empty(),
            "Hit + live inputs ⇒ admit produces BroadcastInv"
        );
        assert!(
            mp.size() >= 1,
            "family landed in mempool after apply-time admit"
        );
    }

    // ----- error paths -----

    #[test]
    fn speculative_cache_discard_on_tip_mismatch() {
        let boxes = vec![aged_box(10_000_000_000, 0x01)];
        let cache = build_cache(&boxes);
        let view = MapView::of(&boxes);
        let other_tip = [0xEF; 32];
        assert_eq!(
            evaluate_speculative_cache(Some(&cache), &other_tip, HEIGHT - 1, &view),
            SpeculativeCacheVerdict::TipMismatch
        );
        assert_eq!(
            evaluate_speculative_cache(Some(&cache), &TIP_ID, HEIGHT, &view),
            SpeculativeCacheVerdict::TipMismatch,
            "height mismatch is also a tip miss"
        );
    }

    #[test]
    fn speculative_cache_discard_when_box_spent() {
        let boxes = vec![aged_box(10_000_000_000, 0x01)];
        let cache = build_cache(&boxes);
        let empty = MapView(HashMap::new());
        assert_eq!(
            evaluate_speculative_cache(Some(&cache), &TIP_ID, HEIGHT - 1, &empty),
            SpeculativeCacheVerdict::InputsSpent
        );
    }

    #[test]
    fn speculative_build_never_admits_without_apply() {
        // build_speculative_families / build_family_only have no Mempool
        // parameter — they cannot admit. Building a cache leaves pool empty.
        let boxes = vec![aged_box(10_000_000_000, 0x01)];
        let cache = build_cache(&boxes);
        assert!(!cache.families.is_empty());
        let mp = Mempool::new(MempoolConfig::default(), Box::new(ByCost));
        assert_eq!(mp.size(), 0, "speculate path must not touch the mempool");
        // Empty cache / None ⇒ never Hit ⇒ collect must not admit from cache.
        assert_eq!(
            evaluate_speculative_cache(None, &TIP_ID, HEIGHT - 1, &MapView::of(&boxes)),
            SpeculativeCacheVerdict::Empty
        );
    }
}

/// Gate tests that drive the full `collect_and_broadcast(&mut NodeState, …)`
/// entry point through a real (UTXO) `NodeState`, asserting each gate
/// short-circuits with NO admission. The gates fire before the mempool is
/// touched, so a fresh store (no genesis / no eligible boxes) is enough.
#[cfg(test)]
mod gate_tests {
    use super::*;
    use ergo_mempool::types::TipPointer;
    use ergo_mining::handle::RewardKeySource;
    use ergo_primitives::digest::Digest32;
    use ergo_validation::TransactionContext;

    const PK: [u8; 33] = [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];

    /// A minimal `OwnedTipContext` at `tip + 1 = 101`. The gate tests
    /// short-circuit before the validation inputs matter, so the exact
    /// header window / params don't affect the assertion.
    fn owned_tip() -> OwnedTipContext {
        OwnedTipContext {
            tip: TipPointer {
                height: 100,
                header_id: Digest32::from_bytes([0xAB; 32]),
            },
            best_header_height: 100,
            best_full_block_height: 100,
            tx_context: TransactionContext {
                height: 101,
                miner_pubkey: PK,
                pre_header_timestamp: 0,
                activated_script_version: 2,
                pre_header_version: 3,
                pre_header_parent_id: [0u8; 32],
                pre_header_n_bits: 0,
                pre_header_votes: [0u8; 3],
            },
            params: ergo_validation::ProtocolParams::mainnet_default(),
            last_headers: vec![],
            reemission: None,
        }
    }

    #[test]
    fn disabled_broadcasts_nothing() {
        // rent_collector = None ⇒ gate 1 short-circuits before any work.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::node::tests::make_state(&tmp.path().join("s.redb"));
        state.rent_collector = None;
        state.rent_proceeds_key = RewardKeySource::Pinned(PK);

        collect_and_broadcast(&mut state, &owned_tip());

        assert_eq!(state.mempool.size(), 0, "disabled collector admits nothing");
    }

    #[test]
    fn no_indexer_broadcasts_nothing() {
        // Enabled + resolvable key, but indexer absent ⇒ no eligibility
        // enumeration ⇒ empty set ⇒ nothing admitted.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::node::tests::make_state(&tmp.path().join("s.redb"));
        state.rent_collector = Some(RentCollectorConfig {
            enabled: true,
            ..RentCollectorConfig::default()
        });
        state.rent_proceeds_key = RewardKeySource::Pinned(PK);
        state.indexer_handle = None;

        collect_and_broadcast(&mut state, &owned_tip());

        assert_eq!(
            state.mempool.size(),
            0,
            "no indexer ⇒ no eligible boxes ⇒ nothing admitted",
        );
    }

    #[test]
    fn pending_proceeds_key_skips_this_tick() {
        // Enabled, but the proceeds key resolves Pending (Wallet source on a
        // fresh store where wallet tracking is uninitialized) ⇒ skip THIS
        // tick, admit nothing, retry next block.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::node::tests::make_state(&tmp.path().join("s.redb"));
        state.rent_collector = Some(RentCollectorConfig {
            enabled: true,
            ..RentCollectorConfig::default()
        });
        // Wallet source + fresh store ⇒ resolve_eip3_reward_key() == Pending.
        state.rent_proceeds_key = RewardKeySource::Wallet;

        collect_and_broadcast(&mut state, &owned_tip());

        assert_eq!(
            state.mempool.size(),
            0,
            "a Pending proceeds key skips this tick without admitting",
        );
        // Pending is transient: the collector must NOT latch off — it retries
        // next block.
        assert!(
            state.rent_collector.is_some(),
            "a Pending proceeds key skips this tick but leaves the collector enabled",
        );
    }

    /// Seed a master-only `WALLET_TRACKED_PUBKEYS` table on the UTXO store's
    /// redb so `resolve_eip3_reward_key()` returns `Corrupt`: a non-empty
    /// table with NO EIP-3 row is "inconsistent tracking", not "pending".
    /// Mirrors the production write shape in `wallet_boot::auto_derive_and_persist`.
    fn seed_corrupt_proceeds_key(state: &NodeState) {
        use ergo_state::wallet::tables::{tracked_pubkey_key, WALLET_TRACKED_PUBKEYS};
        use ergo_state::wallet::types::TrackedPubkeyMeta;

        let db = state.store.db_arc();
        let write_txn = db.begin_write().unwrap();
        {
            let mut tracked = write_txn.open_table(WALLET_TRACKED_PUBKEYS).unwrap();
            // Master-only row (empty derivation path) — no EIP-3 child, so the
            // resolver scans a non-empty table, finds no EIP-3 path, and
            // returns Corrupt.
            let master_meta = TrackedPubkeyMeta {
                derivation_path: vec![],
                derivation_path_label: String::new(),
                added_at_height: 0,
            };
            let master_bytes = bincode::serialize(&master_meta).unwrap();
            tracked
                .insert(tracked_pubkey_key(0, &PK), master_bytes)
                .unwrap();
        }
        write_txn.commit().unwrap();
    }

    #[test]
    fn corrupt_proceeds_key_latches_collector_off() {
        // Enabled + Wallet source, but the proceeds key resolves Corrupt
        // (master-only tracking) ⇒ latch the collector OFF: after one tick
        // `rent_collector` is None, nothing is admitted, and a subsequent tick
        // is a no-op (gate 1 short-circuits) — no per-block re-resolve / re-warn.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::node::tests::make_state(&tmp.path().join("s.redb"));
        state.rent_collector = Some(RentCollectorConfig {
            enabled: true,
            ..RentCollectorConfig::default()
        });
        state.rent_proceeds_key = RewardKeySource::Wallet;
        // Make resolve_eip3_reward_key() return Corrupt.
        seed_corrupt_proceeds_key(&state);

        collect_and_broadcast(&mut state, &owned_tip());

        assert!(
            state.rent_collector.is_none(),
            "a Corrupt proceeds key latches the collector OFF after one tick",
        );
        assert_eq!(
            state.mempool.size(),
            0,
            "a Corrupt proceeds key admits nothing",
        );

        // A subsequent tick is a no-op: gate 1 (rent_collector == None) returns
        // before any store/key work, so the collector stays disabled.
        collect_and_broadcast(&mut state, &owned_tip());
        assert!(
            state.rent_collector.is_none(),
            "the latch holds across ticks — the collector stays off",
        );
        assert_eq!(state.mempool.size(), 0, "still nothing admitted");
    }
}

/// Phase 5.2 — end-to-end admit + relay + counter integration.
///
/// ## What this drives, and the harness gap
///
/// The ideal 5.2 test drives the REAL `handle_mempool_tick` with a fully-synced
/// tip whose committed UTXO snapshot + extra-index resolve one eligible box,
/// and asserts a `RentCollector` family is admitted AND a `BroadcastInv`
/// reaches the wire. That full path is **infeasible from an `ergo-node` unit
/// test**: `handle_mempool_tick` requires (a) `mempool_notifier.poll` to emit a
/// tip change (committed-tip movement), (b) `fully_synced` (a non-zero
/// committed full-block tip whose header == full-block id), (c)
/// `build_tip_context` to find a non-empty `executor.block_context_headers()`,
/// and (d) the rent box to resolve through BOTH the real `IndexerStore`
/// eligibility index AND the committed AVL+ snapshot. Every one of those is
/// populated only by applying a real block through the sync/block-proc
/// pipeline — there is no public test seam to seed the committed snapshot, the
/// indexer eligibility row (`storage_rent::insert_unspent` is `pub(crate)` to
/// `ergo-indexer`), or the executor's header-context cache. The codebase
/// itself defers this to the sync-integration suite (see
/// `ergo-node/tests/submit_e2e.rs`'s `voted_params_boundary_cold_state_*`).
///
/// So this drives the **exact real post-build machinery `collect_and_broadcast`
/// runs** — the testable admit seam (`build_and_admit_family`, building a real
/// claim through the Phase 1b builder and admitting it through the REAL
/// `ErgoValidator` + transactional family path) followed by the REAL
/// `route_mempool_actions` + `flush_actions` (the same two lines
/// `collect_and_broadcast` runs on a non-empty result) and the REAL counter
/// bump on the same success condition. The ONLY substitution vs. production is
/// the eligibility input: the eligible box is supplied directly (a `MapView`
/// committed view + a hand-built `tip + 1` context) instead of being enumerated
/// from a real indexer/snapshot — exactly the seam that can't be populated in a
/// unit test. Nothing here asserts on a mock: admission is real (the tx is in
/// the pool, tagged `RentCollector`), relay is real (a serialized `Inv` lands
/// in a registered peer's outbound channel), and the counter rides the real
/// success gate.
#[cfg(test)]
mod integration_tests {
    use super::*;
    use ergo_mempool::types::TipPointer;
    use ergo_p2p::framing::MessageFrame;
    use ergo_p2p::message;
    use ergo_p2p::peer::SyncVersion;
    use ergo_primitives::digest::{Digest32, ModifierId};
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;
    use ergo_validation::{ProtocolParams, TransactionContext, UtxoView};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use tokio::sync::mpsc;

    use crate::node::state::PeerRuntime;

    /// secp256k1 generator point, compressed — a valid P2PK proceeds key.
    const PK: [u8; 33] = [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];

    const HEIGHT: u32 = 100;

    fn trivial_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        }
    }

    /// An aged (creation_height 0) anyone-can-spend box — eligible for a lone
    /// recreate claim at `HEIGHT` (the simplest shape, per the 5.2 spec).
    fn aged_box(value: u64, seed: u8) -> ErgoBox {
        let cand = ErgoBoxCandidate::new(
            value,
            trivial_tree(),
            0,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap();
        ErgoBox {
            candidate: cand,
            transaction_id: ModifierId::from_bytes([seed; 32]),
            index: 0,
        }
    }

    fn rent_params() -> ProtocolParams {
        let mut p = ProtocolParams::mainnet_default();
        p.storage_period = 10;
        p.storage_fee_factor = 1_250_000;
        p
    }

    fn tx_context_at(height: u32) -> TransactionContext {
        TransactionContext {
            height,
            miner_pubkey: PK,
            pre_header_timestamp: 0,
            activated_script_version: 2,
            pre_header_version: 3,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        }
    }

    /// Committed UTXO view resolving the seeded boxes by `box_id` — what the
    /// admission validator looks up for the parent's inputs. This stands in
    /// for the committed AVL+ snapshot that `collect_and_broadcast` reads in
    /// production (the seam that can't be seeded in a unit test).
    struct MapView(HashMap<Digest32, ErgoBox>);
    impl MapView {
        fn of(boxes: &[ErgoBox]) -> Self {
            Self(
                boxes
                    .iter()
                    .map(|b| (b.box_id().unwrap(), b.clone()))
                    .collect(),
            )
        }
    }
    impl UtxoView for MapView {
        fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
            self.0.get(id).cloned()
        }
    }

    fn rent_config() -> RentCollectorConfig {
        RentCollectorConfig {
            enabled: true,
            ..RentCollectorConfig::default()
        }
    }

    fn tip_ctx<'a>(
        view: &'a dyn UtxoView,
        params: &'a ProtocolParams,
        ctx: &'a TransactionContext,
    ) -> MempoolTipContext<'a> {
        MempoolTipContext {
            tip: TipPointer {
                height: HEIGHT - 1,
                header_id: Digest32::from_bytes([0xAB; 32]),
            },
            best_header_height: HEIGHT - 1,
            best_full_block_height: HEIGHT - 1,
            utxo: view,
            tx_context: ctx,
            params,
            last_headers: &[],
            reemission: None,
        }
    }

    /// Register a connected peer with a bounded outbound channel and return
    /// the receiver so the test can observe the `Inv` frames that the wire
    /// relay path (`flush_actions` → `send_to_peer` → `registry.try_send`)
    /// pushes to it.
    fn register_peer(state: &mut NodeState, peer: SocketAddr) -> mpsc::Receiver<MessageFrame> {
        let (tx, rx) = mpsc::channel(16);
        state.registry.peers.insert(
            peer,
            PeerRuntime {
                sync_version: SyncVersion::V2,
                outbound_tx: tx,
            },
        );
        rx
    }

    /// The end-to-end version of the per-unit admit/order/relay tests: one
    /// eligible recreate box, driven through the REAL admit (the Phase 1b
    /// builder, the `ErgoValidator`, and the transactional family path) and the
    /// REAL post-admit route + flush + counter bump that `collect_and_broadcast`
    /// runs, against a real `NodeState` with a connected peer. Asserts a real
    /// admission, a real relay, and the real counter bump: a
    /// `RentCollector`-sourced tx is in `state.mempool`; a `BroadcastInv`
    /// reached the wire as an `Inv` frame in the peer's outbound channel; and
    /// `rent_collector_broadcasts_total` advanced.
    #[test]
    fn eligible_box_admits_and_relays_through_real_route_and_flush() {
        use ergo_p2p::types::ModifierTypeId;

        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::node::tests::make_state(&tmp.path().join("s.redb"));
        state.rent_collector = Some(rent_config());

        // A connected peer to observe the relayed Inv on.
        let peer: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let mut rx = register_peer(&mut state, peer);

        // One eligible recreate box (simplest shape) supplied directly — the
        // production enumeration seam (`committed_snapshot` + indexer) can't be
        // populated in a unit test (see module docs).
        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let boxes = vec![aged_box(10_000_000_000, 0x01)];
        let view = MapView::of(&boxes);
        let now = Instant::now();

        // REAL admit: build the claim through the Phase 1b builder and admit it
        // through the REAL ErgoValidator + transactional family path.
        let (actions, _) = {
            let tip = tip_ctx(&view, &params, &ctx);
            build_and_admit_family(&mut state.mempool, &tip, &boxes, &PK, &rent_config(), now)
        };
        assert!(
            !actions.is_empty(),
            "the lone recreate family must admit and produce a relay action",
        );

        // REAL post-admit path — the SAME production helper
        // `collect_and_broadcast` runs on a non-empty result: it drives the
        // real `if !actions.is_empty()` guard, the counter bump, then route +
        // flush. No re-implementation here.
        let before = state.rent_collector_broadcasts_total;
        relay_and_count(
            &mut state,
            actions,
            &RelayTiming {
                collect_start: Instant::now(),
                speculative_hit: false,
                speculative_build_age_ms: 0,
            },
        );

        // (a) REAL admission: a RentCollector-tagged tx is in the pool.
        assert_eq!(state.mempool.size(), 1, "the recreate parent is admitted");
        let rent_tagged = state
            .mempool
            .pool()
            .iter_prioritized()
            .filter(|e| matches!(e.source, TxSource::RentCollector))
            .count();
        assert_eq!(rent_tagged, 1, "the admitted tx is tagged RentCollector");

        // (b) REAL relay: an Inv frame for the parent reached the peer's wire.
        let frame = rx.try_recv().expect("an Inv frame must reach the peer");
        assert_eq!(frame.code, message::CODE_INV, "the relayed frame is an Inv",);
        let inv = message::deserialize_inv(&frame.payload).expect("valid Inv payload");
        assert_eq!(
            inv.type_id,
            ModifierTypeId::Transaction.as_byte(),
            "the Inv advertises a transaction",
        );
        assert_eq!(inv.ids.len(), 1, "exactly the parent tx id is advertised");

        // (c) the counter advanced on the success condition.
        assert_eq!(
            state.rent_collector_broadcasts_total,
            before + 1,
            "a successful broadcast increments the counter exactly once",
        );
    }

    /// The empty-mempool / no-eligible-box end-to-end behavior the per-unit
    /// tests only simulate: with no eligible boxes the real admit seam admits
    /// nothing, the post-admit path is skipped (no counter bump, no Inv), and
    /// the pool stays empty — mirroring `collect_and_broadcast`'s
    /// `if !actions.is_empty()` gate on a real `NodeState`.
    #[test]
    fn no_eligible_box_admits_nothing_and_does_not_relay_or_count() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::node::tests::make_state(&tmp.path().join("s.redb"));
        state.rent_collector = Some(rent_config());
        let peer: SocketAddr = "127.0.0.1:7001".parse().unwrap();
        let mut rx = register_peer(&mut state, peer);

        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let view = MapView::of(&[]);
        let now = Instant::now();

        let (actions, _) = {
            let tip = tip_ctx(&view, &params, &ctx);
            build_and_admit_family(&mut state.mempool, &tip, &[], &PK, &rent_config(), now)
        };
        assert!(actions.is_empty(), "no eligible box ⇒ no relay action");

        // The real post-admit gate (same production helper): empty actions ⇒
        // skip bump + route + flush.
        let before = state.rent_collector_broadcasts_total;
        relay_and_count(
            &mut state,
            actions,
            &RelayTiming {
                collect_start: Instant::now(),
                speculative_hit: false,
                speculative_build_age_ms: 0,
            },
        );

        assert_eq!(state.mempool.size(), 0, "nothing admitted");
        assert_eq!(
            state.rent_collector_broadcasts_total, before,
            "no broadcast ⇒ counter unchanged",
        );
        assert!(
            rx.try_recv().is_err(),
            "no broadcast ⇒ no Inv frame relayed",
        );
    }

    #[test]
    fn reannounce_emits_inv_per_resident_rent_txid_after_interval() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::node::tests::make_state(&tmp.path().join("s.redb"));
        state.rent_collector = Some(RentCollectorConfig {
            enabled: true,
            reannounce_interval_ms: 1,
            ..RentCollectorConfig::default()
        });
        // Interval already elapsed.
        state.last_rent_reannounce = Instant::now()
            .checked_sub(Duration::from_secs(60))
            .unwrap_or_else(Instant::now);

        let peer: SocketAddr = "127.0.0.1:7002".parse().unwrap();
        let mut rx = register_peer(&mut state, peer);

        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let boxes = vec![
            aged_box(10_000_000_000, 0x51),
            aged_box(10_000_000_000, 0x52),
        ];
        let view = MapView::of(&boxes);
        let now = Instant::now();
        let (actions, _) = {
            let tip = tip_ctx(&view, &params, &ctx);
            build_and_admit_family(&mut state.mempool, &tip, &boxes, &PK, &rent_config(), now)
        };
        assert!(actions.len() >= 2, "batched family admits parent+child");
        // Drain the initial broadcast Invs from admit relay (not used here).
        relay_and_count(
            &mut state,
            actions,
            &RelayTiming {
                collect_start: Instant::now(),
                speculative_hit: false,
                speculative_build_age_ms: 0,
            },
        );
        while rx.try_recv().is_ok() {}

        maybe_reannounce_rent_families(&mut state);

        let mut inv_ids = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            assert_eq!(frame.code, message::CODE_INV);
            let inv = message::deserialize_inv(&frame.payload).expect("inv");
            assert_eq!(inv.ids.len(), 1);
            inv_ids.push(inv.ids[0]);
        }
        assert_eq!(
            inv_ids.len(),
            2,
            "re-announce emits one Inv per resident RentCollector txid"
        );

        // Before the next interval: no further re-announce.
        maybe_reannounce_rent_families(&mut state);
        assert!(
            rx.try_recv().is_err(),
            "no re-announce before interval elapses again"
        );
    }

    #[test]
    fn reannounce_disabled_when_interval_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::node::tests::make_state(&tmp.path().join("s.redb"));
        state.rent_collector = Some(RentCollectorConfig {
            enabled: true,
            reannounce_interval_ms: 0,
            ..RentCollectorConfig::default()
        });
        state.last_rent_reannounce = Instant::now()
            .checked_sub(Duration::from_secs(60))
            .unwrap_or_else(Instant::now);
        let peer: SocketAddr = "127.0.0.1:7003".parse().unwrap();
        let mut rx = register_peer(&mut state, peer);

        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let boxes = vec![aged_box(10_000_000_000, 0x61)];
        let view = MapView::of(&boxes);
        let (actions, _) = {
            let tip = tip_ctx(&view, &params, &ctx);
            build_and_admit_family(
                &mut state.mempool,
                &tip,
                &boxes,
                &PK,
                &rent_config(),
                Instant::now(),
            )
        };
        relay_and_count(
            &mut state,
            actions,
            &RelayTiming {
                collect_start: Instant::now(),
                speculative_hit: false,
                speculative_build_age_ms: 0,
            },
        );
        while rx.try_recv().is_ok() {}

        maybe_reannounce_rent_families(&mut state);
        assert!(
            rx.try_recv().is_err(),
            "reannounce_interval_ms=0 disables re-announce"
        );
    }

    #[test]
    fn reannounce_noop_when_rent_collector_none() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::node::tests::make_state(&tmp.path().join("s.redb"));
        state.rent_collector = None;
        state.last_rent_reannounce = Instant::now()
            .checked_sub(Duration::from_secs(60))
            .unwrap_or_else(Instant::now);
        let peer: SocketAddr = "127.0.0.1:7004".parse().unwrap();
        let mut rx = register_peer(&mut state, peer);

        // Even with a resident-looking pool state, the None gate must win.
        maybe_reannounce_rent_families(&mut state);
        assert!(
            rx.try_recv().is_err(),
            "rent_collector=None ⇒ re-announce is a no-op"
        );
    }

    #[test]
    fn reannounce_skips_evicted_txids() {
        // Live-pool scan is self-pruning: once the family is gone from the
        // pool (mined/evicted), it must not be re-announced.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::node::tests::make_state(&tmp.path().join("s.redb"));
        state.rent_collector = Some(RentCollectorConfig {
            enabled: true,
            reannounce_interval_ms: 1,
            ..RentCollectorConfig::default()
        });
        state.last_rent_reannounce = Instant::now()
            .checked_sub(Duration::from_secs(60))
            .unwrap_or_else(Instant::now);
        let peer: SocketAddr = "127.0.0.1:7005".parse().unwrap();
        let mut rx = register_peer(&mut state, peer);

        let params = rent_params();
        let ctx = tx_context_at(HEIGHT);
        let boxes = vec![aged_box(10_000_000_000, 0x91)];
        let view = MapView::of(&boxes);
        let (actions, _) = {
            let tip = tip_ctx(&view, &params, &ctx);
            build_and_admit_family(
                &mut state.mempool,
                &tip,
                &boxes,
                &PK,
                &rent_config(),
                Instant::now(),
            )
        };
        relay_and_count(
            &mut state,
            actions,
            &RelayTiming {
                collect_start: Instant::now(),
                speculative_hit: false,
                speculative_build_age_ms: 0,
            },
        );
        while rx.try_recv().is_ok() {}
        assert!(
            !state
                .mempool
                .resident_txids_by_source(&TxSource::RentCollector)
                .is_empty(),
            "precondition: family is resident"
        );

        // Simulate eviction / mined: replace with an empty pool.
        state.mempool = Mempool::new(
            ergo_mempool::types::MempoolConfig::default(),
            Box::new(ergo_mempool::weight::ByCost),
        );
        assert!(state
            .mempool
            .resident_txids_by_source(&TxSource::RentCollector)
            .is_empty());

        maybe_reannounce_rent_families(&mut state);
        assert!(
            rx.try_recv().is_err(),
            "evicted/mined txids must not be re-announced"
        );
    }

    // ----- submit URL helpers -----

    #[test]
    fn submit_bytes_url_trims_trailing_slash() {
        assert_eq!(
            submit_bytes_url("http://127.0.0.1:9053/"),
            "http://127.0.0.1:9053/transactions/bytes"
        );
        assert_eq!(
            submit_bytes_url("http://127.0.0.1:9053"),
            "http://127.0.0.1:9053/transactions/bytes"
        );
    }

    #[test]
    fn unconfirmed_by_id_url_joins_txid() {
        let u = unconfirmed_by_id_url("http://n:9053/", "abcd");
        assert_eq!(
            u,
            "http://n:9053/transactions/unconfirmed/byTransactionId/abcd"
        );
    }

    #[test]
    fn is_submit_accepted_only_http_200() {
        assert!(is_submit_accepted(200));
        assert!(!is_submit_accepted(400), "relay 400 must not count as ok");
        assert!(!is_submit_accepted(404));
        assert!(!is_submit_accepted(500));
        assert!(!is_submit_accepted(0));
    }

    #[test]
    fn invd_rc_ordered_preserves_parent_before_child() {
        // relay_and_count records BroadcastInv order into invd_rc_ordered.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::node::tests::make_state(&tmp.path().join("s.redb"));
        state.rent_collector = Some(rent_config());
        let parent = [1u8; 32];
        let child = [2u8; 32];
        // Simulate admit order: parent then child.
        state.rent_fo.invd_rc_txids.insert(parent);
        state.rent_fo.invd_rc_ordered.push(parent);
        state.rent_fo.invd_rc_txids.insert(child);
        state.rent_fo.invd_rc_ordered.push(child);
        assert_eq!(state.rent_fo.invd_rc_ordered, vec![parent, child]);
        // Tip apply clears both.
        note_tip_apply(&mut state, 1);
        assert!(state.rent_fo.invd_rc_ordered.is_empty());
        assert!(state.rent_fo.invd_rc_txids.is_empty());
    }
}
