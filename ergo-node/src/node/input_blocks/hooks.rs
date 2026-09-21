//! Node-loop hooks that drive the processor's clock and chain events
//! (spec 7.6).
//!
//! Three of the processor's seven events are not peer frames: the
//! periodic `Tick` that sweeps TTLs and releases expired request slots,
//! and the two ordering-chain events that bump the generation, prune, and
//! re-run the selection. Without them a peer that stops answering holds
//! its `requests_per_peer` slots for good, and an applied full block
//! never clears `/info.bestInputBlock`.
//!
//! Every function here is a no-op when the subsystem is off.

use std::time::Instant;

use ergo_inputblocks::processor::Event;
use ergo_p2p::handshake::Version;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_sync::coordinator::Action;

use super::super::NodeState;
use super::ctx::build_ctx_data;
use super::effects::execute_effects;
use super::runtime::InputBlocksRuntime;

/// Feed one `Event::Tick`. Called once per `sync_tick` (1 s) from the
/// heartbeat, which is the node's existing "time passed" edge.
pub(in crate::node) fn on_tick(state: &mut NodeState, now: Instant) -> Vec<Action> {
    let mut actions = sync_ordering_tip(state, now);
    actions.extend(drive(state, now, |tick| Event::Tick { now: tick }));
    // Keep the phase map bounded by genuinely in-flight requests: the
    // tracker's own timeout sweep releases ids we never got an answer
    // for, and the record for those must go with them.
    if state.input_blocks.is_some() {
        // `ModifierStatus::Requested` is exactly "the tracker still
        // holds this in flight"; anything else (received, failed,
        // swept) means the record is stale.
        let stale: Vec<[u8; 32]> = state
            .input_blocks
            .as_ref()
            .map(|rt| {
                rt.expected_ids()
                    .filter(|id| {
                        state.coordinator.delivery().status(id)
                            != ergo_p2p::delivery::ModifierStatus::Requested
                    })
                    .collect()
            })
            .unwrap_or_default();
        if let Some(rt) = state.input_blocks.as_mut() {
            rt.prune_expectations(|id| !stale.contains(id));
        }
    }
    // Operator surface for the bounds: every overflow the processor
    // reports is a `Dropped` effect, and a bound that is being hit
    // continuously is the signal that a cap is mis-sized or a peer is
    // abusing one. Logged on change, not on a timer. (Task 6 exposes the
    // same counters on the API.)
    if let Some((new_drops, breakdown)) = state
        .input_blocks
        .as_mut()
        .and_then(InputBlocksRuntime::take_drop_report)
    {
        tracing::info!(
            new_drops,
            breakdown = ?breakdown,
            "input_blocks: drop counters advanced"
        );
    }
    actions
}

/// Drive the ordering-chain events from the committed state itself.
///
/// The processor's view of the best full block has to track the store's,
/// and the store is the only thing that knows when it moved. Reading it
/// here — rather than riding the mempool's tip-change diff — keeps the
/// chain events independent of whether the mempool subsystem is running
/// at all, and classifies reorg-vs-linear on the exact rule (does the
/// new tip's parent pointer name the previous tip?) instead of on the
/// mempool-level proxy "were any pooled transactions demoted".
fn sync_ordering_tip(state: &mut NodeState, now: Instant) -> Vec<Action> {
    let meta = state.store.chain_state_meta();
    let tip = meta.best_full_block_id;
    if tip == [0u8; 32] {
        return Vec::new();
    }
    let previous = match state.input_blocks.as_ref() {
        Some(rt) => rt.last_ordering_tip,
        None => return Vec::new(),
    };
    if previous == Some(tip) {
        return Vec::new();
    }
    let height = meta.best_full_block_height;
    // The first tip we ever see has no predecessor to descend from, so
    // it is a switch by definition.
    let change = match previous {
        Some(prev) => classify_tip_change(state, prev, tip, height),
        None => TipChange::Reorg,
    };
    if let Some(rt) = state.input_blocks.as_mut() {
        rt.last_ordering_tip = Some(tip);
    }
    match change {
        TipChange::Applied => on_ordering_block_applied(state, tip, height, now),
        TipChange::Reorg => on_ordering_reorg(state, tip, height, now),
    }
}

/// How the committed tip got from one id to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum TipChange {
    /// The new tip descends from the previous one: the chain moved
    /// forward, by one block or by several.
    Applied,
    /// The new tip is not a descendant — a fork switch, a rollback, or a
    /// jump we cannot prove is linear.
    Reorg,
}

/// How far back the ancestry walk will look before giving up and calling
/// a tip change a switch.
///
/// The tick runs once a second and blocks are minutes apart, so a
/// multi-block gap means the node was busy or has just caught up. Past
/// this many blocks the processor's own state is stale anyway (its
/// records live within `Bounds::prune_threshold` of the best height), so
/// reporting a switch — which drops the trees — is both cheap and
/// correct, and it bounds the parent-pointer reads this does per tick.
pub(in crate::node) const MAX_LINEAR_CATCHUP: u32 = 64;

/// Does `tip` descend from `previous`?
///
/// Walks parent pointers back from `tip`, bounded by the height delta
/// (and by [`MAX_LINEAR_CATCHUP`]). Anything else — a sibling branch, a
/// rollback to an ancestor, an unknown header, a gap too large to walk —
/// is a switch.
///
/// Classifying on the IMMEDIATE child alone, as this used to, reported
/// every two-blocks-between-ticks advance as a reorg; the reorg handler
/// then retains only the new tip's tree, discarding state a linear
/// advance would have kept.
pub(in crate::node) fn classify_tip_change(
    state: &NodeState,
    previous: [u8; 32],
    tip: [u8; 32],
    tip_height: u32,
) -> TipChange {
    let Some(prev_height) = state
        .store
        .get_header_meta(&previous)
        .ok()
        .flatten()
        .map(|m| m.height)
    else {
        // We cannot show ancestry against a header we no longer hold.
        return TipChange::Reorg;
    };
    // A tip at or below the previous height cannot descend from it —
    // that is a rollback or a same-height sibling.
    if tip_height <= prev_height {
        return TipChange::Reorg;
    }
    let steps = tip_height - prev_height;
    if steps > MAX_LINEAR_CATCHUP {
        return TipChange::Reorg;
    }
    let mut cursor = tip;
    for _ in 0..steps {
        let Some(meta) = state.store.get_header_meta(&cursor).ok().flatten() else {
            return TipChange::Reorg;
        };
        cursor = meta.parent_id;
        if cursor == previous {
            return TipChange::Applied;
        }
    }
    TipChange::Reorg
}

/// A full block was committed at a new best height (spec 7.6).
pub(in crate::node) fn on_ordering_block_applied(
    state: &mut NodeState,
    header_id: [u8; 32],
    height: u32,
    now: Instant,
) -> Vec<Action> {
    drive(state, now, |tick| Event::OrderingBlockApplied {
        header_id,
        height,
        now: tick,
    })
}

/// The node switched best full chain (spec 7.6).
pub(in crate::node) fn on_ordering_reorg(
    state: &mut NodeState,
    new_best_header_id: [u8; 32],
    new_best_height: u32,
    now: Instant,
) -> Vec<Action> {
    drive(state, now, |tick| Event::OrderingReorg {
        new_best_header_id,
        new_best_height,
        now: tick,
    })
}

/// Seed the processor's view of the best full block at boot. The
/// processor starts empty (spec 9.5) but must not think the chain is at
/// height 0, or every announcement lands outside the height window.
pub(in crate::node) fn seed_best_ordering(state: &mut NodeState) {
    let meta = state.store.chain_state_meta();
    if let Some(rt) = state.input_blocks.as_mut() {
        let id = (meta.best_full_block_id != [0u8; 32]).then_some(meta.best_full_block_id);
        rt.processor_mut()
            .set_best_ordering(id, meta.best_full_block_height);
        // The processor now agrees with the store, so the first tick
        // must not re-announce the same tip as a chain event.
        rt.last_ordering_tip = id;
    }
}

/// The protocol version this node advertises in its handshake.
///
/// Scala `Version.SubblocksVersion = 6.5.0` is a capability claim, not a
/// build stamp: a peer reads it to decide whether to send us the
/// input-block messages at all. Advertising it with the subsystem off
/// would invite frames we ignore and make us look like a relay we are
/// not, so it is tied to the config flag rather than to the release.
pub(in crate::node) fn advertised_version(input_blocks_enabled: bool) -> Version {
    if input_blocks_enabled {
        Version::SUBBLOCKS
    } else {
        Version::CURRENT
    }
}

/// Shared shape: build the per-event context, hand the event to the
/// processor, execute the effects it returns.
fn drive(
    state: &mut NodeState,
    now: Instant,
    make: impl FnOnce(ergo_inputblocks::types::Tick) -> Event,
) -> Vec<Action> {
    let Some(rt) = state.input_blocks.as_ref() else {
        return Vec::new();
    };
    let event = make(rt.tick(now));
    let Some(mut rt) = state.input_blocks.take() else {
        return Vec::new();
    };
    let data = build_ctx_data(state, &[]);
    let effects = data.with(|ctx| rt.processor_mut().handle(event, ctx));
    drop(data);
    state.input_blocks = Some(rt);
    execute_effects(state, effects, now)
}
