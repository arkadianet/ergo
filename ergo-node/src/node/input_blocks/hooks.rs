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
use ergo_state::ChainStateRead;
use ergo_sync::coordinator::Action;

use super::super::NodeState;
use super::ctx::build_ctx_data;
use super::effects::execute_effects;
use super::runtime::InputBlocksRuntime;

/// Feed one `Event::Tick`. Called once per `sync_tick` (1 s) from the
/// heartbeat, which is the node's existing "time passed" edge.
pub(in crate::node) fn on_tick(state: &mut NodeState, now: Instant) -> Vec<Action> {
    let actions = drive(state, now, |tick| Event::Tick { now: tick });
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
