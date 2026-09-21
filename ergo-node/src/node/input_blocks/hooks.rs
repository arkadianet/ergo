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

/// Feed one `Event::Tick`. Called once per `sync_tick` (1 s) from the
/// heartbeat, which is the node's existing "time passed" edge.
pub(in crate::node) fn on_tick(state: &mut NodeState, now: Instant) -> Vec<Action> {
    drive(state, now, |tick| Event::Tick { now: tick })
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
