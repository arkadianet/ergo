//! Node-side input-block (weak-block) runtime — spec §9.1-9.2.
//!
//! [`InputBlocksRuntime`] owns the `ergo-inputblocks` processor plus the
//! node-side facts the processor deliberately does not: a clock, a
//! `PeerId` ↔ `PeerTag` bijection, the mempool entries an applied input
//! block evicted, and per-`DropReason` counters.
//!
//! [`ctx`] builds the per-event `ProcessorCtx`, [`validate`] runs spec
//! 6.4's inline validation, and [`effects`] maps the processor's effects
//! onto network actions, mempool calls and pipeline handoffs.
//!
//! The whole subsystem is optional: `NodeState::input_blocks` is `None`
//! unless `[input_blocks] enabled` (devnet-only), and every entry point
//! here is a no-op in that case.

mod ctx;
mod dispatch;
mod effects;
mod hooks;
mod runtime;
mod serve;
mod validate;

#[cfg(test)]
mod tests;

// Re-exported for the rest of the node runtime. Everything else in
// these submodules is internal to this module (the unit tests reach it
// through `super::<submodule>`), so it is deliberately NOT re-exported.
pub(in crate::node) use dispatch::{
    handle as dispatch_frame, handle_ordering_inv, is_input_block_code, serve_modifier_request,
    Dispatched,
};
pub(in crate::node) use hooks::{advertised_version, on_tick, seed_best_ordering};
pub(in crate::node) use runtime::InputBlocksRuntime;
