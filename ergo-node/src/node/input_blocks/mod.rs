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

// Task 4 wires the p2p dispatch (codes 100/102/104/105/106 and the
// −123/−122/−121 Inv arms) that drives this module; until then the unit
// tests below are the only callers, and `-D warnings` would otherwise
// refuse this intermediate commit.
#![allow(dead_code, unused_imports)]

mod ctx;
mod effects;
mod hooks;
mod runtime;
mod validate;

#[cfg(test)]
mod tests;

pub(in crate::node) use ctx::{
    block_transactions_known, build_ctx_data, expected_n_bits_after, transactions_section_id,
};
pub(in crate::node) use effects::{apply_chain_change, execute_effects};
pub(in crate::node) use hooks::{
    on_ordering_block_applied, on_ordering_reorg, on_tick, seed_best_ordering,
};
pub(in crate::node) use runtime::InputBlocksRuntime;
pub(in crate::node) use validate::{build_input_block_context, run_validation};
