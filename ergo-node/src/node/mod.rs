//! Node runtime namespace. Wires the action-loop submodules together
//! and re-exports the public surface (`run`, `run_inner`,
//! `RunHandle`, identity helpers) used by the binary entry point and
//! library embedders.
//!
//! Boot sequence lives in [`boot`]; the action loop body in
//! [`action_loop`]; per-event/message handlers in [`events`] /
//! [`messaging`]; mempool admission in [`admission`]; peer
//! plumbing in [`peer_actions`].

/// Panic-safe stderr write used inside the shutdown sequence.
///
/// `eprintln!` panics if the stderr pipe is closed. When we're a
/// child of `cargo run` and the user hits Ctrl+C, SIGINT is delivered
/// to the whole foreground process group; cargo exits first and
/// tears down our stderr pipe. The first `eprintln!` in our shutdown
/// handler then panics — aborting the process before
/// `shutdown_cleanly()` runs and leaving redb mid-flush. Swallow
/// write errors here so the cleanup path completes regardless of
/// whether anyone is reading stderr.
macro_rules! shutdown_log {
    ($($arg:tt)*) => {{
        use ::std::io::Write;
        let _ = ::std::writeln!(::std::io::stderr().lock(), $($arg)*);
    }};
}

mod action_loop;
mod admission;
mod boot;
mod event_feed;
mod events;
mod first_deliverer;
mod handle;
mod heartbeat;
pub mod identity;
mod memory_sampler;
mod messaging;
mod mining_dispatch;
mod mining_engine;
mod peer_actions;
mod reorg_history;
mod shadow_watch;
mod snapshot_emit;
mod snapshot_state;
mod state;
mod sync_helpers;
mod sync_tick;
mod tip_context;
mod util;
pub mod wallet_bridge;

pub(in crate::node) use self::admission::admit_transaction;
pub use self::boot::{run, run_inner};
pub use self::handle::RunHandle;
#[cfg(test)]
pub(super) use self::identity::mode_label_for;
pub(in crate::node) use self::messaging::handle_message;
pub(in crate::node) use self::peer_actions::{
    cleanup_disconnected_peer, flush_actions, send_to_peer,
};
pub(crate) use self::shadow_watch::ShadowConfig;
pub(in crate::node) use self::state::{NodeState, PeerRuntime};
pub(in crate::node) use self::sync_helpers::{
    hedge_request_modifiers, maybe_exit_ibd, try_send_anchor_sync_info,
};

/// Type alias used across the node runtime. `Send + Sync` is
/// required because the action loop returns errors across thread
/// boundaries via `JoinHandle::await`.
pub type NodeError = Box<dyn std::error::Error + Send + Sync>;

#[cfg(test)]
pub(super) mod tests;
