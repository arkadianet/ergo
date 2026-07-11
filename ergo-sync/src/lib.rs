//! Sync coordinator for the Ergo Rust node.
//!
//! Sits on top of [`ergo_p2p`] (peer manager + delivery tracker),
//! [`ergo_validation`] (header / block validators), [`ergo_state`]
//! (UTXO + chain state), and [`ergo_crypto`] (PoW + difficulty).
//! Drives the four together through initial-block-download (IBD) and
//! steady-state operation.
//!
//! Module map:
//!
//! * [`coordinator`] — the long-running event loop. Consumes peer
//!   events (`Inv`, `Modifier`, `Disconnect`), schedules
//!   inv-batch and request-batch outputs, and steps the apply
//!   pipeline forward as new blocks become assembleable.
//! * [`executor`] — concrete implementation of the coordinator's
//!   action surface — opens / drives the `StateStore`, runs the
//!   header pipeline, sequences full-block validation, and persists
//!   the results.
//! * [`header_proc`] — two-phase header processing helpers:
//!   parallel parse + PoW verify, then sequential chain linkage +
//!   persistence.
//! * [`block_proc`] — full-block processing pipeline: load sections
//!   → validate → apply to state. Includes the epoch-boundary voting
//!   recompute on extension blocks.

pub mod apply_phase;
pub mod block_proc;
pub mod coordinator;
pub mod executor;
pub mod header_proc;
pub mod perf;
pub mod popow_bootstrap;
pub mod snapshot_bootstrap;

pub use apply_phase::ApplyPhaseMetrics;
