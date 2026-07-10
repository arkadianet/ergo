//! Library facade for the `ergo-node` binary.
//!
//! Exposes the runtime (`run`, `run_inner`, [`RunHandle`]) and the
//! supporting modules tests and embedders need. The binary
//! (`src/main.rs`) is a thin wrapper around [`run`].

pub mod anchor_map;
pub mod anchor_scheduler;
pub mod api_bridge;
pub mod config;
pub mod genesis;
pub mod indexer_chain;
pub mod mem_csv;
pub mod mem_probe;
pub mod mem_smaps;
pub mod mining_bridge;
pub mod node;
pub mod notifier;
pub mod peer_loop;
pub mod realtime_mempool_bridge;
pub mod snapshot;
pub mod wallet_boot;

pub use node::{run, run_inner, RunHandle};
