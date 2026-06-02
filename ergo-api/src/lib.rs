//! Operator-facing read-only HTTP API for the Ergo Rust node.
//!
//! The crate's contract with the rest of the workspace is a small set
//! of traits ([`NodeReadState`], [`NodeSubmit`], [`NodeChainQuery`])
//! and the wire-shaped DTOs in [`types`]. The node implements the
//! traits against a snapshot of its runtime state and hands
//! `Arc<dyn ...>` trait objects to [`serve`]. This is the load-bearing
//! boundary; preserve it.
//!
//! Beyond `ergo-primitives` / `ergo-ser` / `ergo-rest-json`, the one
//! internal dep that ships a consumed trait is `ergo-indexer-types`,
//! which provides the `IndexerQuery` trait used by the optional
//! `/blockchain/*` extra-index parity surface. `ergo-api` accepts an
//! `Arc<dyn IndexerQuery>` the same way it accepts the other reader
//! traits — no concrete-type leak, and no dependency on the
//! `ergo-indexer` writer crate (that stays a dev-dependency).

pub mod auth;
pub mod blockchain;
pub mod compat;
pub mod mining;
pub mod server;
pub mod traits;
pub mod types;
pub mod utils;
pub mod wallet;
mod web;

pub use compat::{NodeChainQuery, Parameters, ScalaInfo};
pub use mining::{mining_router, MiningApiError, NodeMining, NoopNodeMining};
pub use server::{
    bind, router_with_wallet, serve, serve_on, serve_on_with_mempool,
    serve_on_with_mempool_and_wallet_and_security, ServerCtx,
};
pub use traits::{
    ChainParamsView, MempoolView, NodeAdmin, NodeReadState, NodeSubmit, NoopMempoolView,
    NoopNodeAdmin, PoolTxDetail,
};
pub use types::*;
