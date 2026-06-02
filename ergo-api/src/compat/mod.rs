//! Scala-compatible API surface.
//!
//! Mounted at bare paths (`/info`, `/blocks/{id}`, `/utxo/byId`, ...) so
//! tooling written against the Scala node can target this node without
//! changes. DTOs and route layout live here; the dashboard surface in
//! `crate::server` is intentionally not mixed with this module.
//!
//! Endpoints land here as the live-read paths they need become available
//! through the bridge.

pub mod blocks;
pub mod handlers;
pub mod traits;
pub mod transactions;
pub mod types;

pub use traits::NodeChainQuery;
pub use types::{Parameters, ScalaInfo};
