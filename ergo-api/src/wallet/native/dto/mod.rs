//! Native `/api/v1/wallet/*` response DTOs.
//!
//! Factual-only, built for permanence: money and token amounts are decimal
//! **strings** (JSON numbers lose precision
//! above 2^53); status/provenance/scope are **tagged unions** `{type:"…"}`; lean
//! summaries extend additively. These are distinct from the Scala-compat
//! `super::super::types` DTOs — neither is reused or mutated.

mod addresses;
mod balance;
mod boxes;
mod lifecycle;
mod rewards;
mod status;
mod transactions;
mod tx_construction;

pub use addresses::*;
pub use balance::*;
pub use boxes::*;
pub use lifecycle::*;
pub use rewards::*;
pub use status::*;
pub use transactions::*;
pub use tx_construction::*;
