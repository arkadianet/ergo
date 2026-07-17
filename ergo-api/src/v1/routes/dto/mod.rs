//! Shared v1 wire DTOs + projection helpers for the `chain/*` and
//! `transactions/*` route groups.
//!
//! **This is the first v1 route group, so the shapes here are the template
//! every later group copies.** Field names are the glossary verbatim
//! (`tx_id`, `header_id`, `value` as string, `size_bytes`, `inclusion_height`,
//! …), timestamps use the format (`*_unix_ms` int + `*_iso` mirror), amounts that
//! can exceed 2^53 are strings, and enums are lowercase strings (`"left"` /
//! `"right"`), never magic ints.
//!
//! Provenance: these are glossary-renamed projections of the frozen Scala-compat
//! DTOs (`ergo_rest_json::types::*`) returned by [`crate::compat::NodeChainQuery`]
//! and of `IndexedErgoBoxResponse` (`crate::blockchain`). The compat shapes stay
//! camelCase and frozen; v1 wraps, never mutates them.

mod boxes;
mod common;
mod header;
mod mempool;

pub use boxes::*;
pub use common::*;
pub use header::*;
pub use mempool::*;
