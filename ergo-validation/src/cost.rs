//! Re-exports the JIT-cost types from [`ergo_primitives::cost`] so the
//! validation surface stays self-contained for downstream callers.
//! See `ergo_primitives::cost` for the type definitions.

pub use ergo_primitives::cost::{CostAccumulator, CostError, CostKind, JitCost};
