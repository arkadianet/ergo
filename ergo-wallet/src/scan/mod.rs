//! The `/scan/*` wallet subsystem (Scala scanning API).
//!
//! Built incrementally. This slice ships the tracking-rule predicate language
//! ([`predicate`]); the persistent scan registry, the block-apply matcher, and
//! the eight HTTP endpoints follow in later PRs.

pub mod predicate;

pub use predicate::{ScanRegister, ScanningPredicate};
