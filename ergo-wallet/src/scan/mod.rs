//! The `/scan/*` wallet subsystem (Scala scanning API).
//!
//! Built incrementally: the tracking-rule predicate language ([`predicate`])
//! and the scan [`registry`] (model + id allocation + CRUD) are in place; the
//! block-apply matcher and the remaining HTTP endpoints follow in later PRs.

pub mod predicate;
pub mod registry;

pub use predicate::{ScanRegister, ScanningPredicate};
pub use registry::{
    Scan, ScanRegistry, ScanRequest, WalletInteraction, MAX_SCAN_NAME_LENGTH, MINING_SCAN_ID,
    PAYMENTS_SCAN_ID,
};
