//! The `/scan/*` wallet subsystem (Scala scanning API).
//!
//! Covers the tracking-rule predicate language ([`predicate`]) and the scan
//! [`registry`] (model + id allocation + CRUD); the block-apply matcher and
//! the remaining HTTP endpoints are not yet implemented.

pub mod predicate;
pub mod registry;

pub use predicate::{ScanRegister, ScanningPredicate};
pub use registry::{
    Scan, ScanRegistry, ScanRequest, WalletInteraction, MAX_SCAN_NAME_LENGTH, MINING_SCAN_ID,
    PAYMENTS_SCAN_ID,
};
