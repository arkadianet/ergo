//! Optional validation observer for the executor.
//!
//! The node's Phase 0 telemetry hook needs header-validation completion
//! timestamps. Rather than teach `ergo-sync` about `ergo-net-observe`
//! (and pull its sink/tokio surface into the sync crate), the executor
//! accepts a tiny callback trait. The default is `None`; when absent the
//! executor behaves exactly as before.
//!
//! Implementations run inline on the executor task, so they must be
//! cheap and must not block. The node hook only performs a bounded map
//! lookup and a non-blocking channel send.

use std::sync::Arc;

/// Receives a header id after it has been fully validated and installed.
pub trait ValidationObserver: Send + Sync {
    /// The header is on the best-header tree after PoW, linkage, and
    /// persistence succeeded.
    fn on_header_validated(&self, header_id: [u8; 32], height: u32);
}

/// Type-erased observer slot used by [`super::SyncExecutor`].
pub type SharedValidationObserver = Arc<dyn ValidationObserver>;
