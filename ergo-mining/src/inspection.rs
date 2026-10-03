//! Frozen, operator-only observations for a mining candidate.
//!
//! These describe the transactions that survived final trimming, under the
//! candidate's original context. They are never recomputed from the live tip.

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;

/// Non-consensus observations retained alongside the assembled candidate.
#[derive(Debug, Clone, Default)]
pub struct CandidateObservation {
    /// `initial` or `enriched`.
    pub mode: &'static str,
    /// In exactly the same order as `Candidate::transactions`.
    pub transactions: Vec<TransactionObservation>,
    /// Materialized eligible boxes examined by this build, not a network total.
    pub rent_scanned: usize,
    pub rent_skipped_preservation: usize,
    pub excluded: Vec<ExcludedTransaction>,
    /// Policy revision the engine froze for this build.
    pub policy_revision: u64,
    /// Operator queue/policy generation the engine froze for this build.
    pub operator_generation: u64,
    pub policy_requires_transactions: bool,
}

/// The exact validated cost and origin of one retained transaction.
#[derive(Debug, Clone, Default)]
pub struct TransactionObservation {
    /// `emission`, `rent`, `public`, `private`, or `fees`.
    pub category: &'static str,
    pub validation_cost: u64,
    pub fee_nano_erg: u64,
    /// Resolved boxes at build time. System transactions retain these to
    /// explain rent collection and miner proceeds; ordinary txs may omit them.
    pub resolved_inputs: Vec<ErgoBox>,
}

/// A transaction considered but excluded from the final template.
#[derive(Debug, Clone)]
pub struct ExcludedTransaction {
    pub tx_id: Digest32,
    pub reason: String,
}

/// One bounded lifecycle observation. This is local diagnostics, not a durable
/// accounting ledger or evidence that a block remains on the canonical chain.
#[derive(Debug, Clone)]
pub struct MiningOutcome {
    pub msg: Option<[u8; 32]>,
    pub template_seq: Option<u64>,
    pub block_id: Option<[u8; 32]>,
    pub at_ms: u64,
    pub outcome: String,
    pub detail: Option<String>,
}

/// Cheap snapshot of a retained template. The Arc avoids copying transactions
/// and AVL proof blobs and permits formatting outside the cache lock.
#[derive(Debug, Clone)]
pub struct InspectionSnapshot {
    pub template: std::sync::Arc<crate::engine::Template>,
    pub status: &'static str,
}
