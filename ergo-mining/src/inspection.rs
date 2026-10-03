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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MiningOutcome {
    pub msg: Option<[u8; 32]>,
    pub template_seq: Option<u64>,
    pub block_id: Option<[u8; 32]>,
    pub at_ms: u64,
    pub outcome: String,
    pub detail: Option<String>,
    pub accounting: Option<OutcomeAccounting>,
}

/// Cheap snapshot of a retained template. The Arc avoids copying transactions
/// and AVL proof blobs and permits formatting outside the cache lock.
#[derive(Debug, Clone)]
pub struct InspectionSnapshot {
    pub template: std::sync::Arc<crate::engine::Template>,
    pub status: &'static str,
}

/// Actual output amounts in a locally applied mined block. Canonical-chain
/// membership must be checked separately after reorgs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutcomeAccounting {
    pub height: u32,
    pub emission_nano_erg: String,
    pub fees_nano_erg: String,
    pub rent_nano_erg: String,
    pub recovered_tokens: Vec<OutcomeAsset>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutcomeAsset {
    pub token_id: String,
    pub amount: String,
}

pub(crate) fn outcome_accounting(template: &crate::engine::Template) -> OutcomeAccounting {
    let reward_script = crate::reward_script::reward_output_script(&template.work.pk);
    let plain_script = ergo_ser::address::build_p2pk_tree_bytes(&template.work.pk).ok();
    let mut emission = 0u128;
    let mut fees = 0u128;
    let mut rent = 0u128;
    let mut tokens = std::collections::BTreeMap::<[u8; 32], u128>::new();
    for (tx, observation) in template
        .candidate
        .transactions
        .iter()
        .zip(&template.candidate.observation.transactions)
    {
        for (index, output) in tx.output_candidates.iter().enumerate() {
            let amount = u128::from(output.value);
            let received = match observation.category {
                "emission" if output.ergo_tree_bytes() == reward_script => {
                    emission += amount;
                    true
                }
                "fees" if output.ergo_tree_bytes() == reward_script => {
                    fees += amount;
                    true
                }
                "rent"
                    if index + 1 == tx.output_candidates.len()
                        && plain_script.as_deref() == Some(output.ergo_tree_bytes()) =>
                {
                    rent += amount;
                    true
                }
                _ => false,
            };
            if received {
                for token in &output.tokens {
                    *tokens.entry(*token.token_id.as_bytes()).or_default() +=
                        u128::from(token.amount);
                }
            }
        }
    }
    OutcomeAccounting {
        height: template.candidate.header.height,
        emission_nano_erg: emission.to_string(),
        fees_nano_erg: fees.to_string(),
        rent_nano_erg: rent.to_string(),
        recovered_tokens: tokens
            .into_iter()
            .map(|(id, amount)| OutcomeAsset {
                token_id: hex::encode(id),
                amount: amount.to_string(),
            })
            .collect(),
    }
}
