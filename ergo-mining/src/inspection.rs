//! Frozen, operator-only observations for a mining candidate.
//!
//! These describe the transactions that survived final trimming, under the
//! candidate's original context. They are never recomputed from the live tip.

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};

use crate::reemission::ReemissionSettings;

/// Non-consensus observations retained alongside the assembled candidate.
#[derive(Debug, Clone, Default)]
pub struct CandidateObservation {
    /// `initial` or `enriched`.
    pub mode: &'static str,
    /// In exactly the same order as `Candidate::transactions`.
    pub transactions: Vec<TransactionObservation>,
    /// Materialized eligible boxes examined by this build, not a network total.
    pub rent_scanned: usize,
    /// Frozen voted fee factor for classifying rent input branches.
    pub rent_storage_fee_factor: Option<i32>,
    pub rent_skipped_preservation: usize,
    pub excluded: Vec<ExcludedTransaction>,
    /// Policy revision the engine froze for this build.
    pub policy_revision: u64,
    /// Operator queue/policy generation the engine froze for this build.
    pub operator_generation: u64,
    pub policy_requires_transactions: bool,
    /// The reward key belonged to the operator when this job was built.
    pub operator_owned: bool,
    /// Ordered IDs of the caller-supplied package, before ordinary selection.
    pub requested_ids: Vec<Digest32>,
}

/// The exact validated cost and origin of one retained transaction.
#[derive(Debug, Clone, Default)]
pub struct TransactionObservation {
    /// `emission`, `requested`, `rent`, `public`, `private`, or `fees`.
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

/// Prefix marking an operator requirement this template does not satisfy.
/// The candidate is published without it; the requirement stays in policy.
pub const REQUIRED_EXCLUSION_PREFIX: &str = "required_";

impl ExcludedTransaction {
    /// An exclusion for `reason`, prefixed with [`REQUIRED_EXCLUSION_PREFIX`]
    /// when the transaction is required (a policy ID or one of its ancestors).
    pub fn new(tx_id: Digest32, reason: &str, required: bool) -> Self {
        let reason = if required {
            format!("{REQUIRED_EXCLUSION_PREFIX}{reason}")
        } else {
            reason.to_owned()
        };
        Self { tx_id, reason }
    }
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
    /// Emission the miner keeps: the reward box value minus its EIP-27
    /// re-emission obligation.
    pub emission_nano_erg: String,
    /// The emission reward box value. Entries saved before the obligation
    /// was tracked lack it until the journal splits them at startup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emission_gross_nano_erg: Option<String>,
    /// nanoERG owed to the re-emission contract when the reward box is spent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reemission_obligation_nano_erg: Option<String>,
    pub fees_nano_erg: String,
    pub rent_nano_erg: String,
    /// Tokens the miner received, excluding re-emission tokens, which are
    /// owed back rather than received.
    pub recovered_tokens: Vec<OutcomeAsset>,
}

impl OutcomeAccounting {
    /// Entries saved before the obligation was tracked recorded the reward
    /// box value as emission and its re-emission tokens as received. Only an
    /// emission reward box carries those tokens, so their amount is the
    /// obligation; split it out exactly as a new entry records it.
    pub(crate) fn split_legacy_emission(&mut self, reemission: Option<&ReemissionSettings>) {
        if self.emission_gross_nano_erg.is_some() {
            return;
        }
        let Ok(gross) = self.emission_nano_erg.parse::<u128>() else {
            return;
        };
        let token = reemission.map(|r| hex::encode(r.reemission_token_id.as_bytes()));
        let owed = match self
            .recovered_tokens
            .iter()
            .position(|t| Some(&t.token_id) == token.as_ref())
        {
            Some(index) => match self.recovered_tokens[index].amount.parse::<u128>() {
                Ok(amount) => {
                    self.recovered_tokens.remove(index);
                    amount
                }
                Err(_) => return,
            },
            None => 0,
        };
        self.emission_nano_erg = gross.saturating_sub(owed).to_string();
        self.emission_gross_nano_erg = Some(gross.to_string());
        self.reemission_obligation_nano_erg = Some(owed.to_string());
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutcomeAsset {
    pub token_id: String,
    pub amount: String,
}

/// nanoERG owed to the EIP-27 re-emission contract when `output` is spent:
/// every spend of a box holding re-emission tokens pays 1 nanoERG per token.
/// Post-activation emission reward boxes carry them, so the miner keeps the
/// box value minus this. Zero on networks without EIP-27.
pub fn reemission_obligation(
    output: &ErgoBoxCandidate,
    reemission: Option<&ReemissionSettings>,
) -> u64 {
    let Some(settings) = reemission else {
        return 0;
    };
    let tokens = output
        .tokens
        .iter()
        .filter(|t| t.token_id == settings.reemission_token_id)
        .fold(0u64, |sum, t| sum.saturating_add(t.amount));
    // The consensus rule, for a spend at the first height after creation.
    ergo_validation::reemission_obligation_core(
        [(output.value, tokens)],
        output.creation_height.saturating_add(1),
        settings.activation_height,
    )
    .to_burn
}

pub(crate) fn outcome_accounting(
    template: &crate::engine::Template,
    reemission: Option<&ReemissionSettings>,
) -> OutcomeAccounting {
    let reward_script = crate::reward_script::reward_output_script(&template.work.pk);
    let plain_script = ergo_ser::address::build_p2pk_tree_bytes(&template.work.pk).ok();
    let mut emission = 0u128;
    let mut obligation = 0u128;
    let mut fees = 0u128;
    let mut rent = 0u128;
    let mut tokens = std::collections::BTreeMap::<[u8; 32], u128>::new();
    for (tx, observation) in template
        .candidate
        .transactions
        .iter()
        .zip(&template.candidate.observation.transactions)
    {
        let recreated = rent_recreated_indices(
            tx,
            observation,
            template.candidate.observation.rent_storage_fee_factor,
        )
        .unwrap_or_default();
        for (index, output) in tx.output_candidates.iter().enumerate() {
            let amount = u128::from(output.value);
            let received = match observation.category {
                "emission" if output.ergo_tree_bytes() == reward_script => {
                    emission += amount;
                    obligation += u128::from(reemission_obligation(output, reemission));
                    true
                }
                "fees" if output.ergo_tree_bytes() == reward_script => {
                    fees += amount;
                    true
                }
                "rent"
                    if !recreated.contains(&index)
                        && plain_script.as_deref() == Some(output.ergo_tree_bytes()) =>
                {
                    rent += amount;
                    true
                }
                _ => false,
            };
            if received {
                for token in output
                    .tokens
                    .iter()
                    .filter(|t| reemission.is_none_or(|r| t.token_id != r.reemission_token_id))
                {
                    *tokens.entry(*token.token_id.as_bytes()).or_default() +=
                        u128::from(token.amount);
                }
            }
        }
    }
    OutcomeAccounting {
        height: template.candidate.header.height,
        emission_nano_erg: emission.saturating_sub(obligation).to_string(),
        emission_gross_nano_erg: Some(emission.to_string()),
        reemission_obligation_nano_erg: Some(obligation.to_string()),
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

/// Destination indices which preserve a rent input after charging its fee.
/// Uses the frozen original boxes and voted fee factor, including the exact
/// consensus wrapping-i32 fee calculation. This remains correct when the
/// rent-distinct activation requires several miner payout boxes.
pub fn rent_recreated_indices(
    tx: &ergo_ser::transaction::Transaction,
    observation: &TransactionObservation,
    fee_factor: Option<i32>,
) -> Result<std::collections::HashSet<usize>, crate::MiningError> {
    let mut indices = std::collections::HashSet::new();
    if observation.category != "rent" {
        return Ok(indices);
    }
    for (input, original) in tx.inputs.iter().zip(&observation.resolved_inputs) {
        let destination =
            input
                .spending_proof
                .extension()
                .values
                .get(&127)
                .and_then(|(_, value)| match value {
                    ergo_ser::sigma_value::SigmaValue::Short(i) => usize::try_from(*i).ok(),
                    _ => None,
                });
        let Some(destination) = destination else {
            continue;
        };
        let Some(output) = tx.output_candidates.get(destination) else {
            continue;
        };
        let recreates = match fee_factor {
            Some(factor) => {
                let serialized = ergo_ser::ergo_box::serialize_ergo_box(original).map_err(|e| {
                    crate::MiningError::IdComputation {
                        op: "rent_inspection",
                        reason: e.to_string(),
                    }
                })?;
                let fee = ergo_validation::storage_rent::compute_storage_fee(
                    serialized.len() as i32,
                    factor,
                );
                fee > 0 && original.candidate.value > fee as u64
            }
            None => {
                output.value < original.candidate.value
                    && output.ergo_tree_bytes() == original.candidate.ergo_tree_bytes()
                    && output.tokens == original.candidate.tokens
            }
        };
        if recreates {
            indices.insert(destination);
        }
    }
    Ok(indices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{BuildReason, Template, TemplateIdentity};
    use crate::work_message::WorkMessage;
    use ergo_primitives::digest::{Digest32, ModifierId};
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::token::Token;
    // ----- helpers -----
    const PK: [u8; 33] = [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];
    fn rent_template() -> Template {
        let pk = PK;
        let tree_bytes = ergo_ser::address::build_p2pk_tree_bytes(&pk).unwrap();
        let tree = ergo_ser::ergo_tree::read_ergo_tree(
            &mut ergo_primitives::reader::VlqReader::new(&tree_bytes),
        )
        .unwrap();
        let boxes: Vec<_> = [10_000_000_000, 1_000_000, 1_000_000]
            .into_iter()
            .enumerate()
            .map(|(index, value)| ErgoBox {
                candidate: ErgoBoxCandidate::new(
                    value,
                    tree.clone(),
                    0,
                    if index == 1 {
                        vec![Token {
                            token_id: Digest32::from_bytes([7; 32]),
                            amount: 3,
                        }]
                    } else {
                        Vec::new()
                    },
                    AdditionalRegisters::empty(),
                )
                .unwrap(),
                transaction_id: ModifierId::from_bytes([index as u8 + 1; 32]),
                index: 0,
            })
            .collect();
        let height = ergo_validation::storage_rent::DISTINCT_RENT_OUTPUTS_ACTIVATION_HEIGHT;
        let mut params = ergo_validation::ProtocolParams::mainnet_default();
        params.storage_period = 10;
        let claim =
            crate::storage_rent_claim::build_rent_claim(&boxes, height, &params, 64, &pk, None)
                .unwrap()
                .unwrap();
        assert_eq!(claim.tx.output_candidates.len(), 3);
        let observation = CandidateObservation {
            mode: "enriched",
            rent_storage_fee_factor: Some(params.storage_fee_factor),
            transactions: vec![TransactionObservation {
                category: "rent",
                resolved_inputs: claim.resolved_inputs,
                ..Default::default()
            }],
            ..Default::default()
        };
        template(height, claim.tx, observation)
    }
    /// A one-transaction template mined at `height` by [`PK`].
    fn template(
        height: u32,
        tx: ergo_ser::transaction::Transaction,
        observation: CandidateObservation,
    ) -> Template {
        let pk = PK;
        let mut header = crate::genesis::parent_header();
        header.height = height;
        let validation_ctx = ergo_validation::pre_header::CandidateValidationContext {
            pre_header: ergo_validation::pre_header::CandidatePreHeader {
                version: header.version,
                parent_id: [0; 32],
                height,
                timestamp: header.timestamp,
                n_bits: header.n_bits,
                votes: header.votes,
                miner_pubkey: pk,
            },
            activated_script_version: 0,
            last_headers: Vec::new(),
            last_block_utxo_root: ergo_validation::pre_header::build_last_block_utxo_root(
                header.state_root,
            ),
        };
        Template {
            candidate: crate::candidate::Candidate {
                header,
                validation_ctx,
                transactions: vec![tx],
                ad_proof_bytes: Vec::new(),
                extension_fields: Vec::new(),
                msg: [1; 32],
                target: 1u8.into(),
                parent_id: [0; 32],
                observation,
            },
            work: WorkMessage {
                msg: [1; 32],
                target: 1u8.into(),
                height,
                pk,
                proof: None,
                metrics: Default::default(),
            },
            identity: TemplateIdentity {
                template_id: [1; 32],
                parent_id: [0; 32],
                chain_seq: 1,
                template_seq: 1,
                clean_jobs: true,
                built_at_ms: 100,
                reason: BuildReason::Tip,
            },
        }
    }
    // ----- happy path -----
    #[test]
    fn rent_inspection_distinguishes_owner_recreation_and_multiple_miner_payouts() {
        let template = rent_template();
        let tx = &template.candidate.transactions[0];
        let observation = &template.candidate.observation.transactions[0];
        let recreated = rent_recreated_indices(
            tx,
            observation,
            template.candidate.observation.rent_storage_fee_factor,
        )
        .unwrap();
        assert_eq!(recreated, std::collections::HashSet::from([0]));
        let amounts = outcome_accounting(&template, Some(&ReemissionSettings::mainnet()));
        let input_total: u128 = observation
            .resolved_inputs
            .iter()
            .map(|b| u128::from(b.candidate.value))
            .sum();
        assert_eq!(
            amounts.rent_nano_erg,
            (input_total - u128::from(tx.output_candidates[0].value)).to_string()
        );
        assert_eq!(amounts.recovered_tokens.len(), 1);
        assert_eq!(amounts.recovered_tokens[0].amount, "3");
        assert_eq!(amounts.emission_nano_erg, "0");
    }

    /// The EIP-27-era emission at `height` from a mainnet-shaped emission box
    /// (NFT plus re-emission stash), as the candidate builder assembles it.
    fn eip27_emission_template(height: u32) -> Template {
        let reemission = ReemissionSettings::mainnet();
        let tree_bytes = ergo_ser::address::build_p2pk_tree_bytes(&PK).unwrap();
        let tree = ergo_ser::ergo_tree::read_ergo_tree(
            &mut ergo_primitives::reader::VlqReader::new(&tree_bytes),
        )
        .unwrap();
        let emission_box = ErgoBox {
            candidate: ErgoBoxCandidate::new(
                10_000_000_000_000_000,
                tree,
                height - 1,
                vec![
                    Token {
                        token_id: reemission.emission_nft_id,
                        amount: 1,
                    },
                    Token {
                        token_id: reemission.reemission_token_id,
                        amount: 10_000_000_000_000_000,
                    },
                ],
                AdditionalRegisters::empty(),
            )
            .unwrap(),
            transaction_id: ModifierId::from_bytes([9; 32]),
            index: 0,
        };
        let tx = crate::reemission::build_post_eip27_emission_tx(
            &emission_box,
            &PK,
            height,
            &crate::MonetarySettings::mainnet(),
            &reemission,
        )
        .unwrap();
        let observation = CandidateObservation {
            mode: "initial",
            transactions: vec![TransactionObservation {
                category: "emission",
                resolved_inputs: vec![emission_box],
                ..Default::default()
            }],
            ..Default::default()
        };
        template(height, tx, observation)
    }

    #[test]
    fn eip27_reward_box_counts_only_what_the_miner_keeps() {
        // A 12 ERG reward box carries 9 ERG worth of re-emission tokens; the
        // spend that unlocks it must pay those 9 ERG to re-emission.
        let height = 1_850_000;
        let reemission = ReemissionSettings::mainnet();
        let monetary = crate::MonetarySettings::mainnet();
        let gross = crate::miners_reward_at_height(height, &monetary);
        let owed = crate::reemission::reemission_for_height(height, &monetary, &reemission);
        assert_eq!((gross, owed), (12_000_000_000, 9_000_000_000));
        let template = eip27_emission_template(height);
        let reward_box = &template.candidate.transactions[0].output_candidates[1];
        assert_eq!(reward_box.value, gross);
        assert_eq!(reemission_obligation(reward_box, Some(&reemission)), owed);

        let accounting = outcome_accounting(&template, Some(&reemission));
        assert_eq!(accounting.emission_nano_erg, "3000000000");
        assert_eq!(
            accounting.emission_gross_nano_erg.as_deref(),
            Some("12000000000")
        );
        assert_eq!(
            accounting.reemission_obligation_nano_erg.as_deref(),
            Some("9000000000")
        );
        assert!(
            accounting.recovered_tokens.is_empty(),
            "re-emission tokens are owed, not received: {:?}",
            accounting.recovered_tokens
        );

        // An entry saved before the split carries the same split after load.
        let mut legacy = OutcomeAccounting {
            emission_nano_erg: gross.to_string(),
            emission_gross_nano_erg: None,
            reemission_obligation_nano_erg: None,
            recovered_tokens: vec![OutcomeAsset {
                token_id: hex::encode(reemission.reemission_token_id.as_bytes()),
                amount: owed.to_string(),
            }],
            ..accounting.clone()
        };
        legacy.split_legacy_emission(Some(&reemission));
        assert_eq!(
            serde_json::to_value(&legacy).unwrap(),
            serde_json::to_value(&accounting).unwrap()
        );
    }
}
