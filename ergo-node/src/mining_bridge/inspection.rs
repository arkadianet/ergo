//! Format an immutable cached template outside the mining-cache lock.

use std::collections::BTreeMap;

use ergo_api::mining::MiningApiError;
use ergo_mining::inspection::InspectionSnapshot;
#[cfg(test)]
use ergo_primitives::digest::Digest32;
use ergo_primitives::writer::VlqWriter;
use ergo_rest_json::mining_inspection::*;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::token::Token;
use ergo_ser::transaction::{transaction_id, write_transaction};

fn internal(error: impl std::fmt::Display) -> MiningApiError {
    MiningApiError::Internal(format!("candidate inspection: {error}"))
}

fn assets(tokens: &[Token]) -> Vec<MiningAssetJson> {
    tokens
        .iter()
        .map(|t| MiningAssetJson {
            token_id: hex::encode(t.token_id.as_bytes()),
            amount: t.amount.to_string(),
        })
        .collect()
}

fn token_totals<'a>(tokens: impl Iterator<Item = &'a Token>) -> BTreeMap<[u8; 32], u128> {
    let mut totals = BTreeMap::new();
    for token in tokens {
        *totals.entry(*token.token_id.as_bytes()).or_insert(0) += u128::from(token.amount);
    }
    totals
}

fn total_assets(totals: BTreeMap<[u8; 32], u128>) -> Vec<MiningAssetJson> {
    totals
        .into_iter()
        .filter(|(_, amount)| *amount > 0)
        .map(|(id, amount)| MiningAssetJson {
            token_id: hex::encode(id),
            amount: amount.to_string(),
        })
        .collect()
}

/// Format only the frozen candidate: current state/indexer reads would make a
/// report disagree with the work a miner is actually hashing. `reemission`
/// prices the EIP-27 obligation an emission reward box carries.
pub(super) fn candidate_details(
    snapshot: InspectionSnapshot,
    network: ergo_ser::address::NetworkPrefix,
    reemission: Option<&ergo_mining::reemission::ReemissionSettings>,
    now_ms: u64,
) -> Result<CandidateDetailsJson, MiningApiError> {
    let template = snapshot.template;
    let candidate = &template.candidate;
    let pk = template.work.pk;
    let delayed_script = ergo_mining::reward_script::reward_output_script(&pk);
    let plain_script = ergo_ser::address::build_p2pk_tree_bytes(&pk).map_err(internal)?;
    let mut transactions = Vec::with_capacity(candidate.transactions.len());
    let mut proceeds = Vec::new();
    let mut emission_total = 0u128;
    let mut obligation_total = 0u128;
    let mut fees_total = 0u128;
    let mut rent_total = 0u128;
    let mut rent = RentBreakdownJson {
        scanned_boxes: candidate.observation.rent_scanned,
        skipped_to_preserve_tokens: candidate.observation.rent_skipped_preservation,
        collected_nano_erg: "0".into(),
        ..Default::default()
    };

    for (index, tx) in candidate.transactions.iter().enumerate() {
        let observation = candidate.observation.transactions.get(index);
        let category = observation.map_or("unknown", |o| o.category);
        let recreated_indices = observation
            .map(|o| {
                ergo_mining::inspection::rent_recreated_indices(
                    tx,
                    o,
                    candidate.observation.rent_storage_fee_factor,
                )
            })
            .transpose()
            .map_err(internal)?
            .unwrap_or_default();
        let id = transaction_id(tx).map_err(internal)?;
        let id_hex = hex::encode(id.as_bytes());
        let mut writer = VlqWriter::new();
        write_transaction(&mut writer, tx).map_err(internal)?;
        let bytes = writer.result();
        let mut outputs = Vec::with_capacity(tx.output_candidates.len());
        for (output_index, output) in tx.output_candidates.iter().enumerate() {
            let output_box = ErgoBox {
                candidate: output.clone(),
                transaction_id: id,
                index: u16::try_from(output_index).map_err(internal)?,
            };
            let box_id = hex::encode(output_box.box_id().map_err(internal)?.as_bytes());
            let output_assets = assets(&output.tokens);
            outputs.push(CandidateOutputJson {
                index: output_index,
                box_id: box_id.clone(),
                value_nano_erg: output.value.to_string(),
                creation_height: output.creation_height,
                ergo_tree: hex::encode(output.ergo_tree_bytes()),
                assets: output_assets.clone(),
            });
            let is_proceeds = match category {
                "emission" | "fees" => output.ergo_tree_bytes() == delayed_script.as_slice(),
                "rent" => {
                    output.ergo_tree_bytes() == plain_script.as_slice()
                        && !recreated_indices.contains(&output_index)
                }
                _ => false,
            };
            if is_proceeds {
                let amount = u128::from(output.value);
                match category {
                    "emission" => {
                        emission_total += amount;
                        obligation_total += u128::from(
                            ergo_mining::inspection::reemission_obligation(output, reemission),
                        );
                    }
                    "fees" => fees_total += amount,
                    "rent" => rent_total += amount,
                    _ => {}
                }
                proceeds.push(MinerProceedsJson {
                    category: category.into(),
                    transaction_id: id_hex.clone(),
                    output_index,
                    box_id,
                    value_nano_erg: output.value.to_string(),
                    address: ergo_ser::address::encode_address(
                        network,
                        output.ergo_tree(),
                        output.ergo_tree_bytes(),
                    ),
                    assets: output_assets,
                    spendable_at_height: output
                        .creation_height
                        .saturating_add(if category == "rent" { 0 } else { 720 }),
                });
            }
        }
        if category == "rent" {
            if let Some(observation) = observation {
                let inputs = &observation.resolved_inputs;
                rent.selected_boxes = inputs.len();
                for (input, original) in tx.inputs.iter().zip(inputs) {
                    let destination =
                        input
                            .spending_proof
                            .extension()
                            .values
                            .get(&127)
                            .and_then(|(_, value)| match value {
                                SigmaValue::Short(i) => usize::try_from(*i).ok(),
                                _ => None,
                            });
                    let recreated = destination.filter(|i| recreated_indices.contains(i));
                    let collected = recreated
                        .and_then(|i| tx.output_candidates.get(i))
                        .map_or(original.candidate.value, |o| {
                            original.candidate.value.saturating_sub(o.value)
                        });
                    if recreated.is_some() {
                        rent.recreated_boxes += 1;
                    } else {
                        rent.consumed_boxes += 1;
                    }
                    rent.claims.push(RentInputJson {
                        box_id: hex::encode(input.box_id.as_bytes()),
                        creation_height: original.candidate.creation_height,
                        age_blocks: candidate
                            .header
                            .height
                            .saturating_sub(original.candidate.creation_height),
                        input_value_nano_erg: original.candidate.value.to_string(),
                        collected_nano_erg: collected.to_string(),
                        branch: if recreated.is_some() {
                            "recreate"
                        } else {
                            "consume"
                        }
                        .into(),
                        recreated_output_index: recreated,
                        input_assets: assets(&original.candidate.tokens),
                    });
                }
                let all_inputs = token_totals(inputs.iter().flat_map(|b| &b.candidate.tokens));
                let all_outputs = token_totals(tx.output_candidates.iter().flat_map(|b| &b.tokens));
                rent.burned_tokens = total_assets(
                    all_inputs
                        .into_iter()
                        .map(|(id, amount)| {
                            (
                                id,
                                amount.saturating_sub(*all_outputs.get(&id).unwrap_or(&0)),
                            )
                        })
                        .collect(),
                );
                rent.recovered_tokens = total_assets(token_totals(
                    tx.output_candidates
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| !recreated_indices.contains(i))
                        .flat_map(|(_, b)| &b.tokens),
                ));
            }
        }
        transactions.push(CandidateTransactionJson {
            index,
            id: id_hex,
            category: category.into(),
            fee_nano_erg: observation.map_or(0, |o| o.fee_nano_erg).to_string(),
            size_bytes: bytes.len(),
            validation_cost: observation.map(|o| o.validation_cost),
            input_ids: tx
                .inputs
                .iter()
                .map(|i| hex::encode(i.box_id.as_bytes()))
                .collect(),
            data_input_ids: tx
                .data_inputs
                .iter()
                .map(|i| hex::encode(i.box_id.as_bytes()))
                .collect(),
            outputs,
            bytes: hex::encode(bytes),
        });
    }
    rent.collected_nano_erg = rent_total.to_string();
    // EIP-27: spending the reward box pays its re-emission tokens' worth back.
    let emission_kept = emission_total.saturating_sub(obligation_total);
    let identity = &template.identity;
    let metrics = &template.work.metrics;
    Ok(CandidateDetailsJson {
        msg: hex::encode(candidate.msg),
        template_seq: identity.template_seq,
        parent_id: hex::encode(candidate.parent_id),
        height: candidate.header.height,
        status: snapshot.status.into(),
        published_at_ms: identity.built_at_ms,
        age_ms: now_ms.saturating_sub(identity.built_at_ms),
        build_reason: format!("{:?}", identity.reason),
        build_mode: if candidate.observation.mode.is_empty() {
            "unknown"
        } else {
            candidate.observation.mode
        }
        .into(),
        metrics: ergo_rest_json::mining::CandidateMetricsJson {
            transaction_count: metrics.transaction_count,
            selected_transaction_count: metrics.selected_transaction_count,
            fees_nano_erg: metrics.fees_nano_erg.to_string(),
            transactions_size_bytes: metrics.transactions_size_bytes,
            max_block_size_bytes: metrics.max_block_size_bytes,
            validation_cost: metrics.validation_cost,
            max_block_cost: metrics.max_block_cost,
        },
        votes: candidate.header.votes,
        extensions: candidate
            .extension_fields
            .iter()
            .map(|(k, v)| ExtensionPreviewJson {
                key: hex::encode(k),
                value: hex::encode(v),
            })
            .collect(),
        transactions,
        rewards: RewardBreakdownJson {
            emission_nano_erg: emission_kept.to_string(),
            emission_gross_nano_erg: emission_total.to_string(),
            reemission_obligation_nano_erg: obligation_total.to_string(),
            fees_nano_erg: fees_total.to_string(),
            rent_nano_erg: rent_total.to_string(),
            total_nano_erg: (emission_kept + fees_total + rent_total).to_string(),
            outputs: proceeds,
        },
        rent,
        exclusions: candidate
            .observation
            .excluded
            .iter()
            .map(|e| CandidateExclusionJson {
                transaction_id: hex::encode(e.tx_id.as_bytes()),
                reason: e.reason.clone(),
            })
            .collect(),
        policy_revision: candidate.observation.policy_revision,
        operator_generation: candidate.observation.operator_generation,
    })
}

pub(super) fn parse_msg(value: Option<String>) -> Result<Option<[u8; 32]>, MiningApiError> {
    value
        .map(|value| {
            let bytes = hex::decode(&value).map_err(|_| {
                MiningApiError::BadRequest("msg must be 64 hexadecimal characters".into())
            })?;
            bytes
                .try_into()
                .map_err(|_| MiningApiError::BadRequest("msg must be 32 bytes".into()))
        })
        .transpose()
}

pub(super) fn summary(snapshot: InspectionSnapshot) -> TemplateSummaryJson {
    let t = snapshot.template;
    TemplateSummaryJson {
        msg: hex::encode(t.candidate.msg),
        template_seq: t.identity.template_seq,
        parent_id: hex::encode(t.candidate.parent_id),
        height: t.candidate.header.height,
        published_at_ms: t.identity.built_at_ms,
        status: snapshot.status.into(),
        build_reason: format!("{:?}", t.identity.reason),
        build_mode: t.candidate.observation.mode.into(),
        transaction_count: t.work.metrics.transaction_count,
        fees_nano_erg: t.work.metrics.fees_nano_erg.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // ----- error paths -----
    #[test]
    fn inspection_selector_rejects_malformed_ids() {
        assert!(parse_msg(Some("ab".into())).is_err());
        assert!(parse_msg(Some("zz".repeat(32))).is_err());
        assert_eq!(parse_msg(Some("ab".repeat(32))).unwrap(), Some([0xab; 32]));
    }
    // ----- happy path -----
    #[test]
    fn inspection_assets_sum_without_browser_precision_loss() {
        let id = Digest32::from_bytes([7; 32]);
        let tokens = [
            Token {
                token_id: id,
                amount: u64::MAX,
            },
            Token {
                token_id: id,
                amount: 2,
            },
        ];
        assert_eq!(
            total_assets(token_totals(tokens.iter()))[0].amount,
            "18446744073709551617"
        );
    }

    /// An initial template whose emission spends a mainnet-shaped EIP-27
    /// emission box (NFT plus re-emission stash) at `height`.
    fn eip27_emission_snapshot(height: u32, pk: [u8; 33]) -> InspectionSnapshot {
        use ergo_mining::reemission::ReemissionSettings;
        use ergo_primitives::digest::{ADDigest, ModifierId};
        let reemission = ReemissionSettings::mainnet();
        let tree_bytes = ergo_ser::address::build_p2pk_tree_bytes(&pk).unwrap();
        let tree = ergo_ser::ergo_tree::read_ergo_tree(
            &mut ergo_primitives::reader::VlqReader::new(&tree_bytes),
        )
        .unwrap();
        let emission_box = ErgoBox {
            candidate: ergo_ser::ergo_box::ErgoBoxCandidate::new(
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
                ergo_ser::register::AdditionalRegisters::empty(),
            )
            .unwrap(),
            transaction_id: ModifierId::from_bytes([9; 32]),
            index: 0,
        };
        let tx = ergo_mining::reemission::build_post_eip27_emission_tx(
            &emission_box,
            &pk,
            height,
            &ergo_mining::MonetarySettings::mainnet(),
            &reemission,
        )
        .unwrap();
        let header = ergo_ser::header::Header {
            version: 3,
            parent_id: ModifierId::from_bytes([1; 32]),
            ad_proofs_root: Digest32::from_bytes([0; 32]),
            transactions_root: Digest32::from_bytes([0; 32]),
            state_root: ADDigest::from_bytes([0; 33]),
            timestamp: 1_700_000_000_000,
            extension_root: Digest32::from_bytes([0; 32]),
            n_bits: 0x0101_0000,
            height,
            votes: [0; 3],
            unparsed_bytes: Vec::new(),
            solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from(pk),
                nonce: [0; 8],
            },
        };
        let validation_ctx = ergo_validation::pre_header::CandidateValidationContext {
            pre_header: ergo_validation::pre_header::CandidatePreHeader {
                version: header.version,
                parent_id: [1; 32],
                height,
                timestamp: header.timestamp,
                n_bits: header.n_bits,
                votes: header.votes,
                miner_pubkey: pk,
            },
            activated_script_version: 2,
            last_headers: Vec::new(),
            last_block_utxo_root: ergo_validation::pre_header::build_last_block_utxo_root(
                header.state_root,
            ),
        };
        let observation = ergo_mining::inspection::CandidateObservation {
            mode: "initial",
            transactions: vec![ergo_mining::inspection::TransactionObservation {
                category: "emission",
                resolved_inputs: vec![emission_box],
                ..Default::default()
            }],
            ..Default::default()
        };
        InspectionSnapshot {
            template: std::sync::Arc::new(ergo_mining::engine::Template {
                candidate: ergo_mining::candidate::Candidate {
                    header,
                    validation_ctx,
                    observation,
                    transactions: vec![tx],
                    ad_proof_bytes: Vec::new(),
                    extension_fields: Vec::new(),
                    msg: [2; 32],
                    target: 1u8.into(),
                    parent_id: [1; 32],
                },
                work: ergo_mining::work_message::WorkMessage {
                    msg: [2; 32],
                    target: 1u8.into(),
                    height,
                    pk,
                    metrics: Default::default(),
                },
                identity: ergo_mining::engine::TemplateIdentity {
                    template_id: [2; 32],
                    parent_id: [1; 32],
                    chain_seq: 1,
                    template_seq: 1,
                    clean_jobs: true,
                    built_at_ms: 0,
                    reason: ergo_mining::engine::BuildReason::Tip,
                },
            }),
            status: "current",
        }
    }

    #[test]
    fn eip27_rewards_count_only_the_emission_the_miner_keeps() {
        // At this height the 12 ERG reward box owes 9 ERG to re-emission.
        let pk: [u8; 33] =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .try_into()
                .unwrap();
        let reemission = ergo_mining::reemission::ReemissionSettings::mainnet();
        let details = candidate_details(
            eip27_emission_snapshot(1_850_000, pk),
            ergo_ser::address::NetworkPrefix::Mainnet,
            Some(&reemission),
            0,
        )
        .unwrap();
        let rewards = &details.rewards;
        assert_eq!(rewards.emission_gross_nano_erg, "12000000000");
        assert_eq!(rewards.reemission_obligation_nano_erg, "9000000000");
        assert_eq!(rewards.emission_nano_erg, "3000000000");
        assert_eq!(rewards.total_nano_erg, "3000000000");
        // The payout box itself is reported as it is.
        assert_eq!(rewards.outputs.len(), 1);
        assert_eq!(rewards.outputs[0].value_nano_erg, "12000000000");

        // Without EIP-27 settings the same box would be all income.
        let plain = candidate_details(
            eip27_emission_snapshot(1_850_000, pk),
            ergo_ser::address::NetworkPrefix::Mainnet,
            None,
            0,
        )
        .unwrap();
        assert_eq!(plain.rewards.reemission_obligation_nano_erg, "0");
        assert_eq!(plain.rewards.total_nano_erg, "12000000000");
    }
}
