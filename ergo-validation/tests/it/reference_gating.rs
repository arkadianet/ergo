//! Transaction rule settings from the reference node validator.
use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::read_ergo_box;
use ergo_ser::transaction::read_transaction;
use ergo_validation::context::{ProtocolParams, TransactionContext};
use ergo_validation::tx::validate_transaction_parsed;
use ergo_validation::ReemissionRuleInputs;
use ergo_validation::{TxValidationCtx, TxValidationRules};

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    disabled: Vec<u16>,
    data_boxes: Vec<String>,
    tx: String,
    boxes: Vec<String>,
    accept: bool,
    tx_parse_accept: bool,
    boxes_parse_accept: bool,
    cost: Option<u64>,
}
#[derive(serde::Deserialize)]
struct Oracle {
    entries: Vec<Case>,
}

#[test]
fn transaction_rule_gating_matches_reference() {
    let oracle: Oracle = serde_json::from_str(include_str!(
        "../../../test-vectors/reference-6.0.7/rule-gating/transactions.json"
    ))
    .unwrap();
    let spec = ergo_chain_spec::ChainSpec::mainnet();
    let mut disagreements = Vec::new();
    for case in oracle.entries {
        let rules = ReemissionRuleInputs::from_chain_spec(&spec, true).unwrap();
        let bytes = hex::decode(case.tx).unwrap();
        let parsed = read_transaction(&mut VlqReader::new(&bytes));
        assert_eq!(
            parsed.is_ok(),
            case.tx_parse_accept,
            "{} transaction parsing",
            case.name
        );
        let Ok(tx) = parsed else {
            assert!(!case.accept);
            continue;
        };
        let boxes: Result<Vec<_>, _> = case
            .boxes
            .iter()
            .map(|h| read_ergo_box(&mut VlqReader::new(&hex::decode(h).unwrap())))
            .collect();
        assert_eq!(
            boxes.is_ok(),
            case.boxes_parse_accept,
            "{} input parsing",
            case.name
        );
        let Ok(boxes) = boxes else {
            assert!(!case.accept);
            continue;
        };
        let mut params = ProtocolParams {
            max_block_cost: 1_000_000,
            block_version: 4,
            ..ProtocolParams::mainnet_default()
        };
        let active = ergo_validation::scala_launch();
        let settings = ergo_validation::ErgoValidationSettings {
            update_from_initial: ergo_validation::ErgoValidationSettingsUpdate {
                rules_to_disable: case.disabled.clone(),
                status_updates: vec![],
            },
        };
        let mut configured =
            ergo_validation::context::ProtocolParams::from_active_with_settings(&active, &settings);
        configured.max_block_cost = params.max_block_cost;
        configured.block_version = params.block_version;
        params = configured;
        let data_boxes = case
            .data_boxes
            .iter()
            .map(|h| read_ergo_box(&mut VlqReader::new(&hex::decode(h).unwrap())).unwrap())
            .collect();
        let ctx = TransactionContext {
            height: 1885000,
            miner_pubkey: hex::decode(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            pre_header_timestamp: 0,
            activated_script_version: 3,
            pre_header_version: 4,
            pre_header_parent_id: [0; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0; 3],
        };
        let mut cost =
            CostAccumulator::new(JitCost::from_block_cost(params.max_block_cost).unwrap());
        let mut cx = TxValidationCtx {
            ctx: &ctx,
            params: &params,
            cost: &mut cost,
            last_headers: &[],
            rules: TxValidationRules {
                reemission: Some(&rules),
            },
        };
        let result = validate_transaction_parsed(tx, &bytes, boxes, data_boxes, false, &mut cx);
        println!(
            "{}\t{}\t{}\t{:?}",
            case.name,
            result.is_ok(),
            cost.total_block_cost(),
            result.as_ref().err()
        );
        if result.is_ok() != case.accept
            || (result.is_ok() && Some(cost.total_block_cost()) != case.cost)
        {
            disagreements.push(case.name);
        }
    }
    assert!(
        disagreements.is_empty(),
        "reference disagreements: {disagreements:?}"
    );
}

#[derive(serde::Deserialize)]
struct Field {
    key: String,
    value: String,
}
#[derive(serde::Deserialize)]
struct BlockCase {
    name: String,
    rule: u16,
    missing: u8,
    cost: Option<u64>,
    disabled: Vec<u16>,
    epoch: bool,
    parent: String,
    header: String,
    fields: Vec<Field>,
    parent_fields: Option<Vec<Field>>,
    no_parent: bool,
    accept: bool,
    adopted_disabled: Option<Vec<u16>>,
}
#[derive(serde::Deserialize)]
struct BlockOracle {
    tx: String,
    boxes: Vec<String>,
    entries: Vec<BlockCase>,
}

fn fields(fs: Vec<Field>) -> Vec<ergo_ser::extension::ExtensionField> {
    fs.into_iter()
        .map(|f| ergo_ser::extension::ExtensionField {
            key: hex::decode(f.key).unwrap().try_into().unwrap(),
            value: hex::decode(f.value).unwrap(),
        })
        .collect()
}

#[test]
fn block_rule_gating_matches_reference() {
    use ergo_primitives::digest::{Digest32, ModifierId};
    use ergo_ser::{
        block_transactions::BlockTransactions, extension::Extension, header::read_header,
    };
    use ergo_validation::block::{
        validate_full_block_parallel_with_costs, validate_full_block_with_costs,
        BlockValidationContext, SoftForkState,
    };
    use ergo_validation::header::CheckedHeader;
    use ergo_validation::voting::{validate_epoch_extension, VotingSettings};
    use ergo_validation::{scala_launch, ErgoValidationSettings, ErgoValidationSettingsUpdate};
    let oracle: BlockOracle = serde_json::from_str(include_str!(
        "../../../test-vectors/reference-6.0.7/rule-gating/blocks.json"
    ))
    .unwrap();
    let tx = read_transaction(&mut VlqReader::new(&hex::decode(oracle.tx).unwrap())).unwrap();
    let boxes: Vec<_> = oracle
        .boxes
        .iter()
        .map(|h| read_ergo_box(&mut VlqReader::new(&hex::decode(h).unwrap())).unwrap())
        .collect();
    let utxo = super::synthetic_block::MapUtxo::of(&boxes.iter().collect::<Vec<_>>());
    for case in oracle.entries {
        let parent = read_header(&mut VlqReader::new(&hex::decode(case.parent).unwrap())).unwrap();
        let mut header =
            read_header(&mut VlqReader::new(&hex::decode(case.header).unwrap())).unwrap();
        let settings = ErgoValidationSettings::empty().updated(&ErgoValidationSettingsUpdate {
            rules_to_disable: case.disabled,
            status_updates: vec![],
        });
        let mut previous = scala_launch();
        previous.epoch_start_height = 1884160;
        previous.block_version = 4;
        previous.subblocks_per_block = Some(30);
        if case.rule == 306 {
            if case.missing == 3 {
                previous.missing_core_parameters |= 1 << 2;
            }
            previous.max_block_size = 0;
        }
        let fork_state = (case.rule == 407).then_some(SoftForkState {
            starting_height: header.height - 32768,
            votes_collected: 0,
            voting_length: 1024,
            soft_fork_epochs: 32,
            activation_epochs: 32,
            approved: false,
        });
        let id = ModifierId::from_bytes([0x5a; 32]);
        let extension = Extension {
            header_id: id,
            fields: fields(case.fields),
        };
        let parent_ext = case.parent_fields.map(|fs| Extension {
            header_id: ModifierId::from_bytes([0x11; 32]),
            fields: fields(fs),
        });
        if case.no_parent {
            let result = ergo_validation::block::validate_interlinks_with_settings(
                &extension,
                &header,
                None,
                parent_ext.as_ref(),
                &settings,
            );
            assert_eq!(
                result.is_ok(),
                case.accept,
                "{} optional prior context",
                case.name
            );
            continue;
        }
        let voted = if case.epoch {
            match validate_epoch_extension(
                &extension,
                &header,
                &previous,
                &settings,
                &[],
                &VotingSettings::mainnet(),
                false,
            ) {
                Ok(outcome) => {
                    if let Some(expected) = &case.adopted_disabled {
                        assert_eq!(
                            outcome.next_settings.disabled_rules(),
                            expected,
                            "{} adopted settings",
                            case.name
                        );
                    }
                    let serialized = outcome.computed.serialize().unwrap();
                    let restored =
                        ergo_validation::ActiveProtocolParameters::deserialize(&serialized)
                            .unwrap();
                    assert_eq!(restored, outcome.computed);
                    Some(restored)
                }
                Err(error) => {
                    println!("{} epoch error: {error}", case.name);
                    assert!(!case.accept, "{} epoch rejected", case.name);
                    continue;
                }
            }
        } else {
            None
        };
        let params = ProtocolParams::for_block(&previous, voted.as_ref(), &settings);
        let tx_id = ergo_ser::transaction::transaction_id(&tx).unwrap();
        let proof_bytes: Vec<u8> = tx
            .inputs
            .iter()
            .flat_map(|i| i.spending_proof.proof.iter().copied())
            .collect();
        let witness = ergo_crypto::autolykos::common::blake2b256(&proof_bytes)[1..].to_vec();
        header.transactions_root = Digest32::from_bytes(ergo_crypto::merkle::transactions_root(
            &[tx_id.as_bytes().as_slice()],
            Some(&[witness.as_slice()]),
        ));
        let kv: Vec<_> = extension
            .fields
            .iter()
            .map(|f| (f.key.as_slice(), f.value.as_slice()))
            .collect();
        header.extension_root = Digest32::from_bytes(ergo_crypto::merkle::extension_root(&kv));
        let checked_parent = CheckedHeader::trust_me(parent, *header.parent_id.as_bytes());
        let ctx = BlockValidationContext {
            parent: &checked_parent,
            utxo: &utxo,
            params: &params,
            rule_306_max_block_size: previous.parameter(3).map(|n| n as u32).unwrap_or(0),
            voting_length: 1024,
            votes_unknown_rule_disabled: settings.is_rule_disabled(215),
            parent_extension: parent_ext.as_ref(),
            soft_fork_state: fork_state,
            last_headers: &[],
            script_validation_checkpoint: None,
            reemission: None,
        };
        let block_txs = BlockTransactions {
            header_id: id,
            transactions: vec![tx.clone()],
        };
        let results = [
            validate_full_block_with_costs(
                CheckedHeader::trust_me(header.clone(), *id.as_bytes()),
                &block_txs,
                &extension,
                &ctx,
            ),
            validate_full_block_parallel_with_costs(
                CheckedHeader::trust_me(header, *id.as_bytes()),
                &block_txs,
                &extension,
                &ctx,
            ),
        ];
        for result in results {
            println!("{} block: {:?}", case.name, result.as_ref().err());
            assert_eq!(result.is_ok(), case.accept, "{}", case.name);
            if let Ok((_, costs)) = result {
                assert_eq!(
                    Some(costs.iter().map(|(_, cost)| cost).sum::<u64>()),
                    case.cost,
                    "{} cost",
                    case.name
                );
            }
        }
    }
}
