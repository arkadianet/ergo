//! Parsed parameter subsets adopted at epoch boundaries by ergo-core 6.0.7.
use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::extension::{Extension, ExtensionField};
use ergo_ser::header::read_header;
use ergo_validation::voting::{validate_epoch_extension, VotingSettings};
use ergo_validation::{scala_launch, ErgoValidationSettings, ErgoValidationSettingsUpdate};

#[derive(serde::Deserialize)]
struct Field {
    key: String,
    value: String,
}
#[derive(serde::Deserialize)]
struct Case {
    omitted: u8,
    fields: Vec<Field>,
    parse_accept: bool,
    first_accept: bool,
    next_accept: bool,
    first_cost: Option<u64>,
    next_cost: Option<u64>,
}
#[derive(serde::Deserialize)]
struct RentCase {
    omitted: u8,
    height: u32,
    tx: String,
    accept: bool,
    cost: Option<u64>,
}
#[derive(serde::Deserialize)]
struct Oracle {
    tx: String,
    boxes: Vec<String>,
    entries: Vec<Case>,
    rent_entries: Vec<RentCase>,
}

#[test]
fn parameter_subsets_match_reference() {
    let oracle: Oracle = serde_json::from_str(include_str!(
        "../../../test-vectors/reference-6.0.7/parameters/subsets.json"
    ))
    .unwrap();
    let headers: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test-vectors/mainnet/headers_1_2000.json"
    ))
    .unwrap();
    let raw = hex::decode(
        headers
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["height"] == 1000)
            .unwrap()["bytes"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let mut header = read_header(&mut VlqReader::new(&raw)).unwrap();
    header.height = 2048;
    header.version = 4;
    header.votes = [0; 3];
    let mut prev = scala_launch();
    prev.epoch_start_height = 1024;
    prev.block_version = 4;
    prev.subblocks_per_block = Some(30);
    let settings = ErgoValidationSettings::empty().updated(&ErgoValidationSettingsUpdate {
        rules_to_disable: vec![215, 409],
        status_updates: vec![],
    });
    let bytes = hex::decode(&oracle.tx).unwrap();
    let tx = ergo_ser::transaction::read_transaction(&mut VlqReader::new(&bytes)).unwrap();
    let boxes: Vec<ergo_ser::ergo_box::ErgoBox> = oracle
        .boxes
        .iter()
        .map(|h| {
            ergo_ser::ergo_box::read_ergo_box(&mut VlqReader::new(&hex::decode(h).unwrap()))
                .unwrap()
        })
        .collect();
    let utxo = super::synthetic_block::MapUtxo::of(&boxes.iter().collect::<Vec<_>>());
    for case in oracle.entries {
        let ext = Extension {
            header_id: ModifierId::from_bytes([0; 32]),
            fields: case
                .fields
                .into_iter()
                .map(|f| ExtensionField {
                    key: hex::decode(f.key).unwrap().try_into().unwrap(),
                    value: hex::decode(f.value).unwrap(),
                })
                .collect(),
        };
        let parsed = ergo_validation::parse_active_params(&ext, 2048);
        let result = validate_epoch_extension(
            &ext,
            &header,
            &prev,
            &settings,
            &[],
            &VotingSettings::mainnet(),
            false,
        );
        assert_eq!(parsed.is_ok(), case.parse_accept, "omit {}", case.omitted);
        let outcome = result.unwrap();
        let adopted = outcome.computed;
        if case.omitted != 0 {
            assert_eq!(adopted.parameter(case.omitted), None);
        }
        let persisted = adopted.serialize().unwrap();
        assert_eq!(
            ergo_validation::ActiveProtocolParameters::deserialize(&persisted).unwrap(),
            adopted
        );
        let params = ergo_validation::context::ProtocolParams::from_active_with_settings(
            &adopted,
            &outcome.next_settings,
        );
        for (parent_size, expected, cost) in [
            (
                Some(prev.max_block_size as u32),
                case.first_accept,
                case.first_cost,
            ),
            (
                adopted.parameter(3).map(|v| v as u32),
                case.next_accept,
                case.next_cost,
            ),
        ] {
            for result in super::synthetic_block::validate_both_with_parent_size(
                vec![tx.clone()],
                &utxo,
                4,
                &params,
                parent_size,
            ) {
                assert_eq!(
                    result.is_ok(),
                    expected,
                    "omit {}, prior size {parent_size:?}: {result:?}",
                    case.omitted
                );
                if let Ok((_, costs)) = result {
                    assert_eq!(Some(costs.iter().map(|(_, c)| c).sum::<u64>()), cost);
                }
            }
        }
        // A second epoch must keep omissions; an approved vote for a missing
        // parameter must fail instead of silently restoring its launch value.
        if matches!(case.omitted, 1 | 9) {
            header.height = 3072;
            let mut next_ext = ext.clone();
            let next = validate_epoch_extension(
                &next_ext,
                &header,
                &adopted,
                &outcome.next_settings,
                &[],
                &VotingSettings::mainnet(),
                false,
            )
            .unwrap();
            assert_eq!(next.computed.parameter(case.omitted), None);
            next_ext.fields =
                ergo_validation::active_params::active_params_to_extension_fields(&next.computed)
                    .unwrap()
                    .into_iter()
                    .map(|(key, value)| ExtensionField { key, value })
                    .chain(next_ext.fields.into_iter().filter(|f| f.key[0] == 2))
                    .collect();
            if case.omitted == 1 {
                assert!(validate_epoch_extension(
                    &next_ext,
                    &header,
                    &adopted,
                    &outcome.next_settings,
                    &[(1, 513)],
                    &VotingSettings::mainnet(),
                    false
                )
                .is_err());
            }
            header.height = 2048;
        }
    }
    for case in oracle.rent_entries {
        let bytes = hex::decode(&case.tx).unwrap();
        let tx = ergo_ser::transaction::read_transaction(&mut VlqReader::new(&bytes)).unwrap();
        let mut active = prev.clone();
        if case.omitted == 1 {
            active.missing_core_parameters = 1;
            active.storage_fee_factor = 0;
        }
        let params = ergo_validation::context::ProtocolParams::from_active(&active);
        let ctx = ergo_validation::context::TransactionContext {
            height: case.height,
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
        let mut cost = ergo_primitives::cost::CostAccumulator::new(
            ergo_primitives::cost::JitCost::from_block_cost(params.max_block_cost).unwrap(),
        );
        let mut cx = ergo_validation::TxValidationCtx {
            ctx: &ctx,
            params: &params,
            cost: &mut cost,
            last_headers: &[],
            rules: Default::default(),
        };
        let result = ergo_validation::tx::validate_transaction_parsed(
            tx,
            &bytes,
            boxes.clone(),
            vec![],
            false,
            &mut cx,
        );
        assert_eq!(
            result.is_ok(),
            case.accept,
            "storage fee omitted {}: {result:?}",
            case.omitted
        );
        if result.is_ok() {
            assert_eq!(Some(cost.total_block_cost()), case.cost);
        }
    }
}
