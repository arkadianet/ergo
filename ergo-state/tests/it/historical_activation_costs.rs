//! Fixed historical cost contexts, rather than a reconstructed global UTXO DB.
//! All six captured bodies and43 transactions are compared against the pinned
//! Ergo6.0.5 offline observer. Headers, raw boxes, epochs and cumulative rules
//! must parse completely; missing records cannot shrink the denominator.
//! EIP37 is a difficulty transition here: version2 and active rule409 persist.
//! These fixtures do not establish JIT/6.0 activation or peer/chain admission.

use std::collections::{BTreeMap, HashMap};

use ergo_primitives::{
    digest::{Digest32, ModifierId},
    reader::VlqReader,
};
use ergo_ser::{
    block_transactions::BlockTransactions,
    ergo_box::{read_ergo_box, ErgoBox},
    extension::{Extension, ExtensionField},
    header::{read_header, serialize_header},
    transaction::read_transaction,
};
use ergo_validation::{
    active_params::{active_params_to_extension_fields, parse_active_params},
    block::{validate_full_block_parallel_with_costs, BlockValidationContext, SoftForkState},
    header::CheckedHeader,
    voting::validation_settings::{
        parse_validation_settings_update, ErgoValidationSettings, ErgoValidationSettingsUpdate,
    },
    ProtocolParams, UtxoView,
};
use serde_json::Value;

struct ArchivedSubset(HashMap<Digest32, ErgoBox>);
impl UtxoView for ArchivedSubset {
    fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
        self.0.get(id).cloned()
    }
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string")).expect("valid hex")
}
fn extension(id: [u8; 32], fields: &Value) -> Extension {
    Extension {
        header_id: ModifierId::from_bytes(id),
        fields: fields
            .as_array()
            .expect("fields")
            .iter()
            .map(|pair| ExtensionField {
                key: bytes(&pair[0]).try_into().expect("two-byte key"),
                value: bytes(&pair[1]),
            })
            .collect(),
    }
}

fn check_fixture(raw: &str, heights: [u32; 3], transaction_count: usize, box_count: usize) {
    let fixture: Value = serde_json::from_str(raw).expect("historical fixture JSON");
    let txs = fixture["transactions"].as_array().expect("transactions");
    assert_eq!(txs.len(), transaction_count);
    assert_eq!(fixture["expected_transaction_count"], transaction_count);
    assert_eq!(fixture["expected_box_count"], box_count);
    let mut boxes = HashMap::new();
    for row in fixture["initial_boxes"].as_array().expect("boxes") {
        let wire = bytes(&row["bytes"]);
        let mut reader = VlqReader::new(&wire);
        let value = read_ergo_box(&mut reader).expect("reference box bytes");
        assert_eq!(reader.position(), wire.len(), "whole box consumed");
        let id = value.box_id().expect("box ID");
        assert_eq!(hex::encode(id.as_bytes()), row["box_id"]);
        assert!(boxes.insert(id, value).is_none(), "duplicate box ID");
    }
    assert_eq!(boxes.len(), box_count);
    let mut utxo = ArchivedSubset(boxes);
    let mut headers = BTreeMap::new();
    for row in fixture["headers"].as_array().expect("headers") {
        let wire = bytes(&row["bytes"]);
        let mut reader = VlqReader::new(&wire);
        let header = read_header(&mut reader).expect("reference header bytes");
        assert_eq!(reader.position(), wire.len());
        let (encoded, id) = serialize_header(&header).expect("canonical header");
        assert_eq!(encoded, wire);
        assert_eq!(header.height, row["height"]);
        // These are recorded context headers, not a complete history/retarget
        // validation proof. Current target PoW is checked below independently.
        assert!(headers
            .insert(
                header.height,
                CheckedHeader::trust_me(header, *id.as_bytes())
            )
            .is_none());
    }
    assert_eq!(
        headers.len(),
        13,
        "all recorded headers including epoch anchor"
    );
    let epochs: BTreeMap<_, _> = fixture["epochs"]
        .as_array()
        .expect("epoch rows")
        .iter()
        .map(|e| {
            let h = u32::try_from(e["height"].as_u64().expect("epoch height")).unwrap();
            let id: [u8; 32] = bytes(&e["header_id"]).try_into().unwrap();
            let ext = extension(id, &e["extension_fields"]);
            let epoch_header = headers.get(&h).expect("recorded epoch anchor");
            assert_eq!(epoch_header.header_id(), &id);
            let fields = ext
                .fields
                .iter()
                .map(|f| (f.key.as_slice(), f.value.as_slice()))
                .collect::<Vec<_>>();
            assert_eq!(
                ergo_crypto::merkle::extension_root(&fields),
                *epoch_header.header().extension_root.as_bytes()
            );
            let active = parse_active_params(&ext, h).expect("captured full parameter table");
            let settings = ErgoValidationSettings {
                update_from_initial: parse_validation_settings_update(&ext)
                    .expect("full cumulative settings"),
            };
            (h, (active, settings))
        })
        .collect();
    let block_rows = fixture["blocks"].as_array().expect("block rows");
    assert_eq!(block_rows.len(), heights.len());
    let voting = ergo_chain_spec::VotingParams::mainnet();
    let mut compared = 0;
    for (row, height) in block_rows.iter().zip(heights) {
        assert_eq!(row["height"], height);
        let checked = headers.get(&height).expect("current header");
        let id = *checked.header_id();
        assert_eq!(hex::encode(id), row["header_id"]);
        ergo_crypto::pow::verify_pow_solution(checked.header()).expect("recorded target PoW");
        let ancestors = (height - 9..height)
            .rev()
            .map(|h| headers.get(&h).expect("every immediate ancestor").clone())
            .collect::<Vec<_>>();
        assert_eq!(ancestors.len(), 9);
        for pair in std::iter::once(checked)
            .chain(ancestors.iter())
            .collect::<Vec<_>>()
            .windows(2)
        {
            assert_eq!(pair[0].header().parent_id.as_bytes(), pair[1].header_id());
        }
        let observation = &fixture["parameters"][height.to_string()];
        let (active, settings) = &epochs
            .range(..=height)
            .next_back()
            .expect("preceding epoch")
            .1;
        assert_eq!(active.epoch_start_height, observation["epoch_height"]);
        assert_eq!(active.block_version, observation["block_version"]);
        let observed_settings = ErgoValidationSettingsUpdate::deserialize(&bytes(
            &observation["validation_settings_bytes"],
        ))
        .unwrap();
        assert_eq!(settings.update_from_initial, observed_settings);
        // Both independently decoded historical tables are initial. Disabling
        //409 here would invent the later6.0 governance change.
        assert!(settings.disabled_rules().is_empty());
        assert!(!settings.is_rule_disabled(215));
        assert!(!settings.is_rule_disabled(409));
        assert_eq!(observation["rule_215_active"], true);
        assert_eq!(observation["rule_409_active"], true);
        let params = ProtocolParams::from_active_with_settings(active, settings);
        let parent_params = &epochs
            .range(..height)
            .next_back()
            .expect("parent epoch")
            .1
             .0;
        // Every voted numeric parameter the reference records, by name. Ids 5
        // (token access) and 7 (data input) are both 100 in each captured
        // epoch, so no check on these fixtures can tell those two apart.
        assert_eq!(params.storage_fee_factor, observation["storage_fee_factor"]);
        assert_eq!(params.min_value_per_byte, observation["min_value_per_byte"]);
        assert_eq!(params.max_block_size, observation["max_block_size"]);
        assert_eq!(params.max_block_cost, observation["max_block_cost"]);
        assert_eq!(params.token_access_cost, observation["token_access_cost"]);
        assert_eq!(params.input_cost, observation["input_cost"]);
        assert_eq!(params.data_input_cost, observation["data_input_cost"]);
        assert_eq!(params.output_cost, observation["output_cost"]);
        // The whole table, including block version and soft-fork state.
        let table: BTreeMap<String, i32> = active_params_to_extension_fields(active)
            .expect("parsed parameters serialize")
            .into_iter()
            .filter(|(key, _)| key[1] != 124)
            .map(|(key, value)| {
                let value = value.try_into().expect("numeric parameter");
                (key[1].to_string(), i32::from_be_bytes(value))
            })
            .collect();
        assert_eq!(serde_json::json!(table), observation["parameter_table"]);
        let ctx_record = &fixture["contexts"][height.to_string()];
        assert_eq!(
            ctx_record["header_heights"],
            serde_json::json!(ancestors.iter().map(|h| h.height()).collect::<Vec<_>>())
        );
        assert_eq!(
            ctx_record["header_ids"],
            serde_json::json!(ancestors
                .iter()
                .map(|h| hex::encode(h.header_id()))
                .collect::<Vec<_>>())
        );
        assert_eq!(
            ctx_record["previous_state_digest"],
            hex::encode(ancestors[0].header().state_root.as_bytes())
        );
        let expected = txs
            .iter()
            .filter(|t| t["height"] == height)
            .collect::<Vec<_>>();
        assert!(!expected.is_empty());
        let transactions = expected
            .iter()
            .map(|t| {
                let wire = bytes(&t["tx_bytes"]);
                let mut r = VlqReader::new(&wire);
                let tx = read_transaction(&mut r).expect("reference tx");
                assert_eq!(r.position(), wire.len());
                assert_eq!(
                    hex::encode(
                        ergo_ser::transaction::transaction_id(&tx)
                            .unwrap()
                            .as_bytes()
                    ),
                    t["tx_id"]
                );
                tx
            })
            .collect();
        let bt = BlockTransactions {
            header_id: ModifierId::from_bytes(id),
            transactions,
        };
        let ext = extension(id, &row["extension_fields"]);
        let parent_ext = extension(*ancestors[0].header_id(), &row["parent_extension_fields"]);
        let soft_fork_state = active
            .soft_fork_starting_height()
            .zip(active.soft_fork_votes_collected())
            .map(|(start, votes)| SoftForkState {
                starting_height: u32::try_from(start).expect("nonnegative start"),
                votes_collected: votes,
                voting_length: voting.voting_length,
                soft_fork_epochs: voting.soft_fork_epochs,
                activation_epochs: voting.activation_epochs,
                approved: voting.soft_fork_approved(votes),
            });
        let ctx = BlockValidationContext {
            parent: &ancestors[0],
            utxo: &utxo,
            params: &params,
            rule_306_max_block_size: Some(u32::try_from(parent_params.max_block_size).unwrap()),
            voting_length: voting.voting_length,
            votes_unknown_rule_disabled: settings.is_rule_disabled(215),
            parent_extension: Some(&parent_ext),
            soft_fork_state,
            last_headers: &ancestors,
            script_validation_checkpoint: None,
            reemission: None,
        };
        let (block, mut costs) =
            validate_full_block_parallel_with_costs(checked.clone(), &bt, &ext, &ctx)
                .unwrap_or_else(|e| panic!("h{height} complete transaction path: {e}"));
        assert_eq!(block.transactions().len(), expected.len());
        // Observations arrive in dependency-layer order; indices retain the
        // original block positions. Sorting preserves full count/uniqueness.
        costs.sort_by_key(|&(index, _)| index);
        assert_eq!(
            costs,
            expected
                .iter()
                .enumerate()
                .map(|(i, t)| (i, t["block_cost"].as_u64().unwrap()))
                .collect::<Vec<_>>(),
            "every original transaction position at h{height}"
        );
        for (tx, record) in block.transactions().iter().zip(expected.iter()) {
            assert_eq!(hex::encode(tx.tx_id()), record["tx_id"]);
        }
        // Carry the actual immutable initial subset forward in block order.
        // Missing spends and duplicate live output IDs are test failures.
        for tx in block.transactions() {
            for input in &tx.transaction().inputs {
                assert!(
                    utxo.0.remove(&input.box_id).is_some(),
                    "spend absent from sequential view"
                );
            }
            let tx_id = ModifierId::from_bytes(*tx.tx_id());
            for (index, candidate) in tx.transaction().output_candidates.iter().enumerate() {
                let value = ErgoBox {
                    candidate: candidate.clone(),
                    transaction_id: tx_id,
                    index: u16::try_from(index).unwrap(),
                };
                let id = value.box_id().unwrap();
                assert!(
                    utxo.0.insert(id, value).is_none(),
                    "duplicate live output ID"
                );
            }
        }
        compared += expected.len();
    }
    assert_eq!(
        compared, transaction_count,
        "no missing context or record may be skipped"
    );
}

#[test]
fn pre_at_post_v1_v2_costs_match_pinned_full_client() {
    check_fixture(
        include_str!("../../../test-vectors/ergo-state/historical-costs/v1v2.json"),
        [417791, 417792, 417793],
        9,
        4,
    );
}

#[test]
fn pre_at_post_eip37_costs_match_pinned_full_client() {
    check_fixture(
        include_str!("../../../test-vectors/ergo-state/historical-costs/eip37.json"),
        [844671, 844672, 844673],
        34,
        249,
    );
}
