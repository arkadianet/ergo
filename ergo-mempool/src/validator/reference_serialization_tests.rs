use super::*;
use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_ser::ergo_box::{read_ergo_box, serialize_ergo_box};
use ergo_ser::header::read_header;
use ergo_validation::{ProtocolParams, TransactionContext, TxValidationCtx, TxValidationRules};
use serde_json::Value;

struct Boxes(Vec<ErgoBox>);
impl UtxoView for Boxes {
    fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
        self.0.iter().find(|b| b.box_id().unwrap() == *id).cloned()
    }
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn reference_serialization_mempool_identifiers() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/reference-6.0.7/serialization");
    for file in ["relations", "transaction-encodings"] {
        let fixture: Value = serde_json::from_str(
            &std::fs::read_to_string(root.join(format!("{file}.json"))).unwrap(),
        )
        .unwrap();
        let oracle = std::fs::read_to_string(root.join(format!("{file}.jvm-ids.tsv"))).unwrap();
        let ids: std::collections::BTreeMap<_, _> = oracle
            .lines()
            .map(|line| {
                let r: Vec<_> = line.split('\t').collect();
                (r[0], r)
            })
            .collect();
        for entry in fixture["entries"].as_array().unwrap() {
            let pre = &entry["preHeader"];
            let ctx = TransactionContext {
                height: entry["context"]["height"].as_u64().unwrap() as u32,
                miner_pubkey: bytes(&pre["minerPk"]).try_into().unwrap(),
                pre_header_timestamp: pre["timestamp"].as_str().unwrap().parse().unwrap(),
                activated_script_version: 3,
                pre_header_version: 4,
                pre_header_parent_id: bytes(&pre["parentId"]).try_into().unwrap(),
                pre_header_n_bits: pre["nBits"].as_u64().unwrap(),
                pre_header_votes: bytes(&pre["votes"]).try_into().unwrap(),
            };
            let mut params = ProtocolParams::mainnet_default();
            params.block_version = 4;
            let headers: Vec<_> = entry["headers_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| read_header(&mut VlqReader::new(&bytes(v))).unwrap())
                .collect();
            let inputs = Boxes(
                entry["input_boxes_hex"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| read_ergo_box(&mut VlqReader::new(&bytes(v))).unwrap())
                    .collect(),
            );
            let tx_bytes = bytes(&entry["tx_bytes_hex"]);
            let mut cost = CostAccumulator::new(JitCost::from_block_cost(1_000_000).unwrap());
            let result = ErgoValidator.validate(
                &tx_bytes,
                &inputs,
                &Boxes(vec![]),
                &mut TxValidationCtx {
                    ctx: &ctx,
                    params: &params,
                    cost: &mut cost,
                    last_headers: &headers,
                    rules: TxValidationRules::default(),
                },
            );
            if !entry["expected"]["valid"].as_bool().unwrap() {
                assert!(result.is_err(), "{result:?}");
                continue;
            }
            let validated = result.unwrap();
            assert_eq!(
                validated.consumed_cost,
                entry["expected"]["cost"].as_u64().unwrap()
            );
            let peeked = ErgoValidator.peek_structure(&tx_bytes).unwrap();
            assert_eq!(peeked.tx_id, validated.tx_id);
            assert_eq!(peeked.output_box_ids, validated.output_box_ids);
            let tx = read_transaction(&mut VlqReader::new(&tx_bytes)).unwrap();
            let output = &validated.outputs[0];
            assert_eq!(
                output.candidate.ergo_tree_bytes(),
                tx.output_candidates[0].ergo_tree_bytes()
            );
            let expected = &ids[entry["name"].as_str().unwrap()];
            assert_eq!(expected[1], "OK");
            let fields: std::collections::BTreeMap<_, _> = expected[2]
                .split_whitespace()
                .map(|field| field.split_once('=').unwrap())
                .collect();
            assert_eq!(hex::encode(validated.tx_id.as_bytes()), fields["txid"]);
            assert_eq!(
                hex::encode(output.box_id().unwrap().as_bytes()),
                fields["out0.id"]
            );
            assert_eq!(
                hex::encode(serialize_ergo_box(output).unwrap()),
                fields["out0.bytes"]
            );
            assert_eq!(validated.size_bytes as usize, tx_bytes.len());
        }
    }
}
