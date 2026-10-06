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
fn sized_output_trees_pass_the_production_mempool_validator_with_exact_costs() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../test-vectors/santa/transaction/v6/authored/sized-tree-output-bytes.json"
    ))
    .unwrap();
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
            assert!(
                matches!(result, Err(ValidationErr::ScriptFailed)),
                "{result:?}"
            );
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
        let serialized = serialize_ergo_box(output).unwrap();
        assert_eq!(&serialized[3..7], &[0x08, 0x02, 0x08, 0xd3]);
        assert_eq!(output.box_id().unwrap(), blake2b256(&serialized));
    }
}
