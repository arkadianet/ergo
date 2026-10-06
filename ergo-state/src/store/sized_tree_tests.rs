use super::StateStore;
use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::digest::{blake2b256, Digest32};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::read_ergo_box;
use ergo_ser::transaction::{bytes_to_sign, read_transaction};
use ergo_validation::{
    validate_transaction_parsed, ProtocolParams, TransactionContext, TxValidationCtx,
    TxValidationRules,
};
use serde_json::Value;

#[test]
fn sized_output_trees_use_canonical_utxo_bytes_and_survive_reopen() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../test-vectors/santa/transaction/v6/authored/sized-tree-output-bytes.json"
    ))
    .unwrap();
    for entry in fixture["entries"].as_array().unwrap().iter().take(3) {
        let bytes = hex::decode(entry["tx_bytes_hex"].as_str().unwrap()).unwrap();
        let tx =
            read_transaction(&mut VlqReader::new(&bytes).with_activated_script_version(3)).unwrap();
        let received_tree = tx.output_candidates[0].ergo_tree_bytes().to_vec();
        let message = bytes_to_sign(&tx).unwrap();
        let inputs = entry["input_boxes_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                read_ergo_box(&mut VlqReader::new(
                    &hex::decode(v.as_str().unwrap()).unwrap(),
                ))
                .unwrap()
            })
            .collect();
        let ctx = TransactionContext {
            height: 1_051_200,
            miner_pubkey: [0; 33],
            pre_header_timestamp: 0,
            activated_script_version: 3,
            pre_header_version: 4,
            pre_header_parent_id: [0; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0; 3],
        };
        let mut params = ProtocolParams::mainnet_default();
        params.block_version = 4;
        let mut cost = CostAccumulator::new(JitCost::from_block_cost(1_000_000).unwrap());
        // The SANTA and mempool tests verify these signatures and script costs.
        // Isolate the production checked-output builder and DB persistence here.
        let checked = validate_transaction_parsed(
            tx,
            &bytes,
            inputs,
            vec![],
            true,
            &mut TxValidationCtx {
                ctx: &ctx,
                params: &params,
                cost: &mut cost,
                last_headers: &[],
                rules: TxValidationRules::default(),
            },
        )
        .unwrap();
        assert_eq!(checked.tx_id(), blake2b256(&message).as_bytes());
        assert_eq!(
            checked.transaction().output_candidates[0].ergo_tree_bytes(),
            received_tree
        );
        let (_, inserted) = StateStore::build_utxo_changes_checked(&[checked]).unwrap();
        assert_eq!(inserted.len(), 2);
        for (id, serialized) in &inserted {
            assert_eq!(*id, *blake2b256(serialized).as_bytes());
        }
        let boxes: Vec<_> = inserted.into_iter().collect();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sized-trees.redb");
        {
            let mut store = StateStore::open(&path).unwrap();
            store.initialize_genesis(&boxes).unwrap();
        }
        let reopened = StateStore::open(&path).unwrap();
        for (id, serialized) in boxes {
            assert_eq!(reopened.get_box_bytes(&id).unwrap(), serialized);
            let output = reopened.get_box(&Digest32::from_bytes(id)).unwrap();
            assert_eq!(output.box_id().unwrap().as_bytes(), &id);
            if output.index == 0 {
                assert_eq!(&serialized[3..7], &[0x08, 0x02, 0x08, 0xd3]);
                assert_eq!(
                    output.candidate.ergo_tree_bytes(),
                    &[0x08, 0x02, 0x08, 0xd3]
                );
            }
        }
    }
}
