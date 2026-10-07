//! Re-emission allocation vectors from the reference node's transaction validator.
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
    height: u32,
    check: bool,
    tx: String,
    boxes: Vec<String>,
    accept: bool,
    cost: Option<u64>,
}
#[derive(serde::Deserialize)]
struct Oracle {
    entries: Vec<Case>,
}

#[test]
fn reemission_spending_matches_reference() {
    let oracle: Oracle = serde_json::from_str(include_str!(
        "../../../test-vectors/reference-6.0.7/reemission/spending.json"
    ))
    .unwrap();
    let spec = ergo_chain_spec::ChainSpec::mainnet();
    let mut disagreements = Vec::new();
    for case in oracle.entries {
        let rules = ReemissionRuleInputs::from_chain_spec(&spec, case.check).unwrap();
        let bytes = hex::decode(case.tx).unwrap();
        let tx = read_transaction(&mut VlqReader::new(&bytes)).unwrap();
        let boxes = case
            .boxes
            .iter()
            .map(|h| read_ergo_box(&mut VlqReader::new(&hex::decode(h).unwrap())).unwrap())
            .collect();
        let params = ProtocolParams {
            max_block_cost: 1_000_000,
            block_version: 4,
            ..ProtocolParams::mainnet_default()
        };
        let ctx = TransactionContext {
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
        let result = validate_transaction_parsed(tx, &bytes, boxes, vec![], false, &mut cx);
        println!(
            "{}\t{}\t{}\t{}\t{:?}",
            case.name,
            case.check,
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
