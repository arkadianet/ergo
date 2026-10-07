//! JVM-produced block cost boundaries, checked through both full-block paths.
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{read_ergo_box, ErgoBox};
use ergo_ser::transaction::read_transaction;
use ergo_validation::context::ProtocolParams;

use super::synthetic_block::{validate_both_with_costs, MapUtxo};

#[derive(serde::Deserialize)]
struct Run {
    transactions: Vec<String>,
    limit: u64,
    verdict: String,
    accumulated: u64,
    per_tx: Vec<TxCost>,
}
#[derive(serde::Deserialize)]
struct TxCost {
    tx_cost: u64,
}
#[derive(serde::Deserialize)]
struct Oracle {
    #[serde(default = "default_block_version")]
    block_version: u8,
    #[serde(default)]
    replaced_rules: Vec<(u16, u16)>,
    tx1_bytes: String,
    tx2_bytes: String,
    boxes1: Vec<String>,
    boxes2: Vec<String>,
    runs: Vec<Run>,
}

fn default_block_version() -> u8 {
    3
}

#[test]
fn full_block_remainder_limits_match_reference() {
    check_oracle(include_str!(
        "../../../test-vectors/reference-6.0.7/block-cost/remainders.json"
    ));
}

#[test]
fn full_block_discarded_budget_checks_match_reference() {
    check_oracle(include_str!(
        "../../../test-vectors/reference-6.0.7/block-cost/budget-probes.json"
    ));
}

#[test]
fn full_block_recovered_budget_checks_match_reference() {
    check_oracle(include_str!(
        "../../../test-vectors/reference-6.0.7/block-cost/recovery-probes.json"
    ));
}

fn check_oracle(json: &str) {
    let oracle: Oracle = serde_json::from_str(json).unwrap();
    let boxes: Vec<ErgoBox> = oracle
        .boxes1
        .iter()
        .chain(&oracle.boxes2)
        .map(|h| read_ergo_box(&mut VlqReader::new(&hex::decode(h).unwrap())).unwrap())
        .collect();
    let utxo = MapUtxo::of(&boxes.iter().collect::<Vec<_>>());
    for run in oracle.runs {
        let txs = run
            .transactions
            .iter()
            .map(|name| {
                let bytes = match name.as_str() {
                    "tx1" => &oracle.tx1_bytes,
                    "tx2" => &oracle.tx2_bytes,
                    other => panic!("unknown reference transaction {other}"),
                };
                read_transaction(&mut VlqReader::new(&hex::decode(bytes).unwrap())).unwrap()
            })
            .collect();
        let params = ProtocolParams {
            max_block_cost: run.limit,
            block_version: oracle.block_version,
            validation_settings: ergo_sigma::evaluator::SigmaValidationSettings(
                oracle
                    .replaced_rules
                    .iter()
                    .map(|(id, target)| (*id, ergo_sigma::evaluator::RuleStatus::Replaced(*target)))
                    .collect(),
            ),
            ..ProtocolParams::mainnet_default()
        };
        for result in validate_both_with_costs(txs, &utxo, oracle.block_version, &params) {
            assert_eq!(
                result.is_ok(),
                run.verdict == "Accept",
                "limit {}, {:?}: {result:?}",
                run.limit,
                run.transactions
            );
            if let Ok((_, costs)) = result {
                assert_eq!(costs.iter().map(|(_, c)| c).sum::<u64>(), run.accumulated);
                assert_eq!(
                    costs.iter().map(|(_, c)| *c).collect::<Vec<_>>(),
                    run.per_tx.iter().map(|c| c.tx_cost).collect::<Vec<_>>()
                );
            }
        }
    }
}
