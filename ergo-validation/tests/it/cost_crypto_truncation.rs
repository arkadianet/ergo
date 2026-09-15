//! Oracle: test-vectors/scala/multi_input_conjunction_cost.json (Scala ErgoTransaction.validateStateful).

use std::collections::HashMap;

use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{read_ergo_box, ErgoBox};
use ergo_ser::transaction::read_transaction;
use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
use ergo_validation::error::ValidationError;
use ergo_validation::tx::validate_transaction;
use ergo_validation::{TxValidationCtx, TxValidationRules, UtxoView};

// ----- helpers -----

#[derive(Debug, PartialEq, serde::Deserialize)]
pub(super) enum Verdict {
    Accept,
    RejectCost,
    RejectScript,
}

#[derive(serde::Deserialize)]
struct InputBox {
    box_id: String,
    bytes: String,
}

#[derive(serde::Deserialize)]
struct SweepPoint {
    limit: u64,
    verdict: Verdict,
}

#[derive(serde::Deserialize)]
pub(super) struct Case {
    name: String,
    tx_bytes: String,
    input_boxes: Vec<InputBox>,
    block_cost: u64,
    verdict: Verdict,
    sweep: Vec<SweepPoint>,
}

#[derive(serde::Deserialize)]
pub(super) struct Context {
    height: u32,
    activated_script_version: u8,
    block_version: u8,
    timestamp: u64,
    n_bits: u64,
    miner_pk_hex: String,
    voted_params: HashMap<String, u64>,
}

#[derive(serde::Deserialize)]
struct Vector {
    context: Context,
    cases: Vec<Case>,
}

fn load_vector() -> Vector {
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../test-vectors/scala/multi_input_conjunction_cost.json"
    ))
    .expect("JVM vector JSON");
    assert_eq!(vector.cases.len(), 2);
    assert_eq!(vector.cases[0].input_boxes.len(), 2);
    assert_eq!(vector.cases[1].input_boxes.len(), 4);
    vector
}

struct MapUtxo(HashMap<Digest32, ErgoBox>);

impl UtxoView for MapUtxo {
    fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
        self.0.get(id).cloned()
    }
}

fn validate_with_limit(case: &Case, context: &Context, limit: u64) -> (Verdict, u64) {
    validate_with_accumulated(case, context, limit, 0)
}

pub(super) fn validate_with_accumulated(
    case: &Case,
    context: &Context,
    limit: u64,
    accumulated: u64,
) -> (Verdict, u64) {
    let mut boxes = HashMap::new();
    for input in &case.input_boxes {
        let bytes = hex::decode(&input.bytes).expect("box hex");
        let mut reader = VlqReader::new(&bytes);
        let ergo_box = read_ergo_box(&mut reader).expect("JVM box bytes");
        assert_eq!(reader.remaining(), 0);
        let id = ergo_box.box_id().expect("box ID");
        assert_eq!(hex::encode(id.as_bytes()), input.box_id);
        assert!(boxes.insert(id, ergo_box).is_none());
    }
    let bytes = hex::decode(&case.tx_bytes).expect("transaction hex");
    let mut reader = VlqReader::new(&bytes);
    let tx = read_transaction(&mut reader).expect("JVM transaction bytes");
    assert_eq!(reader.remaining(), 0);
    assert_eq!(tx.inputs.len(), boxes.len());
    assert!(tx
        .inputs
        .iter()
        .all(|input| boxes.contains_key(&input.box_id)));
    let ctx = TransactionContext {
        height: context.height,
        miner_pubkey: hex::decode(&context.miner_pk_hex)
            .expect("miner PK hex")
            .try_into()
            .expect("33-byte miner PK"),
        pre_header_timestamp: context.timestamp,
        activated_script_version: context.activated_script_version,
        pre_header_version: context.block_version,
        pre_header_parent_id: [0; 32],
        pre_header_n_bits: context.n_bits,
        pre_header_votes: [0; 3],
    };
    let p = &context.voted_params;
    let params = ProtocolParams {
        max_block_cost: limit,
        storage_fee_factor: p["1"].try_into().expect("storage fee i32"),
        min_value_per_byte: p["2"],
        max_block_size: p["3"].try_into().expect("block size u32"),
        token_access_cost: p["5"],
        input_cost: p["6"],
        data_input_cost: p["7"],
        output_cost: p["8"],
        ..ProtocolParams::mainnet_default()
    };
    let mut cost = CostAccumulator::new(JitCost::from_block_cost(limit).expect("limit"));
    cost.add(JitCost::from_block_cost(accumulated).expect("accumulated cost"))
        .expect("precharge below limit");
    let mut tx_ctx = TxValidationCtx {
        ctx: &ctx,
        params: &params,
        cost: &mut cost,
        last_headers: &[],
        rules: TxValidationRules::default(),
    };
    let verdict = match validate_transaction(
        &bytes,
        &MapUtxo(boxes),
        &LocalPolicy::default_policy(),
        &mut tx_ctx,
    ) {
        Ok(_) => Verdict::Accept,
        Err(ValidationError::CostExceeded { .. }) => Verdict::RejectCost,
        Err(ValidationError::ScriptError { reason, .. })
            if reason.contains("cost limit exceeded") =>
        {
            Verdict::RejectCost
        }
        Err(ValidationError::ProofFailed { .. }) => Verdict::RejectScript,
        Err(error) => panic!("{} @ limit {limit}: {error}", case.name),
    };
    (verdict, cost.total_block_cost())
}

// ----- oracle parity -----

// ledger: INTERP-crypto-trunc, ROUND-crypto-per-input
#[test]
fn conjunction_two_inputs_block_cost_matches_scala() {
    let v = load_vector();
    let mut mismatches = Vec::new();
    for case in &v.cases {
        let (verdict, cost) = validate_with_limit(case, &v.context, 1_000_000);
        assert_eq!(verdict, case.verdict, "{}", case.name);
        if cost != case.block_cost {
            mismatches.push(format!(
                "{}: Rust {cost}, JVM {}",
                case.name, case.block_cost
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

// ledger: INTERP-crypto-trunc, ROUND-crypto-per-input
#[test]
fn conjunction_tx_at_exact_scala_limit_accepts() {
    let v = load_vector();
    let mut mismatches = Vec::new();
    for case in &v.cases {
        assert_eq!(
            case.sweep
                .iter()
                .map(|point| point.limit)
                .collect::<Vec<_>>(),
            [case.block_cost - 1, case.block_cost, case.block_cost + 1]
        );
        for point in &case.sweep {
            let (verdict, _) = validate_with_limit(case, &v.context, point.limit);
            if verdict != point.verdict {
                mismatches.push(format!(
                    "{} @ limit {}: Rust {verdict:?}, JVM {:?}",
                    case.name, point.limit, point.verdict
                ));
            }
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
