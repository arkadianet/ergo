//! Parity test: reduce_expr_with_cost (untraced) and reduce_expr_traced_with_cost
//! must produce identical results and identical accumulated costs for the same inputs.
//!
//! This guards against the evaluator unification introducing semantic divergence
//! between the traced and untraced paths.

use ergo_primitives::cost::CostAccumulator;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_sigma::evaluator::{
    reduce_expr_traced_with_cost, reduce_expr_with_cost, EvalBox, ReductionContext,
};

#[derive(serde::Deserialize)]
struct OutputVec {
    creation_height: u32,
    script_bytes: String,
}

#[derive(serde::Deserialize)]
struct EmissionVector {
    ergo_tree: String,
    height: u32,
    outputs: Vec<OutputVec>,
    miner_pk: String,
}

fn load_emission_vectors() -> Vec<EmissionVector> {
    let data =
        std::fs::read_to_string("../test-vectors/mainnet/emission_contract_700000.json").unwrap();
    serde_json::from_str(&data).unwrap()
}

/// For every emission contract vector, run both reduce_expr_with_cost and
/// reduce_expr_traced_with_cost. Assert identical SigmaBoolean result and
/// identical accumulated JIT cost.
#[test]
fn traced_and_untraced_produce_identical_result_and_cost() {
    let vectors = load_emission_vectors();
    assert!(!vectors.is_empty(), "need at least one vector");

    let mut checked = 0;

    for v in &vectors {
        let tree_bytes = hex::decode(&v.ergo_tree).unwrap();
        let mut reader = VlqReader::new(&tree_bytes);
        let ergo_tree = read_ergo_tree(&mut reader).unwrap();
        let miner_pk: [u8; 33] = hex::decode(&v.miner_pk).unwrap().try_into().unwrap();

        let outputs: Vec<EvalBox> = v
            .outputs
            .iter()
            .map(|o| EvalBox::simple(o.creation_height, hex::decode(&o.script_bytes).unwrap()))
            .collect();

        let ctx = ReductionContext {
            height: v.height,
            self_box: None,
            self_creation_height: 0,
            outputs: &outputs,
            inputs: &[],
            data_inputs: &[],
            miner_pubkey: miner_pk,
            pre_header_timestamp: 0,
            extension: indexmap::IndexMap::new(),
            last_headers: &[],
            last_block_utxo_root: None,
            activated_script_version: 2,
            ergo_tree_version: 2,
            pre_header_version: 0,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
            input_extensions: &[],
        };

        // Untraced path
        let mut cost_untraced = CostAccumulator::recording_only();
        let result_untraced = reduce_expr_with_cost(
            &ergo_tree.body,
            &ctx,
            &ergo_tree.constants,
            &mut cost_untraced,
        );

        // Traced path
        let mut cost_traced = CostAccumulator::recording_only();
        let (result_traced, _trace_entries) = reduce_expr_traced_with_cost(
            &ergo_tree.body,
            &ctx,
            &ergo_tree.constants,
            &mut cost_traced,
        );

        // Compare results
        match (&result_untraced, &result_traced) {
            (Ok(sb_u), Ok(sb_t)) => {
                assert_eq!(
                    sb_u, sb_t,
                    "SigmaBoolean mismatch at height {} (vector {})",
                    v.height, checked
                );
            }
            (Err(e_u), Err(e_t)) => {
                assert_eq!(
                    format!("{e_u}"),
                    format!("{e_t}"),
                    "error mismatch at height {} (vector {})",
                    v.height,
                    checked
                );
            }
            _ => {
                panic!(
                    "result type mismatch at height {} (vector {}): untraced={:?}, traced={:?}",
                    v.height, checked, result_untraced, result_traced
                );
            }
        }

        // Compare accumulated costs
        assert_eq!(
            cost_untraced.total().value(),
            cost_traced.total().value(),
            "cost mismatch at height {} (vector {}): untraced={}, traced={}",
            v.height,
            checked,
            cost_untraced.total().value(),
            cost_traced.total().value(),
        );

        checked += 1;
    }

    eprintln!(
        "{checked}/{} vectors: traced/untraced parity confirmed",
        vectors.len()
    );
}
