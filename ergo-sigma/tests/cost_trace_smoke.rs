#![cfg(feature = "cost-trace")]
use ergo_primitives::cost::CostAccumulator;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_sigma::cost_trace;
use ergo_sigma::evaluator::{reduce_expr_with_cost, EvalBox, ReductionContext};

#[derive(serde::Deserialize)]
struct EmissionVector {
    ergo_tree: String,
    height: u32,
    outputs: Vec<OutputVec>,
    miner_pk: String,
}

#[derive(serde::Deserialize)]
struct OutputVec {
    creation_height: u32,
    script_bytes: String,
}

fn load_first_emission_vector() -> EmissionVector {
    let data =
        std::fs::read_to_string("../test-vectors/mainnet/emission_contract_700000.json").unwrap();
    let vecs: Vec<EmissionVector> = serde_json::from_str(&data).unwrap();
    vecs.into_iter().next().unwrap()
}

#[test]
fn trace_captures_opcode_costs() {
    let v = load_first_emission_vector();
    let tree_bytes = hex::decode(&v.ergo_tree).unwrap();
    let mut reader = VlqReader::new(&tree_bytes);
    let ergo_tree = read_ergo_tree(&mut reader).unwrap();

    let outputs: Vec<EvalBox> = v
        .outputs
        .iter()
        .map(|o| EvalBox::simple(o.creation_height, hex::decode(&o.script_bytes).unwrap()))
        .collect();

    let miner_pk: [u8; 33] = hex::decode(&v.miner_pk).unwrap().try_into().unwrap();

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
        pre_header_version: 0,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
        input_extensions: &[],
    };

    cost_trace::enable();
    let mut cost = CostAccumulator::recording_only();
    let _result = reduce_expr_with_cost(&ergo_tree.body, &ctx, &ergo_tree.constants, &mut cost);
    let trace = cost_trace::take().expect("trace should be enabled");

    assert!(!trace.entries.is_empty(), "trace should have entries");
    assert!(
        trace.entries.last().unwrap().total > 0,
        "total cost should be positive"
    );

    // The emission contract uses HEIGHT, GE, BoolToSigmaProp — we should see these opcodes
    assert!(
        trace.count_by_prefix("OP:") > 0,
        "should have opcode entries"
    );

    // Verify trace total matches CostAccumulator total
    let trace_total = trace.entries.last().unwrap().total;
    assert_eq!(
        trace_total,
        cost.total().value(),
        "trace total should match accumulator"
    );

    trace.dump("emission_contract_smoke");
}

/// Regression guard for the `Method:indexOf` cost-trace recording site at
/// `evaluator/opcodes/method_call.rs:89`. The recorded `total` must be the
/// cumulative `cx.cost.total()`, not the local `index_of_delta` — a future
/// "simplification" back to delta-only would silently break every consumer
/// that diffs cost-trace dumps against the Scala oracle. We pin this by
/// constructing a tree where prior dispatch/constant/collection cost
/// charges accumulate before `indexOf` records, then asserting the
/// recorded `total` for the indexOf entry strictly exceeds its own
/// `delta`.
#[test]
fn trace_pins_method_indexof_cumulative_total() {
    use ergo_ser::opcode::{Expr, IrNode, Payload};
    use ergo_ser::sigma_type::SigmaType;

    // HEIGHT (0xA3) charges its cost via add_cost in the OP arm and IS
    // routed through cost_trace::record. Using HEIGHT in every operand
    // position (instead of Expr::Const, which charges in eval_expr WITHOUT
    // recording) keeps every cost-charging step observable in the trace,
    // so the cumulative invariant `entry.total == prev.total + entry.delta`
    // can be checked across every adjacent pair.
    let height = || {
        Expr::Op(IrNode {
            opcode: 0xA3,
            payload: Payload::Zero,
        })
    };

    // With ctx.height = 1, every HEIGHT evaluates to Value::Int(1), so:
    //   collection = [1, 1, 1]
    //   indexOf target = 1, from = 1  -> iterates once, hits index 1
    //   result = 1
    //   1 == 1  -> TrivialProp(true)
    let coll = Expr::Op(IrNode {
        opcode: 0x83,
        payload: Payload::ConcreteCollection {
            elem_type: SigmaType::SInt,
            items: vec![height(), height(), height()],
        },
    });
    let indexof = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 12,
            method_id: 26,
            obj: Box::new(coll),
            args: vec![height(), height()],
            type_args: vec![],
        },
    });
    let body = Expr::Op(IrNode {
        opcode: 0x93,
        payload: Payload::Two(Box::new(indexof), Box::new(height())),
    });

    let ctx = ReductionContext {
        height: 1,
        self_box: None,
        self_creation_height: 0,
        outputs: &[],
        inputs: &[],
        data_inputs: &[],
        miner_pubkey: [0u8; 33],
        pre_header_timestamp: 0,
        extension: indexmap::IndexMap::new(),
        last_headers: &[],
        last_block_utxo_root: None,
        // (12, 26) indexOf is not in the v6 method registry; activated
        // version 2 is sufficient. Keeping below 3 keeps this test
        // independent of EIP-50 activation gates.
        activated_script_version: 2,
        pre_header_version: 0,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
        input_extensions: &[],
    };

    cost_trace::enable();
    let mut cost = CostAccumulator::recording_only();
    reduce_expr_with_cost(&body, &ctx, &[], &mut cost)
        .expect("indexOf script should reduce to Bool");
    let trace = cost_trace::take().expect("trace should be enabled");

    // Shape-only invariant checks. The tree was constructed so that every
    // cost-charging step routes through cost_trace::record (no Expr::Const
    // gaps), so the strict cumulative invariant must hold across every
    // adjacent pair: each entry's `total` is its predecessor's `total`
    // plus its own `delta`. This pins the trace-representation contract:
    // `total` means "accumulator AFTER the charge," not "this charge's
    // local delta" and not "accumulator BEFORE the charge."

    let labels: Vec<&str> = trace.entries.iter().map(|e| e.label.as_str()).collect();
    let indexof_entry = trace
        .entries
        .iter()
        .find(|e| e.label.starts_with("Method:indexOf"))
        .unwrap_or_else(|| panic!("trace must contain a Method:indexOf entry, got: {labels:?}"));

    // 1. Direct delta-only-bug tripwire: a regression to recording
    //    `index_of_delta.value()` would give total == delta.
    assert!(
        indexof_entry.total > indexof_entry.delta,
        "Method:indexOf trace total ({}) must exceed delta ({}); a \
         regression to delta-only recording would publish total == delta.",
        indexof_entry.total,
        indexof_entry.delta,
    );

    // 2. Strict cumulative invariant: every adjacent pair satisfies
    //    next.total == prev.total + next.delta. This catches the
    //    delta-only bug AND the pre-add bug (where total == prev.total,
    //    i.e. the accumulator snapshot before the charge was applied).
    //    The bare-first entry case is handled by checking that the first
    //    entry's `total` equals its own `delta` (effectively prev.total = 0).
    let first = trace
        .entries
        .first()
        .expect("trace must have at least one entry");
    assert_eq!(
        first.total, first.delta,
        "first trace entry total ({}) must equal its delta ({})",
        first.total, first.delta,
    );
    for pair in trace.entries.windows(2) {
        let prev = &pair[0];
        let next = &pair[1];
        assert_eq!(
            next.total,
            prev.total + next.delta,
            "trace entry {:?} total ({}) must equal previous entry {:?} \
             total ({}) plus its own delta ({}); a regression that \
             records a non-cumulative value at any cost_trace::record \
             site breaks this invariant.",
            next.label,
            next.total,
            prev.label,
            prev.total,
            next.delta,
        );
    }

    // 3. The terminal trace entry must agree with the final accumulator.
    let last = trace
        .entries
        .last()
        .expect("trace must have at least one entry");
    assert_eq!(
        last.total,
        cost.total().value(),
        "last trace entry total ({}) must equal final accumulator \
         total ({})",
        last.total,
        cost.total().value(),
    );
}
