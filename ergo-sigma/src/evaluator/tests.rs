use ergo_primitives::cost::CostAccumulator;
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};

use super::cost::*;
use super::dispatch::*;
use super::helpers::*;
use super::types::*;

#[test]
fn cost_accumulates_during_reduction() {
    // ConstPlaceholder(0) referencing a SigmaProp constant.
    let constants = vec![(
        SigmaType::SSigmaProp,
        SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
    )];
    let expr = Expr::Op(IrNode {
        opcode: 0x73,
        payload: Payload::ConstPlaceholder { index: 0 },
    });
    let ctx = ReductionContext::minimal(100_000, 0);
    let mut cost = CostAccumulator::recording_only();
    let result = reduce_expr_with_cost(&expr, &ctx, &constants, &mut cost);
    assert!(result.is_ok());
    assert!(
        cost.total().value() > 0,
        "cost should accumulate, got {}",
        cost.total().value()
    );
}

#[test]
fn cost_accumulates_height_ge_constant() {
    // BoolToSigmaProp(GE(HEIGHT, 100))
    let constants = vec![(SigmaType::SInt, SigmaValue::Int(100))];
    let height_node = Box::new(Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    }));
    let const_node = Box::new(Expr::Op(IrNode {
        opcode: 0x73,
        payload: Payload::ConstPlaceholder { index: 0 },
    }));
    let ge_node = Box::new(Expr::Op(IrNode {
        opcode: 0x92,
        payload: Payload::Two(height_node, const_node),
    }));
    let expr = Expr::Op(IrNode {
        opcode: 0xD1,
        payload: Payload::One(ge_node),
    });
    let ctx = ReductionContext::minimal(200_000, 0);
    let mut cost = CostAccumulator::recording_only();
    let result = reduce_expr_with_cost(&expr, &ctx, &constants, &mut cost);
    assert!(result.is_ok());
    let total = cost.total().value();
    assert!(
        total > 50,
        "expected cost > 50 for HEIGHT >= 100 script, got {total}"
    );
}

#[test]
fn cost_limit_exceeded_rejects() {
    // Use an enforcing accumulator with a tiny limit.
    let constants = vec![(
        SigmaType::SSigmaProp,
        SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
    )];
    let expr = Expr::Op(IrNode {
        opcode: 0x73,
        payload: Payload::ConstPlaceholder { index: 0 },
    });
    let ctx = ReductionContext::minimal(100_000, 0);
    let mut cost = CostAccumulator::new(ergo_primitives::cost::JitCost::from_jit(0));
    let result = reduce_expr_with_cost(&expr, &ctx, &constants, &mut cost);
    assert!(
        matches!(result, Err(EvalError::CostExceeded(_))),
        "expected CostExceeded error, got {result:?}"
    );
}

#[test]
fn box_equality_self_vs_inputs_0() {
    let box0 = EvalBox {
        creation_height: 100,
        script_bytes: vec![0x00],
        value: 1000,
        id: [0xAA; 32],
        transaction_id: [0u8; 32],
        output_index: 0,
        registers: [None, None, None, None, None, None],
        tokens: Vec::new(),
        raw_bytes: Vec::new(),
    };
    let ctx = ReductionContext {
        height: 200,
        self_box: Some(&box0),
        self_creation_height: 100,
        outputs: &[],
        inputs: std::slice::from_ref(&box0),
        data_inputs: &[],
        miner_pubkey: [0u8; 33],
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
    // SELF == INPUTS(0) — same underlying box
    let self_val = Value::SelfBox;
    let input0 = Value::BoxRef {
        source: BoxSource::Inputs,
        index: 0,
    };
    assert!(values_equal(&self_val, &input0, &ctx).unwrap());
    // NEQ should be false
    assert!(!values_equal(&self_val, &input0, &ctx)
        .map(|eq| !eq)
        .unwrap());
}

#[test]
fn box_equality_in_tuple() {
    let box0 = EvalBox {
        creation_height: 100,
        script_bytes: vec![0x00],
        value: 1000,
        id: [0xBB; 32],
        transaction_id: [0u8; 32],
        output_index: 0,
        registers: [None, None, None, None, None, None],
        tokens: Vec::new(),
        raw_bytes: Vec::new(),
    };
    let ctx = ReductionContext {
        height: 200,
        self_box: Some(&box0),
        self_creation_height: 100,
        outputs: &[],
        inputs: std::slice::from_ref(&box0),
        data_inputs: &[],
        miner_pubkey: [0u8; 33],
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
    // (SELF, 42) == (INPUTS(0), 42) — nested box in tuple
    let l = Value::Tuple(vec![Value::SelfBox, Value::Int(42)]);
    let r = Value::Tuple(vec![
        Value::BoxRef {
            source: BoxSource::Inputs,
            index: 0,
        },
        Value::Int(42),
    ]);
    assert!(values_equal(&l, &r, &ctx).unwrap());
}

#[test]
fn box_equality_in_option() {
    let box0 = EvalBox {
        creation_height: 100,
        script_bytes: vec![0x00],
        value: 1000,
        id: [0xCC; 32],
        transaction_id: [0u8; 32],
        output_index: 0,
        registers: [None, None, None, None, None, None],
        tokens: Vec::new(),
        raw_bytes: Vec::new(),
    };
    let ctx = ReductionContext {
        height: 200,
        self_box: Some(&box0),
        self_creation_height: 100,
        outputs: &[],
        inputs: std::slice::from_ref(&box0),
        data_inputs: &[],
        miner_pubkey: [0u8; 33],
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
    // Some(SELF) == Some(INPUTS(0))
    let l = Value::Opt(Some(Box::new(Value::SelfBox)));
    let r = Value::Opt(Some(Box::new(Value::BoxRef {
        source: BoxSource::Inputs,
        index: 0,
    })));
    assert!(values_equal(&l, &r, &ctx).unwrap());
    // None == None
    assert!(values_equal(&Value::Opt(None), &Value::Opt(None), &ctx).unwrap());
    // Some(SELF) != None
    assert!(!values_equal(&l, &Value::Opt(None), &ctx).unwrap());
}

#[test]
fn box_collection_vs_derived_tuple() {
    // INPUTS == INPUTS.filter(_ => true) — BoxCollection vs Tuple of BoxRefs
    let box0 = EvalBox {
        creation_height: 100,
        script_bytes: vec![0x00],
        value: 1000,
        id: [0xDD; 32],
        transaction_id: [0u8; 32],
        output_index: 0,
        registers: [None, None, None, None, None, None],
        tokens: Vec::new(),
        raw_bytes: Vec::new(),
    };
    let box1 = EvalBox {
        creation_height: 101,
        script_bytes: vec![0x00],
        value: 2000,
        id: [0xEE; 32],
        transaction_id: [0u8; 32],
        output_index: 0,
        registers: [None, None, None, None, None, None],
        tokens: Vec::new(),
        raw_bytes: Vec::new(),
    };
    let ctx = ReductionContext {
        height: 200,
        self_box: Some(&box0),
        self_creation_height: 100,
        outputs: &[],
        inputs: &[box0.clone(), box1.clone()],
        data_inputs: &[],
        miner_pubkey: [0u8; 33],
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
    // Left: BoxCollection(Inputs) — the raw INPUTS carrier
    let inputs_coll = Value::BoxCollection(BoxSource::Inputs);
    // Right: CollGeneric of BoxRefs — what INPUTS.filter(_ => true)
    // produces under the boxed-element coll carrier.
    let derived = Value::CollGeneric(
        vec![
            Value::BoxRef {
                source: BoxSource::Inputs,
                index: 0,
            },
            Value::BoxRef {
                source: BoxSource::Inputs,
                index: 1,
            },
        ],
        Box::new(SigmaType::SBox),
    );
    assert!(values_equal(&inputs_coll, &derived, &ctx).unwrap());
    assert!(values_equal(&derived, &inputs_coll, &ctx).unwrap()); // symmetric

    // Different length — should be false
    let partial = Value::CollGeneric(
        vec![Value::BoxRef {
            source: BoxSource::Inputs,
            index: 0,
        }],
        Box::new(SigmaType::SBox),
    );
    assert!(!values_equal(&inputs_coll, &partial, &ctx).unwrap());
}

#[test]
fn coll_box_eq_cost_uses_per_item() {
    use ergo_primitives::cost::CostAccumulator;
    let box0 = EvalBox {
        creation_height: 100,
        script_bytes: vec![0x00],
        value: 1000,
        id: [0xAA; 32],
        registers: [None, None, None, None, None, None],
        transaction_id: [0u8; 32],
        output_index: 0,
        tokens: Vec::new(),
        raw_bytes: Vec::new(),
    };
    let box1 = EvalBox {
        creation_height: 101,
        script_bytes: vec![0x00],
        value: 2000,
        id: [0xBB; 32],
        registers: [None, None, None, None, None, None],
        transaction_id: [0u8; 32],
        output_index: 0,
        tokens: Vec::new(),
        raw_bytes: Vec::new(),
    };
    let ctx = ReductionContext {
        height: 200,
        self_box: Some(&box0),
        self_creation_height: 100,
        outputs: &[],
        inputs: &[box0.clone(), box1.clone()],
        data_inputs: &[],
        miner_pubkey: [0u8; 33],
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
    // BoxCollection(Inputs) with 2 boxes
    // Expected cost: MatchType(1) + PerItem(base=15, perChunk=5, chunk=1, n=2)
    // = 1 + (15 + 5*2) = 26
    let mut cost = CostAccumulator::recording_only();
    eq_with_cost(
        &Value::BoxCollection(BoxSource::Inputs),
        &Value::BoxCollection(BoxSource::Inputs),
        &ctx,
        &mut cost,
    )
    .unwrap();
    assert_eq!(cost.total().value(), 26);

    // Derived `CollGeneric` of BoxRefs (same length) should get the
    // same cost — the post-disambiguation boxed-element coll carrier
    // routes through the `CollGeneric` SBox-descriptor branch in
    // `eq_with_cost`, charging as Coll[Box] EQ.
    let mut cost2 = CostAccumulator::recording_only();
    let derived = Value::CollGeneric(
        vec![
            Value::BoxRef {
                source: BoxSource::Inputs,
                index: 0,
            },
            Value::BoxRef {
                source: BoxSource::Inputs,
                index: 1,
            },
        ],
        Box::new(SigmaType::SBox),
    );
    eq_with_cost(&derived, &derived, &ctx, &mut cost2).unwrap();
    assert_eq!(cost2.total().value(), 26);

    // Empty CollBox (e.g. INPUTS.filter(_ => false)) — charges EQ_COA_Box
    // PerItemCost(15, 5, 1) with 0 items: Scala chunks = (0-1)/1+1 = 0, cost = 15+5*0 = 15
    // Plus 1 MatchType dispatch: total = 1 + 15 = 16
    let mut cost3 = CostAccumulator::recording_only();
    eq_with_cost(
        &Value::CollBox(vec![]),
        &Value::CollBox(vec![]),
        &ctx,
        &mut cost3,
    )
    .unwrap();
    assert_eq!(cost3.total().value(), 16);
}

/// `eq_with_cost` must charge the exact Scala `DataValueComparer` delta (the
/// per-comparison cost, on top of the eval frame) for collections and tuples,
/// AND return the same boolean as `values_equal`. Deltas verified against the
/// JVM reference vectors (NEQ_of_collections / _nested / _tuples): each row's
/// blessed `expected` cost is `95 (frame) + the delta asserted here`.
#[test]
fn eq_with_cost_matches_scala_deltas() {
    let ctx = ReductionContext::minimal(500_000, 0);
    let eq_cost = |l: &Value, r: &Value| -> (bool, u64) {
        let mut cost = CostAccumulator::recording_only();
        let eq = eq_with_cost(l, r, &ctx, &mut cost).unwrap();
        (eq, cost.total().value())
    };
    let ge = |b: u8| Value::GroupElement([b; 33]);
    let coll_ge = |n: usize| {
        Value::CollGeneric(
            (0..n).map(|i| ge(i as u8)).collect(),
            Box::new(SigmaType::SGroupElement),
        )
    };
    let coll_bigint = |n: usize| {
        Value::CollGeneric(
            (0..n).map(|i| Value::BigInt((i as u32).into())).collect(),
            Box::new(SigmaType::SBigInt),
        )
    };

    // Length mismatch: only MatchType(1) is charged, regardless of element type.
    assert_eq!(
        eq_cost(&Value::CollBytes(vec![]), &Value::CollBytes(vec![1])).1,
        1
    );
    assert_eq!(
        eq_cost(&coll_ge(1), &coll_ge(0)).1,
        1,
        "GE length-mismatch charges only MatchType"
    );
    assert_eq!(eq_cost(&coll_bigint(0), &coll_bigint(1)).1, 1);

    // Descriptor colls, equal length: MatchType(1) + EQ_COA PerItem(full len).
    // Coll[Byte] n=2: 1 + (15 + 2*ceil(2/128)) = 1 + 17 = 18.
    assert_eq!(
        eq_cost(&Value::CollBytes(vec![1, 2]), &Value::CollBytes(vec![1, 2])).1,
        18
    );
    // Coll[GroupElement] n=0 (CollGeneric SGroupElement, cs1): 1 + (15 + 5*0) = 16.
    assert_eq!(eq_cost(&coll_ge(0), &coll_ge(0)).1, 16);
    // Coll[BigInt] n=0 (cs5): chunks(0)=(0-1)/5+1=1 -> 1 + (15 + 7*1) = 23.
    assert_eq!(eq_cost(&coll_bigint(0), &coll_bigint(0)).1, 23);

    // Tuple `&&` short-circuit: differ at first element charges only the first.
    let t = |a: i8, b: i8| Value::Tuple(vec![Value::Byte(a), Value::Byte(b)]);
    assert_eq!(
        eq_cost(&t(0, 1), &t(1, 1)),
        (false, 7),
        "EQ_Tuple(4)+EQ_Prim(3), short-circuit"
    );
    assert_eq!(
        eq_cost(&t(1, 0), &t(1, 1)),
        (false, 10),
        "first equal, second differs: 4+3+3"
    );
    assert_eq!(eq_cost(&t(1, 1), &t(1, 1)), (true, 10), "all equal: 4+3+3");

    // Scalar GroupElement: EQ_GroupElement(172).
    assert_eq!(eq_cost(&ge(7), &ge(7)), (true, 172));

    // Nested Coll[Coll[Int]] (fallback): outer MatchType + per-element recursion
    // + EQ_Coll(10,2,1) over k_eff.
    let cci = |inner: Vec<Vec<i32>>| {
        Value::CollGeneric(
            inner.into_iter().map(Value::CollInt).collect(),
            Box::new(SigmaType::SColl(Box::new(SigmaType::SInt))),
        )
    };
    // both empty outer: 1(MT) + EQ_Coll.compute(0)=10 = 11.
    assert_eq!(eq_cost(&cci(vec![]), &cci(vec![])), (true, 11));
    // one element, inner equal-length differing value Coll(1) vs Coll(2):
    // 1(outer MT) + [inner: 1(MT)+PerItem(15,2,64).compute(1)=17 = 18] + EQ_Coll.compute(1)=12 = 31.
    assert_eq!(
        eq_cost(&cci(vec![vec![1]]), &cci(vec![vec![2]])),
        (false, 31)
    );
    // one element, inner length-mismatch Coll() vs Coll(1):
    // 1(outer MT) + [inner: 1(MT) only] + EQ_Coll.compute(1)=12 = 14.
    assert_eq!(
        eq_cost(&cci(vec![vec![]]), &cci(vec![vec![1]])),
        (false, 14)
    );
}

/// Value-safety: `eq_with_cost` must return the SAME boolean as the uncosted
/// `values_equal` for every shape — only the cost is being changed, never the
/// equality result.
#[test]
fn eq_with_cost_boolean_matches_values_equal() {
    let ctx = ReductionContext::minimal(500_000, 0);
    let ge = |b: u8| Value::GroupElement([b; 33]);
    let cases: Vec<(Value, Value)> = vec![
        (Value::Int(1), Value::Int(1)),
        (Value::Int(1), Value::Int(2)),
        (Value::CollBytes(vec![1, 2]), Value::CollBytes(vec![1, 2])),
        (Value::CollBytes(vec![1, 2]), Value::CollBytes(vec![1, 3])),
        (Value::CollBytes(vec![1]), Value::CollBytes(vec![1, 2])),
        (
            Value::CollGeneric(vec![ge(1)], Box::new(SigmaType::SGroupElement)),
            Value::CollGeneric(vec![ge(1)], Box::new(SigmaType::SGroupElement)),
        ),
        (
            Value::CollGeneric(vec![ge(1)], Box::new(SigmaType::SGroupElement)),
            Value::CollGeneric(vec![ge(2)], Box::new(SigmaType::SGroupElement)),
        ),
        (
            Value::Tuple(vec![Value::Byte(1), Value::Byte(2)]),
            Value::Tuple(vec![Value::Byte(1), Value::Byte(2)]),
        ),
        (
            Value::Tuple(vec![Value::Byte(1), Value::Byte(2)]),
            Value::Tuple(vec![Value::Byte(9), Value::Byte(2)]),
        ),
        (
            Value::Opt(Some(Box::new(Value::Int(5)))),
            Value::Opt(Some(Box::new(Value::Int(5)))),
        ),
        (Value::Opt(None), Value::Opt(Some(Box::new(Value::Int(5))))),
        (
            Value::CollGeneric(
                vec![Value::CollInt(vec![1])],
                Box::new(SigmaType::SColl(Box::new(SigmaType::SInt))),
            ),
            Value::CollGeneric(
                vec![Value::CollInt(vec![1])],
                Box::new(SigmaType::SColl(Box::new(SigmaType::SInt))),
            ),
        ),
    ];
    // Check both operand orders: dispatch is left-shape-driven, so a swapped
    // pair exercises a different code path and catches asymmetric regressions.
    for (l, r) in &cases {
        for (a, b) in [(l, r), (r, l)] {
            let mut cost = CostAccumulator::recording_only();
            let costed = eq_with_cost(a, b, &ctx, &mut cost).unwrap();
            let plain = crate::evaluator::helpers::values_equal(a, b, &ctx).unwrap();
            assert_eq!(
                costed, plain,
                "eq_with_cost must match values_equal for {a:?} vs {b:?}"
            );
        }
    }
}

/// SigmaProp `==` mirrors Scala `equalSigmaBoolean` for BOTH cost and the
/// consensus-critical value/error asymmetry: a LEAF (ProveDlog/ProveDHTuple/
/// TrivialProp) on the left vs a different-constructor right returns `false`,
/// but a CONJECTURE (Cand/Cor/Cthreshold) on the left vs a different-constructor
/// right ERRORS (Scala `sys.error`). Order-sensitive. eq_with_cost (costed) and
/// values_equal (uncosted) must agree, including on Err.
#[test]
fn sigmaprop_equality_value_error_and_cost() {
    use ergo_primitives::group_element::GroupElement;
    let ctx = ReductionContext::minimal(500_000, 0);
    let dlog = |b: u8| Value::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes([b; 33])));
    let cand = |b: u8| {
        Value::SigmaProp(SigmaBoolean::Cand(vec![SigmaBoolean::ProveDlog(
            GroupElement::from_bytes([b; 33]),
        )]))
    };
    let eqc = |l: &Value, r: &Value| {
        let mut c = CostAccumulator::recording_only();
        eq_with_cost(l, r, &ctx, &mut c).map(|b| (b, c.total().value()))
    };
    let ve = |l: &Value, r: &Value| crate::evaluator::helpers::values_equal(l, r, &ctx);

    // ProveDlog == ProveDlog (equal): MatchType(equalDataValues) + MatchType(node)
    // + EQ_GroupElement(172) = 174.
    assert_eq!(eqc(&dlog(1), &dlog(1)).unwrap(), (true, 174));
    assert_eq!(eqc(&dlog(1), &dlog(2)).unwrap(), (false, 174));

    // LEAF left vs conjecture right -> false (NOT error), order-sensitive.
    assert!(!eqc(&dlog(1), &cand(1)).unwrap().0);
    assert!(!ve(&dlog(1), &cand(1)).unwrap());

    // CONJECTURE left vs leaf right: the DataValueComparer path (eq_with_cost,
    // used by ==/!=/indexOf) ERRORS; the plain-equality authority (values_equal,
    // used by startsWith/endsWith) returns false (Scala `xs.startsWith` uses
    // structural `==`, never throws). The two paths INTENTIONALLY differ here.
    assert!(matches!(
        eqc(&cand(1), &dlog(1)),
        Err(EvalError::RuntimeException(_))
    ));
    assert!(!ve(&cand(1), &dlog(1)).unwrap());

    // Same conjecture constructor, equal children -> true (no error).
    assert!(eqc(&cand(1), &cand(1)).unwrap().0);

    // Cthreshold k-mismatch is false (NOT error — same constructor).
    let cth = |k: u8| {
        Value::SigmaProp(SigmaBoolean::Cthreshold {
            k,
            children: vec![SigmaBoolean::ProveDlog(GroupElement::from_bytes([1; 33]))],
        })
    };
    assert!(eqc(&cth(1), &cth(1)).unwrap().0);
    // Different k with same single child: equalSigmaBooleans not reached; false.
    let cth2 = Value::SigmaProp(SigmaBoolean::Cthreshold {
        k: 1,
        children: vec![
            SigmaBoolean::ProveDlog(GroupElement::from_bytes([1; 33])),
            SigmaBoolean::ProveDlog(GroupElement::from_bytes([2; 33])),
        ],
    });
    assert!(!eqc(&cth(1), &cth2).unwrap().0);
}

#[test]
fn infer_collection_from_mapper_body() {
    use ergo_ser::opcode::{Expr, IrNode, Payload};

    let empty_bindings = std::collections::HashMap::new();
    let empty_constants: &[(SigmaType, SigmaValue)] = &[];

    // Mapper body is ExtractAmount (0xC1) → Long
    let amount_body = Expr::Op(IrNode {
        opcode: 0xC1,
        payload: Payload::One(Box::new(Expr::Op(IrNode {
            opcode: 0xA7,
            payload: Payload::Zero,
        }))),
    });
    let empty_long =
        infer_collection(vec![], &amount_body, &empty_bindings, empty_constants).unwrap();
    assert!(matches!(empty_long, Value::CollLong(ref v) if v.is_empty()));

    // Mapper body is comparison (0x91 Gt) → Bool
    let gt_body = Expr::Op(IrNode {
        opcode: 0x91,
        payload: Payload::Two(
            Box::new(Expr::Op(IrNode {
                opcode: 0xC1,
                payload: Payload::One(Box::new(Expr::Op(IrNode {
                    opcode: 0xA7,
                    payload: Payload::Zero,
                }))),
            })),
            Box::new(Expr::Const {
                tpe: SigmaType::SLong,
                val: SigmaValue::Long(0),
            }),
        ),
    });
    let empty_bool = infer_collection(vec![], &gt_body, &empty_bindings, empty_constants).unwrap();
    assert!(matches!(empty_bool, Value::CollBool(ref v) if v.is_empty()));

    // Mapper body is Self (0xA7) → Box
    let self_body = Expr::Op(IrNode {
        opcode: 0xA7,
        payload: Payload::Zero,
    });
    let empty_box = infer_collection(vec![], &self_body, &empty_bindings, empty_constants).unwrap();
    assert!(matches!(empty_box, Value::CollBox(ref v) if v.is_empty()));

    // Mapper body using ValUse with typed binding → Long
    let mut typed_bindings = std::collections::HashMap::new();
    typed_bindings.insert(1, SigmaType::SBox);
    let valuse_body = Expr::Op(IrNode {
        opcode: 0xC1,
        payload: Payload::One(Box::new(Expr::Op(IrNode {
            opcode: 0x72,
            payload: Payload::ValUse { id: 1 },
        }))),
    });
    let empty_via_valuse =
        infer_collection(vec![], &valuse_body, &typed_bindings, empty_constants).unwrap();
    assert!(matches!(empty_via_valuse, Value::CollLong(ref v) if v.is_empty()));

    // Mapper body is If(cond, ExtractAmount(self), 0L) → Long (from then branch)
    let if_body = Expr::Op(IrNode {
        opcode: 0x95,
        payload: Payload::Three(
            Box::new(Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            }),
            Box::new(Expr::Op(IrNode {
                opcode: 0xC1,
                payload: Payload::One(Box::new(Expr::Op(IrNode {
                    opcode: 0xA7,
                    payload: Payload::Zero,
                }))),
            })),
            Box::new(Expr::Const {
                tpe: SigmaType::SLong,
                val: SigmaValue::Long(0),
            }),
        ),
    });
    let empty_if = infer_collection(vec![], &if_body, &empty_bindings, empty_constants).unwrap();
    assert!(matches!(empty_if, Value::CollLong(ref v) if v.is_empty()));

    // Mapper body is CreationInfo (0xC7) → STuple([SInt, SColl(SByte)])
    let ci_body = Expr::Op(IrNode {
        opcode: 0xC7,
        payload: Payload::One(Box::new(Expr::Op(IrNode {
            opcode: 0xA7,
            payload: Payload::Zero,
        }))),
    });
    let empty_ci = infer_collection(vec![], &ci_body, &empty_bindings, empty_constants).unwrap();
    // CreationInfo is a tuple type — not a primitive `CollKind` — so
    // `infer_collection`'s empty-path fallback returns the boxed-
    // element coll carrier (`CollGeneric`), not a real `Value::Tuple`.
    assert!(matches!(empty_ci, Value::CollGeneric(ref v, _) if v.is_empty()));

    // Non-empty — inferred from first element, not body
    let non_empty = infer_collection(
        vec![Value::BoxRef {
            source: BoxSource::Inputs,
            index: 0,
        }],
        &amount_body,
        &empty_bindings,
        empty_constants,
    )
    .unwrap();
    assert!(matches!(non_empty, Value::CollBox(_)));
}

#[test]
fn empty_map_with_captured_closure_value() {
    use ergo_ser::opcode::{Expr, IrNode, Payload};

    // Simulate: val x = 1L; INPUTS.filter(_ => false).map(_ => x)
    // The mapper body is ValUse(id=5) which refers to a captured Long value.
    // The captured_env has id=5 → Value::Long(1), param_types has id=10 → SBox.
    // infer_expr_type should resolve ValUse(5) from captured env → SLong.
    let mapper_body = Expr::Op(IrNode {
        opcode: 0x72, // ValUse
        payload: Payload::ValUse { id: 5 },
    });
    let mut captured_env = std::collections::HashMap::new();
    captured_env.insert(5, Value::Long(1));

    let mapper = Value::Func {
        captured_env: std::rc::Rc::new(captured_env),
        params: vec![10],
        param_types: vec![(10, Some(SigmaType::SBox))],
        body: Box::new(mapper_body),
    };

    // Empty input collection (filter removed everything)
    let empty_input = Value::CollBox(vec![]);
    let (_input_kind, items) =
        collection_to_values(empty_input, &ReductionContext::minimal(100, 0)).unwrap();
    assert!(items.is_empty());

    // Now simulate what MapCollection does with the Func
    if let Value::Func {
        captured_env,
        params: _,
        param_types,
        body,
    } = &mapper
    {
        let mut param_bindings = std::collections::HashMap::new();
        for (id, val) in captured_env.iter() {
            if let Some(t) = value_to_sigma_type(val) {
                param_bindings.insert(*id, t);
            }
        }
        for (id, tpe) in param_types {
            if let Some(t) = tpe {
                param_bindings.insert(*id, t.clone());
            }
        }
        let result = infer_collection(vec![], body, &param_bindings, &[]).unwrap();
        // Should be CollLong, not Tuple — the captured Long value's type was resolved
        assert!(
            matches!(result, Value::CollLong(ref v) if v.is_empty()),
            "expected CollLong(vec![]), got {result:?}"
        );
    } else {
        panic!("expected Func");
    }
}

// ── Per-opcode evaluation tests ──────────────────────────────
//
// Sections below follow the AGENTS.md test convention:
//   helpers -> happy path -> error paths -> oracle parity.
// Multi-batch happy-path corpora are grouped by topic with their
// own `// ── Batch N: ...` sub-headers retained for navigation.

// ----- helpers -----

fn op(opcode: u8, payload: Payload) -> Expr {
    Expr::Op(IrNode { opcode, payload })
}

fn const_int(v: i32) -> Expr {
    Expr::Const {
        tpe: SigmaType::SInt,
        val: SigmaValue::Int(v),
    }
}

fn const_long(v: i64) -> Expr {
    Expr::Const {
        tpe: SigmaType::SLong,
        val: SigmaValue::Long(v),
    }
}

fn const_bool(v: bool) -> Expr {
    Expr::Const {
        tpe: SigmaType::SBoolean,
        val: SigmaValue::Boolean(v),
    }
}

fn const_bytes(v: Vec<u8>) -> Expr {
    use ergo_ser::sigma_value::CollValue;
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        val: SigmaValue::Coll(CollValue::Bytes(v)),
    }
}

/// A flat `(Int, Int, ...)` tuple as a CONSTANT. Tuples with more than 2
/// elements only exist as values/constants (STuple = Coll[Any]); the
/// `0x86 CreateTuple` opcode evaluates only pairs (Scala `Tuple.eval`
/// errors for arity != 2). Use this to exercise SelectField on >2-element
/// tuples without building a non-evaluable CreateTuple node.
fn int_tuple_const(vals: &[i32]) -> Expr {
    Expr::Const {
        tpe: SigmaType::STuple(vals.iter().map(|_| SigmaType::SInt).collect()),
        val: SigmaValue::Tuple(vals.iter().map(|&v| SigmaValue::Int(v)).collect()),
    }
}

fn run_eval(expr: &Expr) -> Value {
    eval_to_value(expr, &ReductionContext::minimal(500_000, 0), &[]).unwrap()
}

fn run_eval_ctx(expr: &Expr, ctx: &ReductionContext<'_>) -> Value {
    eval_to_value(expr, ctx, &[]).unwrap()
}

fn run_eval_with_constants(expr: &Expr, constants: &[(SigmaType, SigmaValue)]) -> Value {
    eval_to_value(expr, &ReductionContext::minimal(500_000, 0), constants).unwrap()
}

// -- Audit: every `Value` variant must have a `PartialEq` self-self arm --

/// Pin the cleanup landed by `10d5b9c` (UnsignedBigInt) plus the rest
/// of the variants. Any future `Value` variant that lands without a
/// matching arm in `impl PartialEq for Value` falls through to the
/// catch-all `_ => false`, which silently breaks every script-level
/// `==` on that carrier — `TrivialProp(false)` reductions whose
/// proof can never verify. This test constructs one instance of
/// each variant and asserts `v == v.clone()`; a future variant
/// addition that forgets to add a `(V(a), V(b)) => a == b` arm
/// flips it red.
#[test]
fn every_value_variant_equals_itself() {
    use std::rc::Rc;
    let b = make_test_box();
    let header = EvalHeader {
        id: [0xAA; 32],
        version: 1,
        parent_id: [0xBB; 32],
        ad_proofs_root: [0xCC; 32],
        state_root: [0xDD; 33],
        transactions_root: [0xEE; 32],
        timestamp: 1,
        n_bits: 0x1d_00_ff_ff,
        height: 1,
        extension_root: [0xFF; 32],
        miner_pk: [0x02; 33],
        pow_onetime_pk: SECP256K1_GENERATOR,
        pow_nonce: [0; 8],
        pow_distance: num_bigint::BigInt::from(0),
        votes: [0; 3],
        unparsed_bytes: Vec::new(),
    };
    let avl = ergo_ser::sigma_value::AvlTreeData {
        digest: [0x11; 33].to_vec(),
        insert_allowed: true,
        update_allowed: true,
        remove_allowed: true,
        key_length: 32,
        value_length_opt: None,
    };
    let cases: Vec<(&'static str, Value)> = vec![
        ("Unit", Value::Unit),
        ("Byte", Value::Byte(7)),
        ("Short", Value::Short(7)),
        ("Int", Value::Int(7)),
        ("Long", Value::Long(7)),
        ("BigInt", Value::BigInt(7u32.into())),
        ("UnsignedBigInt", Value::UnsignedBigInt(7u32.into())),
        ("Bool", Value::Bool(true)),
        (
            "SigmaProp",
            Value::SigmaProp(SigmaBoolean::TrivialProp(true)),
        ),
        ("Tuple", Value::Tuple(vec![Value::Int(1), Value::Int(2)])),
        ("CollBool", Value::CollBool(vec![true, false])),
        ("CollBytes", Value::CollBytes(vec![1, 2, 3])),
        ("Tokens", Value::Tokens(vec![([0x42; 32], 100)])),
        ("CollInt", Value::CollInt(vec![1, 2, 3])),
        ("CollLong", Value::CollLong(vec![1, 2, 3])),
        ("CollShort", Value::CollShort(vec![1, 2, 3])),
        (
            "CollSigmaProp",
            Value::CollSigmaProp(vec![SigmaBoolean::TrivialProp(true)]),
        ),
        ("CollBox", Value::CollBox(vec![Value::SelfBox])),
        ("GroupElement", Value::GroupElement(SECP256K1_GENERATOR)),
        ("Opt", Value::Opt(Some(Box::new(Value::Int(42))))),
        ("Opt_None", Value::Opt(None)),
        ("SelfBox", Value::SelfBox),
        (
            "BoxRef",
            Value::BoxRef {
                source: BoxSource::Inputs,
                index: 0,
            },
        ),
        ("BoxCollection", Value::BoxCollection(BoxSource::Inputs)),
        ("Global", Value::Global),
        ("PreHeader", Value::PreHeader),
        ("InlineBox", Value::InlineBox(Box::new(b.clone()))),
        ("AvlTree", Value::AvlTree(avl)),
        ("Header", Value::Header(Box::new(header.clone()))),
        ("CollHeader", Value::CollHeader(vec![header])),
    ];
    for (name, v) in &cases {
        assert!(
            v == &v.clone(),
            "Value::{name} fails self-equality — missing PartialEq arm?",
        );
    }

    // `Value::Func` is intentionally never equal (Scala does not
    // support function equality). Pin that explicitly so a future
    // "let's add Func equality" refactor at least gets a red test.
    let f = Value::Func {
        captured_env: Rc::new(Env::new()),
        params: vec![],
        param_types: vec![],
        body: Box::new(Expr::Op(IrNode {
            opcode: 0x7F,
            payload: Payload::Zero,
        })),
    };
    assert!(
        f != f.clone(),
        "Value::Func must never compare equal — Ergo has no function equality",
    );
}

// ----- happy path -----
//
// Grouped by opcode taxonomy (arithmetic, comparison, boolean, ...).

// -- Arithmetic --

#[test]
fn opcode_plus_int() {
    let expr = op(
        0x9A,
        Payload::Two(Box::new(const_int(10)), Box::new(const_int(32))),
    );
    assert_eq!(run_eval(&expr), Value::Int(42));
}

#[test]
fn opcode_minus_long() {
    let expr = op(
        0x99,
        Payload::Two(Box::new(const_long(100)), Box::new(const_long(37))),
    );
    assert_eq!(run_eval(&expr), Value::Long(63));
}

#[test]
fn opcode_multiply_int() {
    let expr = op(
        0x9C,
        Payload::Two(Box::new(const_int(7)), Box::new(const_int(6))),
    );
    assert_eq!(run_eval(&expr), Value::Int(42));
}

#[test]
fn opcode_division_int() {
    let expr = op(
        0x9D,
        Payload::Two(Box::new(const_int(85)), Box::new(const_int(2))),
    );
    assert_eq!(run_eval(&expr), Value::Int(42));
}

#[test]
fn opcode_modulo_int() {
    let expr = op(
        0x9E,
        Payload::Two(Box::new(const_int(47)), Box::new(const_int(5))),
    );
    assert_eq!(run_eval(&expr), Value::Int(2));
}

#[test]
fn opcode_negation_long() {
    let expr = op(0xF0, Payload::One(Box::new(const_long(42))));
    assert_eq!(run_eval(&expr), Value::Long(-42));
}

// -- Comparisons --

#[test]
fn opcode_gt_true() {
    let expr = op(
        0x91,
        Payload::Two(Box::new(const_int(10)), Box::new(const_int(5))),
    );
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

#[test]
fn opcode_gt_false() {
    let expr = op(
        0x91,
        Payload::Two(Box::new(const_int(3)), Box::new(const_int(5))),
    );
    assert_eq!(run_eval(&expr), Value::Bool(false));
}

#[test]
fn opcode_le_equal() {
    let expr = op(
        0x90,
        Payload::Two(Box::new(const_long(7)), Box::new(const_long(7))),
    );
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

#[test]
fn opcode_ge_int() {
    let expr = op(
        0x92,
        Payload::Two(Box::new(const_int(5)), Box::new(const_int(5))),
    );
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

#[test]
fn opcode_lt_int() {
    let expr = op(
        0x8F,
        Payload::Two(Box::new(const_int(3)), Box::new(const_int(5))),
    );
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

// -- EQ / NEQ --

#[test]
fn opcode_eq_int_true() {
    let expr = op(
        0x93,
        Payload::Two(Box::new(const_int(42)), Box::new(const_int(42))),
    );
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

#[test]
fn opcode_eq_int_false() {
    let expr = op(
        0x93,
        Payload::Two(Box::new(const_int(1)), Box::new(const_int(2))),
    );
    assert_eq!(run_eval(&expr), Value::Bool(false));
}

#[test]
fn eq_coll_bytes_vs_coll_int_is_strict() {
    // Cross-type equality is intentionally not bridged: Scala
    // DataValueComparer is type-strict, and with Value::Byte produced
    // at Coll[Byte] element boundaries, map/filter over Coll[Byte]
    // does not silently become CollInt. Any remaining cross-type
    // compare is a legitimate type mismatch.
    let bytes = Value::CollBytes(vec![10, 20, 78]);
    let ints = Value::CollInt(vec![10, 20, 78]);
    assert!(
        bytes != ints,
        "CollBytes vs CollInt must be strict type mismatch"
    );
    assert!(ints != bytes, "symmetric");
}

#[test]
fn eq_coll_bytes_vs_coll_int_different_is_also_strict() {
    let bytes = Value::CollBytes(vec![10, 20]);
    let ints = Value::CollInt(vec![10, 30]);
    assert!(bytes != ints);
}

#[test]
fn eq_coll_bytes_vs_coll_int_different_len_is_also_strict() {
    let bytes = Value::CollBytes(vec![10, 20]);
    let ints = Value::CollInt(vec![10]);
    assert!(bytes != ints);
}

#[test]
fn opcode_neq_int() {
    let expr = op(
        0x94,
        Payload::Two(Box::new(const_int(1)), Box::new(const_int(2))),
    );
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

#[test]
fn opcode_eq_coll_bytes() {
    let a = const_bytes(vec![1, 2, 3]);
    let b = const_bytes(vec![1, 2, 3]);
    let expr = op(0x93, Payload::Two(Box::new(a), Box::new(b)));
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

#[test]
fn opcode_eq_coll_bytes_different() {
    let a = const_bytes(vec![1, 2, 3]);
    let b = const_bytes(vec![1, 2, 4]);
    let expr = op(0x93, Payload::Two(Box::new(a), Box::new(b)));
    assert_eq!(run_eval(&expr), Value::Bool(false));
}

// -- Boolean logic --

#[test]
fn opcode_bin_and() {
    let expr = op(
        0xED,
        Payload::Two(Box::new(const_bool(true)), Box::new(const_bool(false))),
    );
    assert_eq!(run_eval(&expr), Value::Bool(false));
}

#[test]
fn opcode_bin_or() {
    let expr = op(
        0xEC,
        Payload::Two(Box::new(const_bool(false)), Box::new(const_bool(true))),
    );
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

#[test]
fn opcode_logical_not() {
    let expr = op(0xEF, Payload::One(Box::new(const_bool(true))));
    assert_eq!(run_eval(&expr), Value::Bool(false));
}

// -- If-then-else --

#[test]
fn opcode_if_true_branch() {
    let expr = op(
        0x95,
        Payload::Three(
            Box::new(const_bool(true)),
            Box::new(const_int(1)),
            Box::new(const_int(2)),
        ),
    );
    assert_eq!(run_eval(&expr), Value::Int(1));
}

#[test]
fn opcode_if_false_branch() {
    let expr = op(
        0x95,
        Payload::Three(
            Box::new(const_bool(false)),
            Box::new(const_int(1)),
            Box::new(const_int(2)),
        ),
    );
    assert_eq!(run_eval(&expr), Value::Int(2));
}

// -- Context --

#[test]
fn opcode_height() {
    let expr = op(0xA3, Payload::Zero);
    let ctx = ReductionContext::minimal(750_000, 0);
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Int(750_000));
}

#[test]
fn opcode_inputs_outputs() {
    let expr_in = op(0xA4, Payload::Zero);
    let expr_out = op(0xA5, Payload::Zero);
    assert!(matches!(
        run_eval(&expr_in),
        Value::BoxCollection(BoxSource::Inputs)
    ));
    assert!(matches!(
        run_eval(&expr_out),
        Value::BoxCollection(BoxSource::Outputs)
    ));
}

// -- Type coercions --

#[test]
fn opcode_upcast_int_to_long() {
    let expr = op(
        0x7E,
        Payload::NumericCast {
            input: Box::new(const_int(42)),
            tpe: SigmaType::SLong,
        },
    );
    assert_eq!(run_eval(&expr), Value::Long(42));
}

#[test]
fn opcode_downcast_long_to_int() {
    let expr = op(
        0x7D,
        Payload::NumericCast {
            input: Box::new(const_long(42)),
            tpe: SigmaType::SInt,
        },
    );
    assert_eq!(run_eval(&expr), Value::Int(42));
}

// -- Collection operations --

#[test]
fn opcode_size_of_coll() {
    let coll = const_bytes(vec![10, 20, 30]);
    let expr = op(0xB1, Payload::One(Box::new(coll)));
    assert_eq!(run_eval(&expr), Value::Int(3));
}

#[test]
fn opcode_select_field() {
    // Tuple(10, 20) then SelectField index=2 (1-based)
    let tuple = op(
        0x86,
        Payload::Tuple {
            items: vec![const_int(10), const_int(20)],
        },
    );
    let expr = op(
        0x8C,
        Payload::SelectField {
            input: Box::new(tuple),
            field_idx: 2,
        },
    );
    assert_eq!(run_eval(&expr), Value::Int(20));
}

/// CreateTuple (0x86) must reject any arity other than 2 at evaluation
/// time. Scala `Tuple.eval` does `if (items.length != 2) syntax.error(...)`
/// (values.scala) — only 2-element tuples are valid in v4/v5/v6; an arity-3
/// (or arity-0/1) tuple is deserializable but throws when evaluated. The
/// check is unconditional (no ErgoTree-version gate). A valid pair still
/// evaluates. (ExtractCreationInfo is a separate node and is unaffected.)
#[test]
fn tuple_arity_not_two_rejects() {
    // Arity-2 still works.
    let pair = op(
        0x86,
        Payload::Tuple {
            items: vec![const_int(1), const_int(2)],
        },
    );
    assert_eq!(
        run_eval(&pair),
        Value::Tuple(vec![Value::Int(1), Value::Int(2)])
    );

    // Arity-3 errors.
    let triple = op(
        0x86,
        Payload::Tuple {
            items: vec![const_bool(true), const_int(2), const_int(3)],
        },
    );
    assert!(
        matches!(run_eval_err(&triple), EvalError::ArityMismatch { .. }),
        "arity-3 tuple must error"
    );

    // Arity-1 errors too.
    let single = op(
        0x86,
        Payload::Tuple {
            items: vec![const_int(1)],
        },
    );
    assert!(
        matches!(run_eval_err(&single), EvalError::ArityMismatch { .. }),
        "arity-1 tuple must error"
    );
}

// -- Constants --

#[test]
fn opcode_const_placeholder() {
    let constants = vec![(SigmaType::SInt, SigmaValue::Int(99))];
    let expr = op(0x73, Payload::ConstPlaceholder { index: 0 });
    assert_eq!(run_eval_with_constants(&expr, &constants), Value::Int(99));
}

// -- Sigma propositions --

#[test]
fn opcode_bool_to_sigma_prop_true() {
    let expr = op(0xD1, Payload::One(Box::new(const_bool(true))));
    assert_eq!(
        run_eval(&expr),
        Value::SigmaProp(SigmaBoolean::TrivialProp(true)),
    );
}

#[test]
fn opcode_bool_to_sigma_prop_false() {
    let expr = op(0xD1, Payload::One(Box::new(const_bool(false))));
    assert_eq!(
        run_eval(&expr),
        Value::SigmaProp(SigmaBoolean::TrivialProp(false)),
    );
}

// ── Negative-path tests ──────────────────────────────────────

// ----- error paths -----

fn const_coll_int(vals: Vec<i32>) -> Expr {
    use ergo_ser::sigma_value::CollValue;
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SInt)),
        val: SigmaValue::Coll(CollValue::Values(
            vals.into_iter().map(SigmaValue::Int).collect(),
        )),
    }
}

fn const_coll_bool(vals: Vec<bool>) -> Expr {
    use ergo_ser::sigma_value::CollValue;
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SBoolean)),
        val: SigmaValue::Coll(CollValue::BoolBits(vals)),
    }
}

fn run_eval_err(expr: &Expr) -> EvalError {
    eval_to_value(expr, &ReductionContext::minimal(500_000, 0), &[]).unwrap_err()
}

#[test]
fn error_division_by_zero_int() {
    let expr = op(
        0x9D,
        Payload::Two(Box::new(const_int(42)), Box::new(const_int(0))),
    );
    let err = run_eval_err(&expr);
    // Division by zero is a runtime arithmetic error (Scala/Java throw
    // ArithmeticException), matching the Byte/Short divide-by-zero arms —
    // not a TypeError.
    assert!(
        matches!(err, EvalError::RuntimeException(_)),
        "expected RuntimeException, got {err:?}"
    );
}

#[test]
fn error_modulo_by_zero_int() {
    let expr = op(
        0x9E,
        Payload::Two(Box::new(const_int(42)), Box::new(const_int(0))),
    );
    let err = run_eval_err(&expr);
    // Modulo by zero is a runtime arithmetic error, matching Division and
    // the Byte/Short arms — not a TypeError.
    assert!(
        matches!(err, EvalError::RuntimeException(_)),
        "expected RuntimeException, got {err:?}"
    );
}

/// Long and BigInt divide/modulo by zero must also be RuntimeException,
/// matching Int and the Byte/Short arms (consistency across all numeric
/// types). For BigInt the explicit zero arm also guards the divide path,
/// which would otherwise panic in num_bigint.
#[test]
fn error_div_mod_by_zero_long_bigint() {
    let big = |n: i64| Expr::Const {
        tpe: SigmaType::SBigInt,
        val: SigmaValue::BigInt(n.into()),
    };
    for (label, expr) in [
        (
            "Long /",
            op(
                0x9D,
                Payload::Two(Box::new(const_long(42)), Box::new(const_long(0))),
            ),
        ),
        (
            "Long %",
            op(
                0x9E,
                Payload::Two(Box::new(const_long(42)), Box::new(const_long(0))),
            ),
        ),
        (
            "BigInt /",
            op(0x9D, Payload::Two(Box::new(big(42)), Box::new(big(0)))),
        ),
        (
            "BigInt %",
            op(0x9E, Payload::Two(Box::new(big(42)), Box::new(big(0)))),
        ),
    ] {
        assert!(
            matches!(run_eval_err(&expr), EvalError::RuntimeException(_)),
            "{label} by zero must be RuntimeException"
        );
    }
}

#[test]
fn downcast_long_max_rejects_overflow() {
    // Scala's SInt.downcast uses toIntExact — throws ArithmeticException
    // when the value doesn't fit. SType.scala:471-478. The prior version
    // of this test locked in a wrapping-truncation bug by asserting
    // Long.MaxValue.toInt == -1; that is *not* Scala's contract.
    let expr = op(
        0x7D,
        Payload::NumericCast {
            input: Box::new(const_long(i64::MAX)),
            tpe: SigmaType::SInt,
        },
    );
    let err = run_eval_err(&expr);
    assert!(
        matches!(err, EvalError::RuntimeException(_)),
        "Long.MaxValue → Int downcast must reject with RuntimeException, got {err:?}"
    );
}

#[test]
fn downcast_int_to_byte_in_range_exact() {
    // Exact-fit cases continue to work.
    let expr = op(
        0x7D,
        Payload::NumericCast {
            input: Box::new(const_int(42)),
            tpe: SigmaType::SByte,
        },
    );
    assert_eq!(run_eval(&expr), Value::Byte(42));
}

#[test]
fn downcast_int_to_byte_overflow_rejects() {
    // Int 128 does not fit in i8 (range -128..=127).
    let expr = op(
        0x7D,
        Payload::NumericCast {
            input: Box::new(const_int(128)),
            tpe: SigmaType::SByte,
        },
    );
    let err = run_eval_err(&expr);
    assert!(
        matches!(err, EvalError::RuntimeException(_)),
        "Int 128 → Byte must reject: Scala toByteExact throws. got {err:?}"
    );
}

#[test]
fn error_indexof_wrong_arity() {
    // indexOf expects 2 args, give it 1
    let coll = const_bytes(vec![1, 2, 3]);
    let expr = op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 26,
            obj: Box::new(coll),
            args: vec![const_int(1)], // missing 'from' arg
            type_args: vec![],
        },
    );
    let err = run_eval_err(&expr);
    assert!(
        matches!(
            err,
            EvalError::ArityMismatch {
                expected: 2,
                got: 1
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn error_gt_type_mismatch() {
    // GT with Int vs Long should fail
    let expr = op(
        0x91,
        Payload::Two(Box::new(const_int(1)), Box::new(const_long(2))),
    );
    let err = run_eval_err(&expr);
    assert!(
        matches!(err, EvalError::TypeError { .. }),
        "expected TypeError, got {err:?}"
    );
}

#[test]
fn error_unsupported_method_call() {
    // Non-existent method_id=255 on type_id=12
    let coll = const_bytes(vec![1]);
    let expr = op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 255,
            obj: Box::new(coll),
            args: vec![],
            type_args: vec![],
        },
    );
    let err = run_eval_err(&expr);
    assert!(
        matches!(err, EvalError::TypeError { .. }),
        "expected TypeError, got {err:?}"
    );
}

#[test]
fn error_const_placeholder_out_of_bounds() {
    let expr = op(0x73, Payload::ConstPlaceholder { index: 99 });
    let err = run_eval_err(&expr);
    assert!(
        matches!(err, EvalError::ConstantOutOfBounds(_)),
        "expected ConstantOutOfBounds, got {err:?}"
    );
}

// ----- happy path (continued — extended opcode coverage) -----

// ── Batch 1: Box extractor opcodes ──────────────────────────────

fn make_test_box() -> EvalBox {
    EvalBox {
        creation_height: 500_000,
        script_bytes: vec![0x00, 0x08, 0xCD],
        value: 1_000_000_000,
        id: {
            let mut id = [0u8; 32];
            id[0] = 0xAA;
            id[31] = 0xBB;
            id
        },
        transaction_id: [0u8; 32],
        output_index: 0,
        registers: [
            Some(ergo_ser::register::RegisterValue {
                tpe: SigmaType::SInt,
                value: SigmaValue::Int(42),
            }),
            Some(ergo_ser::register::RegisterValue {
                tpe: SigmaType::SLong,
                value: SigmaValue::Long(999),
            }),
            None,
            None,
            None,
            None,
        ],
        tokens: vec![([0x11; 32], 100), ([0x22; 32], 200)],
        raw_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
    }
}

fn ctx_with_self_box(b: &EvalBox) -> ReductionContext<'_> {
    ReductionContext {
        height: 600_000,
        self_box: Some(b),
        self_creation_height: b.creation_height,
        outputs: &[],
        inputs: &[],
        data_inputs: &[],
        miner_pubkey: [0x33; 33],
        pre_header_timestamp: 1_700_000_000_000,
        extension: indexmap::IndexMap::new(),
        last_headers: &[],
        last_block_utxo_root: None,
        // EIP-50 / Sigma 6.0 activated — same rationale as
        // `ReductionContext::minimal`'s default. Lets v6 MethodCall
        // tests share this helper.
        activated_script_version: 3,
        ergo_tree_version: 3,
        pre_header_version: 0,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
        input_extensions: &[],
    }
}

#[test]
fn opcode_self_returns_self_box() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let expr = op(0xA7, Payload::Zero);
    let val = run_eval_ctx(&expr, &ctx);
    assert!(matches!(val, Value::SelfBox));
}

#[test]
fn opcode_extract_amount() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let expr = op(0xC1, Payload::One(Box::new(op(0xA7, Payload::Zero))));
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Long(1_000_000_000));
}

#[test]
fn opcode_extract_script_bytes() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let expr = op(0xC2, Payload::One(Box::new(op(0xA7, Payload::Zero))));
    assert_eq!(
        run_eval_ctx(&expr, &ctx),
        Value::CollBytes(vec![0x00, 0x08, 0xCD])
    );
}

#[test]
fn opcode_extract_bytes() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let expr = op(0xC3, Payload::One(Box::new(op(0xA7, Payload::Zero))));
    assert_eq!(
        run_eval_ctx(&expr, &ctx),
        Value::CollBytes(vec![0xDE, 0xAD, 0xBE, 0xEF])
    );
}

#[test]
fn opcode_extract_bytes_nonempty_for_real_box() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let expr = op(0xC3, Payload::One(Box::new(op(0xA7, Payload::Zero))));
    match run_eval_ctx(&expr, &ctx) {
        Value::CollBytes(v) => assert!(!v.is_empty(), "raw_bytes must not be empty"),
        other => panic!("expected CollBytes, got {other:?}"),
    }
}

#[test]
fn opcode_extract_id() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let expr = op(0xC5, Payload::One(Box::new(op(0xA7, Payload::Zero))));
    let expected = {
        let mut id = [0u8; 32];
        id[0] = 0xAA;
        id[31] = 0xBB;
        id.to_vec()
    };
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::CollBytes(expected));
}

#[test]
fn opcode_extract_register_r4_some() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let expr = op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(op(0xA7, Payload::Zero)),
            reg_id: 4,
            tpe: SigmaType::SInt,
        },
    );
    assert_eq!(
        run_eval_ctx(&expr, &ctx),
        Value::Opt(Some(Box::new(Value::Int(42))))
    );
}

#[test]
fn opcode_extract_register_r6_none() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let expr = op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(op(0xA7, Payload::Zero)),
            reg_id: 6,
            tpe: SigmaType::SInt,
        },
    );
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Opt(None));
}

/// EIP-50 v6 `SBox.getReg[T]` (MethodCall 99, 19) is the method-call
/// twin of inline opcode `0xC6 ExtractRegisterAs`. Both call into
/// `read_register_option`, so on the same box + register id they
/// must produce byte-identical `Option[T]` values. The wire layer
/// reads the explicit `[T]` byte and the evaluator carries it on
/// `Payload::MethodCall.type_args`, but (per Scala's runtime
/// behaviour) lifts to the register's actual stored type rather than
/// coercing to `T`.
#[test]
fn methodcall_box_getreg_v6_matches_inline_extract_register_as() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);

    // Inline 0xC6 path — already trusted by `opcode_extract_register_r4_some`.
    let inline_some = op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(op(0xA7, Payload::Zero)),
            reg_id: 4,
            tpe: SigmaType::SInt,
        },
    );
    // v6 MethodCall path — `box.getReg[Int](4)`.
    let byte_4 = Expr::Const {
        tpe: SigmaType::SByte,
        val: SigmaValue::Byte(4),
    };
    let method_some = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 99,
            method_id: 19,
            obj: Box::new(op(0xA7, Payload::Zero)),
            args: vec![byte_4],
            type_args: vec![SigmaType::SInt],
        },
    });
    assert_eq!(
        run_eval_ctx(&inline_some, &ctx),
        run_eval_ctx(&method_some, &ctx),
        "v6 SBox.getReg[T] must match inline ExtractRegisterAs on a populated register",
    );
    // And exercise the None path on an empty register.
    let inline_none = op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(op(0xA7, Payload::Zero)),
            reg_id: 6,
            tpe: SigmaType::SInt,
        },
    );
    let byte_6 = Expr::Const {
        tpe: SigmaType::SByte,
        val: SigmaValue::Byte(6),
    };
    let method_none = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 99,
            method_id: 19,
            obj: Box::new(op(0xA7, Payload::Zero)),
            args: vec![byte_6],
            type_args: vec![SigmaType::SInt],
        },
    });
    assert_eq!(
        run_eval_ctx(&inline_none, &ctx),
        run_eval_ctx(&method_none, &ctx),
        "v6 SBox.getReg[T] must match inline ExtractRegisterAs on an empty register",
    );
}

#[test]
fn opcode_extract_creation_info() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let expr = op(0xC7, Payload::One(Box::new(op(0xA7, Payload::Zero))));
    match run_eval_ctx(&expr, &ctx) {
        Value::Tuple(parts) => {
            assert_eq!(parts.len(), 2);
            assert_eq!(parts[0], Value::Int(500_000));
            assert!(matches!(parts[1], Value::CollBytes(_)));
        }
        other => panic!("expected Tuple, got {other:?}"),
    }
}

#[test]
fn opcode_miner_pubkey() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let expr = op(0xAC, Payload::Zero);
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::CollBytes(vec![0x33; 33]));
}

// ── Batch 2: Collection operations ──────────────────────────────

#[test]
fn opcode_by_index_in_range() {
    let coll = const_bytes(vec![10, 20, 30]);
    let expr = op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(coll),
            index: Box::new(const_int(1)),
            default: None,
        },
    );
    // ByIndex on Coll[Byte] surfaces Value::Byte at the element
    // boundary, not erased Int.
    assert_eq!(run_eval(&expr), Value::Byte(20));
}

#[test]
fn opcode_by_index_out_of_range_no_default() {
    let coll = const_bytes(vec![10, 20, 30]);
    let expr = op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(coll),
            index: Box::new(const_int(5)),
            default: None,
        },
    );
    let err = run_eval_err(&expr);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

#[test]
fn opcode_append_bytes() {
    let a = const_bytes(vec![1, 2]);
    let b = const_bytes(vec![3, 4]);
    let expr = op(0xB3, Payload::Two(Box::new(a), Box::new(b)));
    assert_eq!(run_eval(&expr), Value::CollBytes(vec![1, 2, 3, 4]));
}

#[test]
fn opcode_slice_bytes() {
    let coll = const_bytes(vec![10, 20, 30, 40, 50]);
    let expr = op(
        0xB4,
        Payload::Three(
            Box::new(coll),
            Box::new(const_int(1)),
            Box::new(const_int(4)),
        ),
    );
    assert_eq!(run_eval(&expr), Value::CollBytes(vec![20, 30, 40]));
}

#[test]
fn opcode_map_int_collection() {
    let coll = const_coll_int(vec![1, 2, 3]);
    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x9A,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    Box::new(const_int(10)),
                ),
            )),
        },
    );
    let expr = op(0xAD, Payload::Two(Box::new(coll), Box::new(func)));
    assert_eq!(run_eval(&expr), Value::CollInt(vec![11, 12, 13]));
}

#[test]
fn opcode_filter_int_collection() {
    let coll = const_coll_int(vec![1, 2, 3, 4]);
    let pred = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x91,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    Box::new(const_int(2)),
                ),
            )),
        },
    );
    let expr = op(0xB5, Payload::Two(Box::new(coll), Box::new(pred)));
    assert_eq!(run_eval(&expr), Value::CollInt(vec![3, 4]));
}

#[test]
fn opcode_exists_true() {
    let coll = const_coll_int(vec![1, 2, 3]);
    let pred = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x93,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    Box::new(const_int(2)),
                ),
            )),
        },
    );
    let expr = op(0xAE, Payload::Two(Box::new(coll), Box::new(pred)));
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

#[test]
fn opcode_exists_false() {
    let coll = const_coll_int(vec![1, 2, 3]);
    let pred = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x93,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    Box::new(const_int(99)),
                ),
            )),
        },
    );
    let expr = op(0xAE, Payload::Two(Box::new(coll), Box::new(pred)));
    assert_eq!(run_eval(&expr), Value::Bool(false));
}

#[test]
fn opcode_forall_true() {
    let coll = const_coll_int(vec![10, 20, 30]);
    let pred = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x91,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    Box::new(const_int(0)),
                ),
            )),
        },
    );
    let expr = op(0xAF, Payload::Two(Box::new(coll), Box::new(pred)));
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

#[test]
fn opcode_fold_sum() {
    let coll = const_coll_int(vec![1, 2, 3, 4]);
    let zero = const_int(0);
    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(
                1,
                Some(SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SInt])),
            )],
            body: Box::new(op(
                0x9A,
                Payload::Two(
                    Box::new(op(
                        0x8C,
                        Payload::SelectField {
                            input: Box::new(op(0x72, Payload::ValUse { id: 1 })),
                            field_idx: 1,
                        },
                    )),
                    Box::new(op(
                        0x8C,
                        Payload::SelectField {
                            input: Box::new(op(0x72, Payload::ValUse { id: 1 })),
                            field_idx: 2,
                        },
                    )),
                ),
            )),
        },
    );
    let expr = op(
        0xB0,
        Payload::Three(Box::new(coll), Box::new(zero), Box::new(func)),
    );
    assert_eq!(run_eval(&expr), Value::Int(10));
}

#[test]
fn opcode_and_collection_all_true() {
    let coll = const_coll_bool(vec![true, true, true]);
    let expr = op(0x96, Payload::One(Box::new(coll)));
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

#[test]
fn opcode_and_collection_one_false() {
    let coll = const_coll_bool(vec![true, false, true]);
    let expr = op(0x96, Payload::One(Box::new(coll)));
    assert_eq!(run_eval(&expr), Value::Bool(false));
}

#[test]
fn opcode_or_collection() {
    let coll = const_coll_bool(vec![false, true, false]);
    let expr = op(0x97, Payload::One(Box::new(coll)));
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

// ── Batch 3: Crypto, type conversions, Option, misc ─────────────

#[test]
fn opcode_blake2b256_empty() {
    let expr = op(0xCB, Payload::One(Box::new(const_bytes(vec![]))));
    // blake2b256("") = 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8
    assert_eq!(
        run_eval(&expr),
        Value::CollBytes(vec![
            0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2, 0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99,
            0xda, 0xa1, 0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87, 0xfa, 0xab, 0x45, 0xcd,
            0xf1, 0x2f, 0xe3, 0xa8,
        ])
    );
}

#[test]
fn opcode_blake2b256_nonempty() {
    // blake2b256([0x01, 0x02, 0x03]) — pinned from evaluator output
    let expr = op(0xCB, Payload::One(Box::new(const_bytes(vec![1, 2, 3]))));
    assert_eq!(
        run_eval(&expr),
        Value::CollBytes(vec![
            0x11, 0xc0, 0xe7, 0x9b, 0x71, 0xc3, 0x97, 0x6c, 0xcd, 0x0c, 0x02, 0xd1, 0x31, 0x0e,
            0x25, 0x16, 0xc0, 0x8e, 0xdc, 0x9d, 0x8b, 0x6f, 0x57, 0xcc, 0xd6, 0x80, 0xd6, 0x3a,
            0x4d, 0x8e, 0x72, 0xda,
        ])
    );
}

#[test]
fn opcode_sha256_empty() {
    let expr = op(0xCC, Payload::One(Box::new(const_bytes(vec![]))));
    // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert_eq!(
        run_eval(&expr),
        Value::CollBytes(vec![
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ])
    );
}

#[test]
fn opcode_long_to_byte_array() {
    let expr = op(0x7A, Payload::One(Box::new(const_long(256))));
    assert_eq!(
        run_eval(&expr),
        Value::CollBytes(vec![0, 0, 0, 0, 0, 0, 1, 0])
    );
}

#[test]
fn opcode_byte_array_to_long() {
    let expr = op(
        0x7C,
        Payload::One(Box::new(const_bytes(vec![0, 0, 0, 0, 0, 0, 1, 0]))),
    );
    assert_eq!(run_eval(&expr), Value::Long(256));
}

#[test]
fn opcode_long_byte_array_roundtrip() {
    let inner = op(0x7A, Payload::One(Box::new(const_long(123456789))));
    let expr = op(0x7C, Payload::One(Box::new(inner)));
    assert_eq!(run_eval(&expr), Value::Long(123456789));
}

#[test]
fn opcode_byte_array_to_bigint() {
    let expr = op(0x7B, Payload::One(Box::new(const_bytes(vec![0, 1]))));
    match run_eval(&expr) {
        Value::BigInt(bi) => assert_eq!(bi, num_bigint::BigInt::from(1)),
        other => panic!("expected BigInt, got {other:?}"),
    }
}

#[test]
fn opcode_min_int() {
    let expr = op(
        0xA1,
        Payload::Two(Box::new(const_int(5)), Box::new(const_int(3))),
    );
    assert_eq!(run_eval(&expr), Value::Int(3));
}

#[test]
fn opcode_max_int() {
    let expr = op(
        0xA2,
        Payload::Two(Box::new(const_int(5)), Box::new(const_int(3))),
    );
    assert_eq!(run_eval(&expr), Value::Int(5));
}

/// `Value::UnsignedBigInt` must have its own `PartialEq` arm so
/// that script-level `==` on two equal SUnsignedBigInt values
/// returns true. Without it the comparison falls through to the
/// generic `_ => false` arm, making any v6 modular-arithmetic
/// equality check unconditionally false — testnet h=250,628
/// tx[1] input 0 surfaced this as `TrivialProp(false)` from a
/// script that compares modInverse / plusMod / multiplyMod
/// outputs to expected sigma-protocol commitments.
#[test]
fn opcode_eq_unsigned_bigint_equal_values_are_equal() {
    // A 252-bit value in the SUnsignedBigInt range that's far
    // from the curve modulus — same number as the live mismatch
    // captured during the h=250,628 diagnostic.
    let n: num_bigint::BigInt =
        "7294030556956404039511359372482889815144089164922115541085129728007489296680"
            .parse()
            .unwrap();
    let lhs = Expr::Const {
        tpe: SigmaType::SUnsignedBigInt,
        val: SigmaValue::BigInt(n.clone()),
    };
    let rhs = Expr::Const {
        tpe: SigmaType::SUnsignedBigInt,
        val: SigmaValue::BigInt(n),
    };
    let eq = op(0x93, Payload::Two(Box::new(lhs), Box::new(rhs)));
    assert_eq!(run_eval(&eq), Value::Bool(true));
}

/// Twin of the above: distinct SUnsignedBigInt values must compare
/// `false`. Guards against an over-broad fix (e.g. always-true) to
/// the missing-PartialEq-arm bug.
#[test]
fn opcode_eq_unsigned_bigint_distinct_values_are_unequal() {
    let a: num_bigint::BigInt = 100u64.into();
    let b: num_bigint::BigInt = 101u64.into();
    let lhs = Expr::Const {
        tpe: SigmaType::SUnsignedBigInt,
        val: SigmaValue::BigInt(a),
    };
    let rhs = Expr::Const {
        tpe: SigmaType::SUnsignedBigInt,
        val: SigmaValue::BigInt(b),
    };
    let eq = op(0x93, Payload::Two(Box::new(lhs), Box::new(rhs)));
    assert_eq!(run_eval(&eq), Value::Bool(false));
}

/// Scala `sigma.ast.XorOf(input: Coll[SBoolean]) -> SBoolean`
/// (LogicalTransformerCompanion). Returns true iff the collection
/// contains an odd number of `true` values — `bs.fold(false)(_ ^ _)`.
/// Byte-array XOR is opcode `0x9B Xor`, not `0xFF`.
#[test]
fn opcode_xor_of_returns_parity_of_collection() {
    // Odd number of trues -> true.
    let odd = const_coll_bool(vec![true, false, true, true]);
    assert_eq!(
        run_eval(&op(0xFF, Payload::One(Box::new(odd)))),
        Value::Bool(true),
    );
    // Even number of trues -> false.
    let even = const_coll_bool(vec![true, true, false, false]);
    assert_eq!(
        run_eval(&op(0xFF, Payload::One(Box::new(even)))),
        Value::Bool(false),
    );
    // Empty -> false (fold identity).
    let empty = const_coll_bool(vec![]);
    assert_eq!(
        run_eval(&op(0xFF, Payload::One(Box::new(empty)))),
        Value::Bool(false),
    );
}

#[test]
fn opcode_true_false() {
    assert_eq!(run_eval(&op(0x7F, Payload::Zero)), Value::Bool(true));
    assert_eq!(run_eval(&op(0x80, Payload::Zero)), Value::Bool(false));
}

#[test]
fn opcode_option_get_some() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let inner = op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(op(0xA7, Payload::Zero)),
            reg_id: 4,
            tpe: SigmaType::SInt,
        },
    );
    let expr = op(0xE4, Payload::One(Box::new(inner)));
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Int(42));
}

#[test]
fn opcode_option_get_none_errors() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let inner = op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(op(0xA7, Payload::Zero)),
            reg_id: 6,
            tpe: SigmaType::SInt,
        },
    );
    let expr = op(0xE4, Payload::One(Box::new(inner)));
    let err = eval_to_value(&expr, &ctx, &[]).unwrap_err();
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

#[test]
fn opcode_option_is_defined() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let some_expr = op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(op(0xA7, Payload::Zero)),
            reg_id: 4,
            tpe: SigmaType::SInt,
        },
    );
    let none_expr = op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(op(0xA7, Payload::Zero)),
            reg_id: 6,
            tpe: SigmaType::SInt,
        },
    );
    assert_eq!(
        run_eval_ctx(&op(0xE6, Payload::One(Box::new(some_expr))), &ctx),
        Value::Bool(true),
    );
    assert_eq!(
        run_eval_ctx(&op(0xE6, Payload::One(Box::new(none_expr))), &ctx),
        Value::Bool(false),
    );
}

#[test]
fn opcode_option_get_or_else_some() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let opt = op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(op(0xA7, Payload::Zero)),
            reg_id: 4,
            tpe: SigmaType::SInt,
        },
    );
    let expr = op(0xE5, Payload::Two(Box::new(opt), Box::new(const_int(0))));
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Int(42));
}

#[test]
fn opcode_option_get_or_else_none() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let opt = op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(op(0xA7, Payload::Zero)),
            reg_id: 6,
            tpe: SigmaType::SInt,
        },
    );
    let expr = op(0xE5, Payload::Two(Box::new(opt), Box::new(const_int(-1))));
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Int(-1));
}

#[test]
fn none_option_via_constant_encoding() {
    // None: Option[Int] flows through the constant-encoding path
    // (SOption(SInt) type + 0x00 discriminant), not through a bare
    // 0xDF dispatch. This reflects Scala's treatment: no serializer
    // is registered for 0xDF at ValueSerializer.scala:42-151; None
    // values are Constant[SOption[T]] with `None` inside.
    use ergo_ser::sigma_value::CollValue as _CollValue;
    let _ = _CollValue::Values; // keep import warning-free
    let expr = Expr::Const {
        tpe: SigmaType::SOption(Box::new(SigmaType::SInt)),
        val: SigmaValue::Opt(None),
    };
    assert_eq!(run_eval(&expr), Value::Opt(None));
}

#[test]
fn opcode_prove_dlog() {
    let g: Vec<u8> = vec![
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];
    let ge = Expr::Const {
        tpe: SigmaType::SGroupElement,
        val: SigmaValue::GroupElement(ergo_primitives::group_element::GroupElement::from_bytes(
            g.as_slice().try_into().unwrap(),
        )),
    };
    let expr = op(0xCD, Payload::One(Box::new(ge)));
    match run_eval(&expr) {
        Value::SigmaProp(SigmaBoolean::ProveDlog(_)) => {}
        other => panic!("expected SigmaProp(ProveDlog), got {other:?}"),
    }
}

#[test]
fn opcode_sigma_prop_bytes() {
    let inner = op(0xD1, Payload::One(Box::new(const_bool(true))));
    let expr = op(0xD0, Payload::One(Box::new(inner)));
    match run_eval(&expr) {
        Value::CollBytes(bytes) => assert!(!bytes.is_empty()),
        other => panic!("expected CollBytes, got {other:?}"),
    }
}

#[test]
fn opcode_sigma_and_trivial() {
    let items = vec![
        op(0xD1, Payload::One(Box::new(const_bool(true)))),
        op(0xD1, Payload::One(Box::new(const_bool(true)))),
    ];
    let expr = op(0xEA, Payload::SigmaCollection { items });
    match run_eval(&expr) {
        Value::SigmaProp(SigmaBoolean::TrivialProp(true)) => {}
        other => panic!("expected TrivialProp(true), got {other:?}"),
    }
}

#[test]
fn opcode_sigma_or_one_true() {
    let items = vec![
        op(0xD1, Payload::One(Box::new(const_bool(false)))),
        op(0xD1, Payload::One(Box::new(const_bool(true)))),
    ];
    let expr = op(0xEB, Payload::SigmaCollection { items });
    match run_eval(&expr) {
        Value::SigmaProp(SigmaBoolean::TrivialProp(true)) => {}
        other => panic!("expected TrivialProp(true), got {other:?}"),
    }
}

#[test]
fn opcode_decode_point() {
    let g: Vec<u8> = vec![
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];
    let expr = op(0xEE, Payload::One(Box::new(const_bytes(g))));
    match run_eval(&expr) {
        Value::GroupElement(_) => {}
        other => panic!("expected GroupElement, got {other:?}"),
    }
}

/// SGroupElement.exp(unsigned) (MethodCall 7/6, EIP-50 v6 method)
/// is the unsigned-carrier twin of inline opcode 0x9F Exponentiate.
/// Both reduce the scalar mod the secp256k1 group order via
/// `Scalar::reduce` and apply EC scalar multiplication, so for any
/// `n` in [0, 2^256) the two paths must yield byte-identical
/// `GroupElement`s. Pins the (7, 6) dispatch arm against the
/// already-trusted 0x9F path; without this arm Scala's testnet
/// scripts that use `g.exp(unsigned)` stall the evaluator with
/// "expected supported MethodCall".
#[test]
fn methodcall_groupelement_exp_unsigned_matches_inline_exponentiate() {
    let g_ge = Expr::Const {
        tpe: SigmaType::SGroupElement,
        val: SigmaValue::GroupElement(ergo_primitives::group_element::GroupElement::from_bytes(
            SECP256K1_GENERATOR,
        )),
    };
    let n: num_bigint::BigInt = 7u32.into();
    let exp_signed = Expr::Const {
        tpe: SigmaType::SBigInt,
        val: SigmaValue::BigInt(n.clone()),
    };
    let exp_unsigned = Expr::Const {
        tpe: SigmaType::SUnsignedBigInt,
        val: SigmaValue::BigInt(n),
    };
    let inline = op(
        0x9F,
        Payload::Two(Box::new(g_ge.clone()), Box::new(exp_signed)),
    );
    let method_call = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 7,
            method_id: 6,
            obj: Box::new(g_ge),
            args: vec![exp_unsigned],
            type_args: vec![],
        },
    });
    let v_inline = run_eval(&inline);
    let v_method = run_eval(&method_call);
    match (&v_inline, &v_method) {
        (Value::GroupElement(a), Value::GroupElement(b)) => assert_eq!(a, b),
        other => panic!("expected matching GroupElement results, got {other:?}"),
    }
}

#[test]
fn opcode_getvar_present() {
    let b = make_test_box();
    let mut ctx = ctx_with_self_box(&b);
    ctx.extension
        .insert(0, (SigmaType::SInt, SigmaValue::Int(77)));
    let expr = op(
        0xE3,
        Payload::GetVar {
            var_id: 0,
            tpe: SigmaType::SInt,
        },
    );
    assert_eq!(
        run_eval_ctx(&expr, &ctx),
        Value::Opt(Some(Box::new(Value::Int(77))))
    );
}

#[test]
fn opcode_getvar_absent() {
    let expr = op(
        0xE3,
        Payload::GetVar {
            var_id: 99,
            tpe: SigmaType::SInt,
        },
    );
    assert_eq!(run_eval(&expr), Value::Opt(None));
}

/// v6.0.2 `SContext.getVar` is usable ONLY as the inline `0xE3 GetVar`
/// node (which carries `T` on the wire). The Scala compiler never lowers
/// `CONTEXT.getVar[T](id)` to a MethodCall — `getVarV5Method` (id 11) has
/// no `.withIRInfo` — and a hand-crafted `(101, 11)` MethodCall is
/// unbuildable/unevaluable in Scala (`T` stays abstract; both eval paths
/// throw, never returning None). So the node accepts the inline form and
/// REJECTS the `(101, 11)` MethodCall form as unsupported, matching
/// v6.0.2. (`getVarFromInput` (101, 12) is the real v6 MethodCall.)
#[test]
fn context_getvar_inline_works_methodcall_form_unsupported() {
    let b = make_test_box();
    let mut ctx = ctx_with_self_box(&b);
    ctx.extension
        .insert(7, (SigmaType::SInt, SigmaValue::Int(123)));

    // Inline 0xE3 GetVar — the real, evaluable form (carries T).
    let inline = |var_id: u8, tpe: SigmaType| op(0xE3, Payload::GetVar { var_id, tpe });
    assert_eq!(
        run_eval_ctx(&inline(7, SigmaType::SInt), &ctx),
        Value::Opt(Some(Box::new(Value::Int(123)))),
        "inline GetVar must read the present var",
    );
    // Absent var id, and present-but-wrong-type both yield None.
    assert_eq!(
        run_eval_ctx(&inline(99, SigmaType::SInt), &ctx),
        Value::Opt(None)
    );
    assert_eq!(
        run_eval_ctx(&inline(7, SigmaType::SLong), &ctx),
        Value::Opt(None)
    );

    // The (101, 11) getVar MethodCall form is unsupported: it must REJECT
    // (not evaluate to None), regardless of any synthetic type_args, since
    // a real v6.0.2 node cannot build or run it.
    let method_form = |type_args: Vec<SigmaType>| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id: 101,
                method_id: 11,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![Expr::Const {
                    tpe: SigmaType::SByte,
                    val: SigmaValue::Byte(7),
                }],
                type_args,
            },
        })
    };
    for ta in [vec![], vec![SigmaType::SInt]] {
        assert!(
            matches!(
                run_eval_ctx_err(&method_form(ta), &ctx),
                EvalError::TypeError {
                    expected: "supported MethodCall",
                    ..
                }
            ),
            "getVar via (101, 11) MethodCall must reject as unsupported, not return a value",
        );
    }
}

/// EIP-50 v6 `SContext.getVarFromInput[T]` (MethodCall 101, 12) —
/// new in v6, no v5 inline twin. Reads
/// `tx.inputs(inputIndex).extension.getVar[T](varId)` with the
/// same exact-type-match rule as the inline `0xE3 GetVar`.
/// Out-of-range index, missing var id, or type mismatch
/// all return `Opt(None)`.
#[test]
fn methodcall_context_getvarfrominput_v6_reads_other_inputs() {
    let b = make_test_box();
    let mut ctx = ctx_with_self_box(&b);
    let mut ext0 = indexmap::IndexMap::new();
    ext0.insert(7u8, (SigmaType::SInt, SigmaValue::Int(11)));
    let mut ext1 = indexmap::IndexMap::new();
    ext1.insert(7u8, (SigmaType::SLong, SigmaValue::Long(22)));
    let exts = vec![ext0, ext1];
    ctx.input_extensions = &exts;

    let mk = |input_idx: i16, var_id: i8, t: SigmaType| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id: 101,
                method_id: 12,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![
                    Expr::Const {
                        tpe: SigmaType::SShort,
                        val: SigmaValue::Short(input_idx),
                    },
                    Expr::Const {
                        tpe: SigmaType::SByte,
                        val: SigmaValue::Byte(var_id),
                    },
                ],
                type_args: vec![t],
            },
        })
    };

    // Input 0 var 7 as SInt → Some(11).
    assert_eq!(
        run_eval_ctx(&mk(0, 7, SigmaType::SInt), &ctx),
        Value::Opt(Some(Box::new(Value::Int(11)))),
    );
    // Input 1 var 7 as SLong → Some(22).
    assert_eq!(
        run_eval_ctx(&mk(1, 7, SigmaType::SLong), &ctx),
        Value::Opt(Some(Box::new(Value::Long(22)))),
    );
    // Type mismatch → None.
    assert_eq!(
        run_eval_ctx(&mk(0, 7, SigmaType::SLong), &ctx),
        Value::Opt(None),
    );
    // Missing var id → None.
    assert_eq!(
        run_eval_ctx(&mk(0, 99, SigmaType::SInt), &ctx),
        Value::Opt(None),
    );
    // Out-of-range / negative input index → None.
    assert_eq!(
        run_eval_ctx(&mk(5, 7, SigmaType::SInt), &ctx),
        Value::Opt(None),
    );
    assert_eq!(
        run_eval_ctx(&mk(-1, 7, SigmaType::SInt), &ctx),
        Value::Opt(None),
    );
}

/// EIP-50 v6 `SGlobal.deserializeTo[T]` (MethodCall 106, 4) — Scala
/// `SGlobalMethods.deserializeTo_eval` delegates to
/// `DataSerializer.deserialize(typeArg, reader)`, which reads raw
/// typed value bytes (NOT an expression body). For `SBoolean`,
/// `DataSerializer.deserialize` is `r.getUByte() != 0` — non-strict,
/// Zero-arg v6 methods are serialized by the compiler as `0xDB PropertyCall`
/// (not `0xDC MethodCall`), so they must resolve through the shared no-arg
/// dispatch table. Pins the dispatch unification: bitwiseInverse (numeric +
/// UnsignedBigInt), SBigInt.toUnsigned, SUnsignedBigInt.toSigned, and
/// Coll.reverse all evaluate via PropertyCall. Previously these handlers lived
/// only in `eval_method_call`'s args-arms and errored ("supported PropertyCall").
#[test]
fn zero_arg_v6_methods_resolve_via_property_call() {
    let prop = |type_id: u8, method_id: u8, obj: Expr| {
        Expr::Op(IrNode {
            opcode: 0xDB,
            payload: Payload::MethodCall {
                type_id,
                method_id,
                obj: Box::new(obj),
                args: vec![],
                type_args: vec![],
            },
        })
    };
    let bigint = |n: i64| Expr::Const {
        tpe: SigmaType::SBigInt,
        val: SigmaValue::BigInt(num_bigint::BigInt::from(n)),
    };
    let ubigint = |n: u64| Expr::Const {
        tpe: SigmaType::SUnsignedBigInt,
        val: SigmaValue::BigInt(num_bigint::BigInt::from(n)),
    };
    // bitwiseInverse: Int(4)/Long(5) -> ~x
    assert_eq!(run_eval(&prop(4, 8, const_int(1))), Value::Int(-2));
    assert_eq!(run_eval(&prop(5, 8, const_long(1))), Value::Long(-2));
    // bitwiseInverse: BigInt(6) -> ~x
    assert_eq!(
        run_eval(&prop(6, 8, bigint(0))),
        Value::BigInt(num_bigint::BigInt::from(-1))
    );
    // SUnsignedBigInt(9).bitwiseInverse -> (2^256-1) XOR n; for 0 -> 2^256-1
    let mask = (num_bigint::BigInt::from(1) << 256u32) - num_bigint::BigInt::from(1);
    assert_eq!(
        run_eval(&prop(9, 8, ubigint(0))),
        Value::UnsignedBigInt(mask)
    );
    // SBigInt(6).toUnsigned(14)
    assert_eq!(
        run_eval(&prop(6, 14, bigint(5))),
        Value::UnsignedBigInt(num_bigint::BigInt::from(5))
    );
    // SUnsignedBigInt(9).toSigned(19)
    assert_eq!(
        run_eval(&prop(9, 19, ubigint(7))),
        Value::BigInt(num_bigint::BigInt::from(7))
    );
    // SColl(12).reverse(30) preserves the typed carrier
    assert_eq!(
        run_eval(&prop(12, 30, const_coll_int(vec![1, 2, 3]))),
        Value::CollInt(vec![3, 2, 1])
    );

    // Arity is still enforced for the moved no-arg methods: a malformed 0xDC
    // MethodCall carrying extra args must error (not silently ignore them),
    // matching the `check_arity(args, 0)` the explicit arms used to do.
    let bad = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 4,
            method_id: 8, // bitwiseInverse — no-arg
            obj: Box::new(const_int(1)),
            args: vec![const_int(99)], // bogus extra arg
            type_args: vec![],
        },
    });
    assert!(
        matches!(
            run_eval_err(&bad),
            EvalError::ArityMismatch { expected: 0, .. }
        ),
        "no-arg method invoked with args must error on arity"
    );
}

/// so any nonzero byte reads as `true`. Pin the boolean branch
/// here; the multi-type round-trip with serialize is pinned by
/// `methodcall_global_serialize_roundtrips_via_deserializeto`.
#[test]
fn methodcall_global_deserializeto_v6_evaluates_serialized_true() {
    let bytes = const_bytes(vec![0x01]); // DataSerializer canonical true
    let expr = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 4,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![bytes],
            type_args: vec![SigmaType::SBoolean],
        },
    });
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

/// GHSA-hfj8-hjph-7r78 regression: `SGlobal.deserializeTo[SHeader]` must parse
/// the full block-header data format. Scala `DataSerializer.deserialize(SHeader)`
/// delegates to `ErgoHeader.sigmaSerializer.parse` (v3+ ErgoTree); our value
/// deserializer had no SHeader case, so a script using `deserializeTo[SHeader]`
/// errored — halting from-genesis testnet sync at block 28,474 (a block the
/// Scala reference accepts). The bytes are produced by the same header
/// serializer the node uses for block headers, so this is a faithful round-trip.
#[test]
fn methodcall_global_deserializeto_v6_header_roundtrip() {
    let h = ergo_ser::header::Header {
        version: 2,
        parent_id: ergo_primitives::digest::ModifierId::from_bytes([0x11; 32]),
        ad_proofs_root: ergo_primitives::digest::Digest32::from_bytes([0x22; 32]),
        transactions_root: ergo_primitives::digest::Digest32::from_bytes([0x33; 32]),
        state_root: ergo_primitives::digest::ADDigest::from_bytes([0x44; 33]),
        timestamp: 1_700_000_000_000,
        extension_root: ergo_primitives::digest::Digest32::from_bytes([0x55; 32]),
        n_bits: 0x1a01_7660,
        height: 28_474,
        votes: [0, 0, 0],
        unparsed_bytes: vec![],
        solution: ergo_ser::autolykos::AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from_bytes([0x02; 33]),
            nonce: [0; 8],
        },
    };
    let (bytes, id) = ergo_ser::header::serialize_header(&h).expect("serialize header");
    let expr = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 4,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![const_bytes(bytes)],
            type_args: vec![SigmaType::SHeader],
        },
    });
    let expected = Value::Header(Box::new(EvalHeader::from_header(&h, *id.as_bytes())));
    assert_eq!(run_eval(&expr), expected);
}

/// `deserializeTo[SHeader]` is gated on the ErgoTree HEADER version (Scala
/// `isV3OrLaterErgoTreeVersion`), NOT `activatedScriptVersion`. A legacy
/// (version < 3) tree calling it must error even when activated >= 3 —
/// otherwise we'd return a Header where the reference throws (accept-invalid
/// fork hazard, codex P1 / GHSA-hfj8-hjph-7r78).
#[test]
fn deserializeto_sheader_gated_on_ergo_tree_version() {
    let h = ergo_ser::header::Header {
        version: 2,
        parent_id: ergo_primitives::digest::ModifierId::from_bytes([0x11; 32]),
        ad_proofs_root: ergo_primitives::digest::Digest32::from_bytes([0x22; 32]),
        transactions_root: ergo_primitives::digest::Digest32::from_bytes([0x33; 32]),
        state_root: ergo_primitives::digest::ADDigest::from_bytes([0x44; 33]),
        timestamp: 1,
        extension_root: ergo_primitives::digest::Digest32::from_bytes([0x55; 32]),
        n_bits: 0x1a01_7660,
        height: 1,
        votes: [0, 0, 0],
        unparsed_bytes: vec![],
        solution: ergo_ser::autolykos::AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from_bytes([0x02; 33]),
            nonce: [0; 8],
        },
    };
    let (bytes, _id) = ergo_ser::header::serialize_header(&h).unwrap();
    let expr = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 4,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![const_bytes(bytes)],
            type_args: vec![SigmaType::SHeader],
        },
    });
    // activated >= 3 (deserializeTo is callable) but ergoTree version < 3.
    let ctx = ReductionContext {
        ergo_tree_version: 2,
        ..ReductionContext::minimal(0, 0)
    };
    assert!(
        matches!(
            eval_to_value(&expr, &ctx, &[]),
            Err(EvalError::TypeError { .. })
        ),
        "deserializeTo[SHeader] on a v<3 ErgoTree must error (isV3OrLaterErgoTreeVersion)"
    );
}

/// The SHeader version gate is VALUE-based, not TYPE-based: Scala fires it per
/// materialized header (`DataSerializer.deserialize(SHeader)`), so an EMPTY
/// `Coll[Header]` (no header materialized) is accepted even on a v<3 tree,
/// while an actual header is rejected. Regression guard for over-gating
/// empty header collections.
#[test]
fn sheader_gate_is_value_based_not_type_based() {
    let ctx_v2 = ReductionContext {
        ergo_tree_version: 2,
        ..ReductionContext::minimal(0, 0)
    };
    // Empty Coll[Header] on a v<3 tree: NOT gated (no header materialized).
    let empty = SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Values(vec![]));
    let t = SigmaType::SColl(Box::new(SigmaType::SHeader));
    assert!(
        crate::evaluator::helpers::sigma_to_value_versioned(&t, &empty, &ctx_v2).is_ok(),
        "empty Coll[Header] must not be gated on a v<3 tree"
    );
    // A real header value on a v<3 tree IS gated.
    let h = ergo_ser::header::Header {
        version: 2,
        parent_id: ergo_primitives::digest::ModifierId::from_bytes([0x11; 32]),
        ad_proofs_root: ergo_primitives::digest::Digest32::from_bytes([0x22; 32]),
        transactions_root: ergo_primitives::digest::Digest32::from_bytes([0x33; 32]),
        state_root: ergo_primitives::digest::ADDigest::from_bytes([0x44; 33]),
        timestamp: 1,
        extension_root: ergo_primitives::digest::Digest32::from_bytes([0x55; 32]),
        n_bits: 0x1a01_7660,
        height: 1,
        votes: [0, 0, 0],
        unparsed_bytes: vec![],
        solution: ergo_ser::autolykos::AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from_bytes([0x02; 33]),
            nonce: [0; 8],
        },
    };
    let hv = SigmaValue::Header(Box::new(h));
    assert!(
        crate::evaluator::helpers::sigma_to_value_versioned(&SigmaType::SHeader, &hv, &ctx_v2)
            .is_err(),
        "an actual SHeader value must be gated on a v<3 tree"
    );
}

/// EIP-50 v6 `SGlobal.fromBigEndianBytes[T]` (MethodCall 106, 5) —
/// big-endian signed decode into the requested numeric type. Length
/// must match the target's byte width: 1/2/4/8 for Byte/Short/Int/
/// Long, ≤ 32 for BigInt.
#[test]
fn methodcall_global_frombigendianbytes_v6_typed_decode() {
    let mk = |t: SigmaType, bytes: Vec<u8>| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id: 106,
                method_id: 5,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![const_bytes(bytes)],
                type_args: vec![t],
            },
        })
    };
    // SByte: 1 byte
    assert_eq!(
        run_eval(&mk(SigmaType::SByte, vec![0x7F])),
        Value::Byte(127),
    );
    assert_eq!(run_eval(&mk(SigmaType::SByte, vec![0xFF])), Value::Byte(-1),);
    // SShort: 2 bytes BE
    assert_eq!(
        run_eval(&mk(SigmaType::SShort, vec![0x01, 0x02])),
        Value::Short(0x0102),
    );
    // SInt: 4 bytes BE
    assert_eq!(
        run_eval(&mk(SigmaType::SInt, vec![0x00, 0x00, 0x00, 0x2A])),
        Value::Int(42),
    );
    // SLong: 8 bytes BE
    assert_eq!(
        run_eval(&mk(
            SigmaType::SLong,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40]
        )),
        Value::Long(64),
    );
    // SBigInt: ≤ 32 bytes, signed
    let big = run_eval(&mk(SigmaType::SBigInt, vec![0x01, 0x00, 0x00]));
    assert_eq!(big, Value::BigInt(num_bigint::BigInt::from(65536)));
}

/// `SGlobal.xor` (MethodCall 106, 2) — V5+ method, same algorithm as
/// the inline `0x9B Xor` opcode: element-wise byte XOR, truncated to
/// the shorter operand. Pinning both call surfaces here ensures the
/// MethodCall path never drifts away from the inline op.
#[test]
fn methodcall_global_xor_matches_inline_xor_opcode() {
    let a = vec![0xAA, 0xF0, 0x12, 0xFF];
    let b = vec![0x55, 0x0F, 0xFF]; // shorter — truncates result to 3
    let expected = vec![0xAA ^ 0x55, 0xF0 ^ 0x0F, 0x12 ^ 0xFF];

    let via_method = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 2,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![const_bytes(a.clone()), const_bytes(b.clone())],
            type_args: vec![],
        },
    });
    let via_inline = Expr::Op(IrNode {
        opcode: 0x9B,
        payload: Payload::Two(Box::new(const_bytes(a)), Box::new(const_bytes(b))),
    });
    assert_eq!(run_eval(&via_method), Value::CollBytes(expected.clone()));
    assert_eq!(run_eval(&via_inline), Value::CollBytes(expected));
}

/// EIP-50 v6 `SGlobal.serialize[T]` (MethodCall 106, 3) round-trips
/// against `deserializeTo[T]` (106, 4). Serializing a value and
/// re-parsing it through `deserializeTo` must yield the original
/// for every supported runtime carrier. This is the only structural
/// guarantee the (106, 3) arm needs: if `write_value` and
/// `read_value` disagree about any carrier's wire format, the
/// round-trip breaks here.
#[test]
fn methodcall_global_serialize_roundtrips_via_deserializeto() {
    // SBigInt / SUnsignedBigInt: exercise wide values so the
    // 2-byte length prefix (Scala `putUShort` in DataSerializer) is
    // non-trivial. SColl[SBoolean]: Scala packs via `putBits`, so the
    // 9-bit payload below crosses a byte boundary and would catch
    // any drift between `write_value` and `read_value` on the bit
    // packing.
    let signed_wide: num_bigint::BigInt = num_bigint::BigInt::from(1) << 200;
    let unsigned_wide = signed_wide.clone();
    let bools = vec![true, false, true, true, false, false, true, false, true];
    let cases: Vec<(SigmaType, Expr, Value)> = vec![
        (SigmaType::SBoolean, const_bool(true), Value::Bool(true)),
        (SigmaType::SInt, const_int(0x4242), Value::Int(0x4242)),
        (SigmaType::SLong, const_long(-1), Value::Long(-1)),
        (
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            const_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            Value::CollBytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        ),
        (
            SigmaType::SBigInt,
            Expr::Const {
                tpe: SigmaType::SBigInt,
                val: SigmaValue::BigInt(signed_wide.clone()),
            },
            Value::BigInt(signed_wide),
        ),
        (
            SigmaType::SUnsignedBigInt,
            Expr::Const {
                tpe: SigmaType::SUnsignedBigInt,
                val: SigmaValue::BigInt(unsigned_wide.clone()),
            },
            Value::UnsignedBigInt(unsigned_wide),
        ),
        (
            SigmaType::SColl(Box::new(SigmaType::SBoolean)),
            Expr::Const {
                tpe: SigmaType::SColl(Box::new(SigmaType::SBoolean)),
                val: SigmaValue::Coll(ergo_ser::sigma_value::CollValue::BoolBits(bools.clone())),
            },
            Value::CollBool(bools),
        ),
        // STuple (real fixed-arity heterogeneous tuple) — exercises
        // the `Value::Tuple` serialize-back arm against the
        // Scala-anchored parse path. Mixed Int + Long widths so any
        // accidental width erasure or element reordering shows up.
        (
            SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong]),
            Expr::Const {
                tpe: SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong]),
                val: SigmaValue::Tuple(vec![SigmaValue::Int(0x4242), SigmaValue::Long(-1)]),
            },
            Value::Tuple(vec![Value::Int(0x4242), Value::Long(-1)]),
        ),
        // Coll[(Int, Long)] — boxed-element coll carrier post split.
        // Hits the `Value::CollGeneric` serialize-back arm with a
        // non-trivial element type (STuple). Inverse parity of
        // `sigma_to_value`'s `SColl(non-primitive)` fallback.
        (
            SigmaType::SColl(Box::new(SigmaType::STuple(vec![
                SigmaType::SInt,
                SigmaType::SLong,
            ]))),
            Expr::Const {
                tpe: SigmaType::SColl(Box::new(SigmaType::STuple(vec![
                    SigmaType::SInt,
                    SigmaType::SLong,
                ]))),
                val: SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Values(vec![
                    SigmaValue::Tuple(vec![SigmaValue::Int(1), SigmaValue::Long(10)]),
                    SigmaValue::Tuple(vec![SigmaValue::Int(2), SigmaValue::Long(20)]),
                ])),
            },
            Value::CollGeneric(
                vec![
                    Value::Tuple(vec![Value::Int(1), Value::Long(10)]),
                    Value::Tuple(vec![Value::Int(2), Value::Long(20)]),
                ],
                Box::new(SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong])),
            ),
        ),
        // Empty Coll[(Int, Long)] — the typed carrier preserves
        // `elem_type` even when `items` is empty, so the
        // serialize-back path can emit the right `SColl(STuple(_))`
        // bytes instead of erroring on a missing element to probe.
        (
            SigmaType::SColl(Box::new(SigmaType::STuple(vec![
                SigmaType::SInt,
                SigmaType::SLong,
            ]))),
            Expr::Const {
                tpe: SigmaType::SColl(Box::new(SigmaType::STuple(vec![
                    SigmaType::SInt,
                    SigmaType::SLong,
                ]))),
                val: SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Values(vec![])),
            },
            Value::CollGeneric(
                vec![],
                Box::new(SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong])),
            ),
        ),
        // Coll[Option[Coll[Byte]]] with mixed `Some(_)` and `None` —
        // exercises both the new `Value::Opt` serialize-back arms
        // and the `sigma_type_compatible` wildcard that lets a
        // `None`'s recovered `SOption(SAny)` survive uniformity
        // against the carrier's concrete `SOption(SColl(SByte))`.
        (
            SigmaType::SColl(Box::new(SigmaType::SOption(Box::new(SigmaType::SColl(
                Box::new(SigmaType::SByte),
            ))))),
            Expr::Const {
                tpe: SigmaType::SColl(Box::new(SigmaType::SOption(Box::new(SigmaType::SColl(
                    Box::new(SigmaType::SByte),
                ))))),
                val: SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Values(vec![
                    SigmaValue::Opt(Some(Box::new(SigmaValue::Coll(
                        ergo_ser::sigma_value::CollValue::Bytes(vec![0xAA; 4]),
                    )))),
                    SigmaValue::Opt(None),
                    SigmaValue::Opt(Some(Box::new(SigmaValue::Coll(
                        ergo_ser::sigma_value::CollValue::Bytes(vec![0xBB; 4]),
                    )))),
                ])),
            },
            Value::CollGeneric(
                vec![
                    Value::Opt(Some(Box::new(Value::CollBytes(vec![0xAA; 4])))),
                    Value::Opt(None),
                    Value::Opt(Some(Box::new(Value::CollBytes(vec![0xBB; 4])))),
                ],
                Box::new(SigmaType::SOption(Box::new(SigmaType::SColl(Box::new(
                    SigmaType::SByte,
                ))))),
            ),
        ),
    ];
    for (tpe, value_expr, expected) in cases {
        // serialize(value) -> Coll[Byte]
        let serialized = Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id: 106,
                method_id: 3,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![value_expr],
                type_args: vec![tpe.clone()],
            },
        });
        // deserializeTo[T](serialized) -> T
        let roundtrip = Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id: 106,
                method_id: 4,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![serialized],
                type_args: vec![tpe],
            },
        });
        assert_eq!(run_eval(&roundtrip), expected);
    }
}

/// `SGlobal.serialize` carries NO wire type byte in v6.0.2, so the real
/// (101,3) MethodCall has empty `type_args`; it must still serialize,
/// recovering the type from the argument value. Byte goldens (the layout
/// is value-only, no type tag): serialize(true) = [0x01], serialize(Byte
/// -1) = [0xFF], serialize(Coll[Byte][0xDE,0xAD]) = [0x02,0xDE,0xAD]
/// (putUShort(2) VLQ then the bytes).
#[test]
fn methodcall_global_serialize_works_without_type_args_byte_goldens() {
    let mut cx = ReductionContext::minimal(0, 0);
    cx.activated_script_version = 3;
    let ser = |arg: Expr| {
        op(
            0xDC,
            Payload::MethodCall {
                type_id: 106,
                method_id: 3,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![arg],
                type_args: vec![], // real wire: serialize has no type byte
            },
        )
    };
    assert_eq!(
        eval_to_value(&ser(const_bool(true)), &cx, &[]).unwrap(),
        Value::CollBytes(vec![0x01]),
    );
    let byte_neg1 = Expr::Const {
        tpe: SigmaType::SByte,
        val: SigmaValue::Byte(-1),
    };
    assert_eq!(
        eval_to_value(&ser(byte_neg1), &cx, &[]).unwrap(),
        Value::CollBytes(vec![0xFF]),
    );
    assert_eq!(
        eval_to_value(&ser(const_bytes(vec![0xDE, 0xAD])), &cx, &[]).unwrap(),
        Value::CollBytes(vec![0x02, 0xDE, 0xAD]),
    );
    // SString "ab": lowered to Coll(Bytes) at the value layer, serialized
    // byte-identically to Coll[Byte] (VLQ length 2 + bytes), so the static
    // type only affects cost, not bytes.
    let str_ab = Expr::Const {
        tpe: SigmaType::SString,
        val: SigmaValue::Str("ab".to_string()),
    };
    assert_eq!(
        eval_to_value(&ser(str_ab), &cx, &[]).unwrap(),
        Value::CollBytes(vec![0x02, 0x61, 0x62]),
    );
    // The carrier itself: an SString value stays Value::Str through eval
    // (NOT lowered to Coll[Byte]), which is what lets serialize cost it as
    // SString (3+n) rather than Coll[Byte] (6+n) regardless of how the
    // string reaches serialize (const, deserializeTo, or a val binding).
    assert_eq!(
        eval_to_value(
            &Expr::Const {
                tpe: SigmaType::SString,
                val: SigmaValue::Str("hi".to_string()),
            },
            &cx,
            &[],
        )
        .unwrap(),
        Value::Str("hi".to_string()),
    );
}

/// Pins `SGlobal.serialize`'s v6.0.2 `DynamicCost` model (the put-cost
/// sum the caller adds StartWriterCost=10 onto): put(Byte)/putBoolean/
/// putOption-tag = 1; putShort/Int/Long = 3; putUShort = 3;
/// putBytes(n)/putBits(n) = 3 + n. Anchored to the verbatim
/// `SigmaByteWriter`/`CoreDataSerializer`/`SigmaBoolean.serializer`
/// per-put costs (source-derived).
#[test]
fn serialize_put_cost_matches_v6_0_2_dynamiccost() {
    use crate::evaluator::opcodes::method_call::serialize_put_cost;
    use ergo_ser::sigma_type::SigmaType as T;
    use ergo_ser::sigma_value::{CollValue, SigmaBoolean, SigmaValue as Sv};
    let cost = |t: T, v: Sv| serialize_put_cost(&t, &v).unwrap();
    assert_eq!(cost(T::SBoolean, Sv::Boolean(true)), 1);
    assert_eq!(cost(T::SByte, Sv::Byte(7)), 1);
    assert_eq!(cost(T::SInt, Sv::Int(42)), 3);
    assert_eq!(cost(T::SLong, Sv::Long(-1)), 3);
    // putUShort(3) + putBytes(byteLen): 7 = +1 signed byte; 0 -> 6.
    assert_eq!(cost(T::SBigInt, Sv::BigInt(num_bigint::BigInt::from(7))), 7);
    assert_eq!(
        cost(T::SUnsignedBigInt, Sv::BigInt(num_bigint::BigInt::from(0))),
        6
    );
    assert_eq!(
        cost(T::SUnsignedBigInt, Sv::BigInt(num_bigint::BigInt::from(7))),
        7
    );
    // SColl: putUShort(3) + body (Byte/Bool: 3+n; else recurse).
    assert_eq!(
        cost(
            T::SColl(Box::new(T::SByte)),
            Sv::Coll(CollValue::Bytes(vec![1, 2, 3]))
        ),
        9
    );
    // SString uses a distinct Value::Str carrier (not Coll[Byte]), so it
    // costs 3 + n (putUInt-no-info + putBytes), strictly cheaper than
    // Coll[Byte]'s 6 + n — the divergence the carrier fixes.
    assert_eq!(cost(T::SString, Sv::Str("abc".to_string())), 6);
    assert_eq!(
        cost(
            T::SColl(Box::new(T::SBoolean)),
            Sv::Coll(CollValue::BoolBits(vec![true, false, true]))
        ),
        9
    );
    // SOption: tag(1) + (Some? body).
    assert_eq!(cost(T::SOption(Box::new(T::SInt)), Sv::Opt(None)), 1);
    assert_eq!(
        cost(
            T::SOption(Box::new(T::SInt)),
            Sv::Opt(Some(Box::new(Sv::Int(5))))
        ),
        4
    );
    // STuple: no prefix, sum of items.
    assert_eq!(
        cost(
            T::STuple(vec![T::SInt, T::SLong]),
            Sv::Tuple(vec![Sv::Int(1), Sv::Long(2)])
        ),
        6
    );
    // SSigmaProp: opCode(1) per node; CAND adds putUShort(3) + children.
    assert_eq!(
        cost(
            T::SSigmaProp,
            Sv::SigmaProp(SigmaBoolean::TrivialProp(true))
        ),
        1
    );
    assert_eq!(
        cost(
            T::SSigmaProp,
            Sv::SigmaProp(SigmaBoolean::Cand(vec![
                SigmaBoolean::TrivialProp(true),
                SigmaBoolean::TrivialProp(false),
            ]))
        ),
        6
    );
}

/// EIP-50 v6 `SHeader.checkPow` (MethodCall 104, 16) reconstructs
/// a serialization-layer `Header` from the carried `EvalHeader`
/// (including `unparsed_bytes` for v5+) and delegates to
/// `ergo_crypto::pow::verify_pow_solution`. The risk is the
/// reconstruction step: any field dropped or shape-shifted between
/// `from_header` and the rebuild would silently fail PoW (the
/// `bytesWithoutPow → blake2b256` hash diverges). This test loads
/// a real mainnet v1 header, runs the round trip, and asserts the
/// reconstructed header passes PoW; then mutates `nBits` to an
/// impossibly tight target and asserts rejection. Together they
/// pin both branches of the `Bool` result without depending on a
/// `SigmaValue::Header` constant carrier (which doesn't exist on
/// the wire).
#[test]
fn methodcall_header_checkpow_v6_reconstructs_for_pow_verify() {
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::read_header;
    let raw = std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json")
        .expect("headers_1_10 fixture must exist for SHeader.checkPow test");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let bytes = hex::decode(v[0]["bytes"].as_str().unwrap()).unwrap();
    let mut r = VlqReader::new(&bytes);
    let h = read_header(&mut r).expect("header parse");
    let eh = EvalHeader::from_header(&h, [0u8; 32]);

    // Round-trip reconstruction: same logic the (104, 16) arm
    // executes before calling verify_pow_solution.
    let pk_ge = ergo_primitives::group_element::GroupElement::from_bytes(eh.miner_pk);
    let solution = if eh.version == 1 {
        let w_ge = ergo_primitives::group_element::GroupElement::from_bytes(eh.pow_onetime_pk);
        ergo_ser::autolykos::AutolykosSolution::V1 {
            pk: pk_ge,
            w: w_ge,
            nonce: eh.pow_nonce,
            d: eh.pow_distance.to_signed_bytes_be(),
        }
    } else {
        ergo_ser::autolykos::AutolykosSolution::V2 {
            pk: pk_ge,
            nonce: eh.pow_nonce,
        }
    };
    let rebuilt = ergo_ser::header::Header {
        version: eh.version,
        parent_id: ergo_primitives::digest::ModifierId::from_bytes(eh.parent_id),
        ad_proofs_root: ergo_primitives::digest::Digest32::from_bytes(eh.ad_proofs_root),
        transactions_root: ergo_primitives::digest::Digest32::from_bytes(eh.transactions_root),
        state_root: ergo_primitives::digest::ADDigest::from_bytes(eh.state_root),
        timestamp: eh.timestamp,
        extension_root: ergo_primitives::digest::Digest32::from_bytes(eh.extension_root),
        n_bits: eh.n_bits,
        height: eh.height,
        votes: eh.votes,
        unparsed_bytes: eh.unparsed_bytes.clone(),
        solution,
    };
    assert!(
        ergo_crypto::pow::verify_pow_solution(&rebuilt).is_ok(),
        "EvalHeader → Header round trip must preserve the PoW invariant",
    );
    // Tighten nBits to an impossible target: same bit pattern as
    // `0x01_00_00_01` → size=1 mantissa=0x01 → target=1 (one
    // valid PoW out of 2^256 possible).
    let mut bad = rebuilt.clone();
    bad.n_bits = 0x0100_0001;
    assert!(
        ergo_crypto::pow::verify_pow_solution(&bad).is_err(),
        "impossibly tight nBits must reject the same header",
    );
}

#[test]
fn opcode_height_custom_ctx() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let expr = op(0xA3, Payload::Zero);
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Int(600_000));
}

#[test]
fn opcode_logical_not_false() {
    let expr = op(0xEF, Payload::One(Box::new(const_bool(false))));
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

#[test]
fn select_field_4_and_5() {
    // Post-Phase-6 parity sweep: tuple field access at indices 4 and
    // 5 goes through 0x8C SelectField with `field_idx = 4/5`, not
    // through the removed 0x8A/0x8B dispatch arms. A >2-element tuple
    // only exists as a value/constant (CreateTuple 0x86 evaluates only
    // pairs), so the fixture is a 5-tuple constant.
    let tuple = int_tuple_const(&[10, 20, 30, 40, 50]);
    let s4 = op(
        0x8C,
        Payload::SelectField {
            input: Box::new(tuple.clone()),
            field_idx: 4,
        },
    );
    let s5 = op(
        0x8C,
        Payload::SelectField {
            input: Box::new(tuple),
            field_idx: 5,
        },
    );
    assert_eq!(run_eval(&s4), Value::Int(40));
    assert_eq!(run_eval(&s5), Value::Int(50));
}

// ── Batch 4: Missing corpus-observed opcodes ────────────────────

// DeserializeContext (0xD4) — deserialize expression from context extension var
#[test]
fn opcode_deserialize_context() {
    // Serialize True (0x7F) as a 1-byte expression, place in extension var 1
    let b = make_test_box();
    let mut ctx = ctx_with_self_box(&b);
    ctx.extension.insert(
        1,
        (
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Bytes(vec![0x7F])),
        ),
    );
    let expr = op(
        0xD4,
        Payload::DeserializeContext {
            id: 1,
            tpe: SigmaType::SBoolean,
        },
    );
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Bool(true));
}

#[test]
fn opcode_deserialize_context_missing_var() {
    let expr = op(
        0xD4,
        Payload::DeserializeContext {
            id: 99,
            tpe: SigmaType::SBoolean,
        },
    );
    let err = run_eval_err(&expr);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

// DeserializeRegister (0xD5) — deserialize expression from SELF register
#[test]
fn opcode_deserialize_register_present() {
    // Put serialized True (0x7F) in R6 as Coll[Byte]
    let mut b = make_test_box();
    b.registers[2] = Some(ergo_ser::register::RegisterValue {
        tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        value: SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Bytes(vec![0x7F])),
    });
    let ctx = ctx_with_self_box(&b);
    let expr = op(
        0xD5,
        Payload::DeserializeRegister {
            reg_id: 6,
            tpe: SigmaType::SBoolean,
            default: None,
        },
    );
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Bool(true));
}

#[test]
fn opcode_deserialize_register_absent_with_default() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    // R8 is None — use default False
    let expr = op(
        0xD5,
        Payload::DeserializeRegister {
            reg_id: 8,
            tpe: SigmaType::SBoolean,
            default: Some(Box::new(op(0x80, Payload::Zero))), // False
        },
    );
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Bool(false));
}

/// Serialized `Global.deserializeTo[Boolean](Coll[Byte](0x01))` body —
/// a v6 MethodCall whose wire form ends with the trailing explicit
/// type byte (`0x01` = SBoolean). Embedded-deserialization payloads
/// carry no tree header, so `parse_body(.., 0)` must consume that
/// byte keyed on `(type_id, method_id)` alone; the layout is
/// oracle-pinned by
/// `test-vectors/scala/sigma/v6_methodcall_typeargs_v0_header/`.
fn v6_typearg_methodcall_payload() -> Vec<u8> {
    let expr = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 4,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![const_bytes(vec![0x01])],
            type_args: vec![SigmaType::SBoolean],
        },
    });
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::opcode::write_body(&mut w, &expr, false).unwrap();
    w.result()
}

#[test]
fn opcode_deserialize_context_v6_typearg_payload_evaluates() {
    let b = make_test_box();
    let mut ctx = ctx_with_self_box(&b);
    ctx.extension.insert(
        1,
        (
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Bytes(
                v6_typearg_methodcall_payload(),
            )),
        ),
    );
    let expr = op(
        0xD4,
        Payload::DeserializeContext {
            id: 1,
            tpe: SigmaType::SBoolean,
        },
    );
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Bool(true));
}

#[test]
fn opcode_deserialize_register_v6_typearg_payload_evaluates() {
    let mut b = make_test_box();
    b.registers[2] = Some(ergo_ser::register::RegisterValue {
        tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        value: SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Bytes(
            v6_typearg_methodcall_payload(),
        )),
    });
    let ctx = ctx_with_self_box(&b);
    let expr = op(
        0xD5,
        Payload::DeserializeRegister {
            reg_id: 6,
            tpe: SigmaType::SBoolean,
            default: None,
        },
    );
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Bool(true));
}

#[test]
fn opcode_deserialize_context_v6_typearg_payload_rejects_pre_eip50() {
    let b = make_test_box();
    let mut ctx = ctx_with_self_box(&b);
    ctx.activated_script_version = 2;
    ctx.extension.insert(
        1,
        (
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Bytes(
                v6_typearg_methodcall_payload(),
            )),
        ),
    );
    let expr = op(
        0xD4,
        Payload::DeserializeContext {
            id: 1,
            tpe: SigmaType::SBoolean,
        },
    );
    // The payload parses (type-byte read is version-independent); the
    // not-yet-activated v6 method is rejected at evaluation time.
    match run_eval_ctx_err(&expr, &ctx) {
        EvalError::SoftForkNotActivated {
            type_id,
            method_id,
            required,
            got,
        } => {
            assert_eq!((type_id, method_id), (106, 4));
            assert_eq!((required, got), (3, 2));
        }
        other => panic!("expected SoftForkNotActivated, got {other:?}"),
    }
}

#[test]
fn opcode_deserialize_context_v6_typearg_payload_truncated_errors() {
    let mut payload = v6_typearg_methodcall_payload();
    payload.pop(); // drop the trailing explicit type byte
    let b = make_test_box();
    let mut ctx = ctx_with_self_box(&b);
    ctx.extension.insert(
        1,
        (
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Bytes(payload)),
        ),
    );
    let expr = op(
        0xD4,
        Payload::DeserializeContext {
            id: 1,
            tpe: SigmaType::SBoolean,
        },
    );
    let err = run_eval_ctx_err(&expr, &ctx);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

/// End-to-end: an inline `SBox` constant whose proposition is the
/// Scala-6.1.2-compiled sizeless v0-header (`0x10`) tree carrying the
/// `SGlobal.none[T]` v6 PropertyCall (oracle vector
/// `test-vectors/scala/sigma/v6_methodcall_typeargs_v0_header/`).
/// `skip_ergo_tree` has no size field to skip by, so capturing the
/// box-byte boundary walks the v6 body through the full parser; the
/// evaluator then rehydrates the `OpaqueBoxBytes` via `read_ergo_box`.
#[test]
fn opcode_extract_amount_sbox_constant_with_sizeless_v6_typearg_tree() {
    let tree = hex::decode("1000d1efe6db6a0add04").unwrap();
    let mut w = ergo_primitives::writer::VlqWriter::new();
    w.put_u64(1_000_000); // value
    w.put_bytes(&tree); // proposition (sizeless v0-header v6 tree)
    w.put_u32(100); // creation height
    w.put_u8(0); // token count
    w.put_u8(0); // register count
    w.put_bytes(&[0u8; 32]); // tx id
    w.put_u16(0); // output index
    let box_bytes = w.result();

    let sbox = Expr::Const {
        tpe: SigmaType::SBox,
        val: SigmaValue::OpaqueBoxBytes(box_bytes),
    };
    let expr = op(0xC1, Payload::One(Box::new(sbox))); // ExtractAmount
    assert_eq!(run_eval(&expr), Value::Long(1_000_000));
}

/// An SBox materialized from a constant must keep the real transaction id
/// and output index from the serialized box tail (read_ergo_box parses
/// both), not zero them. ExtractCreationInfo (0xC7) surfaces them as the R3
/// reference = transactionId.toBytes (32) ++ Shorts.toByteArray(index) (a
/// FIXED 2-byte big-endian index), per Scala ErgoBox.get(ReferenceRegId).
/// Uses a multi-byte index (22588) so a zeroed index is unmistakable.
#[test]
fn sbox_constant_preserves_txid_and_index_in_creation_info() {
    let txid = [0xABu8; 32];
    let index: u16 = 22588; // 0x583C; big-endian 2-byte = [0x58, 0x3C]
    let tree = hex::decode("1000d1efe6db6a0add04").unwrap();
    let mut w = ergo_primitives::writer::VlqWriter::new();
    w.put_u64(1_000_000); // value
    w.put_bytes(&tree); // proposition
    w.put_u32(100); // creation height
    w.put_u8(0); // token count
    w.put_u8(0); // register count
    w.put_bytes(&txid); // tx id (32 bytes)
    w.put_u16(index); // output index (VLQ)
    let box_bytes = w.result();
    let sbox = Expr::Const {
        tpe: SigmaType::SBox,
        val: SigmaValue::OpaqueBoxBytes(box_bytes),
    };

    // ExtractCreationInfo (0xC7) -> (creationHeight, txid ++ index_be2).
    let ci = op(0xC7, Payload::One(Box::new(sbox)));
    match run_eval(&ci) {
        Value::Tuple(items) => {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0], Value::Int(100), "creation height");
            let mut expected_ref = txid.to_vec();
            expected_ref.extend_from_slice(&index.to_be_bytes());
            assert_eq!(
                items[1],
                Value::CollBytes(expected_ref),
                "R3 ref must be the real txid ++ 2-byte big-endian index",
            );
        }
        other => panic!("expected creationInfo tuple, got {other:?}"),
    }
}

// AtLeast (0x98) — k-of-n threshold
#[test]
fn opcode_atleast_all_trivial_true() {
    // atLeast(2, [TrivialTrue, TrivialTrue, TrivialTrue]) → TrivialProp(true)
    use ergo_ser::sigma_value::CollValue;
    let bound = const_int(2);
    let items = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
        val: SigmaValue::Coll(CollValue::Values(vec![
            SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
            SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
            SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
        ])),
    };
    let expr = op(0x98, Payload::Two(Box::new(bound), Box::new(items)));
    match run_eval(&expr) {
        // k <= count(true_children) → TrivialProp(true) OR Cthreshold with all-true children
        Value::SigmaProp(SigmaBoolean::TrivialProp(true)) => {}
        Value::SigmaProp(SigmaBoolean::Cthreshold { k, children }) => {
            assert_eq!(k, 2);
            assert_eq!(children.len(), 3);
        }
        other => panic!("expected threshold-true result, got {other:?}"),
    }
}

#[test]
fn opcode_atleast_bound_exceeds_count() {
    use ergo_ser::sigma_value::CollValue;
    let bound = const_int(5);
    let items = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
        val: SigmaValue::Coll(CollValue::Values(vec![SigmaValue::SigmaProp(
            SigmaBoolean::TrivialProp(true),
        )])),
    };
    let expr = op(0x98, Payload::Two(Box::new(bound), Box::new(items)));
    match run_eval(&expr) {
        Value::SigmaProp(SigmaBoolean::TrivialProp(false)) => {}
        other => panic!("expected TrivialProp(false), got {other:?}"),
    }
}

// SContext.headers (type_id=101, method_id=2) via PropertyCall
#[test]
fn opcode_context_headers() {
    let h = EvalHeader {
        id: [0xAA; 32],
        version: 2,
        parent_id: [0xBB; 32],
        ad_proofs_root: [0; 32],
        state_root: [0; 33],
        transactions_root: [0; 32],
        timestamp: 1_600_000_000_000,
        n_bits: 0x01000000,
        height: 500_000,
        extension_root: [0; 32],
        miner_pk: [0x02; 33],
        pow_onetime_pk: [0x03; 33],
        pow_nonce: [0xFF; 8],
        pow_distance: num_bigint::BigInt::from(0),
        votes: [0, 0, 0],
        unparsed_bytes: Vec::new(),
    };
    let b = make_test_box();
    let headers = vec![h.clone()];
    let mut ctx = ctx_with_self_box(&b);
    ctx.last_headers = &headers;

    // CONTEXT.headers → Coll[Header]
    let context_expr = op(0xFE, Payload::Zero);
    let expr = op(
        0xDB,
        Payload::MethodCall {
            type_id: 101,
            method_id: 2,
            obj: Box::new(context_expr),
            args: vec![],
            type_args: vec![],
        },
    );
    match run_eval_ctx(&expr, &ctx) {
        Value::CollHeader(hdrs) => assert_eq!(hdrs.len(), 1),
        other => panic!("expected CollHeader, got {other:?}"),
    }
}

// SHeader properties via PropertyCall (type_id=104)
#[test]
fn opcode_sheader_properties() {
    let h = EvalHeader {
        id: [0xAA; 32],
        version: 2,
        parent_id: [0xBB; 32],
        ad_proofs_root: [0xCC; 32],
        state_root: [0xDD; 33],
        transactions_root: [0xEE; 32],
        timestamp: 1_600_000_000_000,
        n_bits: 0x01234567,
        height: 500_000,
        extension_root: [0x11; 32],
        miner_pk: [0x02; 33],
        pow_onetime_pk: [0x03; 33],
        pow_nonce: [0xFF; 8],
        pow_distance: num_bigint::BigInt::from(42),
        votes: [1, 2, 3],
        unparsed_bytes: Vec::new(),
    };
    let b = make_test_box();
    let headers = vec![h.clone()];
    let mut ctx = ctx_with_self_box(&b);
    ctx.last_headers = &headers;

    // Get headers(0) then access properties
    let get_header = op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(op(
                0xDB,
                Payload::MethodCall {
                    type_id: 101,
                    method_id: 2,
                    obj: Box::new(op(0xFE, Payload::Zero)),
                    args: vec![],
                    type_args: vec![],
                },
            )),
            index: Box::new(const_int(0)),
            default: None,
        },
    );

    // .id (method 1)
    let id_expr = op(
        0xDB,
        Payload::MethodCall {
            type_id: 104,
            method_id: 1,
            obj: Box::new(get_header.clone()),
            args: vec![],
            type_args: vec![],
        },
    );
    assert_eq!(
        run_eval_ctx(&id_expr, &ctx),
        Value::CollBytes(vec![0xAA; 32])
    );

    // .version (method 2)
    let ver_expr = op(
        0xDB,
        Payload::MethodCall {
            type_id: 104,
            method_id: 2,
            obj: Box::new(get_header.clone()),
            args: vec![],
            type_args: vec![],
        },
    );
    // SHeader.version is Byte (typed carrier, not erased Int).
    assert_eq!(run_eval_ctx(&ver_expr, &ctx), Value::Byte(2));

    // .height (method 9)
    let ht_expr = op(
        0xDB,
        Payload::MethodCall {
            type_id: 104,
            method_id: 9,
            obj: Box::new(get_header.clone()),
            args: vec![],
            type_args: vec![],
        },
    );
    assert_eq!(run_eval_ctx(&ht_expr, &ctx), Value::Int(500_000));

    // .timestamp (method 7)
    let ts_expr = op(
        0xDB,
        Payload::MethodCall {
            type_id: 104,
            method_id: 7,
            obj: Box::new(get_header.clone()),
            args: vec![],
            type_args: vec![],
        },
    );
    assert_eq!(run_eval_ctx(&ts_expr, &ctx), Value::Long(1_600_000_000_000));

    // .votes (method 15)
    let votes_expr = op(
        0xDB,
        Payload::MethodCall {
            type_id: 104,
            method_id: 15,
            obj: Box::new(get_header.clone()),
            args: vec![],
            type_args: vec![],
        },
    );
    assert_eq!(
        run_eval_ctx(&votes_expr, &ctx),
        Value::CollBytes(vec![1, 2, 3])
    );
}

// SubstConstants (0x74) — substitute a constant in a serialized ErgoTree
#[test]
fn opcode_subst_constants() {
    // Build a segregated P2PK ErgoTree:
    //   header: 0x10 (segregated, version 0)
    //   1 constant: SSigmaProp = ProveDlog(pk_a)
    //   body: ConstPlaceholder(0)
    // Then substitute position 0 with ProveDlog(pk_b).
    let pk_a = [0x02; 33]; // dummy pk A
    let pk_b = [0x03; 33]; // dummy pk B

    // Serialize the template tree
    let mut tree_bytes = vec![
        0x10, // header: segregated
        1,    // 1 constant
        0x08, // type: SSigmaProp
        0xCD, // ProveDlog tag
    ];
    tree_bytes.extend_from_slice(&pk_a); // 33-byte pk
    tree_bytes.push(0x73); // body: ConstPlaceholder
    tree_bytes.push(0x00); // index 0

    let script = const_bytes(tree_bytes.clone());
    use ergo_ser::sigma_value::CollValue;
    let positions = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SInt)),
        val: SigmaValue::Coll(CollValue::Values(vec![SigmaValue::Int(0)])),
    };
    // New value: ProveDlog(pk_b)
    let new_pk = ergo_primitives::group_element::GroupElement::from_bytes(pk_b);
    let new_vals = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
        val: SigmaValue::Coll(CollValue::Values(vec![SigmaValue::SigmaProp(
            SigmaBoolean::ProveDlog(new_pk),
        )])),
    };

    let expr = op(
        0x74,
        Payload::Three(Box::new(script), Box::new(positions), Box::new(new_vals)),
    );
    match run_eval(&expr) {
        Value::CollBytes(result) => {
            // The result should be a new ErgoTree with pk_b instead of pk_a
            assert!(result.len() > 33);
            // The constant section should now contain pk_b
            // header(1) + count(1) + type(1) + ProveDlog(1) + pk(33) + body(2) = 39
            assert_eq!(&result[4..37], &pk_b[..]);
        }
        other => panic!("expected CollBytes, got {other:?}"),
    }
}

// ── Negative-path rejection tests ─────────────────────────────

// ----- error paths (rejection parity) -----

// UnsupportedConstant — constant with unhandled type
#[test]
fn reject_unsupported_constant() {
    // SHeader is not a valid constant type — triggers the catch-all in sigma_to_value
    let constants = vec![(SigmaType::SHeader, SigmaValue::Unit)];
    let expr = op(0x73, Payload::ConstPlaceholder { index: 0 });
    let err = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &constants).unwrap_err();
    assert!(
        matches!(err, EvalError::UnsupportedConstant(_)),
        "got {err:?}"
    );
}

// DepthLimitExceeded — deeply nested If expressions
#[test]
fn reject_depth_limit_exceeded() {
    // Build a chain of 200 nested If(true, If(true, ... , 1), 0)
    // which exceeds MAX_EVAL_DEPTH (100)
    let mut expr = const_int(1);
    for _ in 0..200 {
        expr = op(
            0x95,
            Payload::Three(
                Box::new(const_bool(true)),
                Box::new(expr),
                Box::new(const_int(0)),
            ),
        );
    }
    let err = run_eval_err(&expr);
    assert!(
        matches!(err, EvalError::DepthLimitExceeded(_)),
        "got {err:?}"
    );
}

// Script evaluates to TrivialProp(false) — spending should be rejected
#[test]
fn reject_script_evaluates_to_false() {
    // BoolToSigmaProp(false) → TrivialProp(false)
    let expr = op(0xD1, Payload::One(Box::new(const_bool(false))));
    let ctx = ReductionContext::minimal(500_000, 0);
    let result = reduce_expr(&expr, &ctx, &[]).unwrap();
    assert_eq!(result, SigmaBoolean::TrivialProp(false));
}

// Script evaluates to TrivialProp(false) via HEIGHT check
#[test]
fn reject_height_below_threshold() {
    // BoolToSigmaProp(HEIGHT >= 1_000_000) at height 500_000 → false
    let constants = vec![(SigmaType::SInt, SigmaValue::Int(1_000_000))];
    let height = op(0xA3, Payload::Zero);
    let threshold = op(0x73, Payload::ConstPlaceholder { index: 0 });
    let ge = op(0x92, Payload::Two(Box::new(height), Box::new(threshold)));
    let expr = op(0xD1, Payload::One(Box::new(ge)));
    let ctx = ReductionContext::minimal(500_000, 0);
    let result = reduce_expr_with_cost(
        &expr,
        &ctx,
        &constants,
        &mut CostAccumulator::recording_only(),
    )
    .unwrap();
    assert_eq!(result, SigmaBoolean::TrivialProp(false));
}

// Non-SigmaProp script result → TypeError
#[test]
fn reject_non_sigmaprop_result() {
    // A script whose root expression is an Int, not a SigmaProp
    let expr = const_int(42);
    let ctx = ReductionContext::minimal(500_000, 0);
    let err = reduce_expr(&expr, &ctx, &[]).unwrap_err();
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

// OptionGet on None — SELF.R8 not present
#[test]
fn reject_option_get_absent_register() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    // OptionGet(ExtractRegisterAs(SELF, R9, SInt)) — R9 is None
    let reg = op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(op(0xA7, Payload::Zero)),
            reg_id: 9,
            tpe: SigmaType::SInt,
        },
    );
    let expr = op(0xE4, Payload::One(Box::new(reg)));
    let err = eval_to_value(&expr, &ctx, &[]).unwrap_err();
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

// Division by zero — Long variant
#[test]
fn reject_division_by_zero_long() {
    let expr = op(
        0x9D,
        Payload::Two(Box::new(const_long(100)), Box::new(const_long(0))),
    );
    let err = run_eval_err(&expr);
    // Runtime arithmetic error, not a type error (matches Int + Byte/Short).
    assert!(matches!(err, EvalError::RuntimeException(_)), "got {err:?}");
}

// Modulo by zero — Long variant
#[test]
fn reject_modulo_by_zero_long() {
    let expr = op(
        0x9E,
        Payload::Two(Box::new(const_long(100)), Box::new(const_long(0))),
    );
    let err = run_eval_err(&expr);
    // Runtime arithmetic error, not a type error (matches Int + Byte/Short).
    assert!(matches!(err, EvalError::RuntimeException(_)), "got {err:?}");
}

// Lt type mismatch (Int vs Long)
#[test]
fn reject_lt_type_mismatch() {
    let expr = op(
        0x8F,
        Payload::Two(Box::new(const_int(1)), Box::new(const_long(2))),
    );
    let err = run_eval_err(&expr);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

// Arithmetic type mismatch (Int + Long)
#[test]
fn reject_plus_type_mismatch() {
    let expr = op(
        0x9A,
        Payload::Two(Box::new(const_int(1)), Box::new(const_long(2))),
    );
    let err = run_eval_err(&expr);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

// Unsupported opcode
#[test]
fn reject_unsupported_opcode() {
    let expr = op(0x01, Payload::Zero); // 0x01 is not a valid opcode
    let err = run_eval_err(&expr);
    assert!(
        matches!(err, EvalError::UnsupportedOpcode(0x01)),
        "got {err:?}"
    );
}

// BinAnd with non-Bool operand
#[test]
fn reject_binand_non_bool() {
    let expr = op(
        0xED,
        Payload::Two(Box::new(const_int(1)), Box::new(const_bool(true))),
    );
    let err = run_eval_err(&expr);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

// If condition is not Bool
#[test]
fn reject_if_non_bool_condition() {
    let expr = op(
        0x95,
        Payload::Three(
            Box::new(const_int(1)), // not Bool
            Box::new(const_int(2)),
            Box::new(const_int(3)),
        ),
    );
    let err = run_eval_err(&expr);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

// LogicalNot on non-Bool
#[test]
fn reject_logical_not_non_bool() {
    let expr = op(0xEF, Payload::One(Box::new(const_int(42))));
    let err = run_eval_err(&expr);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

// ByteArrayToLong with wrong-length input
#[test]
fn reject_byte_array_to_long_wrong_length() {
    let expr = op(0x7C, Payload::One(Box::new(const_bytes(vec![1, 2, 3]))));
    let err = run_eval_err(&expr);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

// Empty proof for TrivialProp(false) → verification returns false (not error)
#[test]
fn reject_trivial_false_empty_proof() {
    use crate::verify::verify_sigma_proof;
    let result = verify_sigma_proof(&SigmaBoolean::TrivialProp(false), &[], b"message").unwrap();
    assert!(!result, "TrivialProp(false) should reject any proof");
}

// Empty proof for non-trivial ProveDlog → verification returns false
#[test]
fn reject_empty_proof_for_provedlog() {
    use crate::verify::verify_sigma_proof;
    let pk = ergo_primitives::group_element::GroupElement::from_bytes([0x02; 33]);
    let result = verify_sigma_proof(&SigmaBoolean::ProveDlog(pk), &[], b"message").unwrap();
    assert!(!result, "ProveDlog with empty proof should fail");
}

// Garbage proof for ProveDlog → verification returns false
#[test]
fn reject_garbage_proof_for_provedlog() {
    use crate::verify::verify_sigma_proof;
    let pk = ergo_primitives::group_element::GroupElement::from_bytes([0x02; 33]);
    let garbage = vec![0x42u8; 56]; // correct length but wrong content
    let result = verify_sigma_proof(&SigmaBoolean::ProveDlog(pk), &garbage, b"message").unwrap();
    assert!(!result, "ProveDlog with garbage proof should fail");
}

// --- Tuple field access + parity rejects ---
//
// Earlier iterations of these tests used the unregistered
// 0x87/88/89 Select1/2/3 opcodes. Scala registers only SelectField
// (0x8C); these tests go through SelectField directly and keep the
// accept-set parity-reject coverage intact.

/// SelectField with field_idx 1/2/3 is the Scala-emitted form of
/// tuple field access. Exercises all three on a 5-tuple constant
/// (>2-element tuples exist only as values, not CreateTuple nodes).
#[test]
fn select_field_1_2_3_on_tuple_of_5() {
    let tuple = int_tuple_const(&[10, 20, 30, 40, 50]);
    let s1 = op(
        0x8C,
        Payload::SelectField {
            input: Box::new(tuple.clone()),
            field_idx: 1,
        },
    );
    let s2 = op(
        0x8C,
        Payload::SelectField {
            input: Box::new(tuple.clone()),
            field_idx: 2,
        },
    );
    let s3 = op(
        0x8C,
        Payload::SelectField {
            input: Box::new(tuple),
            field_idx: 3,
        },
    );
    assert_eq!(run_eval(&s1), Value::Int(10));
    assert_eq!(run_eval(&s2), Value::Int(20));
    assert_eq!(run_eval(&s3), Value::Int(30));
}

#[test]
fn select_field_out_of_range_errors() {
    // field_idx beyond the tuple arity must error (1-indexed; a pair has
    // only fields 1 and 2).
    let tuple = int_tuple_const(&[10, 20]);
    let s3 = op(
        0x8C,
        Payload::SelectField {
            input: Box::new(tuple),
            field_idx: 3,
        },
    );
    let err = run_eval_err(&s3);
    assert!(
        matches!(err, EvalError::TypeError { .. }),
        "SelectField out of range must error, got {err:?}"
    );
}

#[test]
fn select_field_on_non_tuple_type_errors() {
    let s1 = op(
        0x8C,
        Payload::SelectField {
            input: Box::new(const_int(42)),
            field_idx: 1,
        },
    );
    let err = run_eval_err(&s1);
    assert!(
        matches!(err, EvalError::TypeError { .. }),
        "SelectField on non-tuple must error, got {err:?}"
    );
}

/// Parity rejects — each opcode must fire its specific error variant.
/// Scala file:line citations in the arm comments.
#[test]
fn parity_rejects_fire_specific_errors() {
    // 0xCF SigmaPropIsProven → InternalOpcode
    // transformers.scala:321-329, costKind = notSupportedError.
    let e = Expr::Op(IrNode {
        opcode: 0xCF,
        payload: Payload::Zero,
    });
    let err = run_eval_err(&e);
    match err {
        EvalError::InternalOpcode(code, name) => {
            assert_eq!(code, 0xCF);
            assert_eq!(name, "SigmaPropIsProven");
        }
        other => panic!("0xCF expected InternalOpcode, got {other:?}"),
    }

    // 0xD7 FunDef standalone → InternalOpcode
    // values.scala:940-948, costKind = notSupportedError.
    let e = Expr::Op(IrNode {
        opcode: 0xD7,
        payload: Payload::Zero,
    });
    let err = run_eval_err(&e);
    match err {
        EvalError::InternalOpcode(code, name) => {
            assert_eq!(code, 0xD7);
            assert_eq!(name, "FunDef standalone");
        }
        other => panic!("0xD7 expected InternalOpcode, got {other:?}"),
    }

    // 0xE7/E8/E9 ModQ family → DeprecatedOpcode
    // trees.scala:953-991, class comment "TODO v6.0: implement".
    for &code in &[0xE7u8, 0xE8u8, 0xE9u8] {
        let e = Expr::Op(IrNode {
            opcode: code,
            payload: Payload::Zero,
        });
        let err = run_eval_err(&e);
        match err {
            EvalError::DeprecatedOpcode(c) => assert_eq!(c, code),
            other => panic!("0x{code:02X} expected DeprecatedOpcode, got {other:?}"),
        }
    }

    // 0xF1 BitInversion → NotExecutable
    // trees.scala:898-908, costKind = notSupportedError.
    let e = Expr::Op(IrNode {
        opcode: 0xF1,
        payload: Payload::Zero,
    });
    let err = run_eval_err(&e);
    match err {
        EvalError::NotExecutable(code, name) => {
            assert_eq!(code, 0xF1);
            assert_eq!(name, "BitInversion");
        }
        other => panic!("0xF1 expected NotExecutable, got {other:?}"),
    }
}

/// Parse→eval roundtrip for SelectField(1). Confirms the parser
/// produces the right payload shape and the evaluator dispatches
/// correctly from real wire bytes. (Earlier iterations used 0x87
/// Select1; this uses 0x8C SelectField for Scala parity.)
#[test]
fn select_field_parse_eval_roundtrip() {
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::opcode::{parse_expr, write_body};

    // CreateTuple (0x86) evaluates only pairs, so the roundtrip uses a
    // 2-element tuple; the point of the test is SelectField's wire shape.
    let tuple = op(
        0x86,
        Payload::Tuple {
            items: vec![const_int(100), const_int(200)],
        },
    );
    let ir = op(
        0x8C,
        Payload::SelectField {
            input: Box::new(tuple),
            field_idx: 1,
        },
    );
    let mut w = VlqWriter::new();
    write_body(&mut w, &ir, false).expect("serialize SelectField");
    let bytes = w.result();
    let mut r = VlqReader::new(&bytes);
    let parsed = parse_expr(&mut r, 0, 0).expect("parse SelectField");
    assert_eq!(run_eval(&parsed), Value::Int(100));
}

// --- Standalone BoolColl (0x85) + AVL reject-only (0xB6, 0xB7) ---

/// Standalone `ConcreteCollectionBooleanConstant` (0x85). Parser
/// pre-decodes the packed bits; evaluator wires to Value::CollBool.
/// Cost Fixed(20) shared with ConcreteCollection (values.scala:890).
#[test]
fn bool_coll_standalone_returns_coll_bool() {
    let bits = vec![true, false, true, true, false, true, false, false, true];
    let expr = Expr::Op(IrNode {
        opcode: 0x85,
        payload: Payload::BoolCollection { bits: bits.clone() },
    });
    assert_eq!(run_eval(&expr), Value::CollBool(bits));
}

#[test]
fn bool_coll_standalone_empty() {
    let expr = Expr::Op(IrNode {
        opcode: 0x85,
        payload: Payload::BoolCollection { bits: vec![] },
    });
    assert_eq!(run_eval(&expr), Value::CollBool(vec![]));
}

/// Parse→eval roundtrip for 0x85. The parser decodes the wire-format
/// u16 length + packed bytes; the evaluator reads the decoded bits.
#[test]
fn bool_coll_standalone_parse_eval_roundtrip() {
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::opcode::{parse_expr, write_body};

    // Use a mix of true/false, non-byte-aligned length, to exercise
    // LSB-first packing on both encode and decode sides.
    let bits = vec![
        true, true, false, true, false, false, true, false, true, true,
    ];
    let ir = Expr::Op(IrNode {
        opcode: 0x85,
        payload: Payload::BoolCollection { bits: bits.clone() },
    });
    let mut w = VlqWriter::new();
    write_body(&mut w, &ir, false).expect("serialize BoolColl");
    let bytes = w.result();
    let mut r = VlqReader::new(&bytes);
    let parsed = parse_expr(&mut r, 0, 0).expect("parse BoolColl");
    assert_eq!(run_eval(&parsed), Value::CollBool(bits));
}

/// 0xB6 CreateAvlTree is not executable in Scala
/// (costKind = notSupportedError at trees.scala:89; no eval override).
#[test]
fn create_avl_tree_rejects() {
    // Use a minimal payload — the reject arm fires regardless of shape.
    let expr = Expr::Op(IrNode {
        opcode: 0xB6,
        payload: Payload::Zero,
    });
    let err = run_eval_err(&expr);
    match err {
        EvalError::NotExecutable(code, name) => {
            assert_eq!(code, 0xB6);
            assert_eq!(name, "CreateAvlTree");
        }
        other => panic!("expected NotExecutable, got {other:?}"),
    }
}

/// EIP-50 v6 `SNumericTypeMethods` — bitwise + shift methods (ids
/// 8-13) across Byte/Short/Int/Long/BigInt. Each (type, method)
/// arm is exercised with at least one happy-path vector. Java
/// promotion semantics for Byte/Short shifts are pinned by the
/// edge-case vector that overflows the destination width.
#[test]
fn methodcall_numeric_bitwise_inverse_v6_across_types() {
    // bitwiseInverse: ~x
    let mk = |type_id: u8, obj: Expr| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id,
                method_id: 8,
                obj: Box::new(obj),
                args: vec![],
                type_args: vec![],
            },
        })
    };
    assert_eq!(
        run_eval(&mk(
            2,
            Expr::Const {
                tpe: SigmaType::SByte,
                val: SigmaValue::Byte(0x0F),
            },
        )),
        Value::Byte(!0x0F),
    );
    assert_eq!(
        run_eval(&mk(
            3,
            Expr::Const {
                tpe: SigmaType::SShort,
                val: SigmaValue::Short(0x0F0F),
            },
        )),
        Value::Short(!0x0F0F),
    );
    assert_eq!(
        run_eval(&mk(4, const_int(0x0F0F_0F0F))),
        Value::Int(!0x0F0F_0F0F)
    );
    assert_eq!(
        run_eval(&mk(5, const_long(0x0F0F_0F0F_0F0F_0F0F))),
        Value::Long(!0x0F0F_0F0F_0F0F_0F0F)
    );
    let big: num_bigint::BigInt = 0xABCDu32.into();
    assert_eq!(
        run_eval(&mk(
            6,
            Expr::Const {
                tpe: SigmaType::SBigInt,
                val: SigmaValue::BigInt(big.clone()),
            },
        )),
        Value::BigInt(!big),
    );
}

#[test]
fn methodcall_numeric_bitwise_or_and_xor_v6_across_types() {
    let mk = |type_id: u8, method_id: u8, lhs: Expr, rhs: Expr| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id,
                method_id,
                obj: Box::new(lhs),
                args: vec![rhs],
                type_args: vec![],
            },
        })
    };
    // (Int, Or): 0xF0 | 0x0F = 0xFF
    assert_eq!(
        run_eval(&mk(4, 9, const_int(0xF0), const_int(0x0F))),
        Value::Int(0xFF),
    );
    // (Long, And): 0xFFFF_FFFF & 0x0000_FFFF = 0xFFFF
    assert_eq!(
        run_eval(&mk(5, 10, const_long(0xFFFF_FFFF), const_long(0x0000_FFFF))),
        Value::Long(0xFFFF),
    );
    // (Byte, Xor): 0xAA ^ 0x55 = 0xFF (= -1 as i8)
    let byte = |v: i8| Expr::Const {
        tpe: SigmaType::SByte,
        val: SigmaValue::Byte(v),
    };
    assert_eq!(
        run_eval(&mk(2, 11, byte(0xAA_u8 as i8), byte(0x55))),
        Value::Byte(0xFF_u8 as i8),
    );
    // (BigInt, Xor): large value
    let big = |n: i64| Expr::Const {
        tpe: SigmaType::SBigInt,
        val: SigmaValue::BigInt(n.into()),
    };
    assert_eq!(
        run_eval(&mk(6, 11, big(0xFF), big(0x0F))),
        Value::BigInt(num_bigint::BigInt::from(0xF0)),
    );
}

#[test]
fn methodcall_numeric_shift_left_right_v6_match_java_promotion() {
    let mk = |type_id: u8, method_id: u8, lhs: Expr, n: i32| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id,
                method_id,
                obj: Box::new(lhs),
                args: vec![const_int(n)],
                type_args: vec![],
            },
        })
    };
    // (Int, shiftLeft 2): 1 << 2 = 4
    assert_eq!(run_eval(&mk(4, 12, const_int(1), 2)), Value::Int(4),);
    // (Long, shiftRight 4): 0x100 >> 4 = 0x10
    assert_eq!(
        run_eval(&mk(5, 13, const_long(0x100), 4)),
        Value::Long(0x10),
    );
    // Byte promotion for an IN-RANGE shift: (127: Byte) << 1 =
    // (254: Int).toByte = -2. (A shift count >= 8 is out of range for a
    // Byte and is rejected — see methodcall_numeric_shift_out_of_range_rejects;
    // Scala's ExactIntegral.shiftLeft throws there rather than masking.)
    let byte = |v: i8| Expr::Const {
        tpe: SigmaType::SByte,
        val: SigmaValue::Byte(v),
    };
    assert_eq!(run_eval(&mk(2, 12, byte(127), 1)), Value::Byte(-2),);
    // BigInt shift left: 1 << 200 = 2^200
    let big = |n: i64| Expr::Const {
        tpe: SigmaType::SBigInt,
        val: SigmaValue::BigInt(n.into()),
    };
    let two_pow_200 = num_bigint::BigInt::from(1) << 200u32;
    assert_eq!(
        run_eval(&mk(6, 12, big(1), 200)),
        Value::BigInt(two_pow_200),
    );
}

/// Shift count out of range must throw, per Scala ExactIntegral:
/// shiftLeft/shiftRight raise IllegalArgumentException when
/// `bits < 0 || bits >= width` (Byte 8, Short 16, Int 32, Long 64,
/// BigInt 256). Previously the fixed-width arms masked the count
/// (n & 31 / n & 63) and the BigInt arm only checked `n < 0`, so a
/// script with an out-of-range shift was accepted here but rejected by
/// the reference — a consensus divergence.
#[test]
fn methodcall_numeric_shift_out_of_range_rejects() {
    let mk = |type_id: u8, method_id: u8, obj: Expr, n: i32| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id,
                method_id,
                obj: Box::new(obj),
                args: vec![const_int(n)],
                type_args: vec![],
            },
        })
    };
    let byte = |v: i8| Expr::Const {
        tpe: SigmaType::SByte,
        val: SigmaValue::Byte(v),
    };
    let big = |n: i64| Expr::Const {
        tpe: SigmaType::SBigInt,
        val: SigmaValue::BigInt(n.into()),
    };
    // Each at the exclusive upper bound (== width) must throw, for both
    // shiftLeft (12) and shiftRight (13).
    for (label, expr) in [
        ("Byte<<8", mk(2, 12, byte(1), 8)),
        ("Short<<16", mk(3, 12, const_short(1), 16)),
        ("Int<<32", mk(4, 12, const_int(1), 32)),
        ("Long>>64", mk(5, 13, const_long(1), 64)),
        ("BigInt<<256", mk(6, 12, big(1), 256)),
    ] {
        assert!(
            matches!(run_eval_err(&expr), EvalError::RuntimeException(_)),
            "{label} (bits == width) must throw"
        );
    }
    // In-range shifts at width-1 still succeed.
    assert_eq!(run_eval(&mk(4, 12, const_int(1), 31)), Value::Int(1 << 31));
    assert_eq!(run_eval(&mk(2, 12, byte(1), 7)), Value::Byte(-128)); // 1<<7 = 0x80 -> -128
}

#[test]
fn methodcall_numeric_bigint_shift_negative_count_rejects() {
    let big = |n: i64| Expr::Const {
        tpe: SigmaType::SBigInt,
        val: SigmaValue::BigInt(n.into()),
    };
    let expr = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 6,
            method_id: 12,
            obj: Box::new(big(1)),
            args: vec![const_int(-1)],
            type_args: vec![],
        },
    });
    match run_eval_err(&expr) {
        EvalError::RuntimeException(msg) => {
            assert!(msg.contains("out of range"), "{msg}");
        }
        other => panic!("expected RuntimeException, got {other:?}"),
    }
}

/// EIP-50 v6 `SGlobal.decodeNbits` (106, 7) on well-known
/// Bitcoin-style compact-difficulty vectors. The reference values
/// are independent of Ergo source — they're standard Bitcoin
/// nbits/target pairs and have been stable since Satoshi.
#[test]
fn methodcall_global_decodenbits_v6_decodes_known_vectors() {
    let mk = |compact: i64| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id: 106,
                method_id: 7,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![const_long(compact)],
                type_args: vec![],
            },
        })
    };
    let expected_genesis: num_bigint::BigInt =
        "26959535291011309493156476344723991336010898738574164086137773096960"
            .parse()
            .unwrap();
    assert_eq!(run_eval(&mk(0x1d00_ffff)), Value::BigInt(expected_genesis));
    // Bitcoin convention: compact 0 decodes to BigInt 0 (size byte 0,
    // no mantissa bytes — `decodeMPI` reads an empty payload).
    assert_eq!(run_eval(&mk(0)), Value::BigInt(num_bigint::BigInt::from(0)));
    // size=1, mantissa byte at bit 16-23 of the compact. So compact
    // 0x01_03_00_00 means "1-byte mantissa with value 0x03".
    assert_eq!(
        run_eval(&mk(0x0103_0000)),
        Value::BigInt(num_bigint::BigInt::from(3)),
    );
}

/// EIP-50 v6 `SGlobal.encodeNbits` (106, 6): inverse of
/// `decodeNbits` on a canonical compact-bits value.
#[test]
fn methodcall_global_encodenbits_v6_inverts_decodenbits() {
    let encode_expr = |target: num_bigint::BigInt| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id: 106,
                method_id: 6,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![Expr::Const {
                    tpe: SigmaType::SBigInt,
                    val: SigmaValue::BigInt(target),
                }],
                type_args: vec![],
            },
        })
    };
    let expected_genesis: num_bigint::BigInt =
        "26959535291011309493156476344723991336010898738574164086137773096960"
            .parse()
            .unwrap();
    assert_eq!(
        run_eval(&encode_expr(expected_genesis)),
        Value::Long(0x1d00_ffff),
    );
    // Encoding zero mirrors Java's BigInteger.ZERO.toByteArray() (= [0])
    // so the size byte is 1, mantissa byte is 0 — canonical compact
    // form for "zero target" is `0x01_00_00_00`, not raw zero.
    assert_eq!(
        run_eval(&encode_expr(num_bigint::BigInt::from(0))),
        Value::Long(0x0100_0000),
    );
    // encode(3) — single mantissa byte, no sign-bit collision.
    assert_eq!(
        run_eval(&encode_expr(num_bigint::BigInt::from(3))),
        Value::Long(0x0103_0000),
    );
}

/// EIP-50 v6 `SCollection.reverse` (12, 30): preserves the typed
/// `Coll[Byte]` carrier so downstream byte-oriented consumers keep
/// working, and returns elements in reverse order.
#[test]
fn methodcall_coll_reverse_v6_preserves_byte_carrier() {
    let coll = const_bytes(vec![1, 2, 3, 4]);
    let expr = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 12,
            method_id: 30,
            obj: Box::new(coll),
            args: vec![],
            type_args: vec![],
        },
    });
    assert_eq!(run_eval(&expr), Value::CollBytes(vec![4, 3, 2, 1]));
}

/// EIP-50 v6 `SCollection.startsWith` (12, 31): prefix check.
/// Also exercises the v6-required `endsWith` (12, 32) shape with
/// a positive case. Ids per sigmastate-interpreter v6.0.2 (reverse 30,
/// startsWith 31, endsWith 32, get 33; no `distinct` exists).
#[test]
fn methodcall_coll_starts_and_ends_with_v6_match_prefix_suffix() {
    let mk = |coll: Vec<u8>, sub: Vec<u8>, mid: u8| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id: 12,
                method_id: mid,
                obj: Box::new(const_bytes(coll)),
                args: vec![const_bytes(sub)],
                type_args: vec![],
            },
        })
    };
    // startsWith: positive
    assert_eq!(
        run_eval(&mk(vec![1, 2, 3, 4], vec![1, 2], 31)),
        Value::Bool(true)
    );
    // startsWith: negative
    assert_eq!(
        run_eval(&mk(vec![1, 2, 3, 4], vec![2, 3], 31)),
        Value::Bool(false)
    );
    // endsWith: positive
    assert_eq!(
        run_eval(&mk(vec![1, 2, 3, 4], vec![3, 4], 32)),
        Value::Bool(true)
    );
    // endsWith: negative
    assert_eq!(
        run_eval(&mk(vec![1, 2, 3, 4], vec![2, 3], 32)),
        Value::Bool(false)
    );
    // Empty prefix / suffix always matches.
    assert_eq!(
        run_eval(&mk(vec![1, 2, 3, 4], vec![], 31)),
        Value::Bool(true)
    );
    assert_eq!(
        run_eval(&mk(vec![1, 2, 3, 4], vec![], 32)),
        Value::Bool(true)
    );
    // Longer prefix than collection → false (no panic).
    assert_eq!(
        run_eval(&mk(vec![1, 2], vec![1, 2, 3], 31)),
        Value::Bool(false)
    );
}

/// EIP-50 v6 `SCollection.get` (12, 33): bounds-checked indexed
/// access returning `SOption[T]`. Out-of-range index returns
/// `None`, not a runtime error (unlike `0xB2 ByIndex` without a
/// default).
#[test]
fn methodcall_coll_get_v6_returns_option_for_inbounds_and_oob() {
    let mk = |idx: i32| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id: 12,
                method_id: 33,
                obj: Box::new(const_bytes(vec![10, 20, 30])),
                args: vec![const_int(idx)],
                type_args: vec![],
            },
        })
    };
    assert_eq!(
        run_eval(&mk(0)),
        Value::Opt(Some(Box::new(Value::Byte(10))))
    );
    assert_eq!(
        run_eval(&mk(2)),
        Value::Opt(Some(Box::new(Value::Byte(30))))
    );
    assert_eq!(run_eval(&mk(3)), Value::Opt(None));
    assert_eq!(run_eval(&mk(-1)), Value::Opt(None));
}

/// `SAvlTree.contains(9, key, proof) -> Boolean` (Scala's
/// `SAvlTreeMethods.containsMethod`). Builds a real one-entry AVL+
/// tree with `BatchAVLProver`, captures its digest and the lookup
/// proof, then drives both `(100, 9) contains` and the trusted
/// `(100, 10) get` arm against the same proof. The two must agree
/// on the presence bit — pins the cross-arm parity that Scala's
/// `containsMethod = getMethod.isDefined`-style relation depends
/// on. Regression for testnet h=262,028 tx[2] input 0 which stalled
/// the evaluator on "expected supported MethodCall, got
/// type_id=100, method_id=9" before this arm existed.
#[test]
fn methodcall_avltree_contains_matches_get() {
    use bytes::Bytes;
    use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
    use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
    use ergo_avltree_rust::batch_node::{AVLTree as OracleTree, Node, NodeHeader};
    use ergo_avltree_rust::operation::{KeyValue, Operation};

    let key_present: [u8; 32] = [0x42; 32];
    let value: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];

    // Build a one-entry tree.
    let mut prover = BatchAVLProver::new(
        OracleTree::new(
            |digest| Node::LabelOnly(NodeHeader::new(Some(*digest), None)),
            32,
            None,
        ),
        true,
    );
    prover
        .perform_one_operation(&Operation::Insert(KeyValue {
            key: Bytes::from(key_present.to_vec()),
            value: Bytes::from(value.clone()),
        }))
        .expect("insert");
    // Drain the insert into a discarded proof so the verifier-side
    // starting digest matches the post-insert tree.
    let _ = prover.generate_proof().to_vec();
    let digest_vec = prover.digest().expect("digest after insert");
    let mut digest = [0u8; 33];
    digest.copy_from_slice(&digest_vec);
    // Now generate the proof for the lookup against that digest.
    prover
        .perform_one_operation(&Operation::Lookup(Bytes::from(key_present.to_vec())))
        .expect("lookup");
    let proof_bytes = prover.generate_proof().to_vec();

    let tree_data = ergo_ser::sigma_value::AvlTreeData {
        digest: digest.to_vec(),
        insert_allowed: true,
        update_allowed: true,
        remove_allowed: true,
        key_length: 32,
        value_length_opt: None,
    };
    let avl_const = Expr::Const {
        tpe: SigmaType::SAvlTree,
        val: SigmaValue::AvlTree(tree_data),
    };
    let mk = |type_id: u8, method_id: u8, k: Vec<u8>| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id,
                method_id,
                obj: Box::new(avl_const.clone()),
                args: vec![const_bytes(k), const_bytes(proof_bytes.clone())],
                type_args: vec![],
            },
        })
    };

    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);

    // `contains` returns Bool(true) and `get` returns Some(value).
    assert_eq!(
        eval_to_value(&mk(100, 9, key_present.to_vec()), &ctx, &[]).expect("contains"),
        Value::Bool(true),
    );
    assert_eq!(
        eval_to_value(&mk(100, 10, key_present.to_vec()), &ctx, &[]).expect("get"),
        Value::Opt(Some(Box::new(Value::CollBytes(value)))),
    );
}

/// AVL crate-boundary: a malformed proof makes `ergo_avltree_rust` PANIC
/// during proof-graph reconstruction. The `try_make_avl_verifier`
/// catch_unwind boundary must contain it and degrade per Scala: `contains`
/// returns `false` (contains_eval `case Failure(_) => false`), `get` errors
/// (get_eval `case Failure(_) => syntax.error`). Neither may panic or abort.
#[test]
fn methodcall_avltree_bad_proof_contains_false_get_errors() {
    // A valid-shaped 33-byte digest (last byte = tree height 7) but a
    // single-0x00 proof, which panics inside the crate's reconstruct_tree.
    let tree_data = ergo_ser::sigma_value::AvlTreeData {
        digest: [0x07; 33].to_vec(),
        insert_allowed: true,
        update_allowed: true,
        remove_allowed: true,
        key_length: 32,
        value_length_opt: None,
    };
    let avl_const = Expr::Const {
        tpe: SigmaType::SAvlTree,
        val: SigmaValue::AvlTree(tree_data),
    };
    let key = vec![0x11u8; 32];
    let bad_proof = vec![0x00u8];
    let mk = |method_id: u8| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id: 100,
                method_id,
                obj: Box::new(avl_const.clone()),
                args: vec![const_bytes(key.clone()), const_bytes(bad_proof.clone())],
                type_args: vec![],
            },
        })
    };
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);

    // contains -> false (graceful, no panic).
    assert_eq!(
        eval_to_value(&mk(9), &ctx, &[]).expect("contains must not error on a bad proof"),
        Value::Bool(false),
        "contains on a malformed proof must degrade to false",
    );
    // get -> errored (graceful, no panic).
    assert!(
        matches!(
            eval_to_value(&mk(10), &ctx, &[]),
            Err(EvalError::TypeError { .. })
        ),
        "get on a malformed proof must error (not panic)",
    );

    // getMany with EMPTY keys on a malformed proof returns an empty Coll,
    // NOT an error: Scala getMany_eval observes the failure only inside the
    // per-key `keys.map` body, so with no keys no lookup runs. (Non-empty
    // keys DO error — the first key's lookup surfaces the failure.)
    let getmany = |keys: Vec<SigmaValue>| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id: 100,
                method_id: 11,
                obj: Box::new(avl_const.clone()),
                args: vec![
                    Expr::Const {
                        tpe: SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(
                            SigmaType::SByte,
                        )))),
                        val: SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Values(keys)),
                    },
                    const_bytes(bad_proof.clone()),
                ],
                type_args: vec![],
            },
        })
    };
    match eval_to_value(&getmany(vec![]), &ctx, &[]).expect("empty getMany must not error") {
        Value::CollGeneric(items, _) => {
            assert!(
                items.is_empty(),
                "empty getMany on a bad proof -> empty Coll"
            )
        }
        other => panic!("expected empty CollGeneric, got {other:?}"),
    }
    assert!(
        matches!(
            eval_to_value(
                &getmany(vec![SigmaValue::Coll(
                    ergo_ser::sigma_value::CollValue::Bytes(key.clone())
                )]),
                &ctx,
                &[]
            ),
            Err(EvalError::TypeError { .. })
        ),
        "non-empty getMany on a malformed proof must error",
    );
}

/// `SAvlTree.isInsertAllowed(5)` / `isUpdateAllowed(6)` / `isRemoveAllowed(7)`
/// each return the matching `enabledOperations` bit as a Boolean. These are
/// zero-arg flag accessors, so they ride the `0xDB PropertyCall` wire form
/// (empty args) and resolve through `eval_no_arg_method`. Mixed flags
/// (insert=true, update=false, remove=true) prove each accessor reads its own
/// bit rather than aliasing a shared default. Scala `SAvlTreeMethods` cost
/// kind is `FixedCost(JitCost(15))`, V5+/ungated.
#[test]
fn methodcall_avltree_flag_accessors_read_own_bit() {
    let tree_data = ergo_ser::sigma_value::AvlTreeData {
        digest: [0x07; 33].to_vec(),
        insert_allowed: true,
        update_allowed: false,
        remove_allowed: true,
        key_length: 32,
        value_length_opt: None,
    };
    let avl_const = Expr::Const {
        tpe: SigmaType::SAvlTree,
        val: SigmaValue::AvlTree(tree_data),
    };
    let prop = |method_id: u8| {
        Expr::Op(IrNode {
            opcode: 0xDB,
            payload: Payload::MethodCall {
                type_id: 100,
                method_id,
                obj: Box::new(avl_const.clone()),
                args: vec![],
                type_args: vec![],
            },
        })
    };
    assert_eq!(run_eval(&prop(5)), Value::Bool(true), "isInsertAllowed");
    assert_eq!(run_eval(&prop(6)), Value::Bool(false), "isUpdateAllowed");
    assert_eq!(run_eval(&prop(7)), Value::Bool(true), "isRemoveAllowed");
}

/// 0xB7 TreeLookup is not executable in Scala
/// (costKind = notSupportedError at trees.scala:1336). User-level
/// AVL lookup uses SAvlTree.get method call, not this direct form.
#[test]
fn tree_lookup_rejects() {
    let expr = Expr::Op(IrNode {
        opcode: 0xB7,
        payload: Payload::Zero,
    });
    let err = run_eval_err(&expr);
    match err {
        EvalError::NotExecutable(code, name) => {
            assert_eq!(code, 0xB7);
            assert_eq!(name, "TreeLookup");
        }
        other => panic!("expected NotExecutable, got {other:?}"),
    }
}

// --- Global-constant opcodes (0x82, 0xA6) + Unit via Constant ---
//
// 0x81 is not registered in Scala's parser/evaluator. Unit values
// roundtrip through the constant-encoding path; the test below
// pins Unit-via-Constant — the Scala-conformant form.

#[test]
fn unit_via_constant_encoding() {
    let e = Expr::Const {
        tpe: SigmaType::SUnit,
        val: SigmaValue::Unit,
    };
    assert_eq!(run_eval(&e), Value::Unit);
}

#[test]
fn group_generator() {
    let e = op(0x82, Payload::Zero);
    assert_eq!(run_eval(&e), Value::GroupElement(SECP256K1_GENERATOR));
}

#[test]
fn last_block_utxo_root_hash_mainnet_defaults() {
    // Mainnet `ErgoInterpreter.avlTreeFromDigest` builds AvlTreeData
    // with AllOperationsAllowed flags + key_length=32 + value_length_opt=None.
    // See ergo-master/ergo-wallet/…/ErgoInterpreter.scala:103.
    let state_root: [u8; 33] = [0xAB; 33];
    let tree = ergo_ser::sigma_value::AvlTreeData {
        digest: state_root.to_vec(),
        insert_allowed: true,
        update_allowed: true,
        remove_allowed: true,
        key_length: 32,
        value_length_opt: None,
    };
    let b = make_test_box();
    let mut ctx = ctx_with_self_box(&b);
    ctx.last_block_utxo_root = Some(tree);

    let e = op(0xA6, Payload::Zero);
    let result = eval_to_value(&e, &ctx, &[]).expect("eval");
    match result {
        Value::AvlTree(avl) => {
            assert_eq!(avl.digest.as_slice(), &state_root[..]);
            assert!(avl.insert_allowed, "mainnet uses AllOperationsAllowed");
            assert!(avl.update_allowed);
            assert!(avl.remove_allowed);
            assert_eq!(avl.key_length, 32);
            assert!(avl.value_length_opt.is_none());
        }
        other => panic!("expected AvlTree, got {other:?}"),
    }
}

/// Reviewer finding: 0xA6 must return the AvlTreeData unchanged, not
/// synthesize metadata from the header digest. Non-default flags +
/// non-32 keyLength + non-None value_length_opt catch any evaluator
/// that rebuilds metadata from scratch.
#[test]
fn last_block_utxo_root_hash_preserves_non_default_metadata() {
    let state_root: [u8; 33] = [0xCD; 33];
    let tree = ergo_ser::sigma_value::AvlTreeData {
        digest: state_root.to_vec(),
        insert_allowed: true,
        update_allowed: false, // NOT AllOperationsAllowed
        remove_allowed: true,
        key_length: 64, // NOT 32
        value_length_opt: Some(128),
    };
    let b = make_test_box();
    let mut ctx = ctx_with_self_box(&b);
    ctx.last_block_utxo_root = Some(tree);

    let e = op(0xA6, Payload::Zero);
    let result = eval_to_value(&e, &ctx, &[]).expect("eval");
    match result {
        Value::AvlTree(avl) => {
            assert_eq!(avl.digest.as_slice(), &state_root[..]);
            assert!(avl.insert_allowed);
            assert!(!avl.update_allowed, "preserved non-default update flag");
            assert!(avl.remove_allowed);
            assert_eq!(avl.key_length, 64, "preserved non-32 keyLength");
            assert_eq!(
                avl.value_length_opt,
                Some(128),
                "preserved value_length_opt"
            );
        }
        other => panic!("expected AvlTree, got {other:?}"),
    }
}

#[test]
fn last_block_utxo_root_hash_empty_headers_errors() {
    // With no headers (synthetic test context), 0xA6 must signal
    // EmptyHeaderWindow rather than panic. In production,
    // apply_genesis skips script execution so this path is
    // unreachable for real blocks.
    let e = op(0xA6, Payload::Zero);
    let err = run_eval_err(&e);
    assert!(
        matches!(err, EvalError::EmptyHeaderWindow),
        "0xA6 with empty headers must error, got {err:?}"
    );
}

/// End-to-end parse→eval roundtrip for the global-constant opcodes.
#[test]
fn global_const_opcodes_parse_eval_roundtrip() {
    // After the Scala-parity sweep, only 0x82 GroupGenerator remains
    // in this set. 0x81 UnitConstant has no parser arm — Unit values
    // flow through constant encoding, covered by
    // unit_via_constant_encoding above.
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::opcode::{parse_expr, write_body};

    let ir = op(0x82, Payload::Zero);
    let mut w = VlqWriter::new();
    write_body(&mut w, &ir, false).expect("serialize");
    let bytes = w.result();
    let mut r = VlqReader::new(&bytes);
    let parsed = parse_expr(&mut r, 0, 0).expect("parse");
    assert_eq!(run_eval(&parsed), Value::GroupElement(SECP256K1_GENERATOR));
}

// --- BinXor (0xF4) + Xor (0x9B) ---

/// BinXor positive cases + type mismatch. Scala trees.scala:1284-1302.
#[test]
fn bin_xor_booleans() {
    // true ^ false = true
    let e = op(
        0xF4,
        Payload::Two(Box::new(const_bool(true)), Box::new(const_bool(false))),
    );
    assert_eq!(run_eval(&e), Value::Bool(true));

    // false ^ false = false
    let e = op(
        0xF4,
        Payload::Two(Box::new(const_bool(false)), Box::new(const_bool(false))),
    );
    assert_eq!(run_eval(&e), Value::Bool(false));

    // true ^ true = false
    let e = op(
        0xF4,
        Payload::Two(Box::new(const_bool(true)), Box::new(const_bool(true))),
    );
    assert_eq!(run_eval(&e), Value::Bool(false));
}

#[test]
fn bin_xor_type_mismatch_rejects() {
    // BinXor(Int, Int) is not valid — Scala opType is (Boolean, Boolean) → Boolean.
    let e = op(
        0xF4,
        Payload::Two(Box::new(const_int(1)), Box::new(const_int(2))),
    );
    let err = run_eval_err(&e);
    assert!(
        matches!(err, EvalError::TypeError { .. }),
        "BinXor on Int must reject, got {err:?}"
    );
}

/// Xor (byte-array) — element-wise, truncates to shorter operand
/// per Scala CollsOverArrays.scala:261 (`left.zip(right).map(…)`).
#[test]
fn xor_byte_array_same_length() {
    let a = const_bytes(vec![0xFF, 0x00, 0xAA, 0x55]);
    let b = const_bytes(vec![0x0F, 0xF0, 0x55, 0xAA]);
    let e = op(0x9B, Payload::Two(Box::new(a), Box::new(b)));
    assert_eq!(run_eval(&e), Value::CollBytes(vec![0xF0, 0xF0, 0xFF, 0xFF]));
}

#[test]
fn xor_byte_array_empty() {
    let a = const_bytes(vec![]);
    let b = const_bytes(vec![]);
    let e = op(0x9B, Payload::Two(Box::new(a), Box::new(b)));
    assert_eq!(run_eval(&e), Value::CollBytes(vec![]));
}

#[test]
fn xor_byte_array_truncates_to_shorter() {
    // Scala's Colls.xor uses zip(), which truncates at min(len).
    // This is NOT a rejection — it is Scala-conformant behavior.
    let a = const_bytes(vec![0xFF, 0x00, 0xAA, 0x55]);
    let b = const_bytes(vec![0x0F, 0xF0]); // shorter
    let e = op(0x9B, Payload::Two(Box::new(a), Box::new(b)));
    assert_eq!(run_eval(&e), Value::CollBytes(vec![0xF0, 0xF0]));
}

#[test]
fn xor_byte_array_type_mismatch_rejects() {
    // Xor expects (Coll[Byte], Coll[Byte]). Passing (Int, Int) must reject.
    let e = op(
        0x9B,
        Payload::Two(Box::new(const_int(1)), Box::new(const_int(2))),
    );
    let err = run_eval_err(&e);
    assert!(
        matches!(err, EvalError::TypeError { .. }),
        "Xor on Int must reject, got {err:?}"
    );
}

/// End-to-end parse→eval roundtrip for 0xF4 and 0x9B. Serializes IR
/// to VLQ bytes, parses back, evaluates. Confirms dispatch fires from
/// real wire bytes, not just helper-constructed IR nodes.
#[test]
fn xor_parse_eval_roundtrip() {
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::opcode::{parse_expr, write_body};

    // 0xF4 BinXor(true, false) → true
    let ir = op(
        0xF4,
        Payload::Two(Box::new(const_bool(true)), Box::new(const_bool(false))),
    );
    let mut w = VlqWriter::new();
    write_body(&mut w, &ir, false).expect("serialize BinXor");
    let bytes = w.result();
    let mut r = VlqReader::new(&bytes);
    let parsed = parse_expr(&mut r, 0, 0).expect("parse BinXor");
    assert_eq!(run_eval(&parsed), Value::Bool(true));

    // 0x9B Xor(Coll[FF,00], Coll[0F,F0]) → Coll[F0,F0]
    let ir = op(
        0x9B,
        Payload::Two(
            Box::new(const_bytes(vec![0xFF, 0x00])),
            Box::new(const_bytes(vec![0x0F, 0xF0])),
        ),
    );
    let mut w = VlqWriter::new();
    write_body(&mut w, &ir, false).expect("serialize Xor");
    let bytes = w.result();
    let mut r = VlqReader::new(&bytes);
    let parsed = parse_expr(&mut r, 0, 0).expect("parse Xor");
    assert_eq!(run_eval(&parsed), Value::CollBytes(vec![0xF0, 0xF0]));
}

// --- BitOp family reject-only ---

/// Per-opcode regression: each of the six BitOps must reject with
/// EvalError::NotExecutable. Covers dispatch via the `op()` helper
/// which builds the same IrNode the parser produces for arity-Two ops.
/// See `bitop_parse_eval_roundtrip` for real parse coverage.
#[test]
fn bitop_family_rejects_at_dispatch() {
    for &(code, name) in &[
        (0xF2u8, "BitOr"),
        (0xF3u8, "BitAnd"),
        (0xF5u8, "BitXor"),
        (0xF6u8, "BitShiftRight"),
        (0xF7u8, "BitShiftLeft"),
        (0xF8u8, "BitShiftRightZeroed"),
    ] {
        let expr = op(
            code,
            Payload::Two(Box::new(const_int(1)), Box::new(const_int(2))),
        );
        let err = run_eval_err(&expr);
        match err {
            EvalError::NotExecutable(c, n) => {
                assert_eq!(c, code, "{name}: wrong opcode in NotExecutable");
                assert_eq!(n, name, "{name}: wrong name in NotExecutable");
            }
            other => {
                panic!("{name} (0x{code:02X}) must reject with NotExecutable, got {other:?}")
            }
        }
    }
}

/// End-to-end parse→eval roundtrip for a BitOp. Serializes a BitOr
/// IR node to bytes, parses them back, and asserts the parsed tree
/// rejects at eval. This covers the full dispatch path from wire
/// bytes to the reject arm — not just helper-level construction.
#[test]
fn bitop_parse_eval_roundtrip() {
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::opcode::{parse_expr, write_body};

    // Build 0xF2 BitOr(1, 2) as IR, serialize, parse back.
    let ir = op(
        0xF2,
        Payload::Two(Box::new(const_int(1)), Box::new(const_int(2))),
    );
    let mut w = VlqWriter::new();
    write_body(&mut w, &ir, false).expect("serialize BitOr");
    let bytes = w.result();

    let mut r = VlqReader::new(&bytes);
    let parsed = parse_expr(&mut r, 0, 0).expect("parse back");

    let err = run_eval_err(&parsed);
    assert!(
        matches!(err, EvalError::NotExecutable(0xF2, "BitOr")),
        "parsed BitOr must reject with NotExecutable(0xF2, \"BitOr\"), got {err:?}"
    );
}

// TrivialProp(true) always passes regardless of proof
#[test]
fn accept_trivial_true_any_proof() {
    use crate::verify::verify_sigma_proof;
    let result = verify_sigma_proof(&SigmaBoolean::TrivialProp(true), &[], b"message").unwrap();
    assert!(result, "TrivialProp(true) should accept any proof");
}

// --- Byte/Short typed-carrier + ExactIntegral round-trip tests ---

/// Positive Byte flow round-trip.
/// Reads Byte from SHeader.version → puts into Coll[Byte] via
/// ConcreteCollection → indexes back out → non-overflowing arithmetic
/// → EQ against a Byte literal. Every intermediate must be Value::Byte.
#[test]
fn byte_flow_positive() {
    // Downcast(Byte) → checked arithmetic with no overflow
    // ((127.toByte) - 1.toByte) + 1.toByte == 127.toByte
    let one_byte = op(
        0x7D,
        Payload::NumericCast {
            input: Box::new(const_int(1)),
            tpe: SigmaType::SByte,
        },
    );
    let max_byte = op(
        0x7D,
        Payload::NumericCast {
            input: Box::new(const_int(127)),
            tpe: SigmaType::SByte,
        },
    );
    let sub = op(
        0x99,
        Payload::Two(Box::new(max_byte.clone()), Box::new(one_byte.clone())),
    );
    let add = op(
        0x9A,
        Payload::Two(Box::new(sub), Box::new(one_byte.clone())),
    );
    let eq = op(0x93, Payload::Two(Box::new(add), Box::new(max_byte)));
    assert_eq!(run_eval(&eq), Value::Bool(true));

    // Byte typed carrier preserved through a Coll[Byte] round-trip:
    // Coll[Byte](10, 20, 30)(1) == 20.toByte
    let coll = const_bytes(vec![10, 20, 30]);
    let idx_1 = op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(coll),
            index: Box::new(const_int(1)),
            default: None,
        },
    );
    let twenty = op(
        0x7D,
        Payload::NumericCast {
            input: Box::new(const_int(20)),
            tpe: SigmaType::SByte,
        },
    );
    let eq_idx = op(0x93, Payload::Two(Box::new(idx_1), Box::new(twenty)));
    assert_eq!(run_eval(&eq_idx), Value::Bool(true));
}

/// Regression guard for the inference table at infer_op_type.
/// Covers the three Byte-producing method/property sites that
/// empty-map type preservation relies on. Pins (type_id, method_id)
/// → SigmaType — if Scala renumbers a method or we wire the wrong
/// id, this fails immediately.
#[test]
fn infer_op_type_byte_producing_methods() {
    let bindings = std::collections::HashMap::new();
    let constants: Vec<(SigmaType, SigmaValue)> = Vec::new();

    // Helper to build a method-call node with empty obj/args —
    // inference is payload-driven and does not evaluate.
    let mc = |type_id: u8, method_id: u8| IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id,
            method_id,
            obj: Box::new(op(0xFE, Payload::Zero)),
            args: vec![],
            type_args: vec![],
        },
    };

    // SHeader.version (104, 2) → Byte. Cross-check: evaluator
    // dispatch at evaluator.rs:1363 returns Value::Byte for the
    // same (type_id, method_id).
    assert_eq!(
        infer_op_type(&mc(104, 2), &bindings, &constants),
        Some(SigmaType::SByte),
        "SHeader.version type inference"
    );

    // SPreHeader.version (105, 1) → Byte. Note: method id is 1,
    // NOT 2 (method 2 is parentId — Coll[Byte]). Cross-check:
    // evaluator.rs:1397 returns Value::Byte for (105, 1).
    assert_eq!(
        infer_op_type(&mc(105, 1), &bindings, &constants),
        Some(SigmaType::SByte),
        "SPreHeader.version type inference — must be method 1, not 2"
    );

    // Negative: SPreHeader.parentId is (105, 2) and returns
    // Coll[Byte], not SByte. If we accidentally wire (105, 2)
    // → SByte again, this assertion fires.
    assert_ne!(
        infer_op_type(&mc(105, 2), &bindings, &constants),
        Some(SigmaType::SByte),
        "SPreHeader(105, 2) is parentId (Coll[Byte]), not version"
    );

    // SAvlTree.enabledOperations (100, 2) → Byte. Cross-check:
    // evaluator.rs:2277 returns Value::Byte.
    assert_eq!(
        infer_op_type(&mc(100, 2), &bindings, &constants),
        Some(SigmaType::SByte),
        "SAvlTree.enabledOperations type inference"
    );
}

/// End-to-end test of the empty-map inference path. An empty
/// Coll[Int] mapped through a body whose inferred return type is
/// Byte must yield Value::CollBytes(vec![]) — not Value::Tuple(vec![]).
/// Without the inference table fix, the old fallthrough would
/// produce Tuple and silently strip the Byte kind.
#[test]
fn empty_map_over_byte_producing_body_infers_coll_byte() {
    // Input: empty Coll[Int] (cheap to build; contents don't matter
    // because items is empty and the body is never evaluated).
    let empty_coll = const_coll_int(vec![]);

    // Mapper body: ignore the Int argument, produce a Byte via a
    // known-to-inference method call. Using SAvlTree.enabledOperations
    // (100, 2) because it's table-resolvable without needing a real
    // header. The obj is a dummy Context — never evaluated.
    let body = op(
        0xDC,
        Payload::MethodCall {
            type_id: 100,
            method_id: 2,
            obj: Box::new(op(0xFE, Payload::Zero)),
            args: vec![],
            type_args: vec![],
        },
    );

    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(body),
        },
    );
    let expr = op(0xAD, Payload::Two(Box::new(empty_coll), Box::new(func)));

    assert_eq!(
        run_eval(&expr),
        Value::CollBytes(vec![]),
        "empty map with Byte-inferred body must produce empty Coll[Byte], not Tuple"
    );
}

/// Regression guard: the AVL Boolean flag accessors must resolve in the
/// `infer_op_type` table so an empty `map` whose body is one of them infers
/// `Coll[Boolean]` instead of falling back to `CollGeneric(SAny)`. Pins
/// (100, 5/6/7) → SBoolean.
#[test]
fn infer_op_type_avltree_flag_accessors() {
    let bindings = std::collections::HashMap::new();
    let constants: Vec<(SigmaType, SigmaValue)> = Vec::new();
    let mc = |method_id: u8| IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 100,
            method_id,
            obj: Box::new(op(0xFE, Payload::Zero)),
            args: vec![],
            type_args: vec![],
        },
    };
    for mid in [5u8, 6, 7] {
        assert_eq!(
            infer_op_type(&mc(mid), &bindings, &constants),
            Some(SigmaType::SBoolean),
            "SAvlTree flag accessor (100, {mid}) must infer SBoolean"
        );
    }
}

/// End-to-end empty-map inference: an empty `Coll[Int]` mapped through a body
/// of `tree.isInsertAllowed` (100, 5) must yield `Value::CollBool(vec![])`.
/// Without the (100, 5..=7) inference entries the body's type is unknown for
/// an empty input (the body is never evaluated), so the result would degrade
/// to `CollGeneric(SAny)` and diverge from Scala's `Coll[Boolean]()`.
#[test]
fn empty_map_over_bool_producing_body_infers_coll_bool() {
    let empty_coll = const_coll_int(vec![]);
    let body = op(
        0xDB,
        Payload::MethodCall {
            type_id: 100,
            method_id: 5,
            obj: Box::new(op(0xFE, Payload::Zero)),
            args: vec![],
            type_args: vec![],
        },
    );
    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(body),
        },
    );
    let expr = op(0xAD, Payload::Two(Box::new(empty_coll), Box::new(func)));

    assert_eq!(
        run_eval(&expr),
        Value::CollBool(vec![]),
        "empty map with Bool-inferred body must produce empty Coll[Boolean]"
    );
}

/// Byte/Short Plus/Minus overflow rejection.
/// Both cases must return EvalError::RuntimeException — Scala
/// ByteIsExactIntegral / ShortIsExactIntegral override plus/minus/times
/// with addExact/subtractExact/multiplyExact, which throw on overflow.
/// (Division/Modulo/Negation are NOT exact — they wrap; see
/// `byte_short_div_mod_negation_wrap_parity`.)
#[test]
fn byte_short_overflow_rejects() {
    // Byte.MaxValue + 1.toByte
    let max_b = op(
        0x7D,
        Payload::NumericCast {
            input: Box::new(const_int(127)),
            tpe: SigmaType::SByte,
        },
    );
    let one_b = op(
        0x7D,
        Payload::NumericCast {
            input: Box::new(const_int(1)),
            tpe: SigmaType::SByte,
        },
    );
    let overflow_add = op(0x9A, Payload::Two(Box::new(max_b), Box::new(one_b)));
    let err = run_eval_err(&overflow_add);
    assert!(
        matches!(err, EvalError::RuntimeException(_)),
        "Byte.+ overflow must be RuntimeException, got {err:?}"
    );

    // Short.MinValue - 1.toShort
    let min_s = op(
        0x7D,
        Payload::NumericCast {
            input: Box::new(const_int(-32768)),
            tpe: SigmaType::SShort,
        },
    );
    let one_s = op(
        0x7D,
        Payload::NumericCast {
            input: Box::new(const_int(1)),
            tpe: SigmaType::SShort,
        },
    );
    let overflow_sub = op(0x99, Payload::Two(Box::new(min_s), Box::new(one_s)));
    let err = run_eval_err(&overflow_sub);
    assert!(
        matches!(err, EvalError::RuntimeException(_)),
        "Short.- overflow must be RuntimeException, got {err:?}"
    );
    // Note: Byte/Short Division/Modulo of MIN by -1 and unary Negation of
    // MIN do NOT throw — they wrap (Scala routes them through the default
    // ExactIntegral.quot/divisionRemainder = n.quot/n.rem and ExactNumeric
    // .negate = n.negate, all plain two's-complement). Asserted in
    // `byte_short_div_mod_negation_wrap_parity`, not here.
}

/// Int/Long Plus/Minus/Multiply must THROW on 2's-complement overflow
/// (Scala IntIsExactIntegral/LongIsExactIntegral route +/-/* through
/// java7.compat.Math.addExact/subtractExact/multiplyExact, which raise
/// ArithmeticException). Previously these arms used `wrapping_*` and
/// silently succeeded — a consensus divergence: scripts that overflow
/// were accepted here but rejected by the reference. Division/Modulo of
/// MinValue by -1 must instead WRAP (Java `/`/`%` semantics: Scala does
/// not throw there), where Rust's native `/`/`%` would panic.
#[test]
fn int_long_arith_overflow_parity() {
    // +/-/* overflow -> RuntimeException
    let int_add = op(
        0x9A,
        Payload::Two(Box::new(const_int(i32::MAX)), Box::new(const_int(1))),
    );
    assert!(
        matches!(run_eval_err(&int_add), EvalError::RuntimeException(_)),
        "Int.+ overflow must throw"
    );
    let long_add = op(
        0x9A,
        Payload::Two(Box::new(const_long(i64::MAX)), Box::new(const_long(1))),
    );
    assert!(
        matches!(run_eval_err(&long_add), EvalError::RuntimeException(_)),
        "Long.+ overflow must throw"
    );
    let int_sub = op(
        0x99,
        Payload::Two(Box::new(const_int(i32::MIN)), Box::new(const_int(1))),
    );
    assert!(
        matches!(run_eval_err(&int_sub), EvalError::RuntimeException(_)),
        "Int.- overflow must throw"
    );
    let long_mul = op(
        0x9C,
        Payload::Two(Box::new(const_long(i64::MIN)), Box::new(const_long(-1))),
    );
    assert!(
        matches!(run_eval_err(&long_mul), EvalError::RuntimeException(_)),
        "Long.* overflow must throw"
    );

    // Division/Modulo of MinValue by -1 wraps (no panic, no throw).
    let int_div = op(
        0x9D,
        Payload::Two(Box::new(const_int(i32::MIN)), Box::new(const_int(-1))),
    );
    assert_eq!(
        run_eval(&int_div),
        Value::Int(i32::MIN),
        "Int MIN / -1 wraps"
    );
    let long_mod = op(
        0x9E,
        Payload::Two(Box::new(const_long(i64::MIN)), Box::new(const_long(-1))),
    );
    assert_eq!(run_eval(&long_mod), Value::Long(0), "Long MIN % -1 == 0");

    // In-range arithmetic is unaffected.
    let ok = op(
        0x9A,
        Payload::Two(Box::new(const_int(2)), Box::new(const_int(3))),
    );
    assert_eq!(run_eval(&ok), Value::Int(5));
}

/// Byte/Short Division/Modulo of MIN by -1, and unary Negation of MIN,
/// must WRAP (no throw) — matching Scala's default ExactIntegral
/// quot/divisionRemainder (= scala.math.Numeric.{Byte,Short}IsIntegral,
/// which promote to Int, divide, and `.toByte`/`.toShort` back) and
/// ExactNumeric.negate (= n.negate). e.g. (-128:Byte)/(-1) = -128,
/// (-128:Byte)%(-1) = 0, -(-128:Byte) = -128. The current Rust used
/// checked_div/checked_rem/checked_neg, which threw — a consensus
/// divergence invisible to the SANTA harness (error-variant only).
#[test]
fn byte_short_div_mod_negation_wrap_parity() {
    let to_byte = |v: i32| {
        op(
            0x7D,
            Payload::NumericCast {
                input: Box::new(const_int(v)),
                tpe: SigmaType::SByte,
            },
        )
    };
    let to_short = |v: i32| {
        op(
            0x7D,
            Payload::NumericCast {
                input: Box::new(const_int(v)),
                tpe: SigmaType::SShort,
            },
        )
    };

    // Byte MIN / -1 wraps to MIN; MIN % -1 == 0.
    let bdiv = op(
        0x9D,
        Payload::Two(Box::new(to_byte(-128)), Box::new(to_byte(-1))),
    );
    assert_eq!(run_eval(&bdiv), Value::Byte(-128), "(-128:Byte)/(-1) wraps");
    let bmod = op(
        0x9E,
        Payload::Two(Box::new(to_byte(-128)), Box::new(to_byte(-1))),
    );
    assert_eq!(run_eval(&bmod), Value::Byte(0), "(-128:Byte)%(-1) == 0");

    // Short MIN / -1 wraps to MIN; MIN % -1 == 0.
    let sdiv = op(
        0x9D,
        Payload::Two(Box::new(to_short(-32768)), Box::new(to_short(-1))),
    );
    assert_eq!(
        run_eval(&sdiv),
        Value::Short(-32768),
        "(-32768:Short)/(-1) wraps"
    );
    let smod = op(
        0x9E,
        Payload::Two(Box::new(to_short(-32768)), Box::new(to_short(-1))),
    );
    assert_eq!(run_eval(&smod), Value::Short(0), "(-32768:Short)%(-1) == 0");

    // Unary negation of MIN wraps to MIN.
    let bneg = op(0xF0, Payload::One(Box::new(to_byte(-128))));
    assert_eq!(
        run_eval(&bneg),
        Value::Byte(-128),
        "-(-128:Byte) wraps to -128"
    );
    let sneg = op(0xF0, Payload::One(Box::new(to_short(-32768))));
    assert_eq!(
        run_eval(&sneg),
        Value::Short(-32768),
        "-(-32768:Short) wraps to -32768"
    );

    // Divide-by-zero still throws (distinct from MIN/-1 wrap).
    let bdz = op(
        0x9D,
        Payload::Two(Box::new(to_byte(5)), Box::new(to_byte(0))),
    );
    assert!(
        matches!(run_eval_err(&bdz), EvalError::RuntimeException(_)),
        "Byte / 0 still throws"
    );
}

/// BigInt Plus/Minus/Multiply enforce the signed-256-bit bound
/// UNCONDITIONALLY (Scala CBigInt.add/subtract/multiply wrap the result in
/// `.toSignedBigIntValueExact`, which throws "BigInteger out of 256 bit
/// range" when bitLength()>255). The valid signed range is exactly
/// [-2^255, 2^255-1]: -2^255 fits (bitLength 255), 2^255 and -2^255-1 do
/// not. divide/mod/min/max have NO such check.
#[test]
fn bigint_arith_256bit_bound() {
    let big = |n: num_bigint::BigInt| Expr::Const {
        tpe: SigmaType::SBigInt,
        val: SigmaValue::BigInt(n),
    };
    let one = num_bigint::BigInt::from(1);
    let two_pow_255 = &one << 255u32;
    let max = &two_pow_255 - &one; // 2^255 - 1
    let min = -&two_pow_255; // -2^255
    let two_pow_254 = &one << 254u32;

    // In-range arithmetic is unaffected.
    let ok = op(
        0x9A,
        Payload::Two(Box::new(big(100.into())), Box::new(big(200.into()))),
    );
    assert_eq!(run_eval(&ok), Value::BigInt(300.into()));

    // Boundary values are accepted (bitLength == 255).
    let max_ok = op(
        0x9A,
        Payload::Two(Box::new(big(max.clone())), Box::new(big(0.into()))),
    );
    assert_eq!(
        run_eval(&max_ok),
        Value::BigInt(max.clone()),
        "2^255-1 fits"
    );
    let min_ok = op(
        0x99,
        Payload::Two(Box::new(big(min.clone())), Box::new(big(0.into()))),
    );
    assert_eq!(run_eval(&min_ok), Value::BigInt(min.clone()), "-2^255 fits");

    // Plus overflow: (2^255-1) + 1 == 2^255 -> reject.
    let add_of = op(
        0x9A,
        Payload::Two(Box::new(big(max.clone())), Box::new(big(one.clone()))),
    );
    assert!(
        matches!(run_eval_err(&add_of), EvalError::RuntimeException(_)),
        "(2^255-1)+1 overflows 256-bit"
    );
    // Minus underflow: (-2^255) - 1 == -2^255-1 -> reject.
    let sub_uf = op(
        0x99,
        Payload::Two(Box::new(big(min.clone())), Box::new(big(one.clone()))),
    );
    assert!(
        matches!(run_eval_err(&sub_uf), EvalError::RuntimeException(_)),
        "(-2^255)-1 underflows 256-bit"
    );
    // Multiply overflow: 2^254 * 2 == 2^255 -> reject.
    let mul_of = op(
        0x9C,
        Payload::Two(Box::new(big(two_pow_254)), Box::new(big(2.into()))),
    );
    assert!(
        matches!(run_eval_err(&mul_of), EvalError::RuntimeException(_)),
        "2^254*2 overflows 256-bit"
    );
}

/// BigInt unary Negation enforces the same 256-bit bound (CBigInt.negate
/// = wrappedValue.negate().toSignedBigIntValueExact). -(-2^255) == 2^255
/// is out of range and must throw; -(2^255-1) is in range.
#[test]
fn bigint_negate_256bit_bound() {
    let big = |n: num_bigint::BigInt| Expr::Const {
        tpe: SigmaType::SBigInt,
        val: SigmaValue::BigInt(n),
    };
    let one = num_bigint::BigInt::from(1);
    let two_pow_255 = &one << 255u32;
    let max = &two_pow_255 - &one;
    let min = -&two_pow_255;

    let neg_min = op(0xF0, Payload::One(Box::new(big(min))));
    assert!(
        matches!(run_eval_err(&neg_min), EvalError::RuntimeException(_)),
        "-(-2^255) == 2^255 overflows 256-bit"
    );
    let neg_max = op(0xF0, Payload::One(Box::new(big(max.clone()))));
    assert_eq!(
        run_eval(&neg_max),
        Value::BigInt(-max),
        "-(2^255-1) is in range"
    );
}

/// BigInt Modulo follows java.math.BigInteger.mod: a non-positive modulus
/// (b <= 0) throws ("BigInteger: modulus not positive"); for b > 0 the
/// result is the NON-NEGATIVE remainder in [0, b) regardless of the sign
/// of the dividend (floored mod, NOT sign-of-dividend remainder).
#[test]
fn bigint_modulo_nonpositive_modulus_rejects() {
    let big = |n: i64| Expr::Const {
        tpe: SigmaType::SBigInt,
        val: SigmaValue::BigInt(n.into()),
    };

    // Non-positive modulus throws.
    let neg_mod = op(0x9E, Payload::Two(Box::new(big(7)), Box::new(big(-3))));
    assert!(
        matches!(run_eval_err(&neg_mod), EvalError::RuntimeException(_)),
        "7 % -3 (non-positive modulus) must throw"
    );
    // Zero modulus throws too (modulus not positive).
    let zero_mod = op(0x9E, Payload::Two(Box::new(big(7)), Box::new(big(0))));
    assert!(
        matches!(run_eval_err(&zero_mod), EvalError::RuntimeException(_)),
        "7 % 0 must throw"
    );
    // Valid positive modulus: non-negative result even for negative dividend.
    let neg_dividend = op(0x9E, Payload::Two(Box::new(big(-7)), Box::new(big(3))));
    assert_eq!(
        run_eval(&neg_dividend),
        Value::BigInt(2.into()),
        "-7 mod 3 == 2 (non-negative)"
    );
    let pos = op(0x9E, Payload::Two(Box::new(big(7)), Box::new(big(3))));
    assert_eq!(run_eval(&pos), Value::BigInt(1.into()), "7 mod 3 == 1");
}

/// byteArrayToBigInt (0x7B) rejects an empty input (Scala
/// `new BigInteger(new byte[0])` throws NumberFormatException) and a value
/// exceeding the signed 256-bit range (toSignedBigIntValueExact). The
/// decode is SIGNED big-endian; boundary 32-byte values -2^255 and 2^255-1
/// are accepted.
#[test]
fn bytearraytobigint_empty_and_oversize_reject() {
    // Empty input -> reject.
    let empty = op(0x7B, Payload::One(Box::new(const_bytes(vec![]))));
    assert!(
        matches!(run_eval_err(&empty), EvalError::RuntimeException(_)),
        "empty byteArrayToBigInt must throw"
    );

    // 33-byte value 2^256 (0x01 ++ 32 zero bytes) -> out of 256-bit range.
    let mut oversize = vec![0x01u8];
    oversize.extend(std::iter::repeat_n(0u8, 32));
    let over = op(0x7B, Payload::One(Box::new(const_bytes(oversize))));
    assert!(
        matches!(run_eval_err(&over), EvalError::RuntimeException(_)),
        "33-byte 2^256 must throw (out of 256-bit range)"
    );

    // Boundary 32-byte values are accepted.
    let one = num_bigint::BigInt::from(1);
    let min = -(&one << 255u32); // -2^255
    let max = (&one << 255u32) - &one; // 2^255-1
    let mut min_bytes = vec![0x80u8];
    min_bytes.extend(std::iter::repeat_n(0u8, 31));
    let min_expr = op(0x7B, Payload::One(Box::new(const_bytes(min_bytes))));
    assert_eq!(
        run_eval(&min_expr),
        Value::BigInt(min),
        "0x80 ++ 0*31 == -2^255"
    );
    let mut max_bytes = vec![0x7fu8];
    max_bytes.extend(std::iter::repeat_n(0xffu8, 31));
    let max_expr = op(0x7B, Payload::One(Box::new(const_bytes(max_bytes))));
    assert_eq!(
        run_eval(&max_expr),
        Value::BigInt(max),
        "0x7f ++ 0xff*31 == 2^255-1"
    );

    // Small valid value still works.
    let small = op(0x7B, Payload::One(Box::new(const_bytes(vec![0, 1]))));
    assert_eq!(run_eval(&small), Value::BigInt(1.into()), "[0,1] == 1");
}

// ----- oracle parity -----
//
// Tests below pin behavior between two evaluator entry points
// (e.g. PropertyCall vs MethodCall) — equivalent inputs must
// produce equivalent values and identical accumulated cost.

// PropertyCall (0xDB) and MethodCall (0xDC) for the same no-arg
// logical access route through opcodes::property_call::eval_no_arg_method.
// Pins that both entry points produce identical Value AND identical
// total cost. If anything diverges, a no-arg method may have drifted
// in only one of the two paths.
#[test]
fn property_call_and_method_call_parity_for_no_arg_methods() {
    let h = EvalHeader {
        id: [0xAA; 32],
        version: 2,
        parent_id: [0xBB; 32],
        ad_proofs_root: [0xCC; 32],
        state_root: [0xDD; 33],
        transactions_root: [0xEE; 32],
        timestamp: 1_700_000_000_000,
        n_bits: 0x01234567,
        height: 600_000,
        extension_root: [0x11; 32],
        miner_pk: [0x02; 33],
        pow_onetime_pk: [0x03; 33],
        pow_nonce: [0xFF; 8],
        pow_distance: num_bigint::BigInt::from(42),
        votes: [1, 2, 3],
        unparsed_bytes: Vec::new(),
    };
    let b = make_test_box();
    let headers = vec![h];
    let mut ctx = ctx_with_self_box(&b);
    ctx.last_headers = &headers;

    let context_expr = || op(0xFE, Payload::Zero);
    let self_expr = || op(0xA7, Payload::Zero);
    let groupgen_via_pc = move || {
        op(
            0xDB,
            Payload::MethodCall {
                type_id: 106,
                method_id: 1,
                obj: Box::new(context_expr()),
                args: vec![],
                type_args: vec![],
            },
        )
    };

    // (type_id, method_id, obj-builder) — broad sample covering
    // SContext, SHeader (via headers indexing), SPreHeader, SGlobal,
    // SBox, SColl, SGroupElement.
    type ObjBuilder = Box<dyn Fn() -> Expr>;
    let cases: Vec<(u8, u8, ObjBuilder)> = vec![
        // SContext.headers
        (101, 2, Box::new(context_expr)),
        // SContext.minerPubKey
        (101, 10, Box::new(context_expr)),
        // SPreHeader.version
        (105, 1, Box::new(context_expr)),
        // SPreHeader.height
        (105, 5, Box::new(context_expr)),
        // SGlobal.groupGenerator (obj is anything; SGlobal ignores it)
        (106, 1, Box::new(context_expr)),
        // SBox.tokens — PropertyCall-only inline previously; now both
        (99, 8, Box::new(self_expr)),
        // SGroupElement.getEncoded on the secp256k1 generator
        (7, 2, Box::new(groupgen_via_pc)),
        // SGroupElement.negate on the secp256k1 generator
        (7, 5, Box::new(groupgen_via_pc)),
        // SColl.indices on SContext.headers (length = 1)
        (
            12,
            14,
            Box::new(|| {
                op(
                    0xDB,
                    Payload::MethodCall {
                        type_id: 101,
                        method_id: 2,
                        obj: Box::new(op(0xFE, Payload::Zero)),
                        args: vec![],
                        type_args: vec![],
                    },
                )
            }),
        ),
    ];

    let mut env = Env::new();
    let mut depth = 0usize;
    let mut trace = None;

    for (type_id, method_id, build_obj) in &cases {
        let pc_expr = op(
            0xDB,
            Payload::MethodCall {
                type_id: *type_id,
                method_id: *method_id,
                obj: Box::new(build_obj()),
                args: vec![],
                type_args: vec![],
            },
        );
        let mc_expr = op(
            0xDC,
            Payload::MethodCall {
                type_id: *type_id,
                method_id: *method_id,
                obj: Box::new(build_obj()),
                args: vec![],
                type_args: vec![],
            },
        );

        let mut pc_cost = CostAccumulator::recording_only();
        let pc_val = eval_expr(
            &pc_expr,
            &ctx,
            &[],
            &mut env,
            &mut depth,
            &mut pc_cost,
            &mut trace,
        )
        .unwrap_or_else(|e| panic!("PropertyCall ({type_id},{method_id}) failed: {e:?}"));

        let mut mc_cost = CostAccumulator::recording_only();
        let mc_val = eval_expr(
            &mc_expr,
            &ctx,
            &[],
            &mut env,
            &mut depth,
            &mut mc_cost,
            &mut trace,
        )
        .unwrap_or_else(|e| panic!("MethodCall ({type_id},{method_id}) failed: {e:?}"));

        assert_eq!(
            pc_val, mc_val,
            "value drift on ({type_id},{method_id}): PC={pc_val:?} MC={mc_val:?}"
        );
        assert_eq!(
            pc_cost.total().value(),
            mc_cost.total().value(),
            "cost drift on ({type_id},{method_id}): PC={} MC={}",
            pc_cost.total().value(),
            mc_cost.total().value(),
        );
    }
}

// Type-mismatch parity: SHeader.height (104, 9) on a non-Header object
// must produce TypeError on both PropertyCall and MethodCall paths,
// with the same expected/got fields from the shared no-arg dispatch.
#[test]
fn property_call_and_method_call_type_error_parity() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);

    // SELF is an EvalBox — not a Header — so SHeader.height must reject.
    let pc = op(
        0xDB,
        Payload::MethodCall {
            type_id: 104,
            method_id: 9,
            obj: Box::new(op(0xA7, Payload::Zero)),
            args: vec![],
            type_args: vec![],
        },
    );
    let mc = op(
        0xDC,
        Payload::MethodCall {
            type_id: 104,
            method_id: 9,
            obj: Box::new(op(0xA7, Payload::Zero)),
            args: vec![],
            type_args: vec![],
        },
    );

    let pc_err = run_eval_ctx_err(&pc, &ctx);
    let mc_err = run_eval_ctx_err(&mc, &ctx);

    match (&pc_err, &mc_err) {
        (
            EvalError::TypeError {
                expected: e1,
                got: g1,
            },
            EvalError::TypeError {
                expected: e2,
                got: g2,
            },
        ) => {
            assert_eq!(e1, e2, "expected-field drift: PC={e1} MC={e2}");
            assert_eq!(g1, g2, "got-field drift: PC={g1} MC={g2}");
        }
        other => panic!("expected TypeError on both, got {other:?}"),
    }
}

fn run_eval_ctx_err(expr: &Expr, ctx: &ReductionContext<'_>) -> EvalError {
    eval_to_value(expr, ctx, &[]).expect_err("expected error")
}

// Closure-isolation invariants.
//
// Every higher-order arm (FuncApply, ForAll, Filter, Fold, Map,
// Exists, Option.map, Option.filter, flatMap) calls the closure
// body via the free `eval_expr(...)` with `&mut call_env` rather
// than the bundled `cx.env`. These tests pin that contract: a
// shadowed id in caller scope must NOT bleed into the closure
// body's binding lookup, and writes inside the body must NOT
// leak back into the caller's env.
//
// Construction shape: caller establishes `val 1 = SENTINEL`, then
// invokes the higher-order arm with a closure whose param id is
// also `1`. Inside the body, `ValUse(1)` must resolve to the
// per-iteration arg/param, not the caller's SENTINEL. If the
// refactor mistakenly re-routed the body recursion through
// `cx.env`, the assertion would catch it.
//
// SENTINEL is chosen far from any per-element value used so the
// failure mode is unambiguous in the assertion message.

/// FuncApply (0xDA) — body resolves `ValUse(1)` to the apply arg,
/// not to the caller's `val 1 = 999`.
#[test]
fn func_apply_body_resolves_param_not_caller_env() {
    let body = op(
        0x9A,
        Payload::Two(
            Box::new(op(0x72, Payload::ValUse { id: 1 })),
            Box::new(const_int(1)),
        ),
    );
    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(body),
        },
    );
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![op(
                0xD6,
                Payload::ValDef {
                    id: 1,
                    tpe: Some(SigmaType::SInt),
                    rhs: Box::new(const_int(999)),
                },
            )],
            result: Box::new(op(
                0xDA,
                Payload::FuncApply {
                    func: Box::new(func),
                    args: vec![const_int(10)],
                },
            )),
        },
    );
    assert_eq!(
        run_eval(&block),
        Value::Int(11),
        "body must see param=10, not caller's 999"
    );
}

/// FuncApply (0xDA) — args evaluate in the caller's env, so an arg
/// expression that reads `ValUse(2)` sees the caller's binding even
/// though the closure's param shadows id 1.
#[test]
fn func_apply_args_resolve_in_caller_env() {
    // Caller: { val 1 = 7; val 2 = 100; (λp1:Int. p1 * 2)(ValUse(2)) }
    // Arg sees caller's id 2 = 100. Body sees param 1 = 100.
    // Result: 100 * 2 = 200.
    let body = op(
        0x9C,
        Payload::Two(
            Box::new(op(0x72, Payload::ValUse { id: 1 })),
            Box::new(const_int(2)),
        ),
    );
    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(body),
        },
    );
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![
                op(
                    0xD6,
                    Payload::ValDef {
                        id: 1,
                        tpe: Some(SigmaType::SInt),
                        rhs: Box::new(const_int(7)),
                    },
                ),
                op(
                    0xD6,
                    Payload::ValDef {
                        id: 2,
                        tpe: Some(SigmaType::SInt),
                        rhs: Box::new(const_int(100)),
                    },
                ),
            ],
            result: Box::new(op(
                0xDA,
                Payload::FuncApply {
                    func: Box::new(func),
                    args: vec![op(0x72, Payload::ValUse { id: 2 })],
                },
            )),
        },
    );
    assert_eq!(
        run_eval(&block),
        Value::Int(200),
        "arg must read caller's id 2 = 100"
    );
}

/// MapCollection (0xAD) — element binding does not bleed into the
/// caller's env. After the map runs with closure param id=1, an
/// outer `ValUse(1)` still sees the caller's `val 1 = 999`.
#[test]
fn map_element_binding_does_not_leak_into_caller_env() {
    // { val 1 = 999; (Coll(1,2,3).map(λp1. p1 + 100), val 1 = 999) → ValUse(1) }
    // Build as (mapped, ValUse(1)) tuple, then SelectField(2) to get caller id 1.
    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x9A,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    Box::new(const_int(100)),
                ),
            )),
        },
    );
    let mapped = op(
        0xAD,
        Payload::Two(Box::new(const_coll_int(vec![1, 2, 3])), Box::new(func)),
    );
    let tuple = op(
        0x86,
        Payload::Tuple {
            items: vec![mapped, op(0x72, Payload::ValUse { id: 1 })],
        },
    );
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![op(
                0xD6,
                Payload::ValDef {
                    id: 1,
                    tpe: Some(SigmaType::SInt),
                    rhs: Box::new(const_int(999)),
                },
            )],
            result: Box::new(op(
                0x8C,
                Payload::SelectField {
                    input: Box::new(tuple),
                    field_idx: 2,
                },
            )),
        },
    );
    assert_eq!(
        run_eval(&block),
        Value::Int(999),
        "caller's id 1 must survive across the map's closure invocations"
    );
}

/// ForAll (0xAF) — predicate's element binding does not leak.
#[test]
fn forall_element_binding_does_not_leak_into_caller_env() {
    let pred = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x91,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    Box::new(const_int(0)),
                ),
            )),
        },
    );
    let forall = op(
        0xAF,
        Payload::Two(Box::new(const_coll_int(vec![1, 2, 3])), Box::new(pred)),
    );
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![op(
                0xD6,
                Payload::ValDef {
                    id: 1,
                    tpe: Some(SigmaType::SInt),
                    rhs: Box::new(const_int(999)),
                },
            )],
            // (forall_result, caller_id_1) tuple, take field 2 to assert id 1 unchanged.
            result: Box::new(op(
                0x8C,
                Payload::SelectField {
                    input: Box::new(op(
                        0x86,
                        Payload::Tuple {
                            items: vec![forall, op(0x72, Payload::ValUse { id: 1 })],
                        },
                    )),
                    field_idx: 2,
                },
            )),
        },
    );
    assert_eq!(run_eval(&block), Value::Int(999));
}

/// Filter (0xB5) — predicate's element binding does not leak.
#[test]
fn filter_element_binding_does_not_leak_into_caller_env() {
    let pred = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x91,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    Box::new(const_int(2)),
                ),
            )),
        },
    );
    let filtered = op(
        0xB5,
        Payload::Two(Box::new(const_coll_int(vec![1, 2, 3, 4])), Box::new(pred)),
    );
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![op(
                0xD6,
                Payload::ValDef {
                    id: 1,
                    tpe: Some(SigmaType::SInt),
                    rhs: Box::new(const_int(999)),
                },
            )],
            result: Box::new(op(
                0x8C,
                Payload::SelectField {
                    input: Box::new(op(
                        0x86,
                        Payload::Tuple {
                            items: vec![filtered, op(0x72, Payload::ValUse { id: 1 })],
                        },
                    )),
                    field_idx: 2,
                },
            )),
        },
    );
    assert_eq!(run_eval(&block), Value::Int(999));
}

/// Exists (0xAE) — predicate's element binding does not leak.
#[test]
fn exists_element_binding_does_not_leak_into_caller_env() {
    let pred = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x93,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    Box::new(const_int(2)),
                ),
            )),
        },
    );
    let exists = op(
        0xAE,
        Payload::Two(Box::new(const_coll_int(vec![1, 2, 3])), Box::new(pred)),
    );
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![op(
                0xD6,
                Payload::ValDef {
                    id: 1,
                    tpe: Some(SigmaType::SInt),
                    rhs: Box::new(const_int(999)),
                },
            )],
            result: Box::new(op(
                0x8C,
                Payload::SelectField {
                    input: Box::new(op(
                        0x86,
                        Payload::Tuple {
                            items: vec![exists, op(0x72, Payload::ValUse { id: 1 })],
                        },
                    )),
                    field_idx: 2,
                },
            )),
        },
    );
    assert_eq!(run_eval(&block), Value::Int(999));
}

fn const_some_int(v: i32) -> Expr {
    Expr::Const {
        tpe: SigmaType::SOption(Box::new(SigmaType::SInt)),
        val: SigmaValue::Opt(Some(Box::new(SigmaValue::Int(v)))),
    }
}

/// Option.map (MethodCall type=36 method=7) — body's element binding
/// does not leak into the caller's env.
#[test]
fn option_map_body_does_not_leak_into_caller_env() {
    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x9A,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    Box::new(const_int(100)),
                ),
            )),
        },
    );
    let mapped = op(
        0xDC,
        Payload::MethodCall {
            type_id: 36,
            method_id: 7,
            obj: Box::new(const_some_int(42)),
            args: vec![func],
            type_args: vec![],
        },
    );
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![op(
                0xD6,
                Payload::ValDef {
                    id: 1,
                    tpe: Some(SigmaType::SInt),
                    rhs: Box::new(const_int(999)),
                },
            )],
            result: Box::new(op(
                0x8C,
                Payload::SelectField {
                    input: Box::new(op(
                        0x86,
                        Payload::Tuple {
                            items: vec![mapped, op(0x72, Payload::ValUse { id: 1 })],
                        },
                    )),
                    field_idx: 2,
                },
            )),
        },
    );
    assert_eq!(run_eval(&block), Value::Int(999));
}

/// Option.filter (MethodCall type=36 method=8) — predicate's element
/// binding does not leak into the caller's env.
#[test]
fn option_filter_body_does_not_leak_into_caller_env() {
    let pred = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x91,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    Box::new(const_int(0)),
                ),
            )),
        },
    );
    let filtered = op(
        0xDC,
        Payload::MethodCall {
            type_id: 36,
            method_id: 8,
            obj: Box::new(const_some_int(7)),
            args: vec![pred],
            type_args: vec![],
        },
    );
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![op(
                0xD6,
                Payload::ValDef {
                    id: 1,
                    tpe: Some(SigmaType::SInt),
                    rhs: Box::new(const_int(999)),
                },
            )],
            result: Box::new(op(
                0x8C,
                Payload::SelectField {
                    input: Box::new(op(
                        0x86,
                        Payload::Tuple {
                            items: vec![filtered, op(0x72, Payload::ValUse { id: 1 })],
                        },
                    )),
                    field_idx: 2,
                },
            )),
        },
    );
    assert_eq!(run_eval(&block), Value::Int(999));
}

/// flatMap (MethodCall type=12 method=15) — element binding does not
/// leak into the caller's env. Closure maps each Int to a Coll[Int]
/// of length 1, so result is the input flattened identically.
#[test]
fn flatmap_element_binding_does_not_leak_into_caller_env() {
    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x83,
                Payload::ConcreteCollection {
                    elem_type: SigmaType::SInt,
                    items: vec![op(0x72, Payload::ValUse { id: 1 })],
                },
            )),
        },
    );
    let flat = op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 15,
            obj: Box::new(const_coll_int(vec![1, 2, 3])),
            args: vec![func],
            type_args: vec![],
        },
    );
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![op(
                0xD6,
                Payload::ValDef {
                    id: 1,
                    tpe: Some(SigmaType::SInt),
                    rhs: Box::new(const_int(999)),
                },
            )],
            result: Box::new(op(
                0x8C,
                Payload::SelectField {
                    input: Box::new(op(
                        0x86,
                        Payload::Tuple {
                            items: vec![flat, op(0x72, Payload::ValUse { id: 1 })],
                        },
                    )),
                    field_idx: 2,
                },
            )),
        },
    );
    assert_eq!(run_eval(&block), Value::Int(999));
}

/// Fold (0xB0) — accumulator+element tuple binding (id=1) does not
/// leak into the caller's env.
#[test]
fn fold_acc_binding_does_not_leak_into_caller_env() {
    // Fold sums the collection: zero=0, op = (acc, x) -> acc + x.
    // Closure param id 1 holds the (acc, x) tuple.
    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(
                1,
                Some(SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SInt])),
            )],
            body: Box::new(op(
                0x9A,
                Payload::Two(
                    Box::new(op(
                        0x8C,
                        Payload::SelectField {
                            input: Box::new(op(0x72, Payload::ValUse { id: 1 })),
                            field_idx: 1,
                        },
                    )),
                    Box::new(op(
                        0x8C,
                        Payload::SelectField {
                            input: Box::new(op(0x72, Payload::ValUse { id: 1 })),
                            field_idx: 2,
                        },
                    )),
                ),
            )),
        },
    );
    let fold = op(
        0xB0,
        Payload::Three(
            Box::new(const_coll_int(vec![1, 2, 3, 4])),
            Box::new(const_int(0)),
            Box::new(func),
        ),
    );
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![op(
                0xD6,
                Payload::ValDef {
                    id: 1,
                    tpe: Some(SigmaType::SInt),
                    rhs: Box::new(const_int(999)),
                },
            )],
            result: Box::new(op(
                0x8C,
                Payload::SelectField {
                    input: Box::new(op(
                        0x86,
                        Payload::Tuple {
                            items: vec![fold, op(0x72, Payload::ValUse { id: 1 })],
                        },
                    )),
                    field_idx: 2,
                },
            )),
        },
    );
    assert_eq!(run_eval(&block), Value::Int(999));
}

// ----- EIP-50 soft-fork activation gate -----

/// Scala parity: every method in `_v6Methods` is gated on
/// `activatedScriptVersion >= 3`. `MethodCall.evaluate` rejects with
/// an `InterpreterException` when a pre-EIP-50 block tries to
/// dispatch a v6 method. Our gate lives in `eval_method_call` (the
/// `is_v6_method` table -> `require_method_version(3)`); this test
/// covers it directly by invoking a representative v6 method against
/// an explicit `activated_script_version = 2` context and asserting
/// the typed `SoftForkNotActivated` rejection.
///
/// `SGlobal.deserializeTo` (106, 4) is the choice here because it
/// is the most consequential v6 surface: a runtime `Coll[Byte]` ->
/// typed-value carrier that the script can synthesize via
/// `DeserializeContext` / `DeserializeRegister`. If the gate ever
/// regresses, a pre-EIP-50 block could resurrect arbitrary v6
/// values from data — exactly the soft-fork hazard the gate exists
/// to prevent.
#[test]
fn methodcall_v6_method_rejects_when_softfork_not_activated() {
    let bytes = const_bytes(vec![0x01]);
    let expr = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 4,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![bytes],
            type_args: vec![SigmaType::SBoolean],
        },
    });

    let mut pre_eip50 = ReductionContext::minimal(0, 0);
    pre_eip50.activated_script_version = 2;
    match eval_to_value(&expr, &pre_eip50, &[]) {
        Err(EvalError::SoftForkNotActivated {
            type_id,
            method_id,
            required,
            got,
        }) => {
            assert_eq!(type_id, 106);
            assert_eq!(method_id, 4);
            assert_eq!(required, 3);
            assert_eq!(got, 2);
        }
        other => {
            panic!("expected SoftForkNotActivated for SGlobal.deserializeTo at v=2; got {other:?}")
        }
    }

    let mut pre_jit = ReductionContext::minimal(0, 0);
    pre_jit.activated_script_version = 1;
    assert!(matches!(
        eval_to_value(&expr, &pre_jit, &[]),
        Err(EvalError::SoftForkNotActivated { got: 1, .. })
    ));

    // EIP-50 active (v=3 via `minimal()` default). Full dispatch
    // correctness is pinned by
    // `methodcall_global_deserializeto_v6_evaluates_serialized_true`.
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

/// Companion: the gate must NOT reject V5+ methods (anything outside
/// `_v6Methods`). `SGlobal.xor` (106, 2) predates EIP-50 and must
/// remain callable at `activated_script_version = 2`. If a future
/// edit accidentally adds `(106, 2)` to the `is_v6_method` table,
/// the test flips red and prevents the gate from over-rejecting
/// historical scripts.
#[test]
fn methodcall_v5_global_xor_still_dispatches_at_pre_eip50() {
    let expr = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 2,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![const_bytes(vec![0xFF, 0x0F]), const_bytes(vec![0xAA, 0x33])],
            type_args: vec![],
        },
    });
    let mut pre_eip50 = ReductionContext::minimal(0, 0);
    pre_eip50.activated_script_version = 2;
    assert_eq!(
        eval_to_value(&expr, &pre_eip50, &[]).unwrap(),
        Value::CollBytes(vec![0xFF ^ 0xAA, 0x0F ^ 0x33]),
    );
}

/// Scala-source-backed rejection oracle for the full EIP-50 v6
/// method registry. Each `(type_id, method_id)` here is declared in
/// Scala's `_v6Methods` collection for the corresponding type and
/// therefore requires `activatedScriptVersion >= 3` to dispatch.
/// Source-of-truth references:
///
/// * `SNumericTypeMethods._v6Methods` — bitwise ops (8..=11) and
///   shifts (12..=13) on Byte (2) / Short (3) / Int (4) / Long (5)
///   / BigInt (6). `sigma/ast/methods.scala` ~L470–L530.
/// * `SBigIntMethods._v6Methods` — toUnsigned (14), toUnsignedMod
///   (15). `methods.scala` L545–L553.
/// * `SUnsignedBigIntMethods` (entire type, id=9) — inherited numeric
///   bitwise/shift 8..=13 + its own modular arithmetic 14..=19.
///   `methods.scala` L574–L609 + SNumericTypeMethods.v6Methods.
/// * `SCollectionMethods._v6Methods` — reverse(30), startsWith(31),
///   endsWith(32), get(33). `methods.scala` v6.0.2 (no distinct).
/// * `SBoxMethods._v6Methods` — getReg(19); the v5 getReg (id 7) is
///   V5+ and ungated. `methods.scala`.
/// * `SAvlTreeMethods._v6Methods`: insertOrUpdate(16). `methods.scala`.
/// * `SContextMethods._v6Methods` — getVarFromInput(12) only; getVar
///   (id 11) is V5+/commonMethods, not v6-gated.
/// * `SHeaderMethods._v6Methods` — checkPow(16).
/// * `SGlobalMethods._v6Methods` — serialize(3), deserializeTo(4),
///   fromBigEndianBytes(5), encodeNbits(6), decodeNbits(7),
///   powHit(8), some(9), none(10).
///   `methods.scala`. (Global.xor(2) predates EIP-50 — V5+.)
/// * `SGroupElementMethods._v6Methods` — exp(6) with `UnsignedBigInt`
///   exponent (regular exp(5) is v5).
///
/// The test drives every entry through `eval_method_call` at v=2
/// and asserts each one returns the typed `SoftForkNotActivated`
/// variant with matching ids. The argument shapes are intentionally
/// trivial — the gate fires before argument evaluation, so even
/// degenerate args reach it. A future regression that opens any
/// single entry would flip this test red.
#[test]
fn methodcall_v6_full_registry_rejects_at_pre_eip50() {
    // Full enumeration of every (type_id, method_id) for which
    // `is_v6_method` returns `true`. The ranges below MUST match the
    // match arms in `method_call.rs::is_v6_method` exactly — if a
    // future change adds a v6 method to that table without adding
    // the entry here, this test is silently weaker; if a change
    // removes a v6 entry but leaves it here, the test fails loudly
    // on the next run. Total: 61 entries (30 + 2 + 1 + 12 + 4 + 1 + 1 +
    // 1 + 1 + 8) across ten v6 method blocks.
    let mut v6_registry: Vec<(u8, u8)> = Vec::new();
    // SNumericType bitwise (8..=11) + shifts (12..=13) on
    // Byte/Short/Int/Long/BigInt (type ids 2..=6).
    for tid in 2u8..=6 {
        for mid in 8u8..=13 {
            v6_registry.push((tid, mid));
        }
    }
    // SBigInt → unsigned conversions.
    v6_registry.extend([(6u8, 14u8), (6, 15)]);
    // SGroupElement.exp[UnsignedBigInt].
    v6_registry.push((7, 6));
    // SUnsignedBigInt: inherited numeric bitwise/shift (8..=13) + its
    // own modular arithmetic (14..=19).
    for mid in 8u8..=19 {
        v6_registry.push((9, mid));
    }
    // SCollection reverse/startsWith/endsWith/get (no distinct in v6.0.2).
    for mid in 30u8..=33 {
        v6_registry.push((12, mid));
    }
    // SBox.getReg (v6 slot is id 19; v5 getReg id 7 is V5+, not gated).
    v6_registry.push((99, 19));
    // SAvlTree.insertOrUpdate (v6-only addition; pre-v6 AVL methods stay
    // ungated). Reconciled here so the enumeration matches is_v6_method.
    v6_registry.push((100, 16));
    // SContext.getVar / getVarFromInput.
    // Only getVarFromInput(12) is v6-gated; getVar(11) is V5+/commonMethods.
    v6_registry.push((101, 12));
    // SHeader.checkPow.
    v6_registry.push((104, 16));
    // SGlobal v6 methods 3..=10: serialize(3), deserializeTo(4),
    // fromBigEndianBytes(5), encodeNbits(6), decodeNbits(7), powHit(8),
    // some(9), none(10). (xor(2) is V5+ and not gated.)
    for mid in 3u8..=10 {
        v6_registry.push((106, mid));
    }
    assert_eq!(
        v6_registry.len(),
        61,
        "enumeration must cover all 61 v6 methods in the Scala v6.0.2 _v6Methods registry"
    );

    let mut pre_eip50 = ReductionContext::minimal(0, 0);
    pre_eip50.activated_script_version = 2;

    for (tid, mid) in v6_registry {
        // Trivial dispatch shell: SGlobal receiver, no args, no type_args.
        // The activation gate fires at evaluator entry — before arity
        // checking, before obj evaluation, before argument decoding —
        // so a malformed payload doesn't change the rejection.
        let expr = Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id: tid,
                method_id: mid,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![],
                type_args: vec![],
            },
        });
        match eval_to_value(&expr, &pre_eip50, &[]) {
            Err(EvalError::SoftForkNotActivated {
                type_id,
                method_id,
                required,
                got,
            }) => {
                assert_eq!(type_id, tid, "type_id drift on ({tid}, {mid})");
                assert_eq!(method_id, mid, "method_id drift on ({tid}, {mid})");
                assert_eq!(required, 3, "required-version drift on ({tid}, {mid})");
                assert_eq!(got, 2, "got-version drift on ({tid}, {mid})");
            }
            other => panic!(
                "v6 method ({tid}, {mid}) must reject with SoftForkNotActivated \
                 at activatedScriptVersion=2; got {other:?}"
            ),
        }
    }
}

/// EIP-50 v6 `SGlobal.some[T]` (MethodCall 106, 9) wraps its value into
/// a non-empty Option at activatedScriptVersion >= 3. The explicit `[T]`
/// is ignored at runtime since `Value::Opt` is type-erased.
#[test]
fn methodcall_global_some_wraps_value_at_v6() {
    let mut cx = ReductionContext::minimal(0, 0);
    cx.activated_script_version = 3;
    let expr = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 9,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![Expr::Const {
                tpe: SigmaType::SInt,
                val: SigmaValue::Int(42),
            }],
            type_args: vec![SigmaType::SInt],
        },
    });
    assert_eq!(
        eval_to_value(&expr, &cx, &[]).unwrap(),
        Value::Opt(Some(Box::new(Value::Int(42)))),
    );
}

/// EIP-50 v6 `SGlobal.none[T]` (PropertyCall 106, 10) yields an empty
/// Option at activatedScriptVersion >= 3.
#[test]
fn methodcall_global_none_yields_empty_option_at_v6() {
    let mut cx = ReductionContext::minimal(0, 0);
    cx.activated_script_version = 3;
    let expr = Expr::Op(IrNode {
        opcode: 0xDB,
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 10,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![],
            type_args: vec![SigmaType::SInt],
        },
    });
    assert_eq!(eval_to_value(&expr, &cx, &[]).unwrap(), Value::Opt(None));
}

/// The `SGlobal.none` PropertyCall (0xDB) must be soft-fork-rejected at
/// activatedScriptVersion=2. The registry sweep exercises the gate via
/// the 0xDC MethodCall entry; this pins the PropertyCall entry
/// (`eval_property_call`) gate, the path a real zero-arg none takes.
#[test]
fn propertycall_global_none_gated_at_pre_eip50() {
    let mut pre_eip50 = ReductionContext::minimal(0, 0);
    pre_eip50.activated_script_version = 2;
    let expr = Expr::Op(IrNode {
        opcode: 0xDB,
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 10,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![],
            type_args: vec![SigmaType::SInt],
        },
    });
    assert!(
        matches!(
            eval_to_value(&expr, &pre_eip50, &[]),
            Err(EvalError::SoftForkNotActivated {
                type_id: 106,
                method_id: 10,
                ..
            })
        ),
        "v6 none via 0xDB PropertyCall must reject with SoftForkNotActivated at v2",
    );
}

/// Cost pin for the two SGlobal v6 Option constructors, anchored to
/// v6.0.2 `FixedCost(JitCost(5))` for both `someMethod` and
/// `noneMethod`. Instead of pinning an absolute total (which folds in
/// framework overhead), each method's fixed cost is pinned RELATIVE to
/// an established sibling on the identical dispatch path, so the entry +
/// obj + arg overhead cancels and only the method's FixedCost remains:
///   none(106,10) vs groupGenerator(106,1): both 0xDB + same obj, no
///     args, so delta = 10 - 5 = 5.
///   some(106,9) vs encodeNbits(106,6): both 0xDC + same obj + same
///     BigInt arg, so delta = 25 - 5 = 20.
#[test]
fn methodcall_global_some_none_fixed_cost_matches_v6_0_2() {
    let mut cx = ReductionContext::minimal(0, 0);
    cx.activated_script_version = 3;
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut trace = None;

    let cost_of = |expr: &Expr, env: &mut Env, depth: &mut usize, trace: &mut _| {
        let mut acc = CostAccumulator::recording_only();
        eval_expr(expr, &cx, &[], env, depth, &mut acc, trace).unwrap();
        acc.total().value()
    };

    let global = || op(0xDD, Payload::Zero);
    let big = || Expr::Const {
        tpe: SigmaType::SBigInt,
        val: SigmaValue::BigInt(7u64.into()),
    };

    // none(106,10) vs groupGenerator(106,1): 0xDB, no args.
    let none_pc = op(
        0xDB,
        Payload::MethodCall {
            type_id: 106,
            method_id: 10,
            obj: Box::new(global()),
            args: vec![],
            type_args: vec![SigmaType::SInt],
        },
    );
    let group_gen = op(
        0xDB,
        Payload::MethodCall {
            type_id: 106,
            method_id: 1,
            obj: Box::new(global()),
            args: vec![],
            type_args: vec![],
        },
    );
    let none_cost = cost_of(&none_pc, &mut env, &mut depth, &mut trace);
    let group_cost = cost_of(&group_gen, &mut env, &mut depth, &mut trace);
    assert_eq!(
        group_cost - none_cost,
        5,
        "none FixedCost must be 5 (groupGenerator 10 - none via identical 0xDB path)",
    );

    // some(106,9) vs encodeNbits(106,6): 0xDC, one BigInt arg.
    let some_mc = op(
        0xDC,
        Payload::MethodCall {
            type_id: 106,
            method_id: 9,
            obj: Box::new(global()),
            args: vec![big()],
            type_args: vec![SigmaType::SBigInt],
        },
    );
    let encode_nbits = op(
        0xDC,
        Payload::MethodCall {
            type_id: 106,
            method_id: 6,
            obj: Box::new(global()),
            args: vec![big()],
            type_args: vec![],
        },
    );
    let some_cost = cost_of(&some_mc, &mut env, &mut depth, &mut trace);
    let encode_cost = cost_of(&encode_nbits, &mut env, &mut depth, &mut trace);
    assert_eq!(
        encode_cost - some_cost,
        20,
        "some FixedCost must be 5 (encodeNbits 25 - some via identical 0xDC+BigInt path)",
    );
}

/// EIP-50 v6 `SGlobal.powHit` (MethodCall 106, 8) known-answer test
/// against the sigmastate-interpreter v6.0.2 KAT (`BasicOpsTests.scala`
/// "powHit evaluation"): `powHit(32, msg, nonce, h, 1048576)` evaluated
/// at activatedScriptVersion >= 3 must equal the literal hit asserted
/// there. Exercises the full eval arm end to end (arg extraction, cost,
/// delegation to `ergo_crypto::autolykos::v2::hit_for_v2_pow`). The hit
/// is `SUnsignedBigInt`, so the value is `Value::UnsignedBigInt`.
#[test]
fn methodcall_global_powhit_matches_sigmastate_v6_0_2_kat() {
    let mut cx = ReductionContext::minimal(0, 0);
    cx.activated_script_version = 3;
    let expr = op(
        0xDC,
        Payload::MethodCall {
            type_id: 106,
            method_id: 8,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![
                const_int(32),
                const_bytes(vec![0x0a, 0x10, 0x1b, 0x8c, 0x6a, 0x4f, 0x2e]),
                const_bytes(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c]),
                const_bytes(vec![0x00, 0x00, 0x00, 0x00]),
                const_int(1_048_576),
            ],
            type_args: vec![],
        },
    );
    let expected: num_bigint::BigInt =
        "326674862673836209462483453386286740270338859283019276168539876024851191344"
            .parse()
            .unwrap();
    assert_eq!(
        eval_to_value(&expr, &cx, &[]).unwrap(),
        Value::UnsignedBigInt(expected),
    );
}

/// `SGlobal.powHit` enforces Scala's `hitForVersion2ForMessageWithChecks`
/// bounds: k in [2, 32] and N >= 16. Out-of-range parameters must reject
/// (RuntimeException, matching Scala's `require`), not compute a hit.
#[test]
fn methodcall_global_powhit_rejects_out_of_range_params() {
    let mut cx = ReductionContext::minimal(0, 0);
    cx.activated_script_version = 3;
    let call = |k: i32, n: i32| {
        op(
            0xDC,
            Payload::MethodCall {
                type_id: 106,
                method_id: 8,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![
                    const_int(k),
                    const_bytes(vec![0x01, 0x02]),
                    const_bytes(vec![0x03]),
                    const_bytes(vec![0x04]),
                    const_int(n),
                ],
                type_args: vec![],
            },
        )
    };
    for (k, n, why) in [
        (1, 1_048_576, "k<2"),
        (33, 1_048_576, "k>32"),
        (32, 15, "N<16"),
    ] {
        assert!(
            matches!(
                eval_to_value(&call(k, n), &cx, &[]),
                Err(EvalError::RuntimeException(_))
            ),
            "powHit must reject {why}",
        );
    }
}

/// Cost pin for `SGlobal.powHit`'s `PowHitCostKind`:
///   500 + (k + 1) * ((|msg| + |nonce| + |h|) / 128 + 1) * 7.
/// The base (500) and per-input overhead cancel in a same-inputs
/// k-delta, leaving (k2 - k1) * chunks * 7. Two chunk levels are pinned:
/// total < 128 (1 chunk: (32-2)*1*7 = 210) and total in [128, 256)
/// (2 chunks: (32-2)*2*7 = 420). Together these pin the per-index and
/// per-chunk coefficients independent of MethodCall/obj/arg-eval cost.
#[test]
fn methodcall_global_powhit_cost_matches_v6_0_2_powhitcostkind() {
    let mut cx = ReductionContext::minimal(0, 0);
    cx.activated_script_version = 3;
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut trace = None;
    let cost_of = |expr: &Expr, env: &mut Env, depth: &mut usize, trace: &mut _| {
        let mut acc = CostAccumulator::recording_only();
        eval_expr(expr, &cx, &[], env, depth, &mut acc, trace).unwrap();
        acc.total().value()
    };
    let powhit = |k: i32, h: Vec<u8>| {
        op(
            0xDC,
            Payload::MethodCall {
                type_id: 106,
                method_id: 8,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![
                    const_int(k),
                    const_bytes(vec![0x01, 0x02, 0x03]),
                    const_bytes(vec![0x04, 0x05]),
                    const_bytes(h),
                    const_int(1_048_576),
                ],
                type_args: vec![],
            },
        )
    };
    // 1 chunk: total = 3 + 2 + 4 = 9 < 128.
    let small_h = vec![0u8; 4];
    let d1 = cost_of(
        &powhit(32, small_h.clone()),
        &mut env,
        &mut depth,
        &mut trace,
    ) - cost_of(&powhit(2, small_h), &mut env, &mut depth, &mut trace);
    assert_eq!(
        d1, 210,
        "powHit k-delta at 1 chunk must be (32-2)*1*7 = 210"
    );
    // 2 chunks: total = 3 + 2 + 200 = 205 in [128, 256).
    let big_h = vec![0u8; 200];
    let d2 = cost_of(&powhit(32, big_h.clone()), &mut env, &mut depth, &mut trace)
        - cost_of(&powhit(2, big_h), &mut env, &mut depth, &mut trace);
    assert_eq!(
        d2, 420,
        "powHit k-delta at 2 chunks must be (32-2)*2*7 = 420"
    );
}

/// EIP-50 v6 SUnsignedBigInt bitwise/shift methods (9, 8..=13),
/// inherited from SNumericTypeMethods, evaluated at script version 3+.
/// Known-answer values are SOURCE-DERIVED from the verbatim v6.0.2
/// `CUnsignedBigInt`/`UnsignedBigIntIsExactIntegral` algorithms: the
/// critical invariant is that bitwiseInverse is the MASKED 256-bit
/// complement `(2^256-1) XOR n` (a fixed 32-byte flip), NOT the signed
/// two's-complement `!n` that SBigInt uses. (Source-derived, not yet
/// Scala-node-extracted; pins masked-vs-signed + logical shifts.)
#[test]
fn methodcall_unsigned_bigint_bitwise_shift_v6() {
    use num_bigint::BigInt;
    let mut cx = ReductionContext::minimal(0, 0);
    cx.activated_script_version = 3;
    let ubig = |n: BigInt| Expr::Const {
        tpe: SigmaType::SUnsignedBigInt,
        val: SigmaValue::BigInt(n),
    };
    let call0 = |recv: BigInt, mid: u8| {
        op(
            0xDC,
            Payload::MethodCall {
                type_id: 9,
                method_id: mid,
                obj: Box::new(ubig(recv)),
                args: vec![],
                type_args: vec![],
            },
        )
    };
    let call1 = |recv: BigInt, mid: u8, arg: Expr| {
        op(
            0xDC,
            Payload::MethodCall {
                type_id: 9,
                method_id: mid,
                obj: Box::new(ubig(recv)),
                args: vec![arg],
                type_args: vec![],
            },
        )
    };
    let ev = |e: &Expr| eval_to_value(e, &cx, &[]).unwrap();
    let max256: BigInt = (BigInt::from(1) << 256) - BigInt::from(1);

    // bitwiseInverse(8): masked complement (2^256-1) XOR n, NOT signed !n.
    assert_eq!(
        ev(&call0(BigInt::from(0), 8)),
        Value::UnsignedBigInt(max256.clone())
    );
    assert_eq!(
        ev(&call0(BigInt::from(1), 8)),
        Value::UnsignedBigInt(&max256 - BigInt::from(1))
    );
    assert_eq!(
        ev(&call0(BigInt::from(0xFF), 8)),
        Value::UnsignedBigInt(&max256 - BigInt::from(0xFF))
    );
    // bitwiseOr(9)/And(10)/Xor(11): plain, stays in [0, 2^256).
    assert_eq!(
        ev(&call1(BigInt::from(0b1100), 9, ubig(BigInt::from(0b1010)))),
        Value::UnsignedBigInt(BigInt::from(0b1110))
    );
    assert_eq!(
        ev(&call1(BigInt::from(0b1100), 10, ubig(BigInt::from(0b1010)))),
        Value::UnsignedBigInt(BigInt::from(0b1000))
    );
    assert_eq!(
        ev(&call1(BigInt::from(0b1100), 11, ubig(BigInt::from(0b1010)))),
        Value::UnsignedBigInt(BigInt::from(0b0110))
    );
    // shiftLeft(12): logical; max legal shiftLeft(1, 255) = 2^255.
    assert_eq!(
        ev(&call1(BigInt::from(1), 12, const_int(255))),
        Value::UnsignedBigInt(BigInt::from(1) << 255)
    );
    // shiftRight(13): logical (receiver >= 0).
    assert_eq!(
        ev(&call1(BigInt::from(1) << 255, 13, const_int(1))),
        Value::UnsignedBigInt(BigInt::from(1) << 254)
    );
}

/// SUnsignedBigInt shiftLeft/shiftRight reject (RuntimeException) a count
/// outside [0, 256) and a shiftLeft result exceeding 256 bits — matching
/// Scala's `require`/`CUnsignedBigInt` ctor throw (NO mod-masking, NO
/// silent wrap), the trap that distinguishes unsigned shifts from the
/// fixed-width numeric shifts.
#[test]
fn methodcall_unsigned_bigint_shift_rejects_out_of_range_and_overflow() {
    use num_bigint::BigInt;
    let mut cx = ReductionContext::minimal(0, 0);
    cx.activated_script_version = 3;
    let ubig = |n: BigInt| Expr::Const {
        tpe: SigmaType::SUnsignedBigInt,
        val: SigmaValue::BigInt(n),
    };
    let shift = |recv: BigInt, mid: u8, bits: i32| {
        op(
            0xDC,
            Payload::MethodCall {
                type_id: 9,
                method_id: mid,
                obj: Box::new(ubig(recv)),
                args: vec![const_int(bits)],
                type_args: vec![],
            },
        )
    };
    let is_runtime_err = |e: &Expr, cx: &ReductionContext<'_>| {
        matches!(
            eval_to_value(e, cx, &[]),
            Err(EvalError::RuntimeException(_))
        )
    };
    // shiftLeft result exceeds 256 bits: (2^255) << 1 = 2^256 (257 bits).
    assert!(is_runtime_err(&shift(BigInt::from(1) << 255, 12, 1), &cx));
    // shift count == 256 (>= 256) rejected.
    assert!(is_runtime_err(&shift(BigInt::from(1), 12, 256), &cx));
    // negative shift count rejected (not flipped to a right shift).
    assert!(is_runtime_err(&shift(BigInt::from(1), 12, -1), &cx));
    // shiftRight count >= 256 rejected too.
    assert!(is_runtime_err(&shift(BigInt::from(1) << 255, 13, 256), &cx));
}

/// SUnsignedBigInt bitwise/shift methods cost `FixedCost(JitCost(5))`
/// (`BitwiseOp_CostKind`). Pinned relative to toSigned(19)=FixedCost(10)
/// on the identical arity-0 same-receiver path, so overhead cancels and
/// the delta is purely 10 - 5 = 5.
#[test]
fn methodcall_unsigned_bigint_bitwise_fixed_cost_matches_v6_0_2() {
    use num_bigint::BigInt;
    let mut cx = ReductionContext::minimal(0, 0);
    cx.activated_script_version = 3;
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut trace = None;
    let cost_of = |e: &Expr, env: &mut Env, depth: &mut usize, trace: &mut _| {
        let mut acc = CostAccumulator::recording_only();
        eval_expr(e, &cx, &[], env, depth, &mut acc, trace).unwrap();
        acc.total().value()
    };
    let recv = || Expr::Const {
        tpe: SigmaType::SUnsignedBigInt,
        val: SigmaValue::BigInt(BigInt::from(7)),
    };
    let mc = |mid: u8| {
        op(
            0xDC,
            Payload::MethodCall {
                type_id: 9,
                method_id: mid,
                obj: Box::new(recv()),
                args: vec![],
                type_args: vec![],
            },
        )
    };
    let inverse = cost_of(&mc(8), &mut env, &mut depth, &mut trace);
    let to_signed = cost_of(&mc(19), &mut env, &mut depth, &mut trace);
    assert_eq!(
        to_signed - inverse,
        5,
        "bitwiseInverse FixedCost must be 5 (toSigned 10 - inverse, identical arity-0 path)",
    );
}

/// Regression: `SUnsignedBigInt.modInverse(1, 0)` must reject the
/// transaction, not panic. A zero modulus reaches `egcd.x % m` =
/// `1 % 0` (receiver 1 passes the coprime check because gcd(1, 0) == 1),
/// which panicked before the explicit zero guard was added. Java's
/// `BigInteger.modInverse` throws on a non-positive modulus, so the
/// consensus-correct outcome is a rejected script, matching the zero
/// guards the sibling modular methods already carry.
#[test]
fn methodcall_mod_inverse_zero_modulus_errors_not_panics() {
    let mut cx = ReductionContext::minimal(0, 0);
    cx.activated_script_version = 3;
    let obj = Expr::Const {
        tpe: SigmaType::SUnsignedBigInt,
        val: SigmaValue::BigInt(1u64.into()),
    };
    let zero = Expr::Const {
        tpe: SigmaType::SUnsignedBigInt,
        val: SigmaValue::BigInt(0u64.into()),
    };
    let expr = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 9,
            method_id: 14,
            obj: Box::new(obj),
            args: vec![zero],
            type_args: vec![],
        },
    });
    let err = eval_to_value(&expr, &cx, &[]).unwrap_err();
    assert!(
        matches!(err, EvalError::RuntimeException(_)),
        "modInverse(1, 0) must error rather than panic; got {err:?}",
    );
}

/// Consensus cost pin for the Sigma 6.0 SBigInt unsigned conversions.
/// The per-method JitCost is anchored to the RELEASED sigmastate-interpreter
/// v6.0.0 `methods.scala` (data/shared/src/main/scala/sigma/ast/methods.scala):
///   ToUnsigned    = FixedCost(JitCost(5))
///   ToUnsignedMod = FixedCost(JitCost(15))
/// The pre-release `6.0-deserialize` branch carried 10/20; mainnet consensus
/// follows the release. Pinning the accumulated cost guards against a silent
/// revert to the wrong constant.
#[test]
fn methodcall_sbigint_to_unsigned_cost_matches_v6_0_0() {
    let mut cx = ReductionContext::minimal(0, 0);
    cx.activated_script_version = 3;
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut trace = None;

    let receiver = || Expr::Const {
        tpe: SigmaType::SBigInt,
        val: SigmaValue::BigInt(7u64.into()),
    };
    let cost_of = |expr: &Expr, env: &mut Env, depth: &mut usize, trace: &mut _| {
        let mut acc = CostAccumulator::recording_only();
        eval_expr(expr, &cx, &[], env, depth, &mut acc, trace).unwrap();
        acc.total().value()
    };

    let to_unsigned = op(
        0xDC,
        Payload::MethodCall {
            type_id: 6,
            method_id: 14,
            obj: Box::new(receiver()),
            args: vec![],
            type_args: vec![],
        },
    );
    let to_unsigned_mod = op(
        0xDC,
        Payload::MethodCall {
            type_id: 6,
            method_id: 15,
            obj: Box::new(receiver()),
            args: vec![Expr::Const {
                tpe: SigmaType::SUnsignedBigInt,
                val: SigmaValue::BigInt(3u64.into()),
            }],
            type_args: vec![],
        },
    );

    let tu = cost_of(&to_unsigned, &mut env, &mut depth, &mut trace);
    let tum = cost_of(&to_unsigned_mod, &mut env, &mut depth, &mut trace);

    // Totals decompose as: receiver const (5) + 0xDC overhead (4) + method
    // cost; toUnsignedMod additionally evaluates its modulus const (5). With
    // the v6.0.0 per-method costs (toUnsigned 5, toUnsignedMod 15) that is
    // 14 and 29. A revert to the pre-release 10/20 would shift both (19/34),
    // failing this pin.
    assert_eq!(
        tu, 14,
        "SBigInt.toUnsigned cost regressed (v6.0.0 method cost = 5); got {tu}"
    );
    assert_eq!(
        tum, 29,
        "SBigInt.toUnsignedMod cost regressed (v6.0.0 method cost = 15); got {tum}"
    );
}

/// Consensus cost pin for SGlobal.deserializeTo (v6). Anchored to
/// sigmastate-interpreter v6.0.2: `deserializeCostKind = PerItemCost(
/// baseCost = JitCost(100), perChunkCost = JitCost(32), chunkSize = 32)`.
/// The pre-release 6.0-deserialize draft used (30, 20, 32), under-charging.
/// One input byte => one chunk, so the method portion is 100 + 32 = 132.
#[test]
fn methodcall_deserialize_to_cost_matches_v6_0_2() {
    let mut cx = ReductionContext::minimal(0, 0);
    cx.activated_script_version = 3;
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut trace = None;

    // deserializeTo[Boolean](Coll[Byte](1)) -> true (DataSerializer reads one
    // byte; != 0 => true).
    let expr = op(
        0xDC,
        Payload::MethodCall {
            type_id: 106,
            method_id: 4,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![const_bytes(vec![1])],
            type_args: vec![SigmaType::SBoolean],
        },
    );
    let mut acc = CostAccumulator::recording_only();
    let v = eval_expr(&expr, &cx, &[], &mut env, &mut depth, &mut acc, &mut trace).unwrap();
    assert_eq!(
        v,
        Value::Bool(true),
        "deserializeTo[Boolean](Coll(1)) must yield true"
    );
    // Total = method cost 132 (base 100 + one 32-chunk) + 14 shared overhead
    // (SGlobal receiver + 0xDC dispatch + the Coll[Byte] arg const). A revert
    // to the pre-release (30, 20, 32) would drop the method portion to 50
    // (total 64), failing this pin.
    assert_eq!(
        acc.total().value(),
        146,
        "SGlobal.deserializeTo cost regressed (v6.0.2 = PerItemCost(100,32,32)); got {}",
        acc.total().value(),
    );
}

/// Negative companion to the registry sweep: V5+ method ids that
/// SHARE a type with v6 methods must remain dispatchable at
/// pre-EIP-50. If `is_v6_method` ever mis-classifies one of these,
/// historical scripts would start rejecting and consensus would
/// fork. The reference set:
///
/// * `(101, 8) SContext.selfBoxIndex` — has its own pre-JIT bug
///   behavior (<2 returns -1) in property_call.rs, but the gate
///   itself must let it through at v=2.
/// * `(106, 2) SGlobal.xor` — predates EIP-50 entirely.
/// * `(100, 9) SAvlTree.contains` — V5 method on a type with no v6
///   methods at all.
/// * `(12, 26) SCollection.indexOf` — V5 collection method, shares
///   type_id=12 with the v6 reverse/startsWith/etc. cluster.
/// * `(36, 7) Option.getOrElse` — V5 method on a type with no v6
///   surface (type_id=36 is not in is_v6_method at all).
/// * `(99, 7) SBox.getReg` is the V5+ getReg slot; the v6 getReg is a
///   separate id (19), so id 7 must never reach the gate.
/// * `(101, 11) SContext.getVar` is V5+ (commonMethods), so it must NOT
///   be soft-fork-rejected pre-EIP50 (it later rejects as an unsupported
///   MethodCall — getVar is only evaluable as the inline 0xE3 form).
///
/// This test only checks that the gate does not reject — it does
/// not assert successful evaluation, since each method has its own
/// argument requirements. We accept any non-`SoftForkNotActivated`
/// outcome (typically `TypeError` from the empty arg list).
#[test]
fn methodcall_v5_methods_pass_through_pre_eip50_gate() {
    let must_pass_gate: &[(u8, u8)] = &[
        (101, 8),
        (106, 2),
        (100, 9),
        (12, 26),
        (36, 7),
        (99, 7),
        (101, 11),
    ];
    let mut pre_eip50 = ReductionContext::minimal(0, 0);
    pre_eip50.activated_script_version = 2;
    for &(tid, mid) in must_pass_gate {
        let expr = Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id: tid,
                method_id: mid,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![],
                type_args: vec![],
            },
        });
        if let Err(EvalError::SoftForkNotActivated { .. }) = eval_to_value(&expr, &pre_eip50, &[]) {
            panic!(
                "V5+ method ({tid}, {mid}) must NOT be soft-fork-rejected at \
                 activatedScriptVersion=2 — it has been since before EIP-50"
            );
        }
    }
}

/// The crux of the SBox.getReg v5/v6 split, pinned in one place: at
/// pre-EIP50 (activatedScriptVersion=2) the V5+ getReg slot (id 7)
/// must dispatch (never soft-fork-rejected), while the Sigma 6.0
/// getReg slot (id 19) must reject with `SoftForkNotActivated`. A
/// regression that swapped the gated id would flip exactly one of
/// these two assertions.
#[test]
fn methodcall_box_getreg_v5_dispatches_while_v6_gated_at_pre_eip50() {
    let mut pre_eip50 = ReductionContext::minimal(0, 0);
    pre_eip50.activated_script_version = 2;
    let call = |mid: u8| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id: 99,
                method_id: mid,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![],
                type_args: vec![],
            },
        })
    };
    // v5 getReg (id 7): passes the gate and dispatches to the getReg
    // arm, which rejects the empty arg list on arity. Reaching
    // ArityMismatch (not SoftForkNotActivated) proves the v5 slot is
    // both ungated and routed to getReg.
    assert!(
        matches!(
            eval_to_value(&call(7), &pre_eip50, &[]),
            Err(EvalError::ArityMismatch { expected: 1, got: 0 })
        ),
        "v5 getReg (99, 7) must pass the gate and reach the getReg arity check at activatedScriptVersion=2",
    );
    // v6 getReg (id 19): the soft-fork-gated slot rejects until EIP-50.
    assert!(
        matches!(
            eval_to_value(&call(19), &pre_eip50, &[]),
            Err(EvalError::SoftForkNotActivated {
                type_id: 99,
                method_id: 19,
                ..
            })
        ),
        "v6 getReg (99, 19) must reject with SoftForkNotActivated at activatedScriptVersion=2",
    );
}

// ----- Coll.updated index-bounds parity -----
//
// Oracle: sigma-state's `CollsOverArrays.scala:100-104` delegates to
// `Array[A].updated(index, elem)`, which is documented to throw
// `IndexOutOfBoundsException` for `index < 0 || index >= length`.
// `sigma/ast/methods.scala::updated_eval` wraps that call inside
// `addSeqCost(costKind, coll.length, opDesc) { coll.updated(...) }`
// so cost is charged on `coll.length` BEFORE the bounds check fires
// (we mirror this ordering: `add_cost_per_item` precedes the gate).
//
// A naive port can silently no-op on out-of-range indices: `n as usize`
// wraps negatives to `usize::MAX` and a `if idx < coll.len()` check
// returns the original collection unchanged. That would accept
// `coll.updated(-1, x)` scripts that Scala rejects.

fn const_coll_long(vals: Vec<i64>) -> Expr {
    use ergo_ser::sigma_value::CollValue;
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SLong)),
        val: SigmaValue::Coll(CollValue::Values(
            vals.into_iter().map(SigmaValue::Long).collect(),
        )),
    }
}

fn coll_updated_call(obj: Expr, idx: i32, elem: Expr) -> Expr {
    op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 20, // updated
            obj: Box::new(obj),
            args: vec![const_int(idx), elem],
            type_args: vec![],
        },
    )
}

fn assert_updated_oob(expr: Expr, label: &str) {
    let err = run_eval_err(&expr);
    match err {
        EvalError::RuntimeException(msg) => assert!(
            msg.contains("Coll.updated") && msg.contains("out of bounds"),
            "{label}: wrong message: {msg}"
        ),
        other => panic!("{label}: expected RuntimeException(out of bounds), got {other:?}"),
    }
}

#[test]
fn coll_updated_negative_index_throws_int_carrier() {
    // CollInt: Coll(1, 2, 3).updated(-1, 99). Scala throws
    // IndexOutOfBoundsException; we surface as RuntimeException to
    // keep the typed error variant.
    let expr = coll_updated_call(const_coll_int(vec![1, 2, 3]), -1, const_int(99));
    assert_updated_oob(expr, "CollInt updated(-1, 99)");
}

#[test]
fn coll_updated_negative_index_throws_byte_carrier() {
    let expr = coll_updated_call(const_bytes(vec![1, 2, 3]), -1, const_int(99));
    assert_updated_oob(expr, "CollBytes updated(-1, 99)");
}

#[test]
fn coll_updated_negative_index_throws_long_carrier() {
    let expr = coll_updated_call(const_coll_long(vec![1, 2, 3]), -1, const_long(99));
    assert_updated_oob(expr, "CollLong updated(-1, 99)");
}

#[test]
fn coll_updated_index_at_len_throws() {
    // `updated(len, x)` is out-of-range — Scala throws. A bounds
    // check of `< coll.len()` already catches `idx == len`, but
    // silently no-op'ing instead of throwing was the divergence.
    // This arm must throw.
    let expr = coll_updated_call(const_coll_int(vec![1, 2, 3]), 3, const_int(99));
    assert_updated_oob(expr, "CollInt updated(3, 99)");
}

#[test]
fn coll_updated_index_past_len_throws() {
    let expr = coll_updated_call(const_coll_int(vec![1, 2, 3]), 100, const_int(99));
    assert_updated_oob(expr, "CollInt updated(100, 99)");
}

#[test]
fn coll_updated_valid_index_succeeds_regression_guard() {
    // Happy path — must keep working after the throw-on-oob fix.
    let expr = coll_updated_call(const_coll_int(vec![1, 2, 3]), 1, const_int(99));
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("valid index must succeed");
    let coll = match v {
        Value::CollInt(c) => c,
        other => panic!("expected CollInt, got {other:?}"),
    };
    assert_eq!(coll, vec![1, 99, 3], "updated(1, 99) must replace index 1");
}

#[test]
fn coll_updated_non_collection_receiver_returns_type_error() {
    // Receiver type-gate. A non-collection receiver must fall through
    // the carrier-dispatch arms and produce `TypeError`. If the bounds
    // check ran before the type dispatch the error would silently drift
    // to `RuntimeException` — silent error-class drift on a consensus-
    // critical surface. The explicit receiver-type gate keeps the
    // `TypeError` ordering.
    let expr = op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 20,
            obj: Box::new(const_int(42)), // Int, not a Coll
            args: vec![const_int(0), const_int(99)],
            type_args: vec![],
        },
    );
    let err = run_eval_err(&expr);
    assert!(
        matches!(err, EvalError::TypeError { .. }),
        "non-collection receiver must yield TypeError, got {err:?}"
    );
}

// Cost-charged-before-throw test for Coll.updated bounds violation.
// Per sigma-state `methods.scala::updated_eval`, cost is charged via
// `addSeqCost(costKind, coll.length, opDesc) { () => coll.updated(...) }`:
// the PerItemCost charge fires BEFORE the closure runs, so the
// out-of-range throw inside the closure happens AFTER cost has been
// accumulated. Our Rust evaluator must mirror that ordering.

#[test]
fn coll_updated_charges_cost_before_oob_throw() {
    use ergo_primitives::cost::CostAccumulator;
    let ctx = ReductionContext::minimal(10_000_000, 0);
    // Coll(1, 2, 3).updated(-1, 99) — OOB. Cost must be charged
    // before the RuntimeException fires. PerItemCost(20, 1, 10) at
    // n=3: chunks = ceil(3/10) = 1; cost = 20 + 1*1 = 21.
    let expr = coll_updated_call(const_coll_int(vec![1, 2, 3]), -1, const_int(99));
    let mut cost = CostAccumulator::recording_only();
    let result = reduce_expr_with_cost(&expr, &ctx, &[], &mut cost);
    // Must error (out-of-bounds), AND must have charged the per-item
    // cost before the error fired.
    assert!(result.is_err(), "OOB must surface as Err");
    // The cost trace records at minimum: MethodCall (Fixed(4)) +
    // ByIndex evals + the PerItemCost(20,1,10) charge for updated.
    // We assert a lower bound that proves the updated cost was
    // charged: > 20 (the PerItemCost base alone). A passing assertion
    // with the prior `Fixed(4)` charge would have shown a total
    // lower than that.
    assert!(
        cost.total().value() >= 21,
        "Coll.updated must charge PerItemCost(20, 1, 10) over n=3 \
         (= 21) BEFORE the bounds-check throw fires; got total={}",
        cost.total().value(),
    );
}

// ----- Coll.updated element-carrier parity -----
//
// `eval_by_index` on a Coll[Byte] (collection.rs:118) returns
// `Value::Byte`, so a natural ErgoScript like
// `bytes.updated(0, otherBytes(0))` feeds a `Value::Byte` element
// into Coll.updated. The Rust dispatch must accept that — Scala-sigma's
// typed method signature for `Coll[Byte].updated` pins the element to
// `Byte`, so this is the natural Scala-parity arm.

fn coll_updated_call_byte_elem(obj: Expr, idx: i32, byte_val: i8) -> Expr {
    // Build a Coll[Byte] element by fetching index 0 from a single-
    // byte literal collection. Mirrors the natural compile-time IR
    // where the element is sourced from another Coll[Byte] read.
    let byte_source = const_bytes(vec![byte_val as u8]);
    let byte_elem = op(
        0xB2, // ByIndex
        Payload::ByIndex {
            input: Box::new(byte_source),
            index: Box::new(const_int(0)),
            default: None,
        },
    );
    coll_updated_call(obj, idx, byte_elem)
}

#[test]
fn coll_updated_bytes_accepts_byte_element_natural_carrier() {
    // `bytes.updated(0, bytes(0))` where the second arg is sourced from
    // another Coll[Byte] index — natural compile-time output.
    // Previously rejected with TypeError because the dispatch only
    // matched `Value::Int`; the byte-element arm closes that gap.
    let expr = coll_updated_call_byte_elem(const_bytes(vec![10, 20, 30]), 1, 99);
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("byte-element update on Coll[Byte] must succeed (Scala-parity)");
    let coll = match v {
        Value::CollBytes(c) => c,
        other => panic!("expected CollBytes, got {other:?}"),
    };
    assert_eq!(
        coll,
        vec![10, 99, 30],
        "byte-element update must replace the targeted index",
    );
}

#[test]
fn coll_updated_bytes_rejects_int_element_strict_scala_parity() {
    // Scala-sigma's typed method dispatch pins
    // `Coll[Byte].updated`'s element to `SByte`, so a hand-built
    // ErgoTree presenting an `Int` element rejects at the typed
    // boundary. The Rust dispatch matches that rejection rather than
    // silently casting `Int` to `u8` (which would accept scripts
    // Scala refuses — a consensus-loosening divergence).
    let expr = coll_updated_call(const_bytes(vec![10, 20, 30]), 1, const_int(99));
    let err = run_eval_err(&expr);
    assert!(
        matches!(err, EvalError::TypeError { .. }),
        "Coll[Byte].updated(_, Int) must reject as TypeError, got {err:?}",
    );
}

#[test]
fn coll_updated_bytes_sign_boundary_0x80_round_trips() {
    // Sign-boundary coverage: `Value::Byte` is `i8` while
    // `CollBytes` stores `u8`. `0x80` (-128 as i8) and `0xFF`
    // (-1 as i8) are the boundary values where a sloppy cast
    // could silently drift. The `v as u8` reinterpretation must
    // preserve the bit pattern.
    let byte_source = const_bytes(vec![0x80]);
    let byte_elem = op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(byte_source),
            index: Box::new(const_int(0)),
            default: None,
        },
    );
    let expr = coll_updated_call(const_bytes(vec![0x00, 0x00, 0x00]), 1, byte_elem);
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("0x80 byte element must round-trip");
    let coll = match v {
        Value::CollBytes(c) => c,
        other => panic!("expected CollBytes, got {other:?}"),
    };
    assert_eq!(
        coll,
        vec![0x00, 0x80, 0x00],
        "0x80 byte must land at index 1 with the bit pattern intact",
    );
}

#[test]
fn coll_updated_bytes_sign_boundary_0xff_round_trips() {
    let byte_source = const_bytes(vec![0xFF]);
    let byte_elem = op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(byte_source),
            index: Box::new(const_int(0)),
            default: None,
        },
    );
    let expr = coll_updated_call(const_bytes(vec![0x00, 0x00, 0x00]), 0, byte_elem);
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("0xFF byte element must round-trip");
    let coll = match v {
        Value::CollBytes(c) => c,
        other => panic!("expected CollBytes, got {other:?}"),
    };
    assert_eq!(
        coll,
        vec![0xFF, 0x00, 0x00],
        "0xFF byte must land at index 0 with the bit pattern intact",
    );
}

// ----- Coll.updated CollShort + CollBool carrier extension -----
//
// Scala-sigma's `Coll[T].updated` is generic over T; the prior Rust
// receiver gate excluded `CollShort` and `CollBool` so those types
// rejected at `TypeError` before the bounds check could fire.
// Extending the gate + dispatch arms closes the Scala-parity hole.

fn const_coll_short(vals: Vec<i16>) -> Expr {
    use ergo_ser::sigma_value::CollValue;
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SShort)),
        val: SigmaValue::Coll(CollValue::Values(
            vals.into_iter().map(SigmaValue::Short).collect(),
        )),
    }
}

fn const_short(v: i16) -> Expr {
    Expr::Const {
        tpe: SigmaType::SShort,
        val: SigmaValue::Short(v),
    }
}

#[test]
fn coll_updated_short_carrier_succeeds() {
    // CollShort.updated(1, 99) must succeed under the extended gate.
    let expr = coll_updated_call(const_coll_short(vec![10, 20, 30]), 1, const_short(99));
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("Coll[Short].updated must succeed under the extended receiver gate");
    let coll = match v {
        Value::CollShort(c) => c,
        other => panic!("expected CollShort, got {other:?}"),
    };
    assert_eq!(
        coll,
        vec![10, 99, 30],
        "updated(1, 99) must replace index 1"
    );
}

#[test]
fn coll_updated_bool_carrier_succeeds() {
    // CollBool.updated(0, false) must succeed under the extended gate.
    let expr = coll_updated_call(
        const_coll_bool(vec![true, true, true]),
        0,
        const_bool(false),
    );
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("Coll[Bool].updated must succeed under the extended receiver gate");
    let coll = match v {
        Value::CollBool(c) => c,
        other => panic!("expected CollBool, got {other:?}"),
    };
    assert_eq!(
        coll,
        vec![false, true, true],
        "updated(0, false) must replace index 0",
    );
}

#[test]
fn coll_updated_short_negative_index_throws_runtime() {
    // Receiver-gate extension also propagates the out-of-bounds throw
    // semantics: previously this rejected at the receiver gate with
    // TypeError before the bounds check ran. Now it should surface as
    // RuntimeException, matching the int/long/byte carriers.
    let expr = coll_updated_call(const_coll_short(vec![1, 2, 3]), -1, const_short(99));
    assert_updated_oob(expr, "CollShort updated(-1, 99)");
}

#[test]
fn coll_updated_bool_negative_index_throws_runtime() {
    let expr = coll_updated_call(
        const_coll_bool(vec![true, false, true]),
        -1,
        const_bool(true),
    );
    assert_updated_oob(expr, "CollBool updated(-1, true)");
}

// ----- Coll.updated CollSigmaProp + CollHeader carrier extension -----
//
// Scala-sigma's `Coll[T].updated` for boxed carriers (SigmaProp,
// Header) materializes through the same `Array[A].updated` path as
// primitives. The Rust dispatch needs strict element-type arms so
// e.g. `Coll[Header].updated(0, Value::Int(...))` rejects with
// TypeError instead of silently wrapping the bad element.

fn const_coll_sigma_prop_trivial(vals: Vec<bool>) -> Expr {
    use ergo_ser::sigma_value::CollValue;
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
        val: SigmaValue::Coll(CollValue::Values(
            vals.into_iter()
                .map(|b| SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(b)))
                .collect(),
        )),
    }
}

fn const_sigma_prop_trivial(v: bool) -> Expr {
    Expr::Const {
        tpe: SigmaType::SSigmaProp,
        val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(v)),
    }
}

#[test]
fn coll_updated_sigma_prop_carrier_succeeds() {
    // Coll[SigmaProp].updated(1, falseProp): replace one trivial
    // proposition with another. Scala-sigma accepts via the generic
    // Coll[T].updated path; the Rust dispatch needs the matching arm.
    let expr = coll_updated_call(
        const_coll_sigma_prop_trivial(vec![true, true, true]),
        1,
        const_sigma_prop_trivial(false),
    );
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("Coll[SigmaProp].updated must succeed under the extended dispatch");
    let coll = match v {
        Value::CollSigmaProp(c) => c,
        other => panic!("expected CollSigmaProp, got {other:?}"),
    };
    assert_eq!(
        coll,
        vec![
            SigmaBoolean::TrivialProp(true),
            SigmaBoolean::TrivialProp(false),
            SigmaBoolean::TrivialProp(true),
        ],
        "updated(1, falseProp) must replace index 1",
    );
}

#[test]
fn coll_updated_sigma_prop_rejects_int_element() {
    // Strict element-type parity: passing an `Int` to a Coll[SigmaProp]
    // updated call must reject (Scala-sigma's typed dispatch enforces
    // the SigmaProp element type).
    let expr = coll_updated_call(
        const_coll_sigma_prop_trivial(vec![true, true, true]),
        1,
        const_int(99),
    );
    let err = run_eval_err(&expr);
    assert!(
        matches!(err, EvalError::TypeError { .. }),
        "Coll[SigmaProp].updated(_, Int) must reject as TypeError, got {err:?}",
    );
}

#[test]
fn coll_updated_sigma_prop_negative_index_throws_runtime() {
    let expr = coll_updated_call(
        const_coll_sigma_prop_trivial(vec![true, false, true]),
        -1,
        const_sigma_prop_trivial(true),
    );
    assert_updated_oob(expr, "CollSigmaProp updated(-1, true)");
}

// ----- Coll.updated CollBox + BoxCollection + Tokens via real eval-path -----

/// Build a `MethodCall(12, 20)` Expr — the same shape `coll_updated_call`
/// uses but with arbitrary `obj` + `elem` Expr inputs.
fn coll_updated_via_method_call(obj: Expr, idx: Expr, elem: Expr) -> Expr {
    op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 20,
            obj: Box::new(obj),
            args: vec![idx, elem],
            type_args: vec![],
        },
    )
}

fn op_inputs() -> Expr {
    // 0xA4 INPUTS — yields Value::BoxCollection(BoxSource::Inputs).
    op(0xA4, Payload::Zero)
}

fn op_self() -> Expr {
    // 0xA7 SELF — yields Value::SelfBox.
    op(0xA7, Payload::Zero)
}

fn op_by_index(coll: Expr, idx: Expr) -> Expr {
    op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(coll),
            index: Box::new(idx),
            default: None,
        },
    )
}

#[test]
fn coll_updated_inputs_updated_self_succeeds_via_eval() {
    // `INPUTS.updated(0, SELF)` — Scala-sigma's
    // `CollsOverArrays.scala:100-104` accepts generic
    // `Coll[Box].updated(i, e: Box)`; INPUTS is a Coll[Box] at the
    // typed-IR layer but materializes as `Value::BoxCollection` at
    // runtime, so the receiver gate + dispatch arm must materialize
    // the source-ref carrier into a `CollBox` before the update.
    let test_box = make_test_box();
    let other_box = make_test_box();
    let ctx = ReductionContext {
        height: 600_000,
        self_box: Some(&test_box),
        self_creation_height: test_box.creation_height,
        outputs: &[],
        inputs: &[other_box.clone(), other_box.clone()],
        data_inputs: &[],
        miner_pubkey: [0x33; 33],
        pre_header_timestamp: 1_700_000_000_000,
        extension: indexmap::IndexMap::new(),
        last_headers: &[],
        last_block_utxo_root: None,
        activated_script_version: 3,
        ergo_tree_version: 3,
        pre_header_version: 0,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
        input_extensions: &[],
    };
    let expr = coll_updated_via_method_call(op_inputs(), const_int(0), op_self());
    let v = eval_to_value(&expr, &ctx, &[])
        .expect("INPUTS.updated(0, SELF) must succeed under the extended dispatch");
    match v {
        Value::CollBox(coll) => {
            assert_eq!(coll.len(), 2, "INPUTS length preserved");
            assert!(
                matches!(coll[0], Value::SelfBox),
                "index 0 must be replaced with SELF",
            );
            assert!(
                matches!(
                    coll[1],
                    Value::BoxRef {
                        source: BoxSource::Inputs,
                        index: 1
                    }
                ),
                "index 1 unchanged",
            );
        }
        other => panic!("expected CollBox, got {other:?}"),
    }
}

#[test]
fn coll_updated_inputs_rejects_int_element_via_eval() {
    // Strict element-type parity at the eval-path: passing an `Int`
    // to `INPUTS.updated` rejects (the dispatch arm only matches
    // box-typed elements).
    let test_box = make_test_box();
    let ctx = ReductionContext {
        height: 600_000,
        self_box: Some(&test_box),
        self_creation_height: test_box.creation_height,
        outputs: &[],
        inputs: std::slice::from_ref(&test_box),
        data_inputs: &[],
        miner_pubkey: [0x33; 33],
        pre_header_timestamp: 1_700_000_000_000,
        extension: indexmap::IndexMap::new(),
        last_headers: &[],
        last_block_utxo_root: None,
        activated_script_version: 3,
        ergo_tree_version: 3,
        pre_header_version: 0,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
        input_extensions: &[],
    };
    let expr = coll_updated_via_method_call(op_inputs(), const_int(0), const_int(99));
    let err = match eval_to_value(&expr, &ctx, &[]) {
        Ok(v) => panic!("INPUTS.updated(0, Int) must reject, got {v:?}"),
        Err(e) => e,
    };
    assert!(
        matches!(err, EvalError::TypeError { .. }),
        "INPUTS.updated(0, Int) must reject as TypeError, got {err:?}",
    );
}

// `SELF.tokens` returns Value::Opt(Tokens) via ExtractRegisterAs (0xC6)
// + register id 2. Unwrap with `.get` to test Tokens.updated. The
// fixture is non-trivial — make_test_box ships with two tokens.

fn op_extract_register_2_tokens(box_expr: Expr) -> Expr {
    op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(box_expr),
            reg_id: 2,
            tpe: SigmaType::SColl(Box::new(SigmaType::STuple(vec![
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaType::SLong,
            ]))),
        },
    )
}

fn op_opt_get(opt_expr: Expr) -> Expr {
    // 0xE4 OptionGet — unwrap Option, error if None or non-Option.
    op(0xE4, Payload::One(Box::new(opt_expr)))
}

// Coll[Tuple].updated on the boxed-element coll carrier
// (`Value::CollGeneric`). Scala-sigma's `Coll[A].updated` is generic
// over `A`; the receiver allowlist accepts the carrier and the match
// arm replaces the box at `idx`, preserving `CollGeneric`. The
// constant builds an `SColl(STuple(Int, Long))` so the parse path
// produces `CollGeneric` (same shape `zip` and `flatMap` yield at
// runtime), exercising the receiver path end-to-end.
#[test]
fn coll_updated_collgeneric_replaces_boxed_element() {
    let coll_ty = SigmaType::SColl(Box::new(SigmaType::STuple(vec![
        SigmaType::SInt,
        SigmaType::SLong,
    ])));
    let coll_const = Expr::Const {
        tpe: coll_ty.clone(),
        val: SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Values(vec![
            SigmaValue::Tuple(vec![SigmaValue::Int(1), SigmaValue::Long(10)]),
            SigmaValue::Tuple(vec![SigmaValue::Int(2), SigmaValue::Long(20)]),
            SigmaValue::Tuple(vec![SigmaValue::Int(3), SigmaValue::Long(30)]),
        ])),
    };
    let elem = Expr::Const {
        tpe: SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong]),
        val: SigmaValue::Tuple(vec![SigmaValue::Int(99), SigmaValue::Long(999)]),
    };
    let expr = coll_updated_via_method_call(coll_const, const_int(1), elem);
    let v = run_eval(&expr);
    match v {
        Value::CollGeneric(items, _) => {
            assert_eq!(items.len(), 3);
            assert_eq!(items[0], Value::Tuple(vec![Value::Int(1), Value::Long(10)]));
            assert_eq!(
                items[1],
                Value::Tuple(vec![Value::Int(99), Value::Long(999)])
            );
            assert_eq!(items[2], Value::Tuple(vec![Value::Int(3), Value::Long(30)]));
        }
        other => panic!("expected CollGeneric carrier preserved, got {other:?}"),
    }
}

// `Coll[Option[Coll[Byte]]].updated` end-to-end through the evaluator.
// `R4` carries a `Coll[Option[Coll[Byte]]]` constant; the script calls
// `.updated(0, R5)` where `R5` is a `Some(CollBytes)`. This exercises:
//   1. The constant-decode path (`sigma_to_value` → `CollGeneric`
//      tagged `SOption(SColl(SByte))`).
//   2. The `(12, 26) Coll.updated` MethodCall on the boxed-element
//      carrier with a non-serializable `Value::Opt` replacement —
//      the path that previously rejected through `value_to_typed_sigma`.
//   3. The `value_to_sigma_type` compatibility check including the
//      `Opt(None)` case via the `SAny` wildcard in the second
//      assertion (replace with `None` at index 1).
#[test]
fn coll_updated_collgeneric_accepts_option_element_via_eval() {
    let inner_ty = SigmaType::SColl(Box::new(SigmaType::SByte));
    let opt_ty = SigmaType::SOption(Box::new(inner_ty.clone()));
    let coll_ty = SigmaType::SColl(Box::new(opt_ty.clone()));

    // Coll[Option[Coll[Byte]]] constant — two Some(_) entries.
    let coll_const = Expr::Const {
        tpe: coll_ty,
        val: SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Values(vec![
            SigmaValue::Opt(Some(Box::new(SigmaValue::Coll(
                ergo_ser::sigma_value::CollValue::Bytes(vec![0xAA; 32]),
            )))),
            SigmaValue::Opt(Some(Box::new(SigmaValue::Coll(
                ergo_ser::sigma_value::CollValue::Bytes(vec![0xBB; 32]),
            )))),
        ])),
    };
    // Replacement: Some(CollBytes) — non-serializable Value::Opt at
    // runtime, exercising the new `value_to_sigma_type` probe.
    let new_some = Expr::Const {
        tpe: opt_ty.clone(),
        val: SigmaValue::Opt(Some(Box::new(SigmaValue::Coll(
            ergo_ser::sigma_value::CollValue::Bytes(vec![0xCC; 32]),
        )))),
    };
    let expr = coll_updated_via_method_call(coll_const.clone(), const_int(0), new_some);
    let v = run_eval(&expr);
    match v {
        Value::CollGeneric(items, elem_type) => {
            assert_eq!(items.len(), 2);
            assert_eq!(*elem_type, opt_ty, "carrier elem_type preserved");
            // Index 0 was replaced with the new Some(CollBytes[CC; 32]).
            assert_eq!(
                items[0],
                Value::Opt(Some(Box::new(Value::CollBytes(vec![0xCC; 32]))))
            );
            // Index 1 untouched.
            assert_eq!(
                items[1],
                Value::Opt(Some(Box::new(Value::CollBytes(vec![0xBB; 32]))))
            );
        }
        other => panic!("expected CollGeneric carrier, got {other:?}"),
    }

    // Now the None case: SAny wildcard compatibility must accept
    // `Opt(None)` against an `SOption(SColl(SByte))` carrier.
    let new_none = Expr::Const {
        tpe: opt_ty,
        val: SigmaValue::Opt(None),
    };
    let expr_none = coll_updated_via_method_call(coll_const, const_int(1), new_none);
    let v_none = run_eval(&expr_none);
    match v_none {
        Value::CollGeneric(items, _) => {
            assert_eq!(items[1], Value::Opt(None));
        }
        other => panic!("expected CollGeneric for None-update, got {other:?}"),
    }
}

// Regression pin: `SubstConstants` substituting a `Value::Opt(None)`
// into an `Option[T]` template slot must preserve the template's
// declared `Option[T]` type descriptor in the rewritten ErgoTree.
// Pre-fix, `value_to_typed_sigma` returned `SOption(SAny)` for the
// None value and that degraded type wrote back into the constant
// pool — shifting the ErgoTree bytes (and the resulting script id)
// away from Scala's `ErgoTreeSerializer.substituteConstants`. Post-
// fix, the template's existing typed slot is authoritative.
#[test]
fn subst_constants_none_preserves_template_option_type() {
    use super::helpers::subst_constants;
    use ergo_ser::ergo_tree::{read_ergo_tree, write_ergo_tree, ErgoTree};
    use ergo_ser::sigma_value::{CollValue, SigmaValue};
    // Build a template ErgoTree with one `Option[Coll[Byte]]` constant
    // (the body is a trivial true sigmaprop so the tree is valid).
    let opt_ty = SigmaType::SOption(Box::new(SigmaType::SColl(Box::new(SigmaType::SByte))));
    let body = Expr::Const {
        tpe: SigmaType::SSigmaProp,
        val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
    };
    let template = ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: true,
        constants: vec![(
            opt_ty.clone(),
            SigmaValue::Opt(Some(Box::new(SigmaValue::Coll(CollValue::Bytes(vec![
                0xAA;
                4
            ]))))),
        )],
        body,
    };
    let mut w = ergo_primitives::writer::VlqWriter::new();
    write_ergo_tree(&mut w, &template).expect("template write");
    let template_bytes = w.result();
    // Substitute the constant at index 0 with Value::Opt(None).
    let (new_bytes, _) = subst_constants(&template_bytes, &[0], &[Value::Opt(None)], true)
        .expect("subst_constants succeeds");
    // The rewritten tree must keep the template's declared
    // `SOption(SColl(SByte))` type descriptor on the slot — NOT
    // degrade to `SOption(SAny)`.
    let mut r = ergo_primitives::reader::VlqReader::new(&new_bytes);
    let rewritten = read_ergo_tree(&mut r).expect("rewritten tree re-parses");
    assert_eq!(
        rewritten.constants[0].0, opt_ty,
        "Template's declared Option[Coll[Byte]] type must survive a None \
         substitution (not degrade to Option[Any])",
    );
    assert_eq!(
        rewritten.constants[0].1,
        SigmaValue::Opt(None),
        "Substituted value must be None",
    );
}

// substConstants parity with Scala ErgoTreeSerializer.substituteConstants
// (over-strict fix). Byte vectors taken verbatim from the SANTA
// substConstants_equivalence vector (blessed jvm:sigma-state-6.0.3); the
// replacement value is always sigmaProp(false). The substitution keeps the
// tree body as opaque raw bytes, skips out-of-range positions
// (getPositionsBackref ignores them), returns no-segregation trees unchanged,
// and the returned nConstants drives the PerItemCost(100,100,1) charge.
#[test]
fn subst_constants_scala_parity_success_cases() {
    use super::helpers::subst_constants;
    let false_prop = || Value::SigmaProp(SigmaBoolean::TrivialProp(false));

    // No-segregation tree (header 0x00): no constants section -> returned
    // unchanged, nConstants = 0.
    assert_eq!(
        subst_constants(&[0x00, 0x08, 0xD3], &[0], &[false_prop()], false).unwrap(),
        (vec![0x00, 0x08, 0xD3], 0),
    );
    assert_eq!(
        subst_constants(&[0x00, 0x00, 0x08, 0xD3], &[0], &[false_prop()], false).unwrap(),
        (vec![0x00, 0x00, 0x08, 0xD3], 0),
    );
    // Segregated (0x10) but with 0 constants -> position 0 is out of range ->
    // skipped -> unchanged, nConstants = 0.
    assert_eq!(
        subst_constants(&[0x10, 0x00, 0x08, 0xD3], &[0], &[false_prop()], false).unwrap(),
        (vec![0x10, 0x00, 0x08, 0xD3], 0),
    );
    // Segregated, 1 SSigmaProp constant (true = 0xD3), substitute position 0 ->
    // sigmaProp(false) = 0xD2. Body (0x73 0x00) preserved verbatim. nConstants = 1.
    assert_eq!(
        subst_constants(
            &[0x10, 0x01, 0x08, 0xD3, 0x73, 0x00],
            &[0],
            &[false_prop()],
            false
        )
        .unwrap(),
        (vec![0x10, 0x01, 0x08, 0xD2, 0x73, 0x00], 1),
    );
    // Segregated, 1 constant, position 1 is out of range -> skipped ->
    // unchanged, nConstants = 1.
    assert_eq!(
        subst_constants(
            &[0x10, 0x01, 0x08, 0xD3, 0x73, 0x00],
            &[1],
            &[false_prop()],
            false
        )
        .unwrap(),
        (vec![0x10, 0x01, 0x08, 0xD3, 0x73, 0x00], 1),
    );
}

#[test]
fn subst_constants_scala_parity_error_cases() {
    use super::helpers::subst_constants;
    let false_prop = || Value::SigmaProp(SigmaBoolean::TrivialProp(false));
    // Empty bytes: the header read fails -> Scala throws RuntimeException
    // ("errored"), NOT UnsupportedOpcode ("not-implemented").
    let e_empty = subst_constants(&[], &[0], &[false_prop()], false).unwrap_err();
    assert!(
        matches!(e_empty, EvalError::RuntimeException(_)),
        "empty bytes must error as RuntimeException, got {e_empty:?}",
    );
    // Type mismatch: replacing an SInt constant (=10) with a SigmaProp ->
    // Scala `require(c.tpe == newConst.tpe)` throws -> RuntimeException.
    let e_type = subst_constants(
        &[0x10, 0x01, 0x04, 0x14, 0x73, 0x00],
        &[0],
        &[false_prop()],
        false,
    )
    .unwrap_err();
    assert!(
        matches!(e_type, EvalError::RuntimeException(_)),
        "type mismatch must error as RuntimeException, got {e_type:?}",
    );
    // Length mismatch (positions vs newValues) -> require fails -> RuntimeException.
    let e_len = subst_constants(&[0x10, 0x00], &[0, 1], &[false_prop()], false).unwrap_err();
    assert!(
        matches!(e_len, EvalError::RuntimeException(_)),
        "positions/newValues length mismatch must error, got {e_len:?}",
    );
}

// A template whose constants section carries an SHeader value (reachable via
// crafted scriptBytes) must be rejected by a pre-v3 executing ErgoTree even
// when that constant is NOT the one being substituted: Scala deserializes the
// constants under the executing VersionContext and DataSerializer.deserialize
// (SHeader) throws pre-v3. A v3+ executing tree accepts it and round-trips.
#[test]
fn subst_constants_pre_v3_template_header_constant_rejected() {
    use super::helpers::subst_constants;
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::header::read_header;
    use ergo_ser::sigma_value::write_constant;
    // Real mainnet header -> a single SHeader constant in a segregated tree.
    let raw = std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json")
        .expect("headers_1_10 fixture must exist");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let hbytes = hex::decode(v[0]["bytes"].as_str().unwrap()).unwrap();
    let header = read_header(&mut VlqReader::new(&hbytes)).expect("header parse");
    let header_val = SigmaValue::Header(Box::new(header));

    let mut w = VlqWriter::new();
    w.put_u8(0x10); // header: segregated
    w.put_u32(1); // 1 constant
    write_constant(&mut w, &SigmaType::SHeader, &header_val).unwrap();
    w.put_u8(0x73); // body: ConstPlaceholder
    w.put_u8(0x00); // index 0
    let tree = w.result();

    // Pre-v3: rejected even with NO substitution (the parsed template SHeader
    // constant materializes a header under a pre-v3 context).
    let err = subst_constants(&tree, &[], &[], false).unwrap_err();
    assert!(
        matches!(err, EvalError::RuntimeException(_)),
        "pre-v3 SHeader template constant must error, got {err:?}",
    );
    // v3+: accepted; with no substitution the tree round-trips unchanged.
    let (out, n) = subst_constants(&tree, &[], &[], true).expect("v3+ accepts SHeader constant");
    assert_eq!(out, tree, "no substitution must return the tree unchanged");
    assert_eq!(n, 1);
}

// Regression pin: a `map` whose first result element is `None`
// must still produce a `CollGeneric` carrier tagged with the
// concrete element type — `infer_collection` prefers the mapper-
// body's IR-inferred SOption(T) over the per-item recovery of
// SOption(SAny) from the first `Value::Opt(None)`. Without this,
// later `.updated` / `SGlobal.serialize` calls on the result
// would spuriously reject against the one-way SAny rule.
#[test]
fn map_collection_first_none_preserves_concrete_elem_type() {
    use super::helpers::infer_collection;
    let mapper_body = Expr::Const {
        tpe: SigmaType::SOption(Box::new(SigmaType::SInt)),
        val: SigmaValue::Opt(None),
    };
    let bindings = std::collections::HashMap::new();
    let items = vec![Value::Opt(None), Value::Opt(Some(Box::new(Value::Int(42))))];
    let result = infer_collection(items, &mapper_body, &bindings, &[]).unwrap();
    match result {
        Value::CollGeneric(_, elem_type) => {
            assert_eq!(
                *elem_type,
                SigmaType::SOption(Box::new(SigmaType::SInt)),
                "infer_collection must thread the IR-declared SOption(SInt) \
                 onto the carrier even when items[0] is Opt(None)",
            );
        }
        other => panic!("expected CollGeneric carrier, got {other:?}"),
    }
}

// Fail-closed: a CollGeneric carrier whose declared `elem_type` has
// been degraded to contain `SAny` (e.g. constructed from items where
// every element was `Value::Opt(None)`) must NOT pass the
// `Coll.updated` type gate against a CONCRETE replacement element.
// `sigma_type_compatible` is one-directional: SAny is only accepted
// on the observed side (the per-element recovery), never on the
// declared side (the carrier's elem_type tag).
#[test]
fn coll_updated_collgeneric_rejects_sany_declared_carrier() {
    // Carrier elem_type is SOption(SAny) — the degraded case that
    // signals "carrier built without proper type info". A concrete
    // replacement must REJECT here.
    let coll = Value::CollGeneric(
        vec![Value::Opt(None), Value::Opt(None)],
        Box::new(SigmaType::SOption(Box::new(SigmaType::SAny))),
    );
    let new_concrete = Value::Opt(Some(Box::new(Value::CollBytes(vec![0xAA; 32]))));
    use super::helpers::sigma_type_compatible;
    let declared = match &coll {
        Value::CollGeneric(_, t) => (**t).clone(),
        _ => unreachable!(),
    };
    let observed = super::helpers::value_to_sigma_type(&new_concrete).unwrap();
    assert!(
        !sigma_type_compatible(&declared, &observed),
        "Declared SOption(SAny) must REJECT a concrete observed \
         SOption(SColl(SByte)) — SAny is observed-side-only",
    );
}

// Negative case: malformed `Coll.updated` where the replacement
// element's SigmaType disagrees with the existing element type must
// reject — protects against rebuilt ErgoTree bytes that bypass the
// script-load typecheck.
#[test]
fn coll_updated_collgeneric_rejects_type_mismatch() {
    let coll_ty = SigmaType::SColl(Box::new(SigmaType::STuple(vec![
        SigmaType::SInt,
        SigmaType::SLong,
    ])));
    let coll_const = Expr::Const {
        tpe: coll_ty,
        val: SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Values(vec![
            SigmaValue::Tuple(vec![SigmaValue::Int(1), SigmaValue::Long(10)]),
        ])),
    };
    // Wrong-typed replacement element (Int instead of (Int, Long)).
    let elem = const_int(99);
    let expr = coll_updated_via_method_call(coll_const, const_int(0), elem);
    let err = run_eval_err(&expr);
    assert!(
        matches!(err, EvalError::TypeError { expected, .. }
            if expected == "matching element type for Coll.updated"),
        "Coll[(Int,Long)].updated(0, Int) must reject as element-type TypeError, got {err:?}",
    );
}

#[test]
fn coll_updated_tokens_canonical_shape_preserves_carrier_via_eval() {
    // `SELF.tokens.get.updated(0, SELF.tokens.get(1))` — canonical
    // shape preserved → return type stays Value::Tokens.
    let test_box = make_test_box();
    let ctx = ctx_with_self_box(&test_box);
    let tokens_expr = op_opt_get(op_extract_register_2_tokens(op_self()));
    let elem_expr = op_by_index(
        op_opt_get(op_extract_register_2_tokens(op_self())),
        const_int(1),
    );
    let expr = coll_updated_via_method_call(tokens_expr, const_int(0), elem_expr);
    let v = eval_to_value(&expr, &ctx, &[])
        .expect("SELF.tokens.updated with canonical element must succeed");
    match v {
        Value::Tokens(coll) => {
            assert_eq!(coll.len(), 2, "tokens length preserved");
            assert_eq!(
                coll[0].0, [0x22; 32],
                "index 0 must now hold the token at original index 1",
            );
            assert_eq!(coll[0].1, 200);
        }
        other => panic!("expected Tokens carrier preserved, got {other:?}"),
    }
}

// ----- Coll.patch index-bounds parity (Scala-bytecode-verified) -----
//
// Oracle: Scala 2.13.16 `scala-library` JAR, `scala.collection.ArrayOps$
// .patch$extension` (decoded from bytecode of the cached coursier JAR).
// sigma-state's `CollsOverArrays.scala:94-98` delegates to
// `Array[A].patch(from, patch.toArray, replaced)`, which is exactly
// that extension method. `immutable.Vector.patch` resolves through
// `immutable.StrictOptimizedSeqOps.patch` and produces identical results
// for negative inputs (also bytecode-verified). The re-extractable
// oracle script + disassembly recipe is in
// `test-vectors/ergo-sigma/coll-negative-index-parity/`.
//
// Decoded algorithm (locals 1=from, 3=replaced, 4=builder, 5=counter):
//
//     chunk1            = if (from > 0) min(from, xs.length) else 0
//     clampedReplaced   = if (replaced < 0) 0 else replaced
//     chunk2            = xs.length - chunk1 - clampedReplaced
//     if (chunk2 > 0):
//         suffix = xs[xs.length - chunk2 .. xs.length]
//     else:
//         suffix = []                                        // no throw
//     result = xs[0..chunk1] ++ patch ++ suffix
//
// Both `from < 0` and `replaced < 0` clamp silently to 0; the Scala
// path does NOT throw `IndexOutOfBoundsException` for either.
// `Coll.updated` is the only Coll method whose Scala backing delegates
// to `Array.updated`, which DOES throw — see the `coll_updated_*` arms
// above.
//
// The Rust impl `coll.splice(from.min(n) .. (from + replaced).min(n),
// patch)` after `from = max(0, n_int) as usize` / `replaced = max(0,
// n_int) as usize` is byte-identical to the Scala chunk1/chunk2 model
// for every i32 input pair. These tests pin the byte-exact parity at
// the negative-index boundary plus the i32 extremes so a future
// "fix on negative" patch would fail visibly.

fn coll_patch_call(obj: Expr, from: i32, patch: Expr, replaced: i32) -> Expr {
    op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 19, // patch
            obj: Box::new(obj),
            args: vec![const_int(from), patch, const_int(replaced)],
            type_args: vec![],
        },
    )
}

fn run_patch_int(xs: Vec<i32>, from: i32, patch: Vec<i32>, replaced: i32) -> Vec<i32> {
    let expr = coll_patch_call(const_coll_int(xs), from, const_coll_int(patch), replaced);
    match eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("Coll.patch must not throw for non-negative-throw inputs")
    {
        Value::CollInt(c) => c,
        other => panic!("expected CollInt, got {other:?}"),
    }
}

#[test]
fn coll_patch_happy_path_regression_guard() {
    // patch(0, [99], 2) on [1..5] → splice middle.
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], 0, vec![99], 2),
        vec![99, 3, 4, 5],
    );
}

#[test]
fn coll_patch_negative_from_clamps_to_zero() {
    // patch(-1, [99], 2): Scala chunk1 = 0, clampedReplaced = 2,
    // chunk2 = 5 - 0 - 2 = 3, suffix = xs[2..5] = [3,4,5].
    // Result must equal patch(0, [99], 2) — both clamp negative `from`.
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], -1, vec![99], 2),
        vec![99, 3, 4, 5],
    );
}

#[test]
fn coll_patch_negative_replaced_with_from_zero_is_pure_insertion() {
    // patch(0, [99], -1): Scala clampedReplaced = 0, chunk2 = 5,
    // suffix = xs[0..5]. Result = [] ++ [99] ++ xs = pure prepend.
    // Negative `replaced` does NOT throw; it clamps to 0.
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], 0, vec![99], -1),
        vec![99, 1, 2, 3, 4, 5],
    );
}

#[test]
fn coll_patch_negative_replaced_with_positive_from_is_insertion_at_from() {
    // patch(2, [99], -1): chunk1 = 2, clampedReplaced = 0,
    // chunk2 = 5 - 2 - 0 = 3, suffix = xs[2..5]. Result inserts at
    // index 2 without removing — equivalent to insertAt(2, [99]).
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], 2, vec![99], -1),
        vec![1, 2, 99, 3, 4, 5],
    );
}

#[test]
fn coll_patch_from_past_length_appends() {
    // patch(10, [99], 2) on [1..5]: chunk1 = min(10, 5) = 5,
    // clampedReplaced = 2, chunk2 = 5 - 5 - 2 = -2, no suffix.
    // Result = xs ++ [99].
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], 10, vec![99], 2),
        vec![1, 2, 3, 4, 5, 99],
    );
}

#[test]
fn coll_patch_replaced_past_remaining_truncates_tail() {
    // patch(2, [99], 100): chunk1 = 2, clampedReplaced = 100,
    // chunk2 = 5 - 2 - 100 = -97, no suffix. Result = [1,2] ++ [99].
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], 2, vec![99], 100),
        vec![1, 2, 99],
    );
}

#[test]
fn coll_patch_i32_max_from_clamps_to_length() {
    // patch(i32::MAX, [99], 1): chunk1 = min(i32::MAX, 5) = 5,
    // clampedReplaced = 1, chunk2 = 5 - 5 - 1 = -1, no suffix.
    // Result = xs ++ [99].
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], i32::MAX, vec![99], 1),
        vec![1, 2, 3, 4, 5, 99],
    );
}

#[test]
fn coll_patch_i32_min_from_clamps_to_zero() {
    // patch(i32::MIN, [99], 10): chunk1 = 0, clampedReplaced = 10,
    // chunk2 = 5 - 0 - 10 = -5, no suffix. Result = [99].
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], i32::MIN, vec![99], 10),
        vec![99],
    );
}

#[test]
fn coll_patch_i32_max_replaced_truncates_tail() {
    // patch(2, [99], i32::MAX): chunk1 = 2, clampedReplaced = i32::MAX,
    // chunk2 = 5 - 2 - i32::MAX (no JVM wrap, fits in i32 as a large
    // negative), no suffix. Result = [1,2] ++ [99].
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], 2, vec![99], i32::MAX),
        vec![1, 2, 99],
    );
}

#[test]
fn coll_patch_bytes_carrier_negative_from() {
    // Byte carrier — exercise the CollBytes splice arm at the negative
    // boundary so a future divergent fix can't slip through one carrier.
    let expr = coll_patch_call(
        const_bytes(vec![1, 2, 3, 4, 5]),
        -1,
        const_bytes(vec![99]),
        2,
    );
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[]).unwrap();
    match v {
        Value::CollBytes(c) => assert_eq!(c, vec![99, 3, 4, 5]),
        other => panic!("expected CollBytes, got {other:?}"),
    }
}

#[test]
fn coll_patch_long_carrier_negative_replaced() {
    // Long carrier, negative replaced — pure insertion at from=1.
    let expr = coll_patch_call(
        const_coll_long(vec![10, 20, 30]),
        1,
        const_coll_long(vec![99]),
        -5,
    );
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[]).unwrap();
    match v {
        Value::CollLong(c) => assert_eq!(c, vec![10, 99, 20, 30]),
        other => panic!("expected CollLong, got {other:?}"),
    }
}

// ----- Coll.indexOf / Slice negative-input guards -----
//
// These guard tests lock the contract split: any future "negative
// collection index" refactor that routes both `indexOf` and `Slice`
// through a single throws-on-negative helper would fail these tests.
// Scala's `indexOf_eval` at `methods.scala:1080-1100` explicitly
// clamps via `math.max(from, 0)`; Scala's `Slice.eval` at
// `transformers.scala:86-103` delegates to `Array.slice` which clamps
// both bounds. Both must silently clamp, not throw.

#[test]
fn coll_indexof_negative_from_clamps_to_zero() {
    // indexOf(2, -1) on [1,2,3]: Scala `math.max(-1, 0) = 0`,
    // loop finds 2 at index 1. Must match indexOf(2, 0).
    let coll = || const_coll_int(vec![1, 2, 3]);
    let elem = || const_int(2);
    let make = |from: i32| {
        op(
            0xDC,
            Payload::MethodCall {
                type_id: 12,
                method_id: 26,
                obj: Box::new(coll()),
                args: vec![elem(), const_int(from)],
                type_args: vec![],
            },
        )
    };
    let neg = run_eval(&make(-1));
    let zero = run_eval(&make(0));
    assert_eq!(
        neg, zero,
        "indexOf(elem, -1) must clamp to indexOf(elem, 0), not throw or no-op"
    );
    match neg {
        Value::Int(1) => {}
        other => panic!("expected Int(1), got {other:?}"),
    }
}

#[test]
fn slice_negative_from_clamps_to_zero() {
    // Slice(xs, -1, 3) on [1,2,3,4,5]: Scala clamps lo = max(-1, 0) = 0,
    // hi = min(max(3,0), 5) = 3, copies xs[0..3] = [1,2,3].
    // Must NOT throw.
    let expr = op(
        0xB4,
        Payload::Three(
            Box::new(const_coll_int(vec![1, 2, 3, 4, 5])),
            Box::new(const_int(-1)),
            Box::new(const_int(3)),
        ),
    );
    let v = run_eval(&expr);
    match v {
        Value::CollInt(c) => assert_eq!(c, vec![1, 2, 3]),
        other => panic!("expected CollInt [1,2,3], got {other:?}"),
    }
}

#[test]
fn slice_negative_until_returns_empty() {
    // Slice(xs, 0, -1) on [1,2,3]: hi clamps to 0, lo = 0, hi <= lo,
    // returns empty Coll. Must NOT throw.
    let expr = op(
        0xB4,
        Payload::Three(
            Box::new(const_coll_int(vec![1, 2, 3])),
            Box::new(const_int(0)),
            Box::new(const_int(-1)),
        ),
    );
    let v = run_eval(&expr);
    match v {
        Value::CollInt(c) => assert!(c.is_empty(), "expected empty CollInt, got {c:?}"),
        other => panic!("expected CollInt, got {other:?}"),
    }
}

#[test]
fn slice_until_less_than_from_returns_empty() {
    // Slice(xs, 4, 2): from > until → empty. Scala's `if (hi > lo)`
    // gate handles this. Must NOT throw.
    let expr = op(
        0xB4,
        Payload::Three(
            Box::new(const_coll_int(vec![1, 2, 3, 4, 5])),
            Box::new(const_int(4)),
            Box::new(const_int(2)),
        ),
    );
    let v = run_eval(&expr);
    match v {
        Value::CollInt(c) => assert!(c.is_empty(), "expected empty CollInt, got {c:?}"),
        other => panic!("expected CollInt, got {other:?}"),
    }
}

// ----- Slice cost-charge direction parity -----
//
// Scala's `transformers.scala::Slice.eval` charges
// `Math.max(0, until - from)` over the per-arg-clamped bounds
// **before** the length clamp. Our prior implementation charged over
// `sliced.len()` (post-len-clamp), which under-charges when
// `until > len` — a consensus-loosening direction. The fix moves
// the cost charge to use the pre-len-clamp `until - from` range,
// matching Scala.

// ----- Coll.updated / Coll.patch JIT cost parity -----
//
// Scala-source-anchored values from
// `sigmastate-interpreter/data/shared/src/main/scala/sigma/ast/methods.scala`:
//   - `UpdatedMethod` declares `PerItemCost(20, 1, 10)` charged over
//     `coll.length`.
//   - `PatchMethod` declares `PerItemCost(30, 2, 10)` charged over
//     `xs.length + patch.length`.
// Prior implementation routed both through `add_cost_per_item(0xDC, n)`
// which resolved to `Fixed(4)` regardless of `n` — under-charging vs.
// Scala. Closing the gap is consensus-tightening; the mainnet sync
// corpus (850-tx validation at heights 700000-700200) confirms no
// historical script trips the new cost limit.

/// Compute the per-method PerItemCost charge for a given n, matching
/// `CostKind::PerItem::compute`'s `base + perChunk * ceil(n/chunkSize)`.
fn per_item_compute(base: u32, per_chunk: u32, chunk_size: u32, n: u32) -> u32 {
    base + per_chunk * n.div_ceil(chunk_size)
}

#[test]
fn coll_updated_cost_exact_per_item_charge() {
    use ergo_primitives::cost::CostAccumulator;
    let ctx = ReductionContext::minimal(10_000_000, 0);
    // Run an `updated` call and another evaluation that's identical
    // EXCEPT for the receiver length. Subtract to isolate the
    // PerItemCost-driven delta — the constant cost contributors
    // (MethodCall dispatch, ByIndex on the Const, arg evals) cancel.
    let cost_for = |coll_size: usize| -> u32 {
        let coll: Vec<i32> = (0..coll_size as i32).collect();
        let expr = coll_updated_call(const_coll_int(coll), 0, const_int(99));
        let mut cost = CostAccumulator::recording_only();
        // `reduce_expr_with_cost` requires a final SigmaProp/Bool
        // reduction; CollInt-returning expressions error at the
        // outer reduction step. The cost we want is what's
        // accumulated BEFORE that final-stage check, so ignore
        // the result.
        let _ = reduce_expr_with_cost(&expr, &ctx, &[], &mut cost);
        cost.total().value() as u32
    };
    // Scala PerItemCost(20, 1, 10) at:
    //   n=3:  20 + 1*ceil(3/10)  = 20 + 1 = 21
    //   n=10: 20 + 1*ceil(10/10) = 20 + 1 = 21
    //   n=11: 20 + 1*ceil(11/10) = 20 + 2 = 22
    //   n=60: 20 + 1*ceil(60/10) = 20 + 6 = 26
    // Delta(n=60, n=3): expected_delta_updated = 26 - 21 = 5.
    let updated_delta_observed = cost_for(60) - cost_for(3);
    let expected_delta = per_item_compute(20, 1, 10, 60) - per_item_compute(20, 1, 10, 3);
    assert_eq!(
        updated_delta_observed, expected_delta,
        "Coll.updated delta between n=60 and n=3 must equal the Scala \
         PerItemCost(20, 1, 10) delta exactly (26 - 21 = 5)",
    );
    // Sanity-check the n=10 chunk-boundary: same chunks as n=3, so
    // delta should be 0 over the per-item portion (everything else
    // is constant since both calls evaluate the same n=10 input).
    let chunk_boundary_delta = cost_for(10) - cost_for(3);
    assert_eq!(
        chunk_boundary_delta, 0,
        "Cost at n=10 and n=3 must match (both fit in 1 chunk of 10): \
         PerItemCost(20, 1, 10) yields 21 for both",
    );
}

fn patch_call(obj: Expr, from: i32, patch: Expr, replaced: i32) -> Expr {
    op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 19,
            obj: Box::new(obj),
            args: vec![const_int(from), patch, const_int(replaced)],
            type_args: vec![],
        },
    )
}

#[test]
fn coll_patch_cost_exact_per_item_charge() {
    use ergo_primitives::cost::CostAccumulator;
    let ctx = ReductionContext::minimal(10_000_000, 0);
    let cost_for = |xs_size: usize, patch_size: usize| -> u32 {
        let xs: Vec<i32> = (0..xs_size as i32).collect();
        let patch: Vec<i32> = (0..patch_size as i32).collect();
        let expr = patch_call(const_coll_int(xs), 1, const_coll_int(patch), 1);
        let mut cost = CostAccumulator::recording_only();
        // `reduce_expr_with_cost` requires a final SigmaProp/Bool
        // reduction; CollInt-returning expressions error at the
        // outer reduction step. The cost we want is what's
        // accumulated BEFORE that final-stage check, so ignore
        // the result.
        let _ = reduce_expr_with_cost(&expr, &ctx, &[], &mut cost);
        cost.total().value() as u32
    };
    // Scala PerItemCost(30, 2, 10) charged over xs.length + patch.length.
    //   n=5 (xs=3, patch=2): 30 + 2*ceil(5/10) = 30 + 2 = 32
    //   n=70 (xs=50, patch=20): 30 + 2*ceil(70/10) = 30 + 14 = 44
    // Delta should equal Scala formula delta exactly.
    let observed_delta = cost_for(50, 20) - cost_for(3, 2);
    let expected_delta = per_item_compute(30, 2, 10, 70) - per_item_compute(30, 2, 10, 5);
    assert_eq!(
        observed_delta, expected_delta,
        "Coll.patch delta between (xs=50, patch=20, n=70) and \
         (xs=3, patch=2, n=5) must equal the Scala PerItemCost(30, 2, 10) \
         delta exactly (44 - 32 = 12)",
    );
}

#[test]
fn slice_cost_charges_over_pre_len_clamp_range() {
    use ergo_primitives::cost::CostAccumulator;
    // Slice(xs, 0, 1000) on a 5-element coll: the actual result has
    // length 5 (clamped by len), but Scala charges cost over
    // `until - from = 1000` — far higher than `sliced.len() = 5`.
    let expr = op(
        0xB4,
        Payload::Three(
            Box::new(const_coll_int(vec![1, 2, 3, 4, 5])),
            Box::new(const_int(0)),
            Box::new(const_int(1000)),
        ),
    );
    let ctx = ReductionContext::minimal(10_000_000, 0);
    let mut cost_pre_clamp = CostAccumulator::recording_only();
    let _ = reduce_expr_with_cost(&expr, &ctx, &[], &mut cost_pre_clamp);

    // Same op with `until == len`: cost should be lower than the
    // 1000-cap variant by enough to confirm the pre-clamp behavior
    // (the per-item-cost delta scales with the cap).
    let expr_at_len = op(
        0xB4,
        Payload::Three(
            Box::new(const_coll_int(vec![1, 2, 3, 4, 5])),
            Box::new(const_int(0)),
            Box::new(const_int(5)),
        ),
    );
    let mut cost_at_len = CostAccumulator::recording_only();
    let _ = reduce_expr_with_cost(&expr_at_len, &ctx, &[], &mut cost_at_len);

    assert!(
        cost_pre_clamp.total().value() > cost_at_len.total().value(),
        "Slice(_, 0, 1000) must charge more than Slice(_, 0, 5) under the \
         pre-len-clamp Scala-parity formula. Got 1000-variant={}, \
         at-len-variant={}",
        cost_pre_clamp.total().value(),
        cost_at_len.total().value(),
    );
}

// ----- CollShort higher-order cost parity -----
//
// The `Coll[Byte]` carrier work added the missing `CollShort` arm to
// `collection_len`; before the fix the helper returned 0 for any
// `CollShort` receiver, silently zero-iterating every higher-order
// opcode (`map`, `filter`, `fold`, `exists`, `forall`) over Coll[Short]
// and under-charging cost by the per-item rate * n.
//
// These tests pin the post-fix behavior: cost.total() for a higher-
// order opcode on `Coll[Short]` of length N must scale with N at the
// same Scala-anchored per-item rate as the equivalent `Coll[Int]`
// call (per-item rate is keyed on the opcode, not the element-coll
// carrier — see `cost_table::opcode_cost` 0xAD/0xAE/0xAF/0xB0/0xB5).
//
// Self-anchored against the Coll[Int] path because:
//   1. `Coll[Int]` higher-order parity is already pinned by the
//      mainnet sync corpus + per-opcode JIT cost work.
//   2. The opcode-level per-item rate from `cost_table::opcode_cost`
//      is keyed solely on the opcode byte, not the receiver carrier;
//      so equal-length Coll[Short]/Coll[Int] must charge identically
//      at the per-item layer.
//   3. Any future regression to the zero-iteration bug would surface
//      as `cost_short == base only` (per-item layer skipped), which
//      these deltas catch immediately.

fn cost_of(expr: &Expr) -> u64 {
    let ctx = ReductionContext::minimal(10_000_000, 0);
    let mut cost = CostAccumulator::recording_only();
    let _ = reduce_expr_with_cost(expr, &ctx, &[], &mut cost);
    cost.total().value()
}

/// 1-arg `Func` over `tpe` whose body ignores the bound argument
/// and returns a constant. Lets cost comparisons across element
/// carriers (Coll[Short] vs Coll[Int]) isolate the per-item layer
/// — body cost is identical regardless of carrier because the
/// argument is never touched.
fn const_pred_of(tpe: SigmaType, body: Expr) -> Expr {
    op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(tpe))],
            body: Box::new(body),
        },
    )
}

/// Functional CollShort regressions for the higher-order opcodes.
/// Cost-parity tests below isolate the per-item layer; these pin
/// VALUE behavior — without them a future regression in carrier
/// reconstruction could keep identical costs and still produce
/// silently-wrong results.
#[test]
fn coll_short_filter_returns_kept_items() {
    // Filter Coll[Short]([-2, -1, 0, 1, 2]) with predicate `_ => true`
    // returns the full coll unchanged (5 shorts).
    let filter = op(
        0xB5,
        Payload::Two(
            Box::new(const_coll_short(vec![-2, -1, 0, 1, 2])),
            Box::new(const_pred_of(SigmaType::SShort, op(0x7F, Payload::Zero))),
        ),
    );
    let result = run_eval(&filter);
    assert_eq!(
        result,
        Value::CollShort(vec![-2, -1, 0, 1, 2]),
        "Filter Coll[Short] _ => true must preserve all items and \
         carrier kind",
    );
}

#[test]
fn coll_short_exists_returns_true_on_match() {
    let exists = op(
        0xAE,
        Payload::Two(
            Box::new(const_coll_short(vec![1, 2, 3])),
            Box::new(const_pred_of(SigmaType::SShort, op(0x7F, Payload::Zero))),
        ),
    );
    assert_eq!(run_eval(&exists), Value::Bool(true));
}

#[test]
fn coll_short_forall_returns_true_when_all_match() {
    let forall = op(
        0xAF,
        Payload::Two(
            Box::new(const_coll_short(vec![1, 2, 3])),
            Box::new(const_pred_of(SigmaType::SShort, op(0x7F, Payload::Zero))),
        ),
    );
    assert_eq!(run_eval(&forall), Value::Bool(true));
}

#[test]
fn coll_short_fold_accumulates_acc() {
    // Fold with body `(acc, _) => acc` over a length-3 coll: zero
    // remains zero. Pin both the iteration count (visible via cost
    // tests above) and the value reduction.
    let fold = op(
        0xB0,
        Payload::Three(
            Box::new(const_coll_short(vec![10, 20, 30])),
            Box::new(const_int(7)),
            Box::new(op(
                0xD9,
                Payload::FuncValue {
                    args: vec![(1, Some(SigmaType::SInt)), (2, Some(SigmaType::SShort))],
                    body: Box::new(op(0x72, Payload::ValUse { id: 1 })),
                },
            )),
        ),
    );
    assert_eq!(run_eval(&fold), Value::Int(7));
}

/// `SizeOf` (0xB1) — pins the regression: pre-fix `collection_len`
/// returned 0 for CollShort and the SizeOf opcode had no CollShort
/// arm (a real bug surfaced by this test pass — fixed in same
/// commit by adding `Value::CollShort(v) => Ok(Value::Int(v.len()
/// as i32))` to `eval_size_of`). Post-fix, it returns the actual
/// length matching the equivalent Coll[Int] call.
#[test]
fn coll_short_size_of_matches_coll_int_size() {
    let shorts = const_coll_short(vec![1, 2, 3, 4, 5]);
    let ints = const_coll_int(vec![1, 2, 3, 4, 5]);
    let size_short = op(0xB1, Payload::One(Box::new(shorts)));
    let size_int = op(0xB1, Payload::One(Box::new(ints)));
    assert_eq!(run_eval(&size_short), Value::Int(5));
    assert_eq!(run_eval(&size_int), Value::Int(5));
    // Cost must match too — the SizeOf op cost is independent of
    // element carrier (both are Coll receivers of length 5).
    assert_eq!(
        cost_of(&size_short),
        cost_of(&size_int),
        "SizeOf cost on Coll[Short] must equal SizeOf cost on Coll[Int] \
         at the same length",
    );
}

/// `MapCollection` (0xAD) — per-item cost scales with N at the
/// Scala-anchored `per_item(20, 1, 10)` rate. Pre-fix this would
/// have zero-iterated (silent regression in cost.total()) and the
/// delta would be flat. Post-fix the delta scales with N at the
/// same rate as Coll[Int].
#[test]
fn coll_short_map_cost_scales_with_length_and_matches_coll_int_layer() {
    let map_short_n = |n: usize| {
        op(
            0xAD,
            Payload::Two(
                Box::new(const_coll_short((0..n as i16).collect())),
                Box::new(const_pred_of(SigmaType::SShort, const_int(0))),
            ),
        )
    };
    let map_int_n = |n: usize| {
        op(
            0xAD,
            Payload::Two(
                Box::new(const_coll_int((0..n as i32).collect())),
                Box::new(const_pred_of(SigmaType::SInt, const_int(0))),
            ),
        )
    };
    let short_5 = cost_of(&map_short_n(5));
    let short_50 = cost_of(&map_short_n(50));
    let int_5 = cost_of(&map_int_n(5));
    let int_50 = cost_of(&map_int_n(50));
    assert!(
        short_50 > short_5,
        "MapCollection cost on Coll[Short] must grow with N (regression \
         pin against silent zero-iteration). short_5={short_5}, \
         short_50={short_50}",
    );
    // The per-item-rate (opcode-keyed) plus AddToEnv (5/element) plus
    // the constant-body cost are all carrier-independent when the
    // body ignores the bound argument. Strict equality between
    // short/int at the same N proves the per-item layer ran the
    // correct number of iterations.
    assert_eq!(
        short_5, int_5,
        "MapCollection cost on Coll[Short](5) must equal Coll[Int](5) \
         when the body ignores the bound argument",
    );
    assert_eq!(short_50, int_50, "same per-item-layer parity at N=50");
}

/// `Filter` (0xB5) — per-item rate `per_item(20, 1, 10)`. The
/// constant-body shape always returns `true`, so every element is
/// retained; iteration count = N for both carriers.
#[test]
fn coll_short_filter_cost_matches_coll_int_layer() {
    let filter_short = op(
        0xB5,
        Payload::Two(
            Box::new(const_coll_short((0..20i16).collect())),
            Box::new(const_pred_of(
                SigmaType::SShort,
                op(0x7F, Payload::Zero), // True
            )),
        ),
    );
    let filter_int = op(
        0xB5,
        Payload::Two(
            Box::new(const_coll_int((0..20i32).collect())),
            Box::new(const_pred_of(
                SigmaType::SInt,
                op(0x7F, Payload::Zero), // True
            )),
        ),
    );
    assert_eq!(cost_of(&filter_short), cost_of(&filter_int));
}

/// `Exists` (0xAE) — per-item rate `per_item(3, 1, 10)`. The
/// constant-body shape always returns `true`, so Exists
/// short-circuits on the first element for both carriers and the
/// iteration counts match.
#[test]
fn coll_short_exists_cost_matches_coll_int_layer() {
    let exists_short = op(
        0xAE,
        Payload::Two(
            Box::new(const_coll_short((0..15i16).collect())),
            Box::new(const_pred_of(SigmaType::SShort, op(0x7F, Payload::Zero))),
        ),
    );
    let exists_int = op(
        0xAE,
        Payload::Two(
            Box::new(const_coll_int((0..15i32).collect())),
            Box::new(const_pred_of(SigmaType::SInt, op(0x7F, Payload::Zero))),
        ),
    );
    assert_eq!(cost_of(&exists_short), cost_of(&exists_int));
}

/// `ForAll` (0xAF) — per-item rate `per_item(3, 1, 10)`. Constant-
/// body `true` runs through all N elements without short-circuit.
#[test]
fn coll_short_forall_cost_matches_coll_int_layer() {
    let forall_short = op(
        0xAF,
        Payload::Two(
            Box::new(const_coll_short((0..15i16).collect())),
            Box::new(const_pred_of(SigmaType::SShort, op(0x7F, Payload::Zero))),
        ),
    );
    let forall_int = op(
        0xAF,
        Payload::Two(
            Box::new(const_coll_int((0..15i32).collect())),
            Box::new(const_pred_of(SigmaType::SInt, op(0x7F, Payload::Zero))),
        ),
    );
    assert_eq!(cost_of(&forall_short), cost_of(&forall_int));
}

/// `Fold` (0xB0) — per-item rate `per_item(3, 1, 10)`. The 2-arg
/// body ignores `elem` and returns `acc` directly, so per-element
/// body cost is identical between Coll[Short] and Coll[Int]
/// receivers — isolates the per-item layer at the opcode-keyed
/// rate.
#[test]
fn coll_short_fold_cost_matches_coll_int_layer() {
    // 2-arg fold body: (acc: Int, elem: T) => acc. T differs per
    // carrier but is unused; body cost is the ValUse(1) load.
    let fold_body = |elem_ty: SigmaType| {
        op(
            0xD9,
            Payload::FuncValue {
                args: vec![(1, Some(SigmaType::SInt)), (2, Some(elem_ty))],
                body: Box::new(op(0x72, Payload::ValUse { id: 1 })),
            },
        )
    };
    let fold_short = op(
        0xB0,
        Payload::Three(
            Box::new(const_coll_short((0..15i16).collect())),
            Box::new(const_int(0)),
            Box::new(fold_body(SigmaType::SShort)),
        ),
    );
    let fold_int = op(
        0xB0,
        Payload::Three(
            Box::new(const_coll_int((0..15i32).collect())),
            Box::new(const_int(0)),
            Box::new(fold_body(SigmaType::SInt)),
        ),
    );
    assert_eq!(cost_of(&fold_short), cost_of(&fold_int));
}

/// Per-item rate isolation: at the same opcode the cost-delta
/// between N=50 and N=5 must equal the Scala-anchored
/// `per_item_compute(base, perChunk, chunkSize, 50) -
/// per_item_compute(..., 5)` exactly, plus the per-element cost
/// of (AddToEnv + body) * 45. The body-cost-per-element factor
/// drops out when the body is constant, so the delta isolates
/// the per-item rate plus AddToEnv.
///
/// AddToEnv is `fixed(5)` per element. Per-element constant-body
/// cost is `5` (ConstLoad). So delta per element = 5 + 5 + 0 = 10
/// (plus the carrier-independent per-item-rate delta).
#[test]
fn coll_short_map_per_item_delta_matches_coll_int() {
    let map_short = |n: usize| {
        op(
            0xAD,
            Payload::Two(
                Box::new(const_coll_short((0..n as i16).collect())),
                Box::new(const_pred_of(SigmaType::SShort, const_int(0))),
            ),
        )
    };
    let map_int = |n: usize| {
        op(
            0xAD,
            Payload::Two(
                Box::new(const_coll_int((0..n as i32).collect())),
                Box::new(const_pred_of(SigmaType::SInt, const_int(0))),
            ),
        )
    };
    let short_delta = cost_of(&map_short(50)) - cost_of(&map_short(5));
    let int_delta = cost_of(&map_int(50)) - cost_of(&map_int(5));
    assert_eq!(
        short_delta, int_delta,
        "Per-item cost delta on MapCollection must be identical between \
         Coll[Short] and Coll[Int] (opcode-keyed per-item rate, not \
         carrier-keyed). Δshort={short_delta}, Δint={int_delta}",
    );
    // The delta must also equal the Scala-anchored sum of:
    //   per_item_compute(20, 1, 10, 50) - per_item_compute(20, 1, 10, 5) +
    //   (AddToEnv(5) + body-const-load(5)) * 45
    // Asserting against this absolute expectation pins the rate.
    let rate_delta = per_item_compute(20, 1, 10, 50) - per_item_compute(20, 1, 10, 5);
    let per_elem_delta = 10 * 45;
    let expected = rate_delta as u64 + per_elem_delta;
    assert_eq!(
        short_delta, expected,
        "MapCollection Δ(N=50, N=5) must equal the Scala-anchored \
         per_item_compute(20,1,10) delta plus 10*45 AddToEnv+body cost. \
         Expected={expected}, got={short_delta}",
    );
}

// ---- AtLeast (0x98) cost: Scala PerItemCost(base=20, perChunk=3, chunkSize=5) ----
// `sigma.ast.AtLeast.costKind` is charged via `addSeqCost(costKind,
// props.length)`. Scala `chunks(n) = (n-1)/chunkSize + 1` with JVM
// truncation toward zero, so for chunkSize=5: chunks(0)=1 (-1/5=0), and
// cost(n) = 20 + 3*chunks(n): cost(0..=5)=23, cost(6..=10)=26, ...

#[test]
fn atleast_cost_kind_matches_scala_peritem_20_3_5() {
    let ck = crate::cost_table::opcode_cost(0x98).unwrap();
    for (n, want) in [
        (0u32, 23u64),
        (1, 23),
        (2, 23),
        (5, 23),
        (6, 26),
        (10, 26),
        (11, 29),
    ] {
        assert_eq!(
            ck.compute(n).unwrap().value(),
            want,
            "AtLeast PerItemCost(20,3,5).cost(n={n})",
        );
    }
}

#[test]
fn atleast_eval_total_cost_matches_scala() {
    // AtLeast(Int 2, Coll[SigmaProp]([true, true])): one bound constant (5),
    // one collection constant (5), and the AtLeast PerItemCost(20,3,5).cost(2)
    // = 23 — total 33.
    use ergo_ser::sigma_value::CollValue;
    let bound = const_int(2);
    let items = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
        val: SigmaValue::Coll(CollValue::Values(vec![
            SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
            SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
        ])),
    };
    let expr = op(0x98, Payload::Two(Box::new(bound), Box::new(items)));
    let cx = ReductionContext::minimal(500_000, 0);
    let mut cost = CostAccumulator::recording_only();
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut trace = None;
    eval_expr(&expr, &cx, &[], &mut env, &mut depth, &mut cost, &mut trace).unwrap();
    assert_eq!(
        cost.total().value(),
        33,
        "AtLeast(2, [true,true]) total cost: 5 (bound) + 5 (coll) + 23 (AtLeast)",
    );
}

// ---- v6 UnsignedBigInt arithmetic (ArithOp on SUnsignedBigInt) ----
//
// SUnsignedBigInt is NOT SBigInt, so ArithOp's TypeBasedCost
// (`sigma.ast.ArithOp.{Plus,Minus,Multiply,Division,Modulo}.costKind`:
// `case SBigInt => 20/25; case _ => 15`) charges the default 15 for every
// UnsignedBigInt arithmetic op. Values follow `CUnsignedBigInt`
// (core/.../sigma/data/CUnsignedBigInt.scala): add/subtract/multiply route
// their result through `toUnsignedBigIntValueExact` — EXACT, not modular:
// the result must satisfy `0 <= r && r.bitLength() <= 256` (i.e. r in
// [0, 2^256-1]) or an ArithmeticException is thrown. divide is
// BigInteger.divide (truncating, both operands non-negative); mod is
// BigInteger.mod, which throws on a non-positive (here: zero) modulus and
// otherwise returns the non-negative remainder in [0, m).

/// An `SUnsignedBigInt` CONSTANT carrying `v` (must be in [0, 2^256-1] for a
/// legal value; eval rejects a negative magnitude).
fn const_ubi(v: num_bigint::BigInt) -> Expr {
    Expr::Const {
        tpe: SigmaType::SUnsignedBigInt,
        val: SigmaValue::BigInt(v),
    }
}

fn ubi(v: i64) -> num_bigint::BigInt {
    num_bigint::BigInt::from(v)
}

/// `op(left, right)` where `op` is a binary ArithOp opcode, both operands
/// `SUnsignedBigInt` constants.
fn ubi_arith(opcode: u8, a: num_bigint::BigInt, b: num_bigint::BigInt) -> Expr {
    op(
        opcode,
        Payload::Two(Box::new(const_ubi(a)), Box::new(const_ubi(b))),
    )
}

#[test]
fn ubi_arith_values_match_cunsignedbigint() {
    let cx = ReductionContext::minimal(500_000, 0);
    let max: num_bigint::BigInt = (num_bigint::BigInt::from(1) << 256u32) - ubi(1); // 2^256 - 1
    let two_127 = num_bigint::BigInt::from(1) << 127u32;
    let two_128 = num_bigint::BigInt::from(1) << 128u32;
    let two_255 = num_bigint::BigInt::from(1) << 255u32;
    let cases: &[(
        u8,
        num_bigint::BigInt,
        num_bigint::BigInt,
        num_bigint::BigInt,
    )] = &[
        (0x9A, ubi(3), ubi(5), ubi(8)),                    // plus-small
        (0x9A, max.clone() - ubi(1), ubi(1), max.clone()), // plus-to-max (boundary OK)
        (0x99, ubi(5), ubi(3), ubi(2)),                    // minus-small
        (0x99, ubi(7), ubi(7), ubi(0)),                    // minus-to-zero
        (0x9C, ubi(3), ubi(5), ubi(15)),                   // multiply-small
        (0x9C, two_128.clone(), two_127.clone(), two_255), // multiply-big (boundary OK)
        (0x9D, ubi(7), ubi(2), ubi(3)),                    // divide-floor
        (0x9E, ubi(7), ubi(5), ubi(2)),                    // mod-small
    ];
    for (opcode, a, b, want) in cases {
        assert_eq!(
            eval_to_value(&ubi_arith(*opcode, a.clone(), b.clone()), &cx, &[]).unwrap(),
            Value::UnsignedBigInt(want.clone()),
            "0x{opcode:02X}({a}, {b})",
        );
    }
}

#[test]
fn ubi_arith_exact_bounds_and_zero_divisor_throw() {
    let cx = ReductionContext::minimal(500_000, 0);
    let max: num_bigint::BigInt = (num_bigint::BigInt::from(1) << 256u32) - ubi(1); // 2^256 - 1
    let two_255 = num_bigint::BigInt::from(1) << 255u32;
    // (opcode, a, b, why)
    let cases: &[(u8, num_bigint::BigInt, num_bigint::BigInt, &str)] = &[
        (0x9A, max.clone(), ubi(1), "plus overflow > 2^256-1"),
        (0x99, ubi(3), ubi(5), "minus underflow < 0"),
        (0x9C, two_255.clone(), ubi(2), "multiply overflow = 2^256"),
        (0x9D, ubi(7), ubi(0), "divide by zero"),
        (0x9E, ubi(7), ubi(0), "modulo by zero"),
    ];
    for (opcode, a, b, why) in cases {
        assert!(
            matches!(
                eval_to_value(&ubi_arith(*opcode, a.clone(), b.clone()), &cx, &[]),
                Err(EvalError::RuntimeException(_))
            ),
            "0x{opcode:02X} must throw RuntimeException: {why}",
        );
    }
}

#[test]
fn ubi_min_max_values_and_cost() {
    // SUnsignedBigInt is in ArithOp.impls, so Min/Max (0xA1/0xA2) are
    // consensus-reachable: `impl.o.{min,max}` via UnsignedBigIntOrdering.
    // Cost is the `case _ => 5` default; with two placeholders the total is
    // 1 + 1 + 5 = 7.
    let cx = ReductionContext::minimal(500_000, 0);
    // direct-constant value checks
    assert_eq!(
        eval_to_value(&ubi_arith(0xA1, ubi(7), ubi(5)), &cx, &[]).unwrap(),
        Value::UnsignedBigInt(ubi(5)),
        "min(7,5)",
    );
    assert_eq!(
        eval_to_value(&ubi_arith(0xA2, ubi(7), ubi(5)), &cx, &[]).unwrap(),
        Value::UnsignedBigInt(ubi(7)),
        "max(7,5)",
    );
    // cost via placeholders
    let constants = vec![
        (SigmaType::SUnsignedBigInt, SigmaValue::BigInt(ubi(7))),
        (SigmaType::SUnsignedBigInt, SigmaValue::BigInt(ubi(5))),
    ];
    for opcode in [0xA1_u8, 0xA2] {
        let body = op(
            opcode,
            Payload::Two(
                Box::new(op(0x73, Payload::ConstPlaceholder { index: 0 })),
                Box::new(op(0x73, Payload::ConstPlaceholder { index: 1 })),
            ),
        );
        let mut cost = CostAccumulator::recording_only();
        let mut env = Env::new();
        let mut depth = 0usize;
        let mut trace = None;
        eval_expr(
            &body, &cx, &constants, &mut env, &mut depth, &mut cost, &mut trace,
        )
        .unwrap();
        assert_eq!(
            cost.total().value(),
            7,
            "0x{opcode:02X} UnsignedBigInt min/max total cost must be 7 (1 + 1 + 5)",
        );
    }
}

#[test]
fn ubi_arith_cost_is_17_via_constant_placeholders() {
    // Mirror the SANTA vector exactly: segregated constants + the body
    // `Plus(ConstPlaceholder(0), ConstPlaceholder(1))`. Cost =
    // 1 (placeholder) + 1 (placeholder) + 15 (ArithOp `case _`) = 17.
    let cx = ReductionContext::minimal(500_000, 0);
    // 7 and 5 keep every op in range: +12, -2, *35, /1, %2.
    let constants = vec![
        (SigmaType::SUnsignedBigInt, SigmaValue::BigInt(ubi(7))),
        (SigmaType::SUnsignedBigInt, SigmaValue::BigInt(ubi(5))),
    ];
    for opcode in [0x9A_u8, 0x99, 0x9C, 0x9D, 0x9E] {
        let body = op(
            opcode,
            Payload::Two(
                Box::new(op(0x73, Payload::ConstPlaceholder { index: 0 })),
                Box::new(op(0x73, Payload::ConstPlaceholder { index: 1 })),
            ),
        );
        let mut cost = CostAccumulator::recording_only();
        let mut env = Env::new();
        let mut depth = 0usize;
        let mut trace = None;
        let v = eval_expr(
            &body, &cx, &constants, &mut env, &mut depth, &mut cost, &mut trace,
        )
        .unwrap_or_else(|e| panic!("0x{opcode:02X} eval failed: {e:?}"));
        assert!(
            matches!(v, Value::UnsignedBigInt(_)),
            "0x{opcode:02X} must yield UnsignedBigInt, got {v:?}",
        );
        assert_eq!(
            cost.total().value(),
            17,
            "0x{opcode:02X} UnsignedBigInt arith total cost must be 17 \
             (1 + 1 placeholders + 15 ArithOp default)",
        );
    }
}

// ---- Coll.indices (12,14) cost: Scala PerItemCost(20, 2, 16) ----
// `SCollection.IndicesMethod_CostKind = PerItemCost(20, 2, 16)`, not a flat
// 20. For small collections chunks(n) = (n-1)/16+1 = 1, so cost(n)=22 for
// n in 0..=16; n in 17..=32 -> 24, etc.

fn eval_total(expr: &Expr) -> u64 {
    let cx = ReductionContext::minimal(10_000_000, 0);
    let mut cost = CostAccumulator::recording_only();
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut trace = None;
    eval_expr(expr, &cx, &[], &mut env, &mut depth, &mut cost, &mut trace).unwrap();
    cost.total().value()
}

#[test]
fn coll_indices_cost_matches_scala_peritem_20_2_16() {
    // PropertyCall(12,14) on a Coll[Int] const: 4 (PropertyCall 0xDB) +
    // 5 (coll const) + IndicesCost. IndicesCost(n<=16)=22, (17..=32)=24.
    let indices = |coll: Expr| {
        op(
            0xDB,
            Payload::MethodCall {
                type_id: 12,
                method_id: 14,
                obj: Box::new(coll),
                args: vec![],
                type_args: vec![],
            },
        )
    };
    // size 2 -> chunks(2)=1 -> 22; total 4 + 5 + 22 = 31
    assert_eq!(
        eval_total(&indices(const_coll_int(vec![1, 2]))),
        31,
        "indices over Coll[Int] size 2: 4 + 5 + PerItem(20,2,16).cost(2)=22",
    );
    // size 20 -> chunks(20)=(20-1)/16+1=2 -> 20+2*2=24; total 4 + 5 + 24 = 33
    assert_eq!(
        eval_total(&indices(const_coll_int((0..20).collect()))),
        33,
        "indices over Coll[Int] size 20: 4 + 5 + PerItem(20,2,16).cost(20)=24",
    );
}

// ---- Option.map (36,7) cost: Scala FixedCost(20) + lambda AddToEnv(5) ----
// `SOption.MapMethod.costKind = FixedCost(JitCost(20))` (we charged 10), and
// applying the lambda to a Some value charges AddToEnv(5) like every other
// HOF lambda application (Coll.map etc.). None applies no lambda.

fn option_map_inc(obj: Expr) -> Expr {
    // obj.map((y: Int) => y + 1) as MethodCall(36, 7)
    let lambda = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(2, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x9A,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 2 })),
                    Box::new(const_int(1)),
                ),
            )),
        },
    );
    op(
        0xDC,
        Payload::MethodCall {
            type_id: 36,
            method_id: 7,
            obj: Box::new(obj),
            args: vec![lambda],
            type_args: vec![],
        },
    )
}

#[test]
fn option_map_cost_matches_scala_fixed20_plus_addtoenv() {
    // Some(5).map(y => y+1): 4 (MethodCall) + 5 (obj const) + 20 (map) +
    // 5 (FuncValue arg) + 5 (AddToEnv) + body[ValUse 5 + Const 5 + Plus 15
    // = 25] = 64.
    let some = Expr::Const {
        tpe: SigmaType::SOption(Box::new(SigmaType::SInt)),
        val: SigmaValue::Opt(Some(Box::new(SigmaValue::Int(5)))),
    };
    assert_eq!(
        eval_total(&option_map_inc(some)),
        64,
        "Some.map: 4 + 5 + 20 (map) + 5 (func) + 5 (AddToEnv) + 25 (body)",
    );
    // None.map(...): 4 + 5 (obj const) + 20 (map) + 5 (FuncValue) = 34 (no
    // lambda application, no AddToEnv, no body).
    let none = Expr::Const {
        tpe: SigmaType::SOption(Box::new(SigmaType::SInt)),
        val: SigmaValue::Opt(None),
    };
    assert_eq!(
        eval_total(&option_map_inc(none)),
        34,
        "None.map: 4 + 5 + 20 (map) + 5 (func)",
    );
}

// ---- Coll.updateMany (12,21): Scala CollOverArray.updateMany + PerItemCost(20,2,10) ----
// `coll.updateMany(indexes, values)`: requireSameLength(indexes, values)
// (throw on mismatch), then for each i write resArr[indexes[i]] = values[i]
// with an out-of-range index throwing IndexOutOfBoundsException (duplicate
// indexes allowed, in order). Cost = PerItemCost(20, 2, 10) over the
// RECEIVER length.

fn coll_update_many(recv: Expr, indexes: Expr, values: Expr) -> Expr {
    op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 21,
            obj: Box::new(recv),
            args: vec![indexes, values],
            type_args: vec![],
        },
    )
}

#[test]
fn coll_update_many_value_and_bounds() {
    let cx = ReductionContext::minimal(500_000, 0);
    // [1,2,3].updateMany([0,2],[10,30]) -> [10,2,30]
    assert_eq!(
        eval_to_value(
            &coll_update_many(
                const_coll_int(vec![1, 2, 3]),
                const_coll_int(vec![0, 2]),
                const_coll_int(vec![10, 30]),
            ),
            &cx,
            &[],
        )
        .unwrap(),
        Value::CollInt(vec![10, 2, 30]),
    );
    // duplicate index, last write wins (in order): [1,2].updateMany([0,0],[7,9]) -> [9,2]
    assert_eq!(
        eval_to_value(
            &coll_update_many(
                const_coll_int(vec![1, 2]),
                const_coll_int(vec![0, 0]),
                const_coll_int(vec![7, 9]),
            ),
            &cx,
            &[],
        )
        .unwrap(),
        Value::CollInt(vec![9, 2]),
    );
    // out-of-range index throws: [1].updateMany([5],[0])
    assert!(matches!(
        eval_to_value(
            &coll_update_many(
                const_coll_int(vec![1]),
                const_coll_int(vec![5]),
                const_coll_int(vec![0]),
            ),
            &cx,
            &[],
        ),
        Err(EvalError::RuntimeException(_))
    ));
    // empty receiver, index 0 -> out of range throws (mirrors nice vector #0)
    assert!(matches!(
        eval_to_value(
            &coll_update_many(
                const_coll_int(vec![]),
                const_coll_int(vec![0]),
                const_coll_int(vec![0]),
            ),
            &cx,
            &[],
        ),
        Err(EvalError::RuntimeException(_))
    ));
    // length mismatch throws: [1,2].updateMany([0,1],[0])
    assert!(matches!(
        eval_to_value(
            &coll_update_many(
                const_coll_int(vec![1, 2]),
                const_coll_int(vec![0, 1]),
                const_coll_int(vec![0]),
            ),
            &cx,
            &[],
        ),
        Err(EvalError::RuntimeException(_))
    ));
}

#[test]
fn coll_update_many_cost_matches_scala() {
    // MethodCall(4) + obj const(5) + indexes const(5) + values const(5) +
    // updateMany PerItemCost(20,2,10).cost(3): chunks(3)=(3-1)/10+1=1 -> 22.
    // Total 4 + 5 + 5 + 5 + 22 = 41.
    let expr = coll_update_many(
        const_coll_int(vec![1, 2, 3]),
        const_coll_int(vec![0, 2]),
        const_coll_int(vec![10, 30]),
    );
    let cx = ReductionContext::minimal(500_000, 0);
    let mut cost = CostAccumulator::recording_only();
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut trace = None;
    eval_expr(&expr, &cx, &[], &mut env, &mut depth, &mut cost, &mut trace).unwrap();
    assert_eq!(
        cost.total().value(),
        41,
        "updateMany over receiver len 3: 4 + 5 + 5 + 5 + PerItem(20,2,10).cost(3)=22",
    );
}

#[test]
fn coll_update_many_rejects_mismatched_value_type() {
    let cx = ReductionContext::minimal(500_000, 0);
    // Writing a Long into a Coll[Int] receiver mirrors Scala's Array[Int]
    // store of a boxed Long -> ArrayStoreException. Reject.
    assert!(matches!(
        eval_to_value(
            &coll_update_many(
                const_coll_int(vec![1, 2]),
                const_coll_int(vec![0]),
                const_coll_long(vec![5]),
            ),
            &cx,
            &[],
        ),
        Err(EvalError::TypeError { .. })
    ));
    // But an EMPTY mismatched values collection writes nothing, so it is
    // accepted (returns the receiver clone) — matching Scala, which only
    // touches `values` per written index. The indexes carrier is likewise
    // erased: an empty non-Int indexes collection (Coll[Long]()) passes
    // requireSameLength and the zero-iteration loop, returning the clone.
    assert_eq!(
        eval_to_value(
            &coll_update_many(
                const_coll_int(vec![1, 2]),
                const_coll_long(vec![]),
                const_coll_long(vec![]),
            ),
            &cx,
            &[],
        )
        .unwrap(),
        Value::CollInt(vec![1, 2]),
    );
    // A NON-empty non-Int indexes collection IS rejected — but only once an
    // index is actually read and cast to Int. The lengths must match first
    // (requireSameLength precedes the per-index cast), so values is length 1
    // here; the Long index then fails the Int cast -> TypeError.
    assert!(matches!(
        eval_to_value(
            &coll_update_many(
                const_coll_int(vec![1, 2]),
                const_coll_long(vec![0]),
                const_coll_int(vec![5]),
            ),
            &cx,
            &[],
        ),
        Err(EvalError::TypeError { .. })
    ));
    // The same non-Int indexes paired with an EMPTY values collection is a
    // length mismatch, which throws BEFORE any index is read —
    // RuntimeException, not TypeError (the index cast is never reached). This
    // is why the "empty values" shape is not a TypeError.
    assert!(matches!(
        eval_to_value(
            &coll_update_many(
                const_coll_int(vec![1, 2]),
                const_coll_long(vec![0]),
                const_coll_long(vec![]),
            ),
            &cx,
            &[],
        ),
        Err(EvalError::RuntimeException(_))
    ));
}

// ---- Global.serialize for AvlTree + Header (DynamicCost = StartWriterCost(10)
//      + DataSerializer put-op sum). chunk(n) = 3 + n. Costs verified against
//      the SANTA vectors: AvlTree total 127 (= 79 framing + 10 + 38), Header
//      specFixture total 333 (= 79 + 10 + 244). ----

fn test_avl_tree(value_length: Option<i32>) -> ergo_ser::sigma_value::AvlTreeData {
    ergo_ser::sigma_value::AvlTreeData {
        digest: [0u8; 33].to_vec(),
        insert_allowed: true,
        update_allowed: false,
        remove_allowed: true,
        key_length: 32,
        value_length_opt: value_length,
    }
}

fn test_eval_header_v2() -> EvalHeader {
    EvalHeader {
        id: [0xAA; 32],
        version: 2,
        parent_id: [0xBB; 32],
        ad_proofs_root: [0; 32],
        state_root: [0; 33],
        transactions_root: [0; 32],
        timestamp: 1_600_000_000_000,
        n_bits: 0x0100_0000,
        height: 500_000,
        extension_root: [0; 32],
        miner_pk: [0x02; 33],
        pow_onetime_pk: [0x03; 33],
        pow_nonce: [0xFF; 8],
        pow_distance: num_bigint::BigInt::from(0),
        votes: [0, 0, 0],
        unparsed_bytes: Vec::new(),
    }
}

#[test]
fn serialize_put_cost_avltree_is_constant_38() {
    use ergo_ser::sigma_type::SigmaType as T;
    use ergo_ser::sigma_value::SigmaValue as Sv;
    // 38 = chunk(33) digest (36) + putUByte flags (1) + putUInt keyLength (0)
    //      + putOption tag (1) [+ Some: inner putUInt 0].
    for vlen in [None, Some(64), Some(1)] {
        let avl = test_avl_tree(vlen);
        assert_eq!(
            crate::evaluator::opcodes::method_call::serialize_put_cost(
                &T::SAvlTree,
                &Sv::AvlTree(avl)
            )
            .unwrap(),
            38,
            "AvlTree serialize put-cost is the constant 38 (vlen={vlen:?})",
        );
    }
}

#[test]
fn serialize_put_cost_header_v2_is_244() {
    use ergo_ser::sigma_type::SigmaType as T;
    use ergo_ser::sigma_value::SigmaValue as Sv;
    let h = test_eval_header_v2().to_header();
    // 244 = 1(version) + 35*3(parent/adProofs/txRoot) + 36(stateRoot) +
    //       3(timestamp) + 35(extensionRoot) + 7(nBits) + 0(height) + 6(votes)
    //       + 1(unparsedLen) + 3(chunk(0)) + 36(pk) + 11(nonce).
    assert_eq!(
        crate::evaluator::opcodes::method_call::serialize_put_cost(
            &T::SHeader,
            &Sv::Header(Box::new(h))
        )
        .unwrap(),
        244,
        "Header(v2, unparsed empty) serialize put-cost is 244",
    );
}

#[test]
fn serialize_put_cost_header_v1_is_283() {
    use ergo_ser::sigma_type::SigmaType as T;
    use ergo_ser::sigma_value::SigmaValue as Sv;
    // Version 1 header -> Autolykos V1 PoW (pk + w + nonce + d) and NO
    // unparsed-bytes block (version > 1 is false). pow_distance 0x010203 ->
    // d = to_signed_bytes_be() = [1,2,3] (len 3). 283 = 1(version) + 35*3 +
    // 36(stateRoot) + 3(timestamp) + 35(extensionRoot) + 7(nBits) + 0(height)
    // + 6(votes) + [36(pk)+36(w)+11(nonce)+1(dLen)+6(chunk(3))]. Pins the V1
    // PoW path (also validated end-to-end by the Global.deserializeTo_header#1
    // roundtrip vector, a real v1 header).
    let mut eh = test_eval_header_v2();
    eh.version = 1;
    eh.pow_distance = num_bigint::BigInt::from(0x01_02_03);
    let h = eh.to_header();
    assert_eq!(
        crate::evaluator::opcodes::method_call::serialize_put_cost(
            &T::SHeader,
            &Sv::Header(Box::new(h))
        )
        .unwrap(),
        283,
        "Header(v1, d=[1,2,3]) serialize put-cost is 283",
    );
}

#[test]
fn serialize_avltree_and_header_eval_total_and_bytes() {
    // Global.serialize(value): obj = Global (0xDD=5), args[0] = the value
    // const (5), MethodCall (0xDC=4), then StartWriterCost(10) + put-ops.
    let mut cx = ReductionContext::minimal(500_000, 0);
    cx.activated_script_version = 3;
    cx.ergo_tree_version = 3;
    let serialize_call = |tpe: SigmaType, val: SigmaValue| {
        op(
            0xDC,
            Payload::MethodCall {
                type_id: 106,
                method_id: 3,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![Expr::Const { tpe, val }],
                type_args: vec![],
            },
        )
    };
    let eval_cost = |expr: &Expr| -> (Value, u64) {
        let mut cost = CostAccumulator::recording_only();
        let mut env = Env::new();
        let mut depth = 0usize;
        let mut trace = None;
        let v = eval_expr(expr, &cx, &[], &mut env, &mut depth, &mut cost, &mut trace).unwrap();
        (v, cost.total().value())
    };
    // AvlTree: 4 + 5 + 5 + 10 + 38 = 62; output bytes = 36 (digest 33 + flags 1
    // + keyLen VLQ 1 + option-None 1).
    let avl = test_avl_tree(None);
    let (v, total) = eval_cost(&serialize_call(
        SigmaType::SAvlTree,
        SigmaValue::AvlTree(avl),
    ));
    assert_eq!(total, 62, "serialize(AvlTree) total");
    match v {
        Value::CollBytes(b) => assert_eq!(b.len(), 36, "AvlTree serialize output length"),
        other => panic!("expected CollBytes, got {other:?}"),
    }
    // Header: 4 + 5 + 5 + 10 + 244 = 268.
    let h = test_eval_header_v2().to_header();
    let (v, total) = eval_cost(&serialize_call(
        SigmaType::SHeader,
        SigmaValue::Header(Box::new(h)),
    ));
    assert_eq!(total, 268, "serialize(Header) total");
    assert!(
        matches!(v, Value::CollBytes(_)),
        "Header serialize -> CollBytes"
    );
}

// CONTEXT.headers(idx) — a RUNTIME-sourced header, materialized from
// ctx.last_headers rather than a constant. A const Header (Expr::Const) would
// be rejected by the const/value-decoder SHeader gate
// (sigma_to_value_versioned) BEFORE reaching the (106,3) serialize gate, so
// these gate tests must use a runtime source to prove the serialize gate
// itself (per CodeRabbit on PR #38).
fn ctx_headers_index(idx: i32) -> Expr {
    op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(op(
                0xDB,
                Payload::MethodCall {
                    type_id: 101, // SContext.headers
                    method_id: 2,
                    obj: Box::new(op(0xFE, Payload::Zero)),
                    args: vec![],
                    type_args: vec![],
                },
            )),
            index: Box::new(const_int(idx)),
            default: None,
        },
    )
}

fn serialize_call_expr(arg: Expr) -> Expr {
    op(
        0xDC,
        Payload::MethodCall {
            type_id: 106,
            method_id: 3,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![arg],
            type_args: vec![],
        },
    )
}

#[test]
fn serialize_header_rejected_pre_v3_ergo_tree() {
    // Scala DataSerializer.serialize(SHeader) is gated on
    // isV3OrLaterErgoTreeVersion. The v6 method gate only checks
    // activatedScriptVersion, so a tree with ergo_tree_version < 3 (spent
    // post-activation) must still reject serializing a Header. Use a
    // RUNTIME header (CONTEXT.headers(0)) so this exercises the (106,3) gate,
    // not the const-decoder gate.
    let headers = vec![test_eval_header_v2()];
    let mut cx = ReductionContext::minimal(500_000, 0);
    cx.activated_script_version = 3; // method gate satisfied
    cx.ergo_tree_version = 2; // but the ErgoTree is pre-v3
    cx.last_headers = &headers;
    let expr = serialize_call_expr(ctx_headers_index(0));
    assert!(
        matches!(
            eval_to_value(&expr, &cx, &[]),
            Err(EvalError::TypeError { .. })
        ),
        "serialize(runtime Header) must reject at ergo_tree_version < 3",
    );
    // Sanity: the SAME expression succeeds once the ErgoTree is v3, proving
    // the rejection above is the version gate (not an unrelated failure).
    let mut cx_v3 = ReductionContext::minimal(500_000, 0);
    cx_v3.activated_script_version = 3;
    cx_v3.ergo_tree_version = 3;
    cx_v3.last_headers = &headers;
    assert!(
        matches!(eval_to_value(&expr, &cx_v3, &[]), Ok(Value::CollBytes(_))),
        "serialize(runtime Header) succeeds at ergo_tree_version >= 3",
    );
}

#[test]
fn serialize_avltree_rejects_negative_lengths() {
    // read_avl_tree preserves an out-of-i32-range keyLength/valueLengthOpt as
    // a wrapped-negative i32; Scala's putUInt throws on negative, so serialize
    // must error rather than emit u32-cast bytes.
    let mut cx = ReductionContext::minimal(500_000, 0);
    cx.activated_script_version = 3;
    cx.ergo_tree_version = 3;
    let serialize_avl = |avl: ergo_ser::sigma_value::AvlTreeData| {
        op(
            0xDC,
            Payload::MethodCall {
                type_id: 106,
                method_id: 3,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![Expr::Const {
                    tpe: SigmaType::SAvlTree,
                    val: SigmaValue::AvlTree(avl),
                }],
                type_args: vec![],
            },
        )
    };
    let mut bad_key = test_avl_tree(None);
    bad_key.key_length = -1;
    assert!(
        matches!(
            eval_to_value(&serialize_avl(bad_key), &cx, &[]),
            Err(EvalError::TypeError { .. })
        ),
        "serialize(AvlTree) must reject negative keyLength",
    );
    let bad_vlen = test_avl_tree(Some(-5));
    assert!(
        matches!(
            eval_to_value(&serialize_avl(bad_vlen), &cx, &[]),
            Err(EvalError::TypeError { .. })
        ),
        "serialize(AvlTree) must reject negative valueLengthOpt",
    );
}

#[test]
fn serialize_coll_header_native_carrier() {
    // The native Coll[Header] carrier (CONTEXT.headers) must serialize:
    // value_to_typed_sigma -> SColl(SHeader) with SigmaValue::Header elements.
    use ergo_ser::sigma_type::SigmaType as T;
    use ergo_ser::sigma_value::{CollValue, SigmaValue as Sv};
    let coll = Value::CollHeader(vec![test_eval_header_v2(), test_eval_header_v2()]);
    let (t, sv) = value_to_typed_sigma(&coll).unwrap();
    assert_eq!(t, T::SColl(Box::new(T::SHeader)));
    assert!(matches!(&sv, Sv::Coll(CollValue::Values(v)) if v.len() == 2));
    // Cost = putUShort(len)=3 + 2 * Header(v2)=244 = 491.
    assert_eq!(
        crate::evaluator::opcodes::method_call::serialize_put_cost(&t, &sv).unwrap(),
        3 + 244 + 244,
        "Coll[Header] of 2 v2 headers: 3 + 244*2",
    );
}

#[test]
fn serialize_coll_header_v3_gate() {
    // Non-empty Coll[Header] is rejected on a pre-v3 ErgoTree (per
    // materialized header); an EMPTY Coll[Header] is accepted (no header
    // materialized) — matching the value-based contains_header gate. Uses the
    // RUNTIME CONTEXT.headers carrier (Value::CollHeader), which bypasses the
    // const-decoder gate, so this proves the (106,3) serialize gate.
    let expr = serialize_call_expr(op(
        0xDB,
        Payload::MethodCall {
            type_id: 101, // SContext.headers
            method_id: 2,
            obj: Box::new(op(0xFE, Payload::Zero)),
            args: vec![],
            type_args: vec![],
        },
    ));
    // Non-empty headers, pre-v3 ErgoTree -> reject.
    let headers = vec![test_eval_header_v2()];
    let mut cx = ReductionContext::minimal(500_000, 0);
    cx.activated_script_version = 3;
    cx.ergo_tree_version = 2;
    cx.last_headers = &headers;
    assert!(
        matches!(
            eval_to_value(&expr, &cx, &[]),
            Err(EvalError::TypeError { .. })
        ),
        "non-empty Coll[Header] serialize must reject at ergo_tree_version < 3",
    );
    // Empty headers, pre-v3 -> accepted (no materialized header).
    let empty: Vec<EvalHeader> = vec![];
    let mut cx_empty = ReductionContext::minimal(500_000, 0);
    cx_empty.activated_script_version = 3;
    cx_empty.ergo_tree_version = 2;
    cx_empty.last_headers = &empty;
    assert!(
        matches!(
            eval_to_value(&expr, &cx_empty, &[]),
            Ok(Value::CollBytes(_))
        ),
        "empty Coll[Header] serialize is accepted even pre-v3",
    );
}

#[test]
fn unpack_collection_accepts_native_coll_header() {
    // SubstConstants unpacks replacement values via unpack_collection before
    // value_to_typed_sigma; the native Coll[Header] carrier (CONTEXT.headers)
    // must unpack to Header elements rather than erroring.
    let items = unpack_collection(Value::CollHeader(vec![
        test_eval_header_v2(),
        test_eval_header_v2(),
    ]))
    .unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|v| matches!(v, Value::Header(_))));
}

// ════════════════════ SGlobal.serialize(Box) — EIP-50 v6 ════════════════════
// SBox serialize: `value_to_typed_sigma(InlineBox)` surfaces
// `(SBox, OpaqueBoxBytes(raw))` and `serialize_put_cost(SBox)` re-parses those
// bytes to charge the exact `SigmaByteWriter` put-cost sequence
// `ErgoBox.sigmaSerializer` emits (Scala oracle:
// `ErgoBoxCandidate.serializeBodyWithIndexedDigests` + `ErgoBox.sigmaSerializer`):
//   putULong(value)=3, putBytes(tree)=chunk(treeLen), putUInt(height)=0,
//   putUByte(nTokens)=1, per-token putBytes(32)+putULong = chunk(32)+3 = 38,
//   putUByte(nRegs)=1, per-register putValue, putBytes(txId)=chunk(32)=35,
//   putUShort(index)=3.  chunk(n) = 3 + n.
// Register putValue (ValueSerializer): Constant -> type_enc_bytes(tpe) (1/byte)
// + DataSerializer cost; CreateTuple(0x86) -> put(opcode)=1 + putUByte(count)=1
// + Σ item putValue.

/// Scala-6.1.2 sizeless v6 proposition tree (10 bytes); parses via the
/// `read_ergo_box` full-walk so `read_ergo_box_candidate` finds the boundary.
fn ser_box_tree() -> Vec<u8> {
    hex::decode("1000d1efe6db6a0add04").unwrap()
}

/// Assemble standalone box bytes (candidate body + 32-byte txId + VLQ index)
/// from parts. `reg_section` is the verbatim register block (count byte +
/// entries) so const-vs-expr register encodings round-trip byte-exact.
fn build_box(
    value: u64,
    tree: &[u8],
    height: u32,
    tokens: &[([u8; 32], u64)],
    reg_section: &[u8],
    txid: &[u8; 32],
    index: u16,
) -> Vec<u8> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    w.put_u64(value);
    w.put_bytes(tree);
    w.put_u32(height);
    w.put_u8(tokens.len() as u8);
    for (id, amt) in tokens {
        w.put_bytes(id);
        w.put_u64(*amt);
    }
    w.put_bytes(reg_section);
    w.put_bytes(txid);
    w.put_u16(index);
    w.result()
}

/// Register block with zero registers (the bare count byte).
fn reg_none() -> Vec<u8> {
    vec![0u8]
}

/// Register block: a single R4 written in CONSTANT form (type code <= 0x70
/// followed by data). Tuple constants (quad code 0x54, tuple-n code 0x60) are
/// detected as constants by `read_register_value` and cost
/// type_enc_bytes(tpe) + DataSerializer cost.
fn reg_const(tpe: &SigmaType, val: &SigmaValue) -> Vec<u8> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    w.put_u8(1);
    ergo_ser::sigma_value::write_constant(&mut w, tpe, val).unwrap();
    w.result()
}

/// Register block from structured `AdditionalRegisters` — `write_registers`
/// emits tuples in the CreateTuple (0x86) EXPRESSION form, which costs
/// 1(opcode) + 1(count) + Σ item putValue.
fn reg_from_registers(regs: ergo_ser::register::AdditionalRegisters) -> Vec<u8> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::register::write_registers(&mut w, &regs).unwrap();
    w.result()
}

fn ser_box_cost(bytes: Vec<u8>) -> u64 {
    crate::evaluator::opcodes::method_call::serialize_put_cost(
        &SigmaType::SBox,
        &SigmaValue::OpaqueBoxBytes(bytes),
    )
    .unwrap()
}

#[test]
fn serialize_put_cost_box_minimal() {
    // 3(value) + chunk(10)=13(tree) + 0(height) + 1(nTok) + 1(nRegs)
    // + 35(txId) + 3(index) = 56.
    let b = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_none(),
        &[0xAB; 32],
        7,
    );
    assert_eq!(ser_box_cost(b), 56);
}

#[test]
fn serialize_put_cost_box_with_tokens() {
    // Each token adds chunk(32)+putULong = 35 + 3 = 38.
    let one = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[([0x11; 32], 1000)],
        &reg_none(),
        &[0xAB; 32],
        7,
    );
    assert_eq!(ser_box_cost(one), 56 + 38);
    let two = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[([0x11; 32], 1000), ([0x22; 32], 5)],
        &reg_none(),
        &[0xAB; 32],
        7,
    );
    assert_eq!(ser_box_cost(two), 56 + 76);
}

#[test]
fn serialize_put_cost_box_with_int_register() {
    // R4 = Int(42) CONSTANT: type_enc(SInt)=1 + DataSerializer(SInt)=3 = 4.
    let reg = reg_const(&SigmaType::SInt, &SigmaValue::Int(42));
    let b = build_box(1_000_000, &ser_box_tree(), 100, &[], &reg, &[0xAB; 32], 7);
    assert_eq!(ser_box_cost(b), 56 + 4);
}

#[test]
fn serialize_put_cost_box_with_const_tuple_registers() {
    // R4 = 4-tuple of Byte CONSTANT: type_enc(quad)=5 + data(4) = 9.
    let tpe4 = SigmaType::STuple(vec![SigmaType::SByte; 4]);
    let val4 = SigmaValue::Tuple((1u8..=4).map(|n| SigmaValue::Byte(n as i8)).collect());
    let b4 = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_const(&tpe4, &val4),
        &[0xAB; 32],
        7,
    );
    assert_eq!(ser_box_cost(b4), 56 + 9);

    // R4 = 5-tuple of Byte CONSTANT: type_enc(tuple5)=7 + data(5) = 12.
    let tpe5 = SigmaType::STuple(vec![SigmaType::SByte; 5]);
    let val5 = SigmaValue::Tuple((1u8..=5).map(|n| SigmaValue::Byte(n as i8)).collect());
    let b5 = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_const(&tpe5, &val5),
        &[0xAB; 32],
        7,
    );
    assert_eq!(ser_box_cost(b5), 56 + 12);
}

#[test]
fn serialize_put_cost_box_with_expr_tuple_register() {
    // R4 = (Byte, Byte) as CreateTuple(0x86) EXPRESSION:
    // 1(opcode) + 1(count) + 2 * [type_enc(SByte)=1 + data=1] = 6.
    use ergo_ser::register::{AdditionalRegisters, RegisterValue};
    let regs = AdditionalRegisters {
        registers: vec![RegisterValue {
            tpe: SigmaType::STuple(vec![SigmaType::SByte, SigmaType::SByte]),
            value: SigmaValue::Tuple(vec![SigmaValue::Byte(102), SigmaValue::Byte(99)]),
        }],
    };
    let b = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_from_registers(regs),
        &[0xAB; 32],
        7,
    );
    assert_eq!(ser_box_cost(b), 56 + 6);
}

#[test]
fn serialize_put_cost_nested_box_int_tuple() {
    // serialize((box, Int)) costs serialize(box) + DataSerializer(SInt)=3,
    // exercising the STuple -> SBox recursion in serialize_put_cost.
    use crate::evaluator::opcodes::method_call::serialize_put_cost;
    let b = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_none(),
        &[0xAB; 32],
        7,
    );
    let tpe = SigmaType::STuple(vec![SigmaType::SBox, SigmaType::SInt]);
    let val = SigmaValue::Tuple(vec![SigmaValue::OpaqueBoxBytes(b), SigmaValue::Int(7)]);
    assert_eq!(serialize_put_cost(&tpe, &val).unwrap(), 56 + 3);
}

#[test]
fn serialize_put_cost_box_with_nested_expr_tuple_register() {
    // R4 = ((Byte,Byte),(Byte,Byte)) as nested CreateTuple(0x86) expressions
    // (write_registers emits the expression form recursively). Outer putValue =
    // 1(opcode)+1(count) + 2 * inner; inner putValue = 1(opcode)+1(count) +
    // 2*[type_enc(SByte)=1 + data=1] = 6. So register cost = 2 + 2*6 = 14.
    use ergo_ser::register::{AdditionalRegisters, RegisterValue};
    let inner_t = SigmaType::STuple(vec![SigmaType::SByte, SigmaType::SByte]);
    let inner_v = || SigmaValue::Tuple(vec![SigmaValue::Byte(1), SigmaValue::Byte(2)]);
    let regs = AdditionalRegisters {
        registers: vec![RegisterValue {
            tpe: SigmaType::STuple(vec![inner_t.clone(), inner_t]),
            value: SigmaValue::Tuple(vec![inner_v(), inner_v()]),
        }],
    };
    let b = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_from_registers(regs),
        &[0xAB; 32],
        7,
    );
    assert_eq!(ser_box_cost(b), 56 + 14);
}

#[test]
fn serialize_put_cost_box_with_concrete_collection_register() {
    // R4 = Coll[Int](1, 2) stored as a ConcreteCollection(0x83) EXPRESSION (a
    // valid register EvaluatedValue). putValue cost = 1(opcode) + 3(putUShort
    // size) + type_enc(SInt elem)=1 + 2 * [type_enc(SInt)=1 + DataSerializer=3]
    // = 5 + 8 = 13. Anchored to ConcreteCollectionSerializer.serialize.
    use ergo_ser::opcode::{write_expr, Expr as SerExpr, IrNode as SerNode, Payload as SerPayload};
    let cc = SerExpr::Op(SerNode {
        opcode: 0x83,
        payload: SerPayload::ConcreteCollection {
            elem_type: SigmaType::SInt,
            items: vec![
                SerExpr::Const {
                    tpe: SigmaType::SInt,
                    val: SigmaValue::Int(1),
                },
                SerExpr::Const {
                    tpe: SigmaType::SInt,
                    val: SigmaValue::Int(2),
                },
            ],
        },
    });
    let mut w = ergo_primitives::writer::VlqWriter::new();
    w.put_u8(1); // register count
    write_expr(&mut w, &cc, false).unwrap();
    let reg = w.result();
    let b = build_box(1_000_000, &ser_box_tree(), 100, &[], &reg, &[0xAB; 32], 7);
    assert_eq!(ser_box_cost(b), 56 + 13);
}

#[test]
fn value_to_typed_sigma_inline_box_surfaces_opaque_bytes() {
    // The InlineBox carrier (a decoded SBox) serializes back via its verbatim
    // raw_bytes: value_to_typed_sigma yields (SBox, OpaqueBoxBytes(raw)) and the
    // raw bytes round-trip the canonical box bytes byte-for-byte.
    let bytes = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_none(),
        &[0xAB; 32],
        7,
    );
    let v = sigma_to_value(&SigmaType::SBox, &SigmaValue::OpaqueBoxBytes(bytes.clone())).unwrap();
    assert!(matches!(v, Value::InlineBox(_)));
    let (t, sv) = value_to_typed_sigma(&v).unwrap();
    assert_eq!(t, SigmaType::SBox);
    match sv {
        SigmaValue::OpaqueBoxBytes(raw) => assert_eq!(raw, bytes),
        other => panic!("expected OpaqueBoxBytes, got {other:?}"),
    }
}

#[test]
fn methodcall_global_serialize_box_value_and_cost() {
    // End-to-end: SGlobal.serialize(box constant) -> Coll[Byte] equal to the
    // box bytes (verbatim raw_bytes), AND the total JitCost = 80:
    //   14 shared MethodCall framing (SGlobal receiver 0xDD + 0xDC dispatch +
    //      the SBox arg const) — the same 14 documented in
    //      methodcall_deserialize_to_cost_matches_v6_0_2
    //   + StartWriterCost(10) + serialize_put_cost(SBox minimal)=56
    //   (56 is pinned independently by serialize_put_cost_box_minimal).
    let bytes = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_none(),
        &[0xAB; 32],
        7,
    );
    let sbox = Expr::Const {
        tpe: SigmaType::SBox,
        val: SigmaValue::OpaqueBoxBytes(bytes.clone()),
    };
    let ser = op(
        0xDC,
        Payload::MethodCall {
            type_id: 106,
            method_id: 3,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![sbox],
            type_args: vec![],
        },
    );
    let mut cx = ReductionContext::minimal(0, 0);
    cx.activated_script_version = 3;
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut acc = CostAccumulator::recording_only();
    let mut trace = None;
    let v = eval_expr(&ser, &cx, &[], &mut env, &mut depth, &mut acc, &mut trace).unwrap();
    assert_eq!(v, Value::CollBytes(bytes));
    assert_eq!(acc.total().value(), 80);
}

// ── Coll.flatMap cost = PerItemCost(60,10,8) over OUTPUT length ──────────────
// Scala flatMap_eval (methods.scala) charges FlatMapMethod_CostKind =
// PerItemCost(base=60, perChunk=10, chunkSize=8) over res.length — the OUTPUT
// (flattened) length — via addSeqCost. Our arm previously charged a flat
// bogus 0xDC=4 + a bogus 10/input and NO output cost. This pins the missing
// output-length term: two flatMaps differing ONLY in output length must differ
// in total cost by exactly FlatMap.cost(big) - FlatMap.cost(small). The lambda
// body is a constant Coll[Byte] (Expr::Const = fixed 5 regardless of length),
// so per-input cost and framing are identical across the two — only outLen
// (= n_in * body_len) differs.
#[test]
fn flatmap_charges_peritemcost_over_output_length() {
    fn mk(body_len: usize) -> Expr {
        let coll = const_coll_int(vec![1, 2]); // n_in = 2
        let func = op(
            0xD9,
            Payload::FuncValue {
                args: vec![(1, Some(SigmaType::SInt))],
                body: Box::new(const_bytes(vec![7u8; body_len])),
            },
        );
        op(
            0xDC,
            Payload::MethodCall {
                type_id: 12,
                method_id: 15,
                obj: Box::new(coll),
                args: vec![func],
                type_args: vec![],
            },
        )
    }
    fn cost_of(e: &Expr) -> u64 {
        let cx = ReductionContext::minimal(0, 0);
        let mut env = Env::new();
        let mut depth = 0usize;
        let mut acc = CostAccumulator::recording_only();
        let mut trace = None;
        eval_expr(e, &cx, &[], &mut env, &mut depth, &mut acc, &mut trace).unwrap();
        acc.total().value()
    }
    // small: outLen = 2*2  = 4  -> chunks((4-1)/8+1)=1  -> FlatMap.cost = 70
    // big:   outLen = 2*18 = 36 -> chunks((36-1)/8+1)=5 -> FlatMap.cost = 110
    // empty: outLen = 2*0  = 0  -> chunks=1 (truncates)  -> FlatMap.cost = 70
    // difference attributable solely to the output-length cost.
    let empty = cost_of(&mk(0));
    let small = cost_of(&mk(2));
    let big = cost_of(&mk(18));
    assert_eq!(
        big - small,
        40,
        "flatMap must charge PerItemCost(60,10,8) over the OUTPUT length \
         (got diff {} between outLen 36 and 4)",
        big - small,
    );
    // compute(0) = 70 (chunks truncate to 1), so the empty-output case costs
    // the same as outLen=4 (both chunk to 1); the big case is +40 over either.
    assert_eq!(
        small - empty,
        0,
        "outLen 4 and 0 both chunk to 1 -> identical FlatMap.cost (70)",
    );
    assert_eq!(
        big - empty,
        40,
        "empty-output compute(0) path must be charged"
    );
}

// The flatMap flattening arms must cover every Coll element type the lambda
// body can produce — including Coll[Short]/Coll[SigmaProp]/Coll[Header], which
// the `first_shape` empty-result capture already handles. A lambda returning
// Coll[Short] must flatten, not fall through to a TypeError (reject-valid).
#[test]
fn flatmap_flattens_coll_short_body() {
    use ergo_ser::sigma_value::CollValue;
    let coll = const_coll_int(vec![1, 2]);
    // body: i => Coll[Short](9, 9)  (independent of i)
    let short_coll = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SShort)),
        val: SigmaValue::Coll(CollValue::Values(vec![
            SigmaValue::Short(9),
            SigmaValue::Short(9),
        ])),
    };
    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(short_coll),
        },
    );
    let expr = op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 15,
            obj: Box::new(coll),
            args: vec![func],
            type_args: vec![],
        },
    );
    assert_eq!(run_eval(&expr), Value::CollShort(vec![9, 9, 9, 9]));
}

// ── AvlTree.updateDigest (100,15) / updateOperations (100,8) + variable digest ──
// Scala CAvlTree.updateDigest stores any-length Coll[Byte] verbatim (no length
// check); updateOperations swaps the flags byte (insert=&0x01, update=&0x02,
// remove=&0x04). Costs (46/51/65/262) are pinned by the SANTA vectors (which
// use ConstPlaceholder framing); these tests pin the VALUE behavior + the
// variable-length-digest cost-helper guard. The digest field is now Vec<u8>.
fn avl_const_expr(digest: Vec<u8>) -> Expr {
    Expr::Const {
        tpe: SigmaType::SAvlTree,
        val: SigmaValue::AvlTree(ergo_ser::sigma_value::AvlTreeData {
            digest,
            insert_allowed: true,
            update_allowed: true,
            remove_allowed: true,
            key_length: 32,
            value_length_opt: None,
        }),
    }
}

fn avl_method(obj: Expr, method_id: u8, args: Vec<Expr>) -> Expr {
    Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 100,
            method_id,
            obj: Box::new(obj),
            args,
            type_args: vec![],
        },
    })
}

#[test]
fn avltree_update_digest_accepts_any_length() {
    let ctx = ReductionContext::minimal(0, 0);
    let base = || avl_const_expr(vec![0x07; 33]);
    // 3-byte, empty, and 40-byte digests are all stored verbatim (no validation).
    for new_digest in [vec![1u8, 2, 3], vec![], vec![0xAB; 40], vec![0x05; 33]] {
        let expr = avl_method(base(), 15, vec![const_bytes(new_digest.clone())]);
        match eval_to_value(&expr, &ctx, &[]).unwrap() {
            Value::AvlTree(avl) => {
                assert_eq!(
                    avl.digest, new_digest,
                    "updateDigest stores the digest verbatim"
                );
                // other fields untouched
                assert!(avl.insert_allowed && avl.update_allowed && avl.remove_allowed);
                assert_eq!(avl.key_length, 32);
            }
            other => panic!("updateDigest must return AvlTree, got {other:?}"),
        }
    }
}

#[test]
fn avltree_update_digest_readback_returns_stored_bytes() {
    // tree.updateDigest(Coll[Byte](1,2,3)).digest -> Coll[Byte](1,2,3).
    let ctx = ReductionContext::minimal(0, 0);
    let updated = avl_method(
        avl_const_expr(vec![0x07; 33]),
        15,
        vec![const_bytes(vec![1, 2, 3])],
    );
    let readback = avl_method(updated, 1, vec![]); // (100,1) digest property
    assert_eq!(
        eval_to_value(&readback, &ctx, &[]).unwrap(),
        Value::CollBytes(vec![1, 2, 3]),
    );
}

#[test]
fn avltree_update_operations_swaps_flags() {
    let ctx = ReductionContext::minimal(0, 0);
    // flags 0 -> all read-only; 7 (0b111) -> all allowed; 1 -> insert only.
    let cases: &[(i8, bool, bool, bool)] = &[
        (0, false, false, false),
        (7, true, true, true),
        (1, true, false, false),
        (2, false, true, false),
        (4, false, false, true),
    ];
    for &(flags, ins, upd, rem) in cases {
        let expr = avl_method(
            avl_const_expr(vec![0x07; 33]),
            8,
            vec![Expr::Const {
                tpe: SigmaType::SByte,
                val: SigmaValue::Byte(flags),
            }],
        );
        match eval_to_value(&expr, &ctx, &[]).unwrap() {
            Value::AvlTree(avl) => {
                assert_eq!(
                    (avl.insert_allowed, avl.update_allowed, avl.remove_allowed),
                    (ins, upd, rem),
                    "updateOperations({flags}) flag decode",
                );
                // digest/keyLength untouched
                assert_eq!(avl.digest, vec![0x07; 33]);
                assert_eq!(avl.key_length, 32);
            }
            other => panic!("updateOperations must return AvlTree, got {other:?}"),
        }
    }
}

#[test]
fn avl_tree_height_no_panic_on_variable_digest() {
    use super::cost::{avl_cost_height, avl_tree_height};
    let mk = |digest: Vec<u8>| ergo_ser::sigma_value::AvlTreeData {
        digest,
        insert_allowed: true,
        update_allowed: true,
        remove_allowed: true,
        key_length: 32,
        value_length_opt: None,
    };
    // avl_tree_height = trailing byte, or 0 for empty (NO panic).
    assert_eq!(avl_tree_height(&mk(vec![])), 0);
    assert_eq!(avl_tree_height(&mk(vec![1, 2, 3])), 3);
    assert_eq!(avl_tree_height(&mk(vec![0x07; 33])), 7);
    // avl_cost_height returns 0 unless the digest is exactly 33 bytes (scrypto
    // require(startingDigest.length == 33) throws before rootNodeHeight is set),
    // so a 3-byte digest costs contains at height 0 (the Tier-2 cost), NOT 3.
    assert_eq!(avl_cost_height(&mk(vec![1, 2, 3])), 0);
    assert_eq!(avl_cost_height(&mk(vec![])), 0);
    assert_eq!(avl_cost_height(&mk(vec![0x07; 33])), 7);
}
