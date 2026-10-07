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
        register_bytes: Vec::new(),
    };
    let ctx = ReductionContext {
        validation_settings: Default::default(),
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
        register_bytes: Vec::new(),
    };
    let ctx = ReductionContext {
        validation_settings: Default::default(),
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
        register_bytes: Vec::new(),
    };
    let ctx = ReductionContext {
        validation_settings: Default::default(),
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
        register_bytes: Vec::new(),
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
        register_bytes: Vec::new(),
    };
    let ctx = ReductionContext {
        validation_settings: Default::default(),
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
        register_bytes: Vec::new(),
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
        register_bytes: Vec::new(),
    };
    let ctx = ReductionContext {
        validation_settings: Default::default(),
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
        Value::SigmaProp(SigmaBoolean::Cand(
            vec![SigmaBoolean::ProveDlog(GroupElement::from_bytes([b; 33]))].into(),
        ))
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
    let cth = |k: u16| {
        Value::SigmaProp(SigmaBoolean::Cthreshold {
            k,
            children: vec![SigmaBoolean::ProveDlog(GroupElement::from_bytes([1; 33]))].into(),
        })
    };
    assert!(eqc(&cth(1), &cth(1)).unwrap().0);
    // Different k with same single child: equalSigmaBooleans not reached; false.
    let cth2 = Value::SigmaProp(SigmaBoolean::Cthreshold {
        k: 1,
        children: vec![
            SigmaBoolean::ProveDlog(GroupElement::from_bytes([1; 33])),
            SigmaBoolean::ProveDlog(GroupElement::from_bytes([2; 33])),
        ]
        .into(),
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

// -- Audit: every `Value` variant must have a `PartialEq` self-self arm --

/// Covers every `Value` variant, including `UnsignedBigInt`. Any future
/// `Value` variant that lands without a
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
