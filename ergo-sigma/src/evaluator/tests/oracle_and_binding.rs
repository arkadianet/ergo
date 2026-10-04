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

// ── FunDef tpeArgs + SFunc-as-value (Scala ValDefSerializer /
//    FuncValue.eval / isValueOfType) ─────────────────────────────
//
// FunDef (0xD7) carries `nTpeArgs(u8) + STypeVar types` on the wire
// and binds exactly like ValDef (Scala BlockValue.eval casts items
// asInstanceOf[ValDef]). Type-variable enforcement happens at
// APPLICATION: the closure built by FuncValue.eval runs
// Value.checkType(argTpe, vArg) and SType.isValueOfType has no
// STypeVar case (sys.error "Unknown type"). Pinned by
// HOF_FunDef_type_var_body / HOF_FunDef_polymorphic_identity /
// HOF_function_in_Coll_of_SFunc / higher_order_lambdas.

#[test]
fn fun_def_polymorphic_binds_without_application() {
    // { val id[T] = {(x: T) => x}; 5 } — never applied → accepts.
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![fun_def_t(
                SigmaType::STypeVar("T".into()),
                op(0x72, Payload::ValUse { id: 2 }),
            )],
            result: Box::new(const_int(5)),
        },
    );
    assert_eq!(run_eval(&block), Value::Int(5));
}

#[test]
fn fun_def_polymorphic_apply_rejects_type_var_param() {
    // { val id[T] = {(x: T) => x}; id(7) } — applying a closure whose
    // param type is a type VARIABLE errors regardless of body.
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![fun_def_t(
                SigmaType::STypeVar("T".into()),
                op(0x72, Payload::ValUse { id: 2 }),
            )],
            result: Box::new(op(
                0xDA,
                Payload::FuncApply {
                    func: Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    args: vec![const_int(7)],
                },
            )),
        },
    );
    let err = run_eval_err(&block);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

#[test]
fn fun_def_type_args_with_concrete_param_applies() {
    // { val id[T] = {(x: Int) => x}; id(7) } — tpeArgs on the FunDef
    // but a CONCRETE lambda param type → applies fine (vector:
    // HOF_FunDef_polymorphic_identity v3#0).
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![fun_def_t(
                SigmaType::SInt,
                op(0x72, Payload::ValUse { id: 2 }),
            )],
            result: Box::new(op(
                0xDA,
                Payload::FuncApply {
                    func: Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    args: vec![const_int(7)],
                },
            )),
        },
    );
    assert_eq!(run_eval(&block), Value::Int(7));
}

#[test]
fn coll_of_sfunc_index_then_apply() {
    // { Coll({(x:Int)=>x+1}, {(x:Int)=>x*2})(0)(5) } == 6 — functions
    // flow through the generic collection carrier, ByIndex hands the
    // Func back, FuncApply invokes it.
    let inc = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x9A,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    Box::new(const_int(1)),
                ),
            )),
        },
    );
    let dbl = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(2, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x9C,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 2 })),
                    Box::new(const_int(2)),
                ),
            )),
        },
    );
    let sfunc = SigmaType::SFunc {
        t_dom: vec![SigmaType::SInt],
        t_range: Box::new(SigmaType::SInt),
        tpe_params: vec![],
    };
    let coll = op(
        0x83,
        Payload::ConcreteCollection {
            elem_type: sfunc,
            items: vec![inc, dbl],
        },
    );
    let indexed = op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(coll),
            index: Box::new(const_int(0)),
            default: None,
        },
    );
    let applied = op(
        0xDA,
        Payload::FuncApply {
            func: Box::new(indexed),
            args: vec![const_int(5)],
        },
    );
    assert_eq!(run_eval(&applied), Value::Int(6));
}

#[test]
fn func_in_tuple_select_then_apply() {
    // (({(x:Int)=>x+1}, 5))._1 applied to ._2 — functions flow through
    // tuple carriers and SelectField (higher_order_lambdas shape).
    let inc = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x9A,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    Box::new(const_int(1)),
                ),
            )),
        },
    );
    let pair = op(
        0x86,
        Payload::Tuple {
            items: vec![inc, const_int(5)],
        },
    );
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![op(
                0xD6,
                Payload::ValDef {
                    id: 3,
                    tpe: None,
                    rhs: Box::new(pair),
                },
            )],
            result: Box::new(op(
                0xDA,
                Payload::FuncApply {
                    func: Box::new(op(
                        0x8C,
                        Payload::SelectField {
                            input: Box::new(op(0x72, Payload::ValUse { id: 3 })),
                            field_idx: 1,
                        },
                    )),
                    args: vec![op(
                        0x8C,
                        Payload::SelectField {
                            input: Box::new(op(0x72, Payload::ValUse { id: 3 })),
                            field_idx: 2,
                        },
                    )],
                },
            )),
        },
    );
    assert_eq!(run_eval(&block), Value::Int(6));
}

// ── hasDeserialize inline-constants fork (Scala fullReduction) ───
//
// A tree containing DeserializeContext/DeserializeRegister reduces
// through Scala's reductionWithDeserialize: segregated constants are
// INLINED (toProposition(isConstantSegregation)) and evaluation runs
// with EmptyConstants — an inline Constant charges 5 jit where a
// ConstantPlaceholder charges 1. Pinned by
// DeserializeContext_over_absent_wrong_typed_var dead-branch entries
// (+4 per evaluated segregated constant).

#[test]
fn deserialize_dead_branch_inlines_segregated_constants() {
    // Twin trees: { if (true) true else <else-branch> } over two
    // segregated Boolean constants. The deserialize twin must cost
    // exactly +4 per evaluated constant (2 here) over the plain twin —
    // placeholders are inlined to Constant nodes (5 jit vs 1).
    let constants = vec![
        (SigmaType::SBoolean, SigmaValue::Boolean(true)),
        (SigmaType::SBoolean, SigmaValue::Boolean(true)),
    ];
    let if_tree = |else_branch: Expr| {
        op(
            0x95,
            Payload::Three(
                Box::new(op(0x73, Payload::ConstPlaceholder { index: 0 })),
                Box::new(op(0x73, Payload::ConstPlaceholder { index: 1 })),
                Box::new(else_branch),
            ),
        )
    };
    let with_deser = if_tree(op(
        0xD4,
        Payload::DeserializeContext {
            id: 0,
            tpe: SigmaType::SBoolean,
        },
    ));
    let plain = if_tree(const_bool(false));

    let (deser_val, deser_cost) = eval_value_and_cost_consts(&with_deser, &constants);
    let (plain_val, plain_cost) = eval_value_and_cost_consts(&plain, &constants);
    assert_eq!(deser_val.unwrap(), Value::Bool(true));
    assert_eq!(plain_val.unwrap(), Value::Bool(true));
    assert_eq!(
        deser_cost,
        plain_cost + 2 * 4,
        "hasDeserialize tree must charge inline-Constant (5) instead of placeholder (1) per evaluated constant"
    );
}

// ── ValDef/FunDef bind ONLY inside BlockValue (Scala BlockValue.eval) ─
//
// The ValDef/FunDef NODES have no eval override in Scala — a bare
// occurrence at any live expression position hits Value.eval's
// notSupportedError. Only the BlockValue item loop binds them
// (asInstanceOf[ValDef] + inline env update).

#[test]
fn val_def_standalone_rejects() {
    let bare = op(
        0xD6,
        Payload::ValDef {
            id: 1,
            tpe: None,
            rhs: Box::new(const_bool(true)),
        },
    );
    let err = run_eval_err(&bare);
    assert!(
        matches!(err, EvalError::InternalOpcode(0xD6, _)),
        "got {err:?}"
    );
}

#[test]
fn fun_def_standalone_rejects() {
    let bare = fun_def_t(SigmaType::SInt, op(0x72, Payload::ValUse { id: 2 }));
    let err = run_eval_err(&bare);
    assert!(
        matches!(err, EvalError::InternalOpcode(0xD7, _)),
        "got {err:?}"
    );
}

// ── BlockValue bindings are scoped to the block (Scala curEnv) ───
//
// Scala BlockValue.eval threads a LOCAL immutable `curEnv`: bindings
// are visible to later items and the result, but the caller's env is
// untouched once the block returns.

#[test]
fn block_value_shadowed_binding_restored_after_block() {
    // { val 1 = 10; ({ val 1 = 20; ValUse(1) }, ValUse(1)) }
    // The inner block sees its own 20; the second tuple item evaluates
    // AFTER the inner block returned and must see the OUTER 10 again.
    let inner = block(
        vec![val_def_item(1, const_int(20))],
        op(0x72, Payload::ValUse { id: 1 }),
    );
    let outer = block(
        vec![val_def_item(1, const_int(10))],
        op(
            0x86,
            Payload::Tuple {
                items: vec![inner, op(0x72, Payload::ValUse { id: 1 })],
            },
        ),
    );
    assert_eq!(
        run_eval(&outer),
        Value::Tuple(vec![Value::Int(20), Value::Int(10)]),
        "shadowed outer binding must reappear after the inner block"
    );
}

#[test]
fn block_value_binding_does_not_leak_past_block() {
    // ({ val 2 = 7; true }, ValUse(2)) — id 2 is bound only inside the
    // block; the second tuple item must NOT see it (Scala: unbound
    // variable error, not a leaked 7).
    let expr = op(
        0x86,
        Payload::Tuple {
            items: vec![
                block(vec![val_def_item(2, const_int(7))], const_bool(true)),
                op(0x72, Payload::ValUse { id: 2 }),
            ],
        },
    );
    let err = run_eval_err(&expr);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

// ── pre-v3 numeric auto-upcast (DeserializationSigmaBuilder) ─────
//
// Scala's DeserializationSigmaBuilder.applyUpcast
// (SigmaBuilder.scala:741-756) auto-inserts an Upcast node on the
// narrower operand of mixed-kind numeric two-operand ops at
// DESERIALIZATION for pre-v3 trees ("since v3 trees, Upcast nodes are
// not inserted automatically"). Routed families: arithOp
// (Plus/Minus/Multiply/Divide/Modulo/Min/Max), comparisonOp
// (GT/GE/LT/LE), equalityOp (EQ/NEQ). We apply the equivalent at eval
// time, charging the Upcast NumericCastCostKind (10; 30 for a BigInt
// target) once. Pinned by ArithOp.numeric_kind_mismatch.json
// int_long_coerced#0 (Plus(Int 1, Long 2) at tree v0 → Long 3, cost
// 35 = Const 5 + Upcast 10 + Const 5 + Plus 15).

#[test]
fn pre_v3_plus_mixed_kinds_auto_upcasts() {
    let expr = binop(0x9A, const_int(1), const_long(2));
    let (val, _) = eval_value_and_cost(&expr, &ctx_with_tree_version(0));
    assert_eq!(val.unwrap(), Value::Long(3));
    // v3+ trees: no auto-upcast — mixed kinds stay a type error.
    let (val, _) = eval_value_and_cost(&expr, &ctx_with_tree_version(3));
    assert!(
        matches!(val, Err(EvalError::TypeError { .. })),
        "got {val:?}"
    );
}

#[test]
fn pre_v3_auto_upcast_charges_numeric_cast_cost() {
    let ctx = ctx_with_tree_version(0);
    // Fixed-width target: +10 over the matched-kind twin.
    let mixed = binop(0x9A, const_int(1), const_long(2));
    let matched = binop(0x9A, const_long(1), const_long(2));
    let (_, mixed_cost) = eval_value_and_cost(&mixed, &ctx);
    let (_, matched_cost) = eval_value_and_cost(&matched, &ctx);
    assert_eq!(
        mixed_cost,
        matched_cost + 10,
        "Upcast to a fixed-width target charges NumericCastCostKind 10"
    );
    // BigInt target: +30 (NumericCastCostKind case SBigInt). The
    // matched twin is BigInt+BigInt so the ArithOp BigInt rate cancels.
    let mixed_big = binop(0x9A, const_int(1), const_bigint(2));
    let matched_big = binop(0x9A, const_bigint(1), const_bigint(2));
    let (val, mixed_big_cost) = eval_value_and_cost(&mixed_big, &ctx);
    assert_eq!(val.unwrap(), Value::BigInt(3.into()));
    let (_, matched_big_cost) = eval_value_and_cost(&matched_big, &ctx);
    assert_eq!(
        mixed_big_cost,
        matched_big_cost + 30,
        "Upcast to a BigInt target charges NumericCastCostKind 30"
    );
}

#[test]
fn pre_v3_comparison_mixed_kinds_auto_upcasts() {
    // GT(Long 2, Int 1): the RIGHT operand is the narrower one — covers
    // the r-side widening branch.
    let expr = binop(0x91, const_long(2), const_int(1));
    let (val, _) = eval_value_and_cost(&expr, &ctx_with_tree_version(0));
    assert_eq!(val.unwrap(), Value::Bool(true));
    let (val, _) = eval_value_and_cost(&expr, &ctx_with_tree_version(3));
    assert!(
        matches!(val, Err(EvalError::TypeError { .. })),
        "got {val:?}"
    );
}

#[test]
fn pre_v3_equality_mixed_kinds_auto_upcasts() {
    // EQ(Int 7, Long 7) pre-v3 → upcast → true (without the upcast the
    // carriers differ and PartialEq's catch-all would yield false).
    let eq = binop(0x93, const_int(7), const_long(7));
    let (val, _) = eval_value_and_cost(&eq, &ctx_with_tree_version(0));
    assert_eq!(val.unwrap(), Value::Bool(true));
    let neq = binop(0x94, const_int(7), const_long(8));
    let (val, _) = eval_value_and_cost(&neq, &ctx_with_tree_version(0));
    assert_eq!(val.unwrap(), Value::Bool(true));
}

#[test]
fn pre_v3_min_mixed_kinds_auto_upcasts() {
    // Min(Int 5, Long 3) → upcast left → Long(3) at the WIDER kind.
    let expr = binop(0xA1, const_int(5), const_long(3));
    let (val, _) = eval_value_and_cost(&expr, &ctx_with_tree_version(0));
    assert_eq!(val.unwrap(), Value::Long(3));
}

#[test]
fn v3_equality_mixed_numeric_kinds_rejects() {
    // At v3+ no auto-upcast happens and Scala's equalityOp fails
    // SameTypeConstrain (tree rejected at deserialization there;
    // rejected at evaluation here). Without the guard, PartialEq's
    // catch-all would return false — and NEQ would return TRUE,
    // validating a script Scala rejects.
    let ctx = ctx_with_tree_version(3);
    let eq = binop(0x93, const_int(7), const_long(7));
    let (val, _) = eval_value_and_cost(&eq, &ctx);
    assert!(
        matches!(val, Err(EvalError::TypeError { .. })),
        "got {val:?}"
    );
    let neq = binop(0x94, const_int(7), const_long(8));
    let (val, _) = eval_value_and_cost(&neq, &ctx);
    assert!(
        matches!(val, Err(EvalError::TypeError { .. })),
        "got {val:?}"
    );
    // Matched kinds keep working at v3+.
    let same = binop(0x93, const_long(7), const_long(7));
    let (val, _) = eval_value_and_cost(&same, &ctx);
    assert_eq!(val.unwrap(), Value::Bool(true));
}

// ── closure param checkType fires on EVERY invocation path ──────
//
// Scala's FuncValue.eval closure runs Value.checkType per invocation
// — from direct Apply AND from every HOF loop. A polymorphic lambda
// over an EMPTY collection never invokes the closure, so it must NOT
// error (the check sits inside the per-element loop, not before it).

#[test]
fn polymorphic_lambda_through_map_rejects() {
    let expr = op(
        0xAD,
        Payload::Two(
            Box::new(const_coll_int(vec![1, 2])),
            Box::new(poly_identity_lambda()),
        ),
    );
    let err = run_eval_err(&expr);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

#[test]
fn polymorphic_lambda_over_empty_coll_accepts() {
    // Zero elements → zero closure invocations → no checkType → Ok.
    let expr = op(
        0xAD,
        Payload::Two(
            Box::new(const_coll_int(vec![])),
            Box::new(poly_identity_lambda()),
        ),
    );
    match run_eval(&expr) {
        Value::CollInt(v) => assert!(v.is_empty()),
        Value::CollGeneric(v, _) => assert!(v.is_empty()),
        other => panic!("expected empty collection, got {other:?}"),
    }
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
