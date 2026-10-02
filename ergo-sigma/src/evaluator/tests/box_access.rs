// ----- happy path (continued — extended opcode coverage) -----

// ── Batch 1: Box extractor opcodes ──────────────────────────────

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

// ── ExtractRegisterAs requested-type check (Scala CBox.getReg) ───
//
// Scala `CBox.getReg[T]` compares the stored register type against the
// requested `T`: a PRESENT register of a different type throws
// `InvalidType` — it does NOT degrade to `None`. Absent registers
// return `None` without a type check. Mandatory R0-R3 carry fixed
// types and are checked the same way. Pinned by the v5 vectors
// Advanced_Box_test (`x.R4[Byte].get` on an Int register → error) and
// Conditional_access_to_registers (`x.R5[Short]` on an Int register
// → error even before `.isDefined`).

#[test]
fn extract_register_requested_type_mismatch_errors() {
    // R4 stores Int(42); reading it as Long must error, not None.
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let err = run_eval_ctx_err(&extract_register_as(4, SigmaType::SLong), &ctx);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

#[test]
fn extract_register_absent_skips_type_check() {
    // R6 is absent; ANY requested type yields None — the type check
    // only applies to present registers.
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let expr = extract_register_as(6, SigmaType::SColl(Box::new(SigmaType::SByte)));
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Opt(None));
}

#[test]
fn extract_register_mandatory_r0_type_checked() {
    // R0 (box.value) is fixed at Long: reading as Long succeeds,
    // reading as Int errors (Scala stores it as a typed CAnyValue).
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    assert_eq!(
        run_eval_ctx(&extract_register_as(0, SigmaType::SLong), &ctx),
        Value::Opt(Some(Box::new(Value::Long(1_000_000_000))))
    );
    let err = run_eval_ctx_err(&extract_register_as(0, SigmaType::SInt), &ctx);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

#[test]
fn extract_register_mandatory_r3_creation_info_type() {
    // R3 (creationInfo) is fixed at (Int, Coll[Byte]).
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let good = SigmaType::STuple(vec![
        SigmaType::SInt,
        SigmaType::SColl(Box::new(SigmaType::SByte)),
    ]);
    assert!(matches!(
        run_eval_ctx(&extract_register_as(3, good), &ctx),
        Value::Opt(Some(_))
    ));
    let bad = SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong]);
    let err = run_eval_ctx_err(&extract_register_as(3, bad), &ctx);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

/// EIP-50 v6 `SBox.getReg[T]` (MethodCall 99, 19) is the method-call
/// twin of inline opcode `0xC6 ExtractRegisterAs`. Both call into
/// `read_register_option`, so on the same box + register id they
/// must produce byte-identical `Option[T]` values. The method takes
/// an INT index (Scala `SFunc(Array(SBox, SInt), SOption(tT))`) and
/// the wire layer reads the explicit `[T]` byte into
/// `Payload::MethodCall.type_args`, which `read_register_option`
/// enforces against the stored register type.
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
    let method_some = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 99,
            method_id: 19,
            obj: Box::new(op(0xA7, Payload::Zero)),
            args: vec![const_int(4)],
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
    let method_none = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 99,
            method_id: 19,
            obj: Box::new(op(0xA7, Payload::Zero)),
            args: vec![const_int(6)],
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
fn methodcall_box_getreg_v6_requested_type_mismatch_errors() {
    // v6 `SBox.getReg[T]` (99, 19) carries the explicit `[T]` in
    // type_args[0]; Scala resolves it into CBox.getReg(i)(tT), so a
    // present register of a different stored type errors on this path
    // exactly like the inline 0xC6 form (vector: Box.getReg_dynamic_index
    // reject-wrong-type#1).
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let getreg = |type_arg: SigmaType| {
        Expr::Op(IrNode {
            opcode: 0xDC,
            payload: Payload::MethodCall {
                type_id: 99,
                method_id: 19,
                obj: Box::new(op(0xA7, Payload::Zero)),
                args: vec![const_int(4)],
                type_args: vec![type_arg],
            },
        })
    };
    // R4 stores Int(42): matching [Int] succeeds...
    assert_eq!(
        run_eval_ctx(&getreg(SigmaType::SInt), &ctx),
        Value::Opt(Some(Box::new(Value::Int(42))))
    );
    // ...mismatching [Long] errors (no None degradation).
    let err = run_eval_ctx_err(&getreg(SigmaType::SLong), &ctx);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

// ── SBox.getReg dynamic index (Scala CBox.getReg + SBoxMethods) ──
//
// `getRegMethodV6` (99, 19) is `SFunc(Array(SBox, SInt), SOption(tT))`
// — an INT index. Scala `CBox.getReg(i)` returns None for
// `i < 0 || i >= 10` (out-of-range is not an error on this path).
// `getRegMethodV5` (99, 7) deserializes at all versions but ALWAYS
// throws on live evaluation (no reflection target for "getRegV5" on
// Box). Pinned by Box.getReg_dynamic_index.json and
// Box.getReg_adversarial.json.

#[test]
fn methodcall_box_getreg_v6_out_of_range_index_none() {
    // CBox.getReg: i < 0 || i >= 10 → None (no error, no type check).
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    assert_eq!(
        run_eval_ctx(&getreg_v6_int_index(10), &ctx),
        Value::Opt(None)
    );
    assert_eq!(
        run_eval_ctx(&getreg_v6_int_index(-1), &ctx),
        Value::Opt(None)
    );
}

#[test]
fn methodcall_box_getreg_v6_non_int_index_errors() {
    // The method signature takes SInt; a Byte index is a type error
    // (Scala would fail the reflective invoke).
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let expr = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 99,
            method_id: 19,
            obj: Box::new(op(0xA7, Payload::Zero)),
            args: vec![Expr::Const {
                tpe: SigmaType::SByte,
                val: SigmaValue::Byte(4),
            }],
            type_args: vec![SigmaType::SInt],
        },
    });
    let err = run_eval_ctx_err(&expr, &ctx);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

#[test]
fn methodcall_box_getreg_v6_rejected_in_pre_v3_tree() {
    // Method id 19 exists only in SBoxMethods.v6Methods, selected on
    // isV3OrLaterErgoTreeVersion — the TREE version. A v2 tree carrying a
    // (99, 19) call is rejected by the depth-0 `check_v3_only_methods` gate
    // (Scala `methodById` -> `_v5MethodsMap` has no id 19 -> ValidationException
    // at deserialize), before the call is reached — even when activated >= 3
    // (vector: Box.getReg_adversarial getReg-v6-method-in-v2-tree-reject#2).
    let b = make_test_box();
    let ctx = ReductionContext {
        ergo_tree_version: 2,
        ..ctx_with_self_box(&b)
    };
    let err = run_eval_ctx_err(&getreg_v6_int_index(4), &ctx);
    assert!(
        matches!(err, EvalError::PreV3V6Method { .. }),
        "got {err:?}"
    );
}

#[test]
fn v6_method_in_dead_branch_rejected_pre_v3_tree() {
    // The depth-0 `check_v3_only_methods` gate walks the WHOLE parsed body, so a
    // v6-only method in a DEAD `If` branch is rejected on a pre-v3 tree exactly
    // as Scala's eager deserialize does — even though lazy `If` evaluation never
    // reaches it (santa vector: Global.none_pre_v3_dead_branch). On a v3 tree the
    // gate is skipped and the lazy `If` returns the live branch.
    let b = make_test_box();
    // if (true) true else <(99,19) getReg — a v6-only method>
    let expr = op(
        0x95,
        Payload::Three(
            Box::new(op(0x7F, Payload::Zero)), // True (condition)
            Box::new(op(0x7F, Payload::Zero)), // True (live then-branch)
            Box::new(getreg_v6_int_index(4)),  // dead else-branch
        ),
    );
    let ctx_v2 = ReductionContext {
        ergo_tree_version: 2,
        ..ctx_with_self_box(&b)
    };
    let err = run_eval_ctx_err(&expr, &ctx_v2);
    assert!(
        matches!(err, EvalError::PreV3V6Method { .. }),
        "got {err:?}"
    );

    let ctx_v3 = ReductionContext {
        ergo_tree_version: 3,
        ..ctx_with_self_box(&b)
    };
    assert_eq!(run_eval_ctx(&expr, &ctx_v3), Value::Bool(true));
}

#[test]
fn unparsed_ergo_tree_body_eval_errors_not_true() {
    // A soft-fork-wrapped (unparsed) tree body must HARD-ERROR on evaluation —
    // Scala throws on an `UnparsedErgoTree` (no active soft-fork), so such a box
    // is unspendable, NOT trivially `true` (the prior `Const(true)` substitution
    // made it spendable — an accept-invalid / fork hazard).
    let body = Expr::Unparsed(hex::decode("0b01fd").unwrap().into());
    let err = run_eval_ctx_err(&body, &ReductionContext::minimal(500_000, 0));
    assert!(matches!(err, EvalError::UnparsedErgoTree), "got {err:?}");
}

#[test]
fn methodcall_box_getregv5_live_eval_errors() {
    // getRegV5 (99, 7) has no runtime implementation in Scala v6.0.x:
    // SMethod.javaMethod falls back to Box.getMethod("getRegV5", Int)
    // → NoSuchMethodException. Args evaluate first; the reject fires
    // even with a perfectly valid index (vector:
    // Box.getReg_adversarial getRegV5-live-reject#0).
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let expr = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 99,
            method_id: 7,
            obj: Box::new(op(0xA7, Payload::Zero)),
            args: vec![const_int(4)],
            type_args: vec![],
        },
    });
    let err = run_eval_ctx_err(&expr, &ctx);
    assert!(matches!(err, EvalError::RuntimeException(_)), "got {err:?}");
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
