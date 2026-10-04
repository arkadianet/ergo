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
    // Build a chain of 200 nested If(true, If(true, ... , 1), 0), which
    // exceeds MAX_EVAL_DEPTH (110). This AST is built directly (bypassing the
    // parser), so the runtime guard is the only backstop against stack
    // overflow on such inputs — keep it.
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

// SIG-2 — the evaluator must accept every depth the PARSER accepts. The parser
// cap (ergo_ser MAX_EXPR_DEPTH = Scala MaxTreeDepth = 110, oracle-pinned) lets a
// tree up to 110 levels deep parse; the evaluator must not reject it at a lower
// bound. 105 nested Ifs reach eval-depth ~106 — above the OLD 100 cap (RED) but
// within the new 110 cap (GREEN) — and must evaluate to the inner Int(1).
#[test]
fn eval_accepts_parser_max_depth() {
    let mut expr = const_int(1);
    for _ in 0..105 {
        expr = op(
            0x95,
            Payload::Three(
                Box::new(const_bool(true)),
                Box::new(expr),
                Box::new(const_int(0)),
            ),
        );
    }
    assert_eq!(run_eval(&expr), Value::Int(1));
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

/// SelectField on a non-pair `STuple` must error: Scala's
/// `Evaluation.toDslTuple` (`Evaluation.scala:99-102`) materializes an arity
/// != 2 tuple as the raw `Coll`, and `SelectField.eval`
/// (`transformers.scala:295-306`) matches only `Tuple2` — anything else falls
/// to `Value.typeError`. SANTA `SelectField.non_pair` pins the 1-tuple case;
/// the 5-tuple case is the same rule (a >2 tuple never indexes).
#[test]
fn select_field_on_non_pair_tuple_errors() {
    for tuple in [
        int_tuple_const(&[5]),
        int_tuple_const(&[10, 20, 30, 40, 50]),
    ] {
        for field_idx in [1u8, 2, 3] {
            let e = op(
                0x8C,
                Payload::SelectField {
                    input: Box::new(tuple.clone()),
                    field_idx,
                },
            );
            let err = run_eval_err(&e);
            assert!(
                matches!(err, EvalError::TypeError { .. }),
                "SelectField on a non-pair tuple must error, got {err:?}"
            );
        }
    }
}

/// SelectField with field_idx 1/2 on a PAIR is the Scala-emitted form of
/// tuple field access (`Tuple2`).
#[test]
fn select_field_1_2_on_pair() {
    let tuple = int_tuple_const(&[10, 20]);
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
            input: Box::new(tuple),
            field_idx: 2,
        },
    );
    assert_eq!(run_eval(&s1), Value::Int(10));
    assert_eq!(run_eval(&s2), Value::Int(20));
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

/// 0xA6 must return the AvlTreeData unchanged, not synthesize metadata
/// from the header digest. Non-default flags +
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
