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
