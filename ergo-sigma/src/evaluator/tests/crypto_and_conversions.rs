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
fn sigma_and_or_evaluate_all_operands_no_short_circuit() {
    // Scala SigmaAnd/SigmaOr evaluate EVERY operand (charging each) before the
    // trivial collapse — they are not boolean short-circuits. So an absorbing
    // first operand (FalseProp for AND, TrueProp for OR) must NOT skip the
    // later operands' evaluation. (This is the +15 cost divergence the fix
    // closes; it also corrects the value/error on a later erroring operand.)
    // FalseProp && <Int> must EVALUATE the Int (erroring on its type), not
    // short-circuit to FalseProp.
    let and = op(
        0xEA,
        Payload::SigmaCollection {
            items: vec![
                op(0xD1, Payload::One(Box::new(const_bool(false)))),
                const_int(5),
            ],
        },
    );
    assert!(
        matches!(run_eval_err(&and), EvalError::TypeError { .. }),
        "SigmaAnd must evaluate all operands (no short-circuit)",
    );
    // TrueProp || <Int> — symmetric.
    let or = op(
        0xEB,
        Payload::SigmaCollection {
            items: vec![
                op(0xD1, Payload::One(Box::new(const_bool(true)))),
                const_int(5),
            ],
        },
    );
    assert!(
        matches!(run_eval_err(&or), EvalError::TypeError { .. }),
        "SigmaOr must evaluate all operands (no short-circuit)",
    );
    // Collapse value is unchanged: FalseProp && TrueProp -> FalseProp.
    let collapse = op(
        0xEA,
        Payload::SigmaCollection {
            items: vec![
                op(0xD1, Payload::One(Box::new(const_bool(false)))),
                op(0xD1, Payload::One(Box::new(const_bool(true)))),
            ],
        },
    );
    assert!(matches!(
        run_eval(&collapse),
        Value::SigmaProp(SigmaBoolean::TrivialProp(false))
    ));
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

#[test]
fn opcode_decode_point_rejects_off_curve() {
    // 0x04 (uncompressed) prefix with only 33 bytes is an invalid SEC1
    // encoding; BouncyCastle/k256 reject it, so Scala errors. We previously
    // accepted it verbatim as a GroupElement (accept-invalid SECURITY bug).
    let mut b = vec![0u8; 33];
    b[0] = 0x04;
    let expr = op(0xEE, Payload::One(Box::new(const_bytes(b))));
    assert!(
        matches!(run_eval_err(&expr), EvalError::TypeError { .. }),
        "off-curve / malformed SEC1 point must error",
    );
}

#[test]
fn opcode_decode_point_zero_lead_canonicalizes_to_identity() {
    // Leading 0x00 -> infinity; the canonical encoding is 33 zero bytes and any
    // trailing X bytes are discarded (CryptoContext.default.infinity).
    let mut b = vec![0u8; 40];
    b[1..].fill(0xAB); // non-zero trailing, must be dropped
    let expr = op(0xEE, Payload::One(Box::new(const_bytes(b))));
    assert_eq!(run_eval(&expr), Value::GroupElement([0u8; 33]));
}

#[test]
fn canonicalize_group_element_helper() {
    use super::opcodes::sigma::canonicalize_group_element;
    // Valid compressed generator -> itself (already canonical).
    let g: [u8; 33] = [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];
    assert_eq!(canonicalize_group_element(g).unwrap(), g);
    // 0x00-lead (with garbage trailing) -> canonical identity (33 zeros).
    let mut z = [0u8; 33];
    z[1..].fill(0xAA);
    assert_eq!(canonicalize_group_element(z).unwrap(), [0u8; 33]);
    // Off-curve / malformed SEC1 -> error.
    let mut bad = [0u8; 33];
    bad[0] = 0x04;
    assert!(canonicalize_group_element(bad).is_err());
}

#[test]
fn group_element_constant_materialization_canonicalizes() {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaValue as SV;
    // A 0x00-lead GroupElement CONSTANT materializes to the canonical identity
    // (sigma_to_value applies the GroupElementSerializer.parse canonicalization,
    // not just decodePoint).
    let mut garbage = [0u8; 33];
    garbage[1..].fill(0xAA);
    let c = Expr::Const {
        tpe: SigmaType::SGroupElement,
        val: SV::GroupElement(GroupElement::from_bytes(garbage)),
    };
    assert_eq!(run_eval(&c), Value::GroupElement([0u8; 33]));
    // An off-curve GE constant errors at materialization (even though Scala/our
    // wire parse stores it raw — the value-basis check fires when materialized).
    let mut bad = [0u8; 33];
    bad[0] = 0x04;
    let c_bad = Expr::Const {
        tpe: SigmaType::SGroupElement,
        val: SV::GroupElement(GroupElement::from_bytes(bad)),
    };
    assert!(matches!(run_eval_err(&c_bad), EvalError::TypeError { .. }));
}

#[test]
fn opcode_decode_point_wrong_length_errors() {
    // < 33 bytes: Scala's getBytes(33) underflows -> error.
    let expr = op(0xEE, Payload::One(Box::new(const_bytes(vec![0x02; 32]))));
    assert!(matches!(run_eval_err(&expr), EvalError::TypeError { .. }));
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
    // An ABSENT var id yields None...
    assert_eq!(
        run_eval_ctx(&inline(99, SigmaType::SInt), &ctx),
        Value::Opt(None)
    );
    // ...but a PRESENT var of the wrong type is an error, not None. Scala's
    // `CContext.getVar` (`sigmastate/eval/CContext.scala:60-74`) throws
    // `InvalidType("Cannot getVar[Long](7): invalid type of value ...")` in
    // that case; returning None here would satisfy scripts the reference
    // node rejects.
    assert!(
        matches!(
            run_eval_ctx_err(&inline(7, SigmaType::SLong), &ctx),
            EvalError::TypeError { .. }
        ),
        "a present context var of the wrong type must fail, not read as None",
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

/// EIP-50 v6 `SGlobal.deserializeTo[T]` (MethodCall 106, 4) — Scala
/// `SGlobalMethods.deserializeTo_eval` delegates to
/// `DataSerializer.deserialize(typeArg, reader)`, which reads raw
/// typed value bytes (NOT an expression body). For `SBoolean`,
/// `DataSerializer.deserialize` is `r.getUByte() != 0` — non-strict,
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
/// fork hazard, GHSA-hfj8-hjph-7r78).
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
    // deserializeTo (106, 4) is v6-only on SGlobal (pre-v3 SGlobal = {1,2}),
    // so a v<3 main-body tree carrying it is rejected at the depth-0
    // `check_v3_only_methods` gate (Scala: method-resolution ValidationException
    // at deserialize) regardless of the activated version.
    assert!(
        matches!(
            eval_to_value(&expr, &ctx, &[]),
            Err(EvalError::PreV3V6Method { .. })
        ),
        "deserializeTo[SHeader] on a v<3 ErgoTree must reject (v6-only method)"
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
    let hv = SigmaValue::Header(Box::new(h), [0u8; 32]);
    assert!(
        crate::evaluator::helpers::sigma_to_value_versioned(&SigmaType::SHeader, &hv, &ctx_v2)
            .is_err(),
        "an actual SHeader value must be gated on a v<3 tree"
    );
}

/// SOption materialization mirrors the SHeader gate: `sigma_to_value_versioned`
/// is the shared boundary for register values (ExtractRegisterAs), context vars,
/// plain constants and `deserializeTo`, so a materialized Option on a v<3 tree
/// is rejected there (matching `CoreDataSerializer`'s v3-gated `SOption` case
/// and the reference's pre-v3 register/context rejection). The gate is
/// value-based: an empty `Coll[Option[T]]` materializes none and is accepted.
#[test]
fn soption_materialization_gate_is_value_based_not_type_based() {
    let ctx_v2 = ReductionContext {
        ergo_tree_version: 2,
        ..ReductionContext::minimal(0, 0)
    };
    // Empty Coll[Option[Int]] on a v<3 tree: NOT gated (no Option materialized).
    let empty = SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Values(vec![]));
    let t = SigmaType::SColl(Box::new(SigmaType::SOption(Box::new(SigmaType::SInt))));
    assert!(
        crate::evaluator::helpers::sigma_to_value_versioned(&t, &empty, &ctx_v2).is_ok(),
        "empty Coll[Option] must not be gated on a v<3 tree"
    );
    // A materialized Some(5) on a v<3 tree IS gated, on the bare boundary that
    // registers / context vars / deserializeTo all funnel through.
    let some = SigmaValue::Opt(Some(Box::new(SigmaValue::Int(5))));
    let ot = SigmaType::SOption(Box::new(SigmaType::SInt));
    assert!(
        crate::evaluator::helpers::sigma_to_value_versioned(&ot, &some, &ctx_v2).is_err(),
        "a materialized Option value must be gated on a v<3 tree"
    );
    // And on a v3 tree it is accepted (CoreDataSerializer matches SOption at v3+).
    let ctx_v3 = ReductionContext {
        ergo_tree_version: 3,
        ..ReductionContext::minimal(0, 0)
    };
    assert!(
        crate::evaluator::helpers::sigma_to_value_versioned(&ot, &some, &ctx_v3).is_ok(),
        "a materialized Option value must be accepted on a v3 tree"
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
            Sv::SigmaProp(SigmaBoolean::Cand(
                vec![
                    SigmaBoolean::TrivialProp(true),
                    SigmaBoolean::TrivialProp(false),
                ]
                .into()
            ))
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
    // pairs). Scala materializes such a constant as the raw `Coll`
    // (`Evaluation.toDslTuple`, arity != 2) and `SelectField.eval` matches
    // only `Tuple2`, so the arm must ERROR — the opcode routing is still
    // exercised, but a non-pair tuple never indexes.
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
    for e in [s4, s5] {
        assert!(matches!(run_eval_err(&e), EvalError::TypeError { .. }));
    }
}
