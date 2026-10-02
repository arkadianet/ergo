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
