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
