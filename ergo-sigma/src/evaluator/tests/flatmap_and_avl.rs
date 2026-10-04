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

#[test]
fn flatmap_empty_receiver_recovers_output_type_from_const_body() {
    use ergo_ser::sigma_value::CollValue;
    // Empty Coll[Int] receiver; mapper body is a Coll[Long] constant. The mapper
    // never runs, but the result must be an empty Coll[Long] — B recovered from
    // the body's static type — NOT the legacy Coll[Byte].
    let empty = const_coll_int(vec![]);
    let long_body = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SLong)),
        val: SigmaValue::Coll(CollValue::Values(vec![SigmaValue::Long(7)])),
    };
    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(long_body),
        },
    );
    let expr = op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 15,
            obj: Box::new(empty),
            args: vec![func],
            type_args: vec![],
        },
    );
    assert_eq!(run_eval(&expr), Value::CollLong(vec![]));
}

#[test]
fn flatmap_empty_receiver_recovers_output_type_from_concrete_collection_body() {
    // Same, but the mapper body is a ConcreteCollection (0x83) of Coll[Int]:
    // empty receiver → empty Coll[Int].
    let empty = const_coll_int(vec![]);
    let concrete_body = op(
        0x83,
        Payload::ConcreteCollection {
            elem_type: SigmaType::SInt,
            items: vec![const_int(5)],
        },
    );
    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(concrete_body),
        },
    );
    let expr = op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 15,
            obj: Box::new(empty),
            args: vec![func],
            type_args: vec![],
        },
    );
    assert_eq!(run_eval(&expr), Value::CollInt(vec![]));
}

// ── flatMap output: result carriers are copied, and charged before building ──
// Scala's CollOverArray.flatMap fills one primitive array. A result already in
// the output carrier is copied, never boxed into one 136-byte `Value` per
// element, and the output length is charged before the output exists.
// `UNPACKED_ELEMENTS` counts the elements this thread boxed; the receiver's own
// elements are the only expected ones.

fn flat_map_of(receiver: Expr, param: SigmaType, body: Expr) -> Expr {
    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(param))],
            body: Box::new(body),
        },
    );
    op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 15,
            obj: Box::new(receiver),
            args: vec![func],
            type_args: vec![],
        },
    )
}

fn unpacked_while<T>(run: impl FnOnce() -> T) -> (T, usize) {
    let before = UNPACKED_ELEMENTS.with(|count| count.get());
    let result = run();
    (result, UNPACKED_ELEMENTS.with(|count| count.get()) - before)
}

fn eval_flat_map(
    expr: &Expr,
    ctx: &ReductionContext<'_>,
    limit: Option<u64>,
) -> (Result<Value, EvalError>, u64) {
    let mut cost = limit.map_or_else(CostAccumulator::recording_only, |limit| {
        CostAccumulator::new(ergo_primitives::cost::JitCost::from_jit(limit))
    });
    let result = eval_expr(
        expr,
        ctx,
        &[],
        &mut Env::new(),
        &mut 0,
        &mut cost,
        &mut None,
    );
    (result, cost.total().value())
}

#[test]
fn flatmap_copies_typed_results_without_boxing_their_elements() {
    use ergo_ser::sigma_value::CollValue;
    let coll = |tpe: SigmaType, values: Vec<SigmaValue>| Expr::Const {
        tpe: SigmaType::SColl(Box::new(tpe)),
        val: SigmaValue::Coll(CollValue::Values(values)),
    };
    let property = |type_id: u8, method_id: u8, opcode: u8| {
        op(
            0xDB,
            Payload::MethodCall {
                type_id,
                method_id,
                obj: Box::new(op(opcode, Payload::Zero)),
                args: vec![],
                type_args: vec![],
            },
        )
    };
    let self_box = make_test_box();
    let headers = vec![test_eval_header_v2(); 3];
    let mut ctx = ctx_with_self_box(&self_box);
    ctx.last_headers = &headers;
    let n = 256;
    let proved = SigmaBoolean::TrivialProp(true);
    let cases = [
        ("Coll[Byte]", const_bytes(vec![7; n]), Value::CollBytes(vec![7; 2 * n])),
        (
            "Coll[Short]",
            coll(SigmaType::SShort, vec![SigmaValue::Short(9); n]),
            Value::CollShort(vec![9; 2 * n]),
        ),
        ("Coll[Int]", const_coll_int(vec![5; n]), Value::CollInt(vec![5; 2 * n])),
        (
            "Coll[Long]",
            coll(SigmaType::SLong, vec![SigmaValue::Long(3); n]),
            Value::CollLong(vec![3; 2 * n]),
        ),
        ("Coll[Boolean]", const_coll_bool(vec![true; n]), Value::CollBool(vec![true; 2 * n])),
        (
            "Coll[SigmaProp]",
            coll(SigmaType::SSigmaProp, vec![SigmaValue::SigmaProp(proved.clone()); n]),
            Value::CollSigmaProp(vec![proved; 2 * n]),
        ),
        (
            "SELF.tokens",
            property(99, 8, 0xA7),
            Value::Tokens(self_box.tokens.repeat(2)),
        ),
        (
            "CONTEXT.headers",
            property(101, 2, 0xFE),
            Value::CollHeader([&headers[..], &headers[..]].concat()),
        ),
    ];
    for (name, body, expected) in cases {
        let expr = flat_map_of(const_coll_int(vec![1, 2]), SigmaType::SInt, body);
        let (value, unpacked) = unpacked_while(|| run_eval_ctx(&expr, &ctx));
        assert!(value == expected, "{name}: flattened to {value:?}");
        assert_eq!(unpacked, 2, "{name}: only the two receiver elements are boxed");
    }
}

#[test]
fn flatmap_output_cost_is_charged_before_the_output_is_built() {
    // 64 receiver elements x 100 lazy OUTPUTS = 6,400 output boxes.
    let outputs = vec![make_test_box(); 100];
    let mut ctx = ReductionContext::minimal(500_000, 0);
    ctx.outputs = &outputs;
    let expr = flat_map_of(
        const_bytes(vec![0; 64]),
        SigmaType::SByte,
        op(0xA5, Payload::Zero),
    );
    let ((built, total), unpacked) = unpacked_while(|| eval_flat_map(&expr, &ctx, None));
    assert_eq!(collection_len(&built.unwrap(), &ctx), 6_400);
    assert_eq!(
        unpacked,
        64 + 6_400,
        "building a box output unpacks every lazy result"
    );
    // The flatMap charge comes last, so one unit less fails on that charge.
    let ((rejected, _), unpacked) =
        unpacked_while(|| eval_flat_map(&expr, &ctx, Some(total - 1)));
    assert!(
        matches!(rejected, Err(EvalError::CostExceeded(_))),
        "{rejected:?}"
    );
    assert_eq!(unpacked, 64, "an over-limit flatMap must not build its output");
}

#[test]
fn flatmap_result_type_errors_still_precede_the_output_cost() {
    // `x => if (x == 1) Coll(1) else other`: with another collection type or a
    // non-collection as `other`, the second result does not fit the Coll[Int]
    // output. Scala's cast fails while building the array, before flatMap_eval
    // charges for it.
    let ctx = ReductionContext::minimal(500_000, 0);
    let flat_map = |other: Expr| {
        let first = op(
            0x93,
            Payload::Two(
                Box::new(op(0x72, Payload::ValUse { id: 1 })),
                Box::new(const_int(1)),
            ),
        );
        let body = op(
            0x95,
            Payload::Three(
                Box::new(first),
                Box::new(const_coll_int(vec![1])),
                Box::new(other),
            ),
        );
        flat_map_of(const_coll_int(vec![1, 2]), SigmaType::SInt, body)
    };
    let (built, total) = eval_flat_map(&flat_map(const_coll_int(vec![1])), &ctx, None);
    assert_eq!(built.unwrap(), Value::CollInt(vec![1, 1]));
    for (other, error) in [
        (const_bytes(vec![1]), "Int in collection"),
        (const_int(5), "collection for lambda operation"),
    ] {
        // The flatMap charge is the well-typed twin's last one, so only that
        // charge exceeds this limit. The type error is still reported.
        let (limited, _) = eval_flat_map(&flat_map(other), &ctx, Some(total - 1));
        assert!(
            matches!(&limited, Err(EvalError::TypeError { expected, .. }) if *expected == error),
            "{limited:?}"
        );
    }
}

// The Scala-captured mixed-carrier fixture asserts only `size == 2` for its box
// cases, which a nested `[SELF, Coll(SELF)]` also satisfies. Evaluate each
// captured tree's own flatMap instead. Scala's `CollOverArray.flatMap` is
// `builder.fromArray(toArray.flatMap(x => f(x).toArray))`: every element of
// every result, in receiver order. Rust carries Coll[Box] as `CollBox`, and a
// `(Coll[Byte], Long)` collection with a non-32-byte id as `CollGeneric`
// tagged with that pair type.
#[test]
fn flatmap_mixed_carrier_fixture_results_are_flat() {
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::ergo_tree::read_ergo_tree;
    fn find_flat_map(expr: &Expr) -> Option<&Expr> {
        let Expr::Op(node) = expr else { return None };
        match &node.payload {
            Payload::MethodCall {
                type_id: 12,
                method_id: 15,
                ..
            } => Some(expr),
            Payload::One(a) => find_flat_map(a),
            Payload::Two(a, b) => find_flat_map(a).or_else(|| find_flat_map(b)),
            Payload::BlockValue { items, result } => items
                .iter()
                .find_map(find_flat_map)
                .or_else(|| find_flat_map(result)),
            Payload::ValDef { rhs, .. } => find_flat_map(rhs),
            _ => None,
        }
    }
    let pair = |id: Vec<u8>, amount| Value::Tuple(vec![Value::CollBytes(id), Value::Long(amount)]);
    let pairs = |items| {
        Value::CollGeneric(
            items,
            Box::new(SigmaType::STuple(vec![
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaType::SLong,
            ])),
        )
    };
    // HEIGHT is 0: x == HEIGHT yields the 32-byte id, x == 1 a one-byte id.
    let (wide, narrow) = (pair(vec![1; 32], 0), pair(vec![1], 1));
    let input = Value::BoxRef {
        source: BoxSource::Inputs,
        index: 0,
    };
    let expected = [
        (
            "flatmap-mixed-width-token-first",
            pairs(vec![wide.clone(), narrow.clone()]),
        ),
        ("flatmap-mixed-width-generic-first", pairs(vec![narrow, wide])),
        (
            "flatmap-mixed-box-generic-first",
            Value::CollBox(vec![Value::SelfBox, Value::SelfBox]),
        ),
        (
            "flatmap-mixed-box-specialized-first",
            Value::CollBox(vec![Value::SelfBox, Value::SelfBox]),
        ),
        (
            "flatmap-box-input-lazy-first",
            Value::CollBox(vec![input.clone(), Value::SelfBox]),
        ),
        (
            "flatmap-box-input-materialized-first",
            Value::CollBox(vec![Value::SelfBox, input]),
        ),
    ];
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../test-vectors/ergo-sigma/mixed-collection-types/cases.json"
    ))
    .unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), expected.len(), "complete fixture denominator");
    for (case, (id, expected)) in cases.iter().zip(expected) {
        assert_eq!(case["id"], id);
        let bytes = hex::decode(case["tree_hex"].as_str().unwrap()).unwrap();
        let tree = read_ergo_tree(&mut VlqReader::new(&bytes)).unwrap();
        // The same SELF/input context as the fixture's own test.
        let mut self_box = EvalBox::simple(0, bytes);
        self_box.value = 1_000_000;
        let inputs = [self_box.clone()];
        let mut ctx = ReductionContext::minimal(0, 0);
        ctx.self_box = Some(&self_box);
        ctx.inputs = &inputs;
        let flat_map = find_flat_map(&tree.body).unwrap();
        let value = eval_to_value(flat_map, &ctx, &tree.constants).unwrap();
        // Debug equality also pins the carrier and its element-type tag.
        assert_eq!(format!("{value:?}"), format!("{expected:?}"), "{id}");
    }
}

// ── AvlTree.updateDigest (100,15) / updateOperations (100,8) + variable digest ──

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
    // Higher bits (>= 0x08) are IGNORED (Scala AvlTreeFlags decodes only the
    // low 3 bits): 0xF8 -> low 3 bits clear -> all false; 0xFF (-1) -> all set.
    let cases: &[(i8, bool, bool, bool)] = &[
        (0, false, false, false),
        (7, true, true, true),
        (1, true, false, false),
        (2, false, true, false),
        (4, false, false, true),
        (0xF8u8 as i8, false, false, false),
        (-1, true, true, true),
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

#[test]
fn avltree_update_digest_operations_fixed_cost_invariant() {
    // updateDigest (100,15) = FixedCost(40), updateOperations (100,8) =
    // FixedCost(45): the eval cost must NOT vary with the digest length or the
    // flags value (a regression guard against per-input cost drift). The
    // absolute totals here use Expr::Const framing, not the vectors'
    // ConstPlaceholder framing — the SANTA vectors pin the exact 46/51.
    let ctx = ReductionContext::minimal(0, 0);
    let cost_of = |e: &Expr| {
        let mut env = Env::new();
        let mut depth = 0usize;
        let mut acc = CostAccumulator::recording_only();
        let mut trace = None;
        eval_expr(e, &ctx, &[], &mut env, &mut depth, &mut acc, &mut trace).unwrap();
        acc.total().value()
    };
    // updateDigest: empty / 3-byte / 33-byte digests all cost the same.
    let ud = |d: Vec<u8>| avl_method(avl_const_expr(vec![0x07; 33]), 15, vec![const_bytes(d)]);
    let c_ud = cost_of(&ud(vec![]));
    assert_eq!(
        cost_of(&ud(vec![1, 2, 3])),
        c_ud,
        "updateDigest cost is digest-length-independent (FixedCost)",
    );
    assert_eq!(cost_of(&ud(vec![0xAB; 33])), c_ud);
    // updateOperations: flags 0 / 7 / 0xFF all cost the same.
    let uo = |f: i8| {
        avl_method(
            avl_const_expr(vec![0x07; 33]),
            8,
            vec![Expr::Const {
                tpe: SigmaType::SByte,
                val: SigmaValue::Byte(f),
            }],
        )
    };
    let c_uo = cost_of(&uo(0));
    assert_eq!(
        cost_of(&uo(7)),
        c_uo,
        "updateOperations cost is flags-value-independent (FixedCost)",
    );
    assert_eq!(cost_of(&uo(-1)), c_uo);
    // Framing is identical (Const obj + MethodCall + Const arg), so the only
    // difference is the method body: updateOperations(45) - updateDigest(40) = 5.
    // Additive form (not `c_uo - c_ud == 5`) so a cost regression that makes
    // c_uo < c_ud surfaces as a value mismatch rather than a u64 underflow panic.
    assert_eq!(
        c_uo,
        c_ud + 5,
        "updateOperations FixedCost(45) - updateDigest FixedCost(40) = 5",
    );
}

