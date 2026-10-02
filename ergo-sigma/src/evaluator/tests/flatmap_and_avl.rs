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
