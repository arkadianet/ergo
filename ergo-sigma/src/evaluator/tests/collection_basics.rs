// ── Batch 2: Collection operations ──────────────────────────────

#[test]
fn opcode_by_index_in_range() {
    let coll = const_bytes(vec![10, 20, 30]);
    let expr = op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(coll),
            index: Box::new(const_int(1)),
            default: None,
        },
    );
    // ByIndex on Coll[Byte] surfaces Value::Byte at the element
    // boundary, not erased Int.
    assert_eq!(run_eval(&expr), Value::Byte(20));
}

#[test]
fn opcode_by_index_out_of_range_no_default() {
    let coll = const_bytes(vec![10, 20, 30]);
    let expr = op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(coll),
            index: Box::new(const_int(5)),
            default: None,
        },
    );
    let err = run_eval_err(&expr);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

// ── ByIndex default: eager pre-v3, lazy v3+ (Scala ByIndex.eval) ─
//
// Scala `ByIndex.eval` (transformers.scala): with a default present,
// a pre-v3 tree evaluates the default eagerly after the index — its
// cost (and any error) lands even when the index is in bounds. A v3+
// tree (`isV3OrLaterErgoTreeVersion`) evaluates the default lazily,
// only on an out-of-bounds index. Pinned by the
// Coll_getOrElse_method_equivalence vector (v5: uniform cost across
// hit and miss entries) and Coll_getOrElse_with_lazy_default (v6).

#[test]
fn by_index_default_pre_v3_eager_uniform_cost() {
    // Pre-v3: the default is evaluated on hit AND miss, so total cost
    // is identical across the two — exactly what the v5 vector pins
    // (uniform 162 across all entries).
    let ctx = ctx_with_tree_version(2);
    let hit = by_index_with_default(const_coll_int(vec![10, 20, 30]), 1, costed_default());
    let miss = by_index_with_default(const_coll_int(vec![10, 20, 30]), 5, costed_default());
    let (hit_val, hit_cost) = eval_value_and_cost(&hit, &ctx);
    let (miss_val, miss_cost) = eval_value_and_cost(&miss, &ctx);
    assert_eq!(hit_val.unwrap(), Value::Int(20));
    assert_eq!(miss_val.unwrap(), Value::Int(2)); // SizeOf(Coll(7,8))
    assert_eq!(
        hit_cost, miss_cost,
        "pre-v3 hit must include the default's eval cost"
    );
}

#[test]
fn by_index_default_pre_v3_eager_error_fires_on_hit() {
    // Pre-v3: an erroring default poisons the whole node even when the
    // index is in bounds.
    let ctx = ctx_with_tree_version(2);
    let hit = by_index_with_default(const_coll_int(vec![10, 20, 30]), 1, erroring_default());
    let (val, _) = eval_value_and_cost(&hit, &ctx);
    assert!(
        matches!(val, Err(EvalError::TypeError { .. })),
        "got {val:?}"
    );
}

#[test]
fn by_index_default_v3_lazy_skips_default_on_hit() {
    // V3+: the default is not evaluated on hit — neither its error
    // nor its cost lands.
    let ctx = ctx_with_tree_version(3);
    let hit_err = by_index_with_default(const_coll_int(vec![10, 20, 30]), 1, erroring_default());
    let (val, _) = eval_value_and_cost(&hit_err, &ctx);
    assert_eq!(val.unwrap(), Value::Int(20));

    let hit = by_index_with_default(const_coll_int(vec![10, 20, 30]), 1, costed_default());
    let miss = by_index_with_default(const_coll_int(vec![10, 20, 30]), 5, costed_default());
    let (_, hit_cost) = eval_value_and_cost(&hit, &ctx);
    let (_, miss_cost) = eval_value_and_cost(&miss, &ctx);
    assert!(
        hit_cost < miss_cost,
        "v3 hit ({hit_cost}) must not pay the default's cost ({miss_cost})"
    );
}

#[test]
fn by_index_default_pre_v3_miss_evaluates_default_once() {
    // The pre-v3 eager value is handed to the miss path — NOT
    // re-evaluated. Totals across versions must agree on a miss
    // (identical component set: input + index + default + ByIndex).
    let miss = by_index_with_default(const_coll_int(vec![10, 20, 30]), 5, costed_default());
    let (v2_val, v2_cost) = eval_value_and_cost(&miss, &ctx_with_tree_version(2));
    let (v3_val, v3_cost) = eval_value_and_cost(&miss, &ctx_with_tree_version(3));
    assert_eq!(v2_val.unwrap(), Value::Int(2));
    assert_eq!(v3_val.unwrap(), Value::Int(2));
    assert_eq!(
        v2_cost, v3_cost,
        "pre-v3 miss must charge the default exactly once"
    );
}

#[test]
fn opcode_append_bytes() {
    let a = const_bytes(vec![1, 2]);
    let b = const_bytes(vec![3, 4]);
    let expr = op(0xB3, Payload::Two(Box::new(a), Box::new(b)));
    assert_eq!(run_eval(&expr), Value::CollBytes(vec![1, 2, 3, 4]));
}

#[test]
fn opcode_slice_bytes() {
    let coll = const_bytes(vec![10, 20, 30, 40, 50]);
    let expr = op(
        0xB4,
        Payload::Three(
            Box::new(coll),
            Box::new(const_int(1)),
            Box::new(const_int(4)),
        ),
    );
    assert_eq!(run_eval(&expr), Value::CollBytes(vec![20, 30, 40]));
}

#[test]
fn opcode_map_int_collection() {
    let coll = const_coll_int(vec![1, 2, 3]);
    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x9A,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    Box::new(const_int(10)),
                ),
            )),
        },
    );
    let expr = op(0xAD, Payload::Two(Box::new(coll), Box::new(func)));
    assert_eq!(run_eval(&expr), Value::CollInt(vec![11, 12, 13]));
}

#[test]
fn opcode_filter_int_collection() {
    let coll = const_coll_int(vec![1, 2, 3, 4]);
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
    let expr = op(0xB5, Payload::Two(Box::new(coll), Box::new(pred)));
    assert_eq!(run_eval(&expr), Value::CollInt(vec![3, 4]));
}

#[test]
fn opcode_exists_true() {
    let coll = const_coll_int(vec![1, 2, 3]);
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
    let expr = op(0xAE, Payload::Two(Box::new(coll), Box::new(pred)));
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

#[test]
fn opcode_exists_false() {
    let coll = const_coll_int(vec![1, 2, 3]);
    let pred = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x93,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    Box::new(const_int(99)),
                ),
            )),
        },
    );
    let expr = op(0xAE, Payload::Two(Box::new(coll), Box::new(pred)));
    assert_eq!(run_eval(&expr), Value::Bool(false));
}

#[test]
fn opcode_forall_true() {
    let coll = const_coll_int(vec![10, 20, 30]);
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
    let expr = op(0xAF, Payload::Two(Box::new(coll), Box::new(pred)));
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

#[test]
fn opcode_fold_sum() {
    let coll = const_coll_int(vec![1, 2, 3, 4]);
    let zero = const_int(0);
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
    let expr = op(
        0xB0,
        Payload::Three(Box::new(coll), Box::new(zero), Box::new(func)),
    );
    assert_eq!(run_eval(&expr), Value::Int(10));
}

#[test]
fn opcode_and_collection_all_true() {
    let coll = const_coll_bool(vec![true, true, true]);
    let expr = op(0x96, Payload::One(Box::new(coll)));
    assert_eq!(run_eval(&expr), Value::Bool(true));
}

#[test]
fn opcode_and_collection_one_false() {
    let coll = const_coll_bool(vec![true, false, true]);
    let expr = op(0x96, Payload::One(Box::new(coll)));
    assert_eq!(run_eval(&expr), Value::Bool(false));
}

#[test]
fn opcode_or_collection() {
    let coll = const_coll_bool(vec![false, true, false]);
    let expr = op(0x97, Payload::One(Box::new(coll)));
    assert_eq!(run_eval(&expr), Value::Bool(true));
}
