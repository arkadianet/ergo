// ----- Coll.patch index-bounds parity (Scala-bytecode-verified) -----
//
// Oracle: Scala 2.13.16 `scala-library` JAR, `scala.collection.ArrayOps$
// .patch$extension` (decoded from bytecode of the cached coursier JAR).
// sigma-state's `CollsOverArrays.scala:94-98` delegates to
// `Array[A].patch(from, patch.toArray, replaced)`, which is exactly
// that extension method. `immutable.Vector.patch` resolves through
// `immutable.StrictOptimizedSeqOps.patch` and produces identical results
// for negative inputs (also bytecode-verified). The re-extractable
// oracle script + disassembly recipe is in
// `test-vectors/ergo-sigma/coll-negative-index-parity/`.
//
// Decoded algorithm (locals 1=from, 3=replaced, 4=builder, 5=counter):
//
//     chunk1            = if (from > 0) min(from, xs.length) else 0
//     clampedReplaced   = if (replaced < 0) 0 else replaced
//     chunk2            = xs.length - chunk1 - clampedReplaced
//     if (chunk2 > 0):
//         suffix = xs[xs.length - chunk2 .. xs.length]
//     else:
//         suffix = []                                        // no throw
//     result = xs[0..chunk1] ++ patch ++ suffix
//
// Both `from < 0` and `replaced < 0` clamp silently to 0; the Scala
// path does NOT throw `IndexOutOfBoundsException` for either.
// `Coll.updated` is the only Coll method whose Scala backing delegates
// to `Array.updated`, which DOES throw — see the `coll_updated_*` arms
// above.
//
// The Rust impl `coll.splice(from.min(n) .. (from + replaced).min(n),
// patch)` after `from = max(0, n_int) as usize` / `replaced = max(0,
// n_int) as usize` is byte-identical to the Scala chunk1/chunk2 model
// for every i32 input pair. These tests pin the byte-exact parity at
// the negative-index boundary plus the i32 extremes so a future
// "fix on negative" patch would fail visibly.

#[test]
fn coll_patch_happy_path_regression_guard() {
    // patch(0, [99], 2) on [1..5] → splice middle.
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], 0, vec![99], 2),
        vec![99, 3, 4, 5],
    );
}

#[test]
fn coll_patch_negative_from_clamps_to_zero() {
    // patch(-1, [99], 2): Scala chunk1 = 0, clampedReplaced = 2,
    // chunk2 = 5 - 0 - 2 = 3, suffix = xs[2..5] = [3,4,5].
    // Result must equal patch(0, [99], 2) — both clamp negative `from`.
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], -1, vec![99], 2),
        vec![99, 3, 4, 5],
    );
}

#[test]
fn coll_patch_negative_replaced_with_from_zero_is_pure_insertion() {
    // patch(0, [99], -1): Scala clampedReplaced = 0, chunk2 = 5,
    // suffix = xs[0..5]. Result = [] ++ [99] ++ xs = pure prepend.
    // Negative `replaced` does NOT throw; it clamps to 0.
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], 0, vec![99], -1),
        vec![99, 1, 2, 3, 4, 5],
    );
}

#[test]
fn coll_patch_negative_replaced_with_positive_from_is_insertion_at_from() {
    // patch(2, [99], -1): chunk1 = 2, clampedReplaced = 0,
    // chunk2 = 5 - 2 - 0 = 3, suffix = xs[2..5]. Result inserts at
    // index 2 without removing — equivalent to insertAt(2, [99]).
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], 2, vec![99], -1),
        vec![1, 2, 99, 3, 4, 5],
    );
}

#[test]
fn coll_patch_from_past_length_appends() {
    // patch(10, [99], 2) on [1..5]: chunk1 = min(10, 5) = 5,
    // clampedReplaced = 2, chunk2 = 5 - 5 - 2 = -2, no suffix.
    // Result = xs ++ [99].
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], 10, vec![99], 2),
        vec![1, 2, 3, 4, 5, 99],
    );
}

#[test]
fn coll_patch_replaced_past_remaining_truncates_tail() {
    // patch(2, [99], 100): chunk1 = 2, clampedReplaced = 100,
    // chunk2 = 5 - 2 - 100 = -97, no suffix. Result = [1,2] ++ [99].
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], 2, vec![99], 100),
        vec![1, 2, 99],
    );
}

#[test]
fn coll_patch_i32_max_from_clamps_to_length() {
    // patch(i32::MAX, [99], 1): chunk1 = min(i32::MAX, 5) = 5,
    // clampedReplaced = 1, chunk2 = 5 - 5 - 1 = -1, no suffix.
    // Result = xs ++ [99].
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], i32::MAX, vec![99], 1),
        vec![1, 2, 3, 4, 5, 99],
    );
}

#[test]
fn coll_patch_i32_min_from_clamps_to_zero() {
    // patch(i32::MIN, [99], 10): chunk1 = 0, clampedReplaced = 10,
    // chunk2 = 5 - 0 - 10 = -5, no suffix. Result = [99].
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], i32::MIN, vec![99], 10),
        vec![99],
    );
}

#[test]
fn coll_patch_i32_max_replaced_truncates_tail() {
    // patch(2, [99], i32::MAX): chunk1 = 2, clampedReplaced = i32::MAX,
    // chunk2 = 5 - 2 - i32::MAX (no JVM wrap, fits in i32 as a large
    // negative), no suffix. Result = [1,2] ++ [99].
    assert_eq!(
        run_patch_int(vec![1, 2, 3, 4, 5], 2, vec![99], i32::MAX),
        vec![1, 2, 99],
    );
}

#[test]
fn coll_patch_bytes_carrier_negative_from() {
    // Byte carrier — exercise the CollBytes splice arm at the negative
    // boundary so a future divergent fix can't slip through one carrier.
    let expr = coll_patch_call(
        const_bytes(vec![1, 2, 3, 4, 5]),
        -1,
        const_bytes(vec![99]),
        2,
    );
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[]).unwrap();
    match v {
        Value::CollBytes(c) => assert_eq!(c, vec![99, 3, 4, 5]),
        other => panic!("expected CollBytes, got {other:?}"),
    }
}

#[test]
fn coll_patch_long_carrier_negative_replaced() {
    // Long carrier, negative replaced — pure insertion at from=1.
    let expr = coll_patch_call(
        const_coll_long(vec![10, 20, 30]),
        1,
        const_coll_long(vec![99]),
        -5,
    );
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[]).unwrap();
    match v {
        Value::CollLong(c) => assert_eq!(c, vec![10, 99, 20, 30]),
        other => panic!("expected CollLong, got {other:?}"),
    }
}

#[test]
fn coll_patch_short_carrier() {
    // Scala `Coll[A].patch` accepts every element type, but the previous impl
    // only matched Byte/Int/Long carriers and rejected `Coll[Short]` — a
    // reject-valid. patch([1,2,3,4,5], 1, [99], 2) → [1, 99, 4, 5].
    let expr = coll_patch_call(
        const_coll_short(vec![1, 2, 3, 4, 5]),
        1,
        const_coll_short(vec![99]),
        2,
    );
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[]).unwrap();
    match v {
        Value::CollShort(c) => assert_eq!(c, vec![1, 99, 4, 5]),
        other => panic!("expected CollShort, got {other:?}"),
    }
}

#[test]
fn coll_patch_bool_carrier() {
    // `Coll[Boolean]` was likewise rejected. patch([T,T,T], 1, [F], 1) →
    // [T, F, T].
    let expr = coll_patch_call(
        const_coll_bool(vec![true, true, true]),
        1,
        const_coll_bool(vec![false]),
        1,
    );
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[]).unwrap();
    match v {
        Value::CollBool(c) => assert_eq!(c, vec![true, false, true]),
        other => panic!("expected CollBool, got {other:?}"),
    }
}

// ----- Coll.indexOf / Slice negative-input guards -----
//
// These guard tests lock the contract split: any future "negative
// collection index" refactor that routes both `indexOf` and `Slice`
// through a single throws-on-negative helper would fail these tests.
// Scala's `indexOf_eval` at `methods.scala:1080-1100` explicitly
// clamps via `math.max(from, 0)`; Scala's `Slice.eval` at
// `transformers.scala:86-103` delegates to `Array.slice` which clamps
// both bounds. Both must silently clamp, not throw.

#[test]
fn coll_indexof_negative_from_clamps_to_zero() {
    // indexOf(2, -1) on [1,2,3]: Scala `math.max(-1, 0) = 0`,
    // loop finds 2 at index 1. Must match indexOf(2, 0).
    let coll = || const_coll_int(vec![1, 2, 3]);
    let elem = || const_int(2);
    let make = |from: i32| {
        op(
            0xDC,
            Payload::MethodCall {
                type_id: 12,
                method_id: 26,
                obj: Box::new(coll()),
                args: vec![elem(), const_int(from)],
                type_args: vec![],
            },
        )
    };
    let neg = run_eval(&make(-1));
    let zero = run_eval(&make(0));
    assert_eq!(
        neg, zero,
        "indexOf(elem, -1) must clamp to indexOf(elem, 0), not throw or no-op"
    );
    match neg {
        Value::Int(1) => {}
        other => panic!("expected Int(1), got {other:?}"),
    }
}

#[test]
fn slice_negative_from_clamps_to_zero() {
    // Slice(xs, -1, 3) on [1,2,3,4,5]: Scala clamps lo = max(-1, 0) = 0,
    // hi = min(max(3,0), 5) = 3, copies xs[0..3] = [1,2,3].
    // Must NOT throw.
    let expr = op(
        0xB4,
        Payload::Three(
            Box::new(const_coll_int(vec![1, 2, 3, 4, 5])),
            Box::new(const_int(-1)),
            Box::new(const_int(3)),
        ),
    );
    let v = run_eval(&expr);
    match v {
        Value::CollInt(c) => assert_eq!(c, vec![1, 2, 3]),
        other => panic!("expected CollInt [1,2,3], got {other:?}"),
    }
}

#[test]
fn slice_negative_until_returns_empty() {
    // Slice(xs, 0, -1) on [1,2,3]: hi clamps to 0, lo = 0, hi <= lo,
    // returns empty Coll. Must NOT throw.
    let expr = op(
        0xB4,
        Payload::Three(
            Box::new(const_coll_int(vec![1, 2, 3])),
            Box::new(const_int(0)),
            Box::new(const_int(-1)),
        ),
    );
    let v = run_eval(&expr);
    match v {
        Value::CollInt(c) => assert!(c.is_empty(), "expected empty CollInt, got {c:?}"),
        other => panic!("expected CollInt, got {other:?}"),
    }
}

#[test]
fn slice_until_less_than_from_returns_empty() {
    // Slice(xs, 4, 2): from > until → empty. Scala's `if (hi > lo)`
    // gate handles this. Must NOT throw.
    let expr = op(
        0xB4,
        Payload::Three(
            Box::new(const_coll_int(vec![1, 2, 3, 4, 5])),
            Box::new(const_int(4)),
            Box::new(const_int(2)),
        ),
    );
    let v = run_eval(&expr);
    match v {
        Value::CollInt(c) => assert!(c.is_empty(), "expected empty CollInt, got {c:?}"),
        other => panic!("expected CollInt, got {other:?}"),
    }
}

// ----- Slice cost-charge direction parity -----
//
// Scala's `transformers.scala::Slice.eval` charges
// `Math.max(0, until - from)` over the per-arg-clamped bounds
// **before** the length clamp. Our prior implementation charged over
// `sliced.len()` (post-len-clamp), which under-charges when
// `until > len` — a consensus-loosening direction. The fix moves
// the cost charge to use the pre-len-clamp `until - from` range,
// matching Scala.

// ----- Coll.updated / Coll.patch JIT cost parity -----
//
// Scala-source-anchored values from
// `sigmastate-interpreter/data/shared/src/main/scala/sigma/ast/methods.scala`:
//   - `UpdatedMethod` declares `PerItemCost(20, 1, 10)` charged over
//     `coll.length`.
//   - `PatchMethod` declares `PerItemCost(30, 2, 10)` charged over
//     `xs.length + patch.length`.
// Prior implementation routed both through `add_cost_per_item(0xDC, n)`
// which resolved to `Fixed(4)` regardless of `n` — under-charging vs.
// Scala. Closing the gap is consensus-tightening; the mainnet sync
// corpus (850-tx validation at heights 700000-700200) confirms no
// historical script trips the new cost limit.

#[test]
fn coll_updated_cost_exact_per_item_charge() {
    use ergo_primitives::cost::CostAccumulator;
    let ctx = ReductionContext::minimal(10_000_000, 0);
    // Run an `updated` call and another evaluation that's identical
    // EXCEPT for the receiver length. Subtract to isolate the
    // PerItemCost-driven delta — the constant cost contributors
    // (MethodCall dispatch, ByIndex on the Const, arg evals) cancel.
    let cost_for = |coll_size: usize| -> u32 {
        let coll: Vec<i32> = (0..coll_size as i32).collect();
        let expr = coll_updated_call(const_coll_int(coll), 0, const_int(99));
        let mut cost = CostAccumulator::recording_only();
        // `reduce_expr_with_cost` requires a final SigmaProp/Bool
        // reduction; CollInt-returning expressions error at the
        // outer reduction step. The cost we want is what's
        // accumulated BEFORE that final-stage check, so ignore
        // the result.
        let _ = reduce_expr_with_cost(&expr, &ctx, &[], &mut cost);
        cost.total().value() as u32
    };
    // Scala PerItemCost(20, 1, 10) at:
    //   n=3:  20 + 1*ceil(3/10)  = 20 + 1 = 21
    //   n=10: 20 + 1*ceil(10/10) = 20 + 1 = 21
    //   n=11: 20 + 1*ceil(11/10) = 20 + 2 = 22
    //   n=60: 20 + 1*ceil(60/10) = 20 + 6 = 26
    // Delta(n=60, n=3): expected_delta_updated = 26 - 21 = 5.
    let updated_delta_observed = cost_for(60) - cost_for(3);
    let expected_delta = per_item_compute(20, 1, 10, 60) - per_item_compute(20, 1, 10, 3);
    assert_eq!(
        updated_delta_observed, expected_delta,
        "Coll.updated delta between n=60 and n=3 must equal the Scala \
         PerItemCost(20, 1, 10) delta exactly (26 - 21 = 5)",
    );
    // Sanity-check the n=10 chunk-boundary: same chunks as n=3, so
    // delta should be 0 over the per-item portion (everything else
    // is constant since both calls evaluate the same n=10 input).
    let chunk_boundary_delta = cost_for(10) - cost_for(3);
    assert_eq!(
        chunk_boundary_delta, 0,
        "Cost at n=10 and n=3 must match (both fit in 1 chunk of 10): \
         PerItemCost(20, 1, 10) yields 21 for both",
    );
}

#[test]
fn coll_patch_cost_exact_per_item_charge() {
    use ergo_primitives::cost::CostAccumulator;
    let ctx = ReductionContext::minimal(10_000_000, 0);
    let cost_for = |xs_size: usize, patch_size: usize| -> u32 {
        let xs: Vec<i32> = (0..xs_size as i32).collect();
        let patch: Vec<i32> = (0..patch_size as i32).collect();
        let expr = patch_call(const_coll_int(xs), 1, const_coll_int(patch), 1);
        let mut cost = CostAccumulator::recording_only();
        // `reduce_expr_with_cost` requires a final SigmaProp/Bool
        // reduction; CollInt-returning expressions error at the
        // outer reduction step. The cost we want is what's
        // accumulated BEFORE that final-stage check, so ignore
        // the result.
        let _ = reduce_expr_with_cost(&expr, &ctx, &[], &mut cost);
        cost.total().value() as u32
    };
    // Scala PerItemCost(30, 2, 10) charged over xs.length + patch.length.
    //   n=5 (xs=3, patch=2): 30 + 2*ceil(5/10) = 30 + 2 = 32
    //   n=70 (xs=50, patch=20): 30 + 2*ceil(70/10) = 30 + 14 = 44
    // Delta should equal Scala formula delta exactly.
    let observed_delta = cost_for(50, 20) - cost_for(3, 2);
    let expected_delta = per_item_compute(30, 2, 10, 70) - per_item_compute(30, 2, 10, 5);
    assert_eq!(
        observed_delta, expected_delta,
        "Coll.patch delta between (xs=50, patch=20, n=70) and \
         (xs=3, patch=2, n=5) must equal the Scala PerItemCost(30, 2, 10) \
         delta exactly (44 - 32 = 12)",
    );
}

#[test]
fn slice_cost_charges_over_pre_len_clamp_range() {
    use ergo_primitives::cost::CostAccumulator;
    // Slice(xs, 0, 1000) on a 5-element coll: the actual result has
    // length 5 (clamped by len), but Scala charges cost over
    // `until - from = 1000` — far higher than `sliced.len() = 5`.
    let expr = op(
        0xB4,
        Payload::Three(
            Box::new(const_coll_int(vec![1, 2, 3, 4, 5])),
            Box::new(const_int(0)),
            Box::new(const_int(1000)),
        ),
    );
    let ctx = ReductionContext::minimal(10_000_000, 0);
    let mut cost_pre_clamp = CostAccumulator::recording_only();
    let _ = reduce_expr_with_cost(&expr, &ctx, &[], &mut cost_pre_clamp);

    // Same op with `until == len`: cost should be lower than the
    // 1000-cap variant by enough to confirm the pre-clamp behavior
    // (the per-item-cost delta scales with the cap).
    let expr_at_len = op(
        0xB4,
        Payload::Three(
            Box::new(const_coll_int(vec![1, 2, 3, 4, 5])),
            Box::new(const_int(0)),
            Box::new(const_int(5)),
        ),
    );
    let mut cost_at_len = CostAccumulator::recording_only();
    let _ = reduce_expr_with_cost(&expr_at_len, &ctx, &[], &mut cost_at_len);

    assert!(
        cost_pre_clamp.total().value() > cost_at_len.total().value(),
        "Slice(_, 0, 1000) must charge more than Slice(_, 0, 5) under the \
         pre-len-clamp Scala-parity formula. Got 1000-variant={}, \
         at-len-variant={}",
        cost_pre_clamp.total().value(),
        cost_at_len.total().value(),
    );
}

// ----- CollShort higher-order cost parity -----
//
// The `Coll[Byte]` carrier work added the missing `CollShort` arm to
// `collection_len`; before the fix the helper returned 0 for any
// `CollShort` receiver, silently zero-iterating every higher-order
// opcode (`map`, `filter`, `fold`, `exists`, `forall`) over Coll[Short]
// and under-charging cost by the per-item rate * n.
//
// These tests pin the post-fix behavior: cost.total() for a higher-
// order opcode on `Coll[Short]` of length N must scale with N at the
// same Scala-anchored per-item rate as the equivalent `Coll[Int]`
// call (per-item rate is keyed on the opcode, not the element-coll
// carrier — see `cost_table::opcode_cost` 0xAD/0xAE/0xAF/0xB0/0xB5).
//
// Self-anchored against the Coll[Int] path because:
//   1. `Coll[Int]` higher-order parity is already pinned by the
//      mainnet sync corpus + per-opcode JIT cost work.
//   2. The opcode-level per-item rate from `cost_table::opcode_cost`
//      is keyed solely on the opcode byte, not the receiver carrier;
//      so equal-length Coll[Short]/Coll[Int] must charge identically
//      at the per-item layer.
//   3. Any future regression to the zero-iteration bug would surface
//      as `cost_short == base only` (per-item layer skipped), which
//      these deltas catch immediately.

/// Functional CollShort regressions for the higher-order opcodes.
/// Cost-parity tests below isolate the per-item layer; these pin
/// VALUE behavior — without them a future regression in carrier
/// reconstruction could keep identical costs and still produce
/// silently-wrong results.
#[test]
fn coll_short_filter_returns_kept_items() {
    // Filter Coll[Short]([-2, -1, 0, 1, 2]) with predicate `_ => true`
    // returns the full coll unchanged (5 shorts).
    let filter = op(
        0xB5,
        Payload::Two(
            Box::new(const_coll_short(vec![-2, -1, 0, 1, 2])),
            Box::new(const_pred_of(SigmaType::SShort, op(0x7F, Payload::Zero))),
        ),
    );
    let result = run_eval(&filter);
    assert_eq!(
        result,
        Value::CollShort(vec![-2, -1, 0, 1, 2]),
        "Filter Coll[Short] _ => true must preserve all items and \
         carrier kind",
    );
}

#[test]
fn coll_short_exists_returns_true_on_match() {
    let exists = op(
        0xAE,
        Payload::Two(
            Box::new(const_coll_short(vec![1, 2, 3])),
            Box::new(const_pred_of(SigmaType::SShort, op(0x7F, Payload::Zero))),
        ),
    );
    assert_eq!(run_eval(&exists), Value::Bool(true));
}

#[test]
fn coll_short_forall_returns_true_when_all_match() {
    let forall = op(
        0xAF,
        Payload::Two(
            Box::new(const_coll_short(vec![1, 2, 3])),
            Box::new(const_pred_of(SigmaType::SShort, op(0x7F, Payload::Zero))),
        ),
    );
    assert_eq!(run_eval(&forall), Value::Bool(true));
}

#[test]
fn coll_short_fold_accumulates_acc() {
    // Fold with body `t => t._1` (acc) over a length-3 coll: zero remains
    // zero. Uses the CANONICAL 1-arg-tuple combiner — Scala fold ops are
    // unary lambdas over an (acc, elem) tuple; a multi-arg FuncValue now
    // errors at creation (FuncValue.eval: `if args.length == 1 ... else
    // syntax.error`), so the previous 2-arg shorthand is no longer legal.
    let func = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(
                1,
                Some(SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SShort])),
            )],
            body: Box::new(op(
                0x8C,
                Payload::SelectField {
                    input: Box::new(op(0x72, Payload::ValUse { id: 1 })),
                    field_idx: 1, // _1 = acc
                },
            )),
        },
    );
    let fold = op(
        0xB0,
        Payload::Three(
            Box::new(const_coll_short(vec![10, 20, 30])),
            Box::new(const_int(7)),
            Box::new(func),
        ),
    );
    assert_eq!(run_eval(&fold), Value::Int(7));
}

/// `SizeOf` (0xB1) — pins the regression: pre-fix `collection_len`
/// returned 0 for CollShort and the SizeOf opcode had no CollShort
/// arm (a real bug surfaced by this test pass — fixed in same
/// commit by adding `Value::CollShort(v) => Ok(Value::Int(v.len()
/// as i32))` to `eval_size_of`). Post-fix, it returns the actual
/// length matching the equivalent Coll[Int] call.
#[test]
fn coll_short_size_of_matches_coll_int_size() {
    let shorts = const_coll_short(vec![1, 2, 3, 4, 5]);
    let ints = const_coll_int(vec![1, 2, 3, 4, 5]);
    let size_short = op(0xB1, Payload::One(Box::new(shorts)));
    let size_int = op(0xB1, Payload::One(Box::new(ints)));
    assert_eq!(run_eval(&size_short), Value::Int(5));
    assert_eq!(run_eval(&size_int), Value::Int(5));
    // Cost must match too — the SizeOf op cost is independent of
    // element carrier (both are Coll receivers of length 5).
    assert_eq!(
        cost_of(&size_short),
        cost_of(&size_int),
        "SizeOf cost on Coll[Short] must equal SizeOf cost on Coll[Int] \
         at the same length",
    );
}

/// `MapCollection` (0xAD) — per-item cost scales with N at the
/// Scala-anchored `per_item(20, 1, 10)` rate. Pre-fix this would
/// have zero-iterated (silent regression in cost.total()) and the
/// delta would be flat. Post-fix the delta scales with N at the
/// same rate as Coll[Int].
#[test]
fn coll_short_map_cost_scales_with_length_and_matches_coll_int_layer() {
    let map_short_n = |n: usize| {
        op(
            0xAD,
            Payload::Two(
                Box::new(const_coll_short((0..n as i16).collect())),
                Box::new(const_pred_of(SigmaType::SShort, const_int(0))),
            ),
        )
    };
    let map_int_n = |n: usize| {
        op(
            0xAD,
            Payload::Two(
                Box::new(const_coll_int((0..n as i32).collect())),
                Box::new(const_pred_of(SigmaType::SInt, const_int(0))),
            ),
        )
    };
    let short_5 = cost_of(&map_short_n(5));
    let short_50 = cost_of(&map_short_n(50));
    let int_5 = cost_of(&map_int_n(5));
    let int_50 = cost_of(&map_int_n(50));
    assert!(
        short_50 > short_5,
        "MapCollection cost on Coll[Short] must grow with N (regression \
         pin against silent zero-iteration). short_5={short_5}, \
         short_50={short_50}",
    );
    // The per-item-rate (opcode-keyed) plus AddToEnv (5/element) plus
    // the constant-body cost are all carrier-independent when the
    // body ignores the bound argument. Strict equality between
    // short/int at the same N proves the per-item layer ran the
    // correct number of iterations.
    assert_eq!(
        short_5, int_5,
        "MapCollection cost on Coll[Short](5) must equal Coll[Int](5) \
         when the body ignores the bound argument",
    );
    assert_eq!(short_50, int_50, "same per-item-layer parity at N=50");
}

/// `Filter` (0xB5) — per-item rate `per_item(20, 1, 10)`. The
/// constant-body shape always returns `true`, so every element is
/// retained; iteration count = N for both carriers.
#[test]
fn coll_short_filter_cost_matches_coll_int_layer() {
    let filter_short = op(
        0xB5,
        Payload::Two(
            Box::new(const_coll_short((0..20i16).collect())),
            Box::new(const_pred_of(
                SigmaType::SShort,
                op(0x7F, Payload::Zero), // True
            )),
        ),
    );
    let filter_int = op(
        0xB5,
        Payload::Two(
            Box::new(const_coll_int((0..20i32).collect())),
            Box::new(const_pred_of(
                SigmaType::SInt,
                op(0x7F, Payload::Zero), // True
            )),
        ),
    );
    assert_eq!(cost_of(&filter_short), cost_of(&filter_int));
}

/// `Exists` (0xAE) — per-item rate `per_item(3, 1, 10)`. The
/// constant-body shape always returns `true`, so Exists
/// short-circuits on the first element for both carriers and the
/// iteration counts match.
#[test]
fn coll_short_exists_cost_matches_coll_int_layer() {
    let exists_short = op(
        0xAE,
        Payload::Two(
            Box::new(const_coll_short((0..15i16).collect())),
            Box::new(const_pred_of(SigmaType::SShort, op(0x7F, Payload::Zero))),
        ),
    );
    let exists_int = op(
        0xAE,
        Payload::Two(
            Box::new(const_coll_int((0..15i32).collect())),
            Box::new(const_pred_of(SigmaType::SInt, op(0x7F, Payload::Zero))),
        ),
    );
    assert_eq!(cost_of(&exists_short), cost_of(&exists_int));
}

/// `ForAll` (0xAF) — per-item rate `per_item(3, 1, 10)`. Constant-
/// body `true` runs through all N elements without short-circuit.
#[test]
fn coll_short_forall_cost_matches_coll_int_layer() {
    let forall_short = op(
        0xAF,
        Payload::Two(
            Box::new(const_coll_short((0..15i16).collect())),
            Box::new(const_pred_of(SigmaType::SShort, op(0x7F, Payload::Zero))),
        ),
    );
    let forall_int = op(
        0xAF,
        Payload::Two(
            Box::new(const_coll_int((0..15i32).collect())),
            Box::new(const_pred_of(SigmaType::SInt, op(0x7F, Payload::Zero))),
        ),
    );
    assert_eq!(cost_of(&forall_short), cost_of(&forall_int));
}

/// `Fold` (0xB0) — per-item rate `per_item(3, 1, 10)`. The 2-arg
/// body ignores `elem` and returns `acc` directly, so per-element
/// body cost is identical between Coll[Short] and Coll[Int]
/// receivers — isolates the per-item layer at the opcode-keyed
/// rate.
#[test]
fn coll_short_fold_cost_matches_coll_int_layer() {
    // Canonical 1-arg-tuple fold body: (t: (Int, T)) => t._1 (= acc). T
    // differs per carrier but is unused; body cost is the SelectField load.
    // (A 2-arg lambda now errors at creation — see func_value_non_unary_arity
    // — so it must be the unary tuple form to actually execute the fold loop
    // and exercise the per-item AddToEnv + body cost this test isolates.)
    let fold_body = |elem_ty: SigmaType| {
        op(
            0xD9,
            Payload::FuncValue {
                args: vec![(1, Some(SigmaType::STuple(vec![SigmaType::SInt, elem_ty])))],
                body: Box::new(op(
                    0x8C,
                    Payload::SelectField {
                        input: Box::new(op(0x72, Payload::ValUse { id: 1 })),
                        field_idx: 1,
                    },
                )),
            },
        )
    };
    let fold_short = op(
        0xB0,
        Payload::Three(
            Box::new(const_coll_short((0..15i16).collect())),
            Box::new(const_int(0)),
            Box::new(fold_body(SigmaType::SShort)),
        ),
    );
    let fold_int = op(
        0xB0,
        Payload::Three(
            Box::new(const_coll_int((0..15i32).collect())),
            Box::new(const_int(0)),
            Box::new(fold_body(SigmaType::SInt)),
        ),
    );
    assert_eq!(cost_of(&fold_short), cost_of(&fold_int));
}

/// Per-item rate isolation: at the same opcode the cost-delta
/// between N=50 and N=5 must equal the Scala-anchored
/// `per_item_compute(base, perChunk, chunkSize, 50) -
/// per_item_compute(..., 5)` exactly, plus the per-element cost
/// of (AddToEnv + body) * 45. The body-cost-per-element factor
/// drops out when the body is constant, so the delta isolates
/// the per-item rate plus AddToEnv.
///
/// AddToEnv is `fixed(5)` per element. Per-element constant-body
/// cost is `5` (ConstLoad). So delta per element = 5 + 5 + 0 = 10
/// (plus the carrier-independent per-item-rate delta).
#[test]
fn coll_short_map_per_item_delta_matches_coll_int() {
    let map_short = |n: usize| {
        op(
            0xAD,
            Payload::Two(
                Box::new(const_coll_short((0..n as i16).collect())),
                Box::new(const_pred_of(SigmaType::SShort, const_int(0))),
            ),
        )
    };
    let map_int = |n: usize| {
        op(
            0xAD,
            Payload::Two(
                Box::new(const_coll_int((0..n as i32).collect())),
                Box::new(const_pred_of(SigmaType::SInt, const_int(0))),
            ),
        )
    };
    let short_delta = cost_of(&map_short(50)) - cost_of(&map_short(5));
    let int_delta = cost_of(&map_int(50)) - cost_of(&map_int(5));
    assert_eq!(
        short_delta, int_delta,
        "Per-item cost delta on MapCollection must be identical between \
         Coll[Short] and Coll[Int] (opcode-keyed per-item rate, not \
         carrier-keyed). Δshort={short_delta}, Δint={int_delta}",
    );
    // The delta must also equal the Scala-anchored sum of:
    //   per_item_compute(20, 1, 10, 50) - per_item_compute(20, 1, 10, 5) +
    //   (AddToEnv(5) + body-const-load(5)) * 45
    // Asserting against this absolute expectation pins the rate.
    let rate_delta = per_item_compute(20, 1, 10, 50) - per_item_compute(20, 1, 10, 5);
    let per_elem_delta = 10 * 45;
    let expected = rate_delta as u64 + per_elem_delta;
    assert_eq!(
        short_delta, expected,
        "MapCollection Δ(N=50, N=5) must equal the Scala-anchored \
         per_item_compute(20,1,10) delta plus 10*45 AddToEnv+body cost. \
         Expected={expected}, got={short_delta}",
    );
}
