// ----- Coll.updated index-bounds parity -----
//
// Oracle: sigma-state's `CollsOverArrays.scala:100-104` delegates to
// `Array[A].updated(index, elem)`, which is documented to throw
// `IndexOutOfBoundsException` for `index < 0 || index >= length`.
// `sigma/ast/methods.scala::updated_eval` wraps that call inside
// `addSeqCost(costKind, coll.length, opDesc) { coll.updated(...) }`
// so cost is charged on `coll.length` BEFORE the bounds check fires
// (we mirror this ordering: `add_cost_per_item` precedes the gate).
//
// A naive port can silently no-op on out-of-range indices: `n as usize`
// wraps negatives to `usize::MAX` and a `if idx < coll.len()` check
// returns the original collection unchanged. That would accept
// `coll.updated(-1, x)` scripts that Scala rejects.

#[test]
fn coll_updated_negative_index_throws_int_carrier() {
    // CollInt: Coll(1, 2, 3).updated(-1, 99). Scala throws
    // IndexOutOfBoundsException; we surface as RuntimeException to
    // keep the typed error variant.
    let expr = coll_updated_call(const_coll_int(vec![1, 2, 3]), -1, const_int(99));
    assert_updated_oob(expr, "CollInt updated(-1, 99)");
}

#[test]
fn coll_updated_negative_index_throws_byte_carrier() {
    let expr = coll_updated_call(const_bytes(vec![1, 2, 3]), -1, const_int(99));
    assert_updated_oob(expr, "CollBytes updated(-1, 99)");
}

#[test]
fn coll_updated_negative_index_throws_long_carrier() {
    let expr = coll_updated_call(const_coll_long(vec![1, 2, 3]), -1, const_long(99));
    assert_updated_oob(expr, "CollLong updated(-1, 99)");
}

#[test]
fn coll_updated_index_at_len_throws() {
    // `updated(len, x)` is out-of-range — Scala throws. A bounds
    // check of `< coll.len()` already catches `idx == len`, but
    // silently no-op'ing instead of throwing was the divergence.
    // This arm must throw.
    let expr = coll_updated_call(const_coll_int(vec![1, 2, 3]), 3, const_int(99));
    assert_updated_oob(expr, "CollInt updated(3, 99)");
}

#[test]
fn coll_updated_index_past_len_throws() {
    let expr = coll_updated_call(const_coll_int(vec![1, 2, 3]), 100, const_int(99));
    assert_updated_oob(expr, "CollInt updated(100, 99)");
}

#[test]
fn coll_updated_valid_index_succeeds_regression_guard() {
    // Happy path — must keep working after the throw-on-oob fix.
    let expr = coll_updated_call(const_coll_int(vec![1, 2, 3]), 1, const_int(99));
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("valid index must succeed");
    let coll = match v {
        Value::CollInt(c) => c,
        other => panic!("expected CollInt, got {other:?}"),
    };
    assert_eq!(coll, vec![1, 99, 3], "updated(1, 99) must replace index 1");
}

#[test]
fn coll_updated_non_collection_receiver_returns_type_error() {
    // Receiver type-gate. A non-collection receiver must fall through
    // the carrier-dispatch arms and produce `TypeError`. If the bounds
    // check ran before the type dispatch the error would silently drift
    // to `RuntimeException` — silent error-class drift on a consensus-
    // critical surface. The explicit receiver-type gate keeps the
    // `TypeError` ordering.
    let expr = op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 20,
            obj: Box::new(const_int(42)), // Int, not a Coll
            args: vec![const_int(0), const_int(99)],
            type_args: vec![],
        },
    );
    let err = run_eval_err(&expr);
    assert!(
        matches!(err, EvalError::TypeError { .. }),
        "non-collection receiver must yield TypeError, got {err:?}"
    );
}

// Cost-charged-before-throw test for Coll.updated bounds violation.
// Per sigma-state `methods.scala::updated_eval`, cost is charged via
// `addSeqCost(costKind, coll.length, opDesc) { () => coll.updated(...) }`:
// the PerItemCost charge fires BEFORE the closure runs, so the
// out-of-range throw inside the closure happens AFTER cost has been
// accumulated. Our Rust evaluator must mirror that ordering.

#[test]
fn coll_updated_charges_cost_before_oob_throw() {
    use ergo_primitives::cost::CostAccumulator;
    let ctx = ReductionContext::minimal(10_000_000, 0);
    // Coll(1, 2, 3).updated(-1, 99) — OOB. Cost must be charged
    // before the RuntimeException fires. PerItemCost(20, 1, 10) at
    // n=3: chunks = ceil(3/10) = 1; cost = 20 + 1*1 = 21.
    let expr = coll_updated_call(const_coll_int(vec![1, 2, 3]), -1, const_int(99));
    let mut cost = CostAccumulator::recording_only();
    let result = reduce_expr_with_cost(&expr, &ctx, &[], &mut cost);
    // Must error (out-of-bounds), AND must have charged the per-item
    // cost before the error fired.
    assert!(result.is_err(), "OOB must surface as Err");
    // The cost trace records at minimum: MethodCall (Fixed(4)) +
    // ByIndex evals + the PerItemCost(20,1,10) charge for updated.
    // We assert a lower bound that proves the updated cost was
    // charged: > 20 (the PerItemCost base alone). A passing assertion
    // with the prior `Fixed(4)` charge would have shown a total
    // lower than that.
    assert!(
        cost.total().value() >= 21,
        "Coll.updated must charge PerItemCost(20, 1, 10) over n=3 \
         (= 21) BEFORE the bounds-check throw fires; got total={}",
        cost.total().value(),
    );
}

// ----- Coll.updated element-carrier parity -----
//
// `eval_by_index` on a Coll[Byte] (collection.rs:118) returns
// `Value::Byte`, so a natural ErgoScript like
// `bytes.updated(0, otherBytes(0))` feeds a `Value::Byte` element
// into Coll.updated. The Rust dispatch must accept that — Scala-sigma's
// typed method signature for `Coll[Byte].updated` pins the element to
// `Byte`, so this is the natural Scala-parity arm.

#[test]
fn coll_updated_bytes_accepts_byte_element_natural_carrier() {
    // `bytes.updated(0, bytes(0))` where the second arg is sourced from
    // another Coll[Byte] index — natural compile-time output.
    // Previously rejected with TypeError because the dispatch only
    // matched `Value::Int`; the byte-element arm closes that gap.
    let expr = coll_updated_call_byte_elem(const_bytes(vec![10, 20, 30]), 1, 99);
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("byte-element update on Coll[Byte] must succeed (Scala-parity)");
    let coll = match v {
        Value::CollBytes(c) => c,
        other => panic!("expected CollBytes, got {other:?}"),
    };
    assert_eq!(
        coll,
        vec![10, 99, 30],
        "byte-element update must replace the targeted index",
    );
}

#[test]
fn coll_updated_bytes_rejects_int_element_strict_scala_parity() {
    // Scala-sigma's typed method dispatch pins
    // `Coll[Byte].updated`'s element to `SByte`, so a hand-built
    // ErgoTree presenting an `Int` element rejects at the typed
    // boundary. The Rust dispatch matches that rejection rather than
    // silently casting `Int` to `u8` (which would accept scripts
    // Scala refuses — a consensus-loosening divergence).
    let expr = coll_updated_call(const_bytes(vec![10, 20, 30]), 1, const_int(99));
    let err = run_eval_err(&expr);
    assert!(
        matches!(err, EvalError::TypeError { .. }),
        "Coll[Byte].updated(_, Int) must reject as TypeError, got {err:?}",
    );
}

#[test]
fn coll_updated_bytes_sign_boundary_0x80_round_trips() {
    // Sign-boundary coverage: `Value::Byte` is `i8` while
    // `CollBytes` stores `u8`. `0x80` (-128 as i8) and `0xFF`
    // (-1 as i8) are the boundary values where a sloppy cast
    // could silently drift. The `v as u8` reinterpretation must
    // preserve the bit pattern.
    let byte_source = const_bytes(vec![0x80]);
    let byte_elem = op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(byte_source),
            index: Box::new(const_int(0)),
            default: None,
        },
    );
    let expr = coll_updated_call(const_bytes(vec![0x00, 0x00, 0x00]), 1, byte_elem);
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("0x80 byte element must round-trip");
    let coll = match v {
        Value::CollBytes(c) => c,
        other => panic!("expected CollBytes, got {other:?}"),
    };
    assert_eq!(
        coll,
        vec![0x00, 0x80, 0x00],
        "0x80 byte must land at index 1 with the bit pattern intact",
    );
}

#[test]
fn coll_updated_bytes_sign_boundary_0xff_round_trips() {
    let byte_source = const_bytes(vec![0xFF]);
    let byte_elem = op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(byte_source),
            index: Box::new(const_int(0)),
            default: None,
        },
    );
    let expr = coll_updated_call(const_bytes(vec![0x00, 0x00, 0x00]), 0, byte_elem);
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("0xFF byte element must round-trip");
    let coll = match v {
        Value::CollBytes(c) => c,
        other => panic!("expected CollBytes, got {other:?}"),
    };
    assert_eq!(
        coll,
        vec![0xFF, 0x00, 0x00],
        "0xFF byte must land at index 0 with the bit pattern intact",
    );
}

// ----- Coll.updated CollShort + CollBool carrier extension -----
//
// Scala-sigma's `Coll[T].updated` is generic over T; the prior Rust
// receiver gate excluded `CollShort` and `CollBool` so those types
// rejected at `TypeError` before the bounds check could fire.
// Extending the gate + dispatch arms closes the Scala-parity hole.

#[test]
fn coll_updated_short_carrier_succeeds() {
    // CollShort.updated(1, 99) must succeed under the extended gate.
    let expr = coll_updated_call(const_coll_short(vec![10, 20, 30]), 1, const_short(99));
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("Coll[Short].updated must succeed under the extended receiver gate");
    let coll = match v {
        Value::CollShort(c) => c,
        other => panic!("expected CollShort, got {other:?}"),
    };
    assert_eq!(
        coll,
        vec![10, 99, 30],
        "updated(1, 99) must replace index 1"
    );
}

#[test]
fn coll_updated_bool_carrier_succeeds() {
    // CollBool.updated(0, false) must succeed under the extended gate.
    let expr = coll_updated_call(
        const_coll_bool(vec![true, true, true]),
        0,
        const_bool(false),
    );
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("Coll[Bool].updated must succeed under the extended receiver gate");
    let coll = match v {
        Value::CollBool(c) => c,
        other => panic!("expected CollBool, got {other:?}"),
    };
    assert_eq!(
        coll,
        vec![false, true, true],
        "updated(0, false) must replace index 0",
    );
}

#[test]
fn coll_updated_short_negative_index_throws_runtime() {
    // Receiver-gate extension also propagates the out-of-bounds throw
    // semantics: previously this rejected at the receiver gate with
    // TypeError before the bounds check ran. Now it should surface as
    // RuntimeException, matching the int/long/byte carriers.
    let expr = coll_updated_call(const_coll_short(vec![1, 2, 3]), -1, const_short(99));
    assert_updated_oob(expr, "CollShort updated(-1, 99)");
}

#[test]
fn coll_updated_bool_negative_index_throws_runtime() {
    let expr = coll_updated_call(
        const_coll_bool(vec![true, false, true]),
        -1,
        const_bool(true),
    );
    assert_updated_oob(expr, "CollBool updated(-1, true)");
}

// ----- Coll.updated CollSigmaProp + CollHeader carrier extension -----
//
// Scala-sigma's `Coll[T].updated` for boxed carriers (SigmaProp,
// Header) materializes through the same `Array[A].updated` path as
// primitives. The Rust dispatch needs strict element-type arms so
// e.g. `Coll[Header].updated(0, Value::Int(...))` rejects with
// TypeError instead of silently wrapping the bad element.

#[test]
fn coll_updated_sigma_prop_carrier_succeeds() {
    // Coll[SigmaProp].updated(1, falseProp): replace one trivial
    // proposition with another. Scala-sigma accepts via the generic
    // Coll[T].updated path; the Rust dispatch needs the matching arm.
    let expr = coll_updated_call(
        const_coll_sigma_prop_trivial(vec![true, true, true]),
        1,
        const_sigma_prop_trivial(false),
    );
    let v = eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("Coll[SigmaProp].updated must succeed under the extended dispatch");
    let coll = match v {
        Value::CollSigmaProp(c) => c,
        other => panic!("expected CollSigmaProp, got {other:?}"),
    };
    assert_eq!(
        coll,
        vec![
            SigmaBoolean::TrivialProp(true),
            SigmaBoolean::TrivialProp(false),
            SigmaBoolean::TrivialProp(true),
        ],
        "updated(1, falseProp) must replace index 1",
    );
}

#[test]
fn coll_updated_sigma_prop_rejects_int_element() {
    // Strict element-type parity: passing an `Int` to a Coll[SigmaProp]
    // updated call must reject (Scala-sigma's typed dispatch enforces
    // the SigmaProp element type).
    let expr = coll_updated_call(
        const_coll_sigma_prop_trivial(vec![true, true, true]),
        1,
        const_int(99),
    );
    let err = run_eval_err(&expr);
    assert!(
        matches!(err, EvalError::TypeError { .. }),
        "Coll[SigmaProp].updated(_, Int) must reject as TypeError, got {err:?}",
    );
}

#[test]
fn coll_updated_sigma_prop_negative_index_throws_runtime() {
    let expr = coll_updated_call(
        const_coll_sigma_prop_trivial(vec![true, false, true]),
        -1,
        const_sigma_prop_trivial(true),
    );
    assert_updated_oob(expr, "CollSigmaProp updated(-1, true)");
}

// ----- Coll.updated CollBox + BoxCollection + Tokens via real eval-path -----

#[test]
fn coll_updated_inputs_updated_self_succeeds_via_eval() {
    // `INPUTS.updated(0, SELF)` — Scala-sigma's
    // `CollsOverArrays.scala:100-104` accepts generic
    // `Coll[Box].updated(i, e: Box)`; INPUTS is a Coll[Box] at the
    // typed-IR layer but materializes as `Value::BoxCollection` at
    // runtime, so the receiver gate + dispatch arm must materialize
    // the source-ref carrier into a `CollBox` before the update.
    let test_box = make_test_box();
    let other_box = make_test_box();
    let ctx = ReductionContext {
        validation_settings: Default::default(),
        height: 600_000,
        self_box: Some(&test_box),
        self_creation_height: test_box.creation_height,
        outputs: &[],
        inputs: &[other_box.clone(), other_box.clone()],
        data_inputs: &[],
        miner_pubkey: [0x33; 33],
        pre_header_timestamp: 1_700_000_000_000,
        extension: indexmap::IndexMap::new(),
        last_headers: &[],
        last_block_utxo_root: None,
        activated_script_version: 3,
        ergo_tree_version: 3,
        pre_header_version: 0,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
        input_extensions: &[],
    };
    let expr = coll_updated_via_method_call(op_inputs(), const_int(0), op_self());
    let v = eval_to_value(&expr, &ctx, &[])
        .expect("INPUTS.updated(0, SELF) must succeed under the extended dispatch");
    match v {
        Value::CollBox(coll) => {
            assert_eq!(coll.len(), 2, "INPUTS length preserved");
            assert!(
                matches!(coll[0], Value::SelfBox),
                "index 0 must be replaced with SELF",
            );
            assert!(
                matches!(
                    coll[1],
                    Value::BoxRef {
                        source: BoxSource::Inputs,
                        index: 1
                    }
                ),
                "index 1 unchanged",
            );
        }
        other => panic!("expected CollBox, got {other:?}"),
    }
}

#[test]
fn coll_updated_inputs_rejects_int_element_via_eval() {
    // Strict element-type parity at the eval-path: passing an `Int`
    // to `INPUTS.updated` rejects (the dispatch arm only matches
    // box-typed elements).
    let test_box = make_test_box();
    let ctx = ReductionContext {
        validation_settings: Default::default(),
        height: 600_000,
        self_box: Some(&test_box),
        self_creation_height: test_box.creation_height,
        outputs: &[],
        inputs: std::slice::from_ref(&test_box),
        data_inputs: &[],
        miner_pubkey: [0x33; 33],
        pre_header_timestamp: 1_700_000_000_000,
        extension: indexmap::IndexMap::new(),
        last_headers: &[],
        last_block_utxo_root: None,
        activated_script_version: 3,
        ergo_tree_version: 3,
        pre_header_version: 0,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
        input_extensions: &[],
    };
    let expr = coll_updated_via_method_call(op_inputs(), const_int(0), const_int(99));
    let err = match eval_to_value(&expr, &ctx, &[]) {
        Ok(v) => panic!("INPUTS.updated(0, Int) must reject, got {v:?}"),
        Err(e) => e,
    };
    assert!(
        matches!(err, EvalError::TypeError { .. }),
        "INPUTS.updated(0, Int) must reject as TypeError, got {err:?}",
    );
}

// `SELF.tokens` returns Value::Opt(Tokens) via ExtractRegisterAs (0xC6)
// + register id 2. Unwrap with `.get` to test Tokens.updated. The
// fixture is non-trivial — make_test_box ships with two tokens.

// Coll[Tuple].updated on the boxed-element coll carrier
// (`Value::CollGeneric`). Scala-sigma's `Coll[A].updated` is generic
// over `A`; the receiver allowlist accepts the carrier and the match
// arm replaces the box at `idx`, preserving `CollGeneric`. The
// constant builds an `SColl(STuple(Int, Long))` so the parse path
// produces `CollGeneric` (same shape `zip` and `flatMap` yield at
// runtime), exercising the receiver path end-to-end.
#[test]
fn coll_updated_collgeneric_replaces_boxed_element() {
    let coll_ty = SigmaType::SColl(Box::new(SigmaType::STuple(vec![
        SigmaType::SInt,
        SigmaType::SLong,
    ])));
    let coll_const = Expr::Const {
        tpe: coll_ty.clone(),
        val: SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Values(vec![
            SigmaValue::Tuple(vec![SigmaValue::Int(1), SigmaValue::Long(10)]),
            SigmaValue::Tuple(vec![SigmaValue::Int(2), SigmaValue::Long(20)]),
            SigmaValue::Tuple(vec![SigmaValue::Int(3), SigmaValue::Long(30)]),
        ])),
    };
    let elem = Expr::Const {
        tpe: SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong]),
        val: SigmaValue::Tuple(vec![SigmaValue::Int(99), SigmaValue::Long(999)]),
    };
    let expr = coll_updated_via_method_call(coll_const, const_int(1), elem);
    let v = run_eval(&expr);
    match v {
        Value::CollGeneric(items, _) => {
            assert_eq!(items.len(), 3);
            assert_eq!(items[0], Value::Tuple(vec![Value::Int(1), Value::Long(10)]));
            assert_eq!(
                items[1],
                Value::Tuple(vec![Value::Int(99), Value::Long(999)])
            );
            assert_eq!(items[2], Value::Tuple(vec![Value::Int(3), Value::Long(30)]));
        }
        other => panic!("expected CollGeneric carrier preserved, got {other:?}"),
    }
}

// `Coll[Option[Coll[Byte]]].updated` end-to-end through the evaluator.
// `R4` carries a `Coll[Option[Coll[Byte]]]` constant; the script calls
// `.updated(0, R5)` where `R5` is a `Some(CollBytes)`. This exercises:
//   1. The constant-decode path (`sigma_to_value` → `CollGeneric`
//      tagged `SOption(SColl(SByte))`).
//   2. The `(12, 26) Coll.updated` MethodCall on the boxed-element
//      carrier with a non-serializable `Value::Opt` replacement —
//      the path that previously rejected through `value_to_typed_sigma`.
//   3. The `value_to_sigma_type` compatibility check including the
//      `Opt(None)` case via the `SAny` wildcard in the second
//      assertion (replace with `None` at index 1).
#[test]
fn coll_updated_collgeneric_accepts_option_element_via_eval() {
    let inner_ty = SigmaType::SColl(Box::new(SigmaType::SByte));
    let opt_ty = SigmaType::SOption(Box::new(inner_ty.clone()));
    let coll_ty = SigmaType::SColl(Box::new(opt_ty.clone()));

    // Coll[Option[Coll[Byte]]] constant — two Some(_) entries.
    let coll_const = Expr::Const {
        tpe: coll_ty,
        val: SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Values(vec![
            SigmaValue::Opt(Some(Box::new(SigmaValue::Coll(
                ergo_ser::sigma_value::CollValue::Bytes(vec![0xAA; 32]),
            )))),
            SigmaValue::Opt(Some(Box::new(SigmaValue::Coll(
                ergo_ser::sigma_value::CollValue::Bytes(vec![0xBB; 32]),
            )))),
        ])),
    };
    // Replacement: Some(CollBytes) — non-serializable Value::Opt at
    // runtime, exercising the new `value_to_sigma_type` probe.
    let new_some = Expr::Const {
        tpe: opt_ty.clone(),
        val: SigmaValue::Opt(Some(Box::new(SigmaValue::Coll(
            ergo_ser::sigma_value::CollValue::Bytes(vec![0xCC; 32]),
        )))),
    };
    let expr = coll_updated_via_method_call(coll_const.clone(), const_int(0), new_some);
    let v = run_eval(&expr);
    match v {
        Value::CollGeneric(items, elem_type) => {
            assert_eq!(items.len(), 2);
            assert_eq!(*elem_type, opt_ty, "carrier elem_type preserved");
            // Index 0 was replaced with the new Some(CollBytes[CC; 32]).
            assert_eq!(
                items[0],
                Value::Opt(Some(Box::new(Value::CollBytes(vec![0xCC; 32]))))
            );
            // Index 1 untouched.
            assert_eq!(
                items[1],
                Value::Opt(Some(Box::new(Value::CollBytes(vec![0xBB; 32]))))
            );
        }
        other => panic!("expected CollGeneric carrier, got {other:?}"),
    }

    // Now the None case: SAny wildcard compatibility must accept
    // `Opt(None)` against an `SOption(SColl(SByte))` carrier.
    let new_none = Expr::Const {
        tpe: opt_ty,
        val: SigmaValue::Opt(None),
    };
    let expr_none = coll_updated_via_method_call(coll_const, const_int(1), new_none);
    let v_none = run_eval(&expr_none);
    match v_none {
        Value::CollGeneric(items, _) => {
            assert_eq!(items[1], Value::Opt(None));
        }
        other => panic!("expected CollGeneric for None-update, got {other:?}"),
    }
}

// Regression pin: `SubstConstants` substituting a `Value::Opt(None)`
// into an `Option[T]` template slot must preserve the template's
// declared `Option[T]` type descriptor in the rewritten ErgoTree.
// Pre-fix, `value_to_typed_sigma` returned `SOption(SAny)` for the
// None value and that degraded type wrote back into the constant
// pool — shifting the ErgoTree bytes (and the resulting script id)
// away from Scala's `ErgoTreeSerializer.substituteConstants`. Post-
// fix, the template's existing typed slot is authoritative.
#[test]
fn subst_constants_none_preserves_template_option_type() {
    use super::helpers::subst_constants;
    use ergo_ser::ergo_tree::{read_ergo_tree, write_ergo_tree, ErgoTree};
    use ergo_ser::sigma_value::{CollValue, SigmaValue};
    // Build a template ErgoTree with one `Option[Coll[Byte]]` constant
    // (the body is a trivial true sigmaprop so the tree is valid).
    let opt_ty = SigmaType::SOption(Box::new(SigmaType::SColl(Box::new(SigmaType::SByte))));
    let body = Expr::Const {
        tpe: SigmaType::SSigmaProp,
        val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
    };
    // ErgoTree version 3: SOption *data constants* are gated on
    // isV3OrLaterErgoTreeVersion (Scala CoreDataSerializer), so a pre-v3 tree
    // carrying an Option constant is rejected at parse (see
    // SOption.pre_v3_data_constant). v3 is the valid version for this fixture.
    let template = ErgoTree {
        version: 3,
        has_size: false,
        constant_segregation: true,
        reserved_header_bits: 0,
        constants: vec![(
            opt_ty.clone(),
            SigmaValue::Opt(Some(Box::new(SigmaValue::Coll(CollValue::Bytes(vec![
                0xAA;
                4
            ]))))),
        )],
        body,
    };
    let mut w = ergo_primitives::writer::VlqWriter::new();
    write_ergo_tree(&mut w, &template).expect("template write");
    let template_bytes = w.result();
    // Substitute the constant at index 0 with Value::Opt(None).
    let (new_bytes, _) = subst_constants(&template_bytes, &[0], &[Value::Opt(None)], true)
        .expect("subst_constants succeeds");
    // The rewritten tree must keep the template's declared
    // `SOption(SColl(SByte))` type descriptor on the slot — NOT
    // degrade to `SOption(SAny)`.
    let mut r = ergo_primitives::reader::VlqReader::new(&new_bytes);
    let rewritten = read_ergo_tree(&mut r).expect("rewritten tree re-parses");
    assert_eq!(
        rewritten.constants[0].0, opt_ty,
        "Template's declared Option[Coll[Byte]] type must survive a None \
         substitution (not degrade to Option[Any])",
    );
    assert_eq!(
        rewritten.constants[0].1,
        SigmaValue::Opt(None),
        "Substituted value must be None",
    );
}

// substConstants parity with Scala ErgoTreeSerializer.substituteConstants
// (over-strict fix). Byte vectors taken verbatim from the SANTA
// substConstants_equivalence vector (blessed jvm:sigma-state-6.0.3); the
// replacement value is always sigmaProp(false). The substitution keeps the
// tree body as opaque raw bytes, skips out-of-range positions
// (getPositionsBackref ignores them), returns no-segregation trees unchanged,
// and the returned nConstants drives the PerItemCost(100,100,1) charge.
#[test]
fn subst_constants_scala_parity_success_cases() {
    use super::helpers::subst_constants;
    let false_prop = || Value::SigmaProp(SigmaBoolean::TrivialProp(false));

    // No-segregation tree (header 0x00): no constants section -> returned
    // unchanged, nConstants = 0.
    assert_eq!(
        subst_constants(&[0x00, 0x08, 0xD3], &[0], &[false_prop()], false).unwrap(),
        (vec![0x00, 0x08, 0xD3], 0),
    );
    assert_eq!(
        subst_constants(&[0x00, 0x00, 0x08, 0xD3], &[0], &[false_prop()], false).unwrap(),
        (vec![0x00, 0x00, 0x08, 0xD3], 0),
    );
    // Segregated (0x10) but with 0 constants -> position 0 is out of range ->
    // skipped -> unchanged, nConstants = 0.
    assert_eq!(
        subst_constants(&[0x10, 0x00, 0x08, 0xD3], &[0], &[false_prop()], false).unwrap(),
        (vec![0x10, 0x00, 0x08, 0xD3], 0),
    );
    // Segregated, 1 SSigmaProp constant (true = 0xD3), substitute position 0 ->
    // sigmaProp(false) = 0xD2. Body (0x73 0x00) preserved verbatim. nConstants = 1.
    assert_eq!(
        subst_constants(
            &[0x10, 0x01, 0x08, 0xD3, 0x73, 0x00],
            &[0],
            &[false_prop()],
            false
        )
        .unwrap(),
        (vec![0x10, 0x01, 0x08, 0xD2, 0x73, 0x00], 1),
    );
    // Segregated, 1 constant, position 1 is out of range -> skipped ->
    // unchanged, nConstants = 1.
    assert_eq!(
        subst_constants(
            &[0x10, 0x01, 0x08, 0xD3, 0x73, 0x00],
            &[1],
            &[false_prop()],
            false
        )
        .unwrap(),
        (vec![0x10, 0x01, 0x08, 0xD3, 0x73, 0x00], 1),
    );
}

#[test]
fn subst_constants_scala_parity_error_cases() {
    use super::helpers::subst_constants;
    let false_prop = || Value::SigmaProp(SigmaBoolean::TrivialProp(false));
    // Empty bytes: the header read fails -> Scala throws RuntimeException
    // ("errored"), NOT UnsupportedOpcode ("not-implemented").
    let e_empty = subst_constants(&[], &[0], &[false_prop()], false).unwrap_err();
    assert!(
        matches!(e_empty, EvalError::RuntimeException(_)),
        "empty bytes must error as RuntimeException, got {e_empty:?}",
    );
    // Type mismatch: replacing an SInt constant (=10) with a SigmaProp ->
    // Scala `require(c.tpe == newConst.tpe)` throws -> RuntimeException.
    let e_type = subst_constants(
        &[0x10, 0x01, 0x04, 0x14, 0x73, 0x00],
        &[0],
        &[false_prop()],
        false,
    )
    .unwrap_err();
    assert!(
        matches!(e_type, EvalError::RuntimeException(_)),
        "type mismatch must error as RuntimeException, got {e_type:?}",
    );
    // Length mismatch (positions vs newValues) -> require fails -> RuntimeException.
    let e_len = subst_constants(&[0x10, 0x00], &[0, 1], &[false_prop()], false).unwrap_err();
    assert!(
        matches!(e_len, EvalError::RuntimeException(_)),
        "positions/newValues length mismatch must error, got {e_len:?}",
    );
}

// Scala's `deserializeHeaderWithTreeBytes` reads the declared size and the
// constants count as `getUInt().toInt`: both accept anything up to u32::MAX,
// the size is otherwise ignored, and a count that wraps negative means no
// constants. Templates from SANTA `substConstants:declared_size_u32` #0-#2 and
// `substConstants:template_forms` #0-#2 (https://github.com/mwaddip/santa,
// MIT, blessed jvm:sigma-state-6.0.6), plus two extra rows. Every expectation
// is our own JVM run of `ErgoTreeSerializer.substituteConstants(template, [0],
// [sigmaProp(false)])` under `VersionContext.withVersions(3, 3)`, identical on
// sigma-state 6.0.2 and 6.0.6.
#[test]
fn subst_constants_reads_size_and_count_like_scala_get_uint_to_int() {
    use super::helpers::subst_constants;
    let false_prop = || Value::SigmaProp(SigmaBoolean::TrivialProp(false));
    let accepted = [
        // declared size 2^32 - 1: fits u32, ignored, recomputed as 5.
        ("18ffffffff0f0108d37300", "18050108d27300", 1),
        // the true size: the control.
        ("18050108d37300", "18050108d27300", 1),
        // header bit 5 is written back as read.
        ("38050108d37300", "38050108d27300", 1),
        // count 2^32 - 1 wraps negative: no constants, position 0 skipped.
        ("1807ffffffff0f08d3", "18030008d3", 0),
        ("10ffffffff0f08d3", "100008d3", 0),
        // count 2^31: Int.MinValue once narrowed, again no constants.
        ("1807808080800808d3", "18030008d3", 0),
        // a negative count leaves the constant's bytes to the tree body.
        ("1808ffffffff0f0108d37300", "1806000108d37300", 0),
    ];
    for (template, expected, n_constants) in accepted {
        let result = subst_constants(&hex::decode(template).unwrap(), &[0], &[false_prop()], true)
            .unwrap_or_else(|e| panic!("{template}: {e:?}"));
        assert_eq!(
            (hex::encode(result.0), result.1),
            (expected.to_string(), n_constants),
            "{template}"
        );
    }
    // declared size 2^32: out of getUInt's range, IllegalArgumentException.
    let err = subst_constants(
        &hex::decode("1880808080100108d37300").unwrap(),
        &[0],
        &[false_prop()],
        true,
    )
    .unwrap_err();
    assert!(matches!(err, EvalError::RuntimeException(_)), "{err:?}");
}

// A template whose constants section carries an SHeader value (reachable via
// crafted scriptBytes) must be rejected by a pre-v3 executing ErgoTree even
// when that constant is NOT the one being substituted: Scala deserializes the
// constants under the executing VersionContext and DataSerializer.deserialize
// (SHeader) throws pre-v3. A v3+ executing tree accepts it and round-trips.
#[test]
fn subst_constants_pre_v3_template_header_constant_rejected() {
    use super::helpers::subst_constants;
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::header::read_header;
    use ergo_ser::sigma_value::write_constant;
    // Real mainnet header -> a single SHeader constant in a segregated tree.
    let raw = std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json")
        .expect("headers_1_10 fixture must exist");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let hbytes = hex::decode(v[0]["bytes"].as_str().unwrap()).unwrap();
    let header = read_header(&mut VlqReader::new(&hbytes)).expect("header parse");
    let header_val = SigmaValue::Header(
        Box::new(header),
        *ergo_primitives::digest::blake2b256(&hbytes).as_bytes(),
    );

    let mut w = VlqWriter::new();
    w.put_u8(0x10); // header: segregated
    w.put_u32(1); // 1 constant
    write_constant(&mut w, &SigmaType::SHeader, &header_val).unwrap();
    w.put_u8(0x73); // body: ConstPlaceholder
    w.put_u8(0x00); // index 0
    let tree = w.result();

    // Pre-v3: rejected even with NO substitution (the parsed template SHeader
    // constant materializes a header under a pre-v3 context).
    let err = subst_constants(&tree, &[], &[], false).unwrap_err();
    assert!(
        matches!(err, EvalError::RuntimeException(_)),
        "pre-v3 SHeader template constant must error, got {err:?}",
    );
    // v3+: accepted; with no substitution the tree round-trips unchanged.
    let (out, n) = subst_constants(&tree, &[], &[], true).expect("v3+ accepts SHeader constant");
    assert_eq!(out, tree, "no substitution must return the tree unchanged");
    assert_eq!(n, 1);
}

// Regression pin: a `map` whose first result element is `None`
// must still produce a `CollGeneric` carrier tagged with the
// concrete element type — `infer_collection` prefers the mapper-
// body's IR-inferred SOption(T) over the per-item recovery of
// SOption(SAny) from the first `Value::Opt(None)`. Without this,
// later `.updated` / `SGlobal.serialize` calls on the result
// would spuriously reject against the one-way SAny rule.
#[test]
fn map_collection_first_none_preserves_concrete_elem_type() {
    use super::helpers::infer_collection;
    let mapper_body = Expr::Const {
        tpe: SigmaType::SOption(Box::new(SigmaType::SInt)),
        val: SigmaValue::Opt(None),
    };
    let bindings = std::collections::HashMap::new();
    let items = vec![Value::Opt(None), Value::Opt(Some(Box::new(Value::Int(42))))];
    let result = infer_collection(items, &mapper_body, &bindings, &[]).unwrap();
    match result {
        Value::CollGeneric(_, elem_type) => {
            assert_eq!(
                *elem_type,
                SigmaType::SOption(Box::new(SigmaType::SInt)),
                "infer_collection must thread the IR-declared SOption(SInt) \
                 onto the carrier even when items[0] is Opt(None)",
            );
        }
        other => panic!("expected CollGeneric carrier, got {other:?}"),
    }
}

// Fail-closed: a CollGeneric carrier whose declared `elem_type` has
// been degraded to contain `SAny` (e.g. constructed from items where
// every element was `Value::Opt(None)`) must NOT pass the
// `Coll.updated` type gate against a CONCRETE replacement element.
// `sigma_type_compatible` is one-directional: SAny is only accepted
// on the observed side (the per-element recovery), never on the
// declared side (the carrier's elem_type tag).
#[test]
fn coll_updated_collgeneric_rejects_sany_declared_carrier() {
    // Carrier elem_type is SOption(SAny) — the degraded case that
    // signals "carrier built without proper type info". A concrete
    // replacement must REJECT here.
    let coll = Value::CollGeneric(
        vec![Value::Opt(None), Value::Opt(None)],
        Box::new(SigmaType::SOption(Box::new(SigmaType::SAny))),
    );
    let new_concrete = Value::Opt(Some(Box::new(Value::CollBytes(vec![0xAA; 32]))));
    use super::helpers::sigma_type_compatible;
    let declared = match &coll {
        Value::CollGeneric(_, t) => (**t).clone(),
        _ => unreachable!(),
    };
    let observed = super::helpers::value_to_sigma_type(&new_concrete).unwrap();
    assert!(
        !sigma_type_compatible(&declared, &observed),
        "Declared SOption(SAny) must REJECT a concrete observed \
         SOption(SColl(SByte)) — SAny is observed-side-only",
    );
}

// Negative case: malformed `Coll.updated` where the replacement
// element's SigmaType disagrees with the existing element type must
// reject — protects against rebuilt ErgoTree bytes that bypass the
// script-load typecheck.
#[test]
fn coll_updated_collgeneric_rejects_type_mismatch() {
    let coll_ty = SigmaType::SColl(Box::new(SigmaType::STuple(vec![
        SigmaType::SInt,
        SigmaType::SLong,
    ])));
    let coll_const = Expr::Const {
        tpe: coll_ty,
        val: SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Values(vec![
            SigmaValue::Tuple(vec![SigmaValue::Int(1), SigmaValue::Long(10)]),
        ])),
    };
    // Wrong-typed replacement element (Int instead of (Int, Long)).
    let elem = const_int(99);
    let expr = coll_updated_via_method_call(coll_const, const_int(0), elem);
    let err = run_eval_err(&expr);
    assert!(
        matches!(err, EvalError::TypeError { expected, .. }
            if expected == "matching element type for Coll.updated"),
        "Coll[(Int,Long)].updated(0, Int) must reject as element-type TypeError, got {err:?}",
    );
}

#[test]
fn coll_updated_tokens_canonical_shape_preserves_carrier_via_eval() {
    // `SELF.tokens.get.updated(0, SELF.tokens.get(1))` — canonical
    // shape preserved → return type stays Value::Tokens.
    let test_box = make_test_box();
    let ctx = ctx_with_self_box(&test_box);
    let tokens_expr = op_opt_get(op_extract_register_2_tokens(op_self()));
    let elem_expr = op_by_index(
        op_opt_get(op_extract_register_2_tokens(op_self())),
        const_int(1),
    );
    let expr = coll_updated_via_method_call(tokens_expr, const_int(0), elem_expr);
    let v = eval_to_value(&expr, &ctx, &[])
        .expect("SELF.tokens.updated with canonical element must succeed");
    match v {
        Value::Tokens(coll) => {
            assert_eq!(coll.len(), 2, "tokens length preserved");
            assert_eq!(
                coll[0].0, [0x22; 32],
                "index 0 must now hold the token at original index 1",
            );
            assert_eq!(coll[0].1, 200);
        }
        other => panic!("expected Tokens carrier preserved, got {other:?}"),
    }
}
