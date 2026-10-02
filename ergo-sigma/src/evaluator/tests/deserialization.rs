// ── Batch 4: Missing corpus-observed opcodes ────────────────────

// DeserializeContext (0xD4) — deserialize expression from context extension var
#[test]
fn opcode_deserialize_context() {
    // Serialize True (0x7F) as a 1-byte expression, place in extension var 1
    let b = make_test_box();
    let mut ctx = ctx_with_self_box(&b);
    ctx.extension.insert(
        1,
        (
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Bytes(vec![0x7F])),
        ),
    );
    let expr = op(
        0xD4,
        Payload::DeserializeContext {
            id: 1,
            tpe: SigmaType::SBoolean,
        },
    );
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Bool(true));
}

#[test]
fn opcode_deserialize_context_missing_var() {
    let expr = op(
        0xD4,
        Payload::DeserializeContext {
            id: 99,
            tpe: SigmaType::SBoolean,
        },
    );
    let err = run_eval_err(&expr);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

// DeserializeRegister (0xD5) — deserialize expression from SELF register
#[test]
fn opcode_deserialize_register_present() {
    // Put serialized True (0x7F) in R6 as Coll[Byte]
    let mut b = make_test_box();
    b.registers[2] = Some(ergo_ser::register::RegisterValue {
        tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        value: SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Bytes(vec![0x7F])),
    });
    let ctx = ctx_with_self_box(&b);
    let expr = op(
        0xD5,
        Payload::DeserializeRegister {
            reg_id: 6,
            tpe: SigmaType::SBoolean,
            default: None,
        },
    );
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Bool(true));
}

#[test]
fn opcode_deserialize_register_absent_with_default() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    // R8 is None — use default False
    let expr = op(
        0xD5,
        Payload::DeserializeRegister {
            reg_id: 8,
            tpe: SigmaType::SBoolean,
            default: Some(Box::new(op(0x80, Payload::Zero))), // False
        },
    );
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Bool(false));
}

#[test]
fn opcode_deserialize_context_v6_typearg_payload_evaluates() {
    let b = make_test_box();
    let mut ctx = ctx_with_self_box(&b);
    ctx.extension.insert(
        1,
        (
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Bytes(
                v6_typearg_methodcall_payload(),
            )),
        ),
    );
    let expr = op(
        0xD4,
        Payload::DeserializeContext {
            id: 1,
            tpe: SigmaType::SBoolean,
        },
    );
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Bool(true));
}

#[test]
fn opcode_deserialize_register_v6_typearg_payload_evaluates() {
    let mut b = make_test_box();
    b.registers[2] = Some(ergo_ser::register::RegisterValue {
        tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        value: SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Bytes(
            v6_typearg_methodcall_payload(),
        )),
    });
    let ctx = ctx_with_self_box(&b);
    let expr = op(
        0xD5,
        Payload::DeserializeRegister {
            reg_id: 6,
            tpe: SigmaType::SBoolean,
            default: None,
        },
    );
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Bool(true));
}

#[test]
fn opcode_deserialize_context_v6_typearg_payload_rejects_pre_eip50() {
    let b = make_test_box();
    let mut ctx = ctx_with_self_box(&b);
    ctx.activated_script_version = 2;
    ctx.extension.insert(
        1,
        (
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Bytes(
                v6_typearg_methodcall_payload(),
            )),
        ),
    );
    let expr = op(
        0xD4,
        Payload::DeserializeContext {
            id: 1,
            tpe: SigmaType::SBoolean,
        },
    );
    // The payload parses (type-byte read is version-independent); the
    // not-yet-activated v6 method is rejected at evaluation time.
    match run_eval_ctx_err(&expr, &ctx) {
        EvalError::SoftForkNotActivated {
            type_id,
            method_id,
            required,
            got,
        } => {
            assert_eq!((type_id, method_id), (106, 4));
            assert_eq!((required, got), (3, 2));
        }
        other => panic!("expected SoftForkNotActivated, got {other:?}"),
    }
}

#[test]
fn opcode_deserialize_context_v6_typearg_payload_truncated_errors() {
    let mut payload = v6_typearg_methodcall_payload();
    payload.pop(); // drop the trailing explicit type byte
    let b = make_test_box();
    let mut ctx = ctx_with_self_box(&b);
    ctx.extension.insert(
        1,
        (
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Bytes(payload)),
        ),
    );
    let expr = op(
        0xD4,
        Payload::DeserializeContext {
            id: 1,
            tpe: SigmaType::SBoolean,
        },
    );
    let err = run_eval_ctx_err(&expr, &ctx);
    assert!(matches!(err, EvalError::TypeError { .. }), "got {err:?}");
}

/// End-to-end: an inline `SBox` constant whose proposition is a minimal
/// sizeless v0 `sigmaProp(true)` tree (`0008d3`). `skip_ergo_tree` has no size
/// field to skip by, so capturing the box-byte boundary walks the body through
/// the full parser; the evaluator then rehydrates the `OpaqueBoxBytes` via
/// `read_ergo_box`. (A v6-method proposition in a sizeless pre-v3 tree is now
/// rejected at parse — see `sbox_constant_sizeless_v6_tree_rejected` in
/// ergo-ser.)
#[test]
fn opcode_extract_amount_sbox_constant_sizeless_tree() {
    let tree = hex::decode("0008d3").unwrap();
    let mut w = ergo_primitives::writer::VlqWriter::new();
    w.put_u64(1_000_000); // value
    w.put_bytes(&tree); // proposition (sizeless v0 sigmaProp(true))
    w.put_u32(100); // creation height
    w.put_u8(0); // token count
    w.put_u8(0); // register count
    w.put_bytes(&[0u8; 32]); // tx id
    w.put_u16(0); // output index
    let box_bytes = w.result();

    let sbox = Expr::Const {
        tpe: SigmaType::SBox,
        val: SigmaValue::OpaqueBoxBytes(box_bytes),
    };
    let expr = op(0xC1, Payload::One(Box::new(sbox))); // ExtractAmount
    assert_eq!(run_eval(&expr), Value::Long(1_000_000));
}

/// Scala parses an `SBox` constant on the enclosing tree's reader, so its
/// script may use a val the enclosing tree bound, and it keeps the parsed
/// `ErgoBox` rather than parsing the bytes again. Materializing the constant
/// must not run a standalone box parse, whose empty binding store rejects
/// that `ValUse`. JVM (ErgoSerdeOracle `ergo_tree`, sigma-state 6.0.6):
/// `{ val v1 = sigmaProp(true); sigmaProp(<box>.value > 0L) }` ACCEPT, the
/// same box without the binding REJECT NoSuchElementException.
#[test]
fn sbox_constant_using_enclosing_val_materializes() {
    let mut tree = hex::decode("00d801d60108d3d191c163").unwrap();
    tree.extend_from_slice(&box_bytes_using_val_1());
    tree.extend_from_slice(&[0x05, 0x00]);
    let mut r = ergo_primitives::reader::VlqReader::new(&tree);
    let parsed = ergo_ser::ergo_tree::read_ergo_tree(&mut r).expect("JVM accepts");
    assert!(r.is_empty());
    assert_eq!(
        run_eval(&parsed.body),
        Value::SigmaProp(SigmaBoolean::TrivialProp(true))
    );

    let mut unbound = hex::decode("00d191c163").unwrap();
    unbound.extend_from_slice(&box_bytes_using_val_1());
    unbound.extend_from_slice(&[0x05, 0x00]);
    let mut r = ergo_primitives::reader::VlqReader::new(&unbound);
    assert!(
        ergo_ser::ergo_tree::read_ergo_tree(&mut r).is_err(),
        "JVM rejects"
    );
}

/// `SGlobal.serialize` charges an `SBox` by walking its bytes; like
/// materializing it, that walk must not reparse the box standalone.
#[test]
fn serialize_put_cost_box_using_enclosing_val() {
    // 3(value) + chunk(4)=7(tree) + 0(height) + 1(nTok) + 1(nRegs)
    // + 35(txId) + 3(index) = 50.
    assert_eq!(ser_box_cost(box_bytes_using_val_1()), 50);
}

/// An SBox materialized from a constant must keep the real transaction id
/// and output index from the serialized box tail (read_ergo_box parses
/// both), not zero them. ExtractCreationInfo (0xC7) surfaces them as the R3
/// reference = transactionId.toBytes (32) ++ Shorts.toByteArray(index) (a
/// FIXED 2-byte big-endian index), per Scala ErgoBox.get(ReferenceRegId).
/// Uses a multi-byte index (22588) so a zeroed index is unmistakable.
#[test]
fn sbox_constant_preserves_txid_and_index_in_creation_info() {
    let txid = [0xABu8; 32];
    let index: u16 = 22588; // 0x583C; big-endian 2-byte = [0x58, 0x3C]
    let tree = hex::decode("0008d3").unwrap(); // sizeless v0 sigmaProp(true)
    let mut w = ergo_primitives::writer::VlqWriter::new();
    w.put_u64(1_000_000); // value
    w.put_bytes(&tree); // proposition
    w.put_u32(100); // creation height
    w.put_u8(0); // token count
    w.put_u8(0); // register count
    w.put_bytes(&txid); // tx id (32 bytes)
    w.put_u16(index); // output index (VLQ)
    let box_bytes = w.result();
    let sbox = Expr::Const {
        tpe: SigmaType::SBox,
        val: SigmaValue::OpaqueBoxBytes(box_bytes),
    };

    // ExtractCreationInfo (0xC7) -> (creationHeight, txid ++ index_be2).
    let ci = op(0xC7, Payload::One(Box::new(sbox)));
    match run_eval(&ci) {
        Value::Tuple(items) => {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0], Value::Int(100), "creation height");
            let mut expected_ref = txid.to_vec();
            expected_ref.extend_from_slice(&index.to_be_bytes());
            assert_eq!(
                items[1],
                Value::CollBytes(expected_ref),
                "R3 ref must be the real txid ++ 2-byte big-endian index",
            );
        }
        other => panic!("expected creationInfo tuple, got {other:?}"),
    }
}

// AtLeast (0x98) — k-of-n threshold
#[test]
fn opcode_atleast_all_trivial_true() {
    // atLeast(2, [TrivialTrue, TrivialTrue, TrivialTrue]) → TrivialProp(true)
    use ergo_ser::sigma_value::CollValue;
    let bound = const_int(2);
    let items = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
        val: SigmaValue::Coll(CollValue::Values(vec![
            SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
            SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
            SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
        ])),
    };
    let expr = op(0x98, Payload::Two(Box::new(bound), Box::new(items)));
    // Scala AtLeast.reduce folds TrueProp children out and decrements the
    // bound: the first two satisfy bound=2, so the whole threshold collapses
    // to TrivialProp(true). It must NOT stay a Cthreshold carrying TrivialProp
    // children — that shape later panics the proof verifier (verify.rs).
    match run_eval(&expr) {
        Value::SigmaProp(SigmaBoolean::TrivialProp(true)) => {}
        other => panic!("expected TrivialProp(true), got {other:?}"),
    }
}

#[test]
fn opcode_atleast_bound_exceeds_count() {
    use ergo_ser::sigma_value::CollValue;
    let bound = const_int(5);
    let items = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
        val: SigmaValue::Coll(CollValue::Values(vec![SigmaValue::SigmaProp(
            SigmaBoolean::TrivialProp(true),
        )])),
    };
    let expr = op(0x98, Payload::Two(Box::new(bound), Box::new(items)));
    match run_eval(&expr) {
        Value::SigmaProp(SigmaBoolean::TrivialProp(false)) => {}
        other => panic!("expected TrivialProp(false), got {other:?}"),
    }
}

#[test]
fn opcode_atleast_children_cap_errors_over_255() {
    use ergo_ser::sigma_value::CollValue;
    // 256 trivial-true children. Scala's eval path goes through
    // CSigmaDslBuilder.atLeast, which throws when props.length >
    // MaxChildrenCount(255) BEFORE AtLeast.reduce — so even a degenerate
    // bound (<=0, which reduce would short-circuit to TrueProp) errors.
    // SANTA: atLeast.children_cap.
    let children: Vec<SigmaValue> = (0..256)
        .map(|_| SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)))
        .collect();
    let items = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
        val: SigmaValue::Coll(CollValue::Values(children)),
    };
    // Valid bound: would reduce, but the cap fires first.
    let valid = op(
        0x98,
        Payload::Two(Box::new(const_int(2)), Box::new(items.clone())),
    );
    assert!(
        matches!(run_eval_err(&valid), EvalError::RuntimeException(_)),
        "256 children + valid bound must error on the MaxChildrenCount cap",
    );
    // Degenerate bound (0): the cap STILL overrides (it precedes the
    // bound<=0 -> TrueProp short-circuit in the eval/builder path).
    let degenerate = op(0x98, Payload::Two(Box::new(const_int(0)), Box::new(items)));
    assert!(
        matches!(run_eval_err(&degenerate), EvalError::RuntimeException(_)),
        "256 children + degenerate bound must STILL error (cap before reduce)",
    );
}

#[test]
fn opcode_atleast_255_children_accepted() {
    use ergo_ser::sigma_value::CollValue;
    // Exactly MaxChildrenCount (255) is the boundary — accepted; bound 2 over
    // 255 trivial-true children folds to TrivialProp(true).
    let children: Vec<SigmaValue> = (0..255)
        .map(|_| SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)))
        .collect();
    let items = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
        val: SigmaValue::Coll(CollValue::Values(children)),
    };
    let expr = op(0x98, Payload::Two(Box::new(const_int(2)), Box::new(items)));
    assert!(matches!(
        run_eval(&expr),
        Value::SigmaProp(SigmaBoolean::TrivialProp(true))
    ));
}

#[test]
fn func_value_non_unary_arity_errors() {
    // Scala FuncValue.eval (values.scala:1040-1056): addCost, then
    // `if (args.length == 1) <closure> else syntax.error(...)`. A 0- or
    // 2-arg lambda errors when the FuncValue node is evaluated (created),
    // even before any application. SANTA: FuncValue.non_unary_arity.
    let two_arg = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt)), (2, Some(SigmaType::SInt))],
            body: Box::new(const_int(5)),
        },
    );
    assert!(
        matches!(run_eval_err(&two_arg), EvalError::RuntimeException(_)),
        "2-arg lambda must error at creation",
    );
    let zero_arg = op(
        0xD9,
        Payload::FuncValue {
            args: vec![],
            body: Box::new(const_int(5)),
        },
    );
    assert!(
        matches!(run_eval_err(&zero_arg), EvalError::RuntimeException(_)),
        "0-arg lambda must error at creation",
    );
}

#[test]
fn func_value_unary_arity_creates_func() {
    // The unary case is the only legal one — creates a closure value.
    let one_arg = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(const_int(5)),
        },
    );
    assert!(matches!(run_eval(&one_arg), Value::Func { .. }));
}

// AtLeast trivial-child folding (Scala `AtLeast.reduce`). A `Coll[SigmaProp]`
// can carry runtime trivial props (e.g. `sigmaProp(HEIGHT > x)` reduces to
// TrivialProp), so the reducer MUST fold them out — otherwise the result is a
// conjecture with a nested TrivialProp child, which the proof verifier rejects
// (and previously panicked on). See verify.rs and the fix in eval_at_least.

#[test]
fn opcode_atleast_folds_true_child() {
    // atLeast(2, [TrivialTrue, dlog, dlog]): the TrueProp satisfies one slot
    // for free → "1 of {dlog, dlog}" = COR(dlog, dlog). No trivial may survive.
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::CollValue;
    let items = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
        val: SigmaValue::Coll(CollValue::Values(vec![
            SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
            SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes([2u8; 33]))),
            SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes([3u8; 33]))),
        ])),
    };
    let expr = op(0x98, Payload::Two(Box::new(const_int(2)), Box::new(items)));
    match run_eval(&expr) {
        Value::SigmaProp(SigmaBoolean::Cor(children)) => {
            assert_eq!(children.len(), 2, "TrueProp child must be folded out");
            assert!(
                children
                    .iter()
                    .all(|c| matches!(c, SigmaBoolean::ProveDlog(_))),
                "no trivial child may survive, got {children:?}"
            );
        }
        other => panic!("expected COR(dlog, dlog), got {other:?}"),
    }
}

#[test]
fn opcode_atleast_folds_false_child() {
    // atLeast(2, [TrivialFalse, dlog, dlog]): the FalseProp is dead weight →
    // "2 of {dlog, dlog}" = CAND(dlog, dlog). No trivial may survive.
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::CollValue;
    let items = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
        val: SigmaValue::Coll(CollValue::Values(vec![
            SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(false)),
            SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes([2u8; 33]))),
            SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes([3u8; 33]))),
        ])),
    };
    let expr = op(0x98, Payload::Two(Box::new(const_int(2)), Box::new(items)));
    match run_eval(&expr) {
        Value::SigmaProp(SigmaBoolean::Cand(children)) => {
            assert_eq!(children.len(), 2, "FalseProp child must be folded out");
            assert!(children
                .iter()
                .all(|c| matches!(c, SigmaBoolean::ProveDlog(_))));
        }
        other => panic!("expected CAND(dlog, dlog), got {other:?}"),
    }
}

#[test]
fn opcode_atleast_folds_to_single_dlog() {
    // atLeast(2, [TrivialTrue, dlog]): TrueProp drops, bound→1 over a single
    // real child → the bare ProveDlog (no COR/CAND wrapper, no trivial).
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::CollValue;
    let items = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
        val: SigmaValue::Coll(CollValue::Values(vec![
            SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
            SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes([7u8; 33]))),
        ])),
    };
    let expr = op(0x98, Payload::Two(Box::new(const_int(2)), Box::new(items)));
    match run_eval(&expr) {
        Value::SigmaProp(SigmaBoolean::ProveDlog(ge)) => {
            assert_eq!(ge.as_bytes(), &[7u8; 33]);
        }
        other => panic!("expected bare ProveDlog, got {other:?}"),
    }
}

#[test]
fn opcode_atleast_no_trivial_stays_threshold() {
    // Regression guard: a genuine 2-of-3 with no trivial children must stay a
    // CTHRESHOLD(2, [dlog, dlog, dlog]) — the fold must not disturb this path.
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::CollValue;
    let items = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
        val: SigmaValue::Coll(CollValue::Values(vec![
            SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes([2u8; 33]))),
            SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes([3u8; 33]))),
            SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes([4u8; 33]))),
        ])),
    };
    let expr = op(0x98, Payload::Two(Box::new(const_int(2)), Box::new(items)));
    match run_eval(&expr) {
        Value::SigmaProp(SigmaBoolean::Cthreshold { k, children }) => {
            assert_eq!(k, 2);
            assert_eq!(children.len(), 3);
            assert!(children
                .iter()
                .all(|c| matches!(c, SigmaBoolean::ProveDlog(_))));
        }
        other => panic!("expected CTHRESHOLD(2, 3 dlogs), got {other:?}"),
    }
}

/// `CONTEXT.headers.size` — pins the regression: `eval_size_of` had no
/// `CollHeader` arm, so a script reading the header count raised a type
/// error where Scala answers the number of headers (10 on mainnet).
#[test]
fn opcode_size_of_context_headers() {
    let headers = vec![test_eval_header_v2(), test_eval_header_v2()];
    let b = make_test_box();
    let mut ctx = ctx_with_self_box(&b);
    ctx.last_headers = &headers;
    let context_expr = op(0xFE, Payload::Zero);
    let coll = op(
        0xDB,
        Payload::MethodCall {
            type_id: 101,
            method_id: 2,
            obj: Box::new(context_expr),
            args: vec![],
            type_args: vec![],
        },
    );
    let expr = op(0xB1, Payload::One(Box::new(coll)));
    assert_eq!(run_eval_ctx(&expr, &ctx), Value::Int(2));
}

// SContext.headers (type_id=101, method_id=2) via PropertyCall
#[test]
fn opcode_context_headers() {
    let h = EvalHeader {
        id: [0xAA; 32],
        version: 2,
        parent_id: [0xBB; 32],
        ad_proofs_root: [0; 32],
        state_root: [0; 33],
        transactions_root: [0; 32],
        timestamp: 1_600_000_000_000,
        n_bits: 0x01000000,
        height: 500_000,
        extension_root: [0; 32],
        miner_pk: [0x02; 33],
        pow_onetime_pk: [0x03; 33],
        pow_nonce: [0xFF; 8],
        pow_distance: num_bigint::BigInt::from(0),
        votes: [0, 0, 0],
        unparsed_bytes: Vec::new(),
    };
    let b = make_test_box();
    let headers = vec![h.clone()];
    let mut ctx = ctx_with_self_box(&b);
    ctx.last_headers = &headers;

    // CONTEXT.headers → Coll[Header]
    let context_expr = op(0xFE, Payload::Zero);
    let expr = op(
        0xDB,
        Payload::MethodCall {
            type_id: 101,
            method_id: 2,
            obj: Box::new(context_expr),
            args: vec![],
            type_args: vec![],
        },
    );
    match run_eval_ctx(&expr, &ctx) {
        Value::CollHeader(hdrs) => assert_eq!(hdrs.len(), 1),
        other => panic!("expected CollHeader, got {other:?}"),
    }
}

// SHeader properties via PropertyCall (type_id=104)
#[test]
fn opcode_sheader_properties() {
    let h = EvalHeader {
        id: [0xAA; 32],
        version: 2,
        parent_id: [0xBB; 32],
        ad_proofs_root: [0xCC; 32],
        state_root: [0xDD; 33],
        transactions_root: [0xEE; 32],
        timestamp: 1_600_000_000_000,
        n_bits: 0x01234567,
        height: 500_000,
        extension_root: [0x11; 32],
        miner_pk: [0x02; 33],
        pow_onetime_pk: [0x03; 33],
        pow_nonce: [0xFF; 8],
        pow_distance: num_bigint::BigInt::from(42),
        votes: [1, 2, 3],
        unparsed_bytes: Vec::new(),
    };
    let b = make_test_box();
    let headers = vec![h.clone()];
    let mut ctx = ctx_with_self_box(&b);
    ctx.last_headers = &headers;

    // Get headers(0) then access properties
    let get_header = op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(op(
                0xDB,
                Payload::MethodCall {
                    type_id: 101,
                    method_id: 2,
                    obj: Box::new(op(0xFE, Payload::Zero)),
                    args: vec![],
                    type_args: vec![],
                },
            )),
            index: Box::new(const_int(0)),
            default: None,
        },
    );

    // .id (method 1)
    let id_expr = op(
        0xDB,
        Payload::MethodCall {
            type_id: 104,
            method_id: 1,
            obj: Box::new(get_header.clone()),
            args: vec![],
            type_args: vec![],
        },
    );
    assert_eq!(
        run_eval_ctx(&id_expr, &ctx),
        Value::CollBytes(vec![0xAA; 32])
    );

    // .version (method 2)
    let ver_expr = op(
        0xDB,
        Payload::MethodCall {
            type_id: 104,
            method_id: 2,
            obj: Box::new(get_header.clone()),
            args: vec![],
            type_args: vec![],
        },
    );
    // SHeader.version is Byte (typed carrier, not erased Int).
    assert_eq!(run_eval_ctx(&ver_expr, &ctx), Value::Byte(2));

    // .height (method 9)
    let ht_expr = op(
        0xDB,
        Payload::MethodCall {
            type_id: 104,
            method_id: 9,
            obj: Box::new(get_header.clone()),
            args: vec![],
            type_args: vec![],
        },
    );
    assert_eq!(run_eval_ctx(&ht_expr, &ctx), Value::Int(500_000));

    // .timestamp (method 7)
    let ts_expr = op(
        0xDB,
        Payload::MethodCall {
            type_id: 104,
            method_id: 7,
            obj: Box::new(get_header.clone()),
            args: vec![],
            type_args: vec![],
        },
    );
    assert_eq!(run_eval_ctx(&ts_expr, &ctx), Value::Long(1_600_000_000_000));

    // .votes (method 15)
    let votes_expr = op(
        0xDB,
        Payload::MethodCall {
            type_id: 104,
            method_id: 15,
            obj: Box::new(get_header.clone()),
            args: vec![],
            type_args: vec![],
        },
    );
    assert_eq!(
        run_eval_ctx(&votes_expr, &ctx),
        Value::CollBytes(vec![1, 2, 3])
    );

    // .stateRoot (method 5): Scala CHeader.stateRoot wraps the digest
    // via AvlTreeData.avlTreeFromDigest — ALL operations enabled
    // (serialized treeFlags 0x07), keyLength 32, no value length.
    // Pinned by Header.property_accessors.json :: h.stateRoot#nominal
    // (flags byte 0x07 vs 0x00 was a one-byte value divergence).
    let sr_expr = op(
        0xDB,
        Payload::MethodCall {
            type_id: 104,
            method_id: 5,
            obj: Box::new(get_header.clone()),
            args: vec![],
            type_args: vec![],
        },
    );
    assert_eq!(
        run_eval_ctx(&sr_expr, &ctx),
        Value::AvlTree(ergo_ser::sigma_value::AvlTreeData {
            digest: vec![0xDD; 33],
            insert_allowed: true,
            update_allowed: true,
            remove_allowed: true,
            key_length: 32,
            value_length_opt: None,
        })
    );
}

// SubstConstants (0x74) — substitute a constant in a serialized ErgoTree
#[test]
fn opcode_subst_constants() {
    // Build a segregated P2PK ErgoTree:
    //   header: 0x10 (segregated, version 0)
    //   1 constant: SSigmaProp = ProveDlog(pk_a)
    //   body: ConstPlaceholder(0)
    // Then substitute position 0 with ProveDlog(pk_b).
    let pk_a = [0x02; 33]; // dummy pk A
    let pk_b = [0x03; 33]; // dummy pk B

    // Serialize the template tree
    let mut tree_bytes = vec![
        0x10, // header: segregated
        1,    // 1 constant
        0x08, // type: SSigmaProp
        0xCD, // ProveDlog tag
    ];
    tree_bytes.extend_from_slice(&pk_a); // 33-byte pk
    tree_bytes.push(0x73); // body: ConstPlaceholder
    tree_bytes.push(0x00); // index 0

    let script = const_bytes(tree_bytes.clone());
    use ergo_ser::sigma_value::CollValue;
    let positions = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SInt)),
        val: SigmaValue::Coll(CollValue::Values(vec![SigmaValue::Int(0)])),
    };
    // New value: ProveDlog(pk_b)
    let new_pk = ergo_primitives::group_element::GroupElement::from_bytes(pk_b);
    let new_vals = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
        val: SigmaValue::Coll(CollValue::Values(vec![SigmaValue::SigmaProp(
            SigmaBoolean::ProveDlog(new_pk),
        )])),
    };

    let expr = op(
        0x74,
        Payload::Three(Box::new(script), Box::new(positions), Box::new(new_vals)),
    );
    match run_eval(&expr) {
        Value::CollBytes(result) => {
            // The result should be a new ErgoTree with pk_b instead of pk_a
            assert!(result.len() > 33);
            // The constant section should now contain pk_b
            // header(1) + count(1) + type(1) + ProveDlog(1) + pk(33) + body(2) = 39
            assert_eq!(&result[4..37], &pk_b[..]);
        }
        other => panic!("expected CollBytes, got {other:?}"),
    }
}
