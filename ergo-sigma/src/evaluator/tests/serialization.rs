// ---- Global.serialize for AvlTree + Header (DynamicCost = StartWriterCost(10)
//      + DataSerializer put-op sum). chunk(n) = 3 + n. Costs verified against
//      the SANTA vectors: AvlTree total 127 (= 79 framing + 10 + 38), Header
//      specFixture total 333 (= 79 + 10 + 244). ----

/// SANTA `Global.deserializeTo_Header_id_basis`: a header read by the data
/// serializer keeps the Blake2b256 of the RETAINED input slice as its id
/// (Scala `ErgoHeader.serializedId`; `ErgoHeader.scala:132-140,167-180`), so two
/// headers that decode to the same fields but differ in a non-canonical pk
/// encoding are NOT equal (`CHeader.equals`/`hashCode` are id-based) — hashing a
/// canonical re-serialization would collapse them.
#[test]
fn sheader_constant_retains_input_slice_id() {
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::header::Header;
    use ergo_ser::sigma_value::read_value;

    let h = Header {
        version: 2,
        parent_id: ModifierId::from_bytes([0x01; 32]),
        ad_proofs_root: Digest32::from_bytes([0x02; 32]),
        transactions_root: Digest32::from_bytes([0x03; 32]),
        state_root: ADDigest::from_bytes([0x04; 33]),
        timestamp: 1,
        extension_root: Digest32::from_bytes([0x05; 32]),
        n_bits: 0x1a01_7660,
        height: 1,
        votes: [0, 0, 0],
        unparsed_bytes: Vec::new(),
        // Identity pk so the non-canonical `00 aa..aa` encoding decodes to the
        // same point; a distinctive nonce anchors the pk offset below.
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes([0x00; 33]),
            nonce: [0xAB; 8],
        },
    };
    let (canonical, canonical_id) = ergo_ser::header::serialize_header(&h).unwrap();

    // Locate the identity pk: 33 zero bytes immediately before the nonce.
    let nonce = [0xABu8; 8];
    let pos = canonical
        .windows(41)
        .position(|w| w[..33] == [0x00u8; 33] && w[33..] == nonce)
        .expect("identity pk + nonce must appear in the serialization");
    let mut garbage = canonical.clone();
    let mut ge_garbage = [0xaau8; 33];
    ge_garbage[0] = 0x00;
    garbage[pos..pos + 33].copy_from_slice(&ge_garbage);

    let mut r = ergo_primitives::reader::VlqReader::new(&garbage);
    let val = read_value(&mut r, &SigmaType::SHeader).expect("garbage-encoded header parses");
    let retained_id = match &val {
        SigmaValue::Header(_, id) => *id,
        other => panic!("expected SigmaValue::Header, got {other:?}"),
    };
    assert_eq!(
        retained_id,
        *ergo_primitives::digest::blake2b256(&garbage).as_bytes(),
        "id must hash the retained input slice"
    );
    assert_ne!(
        retained_id,
        *canonical_id.as_bytes(),
        "the garbage encoding must not collapse to the canonical id"
    );

    // Materialization carries the retained id through to the evaluator value.
    let v = sigma_to_value(&SigmaType::SHeader, &val).unwrap();
    match v {
        Value::Header(eh) => assert_eq!(eh.id, retained_id),
        other => panic!("expected Value::Header, got {other:?}"),
    }
}

#[test]
fn serialize_put_cost_avltree_is_constant_38() {
    use ergo_ser::sigma_type::SigmaType as T;
    use ergo_ser::sigma_value::SigmaValue as Sv;
    // 38 = chunk(33) digest (36) + putUByte flags (1) + putUInt keyLength (0)
    //      + putOption tag (1) [+ Some: inner putUInt 0].
    for vlen in [None, Some(64), Some(1)] {
        let avl = test_avl_tree(vlen);
        assert_eq!(
            crate::evaluator::opcodes::method_call::serialize_put_cost(
                &T::SAvlTree,
                &Sv::AvlTree(avl)
            )
            .unwrap(),
            38,
            "AvlTree serialize put-cost is the constant 38 (vlen={vlen:?})",
        );
    }
}

#[test]
fn serialize_put_cost_header_v2_is_244() {
    use ergo_ser::sigma_type::SigmaType as T;
    use ergo_ser::sigma_value::SigmaValue as Sv;
    let h = test_eval_header_v2().to_header();
    // 244 = 1(version) + 35*3(parent/adProofs/txRoot) + 36(stateRoot) +
    //       3(timestamp) + 35(extensionRoot) + 7(nBits) + 0(height) + 6(votes)
    //       + 1(unparsedLen) + 3(chunk(0)) + 36(pk) + 11(nonce).
    assert_eq!(
        crate::evaluator::opcodes::method_call::serialize_put_cost(
            &T::SHeader,
            &Sv::Header(Box::new(h), [0u8; 32])
        )
        .unwrap(),
        244,
        "Header(v2, unparsed empty) serialize put-cost is 244",
    );
}

#[test]
fn serialize_put_cost_header_v1_is_283() {
    use ergo_ser::sigma_type::SigmaType as T;
    use ergo_ser::sigma_value::SigmaValue as Sv;
    // Version 1 header -> Autolykos V1 PoW (pk + w + nonce + d) and NO
    // unparsed-bytes block (version > 1 is false). pow_distance 0x010203 ->
    // d = to_signed_bytes_be() = [1,2,3] (len 3). 283 = 1(version) + 35*3 +
    // 36(stateRoot) + 3(timestamp) + 35(extensionRoot) + 7(nBits) + 0(height)
    // + 6(votes) + [36(pk)+36(w)+11(nonce)+1(dLen)+6(chunk(3))]. Pins the V1
    // PoW path (also validated end-to-end by the Global.deserializeTo_header#1
    // roundtrip vector, a real v1 header).
    let mut eh = test_eval_header_v2();
    eh.version = 1;
    eh.pow_distance = num_bigint::BigInt::from(0x01_02_03);
    let h = eh.to_header();
    assert_eq!(
        crate::evaluator::opcodes::method_call::serialize_put_cost(
            &T::SHeader,
            &Sv::Header(Box::new(h), [0u8; 32])
        )
        .unwrap(),
        283,
        "Header(v1, d=[1,2,3]) serialize put-cost is 283",
    );
}

#[test]
fn serialize_avltree_and_header_eval_total_and_bytes() {
    // Global.serialize(value): obj = Global (0xDD=5), args[0] = the value
    // const (5), MethodCall (0xDC=4), then StartWriterCost(10) + put-ops.
    let mut cx = ReductionContext::minimal(500_000, 0);
    cx.activated_script_version = 3;
    cx.ergo_tree_version = 3;
    let serialize_call = |tpe: SigmaType, val: SigmaValue| {
        op(
            0xDC,
            Payload::MethodCall {
                type_id: 106,
                method_id: 3,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![Expr::Const { tpe, val }],
                type_args: vec![],
            },
        )
    };
    let eval_cost = |expr: &Expr| -> (Value, u64) {
        let mut cost = CostAccumulator::recording_only();
        let mut env = Env::new();
        let mut depth = 0usize;
        let mut trace = None;
        let v = eval_expr(expr, &cx, &[], &mut env, &mut depth, &mut cost, &mut trace).unwrap();
        (v, cost.total().value())
    };
    // AvlTree: 4 + 5 + 5 + 10 + 38 = 62; output bytes = 36 (digest 33 + flags 1
    // + keyLen VLQ 1 + option-None 1).
    let avl = test_avl_tree(None);
    let (v, total) = eval_cost(&serialize_call(
        SigmaType::SAvlTree,
        SigmaValue::AvlTree(avl),
    ));
    assert_eq!(total, 62, "serialize(AvlTree) total");
    match v {
        Value::CollBytes(b) => assert_eq!(b.len(), 36, "AvlTree serialize output length"),
        other => panic!("expected CollBytes, got {other:?}"),
    }
    // Header: 4 + 5 + 5 + 10 + 244 = 268.
    let h = test_eval_header_v2().to_header();
    let (v, total) = eval_cost(&serialize_call(
        SigmaType::SHeader,
        SigmaValue::Header(Box::new(h), [0u8; 32]),
    ));
    assert_eq!(total, 268, "serialize(Header) total");
    assert!(
        matches!(v, Value::CollBytes(_)),
        "Header serialize -> CollBytes"
    );
}

#[test]
fn serialize_header_rejected_pre_v3_ergo_tree() {
    // SGlobal.serialize (106, 3) is v6-only (pre-v3 SGlobal = {1, 2}), so a
    // v<3 main-body tree carrying it is rejected at the depth-0
    // `check_v3_only_methods` gate (Scala: `methodById` -> `_v5MethodsMap`
    // misses id 3 -> ValidationException at deserialize) — even when activated
    // >= 3. The separate VALUE-based SHeader gate (materializing an SHeader on a
    // v<3 tree, reachable via registers/context without any v6 method) is
    // covered by `sheader_gate_is_value_based_not_type_based`.
    let headers = vec![test_eval_header_v2()];
    let mut cx = ReductionContext::minimal(500_000, 0);
    cx.activated_script_version = 3; // method gate satisfied
    cx.ergo_tree_version = 2; // but the ErgoTree is pre-v3
    cx.last_headers = &headers;
    let expr = serialize_call_expr(ctx_headers_index(0));
    assert!(
        matches!(
            eval_to_value(&expr, &cx, &[]),
            Err(EvalError::PreV3V6Method { .. })
        ),
        "serialize(runtime Header) must reject at ergo_tree_version < 3",
    );
    // Sanity: the SAME expression succeeds once the ErgoTree is v3, proving
    // the rejection above is the version gate (not an unrelated failure).
    let mut cx_v3 = ReductionContext::minimal(500_000, 0);
    cx_v3.activated_script_version = 3;
    cx_v3.ergo_tree_version = 3;
    cx_v3.last_headers = &headers;
    assert!(
        matches!(eval_to_value(&expr, &cx_v3, &[]), Ok(Value::CollBytes(_))),
        "serialize(runtime Header) succeeds at ergo_tree_version >= 3",
    );
}

#[test]
fn serialize_avltree_rejects_negative_lengths() {
    // read_avl_tree preserves an out-of-i32-range keyLength/valueLengthOpt as
    // a wrapped-negative i32; Scala's putUInt throws on negative, so serialize
    // must error rather than emit u32-cast bytes.
    let mut cx = ReductionContext::minimal(500_000, 0);
    cx.activated_script_version = 3;
    cx.ergo_tree_version = 3;
    let serialize_avl = |avl: ergo_ser::sigma_value::AvlTreeData| {
        op(
            0xDC,
            Payload::MethodCall {
                type_id: 106,
                method_id: 3,
                obj: Box::new(op(0xDD, Payload::Zero)),
                args: vec![Expr::Const {
                    tpe: SigmaType::SAvlTree,
                    val: SigmaValue::AvlTree(avl),
                }],
                type_args: vec![],
            },
        )
    };
    let mut bad_key = test_avl_tree(None);
    bad_key.key_length = -1;
    assert!(
        matches!(
            eval_to_value(&serialize_avl(bad_key), &cx, &[]),
            Err(EvalError::TypeError { .. })
        ),
        "serialize(AvlTree) must reject negative keyLength",
    );
    let bad_vlen = test_avl_tree(Some(-5));
    assert!(
        matches!(
            eval_to_value(&serialize_avl(bad_vlen), &cx, &[]),
            Err(EvalError::TypeError { .. })
        ),
        "serialize(AvlTree) must reject negative valueLengthOpt",
    );
}

#[test]
fn serialize_coll_header_native_carrier() {
    // The native Coll[Header] carrier (CONTEXT.headers) must serialize:
    // value_to_typed_sigma -> SColl(SHeader) with SigmaValue::Header elements.
    use ergo_ser::sigma_type::SigmaType as T;
    use ergo_ser::sigma_value::{CollValue, SigmaValue as Sv};
    let coll = Value::CollHeader(vec![test_eval_header_v2(), test_eval_header_v2()]);
    let (t, sv) = value_to_typed_sigma(&coll, None).unwrap();
    assert_eq!(t, T::SColl(Box::new(T::SHeader)));
    assert!(matches!(&sv, Sv::Coll(CollValue::Values(v)) if v.len() == 2));
    // Cost = putUShort(len)=3 + 2 * Header(v2)=244 = 491.
    assert_eq!(
        crate::evaluator::opcodes::method_call::serialize_put_cost(&t, &sv).unwrap(),
        3 + 244 + 244,
        "Coll[Header] of 2 v2 headers: 3 + 244*2",
    );
}

#[test]
fn serialize_coll_header_v3_gate() {
    // A pre-v3 main-body `Global.serialize(...)` is rejected at the depth-0
    // `check_v3_only_methods` gate because SGlobal.serialize (106, 3) is v6-only
    // (pre-v3 SGlobal = {1, 2}) — Scala rejects at method resolution
    // (deserialize), BEFORE any argument is evaluated. So the rejection is
    // structural and does NOT depend on the header collection being empty: the
    // value-based "empty Coll[Header] accepts" case is unreachable through a
    // real pre-v3 serialize tree (the method itself never resolves). The
    // value-based SHeader gate is covered by
    // `sheader_gate_is_value_based_not_type_based`.
    let expr = serialize_call_expr(op(
        0xDB,
        Payload::MethodCall {
            type_id: 101, // SContext.headers
            method_id: 2,
            obj: Box::new(op(0xFE, Payload::Zero)),
            args: vec![],
            type_args: vec![],
        },
    ));
    for (label, headers) in [
        ("non-empty", vec![test_eval_header_v2()]),
        ("empty", vec![]),
    ] {
        let mut cx = ReductionContext::minimal(500_000, 0);
        cx.activated_script_version = 3;
        cx.ergo_tree_version = 2;
        cx.last_headers = &headers;
        assert!(
            matches!(
                eval_to_value(&expr, &cx, &[]),
                Err(EvalError::PreV3V6Method { .. })
            ),
            "{label} Coll[Header] serialize must reject (v6-only method) at ergo_tree_version < 3",
        );
    }
}

#[test]
fn unpack_collection_accepts_native_coll_header() {
    // SubstConstants unpacks replacement values via unpack_collection before
    // value_to_typed_sigma; the native Coll[Header] carrier (CONTEXT.headers)
    // must unpack to Header elements rather than erroring.
    let items = unpack_collection(Value::CollHeader(vec![
        test_eval_header_v2(),
        test_eval_header_v2(),
    ]))
    .unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|v| matches!(v, Value::Header(_))));
}

// ════════════════════ SGlobal.serialize(Box) — EIP-50 v6 ════════════════════
// SBox serialize: `value_to_typed_sigma(InlineBox)` surfaces
// `(SBox, OpaqueBoxBytes(raw))` and `serialize_put_cost(SBox)` re-parses those
// bytes to charge the exact `SigmaByteWriter` put-cost sequence
// `ErgoBox.sigmaSerializer` emits (Scala oracle:
// `ErgoBoxCandidate.serializeBodyWithIndexedDigests` + `ErgoBox.sigmaSerializer`):
//   putULong(value)=3, putBytes(tree)=chunk(treeLen), putUInt(height)=0,
//   putUByte(nTokens)=1, per-token putBytes(32)+putULong = chunk(32)+3 = 38,
//   putUByte(nRegs)=1, per-register putValue, putBytes(txId)=chunk(32)=35,
//   putUShort(index)=3.  chunk(n) = 3 + n.
// Register putValue (ValueSerializer): Constant -> type_enc_bytes(tpe) (1/byte)
// + DataSerializer cost; CreateTuple(0x86) -> put(opcode)=1 + putUByte(count)=1
// + Σ item putValue.

#[test]
fn serialize_put_cost_box_minimal() {
    // 3(value) + chunk(3)=6(tree) + 0(height) + 1(nTok) + 1(nRegs)
    // + 35(txId) + 3(index) = 49.
    let b = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_none(),
        &[0xAB; 32],
        7,
    );
    assert_eq!(ser_box_cost(b), 49);
}

#[test]
fn serialize_put_cost_box_with_tokens() {
    // Each token adds chunk(32)+putULong = 35 + 3 = 38.
    let one = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[([0x11; 32], 1000)],
        &reg_none(),
        &[0xAB; 32],
        7,
    );
    assert_eq!(ser_box_cost(one), 49 + 38);
    let two = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[([0x11; 32], 1000), ([0x22; 32], 5)],
        &reg_none(),
        &[0xAB; 32],
        7,
    );
    assert_eq!(ser_box_cost(two), 49 + 76);
}

#[test]
fn serialize_put_cost_box_with_int_register() {
    // R4 = Int(42) CONSTANT: type_enc(SInt)=1 + DataSerializer(SInt)=3 = 4.
    let reg = reg_const(&SigmaType::SInt, &SigmaValue::Int(42));
    let b = build_box(1_000_000, &ser_box_tree(), 100, &[], &reg, &[0xAB; 32], 7);
    assert_eq!(ser_box_cost(b), 49 + 4);
}

#[test]
fn serialize_put_cost_box_with_const_tuple_registers() {
    // R4 = 4-tuple of Byte CONSTANT: type_enc(quad)=5 + data(4) = 9.
    let tpe4 = SigmaType::STuple(vec![SigmaType::SByte; 4]);
    let val4 = SigmaValue::Tuple((1u8..=4).map(|n| SigmaValue::Byte(n as i8)).collect());
    let b4 = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_const(&tpe4, &val4),
        &[0xAB; 32],
        7,
    );
    assert_eq!(ser_box_cost(b4), 49 + 9);

    // R4 = 5-tuple of Byte CONSTANT: type_enc(tuple5)=7 + data(5) = 12.
    let tpe5 = SigmaType::STuple(vec![SigmaType::SByte; 5]);
    let val5 = SigmaValue::Tuple((1u8..=5).map(|n| SigmaValue::Byte(n as i8)).collect());
    let b5 = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_const(&tpe5, &val5),
        &[0xAB; 32],
        7,
    );
    assert_eq!(ser_box_cost(b5), 49 + 12);
}

#[test]
fn serialize_put_cost_box_with_expr_tuple_register() {
    // R4 = (Byte, Byte) as CreateTuple(0x86) EXPRESSION:
    // 1(opcode) + 1(count) + 2 * [type_enc(SByte)=1 + data=1] = 6.
    use ergo_ser::register::{AdditionalRegisters, RegisterValue};
    use ergo_ser::sigma_value::CollValue;
    // The CreateTuple NODE form is `(STuple, SigmaValue::Coll)` — Scala's
    // `Tuple.value` is a `Coll`. A `SigmaValue::Tuple` under the same type is
    // a tuple CONSTANT and encodes as a constant instead.
    let regs = AdditionalRegisters {
        registers: vec![RegisterValue {
            tpe: SigmaType::STuple(vec![SigmaType::SByte, SigmaType::SByte]),
            value: SigmaValue::Coll(CollValue::Values(vec![
                SigmaValue::Byte(102),
                SigmaValue::Byte(99),
            ])),
        }],
    };
    let b = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_from_registers(regs),
        &[0xAB; 32],
        7,
    );
    assert_eq!(ser_box_cost(b), 49 + 6);
}

#[test]
fn serialize_put_cost_nested_box_int_tuple() {
    // serialize((box, Int)) costs serialize(box) + DataSerializer(SInt)=3,
    // exercising the STuple -> SBox recursion in serialize_put_cost.
    use crate::evaluator::opcodes::method_call::serialize_put_cost;
    let b = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_none(),
        &[0xAB; 32],
        7,
    );
    let tpe = SigmaType::STuple(vec![SigmaType::SBox, SigmaType::SInt]);
    let val = SigmaValue::Tuple(vec![SigmaValue::OpaqueBoxBytes(b), SigmaValue::Int(7)]);
    assert_eq!(serialize_put_cost(&tpe, &val).unwrap(), 49 + 3);
}

#[test]
fn serialize_put_cost_box_with_nested_expr_tuple_register() {
    // R4 = ((Byte,Byte),(Byte,Byte)) as nested CreateTuple(0x86) expressions
    // (write_registers emits the expression form recursively). Outer putValue =
    // 1(opcode)+1(count) + 2 * inner; inner putValue = 1(opcode)+1(count) +
    // 2*[type_enc(SByte)=1 + data=1] = 6. So register cost = 2 + 2*6 = 14.
    use ergo_ser::register::{AdditionalRegisters, RegisterValue};
    use ergo_ser::sigma_value::CollValue;
    let inner_t = SigmaType::STuple(vec![SigmaType::SByte, SigmaType::SByte]);
    let inner_v = || {
        SigmaValue::Coll(CollValue::Values(vec![
            SigmaValue::Byte(1),
            SigmaValue::Byte(2),
        ]))
    };
    let regs = AdditionalRegisters {
        registers: vec![RegisterValue {
            tpe: SigmaType::STuple(vec![inner_t.clone(), inner_t]),
            value: SigmaValue::Coll(CollValue::Values(vec![inner_v(), inner_v()])),
        }],
    };
    let b = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_from_registers(regs),
        &[0xAB; 32],
        7,
    );
    assert_eq!(ser_box_cost(b), 49 + 14);
}

#[test]
fn serialize_put_cost_box_with_concrete_collection_register() {
    // R4 = Coll[Int](1, 2) stored as a ConcreteCollection(0x83) EXPRESSION (a
    // valid register EvaluatedValue). putValue cost = 1(opcode) + 3(putUShort
    // size) + type_enc(SInt elem)=1 + 2 * [type_enc(SInt)=1 + DataSerializer=3]
    // = 5 + 8 = 13. Anchored to ConcreteCollectionSerializer.serialize.
    use ergo_ser::opcode::{write_expr, Expr as SerExpr, IrNode as SerNode, Payload as SerPayload};
    let cc = SerExpr::Op(SerNode {
        opcode: 0x83,
        payload: SerPayload::ConcreteCollection {
            elem_type: SigmaType::SInt,
            items: vec![
                SerExpr::Const {
                    tpe: SigmaType::SInt,
                    val: SigmaValue::Int(1),
                },
                SerExpr::Const {
                    tpe: SigmaType::SInt,
                    val: SigmaValue::Int(2),
                },
            ],
        },
    });
    let mut w = ergo_primitives::writer::VlqWriter::new();
    w.put_u8(1); // register count
    write_expr(&mut w, &cc, false).unwrap();
    let reg = w.result();
    let b = build_box(1_000_000, &ser_box_tree(), 100, &[], &reg, &[0xAB; 32], 7);
    assert_eq!(ser_box_cost(b), 49 + 13);
}

#[test]
fn value_to_typed_sigma_inline_box_surfaces_opaque_bytes() {
    // The InlineBox carrier (a decoded SBox) serializes back via its verbatim
    // raw_bytes: value_to_typed_sigma yields (SBox, OpaqueBoxBytes(raw)) and the
    // raw bytes round-trip the canonical box bytes byte-for-byte.
    let bytes = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_none(),
        &[0xAB; 32],
        7,
    );
    let v = sigma_to_value(&SigmaType::SBox, &SigmaValue::OpaqueBoxBytes(bytes.clone())).unwrap();
    assert!(matches!(v, Value::InlineBox(_)));
    let (t, sv) = value_to_typed_sigma(&v, None).unwrap();
    assert_eq!(t, SigmaType::SBox);
    match sv {
        SigmaValue::OpaqueBoxBytes(raw) => assert_eq!(raw, bytes),
        other => panic!("expected OpaqueBoxBytes, got {other:?}"),
    }
}

#[test]
fn sbox_constant_rejects_trailing_bytes() {
    let bytes = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_none(),
        &[0xAB; 32],
        7,
    );
    assert!(sigma_to_value(&SigmaType::SBox, &SigmaValue::OpaqueBoxBytes(bytes.clone())).is_ok());
    for trailing_count in [1, 3] {
        let mut padded = bytes.clone();
        padded.extend(vec![0xAA; trailing_count]);
        let error = sigma_to_value(&SigmaType::SBox, &SigmaValue::OpaqueBoxBytes(padded))
            .expect_err("SBox materialization must consume the entire buffer");
        match error {
            EvalError::TypeError { expected, got } => {
                assert_eq!(expected, "valid SBox constant");
                assert_eq!(got, format!("box has {trailing_count} trailing byte(s)"));
            }
            other => panic!("expected TypeError, got {other:?}"),
        }
    }
}

#[test]
fn value_to_typed_sigma_resolves_self_box_via_context() {
    // serialize(SELF): the SelfBox carrier resolves through the
    // ReductionContext to the concrete box and yields the same
    // (SBox, OpaqueBoxBytes(raw)) the InlineBox path does — where it was
    // previously rejected. Without a context (the SubstConstants path) it
    // still rejects. The raw bytes are the canonical box serialization
    // (`ExtractBytes`/`ErgoBox.sigmaSerializer`).
    let bytes = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_none(),
        &[0xAB; 32],
        7,
    );
    let inline =
        sigma_to_value(&SigmaType::SBox, &SigmaValue::OpaqueBoxBytes(bytes.clone())).unwrap();
    let eb = match inline {
        Value::InlineBox(eb) => *eb,
        other => panic!("expected InlineBox, got {other:?}"),
    };
    let ctx = ReductionContext {
        self_box: Some(&eb),
        ..ReductionContext::minimal(500_000, 0)
    };

    let (t, sv) = value_to_typed_sigma(&Value::SelfBox, Some(&ctx)).unwrap();
    assert_eq!(t, SigmaType::SBox);
    match sv {
        SigmaValue::OpaqueBoxBytes(raw) => assert_eq!(raw, bytes),
        other => panic!("expected OpaqueBoxBytes, got {other:?}"),
    }

    // No context → still rejected (SubstConstants behavior unchanged).
    assert!(value_to_typed_sigma(&Value::SelfBox, None).is_err());
}

#[test]
fn methodcall_global_serialize_box_value_and_cost() {
    // End-to-end: SGlobal.serialize(box constant) -> Coll[Byte] equal to the
    // box bytes (verbatim raw_bytes), AND the total JitCost = 73:
    //   14 shared MethodCall framing (SGlobal receiver 0xDD + 0xDC dispatch +
    //      the SBox arg const) — the same 14 documented in
    //      methodcall_deserialize_to_cost_matches_v6_0_2
    //   + StartWriterCost(10) + serialize_put_cost(SBox minimal)=49
    //   (49 is pinned independently by serialize_put_cost_box_minimal).
    let bytes = build_box(
        1_000_000,
        &ser_box_tree(),
        100,
        &[],
        &reg_none(),
        &[0xAB; 32],
        7,
    );
    let sbox = Expr::Const {
        tpe: SigmaType::SBox,
        val: SigmaValue::OpaqueBoxBytes(bytes.clone()),
    };
    let ser = op(
        0xDC,
        Payload::MethodCall {
            type_id: 106,
            method_id: 3,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![sbox],
            type_args: vec![],
        },
    );
    let mut cx = ReductionContext::minimal(0, 0);
    cx.activated_script_version = 3;
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut acc = CostAccumulator::recording_only();
    let mut trace = None;
    let v = eval_expr(&ser, &cx, &[], &mut env, &mut depth, &mut acc, &mut trace).unwrap();
    assert_eq!(v, Value::CollBytes(bytes));
    assert_eq!(acc.total().value(), 73);
}
