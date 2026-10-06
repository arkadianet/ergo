// ---- Cluster A: whole-tree pre-eval checks (Scala parity, SANTA eval tier) ----

/// An off-curve GroupElement *constant* in the tree's constant segment is
/// rejected at deserialize even when the live path never reads it — Scala's
/// `GroupElementSerializer.parse` curve-validates every GE constant up front,
/// so `if (true) 5 else <off-curve GE>` errors despite the dead else-branch.
#[test]
fn ge_offcurve_constant_errors_even_when_unused() {
    let mut bytes = [0xffu8; 33];
    bytes[0] = 0x02; // x = 0xff*32 is not a valid SecP256K1 field element
    let constants = vec![(
        SigmaType::SGroupElement,
        SigmaValue::GroupElement(ergo_primitives::group_element::GroupElement::from_bytes(
            bytes,
        )),
    )];
    // HEIGHT — never references the GE constant (it stays on a dead path).
    let expr = Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    });
    let ctx = ReductionContext::minimal(200_000, 0);
    let result = eval_to_value(&expr, &ctx, &constants);
    assert!(
        result.is_err(),
        "off-curve GE constant must error even unused, got {result:?}"
    );
}

/// A non-canonical *identity* GE constant (lead byte 0x00, trailing garbage)
/// parses fine — only a non-zero lead triggers curve validation — so a tree
/// carrying it on a dead branch still evaluates normally.
#[test]
fn ge_identity_garbage_constant_accepted() {
    let mut bytes = [0xaau8; 33];
    bytes[0] = 0x00; // identity encoding: trailing bytes discarded at parse
    let constants = vec![(
        SigmaType::SGroupElement,
        SigmaValue::GroupElement(ergo_primitives::group_element::GroupElement::from_bytes(
            bytes,
        )),
    )];
    let expr = Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    });
    let ctx = ReductionContext::minimal(200_000, 0);
    let result = eval_to_value(&expr, &ctx, &constants);
    assert_eq!(result.unwrap(), Value::Int(200_000));
}

/// A ContextExtension carrying a key with the high bit set (>= 0x80) makes
/// Scala's `toSigmaContext` build a `new Array(maxKey+1)` indexed by the
/// signed-negative Byte key and throw before any bytecode runs — the spend
/// fails regardless of whether the script reads the extension.
#[test]
fn extension_key_high_bit_errors() {
    let expr = Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    });
    let mut ctx = ReductionContext::minimal(200_000, 0);
    ctx.extension
        .insert(128, (SigmaType::SInt, SigmaValue::Int(42)));
    let result = eval_to_value(&expr, &ctx, &[]);
    assert!(
        result.is_err(),
        "extension key 0x80 must error before eval, got {result:?}"
    );
}

/// Key 0x7f (127) is the inclusive max signed-positive Byte — the context
/// builds and the script evaluates normally (the accept boundary).
#[test]
fn extension_key_max_signed_accepted() {
    let expr = Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    });
    let mut ctx = ReductionContext::minimal(200_000, 0);
    ctx.extension
        .insert(127, (SigmaType::SInt, SigmaValue::Int(42)));
    let result = eval_to_value(&expr, &ctx, &[]);
    assert_eq!(result.unwrap(), Value::Int(200_000));
}

// ---- Cluster: Tuple.checkType — non-pair tuple as a tuple item (Scala parity) ----

/// Scala `Tuple.eval` runs `Value.checkType(item, itemV)` on each of the two
/// items; `SType.isValueOfType` then `sys.error("Unsupported tuple type")` for
/// any item whose type is a tuple of arity != 2. So constructing `Tuple(t3, 1)`
/// where `t3` is a 3-tuple errors — at both the inline-constant and the
/// ConstantPlaceholder seam (both arrive as item0 of the outer `Tuple` op).
#[test]
fn tuple_item_three_tuple_errors() {
    let constants = vec![
        (
            SigmaType::STuple(vec![
                SigmaType::SBoolean,
                SigmaType::SBoolean,
                SigmaType::SBoolean,
            ]),
            SigmaValue::Tuple(vec![
                SigmaValue::Boolean(true),
                SigmaValue::Boolean(true),
                SigmaValue::Boolean(true),
            ]),
        ),
        (SigmaType::SInt, SigmaValue::Int(1)),
    ];
    let item0 = Expr::Op(IrNode {
        opcode: 0x73,
        payload: Payload::ConstPlaceholder { index: 0 },
    });
    let item1 = Expr::Op(IrNode {
        opcode: 0x73,
        payload: Payload::ConstPlaceholder { index: 1 },
    });
    let expr = Expr::Op(IrNode {
        opcode: 0x86,
        payload: Payload::Tuple {
            items: vec![item0, item1],
        },
    });
    let ctx = ReductionContext::minimal(100_000, 0);
    let result = eval_to_value(&expr, &ctx, &constants);
    assert!(
        result.is_err(),
        "a 3-tuple as a tuple item must error (checkType), got {result:?}"
    );
}

/// A nested *pair* item is fine: `Tuple( (a,b), c )` — item0 is an arity-2
/// tuple, which `isValueOfType` accepts — so the construction succeeds.
#[test]
fn tuple_item_nested_pair_ok() {
    let constants = vec![
        (
            SigmaType::STuple(vec![SigmaType::SBoolean, SigmaType::SBoolean]),
            SigmaValue::Tuple(vec![SigmaValue::Boolean(true), SigmaValue::Boolean(false)]),
        ),
        (SigmaType::SInt, SigmaValue::Int(1)),
    ];
    let item0 = Expr::Op(IrNode {
        opcode: 0x73,
        payload: Payload::ConstPlaceholder { index: 0 },
    });
    let item1 = Expr::Op(IrNode {
        opcode: 0x73,
        payload: Payload::ConstPlaceholder { index: 1 },
    });
    let expr = Expr::Op(IrNode {
        opcode: 0x86,
        payload: Payload::Tuple {
            items: vec![item0, item1],
        },
    });
    let ctx = ReductionContext::minimal(100_000, 0);
    let result = eval_to_value(&expr, &ctx, &constants);
    assert!(
        result.is_ok(),
        "a nested pair item is valid, got {result:?}"
    );
}

// ---- Cluster: ExtractBytesWithNoRef canonicalizes register GE garbage ----

/// A box received on the wire with an identity `GroupElement` register whose
/// trailing 32 bytes are garbage (`00 aa*32`) must surface `bytesWithoutRef`
/// (0xC4) CANONICALLY: Scala `GroupElementSerializer.parse` maps any
/// `0x00`-lead encoding to the identity point and re-serializes it as 33
/// zeroes, and the box id is computed over the re-serialized bytes. The
/// normalization happens at parse (`read_group_element`), so the parsed
/// candidate's cached register block is already canonical and the evaluator
/// simply emits it. Goes through the production reader rather than a
/// hand-built `EvalBox`, because that is where the contract now lives.
#[test]
fn extract_bytes_with_no_ref_canonicalizes_register_ge() {
    use ergo_ser::ergo_box::{read_ergo_box_candidate, write_ergo_box, ErgoBox};
    let ge_garbage = {
        let mut g = [0xaau8; 33];
        g[0] = 0x00; // identity lead: trailing bytes discarded at parse
        g
    };
    // Candidate: value 1000000, `sigmaProp(true)`, height 0, no tokens, R4 = GE
    // (the JVM oracle's box shape, `canonical_extension_and_group_element.json`).
    let mut wire = hex::decode("c0843d10010101d1730000000107").unwrap();
    wire.extend_from_slice(&ge_garbage);
    let mut r = ergo_primitives::reader::VlqReader::new(&wire);
    let candidate = read_ergo_box_candidate(&mut r).expect("Scala accepts a 0x00-lead point");
    assert!(r.is_empty());
    assert!(
        !candidate.register_bytes().contains(&0xAA),
        "the reader must normalize the identity garbage at parse"
    );
    let ergo_box = ErgoBox {
        candidate,
        transaction_id: ergo_primitives::digest::ModifierId::from_bytes([0x11; 32]),
        index: 0,
    };
    let raw_bytes = {
        let mut w = ergo_primitives::writer::VlqWriter::new();
        write_ergo_box(&mut w, &ergo_box).unwrap();
        w.result()
    };
    let b = EvalBox {
        bytes_without_ref_cache: Default::default(),
        creation_height: 0,
        script_bytes: ergo_box.candidate.ergo_tree_bytes().to_vec(),
        value: ergo_box.candidate.value as i64,
        id: *ergo_box.box_id().unwrap().as_bytes(),
        transaction_id: [0x11; 32],
        output_index: 0,
        registers: [
            ergo_box
                .candidate
                .additional_registers()
                .get(ergo_ser::register::RegisterId::R4)
                .cloned(),
            None,
            None,
            None,
            None,
            None,
        ],
        tokens: Vec::new(),
        raw_bytes,
        register_bytes: ergo_box.candidate.register_bytes().to_vec(),
    };
    let ctx = ctx_with_self_box(&b);
    let expr = op(0xC4, Payload::One(Box::new(op(0xA7, Payload::Zero))));
    let out = match run_eval_ctx(&expr, &ctx) {
        Value::CollBytes(v) => v,
        other => panic!("expected CollBytes, got {other:?}"),
    };
    assert!(
        !out.contains(&0xAA),
        "bytesWithoutRef must carry the canonical identity GE, got {out:?}"
    );
    let mut expected_tail = vec![0x07u8];
    expected_tail.extend_from_slice(&[0x00; 33]);
    assert_eq!(
        &out[out.len() - 34..],
        expected_tail.as_slice(),
        "register tail must be canonical identity GE"
    );
}

/// SANTA `Box.bytes_byte_basis` / `Box.accessor_method_form` /
/// `Box.eq_id_basis`: a box materialized from the data serializer retains the
/// exact parse slice (Scala `ErgoBox._bytes`; `ErgoBox.scala:73,87-91,214-227`),
/// so `.bytes`/`.id` keep a non-canonical identity GE encoding (`00 aa..aa`)
/// and a garbage-encoded twin has a different id (box equality is id-based).
/// `Global.serialize(SBox)` must still re-serialize canonically
/// (`DataSerializer.serialize(SBox)`; `ErgoBox.scala:204-211`).
#[test]
fn sbox_constant_retains_wire_bytes_for_bytes_and_id() {
    // Candidate: value 1000000, `sigmaProp(true)`, height 0, no tokens, R4 = GE
    // with a 0x00 lead and garbage trailing bytes (the vector's box shape).
    let mut candidate = hex::decode("c0843d10010101d1730000000107").unwrap();
    let mut ge_garbage = [0xaau8; 33];
    ge_garbage[0] = 0x00;
    candidate.extend_from_slice(&ge_garbage);
    // Full box constant = candidate + txId + output index.
    let mut box_bytes = candidate.clone();
    box_bytes.extend_from_slice(&[0x11u8; 32]);
    box_bytes.push(0x00);

    let v = sigma_to_value(
        &SigmaType::SBox,
        &SigmaValue::OpaqueBoxBytes(box_bytes.clone()),
    )
    .expect("Scala accepts a 0x00-lead point");
    let eb = match v.clone() {
        Value::InlineBox(eb) => *eb,
        other => panic!("expected InlineBox, got {other:?}"),
    };
    assert!(
        eb.raw_bytes.contains(&0xAA),
        "`.bytes` must retain the parse slice, got {:?}",
        eb.raw_bytes
    );
    assert_eq!(
        eb.id,
        *ergo_primitives::digest::blake2b256(&box_bytes).as_bytes(),
        "`.id` must hash the retained slice"
    );

    // ExtractBytes (0xC3) surfaces the retained slice.
    let ctx = ctx_with_self_box(&eb);
    let expr = op(0xC3, Payload::One(Box::new(op(0xA7, Payload::Zero))));
    match run_eval_ctx(&expr, &ctx) {
        Value::CollBytes(b) => assert!(b.contains(&0xAA), "ExtractBytes must be retained"),
        other => panic!("expected CollBytes, got {other:?}"),
    }

    // The canonical twin (same decoded value, canonical R4) has a different id
    // — the `box1 == box2` false case.
    let mut canon = candidate.clone();
    canon[14..47].copy_from_slice(&[0x00; 33]);
    canon.extend_from_slice(&[0x11u8; 32]);
    canon.push(0x00);
    let canon_eb = match sigma_to_value(&SigmaType::SBox, &SigmaValue::OpaqueBoxBytes(canon))
        .expect("canonical twin parses")
    {
        Value::InlineBox(eb) => *eb,
        other => panic!("expected InlineBox, got {other:?}"),
    };
    assert_ne!(
        eb.id, canon_eb.id,
        "byte-basis identity: the garbage encoding must yield a different id"
    );

    // `Global.serialize(SBox)` re-serializes from structure — no garbage.
    let (tpe, sv) = value_to_typed_sigma(&v, None).unwrap();
    assert_eq!(tpe, SigmaType::SBox);
    match sv {
        SigmaValue::OpaqueBoxBytes(canonical) => {
            assert!(
                !canonical.contains(&0xAA),
                "serialize must canonicalize the register, got {canonical:?}"
            );
            let mut r = ergo_primitives::reader::VlqReader::new(&canonical);
            ergo_ser::ergo_box::read_ergo_box(&mut r).expect("canonical bytes parse");
        }
        other => panic!("expected OpaqueBoxBytes, got {other:?}"),
    }
}

// ---- Cluster: ExtractBytesWithNoRef preserves register node provenance ----

/// A tuple-typed register encoded as a Constant (DataSerializer form) must
/// round-trip through bytesWithoutRef byte-for-byte — NOT collapse into a
/// `CreateTuple` (0x86) expression. This is the divergence that stalled
/// mainnet block 1808895.
///
/// The parsed `RegisterValue` now carries the provenance itself: a tuple
/// Constant is `(STuple, SigmaValue::Tuple)` and a `CreateTuple` node is
/// `(STuple, SigmaValue::Coll)` — Scala's `Tuple.value` really is a `Coll`
/// (`sigma/ast/values.scala:786-791`). So the structural writer reproduces
/// either form faithfully, and the verbatim bytes are a belt-and-braces
/// second copy rather than the only source of truth.
#[test]
fn extract_bytes_with_no_ref_preserves_constant_tuple_register() {
    let tpe = SigmaType::STuple(vec![SigmaType::SLong, SigmaType::SLong]);
    let val = SigmaValue::Tuple(vec![SigmaValue::Long(5), SigmaValue::Long(7)]);
    let entry = expr_wire_bytes(&Expr::Const {
        tpe: tpe.clone(),
        val: val.clone(),
    });
    assert!(
        entry[0] <= 0x70,
        "fixture must be Constant-encoded, got lead {:#x}",
        entry[0]
    );

    // The same value through the structural register writer must ALSO stay a
    // Constant — it used to be rewritten as a `CreateTuple` (0x86), which gave
    // a box carrying this shape (block 836113, tx[18].R9 on mainnet) the wrong
    // id and the containing transaction the wrong id on the JSON submit path.
    let structural = {
        let mut w = ergo_primitives::writer::VlqWriter::new();
        ergo_ser::register::write_registers(
            &mut w,
            &ergo_ser::register::AdditionalRegisters {
                registers: vec![ergo_ser::register::RegisterValue { tpe, value: val }],
            },
        )
        .unwrap();
        w.result()
    };
    assert_eq!(
        structural[1], entry[0],
        "structural writer must keep a tuple Constant as a Constant"
    );

    let mut register_bytes = vec![0x01u8];
    register_bytes.extend_from_slice(&entry);
    let out = bytes_with_no_ref_for_register_block(register_bytes);

    assert_eq!(
        &out[out.len() - entry.len()..],
        entry.as_slice(),
        "Constant-encoded tuple register must round-trip verbatim (not 0x86)"
    );
}

/// A register genuinely encoded as a `CreateTuple` expression (0x86) — real
/// mainnet boxes carry these (e.g. block 855650 R8) — must KEEP its 0x86 form
/// through bytesWithoutRef. The fix preserves provenance both ways: it must not
/// rewrite a Constant tuple as 0x86, nor a 0x86 register as a Constant.
#[test]
fn extract_bytes_with_no_ref_preserves_create_tuple_register() {
    let create_tuple = Expr::Op(IrNode {
        opcode: 0x86,
        payload: Payload::Tuple {
            items: vec![
                Expr::Const {
                    tpe: SigmaType::SLong,
                    val: SigmaValue::Long(5),
                },
                Expr::Const {
                    tpe: SigmaType::SLong,
                    val: SigmaValue::Long(7),
                },
            ],
        },
    });
    let entry = expr_wire_bytes(&create_tuple);
    assert_eq!(entry[0], 0x86, "fixture must be a CreateTuple expression");

    let mut register_bytes = vec![0x01u8];
    register_bytes.extend_from_slice(&entry);
    let out = bytes_with_no_ref_for_register_block(register_bytes);

    assert_eq!(
        &out[out.len() - entry.len()..],
        entry.as_slice(),
        "CreateTuple (0x86) register must stay 0x86 (provenance preserved)"
    );
}

/// The exact mainnet-1808895 box shape: a register that is a Constant of a
/// tuple type CONTAINING a GroupElement, received on the wire with identity
/// garbage inside the tuple. The GE must be canonicalized (garbage -> 33
/// zeros) WHILE the register stays Constant form -- both hold because
/// `read_group_element` normalizes at parse and the parsed `RegisterValue`
/// keeps the Constant provenance. The garbage wire form is fabricated from
/// the canonical encoding by overwriting the 33-zero identity run, since the
/// writer no longer emits non-canonical points.
#[test]
fn extract_bytes_with_no_ref_normalizes_ge_inside_constant_tuple_register() {
    use ergo_ser::ergo_box::read_ergo_box_candidate;
    let tpe = SigmaType::STuple(vec![SigmaType::SGroupElement, SigmaType::SLong]);
    let val = SigmaValue::Tuple(vec![
        SigmaValue::GroupElement(ergo_primitives::group_element::GroupElement::from_bytes(
            [0u8; 33],
        )),
        SigmaValue::Long(7),
    ]);
    let canonical_entry = expr_wire_bytes(&Expr::Const { tpe, val });
    assert!(
        canonical_entry[0] <= 0x70,
        "fixture must be Constant-encoded"
    );
    let zero_run = canonical_entry
        .windows(33)
        .position(|w| w.iter().all(|b| *b == 0))
        .expect("canonical entry carries the 33-zero identity point");
    let mut wire_entry = canonical_entry.clone();
    wire_entry[zero_run + 1..zero_run + 33].fill(0xAA); // `00 aa*32`
    assert!(wire_entry.contains(&0xAA), "fixture must carry GE garbage");

    // Candidate: value 1000000, `sigmaProp(true)`, height 0, no tokens, one register.
    let mut wire = hex::decode("c0843d10010101d17300000001").unwrap();
    wire.extend_from_slice(&wire_entry);
    let mut r = ergo_primitives::reader::VlqReader::new(&wire);
    let candidate = read_ergo_box_candidate(&mut r).expect("Scala accepts the garbage point");
    assert!(r.is_empty());

    let out = bytes_with_no_ref_for_register_block(candidate.register_bytes().to_vec());
    assert!(
        !out.contains(&0xAA),
        "identity garbage inside the tuple must be normalized, got {out:?}"
    );
    assert_eq!(
        &out[out.len() - canonical_entry.len()..],
        canonical_entry.as_slice(),
        "register must stay Constant form with the canonical identity GE"
    );
}

// ---- Cluster: SBox accessor method-forms (PropertyCall 99:1..6) ----

/// The box accessors have a method-form (`PropertyCall(99, n)`) in addition to
/// their dedicated opcode (ExtractAmount, ...). Scala dispatches both to the
/// same logic. Add the no-arg SBox arms 1..6 so the method-form returns the
/// same values: value, propositionBytes, bytes (retained), bytesWithoutRef
/// (canonical), id, creationInfo.
#[test]
fn sbox_accessor_method_forms() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let pc = |mid: u8| {
        op(
            0xDB,
            Payload::MethodCall {
                type_id: 99,
                method_id: mid,
                obj: Box::new(op(0xA7, Payload::Zero)),
                args: vec![],
                type_args: vec![],
            },
        )
    };
    assert_eq!(run_eval_ctx(&pc(1), &ctx), Value::Long(1_000_000_000));
    assert_eq!(
        run_eval_ctx(&pc(2), &ctx),
        Value::CollBytes(vec![0x00, 0x08, 0xCD])
    );
    assert_eq!(
        run_eval_ctx(&pc(3), &ctx),
        Value::CollBytes(vec![0xDE, 0xAD, 0xBE, 0xEF])
    );
    assert_eq!(run_eval_ctx(&pc(5), &ctx), Value::CollBytes(b.id.to_vec()));
    let mut ref_bytes = b.transaction_id.to_vec();
    ref_bytes.extend_from_slice(&b.output_index.to_be_bytes());
    assert_eq!(
        run_eval_ctx(&pc(6), &ctx),
        Value::Tuple(vec![Value::Int(500_000), Value::CollBytes(ref_bytes)])
    );
    // bytesWithoutRef: canonical re-serialization (own dedicated test covers
    // the GE normalization); here just assert it dispatches to CollBytes.
    match run_eval_ctx(&pc(4), &ctx) {
        Value::CollBytes(v) => assert!(!v.is_empty(), "bytesWithoutRef must be non-empty"),
        other => panic!("expected CollBytes for bytesWithoutRef, got {other:?}"),
    }
}

/// The method-form cost matches the opcode-form: envelope (PropertyCall 0xDB =
/// 4) + the extract method body equal to the dedicated opcode's cost. e.g.
/// value = 4 + ExtractAmount(8); creationInfo = 4 + ExtractCreationInfo(16).
#[test]
fn sbox_accessor_method_form_costs() {
    let b = make_test_box();
    let ctx = ctx_with_self_box(&b);
    let cost_of = |mid: u8| {
        let expr = op(
            0xDB,
            Payload::MethodCall {
                type_id: 99,
                method_id: mid,
                obj: Box::new(op(0xA7, Payload::Zero)),
                args: vec![],
                type_args: vec![],
            },
        );
        let mut cost = CostAccumulator::recording_only();
        let mut env = Env::new();
        let mut depth = 0usize;
        let mut trace = None;
        eval_expr(
            &expr,
            &ctx,
            &[],
            &mut env,
            &mut depth,
            &mut cost,
            &mut trace,
        )
        .unwrap();
        cost.total().value()
    };
    // SELF(0xA7) cost is the same constant for every call, so the deltas are
    // purely the per-method extract body: 8/10/12/12/12/16.
    let self_only = {
        let expr = op(0xA7, Payload::Zero);
        let mut cost = CostAccumulator::recording_only();
        let mut env = Env::new();
        let mut depth = 0usize;
        let mut trace = None;
        eval_expr(
            &expr,
            &ctx,
            &[],
            &mut env,
            &mut depth,
            &mut cost,
            &mut trace,
        )
        .unwrap();
        cost.total().value()
    };
    // total = SELF visit + envelope(4) + body. Additive form (not
    // `cost_of - self_only - 4`) so a regression surfaces as a value mismatch
    // rather than a u64 underflow panic.
    assert_eq!(
        cost_of(1),
        self_only + 4 + 8,
        "value body = ExtractAmount(8)"
    );
    assert_eq!(
        cost_of(6),
        self_only + 4 + 16,
        "creationInfo body = ExtractCreationInfo(16)"
    );
}

/// `value-trace`: every evaluated node's value, keyed by its preorder id
/// in the armed root — `SizeOf(Coll(10,20,30))` records the collection
/// (id 1) and the size (id 0), in evaluation order.
#[cfg(feature = "value-trace")]
#[test]
fn value_trace_records_every_evaluated_node_by_preorder_id() {
    let coll = const_bytes(vec![10, 20, 30]);
    let expr = op(0xB1, Payload::One(Box::new(coll)));
    crate::value_trace::enable(&expr);
    assert_eq!(run_eval(&expr), Value::Int(3));
    let entries = crate::value_trace::take().expect("armed");
    let ids: Vec<u64> = entries.iter().map(|e| e.id).collect();
    assert_eq!(ids, vec![1, 0], "{entries:?}");
    assert!(entries[1].value.contains("Int(3)"), "{entries:?}");
    // Nothing is recorded once taken.
    assert_eq!(run_eval(&expr), Value::Int(3));
    assert!(crate::value_trace::take().is_none());
}
