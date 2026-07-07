use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use super::types::{opcode_pattern, MAX_EXPR_DEPTH};
use super::*;

use crate::sigma_type::SigmaType;
use crate::sigma_value::SigmaValue;

// ----- helpers -----

fn roundtrip(body: &Body, cseg: bool) {
    roundtrip_v(body, cseg, 0);
}

fn roundtrip_v(body: &Body, cseg: bool, tree_version: u8) {
    let mut w = VlqWriter::new();
    write_body(&mut w, body, cseg).unwrap();
    let data = w.result();
    let mut r = VlqReader::new(&data);
    let decoded = parse_body(&mut r, tree_version).unwrap();
    assert!(r.is_empty(), "leftover bytes after roundtrip");
    assert_eq!(&decoded, body);
    // Verify byte-identical reserialization
    let mut w2 = VlqWriter::new();
    write_body(&mut w2, &decoded, cseg).unwrap();
    assert_eq!(data, w2.result(), "reserialized bytes differ");
}

// ----- round-trips -----

#[test]
fn roundtrip_inline_constant_int() {
    let body = Expr::Const {
        tpe: SigmaType::SInt,
        val: SigmaValue::Int(42),
    };
    roundtrip(&body, false);
}

#[test]
fn roundtrip_inline_constant_sigmaprop() {
    use crate::sigma_value::SigmaBoolean;
    use ergo_primitives::group_element::GroupElement;
    // P2PK body: a constant SSigmaProp(ProveDlog(ge))
    let ge = GroupElement::from_bytes([0x02; 33]);
    let body = Expr::Const {
        tpe: SigmaType::SSigmaProp,
        val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(ge)),
    };
    roundtrip(&body, false);
}

#[test]
fn relation2_bool_constant_pair_writes_compact_0x85_form() {
    // Scala's Relation2Serializer encodes a relation over two boolean CONSTANTS
    // as a compact BoolCollection: opcode + 0x85 marker + one packed byte,
    // LSB-first (bit 0 = left, bit 1 = right). Pin the exact bytes for `Eq`
    // (0x93) and confirm the reader decodes them back to the two Consts and the
    // re-serialization is byte-identical.
    let pair = |opcode: u8, left: bool, right: bool| {
        Expr::Op(IrNode {
            opcode,
            payload: Payload::Two(
                Box::new(Expr::Const {
                    tpe: SigmaType::SBoolean,
                    val: SigmaValue::Boolean(left),
                }),
                Box::new(Expr::Const {
                    tpe: SigmaType::SBoolean,
                    val: SigmaValue::Boolean(right),
                }),
            ),
        })
    };
    let bytes = |body: &Body| {
        let mut w = VlqWriter::new();
        write_body(&mut w, body, false).unwrap();
        w.result()
    };
    // Eq (0x93): all four bit combinations pin the packed byte (LSB-first).
    assert_eq!(bytes(&pair(0x93, true, false)), vec![0x93, 0x85, 0x01]);
    assert_eq!(bytes(&pair(0x93, false, true)), vec![0x93, 0x85, 0x02]);
    assert_eq!(bytes(&pair(0x93, true, true)), vec![0x93, 0x85, 0x03]);
    assert_eq!(bytes(&pair(0x93, false, false)), vec![0x93, 0x85, 0x00]);
    // The compact form applies to every Relation2 opcode, incl. BinXor (0xF4)
    // and the lazy BinOr/BinAnd (0xEC/0xED) — keyed off opcode_pattern.
    assert_eq!(bytes(&pair(0xF4, true, false)), vec![0xF4, 0x85, 0x01]);
    assert_eq!(bytes(&pair(0xEC, false, true)), vec![0xEC, 0x85, 0x02]);
    assert_eq!(bytes(&pair(0xED, true, true)), vec![0xED, 0x85, 0x03]);
    roundtrip(&pair(0x93, true, false), false);
    roundtrip(&pair(0xF4, false, true), false);
}

#[test]
fn non_relation2_two_arg_opcode_with_bool_consts_stays_expanded() {
    // The compact 0x85 form is gated on the opcode being a Relation2, not just
    // on the operands being bool consts. A Two-arg non-Relation2 opcode (Plus,
    // 0x9A) over two boolean Consts must stay expanded (opcode + two Consts).
    let body = Expr::Op(IrNode {
        opcode: 0x9A, // Plus — Two-arg, NOT a Relation2
        payload: Payload::Two(
            Box::new(Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            }),
            Box::new(Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(false),
            }),
        ),
    });
    let mut w = VlqWriter::new();
    write_body(&mut w, &body, false).unwrap();
    assert_ne!(
        w.result().get(1),
        Some(&0x85),
        "non-Relation2 Two-arg opcode must not emit the compact 0x85 form"
    );
    roundtrip(&body, false);
}

#[test]
fn relation2_non_bool_operands_stay_expanded() {
    // A Relation2 whose operands are NOT both boolean constants must use the
    // expanded two-child encoding (no 0x85 compact form). Here both operands
    // are Int constants, so the bytes are opcode + Const(Int) + Const(Int).
    let body = Expr::Op(IrNode {
        opcode: 0x93, // Eq
        payload: Payload::Two(
            Box::new(Expr::Const {
                tpe: SigmaType::SInt,
                val: SigmaValue::Int(1),
            }),
            Box::new(Expr::Const {
                tpe: SigmaType::SInt,
                val: SigmaValue::Int(2),
            }),
        ),
    });
    let mut w = VlqWriter::new();
    write_body(&mut w, &body, false).unwrap();
    let out = w.result();
    assert_ne!(
        out.get(1),
        Some(&0x85),
        "Int-operand Relation2 must not emit the compact 0x85 form"
    );
    roundtrip(&body, false);
}

#[test]
fn roundtrip_zero_arg_opcodes() {
    // 0x81 UnitConstant intentionally absent from this set: SUnit
    // values roundtrip through the constant-encoding path, not a
    // dispatch arm.
    for &op in &[0x7F, 0x80, 0x82, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xAC, 0xFE] {
        let body = Expr::Op(IrNode {
            opcode: op,
            payload: Payload::Zero,
        });
        roundtrip(&body, false);
    }
}

#[test]
fn roundtrip_one_arg_opcode() {
    // SizeOf(Height)
    let height = Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    });
    let body = Expr::Op(IrNode {
        opcode: 0xB1, // SizeOf
        payload: Payload::One(Box::new(height)),
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_two_arg_opcode() {
    // Eq(Height, Height)
    let h1 = Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    });
    let h2 = Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    });
    let body = Expr::Op(IrNode {
        opcode: 0x93, // Eq
        payload: Payload::Two(Box::new(h1), Box::new(h2)),
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_three_arg_opcode() {
    // If(True, Height, Height)
    let cond = Expr::Op(IrNode {
        opcode: 0x7F,
        payload: Payload::Zero,
    });
    let h1 = Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    });
    let h2 = Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    });
    let body = Expr::Op(IrNode {
        opcode: 0x95, // If
        payload: Payload::Three(Box::new(cond), Box::new(h1), Box::new(h2)),
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_const_placeholder() {
    let body = Expr::Op(IrNode {
        opcode: 0x73,
        payload: Payload::ConstPlaceholder { index: 5 },
    });
    roundtrip(&body, true);
}

#[test]
fn roundtrip_val_use() {
    let body = Expr::Op(IrNode {
        opcode: 0x72,
        payload: Payload::ValUse { id: 1 },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_tagged_var() {
    // Type is never serialized (Scala ConstantStore.empty always non-null).
    let body = Expr::Op(IrNode {
        opcode: 0x71,
        payload: Payload::TaggedVar { id: 3, tpe: None },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_valdef_no_cseg() {
    // Type is never serialized regardless of cseg flag.
    let rhs = Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    });
    let body = Expr::Op(IrNode {
        opcode: 0xD6,
        payload: Payload::ValDef {
            id: 1,
            tpe: None,
            rhs: Box::new(rhs),
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_valdef_cseg() {
    let rhs = Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    });
    let body = Expr::Op(IrNode {
        opcode: 0xD6,
        payload: Payload::ValDef {
            id: 1,
            tpe: None,
            rhs: Box::new(rhs),
        },
    });
    roundtrip(&body, true);
}

/// FunDef (0xD7) wire format per Scala `ValDefSerializer`: between the
/// id and the rhs sits `nTpeArgs(u8)` + that many STypeVar types —
/// always present, possibly empty. Skipping it (the old behavior)
/// misreads the count byte as the rhs opcode and the whole body parse
/// derails, so every tree containing a polymorphic FunDef was falsely
/// rejected. Byte-identical reserialization pins both directions.
#[test]
fn roundtrip_fun_def_with_tpe_args() {
    let lambda = Expr::Op(IrNode {
        opcode: 0xD9,
        payload: Payload::FuncValue {
            args: vec![(2, Some(SigmaType::STypeVar("T".into())))],
            body: Box::new(Expr::Op(IrNode {
                opcode: 0x72,
                payload: Payload::ValUse { id: 2 },
            })),
        },
    });
    let body = Expr::Op(IrNode {
        opcode: 0xD7,
        payload: Payload::FunDef {
            id: 1,
            tpe: None,
            tpe_args: vec![SigmaType::STypeVar("T".into())],
            rhs: Box::new(lambda),
        },
    });
    roundtrip(&body, false);
}

/// A FunDef with an empty tpeArgs block still carries the count byte.
#[test]
fn roundtrip_fun_def_empty_tpe_args() {
    let body = Expr::Op(IrNode {
        opcode: 0xD7,
        payload: Payload::FunDef {
            id: 1,
            tpe: None,
            tpe_args: vec![],
            rhs: Box::new(Expr::Op(IrNode {
                opcode: 0xA3,
                payload: Payload::Zero,
            })),
        },
    });
    roundtrip(&body, false);
}

/// A non-STypeVar type in the FunDef tpeArgs position fails the parse
/// (Scala: `r.getType().asInstanceOf[STypeVar]` ClassCastException).
#[test]
fn fun_def_non_type_var_tpe_arg_rejected() {
    let mut w = VlqWriter::new();
    // 0xD7 FunDef, id=1, nTpeArgs=1, then SInt (0x04) — not a typevar.
    w.put_u8(0xD7);
    w.put_u32(1);
    w.put_u8(1);
    w.put_u8(0x04);
    w.put_u8(0xA3); // rhs: Height (never reached)
    let data = w.result();
    let mut r = VlqReader::new(&data);
    assert!(parse_body(&mut r, 3).is_err());
}

#[test]
fn roundtrip_block_value() {
    let def = Expr::Op(IrNode {
        opcode: 0xD6,
        payload: Payload::ValDef {
            id: 1,
            tpe: None,
            rhs: Box::new(Expr::Op(IrNode {
                opcode: 0xA3,
                payload: Payload::Zero,
            })),
        },
    });
    let result = Expr::Op(IrNode {
        opcode: 0x72,
        payload: Payload::ValUse { id: 1 },
    });
    let body = Expr::Op(IrNode {
        opcode: 0xD8,
        payload: Payload::BlockValue {
            items: vec![def],
            result: Box::new(result),
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_func_value() {
    let use_expr = Expr::Op(IrNode {
        opcode: 0x72,
        payload: Payload::ValUse { id: 1 },
    });
    let body = Expr::Op(IrNode {
        opcode: 0xD9,
        payload: Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(use_expr),
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_method_call() {
    let obj = Expr::Op(IrNode {
        opcode: 0xA7,
        payload: Payload::Zero,
    }); // Self
    let body = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 1,
            method_id: 5,
            obj: Box::new(obj),
            args: vec![],
            type_args: vec![],
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_method_call_with_args() {
    let obj = Expr::Op(IrNode {
        opcode: 0xA7,
        payload: Payload::Zero,
    });
    let arg = Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    });
    let body = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 12,
            method_id: 2,
            obj: Box::new(obj),
            args: vec![arg],
            type_args: vec![],
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_concrete_collection() {
    let items = vec![
        Expr::Op(IrNode {
            opcode: 0xA3,
            payload: Payload::Zero,
        }),
        Expr::Op(IrNode {
            opcode: 0xA3,
            payload: Payload::Zero,
        }),
    ];
    let body = Expr::Op(IrNode {
        opcode: 0x83,
        payload: Payload::ConcreteCollection {
            elem_type: SigmaType::SInt,
            items,
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_bool_collection() {
    let body = Expr::Op(IrNode {
        opcode: 0x85,
        payload: Payload::BoolCollection {
            bits: vec![true, false, true, true, false, false, true, false, true],
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_tuple() {
    let items = vec![
        Expr::Op(IrNode {
            opcode: 0xA3,
            payload: Payload::Zero,
        }),
        Expr::Op(IrNode {
            opcode: 0x7F,
            payload: Payload::Zero,
        }),
    ];
    let body = Expr::Op(IrNode {
        opcode: 0x86,
        payload: Payload::Tuple { items },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_select_field() {
    let input = Expr::Op(IrNode {
        opcode: 0xA7,
        payload: Payload::Zero,
    });
    let body = Expr::Op(IrNode {
        opcode: 0x8C,
        payload: Payload::SelectField {
            input: Box::new(input),
            field_idx: 1,
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_extract_register_as() {
    let input = Expr::Op(IrNode {
        opcode: 0xA7,
        payload: Payload::Zero,
    });
    let body = Expr::Op(IrNode {
        opcode: 0xC6,
        payload: Payload::ExtractRegisterAs {
            input: Box::new(input),
            reg_id: 4,
            tpe: SigmaType::SOption(Box::new(SigmaType::SLong)),
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_get_var() {
    let body = Expr::Op(IrNode {
        opcode: 0xE3,
        payload: Payload::GetVar {
            var_id: 7,
            tpe: SigmaType::SInt,
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_deserialize_context() {
    let body = Expr::Op(IrNode {
        opcode: 0xD4,
        payload: Payload::DeserializeContext {
            id: 1,
            tpe: SigmaType::SBoolean,
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_deserialize_register_no_default() {
    let body = Expr::Op(IrNode {
        opcode: 0xD5,
        payload: Payload::DeserializeRegister {
            reg_id: 4,
            tpe: SigmaType::SInt,
            default: None,
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_deserialize_register_with_default() {
    let default = Expr::Const {
        tpe: SigmaType::SInt,
        val: SigmaValue::Int(0),
    };
    let body = Expr::Op(IrNode {
        opcode: 0xD5,
        payload: Payload::DeserializeRegister {
            reg_id: 4,
            tpe: SigmaType::SInt,
            default: Some(Box::new(default)),
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_sigma_and() {
    let items = vec![
        Expr::Op(IrNode {
            opcode: 0x7F,
            payload: Payload::Zero,
        }),
        Expr::Op(IrNode {
            opcode: 0x80,
            payload: Payload::Zero,
        }),
    ];
    let body = Expr::Op(IrNode {
        opcode: 0xEA,
        payload: Payload::SigmaCollection { items },
    });
    roundtrip(&body, false);
}

/// 0xDF NoneValue is rejected at parse, matching Scala. `None`
/// values flow through the constant-encoding path (SOption with the
/// `0x00` discriminant), not through a dispatch arm.
#[test]
fn parse_rejects_none_value_0xdf() {
    let bytes = vec![0xDF];
    let mut r = VlqReader::new(&bytes);
    let err = parse_expr(&mut r, 0, 0).unwrap_err();
    match err {
        ReadError::InvalidData(msg) => {
            assert!(
                msg.contains("0xDF"),
                "expected unknown-opcode message, got {msg:?}"
            );
        }
        other => panic!("expected InvalidData, got {other:?}"),
    }
}

#[test]
fn roundtrip_by_index_no_default() {
    let input = Expr::Op(IrNode {
        opcode: 0xA4,
        payload: Payload::Zero,
    }); // Inputs
    let index = Expr::Const {
        tpe: SigmaType::SInt,
        val: SigmaValue::Int(0),
    };
    let body = Expr::Op(IrNode {
        opcode: 0xB2,
        payload: Payload::ByIndex {
            input: Box::new(input),
            index: Box::new(index),
            default: None,
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_by_index_with_default() {
    let input = Expr::Op(IrNode {
        opcode: 0xA4,
        payload: Payload::Zero,
    });
    let index = Expr::Const {
        tpe: SigmaType::SInt,
        val: SigmaValue::Int(0),
    };
    let default = Expr::Op(IrNode {
        opcode: 0xA7,
        payload: Payload::Zero,
    }); // Self
    let body = Expr::Op(IrNode {
        opcode: 0xB2,
        payload: Payload::ByIndex {
            input: Box::new(input),
            index: Box::new(index),
            default: Some(Box::new(default)),
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_four_arg_prove_dh() {
    // ProveDHTuple with 4 children (all GroupGenerator for simplicity)
    let gg = || {
        Expr::Op(IrNode {
            opcode: 0x82,
            payload: Payload::Zero,
        })
    };
    let body = Expr::Op(IrNode {
        opcode: 0xCE,
        payload: Payload::Four(
            Box::new(gg()),
            Box::new(gg()),
            Box::new(gg()),
            Box::new(gg()),
        ),
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_property_call() {
    let obj = Expr::Op(IrNode {
        opcode: 0xA7,
        payload: Payload::Zero,
    });
    let body = Expr::Op(IrNode {
        opcode: 0xDB, // PropertyCall
        payload: Payload::MethodCall {
            type_id: 99,
            method_id: 1,
            obj: Box::new(obj),
            args: vec![],
            type_args: vec![],
        },
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_nested_expression() {
    // BoolToSigmaProp(Eq(ExtractAmount(Self), Const(1000L)))
    let self_node = Expr::Op(IrNode {
        opcode: 0xA7,
        payload: Payload::Zero,
    });
    let extract_amount = Expr::Op(IrNode {
        opcode: 0xC1,
        payload: Payload::One(Box::new(self_node)),
    });
    let const_val = Expr::Const {
        tpe: SigmaType::SLong,
        val: SigmaValue::Long(1000),
    };
    let eq = Expr::Op(IrNode {
        opcode: 0x93,
        payload: Payload::Two(Box::new(extract_amount), Box::new(const_val)),
    });
    let body = Expr::Op(IrNode {
        opcode: 0xD1, // BoolToSigmaProp
        payload: Payload::One(Box::new(eq)),
    });
    roundtrip(&body, false);
}

#[test]
fn roundtrip_func_apply() {
    let func = Expr::Op(IrNode {
        opcode: 0xD9,
        payload: Payload::FuncValue {
            args: vec![(1, Some(SigmaType::SInt))],
            body: Box::new(Expr::Op(IrNode {
                opcode: 0x72,
                payload: Payload::ValUse { id: 1 },
            })),
        },
    });
    let arg = Expr::Const {
        tpe: SigmaType::SInt,
        val: SigmaValue::Int(10),
    };
    let body = Expr::Op(IrNode {
        opcode: 0xDA, // FuncApply
        payload: Payload::FuncApply {
            func: Box::new(func),
            args: vec![arg],
        },
    });
    roundtrip(&body, false);
}

// ----- error paths -----

#[test]
fn error_unknown_opcode() {
    let data = [0x75]; // reserved opcode
    let mut r = VlqReader::new(&data);
    let err = parse_body(&mut r, 0).unwrap_err();
    assert!(matches!(err, ReadError::InvalidData(_)));
}

#[test]
fn error_depth_limit() {
    // Build a deeply nested expression that exceeds MAX_EXPR_DEPTH.
    // SizeOf(SizeOf(SizeOf(...Height))) with depth = MAX_EXPR_DEPTH + 1.
    // We spawn a thread with an explicit large stack so that the guard
    // fires before the OS stack overflows.
    let result = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024) // 32 MiB — debug frames are large
        .spawn(|| {
            let mut data = vec![0xB1; MAX_EXPR_DEPTH + 1]; // SizeOf (One arg)
            data.push(0xA3); // Height (leaf)
            let mut r = VlqReader::new(&data);
            parse_body(&mut r, 0)
        })
        .unwrap()
        .join()
        .unwrap();
    let err = result.unwrap_err();
    assert!(
        matches!(err, ReadError::DepthLimitExceeded { max } if max == MAX_EXPR_DEPTH),
        "expected depth-limit error, got: {err:?}"
    );
}

/// Exact expression-depth boundary, pinned against the Scala reference node
/// (mainnet, sigma-state 6.0.2, GET /utils/ergoTreeToAddress): a no-size tree
/// body of 110 `SizeOf` ops reports `nested value deserialization call
/// depth(111) exceeds allowed maximum 110` (DeserializeCallDepthExceeded),
/// while 109 does NOT hit the depth limit. Our 0-based `depth >= MAX_EXPR_DEPTH`
/// must reject at exactly the same point: 110 SizeOf rejects, 109 parses.
#[test]
fn expr_depth_boundary_matches_scala_oracle() {
    let chain = |n: usize| {
        let mut data = vec![0xB1u8; n]; // n SizeOf (One arg)
        data.push(0xA3); // Height leaf
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(move || parse_body(&mut VlqReader::new(&data), 0))
            .unwrap()
            .join()
            .unwrap()
    };
    // 110 SizeOf -> Scala depth(111) > 110 -> reject; we reject identically.
    assert!(matches!(
        chain(MAX_EXPR_DEPTH).unwrap_err(),
        ReadError::DepthLimitExceeded { .. }
    ));
    // 109 SizeOf -> Scala does NOT hit the depth limit; we must parse it.
    assert!(chain(MAX_EXPR_DEPTH - 1).is_ok());
}

/// 0xDE SomeValue is rejected at parse, matching Scala. The opcode
/// has no Scala serializer registration, so accepting it would be
/// an accept-more divergence — this test asserts the rejection.
#[test]
fn parse_rejects_some_value_0xde() {
    let bytes = vec![0xDE];
    let mut r = VlqReader::new(&bytes);
    let err = parse_expr(&mut r, 0, 0).unwrap_err();
    match err {
        ReadError::InvalidData(msg) => {
            assert!(
                msg.contains("0xDE"),
                "expected unknown-opcode message, got {msg:?}"
            );
        }
        other => panic!("expected InvalidData, got {other:?}"),
    }
}

/// 0xB8 FlatMapCollection — same rejection rationale.
#[test]
fn parse_rejects_flat_map_0xb8() {
    let bytes = vec![0xB8];
    let mut r = VlqReader::new(&bytes);
    let err = parse_expr(&mut r, 0, 0).unwrap_err();
    match err {
        ReadError::InvalidData(msg) => {
            assert!(
                msg.contains("0xB8"),
                "expected unknown-opcode message, got {msg:?}"
            );
        }
        other => panic!("expected InvalidData, got {other:?}"),
    }
}

/// Closed-divergence rejections: 0x81, 0x87-0x8B, 0xDF. All seven
/// had parser arms that accepted bytes Scala rejects via
/// CheckValidOpCode; this test pins that the rejections stay closed.
#[test]
fn parse_rejects_closed_accept_more_opcodes() {
    for &opcode in &[0x81u8, 0x87u8, 0x88u8, 0x89u8, 0x8A, 0x8B, 0xDF] {
        let bytes = vec![opcode];
        let mut r = VlqReader::new(&bytes);
        let err = parse_expr(&mut r, 0, 0).unwrap_err();
        match err {
            ReadError::InvalidData(msg) => {
                let tag = format!("0x{opcode:02X}");
                assert!(
                    msg.contains(&tag),
                    "0x{opcode:02X}: expected rejection with opcode tag, got {msg:?}"
                );
            }
            other => panic!("0x{opcode:02X} expected InvalidData, got {other:?}"),
        }
    }
}

// ----- oracle parity (encoding-scheme alignment) -----
//
// Each test below picks values that VLQ-encode DIFFERENTLY from
// a raw single byte — i.e. above the 0..127 alias band. For
// values < 128, both encodings produce the same byte and a
// roundtrip would pass either way. The tests assert the exact
// single-byte layout to catch any regression that re-introduces
// VLQ.

/// Scala-parity opcode audit. Asserts the symmetric difference
/// between our parser's accepted-opcode set and Scala's
/// `ValueSerializer.serializers` registered set is exactly the
/// known accept-more cases (or empty after they're all closed).
/// Source: sigmastate-interpreter/data/shared/src/main/scala/sigma/serialization/ValueSerializer.scala:42-151.
/// Failure means a new opcode appeared on either side without the
/// audit being updated.
#[test]
fn parser_parity_audit_against_scala_registered_set() {
    // Scala-registered opcodes — every entry in
    // ValueSerializer.scala:42-151 with its lookup byte.
    // Constants (≤ 0x70) are handled by ConstantSerializer, not
    // by the dispatch table — excluded from this set.
    let scala_registered: std::collections::BTreeSet<u8> = [
        0x71, 0x72, 0x73, 0x74, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x82, 0x83, 0x85, 0x86,
        0x8C, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C,
        0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
        0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB,
        0xDC, 0xDD, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xFE, 0xFF,
    ]
    .into_iter()
    .collect();

    // Our parser-accepted opcodes — derived by polling opcode_pattern.
    let parser_accepted: std::collections::BTreeSet<u8> = (0x71u8..=0xFFu8)
        .filter(|&b| opcode_pattern(b).is_some())
        .collect();

    // Known accept-more divergences — currently empty. If this set
    // grows, a new parser arm was added that Scala's
    // ValueSerializer.serializers registry does not include — audit
    // before merging.
    let known_accept_more: std::collections::BTreeSet<u8> = std::collections::BTreeSet::new();

    let parser_only: std::collections::BTreeSet<u8> = parser_accepted
        .difference(&scala_registered)
        .copied()
        .collect();
    let scala_only: std::collections::BTreeSet<u8> = scala_registered
        .difference(&parser_accepted)
        .copied()
        .collect();

    // parser_only must be exactly the known set. New entries either
    // mean a real new divergence (file-level fix needed) or that this
    // audit table is stale (update both sides together).
    assert_eq!(
        parser_only, known_accept_more,
        "parser-accepts-but-Scala-doesn't set drifted; left=parser_only, right=known_accept_more"
    );

    // scala_only should be empty. Stricter-than-Scala parsing is
    // technically Scala-conformant if Scala would also reject (e.g.,
    // 0xB7 TreeLookup: Scala accepts deserialization but rejects
    // execution via notSupportedError; our parser rejects upfront,
    // same end state). But ANY entry here means we may reject a tree
    // Scala accepts; warrants explicit review.
    assert!(
        scala_only.is_empty(),
        "parser rejects opcodes Scala accepts: {:?}",
        scala_only
    );
}

#[test]
fn taggedvar_negative_byte_id_emits_one_byte_not_5_byte_vlq() {
    // TaggedVar id is one signed byte on the wire (Scala
    // TaggedVariableSerializer.scala:16). For id = 0xFFFF_FFFF
    // (signed Byte = -1) the emitted form is `put_u8(0xFF)` — a single
    // byte, not a 5-byte VLQ-u32. Pin the total payload size so a
    // regression to VLQ-u32 fails loud.
    let body = Expr::Op(IrNode {
        opcode: 0x71,
        payload: Payload::TaggedVar {
            id: 0xFFFF_FFFF, // signed Byte = -1
            tpe: None,
        },
    });
    let mut w = VlqWriter::new();
    write_body(&mut w, &body, false).unwrap();
    let bytes = w.result();
    assert_eq!(
        bytes.len(),
        2,
        "TaggedVar wire form must be 2 bytes (opcode + 1-byte id); a 5-byte VLQ regression would yield 6: got {bytes:?}"
    );
    assert_eq!(bytes[1], 0xFF, "low byte of sign-extended id must be 0xFF");
    roundtrip(&body, false);
}

#[test]
fn taggedvar_signed_byte_min_id_round_trips() {
    // Scala Byte = -128 → id = 0xFFFF_FF80 in our u32 representation.
    let body = Expr::Op(IrNode {
        opcode: 0x71,
        payload: Payload::TaggedVar {
            id: 0xFFFF_FF80,
            tpe: None,
        },
    });
    let mut w = VlqWriter::new();
    write_body(&mut w, &body, false).unwrap();
    let bytes = w.result();
    assert_eq!(bytes.len(), 2);
    assert_eq!(bytes[1], 0x80);
    roundtrip(&body, false);
}

#[test]
#[should_panic(expected = "TaggedVar id 0x80 outside Scala signed-Byte range")]
fn taggedvar_id_0x80_unsigned_panics_on_write() {
    // 0x80 (128 unsigned, NOT sign-extended) is an invalid
    // in-memory id. Sign-extended -128 would be 0xFFFF_FF80;
    // bare 0x80 indicates a programmer bug constructing the
    // payload directly.
    let body = Expr::Op(IrNode {
        opcode: 0x71,
        payload: Payload::TaggedVar {
            id: 0x80,
            tpe: None,
        },
    });
    let mut w = VlqWriter::new();
    let _ = write_body(&mut w, &body, false);
}

#[test]
fn tuple_count_at_128_writes_single_byte_then_reader_rejects_per_scala() {
    // 128 items: VLQ would emit `0x80 0x01`; raw u8 is `0x80`.
    // The writer emits one byte (mirrors Scala `putUByte`).
    // The reader rejects (mirrors Scala `getByte` + `safeNewArray`
    // which throws on the resulting negative size = -128). This
    // write/read asymmetry is exact Scala parity — Scala
    // round-trips only counts 0..=127.
    let items: Vec<Expr> = (0..128)
        .map(|i| Expr::Const {
            tpe: crate::sigma_type::SigmaType::SInt,
            val: crate::sigma_value::SigmaValue::Int(i),
        })
        .collect();
    let body = Expr::Op(IrNode {
        opcode: 0x86,
        payload: Payload::Tuple { items },
    });
    let mut w = VlqWriter::new();
    write_body(&mut w, &body, false).unwrap();
    let bytes = w.result();
    // Byte 0 = opcode, byte 1 = count = 0x80 (raw, NOT VLQ).
    assert_eq!(bytes[1], 0x80, "tuple count 128 must encode as 0x80 raw");
    // Reader rejects this byte as negative signed Byte.
    let mut r = VlqReader::new(&bytes);
    let parsed = parse_body(&mut r, 0);
    assert!(
        matches!(&parsed, Err(ReadError::InvalidData(msg)) if msg.contains("negative")),
        "Scala safeNewArray rejection parity broken: got {parsed:?}"
    );
}

#[test]
fn tuple_count_at_127_round_trips_as_single_byte() {
    // 127 items: maximum tuple count Scala accepts (signed Byte
    // = 0x7F). VLQ would also be 0x7F (1 byte) — but we still
    // pin the byte position to prove count is the second byte
    // of the body, not part of a multi-byte VLQ.
    let items: Vec<Expr> = (0..127)
        .map(|i| Expr::Const {
            tpe: crate::sigma_type::SigmaType::SInt,
            val: crate::sigma_value::SigmaValue::Int(i),
        })
        .collect();
    let body = Expr::Op(IrNode {
        opcode: 0x86,
        payload: Payload::Tuple { items },
    });
    let mut w = VlqWriter::new();
    write_body(&mut w, &body, false).unwrap();
    let bytes = w.result();
    assert_eq!(bytes[1], 0x7F);
    roundtrip(&body, false);
}

#[test]
#[should_panic(expected = "Tuple item count too large for Scala wire format")]
fn tuple_count_above_255_panics_on_write() {
    // 256 items would overflow the single-byte count. Programmer
    // bug; assert catches it.
    let items: Vec<Expr> = (0..256)
        .map(|i| Expr::Const {
            tpe: crate::sigma_type::SigmaType::SInt,
            val: crate::sigma_value::SigmaValue::Int(i),
        })
        .collect();
    let body = Expr::Op(IrNode {
        opcode: 0x86,
        payload: Payload::Tuple { items },
    });
    let mut w = VlqWriter::new();
    let _ = write_body(&mut w, &body, false);
}

// ----- oracle parity -----

/// v6 / EIP-50 MethodCall wire format must round-trip the explicit
/// type-args block for methods whose Scala `SMethod` sets
/// `hasExplicitTypeArgs`. Pins `SBox.getReg[Int](R4)` — the most
/// common production case — under tree_version=3. The reserialized
/// bytes must be byte-identical (same wire layout = same merkle root
/// = same blockchain digest).
#[test]
fn methodcall_box_getreg_v6_roundtrips_with_explicit_type_arg() {
    let obj = Expr::Op(IrNode {
        opcode: 0xA7,
        payload: Payload::Zero,
    });
    let reg_id_arg = Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    });
    let body = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 99,
            method_id: 19,
            obj: Box::new(obj),
            args: vec![reg_id_arg],
            type_args: vec![SigmaType::SInt],
        },
    });
    roundtrip_v(&body, false, 3);
}

/// Companion guard: the V5+ `getReg` (id 7, distinct from the v6
/// id-19 slot) carries NO explicit type arg in any tree version, so a
/// v5 tree (tree_version=0) using it must NOT consume a trailing type
/// byte. This pins that the legacy slot stays out of the wire-count
/// list; the version discriminator lives on id 19, exercised below.
#[test]
fn methodcall_box_getreg_v5_roundtrips_without_explicit_type_arg() {
    let obj = Expr::Op(IrNode {
        opcode: 0xA7,
        payload: Payload::Zero,
    });
    let reg_id_arg = Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    });
    let body = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 99,
            method_id: 7,
            obj: Box::new(obj),
            args: vec![reg_id_arg],
            type_args: vec![],
        },
    });
    roundtrip_v(&body, false, 0);
}

/// v6-shaped MethodCall (with one explicit type arg) must round-trip
/// byte-identically even when parsed with `tree_version=0`. The Scala
/// 6.0 compiler emits v6 method calls inside v0-header trees (the
/// tree-header version is a wire-format selector, not a script-version
/// selector), so the parser must read `hasExplicitTypeArgs` based on
/// `(type_id, method_id)` alone. Soft-fork rejection happens at
/// evaluation time via `activated_script_version`, not at parse time.
///
/// This test previously asserted the *opposite* (asserting that v0
/// parse should NOT round-trip a v6-shaped MethodCall, guarding a
/// version gate). That gate was wrong: it caused real 6.0-compiled
/// trees with header byte 0x10 to mis-align right after the value
/// args, mis-interpreting the trailing type byte as the next
/// expression's opcode/type-code. Removed when the gate was lifted in
/// `method_explicit_type_args_count`.
#[test]
fn methodcall_box_getreg_v6_shape_roundtrips_in_v0_tree() {
    let body = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 99,
            method_id: 19,
            obj: Box::new(Expr::Op(IrNode {
                opcode: 0xA7,
                payload: Payload::Zero,
            })),
            args: vec![Expr::Op(IrNode {
                opcode: 0xA3,
                payload: Payload::Zero,
            })],
            type_args: vec![SigmaType::SInt],
        },
    });
    // Parse-version 0: must still consume the explicit type byte for
    // (99, 19) because the method id is what governs the wire shape.
    roundtrip_v(&body, false, 0);
}

/// Regression surface for the v5/v6 `getReg` split: the v5 slot (id 7)
/// must consume NO explicit type byte even on a v6 tree
/// (tree_version=3), the very version where the id-19 slot DOES read
/// one. Pins that id 7 stayed out of the wire-count list once EIP-50
/// is active, not merely on legacy v5 trees.
#[test]
fn methodcall_box_getreg_v5_id_on_v6_tree_roundtrips_without_explicit_type_arg() {
    let obj = Expr::Op(IrNode {
        opcode: 0xA7,
        payload: Payload::Zero,
    });
    let reg_id_arg = Expr::Op(IrNode {
        opcode: 0xA3,
        payload: Payload::Zero,
    });
    let body = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 99,
            method_id: 7,
            obj: Box::new(obj),
            args: vec![reg_id_arg],
            type_args: vec![],
        },
    });
    roundtrip_v(&body, false, 3);
}

/// EIP-50 v6 `SGlobal.some[T]` (MethodCall 106, 9) is a 0xDC MethodCall
/// with one value arg AND one explicit `[T]` type byte. Scala registers
/// `Seq(tT)` even though T is inferable from the arg, so the byte IS
/// serialized; match the table, not an inference heuristic. The type
/// byte follows the args on the wire and must round-trip byte-identically.
#[test]
fn methodcall_global_some_v6_roundtrips_with_explicit_type_arg() {
    let obj = Expr::Op(IrNode {
        opcode: 0xDD, // Global (SGlobal receiver)
        payload: Payload::Zero,
    });
    let value = Expr::Const {
        tpe: SigmaType::SInt,
        val: SigmaValue::Int(42),
    };
    let body = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 9,
            obj: Box::new(obj),
            args: vec![value],
            type_args: vec![SigmaType::SInt],
        },
    });
    roundtrip_v(&body, false, 3);
}

/// EIP-50 v6 `SGlobal.none[T]` (PropertyCall 106, 10) is the case the
/// old PropertyCall parser mishandled: a 0xDB property call (zero value
/// args) that NONETHELESS carries an explicit `[T]` type byte right
/// after `obj`. Scala's `PropertyCallSerializer` writes `explicitTypeArgs`
/// whenever `hasExplicitTypeArgs`, with no args list in between. The byte
/// must round-trip; `roundtrip_v`'s `r.is_empty()` catches a missed read.
#[test]
fn propertycall_global_none_v6_roundtrips_with_explicit_type_arg() {
    let obj = Expr::Op(IrNode {
        opcode: 0xDD, // Global (SGlobal receiver)
        payload: Payload::Zero,
    });
    let body = Expr::Op(IrNode {
        opcode: 0xDB, // PropertyCall
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 10,
            obj: Box::new(obj),
            args: vec![],
            type_args: vec![SigmaType::SInt],
        },
    });
    roundtrip_v(&body, false, 3);
}

/// `SGlobal.none[T]` PropertyCall carries its explicit `[T]` type
/// byte in any tree version. The Scala 6.0 compiler emits v6
/// PropertyCalls in v0-header trees (header byte 0x10), so the
/// explicit-type-arg read must be governed by `(type_id, method_id)`
/// alone, not by `tree_version`. Previously gated on `tree_version >=
/// 3`; the gate caused real 6.0-compiled trees to mis-align after the
/// PropertyCall body. See `method_explicit_type_args_count` doc for
/// the design correction.
#[test]
fn propertycall_global_none_v6_roundtrips_in_v0_tree() {
    let obj = Expr::Op(IrNode {
        opcode: 0xDD, // Global (SGlobal receiver)
        payload: Payload::Zero,
    });
    let body = Expr::Op(IrNode {
        opcode: 0xDB, // PropertyCall
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 10,
            obj: Box::new(obj),
            args: vec![],
            type_args: vec![SigmaType::SInt], // [Int] type arg now always present
        },
    });
    roundtrip_v(&body, false, 0);
}

/// Byte-level golden for `SGlobal.some[Int]` on a v3 tree. Symmetric
/// roundtrips cannot catch a *mirrored* parse/write bug (both sides
/// agreeing on a wrong layout); this pins the exact MethodCall (0xDC)
/// wire bytes against the v6.0.2 serializer layout: opcode, typeId=106,
/// methodId=9, obj=Global, u32 arg-count=1, the arg, then the explicit
/// `[Int]` type byte (SInt=0x04) LAST. (Literals are the documented
/// layout, not a self-oracle of the writer; a true Scala-extracted
/// vector is deferred — sigma-rust has no v6 SGlobal methods.)
#[test]
fn methodcall_global_some_v6_exact_wire_bytes() {
    use ergo_primitives::writer::VlqWriter;
    let body = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 9,
            // Global receiver, then a Height (SInt) value arg.
            obj: Box::new(Expr::Op(IrNode {
                opcode: 0xDD,
                payload: Payload::Zero,
            })),
            args: vec![Expr::Op(IrNode {
                opcode: 0xA3,
                payload: Payload::Zero,
            })],
            type_args: vec![SigmaType::SInt],
        },
    });
    let mut w = VlqWriter::new();
    write_body(&mut w, &body, false).unwrap();
    assert_eq!(
        w.result(),
        vec![0xDC, 106, 9, 0xDD, 0x01, 0xA3, 0x04],
        "some[Int] wire layout: 0xDC,typeId,methodId,obj,argCount=1,arg,SInt",
    );
}

/// Byte-level golden for `SGlobal.none[Int]` on a v3 tree. Pins the
/// PropertyCall (0xDB) layout: opcode, typeId=106, methodId=10, obj,
/// then the explicit `[Int]` type byte (SInt=0x04) directly after obj
/// with NO arg-count and NO args. Catches a mirrored parse/write bug
/// and proves the PropertyCall path emits the type byte in the v6.0.2
/// position.
#[test]
fn propertycall_global_none_v6_exact_wire_bytes() {
    use ergo_primitives::writer::VlqWriter;
    let body = Expr::Op(IrNode {
        opcode: 0xDB,
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 10,
            obj: Box::new(Expr::Op(IrNode {
                opcode: 0xDD,
                payload: Payload::Zero,
            })),
            args: vec![],
            type_args: vec![SigmaType::SInt],
        },
    });
    let mut w = VlqWriter::new();
    write_body(&mut w, &body, false).unwrap();
    assert_eq!(
        w.result(),
        vec![0xDB, 106, 10, 0xDD, 0x04],
        "none[Int] wire layout: 0xDB,typeId,methodId,obj,SInt (no args)",
    );
}

/// Negative wire guard: a v3 `SGlobal.none` PropertyCall whose trailing
/// explicit type byte is truncated must FAIL to parse, not silently
/// succeed by skipping the read. This is exactly the desync the old
/// `type_args = vec![]` PropertyCall parser would have hidden.
#[test]
fn propertycall_global_none_v6_truncated_type_byte_fails_parse() {
    use ergo_primitives::reader::VlqReader;
    // Full v6 `none[Int]` bytes minus the trailing SInt type byte.
    let full = [0xDB, 106, 10, 0xDD, 0x04];
    let truncated = &full[..full.len() - 1];
    let mut r = VlqReader::new(truncated);
    assert!(
        parse_body(&mut r, 3).is_err(),
        "v3 none missing its explicit type byte must fail to parse",
    );
}

// ----- v3-only method gate (is_v3_only_method / find_v3_only_method) -----

#[test]
fn is_v3_only_method_table_spot_checks() {
    // v6-only — a pre-v3 tree carrying these rejects at deserialize
    // (methodById -> _v5MethodsMap misses the id).
    assert!(is_v3_only_method(106, 10)); // SGlobal.none
    assert!(is_v3_only_method(106, 3)); // SGlobal.serialize
    assert!(is_v3_only_method(99, 19)); // SBox.getReg[T]
    assert!(is_v3_only_method(101, 12)); // SContext.getVarFromInput
    assert!(is_v3_only_method(9, 1)); // SUnsignedBigInt (v3-only type)
    assert!(is_v3_only_method(3, 1)); // SInt numeric on the concrete type id
    assert!(is_v3_only_method(104, 16)); // SHeader.checkPow
                                         // pre-v3-legal — must NOT be flagged.
    assert!(!is_v3_only_method(106, 1)); // SGlobal.groupGenerator
    assert!(!is_v3_only_method(106, 2)); // SGlobal.xor
    assert!(!is_v3_only_method(99, 7)); // SBox.getRegV5
    assert!(!is_v3_only_method(101, 11)); // SContext.getVar
    assert!(!is_v3_only_method(104, 1)); // SHeader.version (pre-v3 accessor)
    assert!(!is_v3_only_method(100, 1)); // SAvlTree.digest
    assert!(!is_v3_only_method(12, 26)); // SCollection.indexOf (pre-v3)
}

// ----- oracle parity -----

/// EXHAUSTIVE: `is_v5_method` / `is_v6_method` must match Scala's `SMethod.fromIds`
/// for EVERY one of the 65 536 single-byte `(typeId, methodId)` pairs. The expected
/// column is the external oracle (sigma-state 6.0.2), checked in at
/// `test-vectors/scala/sigma/method_registry_v5_v6.txt`. Mis-encoding a single arm
/// is a consensus divergence (reject-valid if a real method is flagged unresolved,
/// accept-invalid if an unresolved id is treated as known), so the whole space is
/// pinned — not spot-checked.
#[test]
fn method_registry_predicates_match_scala_oracle() {
    let vectors = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-vectors/scala/sigma/method_registry_v5_v6.txt"
    ))
    .expect("registry oracle vector present");

    // (typeId, methodId) -> (resolves_v5, resolves_v6); absent pair => (false, false).
    let mut oracle = std::collections::HashMap::new();
    for line in vectors.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(cols.len(), 4, "malformed registry line: {line:?}");
        let t: u8 = cols[0].parse().unwrap();
        let m: u8 = cols[1].parse().unwrap();
        oracle.insert((t, m), (cols[2] == "1", cols[3] == "1"));
    }
    assert!(!oracle.is_empty(), "oracle vector parsed to zero pairs");

    for t in 0u8..=255 {
        for m in 0u8..=255 {
            let (exp_v5, exp_v6) = oracle.get(&(t, m)).copied().unwrap_or((false, false));
            assert_eq!(is_v5_method(t, m), exp_v5, "is_v5_method({t}, {m})");
            assert_eq!(is_v6_method(t, m), exp_v6, "is_v6_method({t}, {m})");

            // v5 ⊆ v6: resolving at v5 implies resolving at v6 (oracle-verified).
            assert!(
                !is_v5_method(t, m) || is_v6_method(t, m),
                "({t}, {m}) resolves at v5 but not v6 — breaks the subset invariant"
            );
            // The v6-only set is exactly "resolves at v6, not at v5".
            assert_eq!(
                is_v3_only_method(t, m),
                is_v6_method(t, m) && !is_v5_method(t, m),
                "is_v3_only_method disagrees with is_v6 ∧ ¬is_v5 at ({t}, {m})"
            );
            // is_known_method routes by the tree-header version split (0/1/2 → v5, 3 → v6).
            assert_eq!(
                is_known_method(t, m, 0),
                exp_v5,
                "is_known_method v0 ({t}, {m})"
            );
            assert_eq!(
                is_known_method(t, m, 2),
                exp_v5,
                "is_known_method v2 ({t}, {m})"
            );
            assert_eq!(
                is_known_method(t, m, 3),
                exp_v6,
                "is_known_method v3 ({t}, {m})"
            );
        }
    }
}

/// `find_unresolved_v5_method` flags both a v6-only method AND a genuinely unknown
/// id, but never a pre-v3-legal one — the superset relationship the box-deserialize
/// sizeless gate relies on.
#[test]
fn find_unresolved_v5_method_flags_v6_only_and_unknown() {
    let global = || {
        Expr::Op(IrNode {
            opcode: 0xDD,
            payload: Payload::Zero,
        })
    };
    let prop = |type_id, method_id| {
        Expr::Op(IrNode {
            opcode: 0xDB,
            payload: Payload::MethodCall {
                type_id,
                method_id,
                obj: Box::new(global()),
                args: vec![],
                type_args: vec![],
            },
        })
    };
    // v6-only (SGlobal.none, 106/10) — unresolved at v5.
    assert_eq!(find_unresolved_v5_method(&prop(106, 10)), Some((106, 10)));
    // genuinely unknown id (SGlobal has no method 42) — unresolved at v5,
    // and previously MISSED by the v6-only-specific walk.
    assert_eq!(find_unresolved_v5_method(&prop(106, 42)), Some((106, 42)));
    assert!(!is_v3_only_method(106, 42)); // not v6-only — the gap this closes
                                          // method on a type with no methods at all (SBoolean, type 1).
    assert_eq!(find_unresolved_v5_method(&prop(1, 1)), Some((1, 1)));
    // pre-v3-legal (SGlobal.groupGenerator, 106/1) — NOT flagged.
    assert_eq!(find_unresolved_v5_method(&prop(106, 1)), None);
}

#[test]
fn find_v3_only_method_walks_dead_branch_and_skips_clean_tree() {
    let global = || {
        Expr::Op(IrNode {
            opcode: 0xDD,
            payload: Payload::Zero,
        })
    };
    let property_call = |method_id| {
        Expr::Op(IrNode {
            opcode: 0xDB,
            payload: Payload::MethodCall {
                type_id: 106,
                method_id,
                obj: Box::new(global()),
                args: vec![],
                type_args: vec![],
            },
        })
    };
    let tru = || {
        Expr::Op(IrNode {
            opcode: 0x7F,
            payload: Payload::Zero,
        })
    };
    // `if (true) true else Global.none` — the v6-only method is in the DEAD
    // else-branch, yet the walk finds it (Scala deserializes the whole AST).
    let if_dead = Expr::Op(IrNode {
        opcode: 0x95,
        payload: Payload::Three(
            Box::new(tru()),
            Box::new(tru()),
            Box::new(property_call(10)), // SGlobal.none
        ),
    });
    assert_eq!(find_v3_only_method(&if_dead), Some((106, 10)));

    // A clean tree (groupGenerator is pre-v3-legal) returns None.
    let clean = Expr::Op(IrNode {
        opcode: 0x95,
        payload: Payload::Three(
            Box::new(tru()),
            Box::new(tru()),
            Box::new(property_call(1)), // SGlobal.groupGenerator
        ),
    });
    assert_eq!(find_v3_only_method(&clean), None);
}

// ----- constant segregation (write-time sink) -----

// Segregating an expression whose ONLY constants are a compact Relation2
// bool-pair must leave the sink EMPTY: the `0x85` BoolCollection compaction
// bypasses the `Expr::Const` arm the sink lives in, so those two booleans are
// written inline (as `85 <packed>`) and never reach the store. Oracle-derived:
// the segregated `true && (1 == 1)` tree is `1000d1ed8503` — a segregated
// header (0x10) with a ZERO-entry constants table; the body here is the inner
// `BinAnd(true, true)` = `ed 85 03` (0xED BinAnd, 0x85 marker, 0x03 packed
// bits = both true). See `dev-docs/.../recon-segregation.md` §3.
#[test]
fn segregate_relation2_bool_pair_stays_inline_zero_constants() {
    let bin_and = Expr::Op(IrNode {
        opcode: 0xED, // BinAnd (a Relation2-class opcode)
        payload: Payload::Two(
            Box::new(Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            }),
            Box::new(Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            }),
        ),
    });

    let mut sink = ConstantSink::new();
    let mut w = VlqWriter::new();
    write_expr_segregating(&mut w, &bin_and, &mut sink).unwrap();
    let bytes = w.result();

    // Compact form emitted, NO placeholders, NO extracted constants.
    assert_eq!(hex::encode(&bytes), "ed8503", "compact bool-pair body");
    assert!(
        sink.into_constants().is_empty(),
        "the compacted bool pair must NOT segregate"
    );
}

// A non-bool constant DOES segregate: it is replaced by a `ConstPlaceholder`
// (opcode 0x73 + index) and appended to the sink. Slot order = first-write
// (pre-order) order, append-only with NO dedup — two equal constants at
// distinct positions take distinct slots.
#[test]
fn segregate_extracts_constants_in_first_write_order_no_dedup() {
    // `Plus(100, 100)` — a non-Relation2 op over two structurally-equal `Int`
    // constants; each segregates to its OWN slot (append-only, NO dedup).
    let plus = Expr::Op(IrNode {
        opcode: 0x9A, // ArithOp Plus (ArgPattern::Two, NOT Relation2)
        payload: Payload::Two(
            Box::new(Expr::Const {
                tpe: SigmaType::SInt,
                val: SigmaValue::Int(100),
            }),
            Box::new(Expr::Const {
                tpe: SigmaType::SInt,
                val: SigmaValue::Int(100),
            }),
        ),
    });

    let mut sink = ConstantSink::new();
    let mut w = VlqWriter::new();
    write_expr_segregating(&mut w, &plus, &mut sink).unwrap();
    let bytes = w.result();

    // Two distinct slots (no dedup); both are (SInt, 100).
    let constants = sink.into_constants();
    assert_eq!(constants.len(), 2, "two slots, no dedup");
    assert_eq!(constants[0], (SigmaType::SInt, SigmaValue::Int(100)));
    assert_eq!(constants[1], (SigmaType::SInt, SigmaValue::Int(100)));

    // Re-reading the segregated bytes materializes ConstPlaceholder nodes in
    // place of the constants (Scala's withSegregation step-6 re-read shape),
    // in first-write slot order.
    let mut r = VlqReader::new(&bytes);
    let reread = parse_expr(&mut r, 0, 0).unwrap();
    assert!(r.is_empty());
    let Expr::Op(IrNode {
        opcode: 0x9A,
        payload: Payload::Two(a, b),
    }) = &reread
    else {
        panic!("expected Plus root, got {reread:?}");
    };
    let ph = |e: &Expr| match e {
        Expr::Op(IrNode {
            payload: Payload::ConstPlaceholder { index },
            ..
        }) => Some(*index),
        _ => None,
    };
    assert_eq!(ph(a), Some(0), "first constant → ConstPlaceholder(0)");
    assert_eq!(ph(b), Some(1), "second constant → ConstPlaceholder(1)");
}
