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
