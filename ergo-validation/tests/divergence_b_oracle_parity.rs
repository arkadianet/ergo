//! Oracle-parity for the v6-method / group-element ordering surface
//! (SANTA "divergence B"). For a size-delimited pre-v3 tree carrying a v6/EIP-50
//! method, Scala wraps it as `UnparsedErgoTree` (the method is absent from
//! `_v5MethodsMap` → `ValidationException`, caught under has_size) and
//! curve-checks ONLY the group elements it deserialized BEFORE the throw — the
//! method's receiver/args and anything earlier. Points after are never reached.
//!
//! The node parses version-independently, so it records a sideband checkpoint at
//! the v6-method resolution point and, at the ErgoTree layer, wraps + forwards
//! exactly that GE prefix. Each `scala` outcome below was blessed against the
//! Scala oracle (sigma-state 6.0.2 `deserializeErgoTree`, activated version 3);
//! `PARSED`/`UNPARSED` ⇒ the box is ACCEPTED at creation, `THROW` ⇒ REJECTED.
//! Rust must agree on that accept/reject (the consensus-relevant axis).

use ergo_primitives::group_element::GroupElement;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_tree::{read_ergo_tree, write_ergo_tree, ErgoTree};
use ergo_ser::opcode::{Body, Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use ergo_sigma::evaluator::validate_group_element;

fn on_curve() -> [u8; 33] {
    let mut b = [0u8; 33];
    let g =
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
    b.copy_from_slice(&g);
    b
}
fn off_curve() -> [u8; 33] {
    let mut b = [0xffu8; 33];
    b[0] = 0x02;
    b
}
fn ge_const(bytes: [u8; 33]) -> Expr {
    Expr::Const {
        tpe: SigmaType::SGroupElement,
        val: SigmaValue::GroupElement(GroupElement::from_bytes(bytes)),
    }
}
fn sigma_true() -> Expr {
    Expr::Const {
        tpe: SigmaType::SSigmaProp,
        val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
    }
}
fn leaf(op: u8) -> Expr {
    Expr::Op(IrNode {
        opcode: op,
        payload: Payload::Zero,
    })
}
/// `SBox.getReg[Int]` (99/19) — a v6-only method; `obj`/`arg` let us inject a
/// group element into the method's own receiver/args.
fn v6_method(obj: Expr, arg: Expr) -> Expr {
    Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 99,
            method_id: 19,
            obj: Box::new(obj),
            args: vec![arg],
            type_args: vec![SigmaType::SInt],
        },
    })
}
/// `SGlobal.none[Int]` (106/10) — a v6-only PropertyCall (zero value args).
fn global_none() -> Expr {
    Expr::Op(IrNode {
        opcode: 0xDB, // PropertyCall
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 10,
            obj: Box::new(leaf(0xDD)), // Global
            args: vec![],
            type_args: vec![SigmaType::SInt],
        },
    })
}
fn plus(a: Expr, b: Expr) -> Expr {
    Expr::Op(IrNode {
        opcode: 0x9A,
        payload: Payload::Two(Box::new(a), Box::new(b)),
    })
}
fn placeholder(i: u32) -> Expr {
    Expr::Op(IrNode {
        opcode: 0x73,
        payload: Payload::ConstPlaceholder { index: i },
    })
}
fn tree(version: u8, cseg: bool, constants: Vec<(SigmaType, SigmaValue)>, body: Body) -> ErgoTree {
    ErgoTree {
        version,
        has_size: true,
        constant_segregation: cseg,
        constants,
        body,
    }
}

/// Mirror Scala's box-creation accept/reject: deserialize the tree, then
/// curve-check every group element the parse forwarded. `true` = accepted.
fn rust_accepts(t: &ErgoTree) -> bool {
    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, t).expect("serialize");
    let bytes = w.result();
    let mut r = VlqReader::new(&bytes);
    match read_ergo_tree(&mut r) {
        Err(_) => false,
        Ok(_) => r
            .take_group_elements()
            .iter()
            .all(|ge| validate_group_element(*ge).is_ok()),
    }
}

/// Does the parsed tree wrap as `UnparsedErgoTree`?
fn rust_wraps(t: &ErgoTree) -> bool {
    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, t).expect("serialize");
    let bytes = w.result();
    let mut r = VlqReader::new(&bytes);
    matches!(
        read_ergo_tree(&mut r).map(|d| d.body),
        Ok(Expr::Unparsed(_))
    )
}

#[test]
fn divergence_b_oracle_parity() {
    // (name, tree, scala-oracle label, accepted-at-creation)
    let cases: Vec<(&str, ErgoTree, &str, bool)> = vec![
        (
            "valid_p2pk",
            tree(0, false, vec![], sigma_true()),
            "PARSED",
            true,
        ),
        // off-curve GE, no v6 method, reached before the (non-SigmaProp) root check.
        (
            "offcurve_ge_no_v6",
            tree(0, false, vec![], plus(ge_const(off_curve()), sigma_true())),
            "THROW",
            false,
        ),
        (
            "v6_no_ge",
            tree(0, false, vec![], v6_method(leaf(0xA7), leaf(0xA3))),
            "UNPARSED",
            true,
        ),
        // *** divergence B: off-curve GE AFTER the v6 method — Scala wraps before
        // reaching it, so the box is accepted; we must drop the trailing GE. ***
        (
            "v6_then_offcurve_AFTER",
            tree(
                0,
                false,
                vec![],
                plus(v6_method(leaf(0xA7), leaf(0xA3)), ge_const(off_curve())),
            ),
            "UNPARSED",
            true,
        ),
        // off-curve GE BEFORE the method — Scala decodes it first and throws; the
        // GE is within the checkpoint prefix, so we still forward+reject it.
        (
            "offcurve_BEFORE_v6",
            tree(
                0,
                false,
                vec![],
                plus(ge_const(off_curve()), v6_method(leaf(0xA7), leaf(0xA3))),
            ),
            "THROW",
            false,
        ),
        (
            "v6_then_oncurve_AFTER",
            tree(
                0,
                false,
                vec![],
                plus(v6_method(leaf(0xA7), leaf(0xA3)), ge_const(on_curve())),
            ),
            "UNPARSED",
            true,
        ),
        // off-curve GE inside the v6 method's own receiver / args — parsed before
        // the throw, so checked by both.
        (
            "offcurve_in_v6_obj",
            tree(
                0,
                false,
                vec![],
                v6_method(ge_const(off_curve()), leaf(0xA3)),
            ),
            "THROW",
            false,
        ),
        (
            "offcurve_in_v6_arg",
            tree(
                0,
                false,
                vec![],
                v6_method(leaf(0xA7), ge_const(off_curve())),
            ),
            "THROW",
            false,
        ),
        // version 3: the v6 method is VALID, so no wrap; the trailing GE is parsed
        // and curve-checked by both.
        (
            "v3_v6_offcurve_AFTER",
            tree(
                3,
                false,
                vec![],
                plus(v6_method(leaf(0xA7), leaf(0xA3)), ge_const(off_curve())),
            ),
            "THROW",
            false,
        ),
        // segregated off-curve GE, parsed before the body — checked by both.
        (
            "seg_offcurve_then_v6",
            tree(
                0,
                true,
                vec![(
                    SigmaType::SGroupElement,
                    SigmaValue::GroupElement(GroupElement::from_bytes(off_curve())),
                )],
                plus(placeholder(0), v6_method(leaf(0xA7), leaf(0xA3))),
            ),
            "THROW",
            false,
        ),
        // nested v6 method in the outer method's receiver, off-curve GE after the
        // outer method — the inner method's checkpoint drops the trailing GE.
        (
            "nested_v6_then_offcurve_AFTER",
            tree(
                0,
                false,
                vec![],
                plus(
                    v6_method(v6_method(leaf(0xA7), leaf(0xA3)), leaf(0xA3)),
                    ge_const(off_curve()),
                ),
            ),
            "UNPARSED",
            true,
        ),
        // PropertyCall form (SGlobal.none[Int]) with off-curve GE after it.
        (
            "propcall_none_then_offcurve_AFTER",
            tree(0, false, vec![], plus(global_none(), ge_const(off_curve()))),
            "UNPARSED",
            true,
        ),
        // Two sibling v6 methods; the SECOND carries an off-curve GE in its
        // receiver. Scala throws at the FIRST and never reaches the second, so
        // the GE is dropped (our checkpoint sits at the first method).
        (
            "two_sibling_v6_2nd_has_offcurve",
            tree(
                0,
                false,
                vec![],
                plus(
                    v6_method(leaf(0xA7), leaf(0xA3)),
                    v6_method(ge_const(off_curve()), leaf(0xA3)),
                ),
            ),
            "UNPARSED",
            true,
        ),
    ];

    for (name, t, scala, accepted) in &cases {
        assert_eq!(
            rust_accepts(t),
            *accepted,
            "{name}: Scala oracle = {scala} (accepted={accepted}), Rust disagreed"
        );
        // A pre-v3 tree carrying a v6 method must take Scala's UnparsedErgoTree
        // representation (so spend rejects via the unparsed-eval path).
        if scala == &"UNPARSED" && t.version < 3 && name.contains("v6") {
            assert!(
                rust_wraps(t),
                "{name}: pre-v3 v6 tree must wrap as Unparsed"
            );
        }
    }
}
