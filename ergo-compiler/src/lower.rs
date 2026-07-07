//! M4 Task 3 — lowering-block AST→AST passes over the emitted opcode IR
//! (`ergo_ser::opcode::Expr`), mirroring two rules from Scala's
//! `GraphBuilding.rewriteDef` fixpoint cascade:
//!
//! - **D-C2** (`dev-docs/ergoscript-compiler-m4-recon/recon-transforms.md`
//!   §5, `TreeBuilding.scala:416-430`): `CreateProveDlog(Const{GroupElement})`
//!   folds to a bare `Const{SigmaProp, ProveDlog(ge)}`, and the
//!   `CreateProveDHTuple` analog folds when **all four** arguments are
//!   `Const{GroupElement}`.
//! - **single-element sigma unwrap** (recon-transforms.md §4,
//!   `GraphBuilding.scala:205-208`): a logical `And`/`Or` over a one-item
//!   `ConcreteCollection`, or a `SigmaAnd`/`SigmaOr` over a one-item
//!   `SigmaCollection`, collapses to its sole item. `AtLeast` is
//!   DELIBERATELY excluded — the dossier's unwrap bullet lists only
//!   `AllOf`/`AnyOf`/`AllZk`/`AnyZk`, and recon-targets vector #15
//!   (`atLeast(1, Coll(proveDlog(g1)))`) pins the `AtLeast` shape as
//!   unchanged even over a singleton `Coll`.
//!
//! Deliberately NOT implemented here (deferred to later M4 tasks, per the
//! plan's narrow-PR-granularity locked decision): the `HasSigmas`
//! Boolean/`isValid`-of-SigmaProp split (recon-transforms.md §4,
//! `GraphBuilding.scala:191-203`) needs the `SigmaPropIsProven` elimination
//! that is Task 6's D-C3; the all-`Const[Boolean]` `AnyOf`/`AllOf` fold
//! (§4, `:214-219`) belongs to Task 5's generic constant-folding engine.
//!
//! **Pass position** (plan locked decision 1): the lowering block — AFTER
//! the D-C5 reject gates and every constant fold (incl. the D-C6
//! `fold_literal_coll_sizes` wave) and the v0-unserializable-data gate, and
//! BEFORE constant segregation (`tree.rs::build_tree`) — wired in
//! `tree::compile`.

use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};

// Opcode constants this pass matches on (ergo-ser/src/opcode/types.rs).
const CREATE_PROVE_DLOG: u8 = 0xCD;
const CREATE_PROVE_DHTUPLE: u8 = 0xCE;
const CONCRETE_COLLECTION: u8 = 0x83;
const LOGICAL_AND: u8 = 0x96;
const LOGICAL_OR: u8 = 0x97;
const SIGMA_AND: u8 = 0xEA;
const SIGMA_OR: u8 = 0xEB;

/// Run the M4 Task-3 lowering rules over `expr`, bottom-up (children are
/// lowered before a node's own shape is inspected).
///
/// A single post-order traversal suffices — no fixpoint loop is needed. Each
/// rule only ever looks at its DIRECT children, and those children are
/// already fully lowered by the time a node's own rule runs, so a fold deep
/// in the tree is visible to an enclosing unwrap in the SAME pass. Worked
/// example (recon-targets vector #16's Task-3 ingredient):
/// `allOf(Coll(proveDlog(g1)))` emits as
/// `And(One(ConcreteCollection([SigmaPropIsProven(CreateProveDlog(Const g1))])))`.
/// Recursing into the `And`'s child first lowers the inner
/// `CreateProveDlog(Const)` to `Const{SigmaProp}` (D-C2); the single-item
/// `ConcreteCollection` and its parent `And` are then unwrapped, leaving bare
/// `SigmaPropIsProven(Const{SigmaProp})` — matching recon-targets' `And:1→0,
/// ConcreteCollection:1→0, ProveDlog:1→0` deltas exactly (the residual
/// `SigmaPropIsProven`/`BoolToSigmaProp` deltas are D-C3, Task 6).
pub(crate) fn lower(expr: Expr) -> Expr {
    let expr = match expr {
        Expr::Op(IrNode { opcode, payload }) => Expr::Op(IrNode {
            opcode,
            payload: map_children(payload),
        }),
        other => other,
    };
    unwrap_single_element_sigma_collection(fold_prove_dlog_dhtuple(expr))
}

/// By-value child map — the lowering-pass twin of `tree.rs::push_children`/
/// `fold_payload` (a new child-carrying `Payload` variant fails to compile
/// here until it is mapped).
fn map_children(payload: Payload) -> Payload {
    let f = |b: Box<Expr>| Box::new(lower(*b));
    let fv = |items: Vec<Expr>| -> Vec<Expr> { items.into_iter().map(lower).collect() };
    match payload {
        Payload::Zero
        | Payload::ValUse { .. }
        | Payload::ConstPlaceholder { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::DeserializeContext { .. }
        | Payload::NoneValue { .. } => payload,
        Payload::One(a) => Payload::One(f(a)),
        Payload::NumericCast { input, tpe } => Payload::NumericCast {
            input: f(input),
            tpe,
        },
        Payload::Two(a, b) => Payload::Two(f(a), f(b)),
        Payload::Three(a, b, c) => Payload::Three(f(a), f(b), f(c)),
        Payload::Four(a, b, c, d) => Payload::Four(f(a), f(b), f(c), f(d)),
        Payload::ValDef { id, tpe, rhs } => Payload::ValDef {
            id,
            tpe,
            rhs: f(rhs),
        },
        Payload::FunDef {
            id,
            tpe,
            tpe_args,
            rhs,
        } => Payload::FunDef {
            id,
            tpe,
            tpe_args,
            rhs: f(rhs),
        },
        Payload::BlockValue { items, result } => Payload::BlockValue {
            items: fv(items),
            result: f(result),
        },
        Payload::FuncValue { args, body } => Payload::FuncValue {
            args,
            body: f(body),
        },
        Payload::MethodCall {
            type_id,
            method_id,
            obj,
            args,
            type_args,
        } => Payload::MethodCall {
            type_id,
            method_id,
            obj: f(obj),
            args: fv(args),
            type_args,
        },
        Payload::ConcreteCollection { elem_type, items } => Payload::ConcreteCollection {
            elem_type,
            items: fv(items),
        },
        Payload::Tuple { items } => Payload::Tuple { items: fv(items) },
        Payload::SigmaCollection { items } => Payload::SigmaCollection { items: fv(items) },
        Payload::SelectField { input, field_idx } => Payload::SelectField {
            input: f(input),
            field_idx,
        },
        Payload::ExtractRegisterAs { input, reg_id, tpe } => Payload::ExtractRegisterAs {
            input: f(input),
            reg_id,
            tpe,
        },
        Payload::DeserializeRegister {
            reg_id,
            tpe,
            default,
        } => Payload::DeserializeRegister {
            reg_id,
            tpe,
            default: default.map(f),
        },
        Payload::ByIndex {
            input,
            index,
            default,
        } => Payload::ByIndex {
            input: f(input),
            index: f(index),
            default: default.map(f),
        },
        Payload::FuncApply { func, args } => Payload::FuncApply {
            func: f(func),
            args: fv(args),
        },
    }
}

/// D-C2 (recon-transforms.md §5): `CreateProveDlog(Const{GroupElement})` ->
/// `Const{SigmaProp, ProveDlog(ge)}`; `CreateProveDHTuple` folds only when
/// **all four** arguments are `Const{GroupElement}` (`TreeBuilding.scala:
/// 416-430` — a partially-constant `proveDHTuple` stays a `CreateProveDHTuple`
/// node, matching Scala's `mkCreateProveDHTuple` fallback exactly).
fn fold_prove_dlog_dhtuple(expr: Expr) -> Expr {
    match expr {
        Expr::Op(IrNode {
            opcode: CREATE_PROVE_DLOG,
            payload: Payload::One(inner),
        }) => match *inner {
            Expr::Const {
                tpe: SigmaType::SGroupElement,
                val: SigmaValue::GroupElement(ge),
            } => Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(ge)),
            },
            other => Expr::Op(IrNode {
                opcode: CREATE_PROVE_DLOG,
                payload: Payload::One(Box::new(other)),
            }),
        },
        Expr::Op(IrNode {
            opcode: CREATE_PROVE_DHTUPLE,
            payload: Payload::Four(g, h, u, v),
        }) => match (*g, *h, *u, *v) {
            (
                Expr::Const {
                    tpe: SigmaType::SGroupElement,
                    val: SigmaValue::GroupElement(g),
                },
                Expr::Const {
                    tpe: SigmaType::SGroupElement,
                    val: SigmaValue::GroupElement(h),
                },
                Expr::Const {
                    tpe: SigmaType::SGroupElement,
                    val: SigmaValue::GroupElement(u),
                },
                Expr::Const {
                    tpe: SigmaType::SGroupElement,
                    val: SigmaValue::GroupElement(v),
                },
            ) => Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::ProveDHTuple { g, h, u, v }),
            },
            (g, h, u, v) => Expr::Op(IrNode {
                opcode: CREATE_PROVE_DHTUPLE,
                payload: Payload::Four(Box::new(g), Box::new(h), Box::new(u), Box::new(v)),
            }),
        },
        other => other,
    }
}

/// Single-element unwrap (recon-transforms.md §4, `GraphBuilding.scala:
/// 205-208`): `And`(0x96)/`Or`(0x97) over a one-item `ConcreteCollection`, or
/// `SigmaAnd`(0xEA)/`SigmaOr`(0xEB) over a one-item `SigmaCollection`,
/// collapses to its sole item. The `SigmaAnd`/`SigmaOr` arm is PERMANENTLY
/// unreachable from ErgoScript source, not merely pending a future wiring
/// (M4 Task 8 review, lib.rs D-C8): binary `&&`/`||` between `SigmaProp`s
/// always produces >= 2 items, and `allZK`/`anyZK` — the only OTHER route
/// that could construct a single-item `SigmaAnd`/`SigmaOr` — never lowers to
/// one at all: Scala's own `SigmaPredef.AllZKFunc`/`AnyZKFunc` irBuilder is
/// the `undefined` sentinel (genuinely unimplemented upstream, not a porting
/// gap), so `allZK(Coll(x))` rejects with `StagingException` before any
/// lowering runs (oracle-probed, 3 forms, 3 runs — see D-C8). This arm is
/// pinned by the same `GraphBuilding.scala:205-208` citation as the
/// `And`/`Or` arm it ships alongside and is kept for spec completeness.
fn unwrap_single_element_sigma_collection(expr: Expr) -> Expr {
    match expr {
        Expr::Op(IrNode {
            opcode: op @ (LOGICAL_AND | LOGICAL_OR),
            payload: Payload::One(inner),
        }) => match *inner {
            Expr::Op(IrNode {
                opcode: CONCRETE_COLLECTION,
                payload: Payload::ConcreteCollection { items, .. },
            }) if items.len() == 1 => items.into_iter().next().expect("len checked above"),
            other => Expr::Op(IrNode {
                opcode: op,
                payload: Payload::One(Box::new(other)),
            }),
        },
        Expr::Op(IrNode {
            opcode: op @ (SIGMA_AND | SIGMA_OR),
            payload: Payload::SigmaCollection { items },
        }) => {
            if items.len() == 1 {
                items.into_iter().next().expect("len checked above")
            } else {
                Expr::Op(IrNode {
                    opcode: op,
                    payload: Payload::SigmaCollection { items },
                })
            }
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::group_element::GroupElement;

    // ----- helpers -----

    fn ge(byte: u8) -> GroupElement {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        bytes[1] = byte;
        GroupElement::from_bytes(bytes)
    }

    fn ge_const(byte: u8) -> Expr {
        Expr::Const {
            tpe: SigmaType::SGroupElement,
            val: SigmaValue::GroupElement(ge(byte)),
        }
    }

    fn height() -> Expr {
        Expr::Op(IrNode {
            opcode: 0xA5, // Height (arbitrary non-const leaf for shape tests).
            payload: Payload::Zero,
        })
    }

    // ----- happy path -----

    #[test]
    fn lower_create_prove_dlog_const_folds_to_sigma_prop_constant() {
        let dlog = Expr::Op(IrNode {
            opcode: CREATE_PROVE_DLOG,
            payload: Payload::One(Box::new(ge_const(0xAA))),
        });
        assert_eq!(
            lower(dlog),
            Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(ge(0xAA))),
            }
        );
    }

    #[test]
    fn lower_create_prove_dlog_non_const_stays_unfolded() {
        // A non-constant GroupElement argument (e.g. a ValUse) must NOT fold —
        // the D-C2 rule is gated on a DIRECT Constant (`TreeBuilding.scala:
        // 416-430`'s `Constant[SGroupElement]` match).
        let non_const = Expr::Op(IrNode {
            opcode: 0xA6, // arbitrary non-const shape (ValUse-like leaf)
            payload: Payload::ValUse { id: 7 },
        });
        let dlog = Expr::Op(IrNode {
            opcode: CREATE_PROVE_DLOG,
            payload: Payload::One(Box::new(non_const.clone())),
        });
        assert_eq!(
            lower(dlog),
            Expr::Op(IrNode {
                opcode: CREATE_PROVE_DLOG,
                payload: Payload::One(Box::new(non_const)),
            })
        );
    }

    #[test]
    fn lower_create_prove_dhtuple_all_const_folds() {
        let dht = Expr::Op(IrNode {
            opcode: CREATE_PROVE_DHTUPLE,
            payload: Payload::Four(
                Box::new(ge_const(1)),
                Box::new(ge_const(2)),
                Box::new(ge_const(3)),
                Box::new(ge_const(4)),
            ),
        });
        assert_eq!(
            lower(dht),
            Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::ProveDHTuple {
                    g: ge(1),
                    h: ge(2),
                    u: ge(3),
                    v: ge(4),
                }),
            }
        );
    }

    #[test]
    fn lower_create_prove_dhtuple_partial_const_stays_unfolded() {
        // ONE non-constant argument (e.g. a env-bound group element reached
        // via ValUse) must block the fold entirely — Scala's
        // `TreeBuilding.scala:416-430` requires ALL FOUR to be constants.
        let dyn_ge = Expr::Op(IrNode {
            opcode: 0xA6,
            payload: Payload::ValUse { id: 9 },
        });
        let dht = Expr::Op(IrNode {
            opcode: CREATE_PROVE_DHTUPLE,
            payload: Payload::Four(
                Box::new(ge_const(1)),
                Box::new(ge_const(2)),
                Box::new(ge_const(3)),
                Box::new(dyn_ge.clone()),
            ),
        });
        assert_eq!(
            lower(dht),
            Expr::Op(IrNode {
                opcode: CREATE_PROVE_DHTUPLE,
                payload: Payload::Four(
                    Box::new(ge_const(1)),
                    Box::new(ge_const(2)),
                    Box::new(ge_const(3)),
                    Box::new(dyn_ge),
                ),
            })
        );
    }

    #[test]
    fn lower_single_element_or_unwraps_to_bare_item() {
        // anyOf(Coll(HEIGHT > 5)) shape: Or(One(ConcreteCollection([item]))).
        let item = height();
        let or_node = Expr::Op(IrNode {
            opcode: LOGICAL_OR,
            payload: Payload::One(Box::new(Expr::Op(IrNode {
                opcode: CONCRETE_COLLECTION,
                payload: Payload::ConcreteCollection {
                    elem_type: SigmaType::SBoolean,
                    items: vec![item.clone()],
                },
            }))),
        });
        assert_eq!(lower(or_node), item);
    }

    #[test]
    fn lower_single_element_and_unwraps_to_bare_item() {
        let item = height();
        let and_node = Expr::Op(IrNode {
            opcode: LOGICAL_AND,
            payload: Payload::One(Box::new(Expr::Op(IrNode {
                opcode: CONCRETE_COLLECTION,
                payload: Payload::ConcreteCollection {
                    elem_type: SigmaType::SBoolean,
                    items: vec![item.clone()],
                },
            }))),
        });
        assert_eq!(lower(and_node), item);
    }

    #[test]
    fn lower_multi_element_or_stays_unwrapped() {
        // Two-item ConcreteCollection must NOT unwrap (the rule is gated on
        // items.length == 1, GraphBuilding.scala:205-208).
        let items = vec![height(), height()];
        let or_node = Expr::Op(IrNode {
            opcode: LOGICAL_OR,
            payload: Payload::One(Box::new(Expr::Op(IrNode {
                opcode: CONCRETE_COLLECTION,
                payload: Payload::ConcreteCollection {
                    elem_type: SigmaType::SBoolean,
                    items: items.clone(),
                },
            }))),
        });
        assert_eq!(
            lower(or_node),
            Expr::Op(IrNode {
                opcode: LOGICAL_OR,
                payload: Payload::One(Box::new(Expr::Op(IrNode {
                    opcode: CONCRETE_COLLECTION,
                    payload: Payload::ConcreteCollection {
                        elem_type: SigmaType::SBoolean,
                        items,
                    },
                }))),
            })
        );
    }

    #[test]
    fn lower_atleast_singleton_coll_stays_unchanged() {
        // atLeast(1, Coll(proveDlog(g1))): the AtLeast (0x98) shape itself is
        // NOT touched by the single-element unwrap (recon-targets vector #15
        // — only the nested proveDlog(const) folds).
        let bound = Expr::Const {
            tpe: SigmaType::SInt,
            val: SigmaValue::Int(1),
        };
        let coll = Expr::Op(IrNode {
            opcode: CONCRETE_COLLECTION,
            payload: Payload::ConcreteCollection {
                elem_type: SigmaType::SSigmaProp,
                items: vec![Expr::Op(IrNode {
                    opcode: CREATE_PROVE_DLOG,
                    payload: Payload::One(Box::new(ge_const(0xBB))),
                })],
            },
        });
        let at_least = Expr::Op(IrNode {
            opcode: 0x98,
            payload: Payload::Two(Box::new(bound.clone()), Box::new(coll)),
        });
        let expected_coll = Expr::Op(IrNode {
            opcode: CONCRETE_COLLECTION,
            payload: Payload::ConcreteCollection {
                elem_type: SigmaType::SSigmaProp,
                items: vec![Expr::Const {
                    tpe: SigmaType::SSigmaProp,
                    val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(ge(0xBB))),
                }],
            },
        });
        assert_eq!(
            lower(at_least),
            Expr::Op(IrNode {
                opcode: 0x98,
                payload: Payload::Two(Box::new(bound), Box::new(expected_coll)),
            })
        );
    }

    #[test]
    fn lower_single_element_sigma_and_unwraps() {
        // Structural-only: allZK(Coll(x))'s shape (unreachable from real
        // ErgoScript source today, per the fn docs) — pinned by the SAME
        // GraphBuilding.scala:205-208 citation as And/Or.
        let item = height();
        let sigma_and = Expr::Op(IrNode {
            opcode: SIGMA_AND,
            payload: Payload::SigmaCollection {
                items: vec![item.clone()],
            },
        });
        assert_eq!(lower(sigma_and), item);
    }

    #[test]
    fn lower_multi_element_sigma_or_stays_unwrapped() {
        let items = vec![height(), height()];
        let sigma_or = Expr::Op(IrNode {
            opcode: SIGMA_OR,
            payload: Payload::SigmaCollection {
                items: items.clone(),
            },
        });
        assert_eq!(
            lower(sigma_or),
            Expr::Op(IrNode {
                opcode: SIGMA_OR,
                payload: Payload::SigmaCollection { items },
            })
        );
    }

    // ----- round-trips -----

    #[test]
    fn lower_is_idempotent_on_already_lowered_trees() {
        let folded = Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(ge(1))),
        };
        assert_eq!(lower(folded.clone()), folded);
    }

    // ----- error paths -----
    // (Pure AST rewrite — no fallible paths; error-path coverage lives in the
    // typer/emit gates upstream of this pass.)
}
