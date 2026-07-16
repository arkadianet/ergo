//! Multi-arg lambda tupling (D-C4).
//!
//! Scala's `buildGraph` builds a 2-arg `Lambda` as a **single tuple-arg**
//! graph function (`GraphBuilding.scala:917-924`:
//! `fun { x: Ref[(s,a)] => body[accN → x._1, n → x._2] }`), and `buildTree`
//! materializes that graph `Lambda` as a **1-arg `FuncValue`** over the tuple
//! element type with `SelectField` projections in the body
//! (`TreeBuilding.scala:185-190` — `varId = defId + 1`, single arg
//! `(varId, STuple(..))`; the `x._1`/`x._2` graph nodes are `First`/`Second`,
//! materialized as `SelectField(ValUse(varId), 1/2)` at `:454-457`).
//!
//! So `.fold(0, {(a, b) => a + b})` compiles to
//! `FuncValue([(id, STuple(t_a, t_b))], body[a := SelectField(ValUse(id), 1),
//! b := SelectField(ValUse(id), 2)])`. The reference JIT hard-errors on any
//! non-1-arg `FuncValue` (`values.scala:1042-1056`, "Function must have 1
//! argument"), so the tupled 1-arg shape is the ONLY valid on-chain form —
//! and the ONLY one Scala's compiler ever emits.
//!
//! This pass corrects a deviation (lib.rs D-C4): the emitter produces a 2-arg
//! `FuncValue`, which is wire-legal but unevaluable. Lowering it to the tupled
//! 1-arg form here makes fold-slot lambdas evaluable and byte-matchable.
//!
//! # Id allocation (Scala-faithful)
//!
//! The tuple param reuses the FIRST original arg's id. In emit's monotonic
//! scope counter (`emit::Scope`) a lambda's first arg takes the enclosing
//! scope's next id — exactly Scala's `varId = defId + 1` for the graph
//! function's single tuple param. So reusing `args[0].0` for the tuple param
//! reproduces Scala's id for the non-CSE case (verified byte-identical against
//! the oracle for `Coll(1, 2).fold(0, {(a, b) => a + b})`). The second arg's
//! id is dropped — Scala never materializes the two arg names as separate
//! bindings; they only ever appear as `x._1`/`x._2`. Ids are globally unique
//! in the never-reuse relaxation, so substituting `ValUse(arg_id)` throughout
//! the body cannot collide with any inner binding.
//!
//! **Pass position:** the lowering block, AFTER the
//! `graph_building_lambda_reject` gate (which rejects non-1-arg *applications*
//! — `FuncApply` — that Scala refuses; the multi-arg *definitions* that reach
//! here are the D-C4 both-accept class: fold-slot and un-applied lambdas) and
//! the constant folds, BEFORE constant segregation.

use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;

use std::collections::HashMap;

const VAL_USE: u8 = 0x72;
const SELECT_FIELD: u8 = 0x8C;
const FUNC_VALUE: u8 = 0xD9;

/// Lower every multi-arg `FuncValue` in `expr` to the Scala-faithful tupled
/// 1-arg form. Bottom-up: a node's children are tupled before the node itself,
/// so a nested lambda is already in tupled form when its enclosing lambda's
/// body is rewritten.
pub(crate) fn tuple_lambdas(expr: Expr) -> Expr {
    transform_post_order(expr, &mut tuple_node)
}

/// Node-level rule: a `FuncValue` with 2+ fully-typed args becomes a 1-arg
/// tupled `FuncValue` with `SelectField` projections. Anything else is
/// unchanged. (A single-arg lambda is already valid; a zero-arg lambda is
/// rejected upstream by the reject gate and never reaches here.)
fn tuple_node(expr: Expr) -> Expr {
    let Expr::Op(IrNode {
        opcode: FUNC_VALUE,
        payload: Payload::FuncValue { args, body },
    }) = expr
    else {
        return expr;
    };
    if args.len() < 2 {
        return rebuild_func_value(args, body);
    }
    // Every arg must carry a concrete type to form the tuple element type;
    // HOF-callback lambdas always do (emit types every FuncValue arg). If one
    // is missing we cannot build an `STuple`, so leave the node untouched
    // (defensive — unreachable from real emit output).
    let mut elem_types = Vec::with_capacity(args.len());
    for (_, tpe) in &args {
        match tpe {
            Some(t) => elem_types.push(t.clone()),
            None => return rebuild_func_value(args, body),
        }
    }

    let tuple_id = args[0].0;
    // Map each original arg id → its 1-based tuple field index.
    let id_to_field: HashMap<u32, u8> = args
        .iter()
        .enumerate()
        .map(|(i, (id, _))| (*id, (i + 1) as u8))
        .collect();

    let new_body = substitute_args(*body, tuple_id, &id_to_field);

    Expr::Op(IrNode {
        opcode: FUNC_VALUE,
        payload: Payload::FuncValue {
            args: vec![(tuple_id, Some(SigmaType::STuple(elem_types)))],
            body: Box::new(new_body),
        },
    })
}

fn rebuild_func_value(args: Vec<(u32, Option<SigmaType>)>, body: Box<Expr>) -> Expr {
    Expr::Op(IrNode {
        opcode: FUNC_VALUE,
        payload: Payload::FuncValue { args, body },
    })
}

/// Replace every `ValUse(arg_id)` in `body` with
/// `SelectField(ValUse(tuple_id), field_idx)`. Post-order: the `ValUse` we
/// synthesize inside the new `SelectField` is inserted AFTER the visit and is
/// never re-substituted (even though `tuple_id` is itself a key), so this
/// terminates.
fn substitute_args(body: Expr, tuple_id: u32, id_to_field: &HashMap<u32, u8>) -> Expr {
    let mut visit = |e: Expr| -> Expr {
        if let Expr::Op(IrNode {
            payload: Payload::ValUse { id },
            ..
        }) = &e
        {
            if let Some(&field_idx) = id_to_field.get(id) {
                return Expr::Op(IrNode {
                    opcode: SELECT_FIELD,
                    payload: Payload::SelectField {
                        input: Box::new(Expr::Op(IrNode {
                            opcode: VAL_USE,
                            payload: Payload::ValUse { id: tuple_id },
                        })),
                        field_idx,
                    },
                });
            }
        }
        e
    };
    transform_post_order(body, &mut visit)
}

/// Rebuild `expr` bottom-up, applying `visit` to each node after its children
/// have been transformed. The exhaustive child map (`map_children`) fails to
/// compile if a new child-carrying [`Payload`] variant is added without being
/// mapped — the same safety invariant as `tree::push_children` and
/// `lower::map_children`.
fn transform_post_order<F: FnMut(Expr) -> Expr>(expr: Expr, visit: &mut F) -> Expr {
    let expr = match expr {
        Expr::Op(IrNode { opcode, payload }) => Expr::Op(IrNode {
            opcode,
            payload: map_children(payload, visit),
        }),
        other => other,
    };
    visit(expr)
}

fn boxed<F: FnMut(Expr) -> Expr>(e: Expr, visit: &mut F) -> Box<Expr> {
    Box::new(transform_post_order(e, visit))
}

fn map_children<F: FnMut(Expr) -> Expr>(payload: Payload, visit: &mut F) -> Payload {
    match payload {
        Payload::Zero
        | Payload::ValUse { .. }
        | Payload::ConstPlaceholder { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::DeserializeContext { .. }
        | Payload::NoneValue { .. } => payload,
        Payload::One(a) => Payload::One(boxed(*a, visit)),
        Payload::NumericCast { input, tpe } => Payload::NumericCast {
            input: boxed(*input, visit),
            tpe,
        },
        Payload::Two(a, b) => Payload::Two(boxed(*a, visit), boxed(*b, visit)),
        Payload::Three(a, b, c) => {
            Payload::Three(boxed(*a, visit), boxed(*b, visit), boxed(*c, visit))
        }
        Payload::Four(a, b, c, d) => Payload::Four(
            boxed(*a, visit),
            boxed(*b, visit),
            boxed(*c, visit),
            boxed(*d, visit),
        ),
        Payload::ValDef { id, tpe, rhs } => Payload::ValDef {
            id,
            tpe,
            rhs: boxed(*rhs, visit),
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
            rhs: boxed(*rhs, visit),
        },
        Payload::BlockValue { items, result } => Payload::BlockValue {
            items: map_vec(items, visit),
            result: boxed(*result, visit),
        },
        Payload::FuncValue { args, body } => Payload::FuncValue {
            args,
            body: boxed(*body, visit),
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
            obj: boxed(*obj, visit),
            args: map_vec(args, visit),
            type_args,
        },
        Payload::ConcreteCollection { elem_type, items } => Payload::ConcreteCollection {
            elem_type,
            items: map_vec(items, visit),
        },
        Payload::Tuple { items } => Payload::Tuple {
            items: map_vec(items, visit),
        },
        Payload::SigmaCollection { items } => Payload::SigmaCollection {
            items: map_vec(items, visit),
        },
        Payload::SelectField { input, field_idx } => Payload::SelectField {
            input: boxed(*input, visit),
            field_idx,
        },
        Payload::ExtractRegisterAs { input, reg_id, tpe } => Payload::ExtractRegisterAs {
            input: boxed(*input, visit),
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
            default: default.map(|d| boxed(*d, visit)),
        },
        Payload::ByIndex {
            input,
            index,
            default,
        } => Payload::ByIndex {
            input: boxed(*input, visit),
            index: boxed(*index, visit),
            default: default.map(|d| boxed(*d, visit)),
        },
        Payload::FuncApply { func, args } => Payload::FuncApply {
            func: boxed(*func, visit),
            args: map_vec(args, visit),
        },
    }
}

fn map_vec<F: FnMut(Expr) -> Expr>(items: Vec<Expr>, visit: &mut F) -> Vec<Expr> {
    items
        .into_iter()
        .map(|e| transform_post_order(e, visit))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn val_use(id: u32) -> Expr {
        Expr::Op(IrNode {
            opcode: VAL_USE,
            payload: Payload::ValUse { id },
        })
    }

    fn select_field(id: u32, field_idx: u8) -> Expr {
        Expr::Op(IrNode {
            opcode: SELECT_FIELD,
            payload: Payload::SelectField {
                input: Box::new(val_use(id)),
                field_idx,
            },
        })
    }

    /// `a + b` over ids `a_id`/`b_id` (opcode 0x9A = arithmetic Plus).
    fn plus(a: Expr, b: Expr) -> Expr {
        Expr::Op(IrNode {
            opcode: 0x9A,
            payload: Payload::Two(Box::new(a), Box::new(b)),
        })
    }

    fn func_value(args: Vec<(u32, Option<SigmaType>)>, body: Expr) -> Expr {
        Expr::Op(IrNode {
            opcode: FUNC_VALUE,
            payload: Payload::FuncValue {
                args,
                body: Box::new(body),
            },
        })
    }

    // ----- happy path -----

    #[test]
    fn two_arg_lambda_tuples_to_one_arg_with_selectfields() {
        // FuncValue([(1, Long), (2, Long)], Plus(ValUse(1), ValUse(2)))
        // → FuncValue([(1, STuple(Long, Long))],
        //             Plus(SelectField(ValUse(1),1), SelectField(ValUse(1),2)))
        let input = func_value(
            vec![(1, Some(SigmaType::SLong)), (2, Some(SigmaType::SLong))],
            plus(val_use(1), val_use(2)),
        );
        let expected = func_value(
            vec![(
                1,
                Some(SigmaType::STuple(vec![SigmaType::SLong, SigmaType::SLong])),
            )],
            plus(select_field(1, 1), select_field(1, 2)),
        );
        assert_eq!(tuple_lambdas(input), expected);
    }

    #[test]
    fn tuple_param_reuses_first_arg_id() {
        // Args (3, 4) → tuple param id 3 (the FIRST arg's id, Scala varId).
        let input = func_value(
            vec![(3, Some(SigmaType::SInt)), (4, Some(SigmaType::SInt))],
            plus(val_use(3), val_use(4)),
        );
        let Expr::Op(IrNode {
            payload: Payload::FuncValue { args, .. },
            ..
        }) = tuple_lambdas(input)
        else {
            panic!("expected FuncValue");
        };
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].0, 3, "tuple param reuses first arg id");
        assert_eq!(
            args[0].1,
            Some(SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SInt]))
        );
    }

    #[test]
    fn single_arg_lambda_is_untouched() {
        // 1-arg lambdas are already valid — no tupling.
        let input = func_value(vec![(1, Some(SigmaType::SLong))], val_use(1));
        assert_eq!(tuple_lambdas(input.clone()), input);
    }

    // ----- nested / recursion -----

    #[test]
    fn tuples_lambda_nested_inside_a_fold_op_slot() {
        // Fold(coll, zero, FuncValue([(1,Long),(2,Long)], Plus(...)))
        // The tupling must reach the op-slot lambda (Payload::Three child).
        let lambda = func_value(
            vec![(1, Some(SigmaType::SLong)), (2, Some(SigmaType::SLong))],
            plus(val_use(1), val_use(2)),
        );
        let fold = Expr::Op(IrNode {
            opcode: 0xB0, // Fold
            payload: Payload::Three(
                Box::new(Expr::Op(IrNode {
                    opcode: 0x72,
                    payload: Payload::ValUse { id: 9 }, // stand-in collection
                })),
                Box::new(Expr::Op(IrNode {
                    opcode: 0x72,
                    payload: Payload::ValUse { id: 10 }, // stand-in zero
                })),
                Box::new(lambda),
            ),
        });
        let Expr::Op(IrNode {
            payload: Payload::Three(_, _, op),
            ..
        }) = tuple_lambdas(fold)
        else {
            panic!("expected Fold Three payload");
        };
        let Expr::Op(IrNode {
            payload: Payload::FuncValue { args, body },
            ..
        }) = *op
        else {
            panic!("expected tupled FuncValue op");
        };
        assert_eq!(args.len(), 1);
        assert_eq!(
            *body,
            plus(select_field(1, 1), select_field(1, 2)),
            "body projects the tuple param"
        );
    }

    #[test]
    fn tuples_lambda_bound_in_a_valdef_rhs() {
        // { val f = {(a,b) => a+b}; ... } — the FuncValue lives in a ValDef rhs
        // (the val-bound fold-slot class, e.g. crystalpool). Tupling must reach
        // it even though Scala inlines the val (inlining is Task 9).
        let vd = Expr::Op(IrNode {
            opcode: 0xD6, // ValDef
            payload: Payload::ValDef {
                id: 5,
                tpe: None,
                rhs: Box::new(func_value(
                    vec![(1, Some(SigmaType::SLong)), (2, Some(SigmaType::SLong))],
                    plus(val_use(1), val_use(2)),
                )),
            },
        });
        let Expr::Op(IrNode {
            payload: Payload::ValDef { rhs, .. },
            ..
        }) = tuple_lambdas(vd)
        else {
            panic!("expected ValDef");
        };
        let Expr::Op(IrNode {
            payload: Payload::FuncValue { args, .. },
            ..
        }) = *rhs
        else {
            panic!("expected tupled FuncValue rhs");
        };
        assert_eq!(args.len(), 1, "rhs lambda is tupled");
    }

    #[test]
    fn closure_var_from_enclosing_scope_is_not_substituted() {
        // FuncValue([(1,Long),(2,Long)], Plus(ValUse(1), ValUse(7))) — id 7 is
        // an enclosing-scope binding, NOT a lambda arg; it must stay a bare
        // ValUse, only the arg ids project.
        let input = func_value(
            vec![(1, Some(SigmaType::SLong)), (2, Some(SigmaType::SLong))],
            plus(val_use(1), val_use(7)),
        );
        let expected = func_value(
            vec![(
                1,
                Some(SigmaType::STuple(vec![SigmaType::SLong, SigmaType::SLong])),
            )],
            plus(select_field(1, 1), val_use(7)),
        );
        assert_eq!(tuple_lambdas(input), expected);
    }
}
