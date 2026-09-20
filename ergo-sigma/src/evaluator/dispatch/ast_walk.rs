//! Exhaustive structural walks over every `Payload` variant:
//! `expr_has_deserialize` (does the tree contain a DeserializeContext/Register
//! node?) and `inline_placeholders` (rebuild the tree with segregated
//! constants inlined). Both are wildcard-free so a new `Payload` variant with
//! children cannot silently escape the walk.

use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;

#[inline(never)]
/// Deep walk: does the expression contain a `DeserializeContext` (0xD4)
/// or `DeserializeRegister` (0xD5) node anywhere? Mirrors Scala
/// `Value.hasDeserialize` (counts exactly those two node classes).
/// Exhaustive over `Payload` — no wildcard arm, so a future variant
/// with children cannot silently escape the walk.
pub(crate) fn expr_has_deserialize(expr: &Expr) -> bool {
    let node = match expr {
        // An unparsed (soft-fork-wrapped) body has no AST to inspect; it errors
        // at evaluation regardless, so the deserialize-substitution path is moot.
        Expr::Const { .. } | Expr::Unparsed(_) => return false,
        Expr::Op(node) => node,
    };
    match &node.payload {
        Payload::DeserializeContext { .. } | Payload::DeserializeRegister { .. } => true,
        Payload::Zero
        | Payload::ValUse { .. }
        | Payload::ConstPlaceholder { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::NoneValue { .. } => false,
        Payload::One(a) => expr_has_deserialize(a),
        Payload::Two(a, b) => expr_has_deserialize(a) || expr_has_deserialize(b),
        Payload::Three(a, b, c) => {
            expr_has_deserialize(a) || expr_has_deserialize(b) || expr_has_deserialize(c)
        }
        Payload::Four(a, b, c, d) => {
            expr_has_deserialize(a)
                || expr_has_deserialize(b)
                || expr_has_deserialize(c)
                || expr_has_deserialize(d)
        }
        Payload::ValDef { rhs, .. } | Payload::FunDef { rhs, .. } => expr_has_deserialize(rhs),
        Payload::BlockValue { items, result } => {
            items.iter().any(expr_has_deserialize) || expr_has_deserialize(result)
        }
        Payload::FuncValue { body, .. } => expr_has_deserialize(body),
        Payload::MethodCall { obj, args, .. } => {
            expr_has_deserialize(obj) || args.iter().any(expr_has_deserialize)
        }
        Payload::ConcreteCollection { items, .. }
        | Payload::Tuple { items }
        | Payload::SigmaCollection { items } => items.iter().any(expr_has_deserialize),
        Payload::SelectField { input, .. }
        | Payload::ExtractRegisterAs { input, .. }
        | Payload::NumericCast { input, .. } => expr_has_deserialize(input),
        Payload::ByIndex {
            input,
            index,
            default,
        } => {
            expr_has_deserialize(input)
                || expr_has_deserialize(index)
                || default.as_deref().is_some_and(expr_has_deserialize)
        }
        Payload::FuncApply { func, args } => {
            expr_has_deserialize(func) || args.iter().any(expr_has_deserialize)
        }
    }
}

/// Structural rebuild replacing every `ConstPlaceholder { index }` with
/// the corresponding inline `Expr::Const` from the segregated constant
/// table. Out-of-range indexes are left as placeholders — they error at
/// evaluation exactly like the placeholder path. Exhaustive over
/// `Payload` (no wildcard) for the same reason as
/// [`expr_has_deserialize`].
pub(super) fn inline_placeholders(expr: &Expr, constants: &[(SigmaType, SigmaValue)]) -> Expr {
    let node = match expr {
        // Nothing to inline in a constant or an unparsed (verbatim) body.
        Expr::Const { .. } | Expr::Unparsed(_) => return expr.clone(),
        Expr::Op(node) => node,
    };
    let sub = |e: &Expr| inline_placeholders(e, constants);
    let sub_box = |e: &Expr| Box::new(inline_placeholders(e, constants));
    let payload = match &node.payload {
        Payload::ConstPlaceholder { index } => match constants.get(*index as usize) {
            Some((tpe, val)) => {
                return Expr::Const {
                    tpe: tpe.clone(),
                    val: val.clone(),
                }
            }
            None => Payload::ConstPlaceholder { index: *index },
        },
        p @ (Payload::Zero
        | Payload::ValUse { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::NoneValue { .. }
        | Payload::DeserializeContext { .. }) => p.clone(),
        Payload::One(a) => Payload::One(sub_box(a)),
        Payload::Two(a, b) => Payload::Two(sub_box(a), sub_box(b)),
        Payload::Three(a, b, c) => Payload::Three(sub_box(a), sub_box(b), sub_box(c)),
        Payload::Four(a, b, c, d) => Payload::Four(sub_box(a), sub_box(b), sub_box(c), sub_box(d)),
        Payload::ValDef { id, tpe, rhs } => Payload::ValDef {
            id: *id,
            tpe: tpe.clone(),
            rhs: sub_box(rhs),
        },
        Payload::FunDef {
            id,
            tpe,
            tpe_args,
            rhs,
        } => Payload::FunDef {
            id: *id,
            tpe: tpe.clone(),
            tpe_args: tpe_args.clone(),
            rhs: sub_box(rhs),
        },
        Payload::BlockValue { items, result } => Payload::BlockValue {
            items: items.iter().map(sub).collect(),
            result: sub_box(result),
        },
        Payload::FuncValue { args, body } => Payload::FuncValue {
            args: args.clone(),
            body: sub_box(body),
        },
        Payload::MethodCall {
            type_id,
            method_id,
            obj,
            args,
            type_args,
        } => Payload::MethodCall {
            type_id: *type_id,
            method_id: *method_id,
            obj: sub_box(obj),
            args: args.iter().map(sub).collect(),
            type_args: type_args.clone(),
        },
        Payload::ConcreteCollection { elem_type, items } => Payload::ConcreteCollection {
            elem_type: elem_type.clone(),
            items: items.iter().map(sub).collect(),
        },
        Payload::Tuple { items } => Payload::Tuple {
            items: items.iter().map(sub).collect(),
        },
        Payload::SigmaCollection { items } => Payload::SigmaCollection {
            items: items.iter().map(sub).collect(),
        },
        Payload::SelectField { input, field_idx } => Payload::SelectField {
            input: sub_box(input),
            field_idx: *field_idx,
        },
        Payload::ExtractRegisterAs { input, reg_id, tpe } => Payload::ExtractRegisterAs {
            input: sub_box(input),
            reg_id: *reg_id,
            tpe: tpe.clone(),
        },
        Payload::DeserializeRegister {
            reg_id,
            tpe,
            default,
        } => Payload::DeserializeRegister {
            reg_id: *reg_id,
            tpe: tpe.clone(),
            default: default.as_deref().map(sub_box),
        },
        Payload::ByIndex {
            input,
            index,
            default,
        } => Payload::ByIndex {
            input: sub_box(input),
            index: sub_box(index),
            default: default.as_deref().map(sub_box),
        },
        Payload::NumericCast { input, tpe } => Payload::NumericCast {
            input: sub_box(input),
            tpe: tpe.clone(),
        },
        Payload::FuncApply { func, args } => Payload::FuncApply {
            func: sub_box(func),
            args: args.iter().map(sub).collect(),
        },
    };
    Expr::Op(IrNode {
        opcode: node.opcode,
        payload,
    })
}

/// Substitute bottom-up, visiting dead branches and defaults before their parent.
/// Inserted scripts are not revisited, matching Scala `everywherebu`.
pub(super) fn substitute_deserialize(
    expr: &mut Expr,
    ctx: &super::ReductionContext<'_>,
    cost: &mut ergo_primitives::cost::CostAccumulator,
) -> Result<(), super::EvalError> {
    use super::EvalError;
    use ergo_ser::sigma_value::CollValue;
    let Expr::Op(node) = expr else {
        return Ok(());
    };
    let children: Vec<&mut Expr> = match &mut node.payload {
        Payload::Zero
        | Payload::ValUse { .. }
        | Payload::ConstPlaceholder { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::DeserializeContext { .. }
        | Payload::NoneValue { .. } => vec![],
        Payload::One(a) => vec![a],
        Payload::Two(a, b) => vec![a, b],
        Payload::Three(a, b, c) => vec![a, b, c],
        Payload::Four(a, b, c, d) => vec![a, b, c, d],
        Payload::ValDef { rhs, .. } | Payload::FunDef { rhs, .. } => vec![rhs],
        Payload::BlockValue { items, result } => {
            let mut v: Vec<&mut Expr> = items.iter_mut().collect();
            v.push(result);
            v
        }
        Payload::FuncValue { body, .. } => vec![body],
        Payload::MethodCall { obj, args, .. } => {
            let mut v = vec![obj.as_mut()];
            v.extend(args.iter_mut());
            v
        }
        Payload::ConcreteCollection { items, .. }
        | Payload::Tuple { items }
        | Payload::SigmaCollection { items } => items.iter_mut().collect(),
        Payload::SelectField { input, .. }
        | Payload::ExtractRegisterAs { input, .. }
        | Payload::NumericCast { input, .. } => vec![input],
        Payload::DeserializeRegister { default, .. } => {
            default.as_deref_mut().into_iter().collect()
        }
        Payload::ByIndex {
            input,
            index,
            default,
        } => {
            let mut v = vec![input.as_mut(), index.as_mut()];
            v.extend(default.as_deref_mut());
            v
        }
        Payload::FuncApply { func, args } => {
            let mut v = vec![func.as_mut()];
            v.extend(args.iter_mut());
            v
        }
    };
    for child in children {
        substitute_deserialize(child, ctx, cost)?;
    }
    let (value, tpe, default) = match &node.payload {
        Payload::DeserializeContext { id, tpe } => {
            (ctx.extension.get(id).map(|(t, v)| (t, v)), tpe, None)
        }
        Payload::DeserializeRegister {
            reg_id,
            tpe,
            default,
        } => {
            let value = ctx
                .self_box
                .and_then(|b| {
                    reg_id
                        .checked_sub(4)
                        .and_then(|i| b.registers.get(i as usize))
                        .and_then(Option::as_ref)
                })
                .map(|r| (&r.tpe, &r.value));
            (value, tpe, default.as_deref())
        }
        _ => return Ok(()),
    };
    if let Some((SigmaType::SColl(inner), SigmaValue::Coll(CollValue::Bytes(bytes)))) = value {
        if **inner == SigmaType::SByte {
            let script = deserialize_measured(bytes, ctx, cost)?;
            let actual = ergo_ser::ergo_tree::substitution_type_of(&script);
            if actual.as_ref() != Some(tpe) {
                if matches!(node.payload, Payload::DeserializeRegister { .. }) {
                    return Err(EvalError::RuntimeException(
                        "DeserializeRegister script type mismatch",
                    ));
                }
                return Err(EvalError::SigmaValidation {
                    rule_id: 1000,
                    args: vec![],
                });
            }
            *expr = script;
            return Ok(());
        }
    }
    // A present incompatible register fails the unchecked cast inside Scala's
    // rewrite strategy, leaving the node unresolved. Only absence uses default;
    // an unresolved node rejects if evaluation reaches it, including with default.
    if value.is_none() {
        if let Some(default) = default {
            *expr = default.clone();
        }
    }
    Ok(())
}

/// Scala parses before `addCostChecked`, then charges the entire supplied buffer.
fn deserialize_measured(
    bytes: &[u8],
    ctx: &super::ReductionContext<'_>,
    cost: &mut ergo_primitives::cost::CostAccumulator,
) -> Result<Expr, super::EvalError> {
    use ergo_primitives::cost::{CostError, JitCost};
    let mut reader = ergo_primitives::reader::VlqReader::new(bytes);
    reader.set_strict_method_resolution();
    reader.set_embeddable_activated_version(Some(ctx.activated_script_version));
    let script = ergo_ser::opcode::parse_body(&mut reader, ctx.ergo_tree_version).map_err(|e| {
        if let ergo_primitives::reader::ReadError::SigmaValidation { rule_id, args, .. } = e {
            // ValidationRules: A6 uses new rule identities even for legacy trees.
            let rule_id = match (rule_id, ctx.activated_script_version >= 3) {
                (1011, true) => 1016,
                (1007, true) => 1017,
                (1008, true) => 1018,
                _ => rule_id,
            };
            super::EvalError::SigmaValidation { rule_id, args }
        } else {
            super::EvalError::TypeError {
                expected: "valid serialized expression",
                got: format!("deserialization error: {e}"),
            }
        }
    })?;
    let charge = JitCost::from_block_cost(bytes.len() as u64 * 2).map_err(CostError::from)?;
    cost.add(charge)?;
    Ok(script)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_ser::ergo_tree::substitution_type_of;

    // ----- helpers -----

    fn op(opcode: u8, payload: Payload) -> Expr {
        Expr::Op(IrNode { opcode, payload })
    }

    // ----- happy path -----

    #[test]
    fn substitution_type_collection_exact_type() {
        let script = op(
            0x83,
            Payload::ConcreteCollection {
                elem_type: SigmaType::SInt,
                items: vec![],
            },
        );
        assert_eq!(
            substitution_type_of(&script),
            Some(SigmaType::SColl(Box::new(SigmaType::SInt)))
        );
    }

    // ----- error paths -----

    #[test]
    fn substitution_type_unknown_or_imprecise_rejected() {
        let unknown = op(0x72, Payload::ValUse { id: 1 });
        assert_eq!(substitution_type_of(&unknown), None);
        let imprecise = op(
            0x86,
            Payload::Tuple {
                items: vec![unknown],
            },
        );
        assert_eq!(substitution_type_of(&imprecise), None);
        assert_eq!(substitution_type_of(&Expr::Unparsed(vec![])), None);
    }
}
